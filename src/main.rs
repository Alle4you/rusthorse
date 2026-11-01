//! The `rusthorse` command-line interface. See `docs/cli.md`.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};

use rusthorse::agent::{self, Agent, AgentConfig};
use rusthorse::client::Client;
use rusthorse::protocol::{
    Binding, EntryChanges, EntryFields, EntryInfo, ErrorCode, Field, ImportedEntry, NewEntry,
    Request, Response, RunRequest, SecretString, ValueChange,
};
use rusthorse::ui::{Prompt, Ui, ZenityUi};
use rusthorse::util::{format_duration, is_valid_env_name, parse_duration};
use rusthorse::vault::{KdfParams, Vault};
use rusthorse::{audit, import, paths};

/// Exit status for `run` when Rusthorse itself fails (as `env`/`docker run` do).
const EXIT_RUN_FAILURE: u8 = 125;
/// Exit status when the human denied or cancelled the request.
const EXIT_DENIED: u8 = 4;

#[derive(Parser)]
#[command(
    name = "rusthorse",
    version,
    about = "A local KeePass vault whose secrets AI agents can use without seeing them.",
    long_about = "Rusthorse keeps secrets in a KeePass (KDBX4) file. A background agent holds \
the unlocked vault; every use of a secret is approved by you in a dialog, and `rusthorse run` \
lets a program (or an AI agent) use a secret without the value being shown to the caller.\n\n\
Documentation: https://github.com/Alle4you/rusthorse/tree/main/docs"
)]
struct Cli {
    /// Agent socket.
    #[arg(long, global = true, env = paths::ENV_SOCKET, value_name = "PATH")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new, empty vault.
    Init {
        /// Vault file to create.
        #[arg(long, env = paths::ENV_VAULT, value_name = "PATH")]
        vault: Option<PathBuf>,
    },
    /// Run the agent in the foreground (normally started by systemd).
    Agent(AgentArgs),
    /// Show whether the agent is running and the vault is unlocked.
    Status {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Unlock the vault (the agent asks for the master password).
    Unlock,
    /// Lock the vault and forget remembered approvals.
    Lock,
    /// List entries (metadata only, never values).
    #[command(visible_alias = "ls")]
    List {
        /// Only entries with this tag.
        #[arg(long)]
        tag: Option<String>,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show an entry's metadata.
    Show {
        /// Entry name or Group/Name path.
        name: String,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add an entry. The agent asks you for the value in a dialog.
    Add(AddArgs),
    /// Change an entry (requires approval).
    Edit(EditArgs),
    /// Delete an entry (requires approval).
    #[command(visible_alias = "rm")]
    Remove {
        /// Entry name or Group/Name path.
        name: String,
    },
    /// Print an entry's value (requires approval; prefer `run`).
    Reveal {
        /// Entry name or Group/Name path.
        name: String,
    },
    /// Run a command with secrets in its environment (requires approval).
    Run(RunArgs),
    /// Import secrets from other stores.
    #[command(subcommand)]
    Import(ImportCommand),
    /// Show the most recent audit log records.
    Audit {
        /// Number of records.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Print JSON Lines.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct AgentArgs {
    /// Vault file.
    #[arg(long, env = paths::ENV_VAULT, value_name = "PATH")]
    vault: Option<PathBuf>,
    /// Audit log file.
    #[arg(long, env = paths::ENV_AUDIT_LOG, value_name = "PATH")]
    audit_log: Option<PathBuf>,
    /// Lock after this much inactivity (`0` = never).
    #[arg(long, default_value = "15m", value_parser = parse_duration, value_name = "DURATION")]
    idle_timeout: Duration,
    /// Offer "Allow for DURATION" in run dialogs, approving identical requests
    /// for that long without asking. Off (`0`) by default; see docs/cli.md.
    #[arg(long, default_value = "0", value_parser = parse_duration, value_name = "DURATION")]
    remember: Duration,
    /// How long dialogs wait for an answer before denying.
    #[arg(long, default_value = "2m", value_parser = parse_duration, value_name = "DURATION")]
    dialog_timeout: Duration,
}

#[derive(Args)]
struct EntryArgs {
    /// Login name.
    #[arg(long, short = 'u')]
    username: Option<String>,
    /// Access link, e.g. https://router.lan/ or ssh://admin@10.0.0.1.
    #[arg(long)]
    url: Option<String>,
    /// Host name or IP address.
    #[arg(long)]
    host: Option<String>,
    /// Port.
    #[arg(long)]
    port: Option<u16>,
    /// Notes (stored protected; never shown without approval).
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Args)]
struct AddArgs {
    /// Entry name. Use an environment-variable-style name (OPENAI_API_KEY)
    /// to make `rusthorse run NAME -- …` work without `VAR=`.
    name: String,
    #[command(flatten)]
    fields: EntryArgs,
    /// Tag (repeatable).
    #[arg(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
    /// Group path such as Work/Servers.
    #[arg(long)]
    group: Option<String>,
    /// Read the value from standard input instead of a dialog (requires approval).
    #[arg(long)]
    stdin: bool,
    /// Overwrite an existing entry with the same name.
    #[arg(long)]
    replace: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ClearField {
    Username,
    Url,
    Host,
    Port,
    Notes,
}

#[derive(Args)]
struct EditArgs {
    /// Entry name or Group/Name path.
    name: String,
    #[command(flatten)]
    fields: EntryArgs,
    /// New name.
    #[arg(long, value_name = "NAME")]
    rename: Option<String>,
    /// Remove a field (repeatable).
    #[arg(long, value_enum, value_name = "FIELD")]
    clear: Vec<ClearField>,
    /// Add a tag (repeatable).
    #[arg(long = "add-tag", value_name = "TAG")]
    add_tags: Vec<String>,
    /// Remove a tag (repeatable).
    #[arg(long = "remove-tag", value_name = "TAG")]
    remove_tags: Vec<String>,
    /// Also change the value; the agent asks you for it in a dialog.
    #[arg(long, conflicts_with = "stdin")]
    value: bool,
    /// Read the new value from standard input.
    #[arg(long)]
    stdin: bool,
}

#[derive(Args)]
struct RunArgs {
    /// Pass secret values through to the output unredacted.
    #[arg(long)]
    no_redact: bool,
    /// Forward this terminal's standard input to the command. By default the
    /// command reads /dev/null (with --no-redact it always gets stdin).
    #[arg(long)]
    stdin: bool,
    /// Secrets to expose: ENTRY (variable named like the entry) or VAR=ENTRY.
    #[arg(required = true, value_name = "SECRET")]
    secrets: Vec<String>,
    /// The command, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Subcommand)]
enum ImportCommand {
    /// Import NAME=value pairs from a .env file.
    Dotenv {
        /// The .env file.
        file: PathBuf,
        /// Prefix added to every name (upper-cased), e.g. --prefix MYAPP_.
        #[arg(long)]
        prefix: Option<String>,
        /// Tag added to every imported entry.
        #[arg(long = "tag", short = 't')]
        tags: Vec<String>,
        /// Overwrite existing entries.
        #[arg(long)]
        replace: bool,
    },
    /// Import items from GNOME Keyring / KWallet (freedesktop Secret Service).
    #[cfg(feature = "secret-service")]
    SecretService {
        /// Only items with this attribute (KEY=VALUE, repeatable, all must match).
        #[arg(
            long = "attribute",
            short = 'a',
            value_name = "KEY=VALUE",
            required = true
        )]
        attributes: Vec<String>,
        /// Attribute holding the entry name (default: the item label).
        #[arg(long, value_name = "ATTRIBUTE")]
        name_from: Option<String>,
        /// Tag added to every imported entry.
        #[arg(long = "tag", short = 't')]
        tags: Vec<String>,
        /// Overwrite existing entries.
        #[arg(long)]
        replace: bool,
    },
}

/// An error that already has an exit status.
struct Exit(u8);

fn main() -> ExitCode {
    let cli = Cli::parse();
    let client = Client::new(cli.socket.clone().unwrap_or_else(paths::socket));
    match dispatch(cli.command, &client) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            if let Some(Exit(code)) = e.downcast_ref::<Exit>() {
                return ExitCode::from(*code);
            }
            eprintln!("rusthorse: {e:#}");
            ExitCode::FAILURE
        }
    }
}

impl std::fmt::Debug for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}", self.0)
    }
}
impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}", self.0)
    }
}
impl std::error::Error for Exit {}

fn dispatch(command: Command, client: &Client) -> anyhow::Result<u8> {
    match command {
        Command::Init { vault } => init(vault.unwrap_or_else(paths::vault)).map(|_| 0),
        Command::Agent(args) => run_agent(args, client.socket().to_path_buf()).map(|_| 0),
        Command::Status { json } => status(client, json),
        Command::Unlock => simple(client, &Request::Unlock),
        Command::Lock => simple(client, &Request::Lock),
        Command::List { tag, json } => list(client, tag, json),
        Command::Show { name, json } => show(client, name, json),
        Command::Add(args) => add(client, args),
        Command::Edit(args) => edit(client, args),
        Command::Remove { name } => simple(client, &Request::Remove { name }),
        Command::Reveal { name } => reveal(client, name),
        Command::Run(args) => run(client, args),
        Command::Import(cmd) => import_cmd(client, cmd),
        Command::Audit { lines, json } => show_audit(lines, json),
    }
}

/// Turn an error response into an error (with the right exit status).
fn check(response: Response) -> anyhow::Result<Response> {
    match response {
        Response::Error { code, message } => {
            eprintln!("rusthorse: {message}");
            let status = match code {
                ErrorCode::Denied | ErrorCode::Cancelled => EXIT_DENIED,
                _ => 1,
            };
            Err(Exit(status).into())
        }
        other => Ok(other),
    }
}

fn simple(client: &Client, request: &Request) -> anyhow::Result<u8> {
    match check(client.call(request)?)? {
        Response::Ok { message } => {
            eprintln!("{message}");
            Ok(0)
        }
        other => bail!("unexpected {} response from the agent", other.kind()),
    }
}

fn init(vault: PathBuf) -> anyhow::Result<()> {
    if vault.exists() {
        bail!("a vault already exists at {}", vault.display());
    }
    let password = new_master_password()?;
    Vault::create(&vault, password, KdfParams::DEFAULT)?;
    println!("Created {}", vault.display());
    println!(
        "Next: start the agent (`systemctl --user enable --now rusthorse-agent`), then `rusthorse add NAME`."
    );
    Ok(())
}

fn new_master_password() -> anyhow::Result<SecretString> {
    let (first, second) = if std::io::stdin().is_terminal() {
        (
            SecretString::new(rpassword::prompt_password("New master password: ")?),
            SecretString::new(rpassword::prompt_password("Repeat it: ")?),
        )
    } else {
        let ui = ZenityUi {
            remember_for: Duration::ZERO,
            timeout: Duration::from_secs(300),
        };
        let ask = |message: &str| -> anyhow::Result<SecretString> {
            ui.master_password(&Prompt {
                title: "Rusthorse — new vault".into(),
                message: message.into(),
                confirm: "OK".into(),
            })?
            .context("cancelled")
        };
        (
            ask(
                "Choose a master password for the new Rusthorse vault.\nAt least 12 characters is recommended.",
            )?,
            ask("Type the master password again.")?,
        )
    };
    if *first != *second {
        bail!("the passwords do not match");
    }
    let length = first.chars().count();
    if length < 8 {
        bail!("the master password must have at least 8 characters");
    }
    if length < 12 {
        eprintln!(
            "warning: a master password of at least 12 characters (or a 5-word passphrase) is recommended"
        );
    }
    Ok(first)
}

fn run_agent(args: AgentArgs, socket: PathBuf) -> anyhow::Result<()> {
    agent::harden_process()?;
    let parent = agent::parent_process_name().unwrap_or_default();
    if parent != "systemd" {
        eprintln!(
            "rusthorse agent: warning: started by {parent:?}, not systemd. \
             Start it with `systemctl --user start rusthorse-agent` so that it does not run \
             inside another program's process tree (see docs/threat-model.md)."
        );
    }
    let config = AgentConfig {
        vault: args.vault.unwrap_or_else(paths::vault),
        socket,
        audit_log: args.audit_log.unwrap_or_else(paths::audit_log),
        idle_timeout: args.idle_timeout,
        request_timeout: Duration::from_secs(10),
    };
    let ui = ZenityUi {
        remember_for: args.remember,
        timeout: args.dialog_timeout,
    };
    let listener = Agent::bind(&config.socket)?;
    eprintln!(
        "rusthorse agent {} listening on {} (vault {}, auto-lock {})",
        env!("CARGO_PKG_VERSION"),
        config.socket.display(),
        config.vault.display(),
        if config.idle_timeout.is_zero() {
            "off".into()
        } else {
            format_duration(config.idle_timeout)
        }
    );
    let agent = Agent::new(config, Box::new(ui));
    agent.serve(listener)
}

fn status(client: &Client, json: bool) -> anyhow::Result<u8> {
    let Response::Status(info) = check(client.call(&Request::Status)?)? else {
        bail!("unexpected response");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(0);
    }
    println!(
        "agent:      running (version {}, protocol {})",
        info.agent_version, info.protocol_version
    );
    println!(
        "vault:      {}{}",
        info.vault,
        if info.vault_exists {
            ""
        } else {
            " (missing — run `rusthorse init`)"
        }
    );
    match (info.locked, info.locks_in_secs) {
        (true, _) => println!("state:      locked"),
        (false, Some(secs)) => println!(
            "state:      unlocked (locks in {})",
            format_duration(Duration::from_secs(secs))
        ),
        (false, None) => println!("state:      unlocked (auto-lock off)"),
    }
    println!("remembered: {} approval(s)", info.remembered_approvals);
    Ok(0)
}

fn endpoint(info: &EntryInfo) -> String {
    let f = &info.fields;
    match (&f.url, &f.host, f.port) {
        (Some(url), _, _) => url.clone(),
        (None, Some(host), Some(port)) => format!("{host}:{port}"),
        (None, Some(host), None) => host.clone(),
        _ => String::new(),
    }
}

fn list(client: &Client, tag: Option<String>, json: bool) -> anyhow::Result<u8> {
    let Response::Entries { mut entries } = check(client.call(&Request::List)?)? else {
        bail!("unexpected response");
    };
    if let Some(tag) = tag {
        entries.retain(|e| e.fields.tags.contains(&tag));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(0);
    }
    if entries.is_empty() {
        eprintln!("No entries.");
        return Ok(0);
    }
    let rows: Vec<[String; 4]> = entries
        .iter()
        .map(|e| {
            let name = match &e.group {
                Some(g) => format!("{g}/{}", e.name),
                None => e.name.clone(),
            };
            [
                name,
                e.fields.username.clone().unwrap_or_default(),
                endpoint(e),
                e.fields.tags.join(","),
            ]
        })
        .collect();
    let headers = ["NAME", "USERNAME", "ENDPOINT", "TAGS"];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let print_row = |cells: [&str; 4]| {
        let line: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        println!("{}", line.join("  ").trim_end());
    };
    print_row(headers);
    for row in &rows {
        print_row([&row[0], &row[1], &row[2], &row[3]]);
    }
    Ok(0)
}

fn show(client: &Client, name: String, json: bool) -> anyhow::Result<u8> {
    let Response::Entry { entry } = check(client.call(&Request::Show { name })?)? else {
        bail!("unexpected response");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(0);
    }
    let f = &entry.fields;
    let line = |label: &str, value: Option<String>| {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            println!("{label:<11} {v}");
        }
    };
    line("name:", Some(entry.name.clone()));
    line("id:", Some(entry.id.clone()));
    line("group:", entry.group.clone());
    line("username:", f.username.clone());
    line("url:", f.url.clone());
    line("host:", f.host.clone());
    line("port:", f.port.map(|p| p.to_string()));
    line("tags:", Some(f.tags.join(", ")));
    line(
        "value:",
        Some(if entry.has_password {
            "set (hidden)".into()
        } else {
            "none".into()
        }),
    );
    line("notes:", entry.has_notes.then(|| "set (hidden)".into()));
    line("protected:", Some(entry.protected_fields.join(", ")));
    line("fields:", Some(entry.other_fields.join(", ")));
    line("modified:", entry.modified.clone());
    Ok(0)
}

fn read_stdin_value() -> anyhow::Result<SecretString> {
    let mut value = SecretString::new(String::new());
    std::io::stdin()
        .read_to_string(&mut value)
        .context("cannot read the value from standard input")?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    if value.is_empty() {
        bail!("empty value on standard input; nothing stored");
    }
    Ok(value)
}

fn add(client: &Client, args: AddArgs) -> anyhow::Result<u8> {
    let value = if args.stdin {
        Some(read_stdin_value()?)
    } else {
        None
    };
    let entry = NewEntry {
        name: args.name,
        group: args.group,
        fields: EntryFields {
            username: args.fields.username,
            url: args.fields.url,
            host: args.fields.host,
            port: args.fields.port,
            tags: args.tags,
        },
        notes: args.fields.notes,
    };
    simple(
        client,
        &Request::Add {
            entry,
            value,
            replace: args.replace,
        },
    )
}

fn edit(client: &Client, args: EditArgs) -> anyhow::Result<u8> {
    let value = if args.stdin {
        Some(ValueChange::Provided(read_stdin_value()?))
    } else if args.value {
        Some(ValueChange::Prompt)
    } else {
        None
    };
    let changes = EntryChanges {
        rename: args.rename,
        username: args.fields.username,
        url: args.fields.url,
        host: args.fields.host,
        port: args.fields.port,
        notes: args.fields.notes,
        clear: args
            .clear
            .into_iter()
            .map(|f| match f {
                ClearField::Username => Field::Username,
                ClearField::Url => Field::Url,
                ClearField::Host => Field::Host,
                ClearField::Port => Field::Port,
                ClearField::Notes => Field::Notes,
            })
            .collect(),
        add_tags: args.add_tags,
        remove_tags: args.remove_tags,
        value,
    };
    if changes.is_empty() {
        bail!("nothing to change (see `rusthorse edit --help`)");
    }
    simple(
        client,
        &Request::Edit {
            name: args.name,
            changes,
        },
    )
}

fn reveal(client: &Client, name: String) -> anyhow::Result<u8> {
    let Response::Secret { value } = check(client.call(&Request::Reveal { name })?)? else {
        bail!("unexpected response");
    };
    println!("{}", value.as_str());
    Ok(0)
}

fn parse_binding(spec: &str) -> anyhow::Result<Binding> {
    let (var, entry) = match spec.split_once('=') {
        Some((var, entry)) => (var, entry),
        None => (spec, spec),
    };
    if entry.is_empty() {
        bail!("{spec:?}: missing entry name after '='");
    }
    if !is_valid_env_name(var) {
        bail!("{var:?} is not a valid environment variable name; write VAR={spec}");
    }
    Ok(Binding {
        var: var.to_string(),
        entry: entry.to_string(),
    })
}

fn run(client: &Client, args: RunArgs) -> anyhow::Result<u8> {
    let outcome = (|| -> anyhow::Result<u8> {
        let bindings = args
            .secrets
            .iter()
            .map(|s| parse_binding(s))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let cwd = std::env::current_dir().context("cannot determine the working directory")?;
        let cwd = cwd
            .to_str()
            .context("the working directory is not valid UTF-8")?
            .to_string();
        let mut env = Vec::new();
        for (key, value) in std::env::vars_os() {
            if let (Some(k), Some(v)) = (key.to_str(), value.to_str()) {
                env.push((k.to_string(), v.to_string()));
            }
        }
        let request = RunRequest {
            bindings,
            argv: args.command,
            cwd,
            env,
            redact: !args.no_redact,
            forward_stdin: args.stdin,
        };
        match client.run(request)? {
            Response::Exited {
                code: Some(code), ..
            } => Ok(code.clamp(0, 255) as u8),
            Response::Exited {
                signal: Some(sig), ..
            } => Ok((128 + sig).clamp(0, 255) as u8),
            Response::Exited { .. } => Ok(EXIT_RUN_FAILURE),
            Response::Error { message, .. } => {
                eprintln!("rusthorse: {message}");
                Ok(EXIT_RUN_FAILURE)
            }
            other => bail!("unexpected {} response from the agent", other.kind()),
        }
    })();
    match outcome {
        Ok(code) => Ok(code),
        Err(e) => {
            eprintln!("rusthorse: {e:#}");
            Ok(EXIT_RUN_FAILURE)
        }
    }
}

fn import_cmd(client: &Client, command: ImportCommand) -> anyhow::Result<u8> {
    let (pairs, tags, replace) = match command {
        ImportCommand::Dotenv {
            file,
            prefix,
            tags,
            replace,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            let text = SecretString::new(text);
            let prefix = prefix.unwrap_or_default().to_uppercase();
            let pairs: Vec<(String, SecretString)> = import::parse_dotenv(&text)
                .into_iter()
                .map(|(name, value)| (format!("{prefix}{name}"), value))
                .collect();
            (pairs, tags, replace)
        }
        #[cfg(feature = "secret-service")]
        ImportCommand::SecretService {
            attributes,
            name_from,
            tags,
            replace,
        } => {
            let attributes = attributes
                .iter()
                .map(|a| {
                    a.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .with_context(|| format!("{a:?}: expected KEY=VALUE"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let pairs = import::read_secret_service(&attributes, name_from.as_deref())?;
            (pairs, tags, replace)
        }
    };
    if pairs.is_empty() {
        bail!("nothing found to import");
    }
    let entries = pairs
        .into_iter()
        .map(|(name, value)| ImportedEntry {
            entry: NewEntry {
                name,
                fields: EntryFields {
                    tags: tags.clone(),
                    ..EntryFields::default()
                },
                ..NewEntry::default()
            },
            value,
        })
        .collect();
    simple(client, &Request::Import { entries, replace })
}

fn show_audit(lines: usize, json: bool) -> anyhow::Result<u8> {
    let path = paths::audit_log();
    let events =
        audit::tail(&path, lines).with_context(|| format!("cannot read {}", path.display()))?;
    for event in events {
        if json {
            println!("{}", serde_json::to_string(&event)?);
            continue;
        }
        let mut line = format!("{}  {:<8} {:<20}", event.time, event.action, event.outcome);
        if !event.entries.is_empty() {
            line.push_str(&format!(" [{}]", event.entries.join(", ")));
        }
        if let Some(argv) = &event.argv {
            line.push_str(&format!(" $ {}", rusthorse::util::shell_join(argv)));
        }
        if let Some(detail) = &event.detail {
            line.push_str(&format!(" ({detail})"));
        }
        line.push_str(&format!("  by {}", event.requester));
        println!("{line}");
    }
    Ok(0)
}
