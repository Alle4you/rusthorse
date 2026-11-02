//! The `rusthorse` command-line interface. See `docs/cli.md`.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use rusthorse::agent::{self, Agent, AgentConfig};
use rusthorse::client::Client;
use rusthorse::dialog_program::DesktopUi;
use rusthorse::generate::{Alphabet, Spec};
use rusthorse::protocol::{
    Binding, EntryChanges, EntryFields, EntryInfo, EntryKind, ErrorCode, Field, ImportedEntry,
    NewEntry, Request, Response, RunRequest, SecretString, ValueChange,
};
use rusthorse::ui::{Prompt, Typed, Ui};
use rusthorse::util::{format_duration, is_valid_env_name, parse_duration};
use rusthorse::vault::{KdfParams, Vault};
use rusthorse::{audit, import, paths};

/// Exit status for `run` when Rusthorse refused or failed and the command
/// did not run (as `env` and `docker run` do).
const EXIT_RUN_FAILURE: u8 = 125;
/// Exit status when the outcome is unknown: the request was sent but no answer
/// came back, or the agent could not confirm it took effect (a command may or
/// may not have run; a change may or may not have been saved).
const EXIT_UNKNOWN: u8 = 124;
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
        /// Only entries of this kind (`other`: entries of no particular kind).
        #[arg(long, value_enum)]
        kind: Option<KindArg>,
        /// Only entries whose name, group, username, URL, host or tags contain
        /// this text (case-insensitive).
        #[arg(long, short = 's', value_name = "TEXT")]
        search: Option<String>,
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
        /// Print the entry's notes instead of its value.
        #[arg(long)]
        notes: bool,
    },
    /// Copy the encrypted vault to a file and verify that the copy opens.
    Backup {
        /// Destination file (must not exist).
        dest: PathBuf,
    },
    /// Open an entry's URL (its access link) in the default browser.
    Open {
        /// Entry name or Group/Name path.
        name: String,
    },
    /// Change the master password (the agent asks for the current and the new one).
    Passwd,
    /// Generate a random value and print it; nothing is stored.
    Generate(GenerateArgs),
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
    /// Check the installation and the environment, and explain any problem.
    Doctor,
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell).
    Completions {
        /// The shell.
        shell: clap_complete::Shell,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum AlphabetArg {
    /// Letters and digits.
    Alnum,
    /// Letters, digits and -_.:@+=~%^
    Symbols,
    /// Hexadecimal digits.
    Hex,
}

impl From<AlphabetArg> for Alphabet {
    fn from(a: AlphabetArg) -> Self {
        match a {
            AlphabetArg::Alnum => Alphabet::Alnum,
            AlphabetArg::Symbols => Alphabet::Symbols,
            AlphabetArg::Hex => Alphabet::Hex,
        }
    }
}

#[derive(Args)]
struct GenerateArgs {
    /// Number of characters (8–1024).
    #[arg(long, short = 'l', default_value_t = 32)]
    length: u16,
    /// Characters to use.
    #[arg(long, short = 'a', value_enum, default_value = "alnum")]
    alphabet: AlphabetArg,
}

/// `--generate` options shared by `add` and `edit`.
#[derive(Args)]
struct GenerateOptions {
    /// Let the agent generate a random value (requires approval); nobody
    /// types or sees it.
    #[arg(long, conflicts_with = "stdin")]
    generate: bool,
    /// Length of the generated value (default 32).
    #[arg(long, requires = "generate", value_name = "N")]
    length: Option<u16>,
    /// Characters of the generated value (default alnum).
    #[arg(long, requires = "generate", value_enum)]
    alphabet: Option<AlphabetArg>,
}

impl GenerateOptions {
    fn spec(&self) -> Option<Spec> {
        self.generate.then(|| Spec {
            length: self.length.unwrap_or(Spec::default().length),
            alphabet: self
                .alphabet
                .map_or(Spec::default().alphabet, Alphabet::from),
        })
    }
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

/// What an entry is for (see `EntryKind`); `other` is no particular kind.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum KindArg {
    /// A key or token for an API; --url is its endpoint.
    ApiKey,
    /// A sign-in to a website or web console.
    Login,
    /// A server reached by host and port (SSH, a database, …).
    Server,
    /// A device such as a router; --url is its admin page.
    Device,
    /// No particular kind.
    Other,
}

impl KindArg {
    fn kind(self) -> Option<EntryKind> {
        match self {
            KindArg::ApiKey => Some(EntryKind::ApiKey),
            KindArg::Login => Some(EntryKind::Login),
            KindArg::Server => Some(EntryKind::Server),
            KindArg::Device => Some(EntryKind::Device),
            KindArg::Other => None,
        }
    }
}

#[derive(Args)]
struct EntryArgs {
    /// What the entry is for. It labels the fields (the URL of an API key is
    /// its endpoint) and grants nothing.
    #[arg(long, value_enum)]
    kind: Option<KindArg>,
    /// Login name.
    #[arg(long, short = 'u')]
    username: Option<String>,
    /// Access link, e.g. https://router.lan/ or ssh://admin@10.0.0.1; for an
    /// API key, the API's endpoint, e.g. https://api.openai.com/v1.
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
    #[command(flatten)]
    generate: GenerateOptions,
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
    Kind,
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
    #[arg(long, conflicts_with_all = ["stdin", "generate"])]
    value: bool,
    /// Read the new value from standard input.
    #[arg(long)]
    stdin: bool,
    #[command(flatten)]
    generate: GenerateOptions,
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
    /// Also put an entry's URL (an API's endpoint) in variable VAR. The URL
    /// is not a secret: it is neither redacted nor listed in the dialog.
    #[arg(long = "url", value_name = "VAR=ENTRY")]
    urls: Vec<String>,
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
        /// Only list what would be imported, and which names already exist.
        #[arg(long)]
        dry_run: bool,
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
        /// Only list what would be imported, and which names already exist;
        /// no secret is read.
        #[arg(long)]
        dry_run: bool,
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
            if e.downcast_ref::<rusthorse::client::OutcomeUnknown>()
                .is_some()
            {
                eprintln!("rusthorse: {e:#}; it may or may not have taken effect");
                ExitCode::from(EXIT_UNKNOWN)
            } else {
                eprintln!("rusthorse: {e:#}");
                ExitCode::FAILURE
            }
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
    let talks_to_agent = !matches!(
        command,
        Command::Init { .. }
            | Command::Agent(_)
            | Command::Status { .. }
            | Command::Audit { .. }
            | Command::Doctor
            | Command::Generate(_)
            | Command::Completions { .. }
            // `run` checks inside its own error handling, so that a missing
            // or incompatible agent is reported as "did not run" (125).
            | Command::Run(_)
    );
    if talks_to_agent {
        client.check_compatible()?;
    }
    match command {
        Command::Init { vault } => init(vault.unwrap_or_else(paths::vault)).map(|_| 0),
        Command::Agent(args) => run_agent(args, client.socket().to_path_buf()).map(|_| 0),
        Command::Status { json } => status(client, json),
        Command::Passwd => simple(client, &Request::ChangePassword),
        Command::Open { name } => open(client, name),
        Command::Generate(args) => generate_cmd(args),
        Command::Doctor => doctor(client),
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "rusthorse",
                &mut std::io::stdout(),
            );
            Ok(0)
        }
        Command::Unlock => simple(client, &Request::Unlock),
        Command::Lock => simple(client, &Request::Lock),
        Command::List {
            tag,
            kind,
            search,
            json,
        } => list(client, tag, kind, search, json),
        Command::Show { name, json } => show(client, name, json),
        Command::Add(args) => add(client, args),
        Command::Edit(args) => edit(client, args),
        Command::Remove { name } => simple(client, &Request::Remove { name }),
        Command::Reveal { name, notes } => reveal(client, name, notes),
        Command::Backup { dest } => {
            let dest = std::env::current_dir()?.join(dest);
            let path = dest
                .to_str()
                .context("the backup path is not valid UTF-8")?
                .to_string();
            simple(client, &Request::Backup { path })
        }
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
                ErrorCode::OutcomeUnknown => EXIT_UNKNOWN,
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
        // An answer that makes no sense says nothing about what happened.
        other if request.has_effects() => Err(anyhow::Error::new(
            rusthorse::client::OutcomeUnknown(format!("unexpected {} response", other.kind())),
        )),
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
        let ui = DesktopUi {
            remember_for: Duration::ZERO,
            timeout: Duration::from_secs(300),
        };
        let ask =
            |headline: &str, explanation: &str, field: &str| -> anyhow::Result<SecretString> {
                match ui.master_password(&Prompt {
                    title: "Rusthorse — new vault".into(),
                    headline: headline.into(),
                    explanation: explanation.into(),
                    notice: None,
                    details: Vec::new(),
                    field: field.into(),
                    confirm: "OK".into(),
                })? {
                    Typed::Value(value) => Ok(value),
                    Typed::Cancelled => bail!("cancelled"),
                    Typed::TimedOut => bail!("nobody answered the dialog in time"),
                }
            };
        (
            ask(
                "Choose a master password for the new Rusthorse vault.",
                "At least 12 characters is recommended.",
                "Master password",
            )?,
            ask(
                "Type the master password again.",
                "",
                "Master password, again",
            )?,
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
        send_buffer: None,
    };
    let ui = DesktopUi {
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
    if let Some(dialogs) = &info.dialogs {
        println!("dialogs:    {dialogs}");
    }
    if !info.agent_executable.is_empty() {
        println!(
            "program:    {}{}",
            info.agent_executable,
            if info.agent_executable_replaced == Some(true) {
                " (replaced since the agent started — restart it)"
            } else {
                ""
            }
        );
    }
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

fn list(
    client: &Client,
    tag: Option<String>,
    kind: Option<KindArg>,
    search: Option<String>,
    json: bool,
) -> anyhow::Result<u8> {
    let Response::Entries { mut entries } = check(client.call(&Request::List)?)? else {
        bail!("unexpected response");
    };
    if let Some(tag) = tag {
        entries.retain(|e| e.fields.tags.contains(&tag));
    }
    if let Some(kind) = kind {
        entries.retain(|e| e.fields.kind == kind.kind());
    }
    if let Some(search) = search {
        let needle = search.to_lowercase();
        entries.retain(|e| {
            let f = &e.fields;
            [
                Some(&e.name),
                e.group.as_ref(),
                f.username.as_ref(),
                f.url.as_ref(),
                f.host.as_ref(),
            ]
            .into_iter()
            .flatten()
            .chain(f.tags.iter())
            .any(|text| text.to_lowercase().contains(&needle))
        });
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
    line(
        "kind:",
        f.kind.map(|k| format!("{} ({})", k.as_str(), k.label())),
    );
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
            kind: args.fields.kind.and_then(KindArg::kind),
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
            generate: args.generate.spec(),
            replace: args.replace,
        },
    )
}

fn edit(client: &Client, args: EditArgs) -> anyhow::Result<u8> {
    let value = if args.stdin {
        Some(ValueChange::Provided(read_stdin_value()?))
    } else if let Some(spec) = args.generate.spec() {
        Some(ValueChange::Generate(spec))
    } else if args.value {
        Some(ValueChange::Prompt)
    } else {
        None
    };
    let mut clear: Vec<Field> = args
        .clear
        .into_iter()
        .map(|f| match f {
            ClearField::Username => Field::Username,
            ClearField::Url => Field::Url,
            ClearField::Host => Field::Host,
            ClearField::Port => Field::Port,
            ClearField::Notes => Field::Notes,
            ClearField::Kind => Field::Kind,
        })
        .collect();
    if args.fields.kind == Some(KindArg::Other) && !clear.contains(&Field::Kind) {
        clear.push(Field::Kind);
    }
    let changes = EntryChanges {
        rename: args.rename,
        kind: args.fields.kind.and_then(KindArg::kind),
        username: args.fields.username,
        url: args.fields.url,
        host: args.fields.host,
        port: args.fields.port,
        notes: args.fields.notes,
        clear,
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

fn reveal(client: &Client, name: String, notes: bool) -> anyhow::Result<u8> {
    let Response::Secret { value } = check(client.call(&Request::Reveal {
        name,
        notes,
        purpose: None,
    })?)?
    else {
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

/// The variables that `run --url VAR=ENTRY` adds: each entry's URL, read
/// from its metadata. A URL is not a secret — `rusthorse show` prints it
/// without approval — so it travels in the client's environment like any
/// variable set in the shell: not redacted, not listed in the dialog.
fn endpoint_urls(
    client: &Client,
    specs: &[String],
    secrets: &[Binding],
) -> anyhow::Result<Vec<(String, String)>> {
    // Every option is checked before any entry is read: reading one may make
    // the agent ask for the master password.
    let mut wanted: Vec<Binding> = Vec::new();
    for spec in specs {
        if !spec.contains('=') {
            bail!("--url {spec:?}: write VAR=ENTRY, e.g. --url OPENAI_BASE_URL=OPENAI_API_KEY");
        }
        let binding = parse_binding(spec)?;
        let var = &binding.var;
        if var.starts_with(rusthorse::exec::LOADER_PREFIX) || rusthorse::exec::is_risky(var) {
            bail!("--url {var}: this variable changes how programs start; it cannot carry a URL");
        }
        if secrets.iter().chain(&wanted).any(|b| b.var == *var) {
            bail!("--url {var}: the variable is already set by another binding");
        }
        wanted.push(binding);
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for Binding { var, entry } in wanted {
        let Response::Entry { entry: info } = check(client.call(&Request::Show {
            name: entry.clone(),
        })?)?
        else {
            bail!("unexpected response");
        };
        let Some(url) = info.fields.url else {
            if info.protected_fields.iter().any(|f| f == "URL") {
                bail!("--url {var}: the URL of {entry} is a protected field; it is not disclosed");
            }
            bail!(
                "--url {var}: {entry} has no URL (add one with `rusthorse edit {entry} --url …`)"
            );
        };
        out.push((var, url));
    }
    Ok(out)
}

fn run(client: &Client, args: RunArgs) -> anyhow::Result<u8> {
    let outcome = (|| -> anyhow::Result<u8> {
        client.check_compatible()?;
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
        for (var, url) in endpoint_urls(client, &args.urls, &bindings)? {
            env.retain(|(k, _)| *k != var);
            env.push((var, url));
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
            Response::Exited { .. } => Err(anyhow::Error::new(rusthorse::client::OutcomeUnknown(
                "an exit status with neither a code nor a signal".into(),
            ))),
            Response::Error {
                code: ErrorCode::OutcomeUnknown,
                message,
            } => {
                eprintln!("rusthorse: {message}");
                Ok(EXIT_UNKNOWN)
            }
            Response::Error { message, .. } => {
                eprintln!("rusthorse: {message}");
                Ok(EXIT_RUN_FAILURE)
            }
            other => Err(anyhow::Error::new(rusthorse::client::OutcomeUnknown(
                format!("unexpected {} response", other.kind()),
            ))),
        }
    })();
    match outcome {
        Ok(code) => Ok(code),
        Err(e) => {
            if e.downcast_ref::<rusthorse::client::OutcomeUnknown>()
                .is_some()
            {
                eprintln!("rusthorse: {e:#}; the command may or may not have run");
                Ok(EXIT_UNKNOWN)
            } else {
                eprintln!("rusthorse: {e:#}");
                Ok(EXIT_RUN_FAILURE)
            }
        }
    }
}

/// Most entries sent to the agent in one batch (each batch is one approval).
const IMPORT_BATCH: usize = 50;
/// Most lines the entry names of one batch may take in the approval dialog,
/// counting each name as if it started a line, so that the dialog lists all
/// of them and still fits on the screen (see `ui::approval_height`).
const IMPORT_BATCH_LINES: usize = 24;

fn import_cmd(client: &Client, command: ImportCommand) -> anyhow::Result<u8> {
    let (pairs, tags, replace) = match command {
        ImportCommand::Dotenv {
            file,
            prefix,
            tags,
            replace,
            dry_run,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            let text = SecretString::new(text);
            let prefix = prefix.unwrap_or_default().to_uppercase();
            let pairs: Vec<(String, SecretString)> = import::parse_dotenv(&text)
                .into_iter()
                .map(|(name, value)| (format!("{prefix}{name}"), value))
                .collect();
            if dry_run {
                let names = pairs.iter().map(|(n, _)| n.clone()).collect();
                return import_preview(client, names, replace);
            }
            (pairs, tags, replace)
        }
        #[cfg(feature = "secret-service")]
        ImportCommand::SecretService {
            attributes,
            name_from,
            tags,
            replace,
            dry_run,
        } => {
            let attributes = attributes
                .iter()
                .map(|a| {
                    a.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .with_context(|| format!("{a:?}: expected KEY=VALUE"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if dry_run {
                let names = import::list_secret_service(&attributes, name_from.as_deref())?;
                return import_preview(client, names, replace);
            }
            let pairs = import::read_secret_service(&attributes, name_from.as_deref())?;
            (pairs, tags, replace)
        }
    };
    if pairs.is_empty() {
        bail!("nothing found to import");
    }
    let mut seen = std::collections::HashSet::new();
    let duplicates: std::collections::BTreeSet<&str> = pairs
        .iter()
        .filter(|(name, _)| !seen.insert(name.as_str()))
        .map(|(name, _)| name.as_str())
        .collect();
    if !duplicates.is_empty() {
        bail!(
            "these names appear more than once, so nothing was imported: {} \
             (fix the source, or use --prefix to tell them apart)",
            duplicates.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    let entries: Vec<ImportedEntry> = pairs
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
    // Split into batches small enough for one dialog each.
    let mut batches: Vec<Vec<ImportedEntry>> = Vec::new();
    let mut lines = 0;
    for item in entries {
        let cost = rusthorse::ui::mono_lines(&format!("{}, ", item.entry.name));
        match batches.last_mut() {
            Some(batch) if batch.len() < IMPORT_BATCH && lines + cost <= IMPORT_BATCH_LINES => {
                lines += cost;
                batch.push(item);
            }
            _ => {
                lines = cost;
                batches.push(vec![item]);
            }
        }
    }
    let total = batches.len();
    for (i, batch) in batches.into_iter().enumerate() {
        if total > 1 {
            eprintln!("batch {} of {total} ({} entries):", i + 1, batch.len());
        }
        let answer = client.call(&Request::Import {
            entries: batch,
            replace,
        });
        let done = if i == 0 {
            "no earlier batch was imported".to_string()
        } else {
            format!("batches 1 to {i} were imported")
        };
        let rerun = if replace {
            "running the same import again re-imports everything (with --replace, \
             already imported entries are overwritten with the same values)"
        } else {
            "running the same import again skips the names already imported"
        };
        let not_imported = |status: u8| -> anyhow::Result<u8> {
            if total > 1 {
                eprintln!(
                    "rusthorse: stopped at batch {} of {total}: {done}; batch {} and later were \
                     not imported — {rerun}",
                    i + 1,
                    i + 1
                );
            }
            Err(Exit(status).into())
        };
        let unsure = |what: &str| -> anyhow::Result<u8> {
            eprintln!(
                "rusthorse: {what} batch {} of {total}: {done}; batch {} may or may not have been \
                 imported, later ones were not — check with `rusthorse list` before {rerun}",
                i + 1,
                i + 1
            );
            Err(Exit(EXIT_UNKNOWN).into())
        };
        match answer {
            Ok(Response::Ok { message }) => eprintln!("{message}"),
            // Every error except `outcome_unknown` means nothing was saved
            // (docs/protocol.md, "Errors").
            Ok(Response::Error { code, message }) if code != ErrorCode::OutcomeUnknown => {
                eprintln!("rusthorse: {message}");
                let denied = matches!(code, ErrorCode::Denied | ErrorCode::Cancelled);
                return not_imported(if denied { EXIT_DENIED } else { 1 });
            }
            Ok(Response::Error { message, .. }) => {
                eprintln!("rusthorse: {message}");
                return unsure("could not confirm");
            }
            Ok(other) => {
                eprintln!(
                    "rusthorse: unexpected {} response from the agent",
                    other.kind()
                );
                return unsure("could not confirm");
            }
            // The request was sent but no answer came back.
            Err(e)
                if e.downcast_ref::<rusthorse::client::OutcomeUnknown>()
                    .is_some() =>
            {
                eprintln!("rusthorse: {e:#}");
                return unsure("lost the connection during");
            }
            // The request was never sent (the agent stopped, say).
            Err(e) => {
                eprintln!("rusthorse: {e:#}");
                return not_imported(1);
            }
        }
    }
    Ok(0)
}

/// Show what an import would do, without reading any secret value.
fn import_preview(client: &Client, names: Vec<String>, replace: bool) -> anyhow::Result<u8> {
    if names.is_empty() {
        bail!("nothing found to import");
    }
    let Response::Entries { entries } = check(client.call(&Request::List)?)? else {
        bail!("unexpected response");
    };
    let existing: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.name.as_str()).collect();
    let mut new = 0;
    let mut seen = std::collections::HashSet::new();
    for name in &names {
        let first = seen.insert(name.as_str());
        let (mark, note) = if !first {
            ("dup", "appears more than once: the import will be refused")
        } else if existing.contains(name.as_str()) {
            (
                "exists",
                if replace {
                    "will be replaced"
                } else {
                    "will be skipped"
                },
            )
        } else if rusthorse::vault::validate_name(name).is_err() {
            ("invalid", "cannot be imported (name not allowed)")
        } else {
            new += 1;
            ("new", "")
        };
        println!(
            "{mark:<8} {name}{}",
            if note.is_empty() {
                String::new()
            } else {
                format!("  ({note})")
            }
        );
    }
    eprintln!(
        "{} found, {new} new; nothing was imported (dry run)",
        names.len()
    );
    Ok(0)
}

fn open(client: &Client, name: String) -> anyhow::Result<u8> {
    let Response::Entry { entry } = check(client.call(&Request::Show { name })?)? else {
        bail!("unexpected response");
    };
    let Some(url) = entry.fields.url.clone() else {
        if entry.protected_fields.iter().any(|f| f == "URL") {
            bail!(
                "{}: the URL is a protected field; it is not disclosed",
                entry.name
            );
        }
        bail!(
            "{} has no URL (add one with `rusthorse edit {} --url …`)",
            entry.name,
            entry.name
        );
    };
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    if !matches!(scheme.as_deref(), Some("http" | "https")) {
        bail!("{url}: only http:// and https:// links are opened");
    }
    eprintln!("Opening {url}");
    let status = std::process::Command::new("xdg-open")
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("cannot run xdg-open")?;
    if !status.success() {
        bail!("xdg-open failed ({status})");
    }
    Ok(0)
}

fn generate_cmd(args: GenerateArgs) -> anyhow::Result<u8> {
    let spec = Spec {
        length: args.length,
        alphabet: args.alphabet.into(),
    };
    let value = rusthorse::generate::generate(spec)?;
    println!("{}", value.as_str());
    if std::io::stderr().is_terminal() {
        eprintln!(
            "({} characters, about {:.0} bits)",
            spec.length,
            spec.entropy_bits()
        );
    }
    Ok(0)
}

/// One line of `rusthorse doctor`.
enum Check {
    Ok(String),
    Warn(String),
    Fail(String),
}

/// What shows the agent's dialogs, as the agent itself reports it (it
/// checked the program in its own mount namespace), and whether the program
/// runs: `rusthorse-dialog --check`, under supervision and a 5-second limit,
/// reports its version and protocol without opening a window.
fn dialog_check(info: &rusthorse::protocol::StatusInfo) -> Check {
    use rusthorse::dialog_program::{Located, PROGRAM, check_program, locate_in};
    let program = match info.dialogs.as_deref() {
        Some("zenity") => {
            return Check::Warn(format!(
                "{PROGRAM} is not installed next to the agent: dialogs use zenity \
                 (see docs/installation.md)"
            ));
        }
        Some(reason) if reason.starts_with("none: ") => {
            return Check::Fail(format!(
                "dialogs cannot be shown: {}",
                &reason["none: ".len()..]
            ));
        }
        Some(path) => std::path::PathBuf::from(path),
        // An agent that predates the field: look next to its program file.
        None => {
            let exe = info.agent_executable.trim_end_matches(" (deleted)");
            match std::path::Path::new(exe)
                .parent()
                .filter(|_| !exe.is_empty())
                .map(locate_in)
            {
                Some(Located::Program(path)) => path,
                Some(Located::Absent(path)) => {
                    return Check::Warn(format!(
                        "{} is not installed: dialogs use zenity (see docs/installation.md)",
                        path.display()
                    ));
                }
                Some(Located::Unusable(why)) => {
                    return Check::Fail(format!("dialogs cannot be shown: {why}"));
                }
                None => {
                    return Check::Warn("cannot tell which dialog program the agent uses".into());
                }
            }
        }
    };
    match check_program(&program, Duration::from_secs(5)) {
        Ok((version, protocol)) if protocol == rusthorse::dialog_protocol::VERSION => Check::Ok(
            format!("dialogs: {PROGRAM} {version} ({})", program.display()),
        ),
        Ok((version, protocol)) => Check::Fail(format!(
            "{PROGRAM} {version} speaks dialog protocol {protocol}, this rusthorse {}: \
             install the same version of both, then restart the agent",
            rusthorse::dialog_protocol::VERSION
        )),
        Err(e) => Check::Fail(format!("{} does not run: {e:#}", program.display())),
    }
}

/// Whether the agent still runs the program file it was started from, and
/// whether that is the same file as this `rusthorse` — compared by the device
/// and inode the agent reads through its own `/proc/self/exe`, never by name.
/// Same file is not proof of the same build if a file is rewritten in place,
/// which installers do not do.
fn agent_executable_check(
    agent: &str,
    replaced: Option<bool>,
    agent_id: Option<(u64, u64)>,
) -> Check {
    use rusthorse::util::file_identity;
    const RESTART: &str = "run `systemctl --user restart rusthorse-agent`";
    if agent.is_empty() {
        return Check::Warn("the agent did not say which program file it runs".into());
    }
    if replaced == Some(true) {
        return Check::Fail(format!(
            "the agent runs an old build: its program file ({agent}) was replaced or removed \
             after it started — {RESTART}"
        ));
    }
    let ours = std::path::Path::new("/proc/self/exe");
    match (agent_id, file_identity(ours)) {
        (Some(theirs), Ok(mine)) if theirs == mine => Check::Ok(format!(
            "the agent runs the same program file as this rusthorse ({agent})"
        )),
        (Some(_), Ok(_)) => Check::Warn(format!(
            "the agent runs {agent}, a different program file from this rusthorse ({}); if \
             both should be the same build, {RESTART}",
            std::fs::read_link(ours).map_or_else(|_| "?".into(), |p| p.display().to_string())
        )),
        _ => Check::Warn(format!(
            "cannot compare the agent's program file ({agent}) with this rusthorse's"
        )),
    }
}

fn doctor(client: &Client) -> anyhow::Result<u8> {
    use std::os::unix::fs::PermissionsExt;
    let mut checks = Vec::new();
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777);

    checks.push(Check::Ok(format!(
        "rusthorse {} (protocol {})",
        env!("CARGO_PKG_VERSION"),
        rusthorse::protocol::PROTOCOL_VERSION
    )));

    // The agent, and the files it actually uses.
    let mut vault = paths::vault();
    let mut audit = paths::audit_log();
    let mut where_from = "the default location (the agent is not reachable)";
    let mut dialog_program = false;
    match client.call(&Request::Status) {
        Ok(Response::Status(info)) => {
            vault = PathBuf::from(&info.vault);
            if !info.audit_log.is_empty() {
                audit = PathBuf::from(&info.audit_log);
            }
            where_from = "the agent's configuration";
            if info.protocol_version == rusthorse::protocol::PROTOCOL_VERSION {
                checks.push(Check::Ok(format!(
                    "agent {} is running ({})",
                    info.agent_version,
                    if info.locked { "locked" } else { "unlocked" }
                )));
            } else {
                checks.push(Check::Fail(format!(
                    "the agent speaks protocol {}, this binary {}: run `systemctl --user restart rusthorse-agent`",
                    info.protocol_version,
                    rusthorse::protocol::PROTOCOL_VERSION
                )));
            }
            checks.push(agent_executable_check(
                &info.agent_executable,
                info.agent_executable_replaced,
                info.agent_executable_id,
            ));
            let dialogs = dialog_check(&info);
            dialog_program = matches!(dialogs, Check::Ok(_));
            checks.push(dialogs);
            if !info.vault_exists {
                checks.push(Check::Fail(format!(
                    "no vault at {} — run `rusthorse init`",
                    info.vault
                )));
            }
        }
        Ok(_) => checks.push(Check::Fail(
            "the agent answered something unexpected".into(),
        )),
        Err(e) => checks.push(Check::Fail(format!("{e:#}"))),
    }

    // How the agent is started.
    let systemctl = |args: &[&str]| {
        std::process::Command::new("systemctl")
            .arg("--user")
            .args(args)
            .stderr(std::process::Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    match systemctl(&["is-enabled", "rusthorse-agent"]).as_str() {
        "enabled" => checks.push(Check::Ok("the systemd user service is enabled".into())),
        other => checks.push(Check::Warn(format!(
            "the systemd user service is {} — the agent should be started by systemd (docs/installation.md)",
            if other.is_empty() { "not installed" } else { other }
        ))),
    }

    // Dialogs.
    if ["/usr/bin/zenity", "/usr/local/bin/zenity"]
        .iter()
        .any(|p| std::path::Path::new(p).is_file())
    {
        checks.push(Check::Ok("zenity is installed".into()));
    } else if dialog_program {
        checks.push(Check::Warn(
            "zenity, the fallback when rusthorse-dialog is missing, is not installed".into(),
        ));
    } else {
        checks.push(Check::Fail(
            "zenity is not installed — `sudo apt install zenity`".into(),
        ));
    }
    match std::env::var("XDG_SESSION_TYPE").as_deref() {
        Ok("wayland") => checks.push(Check::Ok(
            "Wayland session: other programs cannot synthesize input into dialogs (accessibility tools still can: threat model L2)".into(),
        )),
        Ok("x11") => checks.push(Check::Warn(
            "X11 session: any program of your user can click \"Allow\" or read keystrokes (threat model L2)".into(),
        )),
        other => checks.push(Check::Warn(format!("unknown session type {other:?}"))),
    }

    // Kernel protections.
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").map(|s| s.trim().to_string()) {
        Ok(v) if v != "0" => checks.push(Check::Ok(format!("Yama ptrace_scope = {v}"))),
        Ok(_) => checks.push(Check::Fail(
            "Yama ptrace_scope = 0: any process of your user can debug any other (set kernel.yama.ptrace_scope=1)".into(),
        )),
        Err(_) => checks.push(Check::Warn("Yama is not available: process isolation is weaker".into())),
    }

    // Files.
    checks.push(Check::Ok(format!("checking the files of {where_from}")));
    if vault.exists() {
        match mode(&vault) {
            Ok(m) if m & 0o077 == 0 => {
                checks.push(Check::Ok(format!("{} is private ({m:o})", vault.display())))
            }
            Ok(m) => checks.push(Check::Fail(format!(
                "{} is readable by others ({m:o}) — chmod 600",
                vault.display()
            ))),
            Err(e) => checks.push(Check::Fail(format!("{}: {e}", vault.display()))),
        }
        match std::fs::File::open(&vault).map_err(anyhow::Error::from).and_then(|mut f| {
            keepass::Database::get_version(&mut f).map_err(anyhow::Error::from)
        }) {
            Ok(keepass::config::DatabaseVersion::KDB4(minor)) => {
                checks.push(Check::Ok(format!("the vault is KDBX 4.{minor}")))
            }
            Ok(other) => checks.push(Check::Warn(format!(
                "the vault is {other:?}: Rusthorse can read it but not save it (convert it to KDBX 4 in KeePassXC)"
            ))),
            Err(e) => checks.push(Check::Fail(format!("the vault cannot be read: {e:#}"))),
        }
    }
    if let Ok(m) = mode(&audit)
        && m & 0o077 != 0
    {
        checks.push(Check::Warn(format!(
            "{} is readable by others ({m:o})",
            audit.display()
        )));
    }
    if let Some(dir) = client.socket().parent()
        && let Ok(m) = mode(dir)
    {
        if m & 0o077 == 0 {
            checks.push(Check::Ok(format!("{} is private ({m:o})", dir.display())));
        } else {
            checks.push(Check::Fail(format!(
                "{} is accessible to others ({m:o})",
                dir.display()
            )));
        }
    }

    let mut failed = false;
    for check in &checks {
        match check {
            Check::Ok(text) => println!("  ok    {text}"),
            Check::Warn(text) => println!("  warn  {text}"),
            Check::Fail(text) => {
                failed = true;
                println!("  FAIL  {text}");
            }
        }
    }
    Ok(if failed { 1 } else { 0 })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_notices_an_agent_running_a_replaced_binary() {
        use rusthorse::util::file_identity;
        let ours = std::path::Path::new("/proc/self/exe");
        let mine = file_identity(ours).ok();
        let name = std::fs::read_link(ours).expect("exe").display().to_string();
        assert!(matches!(
            agent_executable_check(&format!("{name} (deleted)"), Some(true), mine),
            Check::Fail(m) if m.contains("restart")
        ));
        assert!(matches!(
            agent_executable_check(&name, Some(false), mine),
            Check::Ok(_)
        ));
        // Same name, another file (another mount namespace, say): the
        // agent's own identity decides, not the name.
        let dir = tempfile::tempdir().expect("tempdir");
        let other = dir.path().join("other");
        std::fs::write(&other, b"x").expect("write");
        assert!(matches!(
            agent_executable_check(&name, Some(false), file_identity(&other).ok()),
            Check::Warn(m) if m.contains("different program file")
        ));
        // Cannot tell whether replaced, but it is the very file we run.
        assert!(matches!(
            agent_executable_check(&name, None, mine),
            Check::Ok(_)
        ));
        assert!(matches!(
            agent_executable_check(&name, None, None),
            Check::Warn(m) if m.contains("cannot compare")
        ));
        assert!(matches!(
            agent_executable_check("", None, None),
            Check::Warn(_)
        ));
    }
}
