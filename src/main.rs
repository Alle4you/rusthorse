//! The `rusthorse` command-line interface. See `docs/cli.md`.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use rusthorse::agent::{self, Agent, AgentConfig};
use rusthorse::broker_grant::{AutomaticLocks, Destination, GrantLimits};
use rusthorse::client::Client;
use rusthorse::dialog_program::DesktopUi;
use rusthorse::generate::{Alphabet, Spec};
use rusthorse::protocol::{
    Binding, BrokerBinding, BrokerRunRequest, EntryChanges, EntryFields, EntryInfo, EntryKind,
    ErrorCode, Field, GrantInfo, ImportSource, NewEntry, Request, Response, RunRequest,
    SecretString, StatusInfo, UnauthorizedGrant, ValueChange,
};
use rusthorse::ui::{Connection, Prompt, Typed, Ui};
use rusthorse::util::{format_duration, is_valid_env_name, parse_duration};
use rusthorse::vault::{KdfParams, Vault};
use rusthorse::{audit, paths, settings};

/// `eprintln!` that never panics. The standard one panics when standard
/// error cannot be written (`2>/dev/full`), which would turn an exit status
/// that means something — `125`: the command did not run — into a crash
/// (`101`). A message that cannot be written is dropped instead.
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

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
Documentation: https://github.com/Alle4you/rusthorse/tree/main/docs",
    after_help = "AI agents: read `rusthorse guide ai` before using Rusthorse."
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
    /// Create a new, empty vault. When the agent runs for that vault, it
    /// asks for the master password in its own dialogs.
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
    /// List the grants of the credential broker (never a token), or end
    /// them with `grants revoke`. Needs no approval.
    #[command(args_conflicts_with_subcommands = true)]
    Grants(GrantsArgs),
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
    /// Print a guide (`ai`: the guide for AI agents). Needs no agent.
    Guide {
        /// The guide.
        #[arg(value_enum)]
        topic: GuideTopic,
    },
}

/// The guides of `rusthorse guide`.
#[derive(Clone, Copy, ValueEnum)]
enum GuideTopic {
    /// How an AI agent uses Rusthorse: rules, commands, exit statuses.
    Ai,
}

/// The guide for AI agents, written for the `rusthorse` it is built into.
const AI_GUIDE: &str = include_str!("guide/ai.md");

impl GuideTopic {
    fn text(self) -> String {
        match self {
            GuideTopic::Ai => AI_GUIDE.replace("@VERSION@", env!("CARGO_PKG_VERSION")),
        }
    }
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
    /// Settings file (default `$XDG_CONFIG_HOME/rusthorse/agent.toml`). The
    /// flags below win over it; the manager's Settings page changes it.
    #[arg(long, env = paths::ENV_AGENT_CONFIG, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Lock after this much inactivity: `0` (never), or 1s to 24h. Default
    /// 15m, or the settings file's.
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    idle_timeout: Option<Duration>,
    /// Offer "Allow for DURATION" in run dialogs, approving identical requests
    /// for that long without asking: `0` (off), or 1s to 8h. Off by default;
    /// see docs/cli.md.
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    remember: Option<Duration>,
    /// How long dialogs wait for an answer before denying: 15s to 5m.
    /// Default 2m, or the settings file's.
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    dialog_timeout: Option<Duration>,
    /// Do not lock when the computer is about to sleep (logind).
    #[arg(long)]
    no_lock_on_suspend: bool,
    /// Do not lock when the session is locked or its screensaver starts.
    #[arg(long)]
    no_lock_on_screen_lock: bool,
}

impl AgentArgs {
    /// The settings that explicit flags set, each within its bounds.
    fn settings(&self) -> anyhow::Result<settings::Layer> {
        use settings::{Key, Value};
        let mut flags = settings::Layer::default();
        for (key, value) in [
            (Key::IdleTimeout, self.idle_timeout.map(Value::Duration)),
            (Key::Remember, self.remember.map(Value::Duration)),
            (Key::DialogTimeout, self.dialog_timeout.map(Value::Duration)),
            (
                Key::LockOnSuspend,
                self.no_lock_on_suspend.then_some(Value::Switch(false)),
            ),
            (
                Key::LockOnScreenLock,
                self.no_lock_on_screen_lock.then_some(Value::Switch(false)),
            ),
        ] {
            if let Some(value) = value {
                flags
                    .set(key, value)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", key.flag()))?;
            }
        }
        Ok(flags)
    }
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
    /// A private key for SSH, as the entry's value (--stdin stores one).
    SshKey,
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
            KindArg::SshKey => Some(EntryKind::SshKey),
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ClearField {
    Username,
    Url,
    Host,
    Port,
    Notes,
    Kind,
}

impl ClearField {
    fn field(self) -> Field {
        match self {
            ClearField::Username => Field::Username,
            ClearField::Url => Field::Url,
            ClearField::Host => Field::Host,
            ClearField::Port => Field::Port,
            ClearField::Notes => Field::Notes,
            ClearField::Kind => Field::Kind,
        }
    }
}

/// Whether the automatic locks end a grant, as `--broker-locks` names it
/// ([`AutomaticLocks::ALL`]).
#[derive(Clone, Copy)]
struct LocksArg(AutomaticLocks);

impl ValueEnum for LocksArg {
    fn value_variants<'a>() -> &'a [Self] {
        const ALL: [LocksArg; AutomaticLocks::ALL.len()] = {
            let mut all = [LocksArg(AutomaticLocks::ALL[0]); AutomaticLocks::ALL.len()];
            let mut i = 0;
            while i < all.len() {
                all[i] = LocksArg(AutomaticLocks::ALL[i]);
                i += 1;
            }
            all
        };
        &ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(
            clap::builder::PossibleValue::new(self.0.as_str()).help(match self.0 {
                AutomaticLocks::End => {
                    "The screen locking, a suspend and the idle timeout end the grants"
                }
                AutomaticLocks::Continue => {
                    "They do not: the grants go on while the screen is locked, although the \
                     vault locks"
                }
            }),
        )
    }
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
    /// Move the entry to this group, e.g. Work/Servers, creating it if
    /// needed; `/` moves it to the top level.
    #[arg(long, value_name = "PATH")]
    group: Option<String>,
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
    /// Use an entry through the credential broker (repeatable): VAR gets a
    /// temporary token, never the entry's value, and the broker puts the
    /// value in its place in requests to URL's origin, which you approve
    /// (any path there). URL is https://HOST[:PORT][/BASE]; the base path
    /// only goes into the --url variable. VAR ends at the first '=', URL
    /// starts after the last '@'; ENTRY@URL alone names the variable like
    /// the entry. The grant ends with the command.
    #[arg(long = "broker", value_name = "VAR=ENTRY@URL")]
    brokers: Vec<String>,
    /// The most requests each grant of this run admits (1–1000000); no
    /// limit unless given.
    #[arg(long = "broker-requests", requires = "brokers", value_name = "N")]
    broker_requests: Option<u64>,
    /// The longest each grant of this run lasts, in minutes (1–1440); 720
    /// (12 hours) unless given.
    #[arg(long = "broker-lifetime", requires = "brokers", value_name = "MINUTES")]
    broker_lifetime: Option<u32>,
    /// Whether the screen locking, a suspend and the idle timeout end this
    /// run's grants (`rusthorse lock` always does); continue unless given.
    #[arg(
        long = "broker-locks",
        requires = "brokers",
        value_enum,
        value_name = "POLICY"
    )]
    broker_locks: Option<LocksArg>,
    /// Also put an entry's URL (an API's endpoint) in variable VAR; for an
    /// entry given with --broker, the broker's address instead. Not a secret:
    /// it is not redacted.
    #[arg(long = "url", value_name = "VAR=ENTRY")]
    urls: Vec<String>,
    /// Secrets to expose: ENTRY (variable named like the entry) or VAR=ENTRY.
    /// At least one, unless --broker is given.
    #[arg(required_unless_present = "brokers", value_name = "SECRET")]
    secrets: Vec<String>,
    /// The command, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct GrantsArgs {
    /// Print JSON.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Option<GrantsCommand>,
}

#[derive(Subcommand)]
enum GrantsCommand {
    /// End a grant now, or every grant: its requests are refused, open ones
    /// closed. Needs no approval, like `lock`.
    Revoke(RevokeArgs),
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct RevokeArgs {
    /// The grant's ID, as `rusthorse grants` shows it.
    #[arg(value_name = "ID")]
    id: Option<String>,
    /// End every grant.
    #[arg(long)]
    all: bool,
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
            let is_outcome_unknown = e
                .downcast_ref::<rusthorse::client::OutcomeUnknown>()
                .is_some();
            let is_local_unknown = e.downcast_ref::<LocalOutcomeUnknown>().is_some();
            // An error can quote a name from the vault, the keyring or the
            // agent: shown escaped, like everything they supply.
            let e = printable(&format!("{e:#}"));
            if is_outcome_unknown {
                eprintln!("rusthorse: {e}; it may or may not have taken effect");
                ExitCode::from(EXIT_UNKNOWN)
            } else if is_local_unknown {
                eprintln!("rusthorse: {e}");
                ExitCode::from(EXIT_UNKNOWN)
            } else {
                eprintln!("rusthorse: {e}");
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
            | Command::Guide { .. }
            // `run` checks inside its own error handling, so that a missing
            // or incompatible agent is reported as "did not run" (125).
            | Command::Run(_)
            // These check after their arguments, so that a mistake in them
            // sends nothing at all.
            | Command::Edit(_)
            | Command::Grants(_)
    );
    if talks_to_agent {
        client.check_compatible()?;
    }
    match command {
        Command::Init { vault } => init(client, vault.unwrap_or_else(paths::vault)),
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
        Command::Guide { topic } => guide(topic),
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
        Command::Grants(args) => grants(client, args),
        Command::Import(cmd) => import_cmd(client, cmd),
        Command::Audit { lines, json } => show_audit(lines, json),
    }
}

/// Print a guide. A reader that stops early (`rusthorse guide ai | head`)
/// is not an error.
fn guide(topic: GuideTopic) -> anyhow::Result<u8> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out
        .write_all(topic.text().as_bytes())
        .and_then(|()| out.flush())
    {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            Err(anyhow::Error::new(e).context("cannot print the guide"))
        }
        _ => Ok(0),
    }
}

/// Text that the agent, the vault or a keyring supplies — a message, an
/// error, a name, a field, a path — as the CLI shows it to people: with
/// control and invisible characters escaped ([`rusthorse::util::visible`]).
/// A title or a label that another program wrote can hold terminal
/// controls (threat model L9). `--json` output and what `reveal` prints
/// are data, not shown this way.
fn printable(text: &str) -> String {
    rusthorse::util::visible(text)
}

/// Turn an error response into an error (with the right exit status).
fn check(response: Response) -> anyhow::Result<Response> {
    match response {
        Response::Error { code, message } => {
            eprintln!("rusthorse: {}", printable(&message));
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
            eprintln!("{}", printable(&message));
            Ok(0)
        }
        // An answer that makes no sense says nothing about what happened.
        other if request.has_effects() => Err(anyhow::Error::new(
            rusthorse::client::OutcomeUnknown(format!("unexpected {} response", other.kind())),
        )),
        other => bail!("unexpected {} response from the agent", other.kind()),
    }
}

fn init(client: &Client, vault: PathBuf) -> anyhow::Result<u8> {
    if vault.exists() {
        bail!("a vault already exists at {}", vault.display());
    }
    // An agent that serves this vault creates it, asking for the master
    // password in its own dialogs: the password then never enters this
    // process, which an AI agent may have started and could inspect. Only
    // when no agent runs, or one serves another file, does this process ask.
    let answer = client.call(&Request::Status);
    let serves = match &answer {
        Ok(Response::Status(info)) => match same_vault(Path::new(&info.vault), &vault) {
            Some(same) => same,
            None => bail!(
                "cannot tell whether the agent's vault ({}) is {}, so the vault is not created \
                 here (this command would read the master password itself)",
                info.vault,
                vault.display()
            ),
        },
        _ => false,
    };
    match answer {
        Ok(Response::Status(_)) if serves => {
            client.check_compatible()?;
            eprintln!("The agent asks for the new master password in a dialog.");
            let status = simple(client, &Request::CreateVault)?;
            eprintln!("Next: `rusthorse add NAME`, or open Rusthorse from the applications menu.");
            return Ok(status);
        }
        // An agent that serves another vault cannot create this one.
        Ok(Response::Status(_)) => {}
        Err(e) if agent_not_running(&e) => {}
        Ok(other) => bail!(
            "the agent answered {} to a status request; is it a Rusthorse agent?",
            other.kind()
        ),
        Err(e) => {
            return Err(e.context(
                "cannot ask the agent whether it serves this vault, so the vault is not created \
                 here (this command would read the master password itself)",
            ));
        }
    }
    let password = new_master_password()?;
    Vault::create(&vault, password, KdfParams::DEFAULT).map_err(created_locally)?;
    println!("Created {}", vault.display());
    println!(
        "Next: start the agent (`systemctl --user enable --now rusthorse-agent`), then `rusthorse add NAME`."
    );
    Ok(0)
}

/// Whether `a` and `b` name the same vault file. Each is resolved as the
/// system would follow it — links, including links to what does not exist
/// yet, `.` and `..` — and then compared by the identity (device and inode)
/// of its deepest existing directory and the names below it, so that bind
/// mounts and other spellings of one directory compare equal. `None` when
/// that cannot be told (a directory that cannot be examined, a loop of
/// links): the caller must not take it for "different".
fn same_vault(a: &Path, b: &Path) -> Option<bool> {
    Some(identity(a)? == identity(b)?)
}

/// The deepest existing directory of `path`, resolved, as (device, inode),
/// and the rest of the path below it.
fn identity(path: &Path) -> Option<(u64, u64, PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    let mut dir = resolved(path)?;
    let mut below = Vec::new();
    loop {
        match std::fs::metadata(&dir) {
            Ok(meta) => {
                let rest: PathBuf = below.iter().rev().collect();
                return Some((meta.dev(), meta.ino(), rest));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                below.push(dir.file_name()?.to_owned());
                dir = dir.parent()?.to_path_buf();
            }
            Err(_) => return None,
        }
    }
}

/// `path` made absolute, with every link followed — also one that points to
/// something that does not exist yet — and `.` and `..` applied; below the
/// first component that does not exist, the rest is taken as written (a
/// later `..` that climbs back above it resolves links again).
fn resolved(path: &Path) -> Option<PathBuf> {
    use std::collections::VecDeque;
    use std::path::Component;
    let parts = |path: &Path| -> VecDeque<Option<std::ffi::OsString>> {
        path.components()
            .filter_map(|c| match c {
                Component::Normal(name) => Some(Some(name.to_owned())),
                Component::ParentDir => Some(None),
                _ => None,
            })
            .collect()
    };
    let absolute = std::path::absolute(path).ok()?;
    let mut todo = parts(&absolute);
    let mut out = PathBuf::from("/");
    // How many of the last components of `out` do not exist.
    let mut missing = 0usize;
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        let Some(name) = part else {
            out.pop();
            missing = missing.saturating_sub(1);
            continue;
        };
        let next = out.join(&name);
        if missing > 0 {
            out = next;
            missing += 1;
            continue;
        }
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                if target.is_absolute() {
                    out = PathBuf::from("/");
                }
                for part in parts(&target).into_iter().rev() {
                    todo.push_front(part);
                }
            }
            Ok(_) => out = next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                out = next;
                missing = 1;
            }
            Err(_) => return None,
        }
    }
    Some(out)
}

/// Whether `e` says that nothing listens on the agent's socket.
fn agent_not_running(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
        })
}

/// A change this process made itself (no agent involved) whose outcome is
/// unknown: exit 124, as for a request to the agent.
#[derive(Debug)]
struct LocalOutcomeUnknown(String);

impl std::fmt::Display for LocalOutcomeUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LocalOutcomeUnknown {}

/// The error of a vault this process created: one that is in place but may
/// not survive a crash is an unknown outcome (exit 124).
fn created_locally(e: rusthorse::vault::VaultError) -> anyhow::Error {
    match e {
        rusthorse::vault::VaultError::NotDurable(_) => anyhow::Error::new(LocalOutcomeUnknown(
            format!("{e}; the vault file is in place, but may not survive a crash"),
        )),
        other => other.into(),
    }
}

fn new_master_password() -> anyhow::Result<SecretString> {
    let (first, second) = if std::io::stdin().is_terminal() {
        (
            SecretString::new(rpassword::prompt_password("New master password: ")?),
            SecretString::new(rpassword::prompt_password("Repeat it: ")?),
        )
    } else {
        let ui = DesktopUi::new(Duration::ZERO, Duration::from_secs(300));
        let ask =
            |headline: &str, explanation: &str, field: &str| -> anyhow::Result<SecretString> {
                // Asked by this process itself: no requester to watch.
                let prompt = Prompt {
                    title: "Rusthorse — new vault".into(),
                    headline: headline.into(),
                    explanation: explanation.into(),
                    notice: None,
                    details: Vec::new(),
                    field: field.into(),
                    confirm: "OK".into(),
                };
                match ui.master_password(&prompt, Connection::none())? {
                    Typed::Value(value) => Ok(value),
                    // A dialog cancelled or not answered: exit 4, as with the
                    // agent's dialogs. (Nothing watched cannot go away.)
                    Typed::Cancelled | Typed::RequesterGone => {
                        eprintln!("rusthorse: cancelled; no vault was created");
                        Err(Exit(EXIT_DENIED).into())
                    }
                    Typed::TimedOut => {
                        eprintln!(
                            "rusthorse: nobody answered the dialog in time; no vault was created"
                        );
                        Err(Exit(EXIT_DENIED).into())
                    }
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
    // The settings (ADR 0007, section 3): the defaults, then the file, then
    // explicit flags. A file or a flag the agent cannot accept stops it:
    // the defaults may protect less than what the human set.
    let flags = args.settings()?;
    let path = args.config.clone().unwrap_or_else(paths::agent_config);
    let path = std::path::absolute(&path)
        .with_context(|| format!("cannot resolve the settings path {}", path.display()))?;
    let file = settings::load(&path).map_err(anyhow::Error::msg)?;
    let sources = settings::Sources { path, file, flags };
    let effective = sources.effective();
    // Absolute, so that `status` names the file wherever a client runs.
    let vault = args.vault.unwrap_or_else(paths::vault);
    let vault = std::path::absolute(&vault)
        .with_context(|| format!("cannot resolve the vault path {}", vault.display()))?;
    let config = AgentConfig {
        vault,
        socket,
        audit_log: args.audit_log.unwrap_or_else(paths::audit_log),
        idle_timeout: effective.idle_timeout,
        request_timeout: Duration::from_secs(10),
        send_buffer: None,
        session_lock: rusthorse::session_lock::Settings {
            on_suspend: effective.lock_on_suspend,
            on_screen_lock: effective.lock_on_screen_lock,
            system_bus: None,
            session_bus: None,
            refresh_every: None,
        },
        new_vault_kdf: KdfParams::DEFAULT,
        keyring: Default::default(),
        // `rusthorse-broker` next to this program, with no fallback.
        broker_program: None,
        broker_ready_timeout: None,
        // Each grant lasts as long as its run says (`--broker-lifetime`).
        broker_lifetime: None,
        settings: Some(sources),
        audit_fifo_waits: false,
    };
    let ui = DesktopUi::new(effective.remember, effective.dialog_timeout);
    let listener = Agent::bind(&config.socket)?;
    eprintln!(
        "rusthorse agent {} listening on {} (vault {}, settings {}, auto-lock {}, \
         lock on suspend {}, lock on screen lock {})",
        env!("CARGO_PKG_VERSION"),
        config.socket.display(),
        config.vault.display(),
        config
            .settings
            .as_ref()
            .map(|s| s.path.display().to_string())
            .unwrap_or_default(),
        if config.idle_timeout.is_zero() {
            "off".into()
        } else {
            format_duration(config.idle_timeout)
        },
        if config.session_lock.on_suspend {
            "on"
        } else {
            "off"
        },
        if config.session_lock.on_screen_lock {
            "on"
        } else {
            "off"
        },
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
        printable(&info.agent_version),
        info.protocol_version
    );
    println!(
        "vault:      {}{}",
        printable(&info.vault),
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
    if let Some(s) = &info.settings {
        println!("settings:   {}", printable(&s.file));
        for line in settings_lines(s) {
            println!("            {line}");
        }
    }
    if let Some(dialogs) = &info.dialogs {
        println!("dialogs:    {}", printable(dialogs));
    }
    // The credential broker (ADR 0013), from agents that report it. The
    // count is the agent's: the grants that are starting, active or
    // exhausted, without the revoked ones whose commands still run. It is
    // not called "active" here, and `rusthorse grants`, which lists the
    // revoked ones too, says what each one is.
    if let Some(broker) = &info.broker {
        println!("broker:     {}", printable(broker));
    }
    match info.grants {
        Some(0) => println!("grants:     none"),
        Some(grants) => println!("grants:     {grants} (`rusthorse grants` shows their state)"),
        None => {}
    }
    for (i, line) in rusthorse::session_lock::summary(&info.lock_triggers)
        .iter()
        .enumerate()
    {
        println!(
            "{:<11} {}",
            if i == 0 { "locks on:" } else { "" },
            printable(line)
        );
    }
    if !info.agent_executable.is_empty() {
        println!(
            "program:    {}{}",
            printable(&info.agent_executable),
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
            // From the vault, which another KeePass program may have
            // written: escaped, before the widths are measured.
            [
                printable(&name),
                printable(e.fields.username.as_deref().unwrap_or_default()),
                printable(&endpoint(e)),
                printable(&e.fields.tags.join(",")),
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
            println!("{label:<11} {}", printable(&v));
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
    client.check_compatible()?;
    let value = if args.stdin {
        Some(ValueChange::Provided(read_stdin_value()?))
    } else if let Some(spec) = args.generate.spec() {
        Some(ValueChange::Generate(spec))
    } else if args.value {
        Some(ValueChange::Prompt)
    } else {
        None
    };
    let mut clear: Vec<Field> = args.clear.into_iter().map(ClearField::field).collect();
    if args.fields.kind == Some(KindArg::Other) && !clear.contains(&Field::Kind) {
        clear.push(Field::Kind);
    }
    let changes = EntryChanges {
        rename: args.rename,
        kind: args.fields.kind.and_then(KindArg::kind),
        group: args.group,
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

/// Whether `var` changes how programs start (`LD_*`, `NODE_OPTIONS`, …): a
/// variable `run` refuses to fill with a URL or a token.
fn starts_programs(var: &str) -> bool {
    var.starts_with(rusthorse::exec::LOADER_PREFIX) || rusthorse::exec::is_risky(var)
}

/// Whether the agent sets `var` itself in a run with broker bindings: it
/// adds `127.0.0.1` to `NO_PROXY` and `no_proxy` (ADR 0013), so a token or
/// the broker's address there would be mixed with it. Programs differ in
/// how they read the name's case: every spelling is refused.
fn set_by_the_agent(var: &str) -> bool {
    var.eq_ignore_ascii_case("NO_PROXY")
}

/// What `run` is asked for, as its arguments say it, checked before anything
/// is sent to the agent.
#[derive(Debug, PartialEq, Eq)]
struct RunPlan {
    /// The secrets the command gets by value.
    bindings: Vec<Binding>,
    /// The entries the command uses through the credential broker (ADR
    /// 0013), each with the variable of its token and, from a `--url` for
    /// the same entry, the variable of the broker's address.
    brokered: Vec<BrokerBinding>,
    /// The other `--url VAR=ENTRY`: VAR gets the entry's own URL.
    urls: Vec<Binding>,
}

/// Check the arguments of `run` and sort them out, before anything is sent:
/// valid and distinct variables (a token or a URL never goes in one that
/// changes how programs start, and a token or the broker's address never in
/// `NO_PROXY`, which the agent sets), each brokered entry given once and not
/// also by value (by its name here; the agent compares UUIDs), and at most
/// one `--url` for a brokered entry, which then names the variable of the
/// broker's address.
fn plan_run(secrets: &[String], brokers: &[String], urls: &[String]) -> anyhow::Result<RunPlan> {
    let mut bindings: Vec<Binding> = Vec::new();
    for spec in secrets {
        let binding = parse_binding(spec)?;
        if bindings.iter().any(|b| b.var == binding.var) {
            bail!("{spec}: the variable is already set by another binding");
        }
        bindings.push(binding);
    }
    let mut brokered: Vec<BrokerBinding> = Vec::new();
    for spec in brokers {
        // The URL starts after the last `@`, so that an entry's name may
        // hold one; the variable ends at the first `=`.
        let Some((binding, url)) = spec.rsplit_once('@') else {
            bail!(
                "--broker {spec:?}: name the destination, VAR=ENTRY@https://HOST[:PORT][/BASE], \
                 e.g. --broker OPENAI_API_KEY=OPENAI_API_KEY@https://api.openai.com/v1"
            );
        };
        let Binding { var, entry } =
            parse_binding(binding).map_err(|e| anyhow::anyhow!("--broker: {e}"))?;
        Destination::parse(url).map_err(|e| {
            anyhow::anyhow!(
                "--broker {var}: {e}; write VAR=ENTRY@https://HOST[:PORT][/BASE], with no user, \
                 query or fragment"
            )
        })?;
        if starts_programs(&var) {
            bail!(
                "--broker {var}: this variable changes how programs start; it cannot carry a token"
            );
        }
        if set_by_the_agent(&var) {
            bail!(
                "--broker {var}: the agent adds 127.0.0.1 to this variable; it cannot carry a token"
            );
        }
        if bindings.iter().any(|b| b.var == var) || brokered.iter().any(|b| b.var == var) {
            bail!("--broker {var}: the variable is already set by another binding");
        }
        if brokered.iter().any(|b| b.entry == entry) {
            bail!("--broker {var}: {entry} is already given to --broker; an entry has one grant");
        }
        if bindings.iter().any(|b| b.entry == entry) {
            bail!(
                "--broker {var}: {entry} is also given by value; the command gets an entry's value \
                 or a grant for it, never both"
            );
        }
        brokered.push(BrokerBinding {
            var,
            entry,
            destination: url.to_string(),
            url_var: None,
        });
    }
    let mut plain: Vec<Binding> = Vec::new();
    for spec in urls {
        if !spec.contains('=') {
            bail!("--url {spec:?}: write VAR=ENTRY, e.g. --url OPENAI_BASE_URL=OPENAI_API_KEY");
        }
        let Binding { var, entry } = parse_binding(spec)?;
        if starts_programs(&var) {
            bail!("--url {var}: this variable changes how programs start; it cannot carry a URL");
        }
        let taken = bindings.iter().chain(&plain).any(|b| b.var == var)
            || brokered
                .iter()
                .any(|b| b.var == var || b.url_var.as_deref() == Some(var.as_str()));
        if taken {
            bail!("--url {var}: the variable is already set by another binding");
        }
        match brokered.iter_mut().find(|b| b.entry == entry) {
            Some(binding) => {
                if set_by_the_agent(&var) {
                    bail!(
                        "--url {var}: the agent adds 127.0.0.1 to this variable; it cannot carry \
                         the broker's address"
                    );
                }
                if let Some(other) = &binding.url_var {
                    bail!(
                        "--url {var}: {entry} already has --url {other}; the broker's address \
                         goes in one variable"
                    );
                }
                binding.url_var = Some(var);
            }
            None => plain.push(Binding { var, entry }),
        }
    }
    Ok(RunPlan {
        bindings,
        brokered,
        urls: plain,
    })
}

/// The names that lead to the entry `info` describes: its UUID, and its
/// title and path unless the title is protected (such an entry is found by
/// UUID only).
fn entry_names(info: &EntryInfo) -> Vec<String> {
    let mut names = vec![info.id.clone()];
    if !info.protected_fields.iter().any(|f| f == "Title") {
        if let Some(group) = &info.group {
            names.push(format!("{group}/{}", info.name));
        }
        names.push(info.name.clone());
    }
    names
}

/// The variables that `run --url VAR=ENTRY` adds for entries not given with
/// `--broker`: each entry's URL, read from its metadata. A URL is not a
/// secret — `rusthorse show` prints it without approval — so it travels in
/// the client's environment like any variable set in the shell: not
/// redacted, and listed in the dialog only as such a variable would be (see
/// `exec::destination`). A brokered entry under another name is refused: its
/// own URL would send the token past the broker.
fn endpoint_urls(client: &Client, plan: &RunPlan) -> anyhow::Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for Binding { var, entry } in &plan.urls {
        let Response::Entry { entry: info } = check(client.call(&Request::Show {
            name: entry.clone(),
        })?)?
        else {
            bail!("unexpected response");
        };
        let names = entry_names(&info);
        if let Some(brokered) = plan.brokered.iter().find(|b| names.contains(&b.entry)) {
            bail!(
                "--url {var}: {entry} is the entry of --broker {}={}; name it the same way in both, \
                 and {var} gets the broker's address",
                brokered.var,
                brokered.entry
            );
        }
        let Some(url) = info.fields.url else {
            if info.protected_fields.iter().any(|f| f == "URL") {
                bail!("--url {var}: the URL of {entry} is a protected field; it is not disclosed");
            }
            bail!(
                "--url {var}: {entry} has no URL (add one with `rusthorse edit {entry} --url …`)"
            );
        };
        out.push((var.clone(), url));
    }
    Ok(out)
}

/// The limits of a run's grants, from its options and the defaults (no
/// request limit, 12 hours, `continue`), checked as the agent will check
/// them.
fn run_limits(args: &RunArgs) -> anyhow::Result<GrantLimits> {
    let defaults = GrantLimits::default();
    let limits = GrantLimits {
        automatic_locks: args
            .broker_locks
            .map_or(defaults.automatic_locks, |LocksArg(locks)| locks),
        max_lifetime_minutes: args
            .broker_lifetime
            .unwrap_or(defaults.max_lifetime_minutes),
        max_requests: args.broker_requests.or(defaults.max_requests),
    };
    limits.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(limits)
}

fn run(client: &Client, args: RunArgs) -> anyhow::Result<u8> {
    let outcome = (|| -> anyhow::Result<u8> {
        // Every argument is checked before anything is sent: a mistake asks
        // nothing and runs nothing.
        let plan = plan_run(&args.secrets, &args.brokers, &args.urls)?;
        let limits = run_limits(&args)?;
        client.check_compatible()?;
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
        // The token and the broker's address are the agent's to set: what
        // this environment had in those variables is not sent (the agent
        // drops it too).
        env.retain(|(k, _)| {
            !plan
                .brokered
                .iter()
                .any(|b| b.var == *k || b.url_var.as_deref() == Some(k.as_str()))
        });
        for (var, url) in endpoint_urls(client, &plan)? {
            env.retain(|(k, _)| *k != var);
            env.push((var, url));
        }
        let RunPlan {
            bindings, brokered, ..
        } = plan;
        // Each grant's variable and entry, as this command line gave them:
        // what a note after the command names (the agent reports the entry
        // as dialogs identify it, which `edit` does not take).
        let typed: Vec<(String, String)> = brokered
            .iter()
            .map(|b| (b.var.clone(), b.entry.clone()))
            .collect();
        let request = RunRequest {
            bindings,
            argv: args.command,
            cwd,
            env,
            redact: !args.no_redact,
            forward_stdin: args.stdin,
        };
        // With broker bindings, a request of its own (protocol 9): an older
        // agent refuses it whole instead of running the command without its
        // destinations and limits. There is no fallback to the values, and
        // a refused request is never sent again as another type.
        let response = if brokered.is_empty() {
            client.run(request)?
        } else {
            client.broker_run(BrokerRunRequest {
                run: request,
                brokered,
                limits,
            })?
        };
        match response {
            Response::Exited {
                code,
                signal,
                unauthorized,
            } => {
                let status = match (code, signal) {
                    (Some(code), _) => code.clamp(0, 255) as u8,
                    (None, Some(sig)) => (128 + sig).clamp(0, 255) as u8,
                    (None, None) => {
                        return Err(anyhow::Error::new(rusthorse::client::OutcomeUnknown(
                            "an exit status with neither a code nor a signal".into(),
                        )));
                    }
                };
                // After everything the command wrote, and with its status.
                for grant in &unauthorized {
                    let name = typed
                        .iter()
                        .find(|(var, _)| *var == grant.var)
                        .map(|(_, entry)| entry.as_str());
                    eprintln!("{}", unauthorized_note(grant, name));
                }
                Ok(status)
            }
            Response::Error {
                code: ErrorCode::OutcomeUnknown,
                message,
            } => {
                eprintln!("rusthorse: {}", printable(&message));
                Ok(EXIT_UNKNOWN)
            }
            Response::Error { message, .. } => {
                eprintln!("rusthorse: {}", printable(&message));
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
                eprintln!(
                    "rusthorse: {}; the command may or may not have run",
                    printable(&format!("{e:#}"))
                );
                Ok(EXIT_UNKNOWN)
            } else if e.downcast_ref::<Exit>().is_some() {
                // The agent refused a request made before the run (`show`
                // for `--url`), whose message `check` printed: the run was
                // never sent.
                Ok(EXIT_RUN_FAILURE)
            } else {
                eprintln!("rusthorse: {}", printable(&format!("{e:#}")));
                Ok(EXIT_RUN_FAILURE)
            }
        }
    }
}

/// `rusthorse grants` and `grants revoke` (ADR 0013). Neither needs an
/// approval: listing shows no secret, and revoking only takes away.
fn grants(client: &Client, args: GrantsArgs) -> anyhow::Result<u8> {
    if let Some(GrantsCommand::Revoke(revoke)) = args.command {
        // Checked before anything is sent. (clap lets exactly one through.)
        let id = match (revoke.id, revoke.all) {
            (Some(id), false) => {
                if !rusthorse::broker_protocol::is_well_formed_grant_id(&id) {
                    bail!(
                        "{id:?} is not a grant ID: an ID is g and 16 hexadecimal digits, as \
                         `rusthorse grants` shows it"
                    );
                }
                Some(id)
            }
            (None, true) => None,
            _ => bail!("give the ID of one grant, or --all"),
        };
        client.check_compatible()?;
        return simple(client, &Request::RevokeGrant { id });
    }
    client.check_compatible()?;
    let Response::Grants { grants } = check(client.call(&Request::Grants)?)? else {
        bail!("unexpected response");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&grants)?);
        return Ok(0);
    }
    if grants.is_empty() {
        eprintln!("No grants.");
        return Ok(0);
    }
    print!("{}", grants_table(&grants));
    for grant in &grants {
        if let Some(requests @ 1..) = grant.unauthorized {
            eprintln!("{}", grant_unauthorized_note(grant, requests));
        }
    }
    Ok(0)
}

/// "1 request", "2 requests".
fn requests_count(requests: u64) -> String {
    match requests {
        1 => "1 request".to_string(),
        n => format!("{n} requests"),
    }
}

/// The note `run` prints on standard error after a command whose grant's
/// destination answered `401 Unauthorized` (ADR 0013): the command ran,
/// with its own exit status; the broker accepted its token; the destination
/// did not accept the key stored in the entry. `name` is the entry as the
/// command line gave it, for the command that replaces the key; what the
/// agent reports is shown with control and invisible characters escaped.
fn unauthorized_note(grant: &UnauthorizedGrant, name: Option<&str>) -> String {
    use rusthorse::util::{shell_quote, visible};
    let (entry, fix) = match name {
        // A name that starts with `-` would be read as an option: after
        // `--`, it is not.
        Some(name) if name.starts_with('-') => (
            visible(name),
            format!(
                "replace it: rusthorse edit --value -- {}",
                visible(&shell_quote(name))
            ),
        ),
        Some(name) => (
            visible(name),
            format!(
                "replace it: rusthorse edit {} --value",
                visible(&shell_quote(name))
            ),
        ),
        None => (
            visible(&grant.entry),
            "replace the entry's value".to_string(),
        ),
    };
    format!(
        "rusthorse: note: the command ran, and the broker accepted its token, but the approved \
         origin {} answered 401 Unauthorized to {}: it did not accept the key stored in {entry}. \
         If that key is wrong, revoked, or not of the kind the destination expects, {fix}",
        visible(&grant.destination),
        requests_count(grant.requests),
    )
}

/// The note `rusthorse grants` prints on standard error for a grant whose
/// destination answered `401 Unauthorized`; the table stays as it is.
fn grant_unauthorized_note(grant: &GrantInfo, requests: u64) -> String {
    use rusthorse::util::visible;
    format!(
        "rusthorse: note: grant {}: the approved origin {} answered 401 Unauthorized to {}: it did \
         not accept the key stored in {}. If that key is wrong, revoked, or not of the kind the \
         destination expects, replace the entry's value (rusthorse edit NAME --value)",
        visible(&grant.id),
        visible(&grant.destination),
        requests_count(requests),
        visible(&grant.entry),
    )
}

/// The grants as `rusthorse grants` prints them: a table with a line per
/// grant, its command last (the longest). Everything the agent reports is
/// shown with control and invisible characters escaped
/// ([`rusthorse::util::visible`]): a command line or a requester's process
/// name chosen to rewrite the terminal cannot hide a grant. There is no
/// token to show: the agent never reports one.
fn grants_table(grants: &[GrantInfo]) -> String {
    use rusthorse::util::visible;
    const HEADERS: [&str; 12] = [
        "ID",
        "ENTRY",
        "APPROVED ORIGIN",
        "BASE PATH (NOT A LIMIT)",
        "STATE",
        "STARTED",
        "ENDS IN",
        "REQUESTS",
        "IN FLIGHT",
        "AUTOMATIC LOCKS",
        "REQUESTER",
        "COMMAND",
    ];
    let rows: Vec<[String; 12]> = grants
        .iter()
        .map(|g| {
            [
                visible(&g.id),
                visible(&g.entry),
                visible(&g.destination),
                g.base_path
                    .as_deref()
                    .map_or_else(|| "none".to_string(), visible),
                visible(&g.state),
                visible(&g.started),
                format_duration(Duration::from_secs(g.ends_in_secs)),
                match g.max_requests {
                    Some(limit) => format!("{} of {limit}", g.requests),
                    None => format!("{} (no limit)", g.requests),
                },
                g.in_flight.to_string(),
                g.automatic_locks.as_str().to_string(),
                visible(&g.requester),
                visible(&g.command),
            ]
        })
        .collect();
    let mut widths = HEADERS.map(|h| h.chars().count());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let padded: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut out = line(HEADERS.to_vec());
    for row in &rows {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
    }
    out
}

/// One entry of `rusthorse import`: its name, the keyring item it comes
/// from, and what the dialog shows for it (to fit the batches to dialogs).
struct Pick {
    name: String,
    // Read only for keyring imports, which need the `secret-service` feature.
    #[cfg_attr(not(feature = "secret-service"), allow(dead_code))]
    id: Option<String>,
    /// The keyring item, as the dialog shows it.
    item: Option<String>,
}

/// Where `rusthorse import` asks the agent to read the values.
enum ImportFrom {
    Dotenv {
        path: String,
        prefix: Option<String>,
    },
    #[cfg(feature = "secret-service")]
    Keyring,
}

fn import_cmd(client: &Client, command: ImportCommand) -> anyhow::Result<u8> {
    // The agent reads the values (ADR 0012): this process only names what
    // to import and the entries' names; it never holds a value.
    let (picks, source, tags, replace) = match command {
        ImportCommand::Dotenv {
            file,
            prefix,
            tags,
            replace,
            dry_run,
        } => {
            let path = std::path::absolute(&file)
                .with_context(|| format!("cannot resolve {}", file.display()))?
                .to_str()
                .context("the file's path is not valid UTF-8")?
                .to_string();
            eprintln!("The agent asks before it shows the names in the file to this command.");
            let Response::Names { names, empty } =
                check(client.call(&Request::DotenvNames { path: path.clone() })?)?
            else {
                bail!("unexpected response from the agent");
            };
            let prefix = prefix.map(|p| p.to_uppercase()).filter(|p| !p.is_empty());
            let prefixed = |names: Vec<String>| -> Vec<String> {
                names
                    .into_iter()
                    .map(|name| format!("{}{name}", prefix.as_deref().unwrap_or_default()))
                    .collect()
            };
            let (names, empty) = (prefixed(names), prefixed(empty));
            // Said, never skipped without a word.
            if !empty.is_empty() {
                eprintln!(
                    "not imported, because they have no value: {}",
                    printable(&empty.join(", "))
                );
            }
            if dry_run {
                return import_preview(client, names, replace);
            }
            let picks: Vec<Pick> = names
                .into_iter()
                .map(|name| Pick {
                    name,
                    id: None,
                    item: None,
                })
                .collect();
            (picks, ImportFrom::Dotenv { path, prefix }, tags, replace)
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
            eprintln!("The agent asks before it shows the keyring's items to this command.");
            let Response::KeyringItems { items } = check(client.call(&Request::KeyringItems)?)?
            else {
                bail!("unexpected response from the agent");
            };
            let mut picks = Vec::new();
            for item in items.into_iter().filter(|item| {
                attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            }) {
                let name = match &name_from {
                    Some(attr) => item.attributes.get(attr).cloned().with_context(|| {
                        format!("the item {:?} has no {attr:?} attribute", item.label)
                    })?,
                    None => item.label.clone(),
                };
                picks.push(Pick {
                    name,
                    // What the agent's dialog will show for it.
                    item: Some(rusthorse::keyring::describe_item(&item)),
                    id: Some(item.id),
                });
            }
            picks.sort_by(|a, b| a.name.cmp(&b.name));
            if dry_run {
                let names = picks.into_iter().map(|pick| pick.name).collect();
                return import_preview(client, names, replace);
            }
            (picks, ImportFrom::Keyring, tags, replace)
        }
    };
    if picks.is_empty() {
        bail!("nothing found to import");
    }
    let mut seen = std::collections::HashSet::new();
    let duplicates: std::collections::BTreeSet<&str> = picks
        .iter()
        .filter(|pick| !seen.insert(pick.name.as_str()))
        .map(|pick| pick.name.as_str())
        .collect();
    if !duplicates.is_empty() {
        bail!(
            "these names appear more than once, so nothing was imported: {} \
             (fix the source, or use --prefix to tell them apart)",
            duplicates.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    // Split into batches small enough for one dialog each.
    let planned: Vec<rusthorse::import::Planned> = picks
        .iter()
        .map(|pick| rusthorse::import::Planned {
            name: pick.name.clone(),
            item: pick.item.clone(),
        })
        .collect();
    let dotenv = match &source {
        ImportFrom::Dotenv { path, .. } => Some(path.as_str()),
        #[cfg(feature = "secret-service")]
        ImportFrom::Keyring => None,
    };
    // As tall a dialog as the agent's dialog program shows.
    let dialogs = match client.call(&Request::Status) {
        Ok(Response::Status(info)) => info.dialogs,
        _ => None,
    };
    let limit_height = rusthorse::import::dialogs_limit_height(dialogs.as_deref());
    let sizes = rusthorse::import::batch_sizes(&planned, dotenv, limit_height);
    let mut rest = picks.into_iter();
    let batches: Vec<Vec<Pick>> = sizes
        .into_iter()
        .map(|size| rest.by_ref().take(size).collect())
        .collect();
    let total = batches.len();
    for (i, batch) in batches.into_iter().enumerate() {
        if total > 1 {
            eprintln!("batch {} of {total} ({} entries):", i + 1, batch.len());
        }
        let source = match &source {
            ImportFrom::Dotenv { path, prefix } => ImportSource::Dotenv {
                path: path.clone(),
                prefix: prefix.clone(),
                names: batch.into_iter().map(|pick| pick.name).collect(),
            },
            #[cfg(feature = "secret-service")]
            ImportFrom::Keyring => ImportSource::Keyring {
                items: batch
                    .into_iter()
                    .map(|pick| rusthorse::protocol::KeyringPick {
                        id: pick.id.unwrap_or_default(),
                        name: pick.name,
                    })
                    .collect(),
            },
        };
        let answer = client.call(&Request::ImportFrom {
            source,
            tags: tags.clone(),
            replace,
        });
        let done = if i == 0 {
            "no earlier batch was imported".to_string()
        } else {
            format!("batches 1 to {i} were imported")
        };
        let rerun = if replace {
            "running the same import again re-imports everything (with --replace, \
             already imported entries are overwritten with what the source holds then)"
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
            Ok(Response::Ok { message }) => eprintln!("{}", printable(&message)),
            // Every error except `outcome_unknown` means nothing was saved
            // (docs/protocol.md, "Errors").
            Ok(Response::Error { code, message }) if code != ErrorCode::OutcomeUnknown => {
                eprintln!("rusthorse: {}", printable(&message));
                let denied = matches!(code, ErrorCode::Denied | ErrorCode::Cancelled);
                return not_imported(if denied { EXIT_DENIED } else { 1 });
            }
            Ok(Response::Error { message, .. }) => {
                eprintln!("rusthorse: {}", printable(&message));
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
            // An answer that could not be read is quoted in the error:
            // shown escaped, like everything the agent supplies.
            Err(e)
                if e.downcast_ref::<rusthorse::client::OutcomeUnknown>()
                    .is_some() =>
            {
                eprintln!("rusthorse: {}", printable(&format!("{e:#}")));
                return unsure("lost the connection during");
            }
            // The request was never sent (the agent stopped, say).
            Err(e) => {
                eprintln!("rusthorse: {}", printable(&format!("{e:#}")));
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
            "{mark:<8} {}{}",
            printable(name),
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
    // Shown escaped; the browser gets the URL as stored.
    eprintln!("Opening {}", printable(&url));
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
/// Whether the vault locks when the computer suspends and when the screen
/// locks (ADR 0009). Not watching is a warning: the idle timer still locks.
fn lock_trigger_checks(triggers: &[rusthorse::protocol::LockTrigger]) -> Vec<Check> {
    use rusthorse::session_lock::{SCREEN_LOCK, SUSPEND};
    if triggers.is_empty() {
        return vec![Check::Warn(
            "the agent does not report locking on suspend or screen lock: it predates it \
             (upgrade it and run `systemctl --user restart rusthorse-agent`)"
                .into(),
        )];
    }
    [
        (SUSPEND, "when the computer suspends"),
        (SCREEN_LOCK, "when the screen locks"),
    ]
    .into_iter()
    .map(|(event, when)| {
        let of_event: Vec<_> = triggers.iter().filter(|t| t.event == event).collect();
        let sound: Vec<&str> = of_event
            .iter()
            .filter(|t| t.active && !t.degraded)
            .map(|t| t.source.as_str())
            .collect();
        let degraded: Vec<String> = of_event
            .iter()
            .filter(|t| t.active && t.degraded)
            .map(|t| format!("{}: {}", t.source, t.note.as_deref().unwrap_or("degraded")))
            .collect();
        if !sound.is_empty() {
            Check::Ok(format!(
                "the vault locks {when} (told by {})",
                sound.join(", ")
            ))
        } else if !degraded.is_empty() {
            Check::Warn(format!(
                "the vault locks {when}, but {}",
                degraded.join("; ")
            ))
        } else {
            let why: Vec<&str> = of_event.iter().filter_map(|t| t.note.as_deref()).collect();
            Check::Warn(format!(
                "the vault does not lock {when}: {} (the idle timer still locks it)",
                why.join("; ")
            ))
        }
    })
    .collect()
}

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

/// What doctor says when the credential broker cannot serve grants.
const NO_GRANTS: &str = "no grant of the credential broker can be served (`rusthorse run --broker` \
                         exits with 125 and runs nothing)";

/// What doctor found of the credential broker's program: the line it
/// prints, and whether the program is installed at all — anything but
/// nothing at its place, so that a broken installation counts as one.
struct BrokerProgram {
    check: Check,
    installed: bool,
}

/// The credential broker's program (ADR 0013), as the agent reports using it
/// (it checked the program as it uses it), and whether it runs:
/// `rusthorse-broker --check`, under supervision and a 5-second limit,
/// reports its version and broker protocol, which must be this rusthorse's.
/// When the agent reports that it cannot use the program, its reason is the
/// error, unless nothing at all is next to the agent's program file: then
/// the program is not installed. An agent that does not report it has its
/// program file's directory looked at; without an agent, the directory of
/// this rusthorse. Not installed is a warning, since everything else works
/// without it; unusable, of another version or not running is an error.
fn broker_check(info: Option<&StatusInfo>) -> BrokerProgram {
    use rusthorse::broker_protocol::{PROGRAM, VERSION};
    use rusthorse::helper_program::{Located, check_program, locate, locate_in};
    let installed = |check: Check| BrokerProgram {
        check,
        installed: true,
    };
    let near_the_agent = |info: &StatusInfo| {
        let exe = info.agent_executable.trim_end_matches(" (deleted)");
        Path::new(exe)
            .parent()
            .filter(|_| !exe.is_empty())
            .map(|dir| locate_in(dir, PROGRAM))
    };
    let located = match info {
        Some(info) => match info.broker.as_deref() {
            Some(reason) if reason.starts_with("none: ") => {
                let why = &reason["none: ".len()..];
                return match near_the_agent(info) {
                    // Nothing there: the program is not installed.
                    Some(Located::Absent(path)) => not_installed(&path),
                    _ => installed(Check::Fail(format!("{NO_GRANTS}: {why}"))),
                };
            }
            Some(path) => Located::Program(PathBuf::from(path)),
            // An agent that predates the field.
            None => match near_the_agent(info) {
                Some(located) => located,
                None => {
                    return installed(Check::Warn(
                        "cannot tell which broker program the agent uses".into(),
                    ));
                }
            },
        },
        None => locate(PROGRAM),
    };
    let program = match located {
        Located::Program(path) => path,
        Located::Absent(path) => return not_installed(&path),
        Located::Unusable(why) => return installed(Check::Fail(format!("{NO_GRANTS}: {why}"))),
    };
    let ours = env!("CARGO_PKG_VERSION");
    installed(match check_program(&program, Duration::from_secs(5)) {
        Ok((version, protocol)) if version == ours && protocol == VERSION => Check::Ok(format!(
            "broker: {PROGRAM} {version} ({})",
            program.display()
        )),
        Ok((version, protocol)) => Check::Fail(format!(
            "{PROGRAM} {version} speaks broker protocol {protocol}, this rusthorse {ours} \
             protocol {VERSION}: {NO_GRANTS}; install the same version of both, then restart the \
             agent"
        )),
        Err(e) => Check::Fail(format!(
            "{} does not run: {e:#}; {NO_GRANTS}",
            program.display()
        )),
    })
}

/// The broker's program is not installed at `path`.
fn not_installed(path: &Path) -> BrokerProgram {
    BrokerProgram {
        check: Check::Warn(format!(
            "{} is not installed: {NO_GRANTS}; install it next to the agent (see \
             docs/installation.md)",
            path.display()
        )),
        installed: false,
    }
}

/// The file of certificate authorities the credential broker trusts, as
/// [`rusthorse::broker_protocol::open_ca_file`] opened and checked it: the
/// checks a broker makes of the file, its owner and its directories. Only a
/// broker reads the certificates in it, when a grant starts (a file without
/// a usable one fails then), so the line that passes says no more than
/// where they are read from. Without the file no grant can be served: an
/// error when the broker's program is installed, a warning when it is not
/// either.
fn ca_file_check(opened: Result<PathBuf, String>, broker_installed: bool) -> Check {
    match opened {
        Ok(path) => Check::Ok(format!(
            "the broker reads its certificate authorities from {}, which only root can change; \
             it reads the certificates themselves when a grant starts",
            path.display()
        )),
        Err(why) => {
            let text = format!(
                "{why}: {NO_GRANTS}. The broker reads the first of {} that exists, which must be \
                 a regular file owned by root, in directories owned by root, none of them \
                 writable by group or others (the ca-certificates package installs one)",
                rusthorse::broker_protocol::CA_FILES.join(", ")
            );
            if broker_installed {
                Check::Fail(text)
            } else {
                Check::Warn(text)
            }
        }
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
    let broker_installed = match client.call(&Request::Status) {
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
            let broker = broker_check(Some(&info));
            checks.push(broker.check);
            checks.extend(lock_trigger_checks(&info.lock_triggers));
            if !info.vault_exists {
                checks.push(Check::Fail(format!(
                    "no vault at {} — run `rusthorse init`",
                    info.vault
                )));
            }
            broker.installed
        }
        Ok(_) => {
            checks.push(Check::Fail(
                "the agent answered something unexpected".into(),
            ));
            let broker = broker_check(None);
            checks.push(broker.check);
            broker.installed
        }
        Err(e) => {
            checks.push(Check::Fail(format!("{e:#}")));
            let broker = broker_check(None);
            checks.push(broker.check);
            broker.installed
        }
    };
    // What the credential broker trusts, checked as a broker checks it.
    checks.push(ca_file_check(
        rusthorse::broker_protocol::open_ca_file().map(|ca| ca.path),
        broker_installed,
    ));

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

    for check in &checks {
        println!("{}", check_line(check));
    }
    Ok(if checks.iter().any(|c| matches!(c, Check::Fail(_))) {
        1
    } else {
        0
    })
}

/// The agent's settings as `rusthorse status` shows them, one per line:
/// `Lock after inactivity: 15m (default)`, `Remembered approvals: off (set
/// by --remember)`.
fn settings_lines(info: &rusthorse::protocol::SettingsInfo) -> Vec<String> {
    use settings::{Key, Source, Value};
    let secs = |s: u64| Value::Duration(Duration::from_secs(s));
    [
        (
            Key::IdleTimeout,
            secs(info.idle_timeout_secs.value),
            info.idle_timeout_secs.source,
        ),
        (
            Key::Remember,
            secs(info.remember_secs.value),
            info.remember_secs.source,
        ),
        (
            Key::DialogTimeout,
            secs(info.dialog_timeout_secs.value),
            info.dialog_timeout_secs.source,
        ),
        (
            Key::LockOnSuspend,
            Value::Switch(info.lock_on_suspend.value),
            info.lock_on_suspend.source,
        ),
        (
            Key::LockOnScreenLock,
            Value::Switch(info.lock_on_screen_lock.value),
            info.lock_on_screen_lock.source,
        ),
    ]
    .into_iter()
    .map(|(key, value, source)| {
        format!(
            "{}: {} ({})",
            key.label(),
            value.describe(key),
            match source {
                Source::Default => "default".to_string(),
                Source::File => "settings file".to_string(),
                Source::Flag => format!("set by {}", key.flag()),
            }
        )
    })
    .collect()
}

/// A line of `rusthorse doctor`, its text escaped: it can quote what the
/// agent reports (paths, its version, the sources of its locks).
fn check_line(check: &Check) -> String {
    match check {
        Check::Ok(text) => format!("  ok    {}", printable(text)),
        Check::Warn(text) => format!("  warn  {}", printable(text)),
        Check::Fail(text) => format!("  FAIL  {}", printable(text)),
    }
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
        println!("{}", audit_line(&event));
    }
    Ok(0)
}

/// One audit record as `rusthorse audit` prints it: the time, action and
/// outcome, then what the record has — the entries; for the credential
/// broker (ADR 0013), the grant, the request's number and method label, the
/// destination's status and the bytes each way; the grants a run creates;
/// the command line; why a grant ended and what became of its requests; the
/// detail — and the requester. Control and invisible characters are escaped
/// ([`rusthorse::util::visible`]): any program of the user can write the log
/// (threat model L13), and a value written to rewrite the terminal, or to
/// look like another record, shows as what it is.
fn audit_line(event: &audit::AuditEvent) -> String {
    let mut line = format!("{}  {:<8} {:<20}", event.time, event.action, event.outcome);
    if !event.entries.is_empty() {
        line.push_str(&format!(" [{}]", event.entries.join(", ")));
    }
    if let Some(grant) = &event.grant {
        line.push_str(&format!(" grant {grant}"));
    }
    if let Some(request) = event.request {
        line.push_str(&format!(" #{request}"));
    }
    if let Some(method) = &event.method {
        line.push_str(&format!(" {method}"));
    }
    if let Some(status) = event.status {
        line.push_str(&format!(" status {status}"));
    }
    match (event.bytes_sent, event.bytes_received) {
        (Some(sent), Some(received)) => {
            line.push_str(&format!(" ({sent} bytes sent, {received} received)"));
        }
        (Some(sent), None) => line.push_str(&format!(" ({sent} bytes sent)")),
        (None, Some(received)) => line.push_str(&format!(" ({received} bytes received)")),
        (None, None) => {}
    }
    if let Some(grants) = &event.grants {
        let grants: Vec<String> = grants
            .iter()
            .map(|g| match &g.base_path {
                Some(base) => format!(
                    "{} for {} to {} (base path {base}, not a limit)",
                    g.id, g.entry, g.destination
                ),
                None => format!("{} for {} to {}", g.id, g.entry, g.destination),
            })
            .collect();
        line.push_str(&format!(" grants: {};", grants.join(", ")));
    }
    if let Some(argv) = &event.argv {
        line.push_str(&format!(" $ {}", rusthorse::util::shell_join(argv)));
    }
    if let Some(reason) = &event.reason {
        line.push_str(&format!(" reason: {reason}"));
    }
    if let Some(r) = event.requests {
        line.push_str(&format!(
            " requests: {} admitted ({} finished, {} unknown), {} refused",
            r.admitted, r.finished, r.unknown, r.refused
        ));
    }
    if let Some(detail) = &event.detail {
        line.push_str(&format!(" ({detail})"));
    }
    line.push_str(&format!("  by {}", event.requester));
    rusthorse::util::visible(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_vault_paths_are_the_same_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        std::os::unix::fs::symlink(&real, dir.path().join("link")).expect("symlink");
        let vault = real.join("vault.kdbx");
        for same in [
            dir.path().join("link/vault.kdbx"),
            dir.path().join("real/./vault.kdbx"),
            dir.path().join("link/../real/vault.kdbx"),
        ] {
            assert_eq!(same_vault(&vault, &same), Some(true), "{}", same.display());
        }
        // Relative to the working directory.
        let cwd = std::env::current_dir().expect("cwd");
        let relative = Path::new("relative-vault.kdbx");
        assert_eq!(same_vault(&cwd.join(relative), relative), Some(true));
        // Directories that do not exist yet, with `..` among them.
        assert_eq!(
            same_vault(
                &dir.path().join("link/new/sub/vault.kdbx"),
                &real.join("new/sub/vault.kdbx")
            ),
            Some(true)
        );
        assert_eq!(
            same_vault(
                &real.join("new/vault.kdbx"),
                &dir.path().join("link/new/sub/../vault.kdbx")
            ),
            Some(true)
        );
        // A `..` that climbs back above a missing directory resolves links
        // again; a link to a directory that does not exist yet is followed.
        assert_eq!(
            same_vault(&vault, &dir.path().join("missing/../link/vault.kdbx")),
            Some(true)
        );
        std::os::unix::fs::symlink(dir.path().join("future"), dir.path().join("later"))
            .expect("dangling symlink");
        assert_eq!(
            same_vault(
                &dir.path().join("future/vault.kdbx"),
                &dir.path().join("later/vault.kdbx")
            ),
            Some(true)
        );
        // A loop of links cannot be resolved.
        std::os::unix::fs::symlink(dir.path().join("loop"), dir.path().join("loop")).expect("loop");
        assert_eq!(
            same_vault(&vault, &dir.path().join("loop/vault.kdbx")),
            None
        );
        assert_eq!(same_vault(&vault, &real.join("other.kdbx")), Some(false));
        assert_eq!(
            same_vault(&vault, &dir.path().join("vault.kdbx")),
            Some(false)
        );
        // A directory that cannot be examined: cannot tell (not as root,
        // who can examine anything).
        if !nix::unistd::geteuid().is_root() {
            use std::os::unix::fs::PermissionsExt;
            let closed = dir.path().join("closed");
            std::fs::create_dir(&closed).expect("mkdir");
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
            let unknown = same_vault(&vault, &closed.join("inner/vault.kdbx"));
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
                .expect("chmod back");
            assert_eq!(unknown, None);
        }
    }

    #[test]
    fn a_vault_created_here_that_may_not_survive_a_crash_is_an_unknown_outcome() {
        let e = created_locally(rusthorse::vault::VaultError::NotDurable(
            std::io::Error::other("injected"),
        ));
        assert!(e.downcast_ref::<LocalOutcomeUnknown>().is_some());
        // No agent was involved: the message does not speak of one.
        assert!(!format!("{e:#}").contains("agent"), "{e:#}");
        let e = created_locally(rusthorse::vault::VaultError::Exists("/x".into()));
        assert!(e.downcast_ref::<LocalOutcomeUnknown>().is_none());
    }

    #[test]
    fn only_a_missing_or_refusing_socket_means_that_no_agent_runs() {
        let io = |kind| anyhow::Error::new(std::io::Error::from(kind)).context("cannot reach");
        assert!(agent_not_running(&io(std::io::ErrorKind::NotFound)));
        assert!(agent_not_running(&io(
            std::io::ErrorKind::ConnectionRefused
        )));
        assert!(!agent_not_running(&io(std::io::ErrorKind::TimedOut)));
        assert!(!agent_not_running(&anyhow::anyhow!("an unexpected answer")));
    }

    #[test]
    fn doctor_warns_when_nothing_locks_on_suspend_or_screen_lock() {
        use rusthorse::protocol::LockTrigger;
        let trigger = |event: &str, source: &str, active: bool, note: Option<&str>| LockTrigger {
            event: event.into(),
            source: source.into(),
            active,
            degraded: false,
            note: note.map(Into::into),
        };
        let checks = lock_trigger_checks(&[
            trigger(
                "suspend",
                "logind",
                true,
                Some("locks before the computer sleeps"),
            ),
            trigger(
                "screen_lock",
                "logind",
                false,
                Some("no system bus; trying again"),
            ),
            trigger("screen_lock", "screensaver", false, Some("turned off")),
        ]);
        assert!(
            matches!(&checks[0], Check::Ok(m) if m.contains("when the computer suspends (told by logind)"))
        );
        assert!(matches!(&checks[1], Check::Warn(m)
            if m.contains("does not lock when the screen locks")
                && m.contains("no system bus; trying again")
                && m.contains("turned off")));
        // Watched, but logind would not wait: a warning that says why.
        let mut slow = trigger(
            "suspend",
            "logind",
            true,
            Some("logind would not wait (denied)"),
        );
        slow.degraded = true;
        let checks = lock_trigger_checks(&[slow]);
        assert!(matches!(&checks[0], Check::Warn(m)
            if m.contains("locks when the computer suspends, but logind: logind would not wait")));
        // An agent that predates the field.
        assert!(
            matches!(&lock_trigger_checks(&[])[..], [Check::Warn(m)] if m.contains("predates"))
        );
    }

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

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn binding(var: &str, entry: &str) -> Binding {
        Binding {
            var: var.into(),
            entry: entry.into(),
        }
    }

    #[test]
    fn run_sorts_out_broker_bindings_and_the_variables_of_their_address() {
        let plan = plan_run(
            &strings(&["DB_PASSWORD=db"]),
            &strings(&[
                "ANTHROPIC_AUTH_TOKEN=AI/anthropic@https://api.anthropic.com",
                "OPENAI_API_KEY@https://api.openai.com/v1",
                // The URL starts after the last `@`, the variable ends at
                // the first `=`: an entry's name may hold both.
                "T=me@work=x@https://api.example.com:8443/v2",
            ]),
            &strings(&["DOCS_URL=docs", "ANTHROPIC_BASE_URL=AI/anthropic"]),
        )
        .expect("a valid run");
        assert_eq!(plan.bindings, [binding("DB_PASSWORD", "db")]);
        assert_eq!(
            plan.brokered,
            [
                BrokerBinding {
                    var: "ANTHROPIC_AUTH_TOKEN".into(),
                    entry: "AI/anthropic".into(),
                    destination: "https://api.anthropic.com".into(),
                    url_var: Some("ANTHROPIC_BASE_URL".into()),
                },
                // ENTRY alone: the variable is named like the entry.
                BrokerBinding {
                    var: "OPENAI_API_KEY".into(),
                    entry: "OPENAI_API_KEY".into(),
                    destination: "https://api.openai.com/v1".into(),
                    url_var: None,
                },
                BrokerBinding {
                    var: "T".into(),
                    entry: "me@work=x".into(),
                    destination: "https://api.example.com:8443/v2".into(),
                    url_var: None,
                },
            ]
        );
        // A --url for an entry not given with --broker reads its own URL.
        assert_eq!(plan.urls, [binding("DOCS_URL", "docs")]);
        // Without --broker, nothing changes.
        let plain = plan_run(&strings(&["KEY"]), &[], &strings(&["KEY_URL=KEY"])).expect("plain");
        assert_eq!(
            plain,
            RunPlan {
                bindings: vec![binding("KEY", "KEY")],
                brokered: vec![],
                urls: vec![binding("KEY_URL", "KEY")],
            }
        );
        // One entry in two variables is not one variable set twice.
        let twice = plan_run(&strings(&["A=k", "B=k"]), &[], &[]).expect("two variables");
        assert_eq!(twice.bindings, [binding("A", "k"), binding("B", "k")]);
        // Through the broker only.
        let only = plan_run(&[], &strings(&["T=k@https://x.example"]), &[]).expect("broker only");
        assert!(only.bindings.is_empty() && only.urls.is_empty());
        assert_eq!(only.brokered.len(), 1);
        // The --url of another entry keeps its meaning, whatever its
        // variable: only a token and the broker's address stay out of
        // NO_PROXY.
        let other = plan_run(
            &[],
            &strings(&["T=k@https://x.example"]),
            &strings(&["NO_PROXY=docs"]),
        )
        .expect("url");
        assert_eq!(other.urls, [binding("NO_PROXY", "docs")]);
    }

    /// The secrets, `--broker` and `--url` options of a `run`, and what its
    /// refusal says.
    type Refusal = (
        &'static [&'static str],
        &'static [&'static str],
        &'static [&'static str],
        &'static str,
    );

    #[test]
    fn run_refuses_mistakes_in_broker_bindings_before_anything_is_sent() {
        let cases: [Refusal; 31] = [
            // The destination is named, valid, and not the entry's own URL
            // by default: there is none.
            (&[], &["K=x"], &[], "name the destination"),
            (&[], &["x"], &[], "name the destination"),
            (
                &[],
                &["K=x@http://x.example"],
                &[],
                "must start with https://",
            ),
            (
                &[],
                &["K=x@https://x.example?q=1"],
                &[],
                "query or a fragment",
            ),
            (&[], &["K=x@https://10.0.0.1"], &[], "not an IP address"),
            (
                &[],
                &["K=x@https://x.example/v1/"],
                &[],
                "base path is not valid",
            ),
            (&[], &["K=x@"], &[], "must start with https://"),
            // Every variable is set once: two SECRETs too, with --broker or
            // without it (the agent refuses them anyway; the CLI sends
            // nothing).
            (
                &["K=a", "K=b"],
                &[],
                &[],
                "K=b: the variable is already set by another binding",
            ),
            (
                &["K", "K"],
                &[],
                &[],
                "K: the variable is already set by another binding",
            ),
            (
                &["K=a", "K=b"],
                &["T=x@https://x.example"],
                &[],
                "K=b: the variable is already set by another binding",
            ),
            (
                &[],
                &["1BAD=x@https://x.example"],
                &[],
                "not a valid environment variable name",
            ),
            (
                &[],
                &["x-y@https://x.example"],
                &[],
                "not a valid environment variable name",
            ),
            (&[], &["K=@https://x.example"], &[], "missing entry name"),
            (
                &[],
                &["LD_PRELOAD=x@https://x.example"],
                &[],
                "cannot carry a token",
            ),
            (
                &[],
                &["NODE_OPTIONS=x@https://x.example"],
                &[],
                "cannot carry a token",
            ),
            (
                &[],
                &["BASH_FUNC_x=x@https://x.example"],
                &[],
                "cannot carry a token",
            ),
            // The agent adds 127.0.0.1 to NO_PROXY: neither a token nor the
            // broker's address goes there, whatever the case.
            (
                &[],
                &["NO_PROXY=x@https://x.example"],
                &[],
                "the agent adds 127.0.0.1 to this variable",
            ),
            (
                &[],
                &["no_proxy=x@https://x.example"],
                &[],
                "the agent adds 127.0.0.1 to this variable",
            ),
            (
                &[],
                &["K=x@https://x.example"],
                &["NO_PROXY=x"],
                "it cannot carry the broker's address",
            ),
            (
                &[],
                &["K=x@https://x.example"],
                &["No_Proxy=x"],
                "it cannot carry the broker's address",
            ),
            (
                &["K=y"],
                &["K=x@https://x.example"],
                &[],
                "the variable is already set by another binding",
            ),
            (
                &[],
                &["K=x@https://x.example", "K=y@https://x.example"],
                &[],
                "the variable is already set by another binding",
            ),
            (
                &[],
                &["K=x@https://x.example", "L=x@https://x.example"],
                &[],
                "x is already given to --broker",
            ),
            // The same entry both ways, by its name (the agent compares UUIDs).
            (
                &["V=x"],
                &["K=x@https://x.example"],
                &[],
                "x is also given by value",
            ),
            (
                &[],
                &["K=x@https://x.example"],
                &["U=x", "V=x"],
                "x already has --url U",
            ),
            (
                &[],
                &["K=x@https://x.example"],
                &["K=x"],
                "the variable is already set by another binding",
            ),
            (
                &[],
                &["K=x@https://x.example", "L=y@https://x.example"],
                &["U=x", "U=y"],
                "the variable is already set by another binding",
            ),
            (
                &["S=s"],
                &["K=x@https://x.example"],
                &["S=x"],
                "the variable is already set by another binding",
            ),
            (
                &[],
                &["K=x@https://x.example"],
                &["LD_AUDIT=x"],
                "cannot carry a URL",
            ),
            (&[], &["K=x@https://x.example"], &["x"], "write VAR=ENTRY"),
            (
                &[],
                &["K=x@https://x.example"],
                &["1U=x"],
                "not a valid environment variable name",
            ),
        ];
        for (secrets, brokers, urls, expected) in cases {
            let err = plan_run(&strings(secrets), &strings(brokers), &strings(urls))
                .expect_err(expected)
                .to_string();
            assert!(
                err.contains(expected),
                "{secrets:?} {brokers:?} {urls:?}: {err}"
            );
        }
    }

    fn entry(id: &str, group: Option<&str>, name: &str) -> EntryInfo {
        EntryInfo {
            id: id.into(),
            name: name.into(),
            group: group.map(Into::into),
            fields: EntryFields::default(),
            protected_fields: vec![],
            has_password: true,
            has_notes: false,
            other_fields: vec![],
            modified: None,
        }
    }

    #[test]
    fn an_entry_is_known_by_every_name_that_leads_to_it() {
        let id = "8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12";
        assert_eq!(
            entry_names(&entry(id, Some("AI/Work"), "anthropic")),
            [id, "AI/Work/anthropic", "anthropic"]
        );
        assert_eq!(
            entry_names(&entry(id, None, "anthropic")),
            [id, "anthropic"]
        );
        // A protected title is matched by UUID only.
        let mut hidden = entry(id, Some("AI"), rusthorse::vault::PROTECTED_TITLE);
        hidden.protected_fields = vec!["Title".into()];
        assert_eq!(entry_names(&hidden), [id]);
    }

    #[test]
    fn the_cli_names_every_lock_policy_as_runs_send_them() {
        let policies: Vec<AutomaticLocks> =
            LocksArg::value_variants().iter().map(|l| l.0).collect();
        assert_eq!(policies, AutomaticLocks::ALL);
        for policy in LocksArg::value_variants() {
            let value = policy.to_possible_value().expect("a value");
            assert_eq!(value.get_name(), policy.0.as_str());
        }
        // The help of run's limits, and docs/cli.md, give the defaults.
        let defaults = GrantLimits::default();
        assert_eq!(defaults.automatic_locks, AutomaticLocks::Continue);
        assert_eq!(defaults.max_lifetime_minutes, 720);
        assert_eq!(defaults.max_requests, None);
        let help = Cli::command()
            .find_subcommand_mut("run")
            .expect("run")
            .render_long_help()
            .to_string();
        for said in [
            "continue unless given",
            "720 (12 hours) unless given",
            "no limit unless given",
        ] {
            assert!(help.contains(said), "{said}: {help}");
        }
    }

    /// A line of `rusthorse doctor` shows what it quotes escaped.
    #[test]
    fn doctor_lines_show_what_they_quote_escaped() {
        assert_eq!(
            check_line(&Check::Ok("vault /tmp/v\u{1b}[2J".into())),
            "  ok    vault /tmp/v\\u{1b}[2J"
        );
        assert_eq!(
            check_line(&Check::Warn("source x\u{202e}".into())),
            "  warn  source x\\u{202e}"
        );
        assert_eq!(
            check_line(&Check::Fail("program\r".into())),
            "  FAIL  program\\u{d}"
        );
    }

    /// The command that a run's note suggests for a key the destination
    /// refused edits the entry it names, with a dialog for the new value —
    /// also when the name starts with `-`, which `--` keeps from being read
    /// as an option.
    #[test]
    fn the_command_a_note_suggests_edits_the_entry_it_names() {
        let grant = UnauthorizedGrant {
            var: "T".into(),
            entry: "KEY (8d2f6c1e)".into(),
            destination: "https://api.anthropic.com".into(),
            requests: 1,
        };
        for (name, shown, argv) in [
            ("KEY", "rusthorse edit KEY --value", vec!["KEY", "--value"]),
            (
                "AI/my key",
                "rusthorse edit 'AI/my key' --value",
                vec!["AI/my key", "--value"],
            ),
            (
                "-k",
                "rusthorse edit --value -- -k",
                vec!["--value", "--", "-k"],
            ),
            (
                "--help",
                "rusthorse edit --value -- --help",
                vec!["--value", "--", "--help"],
            ),
        ] {
            let note = unauthorized_note(&grant, Some(name));
            assert!(note.ends_with(&format!("replace it: {shown}")), "{note}");
            let parsed = Cli::try_parse_from(["rusthorse", "edit"].into_iter().chain(argv))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let Command::Edit(args) = parsed.command else {
                panic!("{name}: not an edit")
            };
            assert_eq!(args.name, name);
            assert!(args.value, "{name}");
        }
    }

    /// The arguments of `rusthorse run ARGS… -- true`.
    fn run_args(args: &[&str]) -> Result<RunArgs, clap::Error> {
        let argv = ["rusthorse", "run"]
            .iter()
            .chain(args)
            .chain(&["--", "true"]);
        match Cli::try_parse_from(argv)?.command {
            Command::Run(args) => Ok(args),
            _ => panic!("not a run"),
        }
    }

    #[test]
    fn a_runs_limits_are_its_options_or_the_defaults_once_they_check_out() {
        let broker = ["--broker", "T=k@https://x.example"];
        let limits = |extra: &[&str]| {
            let args: Vec<&str> = broker.iter().chain(extra).copied().collect();
            run_limits(&run_args(&args).expect("parses"))
        };
        assert_eq!(limits(&[]).expect("defaults"), GrantLimits::default());
        assert_eq!(
            limits(&[
                "--broker-locks",
                "end",
                "--broker-lifetime",
                "90",
                "--broker-requests",
                "200",
            ])
            .expect("every option"),
            GrantLimits {
                automatic_locks: AutomaticLocks::End,
                max_lifetime_minutes: 90,
                max_requests: Some(200),
            }
        );
        // Checked as the agent checks them.
        for (args, expected) in [
            (["--broker-lifetime", "0"], "1 to 1440 minutes, not 0"),
            (["--broker-lifetime", "1441"], "1 to 1440 minutes, not 1441"),
            (["--broker-requests", "0"], "1 to 1000000, not 0"),
            (
                ["--broker-requests", "1000001"],
                "1 to 1000000, not 1000001",
            ),
        ] {
            let err = limits(&args).expect_err(expected).to_string();
            assert!(err.contains(expected), "{args:?}: {err}");
        }
        // What clap refuses: an unknown policy, a number that is not one,
        // and the limits without --broker. Neither `edit --broker` nor
        // `--clear broker` exists any more.
        use clap::error::ErrorKind;
        let by_clap: [(&[&str], ErrorKind); 5] = [
            (
                &[
                    "--broker",
                    "T=k@https://x.example",
                    "--broker-locks",
                    "never",
                ],
                ErrorKind::InvalidValue,
            ),
            (
                &[
                    "--broker",
                    "T=k@https://x.example",
                    "--broker-lifetime",
                    "a day",
                ],
                ErrorKind::ValueValidation,
            ),
            (
                &["K", "--broker-locks", "end"],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &["K", "--broker-lifetime", "5"],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &["K", "--broker-requests", "5"],
                ErrorKind::MissingRequiredArgument,
            ),
        ];
        for (args, kind) in by_clap {
            let err = run_args(args).err().expect("refused");
            assert_eq!(err.kind(), kind, "{args:?}: {err}");
            assert_eq!(err.exit_code(), 2, "{args:?}");
        }
        for args in [
            &["rusthorse", "edit", "KEY", "--broker", "anthropic"][..],
            &["rusthorse", "edit", "KEY", "--clear", "broker"],
        ] {
            let err = Cli::try_parse_from(args).err().expect("refused");
            assert_eq!(err.exit_code(), 2, "{args:?}");
        }
    }

    fn grant() -> GrantInfo {
        GrantInfo {
            id: "g0123456789abcdef".into(),
            entry: "AI/ANTHROPIC_API_KEY (8d2f6c1e)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            destination: "https://api.anthropic.com".into(),
            base_path: None,
            command: "claude".into(),
            requester: "rusthorse[4300] ← bash[4242]".into(),
            state: "active".into(),
            started: "2026-11-02T18:00:00-03:00".into(),
            ends_in_secs: 43_140,
            requests: 3,
            max_requests: None,
            in_flight: 1,
            unauthorized: Some(0),
            automatic_locks: AutomaticLocks::Continue,
        }
    }

    #[test]
    fn the_grants_table_shows_every_grant_and_escapes_what_it_reports() {
        let limited = GrantInfo {
            id: "gfedcba9876543210".into(),
            state: "exhausted".into(),
            requests: 200,
            max_requests: Some(200),
            in_flight: 0,
            automatic_locks: AutomaticLocks::End,
            // Chosen to rewrite the terminal and forge a line of the table.
            command: "sh -c 'x\u{1b}[2J\ng0000000000000000  fake'".into(),
            requester: "\u{1b}[8mhidden".into(),
            ..grant()
        };
        // Every other cell the agent reports, forged too: the entry's
        // identity comes from a group and a title that any program writing
        // the vault file can choose (threat model L9).
        let forged = GrantInfo {
            id: "g\u{1b}[1Afake".into(),
            entry: "AI/evil\u{1b}[2J\u{1b}[1;1Hfake".into(),
            destination: "https://api.example.com\u{202e}moc.live".into(),
            base_path: Some("/v1\u{1b}[2K".into()),
            state: "active\u{1b}[8m".into(),
            started: "2026-11-02\u{200b}T18:00\n".into(),
            ..grant()
        };
        let table = grants_table(&[grant(), limited, forged]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4, "{table}");
        for header in [
            "ID",
            "ENTRY",
            "APPROVED ORIGIN",
            "BASE PATH (NOT A LIMIT)",
            "STATE",
            "STARTED",
            "ENDS IN",
            "REQUESTS",
            "IN FLIGHT",
            "AUTOMATIC LOCKS",
            "REQUESTER",
            "COMMAND",
        ] {
            assert!(lines[0].contains(header), "{header}: {}", lines[0]);
        }
        for cell in [
            "g0123456789abcdef",
            "AI/ANTHROPIC_API_KEY (8d2f6c1e)",
            "https://api.anthropic.com",
            "none",
            "active",
            "2026-11-02T18:00:00-03:00",
            "11h59m",
            "3 (no limit)",
            "continue",
            "rusthorse[4300] ← bash[4242]",
        ] {
            assert!(lines[1].contains(cell), "{cell}: {}", lines[1]);
        }
        assert!(lines[1].ends_with("  claude"), "{}", lines[1]);
        // The base path is in a column of its own, after the origin.
        let origin = lines[1].find("https://api.anthropic.com").expect("origin");
        assert!(lines[1][origin..].find(" none ").is_some(), "{}", lines[1]);
        assert!(lines[3].contains(r"/v1\u{1b}[2K"), "{}", lines[3]);
        for cell in ["gfedcba9876543210", "exhausted", "200 of 200", "end"] {
            assert!(lines[2].contains(cell), "{cell}: {}", lines[2]);
        }
        assert!(
            !table.contains(['\u{1b}', '\u{202e}', '\u{200b}']),
            "{table:?}"
        );
        assert_eq!(table.matches('\n').count(), lines.len(), "{table:?}");
        assert!(
            lines[2].contains(r"\u{1b}[2J\u{a}g0000000000000000"),
            "{}",
            lines[2]
        );
        assert!(lines[2].contains(r"\u{1b}[8mhidden"), "{}", lines[2]);
        for escaped in [
            r"g\u{1b}[1Afake",
            r"AI/evil\u{1b}[2J\u{1b}[1;1Hfake",
            r"https://api.example.com\u{202e}moc.live",
            r"active\u{1b}[8m",
            r"2026-11-02\u{200b}T18:00\u{a}",
        ] {
            assert!(lines[3].contains(escaped), "{escaped}: {}", lines[3]);
        }
        // The columns line up: every cell starts where its header does.
        let at = |line: &str, text: &str| line.find(text).expect(text);
        assert_eq!(at(lines[0], "STATE"), at(lines[1], "active"));
        assert_eq!(at(lines[0], "STATE"), at(lines[2], "exhausted"));
    }

    #[test]
    fn audit_lines_escape_what_any_program_can_write() {
        use rusthorse::audit::AuditEvent;
        use rusthorse::peer::Peer;
        // Records are printed as they always were.
        let lock = AuditEvent::new("lock", &Peer::agent()).outcome("requested");
        assert_eq!(
            audit_line(&lock),
            format!(
                "{}  lock     requested             by {}",
                lock.time, lock.requester
            )
        );
        let mut run = AuditEvent::new("run", &Peer::agent())
            .outcome("allowed_once")
            .entries(vec!["KEY (8d2f6c1e)".into()])
            .detail("exit 0");
        run.argv = Some(vec!["sh".into(), "-c".into(), "echo hi".into()]);
        assert_eq!(
            audit_line(&run),
            format!(
                "{}  run      allowed_once         [KEY (8d2f6c1e)] $ sh -c 'echo hi' (exit 0)  by {}",
                run.time, run.requester
            )
        );
        // Anyone can write to the log: what it holds cannot rewrite the
        // terminal or start a line that looks like another record.
        let mut forged = AuditEvent::new("run", &Peer::agent())
            .outcome("denied")
            .entries(vec!["\u{1b}[8mKEY".into()]);
        forged.argv = Some(vec![
            "sh".into(),
            "-c".into(),
            "x\n2026-11-02T00:00:00-03:00  run allowed_once".into(),
        ]);
        forged.detail = Some("\u{202e}evil".into());
        let line = audit_line(&forged);
        assert!(!line.contains(['\n', '\u{1b}', '\u{202e}']), "{line:?}");
        for escaped in [r"\u{a}2026-11-02", r"\u{1b}[8mKEY", r"\u{202e}evil"] {
            assert!(line.contains(escaped), "{escaped}: {line}");
        }
    }

    #[test]
    fn audit_lines_show_the_brokers_fields() {
        use rusthorse::audit::{AuditEvent, AuditGrant, AuditRequestCounts};
        use rusthorse::peer::Peer;
        let event =
            |action: &str, outcome: &str| AuditEvent::new(action, &Peer::agent()).outcome(outcome);
        let grant_id = "g0123456789abcdef";
        let mut run = event("run", "allowed_once").entries(vec!["AI/KEY (8d2f6c1e)".into()]);
        run.argv = Some(strings(&["claude"]));
        run.grants = Some(vec![AuditGrant {
            id: grant_id.into(),
            entry: "AI/KEY (8d2f6c1e)".into(),
            destination: "https://api.anthropic.com".into(),
            base_path: None,
        }]);
        assert!(audit_line(&run).contains(
            " [AI/KEY (8d2f6c1e)] grants: g0123456789abcdef for AI/KEY (8d2f6c1e) to \
             https://api.anthropic.com; $ claude  by "
        ));
        run.grants = Some(vec![AuditGrant {
            id: grant_id.into(),
            entry: "AI/KEY (8d2f6c1e)".into(),
            destination: "https://api.openai.com".into(),
            base_path: Some("/v1".into()),
        }]);
        assert!(
            audit_line(&run)
                .contains(" to https://api.openai.com (base path /v1, not a limit); $ claude  by ")
        );
        let mut admitted = event("broker_request", "admitted");
        admitted.grant = Some(grant_id.into());
        admitted.request = Some(7);
        admitted.method = Some("POST".into());
        assert!(
            audit_line(&admitted).contains(
                "broker_request admitted             grant g0123456789abcdef #7 POST  by "
            )
        );
        let mut finished = event("broker_request", "completed");
        finished.grant = Some(grant_id.into());
        finished.request = Some(7);
        finished.status = Some(200);
        finished.bytes_sent = Some(1234);
        finished.bytes_received = Some(56_789);
        assert!(audit_line(&finished).contains(
            " grant g0123456789abcdef #7 status 200 (1234 bytes sent, 56789 received)  by "
        ));
        finished.bytes_received = None;
        assert!(audit_line(&finished).contains(" status 200 (1234 bytes sent)  by "));
        finished.bytes_sent = None;
        finished.bytes_received = Some(9);
        assert!(audit_line(&finished).contains(" status 200 (9 bytes received)  by "));
        let mut ended = event("grant", "ended");
        ended.grant = Some(grant_id.into());
        ended.reason = Some("command_ended".into());
        ended.requests = Some(AuditRequestCounts {
            admitted: 3,
            finished: 2,
            unknown: 1,
            refused: 4,
        });
        assert!(audit_line(&ended).contains(
            "grant    ended                grant g0123456789abcdef reason: command_ended \
             requests: 3 admitted (2 finished, 1 unknown), 4 refused  by "
        ));
        // The new fields are escaped like the others.
        let mut forged = event("grant", "ended");
        forged.method = Some("\u{1b}[2K".into());
        forged.reason = Some("x\ny".into());
        let line = audit_line(&forged);
        assert!(!line.contains(['\n', '\u{1b}']), "{line:?}");
        assert!(
            line.contains(r"\u{1b}[2K") && line.contains(r"x\u{a}y"),
            "{line}"
        );
    }

    /// A status of an agent that reports `broker` (or not) and runs
    /// `executable`.
    fn status_with(broker: Option<&str>, executable: &str) -> StatusInfo {
        StatusInfo {
            protocol_version: rusthorse::protocol::PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            vault: "/nonexistent".into(),
            vault_exists: false,
            audit_log: String::new(),
            locked: true,
            idle_timeout_secs: 0,
            locks_in_secs: None,
            remembered_approvals: 0,
            agent_executable: executable.into(),
            agent_executable_id: None,
            agent_executable_replaced: None,
            dialogs: None,
            lock_triggers: vec![],
            broker: broker.map(Into::into),
            grants: None,
            settings: None,
        }
    }

    /// `broker_check`, again while the program was just written: another
    /// thread's child may hold it open for writing until its exec ("Text
    /// file busy").
    fn broker_check_of(info: &StatusInfo) -> BrokerProgram {
        for _ in 0..50 {
            match broker_check(Some(info)) {
                BrokerProgram {
                    check: Check::Fail(m),
                    ..
                } if m.contains("Text file busy") => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                other => return other,
            }
        }
        panic!("the program stayed busy")
    }

    /// The text of a line of `doctor`.
    fn check_text(check: &Check) -> &str {
        match check {
            Check::Ok(m) | Check::Warn(m) | Check::Fail(m) => m,
        }
    }

    #[test]
    fn doctor_checks_the_broker_program_the_agent_uses() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join(rusthorse::broker_protocol::PROGRAM);
        let path = program.to_str().expect("utf8").to_string();
        let agent = dir
            .path()
            .join("rusthorse")
            .to_str()
            .expect("utf8")
            .to_string();
        let write = |version: &str, protocol: u32, mode: u32| {
            std::fs::write(
                &program,
                format!(
                    "#!/bin/sh\necho '{{\"version\":\"{version}\",\"protocol\":{protocol}}}'\n"
                ),
            )
            .expect("write");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        let ours = env!("CARGO_PKG_VERSION");
        let protocol = rusthorse::broker_protocol::VERSION;

        // Nothing next to an agent that does not report it, or that says it
        // cannot use one: not installed, a warning.
        for reported in [None, Some("none: it is not installed")] {
            let found = broker_check_of(&status_with(reported, &agent));
            assert!(!found.installed, "{reported:?}");
            assert!(
                matches!(&found.check, Check::Warn(m) if m.contains("is not installed") && m.contains(NO_GRANTS)),
                "{reported:?}: {}",
                check_text(&found.check)
            );
        }
        // The program the agent reports, of this version and protocol.
        write(ours, protocol, 0o700);
        let found = broker_check_of(&status_with(Some(&path), ""));
        assert!(found.installed);
        assert!(
            matches!(&found.check, Check::Ok(m) if m == &format!("broker: rusthorse-broker {ours} ({path})")),
            "{}",
            check_text(&found.check)
        );
        // Found next to an agent that predates the field.
        let found = broker_check_of(&status_with(None, &format!("{agent} (deleted)")));
        assert!(found.installed && matches!(found.check, Check::Ok(_)));
        // Of another version, or another protocol: an error.
        for (version, protocol) in [("0.0.0-other", protocol), (ours, protocol + 1)] {
            write(version, protocol, 0o700);
            let found = broker_check_of(&status_with(Some(&path), ""));
            assert!(found.installed);
            assert!(
                matches!(&found.check, Check::Fail(m) if m.contains("install the same version of both") && m.contains(NO_GRANTS)),
                "{version} {protocol}: {}",
                check_text(&found.check)
            );
        }
        // Unusable: what the agent says, or what is found next to it.
        write(ours, protocol, 0o770);
        let found = broker_check_of(&status_with(
            Some("none: it can be modified by others"),
            &agent,
        ));
        assert!(found.installed);
        assert!(
            matches!(&found.check, Check::Fail(m) if m == &format!("{NO_GRANTS}: it can be modified by others")),
            "{}",
            check_text(&found.check)
        );
        let found = broker_check_of(&status_with(None, &agent));
        assert!(found.installed);
        assert!(
            matches!(&found.check, Check::Fail(m) if m.contains("can be modified by its group or by others")),
            "{}",
            check_text(&found.check)
        );
        // One that does not run.
        std::fs::write(&program, "#!/bin/sh\nexit 3\n").expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let found = broker_check_of(&status_with(Some(&path), ""));
        assert!(found.installed);
        assert!(
            matches!(&found.check, Check::Fail(m) if m.contains("does not run") && m.contains(NO_GRANTS)),
            "{}",
            check_text(&found.check)
        );
        // An agent that does not say which program file it runs.
        let found = broker_check(Some(&status_with(None, "")));
        assert!(found.installed, "not known to be missing");
        assert!(matches!(&found.check, Check::Warn(m) if m.contains("cannot tell")));
    }

    #[test]
    fn doctor_says_which_certificate_file_the_broker_trusts_or_why_none() {
        let path = "/etc/ssl/certs/ca-certificates.crt";
        // The file's checks pass; what is in it only a broker reads, so the
        // line says where it reads from, not that what it reads is usable.
        for installed in [true, false] {
            let check = ca_file_check(Ok(PathBuf::from(path)), installed);
            assert!(
                matches!(&check, Check::Ok(m) if m == &format!(
                    "the broker reads its certificate authorities from {path}, which only root \
                     can change; it reads the certificates themselves when a grant starts"
                )),
                "{}",
                check_text(&check)
            );
        }
        for why in [
            "none of the certificate authority files exists: /a, /b, /c",
            "/etc/ssl/certs/ca-certificates.crt is not owned by root",
            "/x/ca.crt is in /x, which can be modified by its group or by others",
        ] {
            let says = |m: &str| m.starts_with(why) && m.contains(NO_GRANTS) && m.contains(path);
            // An error where the broker is installed; without its program,
            // a warning: everything else works.
            let check = ca_file_check(Err(why.into()), true);
            assert!(matches!(&check, Check::Fail(m) if says(m)), "{why}");
            let check = ca_file_check(Err(why.into()), false);
            assert!(matches!(&check, Check::Warn(m) if says(m)), "{why}");
        }
        // This computer's, whatever it is: a check, never a panic.
        let _ = ca_file_check(
            rusthorse::broker_protocol::open_ca_file().map(|ca| ca.path),
            true,
        );
    }

    /// Where a command line of the AI guide is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shown {
        /// In inline code in the prose: it may be a mention of a command
        /// (`rusthorse reveal`), without the arguments it needs.
        Inline,
        /// In a code block: an example to run, which must be complete.
        Block,
    }

    /// The `rusthorse …` command lines of the AI guide, each cut at the end
    /// of its code span or line: inline code in the prose (whose lines are
    /// joined first, as Markdown does), and the lines of code blocks (a line
    /// that ends with `\` continued by the next, as the shell does).
    fn guide_command_lines(guide: &str) -> Vec<(String, Shown)> {
        fn collect(text: &str, ends: &[char], shown: Shown, into: &mut Vec<(String, Shown)>) {
            for (at, _) in text.match_indices("rusthorse ") {
                let before = text[..at].chars().next_back();
                if before.is_some_and(|c| c.is_alphanumeric() || "-_/".contains(c)) {
                    continue;
                }
                let rest = &text[at + "rusthorse ".len()..];
                let end = rest.find(ends).unwrap_or(rest.len());
                into.push((rest[..end].to_string(), shown));
            }
        }
        let mut lines = Vec::new();
        let mut prose = String::new();
        let mut fenced = false;
        let mut continued = String::new();
        for line in guide.lines() {
            if line.trim_start().starts_with("```") {
                assert!(continued.is_empty(), "a code block ends with `\\`");
                fenced = !fenced;
                prose.push('\n');
            } else if fenced {
                match line.strip_suffix('\\') {
                    Some(start) => continued.push_str(start),
                    None => {
                        continued.push_str(line);
                        collect(&continued, &['\n'], Shown::Block, &mut lines);
                        continued.clear();
                    }
                }
            } else {
                prose.push_str(line);
                prose.push(' ');
            }
        }
        assert!(!fenced, "a code block of the guide is not closed");
        collect(&prose, &['`', '\n'], Shown::Inline, &mut lines);
        lines
    }

    /// The words of a command line as `sh` splits them: quotes removed, a
    /// `#` at the start of a word starting a comment, redirections (`>file`,
    /// `2>&1`) left out, and the command ending at an unquoted `|`, `;` or
    /// `&` (a pipe, a list).
    fn shell_words(line: &str) -> Vec<String> {
        /// End the word being read: an argument, or the target of a
        /// redirection, which is none.
        fn end(words: &mut Vec<String>, word: &mut String, in_word: &mut bool, target: &mut bool) {
            if *in_word {
                let done = std::mem::take(word);
                if *target {
                    *target = false;
                } else {
                    words.push(done);
                }
                *in_word = false;
            }
        }
        let mut words = Vec::new();
        let mut word = String::new();
        let mut in_word = false;
        // Whether a part of the word was quoted: `'2'>x` is an argument.
        let mut quoted = false;
        let mut target = false;
        let mut quote = None;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (Some(_), c) => word.push(c),
                (None, '\'' | '"') => {
                    quote = Some(c);
                    in_word = true;
                    quoted = true;
                }
                (None, c) if c.is_whitespace() => {
                    end(&mut words, &mut word, &mut in_word, &mut target);
                    quoted = false;
                }
                (None, '#') if !in_word => break,
                (None, '<' | '>') => {
                    // The descriptor number before it (`2>`) is no argument.
                    if in_word && !quoted && !target && word.chars().all(|c| c.is_ascii_digit()) {
                        word.clear();
                        in_word = false;
                    } else {
                        end(&mut words, &mut word, &mut in_word, &mut target);
                    }
                    quoted = false;
                    while let Some('<' | '>' | '&') = chars.peek() {
                        chars.next();
                    }
                    target = true;
                }
                (None, '|' | ';' | '&') => break,
                (None, c) => {
                    word.push(c);
                    in_word = true;
                }
            }
        }
        assert!(quote.is_none(), "a quote is not closed in {line:?}");
        end(&mut words, &mut word, &mut in_word, &mut target);
        assert!(!target, "a redirection without a target in {line:?}");
        words
    }

    /// The mentions of a command in the AI guide's prose that leave out
    /// arguments it needs; any other command line must be complete.
    const GUIDE_MENTIONS: &[&str] = &["run", "reveal", "add --stdin", "edit --stdin"];

    /// Whether the CLI accepts a command line of the AI guide. It must be
    /// complete, except a mention listed in [`GUIDE_MENTIONS`] in inline
    /// code, and a line asking for help, which is checked without its
    /// `--help` or `-h` (clap stops reading there).
    fn guide_line_accepted(line: &str, shown: Shown) -> Result<(), String> {
        use clap::error::ErrorKind;
        let words = shell_words(line);
        let end = words.iter().position(|w| w == "--").unwrap_or(words.len());
        let (help, words): (Vec<_>, Vec<_>) = words
            .into_iter()
            .enumerate()
            .partition(|(i, w)| *i < end && matches!(w.as_str(), "--help" | "-h"));
        let words: Vec<String> = words.into_iter().map(|(_, w)| w).collect();
        let mention = shown == Shown::Inline && GUIDE_MENTIONS.contains(&words.join(" ").as_str());
        let argv = std::iter::once("rusthorse".to_string()).chain(words);
        match Cli::try_parse_from(argv) {
            Ok(_) => Ok(()),
            Err(e)
                if e.kind() == ErrorKind::MissingRequiredArgument
                    && (mention || !help.is_empty()) =>
            {
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Every command line the AI guide shows is one the CLI accepts, with
    /// its options and their values: the guide is built into the binary, and
    /// an AI agent follows it to the letter.
    #[test]
    fn the_ai_guide_shows_only_command_lines_the_cli_accepts() {
        let guide = GuideTopic::Ai.text();
        let lines = guide_command_lines(&guide);
        for (line, shown) in &lines {
            if let Err(e) = guide_line_accepted(line, *shown) {
                panic!("`rusthorse {line}` ({shown:?}):\n{e}");
            }
        }
        // The scan found the commands: a broken scan checks nothing.
        let blocks = lines.iter().filter(|(_, s)| *s == Shown::Block).count();
        assert!(
            lines.len() > 30 && blocks > 15,
            "{} lines, {blocks} in code blocks",
            lines.len()
        );
        // It reads inline code across a line break and a code-block line
        // continued with `\`, and stops a code-block line at its comment.
        let found = guide_command_lines(
            "a `rusthorse list\n  --json` b\n```\nrusthorse ls # x\nrusthorse list \\\n  --tag t\n```",
        );
        let found: Vec<_> = found.iter().map(|(l, s)| (shell_words(l), *s)).collect();
        assert_eq!(
            found,
            [
                (vec!["ls".to_string()], Shown::Block),
                (
                    vec!["list".into(), "--tag".into(), "t".into()],
                    Shown::Block
                ),
                (vec!["list".into(), "--json".into()], Shown::Inline),
            ]
        );
        assert_eq!(
            shell_words(r#"run T=x -- sh -c 'a "$T" | b' # c"#),
            ["run", "T=x", "--", "sh", "-c", r#"a "$T" | b"#]
        );
        assert_eq!(shell_words("show ';' --json | jq"), ["show", ";", "--json"]);
        // A listed mention may leave arguments out; nothing else may, and
        // nothing may be wrong.
        assert!(guide_line_accepted("reveal", Shown::Inline).is_ok());
        assert!(guide_line_accepted("run --help", Shown::Inline).is_ok());
        assert!(guide_line_accepted("run -h", Shown::Block).is_ok());
        assert!(guide_line_accepted("--socket /tmp/x.sock list", Shown::Block).is_ok());
        assert!(guide_line_accepted("list 2>&1 >/dev/null --json", Shown::Block).is_ok());
        for (wrong, shown) in [
            ("reveal", Shown::Block),
            ("show", Shown::Inline),
            (
                "add --generate --length 48 --alphabet symbols",
                Shown::Inline,
            ),
            ("add --kind server --host db.lan --generate", Shown::Block),
            ("show ';' --kind api-key", Shown::Inline),
            ("list >/dev/null --kind invented", Shown::Block),
            ("list '2'>/dev/null", Shown::Block),
            ("list --help --kind invented", Shown::Inline),
            ("list -h --kind invented", Shown::Inline),
            ("guide nope", Shown::Inline),
            ("list --definitely-not-an-option", Shown::Inline),
            ("add N --generate --length nope", Shown::Block),
            ("add N --generate --alphabet invented", Shown::Block),
            ("add --stdin --bogus", Shown::Inline),
            ("import nope", Shown::Inline),
        ] {
            assert!(
                guide_line_accepted(wrong, shown).is_err(),
                "{wrong:?} ({shown:?})"
            );
        }
        assert_eq!(shell_words("x 2> err >>out y 2>&1 z"), ["x", "y", "z"]);
        // Every listed mention is in the guide: the list does not grow stale.
        for mention in GUIDE_MENTIONS {
            assert!(
                lines
                    .iter()
                    .any(|(l, s)| *s == Shown::Inline && shell_words(l).join(" ") == *mention),
                "{mention}"
            );
        }
    }

    /// An option the AI guide names alone (`--no-redact`) belongs to some
    /// command.
    #[test]
    fn the_ai_guide_names_only_real_options() {
        fn longs(command: &clap::Command, into: &mut Vec<String>) {
            for arg in command.get_arguments() {
                into.extend(arg.get_long().map(str::to_string));
            }
            for sub in command.get_subcommands() {
                longs(sub, into);
            }
        }
        let mut cli = Cli::command();
        cli.build();
        let mut all = Vec::new();
        longs(&cli, &mut all);
        let guide = GuideTopic::Ai.text();
        let alone: Vec<_> = guide
            .split('`')
            .skip(1)
            .step_by(2)
            .filter_map(|span| span.strip_prefix("--"))
            .map(|span| span.split([' ', '=']).next().expect("split"))
            .collect();
        assert!(alone.len() > 5, "{alone:?}");
        for long in alone {
            assert!(all.iter().any(|a| a == long), "--{long} is no option");
        }
    }

    /// The facts of the AI guide that tests cannot draw from its commands:
    /// the kinds, the exit statuses and the JSON fields it names.
    #[test]
    fn the_ai_guide_lists_the_real_kinds_statuses_and_fields() {
        let guide = GuideTopic::Ai.text();
        assert!(guide.contains(env!("CARGO_PKG_VERSION")));
        // No placeholder (`@VERSION@`) is left; the `@` of `--broker
        // VAR=NAME@URL` is no placeholder.
        let placeholder = guide.split('@').skip(1).any(|part| {
            let word: String = part
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            !word.is_empty() && part[word.len()..].starts_with('@')
        });
        assert!(!placeholder, "a placeholder is left in the guide");
        // Every kind, and nothing else.
        let kinds = guide
            .lines()
            .find_map(|l| l.split_once("# kinds: ").map(|(_, k)| k))
            .expect("the guide lists the kinds");
        let real: Vec<_> = KindArg::value_variants()
            .iter()
            .map(|k| k.to_possible_value().expect("value").get_name().to_string())
            .collect();
        assert_eq!(kinds.split(", ").collect::<Vec<_>>(), real);
        // The exit statuses: exactly the rows of each table. An invalid
        // command line is clap's usage error.
        // Every data row of the table in `section`: its first cell must be
        // a status in backquotes.
        fn statuses(section: &str) -> Vec<u8> {
            let rows: Vec<_> = section.lines().filter(|l| l.starts_with('|')).collect();
            assert!(rows.len() > 2 && rows[1].starts_with("|---"), "{section}");
            rows[2..]
                .iter()
                .map(|row| {
                    let cell = row.split('|').nth(1).expect("a cell").trim();
                    cell.strip_prefix('`')
                        .and_then(|c| c.strip_suffix('`'))
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_else(|| panic!("not a status: {row}"))
                })
                .collect()
        }
        let section = |from: &str, to: &str| {
            let start = guide.find(from).expect("section") + from.len();
            let rest = &guide[start..];
            rest[..rest.find(to).expect("section end")].to_string()
        };
        let run = section("### `rusthorse run`", "### Other commands");
        let other = section("### Other commands", "\n## ");
        assert_eq!(statuses(&run), [EXIT_RUN_FAILURE, EXIT_UNKNOWN, 2, 141]);
        assert_eq!(statuses(&other), [0, 1, 2, EXIT_DENIED, EXIT_UNKNOWN]);
        let usage = Cli::try_parse_from(["rusthorse", "run", "--bogus"]).err();
        assert_eq!(usage.expect("error").exit_code(), 2);
        // The JSON fields it names are fields of `list --json`.
        let info = EntryInfo {
            id: "id".into(),
            name: "n".into(),
            group: Some("g".into()),
            fields: EntryFields {
                kind: Some(EntryKind::Device),
                username: Some("u".into()),
                url: Some("https://x/".into()),
                host: Some("h".into()),
                port: Some(1),
                tags: vec!["t".into()],
            },
            protected_fields: vec!["UserName".into()],
            has_password: true,
            has_notes: true,
            other_fields: vec!["f".into()],
            modified: Some("2026-01-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&info).expect("json");
        let sentence = guide
            .split("The JSON objects have ")
            .nth(1)
            .and_then(|s| s.split('.').next())
            .expect("the guide names the JSON fields");
        let mut named: Vec<_> = sentence.split('`').skip(1).step_by(2).collect();
        assert!(named.len() >= 10, "{named:?}");
        assert!(guide.contains("`protected_fields`"));
        named.push("protected_fields");
        for field in &named {
            assert!(
                json.get(field).is_some(),
                "`{field}` is not a field of list --json"
            );
        }
        // "Fields without a value are left out."
        assert!(guide.contains("Fields without a value are left out."));
        let bare = EntryInfo {
            group: None,
            fields: EntryFields::default(),
            protected_fields: Vec::new(),
            other_fields: Vec::new(),
            modified: None,
            ..info
        };
        let json = serde_json::to_value(&bare).expect("json");
        for field in named {
            let always = ["id", "name", "has_password", "has_notes"].contains(&field);
            assert_eq!(json.get(field).is_some(), always, "{field}");
        }
    }
}
