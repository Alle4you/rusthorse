//! The wire protocol between clients and the agent.
//!
//! Each connection carries exactly one request and its response. A message is
//! a *frame*: a 4-byte big-endian length followed by that many bytes of JSON.
//! A [`Request::Run`] or [`Request::BrokerRun`] frame additionally carries
//! the client's stdin, stdout and stderr (when output is not redacted) as
//! `SCM_RIGHTS` ancillary data attached to its first byte.
//!
//! The full specification, with examples, is in `docs/protocol.md`.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use crate::broker_profile::{AutomaticLocks, BrokerProfile, Preset, ProfileRequest};

/// Protocol version spoken by this build. Bumped on incompatible changes.
///
/// 2: data frames, per-channel credit (stdin credit granted when the
/// command starts), `generate`, `change_password`, `backup`, `reveal.notes`,
/// `status.audit_log`.
///
/// 3: every error other than `outcome_unknown` is definite (the vault file
/// was not changed and no command was started), which clients rely on;
/// `status.agent_executable`, `status.agent_executable_id`,
/// `status.agent_executable_replaced`.
///
/// 4: `reveal.purpose`.
///
/// 5: the entry `kind` (in entries, `edit.kind`, and `kind` in
/// `edit.clear`). A version-4 agent would drop it without a word.
///
/// 6: `create_vault`, and `already_exists` also for the vault file;
/// `keyring_items`, `dotenv_names` and `import_from`.
///
/// 7: `edit.group` moves an entry to another group. A version-6 agent would
/// drop it without a word and report the edit done.
///
/// 8: the credential broker (ADR 0013): the `broker_run` and `broker_edit`
/// requests, the entry's `broker` profile, the `grants` and `revoke_grant`
/// requests and the `grants` response, `status.broker` and `status.grants`.
/// A run with broker bindings and an edit that sets or clears a profile are
/// requests of their own, not fields of `run` and `edit`: a version-7 agent
/// met after the version check (restarted between two connections) refuses
/// them whole, where it would drop the bindings or the profile without a
/// word and act on the rest.
pub const PROTOCOL_VERSION: u32 = 8;

// Clients trust that errors other than `outcome_unknown` mean nothing changed
// (version 3 and later, N31), and that an approval for `reveal.purpose` says
// what the manager does (version 4; builds that reported 3 promised a single
// paste for `copy`), that the agent keeps an entry's `kind` (version 5), and
// that it understands broker bindings and profiles (version 8). The version
// must never go back below 8.
const _: () = assert!(PROTOCOL_VERSION >= 8);

/// Largest accepted frame body, in bytes.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

/// Most file descriptors a frame may carry (stdin, stdout, stderr).
pub const MAX_FDS: usize = 3;

/// The kernel's limit on descriptors per `SCM_RIGHTS` message.
const SCM_MAX_FD: usize = 253;

/// Set in a frame's length word to mark a *data* frame (see [`send_data`]).
pub const DATA_FLAG: u32 = 0x8000_0000;

/// Largest payload of one data frame, in bytes.
pub const MAX_DATA_LEN: usize = 64 * 1024;

/// Data channel: the command's standard input (client → agent). An empty
/// data frame on this channel means end of input.
pub const STDIN: u8 = 0;
/// Data channel: the command's standard output (agent → client).
pub const STDOUT: u8 = 1;
/// Data channel: the command's standard error (agent → client).
pub const STDERR: u8 = 2;

/// Flow-control channel (agent → client): the payload is a big-endian `u32`
/// number of bytes of [`STDIN`] data the agent has delivered to the command
/// and is ready to receive again.
pub const CREDIT_STDIN: u8 = 0x80;
/// Flow-control channel (client → agent): the payload is a big-endian `u32`
/// number of bytes of [`STDOUT`] data the client has written out and is ready
/// to receive again.
pub const CREDIT_STDOUT: u8 = 0x81;
/// Flow-control channel (client → agent) for [`STDERR`]; see [`CREDIT_STDOUT`].
pub const CREDIT_STDERR: u8 = 0x82;

/// How much data may be in flight on each channel before the receiver grants
/// more credit: the agent's output channels, and the client's stdin. Each
/// channel has its own window, so a client whose stdout is stuck still
/// receives stderr, and input waiting for the command never stops the agent
/// from reading control frames.
pub const INITIAL_CREDIT: usize = 1024 * 1024;

/// A string holding secret material; its heap buffer is wiped on drop.
pub type SecretString = Zeroizing<String>;

/// A request from a client to the agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Report the agent's state. Never needs the vault to be unlocked.
    Status,
    /// Unlock the vault (the agent asks the human for the master password).
    Unlock,
    /// Create the vault file, which must not exist yet, at the agent's vault
    /// path. The agent asks the human for the new master password (twice) in
    /// its own dialogs; the new vault is left unlocked.
    CreateVault,
    /// Lock the vault and forget remembered approvals.
    Lock,
    /// List entries (metadata only).
    List,
    /// Show one entry's metadata.
    Show {
        /// Entry name or `Group/Name` path.
        name: String,
    },
    /// Create an entry, or replace one when `replace` is set.
    Add {
        /// The new entry's metadata.
        entry: NewEntry,
        /// The secret value. `None` makes the agent ask the human for it in a
        /// dialog (or generate it, with `generate`); `Some` (value supplied
        /// by the client) requires approval.
        value: Option<SecretString>,
        /// Generate the value in the agent instead (requires approval). Not
        /// allowed together with `value`.
        #[serde(default)]
        generate: Option<crate::generate::Spec>,
        /// Overwrite an existing entry with the same name.
        replace: bool,
    },
    /// Create many entries at once (one approval for the whole batch).
    Import {
        /// Entries and their values.
        entries: Vec<ImportedEntry>,
        /// Overwrite existing entries with the same names.
        replace: bool,
    },
    /// Change an entry (requires approval). An edit that sets or clears the
    /// broker profile ([`EntryChanges::touches_broker`]) is a
    /// [`Request::BrokerEdit`]; the agent refuses it as an `edit`.
    Edit {
        /// Entry name or `Group/Name` path.
        name: String,
        /// What to change.
        changes: EntryChanges,
    },
    /// Delete an entry (requires approval).
    Remove {
        /// Entry name or `Group/Name` path.
        name: String,
    },
    /// Change the master password. The agent asks for the current one and
    /// the new one (twice) in its own dialogs.
    ChangePassword,
    /// Return an entry's password — or its notes — to the client (requires
    /// approval).
    Reveal {
        /// Entry name or `Group/Name` path.
        name: String,
        /// Return the notes instead of the password.
        #[serde(default)]
        notes: bool,
        /// What the client says it will do with the value, so that the
        /// approval dialog and the audit log can say it. The agent cannot
        /// enforce it. Absent: the client prints it (`rusthorse reveal`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<RevealPurpose>,
    },
    /// Copy the (encrypted) vault file to `path` and check that the copy
    /// opens with the current master password.
    Backup {
        /// Absolute destination path; must not exist.
        path: String,
    },
    /// Run a command with secrets in its environment (requires approval).
    /// A run with broker bindings is a [`Request::BrokerRun`]: a `run` that
    /// carries them (a non-empty `brokered` list) does not parse, so it is
    /// refused rather than run without them.
    #[serde(deserialize_with = "plain_run")]
    Run(RunRequest),
    /// The metadata of the items of GNOME Keyring (any Secret Service), to
    /// choose what to import (requires approval: the requester learns their
    /// labels and attributes). No secret is read.
    KeyringItems,
    /// The names of the variables in a `.env` file, to choose what to import
    /// (requires approval: the requester learns them). The agent reads the
    /// file and drops the values at once.
    DotenvNames {
        /// Absolute path of the file.
        path: String,
    },
    /// Import secrets that the agent reads itself, from GNOME Keyring or a
    /// `.env` file (requires approval). The values never pass through the
    /// client.
    ImportFrom {
        /// Where the values are, and the names to give them.
        source: ImportSource,
        /// Tags of every new entry.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tags: Vec<String>,
        /// Overwrite existing entries with the same names.
        #[serde(default)]
        replace: bool,
    },
    /// Run a command with secrets in its environment, some or all of them
    /// through the credential broker (requires approval, ADR 0013): for
    /// each broker binding the command gets the token of a grant, never the
    /// entry's value. It carries descriptors as [`Request::Run`] does. A
    /// request of its own, so that an agent of protocol 7 refuses it whole.
    /// Since protocol 8.
    BrokerRun(BrokerRunRequest),
    /// Change an entry and its broker profile (requires approval, ADR
    /// 0013): an edit that sets or clears the profile, with or without other
    /// changes. A request of its own, so that an agent of protocol 7 refuses
    /// it whole rather than apply the other changes and drop the profile.
    /// Since protocol 8.
    BrokerEdit {
        /// Entry name or `Group/Name` path.
        name: String,
        /// What to change, the profile included.
        changes: EntryChanges,
    },
    /// List the grants of the credential broker (ADR 0013); never a token.
    /// Needs no approval.
    Grants,
    /// End grants of the credential broker. Needs no approval, like
    /// [`Request::Lock`]: it only takes away.
    RevokeGrant {
        /// The grant's ID; `None` ends every grant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

/// Where [`Request::ImportFrom`] reads the values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    /// Items of GNOME Keyring (any Secret Service).
    Keyring {
        /// The items, and the entry name for each.
        items: Vec<KeyringPick>,
    },
    /// Lines of a `.env` file.
    Dotenv {
        /// Absolute path of the file.
        path: String,
        /// Prepended (upper-cased) to each variable's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        /// The entries to import: variable names with the prefix.
        names: Vec<String>,
    },
}

/// One keyring item to import, and the entry name to give it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringPick {
    /// The item's D-Bus object path ([`KeyringItem::id`]).
    pub id: String,
    /// The entry name.
    pub name: String,
}

/// An item of GNOME Keyring (any Secret Service): its metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringItem {
    /// The item's D-Bus object path.
    pub id: String,
    /// Its label (what Passwords and Keys shows).
    pub label: String,
    /// Its attributes (the keys that programs look it up by).
    pub attributes: std::collections::BTreeMap<String, String>,
    /// Whether it is locked: its secret cannot be read until the keyring is
    /// unlocked.
    pub locked: bool,
}

/// What a client says it will do with a revealed value
/// ([`Request::Reveal`]). Stated by the client, not verified by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealPurpose {
    /// Display it in the client's own window for a short time, from where
    /// the human may copy it.
    Show,
    /// Put it on the clipboard, where it stays until something else is
    /// copied (and where clipboard histories may keep it).
    Copy,
}

impl Request {
    /// Whether the request can have an effect that outlasts it — a change to
    /// the vault, a backup file, a command. When such a request gets no
    /// answer, the client cannot tell whether it took effect.
    pub fn has_effects(&self) -> bool {
        match self {
            Request::Status
            | Request::Unlock
            | Request::Lock
            | Request::List
            | Request::Show { .. }
            | Request::Reveal { .. } => false,
            Request::Add { .. }
            | Request::Import { .. }
            | Request::Edit { .. }
            | Request::Remove { .. }
            | Request::ChangePassword
            | Request::CreateVault
            | Request::Backup { .. }
            | Request::ImportFrom { .. }
            | Request::Run(_)
            | Request::BrokerRun(_)
            | Request::BrokerEdit { .. } => true,
            Request::KeyringItems | Request::DotenvNames { .. } => false,
            // Like `lock`: ending a grant twice does no harm.
            Request::Grants | Request::RevokeGrant { .. } => false,
        }
    }
}

/// What an entry is for. It decides which fields a form offers and how they
/// are labelled (the URL of an API key is its endpoint); it never hides a
/// field that has a value, and it grants or restricts nothing.
///
/// Stored in the KDBX custom field `Kind` as [`EntryKind::as_str`]. An entry
/// without one is of no particular kind ("Other": every field is offered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    /// A key or token for an API; its URL is the API's endpoint.
    ApiKey,
    /// A sign-in to a website or web console: username and URL.
    Login,
    /// A server reached by host and port, e.g. over SSH or a database.
    Server,
    /// A device such as a router or a camera: host, admin page, username.
    Device,
}

impl EntryKind {
    /// Every kind, in the order forms offer them.
    pub const ALL: [EntryKind; 4] = [Self::ApiKey, Self::Login, Self::Server, Self::Device];

    /// The stored and serialized form: `api-key`, `login`, `server`, `device`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api-key",
            Self::Login => "login",
            Self::Server => "server",
            Self::Device => "device",
        }
    }

    /// The kind stored as `text`; `None` for anything else (surrounding
    /// spaces and case are forgiven, as a person may have typed it).
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        Self::ALL
            .into_iter()
            .find(|k| k.as_str().eq_ignore_ascii_case(text))
    }

    /// A short name for people: "API key", "Website login", …
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::Login => "Website login",
            Self::Server => "Server",
            Self::Device => "Device",
        }
    }

    /// What the KeePass `URL` field means for this kind.
    pub fn url_label(kind: Option<Self>) -> &'static str {
        match kind {
            Some(Self::ApiKey) => "Endpoint URL",
            Some(Self::Device) => "Admin page",
            _ => "URL",
        }
    }
}

/// Entry metadata that clients may read without approval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFields {
    /// What the entry is for; `None` for no particular kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EntryKind>,
    /// Login name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Access link, e.g. `https://router.lan/` or `ssh://admin@10.0.0.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Host name or IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// TCP/UDP port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Free-form tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// A new entry, as sent by `add` and `import`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewEntry {
    /// Entry name (the KeePass title). Must be unique in the vault.
    pub name: String,
    /// Group path such as `Work/Servers`; `None` means the root group.
    #[serde(default)]
    pub group: Option<String>,
    /// Non-secret metadata.
    #[serde(default)]
    pub fields: EntryFields,
    /// Notes. Stored protected and never returned without approval.
    #[serde(default)]
    pub notes: Option<String>,
}

/// One entry of an [`Request::Import`] batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportedEntry {
    /// The entry.
    pub entry: NewEntry,
    /// Its secret value.
    pub value: SecretString,
}

/// A field that [`EntryChanges::clear`] can remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The login name.
    Username,
    /// The access link.
    Url,
    /// The host name or IP address.
    Host,
    /// The port.
    Port,
    /// The notes.
    Notes,
    /// The kind (the entry becomes of no particular kind).
    Kind,
    /// The broker profile (the entry can no longer be used through the
    /// credential broker); only in a [`Request::BrokerEdit`].
    Broker,
}

/// How an edit changes the secret value.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueChange {
    /// The agent asks the human for the new value in a dialog.
    Prompt,
    /// The client supplies the new value.
    Provided(SecretString),
    /// The agent generates the new value.
    Generate(crate::generate::Spec),
}

/// The changes requested by [`Request::Edit`] and [`Request::BrokerEdit`].
/// Unset fields stay as they are.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EntryChanges {
    /// New entry name.
    #[serde(default)]
    pub rename: Option<String>,
    /// New login name.
    #[serde(default)]
    pub username: Option<String>,
    /// New access link.
    #[serde(default)]
    pub url: Option<String>,
    /// New host name or IP address.
    #[serde(default)]
    pub host: Option<String>,
    /// New port.
    #[serde(default)]
    pub port: Option<u16>,
    /// New kind (to remove it, put [`Field::Kind`] in `clear`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EntryKind>,
    /// Group to move the entry to, as a path (`Work/Servers`), created if
    /// missing; an empty path (or `/`) is the top level. Since protocol 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// New notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// Fields to remove.
    #[serde(default)]
    pub clear: Vec<Field>,
    /// Tags to add.
    #[serde(default)]
    pub add_tags: Vec<String>,
    /// Tags to remove.
    #[serde(default)]
    pub remove_tags: Vec<String>,
    /// New secret value.
    #[serde(default)]
    pub value: Option<ValueChange>,
    /// New broker profile (ADR 0013), from the defaults of the latest
    /// revision of its preset (to remove it, put [`Field::Broker`] in
    /// `clear`); only in a [`Request::BrokerEdit`]. Since protocol 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<ProfileRequest>,
}

impl EntryChanges {
    /// Whether the edit sets or clears the broker profile: such an edit is
    /// a [`Request::BrokerEdit`], and the agent refuses it as a
    /// [`Request::Edit`].
    pub fn touches_broker(&self) -> bool {
        self.broker.is_some() || self.clear.contains(&Field::Broker)
    }

    /// Whether anything other than the secret value would change.
    pub fn touches_metadata(&self) -> bool {
        self.rename.is_some()
            || self.username.is_some()
            || self.url.is_some()
            || self.host.is_some()
            || self.port.is_some()
            || self.kind.is_some()
            || self.broker.is_some()
            || self.group.is_some()
            || self.notes.is_some()
            || !self.clear.is_empty()
            || !self.add_tags.is_empty()
            || !self.remove_tags.is_empty()
    }

    /// Whether the request changes nothing at all.
    pub fn is_empty(&self) -> bool {
        !self.touches_metadata() && self.value.is_none()
    }
}

/// What clients may learn about an entry without approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// The entry's KeePass UUID; stable across renames.
    pub id: String,
    /// Entry name.
    pub name: String,
    /// Group path, `None` for the root group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Non-secret metadata.
    #[serde(flatten)]
    pub fields: EntryFields,
    /// Metadata fields that the KeePass file marks as protected; their values
    /// are withheld like secrets (e.g. `UserName`, `URL`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<String>,
    /// Whether the entry has a non-empty password.
    pub has_password: bool,
    /// Whether the entry has notes (their content is not disclosed).
    pub has_notes: bool,
    /// Names of other fields (their values are not disclosed). An unusable
    /// broker profile is listed here, by its field's name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_fields: Vec<String>,
    /// Last modification time, RFC 3339 in UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// The entry's broker profile (ADR 0013), when it has a usable one: a
    /// protected profile is in `protected_fields`, an unusable one in
    /// `other_fields`. Since protocol 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<BrokerProfile>,
}

impl EntryInfo {
    /// How dialogs and the audit log identify the entry: its full path and
    /// the start of its UUID, e.g. `Production/API_KEY (8d2f6c1e)`. Two entries
    /// with the same title in different groups do not look the same, unless
    /// a file written by another program gave them UUIDs that start alike
    /// (threat model L9).
    pub fn identity(&self) -> String {
        let short: String = self.id.chars().take(8).collect();
        match &self.group {
            Some(group) => format!("{group}/{} ({short})", self.name),
            None => format!("{} ({short})", self.name),
        }
    }
}

/// Exposes an entry's password to a command as an environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Environment variable name.
    pub var: String,
    /// Entry name or `Group/Name` path.
    pub entry: String,
}

/// Gives a command a grant of the credential broker for an entry instead of
/// its value (ADR 0013, `run --broker VAR=ENTRY`): the command receives a
/// token, never the entry's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerBinding {
    /// Environment variable that receives the token.
    pub var: String,
    /// Entry name or `Group/Name` path; the entry needs a value and a usable
    /// broker profile.
    pub entry: String,
    /// Environment variable that receives the broker's address
    /// (`http://127.0.0.1:PORT` and the profile's base path) instead of the
    /// entry's own URL: `--url URLVAR=ENTRY` for the same entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_var: Option<String>,
}

/// A request to run a command with secrets in its environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    /// Which secrets go into which variables.
    pub bindings: Vec<Binding>,
    /// The command line; `argv[0]` is resolved against the client's `PATH`.
    pub argv: Vec<String>,
    /// Absolute working directory.
    pub cwd: String,
    /// The client's environment (the agent removes dangerous variables).
    pub env: Vec<(String, String)>,
    /// Replace secret values in the command's output with `[REDACTED:<entry>]`.
    pub redact: bool,
    /// With `redact`, forward the client's stdin to the command (otherwise
    /// the command reads `/dev/null`). Without `redact`, the command always
    /// gets the client's stdin directly.
    #[serde(default)]
    pub forward_stdin: bool,
}

/// A run whose command uses entries through the credential broker
/// ([`Request::BrokerRun`], ADR 0013): the fields of a run and, beside
/// them, the broker bindings (`{"type": "broker_run", "bindings": [],
/// "brokered": [...], "argv": [...], ...}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRunRequest {
    /// The run: its bindings by value (none for a command that uses the
    /// broker only), command line, directory, environment and output.
    #[serde(flatten)]
    pub run: RunRequest,
    /// Which entries the command uses through the credential broker, each
    /// with a grant of its own; at least one. An entry is either here or in
    /// the run's `bindings`, never both.
    pub brokered: Vec<BrokerBinding>,
}

/// Read the content of a [`Request::Run`], refusing broker bindings. They
/// belong in a [`Request::BrokerRun`]; [`RunRequest`] alone would ignore
/// them, and the command would run without the grants it asked for.
fn plain_run<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RunRequest, D::Error> {
    #[derive(Deserialize)]
    struct PlainRun {
        #[serde(flatten)]
        run: RunRequest,
        #[serde(default)]
        brokered: Option<Vec<serde::de::IgnoredAny>>,
    }
    let plain = PlainRun::deserialize(deserializer)?;
    if plain.brokered.is_some_and(|bindings| !bindings.is_empty()) {
        return Err(serde::de::Error::custom(
            "a run with broker bindings is a broker_run request, not a run",
        ));
    }
    Ok(plain.run)
}

/// The agent's answer to a [`Request`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// The request succeeded.
    Ok {
        /// Human-readable summary.
        message: String,
    },
    /// Answer to [`Request::Status`].
    Status(StatusInfo),
    /// Answer to [`Request::List`].
    Entries {
        /// Entries sorted by group and name.
        entries: Vec<EntryInfo>,
    },
    /// Answer to [`Request::Show`].
    Entry {
        /// The entry.
        entry: EntryInfo,
    },
    /// Answer to [`Request::Reveal`].
    Secret {
        /// The secret value.
        value: SecretString,
    },
    /// Answer to [`Request::KeyringItems`].
    KeyringItems {
        /// The items, sorted by label.
        items: Vec<KeyringItem>,
    },
    /// Answer to [`Request::DotenvNames`].
    Names {
        /// The names of the variables with a value, in the file's order.
        names: Vec<String>,
        /// The names of the variables with an empty value, which cannot be
        /// imported.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        empty: Vec<String>,
    },
    /// Answer to [`Request::Grants`].
    Grants {
        /// The grants, oldest first.
        grants: Vec<GrantInfo>,
    },
    /// The command started by [`Request::Run`] finished.
    Exited {
        /// Exit code, when the command exited normally.
        code: Option<i32>,
        /// Signal number, when the command was killed by a signal.
        signal: Option<i32>,
    },
    /// The request failed.
    Error {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Human-readable explanation.
        message: String,
    },
}

impl Response {
    /// The response's `type` name, for messages that must not print its
    /// content (a [`Response::Secret`] holds a secret value).
    pub fn kind(&self) -> &'static str {
        match self {
            Response::Ok { .. } => "ok",
            Response::Status(_) => "status",
            Response::Entries { .. } => "entries",
            Response::Entry { .. } => "entry",
            Response::Secret { .. } => "secret",
            Response::KeyringItems { .. } => "keyring_items",
            Response::Names { .. } => "names",
            Response::Grants { .. } => "grants",
            Response::Exited { .. } => "exited",
            Response::Error { .. } => "error",
        }
    }
}

/// A grant of the credential broker, as [`Request::Grants`] lists it
/// (ADR 0013). Never its token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInfo {
    /// The grant's public ID: `g` and 16 hexadecimal digits.
    pub id: String,
    /// The entry, as dialogs and the audit log identify it
    /// ([`EntryInfo::identity`]).
    pub entry: String,
    /// The environment variable that holds the token in the command.
    pub var: String,
    /// The destination: the profile's origin and base path.
    pub destination: String,
    /// The profile's preset.
    pub preset: Preset,
    /// The command, as a shell would read it.
    pub command: String,
    /// Who asked for it, as dialogs describe the requester (unverified).
    pub requester: String,
    /// `active`; `exhausted` (its request limit is reached: no new request
    /// is admitted, those admitted finish); or `revoked` (it has ended; its
    /// broker answers `403` until the command ends).
    pub state: String,
    /// When it was created: RFC 3339, local time with its offset, like the
    /// audit log's times.
    pub started: String,
    /// Seconds until its maximum lifetime passes.
    pub ends_in_secs: u64,
    /// Requests admitted so far.
    pub requests: u64,
    /// The profile's request limit; `None` for no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
    /// Requests being forwarded now.
    pub in_flight: u32,
    /// Whether the automatic locks end it.
    pub automatic_locks: AutomaticLocks,
}

/// Answer to [`Request::Status`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    /// [`PROTOCOL_VERSION`] of the agent.
    pub protocol_version: u32,
    /// Agent version (`CARGO_PKG_VERSION`).
    pub agent_version: String,
    /// Vault file path.
    pub vault: String,
    /// Whether the vault file exists.
    pub vault_exists: bool,
    /// Audit log file the agent writes.
    #[serde(default)]
    pub audit_log: String,
    /// Whether the vault is locked.
    pub locked: bool,
    /// Idle time before the vault locks itself, in seconds (0 = never).
    pub idle_timeout_secs: u64,
    /// Seconds until the vault locks itself, when unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locks_in_secs: Option<u64>,
    /// Number of approvals currently remembered.
    pub remembered_approvals: usize,
    /// The program file the agent runs, as the kernel reports it; it ends in
    /// ` (deleted)` when that file was replaced or removed after the agent
    /// started (an upgrade without a restart).
    #[serde(default)]
    pub agent_executable: String,
    /// Device and inode of the file the agent runs, read through
    /// `/proc/self/exe`, so that a client can compare it with its own
    /// without relying on names (which differ between mount namespaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_executable_id: Option<(u64, u64)>,
    /// Whether the agent's program file was replaced or removed after it
    /// started, judged by file identity, not by name; `None` (the field is
    /// left out) when the agent cannot tell, for example without permission
    /// to examine the path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_executable_replaced: Option<bool>,
    /// The dialogs the agent shows: the path of `rusthorse-dialog`, `zenity`
    /// when that program is not installed, or `none: ` and why neither can
    /// be used. Left out by agents that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialogs: Option<String>,
    /// What makes the agent lock by itself besides the idle timer: one entry
    /// per event and source (ADR 0009). Left out by agents that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_triggers: Vec<LockTrigger>,
    /// The credential broker's program (ADR 0013): the path of
    /// `rusthorse-broker`, or `none: ` and why it cannot be used. Left out
    /// by agents that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<String>,
    /// The number of active grants of the credential broker. Left out by
    /// agents that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<usize>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// An event that locks the vault, and where the agent learns of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockTrigger {
    /// `suspend` (the computer is about to sleep) or `screen_lock` (the
    /// session is locked or its screensaver starts).
    pub event: String,
    /// Where the agent learns of it: `logind`, or a screensaver's D-Bus name
    /// such as `org.cinnamon.ScreenSaver`.
    pub source: String,
    /// Whether the agent is watching it now.
    pub active: bool,
    /// Watched, but not as well as it should be: logind would not wait
    /// before a suspend, so the lock may come after the computer wakes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub degraded: bool,
    /// Why not, or a remark (`locks before the computer sleeps`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The human denied the request (or the dialog timed out).
    Denied,
    /// The human cancelled a password or value dialog.
    Cancelled,
    /// The vault is locked and could not be unlocked.
    Locked,
    /// Wrong master password, too many attempts.
    UnlockFailed,
    /// No vault file exists yet.
    VaultMissing,
    /// The vault file was changed by another program since it was unlocked.
    VaultChanged,
    /// No such entry.
    NotFound,
    /// An entry with that name already exists; for `create_vault`, the
    /// vault file does.
    AlreadyExists,
    /// The name matches several entries; use a `Group/Name` path.
    Ambiguous,
    /// The request is malformed or not allowed.
    InvalidRequest,
    /// `run`: the command started, but its result could not be determined.
    /// It may have had effects; do not simply retry.
    OutcomeUnknown,
    /// Anything else (I/O errors, dialog failures, ...).
    Internal,
}

/// Write one frame, attaching `fds` (at most [`MAX_FDS`]) as `SCM_RIGHTS`.
pub fn send_frame<T: Serialize>(
    stream: &UnixStream,
    message: &T,
    fds: &[BorrowedFd<'_>],
) -> io::Result<()> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many file descriptors",
        ));
    }
    let body = Zeroizing::new(serde_json::to_vec(message).map_err(io::Error::other)?);
    if body.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);

    let raw: Vec<RawFd> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
    send_raw(stream, &frame, &raw)
}

/// Write a frame that is already encoded (its length word included),
/// attaching `fds` (at most [`MAX_FDS`]) as `SCM_RIGHTS` to its first byte.
/// For channels framed like this one, such as the broker's control channel
/// ([`crate::broker_protocol`]).
pub(crate) fn send_encoded(
    stream: &UnixStream,
    frame: &[u8],
    fds: &[BorrowedFd<'_>],
) -> io::Result<()> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many file descriptors",
        ));
    }
    if frame.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty frame"));
    }
    let raw: Vec<RawFd> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
    send_raw(stream, frame, &raw)
}

/// Send `data`, attaching `fds` as `SCM_RIGHTS` to its first byte; the rest
/// is written as plain data. (Not `nix::sys::socket::sendmsg`: it builds the
/// control message in a byte buffer, which is not guaranteed to be aligned
/// for `cmsghdr`.)
#[allow(unsafe_code)]
fn send_raw(stream: &UnixStream, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    use nix::libc;

    const FD_SIZE: usize = std::mem::size_of::<RawFd>();
    let payload = fds.len() * FD_SIZE;
    // SAFETY: CMSG_SPACE only computes a size.
    let space = if fds.is_empty() {
        0
    } else {
        (unsafe { libc::CMSG_SPACE(payload as u32) }) as usize
    };
    // u64-backed so that the buffer is aligned for `cmsghdr`.
    let mut control = vec![0u64; space.div_ceil(std::mem::size_of::<u64>())];
    let sent = loop {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        // SAFETY: an all-zero msghdr is a valid (empty) value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if space > 0 {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control buffer is `space` bytes, aligned for
            // `cmsghdr`, and CMSG_SPACE(payload) guarantees room for one
            // header followed by `payload` bytes of data.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(payload as u32) as _;
                let dest = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for (i, fd) in fds.iter().enumerate() {
                    std::ptr::write_unaligned(dest.add(i), *fd);
                }
            }
        }
        // SAFETY: every pointer in `msg` refers to a live buffer of the
        // stated length for the duration of the call.
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    // The descriptors travel with the first byte; the rest is plain data.
    let mut writer = stream;
    writer.write_all(&data[sent..])?;
    writer.flush()
}

/// Send one data frame: a length word with [`DATA_FLAG`] set, one channel
/// byte, then `data`. Used for the input and output of `run` with redaction,
/// so that the agent never writes to (or reads from) the client's own
/// descriptors. The frame is written with a single `write_all`; callers that
/// share a socket between threads must serialize their calls.
pub fn send_data(stream: &UnixStream, channel: u8, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_DATA_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "data frame too large",
        ));
    }
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.extend_from_slice(&(DATA_FLAG | (1 + data.len() as u32)).to_be_bytes());
    frame.push(channel);
    frame.extend_from_slice(data);
    let mut writer = stream;
    writer.write_all(&frame)
}

/// Grant `amount` more bytes of credit for a channel: [`STDOUT`] or
/// [`STDERR`] (client → agent) or [`STDIN`] (agent → client).
pub fn send_credit(stream: &UnixStream, channel: u8, amount: u32) -> io::Result<()> {
    let credit_channel = match channel {
        STDIN => CREDIT_STDIN,
        STDOUT => CREDIT_STDOUT,
        STDERR => CREDIT_STDERR,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "credit is only granted for stdin, stdout and stderr",
            ));
        }
    };
    send_data(stream, credit_channel, &amount.to_be_bytes())
}

/// A frame of either kind.
pub enum Frame {
    /// A JSON message, with any file descriptors attached to it.
    Message(Zeroizing<Vec<u8>>, Vec<OwnedFd>),
    /// A data frame: channel and payload.
    Data(u8, Zeroizing<Vec<u8>>),
}

/// Read one message frame. Returns its body and any file descriptors
/// attached to it. A data frame here is a protocol error.
pub fn recv_frame(stream: &UnixStream) -> io::Result<(Zeroizing<Vec<u8>>, Vec<OwnedFd>)> {
    recv_frame_before(stream, None)
}

/// Read one message frame, failing with [`io::ErrorKind::TimedOut`] if the
/// whole frame has not arrived by `deadline`. (A per-read timeout would let a
/// client that sends one byte at a time hold the connection indefinitely.)
pub fn recv_frame_before(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> io::Result<(Zeroizing<Vec<u8>>, Vec<OwnedFd>)> {
    match recv_any_before(stream, deadline)? {
        Frame::Message(body, fds) => Ok((body, fds)),
        Frame::Data(..) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected data frame",
        )),
    }
}

/// Read one frame of either kind, by `deadline` if one is given.
pub fn recv_any_before(stream: &UnixStream, deadline: Option<Instant>) -> io::Result<Frame> {
    let (word, fds) = recv_length_word(stream, deadline)?;
    let is_data = word & DATA_FLAG != 0;
    let len = (word & !DATA_FLAG) as usize;
    let limit = if is_data {
        MAX_DATA_LEN + 1
    } else {
        MAX_FRAME_LEN
    };
    if len > limit || (is_data && len == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes is invalid (limit {limit})"),
        ));
    }
    if is_data && !fds.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file descriptors attached to a data frame",
        ));
    }
    let body = recv_body(stream, len, deadline)?;
    if is_data {
        let channel = body[0];
        let data = Zeroizing::new(body[1..].to_vec());
        Ok(Frame::Data(channel, data))
    } else {
        Ok(Frame::Message(body, fds))
    }
}

/// Read one frame of a channel that has no data frames, such as the
/// broker's control channel ([`crate::broker_protocol`]): a length word of
/// at most `max`, checked before the body is read, then the body; by
/// `deadline` if one is given. Returns the body and the file descriptors
/// attached to it.
pub(crate) fn recv_message_before(
    stream: &UnixStream,
    deadline: Option<Instant>,
    max: usize,
) -> io::Result<(Zeroizing<Vec<u8>>, Vec<OwnedFd>)> {
    let (word, fds) = recv_length_word(stream, deadline)?;
    let len = word as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes is invalid (limit {max})"),
        ));
    }
    let body = recv_body(stream, len, deadline)?;
    Ok((body, fds))
}

/// Set the read timeout of `stream` to what is left until `deadline`, if
/// one is given; fail with [`io::ErrorKind::TimedOut`] once it has passed.
fn arm_deadline(stream: &UnixStream, deadline: Option<Instant>) -> io::Result<()> {
    if let Some(deadline) = deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the request did not arrive in time",
            ));
        }
        stream.set_read_timeout(Some(left))?;
    }
    Ok(())
}

/// Read a frame's 4-byte length word, taking ownership of the file
/// descriptors attached to its first byte.
fn recv_length_word(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> io::Result<(u32, Vec<OwnedFd>)> {
    let mut header = [0u8; 4];
    arm_deadline(stream, deadline)?;
    let (mut got, fds) = recv_with_fds(stream, &mut header)?;
    if got == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut reader = stream;
    while got < header.len() {
        arm_deadline(stream, deadline)?;
        got += read_some(&mut reader, &mut header[got..])?;
    }
    Ok((u32::from_be_bytes(header), fds))
}

/// Read the `len` bytes of a frame's body, then clear the read timeout that
/// a `deadline` set.
fn recv_body(
    stream: &UnixStream,
    len: usize,
    deadline: Option<Instant>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(vec![0u8; len]);
    let mut reader = stream;
    let mut filled = 0;
    while filled < len {
        arm_deadline(stream, deadline)?;
        filled += read_some(&mut reader, &mut body[filled..])?;
    }
    if deadline.is_some() {
        stream.set_read_timeout(None)?;
    }
    Ok(body)
}

/// One `read`, treating end-of-file as an error and retrying on `EINTR`.
fn read_some(reader: &mut &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the request did not arrive in time",
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Read one frame and decode it, closing any attached file descriptors.
pub fn read_message<T: DeserializeOwned>(stream: &UnixStream) -> io::Result<T> {
    let (body, _fds) = recv_frame(stream)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `recvmsg` into `buf`, taking ownership of every `SCM_RIGHTS` descriptor
/// the kernel installed — including when the message was truncated
/// (`MSG_CTRUNC`), which happens not only when the control buffer is too
/// small but also when the process hits its open-file limit part-way. The
/// control messages are parsed directly because `nix` refuses to iterate a
/// truncated buffer, which would leave the installed descriptors open.
#[allow(unsafe_code)]
fn recv_with_fds(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    use nix::libc;
    use std::os::fd::FromRawFd;

    const FD_SIZE: usize = std::mem::size_of::<RawFd>();
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE((SCM_MAX_FD * FD_SIZE) as u32) } as usize;
    // Backed by u64 so that the buffer is aligned for `cmsghdr` (a Vec<u8>
    // only guarantees byte alignment, and the headers are read in place).
    let mut control = vec![0u64; space.div_ceil(std::mem::size_of::<u64>())];
    loop {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: an all-zero msghdr is a valid (empty) value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: every pointer in `msg` refers to a live buffer of the
        // stated length for the duration of the call.
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        let mut fds = Vec::new();
        // SAFETY: the CMSG_* macros walk the control buffer the kernel just
        // filled, within `msg_controllen`; each SCM_RIGHTS payload holds
        // descriptors that the kernel installed in our table for this
        // message and that nothing else owns yet.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg);
                    let header = data as usize - cmsg as usize;
                    let count = ((*cmsg).cmsg_len as usize).saturating_sub(header) / FD_SIZE;
                    for i in 0..count {
                        let fd = std::ptr::read_unaligned(data.cast::<RawFd>().add(i));
                        fds.push(OwnedFd::from_raw_fd(fd));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            // `fds` is dropped here: everything that did arrive is closed.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file descriptors attached to the request were truncated",
            ));
        }
        return Ok((received as usize, fds));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn unknown_status_fields_are_left_out_not_null() {
        // Clients that know the field as a plain boolean must still read it.
        let status = StatusInfo {
            protocol_version: PROTOCOL_VERSION,
            agent_version: "x".into(),
            vault: "/v".into(),
            vault_exists: true,
            audit_log: String::new(),
            locked: true,
            idle_timeout_secs: 0,
            locks_in_secs: None,
            remembered_approvals: 0,
            agent_executable: "/bin/x".into(),
            agent_executable_id: None,
            agent_executable_replaced: None,
            dialogs: None,
            lock_triggers: vec![],
            broker: None,
            grants: None,
        };
        let json = serde_json::to_value(&status).expect("json");
        assert!(json.get("agent_executable_replaced").is_none(), "{json}");
        assert!(json.get("agent_executable_id").is_none(), "{json}");
        assert!(json.get("broker").is_none(), "{json}");
        assert!(json.get("grants").is_none(), "{json}");
        assert!(!json.to_string().contains("null"), "{json}");
    }

    #[test]
    fn frames_round_trip_with_fds() {
        let (a, b) = UnixStream::pair().expect("socket pair");
        let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe");
        let request = Request::Show {
            name: "router".into(),
        };
        send_frame(&a, &request, &[pipe_w.as_fd()]).expect("send");
        drop(pipe_w);

        let (body, fds) = recv_frame(&b).expect("recv");
        let decoded: Request = serde_json::from_slice(&body).expect("json");
        assert!(matches!(decoded, Request::Show { name } if name == "router"));
        assert_eq!(fds.len(), 1);

        // The received descriptor is the write end of our pipe.
        let mut writer = std::fs::File::from(fds.into_iter().next().expect("fd"));
        writer.write_all(b"hi").expect("write");
        drop(writer);
        let mut reader = std::fs::File::from(pipe_r);
        let mut text = String::new();
        reader.read_to_string(&mut text).expect("read");
        assert_eq!(text, "hi");
    }

    #[test]
    fn every_received_descriptor_is_owned_even_beyond_the_limit() {
        use std::os::fd::AsRawFd;
        let (a, b) = UnixStream::pair().expect("socket pair");
        let pipes: Vec<(OwnedFd, OwnedFd)> =
            (0..8).map(|_| nix::unistd::pipe().expect("pipe")).collect();
        let raw: Vec<RawFd> = pipes.iter().map(|(r, _)| r.as_raw_fd()).collect();
        let body = br#"{"type":"status"}"#;
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        send_raw(&a, &frame, &raw).expect("sendmsg");
        let (_, fds) = recv_frame(&b).expect("recv");
        // All eight arrive as OwnedFd (closed on drop), none is left behind.
        assert_eq!(fds.len(), 8);
    }

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").expect("fd dir").count()
    }

    /// Runs in a child process (the test re-executes itself) because it
    /// lowers RLIMIT_NOFILE, which would disturb other tests running in
    /// parallel threads.
    #[test]
    fn descriptors_are_not_leaked_when_the_fd_limit_is_hit() {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        use std::os::fd::AsRawFd;
        if std::env::var_os("RUSTHORSE_FD_LIMIT_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("exe"))
                .args([
                    "protocol::tests::descriptors_are_not_leaked_when_the_fd_limit_is_hit",
                    "--exact",
                    "--test-threads=1",
                ])
                .env("RUSTHORSE_FD_LIMIT_CHILD", "1")
                .status()
                .expect("re-run");
            assert!(status.success(), "the isolated run failed");
            return;
        }
        let (a, b) = UnixStream::pair().expect("socket pair");
        let pipes: Vec<(OwnedFd, OwnedFd)> = (0..60)
            .map(|_| nix::unistd::pipe().expect("pipe"))
            .collect();
        let raw: Vec<RawFd> = pipes.iter().map(|(r, _)| r.as_raw_fd()).collect();
        let body = br#"{"type":"status"}"#;
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        send_raw(&a, &frame, &raw).expect("sendmsg");
        drop(pipes); // the 60 descriptors now exist only in the socket queue
        let before = open_fd_count();
        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
        // Room for about 20 more descriptors: the kernel installs some, then
        // truncates.
        setrlimit(Resource::RLIMIT_NOFILE, before as u64 + 20, hard).expect("setrlimit");
        let result = recv_frame(&b);
        setrlimit(Resource::RLIMIT_NOFILE, soft, hard).expect("restore");
        let err = result.expect_err("a truncated message must be refused");
        // Make sure the scenario really happened (the kernel truncated).
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
        assert_eq!(open_fd_count(), before, "descriptors leaked");
    }

    #[test]
    fn a_slow_drip_cannot_outlive_the_deadline() {
        let (a, b) = UnixStream::pair().expect("socket pair");
        let writer = std::thread::spawn(move || {
            let mut a = &a;
            for byte in [0u8, 0, 0, 2, b'{', b'}'] {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if a.write_all(&[byte]).is_err() {
                    return;
                }
            }
        });
        let deadline = Instant::now() + std::time::Duration::from_millis(400);
        let err = recv_frame_before(&b, Some(deadline)).expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(b);
        let _ = writer.join();
    }

    #[test]
    fn data_frames_round_trip_and_are_told_apart_from_messages() {
        let (a, b) = UnixStream::pair().expect("socket pair");
        send_data(&a, STDOUT, b"hello").expect("send");
        send_data(&a, STDIN, b"").expect("send eof");
        send_frame(
            &a,
            &Response::Ok {
                message: "done".into(),
            },
            &[],
        )
        .expect("send");
        match recv_any_before(&b, None).expect("recv") {
            Frame::Data(STDOUT, data) => assert_eq!(data.as_slice(), b"hello"),
            _ => panic!("expected stdout data"),
        }
        match recv_any_before(&b, None).expect("recv") {
            Frame::Data(STDIN, data) => assert!(data.is_empty()),
            _ => panic!("expected end of input"),
        }
        assert!(matches!(
            recv_any_before(&b, None).expect("recv"),
            Frame::Message(..)
        ));
        // A data frame where a request is expected is an error.
        send_data(&a, STDOUT, b"x").expect("send");
        assert_eq!(
            recv_frame(&b).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn oversized_frames_are_rejected() {
        let (a, b) = UnixStream::pair().expect("socket pair");
        let mut writer = &a;
        writer
            .write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
            .expect("write");
        let err = recv_frame(&b).expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_entry_kind_json_shape_is_stable() {
        for kind in EntryKind::ALL {
            assert_eq!(
                serde_json::to_value(kind).expect("json"),
                serde_json::json!(kind.as_str())
            );
            assert_eq!(EntryKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(EntryKind::parse("api_key"), None);
        // In an entry the kind sits with the other fields, and is omitted
        // when there is none (what a protocol-4 client would have sent).
        let info = EntryInfo {
            id: "u".into(),
            name: "OPENAI_API_KEY".into(),
            group: None,
            fields: EntryFields {
                kind: Some(EntryKind::ApiKey),
                url: Some("https://api.openai.com/v1".into()),
                ..EntryFields::default()
            },
            protected_fields: vec![],
            has_password: true,
            has_notes: false,
            other_fields: vec![],
            modified: None,
            broker: None,
        };
        let json = serde_json::to_value(&info).expect("json");
        assert_eq!(json["kind"], "api-key");
        assert_eq!(json["url"], "https://api.openai.com/v1");
        let none = serde_json::to_value(EntryFields::default()).expect("json");
        assert!(none.get("kind").is_none());
        let edit = serde_json::to_value(Request::Edit {
            name: "x".into(),
            changes: EntryChanges {
                clear: vec![Field::Kind],
                ..EntryChanges::default()
            },
        })
        .expect("json");
        assert_eq!(edit["changes"]["clear"], serde_json::json!(["kind"]));
        assert!(edit["changes"].get("kind").is_none());
    }

    #[test]
    fn request_json_shape_is_stable() {
        let json = serde_json::to_value(Request::Reveal {
            name: "x".into(),
            notes: false,
            purpose: None,
        })
        .expect("json");
        assert_eq!(
            json,
            serde_json::json!({"type": "reveal", "name": "x", "notes": false})
        );
        let json = serde_json::to_value(Request::Reveal {
            name: "x".into(),
            notes: false,
            purpose: Some(RevealPurpose::Copy),
        })
        .expect("json");
        assert_eq!(
            json,
            serde_json::json!({"type": "reveal", "name": "x", "notes": false, "purpose": "copy"})
        );
        let old: Request =
            serde_json::from_value(serde_json::json!({"type": "reveal", "name": "x"}))
                .expect("a request without purpose");
        assert!(matches!(old, Request::Reveal { purpose: None, .. }));
        let resp = serde_json::to_value(Response::Error {
            code: ErrorCode::Denied,
            message: "no".into(),
        })
        .expect("json");
        assert_eq!(
            resp,
            serde_json::json!({"type": "error", "code": "denied", "message": "no"})
        );
    }

    /// A run of protocol 8 with a binding by value and two broker bindings,
    /// one of which also receives the broker's address.
    fn mixed_run() -> BrokerRunRequest {
        BrokerRunRequest {
            run: RunRequest {
                bindings: vec![Binding {
                    var: "DB_PASSWORD".into(),
                    entry: "db".into(),
                }],
                argv: vec!["claude".into()],
                cwd: "/".into(),
                env: vec![("PATH".into(), "/usr/bin:/bin".into())],
                redact: false,
                forward_stdin: false,
            },
            brokered: vec![
                BrokerBinding {
                    var: "ANTHROPIC_AUTH_TOKEN".into(),
                    entry: "AI/anthropic".into(),
                    url_var: Some("ANTHROPIC_BASE_URL".into()),
                },
                BrokerBinding {
                    var: "OPENAI_API_KEY".into(),
                    entry: "openai".into(),
                    url_var: None,
                },
            ],
        }
    }

    /// An edit of protocol 8 that sets a profile and changes the user name.
    fn profile_edit() -> EntryChanges {
        EntryChanges {
            username: Some("me".into()),
            broker: Some(ProfileRequest {
                automatic_locks: Some(AutomaticLocks::End),
                max_requests: Some(10),
                ..ProfileRequest::new(Preset::Anthropic)
            }),
            ..EntryChanges::default()
        }
    }

    #[test]
    fn broker_runs_and_profile_edits_are_requests_of_their_own() {
        // A run with broker bindings: the run's fields, and the bindings
        // beside them.
        let json = serde_json::to_value(Request::BrokerRun(mixed_run())).expect("json");
        assert_eq!(
            json,
            serde_json::json!({
                "type": "broker_run",
                "bindings": [{"var": "DB_PASSWORD", "entry": "db"}],
                "brokered": [
                    {"var": "ANTHROPIC_AUTH_TOKEN", "entry": "AI/anthropic", "url_var": "ANTHROPIC_BASE_URL"},
                    {"var": "OPENAI_API_KEY", "entry": "openai"}
                ],
                "argv": ["claude"],
                "cwd": "/",
                "env": [["PATH", "/usr/bin:/bin"]],
                "redact": false,
                "forward_stdin": false
            })
        );
        let Request::BrokerRun(back) = serde_json::from_value(json.clone()).expect("back") else {
            panic!("not a broker run")
        };
        assert_eq!(back.brokered, mixed_run().brokered);
        assert_eq!(back.run.bindings, mixed_run().run.bindings);
        assert_eq!(back.run.argv, ["claude"]);
        assert_eq!(back.run.env, mixed_run().run.env);
        // The broker bindings are required: without them it is no
        // broker_run, and nothing is guessed.
        let mut without = json.clone();
        without.as_object_mut().expect("object").remove("brokered");
        assert!(serde_json::from_value::<Request>(without).is_err());

        // A plain run that carries broker bindings is refused, not run
        // without them; an empty list or null carries none.
        let mut plain = json;
        plain["type"] = "run".into();
        let err = serde_json::from_value::<Request>(plain.clone()).expect_err("refused");
        assert!(err.to_string().contains("broker_run"), "{err}");
        for none in [serde_json::json!([]), serde_json::Value::Null] {
            plain["brokered"] = none;
            let Request::Run(run) = serde_json::from_value(plain.clone()).expect("a run") else {
                panic!("not a run")
            };
            assert_eq!(run.bindings, mixed_run().run.bindings);
        }
        // A plain run never sends the field.
        let json = serde_json::to_value(Request::Run(mixed_run().run)).expect("json");
        assert_eq!(json["type"], "run");
        assert!(json.get("brokered").is_none(), "{json}");

        // An edit that sets or clears the profile is a broker_edit, which
        // has the shape of an edit.
        let set = profile_edit();
        assert!(set.touches_broker() && set.touches_metadata() && !set.is_empty());
        let json = serde_json::to_value(Request::BrokerEdit {
            name: "anthropic".into(),
            changes: profile_edit(),
        })
        .expect("json");
        assert_eq!(json["type"], "broker_edit");
        assert_eq!(json["name"], "anthropic");
        assert_eq!(json["changes"]["username"], "me");
        assert_eq!(
            json["changes"]["broker"],
            serde_json::json!({"preset": "anthropic", "automatic_locks": "end", "max_requests": 10})
        );
        let Request::BrokerEdit { name, changes } = serde_json::from_value(json).expect("back")
        else {
            panic!("not a broker edit")
        };
        assert_eq!(name, "anthropic");
        assert_eq!(changes.username.as_deref(), Some("me"));
        assert_eq!(changes.broker, profile_edit().broker);
        let clear = EntryChanges {
            clear: vec![Field::Port, Field::Broker],
            ..EntryChanges::default()
        };
        assert!(clear.touches_broker() && clear.touches_metadata());
        assert_eq!(
            serde_json::to_value(&clear).expect("json")["clear"],
            serde_json::json!(["port", "broker"])
        );
        // Nothing else is a change of the profile.
        let others = [
            EntryChanges::default(),
            EntryChanges {
                rename: Some("x".into()),
                clear: vec![Field::Username, Field::Url, Field::Kind],
                ..EntryChanges::default()
            },
            EntryChanges {
                value: Some(ValueChange::Prompt),
                ..EntryChanges::default()
            },
        ];
        for (i, other) in others.iter().enumerate() {
            assert!(!other.touches_broker(), "case {i}");
        }

        // Both have effects: an answer that is lost leaves the outcome
        // unknown.
        assert!(Request::BrokerRun(mixed_run()).has_effects());
        assert!(
            Request::BrokerEdit {
                name: "x".into(),
                changes: profile_edit(),
            }
            .has_effects()
        );
    }

    /// The requests of protocol 7, as `aff56e1` defines them: an internally
    /// tagged enum of these variants, with no catch-all, that ignores
    /// fields it does not know. Their contents do not matter here, except
    /// those of `run` and `edit`, which are read as protocol 7 read them.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum Protocol7Request {
        Status,
        Unlock,
        CreateVault,
        Lock,
        List,
        Show(serde::de::IgnoredAny),
        Add(serde::de::IgnoredAny),
        Import(serde::de::IgnoredAny),
        Edit {
            name: String,
            changes: Protocol7Changes,
        },
        Remove(serde::de::IgnoredAny),
        ChangePassword,
        Reveal(serde::de::IgnoredAny),
        Backup(serde::de::IgnoredAny),
        Run(Protocol7Run),
        KeyringItems,
        DotenvNames(serde::de::IgnoredAny),
        ImportFrom(serde::de::IgnoredAny),
    }

    /// Protocol 7's run request.
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Protocol7Run {
        bindings: Vec<Binding>,
        argv: Vec<String>,
        cwd: String,
        env: Vec<(String, String)>,
        redact: bool,
        #[serde(default)]
        forward_stdin: bool,
    }

    /// Protocol 7's edit: the fields of [`EntryChanges`] without the
    /// profile, and its fields to clear without `broker`.
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Protocol7Changes {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        clear: Vec<Protocol7Field>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    #[allow(dead_code)]
    enum Protocol7Field {
        Username,
        Url,
        Host,
        Port,
        Notes,
        Kind,
    }

    /// The reason for `broker_run` and `broker_edit`: a client that checked
    /// the version on one connection can meet an agent of protocol 7 on the
    /// next one, after a restart. Such an agent refuses both whole, where
    /// it would have run the command without its grants, or applied an edit
    /// without its profile.
    #[test]
    fn a_protocol_7_agent_refuses_broker_runs_and_profile_edits_whole() {
        let refused = |request: &Request| {
            let json = serde_json::to_value(request).expect("json");
            serde_json::from_value::<Protocol7Request>(json)
                .expect_err("refused by protocol 7")
                .to_string()
        };
        let run = refused(&Request::BrokerRun(mixed_run()));
        assert!(run.contains("unknown variant `broker_run`"), "{run}");
        // The variants protocol 7's own type names in this error, in its
        // order, as a build of `aff56e1` printed it: the mirror is faithful.
        assert!(
            run.contains(
                "expected one of `status`, `unlock`, `create_vault`, `lock`, `list`, `show`, \
                 `add`, `import`, `edit`, `remove`, `change_password`, `reveal`, `backup`, \
                 `run`, `keyring_items`, `dotenv_names`, `import_from`"
            ),
            "{run}"
        );
        let edit = Request::BrokerEdit {
            name: "anthropic".into(),
            changes: profile_edit(),
        };
        assert!(refused(&edit).contains("unknown variant `broker_edit`"));
        let clear = Request::BrokerEdit {
            name: "anthropic".into(),
            changes: EntryChanges {
                clear: vec![Field::Broker],
                ..EntryChanges::default()
            },
        };
        assert!(refused(&clear).contains("unknown variant `broker_edit`"));

        // What protocol 7 does with the shapes these requests replace:
        // broker bindings in a run, and a profile in an edit, are dropped
        // without a word and the rest is acted on.
        let mut run = serde_json::to_value(Request::BrokerRun(mixed_run())).expect("json");
        run["type"] = "run".into();
        let Ok(Protocol7Request::Run(old)) = serde_json::from_value(run) else {
            panic!("protocol 7 refused the run")
        };
        assert_eq!(old.argv, ["claude"]);
        assert_eq!(old.bindings, mixed_run().run.bindings);
        let mut edit = serde_json::to_value(edit).expect("json");
        edit["type"] = "edit".into();
        let Ok(Protocol7Request::Edit { changes, .. }) = serde_json::from_value(edit) else {
            panic!("protocol 7 refused the edit")
        };
        assert_eq!(changes.username.as_deref(), Some("me"));

        // The requests this build sends without broker bindings or a
        // profile are still those protocol 7 knows.
        for request in [
            Request::Run(mixed_run().run),
            Request::Edit {
                name: "x".into(),
                changes: EntryChanges {
                    username: Some("me".into()),
                    clear: vec![Field::Port],
                    ..EntryChanges::default()
                },
            },
            Request::Status,
            Request::Lock,
        ] {
            let json = serde_json::to_value(&request).expect("json");
            assert!(
                serde_json::from_value::<Protocol7Request>(json.clone()).is_ok(),
                "{json}"
            );
        }
    }

    #[test]
    fn protocol_8_fields_are_left_out_when_empty_and_older_json_still_parses() {
        // A run request of protocol 7 is a run of protocol 8.
        let old: Request = serde_json::from_value(serde_json::json!({
            "type": "run",
            "bindings": [{"var": "KEY", "entry": "k"}],
            "argv": ["true"],
            "cwd": "/",
            "env": [],
            "redact": true
        }))
        .expect("a protocol-7 run request");
        let Request::Run(run) = old else {
            panic!("not a run request")
        };
        assert_eq!(run.argv, ["true"]);

        // An edit of protocol 7 has no profile, and leaves the field out.
        let old: EntryChanges =
            serde_json::from_value(serde_json::json!({"rename": "x"})).expect("old edit");
        assert!(old.broker.is_none() && !old.touches_broker());
        let json = serde_json::to_value(&old).expect("json");
        assert!(json.get("broker").is_none(), "{json}");
        assert_eq!(
            serde_json::to_value(profile_edit()).expect("json")["broker"],
            serde_json::json!({"preset": "anthropic", "automatic_locks": "end", "max_requests": 10})
        );
        // A profile request with a field this build does not know is
        // refused, not applied in part.
        assert!(
            serde_json::from_value::<EntryChanges>(serde_json::json!({
                "broker": {"preset": "openai", "routes": ["POST /v1/files"]}
            }))
            .is_err()
        );

        // An entry of protocol 7 has no profile; a usable one is shown whole.
        let old: EntryInfo = serde_json::from_value(serde_json::json!({
            "id": "u", "name": "n", "has_password": true, "has_notes": false
        }))
        .expect("old entry");
        assert!(old.broker.is_none());
        let json = serde_json::to_value(&old).expect("json");
        assert!(json.get("broker").is_none(), "{json}");
        let profile = ProfileRequest::new(Preset::Openai)
            .resolve()
            .expect("profile");
        let with = EntryInfo {
            broker: Some(profile.clone()),
            ..old
        };
        let json = serde_json::to_value(&with).expect("json");
        assert_eq!(json["broker"]["origin"], "https://api.openai.com");
        assert_eq!(json["broker"]["base_path"], "/v1");
        assert_eq!(json["broker"]["preset"], "openai");
        let back: EntryInfo = serde_json::from_value(json).expect("back");
        assert_eq!(back.broker, Some(profile));

        // A status of protocol 7 has neither broker field.
        let status: StatusInfo = serde_json::from_value(serde_json::json!({
            "protocol_version": 7, "agent_version": "x", "vault": "/v",
            "vault_exists": true, "locked": true, "idle_timeout_secs": 0,
            "remembered_approvals": 0
        }))
        .expect("old status");
        assert_eq!((status.broker, status.grants), (None, None));
    }

    #[test]
    fn grant_requests_and_responses_have_a_stable_shape() {
        assert_eq!(
            serde_json::to_value(Request::Grants).expect("json"),
            serde_json::json!({"type": "grants"})
        );
        assert_eq!(
            serde_json::to_value(Request::RevokeGrant { id: None }).expect("json"),
            serde_json::json!({"type": "revoke_grant"})
        );
        assert_eq!(
            serde_json::to_value(Request::RevokeGrant {
                id: Some("g0123456789abcdef".into())
            })
            .expect("json"),
            serde_json::json!({"type": "revoke_grant", "id": "g0123456789abcdef"})
        );
        let all: Request =
            serde_json::from_value(serde_json::json!({"type": "revoke_grant"})).expect("all");
        assert!(matches!(all, Request::RevokeGrant { id: None }));
        // Like `lock`: ending a grant twice does no harm.
        assert!(!Request::Grants.has_effects());
        assert!(!Request::RevokeGrant { id: None }.has_effects());

        let grant = GrantInfo {
            id: "g0123456789abcdef".into(),
            entry: "AI/ANTHROPIC_API_KEY (8d2f6c1e)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            destination: "https://api.anthropic.com".into(),
            preset: Preset::Anthropic,
            command: "claude".into(),
            requester: "claude (pid 4242)".into(),
            state: "active".into(),
            started: "2026-11-02T18:00:00-03:00".into(),
            ends_in_secs: 43_200,
            requests: 3,
            max_requests: None,
            in_flight: 1,
            automatic_locks: AutomaticLocks::Continue,
        };
        let response = Response::Grants {
            grants: vec![grant.clone()],
        };
        assert_eq!(response.kind(), "grants");
        let json = serde_json::to_value(&response).expect("json");
        assert_eq!(json["type"], "grants");
        let listed = &json["grants"][0];
        assert!(listed.get("max_requests").is_none(), "{listed}");
        assert_eq!(listed["preset"], "anthropic");
        assert_eq!(listed["automatic_locks"], "continue");
        assert_eq!(listed["state"], "active");
        let back: Response = serde_json::from_value(json).expect("back");
        let Response::Grants { grants } = back else {
            panic!("not a grants response")
        };
        assert_eq!(grants, vec![grant]);
        let limited = GrantInfo {
            max_requests: Some(200),
            ..grants[0].clone()
        };
        assert_eq!(
            serde_json::to_value(&limited).expect("json")["max_requests"],
            200
        );
    }
}
