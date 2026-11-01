//! The wire protocol between clients and the agent.
//!
//! Each connection carries exactly one request and its response. A message is
//! a *frame*: a 4-byte big-endian length followed by that many bytes of JSON.
//! A [`Request::Run`] frame additionally carries the client's stdin, stdout
//! and stderr as `SCM_RIGHTS` ancillary data attached to its first byte.
//!
//! The full specification, with examples, is in `docs/protocol.md`.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Protocol version spoken by this build. Bumped on incompatible changes.
///
/// 2: data frames, per-channel credit (stdin credit granted when the
/// command starts), `generate`, `change_password`, `backup`, `reveal.notes`,
/// `status.audit_log`.
pub const PROTOCOL_VERSION: u32 = 2;

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
    /// Change an entry (requires approval).
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
    },
    /// Copy the (encrypted) vault file to `path` and check that the copy
    /// opens with the current master password.
    Backup {
        /// Absolute destination path; must not exist.
        path: String,
    },
    /// Run a command with secrets in its environment (requires approval).
    Run(RunRequest),
}

/// Entry metadata that clients may read without approval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFields {
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

/// The changes requested by [`Request::Edit`]. Unset fields stay as they are.
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
}

impl EntryChanges {
    /// Whether anything other than the secret value would change.
    pub fn touches_metadata(&self) -> bool {
        self.rename.is_some()
            || self.username.is_some()
            || self.url.is_some()
            || self.host.is_some()
            || self.port.is_some()
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
    /// Names of other fields (their values are not disclosed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_fields: Vec<String>,
    /// Last modification time, RFC 3339 in UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

impl EntryInfo {
    /// How dialogs and the audit log identify the entry: its full path and
    /// the start of its UUID, e.g. `Production/API_KEY (8d2f6c1e)`. Two entries
    /// with the same title in different groups never look the same.
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
            Response::Exited { .. } => "exited",
            Response::Error { .. } => "error",
        }
    }
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
    /// An entry with that name already exists.
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
    let arm = || -> io::Result<()> {
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
    };
    let mut header = [0u8; 4];
    arm()?;
    let (mut got, fds) = recv_with_fds(stream, &mut header)?;
    if got == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut reader = stream;
    while got < header.len() {
        arm()?;
        got += read_some(&mut reader, &mut header[got..])?;
    }
    let word = u32::from_be_bytes(header);
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
    let mut body = Zeroizing::new(vec![0u8; len]);
    let mut filled = 0;
    while filled < len {
        arm()?;
        filled += read_some(&mut reader, &mut body[filled..])?;
    }
    if deadline.is_some() {
        stream.set_read_timeout(None)?;
    }
    if is_data {
        let channel = body[0];
        let data = Zeroizing::new(body[1..].to_vec());
        Ok(Frame::Data(channel, data))
    } else {
        Ok(Frame::Message(body, fds))
    }
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
    fn request_json_shape_is_stable() {
        let json = serde_json::to_value(Request::Reveal {
            name: "x".into(),
            notes: false,
        })
        .expect("json");
        assert_eq!(
            json,
            serde_json::json!({"type": "reveal", "name": "x", "notes": false})
        );
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
}
