//! The wire protocol between clients and the agent.
//!
//! Each connection carries exactly one request and its response. A message is
//! a *frame*: a 4-byte big-endian length followed by that many bytes of JSON.
//! A [`Request::Run`] frame additionally carries the client's stdin, stdout
//! and stderr as `SCM_RIGHTS` ancillary data attached to its first byte.
//!
//! The full specification, with examples, is in `docs/protocol.md`.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Protocol version spoken by this build. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest accepted frame body, in bytes.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

/// Most file descriptors a frame may carry (stdin, stdout, stderr).
pub const MAX_FDS: usize = 3;

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
        /// dialog; `Some` (value supplied by the client) requires approval.
        value: Option<SecretString>,
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
    /// Return an entry's password to the client (requires approval).
    Reveal {
        /// Entry name or `Group/Name` path.
        name: String,
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
    /// Entry name.
    pub name: String,
    /// Group path, `None` for the root group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Non-secret metadata.
    #[serde(flatten)]
    pub fields: EntryFields,
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
    let cmsgs: Vec<ControlMessage<'_>> = if raw.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&raw)]
    };
    let sent = loop {
        match sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(&frame)],
            &cmsgs,
            MsgFlags::MSG_NOSIGNAL,
            None,
        ) {
            Ok(n) => break n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    // The descriptors travel with the first byte; the rest is plain data.
    let mut writer = stream;
    writer.write_all(&frame[sent..])?;
    writer.flush()
}

/// Read one frame. Returns its body and any file descriptors attached to it.
pub fn recv_frame(stream: &UnixStream) -> io::Result<(Zeroizing<Vec<u8>>, Vec<OwnedFd>)> {
    let mut header = [0u8; 4];
    let (got, fds) = recv_with_fds(stream, &mut header)?;
    if got == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut reader = stream;
    reader.read_exact(&mut header[got..])?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME_LEN}-byte limit"),
        ));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body)?;
    Ok((body, fds))
}

/// Read one frame and decode it, closing any attached file descriptors.
pub fn read_message<T: DeserializeOwned>(stream: &UnixStream) -> io::Result<T> {
    let (body, _fds) = recv_frame(stream)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `recvmsg` into `buf`, taking ownership of any `SCM_RIGHTS` descriptors.
#[allow(unsafe_code)]
fn recv_with_fds(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    use std::os::fd::FromRawFd;

    let mut cmsg_space = nix::cmsg_space!([RawFd; MAX_FDS]);
    loop {
        let mut iov = [IoSliceMut::new(buf)];
        let msg = match recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Ok(msg) => msg,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let mut fds = Vec::new();
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(raw) = cmsg {
                for fd in raw {
                    // SAFETY: the kernel just installed `fd` in our descriptor
                    // table for this message; nothing else owns it yet.
                    fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
            // Some descriptors were discarded by the kernel; refuse the frame.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many file descriptors attached to the request",
            ));
        }
        return Ok((msg.bytes, fds));
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
        let json = serde_json::to_value(Request::Reveal { name: "x".into() }).expect("json");
        assert_eq!(json, serde_json::json!({"type": "reveal", "name": "x"}));
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
