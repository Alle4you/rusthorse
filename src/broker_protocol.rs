//! The control channel between the agent and `rusthorse-broker`
//! ([ADR 0013](../docs/adr/0013-credential-broker.md)).
//!
//! The agent starts one broker process per grant, with one end of a socket
//! pair as its standard input and output, and talks to it over that channel
//! only. It is framed like the dialog protocol ([`crate::dialog_protocol`]):
//! each message is a 4-byte big-endian length and that many bytes of JSON,
//! at most [`MAX_FRAME`], and unknown fields are refused. The listening
//! socket travels with [`ToBroker::Install`] as `SCM_RIGHTS` data.
//!
//! A grant's conversation:
//!
//! 1. The agent sends [`ToBroker::Install`] — the version, grant ID, token,
//!    credential, profile snapshot and limits — with the listening socket.
//!    The broker checks it ([`Install::validate`]) and answers
//!    [`FromBroker::Ready`].
//! 2. For each request that passes its own checks, the broker sends
//!    [`FromBroker::Admit`] and waits: it forwards the request only after
//!    [`ToBroker::Admitted`], and only if it has not been told to revoke
//!    meanwhile; after [`ToBroker::Refused`] it answers locally. It reports
//!    the end of every admitted request with [`FromBroker::Finished`].
//! 3. [`ToBroker::Revoke`] ends the grant: the broker closes every open
//!    request and stream, drops the credential, answers
//!    [`FromBroker::Revoked`] with the number of requests it refused before
//!    admission, and from then on answers `403` until it exits.
//!
//! The broker exits as soon as the channel ends. Nothing else crosses: no
//! vault, no master password, no requester environment. The token and the
//! credential are kept in buffers that are wiped on drop and never printed:
//! [`Install`]'s `Debug` hides them, and frames are built in one buffer of
//! fixed size ([`encode`]), so that no reallocation leaves a copy behind.
//!
//! The module also names the broker program ([`PROGRAM`]) and opens the file
//! of certificate authorities the broker trusts ([`open_ca_file`]).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::broker_profile::{BrokerProfile, MAX_LIFETIME_MINUTES_RANGE, is_valid_credential};
use crate::protocol::{self, SecretString};

/// Version of this protocol. Both sides refuse any other.
pub const VERSION: u32 = 1;

/// File name of the broker program, which the agent looks for next to its
/// own executable ([`helper_program::locate`](crate::helper_program::locate)).
/// Unlike the dialog program, it has no fallback (ADR 0013).
pub const PROGRAM: &str = "rusthorse-broker";

/// Largest frame body, in bytes.
pub const MAX_FRAME: usize = 64 * 1024;

/// Most grants one agent serves at once.
pub const MAX_GRANTS: usize = 16;

/// Most requests of one grant in flight at once; more get `429` with
/// `retry-after: 1` ([`RETRY_AFTER_SECS`]).
pub const MAX_IN_FLIGHT: u32 = 16;

/// Most open client connections of one grant.
pub const MAX_CONNECTIONS: u32 = 64;

/// The `retry-after` of a local `429` (too many requests in flight) or
/// `503` (no room for the body, [`REQUEST_BODY_BUDGET_BYTES`]), in seconds.
pub const RETRY_AFTER_SECS: u64 = 1;

/// Largest request head (request line and headers), in bytes; a larger one
/// gets `431`.
pub const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

/// How long a request's whole head (request line and headers) may take to
/// arrive, from the moment the connection was opened or the previous
/// response on it was sent.
pub const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest request body, in bytes; a larger one gets `413`. The body is read
/// whole into memory before anything is sent.
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Most bytes of request bodies one broker holds at once. A broker reserves
/// a request's declared length against it before it asks for the request's
/// admission, and releases it once it no longer holds that body; a request
/// that does not fit gets `503` with `retry-after: 1` ([`RETRY_AFTER_SECS`]),
/// and nothing was admitted or sent.
pub const REQUEST_BODY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

// The largest body fits the budget on its own.
const _: () = assert!(MAX_REQUEST_BODY_BYTES <= REQUEST_BODY_BUDGET_BYTES);

/// How long a request body may take to arrive whole.
pub const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a client connection may stay idle before it is closed.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the broker has to resolve the origin's host and connect to one
/// of the addresses it checked, both together.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most host names one broker resolves at a time.
pub const MAX_CONCURRENT_RESOLUTIONS: usize = 4;

/// How long the TLS handshake with the destination may take.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the destination has to send its response headers.
pub const RESPONSE_HEADERS_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The longest pause allowed in a response body.
pub const RESPONSE_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Largest response body relayed, in bytes.
pub const MAX_RESPONSE_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// How long a broker has to answer [`ToBroker::Install`] with
/// [`FromBroker::Ready`] before the agent gives up on it, and on its run.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a broker has to confirm a revocation ([`FromBroker::Revoked`])
/// before the agent kills it.
pub const REVOKE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(1);

/// How long after the control channel ends the agent kills a broker's
/// process group if it is still there (a broker exits at once when the
/// channel ends, without waiting for work in progress).
pub const EXIT_KILL_DELAY: Duration = Duration::from_secs(1);

/// Where the broker reads its certificate authorities: the first of these
/// files that exists, which must be owned by root and not writable by group
/// or others ([`open_ca_file`]). No environment variable changes it
/// (`rusthorse doctor` checks the same files).
pub const CA_FILES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// The file of certificate authorities the broker trusts, as
/// [`open_ca_file`] opened and checked it: the checks were made on this open
/// file, so what was checked is what is read.
#[derive(Debug)]
pub struct CaFile {
    /// Its path, links resolved.
    pub path: PathBuf,
    /// The file, open for reading.
    pub file: File,
}

/// Open the file of certificate authorities the broker trusts: the first of
/// [`CA_FILES`] that exists, links resolved. It must be a regular file owned
/// by root and not writable by its group or by others, which is checked on
/// the open file; and every directory from its parent up to `/` must be
/// owned by root and not writable by its group or by others, so that nobody
/// but root can put another file in its place. The first file that exists
/// decides: when it fails a check, the error names it and says why, and the
/// next one is not tried — nor is it when whether a file exists cannot be
/// told (its directory cannot be examined). The error is plain text, for
/// `rusthorse doctor` to show.
pub fn open_ca_file() -> Result<CaFile, String> {
    open_ca_file_from(&CA_FILES.map(Path::new), 0, Path::new("/"))
}

/// [`open_ca_file`] with its parameters: the files to look for, in order;
/// the owner the file and its directories must have (root: 0); and the
/// highest directory checked, `top` itself included (`/`; when `top` is not
/// on the way, every directory up to `/` is checked).
fn open_ca_file_from(candidates: &[&Path], owner: u32, top: &Path) -> Result<CaFile, String> {
    let mut found = None;
    for candidate in candidates {
        match fs::symlink_metadata(candidate) {
            Ok(_) => {
                found = Some(*candidate);
                break;
            }
            // Nothing there, not even a broken link; a path through a file
            // names nothing either.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            // Whether it exists cannot be told: the next one is not tried.
            Err(e) => return Err(format!("cannot examine {}: {e}", candidate.display())),
        }
    }
    let Some(found) = found else {
        let names: Vec<String> = candidates.iter().map(|c| c.display().to_string()).collect();
        return Err(format!(
            "none of the certificate authority files exists: {}",
            names.join(", ")
        ));
    };
    let path =
        fs::canonicalize(found).map_err(|e| format!("cannot resolve {}: {e}", found.display()))?;
    let file = open_no_follow(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot examine {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.uid() != owner {
        return Err(format!(
            "{} is not owned by {}",
            path.display(),
            owner_name(owner)
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be modified by its group or by others",
            path.display()
        ));
    }
    check_directories(&path, owner, top)?;
    Ok(CaFile { path, file })
}

/// Open `path` for reading without following a link at its end
/// (`O_NOFOLLOW`), closed on exec (`O_CLOEXEC`), and without waiting
/// (`O_NONBLOCK`, cleared once it is open): a FIFO is then refused as not a
/// regular file instead of waiting for a writer.
fn open_no_follow(path: &Path) -> io::Result<File> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::libc::{O_CLOEXEC, O_NOFOLLOW, O_NONBLOCK};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        .open(path)?;
    let flags = OFlag::from_bits_retain(fcntl(&file, FcntlArg::F_GETFL)?);
    fcntl(
        &file,
        FcntlArg::F_SETFL(flags.difference(OFlag::O_NONBLOCK)),
    )?;
    Ok(file)
}

/// Check every directory from the parent of `path` up to `top`, included
/// (up to `/` when `top` is not on the way): a directory, owned by `owner`,
/// not writable by its group or by others.
fn check_directories(path: &Path, owner: u32, top: &Path) -> Result<(), String> {
    for dir in path.ancestors().skip(1) {
        let meta = fs::symlink_metadata(dir)
            .map_err(|e| format!("cannot examine {}: {e}", dir.display()))?;
        if !meta.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        if meta.uid() != owner {
            return Err(format!(
                "{} is in {}, which is not owned by {}",
                path.display(),
                dir.display(),
                owner_name(owner)
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is in {}, which can be modified by its group or by others",
                path.display(),
                dir.display()
            ));
        }
        if dir == top {
            break;
        }
    }
    Ok(())
}

/// How errors name the owner a file must have.
fn owner_name(owner: u32) -> String {
    if owner == 0 {
        "root".into()
    } else {
        format!("user {owner}")
    }
}

/// What every token starts with.
pub const TOKEN_PREFIX: &str = "rh_";

/// Length of a token: [`TOKEN_PREFIX`] and 64 hexadecimal digits.
pub const TOKEN_LEN: usize = TOKEN_PREFIX.len() + 64;

/// Length of a grant ID: `g` and 16 hexadecimal digits.
pub const GRANT_ID_LEN: usize = 17;

/// What the agent tells a broker.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToBroker {
    /// Serve a grant: the first message, sent once, with the listening
    /// socket attached.
    Install(Install),
    /// Forward the request: its admission is recorded.
    Admitted {
        /// The request's number, from [`FromBroker::Admit`].
        request: u64,
    },
    /// Do not forward the request; answer it locally.
    Refused {
        /// The request's number, from [`FromBroker::Admit`].
        request: u64,
        /// Why.
        reason: AdmissionRefusal,
    },
    /// End the grant: admit nothing more, close every open request and
    /// stream, drop the credential, answer [`FromBroker::Revoked`] within
    /// [`REVOKE_CONFIRM_TIMEOUT`], and answer `403` from then on.
    /// [`FromBroker::Revoked`] follows the answers to every
    /// [`FromBroker::Admit`] sent before it, and the
    /// [`FromBroker::Finished`] of every admitted request: an answer may
    /// arrive after this message, and an [`ToBroker::Admitted`] that does is
    /// not forwarded (its request finishes `revoked`). On a revocation the
    /// agent answers at once every admission still waiting for its answer —
    /// [`ToBroker::Refused`], `revoked` — without waiting for its audit
    /// record, so that the confirmation never waits for the audit log.
    ///
    /// The agent accepts a [`FromBroker::Revoked`] that comes before the
    /// [`FromBroker::Finished`] of some admitted requests: it counts each of
    /// them as `unknown` in the grant's end record (the destination may have
    /// acted on it). Nothing may follow the confirmation: any message after
    /// it is a broken broker, which the agent kills.
    Revoke {
        /// Why the grant ends.
        reason: EndReason,
    },
}

/// Everything a broker gets to serve one grant (with the listening socket,
/// which travels beside it). A broker checks it with
/// [`Install::validate`] before serving anything.
///
/// The token and the credential are decoded straight from the frame's
/// buffer into buffers that are wiped on drop, except for a credential with
/// a character that JSON escapes (`"` or `\`): `serde_json` decodes escapes
/// through scratch buffers it does not wipe, as on the client socket.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    /// [`VERSION`].
    pub version: u32,
    /// The grant's ID ([`new_grant_id`]).
    pub grant: String,
    /// The token the command was given, which clients present
    /// ([`new_token`]).
    pub token: SecretString,
    /// The entry's value: the credential the broker presents to the
    /// destination.
    pub credential: SecretString,
    /// The entry's profile, as it was when the grant was created.
    pub profile: BrokerProfile,
    /// Most requests in flight at once ([`MAX_IN_FLIGHT`] at most).
    pub max_in_flight: u32,
    /// Most open client connections ([`MAX_CONNECTIONS`] at most).
    pub max_connections: u32,
    /// Seconds the grant has left: at most the profile's maximum lifetime.
    /// The agent ends it then; the broker stops serving then too, should
    /// the agent's word not come.
    pub lifetime_secs: u64,
}

impl fmt::Debug for Install {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Install")
            .field("version", &self.version)
            .field("grant", &self.grant)
            .field("token", &"<hidden>")
            .field("credential", &"<hidden>")
            .field("profile", &self.profile)
            .field("max_in_flight", &self.max_in_flight)
            .field("max_connections", &self.max_connections)
            .field("lifetime_secs", &self.lifetime_secs)
            .finish()
    }
}

impl Install {
    /// Check what a broker must check before serving: this protocol's
    /// version, the forms of the grant ID and of the token, a credential
    /// that can be sent in a header ([`is_valid_credential`]), a valid
    /// profile, limits within phase 1's, and a lifetime of at most the
    /// profile's maximum (and so at most a day). The reason never contains a
    /// secret.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("another version of the control protocol");
        }
        if !is_well_formed_grant_id(&self.grant) {
            return Err("a malformed grant ID");
        }
        if !is_well_formed_token(&self.token) {
            return Err("a malformed token");
        }
        if !is_valid_credential(&self.credential) {
            return Err("a credential that cannot be sent in a header");
        }
        if self.profile.validate().is_err() {
            return Err("an unusable profile");
        }
        if !(1..=MAX_IN_FLIGHT).contains(&self.max_in_flight) {
            return Err("a limit of requests in flight out of range");
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err("a limit of connections out of range");
        }
        let longest = u64::from(*MAX_LIFETIME_MINUTES_RANGE.end()) * 60;
        if !(1..=longest).contains(&self.lifetime_secs) {
            return Err("a lifetime out of range");
        }
        if self.lifetime_secs > u64::from(self.profile.max_lifetime_minutes) * 60 {
            return Err("a lifetime longer than the profile allows");
        }
        Ok(())
    }
}

/// What a broker tells the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromBroker {
    /// The grant is installed and its socket is served: the answer to
    /// [`ToBroker::Install`].
    Ready {
        /// [`VERSION`].
        version: u32,
        /// The grant's ID, as installed.
        grant: String,
    },
    /// Ask to forward a request that passed the broker's own checks: its
    /// framing, its token, its route, and its declared body length, which
    /// fits [`MAX_REQUEST_BODY_BYTES`] and is already reserved from
    /// [`REQUEST_BODY_BUDGET_BYTES`]. The body itself is read only after
    /// [`ToBroker::Admitted`]; nothing is forwarded before it.
    Admit {
        /// A number the broker gives the request, counting from 1; distinct
        /// within the grant.
        request: u64,
        /// The request's method (`POST`).
        method: String,
        /// The route it matched, as
        /// [`MatchedRoute::template`](crate::broker_profile::MatchedRoute::template)
        /// writes it (`POST /v1/messages`): never the raw path.
        route: String,
    },
    /// An admitted request ended.
    Finished {
        /// The request's number.
        request: u64,
        /// How it ended.
        outcome: RequestOutcome,
        /// The destination's status, when its answer began to arrive.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        /// Bytes of the request body sent to the destination.
        bytes_sent: u64,
        /// Bytes of the response body received from the destination.
        bytes_received: u64,
    },
    /// The grant is revoked: every open request and stream is closed and the
    /// credential dropped. The answer to [`ToBroker::Revoke`].
    Revoked {
        /// Requests the broker refused before asking for their admission
        /// (counted, not reported one by one, so that a client cannot flood
        /// the audit log).
        refused: u64,
    },
}

/// Why the agent did not admit a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRefusal {
    /// The grant was revoked, or is being revoked.
    Revoked,
    /// The grant's maximum lifetime has passed.
    Expired,
    /// The grant's request limit is reached.
    Exhausted,
    /// The grant has the most requests in flight it may have.
    TooManyInFlight,
    /// The admission could not be recorded in the audit log.
    AuditFailed,
}

impl AdmissionRefusal {
    /// The serialized form: `revoked`, `expired`, `exhausted`,
    /// `too_many_in_flight`, `audit_failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
            Self::TooManyInFlight => "too_many_in_flight",
            Self::AuditFailed => "audit_failed",
        }
    }
}

/// How an admitted request ended, as the audit log records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    /// The destination's whole answer was relayed to the client.
    Completed,
    /// Nothing reached the destination (the connection or the TLS
    /// handshake failed, or the grant ended first).
    NotForwarded,
    /// The client went away before the answer was complete; the
    /// destination may have acted on the request.
    ClientClosed,
    /// The grant was revoked while the request was open; the destination
    /// may have acted on it.
    Revoked,
    /// Anything else after the request was sent: whether the destination
    /// acted on it is unknown.
    Unknown,
}

impl RequestOutcome {
    /// The form audit records use: `completed`, `not_forwarded`,
    /// `client_closed`, `revoked`, `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::NotForwarded => "not_forwarded",
            Self::ClientClosed => "client_closed",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }
}

/// Why a grant ended, as the audit log records it (ADR 0013, decision 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The command's leader exited, or the requester disconnected.
    CommandEnded,
    /// `rusthorse lock`.
    Locked,
    /// The screen locked (a profile with automatic locks `end`).
    ScreenLocked,
    /// The computer is about to suspend (automatic locks `end`).
    Suspend,
    /// The vault locked after idle time (automatic locks `end`).
    IdleTimeout,
    /// Revoked by hand: `rusthorse grants revoke` or the manager.
    Revoked,
    /// The grant's entry changed or was removed.
    EntryChanged,
    /// The vault file was changed by another program while the vault was
    /// locked, as the agent found when it was unlocked again (the unlock
    /// barrier): every grant that survived the lock ends.
    VaultChanged,
    /// Its maximum lifetime passed.
    Expired,
    /// Its broker process failed.
    BrokerFailed,
    /// A save of the vault failed.
    SaveFailed,
    /// The agent is stopping.
    AgentStopped,
    /// A record of one of its requests could not be written.
    AuditFailed,
}

impl EndReason {
    /// The form audit records use: `command_ended`, `locked`,
    /// `screen_locked`, `suspend`, `idle_timeout`, `revoked`,
    /// `entry_changed`, `vault_changed`, `expired`, `broker_failed`,
    /// `save_failed`, `agent_stopped`, `audit_failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommandEnded => "command_ended",
            Self::Locked => "locked",
            Self::ScreenLocked => "screen_locked",
            Self::Suspend => "suspend",
            Self::IdleTimeout => "idle_timeout",
            Self::Revoked => "revoked",
            Self::EntryChanged => "entry_changed",
            Self::VaultChanged => "vault_changed",
            Self::Expired => "expired",
            Self::BrokerFailed => "broker_failed",
            Self::SaveFailed => "save_failed",
            Self::AgentStopped => "agent_stopped",
            Self::AuditFailed => "audit_failed",
        }
    }
}

/// An [`io::Write`] into a buffer that never grows past `limit` bytes: the
/// buffer is allocated once, and a message that does not fit is refused.
struct Bounded<'a> {
    buffer: &'a mut Vec<u8>,
    limit: usize,
}

impl Write for Bounded<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buffer.len() + data.len() > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the message does not fit in a frame",
            ));
        }
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encode `message` as one frame: the length of its JSON (4 bytes,
/// big-endian) and the JSON. Refuses a message larger than [`MAX_FRAME`].
/// The frame is written into one buffer allocated at its largest size, so
/// that no reallocation leaves a copy of a token or a credential behind; the
/// buffer is wiped on drop.
pub fn encode<T: Serialize>(message: &T) -> io::Result<Zeroizing<Vec<u8>>> {
    let limit = 4 + MAX_FRAME;
    let mut frame = Zeroizing::new(Vec::with_capacity(limit));
    frame.extend_from_slice(&[0; 4]);
    let writer = Bounded {
        buffer: &mut frame,
        limit,
    };
    serde_json::to_writer(writer, message).map_err(|e| {
        if e.is_io() {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("message larger than {MAX_FRAME} bytes"),
            )
        } else {
            io::Error::other(e)
        }
    })?;
    let len = (frame.len() - 4) as u32;
    frame[..4].copy_from_slice(&len.to_be_bytes());
    Ok(frame)
}

/// The length of the body that follows a frame's 4-byte header, refused
/// when it is larger than [`MAX_FRAME`] — before the body is read.
pub fn body_len(header: [u8; 4]) -> io::Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes, limit {MAX_FRAME}"),
        ));
    }
    Ok(len)
}

/// The first whole frame at the start of `buffer`: its body and how many
/// bytes of `buffer` the frame takes; `None` while it is incomplete. A frame
/// larger than [`MAX_FRAME`] is refused as soon as its header is there. For
/// readers that collect bytes themselves, such as an asynchronous one.
pub fn split_frame(buffer: &[u8]) -> io::Result<Option<(&[u8], usize)>> {
    let Some(header) = buffer.first_chunk::<4>() else {
        return Ok(None);
    };
    let len = body_len(*header)?;
    Ok(buffer.get(4..4 + len).map(|body| (body, 4 + len)))
}

/// Decode a frame's body. Unknown fields, types and values are refused; the
/// error says where, never what (a body may hold a token or a credential).
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> io::Result<T> {
    serde_json::from_slice(body).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "malformed message ({:?} error at line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
    })
}

/// Write `message` on `stream` as one frame, attaching `fds` (at most
/// [`protocol::MAX_FDS`]) as `SCM_RIGHTS` to its first byte.
pub fn write_message<T: Serialize>(
    stream: &UnixStream,
    message: &T,
    fds: &[BorrowedFd<'_>],
) -> io::Result<()> {
    let frame = encode(message)?;
    protocol::send_encoded(stream, &frame, fds)
}

/// Read one frame from `stream` — whole by `deadline`, if one is given —
/// and decode it. Returns the message and the file descriptors attached to
/// it (dropping them closes them). A frame larger than [`MAX_FRAME`] is
/// refused before its body is read.
pub fn read_message<T: DeserializeOwned>(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> io::Result<(T, Vec<OwnedFd>)> {
    let (body, fds) = protocol::recv_message_before(stream, deadline, MAX_FRAME)?;
    Ok((decode(&body)?, fds))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

/// A new token: [`TOKEN_PREFIX`] and 64 lowercase hexadecimal digits, from
/// 32 bytes of the operating system's random generator.
///
/// # Panics
///
/// When the operating system cannot provide random bytes;
/// [`try_new_token`] reports that instead.
pub fn new_token() -> SecretString {
    try_new_token().expect("the operating system provides random bytes")
}

/// [`new_token`], reporting a failure of the random generator.
pub fn try_new_token() -> Result<SecretString, getrandom::Error> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes)?;
    let mut token = SecretString::new(String::with_capacity(TOKEN_LEN));
    token.push_str(TOKEN_PREFIX);
    push_hex(&mut token, &*bytes);
    Ok(token)
}

/// A new grant ID: `g` and 16 lowercase hexadecimal digits, random. It is
/// public: the audit log, `rusthorse grants` and the manager show it.
///
/// # Panics
///
/// When the operating system cannot provide random bytes;
/// [`try_new_grant_id`] reports that instead.
pub fn new_grant_id() -> String {
    try_new_grant_id().expect("the operating system provides random bytes")
}

/// [`new_grant_id`], reporting a failure of the random generator.
pub fn try_new_grant_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)?;
    let mut id = String::with_capacity(GRANT_ID_LEN);
    id.push('g');
    push_hex(&mut id, &bytes);
    Ok(id)
}

fn is_lower_hex(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `token` has exactly the form of a token: [`TOKEN_PREFIX`] and 64
/// lowercase hexadecimal digits. Anything else is refused before it is
/// compared with a grant's token.
pub fn is_well_formed_token(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token.starts_with(TOKEN_PREFIX)
        && is_lower_hex(&token.as_bytes()[TOKEN_PREFIX.len()..])
}

/// Whether `id` has exactly the form of a grant ID: `g` and 16 lowercase
/// hexadecimal digits.
pub fn is_well_formed_grant_id(id: &str) -> bool {
    id.len() == GRANT_ID_LEN && id.starts_with('g') && is_lower_hex(&id.as_bytes()[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_profile::{Preset, ProfileRequest};
    use std::io::Read;
    use std::os::fd::AsFd;

    const FAKE_CREDENTIAL: &str = "FAKE-credential-sk-0123456789";

    fn install() -> Install {
        Install {
            version: VERSION,
            grant: new_grant_id(),
            token: new_token(),
            credential: SecretString::new(FAKE_CREDENTIAL.into()),
            profile: ProfileRequest::new(Preset::Anthropic)
                .resolve()
                .expect("profile"),
            max_in_flight: MAX_IN_FLIGHT,
            max_connections: MAX_CONNECTIONS,
            lifetime_secs: 720 * 60,
        }
    }

    fn from_broker() -> Vec<FromBroker> {
        vec![
            FromBroker::Ready {
                version: VERSION,
                grant: "g0123456789abcdef".into(),
            },
            FromBroker::Admit {
                request: 1,
                method: "POST".into(),
                route: "POST /v1/messages".into(),
            },
            FromBroker::Finished {
                request: 1,
                outcome: RequestOutcome::Completed,
                status: Some(200),
                bytes_sent: 1234,
                bytes_received: u64::MAX,
            },
            FromBroker::Finished {
                request: 2,
                outcome: RequestOutcome::NotForwarded,
                status: None,
                bytes_sent: 0,
                bytes_received: 0,
            },
            FromBroker::Revoked { refused: 7 },
        ]
    }

    fn round_trip<T: Serialize + DeserializeOwned>(message: &T) -> T {
        let frame = encode(message).expect("encode");
        let (body, used) = split_frame(&frame)
            .expect("a valid frame")
            .expect("a whole frame");
        assert_eq!(used, frame.len());
        decode(body).expect("decode")
    }

    #[test]
    fn messages_round_trip() {
        for message in from_broker() {
            assert_eq!(round_trip(&message), message);
        }
        let sent = install();
        let ToBroker::Install(got) = round_trip(&ToBroker::Install(install_copy(&sent))) else {
            panic!("not an install")
        };
        assert_eq!(got.grant, sent.grant);
        assert_eq!(got.token.as_str(), sent.token.as_str());
        assert_eq!(got.credential.as_str(), FAKE_CREDENTIAL);
        assert_eq!(got.profile, sent.profile);
        assert_eq!(got.validate(), Ok(()));
        assert!(matches!(
            round_trip(&ToBroker::Admitted { request: 3 }),
            ToBroker::Admitted { request: 3 }
        ));
        assert!(matches!(
            round_trip(&ToBroker::Refused {
                request: 4,
                reason: AdmissionRefusal::TooManyInFlight
            }),
            ToBroker::Refused {
                request: 4,
                reason: AdmissionRefusal::TooManyInFlight
            }
        ));
        assert!(matches!(
            round_trip(&ToBroker::Revoke {
                reason: EndReason::EntryChanged
            }),
            ToBroker::Revoke {
                reason: EndReason::EntryChanged
            }
        ));
    }

    fn install_copy(install: &Install) -> Install {
        Install {
            version: install.version,
            grant: install.grant.clone(),
            token: install.token.clone(),
            credential: install.credential.clone(),
            profile: install.profile.clone(),
            max_in_flight: install.max_in_flight,
            max_connections: install.max_connections,
            lifetime_secs: install.lifetime_secs,
        }
    }

    #[test]
    fn the_wire_form_is_tagged_json() {
        let frame = encode(&FromBroker::Admit {
            request: 9,
            method: "GET".into(),
            route: "GET /v1/models".into(),
        })
        .expect("encode");
        let body = &frame[4..];
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().expect("4")) as usize,
            body.len()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(body).expect("json"),
            serde_json::json!({"type": "admit", "request": 9, "method": "GET", "route": "GET /v1/models"})
        );
        let finished = serde_json::to_value(FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::ClientClosed,
            status: None,
            bytes_sent: 1,
            bytes_received: 2,
        })
        .expect("json");
        assert!(finished.get("status").is_none(), "{finished}");
        assert_eq!(finished["outcome"], "client_closed");
        let install = serde_json::to_value(ToBroker::Install(install())).expect("json");
        assert_eq!(install["type"], "install");
        assert_eq!(install["profile"]["preset"], "anthropic");
    }

    #[test]
    fn frames_carry_the_listening_socket() {
        let (agent, broker) = UnixStream::pair().expect("socket pair");
        // Any descriptor will do as the "listening socket": a pipe's write
        // end, so that the test can see the received one is the same.
        let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe");
        let sent = install();
        let token = sent.token.clone();
        write_message(&agent, &ToBroker::Install(sent), &[pipe_w.as_fd()]).expect("send");
        drop(pipe_w);
        let deadline = Some(Instant::now() + Duration::from_secs(10));
        let (message, fds) = read_message::<ToBroker>(&broker, deadline).expect("receive");
        let ToBroker::Install(got) = message else {
            panic!("not an install")
        };
        assert_eq!(got.token.as_str(), token.as_str());
        assert_eq!(fds.len(), 1);
        let mut writer = std::fs::File::from(fds.into_iter().next().expect("fd"));
        writer.write_all(b"hi").expect("write");
        drop(writer);
        let mut text = String::new();
        std::fs::File::from(pipe_r)
            .read_to_string(&mut text)
            .expect("read");
        assert_eq!(text, "hi");

        // And back, without descriptors.
        write_message(&broker, &FromBroker::Revoked { refused: 2 }, &[]).expect("send");
        let (answer, fds) = read_message::<FromBroker>(&agent, None).expect("receive");
        assert_eq!(answer, FromBroker::Revoked { refused: 2 });
        assert!(fds.is_empty());
        // At most three descriptors, as on the client socket.
        let many: Vec<(OwnedFd, OwnedFd)> =
            (0..4).map(|_| nix::unistd::pipe().expect("pipe")).collect();
        let borrowed: Vec<BorrowedFd<'_>> = many.iter().map(|(r, _)| r.as_fd()).collect();
        assert!(write_message(&agent, &FromBroker::Revoked { refused: 0 }, &borrowed).is_err());
    }

    #[test]
    fn frames_larger_than_the_limit_are_refused() {
        // Too large to send: nothing is written.
        let mut big = install();
        big.credential = SecretString::new("k".repeat(MAX_FRAME));
        let err = encode(&ToBroker::Install(big)).expect_err("too large");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!err.to_string().contains("kkkk"), "{err}");
        // The largest body that fits does.
        let route = "x".repeat(MAX_FRAME - 100);
        let mut fits = FromBroker::Admit {
            request: 1,
            method: "POST".into(),
            route,
        };
        let len = serde_json::to_vec(&fits).expect("json").len();
        if let FromBroker::Admit { route, .. } = &mut fits {
            route.push_str(&"x".repeat(MAX_FRAME - len));
        }
        let frame = encode(&fits).expect("exactly the limit");
        assert_eq!(frame.len(), 4 + MAX_FRAME);
        assert_eq!(round_trip(&fits), fits);

        // Too large to receive: refused from the header alone, before the
        // body is read (none is sent here, and reading does not wait).
        let (a, b) = UnixStream::pair().expect("socket pair");
        (&a).write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .expect("write");
        let err = read_message::<FromBroker>(&b, None).expect_err("too large");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // A length word with the high bit set is no exception.
        (&a).write_all(&0x8000_0010_u32.to_be_bytes())
            .expect("write");
        let err = read_message::<FromBroker>(&b, None).expect_err("too large");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(body_len((MAX_FRAME as u32 + 1).to_be_bytes()).is_err());
        assert_eq!(
            body_len((MAX_FRAME as u32).to_be_bytes()).expect("fits"),
            MAX_FRAME
        );
        let mut header = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        assert!(split_frame(&header).is_err());
        header.extend_from_slice(b"{}");
        assert!(split_frame(&header).is_err());
    }

    #[test]
    fn incomplete_frames_wait_and_slow_ones_time_out() {
        let frame = encode(&FromBroker::Revoked { refused: 1 }).expect("encode");
        for cut in 0..frame.len() {
            assert!(
                split_frame(&frame[..cut]).expect("not an error").is_none(),
                "{cut}"
            );
        }
        let mut two = frame.to_vec();
        two.extend_from_slice(&frame);
        let (body, used) = split_frame(&two).expect("valid").expect("whole");
        assert_eq!(used, frame.len());
        assert_eq!(
            decode::<FromBroker>(body).expect("decode"),
            FromBroker::Revoked { refused: 1 }
        );

        // A peer that sends a byte at a time cannot hold a reader past its
        // deadline.
        let (a, b) = UnixStream::pair().expect("socket pair");
        let bytes = frame.to_vec();
        let writer = std::thread::spawn(move || {
            for byte in bytes {
                std::thread::sleep(Duration::from_millis(150));
                if (&a).write_all(&[byte]).is_err() {
                    return;
                }
            }
        });
        let deadline = Some(Instant::now() + Duration::from_millis(400));
        let err = read_message::<FromBroker>(&b, deadline).expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(b);
        let _ = writer.join();
    }

    #[test]
    fn unknown_fields_types_and_values_are_refused() {
        let good = serde_json::to_value(ToBroker::Install(install())).expect("json");
        assert!(serde_json::from_value::<ToBroker>(good.clone()).is_ok());
        let mut extra = good.clone();
        extra["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ToBroker>(extra).is_err());
        let mut profile = good.clone();
        profile["profile"]["routes"] = serde_json::json!(["POST /v1/files"]);
        assert!(serde_json::from_value::<ToBroker>(profile).is_err());
        let mut missing = good;
        missing
            .as_object_mut()
            .expect("object")
            .remove("lifetime_secs");
        assert!(serde_json::from_value::<ToBroker>(missing).is_err());

        for bad in [
            &br#"{"type":"admitted","request":1,"extra":true}"#[..],
            br#"{"type":"admitted"}"#,
            br#"{"type":"admitted","request":-1}"#,
            br#"{"type":"refused","request":1,"reason":"bored"}"#,
            br#"{"type":"revoke","reason":"locked","why":"x"}"#,
            br#"{"type":"revoke","reason":"Locked"}"#,
            br#"{"type":"unlock"}"#,
            br#"{"request":1}"#,
            br#"[]"#,
            b"",
        ] {
            assert!(
                decode::<ToBroker>(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        for bad in [
            &br#"{"type":"ready","version":1,"grant":"g1","extra":1}"#[..],
            br#"{"type":"admit","request":1,"method":"POST","route":"POST /v1/messages","path":"/v1/messages"}"#,
            br#"{"type":"finished","request":1,"outcome":"done","bytes_sent":0,"bytes_received":0}"#,
            br#"{"type":"finished","request":1,"outcome":"completed","status":70000,"bytes_sent":0,"bytes_received":0}"#,
            br#"{"type":"finished","request":1,"outcome":"completed","bytes_sent":0}"#,
            br#"{"type":"revoked"}"#,
            br#"{"type":"revoked","refused":1,"open":2}"#,
        ] {
            assert!(
                decode::<FromBroker>(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // Errors say where, not what: a value never shows in them.
        let err =
            decode::<ToBroker>(br#"{"type":"refused","request":1,"reason":"FAKE-secret-value"}"#)
                .expect_err("unknown reason");
        assert!(!err.to_string().contains("FAKE-secret"), "{err}");
    }

    #[test]
    fn debug_output_never_shows_the_token_or_the_credential() {
        let install = install();
        let token = install.token.to_string();
        for shown in [
            format!("{install:?}"),
            format!("{install:#?}"),
            format!("{:?}", ToBroker::Install(install_copy(&install))),
        ] {
            assert!(!shown.contains(&token), "{shown}");
            assert!(!shown.contains(&token[TOKEN_PREFIX.len()..]), "{shown}");
            assert!(!shown.contains(FAKE_CREDENTIAL), "{shown}");
            assert!(shown.contains("<hidden>"), "{shown}");
            assert!(shown.contains(&install.grant), "{shown}");
        }
    }

    /// A change that makes an install invalid.
    type Spoil = fn(&mut Install);

    #[test]
    fn installs_are_checked_before_anything_is_served() {
        assert_eq!(install().validate(), Ok(()));
        let secret = |text: &str| SecretString::new(text.into());
        let cases: &[(&str, Spoil)] = &[
            ("version", |i| i.version = VERSION + 1),
            ("grant", |i| i.grant = "g123".into()),
            ("grant case", |i| i.grant = i.grant.to_uppercase()),
            ("token", |i| i.token = SecretString::new("rh_123".into())),
            ("no credential", |i| i.credential = SecretString::default()),
            // Too short for the redactor (shorter than 4), or than phase 1
            // allows (8): an echo would reach the client as it is.
            ("3 characters", |i| {
                i.credential = SecretString::new("abc".into())
            }),
            ("7 characters", |i| {
                i.credential = SecretString::new("k".repeat(7))
            }),
            ("4097 characters", |i| {
                i.credential = SecretString::new("k".repeat(4097))
            }),
            ("line break", |i| {
                i.credential = SecretString::new("sk-1234\r\nb".into())
            }),
            ("profile", |i| i.profile.max_lifetime_minutes = 0),
            ("revision", |i| i.profile.revision = 99),
            ("none in flight", |i| i.max_in_flight = 0),
            ("too many in flight", |i| {
                i.max_in_flight = MAX_IN_FLIGHT + 1
            }),
            ("no connections", |i| i.max_connections = 0),
            ("too many connections", |i| i.max_connections = 65),
            ("no lifetime", |i| i.lifetime_secs = 0),
            ("more than a day", |i| i.lifetime_secs = 24 * 3600 + 1),
            ("longer than the profile", |i| {
                i.lifetime_secs = u64::from(i.profile.max_lifetime_minutes) * 60 + 1
            }),
            ("a day, with a shorter profile", |i| {
                i.profile.max_lifetime_minutes = 60;
                i.lifetime_secs = 24 * 3600;
            }),
        ];
        for (what, spoil) in cases {
            let mut install = install();
            spoil(&mut install);
            let reason = install.validate().expect_err(what);
            assert!(!reason.contains(FAKE_CREDENTIAL), "{what}: {reason}");
        }
        // The token and the credential may be anything of their form.
        let mut other = install();
        other.credential = secret("sk-ant-api03-FAKE_x-y.z~1");
        other.token = secret(&format!("rh_{}", "f".repeat(64)));
        assert_eq!(other.validate(), Ok(()));
        for length in [8, 4096] {
            other.credential = secret(&"k".repeat(length));
            assert_eq!(other.validate(), Ok(()), "{length} characters");
        }
    }

    #[test]
    fn tokens_and_grant_ids_have_their_exact_form() {
        let tokens: Vec<SecretString> = (0..16).map(|_| new_token()).collect();
        for token in &tokens {
            assert_eq!(token.len(), TOKEN_LEN);
            assert!(token.starts_with("rh_"), "{}", token.as_str());
            assert!(is_well_formed_token(token), "{}", token.as_str());
        }
        // Random: all different, and every hexadecimal digit shows up in
        // 1024 of them (each would be missing with odds of about 2^-95).
        for (i, a) in tokens.iter().enumerate() {
            for b in &tokens[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
        let digits: std::collections::BTreeSet<u8> = tokens
            .iter()
            .flat_map(|t| t.as_bytes()[3..].to_vec())
            .collect();
        assert_eq!(digits.len(), 16, "{digits:?}");
        assert!(try_new_token().is_ok());

        let id = new_grant_id();
        assert_eq!(id.len(), GRANT_ID_LEN);
        assert!(is_well_formed_grant_id(&id), "{id}");
        assert_ne!(new_grant_id(), new_grant_id());
        assert!(try_new_grant_id().is_ok());

        let hex64 = "0123456789abcdef".repeat(4);
        assert!(is_well_formed_token(&format!("rh_{hex64}")));
        for bad in [
            String::new(),
            "rh_".into(),
            format!("rh_{}", &hex64[1..]),
            format!("rh_{hex64}0"),
            format!("rh_{}", hex64.to_uppercase()),
            format!("RH_{hex64}"),
            format!("rh-{hex64}"),
            format!("xx_{hex64}"),
            format!(" rh_{}", &hex64[1..]),
            format!("rh_{}g", &hex64[1..]),
            format!("rh_{}\u{e9}", &hex64[2..]),
        ] {
            assert!(!is_well_formed_token(&bad), "{bad:?}");
        }
        assert!(is_well_formed_grant_id("g0123456789abcdef"));
        for bad in [
            "",
            "g",
            "g0123456789abcde",
            "g0123456789abcdef0",
            "G0123456789abcdef",
            "g0123456789ABCDEF",
            "h0123456789abcdef",
            "g0123456789abcdeg",
        ] {
            assert!(!is_well_formed_grant_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn audit_strings_are_the_serialized_names() {
        for reason in [
            EndReason::CommandEnded,
            EndReason::Locked,
            EndReason::ScreenLocked,
            EndReason::Suspend,
            EndReason::IdleTimeout,
            EndReason::Revoked,
            EndReason::EntryChanged,
            EndReason::VaultChanged,
            EndReason::Expired,
            EndReason::BrokerFailed,
            EndReason::SaveFailed,
            EndReason::AgentStopped,
            EndReason::AuditFailed,
        ] {
            assert_eq!(
                serde_json::to_value(reason).expect("json"),
                serde_json::json!(reason.as_str())
            );
        }
        // Every reason ADR 0013's audit records name, and every outcome:
        // each one is a value both sides of the channel read.
        for name in [
            "command_ended",
            "locked",
            "screen_locked",
            "suspend",
            "idle_timeout",
            "revoked",
            "entry_changed",
            "vault_changed",
            "expired",
            "broker_failed",
            "save_failed",
            "agent_stopped",
            "audit_failed",
        ] {
            let reason: EndReason = serde_json::from_value(serde_json::json!(name)).expect(name);
            assert_eq!(reason.as_str(), name);
            let frame = format!(r#"{{"type":"revoke","reason":"{name}"}}"#);
            assert!(matches!(
                decode::<ToBroker>(frame.as_bytes()),
                Ok(ToBroker::Revoke { reason: got }) if got == reason
            ));
        }
        for name in [
            "completed",
            "not_forwarded",
            "client_closed",
            "revoked",
            "unknown",
        ] {
            let outcome: RequestOutcome =
                serde_json::from_value(serde_json::json!(name)).expect(name);
            assert_eq!(outcome.as_str(), name);
        }
        for outcome in [
            RequestOutcome::Completed,
            RequestOutcome::NotForwarded,
            RequestOutcome::ClientClosed,
            RequestOutcome::Revoked,
            RequestOutcome::Unknown,
        ] {
            assert_eq!(
                serde_json::to_value(outcome).expect("json"),
                serde_json::json!(outcome.as_str())
            );
        }
        for refusal in [
            AdmissionRefusal::Revoked,
            AdmissionRefusal::Expired,
            AdmissionRefusal::Exhausted,
            AdmissionRefusal::TooManyInFlight,
            AdmissionRefusal::AuditFailed,
        ] {
            assert_eq!(
                serde_json::to_value(refusal).expect("json"),
                serde_json::json!(refusal.as_str())
            );
        }
        assert_eq!(EndReason::CommandEnded.as_str(), "command_ended");
        assert_eq!(RequestOutcome::NotForwarded.as_str(), "not_forwarded");
        assert_eq!(
            AdmissionRefusal::TooManyInFlight.as_str(),
            "too_many_in_flight"
        );
    }

    /// ADR 0013's numbers, section by section: changing one changes the ADR.
    #[test]
    fn the_limits_are_those_of_phase_1() {
        // Requests and responses.
        assert_eq!(MAX_REQUEST_HEADER_BYTES, 32 * 1024);
        assert_eq!(REQUEST_HEADER_TIMEOUT, Duration::from_secs(30));
        assert_eq!(MAX_REQUEST_BODY_BYTES, 16 * 1024 * 1024);
        assert_eq!(REQUEST_BODY_BUDGET_BYTES, 64 * 1024 * 1024);
        assert_eq!(RETRY_AFTER_SECS, 1);
        assert_eq!(REQUEST_BODY_TIMEOUT, Duration::from_secs(60));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(MAX_CONCURRENT_RESOLUTIONS, 4);
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 64 * 1024 * 1024);
        // Admission, revocation and the agent's registry.
        assert_eq!(READY_TIMEOUT, Duration::from_secs(10));
        assert_eq!(REVOKE_CONFIRM_TIMEOUT, Duration::from_secs(1));
        assert_eq!(MAX_GRANTS, 16);
        assert_eq!(MAX_IN_FLIGHT, 16);
        assert_eq!(MAX_CONNECTIONS, 64);
        assert_eq!(IDLE_CONNECTION_TIMEOUT, Duration::from_secs(60));
        assert_eq!(TLS_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(RESPONSE_HEADERS_TIMEOUT, Duration::from_secs(600));
        assert_eq!(RESPONSE_BODY_IDLE_TIMEOUT, Duration::from_secs(300));
        assert_eq!(EXIT_KILL_DELAY, Duration::from_secs(1));
        // The control channel, and the token.
        assert_eq!(MAX_FRAME, 64 * 1024);
        assert_eq!(TOKEN_LEN, 67);
        assert_eq!(GRANT_ID_LEN, 17);
        // Components and processes: the program, and the files it trusts.
        assert_eq!(PROGRAM, "rusthorse-broker");
        assert_eq!(
            CA_FILES,
            [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            ]
        );
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// A temporary directory for files of certificate authorities, links
    /// resolved, with mode 0755 whatever the umask: the highest directory
    /// the checks look at in these tests.
    fn ca_top() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let top = fs::canonicalize(dir.path()).expect("canonical");
        set_mode(&top, 0o755);
        (dir, top)
    }

    /// A file of certificate authorities at `path` (any text will do here),
    /// with mode 0644 whatever the umask.
    fn ca_file(path: &Path, text: &str) -> PathBuf {
        fs::write(path, text).expect("write");
        set_mode(path, 0o644);
        path.to_path_buf()
    }

    /// The test's user: the owner its files have.
    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// The file `open_ca_file_from` opens, with the test's user as owner:
    /// its path and what reading it gives.
    fn opened(candidates: &[&Path], top: &Path) -> Result<(PathBuf, String), String> {
        let mut ca = open_ca_file_from(candidates, me(), top)?;
        let mut text = String::new();
        ca.file.read_to_string(&mut text).expect("read");
        Ok((ca.path, text))
    }

    #[test]
    fn the_ca_file_is_the_first_that_exists() {
        let (_dir, top) = ca_top();
        let a = top.join("a.crt");
        let b = top.join("b.crt");
        // None exists: the error lists them.
        assert_eq!(
            opened(&[&a, &b], &top),
            Err(format!(
                "none of the certificate authority files exists: {}, {}",
                a.display(),
                b.display()
            ))
        );
        // The first missing, the second used.
        ca_file(&b, "B");
        assert_eq!(opened(&[&a, &b], &top), Ok((b.clone(), "B".into())));
        // A path through a file names nothing either.
        let through = b.join("inner.crt");
        assert_eq!(opened(&[&through, &b], &top), Ok((b.clone(), "B".into())));
        // The first that exists, even when a later one does too.
        ca_file(&a, "A");
        assert_eq!(opened(&[&a, &b], &top), Ok((a.clone(), "A".into())));
        assert_eq!(opened(&[&b, &a], &top), Ok((b.clone(), "B".into())));
        // Links are resolved: the path is the target's, and so is the file.
        let link = top.join("link.crt");
        std::os::unix::fs::symlink(&b, &link).expect("symlink");
        let chain = top.join("chain.crt");
        std::os::unix::fs::symlink(&link, &chain).expect("symlink");
        let relative = top.join("relative.crt");
        std::os::unix::fs::symlink("b.crt", &relative).expect("symlink");
        for candidate in [&link, &chain, &relative] {
            assert_eq!(
                opened(&[candidate, &a], &top),
                Ok((b.clone(), "B".into())),
                "{}",
                candidate.display()
            );
        }
    }

    #[test]
    fn the_ca_file_must_be_a_regular_file_nobody_else_can_change() {
        let (_dir, top) = ca_top();
        let file = ca_file(&top.join("ca.crt"), "CA");
        for mode in [0o664, 0o646, 0o666, 0o660, 0o606, 0o620, 0o602] {
            set_mode(&file, mode);
            assert_eq!(
                opened(&[&file], &top),
                Err(format!(
                    "{} can be modified by its group or by others",
                    file.display()
                )),
                "{mode:o}"
            );
        }
        for mode in [0o644, 0o640, 0o604, 0o600, 0o444, 0o400] {
            set_mode(&file, mode);
            assert_eq!(
                opened(&[&file], &top),
                Ok((file.clone(), "CA".into())),
                "{mode:o}"
            );
        }
        // A directory is not a regular file, even one nobody else can change.
        let dir = top.join("dir.crt");
        fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, 0o755);
        assert_eq!(
            opened(&[&dir], &top),
            Err(format!("{} is not a regular file", dir.display()))
        );
        // Nor is a FIFO, which is refused without waiting for a writer.
        let fifo = top.join("fifo.crt");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o644))
            .expect("mkfifo");
        set_mode(&fifo, 0o644);
        let (tx, rx) = std::sync::mpsc::channel();
        let (candidate, highest) = (fifo.clone(), top.clone());
        std::thread::spawn(move || {
            let _ = tx.send(opened(&[&candidate], &highest));
        });
        let result = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO waited for a writer");
        assert_eq!(
            result,
            Err(format!("{} is not a regular file", fifo.display()))
        );
    }

    #[test]
    fn the_ca_file_is_opened_without_following_a_link_or_waiting() {
        use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
        let (_dir, top) = ca_top();
        let file = ca_file(&top.join("ca.crt"), "CA");
        // Links are resolved first; one that appears at the end of the path
        // after that is not followed.
        let link = top.join("link.crt");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        let err = open_no_follow(&link).expect_err("a link at the end");
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err}");
        // The file it gives waits as files do, and is closed on exec.
        let ca = open_ca_file_from(&[&link], me(), &top).expect("opened");
        assert_eq!(ca.path, file);
        let flags = OFlag::from_bits_retain(fcntl(&ca.file, FcntlArg::F_GETFL).expect("flags"));
        assert!(!flags.contains(OFlag::O_NONBLOCK), "{flags:?}");
        let fd = FdFlag::from_bits_retain(fcntl(&ca.file, FcntlArg::F_GETFD).expect("fd flags"));
        assert!(fd.contains(FdFlag::FD_CLOEXEC), "{fd:?}");
    }

    #[test]
    fn the_ca_file_and_its_directories_must_belong_to_root() {
        if nix::unistd::geteuid().is_root() {
            return; // the test's files belong to root
        }
        let (_dir, top) = ca_top();
        let file = ca_file(&top.join("ca.crt"), "CA");
        assert_eq!(
            open_ca_file_from(&[&file], 0, &top).map(|ca| ca.path),
            Err(format!("{} is not owned by root", file.display()))
        );
        // Its directories too (which only these checks can show: the file
        // itself belongs to the test's user as well).
        assert_eq!(
            check_directories(&file, 0, &top),
            Err(format!(
                "{} is in {}, which is not owned by root",
                file.display(),
                top.display()
            ))
        );
        assert_eq!(check_directories(&file, me(), &top), Ok(()));
        // Above the top, nothing is checked; but with `/` as the top, or a
        // top that is not on the way, every directory up to `/` is, and one
        // of those above the temporary directory belongs to root, at least
        // `/` itself.
        let elsewhere = top.join("elsewhere");
        for highest in [Path::new("/"), &elsewhere] {
            let err = open_ca_file_from(&[&file], me(), highest)
                .map(|ca| ca.path)
                .expect_err("checked up to /");
            let above = top.ancestors().skip(1).any(|dir| {
                err.starts_with(&format!(
                    "{} is in {}, which ",
                    file.display(),
                    dir.display()
                ))
            });
            assert!(above, "{err}");
        }
    }

    #[test]
    fn the_directories_of_the_ca_file_are_checked_up_to_the_top() {
        let (_dir, top) = ca_top();
        let a = top.join("a");
        let b = a.join("b");
        fs::create_dir_all(&b).expect("mkdir");
        set_mode(&a, 0o755);
        set_mode(&b, 0o755);
        let file = ca_file(&b.join("ca.crt"), "CA");
        assert_eq!(opened(&[&file], &top), Ok((file.clone(), "CA".into())));
        for (dir, mode) in [
            (&b, 0o775),
            (&b, 0o757),
            (&b, 0o777),
            (&a, 0o775),
            (&a, 0o1777),
            (&top, 0o775),
            (&top, 0o757),
        ] {
            set_mode(dir, mode);
            assert_eq!(
                opened(&[&file], &top),
                Err(format!(
                    "{} is in {}, which can be modified by its group or by others",
                    file.display(),
                    dir.display()
                )),
                "{} {mode:o}",
                dir.display()
            );
            set_mode(dir, 0o755);
        }
        // Read-only directories are fine, and so are those only the owner
        // can enter.
        set_mode(&a, 0o555);
        set_mode(&b, 0o700);
        assert_eq!(opened(&[&file], &top), Ok((file.clone(), "CA".into())));
        set_mode(&a, 0o755);
        set_mode(&b, 0o755);
        // The directory the checks start from is the file's, links resolved.
        let link = top.join("link.crt");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        set_mode(&b, 0o777);
        assert_eq!(
            opened(&[&link], &top),
            Err(format!(
                "{} is in {}, which can be modified by its group or by others",
                file.display(),
                b.display()
            ))
        );
    }

    #[test]
    fn a_ca_file_that_fails_a_check_is_not_passed_over() {
        let (_dir, top) = ca_top();
        let good = ca_file(&top.join("good.crt"), "GOOD");
        let bad = ca_file(&top.join("bad.crt"), "BAD");
        set_mode(&bad, 0o666);
        let writable = |path: &Path| {
            format!(
                "{} can be modified by its group or by others",
                path.display()
            )
        };
        assert_eq!(opened(&[&bad, &good], &top), Err(writable(&bad)));
        // Through a link too: the error names the file it resolves to.
        let link = top.join("link.crt");
        std::os::unix::fs::symlink(&bad, &link).expect("symlink");
        assert_eq!(opened(&[&link, &good], &top), Err(writable(&bad)));
        // A directory where the file should be.
        let dir = top.join("dir.crt");
        fs::create_dir(&dir).expect("mkdir");
        set_mode(&dir, 0o755);
        assert_eq!(
            opened(&[&dir, &good], &top),
            Err(format!("{} is not a regular file", dir.display()))
        );
        // A file in a directory others can change.
        let shared = top.join("shared");
        fs::create_dir(&shared).expect("mkdir");
        set_mode(&shared, 0o777);
        let inside = ca_file(&shared.join("ca.crt"), "SHARED");
        assert_eq!(
            opened(&[&inside, &good], &top),
            Err(format!(
                "{} is in {}, which can be modified by its group or by others",
                inside.display(),
                shared.display()
            ))
        );
        // A broken link is not "absent".
        let broken = top.join("broken.crt");
        std::os::unix::fs::symlink(top.join("nowhere"), &broken).expect("symlink");
        let err = opened(&[&broken, &good], &top).expect_err("a broken link");
        assert!(
            err.starts_with(&format!("cannot resolve {}: ", broken.display())),
            "{err}"
        );
        // Nor is a file whose directory cannot be examined: whether it exists
        // cannot be told (not as root, who can examine anything).
        if !nix::unistd::geteuid().is_root() {
            let closed = top.join("closed");
            fs::create_dir(&closed).expect("mkdir");
            set_mode(&closed, 0o000);
            let hidden = closed.join("ca.crt");
            let result = opened(&[&hidden, &good], &top);
            set_mode(&closed, 0o755);
            let err = result.expect_err("cannot be told");
            assert!(
                err.starts_with(&format!("cannot examine {}: ", hidden.display())),
                "{err}"
            );
        }
        // Another owner (not as root, whose files belong to root).
        if !nix::unistd::geteuid().is_root() {
            assert_eq!(
                open_ca_file_from(&[&good, &bad], 0, &top).map(|ca| ca.path),
                Err(format!("{} is not owned by root", good.display()))
            );
        }
        // With the bad files out of the way, the good one is used.
        assert_eq!(
            opened(&[&top.join("missing.crt"), &good, &bad], &top),
            Ok((good.clone(), "GOOD".into()))
        );
    }

    /// Whether `path` resolves to a regular file owned by root that nobody
    /// else can change, in directories that only root can change, up to
    /// `/`: what `open_ca_file` requires, found here the simple way.
    fn trusted_by_root(path: &Path) -> bool {
        let Ok(real) = fs::canonicalize(path) else {
            return false;
        };
        let safe = |meta: fs::Metadata| meta.uid() == 0 && meta.mode() & 0o022 == 0;
        fs::metadata(&real).is_ok_and(|meta| meta.is_file() && safe(meta))
            && real
                .ancestors()
                .skip(1)
                .all(|dir| fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir() && safe(meta)))
    }

    #[test]
    fn the_systems_ca_file_is_the_first_of_the_fixed_ones() {
        let first = CA_FILES
            .iter()
            .map(Path::new)
            .find(|file| fs::symlink_metadata(file).is_ok());
        match (first, open_ca_file()) {
            (None, Err(e)) => assert!(
                e.starts_with("none of the certificate authority files exists: "),
                "{e}"
            ),
            (None, Ok(ca)) => panic!("{} opened, where none exists", ca.path.display()),
            (Some(first), Ok(ca)) => {
                assert!(trusted_by_root(first), "{} trusted", first.display());
                assert_eq!(ca.path, fs::canonicalize(first).expect("canonical"));
                assert_eq!(ca.file.metadata().expect("metadata").uid(), 0);
            }
            (Some(first), Err(e)) => {
                assert!(!trusted_by_root(first), "{} refused: {e}", first.display());
            }
        }
    }
}
