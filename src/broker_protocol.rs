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

use std::fmt;
use std::io::{self, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::broker_profile::{BrokerProfile, MAX_LIFETIME_MINUTES_RANGE, is_valid_credential};
use crate::protocol::{self, SecretString};

/// Version of this protocol. Both sides refuse any other.
pub const VERSION: u32 = 1;

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
/// or others. No environment variable changes it (`rusthorse doctor` checks
/// the same files).
pub const CA_FILES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

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
    /// End the grant: close every open request and stream, drop the
    /// credential, answer [`FromBroker::Revoked`] within
    /// [`REVOKE_CONFIRM_TIMEOUT`], and answer `403` from then on.
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
    /// Seconds the grant has left. The agent ends it then; the broker stops
    /// serving then too, should the agent's word not come.
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
    /// profile, limits within phase 1's, and a lifetime of at most a day.
    /// The reason never contains a secret.
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
    /// Ask to forward a request that passed the broker's own checks (token,
    /// route, framing, body). Nothing is forwarded before the answer.
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
    }
}
