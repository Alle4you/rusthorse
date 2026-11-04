//! The audit log: one JSON object per line, appended for every decision the
//! agent makes (unlock, lock, approvals, denials, command exits).
//!
//! Records never contain secret values. The file is created with mode `0600`.
//! Approval-gated actions **fail closed**: if the record cannot be written,
//! the request is refused.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::peer::Peer;
use crate::util::ensure_private_dir;

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// When the record was written, as an RFC 3339 timestamp (local time
    /// with offset) from the system clock: for an approval, after the human
    /// answered (usually within a moment), not when the request arrived.
    /// [`AuditLog::record`] sets it.
    pub time: String,
    /// What was attempted: `unlock`, `lock`, `run`, `run_exit`, `reveal`, ...;
    /// for the credential broker (ADR 0013), `grant` and `broker_request`.
    pub action: String,
    /// How it ended: `allowed_once`, `allowed_remembered`, `denied`,
    /// `timed_out` (nobody answered the dialog), `cancelled`, ...
    ///
    /// A `grant` record is `created` (before the command starts) or `ended`.
    /// A `broker_request` record is `admitted` (before the request is
    /// forwarded), or else it records how an admitted request ended:
    /// `completed`, `not_forwarded`, `client_closed`, `revoked` or `unknown`
    /// ([`RequestOutcome::as_str`](crate::broker_protocol::RequestOutcome::as_str)).
    pub outcome: String,
    /// Entries involved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
    /// Requester process chain, e.g. `rusthorse[1] ← bash[2] ← claude[3]`.
    pub requester: String,
    /// Command line, for `run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Working directory, for `run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Extra information (exit status, error message, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The grant's ID, on `grant` and `broker_request` records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// On the `run` record of a `broker_run_v2`: the grants the run creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<AuditGrant>>,
    /// On `broker_request` records: the request's number within its grant,
    /// as the broker numbered it (from 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<u64>,
    /// On `broker_request` records (its admission and its end): the label
    /// of the request's method, as
    /// [`MethodLabel::as_str`](crate::broker_grant::MethodLabel::as_str)
    /// writes it (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or
    /// `OTHER`) — never the raw method, a path or a query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// On the record of an admitted request's end: the status of the
    /// destination's answer, or of the broker's own answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// On the record of an admitted request's end: the bytes of the request
    /// body sent to the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    /// On the record of an admitted request's end: the bytes of the response
    /// body received from the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    /// On the `grant` record of its end: why the grant ended, as
    /// [`EndReason::as_str`](crate::broker_protocol::EndReason::as_str)
    /// writes it (`command_ended`, `revoked`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// On the `grant` record of its end: what became of its requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<AuditRequestCounts>,
}

/// A grant, as the `run` record of the `broker_run_v2` that creates it lists
/// it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditGrant {
    /// The grant's ID (`g` and 16 hexadecimal digits).
    pub id: String,
    /// Its entry, as records identify entries (in `entries`):
    /// [`EntryInfo::identity`](crate::protocol::EntryInfo::identity).
    pub entry: String,
    /// The approved origin (`https://api.openai.com`): the broker may send
    /// the key to any path there.
    pub destination: String,
    /// The base path the run named (`/v1`), which sets up the program's base
    /// URL and limits nothing; left out when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
}

/// What became of a grant's requests, on the `grant` record of its end.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRequestCounts {
    /// Requests admitted: each spent one of the grant's uses.
    pub admitted: u64,
    /// Admitted requests whose end the broker reported, whatever their
    /// outcome.
    pub finished: u64,
    /// Admitted requests whose end the broker never reported (it failed, or
    /// was stopped first): the destination may have acted on them.
    pub unknown: u64,
    /// Requests refused before admission, by the broker's own checks or by
    /// the agent: none of them was forwarded.
    pub refused: u64,
}

impl AuditEvent {
    /// A new record for `action` by `peer`, with an empty outcome.
    pub fn new(action: &str, peer: &Peer) -> Self {
        Self {
            time: now(),
            action: action.to_string(),
            outcome: String::new(),
            entries: Vec::new(),
            requester: peer.describe(),
            argv: None,
            cwd: None,
            detail: None,
            grant: None,
            grants: None,
            request: None,
            method: None,
            status: None,
            bytes_sent: None,
            bytes_received: None,
            reason: None,
            requests: None,
        }
    }

    /// Set the outcome.
    pub fn outcome(mut self, outcome: &str) -> Self {
        self.outcome = outcome.to_string();
        self
    }

    /// Set the entries involved.
    pub fn entries(mut self, entries: Vec<String>) -> Self {
        self.entries = entries;
        self
    }

    /// Set extra information.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// An append-only JSON Lines file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    /// A log at `path` (created on first write).
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// The log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hold the log, as a slow disk would: every record waits until the
    /// guard is dropped, and is then written as usual. For tests.
    #[cfg(test)]
    pub(crate) fn hold(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Append one record, stamped with the current time. An event is often
    /// built when a request arrives and recorded once its outcome is known —
    /// after a dialog that may stay open for minutes — so the time it was
    /// built would misdate the decision. Stamping under the lock also keeps
    /// the times in file order — unless the system clock is set back.
    pub fn record(&self, event: &AuditEvent) -> io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let event = AuditEvent {
            time: now(),
            ..event.clone()
        };
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            ensure_private_dir(dir)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        let mut line = serde_json::to_vec(&event).map_err(io::Error::other)?;
        line.push(b'\n');
        file.write_all(&line)?;
        // The record of a decision must survive a crash right after it.
        file.sync_data()
    }
}

/// The current local time as an RFC 3339 timestamp, to the second.
fn now() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

/// The last `count` records of the log at `path` (oldest first).
pub fn tail(path: &Path, count: usize) -> io::Result<Vec<AuditEvent>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut events = std::collections::VecDeque::with_capacity(count);
    for line in BufReader::new(file).lines() {
        let line = line?;
        let Ok(event) = serde_json::from_str::<AuditEvent>(&line) else {
            continue;
        };
        if events.len() == count {
            events.pop_front();
        }
        events.push_back(event);
    }
    Ok(events.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_append_and_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("state").join("audit.jsonl"));
        let peer = Peer::agent();
        for i in 0..5 {
            log.record(
                &AuditEvent::new("run", &peer)
                    .outcome("denied")
                    .detail(format!("#{i}")),
            )
            .expect("record");
        }
        let last = tail(log.path(), 2).expect("tail");
        assert_eq!(last.len(), 2);
        assert_eq!(last[1].detail.as_deref(), Some("#4"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(log.path())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A record with every field the credential broker's records use.
    fn broker_event() -> AuditEvent {
        let mut event = AuditEvent::new("grant", &Peer::agent()).outcome("ended");
        event.grant = Some("g0123456789abcdef".into());
        event.grants = Some(vec![AuditGrant {
            id: "g0123456789abcdef".into(),
            entry: "AI/ANTHROPIC_API_KEY (8d2f6c1e)".into(),
            destination: "https://api.openai.com".into(),
            base_path: Some("/v1".into()),
        }]);
        event.request = Some(7);
        event.method = Some("POST".into());
        event.status = Some(200);
        event.bytes_sent = Some(1234);
        event.bytes_received = Some(u64::MAX);
        event.reason = Some("command_ended".into());
        event.requests = Some(AuditRequestCounts {
            admitted: 3,
            finished: 2,
            unknown: 1,
            refused: 4,
        });
        event
    }

    #[test]
    fn records_without_the_brokers_fields_still_parse() {
        // A record as earlier versions wrote it.
        let old = r#"{"time":"2026-11-02T10:00:00-03:00","action":"run","outcome":"allowed_once","entries":["API_KEY (8d2f6c1e)"],"requester":"rusthorse[1]","argv":["true"],"cwd":"/","detail":"x"}"#;
        let event: AuditEvent = serde_json::from_str(old).expect("parse");
        assert_eq!(event.action, "run");
        assert_eq!(event.argv, Some(vec!["true".to_string()]));
        assert_eq!(event.grant, None);
        assert_eq!(event.grants, None);
        assert_eq!(event.request, None);
        assert_eq!(event.method, None);
        assert_eq!(event.status, None);
        assert_eq!(event.bytes_sent, None);
        assert_eq!(event.bytes_received, None);
        assert_eq!(event.reason, None);
        assert_eq!(event.requests, None);
        // Written back, it is what it was.
        assert_eq!(
            serde_json::to_value(&event).expect("json"),
            serde_json::from_str::<serde_json::Value>(old).expect("json")
        );
        // The log reader takes both kinds of record.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let broker = broker_event();
        let new = serde_json::to_string(&broker).expect("json");
        std::fs::write(&path, format!("{old}\n{new}\n")).expect("write");
        assert_eq!(tail(&path, 10).expect("tail"), vec![event, broker]);
    }

    #[test]
    fn the_brokers_fields_round_trip_under_their_names() {
        let event = broker_event();
        let json = serde_json::to_value(&event).expect("json");
        assert_eq!(json["grant"], "g0123456789abcdef");
        assert_eq!(
            json["grants"],
            serde_json::json!([{
                "id": "g0123456789abcdef",
                "entry": "AI/ANTHROPIC_API_KEY (8d2f6c1e)",
                "destination": "https://api.openai.com",
                "base_path": "/v1",
            }])
        );
        assert_eq!(json["request"], 7);
        assert_eq!(json["method"], "POST");
        assert_eq!(json["status"], 200);
        assert_eq!(json["bytes_sent"], 1234);
        assert_eq!(json["bytes_received"], u64::MAX);
        assert_eq!(json["reason"], "command_ended");
        assert_eq!(
            json["requests"],
            serde_json::json!({"admitted": 3, "finished": 2, "unknown": 1, "refused": 4})
        );
        assert_eq!(
            serde_json::from_value::<AuditEvent>(json).expect("parse"),
            event
        );
        // Through the log file too.
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        log.record(&event).expect("record");
        let read = tail(log.path(), 1).expect("tail");
        assert_eq!(read.len(), 1);
        assert_eq!(
            read[0],
            AuditEvent {
                time: read[0].time.clone(),
                ..event
            }
        );
    }

    #[test]
    fn absent_fields_are_left_out() {
        let keys = |event: &AuditEvent| -> std::collections::BTreeSet<String> {
            let line = serde_json::to_string(event).expect("json");
            assert!(!line.contains("null"), "{line}");
            let json: serde_json::Value = serde_json::from_str(&line).expect("json");
            json.as_object().expect("object").keys().cloned().collect()
        };
        let lock = AuditEvent::new("lock", &Peer::agent()).outcome("requested");
        assert_eq!(
            keys(&lock),
            ["action", "outcome", "requester", "time"]
                .map(String::from)
                .into()
        );
        // An admission: only the fields it sets.
        let mut admitted = AuditEvent::new("broker_request", &Peer::agent()).outcome("admitted");
        admitted.grant = Some("g0123456789abcdef".into());
        admitted.request = Some(1);
        admitted.method = Some("POST".into());
        assert_eq!(
            keys(&admitted),
            [
                "action",
                "grant",
                "method",
                "outcome",
                "request",
                "requester",
                "time"
            ]
            .map(String::from)
            .into()
        );
    }

    #[test]
    fn a_record_is_dated_when_it_is_written_not_when_it_was_built() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        // An event built long ago, e.g. when a request whose dialog stayed
        // open arrived.
        let mut event = AuditEvent::new("run", &Peer::agent());
        event.time = "2000-01-01T00:00:00+00:00".into();
        log.record(&event.outcome("allowed_once")).expect("record");
        let written = &tail(log.path(), 1).expect("tail")[0];
        let year: i32 = written.time[..4].parse().expect("year");
        assert!(year >= 2025, "dated {}", written.time);
    }
}
