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
    /// with offset): for an approval, when the human answered, not when the
    /// request arrived. [`AuditLog::record`] sets it.
    pub time: String,
    /// What was attempted: `unlock`, `lock`, `run`, `run_exit`, `reveal`, ...
    pub action: String,
    /// How it ended: `allowed_once`, `allowed_remembered`, `denied`, ...
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

    /// Append one record, stamped with the current time. An event is often
    /// built when a request arrives and recorded once its outcome is known —
    /// after a dialog that may stay open for minutes — so the time it was
    /// built would misdate the decision. Stamping under the lock also keeps
    /// the file in time order.
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
