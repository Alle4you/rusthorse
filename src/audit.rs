//! The audit log: one JSON object per line, appended for every decision the
//! agent makes (unlock, lock, approvals, denials, command exits).
//!
//! Records never contain secret values. The file is created with mode `0600`.
//! Each record is synced to disk, with the names that lead to it
//! ([`AuditLog::record`]). Approval-gated actions **fail closed**: if the
//! record cannot be written, the request is refused.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::peer::Peer;
use crate::util::make_private_dir;

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
    /// Held while a record is written.
    lock: Mutex<Unsynced>,
    /// Records waiting for the log, for tests that hold it.
    #[cfg(test)]
    waiting: std::sync::atomic::AtomicUsize,
}

/// Directories that hold the name of a directory made for the log and have
/// not been synced since: a record synced into a file is lost in a crash
/// with the name of a directory on the way to it. Kept until their sync
/// succeeds, so that a record after one that failed tries again, though the
/// directories are there by then.
#[derive(Debug, Default)]
struct Unsynced {
    dirs: Vec<PathBuf>,
}

impl Unsynced {
    /// Sync `dir` before the next record is written.
    fn add(&mut self, dir: &Path) {
        if !self.dirs.iter().any(|d| d == dir) {
            self.dirs.push(dir.to_path_buf());
        }
    }

    /// Sync the directories waiting to be, each forgotten once it succeeds.
    fn sync(&mut self) -> io::Result<()> {
        while let Some(dir) = self.dirs.first() {
            sync_directory(dir)?;
            self.dirs.remove(0);
        }
        Ok(())
    }
}

/// Why the directory `dir` cannot be synced.
fn cannot_sync(dir: &Path, e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("cannot sync the directory {}: {e}", dir.display()),
    )
}

/// Open the directory `dir`, to sync it, as a directory only: a FIFO put
/// in its place fails the record at once, instead of holding the log.
fn open_directory(dir: &Path) -> io::Result<std::fs::File> {
    crate::util::open_directory(dir).map_err(|e| cannot_sync(dir, e))
}

/// Open the directory `dir` and sync it, as the vault's saves sync theirs:
/// any error is a failure (a file system whose directories cannot be synced
/// cannot hold the log).
fn sync_directory(dir: &Path) -> io::Result<()> {
    open_directory(dir)?
        .sync_all()
        .map_err(|e| cannot_sync(dir, e))
}

/// Test hook: the steps of [`sync_directory_holding`] after which a test
/// acts, as another program could.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The path is resolved, and its directory not opened yet.
    Resolved,
    /// The directory is open, and not checked yet.
    Opened,
    /// The directory has just been synced.
    Synced,
}

/// What a test does after a step.
#[cfg(test)]
type StepHook = Box<dyn FnMut(Step)>;

#[cfg(test)]
thread_local! {
    /// What the test running on this thread does after each step.
    static AT_STEP: std::cell::RefCell<Option<StepHook>> = const { std::cell::RefCell::new(None) };
}

/// Run the hook of the test on this thread, if it set one.
#[cfg(test)]
fn at_step(step: Step) {
    AT_STEP.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(step);
        }
    });
}

/// Sync the directory that holds `file`, opened at `path`: that of the file
/// the path leads to, should its name be a link. The directory is opened,
/// checked through that open directory to hold `file` under that name, and
/// only then synced, so that the sync covers the name checked. A rename,
/// replacement or removal by another program that still stands at the check
/// refuses the record; one undone before the check goes unnoticed, and the
/// sync covers the name put back; one after the check is that program's to
/// sync.
fn sync_directory_holding(file: &std::fs::File, path: &Path) -> io::Result<()> {
    let real = std::fs::canonicalize(path)?;
    let (Some(dir), Some(name)) = (real.parent(), real.file_name()) else {
        return Err(io::Error::other(format!(
            "{} is not a file in a directory",
            real.display()
        )));
    };
    #[cfg(test)]
    at_step(Step::Resolved);
    let directory = open_directory(dir)?;
    #[cfg(test)]
    at_step(Step::Opened);
    let opened = file.metadata()?;
    let holds =
        match nix::sys::stat::fstatat(&directory, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(entry) => (entry.st_dev, entry.st_ino) == (opened.dev(), opened.ino()),
            Err(nix::errno::Errno::ENOENT) => false,
            Err(e) => return Err(e.into()),
        };
    if !holds {
        return Err(io::Error::other(format!(
            "{} was renamed, replaced or removed while a record was written to it",
            path.display()
        )));
    }
    directory.sync_all().map_err(|e| cannot_sync(dir, e))?;
    #[cfg(test)]
    at_step(Step::Synced);
    Ok(())
}

/// The directory that holds `path`'s name.
fn directory_of(path: &Path) -> &Path {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Open the log at `path` for appending, links followed, creating it with
/// mode `0600` if it is missing.
fn open_log(path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

/// Write `line` into `file`, the log opened at `path`: the names that lead
/// to it are synced first, and the line after it is written.
fn append(
    path: &Path,
    unsynced: &mut Unsynced,
    mut file: std::fs::File,
    line: &[u8],
) -> io::Result<()> {
    sync_directory_holding(&file, path)?;
    unsynced.sync()?;
    file.write_all(line)?;
    // The record of a decision must survive a crash right after it.
    file.sync_data()
}

impl AuditLog {
    /// A log at `path` (created on first write).
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::default(),
            #[cfg(test)]
            waiting: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hold the log, as a slow disk would: every record waits until the
    /// guard is dropped, and is then written as usual. For tests.
    #[cfg(test)]
    pub(crate) fn hold(&self) -> impl Sized + '_ {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How many records wait for the log (held, see [`AuditLog::hold`]).
    /// For tests.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Append one record, stamped with the current time. An event is often
    /// built when a request arrives and recorded once its outcome is known —
    /// after a dialog that may stay open for minutes — so the time it was
    /// built would misdate the decision. Stamping under the lock also keeps
    /// the times in file order — unless the system clock is set back.
    ///
    /// The record is synced as data (`fdatasync`). Before it is written, the
    /// names it needs are synced too: at every record, that of the file, in
    /// the directory that holds it, once that directory is found to hold it;
    /// and the name of every directory made for the log, in its parent, until
    /// that sync succeeds. If one of these fails, the record fails and is not
    /// written. If writing or syncing the record fails, the record fails
    /// too, but part or all of it may be in the file.
    pub fn record(&self, event: &AuditEvent) -> io::Result<()> {
        #[cfg(test)]
        self.waiting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut unsynced = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        #[cfg(test)]
        self.waiting
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        let event = AuditEvent {
            time: now(),
            ..event.clone()
        };
        let mut line = serde_json::to_vec(&event).map_err(io::Error::other)?;
        line.push(b'\n');
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            let mut made = Vec::new();
            let result = make_private_dir(dir, &mut made);
            // Also those made before a failure: the next record syncs them.
            for made in &made {
                unsynced.add(directory_of(made));
            }
            result?;
        }
        let file = open_log(&self.path)?;
        append(&self.path, &mut unsynced, file, &line)
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

/// The most bytes [`read_page`] reads for one page, and so the longest line
/// it can read: a longer one stops the reading there ([`Page::too_long`]).
pub const PAGE_BYTES: u64 = 256 * 1024;

/// The most records on one page of [`read_page`].
pub const PAGE_RECORDS: usize = 200;

/// Where the next page of older records ends: the oldest line a page read,
/// in the file it read it from. [`read_page`] reads on from it only while
/// that file still holds that line there and is no shorter than it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    device: u64,
    inode: u64,
    /// The file's size when the page was read: the agent only appends to
    /// it, so a shorter file was truncated.
    size: u64,
    /// Where the line starts.
    offset: u64,
    /// Its length, with its newline.
    length: u64,
    /// A hash of its bytes, newline included.
    hash: u64,
}

/// A page of the audit log, read by [`read_page`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// Its records, newest first.
    pub records: Vec<AuditEvent>,
    /// Lines among them that are not audit records (not JSON, or JSON of
    /// another shape): left out.
    pub unreadable: usize,
    /// Where the next page, of older records, ends; `None` once the start
    /// of the file is reached, or when the reading stopped at a line too
    /// long to read.
    pub older: Option<Cursor>,
    /// The reading stopped at a line longer than [`PAGE_BYTES`]: what comes
    /// before it in the file is not read.
    pub too_long: bool,
}

/// What [`read_page`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageRead {
    /// The page.
    Page(Page),
    /// The file at the path is no longer the one the cursor came from, is
    /// shorter than it was, no longer holds the cursor's line where it was,
    /// or shrank while it was read: it was rotated, replaced, truncated or
    /// rewritten. Read it again from its end. (A rewrite that keeps the
    /// cursor's line and the file's size goes unnoticed.)
    Changed,
}

/// Read a page of the audit log at `path`: its newest records, or with
/// `before`, those before a page read earlier — at most [`PAGE_RECORDS`]
/// records from at most [`PAGE_BYTES`] bytes, whatever the size of the file.
///
/// Only complete lines are read: the last one, without its newline yet, may
/// still be being written. A missing file has no records. A file that is not
/// a regular file is refused, and opening it does not wait (a FIFO would
/// block). Any program of the user can write the file (threat model L13):
/// what it reads is what the file says.
pub fn read_page(path: &Path, before: Option<&Cursor>) -> io::Result<PageRead> {
    read_page_within(path, before, PAGE_BYTES, PAGE_RECORDS)
}

/// [`read_page`], with other limits.
fn read_page_within(
    path: &Path,
    before: Option<&Cursor>,
    max_bytes: u64,
    max_records: usize,
) -> io::Result<PageRead> {
    use std::os::unix::fs::FileExt;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(match before {
                None => PageRead::Page(Page::default()),
                Some(_) => PageRead::Changed,
            });
        }
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let size = meta.len();
    // Bytes the file no longer holds: it shrank since its size was taken.
    let read_at = |buf: &mut [u8], offset: u64| match file.read_exact_at(buf, offset) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    };
    let end = match before {
        // The end of the last complete line: the last one, without its
        // newline yet, may still be being written.
        None => {
            let from = size.saturating_sub(max_bytes.saturating_add(1));
            let mut tail = vec![0; usize::try_from(size - from).map_err(io::Error::other)?];
            if !read_at(&mut tail, from)? {
                return Ok(PageRead::Changed);
            }
            match tail.iter().rposition(|&b| b == b'\n') {
                Some(i) => from + i as u64 + 1,
                // The file holds part of one line only.
                None if from == 0 => return Ok(PageRead::Page(Page::default())),
                // The last line is longer than a page.
                None => {
                    return Ok(PageRead::Page(Page {
                        too_long: true,
                        ..Page::default()
                    }));
                }
            }
        }
        Some(cursor) => {
            let same_file = (meta.dev(), meta.ino()) == (cursor.device, cursor.inode);
            let fits = cursor
                .offset
                .checked_add(cursor.length)
                .is_some_and(|line_end| line_end <= size);
            if !same_file || size < cursor.size || !fits {
                return Ok(PageRead::Changed);
            }
            let mut line = vec![0; usize::try_from(cursor.length).map_err(io::Error::other)?];
            if !read_at(&mut line, cursor.offset)? || line_hash(&line) != cursor.hash {
                return Ok(PageRead::Changed);
            }
            cursor.offset
        }
    };
    let start = end.saturating_sub(max_bytes);
    // With the byte before the window, when there is one: whether the
    // window starts a line.
    let from = start.saturating_sub(1);
    let mut buf = vec![0; usize::try_from(end - from).map_err(io::Error::other)?];
    if !read_at(&mut buf, from)? {
        return Ok(PageRead::Changed);
    }
    // A line ends there: the last complete one, or the one before the
    // cursor's (unless the file was rewritten).
    if end > 0 && buf.last() != Some(&b'\n') {
        return Ok(PageRead::Changed);
    }
    // Where the first line that starts in the window starts: the bytes
    // before it are the end of a line that starts before the window.
    let first = if from == start {
        0
    } else {
        buf.iter()
            .position(|&b| b == b'\n')
            .map_or(buf.len(), |i| i + 1)
    };
    let mut page = Page::default();
    if first == buf.len() {
        // Not one line starts in the window (which then does not start the
        // file): a line longer than the window ends here.
        page.too_long = true;
        return Ok(PageRead::Page(page));
    }
    let mut line_end = buf.len();
    let mut oldest = None;
    while line_end > first && page.records.len() < max_records {
        let line_start = buf[first..line_end - 1]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(first, |i| first + i + 1);
        let line = &buf[line_start..line_end];
        match serde_json::from_slice::<AuditEvent>(&line[..line.len() - 1]) {
            Ok(event) => page.records.push(event),
            Err(_) => page.unreadable += 1,
        }
        oldest = Some((from + line_start as u64, line));
        line_end = line_start;
    }
    page.older = oldest
        .filter(|(offset, _)| *offset > 0)
        .map(|(offset, line)| Cursor {
            device: meta.dev(),
            inode: meta.ino(),
            size,
            offset,
            length: line.len() as u64,
            hash: line_hash(line),
        });
    Ok(PageRead::Page(page))
}

/// A hash of a line, to tell whether the file still holds it: not a
/// protection, as any program of the user can write the file.
fn line_hash(line: &[u8]) -> u64 {
    use std::hash::{DefaultHasher, Hasher};
    let mut hasher = DefaultHasher::new();
    hasher.write(line);
    hasher.finish()
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

    /// A record whose detail is `detail`, as a line of the log.
    fn line(detail: &str) -> String {
        let event = AuditEvent::new("run", &Peer::agent())
            .outcome("denied")
            .detail(detail);
        let mut line = serde_json::to_string(&event).expect("json");
        line.push('\n');
        line
    }

    /// The details of `page`'s records, in its order.
    fn details(page: &Page) -> Vec<&str> {
        page.records
            .iter()
            .map(|r| r.detail.as_deref().unwrap_or_default())
            .collect()
    }

    fn page_of(read: PageRead) -> Page {
        match read {
            PageRead::Page(page) => page,
            PageRead::Changed => panic!("the file changed"),
        }
    }

    /// Every page of the log at `path`, from its end, with these limits.
    fn all_pages(path: &Path, max_bytes: u64, max_records: usize) -> Vec<Page> {
        let mut pages = vec![page_of(
            read_page_within(path, None, max_bytes, max_records).expect("read"),
        )];
        while let Some(cursor) = pages.last().and_then(|p| p.older.clone()) {
            assert!(pages.len() < 10_000, "no end");
            pages.push(page_of(
                read_page_within(path, Some(&cursor), max_bytes, max_records).expect("read"),
            ));
        }
        pages
    }

    #[test]
    fn a_page_holds_the_newest_complete_records_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // No file yet: no records.
        assert_eq!(
            read_page(&path, None).expect("read"),
            PageRead::Page(Page::default())
        );
        // Lines that are not records are counted, not shown; the last line,
        // without its newline, may still be being written, and is left out.
        let text = format!(
            "{}not json\n{}{{\"time\":\"x\"}}\n\n{}{}",
            line("1"),
            line("2"),
            line("3"),
            line("4").trim_end()
        );
        std::fs::write(&path, text).expect("write");
        let page = page_of(read_page(&path, None).expect("read"));
        assert_eq!(details(&page), ["3", "2", "1"]);
        assert_eq!(page.unreadable, 3);
        assert_eq!(page.older, None);
        assert!(!page.too_long);
        // An empty file has no records either.
        std::fs::write(&path, "").expect("write");
        assert_eq!(
            read_page(&path, None).expect("read"),
            PageRead::Page(Page::default())
        );
    }

    #[test]
    fn pages_read_every_record_once_whatever_their_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // Lines of different lengths, so that windows start and end
        // anywhere in them, and at their starts.
        let lines: Vec<String> = (0..12).map(|i| line(&"x".repeat(i * 7 % 23))).collect();
        std::fs::write(&path, lines.concat()).expect("write");
        let longest = lines.iter().map(String::len).max().expect("lines") as u64;
        let total = lines.iter().map(String::len).sum::<usize>() as u64;
        let all: Vec<String> = lines
            .iter()
            .rev()
            .map(|l| {
                serde_json::from_str::<AuditEvent>(l)
                    .expect("record")
                    .detail
                    .expect("detail")
            })
            .collect();
        for max_bytes in longest..=total + 2 {
            for max_records in 1..=lines.len() + 1 {
                let pages = all_pages(&path, max_bytes, max_records);
                let read: Vec<String> = pages
                    .iter()
                    .flat_map(|p| details(p).into_iter().map(String::from))
                    .collect();
                assert_eq!(read, all, "{max_bytes} bytes, {max_records} records");
                assert!(pages.iter().all(|p| p.records.len() <= max_records));
                assert!(pages.iter().all(|p| !p.too_long && p.unreadable == 0));
            }
        }
    }

    #[test]
    fn a_line_longer_than_a_page_stops_the_reading() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let long = line(&"y".repeat(300));
        let text = format!("{}{long}{}{}", line("old"), line("a"), line("b"));
        std::fs::write(&path, text).expect("write");
        let max_bytes = long.len() as u64 - 1;
        let pages = all_pages(&path, max_bytes, 10);
        assert_eq!(pages.len(), 2, "{pages:?}");
        assert_eq!(details(&pages[0]), ["b", "a"]);
        assert!(!pages[0].too_long);
        assert!(pages[1].records.is_empty());
        assert!(pages[1].too_long);
        assert_eq!(pages[1].older, None);
        // The last line, still without its newline, longer than a page.
        let partial = long.trim_end();
        std::fs::write(&path, format!("{}{partial}", line("a"))).expect("write");
        let shorter = partial.len() as u64 - 1;
        let page = page_of(read_page_within(&path, None, shorter, 10).expect("read"));
        assert!(page.records.is_empty());
        assert!(page.too_long);
        assert_eq!(page.older, None);
        // As long as a page: left out, and the records before it are read.
        let page = page_of(read_page_within(&path, None, shorter + 1, 10).expect("read"));
        assert_eq!(details(&page), ["a"]);
        assert!(!page.too_long);
        // The file holds part of a line only: no records, and nothing
        // before it that the reading would miss, unless the window does not
        // reach the start of the file.
        std::fs::write(&path, partial).expect("write");
        for (max_bytes, too_long) in [(shorter - 1, true), (shorter, false), (1 << 20, false)] {
            assert_eq!(
                read_page_within(&path, None, max_bytes, 10).expect("read"),
                PageRead::Page(Page {
                    too_long,
                    ..Page::default()
                }),
                "{max_bytes} bytes"
            );
        }
    }

    #[test]
    fn a_log_changed_under_a_cursor_is_read_again_from_its_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let lines: Vec<String> = (0..6).map(|i| line(&format!("#{i}"))).collect();
        let write = |text: &str| std::fs::write(&path, text).expect("write");
        let first = |path: &Path| page_of(read_page_within(path, None, 1 << 20, 2).expect("read"));
        write(&lines.concat());
        let cursor = first(&path).older.expect("more");
        // Records appended since do not change it.
        std::fs::write(&path, format!("{}{}", lines.concat(), line("new"))).expect("write");
        let page = page_of(read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"));
        assert_eq!(details(&page), ["#3", "#2"]);
        // Truncated.
        write(&lines[..2].concat());
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // Truncated after the cursor's line, which is still there.
        write(&lines[..5].concat());
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // Emptied and written again past the cursor: the line is not there.
        write(&format!("{}{}", line("other"), lines.concat()));
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // The same lines, with the cursor's line rewritten in place.
        let mut rewritten = lines.clone();
        rewritten[4] = line("#X");
        write(&rewritten.concat());
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // The line before the cursor's no longer ends where it starts.
        write(&lines.concat());
        let cursor = first(&path).older.expect("more");
        let mut joined = lines.concat().into_bytes();
        let before = lines[..4].concat().len() - 1;
        assert_eq!(joined[before], b'\n');
        joined[before] = b' ';
        std::fs::write(&path, joined).expect("write");
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // Rotated: another file at the path, even with the same text.
        write(&lines.concat());
        let cursor = first(&path).older.expect("more");
        let rotated = dir.path().join("audit.jsonl.1");
        std::fs::rename(&path, &rotated).expect("rename");
        write(&lines.concat());
        assert_eq!(
            read_page_within(&path, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
        // The rotated file is still the cursor's.
        let page = page_of(read_page_within(&rotated, Some(&cursor), 1 << 20, 2).expect("read"));
        assert_eq!(details(&page), ["#3", "#2"]);
        // Removed.
        std::fs::remove_file(&path).expect("remove");
        let cursor = first(&rotated).older.expect("more");
        std::fs::remove_file(&rotated).expect("remove");
        assert_eq!(
            read_page_within(&rotated, Some(&cursor), 1 << 20, 2).expect("read"),
            PageRead::Changed
        );
    }

    #[test]
    fn only_a_regular_file_is_read_and_a_fifo_does_not_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            read_page(dir.path(), None).expect_err("a directory").kind(),
            io::ErrorKind::InvalidInput
        );
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_page(&fifo, None).map_err(|e| e.kind()));
        });
        let read = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("opening a FIFO waited for a writer");
        assert_eq!(read, Err(io::ErrorKind::InvalidInput));
    }

    /// Gives a directory its mode `0700` back when dropped: a test that
    /// failed with it closed still leaves a directory that can be removed.
    struct Reopen(PathBuf);

    impl Drop for Reopen {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn record(log: &AuditLog, detail: &str) -> io::Result<()> {
        log.record(
            &AuditEvent::new("run", &Peer::agent())
                .outcome("allowed_once")
                .detail(detail),
        )
    }

    fn written(log: &AuditLog) -> Vec<String> {
        tail(log.path(), 100)
            .expect("tail")
            .into_iter()
            .filter_map(|event| event.detail)
            .collect()
    }

    /// A record that fails because a directory cannot be synced.
    fn not_synced(result: io::Result<()>, dir: &Path) {
        let e = result.expect_err("recorded without syncing the directory");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(
            e.to_string()
                .contains(&format!("cannot sync the directory {}", dir.display())),
            "{e}"
        );
    }

    // In a directory of mode `0300` a file can be created, but the directory
    // cannot be opened, and so not synced: a real failure of the sync.

    /// A new directory, by a name the agent would also give it (no link on
    /// the way), in a temporary directory.
    fn new_dir(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().canonicalize().expect("path").join(name);
        std::fs::create_dir(&path).expect("mkdir");
        path
    }

    #[test]
    fn every_record_syncs_the_directory_that_holds_the_log() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        chmod(&closed, 0o300);
        let log = AuditLog::new(closed.join("audit.jsonl"));
        // The record creates the file, whose name cannot be synced: refused,
        // and not written.
        not_synced(record(&log, "first"), &closed);
        assert!(log.path().exists());
        // The file is there now, its name still not synced: refused again.
        not_synced(record(&log, "second"), &closed);
        assert!(written(&log).is_empty());
        // Once the directory can be synced, the record is written.
        chmod(&closed, 0o700);
        record(&log, "third").expect("record");
        // A record after that one syncs the directory again.
        chmod(&closed, 0o300);
        not_synced(record(&log, "fourth"), &closed);
        assert_eq!(written(&log), ["third"]);
        // Removed, and created again by the next record.
        std::fs::remove_file(log.path()).expect("remove");
        not_synced(record(&log, "fifth"), &closed);
        chmod(&closed, 0o700);
        record(&log, "sixth").expect("record");
        assert_eq!(written(&log), ["sixth"]);
    }

    #[test]
    fn a_log_another_program_made_again_is_synced_even_with_the_old_inode() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        let log = AuditLog::new(closed.join("audit.jsonl"));
        record(&log, "first").expect("record");
        // Another program removes the log and makes another, which the file
        // system can give the removed one's inode (as ext4 often does).
        let inode = |path: &Path| std::fs::metadata(path).expect("meta").ino();
        let old = inode(log.path());
        for _ in 0..20 {
            std::fs::remove_file(log.path()).expect("remove");
            std::fs::File::create(log.path()).expect("create");
            if inode(log.path()) == old {
                break;
            }
        }
        chmod(&closed, 0o300);
        not_synced(record(&log, "second"), &closed);
        chmod(&closed, 0o700);
        record(&log, "third").expect("record");
        assert_eq!(written(&log), ["third"]);
    }

    #[test]
    fn the_names_of_directories_made_for_a_log_are_synced_in_their_parents() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        chmod(&closed, 0o300);
        // Two directories are made, in `closed` and in the first; the file's
        // own directory can be synced, the parent of the first cannot.
        let log = AuditLog::new(closed.join("state").join("rusthorse").join("audit.jsonl"));
        not_synced(record(&log, "first"), &closed);
        assert!(log.path().exists());
        // Everything is there now, the first name still not synced.
        not_synced(record(&log, "second"), &closed);
        assert!(written(&log).is_empty());
        chmod(&closed, 0o700);
        record(&log, "third").expect("record");
        // Synced once, the parents are not synced again.
        chmod(&closed, 0o300);
        record(&log, "fourth").expect("record");
        assert_eq!(written(&log), ["third", "fourth"]);
    }

    #[test]
    fn a_directory_made_before_a_failure_is_synced_in_its_parent_by_the_next_record() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        std::fs::create_dir(closed.join("real")).expect("mkdir");
        std::os::unix::fs::symlink(closed.join("real"), closed.join("link")).expect("symlink");
        chmod(&closed, 0o300);
        // The log's directory is reached through `new`, which the record
        // makes in `closed`; then the directory turns out to be a link,
        // which is refused.
        let log = AuditLog::new(closed.join("new/../link/audit.jsonl"));
        let refused = record(&log, "first").expect_err("a link as the directory");
        assert!(
            refused.to_string().contains("is not a directory"),
            "{refused}"
        );
        assert!(closed.join("new").is_dir());
        // A directory in place of the link: the next record goes as far as
        // syncing `closed`, which holds the name of `new`.
        std::fs::remove_file(closed.join("link")).expect("remove");
        std::fs::create_dir(closed.join("link")).expect("mkdir");
        not_synced(record(&log, "second"), &closed);
        chmod(&closed, 0o700);
        record(&log, "third").expect("record");
        assert_eq!(written(&log), ["third"]);
    }

    #[test]
    fn a_log_reached_through_a_link_is_synced_where_the_file_is() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        let link = closed.parent().expect("base").join("audit.jsonl");
        std::os::unix::fs::symlink(closed.join("audit.jsonl"), &link).expect("symlink");
        chmod(&closed, 0o300);
        let log = AuditLog::new(link);
        not_synced(record(&log, "first"), &closed);
        not_synced(record(&log, "second"), &closed);
        chmod(&closed, 0o700);
        record(&log, "third").expect("record");
        assert_eq!(written(&log), ["third"]);
    }

    #[test]
    fn a_log_moved_or_replaced_after_it_was_opened_is_not_written() {
        if nix::unistd::geteuid().is_root() {
            return; // root opens any directory
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().canonicalize().expect("path");
        let closed = new_dir(&dir, "closed");
        let _reopen = Reopen(closed.clone());
        let path = base.join("audit.jsonl");
        let moved = closed.join("moved.jsonl");
        // Moved to a directory that cannot be synced, another file in its
        // place: the directory synced does not hold the file opened.
        let file = open_log(&path).expect("open");
        std::fs::rename(&path, &moved).expect("move");
        std::fs::File::create(&path).expect("substitute");
        chmod(&closed, 0o300);
        replaced(append(&path, &mut Unsynced::default(), file, b"moved\n").expect_err("written"));
        chmod(&closed, 0o700);
        assert_eq!(std::fs::read(&moved).expect("moved"), b"");
        assert_eq!(std::fs::read(&path).expect("substitute"), b"");
        // Replaced in its own directory.
        let file = open_log(&path).expect("open");
        std::fs::rename(&moved, &path).expect("replace");
        replaced(
            append(&path, &mut Unsynced::default(), file, b"replaced\n").expect_err("written"),
        );
        // Removed.
        let file = open_log(&path).expect("open");
        std::fs::remove_file(&path).expect("remove");
        let removed = append(&path, &mut Unsynced::default(), file, b"removed\n");
        assert_eq!(
            removed.expect_err("written").kind(),
            io::ErrorKind::NotFound
        );
        // Left where it was: written.
        let file = open_log(&path).expect("open");
        append(&path, &mut Unsynced::default(), file, b"kept\n").expect("written");
        assert_eq!(std::fs::read(&path).expect("log"), b"kept\n");
    }

    /// Runs a test's hook after the steps of syncing the directory that
    /// holds the log, on the test's thread, until dropped.
    struct AtSteps;

    impl AtSteps {
        fn run(hook: impl FnMut(Step) + 'static) -> AtSteps {
            AT_STEP.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
            AtSteps
        }
    }

    impl Drop for AtSteps {
        fn drop(&mut self) {
            AT_STEP.with(|h| *h.borrow_mut() = None);
        }
    }

    /// A FIFO put in place of a directory the record syncs fails the
    /// record at once, and the next one too: opening it to read would have
    /// waited for a writer, with the log held.
    #[test]
    fn a_fifo_in_place_of_a_directory_fails_records_at_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = new_dir(&dir, "logs");
        let away = dir.path().canonicalize().expect("path").join("away");
        let log = std::sync::Arc::new(AuditLog::new(logs.join("audit.jsonl")));
        record(&log, "first").expect("record");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn({
            let (log, logs, away) = (std::sync::Arc::clone(&log), logs.clone(), away.clone());
            move || {
                // The log's directory, once the record has resolved its path.
                let _hook = AtSteps::run(move |step| {
                    if step == Step::Resolved {
                        std::fs::rename(&logs, &away).expect("away");
                        nix::unistd::mkfifo(&logs, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
                    }
                });
                let _ = tx.send(record(&log, "second").map_err(|e| e.kind()));
            }
        });
        let second = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("opening a FIFO waited for a writer");
        assert_eq!(second, Err(io::ErrorKind::NotADirectory));
        std::fs::remove_file(&logs).expect("remove the FIFO");
        std::fs::rename(&away, &logs).expect("back");
        assert_eq!(written(&log), ["first"]);
        // A directory waiting for its sync, a FIFO by then: every record
        // fails at once, the log never held.
        let fifo = dir.path().canonicalize().expect("path").join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        log.lock.lock().expect("lock").add(&fifo);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn({
            let log = std::sync::Arc::clone(&log);
            move || {
                for detail in ["third", "fourth"] {
                    let _ = tx.send(record(&log, detail).map_err(|e| e.kind()));
                }
            }
        });
        for _ in 0..2 {
            let refused = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("opening a FIFO waited for a writer");
            assert_eq!(refused, Err(io::ErrorKind::NotADirectory));
        }
        assert_eq!(written(&log), ["first"]);
    }

    fn replaced(e: io::Error) {
        assert!(
            e.to_string()
                .contains("was renamed, replaced or removed while a record was written"),
            "{e}"
        );
    }

    #[test]
    fn a_substitute_at_the_check_is_refused_though_the_file_is_put_back_after() {
        // Another program takes the file away and puts a substitute in its
        // place once the directory is open, and puts the file back once the
        // directory is synced: the check comes first, and sees the
        // substitute.
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().canonicalize().expect("path");
        let path = base.join("audit.jsonl");
        let away = base.join("away.jsonl");
        let file = open_log(&path).expect("open");
        let _hook = AtSteps::run({
            let (path, away) = (path.clone(), away.clone());
            move |step| match step {
                Step::Opened => {
                    std::fs::rename(&path, &away).expect("away");
                    std::fs::File::create(&path).expect("substitute");
                }
                Step::Synced => std::fs::rename(&away, &path).expect("back"),
                Step::Resolved => {}
            }
        });
        replaced(append(&path, &mut Unsynced::default(), file, b"refused\n").expect_err("written"));
        assert_eq!(std::fs::read(&away).expect("the file"), b"");
        assert_eq!(std::fs::read(&path).expect("the substitute"), b"");
    }

    #[test]
    fn a_file_put_back_before_the_check_is_synced_after_it() {
        // Taken away, a substitute in its place, and put back, all before
        // the check: the sync that follows the check finds it there.
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().canonicalize().expect("path");
        let path = base.join("audit.jsonl");
        let away = base.join("away.jsonl");
        let file = open_log(&path).expect("open");
        let original = file.metadata().expect("meta").ino();
        let synced_with = std::rc::Rc::new(std::cell::Cell::new(None));
        let _hook = AtSteps::run({
            let (path, synced_with) = (path.clone(), std::rc::Rc::clone(&synced_with));
            move |step| match step {
                Step::Opened => {
                    std::fs::rename(&path, &away).expect("away");
                    std::fs::File::create(&path).expect("substitute");
                    std::fs::rename(&away, &path).expect("back");
                }
                Step::Synced => {
                    synced_with.set(Some(std::fs::metadata(&path).expect("meta").ino()));
                }
                Step::Resolved => {}
            }
        });
        append(&path, &mut Unsynced::default(), file, b"kept\n").expect("written");
        assert_eq!(synced_with.get(), Some(original), "synced after the check");
        assert_eq!(std::fs::read(&path).expect("log"), b"kept\n");
    }

    #[test]
    fn a_file_moved_out_of_the_opened_directory_is_refused_though_the_path_finds_it() {
        // Once the directory is open, another program moves the file into a
        // new directory and puts that directory at the same path: the path
        // leads to the file, the directory opened no longer holds it.
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().canonicalize().expect("path");
        let logs = new_dir(&dir, "logs");
        let path = logs.join("audit.jsonl");
        let file = open_log(&path).expect("open");
        let _hook = AtSteps::run({
            let (base, logs) = (base.clone(), logs.clone());
            move |step| {
                if step == Step::Opened {
                    std::fs::create_dir(base.join("new")).expect("mkdir");
                    std::fs::rename(logs.join("audit.jsonl"), base.join("new/audit.jsonl"))
                        .expect("move the file");
                    std::fs::rename(&logs, base.join("old")).expect("move the directory");
                    std::fs::rename(base.join("new"), &logs).expect("put the new one there");
                }
            }
        });
        replaced(append(&path, &mut Unsynced::default(), file, b"moved\n").expect_err("written"));
        assert_eq!(std::fs::read(&path).expect("the file"), b"");
    }

    #[test]
    fn a_record_whose_data_cannot_be_synced_fails_and_may_be_in_the_file() {
        // A FIFO cannot be synced to disk; a reader holds it open, so that
        // opening it to write does not wait.
        use std::io::Read;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        let mut reader = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open the FIFO");
        let log = AuditLog::new(path);
        record(&log, "refused").expect_err("synced into a FIFO");
        let mut taken = vec![0; 4096];
        let n = reader.read(&mut taken).expect("read");
        assert!(
            String::from_utf8_lossy(&taken[..n]).contains("\"detail\":\"refused\""),
            "{:?}",
            String::from_utf8_lossy(&taken[..n])
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
