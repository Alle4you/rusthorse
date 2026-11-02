//! The agent: a long-running process that holds the unlocked vault and
//! mediates every use of a secret.
//!
//! Policy summary (the rationale is in `docs/threat-model.md`):
//!
//! | Request  | Needs unlock | Human interaction                              |
//! |----------|--------------|------------------------------------------------|
//! | status   | no           | none                                           |
//! | lock     | no           | none                                           |
//! | unlock   | —            | master password dialog                         |
//! | list/show| yes          | none (metadata only)                           |
//! | add      | yes          | value dialog, or approval if the client sends it |
//! | import   | yes          | approval for the whole batch                   |
//! | edit     | yes          | approval (+ value dialog when asked)           |
//! | remove   | yes          | approval                                       |
//! | reveal   | yes          | approval, never remembered                     |
//! | run      | yes          | approval, may be remembered for a while        |
//!
//! Only one dialog is shown at a time. For `run`, the agent itself resolves
//! the program, cleans the environment, spawns the command as its own child
//! and filters its output, so what the human approves is what runs.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, waitid};
use nix::unistd::{Pid, getuid};

use crate::audit::{AuditEvent, AuditLog};
use crate::exec;
use crate::peer::Peer;
use crate::protocol::{
    self, EntryChanges, EntryFields, ErrorCode, ImportSource, ImportedEntry, NewEntry, Request,
    Response, RevealPurpose, RunRequest, SecretString, StatusInfo, ValueChange,
};
use crate::redact::Redactor;
use crate::session_lock;
use crate::ui::{ApprovalRequest, Decision, Prompt, Typed, Ui};
use crate::util::{self, shell_join};
use crate::vault::{KdfParams, Vault, VaultError};

/// How many wrong master passwords are tolerated per unlock.
const UNLOCK_ATTEMPTS: u32 = 3;

/// Grace period between SIGTERM and SIGKILL when a client goes away.
const KILL_GRACE: Duration = Duration::from_secs(3);

/// Connections handled at the same time; more are refused.
const MAX_CONNECTIONS: usize = 64;

/// Requests that may wait for the human at the same time; more are refused.
const MAX_WAITING_FOR_DIALOG: usize = 8;

use crate::ui::MAX_DIALOG_CHARS;

/// Longest text the approval dialog shows for one detail. Longer requests are
/// refused instead of truncated: the human must see everything they approve.
const MAX_DETAIL_CHARS: usize = 1000;

/// Most entries in one import batch (all of them are listed in the dialog).
const MAX_IMPORT: usize = crate::import::MAX_ENTRIES;
/// The largest `.env` file the agent reads for an import.
const MAX_DOTENV_BYTES: u64 = 1024 * 1024;

/// Agent settings.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Vault file.
    pub vault: PathBuf,
    /// Unix socket to listen on.
    pub socket: PathBuf,
    /// Audit log file.
    pub audit_log: PathBuf,
    /// Lock after this much inactivity (zero = never).
    pub idle_timeout: Duration,
    /// How long a client has to send its whole request (10 s in production).
    pub request_timeout: Duration,
    /// Size of each connection's send buffer (`SO_SNDBUF`); `None` keeps the
    /// system default. Only tests set it, to make back-pressure happen after a
    /// few frames instead of after hundreds of kilobytes.
    pub send_buffer: Option<usize>,
    /// Lock when the screen locks or the computer suspends, and which buses
    /// to watch (ADR 0009). The default watches nothing.
    pub session_lock: crate::session_lock::Settings,
    /// Key-derivation settings of a vault created through `create_vault`:
    /// [`KdfParams::DEFAULT`] in production; tests use weaker ones to run
    /// fast.
    pub new_vault_kdf: KdfParams,
    /// Where imports from GNOME Keyring find the Secret Service (ADR 0012).
    pub keyring: crate::keyring::Settings,
}

/// A failed request: what goes back to the client as [`Response::Error`].
#[derive(Debug)]
pub struct Failure {
    /// Machine-readable reason.
    pub code: ErrorCode,
    /// Human-readable explanation.
    pub message: String,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }
}

impl From<VaultError> for Failure {
    fn from(e: VaultError) -> Self {
        let code = match &e {
            VaultError::NotFound(_) => ErrorCode::NotFound,
            VaultError::Ambiguous { .. } => ErrorCode::Ambiguous,
            VaultError::AlreadyExists(_) => ErrorCode::AlreadyExists,
            VaultError::WrongPassword => ErrorCode::UnlockFailed,
            VaultError::ChangedOnDisk => ErrorCode::VaultChanged,
            VaultError::Missing(_) => ErrorCode::VaultMissing,
            VaultError::Invalid(_) => ErrorCode::InvalidRequest,
            VaultError::NotDurable(_) => ErrorCode::OutcomeUnknown,
            VaultError::Exists(_) => ErrorCode::AlreadyExists,
            VaultError::Open(_) | VaultError::Save(_) | VaultError::Io(_) => ErrorCode::Internal,
        };
        Failure::new(code, e.to_string())
    }
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::new(ErrorCode::Internal, format!("{e:#}"))
    }
}

struct Remembered {
    key: String,
    until: Instant,
}

struct State {
    vault: Option<Vault>,
    /// Last approved use; read-only requests (`list`, `show`, `status`) and
    /// denied requests do not count, so they cannot keep the vault unlocked.
    last_used: Instant,
    remembered: Vec<Remembered>,
    /// Incremented on every unlock, lock and saved change. An approval is
    /// only acted on if the generation did not change while the human was
    /// deciding, and remembered approvals are tied to one generation.
    generation: u64,
    /// The last keyring listing the human allowed, and to whom: keyring
    /// imports may only use items of it (ADR 0012). A lock forgets it.
    keyring_listing: Option<KeyringListing>,
    /// Incremented on every lock only: a keyring listing under way when the
    /// vault is locked is not kept.
    locks: u64,
}

impl State {
    fn lock(&mut self) {
        self.vault = None;
        self.remembered.clear();
        self.keyring_listing = None;
        self.locks += 1;
        self.generation += 1;
    }
}

/// A keyring listing that the human allowed a program to see.
struct KeyringListing {
    /// The program it was shown to: process id and start time.
    requester: (i32, Option<u64>),
    at: Instant,
    /// The items, by object path, as they were shown.
    items: std::collections::HashMap<String, crate::protocol::KeyringItem>,
}

/// How long a keyring listing may be imported from.
const KEYRING_LISTING_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Decrements a counter when dropped.
struct CountGuard<'a>(&'a AtomicUsize);

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn locked_meanwhile() -> Failure {
    Failure::new(
        ErrorCode::Locked,
        "the vault was locked or changed while the request was waiting; try again",
    )
}

/// The agent. Create with [`Agent::new`], then call [`Agent::serve`].
pub struct Agent {
    config: AgentConfig,
    ui: Box<dyn Ui>,
    state: Mutex<State>,
    /// Serializes dialogs: the human answers one question at a time.
    dialog: Mutex<()>,
    waiting_for_dialog: AtomicUsize,
    connections: Arc<AtomicUsize>,
    audit: AuditLog,
    /// What else locks the vault, for `status` (ADR 0009).
    lock_triggers: Arc<session_lock::Triggers>,
    /// The watchers behind them; dropping the agent stops them.
    session_watchers: Mutex<session_lock::Watchers>,
}

impl session_lock::Locker for Agent {
    /// Lock as `rusthorse lock` does. The generation changes even when the
    /// vault is already locked, so that an unlock whose password is being
    /// typed now does nothing when it completes.
    fn lock_for(&self, event: &str, source: &str) {
        let mut state = self.state();
        let was_open = state.vault.is_some() || !state.remembered.is_empty();
        state.lock();
        drop(state);
        if was_open {
            let outcome = if event == session_lock::SUSPEND {
                "suspend"
            } else {
                "screen_locked"
            };
            let _ = self.audit.record(
                &AuditEvent::new("lock", &Peer::agent())
                    .outcome(outcome)
                    .detail(source),
            );
        }
    }
}

impl Agent {
    /// Build an agent that asks its questions through `ui`.
    pub fn new(config: AgentConfig, ui: Box<dyn Ui>) -> Arc<Agent> {
        let audit = AuditLog::new(config.audit_log.clone());
        Arc::new(Agent {
            config,
            ui,
            state: Mutex::new(State {
                vault: None,
                last_used: Instant::now(),
                remembered: Vec::new(),
                generation: 0,
                keyring_listing: None,
                locks: 0,
            }),
            dialog: Mutex::new(()),
            waiting_for_dialog: AtomicUsize::new(0),
            connections: Arc::new(AtomicUsize::new(0)),
            audit,
            lock_triggers: Arc::default(),
            session_watchers: Mutex::default(),
        })
    }

    /// Bind the socket at `path`: private directory, stale socket removal,
    /// mode `0600`. Fails if another agent is already listening there.
    pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .context("the socket path has no parent directory")?;
        util::ensure_private_dir(dir)
            .with_context(|| format!("cannot prepare {}", dir.display()))?;
        if std::fs::symlink_metadata(path).is_ok() {
            if UnixStream::connect(path).is_ok() {
                anyhow::bail!("another agent is already listening on {}", path.display());
            }
            std::fs::remove_file(path)
                .with_context(|| format!("cannot remove stale socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path)
            .with_context(|| format!("cannot listen on {}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    /// Accept connections forever, one thread per connection.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) -> anyhow::Result<()> {
        self.start_idle_timer();
        *self
            .session_watchers
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = session_lock::start(
            Arc::downgrade(self),
            self.config.session_lock.clone(),
            Arc::clone(&self.lock_triggers),
        );
        for connection in listener.incoming() {
            match connection {
                Ok(stream) => {
                    if self.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        self.connections.fetch_sub(1, Ordering::SeqCst);
                        drop(stream);
                        continue;
                    }
                    let agent = Arc::clone(self);
                    thread::Builder::new()
                        .name("rusthorse-conn".into())
                        .spawn(move || {
                            let _count = CountGuard(&agent.connections);
                            agent.handle_connection(stream);
                        })
                        .context("cannot start a connection thread")?;
                }
                Err(e) => eprintln!("rusthorse agent: accept failed: {e}"),
            }
        }
        Ok(())
    }

    fn start_idle_timer(self: &Arc<Self>) {
        if self.config.idle_timeout.is_zero() {
            return;
        }
        let weak: Weak<Agent> = Arc::downgrade(self);
        let _ = thread::Builder::new()
            .name("rusthorse-idle".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    let Some(agent) = weak.upgrade() else { return };
                    agent.lock_if_idle();
                }
            });
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Wait for our turn to show a dialog, refusing when too many requests
    /// are already waiting (a flood of requests should not queue forever).
    fn dialog(&self) -> Result<MutexGuard<'_, ()>, Failure> {
        if self.waiting_for_dialog.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_FOR_DIALOG {
            self.waiting_for_dialog.fetch_sub(1, Ordering::SeqCst);
            return Err(Failure::new(
                ErrorCode::Denied,
                "too many requests are waiting for your answer; try again later",
            ));
        }
        let _waiting = CountGuard(&self.waiting_for_dialog);
        Ok(self.dialog.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Note an approved use of the vault (postpones the idle lock).
    fn touch(&self) {
        self.state().last_used = Instant::now();
    }

    fn lock_if_idle(&self) {
        let mut state = self.state();
        if state.vault.is_some() && state.last_used.elapsed() >= self.config.idle_timeout {
            state.lock();
            drop(state);
            let _ = self
                .audit
                .record(&AuditEvent::new("lock", &Peer::agent()).outcome("idle_timeout"));
        }
    }

    /// Write an audit record; refuse the request when that is impossible.
    fn record(&self, event: AuditEvent) -> Result<(), Failure> {
        self.audit.record(&event).map_err(|e| {
            Failure::new(
                ErrorCode::Internal,
                format!(
                    "cannot write the audit log {} ({e}); refusing the request",
                    self.audit.path().display()
                ),
            )
        })
    }

    fn handle_connection(&self, stream: UnixStream) {
        if let Err(e) = self.handle_connection_inner(&stream)
            && !matches!(e.downcast_ref::<io::Error>(), Some(io) if io.kind() == io::ErrorKind::UnexpectedEof || io.kind() == io::ErrorKind::BrokenPipe)
        {
            eprintln!("rusthorse agent: {e:#}");
        }
    }

    fn handle_connection_inner(&self, stream: &UnixStream) -> anyhow::Result<()> {
        let peer = Peer::of(stream).context("cannot identify the client")?;
        if peer.uid != getuid().as_raw() {
            // Another user (only possible if the socket directory was opened up).
            return Ok(());
        }
        if let Some(size) = self.config.send_buffer {
            nix::sys::socket::setsockopt(stream, nix::sys::socket::sockopt::SndBuf, &size)?;
        }
        let deadline = Instant::now() + self.config.request_timeout;
        let (body, fds) = protocol::recv_frame_before(stream, Some(deadline))?;
        let request: Request = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(e) => {
                let response = Response::Error {
                    code: ErrorCode::InvalidRequest,
                    message: format!("malformed request: {e}"),
                };
                protocol::send_frame(stream, &response, &[])?;
                return Ok(());
            }
        };
        drop(body);

        let result = match request {
            Request::Run(run) => self.run(stream, &peer, run, fds),
            _ if !fds.is_empty() => Err(Failure::invalid(
                "only run requests may carry file descriptors",
            )),
            other => self.dispatch(&peer, other),
        };
        let response = result.unwrap_or_else(|f| Response::Error {
            code: f.code,
            message: f.message,
        });
        protocol::send_frame(stream, &response, &[])?;
        Ok(())
    }

    fn dispatch(&self, peer: &Peer, request: Request) -> Result<Response, Failure> {
        match request {
            Request::Status => Ok(Response::Status(self.status())),
            Request::Lock => {
                self.state().lock();
                self.record(AuditEvent::new("lock", peer).outcome("requested"))?;
                Ok(ok("vault locked"))
            }
            Request::Unlock => {
                self.ensure_unlocked(peer)?;
                Ok(ok("vault unlocked"))
            }
            Request::CreateVault => self.create_vault(peer),
            Request::List => self.with_vault(peer, |v| Ok(Response::Entries { entries: v.list() })),
            Request::Show { name } => self.with_vault(peer, |v| {
                let id = v.find(&name)?;
                Ok(Response::Entry { entry: v.info(id) })
            }),
            Request::Add {
                entry,
                value,
                generate,
                replace,
            } => self.add(peer, entry, value, generate, replace),
            Request::ChangePassword => self.change_password(peer),
            Request::Import { entries, replace } => self.import(peer, entries, replace),
            Request::Edit { name, changes } => self.edit(peer, &name, changes),
            Request::Remove { name } => self.remove(peer, &name),
            Request::Reveal {
                name,
                notes,
                purpose,
            } => self.reveal(peer, &name, notes, purpose),
            Request::Backup { path } => self.backup(peer, &path),
            Request::KeyringItems => self.keyring_items(peer),
            Request::DotenvNames { path } => self.dotenv_names(peer, &path),
            Request::ImportFrom {
                source,
                tags,
                replace,
            } => self.import_from(peer, source, tags, replace),
            Request::Run(_) => Err(Failure::invalid("run requests carry file descriptors")),
        }
    }

    fn status(&self) -> StatusInfo {
        let mut state = self.state();
        let now = Instant::now();
        state.remembered.retain(|r| r.until > now);
        let locked = state.vault.is_none();
        let idle = self.config.idle_timeout;
        let executable = std::fs::read_link("/proc/self/exe").ok();
        // `/proc/self/exe` itself always leads to the running file, even once
        // its name points elsewhere or nowhere.
        let running = util::file_identity(Path::new("/proc/self/exe")).ok();
        StatusInfo {
            protocol_version: protocol::PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            vault: self.config.vault.display().to_string(),
            vault_exists: self.config.vault.exists(),
            audit_log: self.config.audit_log.display().to_string(),
            locked,
            idle_timeout_secs: idle.as_secs(),
            locks_in_secs: (!locked && !idle.is_zero())
                .then(|| idle.saturating_sub(state.last_used.elapsed()).as_secs()),
            remembered_approvals: state.remembered.len(),
            agent_executable: executable
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            agent_executable_id: running,
            agent_executable_replaced: executable
                .as_deref()
                .and_then(|path| util::replaced(path, running)),
            dialogs: Some(match crate::dialog_program::locate() {
                crate::dialog_program::Located::Program(path) => path.display().to_string(),
                crate::dialog_program::Located::Absent(_) => "zenity".into(),
                crate::dialog_program::Located::Unusable(why) => format!("none: {why}"),
            }),
            lock_triggers: self.lock_triggers.snapshot(),
        }
    }

    /// Run `f` on the unlocked vault, unlocking it first if needed.
    fn with_vault<R>(
        &self,
        peer: &Peer,
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<R, Failure> {
        self.ensure_unlocked(peer)?;
        let mut state = self.state();
        let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
        f(vault)
    }

    /// The current generation, unlocking first if needed.
    fn generation(&self, peer: &Peer) -> Result<u64, Failure> {
        self.ensure_unlocked(peer)?;
        Ok(self.state().generation)
    }

    /// Run `f` on the vault only if its generation is still `generation`,
    /// checked under the same lock — so that what `f` reads is exactly what
    /// the human approved.
    fn with_vault_at<R>(
        &self,
        generation: u64,
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<R, Failure> {
        let mut state = self.state();
        if state.generation != generation {
            return Err(locked_meanwhile());
        }
        let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
        f(vault)
    }

    /// Apply an approved change and save it, but only if nothing happened to
    /// the vault since `generation`. The change is a transaction: if `f`
    /// fails, everything it did is rolled back. If saving fails, the vault is
    /// locked so that memory never holds changes that are not on disk — and
    /// if it failed after the file was replaced, the answer is
    /// [`ErrorCode::OutcomeUnknown`]: the change is on disk, but may not
    /// survive a crash.
    fn commit<R>(
        &self,
        generation: u64,
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<R, Failure> {
        self.commit_reporting(generation, f)
            .map(|(result, _)| result)
    }

    /// [`Agent::commit`], also returning — read under the same lock as the
    /// save, so that nothing (a `lock`, say) can come in between — any problem
    /// with the cleanup that followed the save.
    fn commit_reporting<R>(
        &self,
        generation: u64,
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<(R, Option<String>), Failure> {
        let mut state = self.state();
        if state.generation != generation {
            return Err(locked_meanwhile());
        }
        let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
        let result = vault.transaction(f)?;
        if let Err(e) = vault.save() {
            state.lock();
            let replaced = matches!(e, VaultError::NotDurable(_));
            let mut failure = Failure::from(e);
            failure.message.push_str(if replaced {
                " (the vault was locked; unlock it to see what the file now holds)"
            } else {
                " (the vault was locked to discard the unsaved change)"
            });
            return Err(failure);
        }
        let cleanup = vault.take_cleanup_error();
        state.generation += 1;
        state.last_used = Instant::now();
        Ok((result, cleanup))
    }

    fn ensure_unlocked(&self, peer: &Peer) -> Result<(), Failure> {
        if self.state().vault.is_some() {
            return Ok(());
        }
        if !self.config.vault.exists() {
            return Err(VaultError::Missing(self.config.vault.clone()).into());
        }
        let _dialog = self.dialog()?;
        let started = {
            let state = self.state();
            if state.vault.is_some() {
                return Ok(());
            }
            state.generation
        };
        let vault = self.config.vault.display().to_string();
        let prompt_with = |notice: Option<String>| Prompt {
            title: "Rusthorse — unlock vault".into(),
            headline: "Type the master password to unlock the Rusthorse vault.".into(),
            explanation: String::new(),
            notice,
            details: vec![
                ("Vault".into(), vault.clone()),
                ("Requested by (unverified)".into(), peer.describe()),
            ],
            field: "Master password".into(),
            confirm: "Unlock".into(),
        };
        // Room is kept for the "Wrong password" or "Nothing was typed" line.
        let base = crate::ui::prompt_text(&prompt_with(None));
        if base.chars().count() > MAX_DIALOG_CHARS - 100
            || (self.ui.limits_height()
                && crate::ui::prompt_height(&base) + 3 * crate::ui::metrics::TEXT
                    > crate::ui::metrics::MAX_HEIGHT)
        {
            return Err(Failure::invalid(
                "the unlock dialog would be too long to show (vault path or requester chain)",
            ));
        }
        let mut notice = None;
        let mut tried = false;
        for attempt in 1..=UNLOCK_ATTEMPTS {
            let prompt = prompt_with(notice.take());
            let password = match self.ui.master_password(&prompt)? {
                Typed::Value(password) => password,
                Typed::Cancelled => {
                    self.record(AuditEvent::new("unlock", peer).outcome("cancelled"))?;
                    return Err(Failure::new(ErrorCode::Cancelled, "unlock cancelled"));
                }
                Typed::TimedOut => {
                    self.record(AuditEvent::new("unlock", peer).outcome("timed_out"))?;
                    return Err(Failure::new(
                        ErrorCode::Cancelled,
                        "nobody answered the unlock dialog in time",
                    ));
                }
            };
            // Clicking Unlock with an empty field is not a guess at the
            // password (Rusthorse vaults always have one): ask again without
            // calling it wrong.
            if password.is_empty() {
                notice = Some(format!(
                    "Nothing was typed (attempt {attempt} of {UNLOCK_ATTEMPTS}). Type the \
                     master password, then click Unlock."
                ));
                continue;
            }
            tried = true;
            match Vault::open(&self.config.vault, password) {
                Ok(vault) => {
                    let mut state = self.state();
                    if state.generation != started {
                        // `lock` was requested while the password was typed.
                        drop(state);
                        drop(vault);
                        let _ = self
                            .audit
                            .record(&AuditEvent::new("unlock", peer).outcome("cancelled_by_lock"));
                        return Err(Failure::new(
                            ErrorCode::Locked,
                            "the vault was locked while the password was being entered",
                        ));
                    }
                    // Record first: if the audit log cannot be written, the
                    // vault stays locked.
                    self.record(AuditEvent::new("unlock", peer).outcome("unlocked"))?;
                    state.vault = Some(vault);
                    state.last_used = Instant::now();
                    state.generation += 1;
                    return Ok(());
                }
                Err(VaultError::WrongPassword) => {
                    self.record(AuditEvent::new("unlock", peer).outcome("wrong_password"))?;
                    notice = Some(format!(
                        "Wrong password (attempt {attempt} of {UNLOCK_ATTEMPTS})."
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
        if !tried {
            self.record(
                AuditEvent::new("unlock", peer)
                    .outcome("cancelled")
                    .detail("no password was typed"),
            )?;
            return Err(Failure::new(
                ErrorCode::Cancelled,
                "unlock cancelled: no master password was typed",
            ));
        }
        Err(Failure::new(
            ErrorCode::UnlockFailed,
            "wrong master password",
        ))
    }

    /// Ask for approval (or use a remembered one). `event` is the audit
    /// record to write with the outcome.
    fn approve(
        &self,
        request: ApprovalRequest,
        remember_key: Option<String>,
        event: AuditEvent,
    ) -> Result<(), Failure> {
        if let Some(key) = &remember_key {
            let mut state = self.state();
            let now = Instant::now();
            state.remembered.retain(|r| r.until > now);
            if state.remembered.iter().any(|r| &r.key == key) {
                drop(state);
                self.record(event.outcome("allowed_remembered"))?;
                self.touch();
                return Ok(());
            }
        }
        let length = crate::ui::approval_text(&request).chars().count()
            + if request.can_remember {
                crate::ui::REMEMBER_NOTE_MAX
            } else {
                0
            };
        if length > MAX_DIALOG_CHARS {
            return Err(Failure::invalid(format!(
                "this request has too much detail to show in one dialog ({length} characters, \
                 limit {MAX_DIALOG_CHARS}); split it into smaller requests"
            )));
        }
        // With zenity, the whole dialog, buttons included, must fit on the
        // screen: a value that wraps over many lines must not push the rest
        // out of sight. Rusthorse's own dialog scrolls instead, and keeps
        // Allow disabled until the end has been reached.
        if let Some(height) = crate::ui::approval_too_tall(&request)
            && self.ui.limits_height()
        {
            return Err(Failure::invalid(format!(
                "this request would make a dialog too tall to read at once (estimated {height} \
                 pixels, limit {}); split it into smaller requests or shorten what it shows",
                crate::ui::metrics::MAX_HEIGHT
            )));
        }
        let decision = {
            let _dialog = self.dialog()?;
            self.ui.approve(&request)?
        };
        match decision {
            Decision::Deny => {
                self.record(event.outcome("denied"))?;
                Err(Failure::new(ErrorCode::Denied, "the request was denied"))
            }
            Decision::TimedOut => {
                self.record(event.outcome("timed_out"))?;
                Err(Failure::new(
                    ErrorCode::Denied,
                    "nobody answered the approval dialog in time; the request was denied",
                ))
            }
            Decision::AllowOnce => {
                self.record(event.outcome("allowed_once"))?;
                self.touch();
                Ok(())
            }
            Decision::AllowFor(duration) => match remember_key {
                Some(key) if request.can_remember => {
                    self.record(
                        event.outcome(&format!("allowed_for_{}", util::format_duration(duration))),
                    )?;
                    self.state().remembered.push(Remembered {
                        key,
                        until: Instant::now() + duration,
                    });
                    self.touch();
                    Ok(())
                }
                _ => {
                    self.record(event.outcome("allowed_once"))?;
                    self.touch();
                    Ok(())
                }
            },
        }
    }

    fn ask_value(
        &self,
        peer: &Peer,
        prompt: Prompt,
        event: AuditEvent,
    ) -> Result<SecretString, Failure> {
        let text = crate::ui::prompt_text(&prompt);
        let length = text.chars().count();
        if length > MAX_DIALOG_CHARS {
            return Err(Failure::invalid(format!(
                "this request has too much detail to show in one dialog ({length} characters, \
                 limit {MAX_DIALOG_CHARS})"
            )));
        }
        if let Some(height) = crate::ui::prompt_too_tall(&prompt)
            && self.ui.limits_height()
        {
            return Err(Failure::invalid(format!(
                "this request would make a dialog too tall to read at once (estimated {height} \
                 pixels, limit {})",
                crate::ui::metrics::MAX_HEIGHT
            )));
        }
        let value = {
            let _dialog = self.dialog()?;
            self.ui.secret_value(&prompt)?
        };
        match value {
            Typed::Value(v) if !v.is_empty() => {
                self.record(event.outcome("value_entered"))?;
                Ok(v)
            }
            Typed::Value(_) => Err(Failure::invalid("empty value; nothing stored")),
            Typed::Cancelled => {
                let _ = peer;
                self.record(event.outcome("cancelled"))?;
                Err(Failure::new(ErrorCode::Cancelled, "cancelled"))
            }
            Typed::TimedOut => {
                self.record(event.outcome("timed_out"))?;
                Err(Failure::new(
                    ErrorCode::Cancelled,
                    "nobody answered the dialog in time",
                ))
            }
        }
    }

    fn add(
        &self,
        peer: &Peer,
        entry: NewEntry,
        value: Option<SecretString>,
        generate: Option<crate::generate::Spec>,
        replace: bool,
    ) -> Result<Response, Failure> {
        crate::vault::validate_name(&entry.name)?;
        if value.is_some() && generate.is_some() {
            return Err(Failure::invalid(
                "give a value or ask for one to be generated, not both",
            ));
        }
        let generation = self.generation(peer)?;
        let exists = self.with_vault(peer, |v| {
            let exists = v.contains(&entry.name);
            // A new entry's group is checked before anyone types a value:
            // the save would refuse the recycle bin or an invalid name after
            // the dialogs. (With `replace`, an existing entry stays where it
            // is and the group is not used.)
            if !exists && let Some(group) = &entry.group {
                v.check_group(group)?;
            }
            Ok(exists)
        })?;
        if exists && !replace {
            return Err(VaultError::AlreadyExists(entry.name.clone()).into());
        }
        let verb = if exists { "Replace" } else { "Create" };
        let event = AuditEvent::new("add", peer).entries(vec![entry.name.clone()]);
        let value = match (value, generate) {
            (None, Some(spec)) => {
                let request = ApprovalRequest {
                    title: "Rusthorse — generate a secret".into(),
                    summary: format!("{verb} an entry with a generated value?"),
                    explanation: "Rusthorse creates a random value and stores it. The value is \
                                  not returned to the program that asked."
                        .into(),
                    command: None,
                    details: vec![
                        ("Entry".into(), entry.name.clone()),
                        ("Fields".into(), describe_fields(&entry)),
                        ("Value".into(), describe_spec(spec)),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    facts: Vec::new(),
                    warnings: if exists {
                        vec!["The current value will be overwritten.".into()]
                    } else {
                        Vec::new()
                    },
                    can_remember: false,
                };
                self.approve(request, None, event)?;
                crate::generate::generate(spec).map_err(|e| Failure::invalid(e.to_string()))?
            }
            (None, None) => {
                let prompt = Prompt {
                    title: "Rusthorse — new secret".into(),
                    headline: if exists {
                        "Type a new value for an existing entry."
                    } else {
                        "Type the value of a new entry."
                    }
                    .into(),
                    explanation: if exists {
                        "It replaces the entry's current value."
                    } else {
                        ""
                    }
                    .into(),
                    notice: None,
                    details: vec![
                        ("Entry".into(), entry.name.clone()),
                        ("Fields".into(), describe_fields(&entry)),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    field: "Secret value".into(),
                    confirm: "Save".into(),
                };
                self.ask_value(peer, prompt, event)?
            }
            (Some(value), _) => {
                let request = ApprovalRequest {
                    title: "Rusthorse — store a secret".into(),
                    summary: format!("{verb} an entry with a value from a program?"),
                    explanation: "The program that asked supplied the value, so it already knows \
                                  it. Rusthorse stores it as it is."
                        .into(),
                    command: None,
                    details: vec![
                        ("Entry".into(), entry.name.clone()),
                        ("Fields".into(), describe_fields(&entry)),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    facts: Vec::new(),
                    warnings: if exists {
                        vec!["The current value will be overwritten.".into()]
                    } else {
                        Vec::new()
                    },
                    can_remember: false,
                };
                self.approve(request, None, event)?;
                value
            }
        };
        self.commit(generation, |v| {
            let replaced = v.add(&entry, &value, replace)?;
            Ok(ok(format!(
                "{} {}",
                entry.name,
                if replaced { "replaced" } else { "added" }
            )))
        })
    }

    fn import(
        &self,
        peer: &Peer,
        entries: Vec<ImportedEntry>,
        replace: bool,
    ) -> Result<Response, Failure> {
        let (entries, values): (Vec<NewEntry>, Vec<SecretString>) =
            entries.into_iter().map(|e| (e.entry, e.value)).unzip();
        self.import_entries(peer, entries, replace, Origin::Requester, || Ok(values))
    }

    /// Show the items of GNOME Keyring to the requester, after approval:
    /// labels and attributes, no secret (ADR 0012).
    fn keyring_items(&self, peer: &Peer) -> Result<Response, Failure> {
        let request = ApprovalRequest {
            title: "Rusthorse — list GNOME Keyring".into(),
            summary: "Show the items of GNOME Keyring to the program that asked?".into(),
            explanation: "It will see each item's label and attributes — not its secret — to \
                          choose what to import into Rusthorse."
                .into(),
            command: None,
            details: vec![("Requested by (unverified)".into(), peer.describe())],
            facts: Vec::new(),
            warnings: Vec::new(),
            can_remember: false,
        };
        self.approve(request, None, AuditEvent::new("keyring_items", peer))?;
        let locks = self.state().locks;
        let items = crate::keyring::items(&self.config.keyring)
            .map_err(|e| Failure::new(ErrorCode::Internal, format!("{e:#}")))?;
        // What this program may now import from, and what its dialogs show —
        // unless the vault was locked meanwhile, which forgets approvals.
        let mut state = self.state();
        if state.locks != locks {
            return Err(Failure::new(
                ErrorCode::Locked,
                "the vault was locked while the keyring was being listed; list it again",
            ));
        }
        state.keyring_listing = Some(KeyringListing {
            requester: (peer.pid, crate::peer::start_time(peer.pid)),
            at: Instant::now(),
            items: items
                .iter()
                .map(|item| (item.id.clone(), item.clone()))
                .collect(),
        });
        drop(state);
        let response = Response::KeyringItems { items };
        let size = serde_json::to_vec(&response).map_or(usize::MAX, |b| b.len());
        if size > protocol::MAX_FRAME_LEN - 1024 {
            return Err(Failure::invalid(
                "the keyring holds too much to list in one answer",
            ));
        }
        Ok(response)
    }

    /// Show the names of the variables in a `.env` file to the requester,
    /// after approval; the values are dropped at once.
    fn dotenv_names(&self, peer: &Peer, path: &str) -> Result<Response, Failure> {
        check_dotenv_path(path)?;
        let request = ApprovalRequest {
            title: "Rusthorse — read a .env file".into(),
            summary: "Show the names in a .env file to the program that asked?".into(),
            explanation: "It will see the names of the variables in the file below — not \
                          their values — to choose what to import into Rusthorse."
                .into(),
            command: None,
            details: vec![
                ("File".into(), path.to_string()),
                ("Requested by (unverified)".into(), peer.describe()),
            ],
            facts: Vec::new(),
            warnings: Vec::new(),
            can_remember: false,
        };
        self.approve(
            request,
            None,
            AuditEvent::new("dotenv_names", peer).detail(path),
        )?;
        let parsed = read_dotenv(path, None)?;
        Ok(Response::Names {
            names: parsed.pairs.into_iter().map(|(name, _)| name).collect(),
            empty: parsed.empty,
        })
    }

    /// Import secrets that the agent reads itself (ADR 0012): the requester
    /// names the items or variables and the entry names, never the values.
    /// Nothing read from the source reaches the requester before the human
    /// allows the import: not a value, not whether an item or a variable
    /// exists. The dialog shows, for keyring items, what the agent found at
    /// each one; the values are read after approval, from items that are
    /// still what the dialog showed.
    fn import_from(
        &self,
        peer: &Peer,
        source: ImportSource,
        tags: Vec<String>,
        replace: bool,
    ) -> Result<Response, Failure> {
        let entry = |name: String| NewEntry {
            name,
            fields: EntryFields {
                tags: tags.clone(),
                ..EntryFields::default()
            },
            ..NewEntry::default()
        };
        match source {
            ImportSource::Keyring { items } => {
                check_import_names(items.iter().map(|p| p.name.as_str()), items.len())?;
                // Only items of a listing this program was allowed to see:
                // then nothing the dialog shows — and nothing that depends on
                // it, such as its size — is news to the requester.
                let shown: Vec<crate::protocol::KeyringItem> = {
                    let state = self.state();
                    let listing = state.keyring_listing.as_ref().filter(|l| {
                        l.requester == (peer.pid, crate::peer::start_time(peer.pid))
                            && l.at.elapsed() < KEYRING_LISTING_LIFETIME
                    });
                    let Some(listing) = listing else {
                        return Err(Failure::invalid(
                            "list the keyring first (keyring_items): items can be imported only \
                             from a listing this program was shown, in the last 10 minutes and \
                             since the vault was last locked",
                        ));
                    };
                    items
                        .iter()
                        .map(|pick| listing.items.get(&pick.id).cloned())
                        .collect::<Option<_>>()
                        .ok_or_else(|| {
                            Failure::invalid(
                                "an item is not in the keyring listing this program was shown; \
                                 list the keyring again",
                            )
                        })?
                };
                let rows = items
                    .iter()
                    .zip(&shown)
                    .map(|(pick, item)| {
                        let mut source = crate::keyring::describe_item(item);
                        if item.locked {
                            source.push_str(" (locked: cannot be read)");
                        }
                        (pick.name.clone(), source)
                    })
                    .collect();
                let entries = items.into_iter().map(|pick| entry(pick.name)).collect();
                let settings = self.config.keyring.clone();
                self.import_entries(peer, entries, replace, Origin::Keyring(rows), move || {
                    // After approval: only items that are still what was shown.
                    crate::keyring::read(&settings, shown)
                        .map_err(|e| Failure::new(ErrorCode::Internal, format!("{e:#}")))
                })
            }
            ImportSource::Dotenv {
                path,
                prefix,
                names,
            } => {
                check_import_names(names.iter().map(String::as_str), names.len())?;
                check_dotenv_path(&path)?;
                let entries = names.iter().cloned().map(entry).collect();
                let file = path.clone();
                self.import_entries(peer, entries, replace, Origin::Dotenv(&path), move || {
                    // After approval: the file as it is now.
                    let parsed = read_dotenv(&file, prefix.as_deref())?;
                    let mut found = parsed.pairs;
                    let mut values = Vec::with_capacity(names.len());
                    for name in &names {
                        if parsed.empty.contains(name) {
                            return Err(Failure::invalid(format!(
                                "{name} has no value in {file}; nothing was imported"
                            )));
                        }
                        let mut matching = found.iter().filter(|(n, _)| n == name);
                        if matching.next().is_none() {
                            return Err(Failure::invalid(format!(
                                "{name} is not in {file}; nothing was imported"
                            )));
                        }
                        if matching.next().is_some() {
                            return Err(Failure::invalid(format!(
                                "{name} appears more than once in {file}; nothing was imported"
                            )));
                        }
                        let at = found
                            .iter()
                            .position(|(n, _)| n == name)
                            .unwrap_or_default();
                        values.push(found.swap_remove(at).1);
                    }
                    Ok(values)
                })
            }
        }
    }

    /// Ask the human to import `entries`, then — only if allowed — get their
    /// values from `values` and save them. Errors before the dialog say
    /// nothing about the source.
    fn import_entries(
        &self,
        peer: &Peer,
        entries: Vec<NewEntry>,
        replace: bool,
        origin: Origin<'_>,
        values: impl FnOnce() -> Result<Vec<SecretString>, Failure>,
    ) -> Result<Response, Failure> {
        check_import_names(entries.iter().map(|e| e.name.as_str()), entries.len())?;
        let generation = self.generation(peer)?;
        let (new, existing): (Vec<&str>, Vec<&str>) = self.with_vault(peer, |v| {
            let mut new = Vec::new();
            let mut existing = Vec::new();
            for entry in &entries {
                if v.contains(&entry.name) {
                    existing.push(entry.name.as_str());
                } else {
                    new.push(entry.name.as_str());
                }
            }
            Ok((new, existing))
        })?;
        let source = match &origin {
            Origin::Requester => crate::import::Source::Requester,
            Origin::Keyring(rows) => crate::import::Source::Keyring(rows),
            Origin::Dotenv(path) => crate::import::Source::Dotenv(path),
        };
        let request = crate::import::approval(&source, &new, &existing, replace, &peer.describe());
        let event = match &origin {
            Origin::Requester => AuditEvent::new("import", peer),
            Origin::Keyring(_) => AuditEvent::new("import_from", peer).detail("GNOME Keyring"),
            Origin::Dotenv(path) => AuditEvent::new("import_from", peer).detail(*path),
        };
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        self.approve(request, None, event.entries(names))?;
        let values = values()?;
        if values.len() != entries.len() {
            return Err(Failure::new(
                ErrorCode::Internal,
                "the source gave a different number of values; nothing was imported",
            ));
        }
        self.commit(generation, |v| {
            let (mut added, mut replaced, mut skipped) = (0, 0, 0);
            for (entry, value) in entries.iter().zip(&values) {
                match v.add(entry, value, replace) {
                    Ok(true) => replaced += 1,
                    Ok(false) => added += 1,
                    Err(VaultError::AlreadyExists(_)) => skipped += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(ok(format!(
                "imported {added}, replaced {replaced}, skipped {skipped}"
            )))
        })
    }

    fn edit(
        &self,
        peer: &Peer,
        name: &str,
        mut changes: EntryChanges,
    ) -> Result<Response, Failure> {
        if changes.is_empty() {
            return Err(Failure::invalid("nothing to change"));
        }
        let generation = self.generation(peer)?;
        let current = self.with_vault(peer, |v| {
            let current = v.info(v.find(name)?);
            // Checked before anyone is asked: an invalid path, or one into
            // the recycle bin, fails here. The dialog shows the destination
            // as it will be: normalized, from the top. A move to the group
            // the entry is in moves nothing, so the dialog does not offer it.
            if let Some(path) = &changes.group {
                let path = v.check_group(path)?;
                let here = current.group.as_deref().unwrap_or_default();
                changes.group = (path != here).then_some(path);
            }
            Ok(current)
        })?;
        if changes.is_empty() {
            return Err(Failure::invalid(
                "nothing to change: the entry is already in that group",
            ));
        }
        let event = AuditEvent::new("edit", peer).entries(vec![current.identity()]);

        let prompt_for_value = matches!(changes.value, Some(ValueChange::Prompt));
        if changes.touches_metadata()
            || matches!(
                changes.value,
                Some(ValueChange::Provided(_) | ValueChange::Generate(_))
            )
        {
            let mut details = vec![("Entry".into(), current.identity())];
            details.extend(describe_changes(&changes));
            details.push(("Requested by (unverified)".into(), peer.describe()));
            let request = ApprovalRequest {
                title: "Rusthorse — change an entry".into(),
                summary: "Change an entry?".into(),
                explanation: "The previous version is kept in the entry's history.".into(),
                command: None,
                details,
                facts: Vec::new(),
                warnings: Vec::new(),
                can_remember: false,
            };
            self.approve(request, None, event.clone())?;
        }
        let new_value = match changes.value.take() {
            Some(ValueChange::Provided(v)) => Some(v),
            Some(ValueChange::Generate(spec)) => {
                Some(crate::generate::generate(spec).map_err(|e| Failure::invalid(e.to_string()))?)
            }
            Some(ValueChange::Prompt) if prompt_for_value => {
                let prompt = Prompt {
                    title: "Rusthorse — new value".into(),
                    headline: "Type the new value of an entry.".into(),
                    explanation: String::new(),
                    notice: None,
                    details: vec![
                        ("Entry".into(), current.identity()),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    field: "New value".into(),
                    confirm: "Save".into(),
                };
                Some(self.ask_value(peer, prompt, event)?)
            }
            _ => None,
        };
        self.commit(generation, |v| {
            let id = v.find(&current.id)?;
            v.edit(id, &changes, new_value.as_ref())?;
            Ok(ok(format!(
                "{} updated",
                changes.rename.as_deref().unwrap_or(name)
            )))
        })
    }

    fn remove(&self, peer: &Peer, name: &str) -> Result<Response, Failure> {
        let generation = self.generation(peer)?;
        let info = self.with_vault(peer, |v| Ok(v.info(v.find(name)?)))?;
        let request = ApprovalRequest {
            title: "Rusthorse — delete an entry".into(),
            summary: "Delete an entry?".into(),
            explanation: "The entry and its history are removed from the vault.".into(),
            command: None,
            details: vec![
                ("Entry".into(), info.identity()),
                ("Group".into(), info.group.clone().unwrap_or_else(|| "(root)".into())),
                ("Requested by (unverified)".into(), peer.describe()),
            ],
            facts: Vec::new(),
            warnings: vec!["This cannot be undone (the previous file is kept as vault.kdbx.bak until the next save).".into()],
            can_remember: false,
        };
        self.approve(
            request,
            None,
            AuditEvent::new("remove", peer).entries(vec![info.identity()]),
        )?;
        self.commit(generation, |v| {
            let id = v.find(&info.id)?;
            v.remove(id);
            Ok(ok(format!("{} deleted", info.name)))
        })
    }

    /// Change the master password: the human proves they know the current
    /// one and types the new one twice, all in the agent's own dialogs.
    fn change_password(&self, peer: &Peer) -> Result<Response, Failure> {
        let generation = self.generation(peer)?;
        let event = AuditEvent::new("passwd", peer);
        let ask = |headline: &str,
                   explanation: &str,
                   field: &str|
         -> Result<SecretString, Failure> {
            let prompt = Prompt {
                title: "Rusthorse — change the master password".into(),
                headline: headline.into(),
                explanation: explanation.into(),
                notice: None,
                details: vec![("Requested by (unverified)".into(), peer.describe())],
                field: field.into(),
                confirm: "Next".into(),
            };
            let answer = {
                let _dialog = self.dialog()?;
                self.ui.master_password(&prompt)?
            };
            // Any dialog of the three that is not answered ends the change,
            // and is recorded as such.
            let (outcome, failure) = match answer {
                Typed::Value(value) => return Ok(value),
                Typed::Cancelled => ("cancelled", Failure::new(ErrorCode::Cancelled, "cancelled")),
                Typed::TimedOut => (
                    "timed_out",
                    Failure::new(ErrorCode::Cancelled, "nobody answered the dialog in time"),
                ),
            };
            self.record(event.clone().outcome(outcome))?;
            Err(failure)
        };
        let current = ask(
            "Type the CURRENT master password.",
            "",
            "Current master password",
        )?;
        let matches = self.with_vault_at(generation, |v| Ok(v.password_matches(&current)))?;
        if !matches {
            self.record(event.outcome("wrong_password"))?;
            return Err(Failure::new(
                ErrorCode::UnlockFailed,
                "wrong master password",
            ));
        }
        let first = ask(
            "Type the NEW master password.",
            "At least 8 characters; 12 or more, or a passphrase, is recommended.",
            "New master password",
        )?;
        let second = ask(
            "Type the new master password again.",
            "",
            "New master password, again",
        )?;
        if *first != *second {
            self.record(event.outcome("mismatch"))?;
            return Err(Failure::invalid(
                "the new passwords do not match; nothing changed",
            ));
        }
        if first.chars().count() < 8 {
            self.record(event.outcome("too_short"))?;
            return Err(Failure::invalid(
                "the new master password must have at least 8 characters",
            ));
        }
        self.record(event.outcome("changed"))?;
        let ((), cleanup) = self.commit_reporting(generation, |v| {
            v.change_password(first);
            Ok(())
        })?;
        Ok(ok(match cleanup {
            None => "master password changed; the previous file (encrypted with the old \
                     password) was deleted"
                .to_string(),
            Some(problem) => format!(
                "master password changed, BUT the previous file could not be deleted: {problem}. \
                 It still opens with the old password — delete it yourself"
            ),
        }))
    }

    /// Create the vault file at the configured path, asking the human for
    /// its master password, twice, in the agent's own dialogs: the password
    /// never passes through a client. The new vault is left unlocked —
    /// unless the vault was locked while the dialogs were open (a screen
    /// lock, a suspend, `rusthorse lock`).
    fn create_vault(&self, peer: &Peer) -> Result<Response, Failure> {
        let path = self.config.vault.clone();
        let exists = || {
            Failure::new(
                ErrorCode::AlreadyExists,
                format!("a vault already exists at {}", path.display()),
            )
        };
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(exists());
        }
        // One dialog at a time: of two requests, the second waits here and
        // then finds the vault the first created.
        let _dialog = self.dialog()?;
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(exists());
        }
        let started = {
            let state = self.state();
            // An open vault whose file is gone (moved or deleted): creating
            // one would leave the old one open beside it.
            if state.vault.is_some() {
                return Err(Failure::invalid(format!(
                    "a vault is unlocked, but its file is no longer at {} (moved or deleted?); \
                     lock it (`rusthorse lock`) before creating a new one",
                    path.display()
                )));
            }
            state.generation
        };
        let event = AuditEvent::new("create_vault", peer);
        let shown = path.display().to_string();
        let prompt = |headline: &str, explanation: &str, field: &str, confirm: &str| Prompt {
            title: "Rusthorse — create a vault".into(),
            headline: headline.into(),
            explanation: explanation.into(),
            notice: None,
            details: vec![
                ("Vault file".into(), shown.clone()),
                ("Requested by (unverified)".into(), peer.describe()),
            ],
            field: field.into(),
            confirm: confirm.into(),
        };
        let first_prompt = prompt(
            "Choose the master password of your new vault.",
            "It encrypts every secret in the vault, and it cannot be recovered: if you \
             forget it, the secrets are lost. Write it down somewhere safe. At least 8 \
             characters; a passphrase of five or more random words is recommended.",
            "New master password",
            "Next",
        );
        let text = crate::ui::prompt_text(&first_prompt);
        if text.chars().count() > MAX_DIALOG_CHARS
            || (self.ui.limits_height()
                && crate::ui::prompt_height(&text) > crate::ui::metrics::MAX_HEIGHT)
        {
            return Err(Failure::invalid(
                "the dialog would be too long to show (vault path or requester chain)",
            ));
        }
        let ask = |prompt: Prompt| -> Result<SecretString, Failure> {
            let (outcome, failure) = match self.ui.master_password(&prompt)? {
                Typed::Value(value) => return Ok(value),
                Typed::Cancelled => (
                    "cancelled",
                    Failure::new(ErrorCode::Cancelled, "cancelled; no vault was created"),
                ),
                Typed::TimedOut => (
                    "timed_out",
                    Failure::new(
                        ErrorCode::Cancelled,
                        "nobody answered the dialog in time; no vault was created",
                    ),
                ),
            };
            self.record(event.clone().outcome(outcome))?;
            Err(failure)
        };
        let first = ask(first_prompt)?;
        let second = ask(prompt(
            "Type the new master password again.",
            "",
            "New master password, again",
            "Create vault",
        ))?;
        if *first != *second {
            self.record(event.outcome("mismatch"))?;
            return Err(Failure::invalid(
                "the passwords do not match; no vault was created",
            ));
        }
        if first.chars().count() < 8 {
            self.record(event.outcome("too_short"))?;
            return Err(Failure::invalid(
                "the master password must have at least 8 characters; no vault was created",
            ));
        }
        // Record first: if the audit log cannot be written, nothing is created.
        self.record(event.clone().outcome("created"))?;
        let vault = match Vault::create(&path, first, self.config.new_vault_kdf) {
            Ok(vault) => vault,
            Err(e) => {
                let failure = match e {
                    VaultError::Exists(_) => exists(),
                    other => Failure::from(other),
                };
                let _ = self.audit.record(&event.outcome("failed"));
                return Err(failure);
            }
        };
        let mut state = self.state();
        // No vault can have been opened meanwhile: unlocking waits for the
        // dialog lock, which this request holds.
        if state.generation != started {
            // Locked while the password was typed: the vault exists, locked.
            drop(state);
            drop(vault);
            return Ok(ok(format!(
                "vault created at {}; it was locked meanwhile — unlock it to use it",
                path.display()
            )));
        }
        state.vault = Some(vault);
        state.last_used = Instant::now();
        state.generation += 1;
        Ok(ok(format!("vault created at {}", path.display())))
    }

    fn reveal(
        &self,
        peer: &Peer,
        name: &str,
        notes: bool,
        purpose: Option<RevealPurpose>,
    ) -> Result<Response, Failure> {
        let what = if notes { "notes" } else { "value" };
        let read = |v: &Vault, id| if notes { v.notes(id) } else { v.secret(id) };
        let generation = self.generation(peer)?;
        let info = self.with_vault(peer, |v| {
            let id = v.find(name)?;
            if read(v, id).is_none() {
                return Err(Failure::new(
                    ErrorCode::NotFound,
                    format!("{name} has no {what}"),
                ));
            }
            Ok(v.info(id))
        })?;
        // The purpose is the requester's own statement: the dialog says so,
        // and the warnings hold whatever the requester really does.
        let (title, summary, stated, warning, audited) = match purpose {
            None => (
                "Rusthorse — reveal a secret",
                format!("Reveal the {what} of an entry?"),
                None,
                format!(
                    "The {what} will be printed by the requesting process. If an AI agent asked, it will see it and it may end up in its logs."
                ),
                what.to_string(),
            ),
            Some(RevealPurpose::Show) => (
                "Rusthorse — show a secret",
                format!("Show the {what} of an entry on screen?"),
                Some(format!(
                    "show the {what} in its own window for a short time; you can copy it from there"
                )),
                format!(
                    "Anyone who can see your screen, and other programs of your desktop session, can see the {what} while it is shown. If you copy it, it stays on the clipboard until something else is copied, and a clipboard history may keep it even after that."
                ),
                format!("{what}, to show"),
            ),
            Some(RevealPurpose::Copy) => (
                "Rusthorse — copy a secret",
                format!("Copy the {what} of an entry to the clipboard?"),
                Some(format!("put the {what} on the clipboard")),
                format!(
                    "The {what} stays on the clipboard until something else is copied, and a clipboard history may keep it even after that; other programs of your desktop session can read it. Paste it only where it belongs — never into a chat with an AI."
                ),
                format!("{what}, to copy to the clipboard"),
            ),
        };
        let mut details = vec![
            ("Entry".into(), info.identity()),
            ("Reveals".into(), what.into()),
        ];
        if let Some(stated) = &stated {
            details.push(("Stated purpose (unverified)".into(), stated.clone()));
        }
        details.push(("Requested by (unverified)".into(), peer.describe()));
        let request = ApprovalRequest {
            title: title.into(),
            summary,
            explanation: format!(
                "The program that asked receives the {what} in clear text and can do anything \
                 with it{}.",
                if purpose.is_some() {
                    ", whatever it says it will do"
                } else {
                    ""
                }
            ),
            command: None,
            details,
            facts: Vec::new(),
            warnings: vec![warning],
            can_remember: false,
        };
        let event = AuditEvent::new("reveal", peer)
            .entries(vec![info.identity()])
            .detail(audited);
        self.approve(request, None, event)?;
        self.with_vault_at(generation, |v| {
            let id = v.find(&info.id)?;
            let value = read(v, id).ok_or_else(|| {
                Failure::new(ErrorCode::NotFound, format!("{name} has no {what}"))
            })?;
            Ok(Response::Secret { value })
        })
    }

    /// Copy the encrypted vault file to `path` and verify that the copy
    /// opens. The copy is as protected as the vault itself, so no approval
    /// is asked; the action is audited.
    fn backup(&self, peer: &Peer, path: &str) -> Result<Response, Failure> {
        let dest = PathBuf::from(path);
        if !dest.is_absolute() {
            return Err(Failure::invalid("the backup path must be absolute"));
        }
        let count = self.with_vault(peer, |v| Ok(v.backup_to(&dest)?))?;
        self.record(
            AuditEvent::new("backup", peer)
                .outcome("written")
                .detail(format!("{} ({count} entries)", dest.display())),
        )?;
        Ok(ok(format!(
            "backup written to {} and verified: it opens with the current master password and holds {count} entries",
            dest.display()
        )))
    }

    fn run(
        &self,
        stream: &UnixStream,
        peer: &Peer,
        run: RunRequest,
        fds: Vec<OwnedFd>,
    ) -> Result<Response, Failure> {
        // With redaction the agent never touches the client's own descriptors:
        // output and input travel over this connection as data frames, and the
        // client writes its stdout and reads its stdin itself. Without
        // redaction, the client hands its three descriptors to the command.
        let client_fds: Option<[OwnedFd; 3]> = if run.redact {
            if !fds.is_empty() {
                return Err(Failure::invalid(
                    "with redaction, run requests carry no file descriptors",
                ));
            }
            None
        } else {
            Some(fds.try_into().map_err(|_| {
                Failure::invalid(
                    "run without redaction needs exactly three file descriptors (stdin, stdout, stderr)",
                )
            })?)
        };
        if run.argv.is_empty() {
            return Err(Failure::invalid("empty command"));
        }
        if run.bindings.is_empty() {
            return Err(Failure::invalid("no secrets requested"));
        }
        let mut seen = Vec::new();
        for binding in &run.bindings {
            if !util::is_valid_env_name(&binding.var) {
                return Err(Failure::invalid(format!(
                    "{:?} is not a valid environment variable name; use VAR=ENTRY",
                    binding.var
                )));
            }
            if seen.contains(&binding.var) {
                return Err(Failure::invalid(format!("{} is bound twice", binding.var)));
            }
            seen.push(binding.var.clone());
        }
        let cwd = PathBuf::from(&run.cwd);
        if !cwd.is_absolute() || !cwd.is_dir() {
            return Err(Failure::invalid(format!(
                "{}: not an absolute directory",
                run.cwd
            )));
        }
        let path_var = run
            .env
            .iter()
            .rev()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str());
        let program =
            exec::resolve_program(&run.argv[0], path_var, &cwd).map_err(Failure::invalid)?;
        let program_id = file_id(&program.canonical)
            .map_err(|e| Failure::invalid(format!("{}: {e}", program.canonical.display())))?;
        let cwd_id = file_id(&cwd).map_err(|e| Failure::invalid(format!("{}: {e}", run.cwd)))?;
        let secret_vars: Vec<&str> = run.bindings.iter().map(|b| b.var.as_str()).collect();
        let prepared = exec::prepare_env(&run.env, &secret_vars);
        // The environment the command will actually get (a later duplicate
        // wins, as with `Command::envs`), in a canonical order.
        let effective_env: BTreeMap<&str, &str> = prepared
            .vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // The human must be able to read everything that decides what runs.
        let command_line = shell_join(&run.argv);
        let program_text = program.describe();
        for (what, text) in [
            ("command line", &command_line),
            ("program path", &program_text),
            ("working directory", &run.cwd),
        ] {
            let length = text.chars().count();
            if length > MAX_DETAIL_CHARS {
                return Err(Failure::invalid(format!(
                    "the {what} is too long to show in an approval dialog ({length} characters, \
                     limit {MAX_DETAIL_CHARS}); put the command in a script and run that"
                )));
            }
        }

        // Every entry must exist (and have a value) before the human is asked.
        let generation = self.generation(peer)?;
        let entries: Vec<(String, String, String)> = self.with_vault_at(generation, |v| {
            run.bindings
                .iter()
                .map(|b| {
                    let id = v.find(&b.entry)?;
                    if v.secret(id).is_none() {
                        return Err(Failure::new(
                            ErrorCode::NotFound,
                            format!("{} has no value", b.entry),
                        ));
                    }
                    let info = v.info(id);
                    Ok((info.id.clone(), info.identity(), info.name))
                })
                .collect()
        })?;
        let identities: Vec<String> = entries
            .iter()
            .map(|(_, identity, _)| identity.clone())
            .collect();

        let mut warnings = Vec::new();
        if !prepared.removed.is_empty() {
            warnings.push(format!(
                "Removed from the environment: {}",
                prepared.removed.join(", ")
            ));
        }
        if !prepared.risky.is_empty() {
            warnings.push(format!(
                "These variables can change what the program executes: {}",
                prepared
                    .risky
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let pairs = |vars: &[(String, String)]| {
            vars.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let endpoints = pairs(&prepared.endpoints);
        let routes = pairs(&prepared.routes);
        if !routes.is_empty() {
            warnings.push(format!(
                "These variables route the program's connections or change which servers it \
                 trusts; with them a requester can send your secrets elsewhere: {routes}"
            ));
        }
        if !prepared.unusual.is_empty() {
            warnings.push(format!(
                "These destination settings hold values that are not plain URLs, host names or \
                 paths; programs may read them differently, so they are not shown: {}. Deny \
                 unless you know why they are set.",
                prepared.unusual.join(", ")
            ));
        }
        if !run.redact {
            warnings.push(
                "Output is NOT redacted: secret values printed by the command reach the requester."
                    .into(),
            );
        }
        let input = match (run.redact, run.forward_stdin) {
            (false, _) => "the requester's own standard input",
            (true, true) => "forwarded from the requester",
            (true, false) => "none (/dev/null)",
        };
        let request = ApprovalRequest {
            title: "Rusthorse — use a secret".into(),
            summary: "Run a command with your secrets?".into(),
            explanation: "Rusthorse runs it as you, outside any sandbox, with the secrets in its \
                          environment; programs it starts can use them too. Read the command \
                          before you allow it."
                .into(),
            command: Some(command_line),
            details: vec![
                (
                    "Secrets".into(),
                    run.bindings
                        .iter()
                        .zip(&identities)
                        .map(|(b, identity)| format!("{} ← {identity}", b.var))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                ("Program".into(), program_text),
                ("Directory".into(), run.cwd.clone()),
                ("Requested by (unverified)".into(), peer.describe()),
            ]
            .into_iter()
            // The destinations its environment sets (threat model L4).
            .chain(
                (!endpoints.is_empty())
                    .then(|| ("Destinations (environment)".to_string(), endpoints.clone())),
            )
            .collect(),
            facts: vec![
                ("Input".into(), input.into()),
                (
                    "Output".into(),
                    if run.redact {
                        "secret values are redacted".into()
                    } else {
                        "not redacted".into()
                    },
                ),
            ],
            warnings,
            can_remember: true,
        };
        // A remembered approval covers exactly this: the same entries (by
        // UUID) in the same vault generation, command line, program, working
        // directory, input and output handling, and effective environment.
        let entry_ids: Vec<&str> = entries.iter().map(|(id, _, _)| id.as_str()).collect();
        let key = serde_json::to_string(&(
            generation,
            &run.bindings,
            &entry_ids,
            &run.argv,
            program.canonical.display().to_string(),
            &run.cwd,
            run.redact,
            run.forward_stdin,
            &effective_env,
        ))
        .map_err(|e| Failure::new(ErrorCode::Internal, e.to_string()))?;
        let mut event = run_event(peer, &run, &identities);
        let audited: Vec<String> = [("destinations", &endpoints), ("routes", &routes)]
            .into_iter()
            .filter(|(_, vars)| !vars.is_empty())
            .map(|(what, vars)| format!("{what}: {vars}"))
            .collect();
        if !audited.is_empty() {
            event = event.detail(audited.join("; "));
        }
        self.approve(request, Some(key), event)?;

        // The answer may have taken a while: make sure the program and the
        // directory were not replaced meanwhile...
        if file_id(&program.canonical).ok() != Some(program_id)
            || file_id(&cwd).ok() != Some(cwd_id)
        {
            let _ = self.audit.record(
                &run_event(peer, &run, &identities)
                    .outcome("aborted")
                    .detail("program or directory replaced after approval"),
            );
            return Err(Failure::invalid(
                "the program or the working directory was replaced after you approved; nothing was run",
            ));
        }
        // ...and read the values under the same lock that checks that the
        // vault did not change (no edit, lock or reload since the dialog).
        // From this point on the approval is consumed: a later `lock` does
        // not stop the command.
        let secrets: Vec<(String, String, SecretString)> = self.with_vault_at(generation, |v| {
            run.bindings
                .iter()
                .zip(&entries)
                .map(|(b, (id, _, name))| {
                    let found = v.find(id)?;
                    let value = v.secret(found).ok_or_else(|| {
                        Failure::new(ErrorCode::NotFound, format!("{name} has no value"))
                    })?;
                    Ok((b.var.clone(), name.clone(), value))
                })
                .collect()
        })?;

        let mut command = Command::new(&program.canonical);
        command
            .arg0(&run.argv[0])
            .args(&run.argv[1..])
            .current_dir(&cwd)
            .env_clear()
            .envs(effective_env.iter())
            .process_group(0);
        for (var, _, value) in &secrets {
            command.env(var, value.as_str());
        }
        // With redaction the command gets only pipes owned by the agent (and
        // /dev/null as input unless forwarding was requested).
        match client_fds {
            Some([stdin, stdout, stderr]) => {
                command
                    .stdin(Stdio::from(stdin))
                    .stdout(Stdio::from(stdout))
                    .stderr(Stdio::from(stderr));
            }
            None => {
                command
                    .stdin(if run.forward_stdin {
                        Stdio::piped()
                    } else {
                        Stdio::null()
                    })
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }
        // Everything that can fail is prepared before the command starts: once
        // it has started, the only answer is its exit status (or, if waiting
        // for it fails, "outcome unknown").
        let internal = |e: io::Error| Failure::new(ErrorCode::Internal, e.to_string());
        let writer = Arc::new(Mutex::new(stream.try_clone().map_err(internal)?));
        let watch_stream = stream.try_clone().map_err(internal)?;
        let mut child = command.spawn().map_err(|e| {
            Failure::new(
                ErrorCode::InvalidRequest,
                format!("cannot start {}: {e}", program.canonical.display()),
            )
        })?;
        drop(command);
        let pid = Pid::from_raw(child.id() as i32);
        // While the leader is not reaped its pid — and so the process group
        // id — cannot be reused, which makes signalling the group safe.
        //
        // `leader_done`: the command exited and the rest of its group was
        // terminated; output workers forward what is left, then stop.
        // `abort`: the client went away; every worker stops at once.
        let leader_done = Arc::new(AtomicBool::new(false));
        let abort = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));

        let mut pumps = Vec::new();
        let credits = Arc::new(Credits::new());
        // Frames to the client from the output workers and the
        // acknowledgement writer go through one lock (`writer`, cloned
        // above), so they never interleave.
        if run.redact {
            let labels: Vec<(String, Vec<u8>)> = secrets
                .iter()
                .map(|(_, entry, value)| (entry.clone(), value.as_bytes().to_vec()))
                .collect();
            let make = || Redactor::new(labels.iter().map(|(l, s)| (l.as_str(), s.as_slice())));
            for (channel, from) in [
                (protocol::STDOUT, child.stdout.take().map(OwnedFd::from)),
                (protocol::STDERR, child.stderr.take().map(OwnedFd::from)),
            ] {
                if let Some(from) = from {
                    let redactor = make();
                    let (writer, credits) = (Arc::clone(&writer), Arc::clone(&credits));
                    let (done, abort) = (Arc::clone(&leader_done), Arc::clone(&abort));
                    pumps.push(thread::spawn(move || {
                        pump(from, channel, writer, credits, redactor, done, abort)
                    }));
                }
            }
            for (_, mut bytes) in labels {
                zeroize::Zeroize::zeroize(&mut bytes);
            }
        }
        let child_stdin = child.stdin.take();
        drop(secrets);

        // With forwarding, the client may send input only once the command
        // has started: its whole stdin window is granted now, so input given
        // to a denied or failed request is never read.
        let forwarding = run.redact && run.forward_stdin;
        let acks = Arc::new(InputAcks::new(if forwarding {
            protocol::INITIAL_CREDIT
        } else {
            0
        }));
        // Stops the acknowledgement writer. It is a different flag from
        // `finished` so that the watcher keeps supervising the connection —
        // and can cancel, releasing a blocked acknowledgement — until the
        // writer has really stopped.
        let acks_done = Arc::new(AtomicBool::new(false));
        let ack_writer = forwarding.then(|| {
            let (acks, writer) = (Arc::clone(&acks), Arc::clone(&writer));
            let (acks_done, abort) = (Arc::clone(&acks_done), Arc::clone(&abort));
            thread::spawn(move || acks.run(&writer, &acks_done, &abort))
        });
        let watcher = Some(watch_stream).map(|s| {
            let watch = Watch {
                stream: s,
                acks: Arc::clone(&acks),
                pgid: pid,
                child_stdin,
                forward_stdin: run.redact && run.forward_stdin,
                credits: Arc::clone(&credits),
                abort: Arc::clone(&abort),
                finished: Arc::clone(&finished),
            };
            thread::spawn(move || watch.run())
        });

        // Wait for the leader to exit without reaping it.
        let waited = loop {
            match waitid(Id::Pid(pid), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT) {
                Err(Errno::EINTR) => continue,
                other => break other,
            }
        };
        // The command has ended: nothing it started may keep running with the
        // secrets.
        terminate_group(pid);
        leader_done.store(true, Ordering::SeqCst);
        // Output workers hold the secrets (in their redactors). They finish
        // when the remaining output has been sent, or at once if the client
        // disconnects (a write to a socket whose peer has gone fails
        // immediately); a client that stays connected without reading keeps
        // them waiting, exactly as a pipeline would (threat model L19).
        for pump in pumps {
            let _ = pump.join();
        }
        // Stop acknowledging input — the watcher still runs, so a client that
        // half-closes or breaks the protocol while an acknowledgement is
        // blocked still cancels (which releases it) — and only then stop
        // supervising.
        acks_done.store(true, Ordering::SeqCst);
        acks.wake();
        if let Some(ack_writer) = ack_writer {
            let _ = ack_writer.join();
        }
        finished.store(true, Ordering::SeqCst);
        if let Some(watcher) = watcher {
            let _ = watcher.join();
        }
        let unknown = |e: &dyn std::fmt::Display| {
            let _ = self.audit.record(
                &run_event(peer, &run, &identities)
                    .outcome("unknown")
                    .detail(e.to_string()),
            );
            Failure::new(
                ErrorCode::OutcomeUnknown,
                format!("the command started but its result could not be determined: {e}"),
            )
        };
        if let Err(e) = waited {
            terminate_group(pid);
            let _ = child.kill();
            let _ = child.wait();
            return Err(unknown(&e));
        }
        let status = child.wait().map_err(|e| unknown(&e))?;
        let detail = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit code {code}"),
            (None, Some(sig)) => format!("killed by signal {sig}"),
            _ => "unknown exit status".into(),
        };
        let _ = self.audit.record(
            &run_event(peer, &run, &identities)
                .outcome("exited")
                .detail(detail),
        );
        Ok(Response::Exited {
            code: status.code(),
            signal: status.signal(),
        })
    }
}

/// Device and inode of a file, to notice it being replaced.
fn file_id(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// Whether any live (non-zombie) process may be in process group `pgid`.
/// `/proc` is parsed as bytes (process names need not be UTF-8), and anything
/// that cannot be inspected counts as alive: a false "dead" would skip the
/// signals.
fn group_alive(pgid: Pid) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return true;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        if name.is_empty() || !name.as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let stat = match std::fs::read(entry.path().join("stat")) {
            Ok(stat) => stat,
            // The process ended while we were looking.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return true,
        };
        match parse_stat_group(&stat) {
            Some((state, pgrp)) if pgrp == pgid.as_raw() => {
                if state != b'Z' && state != b'X' {
                    return true;
                }
                // A thread-group leader that called pthread_exit() shows as a
                // zombie while its other threads keep running.
                if has_live_threads(&entry.path()) {
                    return true;
                }
            }
            Some(_) => {}
            None => return true,
        }
    }
    false
}

/// Whether any thread of the process at `/proc/<pid>` is not a zombie.
/// Uninspectable threads count as live.
fn has_live_threads(proc_dir: &Path) -> bool {
    let Ok(tasks) = std::fs::read_dir(proc_dir.join("task")) else {
        return false;
    };
    tasks
        .flatten()
        .any(|task| match std::fs::read(task.path().join("stat")) {
            Ok(stat) => !matches!(parse_stat_group(&stat), Some((b'Z' | b'X', _))),
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        })
}

/// The state letter and process group from a `/proc/<pid>/stat` line:
/// `pid (comm) state ppid pgrp ...`, where `comm` may contain any byte,
/// including spaces and parentheses.
fn parse_stat_group(stat: &[u8]) -> Option<(u8, i32)> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    let mut fields = rest.split_ascii_whitespace();
    let state = *fields.next()?.as_bytes().first()?;
    let _ppid = fields.next()?;
    let pgrp = fields.next()?.parse().ok()?;
    Some((state, pgrp))
}

/// Terminate every remaining process of the group: SIGTERM, then SIGKILL
/// after [`KILL_GRACE`]. Processes that moved to another session or group
/// (`setsid`) escape this (threat model L17).
fn terminate_group(pgid: Pid) {
    if !group_alive(pgid) {
        return;
    }
    let _ = killpg(pgid, Signal::SIGTERM);
    let deadline = Instant::now() + KILL_GRACE;
    while Instant::now() < deadline {
        if !group_alive(pgid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = killpg(pgid, Signal::SIGKILL);
}

fn ok(message: impl Into<String>) -> Response {
    Response::Ok {
        message: message.into(),
    }
}

fn run_event(peer: &Peer, run: &RunRequest, entries: &[String]) -> AuditEvent {
    let mut event = AuditEvent::new("run", peer).entries(entries.to_vec());
    event.argv = Some(run.argv.clone());
    event.cwd = Some(run.cwd.clone());
    event
}

/// All names, comma-separated. Imports are capped at [`MAX_IMPORT`] entries
/// so that the dialog can list every one of them.
/// Where the values of an import come from, for its dialog and record.
enum Origin<'a> {
    /// The requester sent them (`import`).
    Requester,
    /// The agent reads them from GNOME Keyring (`import_from`): each entry's
    /// name, and the item its value comes from as the agent found it.
    Keyring(Vec<(String, String)>),
    /// The agent reads them from this `.env` file (`import_from`).
    Dotenv(&'a str),
}

/// The checks of an import's names that need no source: a count within
/// [`MAX_IMPORT`], valid names, none twice.
fn check_import_names<'a>(
    names: impl Iterator<Item = &'a str>,
    count: usize,
) -> Result<(), Failure> {
    if count == 0 {
        return Err(Failure::invalid("nothing to import"));
    }
    if count > MAX_IMPORT {
        return Err(Failure::invalid(format!(
            "at most {MAX_IMPORT} entries can be imported at once (got {count}); split the import"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for name in names {
        crate::vault::validate_name(name)?;
        if !seen.insert(name) {
            return Err(Failure::invalid(format!(
                "{name} appears more than once in the import; nothing was imported"
            )));
        }
    }
    Ok(())
}

fn check_dotenv_path(path: &str) -> Result<(), Failure> {
    if !Path::new(path).is_absolute() {
        return Err(Failure::invalid(format!(
            "{path:?} is not an absolute path"
        )));
    }
    Ok(())
}

/// The variables of the `.env` file at `path`, with `prefix` (upper-cased)
/// before each name. Only a regular file of at most [`MAX_DOTENV_BYTES`]
/// is read: opening does not wait (a FIFO would block), and the type is
/// checked on the opened file.
fn read_dotenv(path: &str, prefix: Option<&str>) -> Result<crate::import::Dotenv, Failure> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let cannot = |e: std::io::Error| Failure::invalid(format!("cannot read {path}: {e}"));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(cannot)?;
    let meta = file.metadata().map_err(cannot)?;
    if !meta.is_file() {
        return Err(Failure::invalid(format!("{path} is not a regular file")));
    }
    if meta.len() > MAX_DOTENV_BYTES {
        return Err(Failure::invalid(format!(
            "{path} is larger than {} KiB; Rusthorse reads .env files up to that size",
            MAX_DOTENV_BYTES / 1024
        )));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(MAX_DOTENV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(cannot)?;
    if bytes.len() as u64 > MAX_DOTENV_BYTES {
        return Err(Failure::invalid(format!("{path} grew while it was read")));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::invalid(format!("{path} is not text (UTF-8)")))?;
    let prefix = prefix.unwrap_or_default().to_uppercase();
    let parsed = crate::import::parse_dotenv(text)
        .map_err(|e| Failure::invalid(format!("{path}, {e}; nothing was read from it")))?;
    Ok(crate::import::Dotenv {
        pairs: parsed
            .pairs
            .into_iter()
            .map(|(name, value)| (format!("{prefix}{name}"), value))
            .collect(),
        empty: parsed
            .empty
            .into_iter()
            .map(|name| format!("{prefix}{name}"))
            .collect(),
    })
}

fn describe_fields(entry: &NewEntry) -> String {
    let f = &entry.fields;
    let mut parts = Vec::new();
    if let Some(k) = f.kind {
        parts.push(format!("kind {}", k.label()));
    }
    if let Some(g) = &entry.group {
        parts.push(format!("group {g}"));
    }
    if let Some(u) = &f.username {
        parts.push(format!("user {u}"));
    }
    if let Some(u) = &f.url {
        parts.push(format!("url {u}"));
    }
    if let Some(h) = &f.host {
        parts.push(format!("host {h}"));
    }
    if let Some(p) = f.port {
        parts.push(format!("port {p}"));
    }
    if !f.tags.is_empty() {
        parts.push(format!("tags {}", f.tags.join(",")));
    }
    if parts.is_empty() {
        "(no metadata)".into()
    } else {
        util::visible(&parts.join(" · "))
    }
}

fn describe_changes(changes: &EntryChanges) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    // Always from the top, `/` alone for the top level: no group name
    // (which cannot contain `/`) can pass for another destination.
    if let Some(group) = &changes.group {
        out.push(("Move to group".into(), format!("/{group}")));
    }
    let mut set = |label: &str, value: &Option<String>| {
        if let Some(v) = value {
            out.push((format!("New {label}"), v.clone()));
        }
    };
    set("name", &changes.rename);
    set("username", &changes.username);
    set("url", &changes.url);
    set("host", &changes.host);
    if let Some(port) = changes.port {
        out.push(("New port".into(), port.to_string()));
    }
    if let Some(kind) = changes.kind {
        out.push(("New kind".into(), kind.label().into()));
    }
    if changes.notes.is_some() {
        out.push(("Notes".into(), "replaced".into()));
    }
    if !changes.clear.is_empty() {
        out.push((
            "Clear".into(),
            changes
                .clear
                .iter()
                .map(|f| format!("{f:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if !changes.add_tags.is_empty() {
        out.push(("Add tags".into(), changes.add_tags.join(", ")));
    }
    if !changes.remove_tags.is_empty() {
        out.push(("Remove tags".into(), changes.remove_tags.join(", ")));
    }
    match &changes.value {
        Some(ValueChange::Provided(_)) => out.push((
            "Value".into(),
            "replaced by a value from the requesting process".into(),
        )),
        Some(ValueChange::Prompt) => {
            out.push(("Value".into(), "you will type the new value next".into()))
        }
        Some(ValueChange::Generate(spec)) => out.push(("Value".into(), describe_spec(*spec))),
        None => {}
    }
    out
}

fn describe_spec(spec: crate::generate::Spec) -> String {
    format!(
        "a new random value: {} {} characters (about {:.0} bits); nobody will see it",
        spec.length,
        match spec.alphabet {
            crate::generate::Alphabet::Alnum => "letters and digits",
            crate::generate::Alphabet::Symbols => "letters, digits and symbols",
            crate::generate::Alphabet::Hex => "hexadecimal",
        },
        spec.entropy_bits()
    )
}

/// Per-channel flow control for output frames. The agent may send at most
/// the credit the client has granted for a channel; the client grants more
/// as it writes the data out. Each channel has its own window, so a client
/// whose stdout is stuck still receives stderr.
struct Credits {
    available: Mutex<[usize; 3]>,
    changed: Condvar,
}

impl Credits {
    fn new() -> Self {
        let mut available = [0; 3];
        available[protocol::STDOUT as usize] = protocol::INITIAL_CREDIT;
        available[protocol::STDERR as usize] = protocol::INITIAL_CREDIT;
        Self {
            available: Mutex::new(available),
            changed: Condvar::new(),
        }
    }

    fn grant(&self, channel: u8, amount: usize) {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = available.get_mut(channel as usize) {
            // A client cannot grant itself more than one window ahead.
            *slot = slot.saturating_add(amount).min(protocol::INITIAL_CREDIT);
        }
        self.changed.notify_all();
    }

    /// Wait until `amount` bytes may be sent on `channel` and take them;
    /// `false` if the request was aborted meanwhile.
    fn take(&self, channel: u8, amount: usize, abort: &AtomicBool) -> bool {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if abort.load(Ordering::SeqCst) {
                return false;
            }
            if available[channel as usize] >= amount {
                available[channel as usize] -= amount;
                return true;
            }
            available = self
                .changed
                .wait_timeout(available, Duration::from_millis(100))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    fn wake(&self) {
        self.changed.notify_all();
    }
}

/// Send a command's output to the client as data frames, redacting secrets.
/// Ends at end-of-file; once the command is done, also when the pipe stays
/// quiet for 500 ms (only a descendant that escaped the process group can
/// still hold it open); and at once when the request is aborted.
fn pump(
    from: OwnedFd,
    channel: u8,
    writer: Arc<Mutex<UnixStream>>,
    credits: Arc<Credits>,
    mut redactor: Redactor,
    leader_done: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
) {
    let send = |data: &[u8]| -> io::Result<()> {
        for chunk in data.chunks(protocol::MAX_DATA_LEN) {
            if !credits.take(channel, chunk.len(), &abort) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let stream = writer.lock().unwrap_or_else(|p| p.into_inner());
            protocol::send_data(&stream, channel, chunk)?;
        }
        Ok(())
    };
    let mut from = File::from(from);
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 16 * 1024]);
    let mut quiet_since: Option<Instant> = None;
    loop {
        if abort.load(Ordering::SeqCst) {
            return;
        }
        let mut fds = [PollFd::new(from.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(100u16)) {
            Ok(0) | Err(Errno::EINTR) => {
                if leader_done.load(Ordering::SeqCst) {
                    let since = *quiet_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= Duration::from_millis(500) {
                        break;
                    }
                }
                continue;
            }
            Ok(_) => {}
            Err(_) => break,
        }
        quiet_since = None;
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let out = redactor.push(&buf[..n]);
                if !out.is_empty() && send(&out).is_err() {
                    // Aborted, or the client went away. Dropping `from` gives
                    // the command SIGPIPE on its next write.
                    abort.store(true, Ordering::SeqCst);
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let rest = redactor.finish();
    if !rest.is_empty() {
        let _ = send(&rest);
    }
}

/// `poll(2)` on raw descriptors. `nix`'s `PollFd::revents()` returns `None`
/// when the kernel reports a bit `nix` does not name (`POLLRDHUP`, needed to
/// notice a half-closed connection), so the agent reads the events itself.
#[allow(unsafe_code)]
fn poll_raw(fds: &mut [nix::libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    loop {
        // SAFETY: `fds` is a valid, exclusively borrowed slice of pollfd.
        let n = unsafe { nix::libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout_ms) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Stdin credit to send back to the client, written by its own thread so
/// that the watcher never writes to the socket (a client that does not read
/// would block that write, and the watcher must keep watching).
struct InputAcks {
    owed: Mutex<usize>,
    changed: Condvar,
}

impl InputAcks {
    fn new(initial: usize) -> Self {
        Self {
            owed: Mutex::new(initial),
            changed: Condvar::new(),
        }
    }

    fn add(&self, amount: usize) {
        let mut owed = self.owed.lock().unwrap_or_else(|p| p.into_inner());
        *owed = owed.saturating_add(amount);
        self.changed.notify_all();
    }

    fn wake(&self) {
        self.changed.notify_all();
    }

    /// Send owed credit, aggregated, until the request ends or is aborted.
    /// A send blocked by a client that does not read is released when the
    /// watcher cancels the request (it shuts the socket down).
    fn run(&self, writer: &Mutex<UnixStream>, stop: &AtomicBool, abort: &AtomicBool) {
        loop {
            let amount = {
                let mut owed = self.owed.lock().unwrap_or_else(|p| p.into_inner());
                while *owed == 0 {
                    if stop.load(Ordering::SeqCst) || abort.load(Ordering::SeqCst) {
                        return;
                    }
                    owed = self
                        .changed
                        .wait_timeout(owed, Duration::from_millis(100))
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                let amount = (*owed).min(u32::MAX as usize);
                *owed -= amount;
                amount
            };
            if abort.load(Ordering::SeqCst) {
                return;
            }
            let stream = writer.lock().unwrap_or_else(|p| p.into_inner());
            if protocol::send_credit(&stream, protocol::STDIN, amount as u32).is_err() {
                return;
            }
        }
    }
}

/// The connection's side of a running command: forwards input frames to the
/// command's stdin, applies credit frames, and cancels the request when the
/// client goes away or breaks the protocol.
///
/// It reads the socket continuously — input waiting for the command is held
/// in a buffer bounded by the stdin credit window — so control frames are
/// never stuck behind input (which could deadlock with output credit).
struct Watch {
    stream: UnixStream,
    acks: Arc<InputAcks>,
    pgid: Pid,
    child_stdin: Option<std::process::ChildStdin>,
    forward_stdin: bool,
    credits: Arc<Credits>,
    abort: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl Watch {
    /// Cancel the request: stop every worker, shut the socket down (which
    /// fails any send in progress at once, without taking the send lock) and
    /// terminate the command's process group.
    fn cancel(&self) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.credits.wake();
        self.acks.wake();
        terminate_group(self.pgid);
    }

    fn run(mut self) {
        use nix::libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLRDHUP, pollfd};
        use std::os::fd::AsRawFd;

        // The command's stdin pipe belongs to the agent, so it can be made
        // non-blocking: a command that stops reading cannot block us.
        let mut stdin = self
            .child_stdin
            .take()
            .map(|s| File::from(OwnedFd::from(s)));
        if let Some(file) = &stdin
            && fcntl(file, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).is_err()
        {
            stdin = None;
        }
        // Input received but not yet taken by the command; never more than
        // one credit window.
        let mut pending: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(Vec::new());
        let mut end_of_input = false;
        // Input delivered (or discarded) but not yet acknowledged to the
        // client with a stdin credit frame.
        let mut owed: usize = 0;
        while !self.finished.load(Ordering::SeqCst) {
            let mut fds = vec![pollfd {
                fd: self.stream.as_raw_fd(),
                events: POLLIN | POLLRDHUP,
                revents: 0,
            }];
            if let (false, Some(file)) = (pending.is_empty(), &stdin) {
                fds.push(pollfd {
                    fd: file.as_raw_fd(),
                    events: POLLOUT,
                    revents: 0,
                });
            }
            match poll_raw(&mut fds, 200) {
                Ok(_) => {}
                Err(_) => return self.cancel(),
            }
            let socket = fds[0].revents;
            let input = fds.get(1).map_or(0, |f| f.revents);
            // Any kind of close — full or half — cancels the request.
            if socket & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL) != 0 {
                return self.cancel();
            }
            if socket & POLLIN != 0 {
                let deadline = Instant::now() + Duration::from_secs(10);
                match protocol::recv_any_before(&self.stream, Some(deadline)) {
                    Ok(protocol::Frame::Data(protocol::STDIN, data))
                        if self.forward_stdin && !end_of_input =>
                    {
                        if data.is_empty() {
                            end_of_input = true;
                        } else if pending.len() + data.len() > protocol::INITIAL_CREDIT {
                            // More input than the client was allowed to send.
                            return self.cancel();
                        } else if stdin.is_some() {
                            pending.extend_from_slice(&data);
                        } else {
                            // The command closed its input: discard, but
                            // keep the client's window open.
                            owed += data.len();
                        }
                    }
                    Ok(protocol::Frame::Data(
                        channel @ (protocol::CREDIT_STDOUT | protocol::CREDIT_STDERR),
                        data,
                    )) if data.len() == 4 => {
                        let amount = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                        let output = if channel == protocol::CREDIT_STDOUT {
                            protocol::STDOUT
                        } else {
                            protocol::STDERR
                        };
                        self.credits.grant(output, amount as usize);
                    }
                    // Anything else — a message, unrequested input, an
                    // unknown channel, an oversized or truncated frame — is a
                    // protocol violation.
                    _ => return self.cancel(),
                }
            }
            if input & POLLOUT != 0
                && let Some(file) = &mut stdin
            {
                match file.write(&pending) {
                    Ok(n) => {
                        pending.drain(..n);
                        owed += n;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        // The command closed its input.
                        stdin = None;
                        owed += pending.len();
                        pending.clear();
                    }
                }
            } else if input & (POLLERR | POLLHUP) != 0 {
                stdin = None;
                owed += pending.len();
                pending.clear();
            }
            if end_of_input && pending.is_empty() {
                stdin = None; // the command sees end-of-file
            }
            // Acknowledge delivered input through the acknowledgement writer:
            // this thread never writes to the socket, so a client that does
            // not read cannot stop it from watching the connection.
            if owed > 0 {
                self.acks.add(owed);
                owed = 0;
            }
        }
    }
}

/// Make this process harder to inspect: no core dumps, and not attachable or
/// readable through `/proc` by other processes of the same user.
pub fn harden_process() -> anyhow::Result<()> {
    nix::sys::prctl::set_dumpable(false).context("prctl(PR_SET_DUMPABLE)")?;
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)
        .context("setrlimit(RLIMIT_CORE)")?;
    Ok(())
}

/// The parent process name, to warn when the agent was not started by systemd.
pub fn parent_process_name() -> Option<String> {
    let chain = crate::peer::process_chain(std::process::id() as i32);
    chain.get(1).map(|p| p.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::NewEntry;
    use crate::vault::KdfParams;

    struct NoDialogs;

    impl Ui for NoDialogs {
        fn master_password(&self, _: &Prompt) -> anyhow::Result<Typed> {
            unreachable!("no dialog expected")
        }
        fn secret_value(&self, _: &Prompt) -> anyhow::Result<Typed> {
            unreachable!("no dialog expected")
        }
        fn approve(&self, _: &ApprovalRequest) -> anyhow::Result<Decision> {
            unreachable!("no dialog expected")
        }
    }

    #[test]
    fn a_save_that_fails_after_replacing_the_file_is_an_unknown_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        let password = || SecretString::new("correct horse".into());
        let mut vault =
            Vault::create(&path, password(), KdfParams::INSECURE_FOR_TESTS).expect("create");
        vault.fail_directory_sync();
        let agent = Agent::new(
            AgentConfig {
                vault: path.clone(),
                socket: dir.path().join("agent.sock"),
                audit_log: dir.path().join("audit.jsonl"),
                idle_timeout: Duration::ZERO,
                request_timeout: Duration::from_secs(10),
                send_buffer: None,
                session_lock: Default::default(),
                new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
                keyring: Default::default(),
            },
            Box::new(NoDialogs),
        );
        let generation = {
            let mut state = agent.state();
            state.vault = Some(vault);
            state.generation
        };
        let entry = NewEntry {
            name: "X".into(),
            ..NewEntry::default()
        };
        let failure = agent
            .commit(generation, |v| {
                v.add(&entry, &SecretString::new("abcd".into()), false)?;
                Ok(())
            })
            .expect_err("the save did not complete");
        assert_eq!(failure.code, ErrorCode::OutcomeUnknown);
        assert!(
            failure.message.contains("may not survive"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("discard"), "{}", failure.message);
        assert!(agent.state().vault.is_none(), "locked, to reload from disk");
        let on_disk = Vault::open(&path, password()).expect("reopen");
        assert!(on_disk.find("X").is_ok(), "the change is in the file");
    }

    #[test]
    fn a_session_lock_cancels_an_unlock_under_way_and_records_only_an_open_vault() {
        use crate::session_lock::{Locker, SCREEN_LOCK, SUSPEND};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        let vault = Vault::create(
            &path,
            SecretString::new("correct horse".into()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create");
        let audit = dir.path().join("audit.jsonl");
        let agent = Agent::new(
            AgentConfig {
                vault: path,
                socket: dir.path().join("agent.sock"),
                audit_log: audit.clone(),
                idle_timeout: Duration::ZERO,
                request_timeout: Duration::from_secs(10),
                send_buffer: None,
                session_lock: Default::default(),
                new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
                keyring: Default::default(),
            },
            Box::new(NoDialogs),
        );
        // Locked already, an unlock under way (its password being typed):
        // the generation changes, so the unlock does nothing when it
        // completes. Nothing was open, so nothing is recorded.
        let before = agent.state().generation;
        agent.lock_for(SCREEN_LOCK, "org.cinnamon.ScreenSaver");
        assert_eq!(agent.state().generation, before + 1);
        assert!(
            std::fs::read_to_string(&audit)
                .unwrap_or_default()
                .is_empty()
        );
        // Open: locked, and recorded with the event and the source.
        agent.state().vault = Some(vault);
        agent.lock_for(SUSPEND, "logind");
        assert!(agent.state().vault.is_none());
        let records = std::fs::read_to_string(&audit).expect("audit");
        assert!(records.contains(r#""outcome":"suspend""#), "{records}");
        assert!(records.contains(r#""detail":"logind""#), "{records}");
    }

    #[test]
    fn stat_lines_with_odd_process_names_parse() {
        assert_eq!(
            parse_stat_group(b"42 (sleep) S 1 42 42 0"),
            Some((b'S', 42))
        );
        assert_eq!(
            parse_stat_group(b"42 (\xff\xfe) S 1 77 77 0"),
            Some((b'S', 77))
        );
        assert_eq!(
            parse_stat_group(b"42 (a) b) (c) Z 1 9 9 0"),
            Some((b'Z', 9))
        );
        assert_eq!(parse_stat_group(b"garbage"), None);
    }
}
