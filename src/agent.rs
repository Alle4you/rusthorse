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
//! | broker_run_v2 | yes     | approval, never remembered                     |
//! | grants, revoke_grant | no | none                                         |
//!
//! Only one dialog is shown at a time. For `run`, the agent itself resolves
//! the program, cleans the environment, spawns the command as its own child
//! and filters its output, so what the human approves is what runs. A
//! `broker_run_v2` gives the command, for each entry it names, the token of
//! a grant served by a broker process instead of the entry's value, and the
//! broker sends the value only to the origin the run names and the human
//! approved (ADR 0013; the grants are kept in the registry of the crate's
//! `broker_host` module).

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

use crate::audit::{AuditEvent, AuditGrant, AuditLog};
use crate::broker_grant::{Destination, GrantLimits, is_valid_credential};
use crate::broker_host::{self, NewGrant, Registry, RunEnder, RunGrants, Which};
use crate::broker_protocol::{self, EndReason, Install, MAX_CONNECTIONS as BROKER_CONNECTIONS};
use crate::exec;
use crate::helper_program::{self, Located};
use crate::peer::Peer;
use crate::protocol::{
    self, BrokerBinding, EntryChanges, EntryFields, ErrorCode, ImportSource, ImportedEntry,
    NewEntry, Request, Response, RevealPurpose, RunRequest, SecretString, SettingsChange,
    SettingsInfo, StatusInfo, ValueChange,
};
use crate::redact::Redactor;
use crate::session_lock;
use crate::supervise::poll_raw;
use crate::ui::{ApprovalRequest, Connection, Decision, Prompt, Typed, Ui};
use crate::util::{self, shell_join};
use crate::vault::{ContentFingerprint, FingerprintKey, KdfParams, Vault, VaultError};

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
    /// The credential broker's program (ADR 0013). `None`, in production:
    /// `rusthorse-broker` next to the agent's own executable
    /// ([`helper_program::locate`]), with no fallback. `Some(path)`: that
    /// file, with the same checks ([`helper_program::check_file`]); tests
    /// point it at a stand-in.
    pub broker_program: Option<PathBuf>,
    /// How long a broker has to answer its install. `None` in production:
    /// [`broker_protocol::READY_TIMEOUT`]. Tests shorten it, to see a broker
    /// that never answers fail quickly.
    pub broker_ready_timeout: Option<Duration>,
    /// The longest a grant lasts. `None` in production: its run's maximum
    /// lifetime (`max_lifetime_minutes`), a minute at least. Tests
    /// shorten it, to see grants expire; it never lengthens one.
    pub broker_lifetime: Option<Duration>,
    /// The settings file, and what it and the flags hold (ADR 0007, section
    /// 3). `Some` in production: the settings in effect come from it — in
    /// place of `idle_timeout` and of `session_lock`'s `on_suspend` and
    /// `on_screen_lock`, and the [`Ui`] is told the rest — `status` reports
    /// them, and `configure` changes them. `None` (tests): `idle_timeout`
    /// and `session_lock` are used as given, `status` reports no settings,
    /// and `configure` is refused.
    pub settings: Option<crate::settings::Sources>,
}

/// A failed request: what goes back to the client as [`Response::Error`] —
/// unless its requester went away, which gets no answer.
#[derive(Debug)]
pub struct Failure {
    /// Machine-readable reason.
    pub code: ErrorCode,
    /// Human-readable explanation.
    pub message: String,
    /// The requester went away: its connection is shut down unanswered.
    unanswered: bool,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            unanswered: false,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    /// The requester went away, so the request stops here, unanswered (as a
    /// cancelled run is: its connection is shut down). Nothing is done.
    fn requester_gone(message: impl Into<String>) -> Self {
        Self {
            unanswered: true,
            ..Self::new(ErrorCode::Cancelled, message)
        }
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
    /// The fingerprint of the vault file's encrypted bytes as the agent last
    /// read or wrote them, kept across locks (ADR 0013, the unlock barrier):
    /// an unlock that reads other bytes ends every grant that survived the
    /// lock.
    content: Option<ContentFingerprint>,
    /// The settings in effect (ADR 0007, section 3).
    settings: crate::settings::Settings,
    /// Where they come from, when the agent has a settings file.
    sources: Option<crate::settings::Sources>,
}

impl State {
    /// Lock the vault. The grants that the event ends are the caller's to
    /// end ([`Registry::decide`], under this lock).
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

/// The failure of a request whose requester went away `before` its effect:
/// no answer is sent.
fn departed(before: &str) -> Failure {
    Failure::requester_gone(format!("the requester went away {before}"))
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
    audit: Arc<AuditLog>,
    /// What else locks the vault, for `status` (ADR 0009).
    lock_triggers: Arc<session_lock::Triggers>,
    /// The watchers behind them; dropping the agent stops them.
    session_watchers: Mutex<session_lock::Watchers>,
    /// The grants of the credential broker (ADR 0013): outside the vault's
    /// state, so that they can outlive a lock.
    registry: Arc<Registry>,
    /// The key of the vault file's fingerprints, chosen at start and kept
    /// in memory only (the unlock barrier).
    fingerprint_key: FingerprintKey,
    /// One `configure` at a time, from before its dialog to its end.
    configuring: Mutex<()>,
    /// The agent itself, for the watchers that `configure` starts.
    me: Weak<Agent>,
}

impl session_lock::Locker for Agent {
    /// Lock as `rusthorse lock` does. The generation changes even when the
    /// vault is already locked, so that an unlock whose password is being
    /// typed now does nothing when it completes. The grants whose run said
    /// that the automatic locks end them end too, and so does every
    /// grant still starting; the lock is done once their brokers have
    /// confirmed (or were killed).
    fn lock_for(&self, event: &str, source: &str) {
        let (reason, outcome) = if event == session_lock::SUSPEND {
            (EndReason::Suspend, "suspend")
        } else {
            (EndReason::ScreenLocked, "screen_locked")
        };
        let mut state = self.state();
        let was_open = state.vault.is_some() || !state.remembered.is_empty();
        state.lock();
        let ending = self.registry.decide(Which::AutomaticLock, reason);
        drop(state);
        ending.complete();
        if was_open {
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
    pub fn new(mut config: AgentConfig, ui: Box<dyn Ui>) -> Arc<Agent> {
        let audit = Arc::new(AuditLog::new(config.audit_log.clone()));
        let registry = Registry::new(Arc::clone(&audit) as Arc<dyn broker_host::Recorder>);
        let settings = match &config.settings {
            Some(sources) => {
                let settings = sources.effective();
                // The watchers start from `session_lock`; the idle timer
                // and `status` read the settings in the state.
                config.session_lock.on_suspend = settings.lock_on_suspend;
                config.session_lock.on_screen_lock = settings.lock_on_screen_lock;
                ui.set_timing(settings.remember, settings.dialog_timeout);
                settings
            }
            None => crate::settings::Settings {
                idle_timeout: config.idle_timeout,
                lock_on_suspend: config.session_lock.on_suspend,
                lock_on_screen_lock: config.session_lock.on_screen_lock,
                ..crate::settings::Settings::default()
            },
        };
        let sources = config.settings.clone();
        Arc::new_cyclic(|me| Agent {
            config,
            ui,
            state: Mutex::new(State {
                vault: None,
                last_used: Instant::now(),
                remembered: Vec::new(),
                generation: 0,
                keyring_listing: None,
                locks: 0,
                content: None,
                settings,
                sources,
            }),
            dialog: Mutex::new(()),
            waiting_for_dialog: AtomicUsize::new(0),
            connections: Arc::new(AtomicUsize::new(0)),
            audit,
            lock_triggers: Arc::default(),
            session_watchers: Mutex::default(),
            registry,
            fingerprint_key: FingerprintKey::random(),
            configuring: Mutex::new(()),
            me: me.clone(),
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

    /// Accept connections forever, one thread per connection. However this
    /// ends — an error, a panic — every grant of the credential broker ends
    /// with it (`agent_stopped`), and its broker is stopped.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) -> anyhow::Result<()> {
        let _grants = StopGrants(Arc::clone(&self.registry));
        self.start_idle_timer();
        // Without the timer that ends grants when their lifetime passes, the
        // registry serves no grant (fail closed); everything else still works.
        if let Err(e) = self.registry.start_timer() {
            eprintln!(
                "rusthorse agent: cannot start the timer of the credential broker's grants \
                 ({e}); runs through the broker are refused"
            );
        }
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

    /// Check every second whether the vault has been idle too long — also
    /// while the idle lock is off, since `configure` can turn it on.
    fn start_idle_timer(self: &Arc<Self>) {
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
        let idle = state.settings.idle_timeout;
        if !idle.is_zero() && state.vault.is_some() && state.last_used.elapsed() >= idle {
            state.lock();
            let ending = self
                .registry
                .decide(Which::AutomaticLock, EndReason::IdleTimeout);
            drop(state);
            ending.complete();
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

    /// The requester has gone — it closed its connection or, for a run,
    /// half-closed it — so the request stops before an effect: nothing is
    /// done, `record` is written as `aborted`, saying why (best effort:
    /// nothing acts after it, and it can be missing), and the request is
    /// left unanswered. `record` is called only now, so that a caller with
    /// something to undo first (a run's grants) does it there.
    ///
    /// The rule: the last check before an effect comes after every wait the
    /// agent makes on the way to it for a dialog's turn, for the lock of its
    /// state (which a save or a backup holds for a while), for an audit
    /// record, for brokers to end or to start, and for a read from outside
    /// (the keyring, a file). The registry of grants has a lock of its own,
    /// held only for short work in memory: a wait for it is not followed by
    /// a check. What remains unguarded is a departure during the effect. A
    /// record of what a request does that comes before it does it
    /// (`unlocked`, `changed`, `created`, a grant's `created`) is checked
    /// right before it and again right before the effect (for a grant, at
    /// the next check): a requester that leaves between the two leaves that
    /// record, then `aborted` (or, for a grant, `ended`). Between them the
    /// record is written, and then the agent may wait for its state's lock
    /// (an unlock, a password change) or for the registry's (a grant). Every
    /// such check ends here — through [`Agent::stop_if_gone`] or
    /// [`Agent::state_unless_gone`] for most — or, for a run whose grants
    /// were entered, through [`departed`] and the run's own record, written
    /// once its grants have ended.
    fn requester_left(&self, before: &str, record: impl FnOnce() -> AuditEvent) -> Failure {
        let failure = departed(before);
        let _ = self
            .audit
            .record(&record().outcome("aborted").detail(failure.message.clone()));
        failure
    }

    /// Stop before an effect that does not need the state lock if the
    /// requester has gone ([`Agent::requester_left`]).
    fn stop_if_gone(
        &self,
        peer: &Peer,
        before: &str,
        record: impl FnOnce() -> AuditEvent,
    ) -> Result<(), Failure> {
        if peer.gone() {
            return Err(self.requester_left(before, record));
        }
        Ok(())
    }

    /// The state lock, taken for an effect of `peer`'s request, which it
    /// then makes under it — unless the requester has gone, also while this
    /// waited for the lock (another request may hold it through a save or a
    /// backup): then the lock is let go and the request stops
    /// ([`Agent::requester_left`]).
    fn state_unless_gone(
        &self,
        peer: &Peer,
        before: &str,
        record: impl FnOnce() -> AuditEvent,
    ) -> Result<MutexGuard<'_, State>, Failure> {
        let state = self.state();
        if peer.gone() {
            drop(state);
            return Err(self.requester_left(before, record));
        }
        Ok(state)
    }

    /// The requester went away while its dialog was open, which was taken
    /// down, or before it was shown: `event` is recorded with that outcome
    /// (as a denial would be), and the request stops, unanswered — refused
    /// as well if that record cannot be written, but unanswered still.
    fn dialog_abandoned(&self, event: AuditEvent) -> Failure {
        let mut failure = match self.record(event.outcome("requester_gone")) {
            Ok(()) => Failure::requester_gone("the requester went away; nobody was asked"),
            Err(failure) => failure,
        };
        failure.unanswered = true;
        failure
    }

    /// Show an approval dialog for `peer` — not if it has gone, then
    /// [`Decision::RequesterGone`] (also for a request that waited for its
    /// turn). The caller holds the dialog lock.
    fn show_approval(&self, request: &ApprovalRequest, peer: &Peer) -> anyhow::Result<Decision> {
        if peer.gone() {
            return Ok(Decision::RequesterGone);
        }
        self.ui.approve(request, peer.connection())
    }

    /// [`Agent::show_approval`] for a master-password dialog.
    fn show_password(&self, prompt: &Prompt, peer: &Peer) -> anyhow::Result<Typed> {
        if peer.gone() {
            return Ok(Typed::RequesterGone);
        }
        self.ui.master_password(prompt, peer.connection())
    }

    /// [`Agent::show_approval`] for a dialog asking for a secret value.
    fn show_value(&self, prompt: &Prompt, peer: &Peer) -> anyhow::Result<Typed> {
        if peer.gone() {
            return Ok(Typed::RequesterGone);
        }
        self.ui.secret_value(prompt, peer.connection())
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
        // From here on the connection is watched for the requester leaving
        // — closing it, or half-closing a run's (which cancels a run) — while
        // a dialog is open or waited for, and before the request's effects.
        let half_close_ends = matches!(request, Request::Run(_) | Request::BrokerRunV2(_));
        let peer = peer.connected(Connection::new(stream.as_fd(), half_close_ends));

        let result = match request {
            // (A `run` that carries broker bindings does not parse: see
            // `Request::Run`. It is refused, never run without its grants.)
            Request::Run(run) => self.run(stream, &peer, run, None, fds),
            Request::BrokerRunV2(broker_run) => self.run(
                stream,
                &peer,
                broker_run.run,
                Some((broker_run.brokered, broker_run.limits)),
                fds,
            ),
            _ if !fds.is_empty() => Err(Failure::invalid(
                "only run requests may carry file descriptors",
            )),
            other => self.dispatch(&peer, other),
        };
        let response = match result {
            Ok(response) => response,
            // Nobody to answer: shut down, as a cancelled run's connection.
            Err(f) if f.unanswered => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            Err(f) => Response::Error {
                code: f.code,
                message: f.message,
            },
        };
        protocol::send_frame(stream, &response, &[])?;
        Ok(())
    }

    fn dispatch(&self, peer: &Peer, request: Request) -> Result<Response, Failure> {
        match request {
            Request::Status => Ok(Response::Status(self.status())),
            Request::Lock => {
                // The explicit lock ends every grant, and is done once their
                // brokers have confirmed (or were killed).
                let mut state = self.state();
                state.lock();
                let ending = self.registry.decide(Which::All, EndReason::Locked);
                drop(state);
                ending.complete();
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
            Request::Run(_) | Request::BrokerRunV2(_) => {
                Err(Failure::invalid("run requests carry file descriptors"))
            }
            // Like `lock`: neither needs an approval or an unlocked vault.
            Request::Grants => Ok(Response::Grants {
                grants: self.registry.list(),
            }),
            Request::RevokeGrant { id } => self.revoke_grant(peer, id),
            Request::Configure { settings } => self.configure(peer, settings),
        }
    }

    /// End one grant, or every grant (`id` is `None`), by hand (`revoked`).
    /// Done once their brokers have confirmed, or were killed; the audit log
    /// is not waited for, and the end records say who revoked them. An ID
    /// that names no grant that has not ended is `not_found`.
    fn revoke_grant(&self, peer: &Peer, id: Option<String>) -> Result<Response, Failure> {
        let by = Some(format!("revoked by {}", peer.describe()));
        let Some(id) = id else {
            let ending = self
                .registry
                .decide_with(Which::All, EndReason::Revoked, by);
            let ended = ending.ended();
            ending.complete();
            return Ok(ok(match ended {
                1 => "1 grant revoked".to_string(),
                n => format!("{n} grants revoked"),
            }));
        };
        if !broker_protocol::is_well_formed_grant_id(&id) {
            return Err(Failure::invalid(format!(
                "{} is not a grant ID (g and 16 hexadecimal digits; `rusthorse grants` lists them)",
                util::visible(&util::truncate(&id, 40))
            )));
        }
        let ending = self
            .registry
            .decide_with(Which::Grant(&id), EndReason::Revoked, by);
        let (matched, ended) = (ending.matched(), ending.ended());
        ending.complete();
        match (matched, ended) {
            (0, _) => Err(Failure::new(
                ErrorCode::NotFound,
                format!(
                    "no grant {id} (it ended, or never existed; `rusthorse grants` lists them)"
                ),
            )),
            (_, 0) => Ok(ok(format!("{id} had already ended"))),
            _ => Ok(ok(format!("{id} revoked"))),
        }
    }

    /// The broker program, as `status` reports it and `broker_run_v2` needs
    /// it.
    /// Change the agent's settings (ADR 0007, section 3). They are the
    /// administrator's: the vault must be unlocked (the master password is
    /// asked first when it is not), and the agent's dialog shows each old
    /// and new value, with a warning for each change that protects less.
    /// One at a time. A setting a flag fixes is refused, as is a value out
    /// of bounds. The approval is recorded before the file is written (fail
    /// closed); the file then holds the old settings or the new ones, never
    /// the flags' values; the change applies at once and remembered
    /// approvals are forgotten. A failure once the file was replaced is
    /// `outcome_unknown`; any other error changed nothing.
    fn configure(&self, peer: &Peer, change: SettingsChange) -> Result<Response, Failure> {
        use crate::settings::{self, Key};
        let wanted = change.layer().map_err(Failure::invalid)?;
        if wanted.is_empty() {
            return Err(Failure::invalid("nothing to change"));
        }
        let _one = self.configuring.lock().unwrap_or_else(|p| p.into_inner());
        let sources = self.state().sources.clone().ok_or_else(|| {
            Failure::invalid(
                "this agent was started without a settings file, so its settings cannot be changed",
            )
        })?;
        let fixed: Vec<Key> = wanted
            .iter()
            .map(|(key, _)| key)
            .filter(|key| sources.flags.get(*key).is_some())
            .collect();
        if !fixed.is_empty() {
            let flags: Vec<&str> = fixed.iter().map(|key| key.flag()).collect();
            return Err(Failure::invalid(format!(
                "{} set by {} on the agent's command line, which wins over the settings file: \
                 remove it from the agent's service and restart the agent to change {} here",
                if fixed.len() == 1 {
                    "this setting is"
                } else {
                    "these settings are"
                },
                flags.join(" and "),
                if fixed.len() == 1 { "it" } else { "them" },
            )));
        }
        let current = sources.effective();
        let changes: Vec<(Key, settings::Value, settings::Value)> = wanted
            .iter()
            .filter(|(key, value)| current.get(*key) != *value)
            .map(|(key, value)| (key, current.get(key), value))
            .collect();
        if changes.is_empty() {
            return Err(Failure::invalid(
                "nothing to change: the settings already have these values",
            ));
        }
        let generation = self.generation(peer)?;
        let mut details: Vec<(String, String)> = changes
            .iter()
            .map(|(key, old, new)| {
                (
                    key.label().into(),
                    format!("{} → {}", old.describe(*key), new.describe(*key)),
                )
            })
            .collect();
        details.push(("Settings file".into(), sources.path.display().to_string()));
        details.push(("Requested by (unverified)".into(), peer.describe()));
        let request = ApprovalRequest {
            title: "Rusthorse — change settings".into(),
            summary: "Change the agent's settings?".into(),
            explanation: "The change applies at once and is saved in the agent's settings file. \
                          Remembered approvals are forgotten."
                .into(),
            command: None,
            details,
            facts: Vec::new(),
            warnings: changes
                .iter()
                .filter_map(|(key, old, new)| settings::weakens(*key, *old, *new))
                .map(String::from)
                .collect(),
            can_remember: false,
        };
        let event = AuditEvent::new("configure", peer).detail(
            changes
                .iter()
                .map(|(key, old, new)| format!("{} {} -> {}", key.name(), old.text(), new.text()))
                .collect::<Vec<_>>()
                .join("; "),
        );
        // Not a use of a secret: the idle lock is not postponed.
        self.ask_approval(request, None, event, peer)?;

        let mut changed = settings::Layer::default();
        for (key, _, new) in &changes {
            changed.set(*key, *new).map_err(Failure::invalid)?;
        }
        let updated = settings::Sources {
            file: sources.file.with(&changed),
            ..sources
        };
        let mut state = self.state_unless_gone(
            peer,
            "before the settings were saved; nothing changed",
            || AuditEvent::new("configure", peer),
        )?;
        if state.generation != generation || state.vault.is_none() {
            return Err(locked_meanwhile());
        }
        let saved = settings::save(&updated.path, &updated.file);
        if let Err(e) = &saved
            && !e.replaced
        {
            return Err(Failure::new(
                ErrorCode::Internal,
                format!(
                    "cannot save the settings file {} ({}); nothing changed",
                    updated.path.display(),
                    e.error
                ),
            ));
        }
        let before = state.settings;
        let after = updated.effective();
        let file = updated.path.display().to_string();
        state.settings = after;
        state.sources = Some(updated);
        state.remembered.clear();
        state.generation += 1;
        self.ui.set_timing(after.remember, after.dialog_timeout);
        drop(state);
        if (before.lock_on_suspend, before.lock_on_screen_lock)
            != (after.lock_on_suspend, after.lock_on_screen_lock)
        {
            let mut session = self.config.session_lock.clone();
            session.on_suspend = after.lock_on_suspend;
            session.on_screen_lock = after.lock_on_screen_lock;
            self.session_watchers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .apply(self.me.clone(), &session, &self.lock_triggers);
        }
        // A shorter idle lock counts from the last use, not from now.
        self.lock_if_idle();
        match saved {
            Ok(()) => Ok(ok("settings changed")),
            Err(e) => Err(Failure::new(
                ErrorCode::OutcomeUnknown,
                format!(
                    "the settings were changed and saved in {file}, but the file may not survive \
                     a crash ({})",
                    e.error
                ),
            )),
        }
    }

    fn broker_program(&self) -> Located {
        match &self.config.broker_program {
            None => helper_program::locate(broker_protocol::PROGRAM),
            Some(path) => helper_program::check_file(path),
        }
    }

    /// How long a grant with `limits` lasts: the run's maximum lifetime, or
    /// less where [`AgentConfig::broker_lifetime`] says so.
    fn grant_lifetime(&self, limits: &GrantLimits) -> Duration {
        let longest = limits.max_lifetime();
        self.config
            .broker_lifetime
            .map_or(longest, |shorter| shorter.min(longest))
    }

    fn status(&self) -> StatusInfo {
        // Where the broker is, without running it (`doctor` checks it), and
        // without holding the state lock while the files are examined.
        let broker = match self.broker_program() {
            Located::Program(path) => path.display().to_string(),
            Located::Absent(path) => format!("none: {} does not exist", path.display()),
            Located::Unusable(why) => format!("none: {why}"),
        };
        let mut state = self.state();
        let now = Instant::now();
        state.remembered.retain(|r| r.until > now);
        let locked = state.vault.is_none();
        let idle = state.settings.idle_timeout;
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
            broker: Some(broker),
            // Those that can still be used: not the revoked ones whose
            // commands still run (`grants` lists those too).
            grants: Some(self.registry.count_live()),
            settings: state.sources.as_ref().map(SettingsInfo::of),
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

    /// [`Agent::with_vault_at`] for an effect of `peer`'s request, which
    /// stops instead if the requester has gone ([`Agent::state_unless_gone`]).
    fn with_vault_unless_gone<R>(
        &self,
        generation: u64,
        peer: &Peer,
        (before, record): (&str, impl FnOnce() -> AuditEvent),
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<R, Failure> {
        let mut state = self.state_unless_gone(peer, before, record)?;
        if state.generation != generation {
            return Err(locked_meanwhile());
        }
        let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
        f(vault)
    }

    /// Apply an approved change and save it, but only if nothing happened to
    /// the vault since `generation` — and if `peer`, the requester, has not
    /// gone (`stop`: what to say and record then, see
    /// [`Agent::state_unless_gone`]). The change is a transaction: if `f`
    /// fails, everything it did is rolled back. If saving fails, the vault is
    /// locked so that memory never holds changes that are not on disk — and
    /// if it failed after the file was replaced, the answer is
    /// [`ErrorCode::OutcomeUnknown`]: the change is on disk, but may not
    /// survive a crash. Also returns — read under the same lock as the save,
    /// so that nothing (a `lock`, say) can come in between — any problem with
    /// the cleanup that followed the save.
    fn commit_reporting<R>(
        &self,
        generation: u64,
        peer: &Peer,
        stop: (&str, impl FnOnce() -> AuditEvent),
        f: impl FnOnce(&mut Vault) -> Result<R, Failure>,
    ) -> Result<(R, Option<String>), Failure> {
        self.commit_changing(generation, peer, stop, |v, _| f(v))
    }

    /// [`Agent::commit_reporting`] for a change to entries: `f` names, by
    /// UUID, the entries it changes, replaces or removes, whose grants end
    /// (`entry_changed`) once the change is saved — decided under the lock
    /// that saves, and done (their brokers confirmed or killed) before this
    /// returns. A failed save ends every grant (`save_failed`).
    fn commit_changing<R>(
        &self,
        generation: u64,
        peer: &Peer,
        (before, record): (&str, impl FnOnce() -> AuditEvent),
        f: impl FnOnce(&mut Vault, &mut Vec<String>) -> Result<R, Failure>,
    ) -> Result<(R, Option<String>), Failure> {
        let mut changed = Vec::new();
        let mut state = self.state_unless_gone(peer, before, record)?;
        if state.generation != generation {
            return Err(locked_meanwhile());
        }
        let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
        let result = vault.transaction(|v| f(v, &mut changed))?;
        let saved = vault.save();
        // What the file holds as far as the agent knows: what it wrote, if
        // the save got as far as replacing the file, or else what it read.
        let content = vault.content_fingerprint();
        let cleanup = vault.take_cleanup_error();
        state.content = content;
        if let Err(e) = saved {
            state.lock();
            let ending = self.registry.decide(Which::All, EndReason::SaveFailed);
            drop(state);
            ending.complete();
            let replaced = matches!(e, VaultError::NotDurable(_));
            let mut failure = Failure::from(e);
            failure.message.push_str(if replaced {
                " (the vault was locked; unlock it to see what the file now holds)"
            } else {
                " (the vault was locked to discard the unsaved change)"
            });
            return Err(failure);
        }
        state.generation += 1;
        state.last_used = Instant::now();
        let ending = self
            .registry
            .decide(Which::Entries(&changed), EndReason::EntryChanged);
        drop(state);
        ending.complete();
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
            let password = match self.show_password(&prompt, peer)? {
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
                Typed::RequesterGone => {
                    return Err(self.dialog_abandoned(AuditEvent::new("unlock", peer)));
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
            match Vault::open_fingerprinted(&self.config.vault, password, &self.fingerprint_key) {
                Ok(vault) => {
                    // A lock while the unlock is under way cancels it. (The
                    // fingerprint stays the one of the last unlock.) Its
                    // record says that the vault stays locked: one that comes
                    // after the unlock's own record follows `unlocked`.
                    let locked_meanwhile = |vault: Vault, when: &str| {
                        drop(vault);
                        let _ = self.audit.record(
                            &AuditEvent::new("unlock", peer)
                                .outcome("cancelled_by_lock")
                                .detail(format!("the vault was locked {when}; it stays locked")),
                        );
                        Failure::new(ErrorCode::Locked, format!("the vault was locked {when}"))
                    };
                    // The unlock barrier: a file whose bytes are not those
                    // the agent last read or wrote — another program changed
                    // it while the vault was locked — ends every grant that
                    // survived the lock, whichever entries the change
                    // concerned, before the unlock completes. Decided as
                    // soon as the change is found, under the lock that
                    // checks the generation.
                    // A requester that went away — while the password was
                    // typed, or since — leaves the vault locked before any of
                    // this: no grant ends for it, nothing is recorded but
                    // `aborted`, and the fingerprint stays the last one.
                    let fingerprint = vault.content_fingerprint();
                    let ending = {
                        let state = self.state_unless_gone(
                            peer,
                            "before the vault was unlocked; it stays locked",
                            || AuditEvent::new("unlock", peer),
                        )?;
                        if state.generation != started {
                            drop(state);
                            return Err(locked_meanwhile(
                                vault,
                                "while the password was being entered",
                            ));
                        }
                        let changed = fingerprint.is_none() || state.content != fingerprint;
                        changed.then(|| self.registry.decide(Which::All, EndReason::VaultChanged))
                    };
                    // Their brokers are told and waited for (confirmed, or
                    // killed and gone) before anything waits for the audit
                    // log, and without the state lock: revocation never
                    // waits for the audit log, and a lock meanwhile is not
                    // held up either.
                    let ended = ending.map_or(0, |ending| {
                        let ended = ending.ended();
                        ending.complete();
                        ended
                    });
                    let mut event = AuditEvent::new("unlock", peer).outcome("unlocked");
                    if ended > 0 {
                        event = event.detail(format!(
                            "the vault file was changed by another program while it was \
                             locked: {ended} grant(s) of the credential broker end"
                        ));
                    }
                    // A requester that went away while the grants ended
                    // leaves no `unlocked` record: the vault stays locked
                    // (the grants ended stay ended).
                    self.stop_if_gone(
                        peer,
                        "before its unlock was recorded; the vault stays locked",
                        || AuditEvent::new("unlock", peer),
                    )?;
                    // Recorded before the vault is unlocked, and outside the
                    // state lock, so that no lock waits for this record: if
                    // the audit log cannot be written, the vault stays
                    // locked, and keeps the previous fingerprint, so that
                    // the change is found again at the next unlock.
                    self.record(event)?;
                    // Only a lock can have come meanwhile: this request
                    // holds the dialog lock, without which nothing else
                    // unlocks or creates the vault. A requester that went
                    // away while the unlock was recorded, or while this
                    // waits for the state lock, leaves the vault locked:
                    // the vault read is dropped unused, and `aborted`
                    // follows `unlocked`.
                    let mut state = self.state_unless_gone(
                        peer,
                        "after its unlock was recorded; the vault stays locked",
                        || AuditEvent::new("unlock", peer),
                    )?;
                    if state.generation != started {
                        drop(state);
                        return Err(locked_meanwhile(
                            vault,
                            "while it was being unlocked, after its unlock was recorded",
                        ));
                    }
                    state.vault = Some(vault);
                    state.content = fingerprint;
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
    /// record to write with the outcome. An approval is a use of the vault:
    /// it postpones the idle lock.
    fn approve(
        &self,
        request: ApprovalRequest,
        remember_key: Option<String>,
        event: AuditEvent,
        peer: &Peer,
    ) -> Result<(), Failure> {
        self.ask_approval(request, remember_key, event, peer)?;
        self.touch();
        Ok(())
    }

    /// [`Agent::approve`], without postponing the idle lock: for requests
    /// that use no secret (`configure`).
    fn ask_approval(
        &self,
        request: ApprovalRequest,
        remember_key: Option<String>,
        event: AuditEvent,
        peer: &Peer,
    ) -> Result<(), Failure> {
        if let Some(key) = &remember_key {
            let mut state = self.state();
            let now = Instant::now();
            state.remembered.retain(|r| r.until > now);
            if state.remembered.iter().any(|r| &r.key == key) {
                drop(state);
                self.record(event.outcome("allowed_remembered"))?;
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
            self.show_approval(&request, peer)?
        };
        match decision {
            Decision::RequesterGone => Err(self.dialog_abandoned(event)),
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
                    Ok(())
                }
                _ => {
                    self.record(event.outcome("allowed_once"))?;
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
            self.show_value(&prompt, peer)?
        };
        match value {
            Typed::Value(v) if !v.is_empty() => {
                self.record(event.outcome("value_entered"))?;
                Ok(v)
            }
            Typed::Value(_) => Err(Failure::invalid("empty value; nothing stored")),
            Typed::RequesterGone => Err(self.dialog_abandoned(event)),
            Typed::Cancelled => {
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
        let (exists, current) = self.with_vault(peer, |v| {
            let exists = v.contains(&entry.name);
            // A new entry's group is checked before anyone types a value:
            // the save would refuse the recycle bin or an invalid name after
            // the dialogs. (With `replace`, an existing entry stays where it
            // is and the group is not used.)
            if !exists && let Some(group) = &entry.group {
                v.resolve_group(group)?;
            }
            Ok((exists, v.find(&entry.name).ok().map(|id| v.info(id).id)))
        })?;
        if exists && !replace {
            return Err(VaultError::AlreadyExists(entry.name.clone()).into());
        }
        // Replacing an entry ends its grants (ADR 0013).
        let ends = current
            .as_deref()
            .map_or(0, |uuid| self.registry.count_for_entry(uuid));
        let verb = if exists { "Replace" } else { "Create" };
        let overwritten = || {
            let mut warnings = Vec::new();
            if exists {
                warnings.push("The current value will be overwritten.".to_string());
            }
            warnings.extend(ends_grants(ends));
            warnings
        };
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
                    warnings: overwritten(),
                    can_remember: false,
                };
                self.approve(request, None, event.clone(), peer)?;
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
                    explanation: match (exists, ends_grants(ends)) {
                        (false, _) => String::new(),
                        (true, None) => "It replaces the entry's current value.".into(),
                        (true, Some(ends)) => {
                            format!("It replaces the entry's current value. {ends}")
                        }
                    },
                    notice: None,
                    details: vec![
                        ("Entry".into(), entry.name.clone()),
                        ("Fields".into(), describe_fields(&entry)),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    field: "Secret value".into(),
                    confirm: "Save".into(),
                };
                self.ask_value(peer, prompt, event.clone())?
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
                    warnings: overwritten(),
                    can_remember: false,
                };
                self.approve(request, None, event.clone(), peer)?;
                value
            }
        };
        let stop = ("before the entry was saved; nothing changed", || event);
        self.commit_changing(generation, peer, stop, |v, changed| {
            let uuid = v.find(&entry.name).ok().map(|id| v.info(id).id);
            let replaced = v.add(&entry, &value, replace)?;
            if replaced {
                changed.extend(uuid);
            }
            Ok(ok(format!(
                "{} {}",
                entry.name,
                if replaced { "replaced" } else { "added" }
            )))
        })
        .map(|(response, _)| response)
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
        self.approve(request, None, AuditEvent::new("keyring_items", peer), peer)?;
        // Checked under the lock that reads the count of locks (another
        // request may hold it through a save), which is let go before the
        // keyring is asked.
        let locks = self
            .state_unless_gone(peer, "before the keyring was listed", || {
                AuditEvent::new("keyring_items", peer)
            })?
            .locks;
        let items = crate::keyring::items(&self.config.keyring)
            .map_err(|e| Failure::new(ErrorCode::Internal, format!("{e:#}")))?;
        // What this program may now import from, and what its dialogs show —
        // unless the vault was locked meanwhile, which forgets approvals, or
        // the requester went away while the keyring answered. (Its start
        // time is read first: nothing but the listing comes after the check.)
        let requester = (peer.pid, crate::peer::start_time(peer.pid));
        let mut state = self.state_unless_gone(
            peer,
            "after the keyring was listed; the listing is not kept",
            || AuditEvent::new("keyring_items", peer),
        )?;
        if state.locks != locks {
            return Err(Failure::new(
                ErrorCode::Locked,
                "the vault was locked while the keyring was being listed; list it again",
            ));
        }
        state.keyring_listing = Some(KeyringListing {
            requester,
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
            peer,
        )?;
        self.stop_if_gone(peer, "before the file was read", || {
            AuditEvent::new("dotenv_names", peer)
        })?;
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
        let (new, existing, uuids) = self.with_vault(peer, |v| {
            let mut new = Vec::new();
            let mut existing = Vec::new();
            let mut uuids = Vec::new();
            for entry in &entries {
                if v.contains(&entry.name) {
                    existing.push(entry.name.as_str());
                    uuids.extend(v.find(&entry.name).ok().map(|id| v.info(id).id));
                } else {
                    new.push(entry.name.as_str());
                }
            }
            Ok((new, existing, uuids))
        })?;
        let source = match &origin {
            Origin::Requester => crate::import::Source::Requester,
            Origin::Keyring(rows) => crate::import::Source::Keyring(rows),
            Origin::Dotenv(path) => crate::import::Source::Dotenv(path),
        };
        let mut request =
            crate::import::approval(&source, &new, &existing, replace, &peer.describe());
        // Replacing entries ends their grants (ADR 0013).
        if replace {
            let ends = uuids
                .iter()
                .map(|uuid| self.registry.count_for_entry(uuid))
                .sum();
            request.warnings.extend(ends_grants(ends));
        }
        let event = match &origin {
            Origin::Requester => AuditEvent::new("import", peer),
            Origin::Keyring(_) => AuditEvent::new("import_from", peer).detail("GNOME Keyring"),
            Origin::Dotenv(path) => AuditEvent::new("import_from", peer).detail(*path),
        };
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        let event = event.entries(names);
        self.approve(request, None, event.clone(), peer)?;
        // Before the values are read (the agent reads some itself), and again
        // before they are saved.
        self.stop_if_gone(
            peer,
            "before the values were read; nothing was imported",
            || event.clone(),
        )?;
        let values = values()?;
        if values.len() != entries.len() {
            return Err(Failure::new(
                ErrorCode::Internal,
                "the source gave a different number of values; nothing was imported",
            ));
        }
        let stop = (
            "before the entries were saved; nothing was imported",
            || event,
        );
        self.commit_changing(generation, peer, stop, |v, changed| {
            let (mut added, mut replaced, mut skipped) = (0, 0, 0);
            for (entry, value) in entries.iter().zip(&values) {
                let uuid = v.find(&entry.name).ok().map(|id| v.info(id).id);
                match v.add(entry, value, replace) {
                    Ok(true) => {
                        replaced += 1;
                        changed.extend(uuid);
                    }
                    Ok(false) => added += 1,
                    Err(VaultError::AlreadyExists(_)) => skipped += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(ok(format!(
                "imported {added}, replaced {replaced}, skipped {skipped}"
            )))
        })
        .map(|(response, _)| response)
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
        let (current, destination) = self.with_vault(peer, |v| {
            let id = v.find(name)?;
            // Checked before anyone is asked: an invalid path, one into the
            // recycle bin or through two groups of the same name fails here.
            // A path to the group the entry is in (that very group, not one
            // with the same path) moves nothing: the dialog does not offer it.
            let target = match &changes.group {
                Some(path) => Some(v.resolve_group(path)?).filter(|t| v.moves(id, t)),
                None => None,
            };
            Ok((v.info(id), target))
        })?;
        // The vault resolves the same path the same way when it saves: any
        // change in between bumps the generation, which cancels the request.
        changes.group = destination.as_ref().map(|t| t.path.clone());
        if changes.is_empty() {
            return Err(Failure::invalid(
                "nothing to change: the entry is already in that group",
            ));
        }
        let mut event = AuditEvent::new("edit", peer).entries(vec![current.identity()]);
        if let Some(target) = &destination {
            let from = current.group.as_deref().unwrap_or_default();
            event = event.detail(format!("move from /{from} to {}", target.describe()));
        }

        // Any change to an entry ends its grants (ADR 0013): how many, as
        // the registry counts them now.
        let ends = self.registry.count_for_entry(&current.id);
        let prompt_for_value = matches!(changes.value, Some(ValueChange::Prompt));
        if changes.touches_metadata()
            || matches!(
                changes.value,
                Some(ValueChange::Provided(_) | ValueChange::Generate(_))
            )
        {
            let mut details = vec![("Entry".into(), current.identity())];
            if let Some(target) = &destination {
                details.push(("Move to group".into(), target.describe()));
            }
            details.extend(describe_changes(&changes));
            details.push(("Requested by (unverified)".into(), peer.describe()));
            let request = ApprovalRequest {
                title: "Rusthorse — change an entry".into(),
                summary: "Change an entry?".into(),
                explanation: "The previous version is kept in the entry's history.".into(),
                command: None,
                details,
                facts: Vec::new(),
                warnings: ends_grants(ends).into_iter().collect(),
                can_remember: false,
            };
            self.approve(request, None, event.clone(), peer)?;
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
                    explanation: ends_grants(ends).unwrap_or_default(),
                    notice: None,
                    details: vec![
                        ("Entry".into(), current.identity()),
                        ("Requested by (unverified)".into(), peer.describe()),
                    ],
                    field: "New value".into(),
                    confirm: "Save".into(),
                };
                Some(self.ask_value(peer, prompt, event.clone())?)
            }
            _ => None,
        };
        let stop = ("before the change was saved; nothing changed", || event);
        self.commit_changing(generation, peer, stop, |v, changed| {
            let id = v.find(&current.id)?;
            v.edit(id, &changes, new_value.as_ref())?;
            changed.push(current.id.clone());
            // The entry's name, as `add` and `remove` answer: the request
            // may name it by its UUID or path (the manager sends the UUID).
            Ok(ok(format!(
                "{} updated",
                changes.rename.as_deref().unwrap_or(&current.name)
            )))
        })
        .map(|(response, _)| response)
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
            warnings: std::iter::once("This cannot be undone (the previous file is kept as vault.kdbx.bak until the next save).".to_string())
                .chain(ends_grants(self.registry.count_for_entry(&info.id)))
                .collect(),
            can_remember: false,
        };
        let event = AuditEvent::new("remove", peer).entries(vec![info.identity()]);
        self.approve(request, None, event.clone(), peer)?;
        let stop = ("before the entry was deleted; nothing changed", || event);
        self.commit_changing(generation, peer, stop, |v, changed| {
            let id = v.find(&info.id)?;
            v.remove(id);
            changed.push(info.id.clone());
            Ok(ok(format!("{} deleted", info.name)))
        })
        .map(|(response, _)| response)
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
                self.show_password(&prompt, peer)?
            };
            // Any dialog of the three that is not answered ends the change,
            // and is recorded as such.
            let (outcome, failure) = match answer {
                Typed::Value(value) => return Ok(value),
                Typed::RequesterGone => return Err(self.dialog_abandoned(event.clone())),
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
        // Before the record that says it changed, and again under the lock
        // that saves it (`aborted` then follows `changed`).
        self.stop_if_gone(
            peer,
            "before the password was changed; nothing changed",
            || event.clone(),
        )?;
        self.record(event.clone().outcome("changed"))?;
        let stop = (
            "after its change was recorded; the password was not changed",
            || event,
        );
        let ((), cleanup) = self.commit_reporting(generation, peer, stop, |v| {
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
            let (outcome, failure) = match self.show_password(&prompt, peer)? {
                Typed::Value(value) => return Ok(value),
                Typed::RequesterGone => return Err(self.dialog_abandoned(event.clone())),
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
        self.stop_if_gone(
            peer,
            "before the vault was created; no vault was created",
            || event.clone(),
        )?;
        // Record first: if the audit log cannot be written, nothing is created.
        // A requester that went away while the record waited for the log
        // leaves `created` followed by `aborted`, and no vault.
        self.record(event.clone().outcome("created"))?;
        self.stop_if_gone(
            peer,
            "after its creation was recorded; no vault was created",
            || event.clone(),
        )?;
        let vault = match Vault::create_fingerprinted(
            &path,
            first,
            self.config.new_vault_kdf,
            &self.fingerprint_key,
        ) {
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
        // Created, it is put in use only for a requester still there: one
        // that went away while it was created leaves it locked.
        let created_locked = "after the vault was created; it was created, and stays locked";
        let mut state = self.state_unless_gone(peer, created_locked, || event.clone())?;
        // No vault can have been opened meanwhile: unlocking waits for the
        // dialog lock, which this request holds.
        if state.generation != started {
            // Locked while the password was typed: the vault exists, locked
            // (its next unlock finds a file the agent never read).
            drop(state);
            drop(vault);
            return Ok(ok(format!(
                "vault created at {}; it was locked meanwhile — unlock it to use it",
                path.display()
            )));
        }
        // A new file where the one the agent last read was: as at an
        // unlock, the grants that survived the last lock end (the unlock
        // barrier).
        let fingerprint = vault.content_fingerprint();
        let ending = (fingerprint.is_none() || state.content != fingerprint)
            .then(|| self.registry.decide(Which::All, EndReason::VaultChanged));
        // That decision may have waited for the registry's lock: the
        // requester is checked once more (a poll), right before the vault is
        // put in use. One gone by then leaves it locked; the grants ended
        // stay ended, as at an unlock, and `aborted` is written once they
        // are, without the state lock.
        if peer.gone() {
            drop(state);
            if let Some(ending) = ending {
                ending.complete();
            }
            drop(vault);
            return Err(self.requester_left(created_locked, || event.clone()));
        }
        state.vault = Some(vault);
        state.content = fingerprint;
        state.last_used = Instant::now();
        state.generation += 1;
        drop(state);
        if let Some(ending) = ending {
            ending.complete();
        }
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
        self.approve(request, None, event.clone(), peer)?;
        let before = format!("before the {what} was read; nothing was revealed");
        self.with_vault_unless_gone(generation, peer, (&before, || event), |v| {
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
        // No dialog of its own: it may have waited for the unlock of another
        // request, its requester gone meanwhile.
        self.ensure_unlocked(peer)?;
        let count = {
            let mut state = self.state_unless_gone(
                peer,
                "before the backup was written; nothing was written",
                || AuditEvent::new("backup", peer),
            )?;
            let vault = state.vault.as_mut().ok_or_else(locked_meanwhile)?;
            vault.backup_to(&dest)?
        };
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

    /// Run a command with secrets in its environment: a `run`, or, with
    /// `brokered` (a `broker_run_v2`, ADR 0013), a run whose command gets,
    /// for each broker binding, the token of a grant that a broker process
    /// serves, never the entry's value, within the run's limits.
    fn run(
        &self,
        stream: &UnixStream,
        peer: &Peer,
        run: RunRequest,
        brokered: Option<(Vec<BrokerBinding>, GrantLimits)>,
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
        let (brokered, limits) = match brokered {
            None if run.bindings.is_empty() => {
                return Err(Failure::invalid("no secrets requested"));
            }
            None => (Vec::new(), GrantLimits::default()),
            Some((brokered, _)) if brokered.is_empty() => {
                return Err(Failure::invalid(
                    "a broker_run_v2 needs at least one broker binding; without any, it is a run",
                ));
            }
            Some(brokered) => brokered,
        };
        let is_broker = !brokered.is_empty();
        let mut seen: Vec<&str> = Vec::new();
        let names = run
            .bindings
            .iter()
            .map(|b| (b.var.as_str(), "VAR=ENTRY"))
            .chain(brokered.iter().flat_map(|b| {
                std::iter::once((b.var.as_str(), "VAR=ENTRY"))
                    .chain(b.url_var.as_deref().map(|u| (u, "URLVAR=ENTRY")))
            }));
        for (var, form) in names {
            if !util::is_valid_env_name(var) {
                return Err(Failure::invalid(format!(
                    "{var:?} is not a valid environment variable name; use {form}"
                )));
            }
            if seen.contains(&var) {
                return Err(Failure::invalid(format!("{var} is bound twice")));
            }
            // With grants, Rusthorse sets these itself (127.0.0.1 is added
            // to them).
            if is_broker && (var == "NO_PROXY" || var == "no_proxy") {
                return Err(Failure::invalid(format!(
                    "{var} cannot be bound in a run with grants: Rusthorse adds 127.0.0.1 to it"
                )));
            }
            seen.push(var);
        }
        // Where each grant sends its key, and the limits of all of them:
        // checked before anything else is (ADR 0013, scope amendment). The
        // messages name the variable, never repeat the destination.
        let destinations: Vec<Destination> = brokered
            .iter()
            .map(|b| {
                Destination::parse(&b.destination).map_err(|e| {
                    Failure::invalid(format!(
                        "{} of {}: {e}; use VAR=ENTRY@https://HOST[:PORT][/BASE]",
                        b.var, b.entry
                    ))
                })
            })
            .collect::<Result<_, _>>()?;
        if is_broker {
            limits
                .validate()
                .map_err(|e| Failure::invalid(format!("the grants' limits: {e}")))?;
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
        // The variables that receive values, tokens or the broker's address:
        // whatever the requester sent for them is dropped.
        let secret_vars: Vec<&str> = seen.clone();
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

        // With grants: the broker program, and room for them, before
        // anything is read from the vault.
        let broker_program = if is_broker {
            let program = match self.broker_program() {
                Located::Program(path) => path,
                Located::Absent(path) => {
                    return Err(Failure::new(
                        ErrorCode::Internal,
                        format!(
                            "the credential broker is not installed ({} does not exist); \
                             nothing was run",
                            path.display()
                        ),
                    ));
                }
                Located::Unusable(why) => {
                    return Err(Failure::new(
                        ErrorCode::Internal,
                        format!("the credential broker cannot be used: {why}; nothing was run"),
                    ));
                }
            };
            self.registry
                .room_for(brokered.len())
                .map_err(Failure::invalid)?;
            Some(program)
        } else {
            None
        };

        // Every entry must exist (and have a value) before the human is asked;
        // an entry used through the broker must also have a value the broker
        // can carry.
        let generation = self.generation(peer)?;
        let (entries, grants): (Vec<(String, String, String)>, Vec<Brokered>) = self
            .with_vault_at(generation, |v| {
                let entries: Vec<(String, String, String)> = run
                    .bindings
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
                    .collect::<Result<_, Failure>>()?;
                let mut grants: Vec<Brokered> = Vec::with_capacity(brokered.len());
                for (binding, destination) in brokered.iter().zip(&destinations) {
                    let id = v.find(&binding.entry)?;
                    let info = v.info(id);
                    let identity = info.identity();
                    if entries.iter().any(|(uuid, _, _)| *uuid == info.id) {
                        return Err(Failure::invalid(format!(
                            "{identity} is both used through the broker and given by value; an \
                             entry is one or the other"
                        )));
                    }
                    if grants.iter().any(|g| g.uuid == info.id) {
                        return Err(Failure::invalid(format!(
                            "{identity} is used through the broker twice"
                        )));
                    }
                    match v.secret(id) {
                        None => {
                            return Err(Failure::new(
                                ErrorCode::NotFound,
                                format!("{} has no value", binding.entry),
                            ));
                        }
                        Some(value) if !is_valid_credential(&value) => {
                            return Err(Failure::invalid(format!(
                                "the value of {identity} cannot be used through the broker: it \
                                 must be 8 to 4096 visible ASCII characters, without spaces"
                            )));
                        }
                        Some(_) => {}
                    }
                    grants.push(Brokered {
                        uuid: info.id,
                        name: info.name,
                        identity,
                        var: binding.var.clone(),
                        url_var: binding.url_var.clone(),
                        destination: destination.clone(),
                    });
                }
                Ok((entries, grants))
            })?;
        let identities: Vec<String> = entries
            .iter()
            .map(|(_, identity, _)| identity.clone())
            .collect();
        // What the run's records name: every entry, and the grants it
        // creates (with their IDs, drawn now so that the record of the
        // approval names them).
        let audited: Vec<String> = identities
            .iter()
            .cloned()
            .chain(grants.iter().map(|g| g.identity.clone()))
            .collect();
        let grant_ids: Vec<String> = grants
            .iter()
            .map(|_| broker_protocol::try_new_grant_id())
            .collect::<Result<_, _>>()
            .map_err(|e| {
                Failure::new(ErrorCode::Internal, format!("cannot draw a grant ID: {e}"))
            })?;
        let audit_grants: Option<Vec<AuditGrant>> = is_broker.then(|| {
            grants
                .iter()
                .zip(&grant_ids)
                .map(|(g, id)| AuditGrant {
                    id: id.clone(),
                    entry: g.identity.clone(),
                    destination: g.destination.origin.clone(),
                    base_path: (!g.destination.base_path.is_empty())
                        .then(|| g.destination.base_path.clone()),
                })
                .collect()
        });
        let run_record = || {
            let mut event = run_event(peer, &run, &audited);
            event.grants = audit_grants.clone();
            event
        };

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
        let input = match (run.redact, run.forward_stdin) {
            (false, _) => "the requester's own standard input",
            (true, true) => "forwarded from the requester",
            (true, false) => "none (/dev/null)",
        };
        let secrets_shown = run
            .bindings
            .iter()
            .zip(&identities)
            .map(|(b, identity)| format!("{} ← {identity}", b.var))
            .collect::<Vec<_>>()
            .join(", ");
        let shown = Shown {
            command_line,
            program: program_text,
            cwd: run.cwd.clone(),
            requester: peer.describe(),
            endpoints: endpoints.clone(),
            input,
        };
        let (request, key) = if is_broker {
            let request = broker_approval(
                &shown,
                &secrets_shown,
                &grants,
                &limits,
                run.redact,
                warnings,
            );
            // Each part must be readable on its own, as the command line
            // must: refused rather than shortened.
            if let Some((label, value)) = request
                .details
                .iter()
                .find(|(_, value)| value.chars().count() > MAX_DETAIL_CHARS)
            {
                return Err(Failure::invalid(format!(
                    "the {} part of the approval dialog would be too long to show ({} \
                     characters, limit {MAX_DETAIL_CHARS}); use shorter variable names or \
                     fewer bindings",
                    label.to_lowercase(),
                    value.chars().count()
                )));
            }
            // Never remembered: each approval creates its grants once.
            (request, None)
        } else {
            if !run.redact {
                warnings.push(
                    "Output is NOT redacted: secret values printed by the command reach the \
                     requester."
                        .into(),
                );
            }
            let request = ApprovalRequest {
                title: "Rusthorse — use a secret".into(),
                summary: "Run a command with your secrets?".into(),
                explanation: "Rusthorse runs it as you, outside any sandbox, with the secrets in \
                              its environment; programs it starts can use them too. Read the \
                              command before you allow it."
                    .into(),
                command: Some(shown.command_line.clone()),
                details: vec![
                    ("Secrets".into(), secrets_shown),
                    ("Program".into(), shown.program.clone()),
                    ("Directory".into(), shown.cwd.clone()),
                    ("Requested by (unverified)".into(), shown.requester.clone()),
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
            // UUID) in the same vault generation, command line, program,
            // working directory, input and output handling, and effective
            // environment.
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
            (request, Some(key))
        };
        let mut event = run_record();
        let audited_env: Vec<String> = [("destinations", &endpoints), ("routes", &routes)]
            .into_iter()
            .filter(|(_, vars)| !vars.is_empty())
            .map(|(what, vars)| format!("{what}: {vars}"))
            .collect();
        if !audited_env.is_empty() {
            event = event.detail(audited_env.join("; "));
        }
        self.approve(request, key, event, peer)?;
        let not_run = "before the command started; nothing was run";
        // Every failure from here on, before the command starts, follows the
        // approval's record with one that says why nothing ran (best effort).
        let aborted = |failure: Failure| {
            let _ = self.audit.record(
                &run_record()
                    .outcome("aborted")
                    .detail(failure.message.clone()),
            );
            failure
        };
        // Once the run has grants, such a failure ends them first: their
        // brokers are stopped and their ports released before anything
        // waits for the audit log (revocation never does), and only then
        // does the run fail.
        let abandon = |run_grants: Option<RunGrants>, reason: EndReason, failure: Failure| {
            if let Some(run_grants) = run_grants {
                run_grants.finish(reason);
            }
            aborted(failure)
        };

        // The answer may have taken a while: make sure the program and the
        // directory were not replaced meanwhile...
        if file_id(&program.canonical).ok() != Some(program_id)
            || file_id(&cwd).ok() != Some(cwd_id)
        {
            let _ = self.audit.record(
                &run_record()
                    .outcome("aborted")
                    .detail("program or directory replaced after approval"),
            );
            return Err(Failure::invalid(
                "the program or the working directory was replaced after you approved; nothing was run",
            ));
        }
        // ...and read the values under the same lock that checks that the
        // vault did not change (no edit, lock or reload since the dialog) and
        // that the requester is still there (also after a wait for the
        // lock). The grants are entered under that lock too, as starting: a
        // lock comes either before (nothing was read) or after (it ends
        // them). From this point on the approval is consumed: a later `lock`
        // does not stop the command (it ends its grants).
        let command_text = shell_join(&run.argv);
        type UnderLock = (
            Vec<(String, String, SecretString)>,
            Vec<SecretString>,
            Option<RunGrants>,
        );
        let (secrets, credentials, mut run_grants): UnderLock = self
            .with_vault_unless_gone(generation, peer, (not_run, run_record), |v| {
                let secrets = run
                    .bindings
                    .iter()
                    .zip(&entries)
                    .map(|(b, (id, _, name))| {
                        let found = v.find(id)?;
                        let value = v.secret(found).ok_or_else(|| {
                            Failure::new(ErrorCode::NotFound, format!("{name} has no value"))
                        })?;
                        Ok((b.var.clone(), name.clone(), value))
                    })
                    .collect::<Result<Vec<_>, Failure>>()?;
                let credentials = grants
                    .iter()
                    .map(|g| {
                        let found = v.find(&g.uuid)?;
                        v.secret(found)
                            .filter(|value| is_valid_credential(value))
                            .ok_or_else(|| {
                                Failure::new(
                                    ErrorCode::NotFound,
                                    format!("{} has no value the broker can use", g.name),
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, Failure>>()?;
                let run_grants = if is_broker {
                    let new: Vec<NewGrant> = grants
                        .iter()
                        .zip(&grant_ids)
                        .map(|(g, id)| NewGrant {
                            id: id.clone(),
                            entry_uuid: g.uuid.clone(),
                            entry: g.identity.clone(),
                            var: g.var.clone(),
                            destination: g.destination.clone(),
                            limits,
                            command: command_text.clone(),
                            requester: peer.describe(),
                            lifetime: self.grant_lifetime(&limits),
                        })
                        .collect();
                    Some(self.registry.enter(new).map_err(Failure::invalid)?)
                } else {
                    None
                };
                Ok((secrets, credentials, run_grants))
            })
            // Locked or changed meanwhile, an entry gone, or no room left
            // for the grants (another run took it) — or the requester gone,
            // which is on record already.
            .map_err(|failure| {
                if failure.unanswered {
                    failure
                } else {
                    aborted(failure)
                }
            })?;

        // With grants, before the command starts: each grant's creation is
        // recorded, its broker started and ready, and all of them made
        // active — or none is, and nothing runs.
        let prepared = match (&mut run_grants, &broker_program) {
            (Some(preparing), Some(broker)) => {
                self.prepare_grants(peer, preparing, broker, &grants, &grant_ids, credentials)
            }
            _ => {
                drop(credentials);
                Ok((Vec::new(), Vec::new()))
            }
        };
        let (tokens, ports) = match prepared {
            Ok(prepared) => prepared,
            Err((failure, reason)) => return Err(abandon(run_grants.take(), reason, failure)),
        };
        // The last check, right before the command starts (with grants, once
        // they are ready): a requester that went away meanwhile — while the
        // brokers started, say — has its grants ended first, and nothing
        // runs.
        self.stop_if_gone(peer, not_run, || {
            if let Some(run_grants) = run_grants.take() {
                run_grants.finish(EndReason::CommandEnded);
            }
            run_record()
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
        if is_broker {
            // The token and the broker's address, never the key; and no
            // proxy for the broker's address.
            for ((grant, token), port) in grants.iter().zip(&tokens).zip(&ports) {
                command.env(&grant.var, token.as_str());
                if let Some(url_var) = &grant.url_var {
                    command.env(url_var, grant.destination.local_url(*port));
                }
            }
            for name in ["NO_PROXY", "no_proxy"] {
                let value = match effective_env.get(name) {
                    Some(set) if !set.is_empty() => format!("{set},127.0.0.1"),
                    _ => "127.0.0.1".to_string(),
                };
                command.env(name, value);
            }
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
        let started = stream
            .try_clone()
            .and_then(|writer| Ok((writer, stream.try_clone()?)))
            .map_err(|e| Failure::new(ErrorCode::Internal, e.to_string()))
            .and_then(|streams| {
                let child = command.spawn().map_err(|e| {
                    Failure::new(
                        ErrorCode::InvalidRequest,
                        format!("cannot start {}: {e}", program.canonical.display()),
                    )
                })?;
                Ok((streams, child))
            });
        let ((writer, watch_stream), mut child) = match started {
            Ok(started) => started,
            Err(failure) => {
                return Err(abandon(run_grants.take(), EndReason::CommandEnded, failure));
            }
        };
        drop(command);
        let writer = Arc::new(Mutex::new(writer));
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
            // The tokens are redacted too, labelled with their variable.
            let labels: Vec<(String, Vec<u8>)> = secrets
                .iter()
                .map(|(_, entry, value)| (entry.clone(), value.as_bytes().to_vec()))
                .chain(
                    grants
                        .iter()
                        .zip(&tokens)
                        .map(|(grant, token)| (grant.var.clone(), token.as_bytes().to_vec())),
                )
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
        drop(tokens);

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
                grants: run_grants.as_ref().map(RunGrants::ender),
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
        // The command has ended: its grants end at once — before the rest of
        // its group is terminated and its output drained, so that a token a
        // descendant kept no longer works — and nothing it started may keep
        // running with the secrets.
        if let Some(run_grants) = &run_grants {
            run_grants.ender().end(EndReason::CommandEnded);
        }
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
        // The command is over: its brokers are stopped and its ports
        // released. What they reported of the destinations' answers is
        // complete now, unlike their records (written by another thread).
        let unauthorized = match run_grants.take() {
            Some(run_grants) => run_grants.finish(EndReason::CommandEnded),
            None => Vec::new(),
        };
        let unknown = |e: &dyn std::fmt::Display| {
            let _ = self
                .audit
                .record(&run_record().outcome("unknown").detail(e.to_string()));
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
        let _ = self
            .audit
            .record(&run_record().outcome("exited").detail(detail));
        Ok(Response::Exited {
            code: status.code(),
            signal: status.signal(),
            unauthorized,
        })
    }

    /// Prepare a broker run's grants, which are entered as starting: check
    /// the broker program again, record each grant's creation (fail closed),
    /// start their brokers — each with its install: a new token, the
    /// credential, the approved origin and the limits — and make them all
    /// active. Returns the tokens and ports, in the order of `grants`; on a
    /// failure, the reason the grants end with (the caller ends them, stops
    /// their brokers and releases their ports before it answers).
    fn prepare_grants(
        &self,
        peer: &Peer,
        run_grants: &mut RunGrants,
        broker: &Path,
        grants: &[Brokered],
        ids: &[String],
        credentials: Vec<SecretString>,
    ) -> Result<(Vec<SecretString>, Vec<u16>), (Failure, EndReason)> {
        let failed = |message: String| {
            (
                Failure::new(ErrorCode::Internal, format!("{message}; nothing was run")),
                EndReason::BrokerFailed,
            )
        };
        // Checked again where it is used: the approval may have taken a
        // while, and the agent's own program may have been replaced meanwhile.
        let broker = match self.broker_program() {
            Located::Program(path) if path == broker => path,
            Located::Program(_) | Located::Absent(_) => {
                return Err(failed(
                    "the credential broker's program was moved or removed after the approval"
                        .into(),
                ));
            }
            Located::Unusable(why) => {
                return Err(failed(format!(
                    "the credential broker cannot be used: {why}"
                )));
            }
        };
        // The requester is checked before each grant's record of its
        // creation (a requester already gone leaves none), and once more
        // right before the brokers start, after what can wait on the way
        // there (the tokens, the registry's lock): no broker gets its
        // credential for a requester gone by then. Its run records why
        // nothing ran once the grants have ended.
        let gone = |before: &str| (departed(before), EndReason::CommandEnded);
        for (grant, id) in grants.iter().zip(ids) {
            if peer.gone() {
                return Err(gone("before its grants were created; nothing was run"));
            }
            let mut event = AuditEvent::new("grant", peer)
                .outcome("created")
                .entries(vec![grant.identity.clone()]);
            event.grant = Some(id.clone());
            self.record(event)
                .map_err(|failure| (failure, EndReason::AuditFailed))?;
            run_grants.mark_created(id);
        }
        let tokens: Vec<SecretString> = grants
            .iter()
            .map(|_| broker_protocol::try_new_token())
            .collect::<Result<_, _>>()
            .map_err(|e| failed(format!("cannot draw a token: {e}")))?;
        let installs: Vec<Install> = grants
            .iter()
            .zip(ids)
            .zip(&tokens)
            .zip(credentials)
            .map(|(((grant, id), token), credential)| Install {
                version: broker_protocol::VERSION,
                grant: id.clone(),
                token: token.clone(),
                credential,
                origin: grant.destination.origin.clone(),
                max_in_flight: broker_protocol::MAX_IN_FLIGHT,
                max_connections: BROKER_CONNECTIONS,
                lifetime_secs: run_grants.lifetime_secs(id),
            })
            .collect();
        let ready = self
            .config
            .broker_ready_timeout
            .unwrap_or(broker_protocol::READY_TIMEOUT);
        if peer.gone() {
            return Err(gone(
                "after its grants' creation was recorded; no broker was started and nothing was run",
            ));
        }
        let ports = run_grants.start(&broker, installs, ready).map_err(|why| {
            failed(format!(
                "the credential broker could not serve a grant: {why}"
            ))
        })?;
        // Every grant of the run is still starting, or none becomes active:
        // one that ended meanwhile (a lock, a revocation) fails the run.
        run_grants.activate().map_err(|why| {
            (
                Failure::new(ErrorCode::Internal, format!("{why}; nothing was run")),
                EndReason::CommandEnded,
            )
        })?;
        Ok((tokens, ports))
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

/// Ends every grant when the agent's serve loop ends, however it ends.
struct StopGrants(Arc<Registry>);

impl Drop for StopGrants {
    fn drop(&mut self) {
        self.0.stop_all(EndReason::AgentStopped);
    }
}

/// An entry that a broker run uses through the broker, as checked before
/// its dialog.
struct Brokered {
    /// The entry's UUID.
    uuid: String,
    /// Its name, for messages.
    name: String,
    /// As dialogs and the audit log identify it.
    identity: String,
    /// The variable that receives the token.
    var: String,
    /// The variable that receives the broker's address, if any.
    url_var: Option<String>,
    /// Where the run says its key goes.
    destination: Destination,
}

/// What a run's dialog shows besides its secrets and grants.
struct Shown {
    command_line: String,
    program: String,
    cwd: String,
    requester: String,
    /// The destinations its environment sets (threat model L4).
    endpoints: String,
    input: &'static str,
}

/// The approval of a broker run (ADR 0013, scope amendment): for each grant,
/// which variables get its token and the broker's address, the approved
/// origin and the base path apart from it, that the key may go to any path
/// there, how and when it ends and its requests (the run's limits); then
/// the secrets given as values in a mixed run, the program, the
/// directory and the requester; that the command receives a temporary token
/// and not the key, that it can spend credit, that a request count is not a
/// spending limit and that request bodies are not inspected; and, without
/// redaction, that the output is not filtered.
fn broker_approval(
    shown: &Shown,
    secrets: &str,
    grants: &[Brokered],
    limits: &GrantLimits,
    redact: bool,
    mut warnings: Vec<String>,
) -> ApprovalRequest {
    let mixed = !secrets.is_empty();
    // Short sentences: with zenity, the whole dialog must fit on the screen,
    // and a run with one grant should (a test checks a realistic one).
    let one = grants.len() == 1;
    let mut explanation = format!(
        "It gets {}, not the key; Rusthorse puts the key in its place in requests to the \
         approved origin, {}. It runs as you, outside any sandbox, and programs it starts can \
         use the {} too.",
        if one {
            "a temporary token"
        } else {
            "a temporary token for each grant"
        },
        crate::broker_grant::REACHES,
        if one { "token" } else { "tokens" }
    );
    if mixed {
        explanation.push_str(" The secrets listed are in its environment as values.");
    }
    let mut details: Vec<(String, String)> = grants
        .iter()
        .flat_map(|g| {
            broker_host::grant_details(
                &g.var,
                g.url_var.as_deref(),
                &g.identity,
                &g.destination,
                limits,
            )
        })
        .collect();
    if mixed {
        details.push(("Secrets".into(), secrets.to_string()));
    }
    details.push(("Program".into(), shown.program.clone()));
    details.push(("Directory".into(), shown.cwd.clone()));
    details.push(("Requested by (unverified)".into(), shown.requester.clone()));
    if !shown.endpoints.is_empty() {
        details.push(("Destinations (environment)".into(), shown.endpoints.clone()));
    }
    warnings.insert(
        0,
        "It can spend credit: a request limit is not a spending limit, and request bodies are \
         not inspected."
            .into(),
    );
    if !redact {
        warnings.push(if mixed {
            "Output is NOT redacted: tokens and values the command prints reach the requester, \
             who can use a token until its grant ends."
                .into()
        } else {
            "Output is NOT redacted: a token the command prints reaches the requester, who can \
             use it until its grant ends."
                .into()
        });
    }
    ApprovalRequest {
        title: "Rusthorse — use keys through the broker".into(),
        summary: if one {
            "Run a command with a temporary grant?".into()
        } else {
            format!("Run a command with {} temporary grants?", grants.len())
        },
        explanation,
        command: Some(shown.command_line.clone()),
        details,
        facts: vec![
            ("Input".into(), shown.input.into()),
            (
                "Output".into(),
                match (redact, mixed) {
                    (true, true) => "secret values and tokens are redacted".into(),
                    (true, false) => "tokens are redacted".into(),
                    (false, _) => "not redacted".into(),
                },
            ),
        ],
        warnings,
        // Never "Allow for…": each approval creates its grants once.
        can_remember: false,
    }
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
    // A move is described by the caller, which knows where the path leads.
    let mut out: Vec<(String, String)> = Vec::new();
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

/// The warning of a dialog whose change ends grants of the credential broker
/// (ADR 0013: any change to an entry ends its grants); `None` when it ends
/// none.
fn ends_grants(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some(
            "This ends 1 grant of the credential broker at once: the command using it loses \
             access."
                .into(),
        ),
        n => Some(format!(
            "This ends {n} grants of the credential broker at once: the commands using them \
             lose access."
        )),
    }
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
    /// The run's grants, which end when the requester goes away.
    grants: Option<RunEnder>,
}

impl Watch {
    /// Cancel the request: stop every worker, shut the socket down (which
    /// fails any send in progress at once, without taking the send lock),
    /// end the run's grants and terminate the command's process group.
    fn cancel(&self) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.credits.wake();
        self.acks.wake();
        // Before the group is terminated: a token kept by a process that
        // escapes it stops working first.
        if let Some(grants) = &self.grants {
            grants.end(EndReason::CommandEnded);
        }
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
                // A signal: poll again (the loop waits 200 ms at a time).
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
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
        fn master_password(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            unreachable!("no dialog expected")
        }
        fn secret_value(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            unreachable!("no dialog expected")
        }
        fn approve(&self, _: &ApprovalRequest, _: Connection<'_>) -> anyhow::Result<Decision> {
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
                broker_program: None,
                broker_ready_timeout: None,
                broker_lifetime: None,
                settings: None,
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
            .commit_reporting(
                generation,
                &Peer::agent(),
                ("", || AuditEvent::new("add", &Peer::agent())),
                |v| {
                    v.add(&entry, &SecretString::new("abcd".into()), false)?;
                    Ok(())
                },
            )
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

    /// A save that fails ends every grant (ADR 0013, decision 8:
    /// `save_failed`), as it locks the vault.
    #[test]
    fn a_failed_save_ends_every_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        let password = || SecretString::new("correct horse".into());
        let mut vault =
            Vault::create(&path, password(), KdfParams::INSECURE_FOR_TESTS).expect("create");
        vault.fail_directory_sync();
        let audit = dir.path().join("audit.jsonl");
        let agent = Agent::new(
            AgentConfig {
                vault: path.clone(),
                socket: dir.path().join("agent.sock"),
                audit_log: audit.clone(),
                idle_timeout: Duration::ZERO,
                request_timeout: Duration::from_secs(10),
                send_buffer: None,
                session_lock: Default::default(),
                new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
                keyring: Default::default(),
                broker_program: None,
                broker_ready_timeout: None,
                broker_lifetime: None,
                settings: None,
            },
            Box::new(NoDialogs),
        );
        let generation = {
            let mut state = agent.state();
            state.vault = Some(vault);
            state.generation
        };
        let id = broker_protocol::new_grant_id();
        let run = agent
            .registry
            .enter(vec![NewGrant {
                id: id.clone(),
                entry_uuid: "some-other-entry".into(),
                entry: "OTHER (someothe)".into(),
                var: "KEY".into(),
                destination: example_destination(),
                limits: GrantLimits::default(),
                command: "true".into(),
                requester: "test".into(),
                lifetime: Duration::from_secs(60),
            }])
            .expect("enter");
        run.mark_created(&id);
        let entry = NewEntry {
            name: "X".into(),
            ..NewEntry::default()
        };
        agent
            .commit_reporting(
                generation,
                &Peer::agent(),
                ("", || AuditEvent::new("add", &Peer::agent())),
                |v| {
                    v.add(&entry, &SecretString::new("abcd".into()), false)?;
                    Ok(())
                },
            )
            .expect_err("the save did not complete");
        assert!(agent.state().vault.is_none());
        assert_eq!(agent.registry.list()[0].state, "revoked");
        run.finish(EndReason::CommandEnded);
        let records = std::fs::read_to_string(&audit).expect("audit");
        assert!(records.contains(r#""reason":"save_failed""#), "{records}");
    }

    /// An agent for these tests, in `dir`, with `ui` and a stand-in broker
    /// program at `broker` (which they never run, unless something is
    /// wrong).
    fn agent_in(dir: &Path, broker: &Path, ui: Box<dyn Ui>) -> Arc<Agent> {
        Agent::new(config_in(dir, broker), ui)
    }

    /// The configuration of [`agent_in`].
    fn config_in(dir: &Path, broker: &Path) -> AgentConfig {
        {
            AgentConfig {
                vault: dir.join("vault.kdbx"),
                socket: dir.join("agent.sock"),
                audit_log: dir.join("audit.jsonl"),
                idle_timeout: Duration::ZERO,
                request_timeout: Duration::from_secs(10),
                send_buffer: None,
                session_lock: Default::default(),
                new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
                keyring: Default::default(),
                broker_program: Some(broker.to_path_buf()),
                broker_ready_timeout: Some(Duration::from_secs(2)),
                broker_lifetime: None,
                settings: None,
            }
        }
    }

    /// A stand-in broker program that leaves `marker` behind if it is ever
    /// started.
    fn stand_in_broker(path: &Path, marker: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    /// Where the grants of these tests send their key.
    fn example_destination() -> Destination {
        Destination::parse("https://api.example.com").expect("destination")
    }

    /// A grant lasts its run's maximum lifetime; the tests' override
    /// shortens it and never lengthens it, so that a broker's install never
    /// says more than its run allows.
    #[test]
    fn a_grant_lasts_at_most_its_runs_lifetime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let limits = GrantLimits {
            max_lifetime_minutes: 30,
            ..GrantLimits::default()
        };
        let longest = Duration::from_secs(30 * 60);
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        assert_eq!(agent.grant_lifetime(&limits), longest);
        for (asked, lasts) in [
            (Duration::from_secs(2), Duration::from_secs(2)),
            (Duration::from_secs(48 * 3600), longest),
        ] {
            let agent = Agent::new(
                AgentConfig {
                    broker_lifetime: Some(asked),
                    ..config_in(dir.path(), &broker)
                },
                Box::new(NoDialogs),
            );
            assert_eq!(agent.grant_lifetime(&limits), lasts, "{asked:?}");
        }
    }

    /// A grant whose creation cannot be recorded starts no broker, and its
    /// run fails before anything runs (ADR 0013: `created`, before the
    /// command starts; fail closed): no credential reaches a broker.
    #[test]
    fn a_grant_whose_creation_cannot_be_recorded_starts_no_broker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let marker = dir.path().join("broker-ran");
        stand_in_broker(&broker, &marker);
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        // The audit log cannot be written: a directory is where it goes.
        std::fs::create_dir_all(dir.path().join("audit.jsonl")).expect("block the audit log");
        let id = broker_protocol::new_grant_id();
        let mut run = agent
            .registry
            .enter(vec![NewGrant {
                id: id.clone(),
                entry_uuid: "uuid-of-key".into(),
                entry: "KEY (uuid-of-)".into(),
                var: "K".into(),
                destination: example_destination(),
                limits: GrantLimits::default(),
                command: "true".into(),
                requester: "test".into(),
                lifetime: Duration::from_secs(60),
            }])
            .expect("enter");
        let grants = vec![Brokered {
            uuid: "uuid-of-key".into(),
            name: "KEY".into(),
            identity: "KEY (uuid-of-)".into(),
            var: "K".into(),
            url_var: None,
            destination: example_destination(),
        }];
        let program = std::fs::canonicalize(&broker).expect("canonical");
        let Err((failure, reason)) = agent.prepare_grants(
            &Peer::agent(),
            &mut run,
            &program,
            &grants,
            std::slice::from_ref(&id),
            vec![SecretString::new("sk-ant-test-0000000000000000".into())],
        ) else {
            panic!("the grant was prepared without its record");
        };
        assert_eq!(failure.code, ErrorCode::Internal);
        assert!(
            failure.message.contains("cannot write the audit log"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("sk-ant-test"));
        assert_eq!(reason, EndReason::AuditFailed);
        run.finish(reason);
        assert_eq!(agent.registry.count(), 0, "a grant was left");
        std::thread::sleep(Duration::from_millis(300));
        assert!(!marker.exists(), "a broker was started");
    }

    /// A lock that comes while a run records the creation of its grants —
    /// after the grants were entered, before their brokers start — ends
    /// them, and no broker ever gets their credential: the run fails, saying
    /// so, before anything runs (ADR 0013, preparing a run's grants).
    #[test]
    fn a_lock_while_a_grants_creation_is_recorded_gives_no_broker_its_credential() {
        use crate::session_lock::{Locker, SCREEN_LOCK};
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let received = dir.path().join("received");
        // A stand-in that keeps whatever it is sent, and never answers.
        std::fs::write(
            &broker,
            format!("#!/bin/sh\nexec /bin/cat > '{}'\n", received.display()),
        )
        .expect("write");
        std::fs::set_permissions(&broker, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        let id = broker_protocol::new_grant_id();
        let mut run = agent
            .registry
            .enter(vec![NewGrant {
                id: id.clone(),
                entry_uuid: "uuid-of-key".into(),
                entry: "KEY (uuid-of-)".into(),
                var: "K".into(),
                destination: example_destination(),
                limits: GrantLimits::default(),
                command: "true".into(),
                requester: "test".into(),
                lifetime: Duration::from_secs(60),
            }])
            .expect("enter");
        let grants = vec![Brokered {
            uuid: "uuid-of-key".into(),
            name: "KEY".into(),
            identity: "KEY (uuid-of-)".into(),
            var: "K".into(),
            url_var: None,
            destination: example_destination(),
        }];
        let program = std::fs::canonicalize(&broker).expect("canonical");
        let prepared = std::thread::scope(|scope| {
            // The audit log is slow: the record of the grant's creation
            // waits. (Held in here, so that a failed assertion lets it go.)
            let held = agent.audit.hold();
            let preparing = scope.spawn(|| {
                agent.prepare_grants(
                    &Peer::agent(),
                    &mut run,
                    &program,
                    &grants,
                    std::slice::from_ref(&id),
                    vec![SecretString::new("sk-ant-test-0000000000000000".into())],
                )
            });
            std::thread::sleep(Duration::from_millis(100));
            // The vault was not open: the lock writes no record.
            agent.lock_for(SCREEN_LOCK, "test");
            assert_eq!(agent.registry.list()[0].state, "revoked");
            drop(held);
            preparing.join().expect("the preparation ends")
        });
        let Err((failure, reason)) = prepared else {
            panic!("the grant was prepared after it ended");
        };
        assert_eq!(failure.code, ErrorCode::Internal);
        assert!(
            failure
                .message
                .contains("the grant ended while its broker was starting"),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("nothing was run"));
        assert!(!failure.message.contains("sk-ant-test"));
        // Time for a broker that got an install to write it down.
        std::thread::sleep(Duration::from_millis(300));
        let got = std::fs::read(&received).unwrap_or_default();
        assert!(got.is_empty(), "a broker received {} bytes", got.len());
        run.finish(reason);
        assert_eq!(agent.registry.count(), 0, "a grant was left");
        let records = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit");
        assert!(records.contains(r#""outcome":"created""#), "{records}");
        assert!(records.contains(r#""reason":"screen_locked""#), "{records}");
    }

    /// The approver of [`a_run_refused_after_its_approval_says_why_on_record`]:
    /// while the human decides, other runs take every grant an agent may
    /// hold.
    #[derive(Default)]
    struct TakesTheRoom {
        agent: Mutex<Weak<Agent>>,
        taken: Mutex<Option<RunGrants>>,
    }

    struct TakesTheRoomUi(Arc<TakesTheRoom>);

    impl Ui for TakesTheRoomUi {
        fn master_password(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            unreachable!("no password dialog expected")
        }
        fn secret_value(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            unreachable!("no value dialog expected")
        }
        fn approve(&self, _: &ApprovalRequest, _: Connection<'_>) -> anyhow::Result<Decision> {
            let agent = self.0.agent.lock().expect("lock").upgrade().expect("agent");
            let all: Vec<NewGrant> = (0..broker_protocol::MAX_GRANTS)
                .map(|i| NewGrant {
                    id: broker_protocol::new_grant_id(),
                    entry_uuid: format!("uuid-{i}"),
                    entry: format!("OTHER{i} (uuid-{i})"),
                    var: "K".into(),
                    destination: example_destination(),
                    limits: GrantLimits::default(),
                    command: "true".into(),
                    requester: "test".into(),
                    lifetime: Duration::from_secs(60),
                })
                .collect();
            *self.0.taken.lock().expect("lock") = Some(agent.registry.enter(all).expect("room"));
            Ok(Decision::AllowOnce)
        }
    }

    /// A run that fails after its approval — here because, while the human
    /// decided, other runs took the last grants an agent may hold — follows
    /// the approval's record with one that says why nothing ran.
    #[test]
    fn a_run_refused_after_its_approval_says_why_on_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let marker = dir.path().join("broker-ran");
        stand_in_broker(&broker, &marker);
        let approver = Arc::new(TakesTheRoom::default());
        let agent = agent_in(
            dir.path(),
            &broker,
            Box::new(TakesTheRoomUi(Arc::clone(&approver))),
        );
        *approver.agent.lock().expect("lock") = Arc::downgrade(&agent);
        let mut vault = Vault::create(
            &dir.path().join("vault.kdbx"),
            SecretString::new("correct horse".into()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create");
        let entry = NewEntry {
            name: "KEY".into(),
            ..NewEntry::default()
        };
        vault
            .add(
                &entry,
                &SecretString::new("sk-ant-test-0000000000000000".into()),
                false,
            )
            .expect("add");
        agent.state().vault = Some(vault);
        let run = RunRequest {
            bindings: Vec::new(),
            argv: vec!["true".into()],
            cwd: dir.path().to_str().expect("utf8").into(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            redact: true,
            forward_stdin: false,
        };
        let brokered = vec![BrokerBinding {
            var: "K".into(),
            entry: "KEY".into(),
            destination: "https://api.example.com".into(),
            url_var: None,
        }];
        let (stream, _client) = UnixStream::pair().expect("pair");
        let failure = agent
            .run(
                &stream,
                &Peer::agent(),
                run,
                Some((brokered, GrantLimits::default())),
                Vec::new(),
            )
            .expect_err("no room left");
        assert_eq!(failure.code, ErrorCode::InvalidRequest);
        assert!(
            failure
                .message
                .contains("at most 16 grants can exist at once"),
            "{}",
            failure.message
        );
        let records: Vec<serde_json::Value> =
            std::fs::read_to_string(dir.path().join("audit.jsonl"))
                .expect("audit")
                .lines()
                .map(|line| serde_json::from_str(line).expect("json"))
                .collect();
        let runs: Vec<(&str, &str)> = records
            .iter()
            .filter(|r| r["action"] == "run")
            .map(|r| {
                (
                    r["outcome"].as_str().unwrap_or_default(),
                    r["detail"].as_str().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(runs.len(), 2, "{records:?}");
        assert_eq!(runs[0].0, "allowed_once");
        assert_eq!(runs[1].0, "aborted");
        assert!(runs[1].1.contains("at most 16 grants"), "{}", runs[1].1);
        assert!(
            !records.iter().any(|r| r["action"] == "grant"),
            "{records:?}"
        );
        approver
            .taken
            .lock()
            .expect("lock")
            .take()
            .expect("taken")
            .finish(EndReason::CommandEnded);
        assert_eq!(agent.registry.count(), 0);
        assert!(!marker.exists(), "a broker was started");
    }

    /// Types the master password, and says when it is asked for it.
    struct TypesPassword(Mutex<Option<std::sync::mpsc::Sender<()>>>);

    impl Ui for TypesPassword {
        fn master_password(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            if let Some(asked) = self.0.lock().expect("lock").take() {
                let _ = asked.send(());
            }
            Ok(Typed::Value(SecretString::new("correct horse".into())))
        }
        fn secret_value(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            unreachable!("no value dialog expected")
        }
        fn approve(&self, _: &ApprovalRequest, _: Connection<'_>) -> anyhow::Result<Decision> {
            unreachable!("no approval expected")
        }
    }

    /// An unlock records itself outside the state lock, so that no lock
    /// waits for its record; a lock that comes meanwhile wins: the unlock,
    /// recorded, does not take effect, and says so on record.
    #[test]
    fn a_lock_while_an_unlock_is_recorded_keeps_the_vault_locked() {
        use crate::session_lock::{Locker, SCREEN_LOCK};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        drop(
            Vault::create(
                &path,
                SecretString::new("correct horse".into()),
                KdfParams::INSECURE_FOR_TESTS,
            )
            .expect("create"),
        );
        let audit = dir.path().join("audit.jsonl");
        let (asked, typed) = std::sync::mpsc::channel();
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
                broker_program: None,
                broker_ready_timeout: None,
                broker_lifetime: None,
                settings: None,
            },
            Box::new(TypesPassword(Mutex::new(Some(asked)))),
        );
        let unlocked = std::thread::scope(|scope| {
            // Held in here, so that a failed assertion lets it go.
            let held = agent.audit.hold();
            let unlocking = scope.spawn(|| agent.ensure_unlocked(&Peer::agent()));
            typed
                .recv_timeout(Duration::from_secs(10))
                .expect("the password was asked for");
            // The vault is read; the unlock then waits to record itself.
            std::thread::sleep(Duration::from_millis(500));
            // The vault was not open yet: the lock writes no record. It must
            // not wait for the unlock's record (which the log holds).
            let (done, locked) = std::sync::mpsc::channel();
            let locker: &Agent = &agent;
            scope.spawn(move || {
                locker.lock_for(SCREEN_LOCK, "test");
                let _ = done.send(());
            });
            let waited = locked.recv_timeout(Duration::from_secs(2)).is_err();
            drop(held);
            assert!(!waited, "the lock waited for the unlock's record");
            unlocking.join().expect("the unlock ends")
        });
        let failure = unlocked.expect_err("unlocked after a lock");
        assert_eq!(failure.code, ErrorCode::Locked);
        assert!(
            failure.message.contains("while it was being unlocked"),
            "{}",
            failure.message
        );
        assert!(agent.state().vault.is_none(), "unlocked after a lock");
        assert!(agent.state().content.is_none(), "the fingerprint changed");
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
            .expect("audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        let outcomes: Vec<&str> = records
            .iter()
            .map(|r| r["outcome"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(outcomes, ["unlocked", "cancelled_by_lock"]);
        // What follows the record of the unlock says that it did not happen.
        let cancelled = records[1]["detail"].as_str().unwrap_or_default();
        assert!(cancelled.contains("it stays locked"), "{cancelled}");
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
                broker_program: None,
                broker_ready_timeout: None,
                broker_lifetime: None,
                settings: None,
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

    /// A broker run with one grant, as Claude Code would be run through it
    /// (ADR 0013): its dialog fits on the screen with zenity, which cannot
    /// scroll, with or without a value given beside it and with or without
    /// redaction.
    #[test]
    fn the_dialog_of_a_run_with_one_grant_fits_the_screen() {
        let shown = Shown {
            command_line: "claude --model claude-sonnet-4-5 -p 'Summarise the changes in this \
                           branch'"
                .into(),
            program: "/home/someone/.local/bin/claude → \
                      /home/someone/.local/share/claude/versions/2.1.316"
                .into(),
            cwd: "/home/someone/dev/rusthorse".into(),
            requester: "rusthorse[123456] ← bash[123400] ← claude[120000] ← node[119999] ← \
                        bash[1000]"
                .into(),
            endpoints: String::new(),
            input: "the requester's own standard input",
        };
        let grant = Brokered {
            uuid: "8d2f6c1e-0000-4000-8000-000000000000".into(),
            name: "ANTHROPIC_API_KEY".into(),
            identity: "AI/ANTHROPIC_API_KEY (8d2f6c1e)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            url_var: Some("ANTHROPIC_BASE_URL".into()),
            // A base path, so that the dialog shows every line it can.
            destination: Destination::parse("https://api.anthropic.com/v1").expect("destination"),
        };
        let limits = GrantLimits {
            max_requests: Some(200),
            ..GrantLimits::default()
        };
        for mixed in ["", "GITHUB_TOKEN ← Dev/GITHUB_TOKEN (1a2b3c4d)"] {
            for redact in [true, false] {
                let request = broker_approval(
                    &shown,
                    mixed,
                    std::slice::from_ref(&grant),
                    &limits,
                    redact,
                    Vec::new(),
                );
                let text = crate::ui::approval_text(&request);
                assert!(text.chars().count() <= MAX_DIALOG_CHARS, "{text}");
                // What the approval covers is said whole.
                assert!(text.contains(crate::broker_grant::REACHES), "{text}");
                assert!(text.contains("Approved origin: https://api.anthropic.com\n"));
                assert!(text.contains("Base path: /v1 (not a limit)\n"), "{text}");
                assert_eq!(
                    crate::ui::approval_too_tall(&request),
                    None,
                    "{mixed:?} {redact}: {} pixels",
                    crate::ui::approval_height(&request)
                );
                assert!(!request.can_remember);
            }
        }
    }

    /// Answers every dialog — the master password, a value, Allow once —
    /// and holds the first one open: it says when that one is shown, and
    /// answers it once told to.
    struct HoldsTheFirst {
        shown: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        answer: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        asked: AtomicUsize,
    }

    impl HoldsTheFirst {
        /// The UI, how to know that its first dialog is shown, and how to
        /// have it answered.
        fn new() -> (
            Self,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::Sender<()>,
        ) {
            let (shown, is_shown) = std::sync::mpsc::channel();
            let (answer, answered) = std::sync::mpsc::channel();
            let ui = HoldsTheFirst {
                shown: Mutex::new(Some(shown)),
                answer: Mutex::new(Some(answered)),
                asked: AtomicUsize::new(0),
            };
            (ui, is_shown, answer)
        }

        fn shown(&self) {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let shown = self.shown.lock().expect("lock").take();
            if let Some(shown) = shown {
                let _ = shown.send(());
                let answer = self.answer.lock().expect("lock").take();
                if let Some(answer) = answer {
                    let _ = answer.recv_timeout(Duration::from_secs(30));
                }
            }
        }
    }

    impl Ui for HoldsTheFirst {
        fn master_password(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            self.shown();
            Ok(Typed::Value(SecretString::new("correct horse".into())))
        }
        fn secret_value(&self, _: &Prompt, _: Connection<'_>) -> anyhow::Result<Typed> {
            self.shown();
            Ok(Typed::Value(SecretString::new("fake-typed-value".into())))
        }
        fn approve(&self, _: &ApprovalRequest, _: Connection<'_>) -> anyhow::Result<Decision> {
            self.shown();
            Ok(Decision::AllowOnce)
        }
    }

    /// A vault in `dir` holding `entries` (fake values).
    fn vault_with(dir: &Path, entries: &[&str]) -> Vault {
        let mut vault = Vault::create(
            &dir.join("vault.kdbx"),
            SecretString::new("correct horse".into()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create");
        for name in entries {
            let entry = NewEntry {
                name: (*name).into(),
                ..NewEntry::default()
            };
            vault
                .add(&entry, &SecretString::new("fake-value".into()), false)
                .expect("add");
        }
        vault.save().expect("save");
        vault
    }

    /// The peer at the agent's end of `stream`, its connection watched.
    fn requester(stream: &UnixStream) -> Peer<'_> {
        Peer::of(stream)
            .expect("peer")
            .connected(Connection::new(stream.as_fd(), false))
    }

    /// Wait (at most 10 seconds) until `count` requests wait for the dialog.
    fn waiting_for_the_dialog(agent: &Agent, count: usize) {
        let until = Instant::now() + Duration::from_secs(10);
        while agent.waiting_for_dialog.load(Ordering::SeqCst) != count {
            assert!(Instant::now() < until, "never waited for the dialog");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// The outcomes the audit log holds for `action`, in order.
    fn outcomes(dir: &Path, action: &str) -> Vec<String> {
        std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|record| record["action"] == action)
            .map(|record| record["outcome"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// A backup has no dialog of its own. One that waited for the dialog
    /// while another request unlocked the vault, and whose requester left
    /// meanwhile, writes nothing (CON01).
    #[test]
    fn a_backup_whose_requester_left_while_it_waited_for_an_unlock_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        drop(vault_with(dir.path(), &["T"]));
        let (ui, shown, answer) = HoldsTheFirst::new();
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        let dest = dir.path().join("backup.kdbx");
        let (unlocking, _its_client) = UnixStream::pair().expect("pair");
        let (backing_up, its_client) = UnixStream::pair().expect("pair");
        let backup = std::thread::scope(|scope| {
            let unlock = scope.spawn(|| agent.ensure_unlocked(&requester(&unlocking)));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the unlock's dialog is shown");
            let backup =
                scope.spawn(|| agent.backup(&requester(&backing_up), dest.to_str().expect("utf8")));
            // The backup waits for the dialog the unlock holds; its
            // requester leaves; then the unlock is answered.
            waiting_for_the_dialog(&agent, 1);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            answer.send(()).expect("answer");
            unlock.join().expect("unlock").expect("unlocked");
            backup.join().expect("backup")
        });
        let failure = backup.expect_err("a backup for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(!dest.exists(), "the backup was written");
        assert_eq!(outcomes(dir.path(), "backup"), ["aborted"]);
    }

    /// A request that waits for its turn while another's dialog is open,
    /// and whose requester leaves meanwhile, gets no dialog, and does
    /// nothing.
    #[test]
    fn a_request_whose_requester_left_while_it_waited_gets_no_dialog() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = vault_with(dir.path(), &["A", "B"]);
        let (ui, shown, answer) = HoldsTheFirst::new();
        let ui = Arc::new(ui);
        struct Shared(Arc<HoldsTheFirst>);
        impl Ui for Shared {
            fn master_password(&self, p: &Prompt, c: Connection<'_>) -> anyhow::Result<Typed> {
                self.0.master_password(p, c)
            }
            fn secret_value(&self, p: &Prompt, c: Connection<'_>) -> anyhow::Result<Typed> {
                self.0.secret_value(p, c)
            }
            fn approve(&self, r: &ApprovalRequest, c: Connection<'_>) -> anyhow::Result<Decision> {
                self.0.approve(r, c)
            }
        }
        let agent = agent_in(
            dir.path(),
            &dir.path().join("broker"),
            Box::new(Shared(Arc::clone(&ui))),
        );
        agent.state().vault = Some(vault);
        let (first, _its_client) = UnixStream::pair().expect("pair");
        let (second, its_client) = UnixStream::pair().expect("pair");
        let (removed, waited) = std::thread::scope(|scope| {
            let removing = scope.spawn(|| agent.remove(&requester(&first), "A"));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the first dialog is shown");
            let waiting = scope.spawn(|| agent.remove(&requester(&second), "B"));
            waiting_for_the_dialog(&agent, 1);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            answer.send(()).expect("answer");
            (
                removing.join().expect("first"),
                waiting.join().expect("second"),
            )
        });
        assert!(removed.is_ok());
        let failure = waited.expect_err("removed for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert_eq!(ui.asked.load(Ordering::SeqCst), 1, "a second dialog");
        assert!(agent.state().vault.as_ref().expect("open").contains("B"));
        // (In either order: the dialog is let go before its answer is
        // recorded.)
        let mut recorded = outcomes(dir.path(), "remove");
        recorded.sort();
        assert_eq!(recorded, ["allowed_once", "requester_gone"]);
    }

    /// A change whose requester leaves while it waits for the state lock —
    /// which another request may hold through a save or a backup — is not
    /// saved.
    #[test]
    fn a_change_whose_requester_left_while_it_waited_for_the_state_lock_is_not_saved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = vault_with(dir.path(), &["A"]);
        let (ui, shown, answer) = HoldsTheFirst::new();
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        agent.state().vault = Some(vault);
        let saved = std::fs::read(dir.path().join("vault.kdbx")).expect("vault");
        let (removing, its_client) = UnixStream::pair().expect("pair");
        let removed = std::thread::scope(|scope| {
            let remove = scope.spawn(|| agent.remove(&requester(&removing), "A"));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the dialog is shown");
            // Allowed while the state lock is held elsewhere: the removal
            // waits for it, and its requester leaves meanwhile.
            let held = agent.state();
            answer.send(()).expect("answer");
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            remove.join().expect("remove")
        });
        let failure = removed.expect_err("removed for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(agent.state().vault.as_ref().expect("open").contains("A"));
        assert_eq!(
            std::fs::read(dir.path().join("vault.kdbx")).expect("vault"),
            saved
        );
        assert_eq!(outcomes(dir.path(), "remove"), ["allowed_once", "aborted"]);
    }

    /// An import whose requester leaves while the agent reads its values —
    /// from the keyring or a `.env` file, as `values` stands for here — is
    /// not saved: checked before the values are read, and again before the
    /// entries are saved.
    #[test]
    fn an_import_whose_requester_left_while_its_values_were_read_is_not_saved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = vault_with(dir.path(), &[]);
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        agent.state().vault = Some(vault);
        let (importing, its_client) = UnixStream::pair().expect("pair");
        let entries = vec![NewEntry {
            name: "IMPORTED".into(),
            ..NewEntry::default()
        }];
        let imported = agent.import_entries(
            &requester(&importing),
            entries,
            false,
            Origin::Dotenv("/fake/app.env"),
            || {
                its_client
                    .shutdown(std::net::Shutdown::Both)
                    .expect("leave");
                Ok(vec![SecretString::new("fake-imported-value".into())])
            },
        );
        let failure = imported.expect_err("imported for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("before the entries were saved"),
            "{}",
            failure.message
        );
        assert!(
            !agent
                .state()
                .vault
                .as_ref()
                .expect("open")
                .contains("IMPORTED")
        );
        assert_eq!(
            outcomes(dir.path(), "import_from"),
            ["allowed_once", "aborted"]
        );
    }

    /// Wait (at most 10 seconds) until a record waits for the held log.
    fn a_record_waits(agent: &Agent) {
        let until = Instant::now() + Duration::from_secs(10);
        while agent.audit.waiting() != 1 {
            assert!(Instant::now() < until, "no record waited for the log");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// An unlock whose requester leaves while its `unlocked` record waits
    /// for the log keeps the vault locked: `aborted` follows `unlocked`.
    #[test]
    fn an_unlock_whose_requester_left_after_its_record_keeps_the_vault_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        drop(vault_with(dir.path(), &[]));
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        let generation = agent.state().generation;
        let (unlocking, its_client) = UnixStream::pair().expect("pair");
        let unlocked = std::thread::scope(|scope| {
            let held = agent.audit.hold();
            let unlock = scope.spawn(|| agent.ensure_unlocked(&requester(&unlocking)));
            // The password opened the vault and the requester was there:
            // the unlock waits to record itself. Then it leaves.
            a_record_waits(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            unlock.join().expect("unlock")
        });
        let failure = unlocked.expect_err("unlocked for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(agent.state().vault.is_none(), "the vault was unlocked");
        assert_eq!(agent.state().generation, generation);
        assert_eq!(outcomes(dir.path(), "unlock"), ["unlocked", "aborted"]);
    }

    /// A password change whose requester leaves while its `changed` record
    /// waits for the log is not saved: `aborted` follows `changed`.
    #[test]
    fn a_password_change_whose_requester_left_after_its_record_is_not_saved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = vault_with(dir.path(), &[]);
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        agent.state().vault = Some(vault);
        let saved = std::fs::read(dir.path().join("vault.kdbx")).expect("vault");
        let (changing, its_client) = UnixStream::pair().expect("pair");
        let changed = std::thread::scope(|scope| {
            let held = agent.audit.hold();
            let change = scope.spawn(|| agent.change_password(&requester(&changing)));
            a_record_waits(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            change.join().expect("change")
        });
        let failure = changed.expect_err("changed for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert_eq!(
            std::fs::read(dir.path().join("vault.kdbx")).expect("vault"),
            saved
        );
        assert_eq!(outcomes(dir.path(), "passwd"), ["changed", "aborted"]);
    }

    /// A vault creation whose requester leaves while its `created` record
    /// waits for the log creates no vault: `aborted` follows `created`.
    #[test]
    fn a_vault_whose_requester_left_while_its_creation_was_recorded_is_not_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        let (creating, its_client) = UnixStream::pair().expect("pair");
        let created = std::thread::scope(|scope| {
            let held = agent.audit.hold();
            let create = scope.spawn(|| agent.create_vault(&requester(&creating)));
            a_record_waits(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            create.join().expect("create")
        });
        let failure = created.expect_err("created for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            !dir.path().join("vault.kdbx").exists(),
            "a vault was created"
        );
        assert!(agent.state().vault.is_none());
        assert_eq!(outcomes(dir.path(), "create_vault"), ["created", "aborted"]);
    }

    /// A vault whose requester leaves while it is created is created, but
    /// not put in use: it stays locked.
    #[test]
    fn a_vault_created_for_a_requester_that_left_meanwhile_stays_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ui, shown, answer) = HoldsTheFirst::new();
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        // A grant that outlived the last lock, which the new vault's barrier
        // would end: it is not reached for a requester gone.
        let (survivor, _, _) = grants_entered(&agent, 1);
        let path = dir.path().join("vault.kdbx");
        let (creating, its_client) = UnixStream::pair().expect("pair");
        let created = std::thread::scope(|scope| {
            let create = scope.spawn(|| agent.create_vault(&requester(&creating)));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the first dialog is shown");
            // Answered while the state lock is held elsewhere: the vault is
            // created, then waits for the lock to be put in use; its
            // requester leaves then.
            let held = agent.state();
            answer.send(()).expect("answer");
            let until = Instant::now() + Duration::from_secs(10);
            while !path.exists() {
                assert!(Instant::now() < until, "the vault was never created");
                thread::sleep(Duration::from_millis(5));
            }
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            create.join().expect("create")
        });
        let failure = created.expect_err("put in use for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("after the vault was created"),
            "{}",
            failure.message
        );
        assert!(path.exists());
        assert!(agent.state().vault.is_none(), "the new vault was unlocked");
        assert_eq!(outcomes(dir.path(), "create_vault"), ["created", "aborted"]);
        let states: Vec<String> = agent.registry.list().into_iter().map(|g| g.state).collect();
        assert_eq!(states, ["starting"], "the barrier ended a grant");
        survivor.finish(EndReason::CommandEnded);
    }

    /// Wait (at most 10 seconds) until a taking of the registry's lock waits
    /// for the hold ([`Registry::hold`]).
    fn the_registry_is_waited_for(agent: &Agent) {
        let until = Instant::now() + Duration::from_secs(10);
        while agent.registry.waiting() != 1 {
            assert!(Instant::now() < until, "nothing waited for the registry");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A vault created for a requester that leaves while its barrier waits
    /// for the registry's lock, after the check under the state lock, is not
    /// put in use: the check right before stops it, and it stays locked.
    #[test]
    fn a_vault_whose_requester_left_while_the_registry_was_held_stays_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        let path = dir.path().join("vault.kdbx");
        let (creating, its_client) = UnixStream::pair().expect("pair");
        let created = std::thread::scope(|scope| {
            // The barrier's decision is the creation's first taking of it.
            let held = agent.registry.hold(0);
            let create = scope.spawn(|| agent.create_vault(&requester(&creating)));
            the_registry_is_waited_for(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            create.join().expect("create")
        });
        let failure = created.expect_err("put in use for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("after the vault was created"),
            "{}",
            failure.message
        );
        assert!(path.exists());
        assert!(agent.state().vault.is_none(), "the new vault was unlocked");
        assert_eq!(outcomes(dir.path(), "create_vault"), ["created", "aborted"]);
    }

    /// An unlock whose requester leaves while the grants its barrier ends
    /// are being ended writes no `unlocked` record: the vault stays locked.
    #[test]
    fn an_unlock_whose_requester_left_while_its_grants_ended_records_no_unlock() {
        let dir = tempfile::tempdir().expect("tempdir");
        drop(vault_with(dir.path(), &[]));
        let (ui, _shown, answer) = HoldsTheFirst::new();
        answer.send(()).expect("answer at once");
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        let generation = agent.state().generation;
        let (unlocking, its_client) = UnixStream::pair().expect("pair");
        let unlocked = std::thread::scope(|scope| {
            // A file the agent never read: the barrier decides (one taking
            // let through), then waits to end the grants.
            let held = agent.registry.hold(1);
            let unlock = scope.spawn(|| agent.ensure_unlocked(&requester(&unlocking)));
            the_registry_is_waited_for(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            unlock.join().expect("unlock")
        });
        let failure = unlocked.expect_err("unlocked for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("before its unlock was recorded"),
            "{}",
            failure.message
        );
        assert!(agent.state().vault.is_none(), "the vault was unlocked");
        assert_eq!(agent.state().generation, generation);
        assert_eq!(outcomes(dir.path(), "unlock"), ["aborted"]);
    }

    /// An unlock whose requester leaves while it waits for the state lock,
    /// before its barrier, ends no grant, though the vault's file changed:
    /// the check before the barrier stops it, and a grant that outlived the
    /// last lock stays as it was.
    #[test]
    fn an_unlock_whose_requester_left_before_its_barrier_ends_no_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        drop(vault_with(dir.path(), &[]));
        let (ui, shown, answer) = HoldsTheFirst::new();
        let agent = agent_in(dir.path(), &dir.path().join("broker"), Box::new(ui));
        // A file the agent never read: the barrier would end this grant.
        let (survivor, _, _) = grants_entered(&agent, 1);
        let generation = agent.state().generation;
        let (unlocking, its_client) = UnixStream::pair().expect("pair");
        let unlocked = std::thread::scope(|scope| {
            let unlock = scope.spawn(|| agent.ensure_unlocked(&requester(&unlocking)));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the password is asked");
            // Typed while the state lock is held elsewhere: the unlock opens
            // the file, then waits for the lock; its requester leaves.
            let held = agent.state();
            answer.send(()).expect("answer");
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            unlock.join().expect("unlock")
        });
        let states: Vec<String> = agent.registry.list().into_iter().map(|g| g.state).collect();
        survivor.finish(EndReason::CommandEnded);
        assert_eq!(states, ["starting"], "the barrier ended a grant");
        let failure = unlocked.expect_err("unlocked for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("before the vault was unlocked"),
            "{}",
            failure.message
        );
        assert!(agent.state().vault.is_none(), "the vault was unlocked");
        assert_eq!(agent.state().generation, generation);
        assert_eq!(outcomes(dir.path(), "unlock"), ["aborted"]);
    }

    /// A keyring listing whose requester leaves while it waits for the state
    /// lock, before the keyring is asked, never asks it (CON06): here the
    /// keyring's address is a socket that would see the connection.
    #[cfg(feature = "secret-service")]
    #[test]
    fn the_keyring_is_not_asked_for_a_requester_that_left_while_it_waited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bus = dir.path().join("bus");
        let listener = std::os::unix::net::UnixListener::bind(&bus).expect("bind");
        listener.set_nonblocking(true).expect("non-blocking");
        let (ui, shown, answer) = HoldsTheFirst::new();
        let mut config = config_in(dir.path(), &dir.path().join("broker"));
        config.keyring = crate::keyring::Settings {
            address: Some(format!("unix:path={}", bus.display())),
            plain: true,
            deadline: Duration::from_secs(1),
        };
        let agent = Agent::new(config, Box::new(ui));
        let (listing, its_client) = UnixStream::pair().expect("pair");
        let listed = std::thread::scope(|scope| {
            let list = scope.spawn(|| agent.keyring_items(&requester(&listing)));
            shown
                .recv_timeout(Duration::from_secs(10))
                .expect("the dialog is shown");
            // Allowed while the state lock is held elsewhere: the listing
            // waits for it, and its requester leaves meanwhile.
            let held = agent.state();
            answer.send(()).expect("answer");
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            list.join().expect("list")
        });
        let failure = listed.expect_err("listed for a requester that left");
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the keyring was asked"
        );
        assert_eq!(
            outcomes(dir.path(), "keyring_items"),
            ["allowed_once", "aborted"]
        );
    }

    /// `count` grants of a run, entered: the run, their IDs and what each
    /// is.
    fn grants_entered(agent: &Agent, count: usize) -> (RunGrants, Vec<String>, Vec<Brokered>) {
        let ids: Vec<String> = (0..count)
            .map(|_| broker_protocol::new_grant_id())
            .collect();
        let run = agent
            .registry
            .enter(
                ids.iter()
                    .enumerate()
                    .map(|(i, id)| NewGrant {
                        id: id.clone(),
                        entry_uuid: format!("uuid-of-key-{i}"),
                        entry: format!("KEY{i} (uuid-of-)"),
                        var: format!("K{i}"),
                        destination: example_destination(),
                        limits: GrantLimits::default(),
                        command: "true".into(),
                        requester: "test".into(),
                        lifetime: Duration::from_secs(60),
                    })
                    .collect(),
            )
            .expect("enter");
        let grants = (0..count)
            .map(|i| Brokered {
                uuid: format!("uuid-of-key-{i}"),
                name: format!("KEY{i}"),
                identity: format!("KEY{i} (uuid-of-)"),
                var: format!("K{i}"),
                url_var: None,
                destination: example_destination(),
            })
            .collect();
        (run, ids, grants)
    }

    /// Wait (at most 10 seconds) until the log has the end of every grant
    /// whose creation it has: written by another thread, it must not come
    /// after the test (it would make the test's directory again).
    fn grants_ended(dir: &Path) {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let said = outcomes(dir, "grant");
            let created = said.iter().filter(|o| *o == "created").count();
            if said.iter().filter(|o| *o == "ended").count() == created {
                return;
            }
            assert!(
                Instant::now() < until,
                "a grant's end was not recorded: {said:?}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A run whose requester leaves while its grant's creation is recorded
    /// starts no broker: no credential leaves the agent.
    #[test]
    fn no_broker_is_started_for_a_requester_that_left_while_its_grants_were_recorded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let marker = dir.path().join("broker-ran");
        stand_in_broker(&broker, &marker);
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        let (mut run, ids, grants) = grants_entered(&agent, 1);
        let program = std::fs::canonicalize(&broker).expect("canonical");
        let (running, its_client) = UnixStream::pair().expect("pair");
        let prepared = std::thread::scope(|scope| {
            let held = agent.audit.hold();
            let prepare = scope.spawn(|| {
                agent.prepare_grants(
                    &requester(&running),
                    &mut run,
                    &program,
                    &grants,
                    &ids,
                    vec![SecretString::new("sk-ant-test-0000000000000000".into())],
                )
            });
            a_record_waits(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            prepare.join().expect("prepare")
        });
        let Err((failure, reason)) = prepared else {
            panic!("grants prepared for a requester that left");
        };
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure
                .message
                .contains("after its grants' creation was recorded"),
            "{}",
            failure.message
        );
        assert_eq!(reason, EndReason::CommandEnded);
        run.finish(reason);
        grants_ended(dir.path());
        assert!(!marker.exists(), "a broker was started");
        assert_eq!(outcomes(dir.path(), "grant"), ["created", "ended"]);
    }

    /// A run whose requester leaves while its brokers' installs wait for
    /// the registry's lock, after its grants' records, starts no broker:
    /// the last check comes right before the brokers start.
    #[test]
    fn no_broker_is_started_for_a_requester_that_left_while_the_registry_was_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let marker = dir.path().join("broker-ran");
        stand_in_broker(&broker, &marker);
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        let (mut run, ids, grants) = grants_entered(&agent, 1);
        let program = std::fs::canonicalize(&broker).expect("canonical");
        let (running, its_client) = UnixStream::pair().expect("pair");
        let prepared = std::thread::scope(|scope| {
            // The grant's creation is noted in the registry (one taking let
            // through); then its install's lifetime waits for the lock.
            let held = agent.registry.hold(1);
            let prepare = scope.spawn(|| {
                agent.prepare_grants(
                    &requester(&running),
                    &mut run,
                    &program,
                    &grants,
                    &ids,
                    vec![SecretString::new("sk-ant-test-0000000000000000".into())],
                )
            });
            the_registry_is_waited_for(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            prepare.join().expect("prepare")
        });
        let Err((failure, reason)) = prepared else {
            panic!("grants prepared for a requester that left");
        };
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("no broker was started"),
            "{}",
            failure.message
        );
        assert_eq!(reason, EndReason::CommandEnded);
        run.finish(reason);
        grants_ended(dir.path());
        assert!(!marker.exists(), "a broker was started");
        assert_eq!(outcomes(dir.path(), "grant"), ["created", "ended"]);
    }

    /// A run whose requester has gone records the creation of no further
    /// grant: of two, the one whose record waited when it left is the only
    /// one recorded.
    #[test]
    fn no_grant_is_recorded_as_created_for_a_requester_already_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let broker = dir.path().join("rusthorse-broker");
        let marker = dir.path().join("broker-ran");
        stand_in_broker(&broker, &marker);
        let agent = agent_in(dir.path(), &broker, Box::new(NoDialogs));
        let (mut run, ids, grants) = grants_entered(&agent, 2);
        let program = std::fs::canonicalize(&broker).expect("canonical");
        let (running, its_client) = UnixStream::pair().expect("pair");
        let prepared = std::thread::scope(|scope| {
            let held = agent.audit.hold();
            let prepare = scope.spawn(|| {
                agent.prepare_grants(
                    &requester(&running),
                    &mut run,
                    &program,
                    &grants,
                    &ids,
                    vec![
                        SecretString::new("sk-ant-test-0000000000000000".into()),
                        SecretString::new("sk-ant-test-1111111111111111".into()),
                    ],
                )
            });
            a_record_waits(&agent);
            its_client
                .shutdown(std::net::Shutdown::Both)
                .expect("leave");
            drop(held);
            prepare.join().expect("prepare")
        });
        let Err((failure, reason)) = prepared else {
            panic!("grants prepared for a requester that left");
        };
        assert!(failure.unanswered, "{}", failure.message);
        assert!(
            failure.message.contains("before its grants were created"),
            "{}",
            failure.message
        );
        run.finish(reason);
        grants_ended(dir.path());
        assert!(!marker.exists(), "a broker was started");
        assert_eq!(outcomes(dir.path(), "grant"), ["created", "ended"]);
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
