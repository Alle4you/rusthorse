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

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getuid};

use crate::audit::{AuditEvent, AuditLog};
use crate::exec;
use crate::peer::Peer;
use crate::protocol::{
    self, EntryChanges, ErrorCode, ImportedEntry, NewEntry, Request, Response, RunRequest,
    SecretString, StatusInfo, ValueChange,
};
use crate::redact::Redactor;
use crate::ui::{ApprovalRequest, Decision, Prompt, Ui};
use crate::util::{self, shell_join, truncate};
use crate::vault::{Vault, VaultError};

/// How many wrong master passwords are tolerated per unlock.
const UNLOCK_ATTEMPTS: u32 = 3;

/// Grace period between SIGTERM and SIGKILL when a client goes away.
const KILL_GRACE: Duration = Duration::from_secs(3);

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
            VaultError::Exists(_)
            | VaultError::Open(_)
            | VaultError::Save(_)
            | VaultError::Io(_) => ErrorCode::Internal,
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
    last_used: Instant,
    remembered: Vec<Remembered>,
}

/// The agent. Create with [`Agent::new`], then call [`Agent::serve`].
pub struct Agent {
    config: AgentConfig,
    ui: Box<dyn Ui>,
    state: Mutex<State>,
    /// Serializes dialogs: the human answers one question at a time.
    dialog: Mutex<()>,
    audit: AuditLog,
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
            }),
            dialog: Mutex::new(()),
            audit,
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
        for connection in listener.incoming() {
            match connection {
                Ok(stream) => {
                    let agent = Arc::clone(self);
                    thread::Builder::new()
                        .name("rusthorse-conn".into())
                        .spawn(move || agent.handle_connection(stream))
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

    fn dialog(&self) -> MutexGuard<'_, ()> {
        self.dialog.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock_if_idle(&self) {
        let mut state = self.state();
        if state.vault.is_some() && state.last_used.elapsed() >= self.config.idle_timeout {
            state.vault = None;
            state.remembered.clear();
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
        let (body, fds) = protocol::recv_frame(stream)?;
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
            other => {
                drop(fds);
                self.dispatch(&peer, other)
            }
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
                {
                    let mut state = self.state();
                    state.vault = None;
                    state.remembered.clear();
                }
                self.record(AuditEvent::new("lock", peer).outcome("requested"))?;
                Ok(ok("vault locked"))
            }
            Request::Unlock => {
                self.ensure_unlocked(peer)?;
                Ok(ok("vault unlocked"))
            }
            Request::List => self.with_vault(peer, |v| Ok(Response::Entries { entries: v.list() })),
            Request::Show { name } => self.with_vault(peer, |v| {
                let id = v.find(&name)?;
                Ok(Response::Entry { entry: v.info(id) })
            }),
            Request::Add {
                entry,
                value,
                replace,
            } => self.add(peer, entry, value, replace),
            Request::Import { entries, replace } => self.import(peer, entries, replace),
            Request::Edit { name, changes } => self.edit(peer, &name, changes),
            Request::Remove { name } => self.remove(peer, &name),
            Request::Reveal { name } => self.reveal(peer, &name),
            Request::Run(_) => Err(Failure::invalid("run requests carry file descriptors")),
        }
    }

    fn status(&self) -> StatusInfo {
        let mut state = self.state();
        let now = Instant::now();
        state.remembered.retain(|r| r.until > now);
        let locked = state.vault.is_none();
        let idle = self.config.idle_timeout;
        StatusInfo {
            protocol_version: protocol::PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            vault: self.config.vault.display().to_string(),
            vault_exists: self.config.vault.exists(),
            locked,
            idle_timeout_secs: idle.as_secs(),
            locks_in_secs: (!locked && !idle.is_zero())
                .then(|| idle.saturating_sub(state.last_used.elapsed()).as_secs()),
            remembered_approvals: state.remembered.len(),
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
        state.last_used = Instant::now();
        let vault = state.vault.as_mut().ok_or_else(|| {
            Failure::new(
                ErrorCode::Locked,
                "the vault was locked while the request was in progress",
            )
        })?;
        f(vault)
    }

    fn ensure_unlocked(&self, peer: &Peer) -> Result<(), Failure> {
        if self.state().vault.is_some() {
            return Ok(());
        }
        if !self.config.vault.exists() {
            return Err(VaultError::Missing(self.config.vault.clone()).into());
        }
        let _dialog = self.dialog();
        if self.state().vault.is_some() {
            return Ok(());
        }
        let base = format!(
            "Unlock the Rusthorse vault\n{}\n\nRequested by: {}",
            self.config.vault.display(),
            peer.describe()
        );
        let mut message = base.clone();
        for attempt in 1..=UNLOCK_ATTEMPTS {
            let prompt = Prompt {
                title: "Rusthorse — unlock vault".into(),
                message: message.clone(),
                confirm: "Unlock".into(),
            };
            let Some(password) = self.ui.master_password(&prompt)? else {
                self.record(AuditEvent::new("unlock", peer).outcome("cancelled"))?;
                return Err(Failure::new(ErrorCode::Cancelled, "unlock cancelled"));
            };
            match Vault::open(&self.config.vault, password) {
                Ok(vault) => {
                    {
                        let mut state = self.state();
                        state.vault = Some(vault);
                        state.last_used = Instant::now();
                    }
                    self.record(AuditEvent::new("unlock", peer).outcome("unlocked"))?;
                    return Ok(());
                }
                Err(VaultError::WrongPassword) => {
                    self.record(AuditEvent::new("unlock", peer).outcome("wrong_password"))?;
                    message = format!(
                        "Wrong password (attempt {attempt} of {UNLOCK_ATTEMPTS}).\n\n{base}"
                    );
                }
                Err(e) => return Err(e.into()),
            }
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
                return self.record(event.outcome("allowed_remembered"));
            }
        }
        let decision = {
            let _dialog = self.dialog();
            self.ui.approve(&request)?
        };
        match decision {
            Decision::Deny => {
                self.record(event.outcome("denied"))?;
                Err(Failure::new(ErrorCode::Denied, "the request was denied"))
            }
            Decision::AllowOnce => self.record(event.outcome("allowed_once")),
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
                _ => self.record(event.outcome("allowed_once")),
            },
        }
    }

    fn ask_value(
        &self,
        peer: &Peer,
        prompt: Prompt,
        event: AuditEvent,
    ) -> Result<SecretString, Failure> {
        let value = {
            let _dialog = self.dialog();
            self.ui.secret_value(&prompt)?
        };
        match value {
            Some(v) if !v.is_empty() => {
                self.record(event.outcome("value_entered"))?;
                Ok(v)
            }
            Some(_) => Err(Failure::invalid("empty value; nothing stored")),
            None => {
                let _ = peer;
                self.record(event.outcome("cancelled"))?;
                Err(Failure::new(ErrorCode::Cancelled, "cancelled"))
            }
        }
    }

    fn add(
        &self,
        peer: &Peer,
        entry: NewEntry,
        value: Option<SecretString>,
        replace: bool,
    ) -> Result<Response, Failure> {
        crate::vault::validate_name(&entry.name)?;
        let exists = self.with_vault(peer, |v| Ok(v.contains(&entry.name)))?;
        if exists && !replace {
            return Err(VaultError::AlreadyExists(entry.name.clone()).into());
        }
        let verb = if exists { "Replace" } else { "Create" };
        let event = AuditEvent::new("add", peer).entries(vec![entry.name.clone()]);
        let value = match value {
            None => {
                let message = format!(
                    "{verb} the entry \"{}\"{}\n{}\nType the secret value, or Cancel.\n\nRequested by: {}",
                    util::visible(&entry.name),
                    if exists {
                        " (the current value will be overwritten)"
                    } else {
                        ""
                    },
                    describe_fields(&entry),
                    peer.describe()
                );
                let prompt = Prompt {
                    title: "Rusthorse — new secret".into(),
                    message,
                    confirm: "Save".into(),
                };
                self.ask_value(peer, prompt, event)?
            }
            Some(value) => {
                let request = ApprovalRequest {
                    title: "Rusthorse — store a secret".into(),
                    summary: format!(
                        "{verb} the entry \"{}\" with a value supplied by the requesting process?",
                        entry.name
                    ),
                    details: vec![
                        ("Entry".into(), entry.name.clone()),
                        ("Fields".into(), describe_fields(&entry)),
                        ("Requested by".into(), peer.describe()),
                    ],
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
        self.with_vault(peer, |v| {
            let replaced = v.add(&entry, &value, replace)?;
            v.save()?;
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
        if entries.is_empty() {
            return Err(Failure::invalid("nothing to import"));
        }
        for item in &entries {
            crate::vault::validate_name(&item.entry.name)?;
        }
        let (new, existing): (Vec<&str>, Vec<&str>) = self.with_vault(peer, |v| {
            let mut new = Vec::new();
            let mut existing = Vec::new();
            for item in &entries {
                if v.contains(&item.entry.name) {
                    existing.push(item.entry.name.as_str());
                } else {
                    new.push(item.entry.name.as_str());
                }
            }
            Ok((new, existing))
        })?;
        let mut details = vec![("New entries".into(), list_names(&new))];
        if !existing.is_empty() {
            let label = if replace {
                "Will be replaced"
            } else {
                "Already exist (skipped)"
            };
            details.push((label.into(), list_names(&existing)));
        }
        details.push(("Requested by".into(), peer.describe()));
        let request = ApprovalRequest {
            title: "Rusthorse — import secrets".into(),
            summary: format!(
                "Import {} secrets supplied by the requesting process?",
                entries.len()
            ),
            details,
            warnings: Vec::new(),
            can_remember: false,
        };
        let names: Vec<String> = entries.iter().map(|e| e.entry.name.clone()).collect();
        self.approve(
            request,
            None,
            AuditEvent::new("import", peer).entries(names),
        )?;
        self.with_vault(peer, |v| {
            let (mut added, mut replaced, mut skipped) = (0, 0, 0);
            for item in &entries {
                match v.add(&item.entry, &item.value, replace) {
                    Ok(true) => replaced += 1,
                    Ok(false) => added += 1,
                    Err(VaultError::AlreadyExists(_)) => skipped += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            v.save()?;
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
        let current = self.with_vault(peer, |v| Ok(v.info(v.find(name)?)))?;
        let event = AuditEvent::new("edit", peer).entries(vec![current.name.clone()]);

        let prompt_for_value = matches!(changes.value, Some(ValueChange::Prompt));
        if changes.touches_metadata() || matches!(changes.value, Some(ValueChange::Provided(_))) {
            let mut details = vec![("Entry".into(), current.name.clone())];
            details.extend(describe_changes(&changes));
            details.push(("Requested by".into(), peer.describe()));
            let request = ApprovalRequest {
                title: "Rusthorse — change an entry".into(),
                summary: format!("Change the entry \"{}\"?", current.name),
                details,
                warnings: Vec::new(),
                can_remember: false,
            };
            self.approve(request, None, event.clone())?;
        }
        let new_value = match changes.value.take() {
            Some(ValueChange::Provided(v)) => Some(v),
            Some(ValueChange::Prompt) if prompt_for_value => {
                let prompt = Prompt {
                    title: "Rusthorse — new value".into(),
                    message: format!(
                        "New value for \"{}\"\nType the secret value, or Cancel.\n\nRequested by: {}",
                        util::visible(&current.name),
                        peer.describe()
                    ),
                    confirm: "Save".into(),
                };
                Some(self.ask_value(peer, prompt, event)?)
            }
            _ => None,
        };
        self.with_vault(peer, |v| {
            let id = v.find(name)?;
            v.edit(id, &changes, new_value.as_ref())?;
            v.save()?;
            Ok(ok(format!(
                "{} updated",
                changes.rename.as_deref().unwrap_or(name)
            )))
        })
    }

    fn remove(&self, peer: &Peer, name: &str) -> Result<Response, Failure> {
        let info = self.with_vault(peer, |v| Ok(v.info(v.find(name)?)))?;
        let request = ApprovalRequest {
            title: "Rusthorse — delete an entry".into(),
            summary: format!("Permanently delete the entry \"{}\"?", info.name),
            details: vec![
                ("Entry".into(), info.name.clone()),
                ("Group".into(), info.group.clone().unwrap_or_else(|| "(root)".into())),
                ("Requested by".into(), peer.describe()),
            ],
            warnings: vec!["This cannot be undone (the previous file is kept as vault.kdbx.bak until the next save).".into()],
            can_remember: false,
        };
        self.approve(
            request,
            None,
            AuditEvent::new("remove", peer).entries(vec![info.name.clone()]),
        )?;
        self.with_vault(peer, |v| {
            let id = v.find(name)?;
            v.remove(id);
            v.save()?;
            Ok(ok(format!("{} deleted", info.name)))
        })
    }

    fn reveal(&self, peer: &Peer, name: &str) -> Result<Response, Failure> {
        let info = self.with_vault(peer, |v| {
            let id = v.find(name)?;
            if v.secret(id).is_none() {
                return Err(Failure::new(
                    ErrorCode::NotFound,
                    format!("{name} has no value"),
                ));
            }
            Ok(v.info(id))
        })?;
        let request = ApprovalRequest {
            title: "Rusthorse — reveal a secret".into(),
            summary: format!(
                "REVEAL the value of \"{}\" to the requesting process?",
                info.name
            ),
            details: vec![
                ("Entry".into(), info.name.clone()),
                ("Requested by".into(), peer.describe()),
            ],
            warnings: vec![
                "The value will be printed by the requesting process. If an AI agent asked, it will see the secret and it may end up in its logs.".into(),
            ],
            can_remember: false,
        };
        self.approve(
            request,
            None,
            AuditEvent::new("reveal", peer).entries(vec![info.name.clone()]),
        )?;
        self.with_vault(peer, |v| {
            let id = v.find(name)?;
            let value = v
                .secret(id)
                .ok_or_else(|| Failure::new(ErrorCode::NotFound, format!("{name} has no value")))?;
            Ok(Response::Secret { value })
        })
    }

    fn run(
        &self,
        stream: &UnixStream,
        peer: &Peer,
        run: RunRequest,
        fds: Vec<OwnedFd>,
    ) -> Result<Response, Failure> {
        let [stdin, stdout, stderr]: [OwnedFd; 3] = fds.try_into().map_err(|_| {
            Failure::invalid("run needs exactly three file descriptors (stdin, stdout, stderr)")
        })?;
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
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str());
        let program =
            exec::resolve_program(&run.argv[0], path_var, &cwd).map_err(Failure::invalid)?;
        let secret_vars: Vec<&str> = run.bindings.iter().map(|b| b.var.as_str()).collect();
        let env = exec::prepare_env(&run.env, &secret_vars);

        // Every entry must exist (and have a value) before the human is asked.
        let entry_names: Vec<String> = self.with_vault(peer, |v| {
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
                    Ok(v.info(id).name)
                })
                .collect()
        })?;

        let mut warnings = Vec::new();
        if !env.removed.is_empty() {
            warnings.push(format!(
                "Removed from the environment: {}",
                env.removed.join(", ")
            ));
        }
        if !env.risky.is_empty() {
            warnings.push(format!(
                "These variables can change what the program executes: {}",
                env.risky
                    .iter()
                    .map(|(k, v)| format!("{k}={}", truncate(v, 60)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !run.redact {
            warnings.push(
                "Output is NOT redacted: secret values printed by the command reach the requester."
                    .into(),
            );
        }
        let command_line = shell_join(&run.argv);
        let request = ApprovalRequest {
            title: "Rusthorse — use a secret".into(),
            summary: "Run this command with the secrets below in its environment?".into(),
            details: vec![
                ("Command".into(), truncate(&command_line, 600)),
                ("Program".into(), program.describe()),
                ("Directory".into(), run.cwd.clone()),
                (
                    "Secrets".into(),
                    run.bindings
                        .iter()
                        .map(|b| format!("{} ← {}", b.var, b.entry))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                (
                    "Output".into(),
                    if run.redact {
                        "secret values are redacted".into()
                    } else {
                        "not redacted".into()
                    },
                ),
                ("Requested by".into(), peer.describe()),
            ],
            warnings,
            can_remember: true,
        };
        if command_line.chars().count() > 600 {
            // Never remember what the human could not fully read.
            let mut request = request;
            request.can_remember = false;
            request
                .warnings
                .push("The command line is too long to show in full.".into());
            self.approve(request, None, run_event(peer, &run, &entry_names))?;
        } else {
            let key = serde_json::to_string(&(
                &run.bindings,
                &run.argv,
                program.canonical.display().to_string(),
                &run.cwd,
                run.redact,
                &env.risky,
            ))
            .map_err(|e| Failure::new(ErrorCode::Internal, e.to_string()))?;
            self.approve(request, Some(key), run_event(peer, &run, &entry_names))?;
        }

        // Fetch the values only now, after approval.
        let secrets: Vec<(String, String, SecretString)> = self.with_vault(peer, |v| {
            run.bindings
                .iter()
                .map(|b| {
                    let id = v.find(&b.entry)?;
                    let value = v.secret(id).ok_or_else(|| {
                        Failure::new(ErrorCode::NotFound, format!("{} has no value", b.entry))
                    })?;
                    Ok((b.var.clone(), v.info(id).name, value))
                })
                .collect()
        })?;

        let mut command = Command::new(&program.canonical);
        command
            .arg0(&run.argv[0])
            .args(&run.argv[1..])
            .current_dir(&cwd)
            .env_clear()
            .envs(env.vars.iter().map(|(k, v)| (k, v)))
            .process_group(0)
            .stdin(Stdio::from(stdin));
        for (var, _, value) in &secrets {
            command.env(var, value.as_str());
        }
        let (out_dest, err_dest) = if run.redact {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            (Some(stdout), Some(stderr))
        } else {
            command
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
            (None, None)
        };
        let mut child = command.spawn().map_err(|e| {
            Failure::new(
                ErrorCode::InvalidRequest,
                format!("cannot start {}: {e}", program.canonical.display()),
            )
        })?;
        drop(command);
        let pgid = Pid::from_raw(child.id() as i32);

        let mut pumps = Vec::new();
        if let (Some(out_dest), Some(err_dest)) = (out_dest, err_dest) {
            let labels: Vec<(String, Vec<u8>)> = secrets
                .iter()
                .map(|(_, entry, value)| (entry.clone(), value.as_bytes().to_vec()))
                .collect();
            let make = || Redactor::new(labels.iter().map(|(l, s)| (l.as_str(), s.as_slice())));
            if let Some(out) = child.stdout.take() {
                let redactor = make();
                pumps.push(thread::spawn(move || pump(out, out_dest, redactor)));
            }
            if let Some(err) = child.stderr.take() {
                let redactor = make();
                pumps.push(thread::spawn(move || pump(err, err_dest, redactor)));
            }
            for (_, mut bytes) in labels {
                zeroize::Zeroize::zeroize(&mut bytes);
            }
        }
        drop(secrets);

        let done = Arc::new(AtomicBool::new(false));
        let watcher = stream.try_clone().ok().map(|s| {
            let done = Arc::clone(&done);
            thread::spawn(move || watch_client(s, pgid, done))
        });
        let status = child.wait();
        done.store(true, Ordering::SeqCst);
        for pump in pumps {
            let _ = pump.join();
        }
        if let Some(watcher) = watcher {
            let _ = watcher.join();
        }
        let status = status.map_err(|e| Failure::new(ErrorCode::Internal, e.to_string()))?;
        let detail = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit code {code}"),
            (None, Some(sig)) => format!("killed by signal {sig}"),
            _ => "unknown exit status".into(),
        };
        let _ = self.audit.record(
            &run_event(peer, &run, &entry_names)
                .outcome("exited")
                .detail(detail),
        );
        Ok(Response::Exited {
            code: status.code(),
            signal: status.signal(),
        })
    }
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

fn list_names(names: &[&str]) -> String {
    const SHOWN: usize = 15;
    if names.is_empty() {
        return "(none)".into();
    }
    let mut text = names
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        text.push_str(&format!(" … and {} more", names.len() - SHOWN));
    }
    text
}

fn describe_fields(entry: &NewEntry) -> String {
    let f = &entry.fields;
    let mut parts = Vec::new();
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
        None => {}
    }
    out
}

/// Copy a child's output to the client's descriptor, redacting secrets.
fn pump(mut from: impl Read, to: OwnedFd, mut redactor: Redactor) {
    let mut to = File::from(to);
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let out = redactor.push(&buf[..n]);
                if write_all_blocking(&mut to, &out).is_err() {
                    // The reader went away. Dropping `from` gives the child
                    // SIGPIPE on its next write, as with a normal pipe.
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = write_all_blocking(&mut to, &redactor.finish());
}

/// `write_all` that also copes with descriptors in non-blocking mode (the
/// client's stdout may be a non-blocking pipe set up by its own parent).
fn write_all_blocking(file: &mut File, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match file.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLOUT)];
                match poll(&mut fds, PollTimeout::from(1000u16)) {
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Kill the command's process group if the client disconnects before it ends.
fn watch_client(stream: UnixStream, pgid: Pid, done: Arc<AtomicBool>) {
    let mut buf = [0u8; 64];
    while !done.load(Ordering::SeqCst) {
        let mut fds = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(200u16)) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => match (&stream).read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = killpg(pgid, Signal::SIGTERM);
                    let deadline = Instant::now() + KILL_GRACE;
                    while Instant::now() < deadline {
                        if done.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                    let _ = killpg(pgid, Signal::SIGKILL);
                    return;
                }
                Ok(_) => {}
            },
            Err(_) => return,
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
