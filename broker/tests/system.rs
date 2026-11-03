//! Full-system tests of the credential broker's phase 1 (ADR 0013, decision
//! 12 and "Tests before real credentials"): everything is real but the
//! person and the destination. The library's agent runs in the test process
//! on temporary paths (vault, socket, audit log), with scripted dialogs; its
//! broker program is a wrapper script that starts the real
//! `rusthorse-broker`, built with its `test-upstream` feature, with the
//! test's certificate authority; the commands are `/bin/sh` scripts that the
//! agent runs; the client is the library's, over the agent's socket; the
//! destination is the fake HTTPS server of `support`, on loopback, reached
//! as `https://localhost:PORT` — the origin of the entry's profile, set
//! through an approved `broker_edit`.
//!
//! A test uses a grant's token as a stolen token would be used: the command
//! writes what it received to a file in the test's directory (or prints it,
//! without redaction), and the test sends requests to the broker's address
//! itself. (One test gives the agent the broker itself, without a wrapper,
//! as a real agent would find it.)
//!
//! Every key is fake (`sk-…-test-…`), nothing leaves the loopback interface
//! and no dialog is shown. The whole file needs the broker's `test-upstream`
//! feature (`cargo test -p rusthorse-broker --all-features`): without it, it
//! compiles to nothing. Tests marked `#[ignore]` show findings fixed on
//! other branches: run them with `--ignored` once those are merged.
//!
//! What the tests need of the machine, besides Linux:
//!
//! - `/bin/sh`, and `env`, `mv`, `cp`, `chmod`, `cat`, `touch`, `head`,
//!   `tr`, `sleep`, `mkdir` and `setsid` (util-linux) in `/usr/bin` or
//!   `/bin`;
//! - `/proc`, with `/proc/PID/stat`, `/proc/PID/task`,
//!   `/proc/PID/task/PID/children` (a kernel built with
//!   `CONFIG_PROC_CHILDREN`, as distributions' are) and `/proc/self/fd`,
//!   where the tests that hold the audit log in a full pipe see the agent's
//!   writer that waits on it ([`AuditPipe::writer_waits`]);
//! - the file of certificate authorities that the broker requires before it
//!   serves anything, even with the test's authority added: the first of
//!   `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`
//!   and `/etc/ssl/ca-bundle.pem` that exists, links resolved, a regular
//!   file owned by root in directories owned by root, none of them writable
//!   by group or others;
//! - a `TMPDIR`, when one is set, short enough for a Unix socket's path
//!   (about 80 characters): the agent's socket lives in each test's
//!   temporary directory.

#![cfg(feature = "test-upstream")]

mod support;

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusthorse::agent::{Agent, AgentConfig};
use rusthorse::broker_profile::{AutomaticLocks, Preset, ProfileRequest};
use rusthorse::broker_protocol::is_well_formed_token;
use rusthorse::client::RunIo;
use rusthorse::protocol::{
    self, Binding, BrokerBinding, BrokerRunRequest, EntryChanges, ErrorCode, GrantInfo, NewEntry,
    Request, Response, RunRequest, SecretString, StatusInfo,
};
use rusthorse::session_lock::{Locker, SCREEN_LOCK, SUSPEND};
use rusthorse::ui::{ApprovalRequest, Decision, Prompt, Typed, Ui};
use rusthorse::vault::{KdfParams, Vault};
use serde_json::Value;
use support::*;

// ===== The harness =====

/// The master password of every vault of these tests (fake).
const PASSWORD: &str = "correct horse battery";

/// The fake key of an OpenAI-compatible entry.
const OPENAI_KEY: &str = "sk-test-0000FAKE0000openai-key-0000";

/// Another fake key.
const OTHER_KEY: &str = "sk-ant-test-1111FAKE1111other-key-1111";

/// How long a test waits for a run to end once its command was told to.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// How long a stream of the destination waits between two events.
const TICK: Duration = Duration::from_millis(50);

/// Answers the agent's dialogs from queues and keeps what it was asked.
#[derive(Default)]
struct ScriptedUi {
    /// Master passwords to type, in order; then the right one.
    passwords: Mutex<VecDeque<String>>,
    /// Answers to approvals, in order; then `Deny`.
    decisions: Mutex<VecDeque<Decision>>,
    /// Every approval asked, in order.
    approvals: Mutex<Vec<ApprovalRequest>>,
    /// How many times the master password was asked.
    unlocks: AtomicUsize,
    /// Runs (once) while the "human" types the next master password.
    on_password: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Ui for ScriptedUi {
    fn master_password(&self, _: &Prompt) -> anyhow::Result<Typed> {
        self.unlocks.fetch_add(1, Ordering::SeqCst);
        let hook = self.on_password.lock().expect("lock").take();
        if let Some(hook) = hook {
            hook();
        }
        let next = self.passwords.lock().expect("lock").pop_front();
        Ok(Typed::Value(SecretString::new(
            next.unwrap_or_else(|| PASSWORD.to_string()),
        )))
    }

    fn secret_value(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(Typed::Cancelled)
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.approvals.lock().expect("lock").push(request.clone());
        let next = self.decisions.lock().expect("lock").pop_front();
        Ok(next.unwrap_or(Decision::Deny))
    }
}

/// Lets the test keep a handle on the dialogs the agent owns. Its dialogs
/// scroll, as `rusthorse-dialog`'s do: the agent sets no height limit.
struct SharedUi(Arc<ScriptedUi>);

impl Ui for SharedUi {
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.0.master_password(prompt)
    }

    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.0.secret_value(prompt)
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.0.approve(request)
    }

    fn limits_height(&self) -> bool {
        false
    }
}

/// What an agent of these tests runs with besides its paths.
#[derive(Clone, Copy)]
struct Settings {
    /// Lock after this much inactivity (zero: never).
    idle_timeout: Duration,
    /// The longest a grant lasts (the agent's hook for tests).
    broker_lifetime: Option<Duration>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_timeout: Duration::ZERO,
            broker_lifetime: None,
        }
    }
}

/// An agent of the library in the test process, serving a vault of its own
/// in a temporary directory, with scripted dialogs; its broker program is
/// the wrapper that [`System::install_broker`] writes. The directory also
/// holds what the commands write. Dropping it ends what the test left
/// going, and waits for it, before the directory is removed (see its
/// `Drop`).
struct System {
    dir: tempfile::TempDir,
    socket: PathBuf,
    audit: PathBuf,
    ui: Arc<ScriptedUi>,
    agent: Arc<Agent>,
    ca: TestCa,
    /// Runs sent and not answered yet.
    runs: Arc<AtomicUsize>,
    /// The lines that the pipes put in place of the audit log took instead
    /// of it ([`AuditPipe`]).
    tapped: Arc<Mutex<Vec<String>>>,
    /// The gates of the outputs held for the test ([`System::start_held`]).
    held: Mutex<Vec<Gate>>,
}

/// The file whose creation ends every command of a test that still waits
/// for its `go` ([`waits`]): [`System`]'s drop creates it.
const STOP: &str = "stop-all";

impl Drop for System {
    /// A test that fails may leave its runs going, their brokers serving,
    /// and the agent with records still to write — which, written after the
    /// directory is removed, would create it again. So, before the
    /// directory goes: the vault is locked, which ends every grant at once
    /// and keeps the idle timer from writing anything later; every command
    /// still waiting is told to end, and every held output let go; and the
    /// drop waits until every run has its answer, no grant is left (their
    /// brokers have exited) and every grant whose creation was recorded has
    /// its end recorded, in the log or in a pipe in its place: a grant's end
    /// is the last record of it that the agent writes, possibly after its
    /// run's answer. It never panics (it may run while a test fails) and
    /// gives up after [`PATIENCE`].
    fn drop(&mut self) {
        let _ = self.call_within(&Request::Lock);
        for gate in self.held.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            gate.open("drain");
        }
        let _ = std::fs::write(self.path(STOP), "");
        let until = Instant::now() + PATIENCE;
        while !self.settled() {
            if Instant::now() >= until {
                eprintln!(
                    "the agent still had work {PATIENCE:?} after the test: something may be left \
                     in {}",
                    self.dir.path().display()
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl System {
    fn new() -> System {
        System::with(Settings::default())
    }

    fn with(settings: Settings) -> System {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = dir.path().join("vault.kdbx");
        Vault::create(
            &vault,
            SecretString::new(PASSWORD.to_string()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create the vault");
        let socket = dir.path().join("run").join("agent.sock");
        let audit = dir.path().join("state").join("audit.jsonl");
        let ui = Arc::new(ScriptedUi::default());
        let config = AgentConfig {
            vault,
            socket: socket.clone(),
            audit_log: audit.clone(),
            idle_timeout: settings.idle_timeout,
            request_timeout: Duration::from_secs(10),
            send_buffer: None,
            // Never the real buses: nothing watches the screen or suspend
            // (the tests lock through `Locker` instead).
            session_lock: rusthorse::session_lock::Settings::default(),
            new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
            keyring: rusthorse::keyring::Settings {
                address: Some("unix:path=/nonexistent/rusthorse-test-bus".into()),
                plain: true,
                ..Default::default()
            },
            // Nothing there until a test writes the wrapper.
            broker_program: Some(dir.path().join("rusthorse-broker")),
            broker_ready_timeout: Some(Duration::from_secs(10)),
            broker_lifetime: settings.broker_lifetime,
        };
        let listener = Agent::bind(&socket).expect("bind the agent's socket");
        let agent = Agent::new(config, Box::new(SharedUi(Arc::clone(&ui))));
        let serving = Arc::clone(&agent);
        std::thread::spawn(move || serving.serve(listener));
        System {
            dir,
            socket,
            audit,
            ui,
            agent,
            ca: TestCa::new(),
            runs: Arc::default(),
            tapped: Arc::default(),
            held: Mutex::default(),
        }
    }

    /// Whether the agent has nothing left to do for the test: no run waits
    /// for its answer, no grant is left, and every grant whose creation was
    /// recorded has its end recorded (see the drop).
    fn settled(&self) -> bool {
        self.runs.load(Ordering::SeqCst) == 0
            && matches!(
                self.call_within(&Request::Grants),
                Some(Response::Grants { grants }) if grants.is_empty()
            )
            && self.unfinished_grants().is_empty()
    }

    /// A request for the drop, which must neither fail nor wait for good:
    /// `None` when the agent cannot be reached or does not answer within
    /// [`PATIENCE`].
    fn call_within(&self, request: &Request) -> Option<Response> {
        let stream = UnixStream::connect(&self.socket).ok()?;
        stream.set_read_timeout(Some(PATIENCE)).ok()?;
        protocol::send_frame(&stream, request, &[]).ok()?;
        protocol::read_message(&stream).ok()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn vault(&self) -> PathBuf {
        self.path("vault.kdbx")
    }

    fn broker_program(&self) -> PathBuf {
        self.path("rusthorse-broker")
    }

    fn client(&self) -> rusthorse::client::Client {
        rusthorse::client::Client::new(self.socket.clone())
    }

    fn call(&self, request: &Request) -> Response {
        self.client()
            .call(request)
            .expect("an answer from the agent")
    }

    /// Queue the human's answers to the next approvals.
    fn decide(&self, decisions: &[Decision]) {
        self.ui
            .decisions
            .lock()
            .expect("lock")
            .extend(decisions.iter().copied());
    }

    fn approvals(&self) -> Vec<ApprovalRequest> {
        self.ui.approvals.lock().expect("lock").clone()
    }

    /// Entries, by name and value, written in the vault file before the
    /// agent opens it.
    fn seed(&self, entries: &[(&str, &str)]) {
        let mut vault =
            Vault::open(&self.vault(), SecretString::new(PASSWORD.into())).expect("open");
        for (name, value) in entries {
            let entry = NewEntry {
                name: name.to_string(),
                ..NewEntry::default()
            };
            vault
                .add(&entry, &SecretString::new(value.to_string()), false)
                .expect("add");
        }
        vault.save().expect("save");
    }

    /// Give `entry` the profile `profile` as the human does: a `broker_edit`,
    /// approved.
    fn set_profile(&self, entry: &str, profile: ProfileRequest) {
        self.decide(&[Decision::AllowOnce]);
        let changes = EntryChanges {
            broker: Some(profile),
            ..EntryChanges::default()
        };
        let response = self.call(&Request::BrokerEdit {
            name: entry.into(),
            changes,
        });
        assert!(
            matches!(response, Response::Ok { .. }),
            "the profile of {entry} was not set: {}",
            describe(&response)
        );
    }

    /// Put a wrapper of the real broker where the agent looks for its
    /// program. The agent starts it with an empty environment; it notes its
    /// process ID in `broker-pids` (`exec` keeps it) and the environment it
    /// was given in `broker-env.PID`, sets the broker's hooks for tests —
    /// this test's authority, `127.0.0.1` for every name — and `extra`, and
    /// becomes the broker, whose standard error it keeps in `broker-stderr`
    /// (fixed text and paths, never a value).
    fn install_broker(&self, extra: &[(&str, &str)]) {
        let script = format!(
            "#!/bin/sh\necho $$ >> {pids}\nenv > {env}.$$\n{exports}exec {broker} 2>> {stderr}\n",
            pids = quote(&self.path("broker-pids")),
            env = quote(&self.path("broker-env")),
            exports = self.broker_exports(extra),
            broker = quote(Path::new(program())),
            stderr = quote(&self.path("broker-stderr")),
        );
        write_program(&self.broker_program(), &script);
    }

    /// Put the real broker itself where the agent looks for its program,
    /// without a wrapper: it runs with the empty environment the agent
    /// gives every broker, so without any hook for tests.
    fn install_bare_broker(&self) {
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "cp \"$1\" \"$2.new\" && chmod 700 \"$2.new\" && mv -f \"$2.new\" \"$2\"",
                "sh",
            ])
            .arg(program())
            .arg(self.broker_program())
            .spawn()
            .expect("sh");
        assert!(child.wait().expect("wait").success(), "cp failed");
    }

    /// The environment the agent gave the broker whose wrapper had process
    /// ID `pid`, as `env` printed it.
    fn broker_env(&self, pid: u32) -> Vec<String> {
        let path = self.path(&format!("broker-env.{pid}"));
        let text = std::fs::read_to_string(&path).expect("the broker's environment");
        text.lines().map(str::to_string).collect()
    }

    /// The exports of a wrapper: the broker's hooks for tests and `extra`.
    fn broker_exports(&self, extra: &[(&str, &str)]) -> String {
        let roots = self.ca.roots();
        let roots = roots.to_str().expect("a path in UTF-8");
        [
            ("RUSTHORSE_BROKER_TEST_ROOTS", roots),
            ("RUSTHORSE_BROKER_TEST_ADDRESSES", "127.0.0.1"),
        ]
        .iter()
        .chain(extra)
        .map(|(name, value)| format!("export {name}={}\n", quote(Path::new(value))))
        .collect()
    }

    /// The process IDs the wrappers noted, in the order they started.
    fn broker_pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.path("broker-pids"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.trim().parse().expect("a process ID"))
            .collect()
    }

    /// A run of `sh -c script` in the test's directory, with redaction.
    fn run_request(
        &self,
        bindings: Vec<Binding>,
        brokered: Vec<BrokerBinding>,
        script: &str,
    ) -> BrokerRunRequest {
        BrokerRunRequest {
            run: RunRequest {
                bindings,
                argv: vec!["sh".into(), "-c".into(), script.into()],
                cwd: self.dir.path().to_str().expect("utf8").into(),
                env: vec![("PATH".into(), "/usr/bin:/bin".into())],
                redact: true,
                forward_stdin: false,
            },
            brokered,
        }
    }

    /// Send a run with redaction from a thread of its own, its output (both
    /// channels) captured.
    fn start(&self, request: BrokerRunRequest) -> Running {
        let output = Captured::default();
        self.start_with(request, Box::new(output.clone()), output)
    }

    /// [`System::start`], but the client takes the command's standard
    /// output only once the test opens `gate` at `drain`: until then it
    /// grants the agent no credit for it, so the agent keeps what the
    /// command printed beyond its window, and the run cannot end.
    fn start_held(&self, request: BrokerRunRequest, gate: Gate) -> Running {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(gate.clone());
        let output = Captured::default();
        let held = HeldOutput {
            gate,
            sink: output.clone(),
        };
        self.start_with(request, Box::new(held), output)
    }

    fn start_with(
        &self,
        request: BrokerRunRequest,
        stdout: Box<dyn Write + Send>,
        output: Captured,
    ) -> Running {
        let client = self.client();
        let io = RunIo {
            input: None,
            stdout,
            stderr: Box::new(output.clone()),
        };
        let (tx, answer) = mpsc::channel();
        let runs = Arc::clone(&self.runs);
        runs.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let result = client
                .broker_run_with(request, io)
                .map_err(|e| format!("{e:#}"));
            // Answered first: a run counted done has its answer there.
            let _ = tx.send(result);
            runs.fetch_sub(1, Ordering::SeqCst);
        });
        Running { answer, output }
    }

    /// Send a run without redaction, as the CLI does — the command gets the
    /// client's descriptors — but with a pipe of the test's as its output
    /// (both channels), never the test process's own.
    fn start_unredacted(&self, mut request: BrokerRunRequest) -> Running {
        request.run.redact = false;
        let (mut from_command, to_command) = std::io::pipe().expect("a pipe");
        let null = std::fs::File::open("/dev/null").expect("/dev/null");
        let stream = UnixStream::connect(&self.socket).expect("connect to the agent");
        protocol::send_frame(
            &stream,
            &Request::BrokerRun(request),
            &[null.as_fd(), to_command.as_fd(), to_command.as_fd()],
        )
        .expect("send the run");
        drop(to_command);
        let output = Captured::default();
        let mut sink = output.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = from_command.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = sink.write_all(&buf[..n]);
            }
        });
        let (tx, answer) = mpsc::channel();
        let runs = Arc::clone(&self.runs);
        runs.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let result = protocol::read_message::<Response>(&stream).map_err(|e| e.to_string());
            let _ = tx.send(result);
            runs.fetch_sub(1, Ordering::SeqCst);
        });
        Running { answer, output }
    }

    /// The environment of the command tagged `tag` (see [`waits`]), once it
    /// has written it; a run that ends first fails the test.
    fn command_env(&self, tag: &str, running: &Running) -> BTreeMap<String, String> {
        let path = self.path(&format!("env-{tag}.txt"));
        let text = eventually("the command to start", || {
            if let Ok(answer) = running.answer.try_recv() {
                panic!("the run ended before its command: {}", outcome(&answer));
            }
            std::fs::read_to_string(&path).ok()
        });
        text.lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Let the command tagged `tag` finish.
    fn go(&self, tag: &str) {
        std::fs::write(self.path(&format!("go-{tag}")), "").expect("go");
    }

    /// Start a command tagged `tag`, approved, with a grant of `entry`: the
    /// token in `ANTHROPIC_API_KEY`, the broker's address in
    /// `ANTHROPIC_BASE_URL`; return it once it runs.
    fn start_grant(&self, entry: &str, tag: &str) -> Started {
        self.decide(&[Decision::AllowOnce]);
        let request = self.run_request(
            vec![],
            vec![brokered(
                "ANTHROPIC_API_KEY",
                entry,
                Some("ANTHROPIC_BASE_URL"),
            )],
            &waits(tag),
        );
        let running = self.start(request);
        let env = self.command_env(tag, &running);
        Started {
            endpoint: endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
            id: self.grant_of(tag),
            running,
        }
    }

    fn grants(&self) -> Vec<GrantInfo> {
        match self.call(&Request::Grants) {
            Response::Grants { grants } => grants,
            other => panic!("no listing: {}", describe(&other)),
        }
    }

    fn grant(&self, id: &str) -> Option<GrantInfo> {
        self.grants().into_iter().find(|g| g.id == id)
    }

    /// The state of the grant `id`; `None` once it has ended.
    fn state(&self, id: &str) -> Option<String> {
        self.grant(id).map(|g| g.state)
    }

    /// The ID of the grant of the command tagged `tag`.
    fn grant_of(&self, tag: &str) -> String {
        let mark = format!("go-{tag} ");
        let found: Vec<GrantInfo> = self
            .grants()
            .into_iter()
            .filter(|g| g.command.contains(&mark))
            .collect();
        assert_eq!(found.len(), 1, "the grants of {tag}: {found:?}");
        found[0].id.clone()
    }

    /// The IDs of the grants of the command tagged `tag`, by their entry's
    /// name.
    fn grants_of(&self, tag: &str) -> BTreeMap<String, String> {
        let mark = format!("go-{tag} ");
        self.grants()
            .into_iter()
            .filter(|g| g.command.contains(&mark))
            .map(|g| {
                let name = g.entry.split(" (").next().unwrap_or_default().to_string();
                (name, g.id)
            })
            .collect()
    }

    fn status(&self) -> StatusInfo {
        match self.call(&Request::Status) {
            Response::Status(info) => info,
            other => panic!("no status: {}", describe(&other)),
        }
    }

    /// Unlock the vault, with the right password.
    fn unlock(&self) {
        let response = self.call(&Request::Unlock);
        assert!(
            matches!(response, Response::Ok { .. }),
            "{}",
            describe(&response)
        );
    }

    /// An approved edit of `entry`.
    fn edit(&self, entry: &str, changes: EntryChanges) {
        self.decide(&[Decision::AllowOnce]);
        let request = if changes.touches_broker() {
            Request::BrokerEdit {
                name: entry.into(),
                changes,
            }
        } else {
            Request::Edit {
                name: entry.into(),
                changes,
            }
        };
        let response = self.call(&request);
        assert!(
            matches!(response, Response::Ok { .. }),
            "{}",
            describe(&response)
        );
    }

    /// Change the vault file as another KeePass client could while the
    /// agent has it locked, and put its modification time back.
    fn change_elsewhere(&self, change: impl FnOnce(&mut Vault)) {
        let path = self.vault();
        let modified = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime");
        let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
        change(&mut vault);
        vault.save().expect("save");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(modified))
            .expect("set the time back");
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }

    fn records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// The `broker_request` records of the grant `id`, in order.
    fn requests_of(&self, id: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["action"] == "broker_request" && r["grant"] == id)
            .collect()
    }

    /// The outcomes recorded for the requests of the grant `id`, by request
    /// number, each request's in the order they were recorded.
    fn outcomes_by_request(&self, id: &str) -> BTreeMap<u64, Vec<String>> {
        let mut outcomes: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for record in self.requests_of(id) {
            let number = record["request"].as_u64().expect("a request number");
            let outcome = record["outcome"].as_str().expect("an outcome");
            outcomes
                .entry(number)
                .or_default()
                .push(outcome.to_string());
        }
        outcomes
    }

    /// The record of the end of the grant `id`, once it is written.
    fn end_of(&self, id: &str) -> Value {
        eventually("the grant's end record", || {
            self.records()
                .into_iter()
                .find(|r| r["action"] == "grant" && r["outcome"] == "ended" && r["grant"] == id)
        })
    }

    /// The records that the agent tried to write while a pipe was in place
    /// of the log, and that failed ([`AuditPipe`]), in order.
    fn tapped_records(&self) -> Vec<Value> {
        self.tapped
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// The end records of grants, by grant ID: those written, and those the
    /// agent tried to write while a pipe was in place of the log.
    fn end_records(&self) -> BTreeMap<String, Value> {
        self.records()
            .into_iter()
            .chain(self.tapped_records())
            .filter(|r| r["action"] == "grant" && r["outcome"] == "ended")
            .filter_map(|r| Some((r["grant"].as_str()?.to_string(), r)))
            .collect()
    }

    /// The record of the end of the grant `id`, once the agent has written
    /// it, or tried to while a pipe was in place of the log.
    fn end_anywhere(&self, id: &str) -> Value {
        eventually("the grant's end record", || self.end_records().remove(id))
    }

    /// The grants whose creation was recorded and whose end is not, in the
    /// log or a pipe in its place, yet. (A creation is recorded only in the
    /// log: one that cannot be written fails the run, and that grant's end
    /// is not recorded.)
    fn unfinished_grants(&self) -> Vec<String> {
        let ended = self.end_records();
        self.records()
            .into_iter()
            .filter(|r| r["action"] == "grant" && r["outcome"] == "created")
            .filter_map(|r| r["grant"].as_str().map(str::to_string))
            .filter(|id| !ended.contains_key(id))
            .collect()
    }

    /// Make the audit log unwritable until the guard is dropped: a pipe in
    /// its place, read at once ([`AuditPipe`]): every record fails, and
    /// nobody waits.
    fn break_audit(&self) -> AuditPipe {
        let mut pipe = AuditPipe::install(&self.audit, Arc::clone(&self.tapped), false);
        pipe.open();
        pipe
    }

    /// Hold the audit log until the test opens the guard: a full pipe in its
    /// place, which nobody reads yet ([`AuditPipe`]). A record waits until
    /// [`AuditPipe::open`] — and every other record of the agent, behind it
    /// — and then fails.
    fn hold_audit(&self) -> AuditPipe {
        AuditPipe::install(&self.audit, Arc::clone(&self.tapped), true)
    }
}

/// A named pipe put in place of the audit log ([`System::break_audit`],
/// [`System::hold_audit`]). A record written to it fails — a pipe cannot be
/// synced — though its text goes through: once the pipe is opened
/// ([`AuditPipe::open`]), a thread reads it, and its lines go to the test
/// and to the system's `tapped`. The test holds the pipe open itself, for
/// reading and writing, from before the pipe is in place: nobody ever waits
/// in opening it, so a writer is always seen ([`AuditPipe::writer_waits`]).
/// Dropping it puts the log back.
struct AuditPipe {
    /// The audit log's path, where the pipe is.
    path: PathBuf,
    /// The log meanwhile: a second name of its file.
    aside: Option<PathBuf>,
    /// The pipe, open for reading and writing, never blocking.
    holder: Option<File>,
    /// The end that the reading thread reads, until it starts.
    reader: Option<File>,
    /// The descriptors of the two.
    own: [RawFd; 2],
    /// The pipe's device and inode.
    file: (u64, u64),
    tapped: Arc<Mutex<Vec<String>>>,
    reading: Option<JoinHandle<()>>,
}

impl AuditPipe {
    /// Put a pipe in place of the log at `path`, filled when `full` says so:
    /// a writer then waits until the pipe is read. The log keeps what it
    /// has, and what a writer that had opened it before writes to it.
    fn install(path: &Path, tapped: Arc<Mutex<Vec<String>>>, full: bool) -> AuditPipe {
        use nix::sys::stat::Mode;
        let fifo = path.with_extension("fifo");
        nix::unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("mkfifo");
        let holder = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(&fifo)
            .expect("open the pipe");
        // A writer is there (the holder): this does not wait either.
        let reader = File::open(&fifo).expect("open the pipe for reading");
        if full {
            fill(&holder);
        }
        let aside = path.with_extension("aside");
        let aside = match std::fs::hard_link(path, &aside) {
            Ok(()) => Some(aside),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => panic!("cannot keep the log aside: {e}"),
        };
        std::fs::rename(&fifo, path).expect("put the pipe in place of the log");
        let meta = holder.metadata().expect("the pipe's metadata");
        AuditPipe {
            path: path.to_path_buf(),
            aside,
            own: [holder.as_raw_fd(), reader.as_raw_fd()],
            file: (meta.dev(), meta.ino()),
            holder: Some(holder),
            reader: Some(reader),
            tapped,
            reading: None,
        }
    }

    /// Read the pipe from now on: the record that waits is written, and
    /// fails; its line, and every later one, arrive on the channel. (Once
    /// only: a later call returns a channel that gets nothing.)
    fn open(&mut self) -> mpsc::Receiver<String> {
        let (tx, lines) = mpsc::channel();
        let Some(reader) = self.reader.take() else {
            return lines;
        };
        let tapped = Arc::clone(&self.tapped);
        self.reading = Some(std::thread::spawn(move || {
            for line in std::io::BufReader::new(reader).lines() {
                let Ok(line) = line else { return };
                if line == "stop" {
                    return;
                }
                // What filled the pipe.
                if line.starts_with('#') {
                    continue;
                }
                tapped
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(line.clone());
                let _ = tx.send(line);
            }
        }));
        lines
    }

    /// Whether a writer other than the test has the pipe open: a record is
    /// being written to it — and, the pipe full, waits until it is read.
    /// (It looks for the pipe among this process's open files.)
    fn writer_waits(&self) -> bool {
        let Ok(fds) = std::fs::read_dir("/proc/self/fd") else {
            return false;
        };
        fds.flatten().any(|fd| {
            let number = fd
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<RawFd>().ok());
            let theirs = number.is_some_and(|n| !self.own.contains(&n));
            theirs && std::fs::metadata(fd.path()).is_ok_and(|m| (m.dev(), m.ino()) == self.file)
        })
    }
}

/// Fill a pipe until a write would wait, with lines of `#` whose length
/// divides a page's: every page of the pipe is then full, so that a record
/// can be added to none and waits for one to be read.
fn fill(mut pipe: &File) {
    let mut junk = [b'#'; 64];
    junk[63] = b'\n';
    // Far more than any pipe's capacity (1 MiB at most by default).
    for _ in 0..(16 << 20) / junk.len() {
        match pipe.write(&junk) {
            Ok(n) => assert_eq!(n, junk.len(), "a pipe took part of a short line"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) => panic!("cannot fill the pipe: {e}"),
        }
    }
    panic!("the pipe never filled");
}

impl Drop for AuditPipe {
    /// Let a waiting record go; put the log back, which every record from
    /// then on goes to; and stop reading once no other writer has the pipe
    /// open (one that opened it before the log was back may still write).
    /// The test's own end stays open for good, so that a writer that found
    /// the pipe just before the log was back never waits in opening it.
    fn drop(&mut self) {
        let _ = self.open();
        match &self.aside {
            Some(aside) => {
                let _ = std::fs::rename(aside, &self.path);
            }
            None => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        let until = Instant::now() + PATIENCE;
        while self.writer_waits() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let Some(holder) = self.holder.take() else {
            return;
        };
        let mut stopped = false;
        while !stopped && Instant::now() < until {
            match (&holder).write(b"stop\n") {
                Ok(_) => stopped = true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        if stopped && let Some(reading) = self.reading.take() {
            let _ = reading.join();
        }
        std::mem::forget(holder);
    }
}

/// A run sent from a thread of its own.
struct Running {
    answer: mpsc::Receiver<Result<Response, String>>,
    output: Captured,
}

impl Running {
    /// The agent's answer, once the run is over.
    fn wait(&self) -> Response {
        match self.answer.recv_timeout(RUN_LIMIT) {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => panic!("the run failed: {e}"),
            Err(_) => panic!("the run did not end within {RUN_LIMIT:?}"),
        }
    }

    /// The command's exit code, once the run is over.
    fn exit_code(&self) -> Option<i32> {
        match self.wait() {
            Response::Exited { code, .. } => code,
            other => panic!("not an exit: {}", describe(&other)),
        }
    }

    /// Whether the run is still going: the agent has not answered.
    fn going(&self) -> bool {
        matches!(self.answer.try_recv(), Err(mpsc::TryRecvError::Empty))
    }
}

/// A run under way with its grant: the command waits for its tag's `go`.
struct Started {
    running: Running,
    endpoint: Endpoint,
    id: String,
}

/// What a command printed, as the client received it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

/// A command's output that the client takes only once `gate` opens at
/// `drain` ([`System::start_held`]), or [`RUN_LIMIT`] has passed: longer
/// than any wait of the test, which fails first.
struct HeldOutput {
    gate: Gate,
    sink: Captured,
}

impl Write for HeldOutput {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if !self.gate.wait_within("drain", RUN_LIMIT) {
            return Err(std::io::Error::other("the test never let the output go"));
        }
        self.sink.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A command that writes its environment to `env-TAG.txt`, all at once,
/// then waits until the test creates `go-TAG`, or the drop of the test's
/// [`System`] creates [`STOP`] (about a minute at most).
fn waits(tag: &str) -> String {
    format!(
        "env > env-{tag}.new && mv env-{tag}.new env-{tag}.txt; i=0; \
         while [ ! -e go-{tag} ] && [ ! -e {STOP} ] && [ $i -lt 1200 ]; do \
         sleep 0.05; i=$((i+1)); done"
    )
}

/// Where the command's grant is reached: the broker's port from the address
/// in `url_var`, the token in `token_var`.
fn endpoint(env: &BTreeMap<String, String>, token_var: &str, url_var: &str) -> Endpoint {
    let url = &env[url_var];
    let port = url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("not the broker's address: {url}"));
    Endpoint {
        port,
        token: env[token_var].clone(),
    }
}

fn brokered(var: &str, entry: &str, url_var: Option<&str>) -> BrokerBinding {
    BrokerBinding {
        var: var.into(),
        entry: entry.into(),
        url_var: url_var.map(str::to_string),
    }
}

fn by_value(var: &str, entry: &str) -> Binding {
    Binding {
        var: var.into(),
        entry: entry.into(),
    }
}

/// An Anthropic profile for `destination`, its other settings the
/// preset's.
fn anthropic(destination: &Destination) -> ProfileRequest {
    ProfileRequest {
        origin: Some(destination.origin()),
        ..ProfileRequest::new(Preset::Anthropic)
    }
}

/// The same, whose grants the automatic locks end.
fn anthropic_ending(destination: &Destination) -> ProfileRequest {
    ProfileRequest {
        automatic_locks: Some(AutomaticLocks::End),
        ..anthropic(destination)
    }
}

/// Owned copies of `list`.
fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// A response as a test message describes it (never a value).
fn describe(response: &Response) -> String {
    match response {
        Response::Error { code, message } => format!("{code:?}: {message}"),
        other => other.kind().to_string(),
    }
}

fn outcome(answer: &Result<Response, String>) -> String {
    match answer {
        Ok(response) => describe(response),
        Err(e) => e.clone(),
    }
}

/// The error of a failed request.
fn error_of(response: &Response) -> (ErrorCode, String) {
    match response {
        Response::Error { code, message } => (*code, message.clone()),
        other => panic!("not an error: {}", other.kind()),
    }
}

/// A path or value in single quotes for `sh`.
fn quote(text: &Path) -> String {
    let text = text.to_str().expect("UTF-8");
    assert!(!text.contains('\''), "{text}");
    format!("'{text}'")
}

/// Write an executable file that only its owner can change, from another
/// process, and put it in place at once: a file this process held open for
/// writing could not be run while a process that another test forked
/// meanwhile still held that descriptor ("Text file busy").
fn write_program(path: &Path, text: &str) {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "cat > \"$1.new\" && chmod 700 \"$1.new\" && mv -f \"$1.new\" \"$1\"",
            "sh",
        ])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("sh");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(text.as_bytes())
        .expect("write");
    assert!(child.wait().expect("wait").success());
}

/// Wait until `f` gives something, within [`PATIENCE`].
fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + PATIENCE;
    loop {
        if let Some(found) = f() {
            return found;
        }
        assert!(Instant::now() < until, "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// For checks that something does NOT happen: time for a request that
/// should not be forwarded to reach the destination if it were.
fn settle() {
    std::thread::sleep(Duration::from_millis(200));
}

/// Whether the process `pid` is gone (or a zombie), within a few seconds.
fn process_gone(pid: u32) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Whether the process `pid` exists and is not a zombie.
fn alive(pid: u32) -> bool {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
            !matches!(stat.get(close + 2), Some(b'Z' | b'X'))
        }
        Err(_) => false,
    }
}

/// The child of the process `pid` (a wrapper that runs the broker without
/// `exec`), once it has one.
fn child_of(pid: u32) -> u32 {
    eventually("the wrapper's child", || {
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .ok()?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// The number of threads of the process `pid`.
fn threads(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/task")).map_or(0, |tasks| tasks.count())
}

/// Fail if any of `secrets` is in `text`, saying where (never the secret).
fn assert_free_of(what: &str, text: &str, secrets: &[&str]) {
    for (n, secret) in secrets.iter().enumerate() {
        assert!(!text.contains(secret), "secret #{n} is in {what}");
    }
}

/// An HTTP response's head and body as text, for [`assert_free_of`]. (In
/// this file `Response` is the agent's.)
fn response_text(response: &support::Response) -> String {
    let mut text = String::new();
    for (name, value) in &response.headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push_str(&response.text());
    text
}

// ----- The destination's side -----

const STREAM_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";

/// A small JSON answer, at once.
fn plain() -> Handler {
    answer(
        200,
        &[("content-type", "application/json")],
        br#"{"type":"message","content":[]}"#,
    )
}

/// The streams of a destination ([`Streams::handler`]). Their events are
/// numbered across every stream, from 0, so that a test can tell the events
/// the destination began to send after a moment from those it began
/// before.
#[derive(Clone, Default)]
struct Streams {
    /// Events begun: each is counted before it is written, and its number
    /// is the count before it.
    sent: Arc<AtomicUsize>,
    /// Streams whose connection the broker closed.
    closed: Arc<AtomicUsize>,
}

impl Streams {
    /// `POST /v1/messages` gets a stream of events, one every [`TICK`],
    /// until the broker closes the connection — counted — or [`RUN_LIMIT`]
    /// passes, longer than any test waits for a cut; anything else gets a
    /// small JSON answer at once.
    fn handler(&self) -> Handler {
        let plain = plain();
        let (sent, closed) = (Arc::clone(&self.sent), Arc::clone(&self.closed));
        Arc::new(move |request, peer| {
            if request.method != "POST" {
                plain(request, peer);
                return;
            }
            if peer.send(STREAM_HEAD).is_err() {
                closed.fetch_add(1, Ordering::SeqCst);
                return;
            }
            let deadline = Instant::now() + RUN_LIMIT;
            while Instant::now() < deadline {
                let n = sent.fetch_add(1, Ordering::SeqCst);
                let event = format!("data: {{\"n\":{n}}}\n\n");
                if peer.chunk(event.as_bytes()).is_err() || peer.closed_within(TICK) {
                    closed.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            }
        })
    }

    /// The events begun so far: every event begun later has this number or
    /// a higher one.
    fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    /// The streams whose connection the broker closed so far.
    fn closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }

    /// Wait until the broker has closed the connections of `count` streams,
    /// and no more.
    fn wait_closed(&self, count: usize) {
        eventually("the destination's connections to close", || {
            (self.closed() >= count).then_some(())
        });
        assert_eq!(self.closed(), count, "more streams were closed");
    }
}

/// The numbers of the events in `text` ([`Streams`]): those whose number
/// arrived whole.
fn event_numbers(text: &str) -> Vec<usize> {
    text.split("\n\n")
        .filter_map(|event| {
            event
                .trim_start()
                .strip_prefix("data: {\"n\":")?
                .strip_suffix('}')?
                .parse()
                .ok()
        })
        .collect()
}

/// Holds each request until the test opens the gate named by its target's
/// last segment — or, for `GET /v1/models?after_id=NAME`, by its query —
/// then answers `200` with that name as the body.
fn held(gate: Gate) -> Handler {
    Arc::new(move |request, peer| {
        let name = match request.target.split_once("?after_id=") {
            Some((_, name)) => name,
            None => request.target.rsplit('/').next().unwrap_or_default(),
        }
        .to_string();
        if !gate.wait(&name) {
            return;
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            name.len()
        );
        let _ = peer.send(head.as_bytes());
        let _ = peer.send(name.as_bytes());
    })
}

// ----- The client's side -----

/// Open a stream through `endpoint` (`POST /v1/messages`), and read its
/// head and first event.
fn open_stream(endpoint: &Endpoint) -> Client {
    let mut client = endpoint.connect();
    client.write(&endpoint.request(
        "POST",
        "/v1/messages",
        &[("content-type", "application/json")],
        b"{}",
    ));
    let (status, _) = client.head();
    assert_eq!(status, 200, "the stream did not open");
    let first = client.chunk().expect("the stream's first event");
    assert!(first.starts_with(b"data: "), "{first:?}");
    client
}

/// The stream was cut, and nothing the destination began to send after its
/// `before`th event reached the client: its connection ends without the
/// body's last chunk, and every event it still delivers — read from the
/// connection after the end was reported done — was begun before.
/// `before` is [`Streams::sent`] once the end was reported done.
fn assert_cut(stream: &mut Client, before: usize) {
    let mut body = Vec::new();
    loop {
        let next = stream.next_chunk(PATIENCE);
        if let Next::Data(data) = &next {
            body.extend_from_slice(data);
        }
        let late = event_numbers(&String::from_utf8_lossy(&body))
            .into_iter()
            .find(|n| *n >= before);
        if let Some(late) = late {
            panic!(
                "event {late}, begun after the end was reported done (at event {before}), \
                 reached the client"
            );
        }
        match next {
            Next::Data(_) => {}
            Next::Closed => return,
            Next::Last => panic!("the stream ended as if complete"),
            Next::Stalled => panic!("the stream stalled without its connection ending"),
        }
    }
}

/// The stream is cut while `waiting` still holds, within `limit`: for an
/// end that nothing reports done (one that must not wait for something
/// else, say).
fn assert_cut_while(stream: &mut Client, limit: Duration, waiting: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    loop {
        match stream.next_chunk(limit) {
            Next::Data(_) => assert!(Instant::now() < until, "the stream went on"),
            Next::Closed => break,
            Next::Last => panic!("the stream ended as if complete"),
            Next::Stalled => panic!("the stream stalled without its connection ending"),
        }
    }
    assert!(waiting(), "the stream was cut only once the wait was over");
}

/// The stream goes on: two more events arrive.
fn assert_goes_on(stream: &mut Client) {
    for _ in 0..2 {
        let event = stream.chunk().expect("the stream was cut");
        assert!(event.starts_with(b"data: "), "{event:?}");
    }
}

/// A plain request through `endpoint` works.
fn assert_works(endpoint: &Endpoint) {
    let response = endpoint.send(&endpoint.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200, "{response:?}");
}

/// The token no longer works: its request gets `403`, or its connection is
/// closed or refused (its broker has gone with its command).
fn assert_refused(endpoint: &Endpoint) {
    let Ok(mut client) = Client::try_connect(endpoint.port) else {
        return;
    };
    if !client.try_write(&endpoint.request("GET", "/v1/models", &[], b"")) {
        return;
    }
    if client.closed_within(Duration::from_secs(5)) {
        return;
    }
    client.response().assert_local(403);
}

/// After an end of the grant: the token is refused, again and again, and
/// nothing more reaches the destination.
fn assert_nothing_more_forwarded(endpoint: &Endpoint, destination: &Destination) {
    let before = destination.connections();
    for _ in 0..3 {
        assert_refused(endpoint);
    }
    settle();
    assert_eq!(
        destination.connections(),
        before,
        "a request reached the destination after the grant ended"
    );
}

// ===== The key =====

/// The key never reaches the command: not its environment, a file it writes
/// from what it received, its output, the broker's error bodies or response
/// headers, `grants`, `status` or the audit log. The destination gets it in
/// exactly one header, the one the broker builds — `x-api-key` for the
/// Anthropic preset, `Authorization: Bearer` for an OpenAI-compatible one
/// — and never the token, even in a header the preset forwards (a
/// `User-Agent` that carries it, an `x-stainless-` header named after it).
/// One run, two grants, two brokers.
#[test]
fn the_key_leaves_only_for_the_destination_in_the_one_header_the_broker_builds() {
    let sys = System::new();
    let destination = Destination::new(
        &sys.ca,
        answer(
            200,
            &[
                ("content-type", "application/json"),
                ("request-id", "req-1"),
            ],
            br#"{"type":"message","content":[]}"#,
        ),
    );
    sys.seed(&[("ANTHROPIC", CREDENTIAL), ("OPENAI", OPENAI_KEY)]);
    sys.set_profile("ANTHROPIC", anthropic(&destination));
    sys.set_profile(
        "OPENAI",
        ProfileRequest {
            origin: Some(destination.origin()),
            ..ProfileRequest::new(Preset::OpenaiCompatible)
        },
    );
    sys.install_broker(&[]);
    sys.decide(&[Decision::AllowOnce]);
    let script = format!(
        "printf 'a=%s o=%s\\n' \"$ANTHROPIC_API_KEY\" \"$OPENAI_API_KEY\"; {}; echo done",
        waits("k")
    );
    let running = sys.start(sys.run_request(
        vec![],
        vec![
            brokered("ANTHROPIC_API_KEY", "ANTHROPIC", Some("ANTHROPIC_BASE_URL")),
            brokered("OPENAI_API_KEY", "OPENAI", Some("OPENAI_BASE_URL")),
        ],
        &script,
    ));
    let env = sys.command_env("k", &running);
    let ids = sys.grants_of("k");
    let first = endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL");
    let second = endpoint(&env, "OPENAI_API_KEY", "OPENAI_BASE_URL");
    assert!(
        env["OPENAI_BASE_URL"].ends_with("/v1"),
        "{}",
        env["OPENAI_BASE_URL"]
    );
    assert!(is_well_formed_token(&first.token) && is_well_formed_token(&second.token));
    assert_ne!(first.token, second.token);
    assert_ne!(first.port, second.port);
    let keys = [CREDENTIAL, OPENAI_KEY];
    let everything = [
        CREDENTIAL,
        OPENAI_KEY,
        first.token.as_str(),
        second.token.as_str(),
    ];
    // The command has tokens, never a key, in everything it received.
    let written = std::fs::read_to_string(sys.path("env-k.txt")).expect("env");
    assert_free_of("the command's environment", &written, &keys);

    // The Anthropic grant: both token headers carry the token; a forwarded
    // header carries it in its value, another in its name. The query, the
    // other headers and the body are the destination's alone: the audit log
    // records the route.
    let body = br#"{"model":"claude-test","max_tokens":1,"note":"body-marker-0000"}"#;
    let user_agent = format!("Anthropic/Python 9.9 {}", first.token);
    let named = format!("x-stainless-{}", first.token);
    let response = first.send(&first.request(
        "POST",
        "/v1/messages?beta=true",
        &[
            ("authorization", &format!("Bearer {}", first.token)),
            ("content-type", "application/json"),
            ("user-agent", &user_agent),
            (&named, "1"),
            ("x-stainless-lang", "python"),
            ("anthropic-beta", "header-marker-0000"),
        ],
        body,
    ));
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, br#"{"type":"message","content":[]}"#);
    assert_free_of("a response", &response_text(&response), &everything);
    let got = destination.wait_for(1)[0].clone();
    assert_eq!(got.target, "/v1/messages?beta=true");
    assert_eq!(got.values("x-api-key"), [CREDENTIAL]);
    assert_eq!(
        carrying(&got, CREDENTIAL),
        1,
        "the key in more than one header"
    );
    assert!(got.values("authorization").is_empty(), "{:?}", got.names());
    assert!(
        got.values("user-agent").is_empty(),
        "the token's user-agent"
    );
    assert!(!got.names().contains(&named), "the header named after it");
    assert_eq!(got.values("x-stainless-lang"), ["python"]);
    assert_eq!(got.values("anthropic-beta"), ["header-marker-0000"]);
    assert_free_of(
        "the destination's request",
        &got.head_text(),
        &[first.token.as_str()],
    );
    assert_eq!(got.body, body);
    assert_eq!(got.sni.as_deref(), Some("localhost"));

    // The OpenAI-compatible grant: the key as a bearer token, after the
    // base path.
    let response = second.send(&second.bearer_request(
        "POST",
        "/v1/chat/completions",
        &[("content-type", "application/json")],
        b"{}",
    ));
    assert_eq!(response.status, 200, "{response:?}");
    assert_free_of("a response", &response_text(&response), &everything);
    let got = destination.wait_for(2)[1].clone();
    assert_eq!(got.target, "/v1/chat/completions");
    assert_eq!(
        got.values("authorization"),
        [format!("Bearer {OPENAI_KEY}")]
    );
    assert_eq!(
        carrying(&got, OPENAI_KEY),
        1,
        "the key in more than one header"
    );
    assert!(got.values("x-api-key").is_empty(), "{:?}", got.names());
    assert_free_of(
        "the destination's request",
        &got.head_text(),
        &[second.token.as_str()],
    );

    // The broker's own answers: neither a key nor a token.
    let other_grants = [(
        "authorization".to_string(),
        format!("Bearer {}", first.token),
    )];
    let refused = [
        first.send(&raw_request("GET", "/v1/models", first.port, &[], b"")),
        first.send(&first.request("POST", "/v1/messages/batches", &[], b"{}")),
        first.send(&first.request("GET", "/v1/models", &[("origin", "https://x.example")], b"")),
        second.send(&raw_request(
            "GET",
            "/v1/models",
            second.port,
            &other_grants,
            b"",
        )),
    ];
    for (response, status) in refused.iter().zip([401, 404, 400, 401]) {
        response.assert_local(status);
        assert_free_of("an error answer", &response_text(response), &everything);
    }
    assert_eq!(destination.connections(), 2);

    // What the agent tells anyone who asks.
    let listing = serde_json::to_string(&sys.grants()).expect("json");
    assert_free_of("the grants", &listing, &everything);
    let status = sys.status();
    assert_eq!(status.grants, Some(2));
    let status = serde_json::to_string(&status).expect("json");
    assert_free_of("the status", &status, &everything);

    sys.go("k");
    assert_eq!(running.exit_code(), Some(0));
    let output = running.output.text();
    assert!(
        output.contains("a=[REDACTED:ANTHROPIC_API_KEY] o=[REDACTED:OPENAI_API_KEY]"),
        "{output}"
    );
    assert!(output.contains("done"), "{output}");
    assert_free_of("the output", &output, &everything);
    // The whole log: each grant's end is its last record.
    for id in ids.values() {
        sys.end_of(id);
    }
    let audit = sys.audit_text();
    assert_free_of("the audit log", &audit, &everything);
    assert!(!audit.contains("rh_"), "a token in the audit log");
    // Each request by its route, never its path, query, headers or body.
    let routes: Vec<Value> = sys
        .requests_of(&ids["ANTHROPIC"])
        .into_iter()
        .map(|r| r["route"].clone())
        .collect();
    assert_eq!(routes, ["POST /v1/messages", "POST /v1/messages"]);
    for marker in ["beta=true", "header-marker", "body-marker"] {
        assert!(!audit.contains(marker), "{marker:?} is in the audit log");
    }
}

/// The headers of a request the destination received whose value carries
/// `secret`.
fn carrying(got: &Received, secret: &str) -> usize {
    got.headers
        .iter()
        .filter(|(_, value)| String::from_utf8_lossy(value).contains(secret))
        .count()
}

/// Without redaction the command's output carries the token as the command
/// printed it, and whoever reads it can use the grant — so the dialog says
/// so (ADR 0013, `--no-redact`) — but never the key, which the command
/// never had.
#[test]
fn an_unredacted_run_shows_its_token_never_the_key_and_its_dialog_warns() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    sys.decide(&[Decision::AllowOnce]);
    let script = format!(
        "printf 'token=%s url=%s\\n' \"$ANTHROPIC_API_KEY\" \"$ANTHROPIC_BASE_URL\"; {}",
        waits("u")
    );
    let running = sys.start_unredacted(sys.run_request(
        vec![],
        vec![brokered(
            "ANTHROPIC_API_KEY",
            "KEY",
            Some("ANTHROPIC_BASE_URL"),
        )],
        &script,
    ));
    // The token, as whoever reads the output reads it (once its line is
    // whole).
    let line = eventually("the command's output", || {
        running
            .output
            .text()
            .split_inclusive('\n')
            .find(|line| line.starts_with("token=") && line.ends_with('\n'))
            .map(str::to_string)
    });
    let (token, url) = line
        .trim_end()
        .strip_prefix("token=")
        .and_then(|rest| rest.split_once(" url="))
        .expect("token and url");
    let mut env = BTreeMap::new();
    env.insert("T".to_string(), token.to_string());
    env.insert("U".to_string(), url.to_string());
    let stolen = endpoint(&env, "T", "U");
    assert!(is_well_formed_token(&stolen.token));
    assert_works(&stolen);
    assert_eq!(destination.wait_for(1)[0].values("x-api-key"), [CREDENTIAL]);
    let id = sys.grant_of("u");

    let asked = sys.approvals().pop().expect("the run's approval");
    assert!(
        asked.warnings.iter().any(|w| w
            == "Output is NOT redacted: a token the command prints reaches the requester, who \
                can use it until its grant ends."),
        "{:?}",
        asked.warnings
    );
    assert!(
        asked
            .facts
            .contains(&("Output".to_string(), "not redacted".to_string())),
        "{:?}",
        asked.facts
    );
    sys.go("u");
    assert_eq!(running.exit_code(), Some(0));
    let output = running.output.text();
    assert!(output.contains(&stolen.token), "the output was redacted");
    assert_free_of("the output", &output, &[CREDENTIAL]);
    // The whole log: the grant's end is its last record.
    sys.end_of(&id);
    assert_free_of(
        "the audit log",
        &sys.audit_text(),
        &[CREDENTIAL, stolen.token.as_str()],
    );
}

// ===== Tokens =====

/// A request is forwarded only with its own grant's token: without one,
/// with one malformed or wrong, with the token of another grant (two runs
/// at once, of one entry), or with two token headers that disagree, it
/// gets `401` and nothing reaches the destination; each grant's own token
/// works on its own broker only.
#[test]
fn requests_without_their_grants_token_get_401_and_reach_nothing() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let b = sys.start_grant("KEY", "b");
    assert_ne!(a.endpoint.token, b.endpoint.token);
    let (token, theirs) = (a.endpoint.token.clone(), b.endpoint.token.clone());
    let wrong = rusthorse::broker_protocol::new_token().to_string();
    let header = |name: &str, value: String| (name.to_string(), value);
    let cases: Vec<(&str, Vec<(String, String)>)> = vec![
        ("missing", vec![]),
        ("empty", vec![header("x-api-key", String::new())]),
        ("short", vec![header("x-api-key", token[..20].to_string())]),
        ("uppercase", vec![header("x-api-key", token.to_uppercase())]),
        (
            "the key itself",
            vec![header("x-api-key", CREDENTIAL.into())],
        ),
        ("wrong", vec![header("x-api-key", wrong.clone())]),
        ("another grant's", vec![header("x-api-key", theirs.clone())]),
        (
            "another grant's, as bearer",
            vec![header("authorization", format!("Bearer {theirs}"))],
        ),
        (
            "right and another grant's",
            vec![
                header("x-api-key", token.clone()),
                header("authorization", format!("Bearer {theirs}")),
            ],
        ),
        (
            "right and wrong",
            vec![
                header("authorization", format!("Bearer {token}")),
                header("x-api-key", wrong.clone()),
            ],
        ),
    ];
    for (why, headers) in &cases {
        let response = a.endpoint.send(&raw_request(
            "POST",
            "/v1/messages",
            a.endpoint.port,
            headers,
            b"{}",
        ));
        assert_eq!(response.status, 401, "{why}: {response:?}");
        response.assert_local(401);
    }
    // A's token on B's broker.
    b.endpoint
        .send(&raw_request(
            "GET",
            "/v1/models",
            b.endpoint.port,
            &[header("x-api-key", token.clone())],
            b"",
        ))
        .assert_local(401);
    settle();
    assert_eq!(destination.connections(), 0, "a request was forwarded");
    // Each token works on its own broker.
    assert_works(&a.endpoint);
    assert_works(&b.endpoint);
    assert_eq!(destination.connections(), 2);
    for (started, refused) in [(&a, cases.len() as u64), (&b, 1)] {
        let grant = sys.grant(&started.id).expect("listed");
        assert_eq!(grant.requests, 1);
        sys.go(if started.id == a.id { "a" } else { "b" });
        assert_eq!(started.running.exit_code(), Some(0));
        let end = sys.end_of(&started.id);
        assert_eq!(
            end["requests"],
            serde_json::json!({"admitted": 1, "finished": 1, "unknown": 0, "refused": refused}),
            "{end}"
        );
    }
}

// ===== Routes and framing =====

/// Requests off the profile's routes or badly framed are refused by the
/// real broker before anything else (B's tests go through the whole list):
/// message batches, an escaped `..`, a foreign `Host`, an `Origin`,
/// `CONNECT`, a request `Transfer-Encoding` (alone and with a length) —
/// nothing is asked of the agent, nothing reaches the destination, and the
/// grant's end counts them.
#[test]
fn requests_off_the_routes_or_badly_framed_are_refused_and_reach_nothing() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    let port = ep.port;
    let key = format!("x-api-key: {}\r\n", ep.token);
    let host = format!("host: 127.0.0.1:{port}\r\n");
    let routes = [
        ("POST", "/v1/messages/batches"),
        ("GET", "/v1/messages/batches/msgbatch_01"),
        ("POST", "/v1/files"),
        ("POST", "/v1/%2e%2e/v1/messages"),
        ("POST", "/v1//messages"),
        ("POST", "/v1/messages;x=1"),
        ("POST", "/v1/messages?beta=true&beta=true"),
    ];
    for (method, target) in routes {
        // Only a POST may carry a body (another is a framing error).
        let body: &[u8] = if method == "POST" { b"{}" } else { b"" };
        ep.send(&ep.request(method, target, &[], body))
            .assert_local(404);
    }
    let framing = [
        format!("GET /v1/models HTTP/1.1\r\nhost: localhost:{port}\r\n{key}\r\n"),
        format!("GET /v1/models HTTP/1.1\r\nhost: api.anthropic.com\r\n{key}\r\n"),
        format!("GET /v1/models HTTP/1.1\r\n{host}{key}origin: https://evil.example\r\n\r\n"),
        format!(
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nhost: api.anthropic.com:443\r\n{key}\r\n"
        ),
        format!("GET http://127.0.0.1:{port}/v1/models HTTP/1.1\r\n{host}{key}\r\n"),
        format!(
            "POST /v1/messages HTTP/1.1\r\n{host}{key}transfer-encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n"
        ),
        format!(
            "POST /v1/messages HTTP/1.1\r\n{host}{key}content-length: 2\r\ntransfer-encoding: chunked\r\n\r\n{{}}"
        ),
    ];
    for raw in &framing {
        let mut client = ep.connect();
        client.write(raw.as_bytes());
        let response = client.response();
        response.assert_local(400);
        assert_eq!(response.header("connection"), Some("close"));
    }
    settle();
    assert_eq!(destination.connections(), 0, "a request was forwarded");
    let grant = sys.grant(&a.id).expect("listed");
    assert_eq!((grant.requests, grant.in_flight), (0, 0));
    assert!(sys.requests_of(&a.id).is_empty(), "a request was admitted");
    // The routes themselves are forwarded.
    assert_works(ep);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    let refused = (routes.len() + framing.len()) as u64;
    assert_eq!(
        sys.end_of(&a.id)["requests"],
        serde_json::json!({"admitted": 1, "finished": 1, "unknown": 0, "refused": refused})
    );
}

// ===== Destination =====

/// The broker reaches the profile's destination and no other, whatever the
/// environments say: `Host` and SNI are the profile's, and ALPN is
/// `http/1.1`, the one protocol the broker offers (the destination would
/// rather have `h2`). The requester's proxy and certificate variables reach
/// the command and not the broker, which the agent starts with nothing of
/// its own either — no variable, `/` as its working directory — and the
/// same variables in the broker's own environment (as if the agent passed
/// them on) change nothing: no proxy is used, the test's authority is still
/// trusted, and a destination whose certificate only the authority they
/// name vouches for is not reached. A redirect reaches the client as `502`
/// without its `Location`, and a compressed response is refused before
/// anything of it reaches the client; both are recorded as sent, with an
/// unknown outcome.
#[test]
fn the_broker_reaches_the_profiles_destination_whatever_the_environment_says() {
    let sys = System::new();
    let handler: Handler = Arc::new(|request, peer| {
        let reply: &[u8] = if request.target.ends_with("/redirect") {
            b"HTTP/1.1 302 Found\r\nlocation: https://elsewhere.example/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        } else if request.target.ends_with("/compressed") {
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\nconnection: close\r\n\r\n\x1f\x8b\x08\x00"
        } else {
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
        };
        let _ = peer.send(reply);
    });
    let destination = Destination::new(&sys.ca, handler);
    // Another authority, which the certificate variables name, and a
    // destination it vouches for.
    let other = TestCa::new();
    let impostor = Destination::new(&other, plain());
    let proxy = Counter::new();
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let roots = other.roots().to_str().expect("utf8").to_string();
    let roots_dir = other
        .roots()
        .parent()
        .and_then(Path::to_str)
        .expect("utf8")
        .to_string();
    let variables: Vec<(&str, &str)> = vec![
        ("HTTPS_PROXY", &proxy_url),
        ("https_proxy", &proxy_url),
        ("HTTP_PROXY", &proxy_url),
        ("http_proxy", &proxy_url),
        ("ALL_PROXY", &proxy_url),
        ("all_proxy", &proxy_url),
        ("SSL_CERT_FILE", &roots),
        ("SSL_CERT_DIR", &roots_dir),
        ("REQUESTS_CA_BUNDLE", &roots),
        ("CURL_CA_BUNDLE", &roots),
        ("NODE_EXTRA_CA_CERTS", &roots),
    ];
    sys.seed(&[("KEY", CREDENTIAL), ("ELSEWHERE", OTHER_KEY)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.set_profile("ELSEWHERE", anthropic(&impostor));
    sys.install_broker(&variables);
    sys.decide(&[Decision::AllowOnce]);
    let mut request = sys.run_request(
        vec![],
        vec![
            brokered("ANTHROPIC_API_KEY", "KEY", Some("ANTHROPIC_BASE_URL")),
            brokered("ELSEWHERE_KEY", "ELSEWHERE", Some("ELSEWHERE_URL")),
        ],
        &waits("a"),
    );
    request.run.env.extend(
        variables
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string())),
    );
    let running = sys.start(request);
    let env = sys.command_env("a", &running);
    // The command got the requester's variables (and no proxy for the
    // broker's address); the brokers, nothing from the agent.
    assert_eq!(env["HTTPS_PROXY"], proxy_url);
    assert_eq!(env["SSL_CERT_FILE"], roots);
    assert_eq!(env["NO_PROXY"], "127.0.0.1");
    let pids = sys.broker_pids();
    assert_eq!(pids.len(), 2, "{pids:?}");
    for pid in pids {
        // Names first, and only names in the message: an environment can
        // hold secrets.
        let given = sys.broker_env(pid);
        let names: Vec<&str> = given
            .iter()
            .map(|line| line.split('=').next().unwrap_or_default())
            .collect();
        assert_eq!(names, ["PWD"], "the agent gave its broker variables");
        assert_eq!(given, ["PWD=/"]);
    }
    let ep = endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL");
    let ids = sys.grants_of("a");
    let id = ids["KEY"].clone();
    assert_works(&ep);
    let got = destination.wait_for(1)[0].clone();
    assert_eq!(
        got.values("host"),
        [format!("localhost:{}", destination.port)]
    );
    assert_eq!(got.sni.as_deref(), Some("localhost"));
    assert_eq!(got.alpn.as_deref(), Some(&b"http/1.1"[..]));

    let response = ep.send(&ep.request("GET", "/v1/models/redirect", &[], b""));
    response.assert_local(502);
    assert_eq!(response.header("location"), None);
    assert_free_of("the answer", &response_text(&response), &["elsewhere"]);
    let response = ep.send(&ep.request("GET", "/v1/models/compressed", &[], b""));
    response.assert_local(502);
    assert_eq!(response.header("content-encoding"), None);
    assert!(!response.body.starts_with(b"\x1f\x8b"), "{response:?}");
    assert_eq!(destination.wait_for(3).len(), 3);

    // The destination that only the variables' authority vouches for: its
    // certificate is refused, and nothing was sent to it.
    let elsewhere = endpoint(&env, "ELSEWHERE_KEY", "ELSEWHERE_URL");
    elsewhere
        .send(&elsewhere.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    assert_eq!(impostor.connections(), 1);
    assert!(impostor.received().is_empty(), "the impostor was trusted");
    assert_eq!(proxy.count(), 0, "a proxy was used");

    sys.go("a");
    assert_eq!(running.exit_code(), Some(0));
    // Each grant's records are all written once its end is.
    for id in ids.values() {
        sys.end_of(id);
    }
    let outcomes: Vec<Value> = sys
        .requests_of(&ids["ELSEWHERE"])
        .into_iter()
        .map(|r| r["outcome"].clone())
        .collect();
    assert_eq!(outcomes, ["admitted", "not_forwarded"]);
    let ends: Vec<(String, Value)> = sys
        .requests_of(&id)
        .into_iter()
        .filter(|r| r["outcome"] != "admitted")
        .map(|r| {
            (
                r["outcome"].as_str().unwrap_or_default().to_string(),
                r["status"].clone(),
            )
        })
        .collect();
    assert_eq!(
        ends,
        [
            ("completed".to_string(), serde_json::json!(200)),
            ("unknown".to_string(), serde_json::json!(302)),
            ("unknown".to_string(), serde_json::json!(200)),
        ]
    );
}

/// A broker built for tests (`test-upstream`) that the agent starts as it
/// starts every broker — with an empty environment, so without the
/// variable that asks for test behaviour — behaves as a release build: it
/// reaches no loopback destination, and sends nothing (the request gets
/// the `502` of a destination that cannot be reached).
#[test]
#[ignore = "P05: fixed in broker-p1-fix-broker; run with --ignored once it is merged"]
fn a_broker_built_for_tests_that_the_agent_starts_reaches_no_loopback_destination() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_bare_broker();
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    ep.send(&ep.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    assert_eq!(
        destination.connections(),
        0,
        "a broker built for tests reached a loopback destination"
    );
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    sys.end_of(&a.id);
    let outcomes: Vec<Value> = sys
        .requests_of(&a.id)
        .into_iter()
        .map(|r| r["outcome"].clone())
        .collect();
    assert_eq!(outcomes, ["admitted", "not_forwarded"]);
}

// ===== Redaction =====

/// The key echoed by the destination is redacted on its way back: in a
/// streamed body where it is split across two chunks (the part before it
/// arrives at once, the rest once the destination sends it), in a body sent
/// with a length (whose `Content-Length` is not passed on: the body is
/// re-chunked), and in a header, which is dropped.
#[test]
fn the_key_echoed_by_the_destination_is_redacted_on_its_way_back() {
    let sys = System::new();
    let gate = Gate::default();
    let (first, rest) = CREDENTIAL.split_at(9);
    let handler: Handler = {
        let gate = gate.clone();
        Arc::new(move |request, peer| {
            if request.method == "POST" {
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nrequest-id: {CREDENTIAL}\r\n\
                     x-request-id: req-7\r\ntransfer-encoding: chunked\r\n\r\n"
                );
                let _ = peer.send(head.as_bytes());
                let _ = peer.chunk(format!("data: {{\"echo\":\"{first}").as_bytes());
                if gate.wait("rest") {
                    let _ = peer.chunk(format!("{rest}\"}}\n\n").as_bytes());
                    let _ = peer.end_chunks();
                }
            } else {
                let body = format!("{{\"echo\":\"{CREDENTIAL}\"}}");
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = peer.send(head.as_bytes());
                let _ = peer.send(body.as_bytes());
            }
        })
    };
    let destination = Destination::new(&sys.ca, handler);
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;

    let mut stream = ep.connect();
    stream.write(&ep.request("POST", "/v1/messages", &[], b"{}"));
    let (status, headers) = stream.head();
    assert_eq!(status, 200);
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(header("request-id"), None, "the header holding the key");
    assert_eq!(header("x-request-id").as_deref(), Some("req-7"));
    // What comes before the key arrives before the rest is sent (however
    // the broker frames it); the part of the key is held back, so nothing
    // more can arrive until then.
    let before = b"data: {\"echo\":\"";
    let mut body = Vec::new();
    while body.len() < before.len() {
        body.extend_from_slice(&stream.chunk().expect("the first part"));
    }
    assert_eq!(body, before);
    gate.open("rest");
    while let Some(chunk) = stream.chunk() {
        if chunk.is_empty() {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    assert_eq!(
        String::from_utf8_lossy(&body),
        "data: {\"echo\":\"[REDACTED:credential]\"}\n\n"
    );

    let response = ep.send(&ep.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200);
    assert!(response.complete);
    assert_eq!(response.header("content-length"), None);
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert_eq!(response.text(), "{\"echo\":\"[REDACTED:credential]\"}");
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
}

// ===== Limits =====

/// With a request limit of N, at most N requests reach the destination
/// however many arrive at once: the agent admits N and refuses the rest
/// with `403`, the grant is exhausted, and the N admitted finish all the
/// same. Refused admissions spend no use: five refused for want of an
/// audit record before them leave all N.
#[test]
fn a_request_limit_of_n_lets_n_through_however_many_arrive_at_once() {
    const LIMIT: u64 = 3;
    const AT_ONCE: usize = 10;
    let sys = System::new();
    let gate = Gate::default();
    let destination = Destination::new(&sys.ca, held(gate.clone()));
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile(
        "KEY",
        ProfileRequest {
            max_requests: Some(LIMIT),
            ..anthropic(&destination)
        },
    );
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = a.endpoint.clone();
    {
        let _broken = sys.break_audit();
        for _ in 0..5 {
            ep.send(&ep.request("GET", "/v1/models/refused", &[], b""))
                .assert_local(503);
        }
    }
    assert_eq!(destination.connections(), 0);

    let barrier = Arc::new(Barrier::new(AT_ONCE));
    let (done, answers) = mpsc::channel();
    let clients: Vec<JoinHandle<()>> = (0..AT_ONCE)
        .map(|_| {
            let (ep, barrier, done) = (ep.clone(), Arc::clone(&barrier), done.clone());
            std::thread::spawn(move || {
                let mut client = ep.connect();
                let raw = ep.request("GET", "/v1/models/all", &[], b"");
                barrier.wait();
                client.write(&raw);
                let _ = done.send(client.response());
            })
        })
        .collect();
    // Those refused are answered while the N admitted are held.
    let refused = AT_ONCE - LIMIT as usize;
    for _ in 0..refused {
        let response = answers.recv_timeout(PATIENCE).expect("an answer");
        response.assert_local(403);
    }
    assert_eq!(destination.wait_for(LIMIT as usize).len(), LIMIT as usize);
    let grant = sys.grant(&a.id).expect("listed");
    assert_eq!(grant.state, "exhausted");
    assert_eq!((grant.requests, grant.in_flight), (LIMIT, LIMIT as u32));
    gate.open("all");
    for _ in 0..LIMIT {
        let response = answers.recv_timeout(PATIENCE).expect("an answer");
        assert_eq!(response.status, 200, "{response:?}");
        assert!(response.complete);
    }
    for client in clients {
        client.join().expect("a client");
    }
    ep.send(&ep.request("GET", "/v1/models/all", &[], b""))
        .assert_local(403);
    settle();
    assert_eq!(destination.connections(), LIMIT as usize);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    let refused = 5 + refused as u64 + 1;
    assert_eq!(
        sys.end_of(&a.id)["requests"],
        serde_json::json!({"admitted": LIMIT, "finished": LIMIT, "unknown": 0, "refused": refused})
    );
    // Only the N admitted were ever recorded as admitted: no request beyond
    // the limit held a use, even for a moment.
    let outcomes: Vec<Value> = sys
        .requests_of(&a.id)
        .into_iter()
        .map(|r| r["outcome"].clone())
        .collect();
    let admitted = outcomes.iter().filter(|o| **o == "admitted").count();
    let completed = outcomes.iter().filter(|o| **o == "completed").count();
    assert_eq!(
        (admitted, completed, outcomes.len()),
        (LIMIT as usize, LIMIT as usize, 2 * LIMIT as usize),
        "{outcomes:?}"
    );
}

/// A grant has at most 16 requests in flight: the 17th gets `429` with
/// `retry-after: 1` and is not forwarded. Refused admissions hold no slot —
/// twenty refused for want of an audit record leave all sixteen — and a
/// request that ends frees its slot. Requests that end in another order
/// than they started are counted by their numbers: the listing and the
/// audit log agree, and each request's end is recorded with its own route.
#[test]
fn requests_in_flight_are_limited_and_counted_by_number_whatever_order_they_end_in() {
    let sys = System::new();
    let gate = Gate::default();
    let destination = Destination::new(&sys.ca, held(gate.clone()));
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    // Twenty admissions refused (requests 1 to 20): nothing forwarded.
    {
        let _broken = sys.break_audit();
        for _ in 0..20 {
            ep.send(&ep.request("GET", "/v1/models/refused", &[], b""))
                .assert_local(503);
        }
    }
    // Sixteen held at the destination (requests 21 to 36), numbered in the
    // order they arrive, of two routes in turn: so that a request's end is
    // recorded with its own route only if the agent frees it by its own
    // number.
    let target = |n: usize| {
        if n % 2 == 1 {
            format!("/v1/models/r{n}")
        } else {
            format!("/v1/models?after_id=r{n}")
        }
    };
    let route = |n: usize| {
        if n % 2 == 1 {
            "GET /v1/models/{id}"
        } else {
            "GET /v1/models"
        }
    };
    let mut clients = Vec::new();
    for n in 1..=16 {
        let mut client = ep.connect();
        client.write(&ep.request("GET", &target(n), &[], b""));
        destination.wait_for(n);
        clients.push(client);
    }
    let grant = sys.grant(&a.id).expect("listed");
    assert_eq!((grant.requests, grant.in_flight), (16, 16));
    // One more is refused by the broker before it is even asked.
    let response = ep.send(&ep.request("GET", "/v1/models/r17", &[], b""));
    response.assert_local(429);
    assert_eq!(response.header("retry-after"), Some("1"));
    settle();
    assert_eq!(destination.connections(), 16);
    // The first ends, and its slot takes another (request 37).
    gate.open("r1");
    assert_eq!(clients[0].response().body, b"r1");
    eventually("its slot to be free", || {
        (sys.grant(&a.id).expect("listed").in_flight == 15).then_some(())
    });
    let mut client = ep.connect();
    client.write(&ep.request("GET", &target(17), &[], b""));
    destination.wait_for(17);
    clients.push(client);
    // The others end last first.
    for n in (2..=17).rev() {
        gate.open(&format!("r{n}"));
        let response = clients[n - 1].response();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, format!("r{n}").as_bytes());
    }
    eventually("every slot to be free", || {
        (sys.grant(&a.id).expect("listed").in_flight == 0).then_some(())
    });
    assert_eq!(sys.grant(&a.id).expect("listed").requests, 17);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    // Its records are all written once its end is.
    assert_eq!(
        sys.end_of(&a.id)["requests"],
        serde_json::json!({"admitted": 17, "finished": 17, "unknown": 0, "refused": 21})
    );
    // Each request by its number and route, as admitted and as ended.
    let records = |outcome: &str| -> Vec<(u64, String)> {
        sys.requests_of(&a.id)
            .into_iter()
            .filter(|r| r["outcome"] == outcome)
            .map(|r| {
                let number = r["request"].as_u64().expect("a number");
                (number, r["route"].as_str().expect("a route").to_string())
            })
            .collect()
    };
    let admitted: Vec<(u64, String)> = (1..=17)
        .map(|n| (20 + n as u64, route(n).to_string()))
        .collect();
    assert_eq!(records("admitted"), admitted);
    let ended: Vec<(u64, String)> = [1]
        .into_iter()
        .chain((2..=17).rev())
        .map(|n| (20 + n as u64, route(n).to_string()))
        .collect();
    assert_eq!(records("completed"), ended);
}

// ===== Revocation =====

/// How a test ends grants.
#[derive(Debug, Clone, Copy)]
enum Ending {
    Lock,
    RevokeOne,
    RevokeAll,
    ScreenLock,
    Suspend,
    ProfileEdit,
    EntryEdit,
}

impl Ending {
    /// Whether it ends every grant of every run: the explicit lock and
    /// revoking every grant do, and so do the automatic locks for grants
    /// whose profile says `end` (both profiles of these tests do then).
    /// Revoking one grant, or changing one entry, ends only that grant, or
    /// that entry's.
    fn ends_every_grant(self) -> bool {
        matches!(
            self,
            Ending::Lock | Ending::RevokeAll | Ending::ScreenLock | Ending::Suspend
        )
    }
}

/// Two runs, each with a grant of an entry of its own and a stream open
/// through it: end grants as `ending` says — for an ending of one grant,
/// the first run's, or its entry's — and check, once the ending is reported
/// done, for each grant it ends: the stream is cut at the client — no event
/// the destination began after that reaches it — and at the destination,
/// the token is refused, nothing more reaches the destination, the stream's
/// end is unknown (it may have reached the destination), and the grant's
/// end says `reason`. The other grant, when the ending is not for it, goes
/// on, its stream too, until its command ends.
fn assert_ending_cuts_streams(ending: Ending, reason: &str) {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL), ("OTHER", OTHER_KEY)]);
    for entry in ["KEY", "OTHER"] {
        let profile = match ending {
            Ending::ScreenLock | Ending::Suspend => anthropic_ending(&destination),
            _ => anthropic(&destination),
        };
        sys.set_profile(entry, profile);
    }
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let b = sys.start_grant("OTHER", "b");
    assert_works(&a.endpoint);
    assert_works(&b.endpoint);
    let mut stream = open_stream(&a.endpoint);
    let mut other = open_stream(&b.endpoint);
    assert_eq!(destination.connections(), 4);
    match ending {
        Ending::Lock => {
            let response = sys.call(&Request::Lock);
            assert!(
                matches!(response, Response::Ok { .. }),
                "{}",
                describe(&response)
            );
        }
        Ending::RevokeOne | Ending::RevokeAll => {
            let id = matches!(ending, Ending::RevokeOne).then(|| a.id.clone());
            let response = sys.call(&Request::RevokeGrant { id });
            assert!(
                matches!(response, Response::Ok { .. }),
                "{}",
                describe(&response)
            );
        }
        Ending::ScreenLock => sys.agent.lock_for(SCREEN_LOCK, "test"),
        Ending::Suspend => sys.agent.lock_for(SUSPEND, "test"),
        Ending::ProfileEdit => sys.edit(
            "KEY",
            EntryChanges {
                broker: Some(ProfileRequest {
                    max_requests: Some(5),
                    ..anthropic(&destination)
                }),
                ..EntryChanges::default()
            },
        ),
        Ending::EntryEdit => sys.edit(
            "KEY",
            EntryChanges {
                username: Some("someone".into()),
                ..EntryChanges::default()
            },
        ),
    }
    // Reported done: the grants it ends have ended, their streams are cut,
    // both ways.
    let before = streams.sent();
    let every = ending.ends_every_grant();
    assert_eq!(sys.state(&a.id).as_deref(), Some("revoked"), "{ending:?}");
    assert_cut(&mut stream, before);
    if every {
        assert_eq!(sys.state(&b.id).as_deref(), Some("revoked"), "{ending:?}");
        assert_cut(&mut other, before);
    }
    streams.wait_closed(if every { 2 } else { 1 });
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    if every {
        assert_nothing_more_forwarded(&b.endpoint, &destination);
    } else {
        assert_eq!(sys.state(&b.id).as_deref(), Some("active"), "{ending:?}");
        assert_goes_on(&mut other);
        assert_works(&b.endpoint);
    }
    for (started, tag) in [(&a, "a"), (&b, "b")] {
        sys.go(tag);
        assert_eq!(started.running.exit_code(), Some(0), "{tag}");
    }
    // The other's stream ends with its command.
    if !every {
        assert_cut(&mut other, streams.sent());
    }
    let ended = |id: &str, reason: &str, plain: u64| {
        let end = sys.end_of(id);
        assert_eq!(end["reason"], reason, "{ending:?}: {end}");
        let admitted = plain + 1;
        assert_eq!(
            end["requests"],
            serde_json::json!({
                "admitted": admitted, "finished": admitted, "unknown": 0, "refused": 0
            }),
            "{ending:?}: {end}"
        );
        // The plain requests completed, and the stream (request 2) ended
        // unknown.
        let mut expected: BTreeMap<u64, Vec<String>> = (1..=admitted)
            .map(|n| (n, strings(&["admitted", "completed"])))
            .collect();
        expected.insert(2, strings(&["admitted", "unknown"]));
        assert_eq!(sys.outcomes_by_request(id), expected, "{ending:?}");
    };
    ended(&a.id, reason, 1);
    if every {
        ended(&b.id, reason, 1);
    } else {
        ended(&b.id, "command_ended", 2);
    }
}

#[test]
fn rusthorse_lock_cuts_the_streams_of_every_run_and_nothing_is_forwarded_after_it() {
    assert_ending_cuts_streams(Ending::Lock, "locked");
}

#[test]
fn revoking_one_grant_by_hand_cuts_its_streams_only_and_nothing_is_forwarded_for_it() {
    assert_ending_cuts_streams(Ending::RevokeOne, "revoked");
}

#[test]
fn revoking_every_grant_by_hand_cuts_the_streams_of_every_run_and_nothing_is_forwarded() {
    assert_ending_cuts_streams(Ending::RevokeAll, "revoked");
}

#[test]
fn a_screen_lock_cuts_the_streams_of_every_grant_whose_profile_says_end() {
    assert_ending_cuts_streams(Ending::ScreenLock, "screen_locked");
}

#[test]
fn a_suspend_cuts_the_streams_of_every_grant_whose_profile_says_end() {
    assert_ending_cuts_streams(Ending::Suspend, "suspend");
}

#[test]
fn a_change_to_the_profile_cuts_its_grants_streams_in_flight_and_no_others() {
    assert_ending_cuts_streams(Ending::ProfileEdit, "entry_changed");
}

#[test]
fn a_change_to_the_entry_cuts_its_grants_streams_in_flight_and_no_others() {
    assert_ending_cuts_streams(Ending::EntryEdit, "entry_changed");
}

/// The screen lock and a suspend keep the grants whose profile says
/// `continue`: their streams go on, and new requests are forwarded while
/// the vault is locked.
#[test]
fn the_automatic_locks_keep_the_grants_whose_profile_says_continue() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let mut stream = open_stream(&a.endpoint);
    for event in [SCREEN_LOCK, SUSPEND] {
        sys.agent.lock_for(event, "test");
        assert!(sys.status().locked, "{event}");
        assert_eq!(sys.state(&a.id).as_deref(), Some("active"), "{event}");
        assert_goes_on(&mut stream);
        assert_works(&a.endpoint);
    }
    assert_eq!(streams.closed(), 0);
    // The command's end ends it: done once the run has answered.
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    assert_cut(&mut stream, streams.sent());
    assert_eq!(sys.end_of(&a.id)["reason"], "command_ended");
}

/// The idle lock ends the grants whose profile says `end`, cutting their
/// streams, and keeps the others, whose requests go on. Requests through
/// the broker do not postpone it (P9): they keep coming through the grant
/// that stays while the idle time runs out.
#[test]
fn the_idle_lock_ends_only_the_grants_whose_profile_says_end() {
    // Long enough for the run to start and its streams to open first.
    let sys = System::with(Settings {
        idle_timeout: Duration::from_secs(6),
        ..Settings::default()
    });
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("ENDS", CREDENTIAL), ("STAYS", OTHER_KEY)]);
    sys.set_profile("ENDS", anthropic_ending(&destination));
    sys.set_profile("STAYS", anthropic(&destination));
    sys.install_broker(&[]);
    sys.decide(&[Decision::AllowOnce]);
    let running = sys.start(sys.run_request(
        vec![],
        vec![
            brokered("ENDS_KEY", "ENDS", Some("ENDS_URL")),
            brokered("STAYS_KEY", "STAYS", Some("STAYS_URL")),
        ],
        &waits("a"),
    ));
    let env = sys.command_env("a", &running);
    let ids = sys.grants_of("a");
    let (ends, stays) = (
        endpoint(&env, "ENDS_KEY", "ENDS_URL"),
        endpoint(&env, "STAYS_KEY", "STAYS_URL"),
    );
    let mut ending = open_stream(&ends);
    let mut staying = open_stream(&stays);
    // Requests go on through the grant that stays — admitted, forwarded and
    // recorded — and the streams flow, until the vault locks itself.
    let mut requests = 0;
    let until = Instant::now() + PATIENCE;
    while !sys.status().locked {
        assert!(
            Instant::now() < until,
            "requests through the broker kept the vault from locking itself"
        );
        assert_works(&stays);
        requests += 1;
        let _ = staying.chunk();
    }
    assert!(requests > 0);
    // Its end is recorded once its broker has confirmed it.
    assert_eq!(sys.end_of(&ids["ENDS"])["reason"], "idle_timeout");
    assert_cut(&mut ending, streams.sent());
    streams.wait_closed(1);
    assert_eq!(sys.state(&ids["STAYS"]).as_deref(), Some("active"));
    assert_goes_on(&mut staying);
    assert_works(&stays);
    let forwarded = destination.connections();
    assert_nothing_more_forwarded(&ends, &destination);
    assert_eq!(forwarded, 2 + requests + 1);
    sys.go("a");
    assert_eq!(running.exit_code(), Some(0));
    assert_eq!(sys.end_of(&ids["STAYS"])["reason"], "command_ended");
}

/// A grant ends when its lifetime passes, with its stream open: the agent's
/// timer revokes it and its broker cuts the stream (the lifetime is
/// shortened through the agent's hook for tests, `broker_lifetime`).
#[test]
fn a_grant_whose_lifetime_passes_cuts_its_streams() {
    let lifetime = Duration::from_secs(6);
    let sys = System::with(Settings {
        broker_lifetime: Some(lifetime),
        ..Settings::default()
    });
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let started = Instant::now();
    let a = sys.start_grant("KEY", "a");
    let mut stream = open_stream(&a.endpoint);
    assert!(
        started.elapsed() < lifetime,
        "the stream opened too late to see the lifetime pass: {:?}",
        started.elapsed()
    );
    // Its end is recorded once its broker has confirmed it.
    assert_eq!(sys.end_of(&a.id)["reason"], "expired");
    assert!(started.elapsed() >= lifetime, "{:?}", started.elapsed());
    assert_cut(&mut stream, streams.sent());
    streams.wait_closed(1);
    assert_eq!(sys.state(&a.id).as_deref(), Some("revoked"));
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    assert!(a.running.going(), "the command was stopped");
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
}

/// An admission waiting for its audit record when the grant is revoked is
/// refused: the revocation does not wait for the audit log — the record is
/// held, the log a full pipe nobody reads yet — and answers the admission
/// at once; the client gets `403`, nothing reaches the destination, and the
/// record, once written, does not admit it.
#[test]
fn an_admission_waiting_for_its_record_is_refused_when_the_grant_is_revoked() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    let mut piped = sys.hold_audit();
    let mut waiting = ep.connect();
    waiting.write(&ep.request("POST", "/v1/messages", &[], b"{}"));
    eventually("the admission's record to wait on the pipe", || {
        piped.writer_waits().then_some(())
    });
    assert_eq!(sys.grant(&a.id).expect("listed").in_flight, 1);
    // Revoked meanwhile: done while the record still waits.
    let (tx, revoked) = mpsc::channel();
    let (client, id) = (sys.client(), a.id.clone());
    std::thread::spawn(move || {
        let response = client.call(&Request::RevokeGrant { id: Some(id) });
        let _ = tx.send(response.map_err(|e| format!("{e:#}")));
    });
    let response = revoked
        .recv_timeout(PATIENCE)
        .expect("the revocation waited for the audit log")
        .expect("an answer");
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        describe(&response)
    );
    assert!(
        piped.writer_waits(),
        "the record was written before the revocation was done"
    );
    if !waiting.closed_within(Duration::from_secs(5)) {
        waiting.response().assert_local(403);
    }
    assert_eq!(destination.connections(), 0, "the request was forwarded");
    // The records are written now (and fail: a pipe cannot be synced); the
    // admission's admits nothing, and the grant's end counts it refused.
    let lines = piped.open();
    let mut written: Vec<Value> = Vec::new();
    let end = eventually("the grant's end record", || {
        written.extend(
            lines
                .try_iter()
                .filter_map(|l| serde_json::from_str(&l).ok()),
        );
        written
            .iter()
            .find(|r| r["action"] == "grant" && r["outcome"] == "ended")
            .cloned()
    });
    let requests: Vec<&Value> = written
        .iter()
        .filter(|r| r["action"] == "broker_request")
        .collect();
    assert_eq!(requests.len(), 1, "{written:?}");
    assert_eq!(requests[0]["outcome"], "admitted");
    assert_eq!(end["reason"], "revoked");
    assert_eq!(
        end["requests"],
        serde_json::json!({"admitted": 0, "finished": 0, "unknown": 0, "refused": 1})
    );
    let grant = sys.grant(&a.id).expect("listed until its command ends");
    assert_eq!((grant.state.as_str(), grant.requests), ("revoked", 0));
    drop(piped);
    settle();
    assert_eq!(destination.connections(), 0, "the request was forwarded");
    assert_nothing_more_forwarded(ep, &destination);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
}

/// The unlock barrier: a grant that survived a lock goes on through an
/// unlock of an unchanged file, through the agent's own save of another
/// entry, and through an unlock that fails, for wrong passwords, after
/// another program changed the file; and it ends, its stream cut, at the
/// unlock that finds the change: another entry's value, or its own entry
/// moved, with the file's modification time put back each time. (A failed
/// unlock that has read the changed file: the next test.)
#[test]
fn grants_that_survive_a_lock_end_at_the_unlock_after_another_program_changed_the_file() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL), ("OTHER", OTHER_KEY)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    // Locked: the grant goes on. Unlocked, the file as the agent read it:
    // it goes on.
    sys.agent.lock_for(SCREEN_LOCK, "test");
    assert_works(&a.endpoint);
    sys.unlock();
    assert_works(&a.endpoint);
    // The agent's own save of another entry, then a lock and an unlock.
    sys.edit(
        "OTHER",
        EntryChanges {
            username: Some("someone".into()),
            ..EntryChanges::default()
        },
    );
    assert_works(&a.endpoint);
    sys.agent.lock_for(SCREEN_LOCK, "test");
    sys.unlock();
    assert_eq!(sys.state(&a.id).as_deref(), Some("active"));
    assert_works(&a.endpoint);

    // Another program changes another entry's value while the vault is
    // locked.
    sys.agent.lock_for(SCREEN_LOCK, "test");
    sys.change_elsewhere(change_the_other_value);
    let mut stream = open_stream(&a.endpoint);
    // A failed unlock finds nothing yet.
    sys.ui.passwords.lock().expect("lock").extend([
        "wrong one".to_string(),
        "wrong two".to_string(),
        "wrong three".to_string(),
    ]);
    let failed = sys.call(&Request::Unlock);
    assert_eq!(error_of(&failed).0, ErrorCode::UnlockFailed);
    assert_eq!(sys.state(&a.id).as_deref(), Some("active"));
    assert_goes_on(&mut stream);
    assert_works(&a.endpoint);
    // The next one finds the change, and ends the grant before it is done.
    sys.unlock();
    let before = streams.sent();
    assert_eq!(sys.state(&a.id).as_deref(), Some("revoked"));
    assert_cut(&mut stream, before);
    streams.wait_closed(1);
    assert_nothing_more_forwarded(&a.endpoint, &destination);

    // Its own entry moved to another group.
    let b = sys.start_grant("KEY", "b");
    assert_works(&b.endpoint);
    let mut stream = open_stream(&b.endpoint);
    sys.agent.lock_for(SCREEN_LOCK, "test");
    sys.change_elsewhere(|vault| {
        let key = vault.find("KEY").expect("find");
        let moved = EntryChanges {
            group: Some("Moved".into()),
            ..EntryChanges::default()
        };
        vault.edit(key, &moved, None).expect("move");
    });
    assert_works(&b.endpoint);
    sys.unlock();
    let before = streams.sent();
    assert_eq!(sys.state(&b.id).as_deref(), Some("revoked"));
    assert_cut(&mut stream, before);
    streams.wait_closed(2);
    assert_nothing_more_forwarded(&b.endpoint, &destination);
    for (started, tag) in [(&a, "a"), (&b, "b")] {
        sys.go(tag);
        assert_eq!(started.running.exit_code(), Some(0));
        assert_eq!(sys.end_of(&started.id)["reason"], "vault_changed", "{tag}");
    }
    let unlocked = sys
        .records()
        .into_iter()
        .filter(|r| r["action"] == "unlock" && r["outcome"] == "unlocked")
        .filter(|r| {
            r["detail"]
                .as_str()
                .is_some_and(|d| d.contains("changed by another program"))
        })
        .count();
    assert_eq!(unlocked, 2, "{}", sys.audit_text());
}

/// Another program's change to the entry `OTHER` while the vault is
/// locked: a new value.
fn change_the_other_value(vault: &mut Vault) {
    let other = vault.find("OTHER").expect("find");
    vault
        .edit(
            other,
            &EntryChanges::default(),
            Some(&SecretString::new(
                "sk-ant-test-2222FAKE2222changed-2222".into(),
            )),
        )
        .expect("change the value");
}

/// The failed unlock that has read the changed file — one that a lock
/// cancels while the password is typed, as the screen locking again does —
/// keeps the fingerprint of the last unlock: the grant that survived the
/// lock goes on through it, its stream too, and the change is still found
/// at the next unlock, which ends the grant and cuts its stream. (A wrong
/// password reads nothing: the barrier test above.)
#[test]
fn an_unlock_cancelled_by_a_lock_keeps_the_last_fingerprint_and_the_next_one_ends_the_grants() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL), ("OTHER", OTHER_KEY)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let mut stream = open_stream(&a.endpoint);
    sys.agent.lock_for(SCREEN_LOCK, "test");
    assert_eq!(sys.state(&a.id).as_deref(), Some("active"));
    sys.change_elsewhere(change_the_other_value);
    // The screen locks again while the password is typed: the agent reads
    // the file, then finds the vault locked meanwhile.
    let agent = Arc::downgrade(&sys.agent);
    *sys.ui.on_password.lock().expect("lock") = Some(Box::new(move || {
        if let Some(agent) = agent.upgrade() {
            agent.lock_for(SCREEN_LOCK, "test");
        }
    }));
    let asked = sys.ui.unlocks.load(Ordering::SeqCst);
    let (code, message) = error_of(&sys.call(&Request::Unlock));
    assert_eq!(code, ErrorCode::Locked, "{message}");
    assert!(
        message.contains("locked while the password was being entered"),
        "{message}"
    );
    assert_eq!(sys.ui.unlocks.load(Ordering::SeqCst), asked + 1);
    assert!(sys.status().locked);
    assert_eq!(sys.state(&a.id).as_deref(), Some("active"));
    assert_goes_on(&mut stream);
    assert_works(&a.endpoint);
    // The next unlock finds the change, and ends the grant before it is
    // done.
    sys.unlock();
    let before = streams.sent();
    assert_eq!(sys.state(&a.id).as_deref(), Some("revoked"));
    assert_cut(&mut stream, before);
    streams.wait_closed(1);
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    assert_eq!(sys.end_of(&a.id)["reason"], "vault_changed");
    let unlocks: Vec<(Value, bool)> = sys
        .records()
        .into_iter()
        .filter(|r| r["action"] == "unlock")
        .map(|r| {
            let found = r["detail"]
                .as_str()
                .is_some_and(|d| d.contains("changed by another program"));
            (r["outcome"].clone(), found)
        })
        .collect();
    assert_eq!(
        unlocks,
        [
            (serde_json::json!("unlocked"), false),
            (serde_json::json!("cancelled_by_lock"), false),
            (serde_json::json!("unlocked"), true),
        ]
    );
}

/// The unlock barrier ends grants without waiting for the audit log (ADR
/// 0013: "Revocation never waits for the audit log"): at the unlock that
/// finds the vault file changed by another program, the stream of a grant
/// that survived the lock is cut while that unlock's own record still
/// waits — the log is a full pipe nobody reads yet. Once the record
/// fails, the unlock fails, and the vault stays locked.
#[test]
#[ignore = "P01: fixed in broker-p1-fix-agent; run with --ignored once it is merged"]
fn the_unlock_barrier_cuts_streams_before_the_unlock_is_recorded() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL), ("OTHER", OTHER_KEY)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let mut stream = open_stream(&a.endpoint);
    sys.agent.lock_for(SCREEN_LOCK, "test");
    sys.change_elsewhere(change_the_other_value);
    let mut piped = sys.hold_audit();
    let (tx, unlocked) = mpsc::channel();
    let client = sys.client();
    std::thread::spawn(move || {
        let _ = tx.send(client.call(&Request::Unlock).map_err(|e| format!("{e:#}")));
    });
    // The change is found and the grant ended; the unlock's record waits.
    eventually("the end of the grant", || {
        (sys.state(&a.id).as_deref() == Some("revoked")).then_some(())
    });
    eventually("the unlock's record to wait on the pipe", || {
        piped.writer_waits().then_some(())
    });
    // Its broker is told and confirms (or is killed) within about a second
    // of the decision: well within this limit, though the record waits.
    assert_cut_while(&mut stream, Duration::from_secs(10), || {
        piped.writer_waits() && matches!(unlocked.try_recv(), Err(mpsc::TryRecvError::Empty))
    });
    streams.wait_closed(1);
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    // The record goes through the pipe and fails: no unlock without it.
    let lines = piped.open();
    let response = unlocked
        .recv_timeout(PATIENCE)
        .expect("the unlock's answer")
        .expect("an answer");
    let (code, message) = error_of(&response);
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("cannot write the audit log"), "{message}");
    let mut written: Vec<Value> = Vec::new();
    let end = eventually("the grant's end record", || {
        written.extend(
            lines
                .try_iter()
                .filter_map(|l| serde_json::from_str(&l).ok()),
        );
        written
            .iter()
            .find(|r| r["action"] == "grant" && r["outcome"] == "ended")
            .cloned()
    });
    assert_eq!(end["reason"], "vault_changed", "{end}");
    drop(piped);
    assert!(
        sys.status().locked,
        "the vault was unlocked without its record"
    );
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
}

// ===== The command's end =====

/// A token stolen from the command stops working as soon as the agent sees
/// the command's leader exit: before its output is drained — the client
/// takes none of it until the test lets it, so the agent holds what is
/// left — and for a descendant that called `setsid`, which escaped the
/// command's process group and lives on with the token.
#[test]
fn a_stolen_token_stops_working_once_the_commands_leader_exits() {
    // More than the output the agent sends before the client takes some
    // (its window, 1 MiB), and less than that and a pipe's buffer: the
    // command can write it all and exit, and the agent keeps the rest.
    const OUTPUT: usize = protocol::INITIAL_CREDIT + 32 * 1024;
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let descendant = sys.path("descendant.sh");
    std::fs::write(
        &descendant,
        format!(
            "echo $$ > descendant.pid\ni=0\n\
             while [ ! -e release ] && [ ! -e {STOP} ] && [ $i -lt 1200 ]; do \
             sleep 0.05; i=$((i+1)); done\n"
        ),
    )
    .expect("write");
    sys.decide(&[Decision::AllowOnce]);
    let script = format!(
        "setsid sh {} > /dev/null 2>&1 & \
         head -c {OUTPUT} /dev/zero | tr '\\0' x; {}; exit 3",
        quote(&descendant),
        waits("a")
    );
    let drain = Gate::default();
    let running = sys.start_held(
        sys.run_request(
            vec![],
            vec![brokered(
                "ANTHROPIC_API_KEY",
                "KEY",
                Some("ANTHROPIC_BASE_URL"),
            )],
            &script,
        ),
        drain.clone(),
    );
    let env = sys.command_env("a", &running);
    let stolen = endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL");
    let id = sys.grant_of("a");
    assert_works(&stolen);
    let pid: u32 = eventually("the descendant", || {
        std::fs::read_to_string(sys.path("descendant.pid"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
    });

    sys.go("a");
    eventually("the end of the grant", || {
        (sys.state(&id).as_deref() == Some("revoked")).then_some(())
    });
    // The output is not drained: the run goes on; the descendant lives.
    assert!(running.going(), "the run ended");
    assert!(alive(pid), "the descendant was stopped");
    assert_nothing_more_forwarded(&stolen, &destination);
    assert!(running.going(), "the run ended");
    drain.open("drain");
    assert_eq!(running.exit_code(), Some(3));
    let output = running.output.text();
    assert_eq!(output.len(), OUTPUT);
    assert!(output.bytes().all(|b| b == b'x'));
    assert!(alive(pid), "the descendant was stopped");
    std::fs::write(sys.path("release"), "").expect("release");
    assert!(process_gone(pid));
    assert_eq!(sys.end_of(&id)["reason"], "command_ended");
}

// ===== Failures =====

/// Without a usable broker program a broker run fails before its dialog —
/// the vault, locked, is not even unlocked — and the key goes nowhere: no
/// grant, no broker, no command, no record of the run. (`run` reports the
/// `internal` error as 125.)
#[test]
fn a_missing_or_unusable_broker_program_fails_the_run_before_its_dialog() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    // A usable profile: only the program stands in the way.
    sys.set_profile("KEY", anthropic(&destination));
    let response = sys.call(&Request::Lock);
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        describe(&response)
    );
    let (unlocks, asked) = (sys.ui.unlocks.load(Ordering::SeqCst), sys.approvals().len());
    let program = sys.broker_program();
    let marker = sys.path("ran");
    let script = format!("touch {}", quote(&marker));
    let request = || {
        sys.run_request(
            vec![],
            vec![brokered("ANTHROPIC_API_KEY", "KEY", None)],
            &script,
        )
    };
    let refused = |says: &str| {
        let response = sys.start(request()).wait();
        let (code, message) = error_of(&response);
        assert_eq!(code, ErrorCode::Internal, "{message}");
        assert!(message.contains(says), "{says:?} not in: {message}");
        assert!(message.contains("nothing was run"), "{message}");
        assert_free_of("the error", &message, &[CREDENTIAL]);
    };
    // Had it been asked, the human would have allowed it.
    sys.decide(&[Decision::AllowOnce]);
    refused("not installed");
    sys.install_broker(&[]);
    for (mode, says) in [(0o775, "chmod go-w"), (0o600, "is not executable")] {
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(mode)).expect("chmod");
        refused(says);
    }
    std::fs::remove_file(&program).expect("rm");
    std::fs::create_dir(&program).expect("mkdir");
    refused("is not a regular file");
    assert_eq!(
        sys.ui.unlocks.load(Ordering::SeqCst),
        unlocks,
        "the vault was unlocked"
    );
    assert!(sys.status().locked);
    assert_eq!(sys.approvals().len(), asked, "the human was asked");
    assert!(!marker.exists(), "the command ran");
    assert!(sys.broker_pids().is_empty(), "a broker was started");
    assert!(sys.grants().is_empty());
    let records = sys.records();
    assert!(
        records
            .iter()
            .all(|r| r["action"] != "run" && r["action"] != "grant"),
        "{}",
        sys.audit_text()
    );
    assert_free_of("the audit log", &sys.audit_text(), &[CREDENTIAL]);
    assert_eq!(destination.connections(), 0);
    let status = sys.status();
    assert!(
        status
            .broker
            .as_deref()
            .is_some_and(|b| b.starts_with("none: ")),
        "{:?}",
        status.broker
    );
}

/// One broker of a run that does not start serving fails the whole run
/// before its command starts: the other broker, started too, is stopped
/// (whether it was ready yet or not), none of the run's grants remains,
/// the key is in no error, and the approval's record is followed by one
/// that says why nothing ran.
#[test]
fn a_run_whose_second_broker_fails_to_start_keeps_none_of_its_grants() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("A", CREDENTIAL), ("B", OTHER_KEY)]);
    sys.set_profile("A", anthropic(&destination));
    sys.set_profile("B", anthropic(&destination));
    // Each wrapper notes its process ID first; then the first to get there
    // becomes the broker, and the other exits. (Noted first: the agent
    // stops the whole run as soon as one fails, perhaps before the other
    // got any further.)
    let script = format!(
        "#!/bin/sh\necho $$ >> {pids}\nif /bin/mkdir {first} 2>/dev/null; then\n{exports}exec {broker}\nfi\nexit 7\n",
        first = quote(&sys.path("first-broker")),
        pids = quote(&sys.path("broker-pids")),
        exports = sys.broker_exports(&[]),
        broker = quote(Path::new(program())),
    );
    write_program(&sys.broker_program(), &script);
    sys.decide(&[Decision::AllowOnce]);
    let marker = sys.path("ran");
    let response = sys
        .start(sys.run_request(
            vec![],
            vec![
                brokered("KEY_A", "A", Some("URL_A")),
                brokered("KEY_B", "B", Some("URL_B")),
            ],
            &format!("touch {}", quote(&marker)),
        ))
        .wait();
    let (code, message) = error_of(&response);
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("could not serve a grant"), "{message}");
    assert!(message.contains("nothing was run"), "{message}");
    // Why, as the agent saw it: the wrapper exits without reading its
    // install, so the agent finds its channel gone — when it sends the
    // install, or when it reads the answer (the unread install makes that a
    // reset) — rather than an end it could report with the exit status.
    assert!(
        ["Broken pipe", "Connection reset", "exit status 7"]
            .iter()
            .any(|why| message.contains(why)),
        "{message}"
    );
    assert_free_of("the error", &message, &[CREDENTIAL, OTHER_KEY]);
    assert!(!marker.exists(), "the command ran");
    assert!(sys.grants().is_empty(), "a grant remains");
    let pids = sys.broker_pids();
    assert_eq!(pids.len(), 2, "{pids:?}");
    for pid in pids {
        assert!(process_gone(pid), "a broker of the run was left");
    }
    // The end of the grant whose broker never served is recorded before
    // the answer; that of the other, by the thread that read its broker,
    // perhaps after it (best effort).
    let ends: Vec<Value> = eventually("both grants' end records", || {
        let ends: Vec<Value> = sys
            .records()
            .into_iter()
            .filter(|r| r["action"] == "grant" && r["outcome"] == "ended")
            .collect();
        (ends.len() >= 2).then_some(ends)
    });
    assert_eq!(ends.len(), 2, "{ends:?}");
    assert!(
        ends.iter().all(|e| e["reason"] == "broker_failed"),
        "{ends:?}"
    );
    let runs: Vec<Value> = sys
        .records()
        .into_iter()
        .filter(|r| r["action"] == "run")
        .map(|r| r["outcome"].clone())
        .collect();
    assert_eq!(runs, ["allowed_once", "aborted"]);
    assert_free_of("the audit log", &sys.audit_text(), &[CREDENTIAL, OTHER_KEY]);
    assert_eq!(destination.connections(), 0);
}

/// A broker that dies while a request is at the destination leaves that
/// request's outcome unknown (admitted, never finished), its grant ends
/// (`broker_failed`), the token gets no answer any more — the agent holds
/// the port until the command ends — and the run's status is still the
/// command's.
#[test]
fn a_broker_killed_mid_request_leaves_an_unknown_outcome_and_the_commands_status() {
    let sys = System::new();
    let gate = Gate::default();
    let destination = Destination::new(&sys.ca, held(gate.clone()));
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    sys.decide(&[Decision::AllowOnce]);
    let running = sys.start(sys.run_request(
        vec![],
        vec![brokered(
            "ANTHROPIC_API_KEY",
            "KEY",
            Some("ANTHROPIC_BASE_URL"),
        )],
        &format!("{}; exit 7", waits("a")),
    ));
    let env = sys.command_env("a", &running);
    let ep = endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL");
    let id = sys.grant_of("a");
    let mut client = ep.connect();
    client.write(&ep.request("GET", "/v1/models/held", &[], b""));
    destination.wait_for(1);
    let pids = sys.broker_pids();
    assert_eq!(pids.len(), 1, "{pids:?}");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pids[0] as i32),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("kill the broker");
    assert!(
        client.closed_within(PATIENCE),
        "the client's connection stayed open"
    );
    let end = sys.end_of(&id);
    assert_eq!(end["reason"], "broker_failed", "{end}");
    assert_eq!(
        end["requests"],
        serde_json::json!({"admitted": 1, "finished": 0, "unknown": 1, "refused": 0})
    );
    let outcomes: Vec<Value> = sys
        .requests_of(&id)
        .into_iter()
        .map(|r| r["outcome"].clone())
        .collect();
    assert_eq!(outcomes, ["admitted"]);
    assert!(sys.grant(&id).is_none(), "the grant is still listed");
    // Nobody answers on the port any more: the agent holds it, so that no
    // other program takes it while the command may use it.
    gate.open("held");
    let mut late = ep.connect();
    late.write(&ep.request("GET", "/v1/models/late", &[], b""));
    assert!(
        !late.closed_within(Duration::from_millis(300)),
        "the port was let go"
    );
    settle();
    assert_eq!(destination.connections(), 1);
    assert!(running.going());
    sys.go("a");
    assert_eq!(running.exit_code(), Some(7));
}

/// A broker that cannot confirm a revocation — stopped, it reads nothing —
/// is killed, and the revocation is done all the same, within about a
/// second (ADR 0013: a broker that does not confirm within one second is
/// killed): the broker is gone, the token gets no answer any more — the
/// agent holds the port until the command ends — and nothing more reaches
/// the destination.
#[test]
fn a_broker_that_does_not_confirm_a_revocation_is_killed_and_the_revocation_is_done() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    assert_works(&a.endpoint);
    // Its end reported (the client may have its answer first).
    eventually("the request's end to be recorded", || {
        sys.requests_of(&a.id)
            .iter()
            .any(|r| r["outcome"] == "completed")
            .then_some(())
    });
    let pids = sys.broker_pids();
    assert_eq!(pids.len(), 1, "{pids:?}");
    let broker = nix::unistd::Pid::from_raw(pids[0] as i32);
    nix::sys::signal::kill(broker, nix::sys::signal::Signal::SIGSTOP).expect("stop the broker");
    let started = Instant::now();
    let response = sys.call(&Request::RevokeGrant {
        id: Some(a.id.clone()),
    });
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        describe(&response)
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the revocation waited {:?}",
        started.elapsed()
    );
    assert!(process_gone(pids[0]), "the broker was not killed");
    // Its grant ends once the agent sees its channel end.
    eventually("the grant to end", || {
        sys.state(&a.id).is_none().then_some(())
    });
    let mut late = a.endpoint.connect();
    late.write(&a.endpoint.request("GET", "/v1/models", &[], b""));
    assert!(
        !late.closed_within(Duration::from_millis(300)),
        "the port was let go"
    );
    settle();
    assert_eq!(destination.connections(), 1);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    let end = sys.end_of(&a.id);
    assert_eq!(end["reason"], "revoked", "{end}");
    assert_eq!(
        end["requests"],
        serde_json::json!({"admitted": 1, "finished": 1, "unknown": 0, "refused": 0})
    );
}

/// A broker exits by itself once its control channel ends, even with a name
/// resolution hanging: at the end of the run the agent ends the
/// conversation, and the broker — its wrapper waits for it here, and notes
/// its exit status — exits with status 0, well before the resolution would
/// end; the request it held ends `revoked`, never sent.
#[test]
fn a_broker_exits_by_itself_once_its_channel_ends_even_with_a_resolution_hanging() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    let exit = sys.path("broker-exit");
    // Each resolution hangs for a minute, and the deadline of resolving and
    // connecting is longer still: only the end of the channel can stop it.
    let hooks = [
        ("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "60000"),
        ("RUSTHORSE_BROKER_TEST_TIMEOUTS", "connect=120000"),
    ];
    let script = format!(
        "#!/bin/sh\necho $$ >> {pids}\n{exports}{broker} 2>> {stderr}\necho $? > {exit}\n",
        pids = quote(&sys.path("broker-pids")),
        exports = sys.broker_exports(&hooks),
        broker = quote(Path::new(program())),
        stderr = quote(&sys.path("broker-stderr")),
        exit = quote(&exit),
    );
    write_program(&sys.broker_program(), &script);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    let mut client = ep.connect();
    client.write(&ep.request("GET", "/v1/models", &[], b""));
    eventually("the request to be admitted", || {
        sys.requests_of(&a.id)
            .iter()
            .any(|r| r["outcome"] == "admitted")
            .then_some(())
    });
    // The broker's only thread besides its own is the resolution's.
    let broker = child_of(sys.broker_pids()[0]);
    eventually("the resolution to start", || {
        (threads(broker) >= 2).then_some(())
    });
    let ended = Instant::now();
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    assert!(
        ended.elapsed() < Duration::from_secs(10),
        "{:?}",
        ended.elapsed()
    );
    // Its wrapper noted its exit status: had the agent had to kill it, the
    // wrapper would have been killed with it, before noting anything.
    let status = std::fs::read_to_string(&exit).expect("the broker's exit status");
    assert_eq!(status.trim(), "0", "the broker did not exit by itself");
    assert!(process_gone(broker));
    if !client.closed_within(Duration::from_secs(5)) {
        client.response().assert_local(403);
    }
    assert_eq!(destination.connections(), 0);
    assert_eq!(sys.end_of(&a.id)["reason"], "command_ended");
    let outcomes: Vec<Value> = sys
        .requests_of(&a.id)
        .into_iter()
        .map(|r| r["outcome"].clone())
        .collect();
    assert_eq!(outcomes, ["admitted", "revoked"]);
}

// ===== Audit =====

/// An admission whose record cannot be written is refused (`503`, which
/// the client may retry): nothing reaches the destination, and the use is
/// not spent. With the log back, the next request is forwarded.
#[test]
fn an_admission_that_cannot_be_recorded_is_not_forwarded() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile(
        "KEY",
        ProfileRequest {
            max_requests: Some(1),
            ..anthropic(&destination)
        },
    );
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    {
        let _broken = sys.break_audit();
        let response = a
            .endpoint
            .send(&a.endpoint.request("POST", "/v1/messages", &[], b"{}"));
        response.assert_local(503);
        assert_eq!(response.header("retry-after"), None);
        settle();
        assert_eq!(destination.connections(), 0, "the request was forwarded");
        assert_eq!(sys.grant(&a.id).expect("listed").requests, 0);
    }
    assert_works(&a.endpoint);
    assert_eq!(destination.connections(), 1);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    assert_eq!(
        sys.end_of(&a.id)["requests"],
        serde_json::json!({"admitted": 1, "finished": 1, "unknown": 0, "refused": 1})
    );
}

/// A request whose end cannot be recorded ends its grant (`audit_failed`):
/// the client got its whole answer, but the grant admits nothing more — new
/// requests get `403` and nothing more reaches the destination. (The log is
/// a full pipe, read once the client has its answer: the records fail, a
/// pipe cannot be synced, but their text still comes through, the end
/// record's with its reason.)
#[test]
fn a_finished_record_that_cannot_be_written_ends_the_grant() {
    let sys = System::new();
    let gate = Gate::default();
    let destination = Destination::new(&sys.ca, held(gate.clone()));
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let ep = &a.endpoint;
    let mut client = ep.connect();
    client.write(&ep.request("GET", "/v1/models/held", &[], b""));
    destination.wait_for(1);
    let mut piped = sys.hold_audit();
    gate.open("held");
    let response = client.response();
    assert_eq!(
        (response.status, response.body.as_slice()),
        (200, &b"held"[..])
    );
    // The record of its end fails.
    let lines = piped.open();
    eventually("the end of the grant", || {
        (sys.state(&a.id).as_deref() == Some("revoked")).then_some(())
    });
    assert_nothing_more_forwarded(ep, &destination);
    let mut written: Vec<Value> = Vec::new();
    let end = eventually("the grant's end record", || {
        written.extend(
            lines
                .try_iter()
                .filter_map(|l| serde_json::from_str(&l).ok()),
        );
        written
            .iter()
            .find(|r| r["action"] == "grant" && r["outcome"] == "ended")
            .cloned()
    });
    assert_eq!(end["reason"], "audit_failed", "{end}");
    // (Whether the requests refused after the decision count depends on
    // whether they reached the broker before its revocation.)
    let counts = &end["requests"];
    assert_eq!(
        (&counts["admitted"], &counts["finished"], &counts["unknown"]),
        (
            &serde_json::json!(1),
            &serde_json::json!(1),
            &serde_json::json!(0)
        ),
        "{end}"
    );
    drop(piped);
    assert_nothing_more_forwarded(ep, &destination);
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
}

/// Revocation does not need the audit log: with the log unwritable, a
/// grant revoked by hand and the others by `rusthorse lock` end, their
/// streams cut and nothing more forwarded — the lock is done though its
/// own record cannot be written, which its answer reports.
#[test]
fn revocation_works_while_the_audit_log_cannot_be_written() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("A", CREDENTIAL), ("B", OTHER_KEY)]);
    sys.set_profile("A", anthropic(&destination));
    sys.set_profile("B", anthropic(&destination));
    sys.install_broker(&[]);
    sys.decide(&[Decision::AllowOnce]);
    let running = sys.start(sys.run_request(
        vec![],
        vec![
            brokered("KEY_A", "A", Some("URL_A")),
            brokered("KEY_B", "B", Some("URL_B")),
        ],
        &waits("a"),
    ));
    let env = sys.command_env("a", &running);
    let ids = sys.grants_of("a");
    let (a, b) = (
        endpoint(&env, "KEY_A", "URL_A"),
        endpoint(&env, "KEY_B", "URL_B"),
    );
    let mut stream_a = open_stream(&a);
    let mut stream_b = open_stream(&b);
    let broken = sys.break_audit();
    let response = sys.call(&Request::RevokeGrant {
        id: Some(ids["A"].clone()),
    });
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        describe(&response)
    );
    let before = streams.sent();
    assert_eq!(sys.state(&ids["A"]).as_deref(), Some("revoked"));
    assert_cut(&mut stream_a, before);
    streams.wait_closed(1);
    assert_nothing_more_forwarded(&a, &destination);
    assert_goes_on(&mut stream_b);
    let response = sys.call(&Request::Lock);
    let before = streams.sent();
    let (code, message) = error_of(&response);
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("cannot write the audit log"), "{message}");
    assert!(sys.status().locked);
    assert_eq!(sys.state(&ids["B"]).as_deref(), Some("revoked"));
    assert_cut(&mut stream_b, before);
    streams.wait_closed(2);
    assert_nothing_more_forwarded(&b, &destination);
    drop(broken);
    sys.go("a");
    assert_eq!(running.exit_code(), Some(0));
    // Each grant's end says why, whether its record could be written then
    // or not.
    assert_eq!(sys.end_anywhere(&ids["A"])["reason"], "revoked");
    assert_eq!(sys.end_anywhere(&ids["B"])["reason"], "locked");
}

// ===== Protocol =====

/// A mixed run gets the values of the entries it binds by value and tokens
/// for those it uses through the broker, in one approval; its output
/// redacts both. The same entry both ways is refused before any dialog.
#[test]
fn a_mixed_run_gets_values_and_tokens_and_one_entry_cannot_be_both() {
    let sys = System::new();
    let destination = Destination::new(&sys.ca, plain());
    sys.seed(&[("KEY", CREDENTIAL), ("PLAIN", "plain-value-0000")]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let asked = sys.approvals().len();
    let response = sys
        .start(sys.run_request(
            vec![by_value("VALUE", "KEY")],
            vec![brokered("ANTHROPIC_API_KEY", "KEY", None)],
            "true",
        ))
        .wait();
    let (code, message) = error_of(&response);
    assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
    assert!(message.contains("both"), "{message}");
    assert_eq!(sys.approvals().len(), asked, "the human was asked");
    assert!(sys.grants().is_empty());

    sys.decide(&[Decision::AllowOnce]);
    let script = format!(
        "printf 'v=%s t=%s\\n' \"$VALUE\" \"$ANTHROPIC_API_KEY\"; {}",
        waits("m")
    );
    let running = sys.start(sys.run_request(
        vec![by_value("VALUE", "PLAIN")],
        vec![brokered(
            "ANTHROPIC_API_KEY",
            "KEY",
            Some("ANTHROPIC_BASE_URL"),
        )],
        &script,
    ));
    let env = sys.command_env("m", &running);
    assert_eq!(env["VALUE"], "plain-value-0000");
    let ep = endpoint(&env, "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL");
    assert!(is_well_formed_token(&ep.token));
    let written = std::fs::read_to_string(sys.path("env-m.txt")).expect("env");
    assert_free_of("the command's environment", &written, &[CREDENTIAL]);
    assert_works(&ep);
    assert_eq!(destination.wait_for(1)[0].values("x-api-key"), [CREDENTIAL]);
    assert_eq!(sys.approvals().len(), asked + 1);
    sys.go("m");
    assert_eq!(running.exit_code(), Some(0));
    let output = running.output.text();
    assert!(
        output.contains("v=[REDACTED:PLAIN] t=[REDACTED:ANTHROPIC_API_KEY]"),
        "{output}"
    );
}

// ===== Profiles =====

/// Replacing an entry (`add --replace`) removes its profile and ends its
/// grants, cutting their streams; the entry can no longer be used through
/// the broker until a profile is set again.
#[test]
fn replacing_an_entry_removes_its_profile_and_ends_its_grants() {
    let sys = System::new();
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    let mut stream = open_stream(&a.endpoint);
    sys.decide(&[Decision::AllowOnce]);
    let response = sys.call(&Request::Add {
        entry: NewEntry {
            name: "KEY".into(),
            ..NewEntry::default()
        },
        value: Some(SecretString::new(OTHER_KEY.into())),
        generate: None,
        replace: true,
    });
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        describe(&response)
    );
    let before = streams.sent();
    assert_eq!(sys.state(&a.id).as_deref(), Some("revoked"));
    assert_cut(&mut stream, before);
    streams.wait_closed(1);
    assert_nothing_more_forwarded(&a.endpoint, &destination);
    match sys.call(&Request::Show { name: "KEY".into() }) {
        Response::Entry { entry } => assert_eq!(entry.broker, None, "the profile was kept"),
        other => panic!("{}", describe(&other)),
    }
    let response = sys
        .start(sys.run_request(
            vec![],
            vec![brokered("ANTHROPIC_API_KEY", "KEY", None)],
            "true",
        ))
        .wait();
    let (code, message) = error_of(&response);
    assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
    assert!(message.contains("no broker profile"), "{message}");
    sys.go("a");
    assert_eq!(a.running.exit_code(), Some(0));
    assert_eq!(sys.end_of(&a.id)["reason"], "entry_changed");
}

// ===== The harness =====

/// A test that fails leaves its run going — its command waiting, its broker
/// serving, a stream open — and its agent unlocked, which its idle timer
/// would lock, and record, later. Dropping its system ends all of that
/// before the directory is removed: once the drop returns, the run has its
/// answer, the stream is cut, the broker has exited and the directory is
/// gone, and nothing writes it again, the idle lock included.
#[test]
fn dropping_a_system_with_its_run_going_ends_the_run_and_leaves_nothing_behind() {
    const IDLE: Duration = Duration::from_secs(6);
    let sys = System::with(Settings {
        idle_timeout: IDLE,
        ..Settings::default()
    });
    let streams = Streams::default();
    let destination = Destination::new(&sys.ca, streams.handler());
    sys.seed(&[("KEY", CREDENTIAL)]);
    sys.set_profile("KEY", anthropic(&destination));
    sys.install_broker(&[]);
    let a = sys.start_grant("KEY", "a");
    assert_works(&a.endpoint);
    let mut stream = open_stream(&a.endpoint);
    let brokers = sys.broker_pids();
    assert_eq!(brokers.len(), 1, "{brokers:?}");
    let dir = sys.dir.path().to_path_buf();
    // Unlocked just now: its idle lock is due after the drop.
    sys.agent.lock_for(SCREEN_LOCK, "test");
    sys.unlock();
    let unlocked = Instant::now();
    drop(sys);
    assert!(
        unlocked.elapsed() < IDLE,
        "the drop took {:?}: too long to tell what the idle lock does",
        unlocked.elapsed()
    );
    match a.running.answer.try_recv() {
        Ok(Ok(Response::Exited { code: Some(0), .. })) => {}
        Ok(answer) => panic!("not the command's exit: {}", outcome(&answer)),
        Err(_) => panic!("the run was still going when the drop returned"),
    }
    assert!(!alive(brokers[0]), "the broker was left");
    assert!(!dir.exists(), "the directory was left");
    assert_cut(&mut stream, streams.sent());
    // Past the idle timeout and the next look of its timer, which comes
    // every second: nothing wrote the directory again.
    let until = unlocked + IDLE + Duration::from_secs(2);
    while Instant::now() < until {
        assert!(!dir.exists(), "something wrote the directory again");
        std::thread::sleep(Duration::from_millis(50));
    }
}
