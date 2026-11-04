//! End-to-end tests: a real agent on a temporary socket, driven through the
//! real `rusthorse` binary, with a scripted [`Ui`] instead of zenity.

#![allow(clippy::unwrap_used)] // test code: a poisoned mutex should just fail the test

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusthorse::agent::{Agent, AgentConfig};
use rusthorse::protocol::SecretString;
use rusthorse::ui::{ApprovalRequest, Decision, Prompt, Typed, Ui};
use rusthorse::vault::{KdfParams, Vault};

const PASSWORD: &str = "correct horse battery";

/// Answers dialogs from queues; records what it was asked.
#[derive(Default)]
struct ScriptedUi {
    passwords: Mutex<VecDeque<Option<String>>>,
    values: Mutex<VecDeque<Option<String>>>,
    decisions: Mutex<VecDeque<Decision>>,
    approvals_asked: AtomicUsize,
    last_approval: Mutex<Option<ApprovalRequest>>,
    /// Runs (once) while the "human" is looking at the next approval dialog.
    on_approve: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Runs (once) while the "human" is typing the next master password.
    on_password: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// The text of every master-password dialog shown.
    password_prompts: Mutex<Vec<String>>,
    /// Which master-password dialogs nobody answers, by their index in
    /// `password_prompts`.
    password_timeouts: Mutex<Vec<usize>>,
    /// Behave like a dialog whose content scrolls (rusthorse-dialog), so the
    /// agent applies no height limit.
    scrolls: std::sync::atomic::AtomicBool,
}

/// `Some(text)` is typed and confirmed; `None` cancels.
fn typed(answer: Option<String>) -> Typed {
    answer.map_or(Typed::Cancelled, |v| Typed::Value(SecretString::new(v)))
}

impl Ui for ScriptedUi {
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        let index = {
            let mut prompts = self.password_prompts.lock().unwrap();
            prompts.push(rusthorse::ui::prompt_text(prompt));
            prompts.len() - 1
        };
        if let Some(hook) = self.on_password.lock().unwrap().take() {
            hook();
        }
        if self.password_timeouts.lock().unwrap().contains(&index) {
            return Ok(Typed::TimedOut);
        }
        let next = self.passwords.lock().unwrap().pop_front();
        Ok(typed(next.unwrap_or(Some(PASSWORD.to_string()))))
    }

    fn secret_value(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(typed(self.values.lock().unwrap().pop_front().flatten()))
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.approvals_asked.fetch_add(1, Ordering::SeqCst);
        *self.last_approval.lock().unwrap() = Some(request.clone());
        if let Some(hook) = self.on_approve.lock().unwrap().take() {
            hook();
        }
        Ok(self
            .decisions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Decision::Deny))
    }
}

/// Lets the test keep a handle on the UI that the agent owns.
struct SharedUi(Arc<ScriptedUi>);

impl Ui for SharedUi {
    fn master_password(&self, p: &Prompt) -> anyhow::Result<Typed> {
        self.0.master_password(p)
    }
    fn secret_value(&self, p: &Prompt) -> anyhow::Result<Typed> {
        self.0.secret_value(p)
    }
    fn approve(&self, r: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.0.approve(r)
    }
    fn limits_height(&self) -> bool {
        !self.0.scrolls.load(Ordering::SeqCst)
    }
}

struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    audit: PathBuf,
    ui: Arc<ScriptedUi>,
    /// The agent, for the events that do not come through its socket (a
    /// screen lock, a suspend).
    agent: Arc<Agent>,
}

impl Harness {
    fn new() -> Harness {
        Harness::with_timeouts(Duration::ZERO, Duration::from_secs(10))
    }

    fn with_idle_timeout(idle_timeout: Duration) -> Harness {
        Harness::with_timeouts(idle_timeout, Duration::from_secs(10))
    }

    fn with_timeouts(idle_timeout: Duration, request_timeout: Duration) -> Harness {
        Harness::with_config(idle_timeout, request_timeout, None)
    }

    fn with_config(
        idle_timeout: Duration,
        request_timeout: Duration,
        send_buffer: Option<usize>,
    ) -> Harness {
        // Never the real buses: tests of locking and of the keyring start
        // private ones.
        Harness::build(
            idle_timeout,
            request_timeout,
            send_buffer,
            rusthorse::session_lock::Settings::default(),
            no_keyring(),
            BROKER_READY_TIMEOUT,
            None,
        )
    }

    /// An agent that waits at most `ready` for a broker to answer.
    fn with_broker_ready_timeout(ready: Duration) -> Harness {
        Harness::build(
            Duration::ZERO,
            Duration::from_secs(10),
            None,
            rusthorse::session_lock::Settings::default(),
            no_keyring(),
            ready,
            None,
        )
    }

    /// An agent whose grants last at most `lifetime`.
    fn with_broker_lifetime(lifetime: Duration) -> Harness {
        Harness::build(
            Duration::ZERO,
            Duration::from_secs(10),
            None,
            rusthorse::session_lock::Settings::default(),
            no_keyring(),
            BROKER_READY_TIMEOUT,
            Some(lifetime),
        )
    }

    #[cfg(feature = "session-lock")]
    fn with_session_lock(settings: rusthorse::session_lock::Settings) -> Harness {
        Harness::build(
            Duration::ZERO,
            Duration::from_secs(10),
            None,
            settings,
            no_keyring(),
            BROKER_READY_TIMEOUT,
            None,
        )
    }

    /// An agent that finds the Secret Service on the bus at `address`.
    #[cfg(feature = "fake-keyring")]
    fn with_keyring(address: &str) -> Harness {
        Harness::build(
            Duration::ZERO,
            Duration::from_secs(10),
            None,
            rusthorse::session_lock::Settings::default(),
            rusthorse::keyring::Settings {
                address: Some(address.into()),
                plain: true,
                ..Default::default()
            },
            BROKER_READY_TIMEOUT,
            None,
        )
    }

    fn build(
        idle_timeout: Duration,
        request_timeout: Duration,
        send_buffer: Option<usize>,
        session_lock: rusthorse::session_lock::Settings,
        keyring: rusthorse::keyring::Settings,
        broker_ready_timeout: Duration,
        broker_lifetime: Option<Duration>,
    ) -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = dir.path().join("vault.kdbx");
        Vault::create(
            &vault,
            SecretString::new(PASSWORD.to_string()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create vault");
        let socket = dir.path().join("run").join("agent.sock");
        let audit = dir.path().join("state").join("audit.jsonl");
        let ui = Arc::new(ScriptedUi::default());
        let config = AgentConfig {
            vault,
            socket: socket.clone(),
            audit_log: audit.clone(),
            idle_timeout,
            request_timeout,
            send_buffer,
            session_lock,
            new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
            keyring,
            // Nothing there until a test of the credential broker writes a
            // stand-in (`fake_broker`).
            broker_program: Some(dir.path().join("rusthorse-broker")),
            broker_ready_timeout: Some(broker_ready_timeout),
            broker_lifetime,
        };
        let listener = Agent::bind(&socket).expect("bind");
        let agent = Agent::new(config, Box::new(SharedUi(Arc::clone(&ui))));
        let serving = Arc::clone(&agent);
        std::thread::spawn(move || serving.serve(listener));
        Harness {
            dir,
            socket,
            audit,
            ui,
            agent,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rusthorse"));
        cmd.args(args)
            .env("RUSTHORSE_SOCKET", &self.socket)
            .env("RUSTHORSE_AUDIT_LOG", &self.audit)
            .env("RUSTHORSE_VAULT", self.dir.path().join("vault.kdbx"))
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            // Only the agent shows dialogs, and in these tests it scripts
            // them: a command that tried to show one itself (as `init`
            // without an agent does) fails instead of reaching the desktop.
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).finish()
    }

    fn run_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write");
        within(TEST_LIMIT, move || child.wait_with_output().expect("wait"))
    }

    fn decide(&self, decisions: &[Decision]) {
        self.ui
            .decisions
            .lock()
            .unwrap()
            .extend(decisions.iter().copied());
    }

    fn add_secret(&self, name: &str, value: &str, extra: &[&str]) {
        self.ui
            .values
            .lock()
            .unwrap()
            .push_back(Some(value.to_string()));
        let mut args = vec!["add", name];
        args.extend_from_slice(extra);
        let out = self.run(&args);
        assert!(out.status.success(), "add failed: {}", text(&out.stderr));
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.path().join("vault.kdbx")
    }

    fn call(&self, request: &rusthorse::protocol::Request) -> rusthorse::protocol::Response {
        rusthorse::client::Client::new(self.socket.clone())
            .call(request)
            .expect("call")
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
    }
}

/// A keyring setting that reaches no Secret Service: a bus address where
/// nothing listens, so that no test ever reads the real keyring.
fn no_keyring() -> rusthorse::keyring::Settings {
    rusthorse::keyring::Settings {
        address: Some("unix:path=/nonexistent/rusthorse-test-bus".into()),
        plain: true,
        ..Default::default()
    }
}

/// No single rusthorse invocation in these tests should take this long; a
/// hang is reported as a failure instead of blocking the whole suite.
const TEST_LIMIT: Duration = Duration::from_secs(60);

/// How long the agents of these tests wait for a broker to answer its
/// install (ADR 0013): as long as in production, unless a test shortens it.
const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `f` on a thread and fail the test if it does not finish in time.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("did not finish within {limit:?} (hang?)"))
}

/// `Command::output` with [`TEST_LIMIT`]; a hung child is killed.
trait Finish {
    fn finish(&mut self) -> Output;
}

impl Finish for Command {
    fn finish(&mut self) -> Output {
        self.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = self.spawn().expect("spawn rusthorse");
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(TEST_LIMIT) {
            Ok(output) => output.expect("wait"),
            Err(_) => {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
                panic!("rusthorse did not finish within {TEST_LIMIT:?} (hang?)");
            }
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn status_works_while_locked() {
    let h = Harness::new();
    let out = h.run(&["status", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let status: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(status["locked"], true);
    assert_eq!(status["vault_exists"], true);
}

#[test]
fn add_via_dialog_then_list_and_show_metadata_only() {
    let h = Harness::new();
    h.add_secret(
        "ROUTER",
        "hunter2-router",
        &[
            "--username",
            "admin",
            "--host",
            "192.168.1.1",
            "--port",
            "443",
            "--tag",
            "net",
        ],
    );
    let out = h.run(&["list", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let listing = text(&out.stdout);
    assert!(listing.contains("\"ROUTER\""));
    assert!(listing.contains("192.168.1.1"));
    assert!(
        !listing.contains("hunter2-router"),
        "list must never contain values"
    );

    let out = h.run(&["show", "ROUTER"]);
    let shown = text(&out.stdout);
    assert!(shown.contains("admin") && shown.contains("set (hidden)"));
    assert!(!shown.contains("hunter2-router"));
    // No approval was needed for any of this.
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn run_injects_secret_and_redacts_output() {
    let h = Harness::new();
    h.add_secret("API_KEY", "sk-test-1234567890", &[]);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "run",
        "API_KEY",
        "--",
        "sh",
        "-c",
        "echo \"out=$API_KEY\"; echo \"err=$API_KEY\" >&2; echo len=${#API_KEY}",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(stdout.contains("out=[REDACTED:API_KEY]"), "{stdout}");
    assert!(
        stdout.contains("len=18"),
        "the command saw the real value: {stdout}"
    );
    assert!(stderr.contains("err=[REDACTED:API_KEY]"), "{stderr}");
    assert!(!stdout.contains("sk-test") && !stderr.contains("sk-test"));

    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let details: Vec<String> = request
        .details
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    assert!(
        details.iter().any(|d| d.starts_with("Program: /")),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("Secrets: API_KEY ← API_KEY (")),
        "{details:?}"
    );
    assert!(
        !h.audit_text().contains("sk-test"),
        "the audit log must not contain values"
    );
}

#[test]
fn denied_run_does_not_execute() {
    let h = Harness::new();
    h.add_secret("TOKEN", "abcdefgh", &[]);
    h.decide(&[Decision::Deny]);
    let marker = h.dir.path().join("ran");
    let out = h.run(&[
        "run",
        "TOKEN",
        "--",
        "touch",
        marker.to_str().expect("utf8"),
    ]);
    assert_eq!(out.status.code(), Some(125));
    assert!(!marker.exists(), "a denied command must not run");
    assert!(h.audit_text().contains("\"outcome\":\"denied\""));
}

#[test]
fn exit_codes_are_propagated() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["run", "T", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn command_is_a_child_of_the_agent_not_the_client() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["run", "T", "--", "sh", "-c", "echo $PPID"]);
    let ppid: u32 = text(&out.stdout).trim().parse().expect("ppid");
    // The agent runs inside this test process.
    assert_eq!(ppid, std::process::id());
}

#[test]
fn loader_variables_are_stripped() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let out = h
        .cmd(&[
            "run",
            "T",
            "--",
            "sh",
            "-c",
            "echo ${LD_LIBRARY_PATH-unset}",
        ])
        .env("LD_LIBRARY_PATH", "/nonexistent-rusthorse-test")
        .finish();
    assert_eq!(text(&out.stdout).trim(), "unset");
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        request
            .warnings
            .iter()
            .any(|w| w.contains("LD_LIBRARY_PATH"))
    );
}

#[test]
fn remembered_approval_skips_the_dialog_for_identical_requests_only() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowFor(Duration::from_secs(60))]);
    for _ in 0..2 {
        let out = h.run(&["run", "T", "--", "true"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
    assert!(h.audit_text().contains("allowed_remembered"));

    // A different command line is a new question (denied by default here).
    let out = h.run(&["run", "T", "--", "true", "x"]);
    assert_eq!(out.status.code(), Some(125));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);

    // Locking forgets remembered approvals.
    assert!(h.run(&["lock"]).status.success());
    let out = h.run(&["run", "T", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 3);
}

#[test]
fn reveal_needs_approval() {
    let h = Harness::new();
    h.add_secret("PW", "visible-on-purpose", &[]);
    h.decide(&[Decision::Deny, Decision::AllowOnce]);
    let denied = h.run(&["reveal", "PW"]);
    assert_eq!(denied.status.code(), Some(4));
    assert!(!text(&denied.stdout).contains("visible-on-purpose"));
    let allowed = h.run(&["reveal", "PW"]);
    assert_eq!(text(&allowed.stdout).trim(), "visible-on-purpose");
}

#[test]
fn wrong_master_password_is_retried() {
    let h = Harness::new();
    h.ui.passwords
        .lock()
        .unwrap()
        .extend([Some("wrong".to_string()), Some(PASSWORD.to_string())]);
    let out = h.run(&["unlock"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let audit = h.audit_text();
    assert!(audit.contains("wrong_password") && audit.contains("\"outcome\":\"unlocked\""));
}

#[test]
fn cancelled_unlock_is_reported() {
    let h = Harness::new();
    h.ui.passwords.lock().unwrap().push_back(None);
    let out = h.run(&["list"]);
    assert_eq!(out.status.code(), Some(4));
}

#[test]
fn the_unlock_dialog_says_to_type_the_master_password() {
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    let prompts = h.ui.password_prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 1);
    assert!(
        prompts[0].starts_with("Type the master password"),
        "{}",
        prompts[0]
    );
}

#[test]
fn an_empty_master_password_is_asked_again_not_counted_as_wrong() {
    // The first real test: a person took the password dialog for an
    // approval and clicked Unlock with nothing typed.
    let h = Harness::new();
    h.ui.passwords
        .lock()
        .unwrap()
        .extend([Some(String::new()), Some(PASSWORD.to_string())]);
    let out = h.run(&["unlock"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let prompts = h.ui.password_prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 2);
    assert!(
        prompts[1].starts_with("Nothing was typed (attempt 1 of 3)"),
        "{}",
        prompts[1]
    );
    let audit = h.audit_text();
    assert!(!audit.contains("wrong_password"), "{audit}");
    assert!(audit.contains("\"outcome\":\"unlocked\""));
}

#[test]
fn an_unlock_with_nothing_ever_typed_is_cancelled_not_wrong() {
    let h = Harness::new();
    h.ui.passwords.lock().unwrap().extend([
        Some(String::new()),
        Some(String::new()),
        Some(String::new()),
    ]);
    let out = h.run(&["list"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no master password was typed"));
    let audit = h.audit_text();
    assert!(!audit.contains("wrong_password"), "{audit}");
    assert!(audit.contains("\"outcome\":\"cancelled\",\"requester\""));
    assert!(audit.contains("no password was typed"));
    // A wrong guess among empty attempts is still reported as wrong.
    h.ui.passwords.lock().unwrap().extend([
        Some(String::new()),
        Some("not it".to_string()),
        Some(String::new()),
    ]);
    let out = h.run(&["list"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("wrong master password"));
}

#[test]
fn unanswered_dialogs_are_reported_as_timed_out() {
    let h = Harness::new();
    h.ui.password_timeouts.lock().unwrap().push(0);
    let out = h.run(&["list"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(
        text(&out.stderr).contains("nobody answered the unlock dialog in time"),
        "{}",
        text(&out.stderr)
    );
    assert!(h.audit_text().contains("\"outcome\":\"timed_out\""));

    h.add_secret("TOKEN", "never-printed", &[]);
    h.decide(&[Decision::TimedOut]);
    let out = h.run(&["run", "TOKEN", "--", "/bin/echo", "ran"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(!text(&out.stdout).contains("ran"));
    assert!(
        text(&out.stderr).contains("nobody answered the approval dialog in time"),
        "{}",
        text(&out.stderr)
    );
    let last = h
        .audit_text()
        .lines()
        .last()
        .unwrap_or_default()
        .to_string();
    assert!(
        last.contains("\"action\":\"run\",\"outcome\":\"timed_out\""),
        "{last}"
    );
}

#[test]
fn add_from_stdin_needs_approval() {
    let h = Harness::new();
    h.decide(&[Decision::Deny]);
    let out = h.run_stdin(&["add", "PIPED", "--stdin"], "piped-value\n");
    assert_eq!(out.status.code(), Some(4));
    h.decide(&[Decision::AllowOnce]);
    let out = h.run_stdin(&["add", "PIPED", "--stdin"], "piped-value\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["reveal", "PIPED"]);
    assert_eq!(text(&out.stdout).trim(), "piped-value");
}

#[test]
fn import_dotenv_edit_and_remove() {
    let h = Harness::new();
    let env_file = h.dir.path().join("app.env");
    std::fs::write(&env_file, "A_KEY=aaaa1111\nB_KEY='bbbb 2222'\n").expect("write");
    // One approval to show the names, one to import.
    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
    let out = h.run(&[
        "import",
        "dotenv",
        env_file.to_str().expect("utf8"),
        "--tag",
        "app",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("imported 2"));

    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "edit",
        "A_KEY",
        "--url",
        "https://api.example.com",
        "--add-tag",
        "prod",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let shown = text(&h.run(&["show", "A_KEY", "--json"]).stdout);
    assert!(shown.contains("https://api.example.com") && shown.contains("prod"));
    assert_eq!(text(&out.stderr).trim(), "A_KEY updated");
    // Named by its UUID, as the manager names it: the answer still names
    // the entry, not the UUID.
    let id = serde_json::from_str::<serde_json::Value>(&shown).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_string();
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", &id, "--add-tag", "by-uuid"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr).trim(), "A_KEY updated");

    h.decide(&[Decision::AllowOnce]);
    assert!(h.run(&["remove", "B_KEY"]).status.success());
    let listing = text(&h.run(&["list"]).stdout);
    assert!(listing.contains("A_KEY") && !listing.contains("B_KEY"));
}

/// What the vault holds is shown with control and invisible characters
/// escaped: an entry's title and username written by another KeePass
/// client can hold terminal controls. `list` and `show` show them escaped,
/// `--json` gives them as they are, and an edit or a removal that names the
/// entry by its UUID (as the manager does) answers with the escaped title.
#[test]
fn a_title_written_elsewhere_is_printed_escaped() {
    use keepass::db::fields;
    let h = Harness::new();
    let uuids = seed(&h, &[("PLAIN", "value-1234")]);
    set_field_elsewhere(&h, "PLAIN", fields::USERNAME, "user\u{202e}gpj.exe", false);
    set_field_elsewhere(&h, "PLAIN", fields::TITLE, "SAFE\u{1b}[2J\rFORGED", false);
    let raw = |out: &str| out.contains('\u{1b}') || out.contains('\r') || out.contains('\u{202e}');
    for args in [&["list"][..], &["show", &uuids["PLAIN"]][..]] {
        let out = h.run(args);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let shown = text(&out.stdout);
        assert!(!raw(&shown), "{args:?}: {shown:?}");
        assert!(
            shown.contains("SAFE\\u{1b}[2J\\u{d}FORGED"),
            "{args:?}: {shown}"
        );
        assert!(shown.contains("user\\u{202e}gpj.exe"), "{args:?}: {shown}");
    }
    let json = text(&h.run(&["show", &uuids["PLAIN"], "--json"]).stdout);
    let entry: serde_json::Value = serde_json::from_str(&json).expect("json");
    assert_eq!(entry["name"], "SAFE\u{1b}[2J\rFORGED");
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", &uuids["PLAIN"], "--add-tag", "by-uuid"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "SAFE\\u{1b}[2J\\u{d}FORGED updated\n");
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["remove", &uuids["PLAIN"]]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "SAFE\\u{1b}[2J\\u{d}FORGED deleted\n");
}

/// The group of entry `name` as `list --json` shows it (`None`: the top
/// level).
fn listed_group(h: &Harness, name: &str) -> Option<String> {
    let out = h.run(&["list", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    let entry = entries
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed"));
    entry["group"].as_str().map(str::to_string)
}

/// The value of the detail `label` in the last approval dialog.
fn approval_detail(h: &Harness, label: &str) -> Option<String> {
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    request
        .details
        .iter()
        .find(|(k, _)| k == label)
        .map(|(_, v)| v.clone())
}

#[test]
fn edit_moves_an_entry_to_another_group_only_when_allowed() {
    let h = Harness::new();
    h.add_secret(
        "DB_PASSWORD",
        "db-value-1234",
        &["--group", "Home", "--host", "db.lan"],
    );
    let on_disk = std::fs::read(h.vault_path()).expect("read");

    // Denied: the entry stays where it was, and no group is created.
    h.decide(&[Decision::Deny]);
    let out = h.run(&["edit", "DB_PASSWORD", "--group", "Work/Servers"]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
    assert_eq!(
        approval_detail(&h, "Move to group").as_deref(),
        Some("/Work/Servers (creates Work/Servers at the top level)")
    );
    assert!(
        approval_detail(&h, "Entry")
            .expect("entry")
            .starts_with("Home/DB_PASSWORD (")
    );
    assert_eq!(listed_group(&h, "DB_PASSWORD").as_deref(), Some("Home"));
    assert_eq!(std::fs::read(h.vault_path()).expect("read"), on_disk);

    // Allowed: moved into a new nested group. The dialog shows the path as
    // it will be, from the top.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "DB_PASSWORD", "--group", " Work / Servers/"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        approval_detail(&h, "Move to group").as_deref(),
        Some("/Work/Servers (creates Work/Servers at the top level)")
    );
    // The audit log says from where to where.
    let moved = audit_records(&h)
        .into_iter()
        .rev()
        .find(|r| r["action"] == "edit")
        .expect("edit record");
    assert_eq!(
        moved["detail"],
        "move from /Home to /Work/Servers (creates Work/Servers at the top level)"
    );
    assert_eq!(
        listed_group(&h, "DB_PASSWORD").as_deref(),
        Some("Work/Servers")
    );
    let out = h.run(&["show", "Work/Servers/DB_PASSWORD"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("db.lan"),
        "{}",
        text(&out.stdout)
    );
    assert!(!h.run(&["show", "Home/DB_PASSWORD"]).status.success());
    let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
    let id = vault
        .find("Work/Servers/DB_PASSWORD")
        .expect("moved on disk");
    assert_eq!(
        vault.secret(id).as_deref().map(String::as_str),
        Some("db-value-1234")
    );

    // Back to the top level with `/`, shown as `/`.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "DB_PASSWORD", "--group", "/"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        approval_detail(&h, "Move to group").as_deref(),
        Some("/ (the top level)")
    );
    // An existing group is named by the start of its UUID: names alone can
    // look alike.
    let work = {
        let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
        vault.resolve_group("Work").expect("work")
    };
    let uuid = work.existing_uuid.clone().expect("an existing group");
    h.decide(&[Decision::Deny]);
    let out = h.run(&["edit", "DB_PASSWORD", "--group", "Work"]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        approval_detail(&h, "Move to group"),
        Some(format!("/Work (existing group {})", uuid))
    );
    h.decide(&[Decision::Deny]);
    let out = h.run(&["edit", "DB_PASSWORD", "--group", "Work/Servers/Db"]);
    assert_eq!(out.status.code(), Some(4));
    let servers = {
        let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
        vault.resolve_group("Work/Servers").expect("servers")
    };
    assert_eq!(
        approval_detail(&h, "Move to group"),
        Some(format!(
            "/Work/Servers/Db (creates Db in /Work/Servers, group {})",
            servers.existing_uuid.expect("existing")
        ))
    );
    assert_eq!(listed_group(&h, "DB_PASSWORD"), None);
    assert!(h.run(&["show", "DB_PASSWORD"]).status.success());

    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 5);
    assert_eq!(
        audit_outcomes(&h, "edit"),
        ["denied", "allowed_once", "allowed_once", "denied", "denied"]
    );
}

#[test]
fn a_move_goes_to_the_group_the_path_leads_to_and_only_one() {
    use keepass::db::fields;
    use keepass::{Database, DatabaseKey};
    let h = Harness::new();
    // Groups of another KeePass client, written before the agent opens the
    // vault: two named `Shared` side by side, one named `Work/Servers`
    // holding the entry, and the nested `Work` → `Servers`.
    let mut db = Database::open(
        &mut std::fs::File::open(h.vault_path()).expect("open"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("decrypt");
    {
        let mut root = db.root_mut();
        root.add_group().name = "Shared".into();
        root.add_group().name = "Shared".into();
        let mut literal = root.add_group();
        literal.name = "Work/Servers".into();
        let mut entry = literal.add_entry();
        entry.set_unprotected(fields::TITLE, "API_KEY");
        entry.set_protected(fields::PASSWORD, "key-value-1234");
        let mut work = root.add_group();
        work.name = "Work".into();
        work.add_group().name = "Servers".into();
    }
    db.save(
        &mut std::fs::File::create(h.vault_path()).expect("create"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("save");

    // `Shared` could be either group: refused before anyone is asked, for
    // a move and for a new entry (before its value is asked for).
    let out = h.run(&["edit", "API_KEY", "--group", "Shared", "--host", "h.lan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("several groups named"),
        "{}",
        text(&out.stderr)
    );
    h.ui.values
        .lock()
        .unwrap()
        .push_back(Some("other-value-1234".into()));
    let out = h.run(&["add", "OTHER", "--group", "Shared/Sub"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        h.ui.values.lock().unwrap().len(),
        1,
        "the value was asked for"
    );
    h.ui.values.lock().unwrap().clear();
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);

    // The path `Work/Servers` leads to the nested group, not to the group
    // whose name reads the same: a move, shown with that group's UUID.
    let nested = {
        let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
        vault.resolve_group("Work/Servers").expect("nested")
    };
    let uuid = nested.existing_uuid.clone().expect("existing");
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "API_KEY", "--group", "Work/Servers"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        approval_detail(&h, "Move to group"),
        Some(format!("/Work/Servers (existing group {})", uuid))
    );
    let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
    let id = vault.find("API_KEY").expect("entry");
    assert!(
        !vault.moves(id, &vault.resolve_group("Work/Servers").expect("again")),
        "the entry is not in the nested group"
    );
    // Now it is there: a move to it moves nothing.
    let out = h.run(&["edit", "API_KEY", "--group", "Work/Servers"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("already in that group"));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
}

#[test]
fn a_bad_destination_group_is_refused_before_any_dialog() {
    use keepass::{Database, DatabaseKey};
    let h = Harness::new();
    // A recycle bin with a group inside, as another KeePass client makes
    // them; written before the agent opens the vault.
    let raw = |path: &Path| {
        Database::open(
            &mut std::fs::File::open(path).expect("open"),
            DatabaseKey::new().with_password(PASSWORD),
        )
        .expect("decrypt")
    };
    let mut db = raw(&h.vault_path());
    let bin = {
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        bin.add_group().name = "Old".into();
        bin.id()
    };
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(bin.uuid());
    db.save(
        &mut std::fs::File::create(h.vault_path()).expect("create"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("save");

    h.add_secret("API_KEY", "key-value-1234", &["--group", "Work"]);
    let on_disk = std::fs::read(h.vault_path()).expect("read");
    for (path, expected) in [
        ("Recycle Bin", "recycle bin"),
        ("/Recycle Bin/Old", "recycle bin"),
        ("Recycle Bin/New", "recycle bin"),
        ("Work/evil\u{202E}name", "group "),
        ("Work/a\tb", "group "),
    ] {
        let out = h.run(&["edit", "API_KEY", "--group", path, "--host", "h.lan"]);
        assert_eq!(out.status.code(), Some(1), "{path:?}");
        assert!(
            text(&out.stderr).contains(expected),
            "{}",
            text(&out.stderr)
        );
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(audit_outcomes(&h, "edit").is_empty());
    assert_eq!(listed_group(&h, "API_KEY").as_deref(), Some("Work"));
    assert_eq!(std::fs::read(h.vault_path()).expect("read"), on_disk);

    // `add --group` refuses the recycle bin too, where the entry would be
    // hidden from every listing.
    h.ui.values
        .lock()
        .unwrap()
        .push_back(Some("other-value-1234".into()));
    let out = h.run(&["add", "OTHER", "--group", "Recycle Bin/Old"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("recycle bin"),
        "{}",
        text(&out.stderr)
    );
    // Before the value is asked for: nobody types a value for nothing.
    assert_eq!(
        h.ui.values.lock().unwrap().len(),
        1,
        "the value was asked for"
    );
    h.ui.values.lock().unwrap().clear();
    let db = raw(&h.vault_path());
    assert!(
        db.iter_all_entries()
            .all(|e| e.get(keepass::db::fields::TITLE) != Some("OTHER")),
        "the entry was put in the recycle bin"
    );

    // A move to the group the entry is in moves nothing: refused before any
    // dialog, alone; with other changes, the dialog does not offer it.
    for same in ["Work", " Work /", "/Work"] {
        let out = h.run(&["edit", "API_KEY", "--group", same]);
        assert_eq!(out.status.code(), Some(1), "{same:?}");
        assert!(
            text(&out.stderr).contains("already in that group"),
            "{}",
            text(&out.stderr)
        );
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "API_KEY", "--group", "Work", "--host", "h.lan"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        approval_detail(&h, "Move to group").is_none(),
        "the dialog offered a move to the group the entry is in"
    );
    assert_eq!(listed_group(&h, "API_KEY").as_deref(), Some("Work"));
}

#[test]
fn client_disconnect_kills_the_command() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("pid");
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let mut client = h
        .cmd(&["run", "T", "--", "sh", "-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = wait_for_pid(&pidfile);
    client.kill().expect("kill client");
    let _ = client.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&format!("/proc/{pid}")).exists() {
        if Instant::now() >= deadline {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            panic!("the command outlived its client: {stat}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The agent records the end just after it reaps the command.
    wait_for_run_end(&h, "the run did not end after its client left");
}

#[test]
fn unredacted_run_passes_values_through() {
    let h = Harness::new();
    h.add_secret("T", "plainvalue", &[]);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["run", "--no-redact", "T", "--", "sh", "-c", "echo $T"]);
    assert_eq!(text(&out.stdout).trim(), "plainvalue");
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(request.warnings.iter().any(|w| w.contains("NOT redacted")));
}

#[test]
fn unknown_entries_fail_before_asking() {
    let h = Harness::new();
    let out = h.run(&["run", "MISSING", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(text(&out.stderr).contains("no entry named"));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn a_writable_stdin_is_not_an_unredacted_way_out() {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let h = Harness::new();
    h.add_secret("T", "leak-through-stdin", &[]);
    h.decide(&[Decision::AllowOnce]);
    // The client's "stdin" is a bidirectional socket; the command tries to
    // write the secret into it.
    let (mut ours, theirs) = UnixStream::pair().expect("pair");
    let out = h
        .cmd(&[
            "run",
            "T",
            "--",
            "sh",
            "-c",
            "printf %s \"$T\" >&0; echo done",
        ])
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .finish();
    assert!(text(&out.stdout).contains("done"));
    ours.set_nonblocking(true).expect("nonblocking");
    let mut received = Vec::new();
    let _ = ours.read_to_end(&mut received);
    assert!(
        !String::from_utf8_lossy(&received).contains("leak-through-stdin"),
        "the secret came back through stdin"
    );
}

#[test]
fn a_writable_stdin_is_not_a_way_out_with_forwarding_either() {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let h = Harness::new();
    h.add_secret("T", "leak-through-stdin", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (mut ours, theirs) = UnixStream::pair().expect("pair");
    let out = h
        .cmd(&[
            "run",
            "--stdin",
            "T",
            "--",
            "sh",
            "-c",
            "printf %s \"$T\" >&0; echo done",
        ])
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .finish();
    assert!(text(&out.stdout).contains("done"));
    ours.set_nonblocking(true).expect("nonblocking");
    let mut received = Vec::new();
    let _ = ours.read_to_end(&mut received);
    assert!(!String::from_utf8_lossy(&received).contains("leak-through-stdin"));
}

#[test]
fn input_is_not_consumed_unless_forwarding_is_requested() {
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);

    // Default: the command reads /dev/null and the caller's input stays put.
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    writer.write_all(b"NEXT_COMMAND\n").expect("write");
    let out = h
        .cmd(&["run", "T", "--", "cat"])
        .stdin(Stdio::from(OwnedFd::from(reader.try_clone().expect("dup"))))
        .finish();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "", "cat must see an empty input");
    drop(writer);
    let mut left = String::new();
    let mut reader = reader;
    reader.read_to_string(&mut left).expect("read");
    assert_eq!(left, "NEXT_COMMAND\n", "the caller's input was consumed");

    // With --stdin the input is forwarded.
    let out = h.run_stdin(&["run", "--stdin", "T", "--", "cat"], "hello\n");
    assert_eq!(text(&out.stdout), "hello\n");
}

#[test]
fn background_processes_do_not_outlive_the_command() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("bg.pid");
    let script = format!("sleep 30 & echo $! > {}", pidfile.display());
    let started = Instant::now();
    let out = h.run(&["run", "T", "--", "sh", "-c", &script]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(10));
    let pid = wait_for_pid(&pidfile);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "the background process kept running"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_lock_while_the_password_is_typed_keeps_the_vault_locked() {
    let h = Harness::new();
    let socket = h.socket.clone();
    *h.ui.on_password.lock().unwrap() = Some(Box::new(move || {
        rusthorse::client::Client::new(socket)
            .call(&rusthorse::protocol::Request::Lock)
            .expect("lock");
    }));
    let out = h.run(&["unlock"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("locked while the password"));
    let status: serde_json::Value =
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).expect("json");
    assert_eq!(status["locked"], true);
}

/// A harness whose vault does not exist yet.
fn without_vault() -> Harness {
    let h = Harness::new();
    std::fs::remove_file(h.vault_path()).expect("remove the vault");
    h
}

/// The outcomes of the audit records of `action`, in order.
fn audit_records(h: &Harness) -> Vec<serde_json::Value> {
    h.audit_text()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn audit_outcomes(h: &Harness, action: &str) -> Vec<String> {
    h.audit_text()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record["action"] == action)
        .map(|record| record["outcome"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn init_with_an_agent_creates_the_vault_through_the_agents_dialogs() {
    use std::os::unix::fs::PermissionsExt;
    let h = without_vault();
    let new = "a long new master password";
    h.ui.passwords
        .lock()
        .unwrap()
        .extend([Some(new.to_string()), Some(new.to_string())]);
    let out = h.run(&["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("vault created at"),
        "{}",
        text(&out.stderr)
    );
    // Both dialogs were the agent's: the command asked for nothing itself.
    let prompts = h.ui.password_prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts[0].contains("Choose the master password"),
        "{}",
        prompts[0]
    );
    assert!(prompts[0].contains("cannot be recovered"), "{}", prompts[0]);
    assert!(
        prompts[0].contains(&h.vault_path().display().to_string()),
        "{}",
        prompts[0]
    );
    assert!(prompts[1].contains("again"), "{}", prompts[1]);
    // Left unlocked, private, and it opens with the new password.
    let status: serde_json::Value =
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).expect("json");
    assert_eq!(status["locked"], false);
    assert!(h.run(&["list"]).status.success());
    let mode = std::fs::metadata(h.vault_path())
        .expect("vault")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    Vault::open(&h.vault_path(), SecretString::new(new.to_string())).expect("opens");
    assert_eq!(audit_outcomes(&h, "create_vault"), ["created"]);
}

#[test]
fn creating_a_vault_creates_nothing_unless_both_passwords_are_given_and_match() {
    // (passwords typed, outcome recorded, message)
    let cases: [(&[Option<&str>], &str, &str); 4] = [
        (&[None], "cancelled", "cancelled"),
        (&[Some("first password"), None], "cancelled", "cancelled"),
        (
            &[Some("first password"), Some("second password")],
            "mismatch",
            "do not match",
        ),
        (&[Some("short"), Some("short")], "too_short", "at least 8"),
    ];
    for (typed, outcome, message) in cases {
        let h = without_vault();
        h.ui.passwords
            .lock()
            .unwrap()
            .extend(typed.iter().map(|t| t.map(String::from)));
        let out = h.run(&["init"]);
        assert!(!out.status.success(), "{outcome}");
        let expected = if outcome == "cancelled" { 4 } else { 1 };
        assert_eq!(out.status.code(), Some(expected), "{outcome}");
        assert!(text(&out.stderr).contains(message), "{}", text(&out.stderr));
        assert!(!h.vault_path().exists(), "{outcome}: a vault was created");
        assert_eq!(audit_outcomes(&h, "create_vault"), [outcome]);
    }
}

#[test]
fn an_unwritable_audit_log_creates_no_vault() {
    let h = without_vault();
    std::fs::create_dir_all(&h.audit).expect("block the audit path with a directory");
    let out = h.run(&["init"]);
    assert!(!out.status.success());
    assert!(
        !h.vault_path().exists(),
        "a vault was created without a record"
    );
}

#[test]
fn init_with_another_spelling_of_the_agents_vault_still_uses_the_agent() {
    // The commands run in the harness's directory, where the vault would be.
    // ("new" does not exist: the path still names the same file.)
    for spelling in [
        "vault.kdbx",
        "./sub/../vault.kdbx",
        "new/sub/../../vault.kdbx",
    ] {
        let h = without_vault();
        std::fs::create_dir(h.dir.path().join("sub")).expect("mkdir");
        let out = h.run(&["init", "--vault", spelling]);
        assert!(out.status.success(), "{spelling}: {}", text(&out.stderr));
        assert_eq!(h.ui.password_prompts.lock().unwrap().len(), 2, "{spelling}");
        assert!(h.vault_path().exists(), "{spelling}");
    }
}

#[test]
fn the_agent_reports_its_vault_as_an_absolute_path() {
    // The real program, with a relative --vault, on private paths; it
    // watches no bus and shows no dialog.
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("run").join("agent.sock");
    let _agent = Stop(
        Command::new(env!("CARGO_BIN_EXE_rusthorse"))
            .args([
                "agent",
                "--vault",
                "relative.kdbx",
                "--no-lock-on-suspend",
                "--no-lock-on-screen-lock",
            ])
            .current_dir(dir.path())
            .env("RUSTHORSE_SOCKET", &socket)
            .env("RUSTHORSE_AUDIT_LOG", dir.path().join("audit.jsonl"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the agent"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["status", "--json"])
        .env("RUSTHORSE_SOCKET", &socket)
        .current_dir("/")
        .stdin(Stdio::null())
        .finish();
    let status: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(
        status["vault"],
        dir.path().join("relative.kdbx").display().to_string()
    );
}

#[test]
fn init_stops_when_it_cannot_tell_whether_the_agent_serves_that_file() {
    if nix::unistd::geteuid().is_root() {
        return; // root can examine any directory
    }
    use std::os::unix::fs::PermissionsExt;
    let h = without_vault();
    let closed = h.dir.path().join("closed");
    std::fs::create_dir(&closed).expect("mkdir");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let out = h.run(&["init", "--vault", "closed/inner/vault.kdbx"]);
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot tell whether the agent's vault"),
        "{stderr}"
    );
    assert!(h.ui.password_prompts.lock().unwrap().is_empty());
}

#[test]
fn init_stops_when_the_agent_cannot_be_asked() {
    // Something listens on the socket but never answers properly: `init`
    // must not decide that no agent runs and ask for the password itself.
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("mute.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    let mute = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        drop(stream);
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["init", "--vault"])
        .arg(dir.path().join("vault.kdbx"))
        .env("RUSTHORSE_SOCKET", &socket)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .finish();
    mute.join().expect("mute agent");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("cannot ask the agent"), "{stderr}");
    assert!(!stderr.contains("dialog"), "{stderr}");
    assert!(!dir.path().join("vault.kdbx").exists());
}

#[test]
fn a_new_vault_is_refused_while_one_is_open_whose_file_is_gone() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    let h = Harness::new();
    h.add_secret("KEEP", "fake-keep-value", &[]);
    std::fs::rename(h.vault_path(), h.dir.path().join("moved.kdbx")).expect("move the file");
    match h.call(&Request::CreateVault) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::InvalidRequest);
            assert!(message.contains("no longer at"), "{message}");
        }
        other => panic!("unexpected {}", other.kind()),
    }
    assert!(!h.vault_path().exists(), "a new vault was created");
    // Locked, the request goes ahead.
    assert!(h.run(&["lock"]).status.success());
    assert!(h.run(&["init"]).status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).expect("json");
    assert_eq!(status["locked"], false);
    assert!(!text(&h.run(&["list"]).stdout).contains("KEEP"));
}

#[test]
fn creating_a_vault_where_one_exists_shows_no_dialog() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    let h = Harness::new();
    let before = std::fs::read(h.vault_path()).expect("vault");
    match h.call(&Request::CreateVault) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::AlreadyExists);
            assert!(message.contains("already exists"), "{message}");
        }
        other => panic!("unexpected {}", other.kind()),
    }
    assert!(h.ui.password_prompts.lock().unwrap().is_empty());
    assert_eq!(std::fs::read(h.vault_path()).expect("vault"), before);
    assert!(audit_outcomes(&h, "create_vault").is_empty());
}

#[test]
fn a_lock_while_the_new_password_is_typed_creates_the_vault_locked() {
    let h = without_vault();
    let socket = h.socket.clone();
    *h.ui.on_password.lock().unwrap() = Some(Box::new(move || {
        rusthorse::client::Client::new(socket)
            .call(&rusthorse::protocol::Request::Lock)
            .expect("lock");
    }));
    let out = h.run(&["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("locked meanwhile"),
        "{}",
        text(&out.stderr)
    );
    assert!(h.vault_path().exists());
    let status: serde_json::Value =
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).expect("json");
    assert_eq!(status["locked"], true);
}

#[test]
fn of_two_requests_to_create_the_vault_the_second_finds_it_created() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    let h = without_vault();
    let socket = h.socket.clone();
    let second = Arc::new(Mutex::new(None));
    let started = Arc::clone(&second);
    // While the first creation's dialog is open, a second request arrives;
    // it must wait for the dialog, not open its own.
    *h.ui.on_password.lock().unwrap() = Some(Box::new(move || {
        let handle = std::thread::spawn(move || {
            rusthorse::client::Client::new(socket)
                .call(&Request::CreateVault)
                .expect("second request")
        });
        *started.lock().unwrap() = Some(handle);
        std::thread::sleep(Duration::from_millis(200));
    }));
    let out = h.run(&["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let handle = second
        .lock()
        .unwrap()
        .take()
        .expect("second request started");
    match handle.join().expect("join") {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::AlreadyExists),
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(h.ui.password_prompts.lock().unwrap().len(), 2);
    assert_eq!(audit_outcomes(&h, "create_vault"), ["created"]);
}

#[test]
fn an_unwritable_audit_log_keeps_the_vault_locked() {
    let h = Harness::new();
    std::fs::create_dir_all(&h.audit).expect("block the audit path with a directory");
    let out = h.run(&["unlock"]);
    assert!(!out.status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).expect("json");
    assert_eq!(status["locked"], true);
    assert!(!h.run(&["list"]).status.success());
}

#[test]
fn a_failed_import_changes_nothing_in_memory_or_on_disk() {
    use rusthorse::protocol::{EntryFields, ImportedEntry, NewEntry, Request, Response};
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    h.decide(&[Decision::AllowOnce]);
    let item = |name: &str, url: Option<&str>| ImportedEntry {
        entry: NewEntry {
            name: name.into(),
            fields: EntryFields {
                url: url.map(Into::into),
                ..EntryFields::default()
            },
            ..NewEntry::default()
        },
        value: SecretString::new("abcd1234".into()),
    };
    let response = h.call(&Request::Import {
        entries: vec![
            item("PARTIAL", None),
            item("INVALID", Some("https://x\nAllow once")),
        ],
        replace: false,
    });
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(!text(&h.run(&["list"]).stdout).contains("PARTIAL"));
    // A later, unrelated change must not persist the failed batch either.
    h.add_secret("LATER", "efgh5678", &[]);
    let on_disk = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
    assert!(on_disk.find("PARTIAL").is_err());
    assert!(on_disk.find("LATER").is_ok());
}

#[test]
fn a_different_oldpwd_is_a_different_request() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowFor(Duration::from_secs(60)), Decision::Deny]);
    let first = h
        .cmd(&["run", "T", "--", "printenv", "OLDPWD"])
        .env("OLDPWD", "/first")
        .finish();
    assert_eq!(text(&first.stdout).trim(), "/first");
    let second = h
        .cmd(&["run", "T", "--", "printenv", "OLDPWD"])
        .env("OLDPWD", "/second")
        .finish();
    assert_eq!(
        second.status.code(),
        Some(125),
        "a changed environment was not asked about"
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
}

#[test]
fn dialogs_identify_entries_by_path_and_uuid() {
    let h = Harness::new();
    h.add_secret("API_KEY", "abcdefgh", &["--group", "Production"]);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["run", "T=Production/API_KEY", "--", "true"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let secrets = request
        .details
        .iter()
        .find(|(k, _)| k == "Secrets")
        .map(|(_, v)| v.clone())
        .expect("secrets line");
    assert!(secrets.starts_with("T ← Production/API_KEY ("), "{secrets}");
    assert!(secrets.ends_with(')') && secrets.len() > "T ← Production/API_KEY ()".len() + 7);
}

#[test]
fn requests_too_long_for_one_dialog_are_refused() {
    use rusthorse::protocol::{EntryFields, ImportedEntry, NewEntry, Request, Response};
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    // Sent directly (the CLI would split it): 60 long names in one batch.
    let entries = (0..60)
        .map(|i| ImportedEntry {
            entry: NewEntry {
                name: format!(
                    "A_VERY_LONG_VARIABLE_NAME_FOR_TESTING_THE_DIALOG_LIMIT_NUMBER_{i:03}_XXXXXXXX"
                ),
                fields: EntryFields::default(),
                ..NewEntry::default()
            },
            value: SecretString::new(format!("value{i}")),
        })
        .collect();
    let response = h.call(&Request::Import {
        entries,
        replace: false,
    });
    match response {
        Response::Error { message, .. } => {
            assert!(message.contains("too much detail"), "{message}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn large_imports_are_split_into_readable_batches() {
    let h = Harness::new();
    let env_file = h.dir.path().join("many.env");
    let lines: String = (0..60)
        .map(|i| format!("A_VERY_LONG_VARIABLE_NAME_FOR_TESTING_THE_DIALOG_LIMIT_NUMBER_{i:03}_XXXXXXXX=value{i}\n"))
        .collect();
    std::fs::write(&env_file, lines).expect("write");
    assert!(h.run(&["unlock"]).status.success());
    // Dry run: names and their status, nothing imported; only showing the
    // names is asked.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "import",
        "dotenv",
        env_file.to_str().expect("utf8"),
        "--dry-run",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout)
            .lines()
            .filter(|l| l.starts_with("new"))
            .count(),
        60
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
    // Real run: the names, then several batches, one approval each,
    // everything imported.
    h.decide(&[Decision::AllowOnce; 30]);
    let out = h.run(&["import", "dotenv", env_file.to_str().expect("utf8")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(h.ui.approvals_asked.load(Ordering::SeqCst) >= 4);
    let listing = text(&h.run(&["list"]).stdout);
    assert_eq!(
        listing.lines().filter(|l| l.contains("_XXXXXXXX")).count(),
        60
    );
}

#[test]
fn a_slow_client_is_disconnected_at_the_deadline() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let h = Harness::with_timeouts(Duration::ZERO, Duration::from_millis(500));
    let mut stream = UnixStream::connect(&h.socket).expect("connect");
    let body = br#"{"type":"status"}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    for byte in frame {
        std::thread::sleep(Duration::from_millis(100));
        if stream.write_all(&[byte]).is_err() {
            break;
        }
    }
    let answer: std::io::Result<rusthorse::protocol::Response> =
        rusthorse::protocol::read_message(&stream);
    assert!(
        answer.is_err(),
        "a request dripped over {} ms was served",
        100 * 21
    );
}

#[test]
fn a_different_underscore_variable_is_a_different_request() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowFor(Duration::from_secs(60)), Decision::Deny]);
    let first = h
        .cmd(&["run", "T", "--", "printenv", "_"])
        .env("_", "/first")
        .finish();
    assert!(first.status.success(), "{}", text(&first.stderr));
    let second = h
        .cmd(&["run", "T", "--", "printenv", "_"])
        .env("_", "/second")
        .finish();
    assert_eq!(second.status.code(), Some(125));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
}

#[test]
fn processes_with_non_utf8_names_are_terminated_too() {
    let h = Harness::new();
    // The scenario is real: a program run through a link named "\xff" gets
    // a process name that is not valid UTF-8.
    let probe = h.dir.path().join("probe");
    std::fs::create_dir(&probe).expect("mkdir");
    let mut sanity = Command::new("sh")
        .args(["-c", "n=$(printf '\\377'); ln -s \"$(command -v sh)\" \"./$n\"; exec \"./$n\" -c 'sleep 30; :'"])
        .current_dir(&probe)
        .spawn()
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(300));
    let comm = std::fs::read(format!("/proc/{}/comm", sanity.id())).expect("comm");
    let _ = sanity.kill();
    let _ = sanity.wait();
    assert!(
        std::str::from_utf8(&comm).is_err(),
        "expected a non-UTF-8 name, got {comm:?}"
    );

    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("odd.pid");
    let script = format!(
        "n=$(printf '\\377'); ln -s \"$(command -v sh)\" \"./$n\"; \"./$n\" -c 'sleep 30; :' & echo $! > {}",
        pidfile.display()
    );
    let out = h.run(&["run", "T", "--", "sh", "-c", &script]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let pid = wait_for_pid(&pidfile);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "a process with a non-UTF-8 name survived"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_client_that_stops_reading_releases_the_request_when_it_leaves() {
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (reader, writer) = std::io::pipe().expect("pipe");
    nix::fcntl::fcntl(&writer, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).expect("pipe size");
    // 32 KiB fits in the agent's own pipe, so the command exits; it does not
    // fit in the client's 4 KiB pipe, which nobody reads.
    let mut client = h
        .cmd(&[
            "run",
            "T",
            "--",
            "sh",
            "-c",
            "head -c 32768 /dev/zero | tr '\\000' x",
        ])
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(800));
    assert!(
        client.try_wait().expect("try_wait").is_none(),
        "output must not be dropped while the client is connected"
    );
    client.kill().expect("kill client");
    let _ = client.wait();
    wait_for_run_end(&h, "the request stayed blocked after the client left");
    drop(reader);
}

#[test]
fn the_dialog_limit_counts_the_remember_note() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    // Measure the dialog for a request with one short risky variable.
    h.decide(&[Decision::Deny]);
    let first = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", "x")
        .finish();
    assert_eq!(first.status.code(), Some(125));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let base = rusthorse::ui::approval_text(&request).chars().count();
    // Grow it to 3900 characters: under the 4000 limit on its own, over it
    // once the room for the "Allow for …" note is counted.
    let value = "x".repeat(1 + 3900 - base);
    let second = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", &value)
        .finish();
    assert_eq!(second.status.code(), Some(125));
    assert!(
        text(&second.stderr).contains("too much detail"),
        "{}",
        text(&second.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
}

#[test]
fn a_process_whose_main_thread_exited_is_still_terminated() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipped: python3 not available");
        return;
    }
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("mt.pid");
    // The main thread exits with pthread_exit(); another thread keeps the
    // process alive, so /proc shows the leader as a zombie.
    let program = format!(
        "import ctypes, os, threading, time\n\
         open({:?}, 'w').write(str(os.getpid()))\n\
         threading.Thread(target=time.sleep, args=(30,)).start()\n\
         ctypes.CDLL(None).pthread_exit(None)\n",
        pidfile.display().to_string()
    );
    let mut client = h
        .cmd(&["run", "T", "--", "python3", "-c", &program])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = wait_for_pid(&pidfile);
    std::thread::sleep(Duration::from_millis(300));
    client.kill().expect("kill client");
    let _ = client.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&format!("/proc/{pid}/task")).exists() && threads_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "a thread of the command outlived its client"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    wait_for_run_end(&h, "the run did not end after its client left");
}

#[test]
fn descriptors_go_with_unredacted_runs_only() {
    use rusthorse::protocol::{
        Binding, ErrorCode, Request, Response, RunRequest, read_message, send_frame,
    };
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    let request = |redact: bool| {
        Request::Run(RunRequest {
            bindings: vec![Binding {
                var: "T".into(),
                entry: "T".into(),
            }],
            argv: vec!["true".into()],
            cwd: "/".into(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            redact,
            forward_stdin: false,
        })
    };
    let devnull = std::fs::File::open("/dev/null").expect("devnull");
    let fd = devnull.as_fd();
    for (redact, fds) in [(true, vec![fd, fd, fd]), (false, vec![])] {
        let stream = UnixStream::connect(&h.socket).expect("connect");
        send_frame(&stream, &request(redact), &fds).expect("send");
        let response: Response = read_message(&stream).expect("read");
        assert!(
            matches!(
                response,
                Response::Error {
                    code: ErrorCode::InvalidRequest,
                    ..
                }
            ),
            "redact={redact}: {response:?}"
        );
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn a_closed_stdout_stops_the_command_like_sigpipe() {
    use std::io::Read;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("yes.pid");
    let script = format!("echo $$ > {}; exec yes", pidfile.display());
    let mut client = h
        .cmd(&["run", "T", "--", "sh", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut out = client.stdout.take().expect("stdout");
    let mut first = [0u8; 4];
    out.read_exact(&mut first).expect("some output");
    drop(out); // like `| head -c 4`
    let status = within(TEST_LIMIT, move || client.wait().expect("wait"));
    assert_eq!(status.code(), Some(141));
    let pid = wait_for_pid(&pidfile);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) {
        assert!(Instant::now() < deadline, "the command kept running");
        std::thread::sleep(Duration::from_millis(50));
    }
    wait_for_run_end(&h, "the run did not end after its output was closed");
}

fn raw_run(h: &Harness, argv: &[&str], forward_stdin: bool) -> std::os::unix::net::UnixStream {
    use rusthorse::protocol::{Binding, Request, RunRequest, send_frame};
    let stream = std::os::unix::net::UnixStream::connect(&h.socket).expect("connect");
    let request = Request::Run(RunRequest {
        bindings: vec![Binding {
            var: "T".into(),
            entry: "T".into(),
        }],
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd: h.dir.path().to_str().expect("utf8").into(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        redact: true,
        forward_stdin,
    });
    send_frame(&stream, &request, &[]).expect("send");
    stream
}

/// Wait until the agent has recorded the end of a run (`exited`), within ten
/// seconds, or fail with `what`. A run whose client went away — killed,
/// half-closed, broken off — ends in the agent a moment later: a test that
/// returned first would have its directory removed while the agent still
/// writes to it, and that record would make the directory again (the audit
/// log creates its missing parents), left behind in `TMPDIR`.
fn wait_for_run_end(h: &Harness, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.audit_text().contains("\"outcome\":\"exited\"") {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_until_dead(pid: u32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_protocol_violation_cancels_even_a_blocked_run() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("flood.pid");
    let script = format!("echo $$ > {}; exec yes", pidfile.display());
    // Never read: the agent's sends fill the socket and block.
    let stream = raw_run(&h, &["sh", "-c", &script], false);
    let pid = wait_for_pid(&pidfile);
    std::thread::sleep(Duration::from_millis(500));
    rusthorse::protocol::send_data(&stream, 7, b"what is this").expect("send garbage");
    wait_until_dead(pid, "the command survived a protocol violation");
    wait_for_run_end(&h, "the request stayed blocked after cancelling");
    drop(stream);
}

#[test]
fn a_half_closed_connection_cancels_even_with_input_pending() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("idle.pid");
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let stream = raw_run(&h, &["sh", "-c", &script], true);
    let pid = wait_for_pid(&pidfile);
    // More input than the command's stdin pipe holds; it never reads it.
    let chunk = vec![b'x'; rusthorse::protocol::MAX_DATA_LEN];
    for _ in 0..3 {
        rusthorse::protocol::send_data(&stream, rusthorse::protocol::STDIN, &chunk).expect("send");
    }
    std::thread::sleep(Duration::from_millis(300));
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close");
    wait_until_dead(pid, "a half-closed connection was not noticed");
    wait_for_run_end(&h, "the run did not end after the half-close");
    drop(stream);
}

#[test]
fn stderr_keeps_flowing_while_stdout_is_stuck() {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (_out_reader, out_writer) = std::io::pipe().expect("pipe");
    nix::fcntl::fcntl(&out_writer, nix::fcntl::FcntlArg::F_SETPIPE_SZ(4096)).expect("pipe size");
    let (mut err_reader, err_writer) = std::io::pipe().expect("pipe");
    let mut client = h
        .cmd(&[
            "run",
            "T",
            "--",
            "sh",
            "-c",
            "head -c 12000 /dev/zero; echo READY >&2; sleep 5",
        ])
        .stdout(Stdio::from(OwnedFd::from(out_writer)))
        .stderr(Stdio::from(OwnedFd::from(err_writer)))
        .spawn()
        .expect("spawn");
    let seen = within(Duration::from_secs(10), move || {
        let mut text = Vec::new();
        let mut byte = [0u8; 1];
        while !String::from_utf8_lossy(&text).contains("READY") {
            if err_reader.read(&mut byte).unwrap_or(0) == 0 {
                break;
            }
            text.push(byte[0]);
        }
        String::from_utf8_lossy(&text).into_owned()
    });
    assert!(seen.contains("READY"), "stderr was held back: {seen:?}");
    let _ = client.kill();
    let _ = client.wait();
    wait_for_run_end(&h, "the run did not end after its client left");
}

#[test]
fn the_library_input_reader_stops_when_the_run_returns() {
    use rusthorse::client::{Client, RunIo};
    use rusthorse::protocol::{Binding, RunRequest};
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (mut reader, mut writer) = std::io::pipe().expect("pipe");
    let input = OwnedFd::from(reader.try_clone().expect("dup"));
    let client = Client::new(h.socket.clone());
    let request = RunRequest {
        bindings: vec![Binding {
            var: "T".into(),
            entry: "T".into(),
        }],
        argv: vec!["true".into()],
        cwd: h.dir.path().to_str().expect("utf8").into(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        redact: true,
        forward_stdin: true,
    };
    let response = client
        .run_with(
            request,
            RunIo {
                input: Some(input),
                stdout: Box::new(std::io::sink()),
                stderr: Box::new(std::io::sink()),
            },
        )
        .expect("run");
    assert!(matches!(
        response,
        rusthorse::protocol::Response::Exited { code: Some(0), .. }
    ));
    std::thread::sleep(Duration::from_millis(300));
    writer.write_all(b"LATER\n").expect("write");
    // Give a reader that is (wrongly) still running ample time to take it.
    std::thread::sleep(Duration::from_millis(500));
    drop(writer);
    let mut left = String::new();
    reader.read_to_string(&mut left).expect("read");
    assert_eq!(left, "LATER\n", "input written after the run was consumed");
}

fn run_request(h: &Harness, argv: &[&str], forward_stdin: bool) -> rusthorse::protocol::RunRequest {
    rusthorse::protocol::RunRequest {
        bindings: vec![rusthorse::protocol::Binding {
            var: "T".into(),
            entry: "T".into(),
        }],
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd: h.dir.path().to_str().expect("utf8").into(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        redact: true,
        forward_stdin,
    }
}

/// A destination that fails every write, like a closed pipe.
struct Broken;
impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A destination that blocks forever, like a pipe nobody reads.
struct Stuck;
impl std::io::Write for Stuck {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        loop {
            std::thread::park();
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn big_input_and_big_output_do_not_deadlock() {
    use std::io::Write;
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    // 2 MiB of input, more than every window; the command first writes 2 MiB
    // and only then reads its input.
    std::thread::spawn(move || {
        let chunk = vec![b'i'; 64 * 1024];
        for _ in 0..32 {
            if writer.write_all(&chunk).is_err() {
                return;
            }
        }
    });
    let client = h
        .cmd(&[
            "run",
            "--stdin",
            "T",
            "--",
            "sh",
            "-c",
            "head -c 2097152 /dev/zero; wc -c >&2",
        ])
        .stdin(Stdio::from(OwnedFd::from(reader)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let out = within(Duration::from_secs(30), move || {
        client.wait_with_output().expect("wait")
    });
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr).trim(), "2097152");
}

#[test]
fn a_violation_behind_pending_input_still_cancels() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("idle2.pid");
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let stream = raw_run(&h, &["sh", "-c", &script], true);
    let pid = wait_for_pid(&pidfile);
    let chunk = vec![b'x'; rusthorse::protocol::MAX_DATA_LEN];
    for _ in 0..3 {
        rusthorse::protocol::send_data(&stream, rusthorse::protocol::STDIN, &chunk).expect("send");
    }
    std::thread::sleep(Duration::from_millis(300));
    rusthorse::protocol::send_data(&stream, 7, b"garbage").expect("send garbage");
    wait_until_dead(
        pid,
        "a protocol violation behind pending input was not noticed",
    );
    wait_for_run_end(&h, "the run did not end after the violation");
    drop(stream);
}

#[test]
fn a_failing_destination_cancels_without_waiting_for_input() {
    use rusthorse::client::{Client, RunIo};
    use std::io::Write;
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    std::thread::spawn(move || {
        let chunk = vec![b'i'; 64 * 1024];
        for _ in 0..32 {
            if writer.write_all(&chunk).is_err() {
                return;
            }
        }
    });
    let client = Client::new(h.socket.clone());
    let request = run_request(&h, &["sh", "-c", "echo oops >&2; exec sleep 30"], true);
    let started = Instant::now();
    let response = within(Duration::from_secs(20), move || {
        client
            .run_with(
                request,
                RunIo {
                    input: Some(OwnedFd::from(reader)),
                    stdout: Box::new(std::io::sink()),
                    stderr: Box::new(Broken),
                },
            )
            .expect("run")
    });
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            response,
            rusthorse::protocol::Response::Exited {
                signal: Some(13),
                ..
            }
        ),
        "{response:?}"
    );
    // The client answered once it had closed the connection; the agent
    // ends the run after that.
    wait_for_run_end(&h, "the run did not end after its client left");
}

#[test]
fn a_stuck_destination_does_not_hold_back_a_broken_pipe() {
    use rusthorse::client::{Client, RunIo};
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let client = Client::new(h.socket.clone());
    let request = run_request(
        &h,
        &[
            "sh",
            "-c",
            "echo out; sleep 0.3; echo err >&2; exec sleep 30",
        ],
        false,
    );
    let started = Instant::now();
    let response = within(Duration::from_secs(20), move || {
        client
            .run_with(
                request,
                RunIo {
                    input: None,
                    stdout: Box::new(Stuck),
                    stderr: Box::new(Broken),
                },
            )
            .expect("run")
    });
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            response,
            rusthorse::protocol::Response::Exited {
                signal: Some(13),
                ..
            }
        ),
        "{response:?}"
    );
    wait_for_run_end(&h, "the run did not end after its client left");
}

#[test]
fn end_of_input_waits_for_pending_input() {
    use rusthorse::protocol::{Frame, MAX_DATA_LEN, STDIN, STDOUT, recv_any_before, send_data};
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    // The command starts reading late, so most input is still pending in the
    // agent when end-of-input arrives.
    let stream = raw_run(&h, &["sh", "-c", "sleep 1; wc -c"], true);
    let chunk = vec![b'x'; MAX_DATA_LEN];
    for _ in 0..3 {
        send_data(&stream, STDIN, &chunk).expect("send");
    }
    send_data(&stream, STDIN, &[]).expect("end of input");
    let mut out = Vec::new();
    loop {
        match recv_any_before(&stream, Some(Instant::now() + Duration::from_secs(20))) {
            Ok(Frame::Data(STDOUT, data)) => out.extend_from_slice(&data),
            Ok(Frame::Data(..)) => {}
            Ok(Frame::Message(..)) => break,
            Err(e) => panic!("connection failed: {e}"),
        }
    }
    assert_eq!(
        text(&out).trim(),
        (3 * MAX_DATA_LEN).to_string(),
        "input was cut short"
    );
}

#[test]
fn the_master_password_can_be_changed() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    let new = "a brand new passphrase";
    h.ui.passwords.lock().unwrap().extend([
        Some(PASSWORD.to_string()),
        Some(new.to_string()),
        Some(new.to_string()),
    ]);
    let out = h.run(&["passwd"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        !h.dir.path().join("vault.kdbx.bak").exists(),
        "old-password backup kept"
    );
    assert!(Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).is_err());
    let reopened =
        Vault::open(&h.vault_path(), SecretString::new(new.into())).expect("new password");
    assert!(reopened.find("T").is_ok());
    assert!(
        h.audit_text()
            .contains("\"action\":\"passwd\",\"outcome\":\"changed\"")
    );
}

#[test]
fn every_unanswered_passwd_dialog_is_recorded_once_and_changes_nothing() {
    let new = "a brand new passphrase";
    for position in 0..3 {
        for timed_out in [false, true] {
            let h = Harness::new();
            assert!(h.run(&["unlock"]).status.success()); // dialog 0
            // Answer the dialogs before `position` (current, new, new again),
            // then leave that one cancelled or unanswered.
            let mut answers: Vec<Option<String>> = [PASSWORD, new, new][..position]
                .iter()
                .map(|a| Some(a.to_string()))
                .collect();
            if timed_out {
                h.ui.password_timeouts.lock().unwrap().push(1 + position);
            } else {
                answers.push(None);
            }
            h.ui.passwords.lock().unwrap().extend(answers);
            let out = h.run(&["passwd"]);
            let case = format!("dialog {position}, timed out: {timed_out}");
            assert_eq!(out.status.code(), Some(4), "{case}: {}", text(&out.stderr));
            assert_eq!(h.ui.password_prompts.lock().unwrap().len(), 2 + position);
            let audit = h.audit_text();
            let records: Vec<&str> = audit
                .lines()
                .filter(|l| l.contains("\"action\":\"passwd\""))
                .collect();
            assert_eq!(records.len(), 1, "{case}: {records:?}");
            let outcome = if timed_out { "timed_out" } else { "cancelled" };
            assert!(
                records[0].contains(&format!("\"outcome\":\"{outcome}\"")),
                "{case}: {}",
                records[0]
            );
            assert!(
                Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).is_ok(),
                "{case}: the password changed"
            );
            // Nor did it change in memory: the next save still uses the
            // original password.
            h.add_secret("SAVED_AFTER", "value", &[]);
            let reopened = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into()))
                .unwrap_or_else(|e| panic!("{case}: the in-memory password changed: {e}"));
            assert!(reopened.find("SAVED_AFTER").is_ok(), "{case}");
        }
    }
}

#[test]
fn a_request_too_tall_to_read_at_once_is_refused() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    // Line breaks in an environment value are shown as escapes: 600 of them
    // are 3000 characters, under the character limit, but far more lines
    // than fit on the screen.
    let out = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", "\n".repeat(600))
        .finish();
    assert_eq!(out.status.code(), Some(125));
    assert!(
        text(&out.stderr).contains("too tall to read at once"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn the_allow_for_note_counts_toward_the_height_limit() {
    use rusthorse::ui::{REMEMBER_NOTE_HEIGHT, approval_height, metrics};
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::Deny]);
    let first = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", "x")
        .finish();
    assert_eq!(first.status.code(), Some(125));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    // The same request with a longer value, as the agent will build it.
    let with_value = |value: &str| {
        let mut grown = request.clone();
        for warning in &mut grown.warnings {
            *warning = warning.replace("GIT_SSH_COMMAND=x", &format!("GIT_SSH_COMMAND={value}"));
        }
        grown
    };
    // The shortest value whose dialog fits on its own but not with the note.
    let value = (1..4000)
        .map(|n| "x".repeat(n))
        .find(|v| approval_height(&with_value(v)) + REMEMBER_NOTE_HEIGHT > metrics::MAX_HEIGHT)
        .expect("a value that is too tall");
    assert!(approval_height(&with_value(&value)) <= metrics::MAX_HEIGHT);
    let second = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", &value)
        .finish();
    assert_eq!(second.status.code(), Some(125));
    assert!(
        text(&second.stderr).contains("too tall to read at once"),
        "{}",
        text(&second.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
    // One character less, and it is asked.
    h.decide(&[Decision::Deny]);
    let third = h
        .cmd(&["run", "T", "--", "true"])
        .env("GIT_SSH_COMMAND", &value[1..])
        .finish();
    assert_eq!(third.status.code(), Some(125));
    assert!(
        text(&third.stderr).contains("denied"),
        "{}",
        text(&third.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
}

#[test]
fn a_value_prompt_too_tall_to_read_at_once_is_refused() {
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    // The new-secret prompt lists the entry's fields: a long URL of wide
    // characters fits the character limit but not the screen.
    let url = format!("https://{}", "W".repeat(1800));
    let out = h.run(&["add", "WIDE", "--url", &url]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("too tall to read at once"),
        "{}",
        text(&out.stderr)
    );
    // No dialog was shown and nothing was stored.
    assert!(h.ui.values.lock().unwrap().is_empty());
    assert!(!text(&h.run(&["list"]).stdout).contains("WIDE"));
}

#[test]
fn a_dialog_that_scrolls_takes_what_is_too_tall_for_zenity() {
    let h = Harness::new();
    h.ui.scrolls.store(true, Ordering::SeqCst);
    assert!(h.run(&["unlock"]).status.success());
    // The prompt that zenity could not show is asked.
    let url = format!("https://{}", "W".repeat(1800));
    h.ui.values
        .lock()
        .unwrap()
        .push_back(Some("value".to_string()));
    let out = h.run(&["add", "WIDE", "--url", &url]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    // So is an approval taller than zenity allows.
    h.decide(&[Decision::Deny]);
    let out = h
        .cmd(&["run", "WIDE", "--", "true"])
        .env("GIT_SSH_COMMAND", "\n".repeat(600))
        .finish();
    assert_eq!(out.status.code(), Some(125));
    assert!(
        text(&out.stderr).contains("denied"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
}

#[test]
fn a_wrong_or_mismatched_password_changes_nothing() {
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    h.ui.passwords
        .lock()
        .unwrap()
        .push_back(Some("not the password".into()));
    assert!(!h.run(&["passwd"]).status.success());
    h.ui.passwords.lock().unwrap().extend([
        Some(PASSWORD.to_string()),
        Some("first version!".to_string()),
        Some("second version".to_string()),
    ]);
    assert!(!h.run(&["passwd"]).status.success());
    assert!(Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).is_ok());
}

#[test]
fn generated_values_are_created_without_anyone_typing_them() {
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    h.decide(&[Decision::Deny]);
    let out = h.run(&["add", "GEN", "--generate"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(!text(&h.run(&["list"]).stdout).contains("GEN"));

    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "add",
        "GEN",
        "--generate",
        "--length",
        "40",
        "--alphabet",
        "hex",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        request
            .details
            .iter()
            .any(|(k, v)| k == "Value" && v.contains("40 hexadecimal"))
    );

    h.decide(&[Decision::AllowOnce]);
    let first = text(&h.run(&["reveal", "GEN"]).stdout).trim().to_string();
    assert_eq!(first.len(), 40);
    assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));

    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
    assert!(h.run(&["edit", "GEN", "--generate"]).status.success());
    let second = text(&h.run(&["reveal", "GEN"]).stdout).trim().to_string();
    assert_eq!(second.len(), 32);
    assert_ne!(first, second);
}

#[test]
fn list_search_matches_names_urls_hosts_and_tags() {
    let h = Harness::new();
    h.add_secret(
        "core-router",
        "abcdefgh",
        &["--host", "10.0.0.1", "--tag", "network"],
    );
    h.add_secret("GITHUB_TOKEN", "abcdefgh", &["--url", "https://github.com"]);
    let names = |search: &str| text(&h.run(&["list", "--search", search]).stdout);
    assert!(names("10.0.0").contains("core-router") && !names("10.0.0").contains("GITHUB"));
    assert!(names("GitHub.COM").contains("GITHUB_TOKEN"));
    assert!(names("netw").contains("core-router"));
}

#[test]
fn open_hands_only_http_links_to_the_browser() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    h.add_secret("site", "abcdefgh", &["--url", "https://router.lan/admin"]);
    h.add_secret("shell", "abcdefgh", &["--url", "ssh://admin@10.0.0.1"]);
    h.add_secret("bare", "abcdefgh", &[]);
    // A stand-in for xdg-open that records what it was asked to open.
    let bin = h.dir.path().join("bin");
    std::fs::create_dir(&bin).expect("mkdir");
    let opened = h.dir.path().join("opened");
    let fake = bin.join("xdg-open");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\necho \"$1\" > {}\n",
            rusthorse::util::shell_quote(&opened.to_string_lossy())
        ),
    )
    .expect("write");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let out = h.cmd(&["open", "site"]).env("PATH", &path).finish();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(&opened).expect("opened").trim(),
        "https://router.lan/admin"
    );
    assert!(
        !h.cmd(&["open", "shell"])
            .env("PATH", &path)
            .finish()
            .status
            .success()
    );
    assert!(
        !h.cmd(&["open", "bare"])
            .env("PATH", &path)
            .finish()
            .status
            .success()
    );
}

/// `open` shows the URL it opens escaped — one that another KeePass client
/// wrote can hold terminal controls — and gives the browser the URL as
/// stored.
#[test]
fn open_shows_a_url_written_elsewhere_escaped() {
    use keepass::db::fields;
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    seed(&h, &[("SITE", "value-1234")]);
    let url = "https://example.invalid/\u{1b}[2J\rFORGED";
    set_field_elsewhere(&h, "SITE", fields::URL, url, false);
    let bin = h.dir.path().join("bin");
    std::fs::create_dir(&bin).expect("mkdir");
    let opened = h.dir.path().join("opened");
    let fake = bin.join("xdg-open");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" > {}\n",
            rusthorse::util::shell_quote(&opened.to_string_lossy())
        ),
    )
    .expect("write");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let out = h.cmd(&["open", "SITE"]).env("PATH", &path).finish();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stderr),
        "Opening https://example.invalid/\\u{1b}[2J\\u{d}FORGED\n"
    );
    assert_eq!(
        std::fs::read_to_string(&opened).expect("opened"),
        format!("{url}\n")
    );
}

/// A raw agent for a client's whole conversation: it answers `status` as a
/// current agent does, and each other request with the raw JSON given for
/// its type, until it has answered `last`.
fn scripted_raw_agent(
    socket: &Path,
    replies: Vec<(&'static str, &'static str)>,
    last: &'static str,
) -> std::thread::JoinHandle<()> {
    use rusthorse::protocol::{PROTOCOL_VERSION, Response, StatusInfo, recv_frame, send_frame};
    use std::io::Write;
    let listener = std::os::unix::net::UnixListener::bind(socket).expect("bind");
    std::thread::spawn(move || {
        loop {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok((body, _fds)) = recv_frame(&stream) else {
                continue;
            };
            let request: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let kind = request["type"].as_str().unwrap_or_default().to_string();
            if kind == "status" {
                let status = Response::Status(StatusInfo {
                    protocol_version: PROTOCOL_VERSION,
                    agent_version: "fake".into(),
                    vault: "/nonexistent".into(),
                    vault_exists: true,
                    audit_log: String::new(),
                    locked: false,
                    idle_timeout_secs: 0,
                    locks_in_secs: None,
                    remembered_approvals: 0,
                    agent_executable: String::new(),
                    agent_executable_id: None,
                    agent_executable_replaced: None,
                    dialogs: None,
                    lock_triggers: vec![],
                    broker: None,
                    grants: None,
                });
                let _ = send_frame(&stream, &status, &[]);
                continue;
            }
            let reply = replies
                .iter()
                .find(|(k, _)| *k == kind)
                .unwrap_or_else(|| panic!("unexpected {kind}"))
                .1;
            let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(reply.as_bytes());
            let _ = stream.write_all(&frame);
            if kind == last {
                return;
            }
        }
    })
}

/// An import whose answer cannot be read is an unknown outcome (124), and
/// the error that quotes the answer is shown escaped.
#[test]
fn an_import_answer_that_cannot_be_read_is_shown_escaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let file = dir.path().join("app.env");
    std::fs::write(&file, "A_KEY=aaaa1111\n").expect("write");
    let fake = scripted_raw_agent(
        &socket,
        vec![
            ("dotenv_names", r#"{"type":"names","names":["A_KEY"]}"#),
            ("import_from", r#"{"type":"\u001b[2J\rFORGED"}"#),
        ],
        "import_from",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["import", "dotenv", file.to_str().expect("utf8")])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(124), "{stderr}");
    assert!(
        !stderr.contains('\u{1b}') && !stderr.contains('\r'),
        "{stderr:?}"
    );
    assert!(stderr.contains("\\u{1b}[2J\\u{d}FORGED"), "{stderr}");
}

#[test]
fn generate_completions_and_doctor_work_offline() {
    let h = Harness::new();
    let out = h.run(&["generate", "--length", "20", "--alphabet", "symbols"]);
    let value = text(&out.stdout).trim().to_string();
    assert_eq!(value.chars().count(), 20);
    let out = h.run(&["completions", "bash"]);
    assert!(out.status.success() && text(&out.stdout).contains("rusthorse"));
    let out = h.run(&["doctor"]);
    let report = text(&out.stdout);
    assert!(report.contains("agent 0.1.0 is running"), "{report}");
    assert!(report.contains("the vault is KDBX 4."), "{report}");
}

#[test]
fn the_ai_guide_needs_no_agent_and_the_help_points_to_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rusthorse = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rusthorse"));
        cmd.env("RUSTHORSE_SOCKET", dir.path().join("nobody.sock"))
            .stdin(Stdio::null());
        cmd
    };
    let out = rusthorse().args(["guide", "ai"]).finish();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let guide = text(&out.stdout);
    assert!(guide.starts_with(&format!(
        "# Rusthorse {}: guide for AI agents\n",
        env!("CARGO_PKG_VERSION")
    )));
    for rule in [
        "Never ask the human for a secret value",
        "Never use `rusthorse reveal`",
        "stop and ask the human",
        "rusthorse run VAR=NAME -- COMMAND",
    ] {
        assert!(guide.contains(rule), "{rule}");
    }
    // A reader that stops early is no error: the pipe has no reader left
    // before the guide is written.
    let guide_to = |stdout: Stdio| {
        let child = rusthorse()
            .args(["guide", "ai"])
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        within(TEST_LIMIT, move || child.wait_with_output().expect("wait"))
    };
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = guide_to(writer.into());
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    // Any other failure to write is an error.
    let full = std::fs::File::create("/dev/full").expect("/dev/full");
    let out = guide_to(full.into());
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("cannot print the guide"));
    // An unknown guide is a command-line error.
    let out = rusthorse().args(["guide", "nope"]).finish();
    assert_eq!(out.status.code(), Some(2));
    let out = rusthorse().arg("--help").finish();
    assert!(text(&out.stdout).contains("`rusthorse guide ai`"));
}

#[test]
fn a_client_that_never_reads_acknowledgements_can_still_cancel() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let pidfile = h.dir.path().join("cat.pid");
    let script = format!("echo $$ > {}; exec cat >/dev/null", pidfile.display());
    let stream = raw_run(&h, &["sh", "-c", &script], true);
    let pid = wait_for_pid(&pidfile);
    // Thousands of one-byte input frames; every one is acknowledged with a
    // credit frame that this client never reads, so the agent's sends back
    // block quickly. The agent must keep reading regardless.
    let sender = stream.try_clone().expect("clone");
    within(Duration::from_secs(20), move || {
        for _ in 0..5000 {
            rusthorse::protocol::send_data(&sender, rusthorse::protocol::STDIN, b"x")
                .expect("the agent stopped reading the connection");
        }
    });
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close");
    wait_until_dead(pid, "the agent stopped watching the connection");
    wait_for_run_end(&h, "the run did not end after the half-close");
    drop(stream);
}

#[test]
fn input_is_not_read_before_the_command_starts() {
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::Deny]);
    let (reader, mut writer) = std::io::pipe().expect("pipe");
    writer.write_all(b"KEEP ME\n").expect("write");
    let out = h
        .cmd(&["run", "--stdin", "T", "--", "cat"])
        .stdin(Stdio::from(OwnedFd::from(reader.try_clone().expect("dup"))))
        .finish();
    assert_eq!(out.status.code(), Some(125));
    drop(writer);
    let mut left = String::new();
    let mut reader = reader;
    reader.read_to_string(&mut left).expect("read");
    assert_eq!(left, "KEEP ME\n", "input was consumed by a denied request");
}

#[test]
fn notes_can_be_revealed_with_approval() {
    let h = Harness::new();
    h.add_secret("router", "abcdefgh", &["--notes", "console on J3"]);
    h.decide(&[Decision::Deny, Decision::AllowOnce]);
    assert_eq!(
        h.run(&["reveal", "router", "--notes"]).status.code(),
        Some(4)
    );
    let out = h.run(&["reveal", "router", "--notes"]);
    assert_eq!(text(&out.stdout).trim(), "console on J3");
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert_eq!(request.summary, "Reveal the notes of an entry?");
    assert!(
        request
            .details
            .iter()
            .any(|(k, v)| k == "Reveals" && v == "notes")
    );
}

#[test]
fn a_stated_reveal_purpose_is_shown_and_audited() {
    use rusthorse::protocol::{ErrorCode, Request, Response, RevealPurpose};
    let h = Harness::new();
    h.add_secret("API", "copy-me-once", &[]);
    let reveal = |purpose| Request::Reveal {
        name: "API".into(),
        notes: false,
        purpose: Some(purpose),
    };

    // Denied: no value, and the dialog said what the value was wanted for.
    h.decide(&[Decision::Deny]);
    match h.call(&reveal(RevealPurpose::Copy)) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
        _ => panic!("a denied reveal must be an error"),
    }
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert_eq!(
        request.summary,
        "Copy the value of an entry to the clipboard?"
    );
    assert!(request.details.iter().any(|(k, v)| {
        k == "Stated purpose (unverified)" && v == "put the value on the clipboard"
    }));
    assert!(request.warnings[0].contains("never into a chat with an AI"));
    // Copying something else replaces the clipboard, not a history's copy.
    assert!(request.warnings[0].contains(
        "until something else is copied, and a clipboard history may keep it even after that"
    ));
    assert!(!request.can_remember);

    // Allowed: the value, and an audit record that names the purpose.
    h.decide(&[Decision::AllowOnce]);
    match h.call(&reveal(RevealPurpose::Copy)) {
        Response::Secret { value } => assert_eq!(value.as_str(), "copy-me-once"),
        _ => panic!("an approved reveal must return the value"),
    }
    h.decide(&[Decision::AllowOnce]);
    assert!(matches!(
        h.call(&reveal(RevealPurpose::Show)),
        Response::Secret { .. }
    ));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert_eq!(request.summary, "Show the value of an entry on screen?");
    // The manager's Show window can copy what it shows without asking again:
    // this approval must say so.
    assert!(request.details.iter().any(|(k, v)| {
        k == "Stated purpose (unverified)" && v.contains("you can copy it from there")
    }));
    assert!(request.warnings[0].contains("clipboard history"));
    let audit = h.audit_text();
    assert!(audit.contains("value, to copy to the clipboard"));
    assert!(audit.contains("value, to show"));
    assert!(!audit.contains("copy-me-once"));

    // Without a purpose (the CLI), the dialog is unchanged.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["reveal", "API"]);
    assert_eq!(text(&out.stdout).trim(), "copy-me-once");
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert_eq!(request.summary, "Reveal the value of an entry?");
    assert!(
        !request
            .details
            .iter()
            .any(|(k, _)| k == "Stated purpose (unverified)")
    );
}

#[test]
fn backups_are_written_and_verified() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    let dest = h.dir.path().join("backups").join("copy.kdbx");
    std::fs::create_dir(dest.parent().expect("dir")).expect("mkdir");
    let out = h.run(&["backup", dest.to_str().expect("utf8")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("verified"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&dest).expect("meta").permissions().mode() & 0o777,
        0o600
    );
    let copy = Vault::open(&dest, SecretString::new(PASSWORD.into())).expect("the copy opens");
    assert!(copy.find("T").is_ok());
    // Never overwrites.
    assert!(
        !h.run(&["backup", dest.to_str().expect("utf8")])
            .status
            .success()
    );
}

#[test]
fn a_lost_connection_after_the_request_is_reported_as_unknown() {
    use rusthorse::protocol::{
        PROTOCOL_VERSION, Request, Response, StatusInfo, recv_frame, send_frame,
    };
    use std::os::unix::net::UnixListener;
    // A fake agent: answers the version check, accepts the run request and
    // then drops the connection without a result.
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    let fake = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            let (body, _fds) = recv_frame(&stream).expect("request");
            let request: Request = serde_json::from_slice(&body).expect("json");
            if matches!(request, Request::Status) {
                let status = Response::Status(StatusInfo {
                    protocol_version: PROTOCOL_VERSION,
                    agent_version: "fake".into(),
                    vault: "/nonexistent".into(),
                    vault_exists: true,
                    audit_log: String::new(),
                    locked: false,
                    idle_timeout_secs: 0,
                    locks_in_secs: None,
                    remembered_approvals: 0,
                    agent_executable: String::new(),
                    agent_executable_id: None,
                    agent_executable_replaced: None,
                    dialogs: None,
                    lock_triggers: vec![],
                    broker: None,
                    grants: None,
                });
                send_frame(&stream, &status, &[]).expect("status");
            } else {
                assert!(matches!(request, Request::Run(_)));
                drop(stream); // gone, after the request arrived
            }
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    within(TEST_LIMIT, move || fake.join()).expect("fake agent");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("may or may not have run"));
}

/// A fake agent on `socket` that answers `status` with `version` and answers
/// a run request with `run_reply` (raw JSON), or drops the connection.
fn fake_agent(
    socket: &Path,
    version: u32,
    run_reply: Option<&'static str>,
    connections: usize,
) -> std::thread::JoinHandle<()> {
    use rusthorse::protocol::{Request, Response, StatusInfo, recv_frame, send_frame};
    let listener = std::os::unix::net::UnixListener::bind(socket).expect("bind");
    std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok((body, _fds)) = recv_frame(&stream) else {
                continue;
            };
            let request: Request = serde_json::from_slice(&body).expect("json");
            if matches!(request, Request::Status) {
                let status = Response::Status(StatusInfo {
                    protocol_version: version,
                    agent_version: "fake".into(),
                    vault: "/nonexistent".into(),
                    vault_exists: true,
                    audit_log: String::new(),
                    locked: false,
                    idle_timeout_secs: 0,
                    locks_in_secs: None,
                    remembered_approvals: 0,
                    agent_executable: String::new(),
                    agent_executable_id: None,
                    agent_executable_replaced: None,
                    dialogs: None,
                    lock_triggers: vec![],
                    broker: None,
                    grants: None,
                });
                let _ = send_frame(&stream, &status, &[]);
            } else if let Some(reply) = run_reply {
                let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(reply.as_bytes());
                use std::io::Write;
                let _ = (&stream).write_all(&frame);
            }
        }
    })
}

#[test]
fn a_malformed_result_after_the_request_is_unknown_not_did_not_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let fake = fake_agent(
        &socket,
        rusthorse::protocol::PROTOCOL_VERSION,
        Some(r#"{"type":"bogus"}"#),
        2,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
}

#[test]
fn a_missing_or_old_agent_means_did_not_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    // No agent at all.
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", dir.path().join("nobody.sock"))
        .stdin(Stdio::null())
        .finish();
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    // Also when the message cannot be written: no crash (101).
    let mut child = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", dir.path().join("nobody.sock"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create("/dev/full").expect("/dev/full"))
        .spawn()
        .expect("spawn");
    let status = within(TEST_LIMIT, move || child.wait().expect("wait"));
    assert_eq!(status.code(), Some(125));
    // An agent speaking an older protocol.
    let socket = dir.path().join("old.sock");
    // Protocol 3: its dialogs for `reveal.purpose` say something else.
    let fake = fake_agent(&socket, 3, None, 2);
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("restart the agent"));
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["list"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("restart the agent"));
    drop(fake);
}

#[test]
fn unread_acknowledgements_do_not_pin_a_finished_command() {
    // A tiny send buffer on the agent side: a handful of unread
    // acknowledgements is enough to block the agent's acknowledgement writer.
    let h = Harness::with_config(Duration::ZERO, Duration::from_secs(10), Some(4096));
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    const FRAMES: usize = 2_000;
    // No output: the output workers finish as soon as the command exits, so
    // only the acknowledgement writer is left blocked.
    let script = format!("head -c {FRAMES} >/dev/null");
    let stream = raw_run(&h, &["sh", "-c", &script], true);
    let sender = stream.try_clone().expect("clone");
    within(Duration::from_secs(30), move || {
        for i in 0..FRAMES {
            rusthorse::protocol::send_data(&sender, rusthorse::protocol::STDIN, b"x")
                .expect("the agent stopped reading the connection");
            if i % 50 == 0 {
                // Let the agent acknowledge in many small steps.
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });
    // The command has read everything and exited; its acknowledgements were
    // never read. A half-close must still end the request, releasing the
    // blocked writer.
    std::thread::sleep(Duration::from_millis(500));
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close");
    wait_for_run_end(&h, "the request stayed pinned by unread acknowledgements");
    drop(stream);
}

#[test]
fn doctor_checks_the_vault_the_agent_uses() {
    let h = Harness::new();
    let out = h
        .cmd(&["doctor"])
        .env(
            "RUSTHORSE_VAULT",
            h.dir.path().join("not-the-agents-vault.kdbx"),
        )
        .finish();
    let report = text(&out.stdout);
    assert!(
        report.contains(&format!("{} is private", h.vault_path().display())),
        "{report}"
    );
    assert!(report.contains("the agent's configuration"), "{report}");
}

#[test]
fn duplicate_names_are_refused_before_anything_is_imported() {
    use rusthorse::protocol::{EntryFields, ImportedEntry, NewEntry, Request, Response};
    let h = Harness::new();
    assert!(h.run(&["unlock"]).status.success());
    let env_file = h.dir.path().join("dup.env");
    std::fs::write(&env_file, "DUP=first\nOTHER=x1234\nDUP=second\n").expect("write");
    let file = env_file.to_str().expect("utf8");
    // The file is refused as soon as the agent reads it for the names:
    // nothing is listed, nothing imported.
    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
    let preview = h.run(&["import", "dotenv", file, "--dry-run"]);
    assert!(!preview.status.success());
    assert!(
        text(&preview.stderr).contains("line 3: DUP is set again (also on line 1)"),
        "{}",
        text(&preview.stderr)
    );
    assert!(text(&preview.stdout).is_empty());
    let out = h.run(&["import", "dotenv", file, "--replace"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("DUP is set again"));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
    assert!(!text(&h.run(&["list"]).stdout).contains("OTHER"));
    // The agent refuses such a batch too.
    let item = |value: &str| ImportedEntry {
        entry: NewEntry {
            name: "DUP".into(),
            fields: EntryFields::default(),
            ..NewEntry::default()
        },
        value: SecretString::new(value.into()),
    };
    // Would be approved: the refusal must come from the duplicate check,
    // before any dialog.
    h.decide(&[Decision::AllowOnce]);
    let response = h.call(&Request::Import {
        entries: vec![item("aaaa1"), item("bbbb2")],
        replace: true,
    });
    match response {
        Response::Error { message, .. } => assert!(message.contains("more than once"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
}

/// A fake agent that answers `status` and `dotenv_names` (the names in the
/// file), then answers each `import_from` with the next raw JSON reply
/// (`None`: the answer is lost), then stops listening.
fn fake_import_agent(
    socket: &Path,
    replies: Vec<Option<&'static str>>,
) -> std::thread::JoinHandle<()> {
    use rusthorse::protocol::{
        PROTOCOL_VERSION, Request, Response, StatusInfo, recv_frame, send_frame,
    };
    let mut listener = Some(std::os::unix::net::UnixListener::bind(socket).expect("bind"));
    let path = socket.to_path_buf();
    std::thread::spawn(move || {
        let mut replies = replies.into_iter();
        while let Some(open) = &listener {
            let Ok((stream, _)) = open.accept() else {
                return;
            };
            let (body, _fds) = recv_frame(&stream).expect("request");
            match serde_json::from_slice::<Request>(&body).expect("json") {
                Request::Status => {
                    let status = Response::Status(StatusInfo {
                        protocol_version: PROTOCOL_VERSION,
                        agent_version: "fake".into(),
                        vault: "/nonexistent".into(),
                        vault_exists: true,
                        audit_log: String::new(),
                        locked: false,
                        idle_timeout_secs: 0,
                        locks_in_secs: None,
                        remembered_approvals: 0,
                        agent_executable: String::new(),
                        agent_executable_id: None,
                        agent_executable_replaced: None,
                        dialogs: None,
                        lock_triggers: vec![],
                        broker: None,
                        grants: None,
                    });
                    send_frame(&stream, &status, &[]).expect("status");
                }
                Request::DotenvNames { path } => {
                    let text = std::fs::read_to_string(&path).expect("the .env file");
                    let parsed = rusthorse::import::parse_dotenv(&text).expect("parse");
                    let names = parsed.pairs.into_iter().map(|(name, _)| name).collect();
                    let empty = parsed.empty;
                    send_frame(&stream, &Response::Names { names, empty }, &[]).expect("names");
                }
                Request::ImportFrom { .. } => {
                    let Some(reply) = replies.next() else {
                        panic!("more batches than expected");
                    };
                    if replies.len() == 0 {
                        // Stop listening *before* answering, so that no later
                        // connection can be queued and then reset; its request
                        // must never be sent. Closing the listener is not
                        // enough: a child forked by another test keeps a copy
                        // of it until its exec. Removing the socket file makes
                        // every later connect fail at once.
                        std::fs::remove_file(&path).expect("remove socket");
                        listener = None;
                    }
                    if let Some(reply) = reply {
                        let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
                        frame.extend_from_slice(reply.as_bytes());
                        use std::io::Write;
                        (&stream).write_all(&frame).expect("reply");
                    }
                }
                other => panic!("unexpected request {other:?}"),
            }
        }
    })
}

/// Import names that make exactly two batches (as many as fit in one
/// dialog, and five more) through the fake agent on `socket`.
fn import_two_batches(dir: &Path, socket: &Path) -> std::process::Output {
    let env_file = dir.join("many.env");
    let path = env_file.display().to_string();
    let planned = |n: usize| -> Vec<rusthorse::import::Planned> {
        (0..n)
            .map(|i| rusthorse::import::Planned {
                name: format!("NAME_{i:03}"),
                item: None,
            })
            .collect()
    };
    // (The fake agent does not say which dialogs it shows: heights count.)
    let first = rusthorse::import::batch_sizes(&planned(500), Some(&path), true)[0];
    let count = first + 5;
    assert_eq!(
        rusthorse::import::batch_sizes(&planned(count), Some(&path), true),
        [first, 5]
    );
    let lines: String = (0..count)
        .map(|i| format!("NAME_{i:03}=value{i}\n"))
        .collect();
    std::fs::write(&env_file, lines).expect("write");
    Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["import", "dotenv", env_file.to_str().expect("utf8")])
        .env("RUSTHORSE_SOCKET", socket)
        .stdin(Stdio::null())
        .finish()
}

const IMPORTED: Option<&str> = Some(r#"{"type":"ok","message":"imported 50"}"#);

#[test]
fn a_batch_whose_answer_is_lost_is_reported_as_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let fake = fake_import_agent(&socket, vec![IMPORTED, None]);
    let out = import_two_batches(dir.path(), &socket);
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("lost the connection during batch 2 of 2"),
        "{stderr}"
    );
    assert!(stderr.contains("batches 1 to 1 were imported"), "{stderr}");
    assert!(
        stderr.contains("batch 2 may or may not have been imported"),
        "{stderr}"
    );
}

#[test]
fn a_batch_the_agent_cannot_confirm_is_reported_as_unknown() {
    // For example, the vault file was replaced but its directory not synced.
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let fake = fake_import_agent(
        &socket,
        vec![
            IMPORTED,
            Some(r#"{"type":"error","code":"outcome_unknown","message":"not durable"}"#),
        ],
    );
    let out = import_two_batches(dir.path(), &socket);
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("could not confirm batch 2 of 2"),
        "{stderr}"
    );
    assert!(
        stderr.contains("batch 2 may or may not have been imported"),
        "{stderr}"
    );
    assert!(!stderr.contains("were not imported —"), "{stderr}");
}

#[test]
fn a_batch_the_agent_refuses_or_never_receives_is_reported_as_not_imported() {
    for second in [
        // Refused: any error other than outcome_unknown means nothing changed.
        Some(r#"{"type":"error","code":"internal","message":"disk full"}"#),
        // Never sent: the agent stopped after the first batch.
        IMPORTED,
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("fake.sock");
        let replies = if second == IMPORTED {
            vec![IMPORTED]
        } else {
            vec![IMPORTED, second]
        };
        let fake = fake_import_agent(&socket, replies);
        let out = import_two_batches(dir.path(), &socket);
        within(TEST_LIMIT, move || fake.join()).expect("fake");
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("stopped at batch 2 of 2: batches 1 to 1 were imported; batch 2 and later were not imported"),
            "{stderr}"
        );
        assert!(!stderr.contains("may or may not"), "{stderr}");
    }
}

#[test]
fn a_lost_answer_is_an_unknown_outcome_only_for_requests_with_effects() {
    for (args, expected) in [
        (&["remove", "X"][..], 124),
        (&["edit", "X", "--host", "h"][..], 124),
        (&["list"][..], 1),
        (&["show", "X"][..], 1),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("fake.sock");
        let fake = fake_agent(&socket, rusthorse::protocol::PROTOCOL_VERSION, None, 2);
        let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
            .args(args)
            .env("RUSTHORSE_SOCKET", &socket)
            .stdin(Stdio::null())
            .finish();
        within(TEST_LIMIT, move || fake.join()).expect("fake");
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(expected), "{args:?}: {stderr}");
        assert_eq!(
            stderr.contains("may or may not have taken effect"),
            expected == 124,
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn an_unknown_outcome_reported_for_a_change_exits_124() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let fake = fake_agent(
        &socket,
        rusthorse::protocol::PROTOCOL_VERSION,
        Some(r#"{"type":"error","code":"outcome_unknown","message":"not durable"}"#),
        2,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["remove", "X"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
}

#[test]
fn an_unexpected_answer_to_run_is_an_unknown_outcome() {
    for reply in [
        r#"{"type":"ok","message":"?"}"#,
        // An exit status with neither a code nor a signal.
        r#"{"type":"exited"}"#,
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("fake.sock");
        let fake = fake_agent(
            &socket,
            rusthorse::protocol::PROTOCOL_VERSION,
            Some(reply),
            2,
        );
        let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
            .args(["run", "T", "--", "true"])
            .env("RUSTHORSE_SOCKET", &socket)
            .stdin(Stdio::null())
            .finish();
        within(TEST_LIMIT, move || fake.join()).expect("fake");
        assert_eq!(
            out.status.code(),
            Some(124),
            "{reply}: {}",
            text(&out.stderr)
        );
        assert!(text(&out.stderr).contains("may or may not have run"));
    }
}

#[test]
fn an_unexpected_answer_to_a_change_is_an_unknown_outcome() {
    for (args, expected) in [(&["remove", "X"][..], 124), (&["lock"][..], 1)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("fake.sock");
        let fake = fake_agent(
            &socket,
            rusthorse::protocol::PROTOCOL_VERSION,
            Some(r#"{"type":"exited","code":0}"#),
            2,
        );
        let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
            .args(args)
            .env("RUSTHORSE_SOCKET", &socket)
            .stdin(Stdio::null())
            .finish();
        within(TEST_LIMIT, move || fake.join()).expect("fake");
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn status_names_the_agents_program_file() {
    let h = Harness::new();
    let client = rusthorse::client::Client::new(h.socket.clone());
    let rusthorse::protocol::Response::Status(info) = client
        .call(&rusthorse::protocol::Request::Status)
        .expect("status")
    else {
        panic!("not a status answer");
    };
    // The harness agent runs inside this test binary.
    let ours = std::fs::read_link("/proc/self/exe").expect("exe");
    assert_eq!(info.agent_executable, ours.display().to_string());
    assert_eq!(info.agent_executable_replaced, Some(false));
    assert_eq!(
        info.agent_executable_id,
        rusthorse::util::file_identity(std::path::Path::new("/proc/self/exe")).ok()
    );
}

#[test]
fn an_unknown_outcome_from_the_agent_exits_124() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("fake.sock");
    let fake = fake_agent(
        &socket,
        rusthorse::protocol::PROTOCOL_VERSION,
        Some(r#"{"type":"error","code":"outcome_unknown","message":"waiting failed"}"#),
        2,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rusthorse"))
        .args(["run", "T", "--", "true"])
        .env("RUSTHORSE_SOCKET", &socket)
        .stdin(Stdio::null())
        .finish();
    within(TEST_LIMIT, move || fake.join()).expect("fake");
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
}

#[test]
fn locking_while_the_dialog_is_open_cancels_the_run() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let socket = h.socket.clone();
    *h.ui.on_approve.lock().unwrap() = Some(Box::new(move || {
        let client = rusthorse::client::Client::new(socket);
        client
            .call(&rusthorse::protocol::Request::Lock)
            .expect("lock");
    }));
    let marker = h.dir.path().join("ran");
    let out = h.run(&["run", "T", "--", "touch", marker.to_str().expect("utf8")]);
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("locked or changed"));
    assert!(!marker.exists());
    // The approval is on record, and after it why nothing ran.
    assert_eq!(audit_outcomes(&h, "run"), ["allowed_once", "aborted"]);
    let aborted = audit_records(&h)
        .into_iter()
        .rfind(|r| r["action"] == "run")
        .expect("the run's record");
    assert!(
        aborted["detail"]
            .as_str()
            .is_some_and(|d| d.contains("locked or changed")),
        "{aborted}"
    );
}

#[test]
fn replacing_the_program_after_approval_cancels_the_run() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let script = h.dir.path().join("tool.sh");
    std::fs::write(&script, "#!/bin/sh\necho approved-version\n").expect("write");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let swapped = script.clone();
    *h.ui.on_approve.lock().unwrap() = Some(Box::new(move || {
        let evil = swapped.with_extension("new");
        std::fs::write(&evil, "#!/bin/sh\necho swapped-version\n").expect("write");
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::rename(&evil, &swapped).expect("rename");
    }));
    let out = h.run(&["run", "T", "--", "./tool.sh"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(!text(&out.stdout).contains("swapped-version"));
    assert!(text(&out.stderr).contains("replaced after you approved"));
}

#[test]
fn command_lines_too_long_to_read_are_refused() {
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    let long = "x".repeat(1200);
    let out = h.run(&["run", "T", "--", "echo", &long]);
    assert_eq!(out.status.code(), Some(125));
    assert!(text(&out.stderr).contains("too long"));
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
}

#[test]
fn descriptors_on_other_requests_are_rejected() {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    let h = Harness::new();
    let stream = UnixStream::connect(&h.socket).expect("connect");
    let devnull = std::fs::File::open("/dev/null").expect("devnull");
    rusthorse::protocol::send_frame(
        &stream,
        &rusthorse::protocol::Request::Status,
        &[devnull.as_fd()],
    )
    .expect("send");
    let response: rusthorse::protocol::Response =
        rusthorse::protocol::read_message(&stream).expect("read");
    assert!(matches!(
        response,
        rusthorse::protocol::Response::Error {
            code: rusthorse::protocol::ErrorCode::InvalidRequest,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// The credential broker (ADR 0013). The agent starts `rusthorse-broker` for
// each grant; here a stand-in written in Python plays it (`fake_broker`): it
// follows the control channel as far as its mode says and logs what it
// receives. The real broker is tested with the agent after the merge.

/// A fake key: what the broker would present to the destination.
const FAKE_KEY: &str = "sk-ant-test-0000000000000000";

/// Whether these tests can run a stand-in broker: it is a Python script.
/// Without `/usr/bin/python3` they fail — a machine without Python must not
/// lose every end-to-end test of the broker's side silently — unless
/// `RUSTHORSE_TEST_WITHOUT_PYTHON` is set, which skips them, saying so.
fn python3() -> bool {
    if Path::new("/usr/bin/python3").exists() {
        return true;
    }
    assert!(
        std::env::var_os("RUSTHORSE_TEST_WITHOUT_PYTHON").is_some(),
        "/usr/bin/python3 is needed for the stand-in broker of this test; set \
         RUSTHORSE_TEST_WITHOUT_PYTHON=1 to skip the tests that need it"
    );
    eprintln!("skipped: /usr/bin/python3 is needed for a stand-in broker");
    false
}

/// Write an executable file that only its owner can change, from another
/// process, and put it in place at once: a file that this process held open
/// for writing could not be run while a process forked meanwhile by another
/// test still held that descriptor ("Text file busy").
fn write_program(path: &Path, text: &str) {
    use std::io::Write;
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

/// A stand-in for `rusthorse-broker`. It reads the install (and the
/// listening socket that comes with it), logs it with what it can see of
/// its own process, then, by `MODE`:
///
/// - `silent`: never answers;
/// - `wrong_grant`, `old_version`: answers ready for another grant, or in
///   another version;
/// - `first_serves`: the first of its brokers to read its install (which
///   creates `LOG.first`) goes on; any other exits with status 5 without
///   answering;
/// - `held_ready`: answers ready only once the test has created
///   `LOG.ready`;
/// - anything else: answers ready; `bad_number` then asks for request 5
///   first, and `admit` for requests 1 and 2 (finishing 1 between them),
///   once the command has created `LOG.go`; `unauthorized` asks for
///   requests 1 to 3 one at a time and, once each is admitted, reports its
///   end with the destination's status 401, 200 and 401 (the last one
///   closed by the client), then creates `LOG.done`; `ignore_revoke` never
///   confirms a revocation, the others confirm at once.
///
/// It logs every message it receives and exits when its channel ends.
const FAKE_BROKER: &str = r#"#!/usr/bin/python3 -I
import json, os, socket, struct, sys, time

MODE = "@MODE@"
LOG = "@LOG@"

def log(entry):
    with open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

chan = socket.socket(fileno=0)

def recv_exact(n, got=b""):
    while len(got) < n:
        part = chan.recv(n - len(got))
        if not part:
            log({"event": "eof"})
            sys.exit(0)
        got += part
    return got

def read_frame(want_fds=False):
    fds = []
    if want_fds:
        data, ancillary, _, _ = chan.recvmsg(4, socket.CMSG_SPACE(16 * 4))
        if not data:
            log({"event": "eof"})
            sys.exit(0)
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(payload) // 4
                fds += struct.unpack("%di" % count, payload[: count * 4])
        head = recv_exact(4, data)
    else:
        head = recv_exact(4)
    (length,) = struct.unpack(">I", head)
    return json.loads(recv_exact(length)), list(fds)

def send(message):
    body = json.dumps(message).encode()
    chan.sendall(struct.pack(">I", len(body)) + body)

def wait_for(path):
    for _ in range(600):
        if os.path.exists(path):
            return
        time.sleep(0.05)

install, fds = read_frame(want_fds=True)
with open("/proc/self/environ", "rb") as f:
    environ = f.read().decode("latin-1")
entry = {
    "event": "install",
    "pid": os.getpid(),
    "pgid": os.getpgrp(),
    "argv": sys.argv[1:],
    "environ": environ,
    "cwd": os.getcwd(),
    "stderr": os.readlink("/proc/self/fd/2"),
    "fds": len(fds),
    "install": install,
}
if len(fds) == 1:
    listener = socket.socket(fileno=fds[0])
    entry["listen"] = list(listener.getsockname())
    entry["inet"] = listener.family == socket.AF_INET
    entry["accepting"] = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
log(entry)

if MODE == "first_serves":
    try:
        os.close(os.open(LOG + ".first", os.O_CREAT | os.O_EXCL))
    except FileExistsError:
        sys.exit(5)
if MODE == "held_ready":
    wait_for(LOG + ".ready")
if MODE == "silent":
    while chan.recv(65536):
        pass
    log({"event": "eof"})
    sys.exit(0)
grant = install["grant"]
version = install["version"]
if MODE == "wrong_grant":
    grant = "g0000000000000000"
if MODE == "old_version":
    version = 99
send({"type": "ready", "version": version, "grant": grant})

if MODE == "bad_number":
    wait_for(LOG + ".go")
    send({"type": "admit", "request": 5, "method": "POST"})
if MODE == "admit":
    wait_for(LOG + ".go")
    send({"type": "admit", "request": 1, "method": "POST"})
    answer, _ = read_frame()
    log({"event": "answer", "message": answer})
    send({"type": "finished", "request": 1, "outcome": "completed", "status": 200,
          "bytes_sent": 10, "bytes_received": 20})
    send({"type": "admit", "request": 2, "method": "GET"})
    answer, _ = read_frame()
    log({"event": "answer", "message": answer})
    open(LOG + ".done", "w").close()
if MODE == "unauthorized":
    wait_for(LOG + ".go")
    for request, status, outcome in [(1, 401, "completed"), (2, 200, "completed"),
                                      (3, 401, "client_closed")]:
        send({"type": "admit", "request": request, "method": "POST"})
        answer, _ = read_frame()
        log({"event": "answer", "message": answer})
        send({"type": "finished", "request": request, "outcome": outcome, "status": status,
              "bytes_sent": 10, "bytes_received": 20})
    open(LOG + ".done", "w").close()

while True:
    message, _ = read_frame()
    log({"event": message["type"], "message": message})
    if message["type"] == "revoke" and MODE != "ignore_revoke":
        send({"type": "revoked", "refused": 0})
"#;

impl Harness {
    /// Where this harness's agent looks for `rusthorse-broker`.
    fn broker_program(&self) -> PathBuf {
        self.dir.path().join("rusthorse-broker")
    }
}

/// Put a stand-in broker in `mode` where the agent looks for it; returns
/// the log it writes.
fn fake_broker(h: &Harness, mode: &str) -> PathBuf {
    let log = h.dir.path().join(format!("broker-{mode}.jsonl"));
    let _ = std::fs::remove_file(&log);
    let script = FAKE_BROKER
        .replace("@MODE@", mode)
        .replace("@LOG@", log.to_str().expect("utf8"));
    write_program(&h.broker_program(), &script);
    log
}

/// Whether an install a stand-in broker logged is one the real broker would
/// take: the checks of `Install::validate` — control channel 2, a valid
/// origin, a lifetime of at most a day among them.
fn installs_validly(install: &serde_json::Value) -> Result<(), String> {
    use rusthorse::broker_protocol::ToBroker;
    match serde_json::from_value::<ToBroker>(install.clone()) {
        Ok(ToBroker::Install(install)) => install.validate().map_err(str::to_string),
        Ok(other) => Err(format!("not an install: {other:?}")),
        Err(e) => Err(format!("not a message: {e}")),
    }
}

/// What a stand-in broker logged so far.
fn broker_log(log: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Wait until `f` gives something, within [`TEST_LIMIT`].
fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + TEST_LIMIT;
    loop {
        if let Some(found) = f() {
            return found;
        }
        assert!(Instant::now() < until, "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The first entry of a stand-in broker's log with this event, once it is
/// there.
fn logged(log: &Path, event: &str) -> serde_json::Value {
    eventually(event, || {
        broker_log(log)
            .into_iter()
            .find(|entry| entry["event"] == event)
    })
}

/// The first entry of a stand-in broker's log with this event, if it is
/// there within `limit`.
fn logged_within(log: &Path, event: &str, limit: Duration) -> Option<serde_json::Value> {
    let until = Instant::now() + limit;
    loop {
        if let Some(found) = broker_log(log)
            .into_iter()
            .find(|entry| entry["event"] == event)
        {
            return Some(found);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The audit log, blocked: a FIFO in its place, which nobody opens until
/// [`BlockedAudit::release`]. A record waits to open it; once it can, it
/// fails (a FIFO cannot be synced to disk), as a log on a failing disk
/// would. Dropping it puts the log back: the records that follow are kept.
struct BlockedAudit {
    path: PathBuf,
    reader: Option<std::fs::File>,
    /// What the records written into the FIFO put there, as read so far.
    taken: Vec<u8>,
}

impl BlockedAudit {
    fn new(h: &Harness) -> BlockedAudit {
        let path = h.audit.clone();
        let _ = std::fs::remove_file(&path);
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        BlockedAudit {
            path,
            reader: None,
            taken: Vec::new(),
        }
    }

    /// Once released, wait until the end record of the grant `id` has been
    /// written into the FIFO, where it fails. A grant's end is recorded by
    /// another thread of the agent, once its broker confirms: a test that
    /// put the log back first could have it written in the log instead,
    /// possibly after the test, into a directory already removed.
    fn wait_for_end_of(&mut self, id: &str) {
        use std::io::Read;
        let reader = self.reader.as_mut().expect("released first");
        nix::fcntl::fcntl(
            &*reader,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .expect("non-blocking");
        let until = Instant::now() + TEST_LIMIT;
        loop {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => self.taken.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("cannot read the FIFO: {e}"),
                }
            }
            let ended = String::from_utf8_lossy(&self.taken).lines().any(|line| {
                serde_json::from_str::<serde_json::Value>(line).is_ok_and(|record| {
                    record["action"] == "grant"
                        && record["outcome"] == "ended"
                        && record["grant"] == id
                })
            });
            if ended {
                return;
            }
            assert!(
                Instant::now() < until,
                "the end of grant {id} was never recorded"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Let the records waiting for the log go on, to fail.
    fn release(&mut self) {
        // For reading and writing: opening it never waits, and the records
        // written meanwhile stay in the pipe, unread.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .expect("open the FIFO");
        self.reader = Some(reader);
    }
}

impl Drop for BlockedAudit {
    fn drop(&mut self) {
        // Records still waiting — a test that failed before it released
        // them — go on, to fail, rather than wait forever.
        if self.reader.is_none() {
            self.reader = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .ok();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether the process `pid` runs now: it exists and is not a zombie.
fn process_alive(pid: u64) -> bool {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Err(_) => false,
        Ok(stat) => {
            let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
            !matches!(stat.get(close + 2), Some(b'Z' | b'X'))
        }
    }
}

/// Whether the process `pid` is gone (or a zombie nobody waits for any
/// more), within a few seconds.
fn process_gone(pid: u64) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        match std::fs::read(format!("/proc/{pid}/stat")) {
            Err(_) => return true,
            Ok(stat) => {
                let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
                if matches!(stat.get(close + 2), Some(b'Z' | b'X')) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Whether the port `port` of 127.0.0.1 can be listened on again, within a
/// few seconds. A process forked meanwhile by another test holds a copy of
/// every descriptor of this process — the agent's listening sockets among
/// them — until it executes its program, which under load can take a
/// moment after the agent closed its own; a socket still held after a few
/// seconds was not let go.
fn port_released(port: u16) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Write entries into the vault file before the agent opens it — name and
/// value — and return their UUIDs by name.
fn seed(h: &Harness, entries: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    use rusthorse::protocol::NewEntry;
    let mut vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
    let mut uuids = std::collections::HashMap::new();
    for (name, value) in entries {
        let entry = NewEntry {
            name: name.to_string(),
            ..NewEntry::default()
        };
        vault
            .add(&entry, &SecretString::new(value.to_string()), false)
            .expect("add");
        let id = vault.find(name).expect("find");
        uuids.insert(name.to_string(), vault.info(id).id);
    }
    vault.save().expect("save");
    uuids
}

/// Set a field of the entry titled `title` as another KeePass client could:
/// in the file, while the agent does not have it open.
fn set_field_elsewhere(h: &Harness, title: &str, key: &str, value: &str, protected: bool) {
    use keepass::{Database, DatabaseKey};
    let path = h.vault_path();
    let mut db = Database::open(
        &mut std::fs::File::open(&path).expect("open"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("decrypt");
    let id = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .map(|e| e.id())
        .expect("the entry");
    {
        let mut entry = db.entry_mut(id).expect("entry");
        if protected {
            entry.set_protected(key, value);
        } else {
            entry.set_unprotected(key, value);
        }
    }
    let mut file = std::fs::File::create(&path).expect("rewrite");
    db.save(&mut file, DatabaseKey::new().with_password(PASSWORD))
        .expect("save");
}

fn by_value(var: &str, entry: &str) -> rusthorse::protocol::Binding {
    rusthorse::protocol::Binding {
        var: var.into(),
        entry: entry.into(),
    }
}

/// Where the grants of these tests send their key, unless a test names
/// another destination: no stand-in broker connects anywhere.
const DESTINATION: &str = "https://api.example.com";

/// A broker binding of `entry` to [`DESTINATION`].
fn brokered(var: &str, entry: &str, url_var: Option<&str>) -> rusthorse::protocol::BrokerBinding {
    brokered_to(var, entry, DESTINATION, url_var)
}

/// A broker binding of `entry` to `destination`, as `--broker
/// VAR=ENTRY@URL` sends it.
fn brokered_to(
    var: &str,
    entry: &str,
    destination: &str,
    url_var: Option<&str>,
) -> rusthorse::protocol::BrokerBinding {
    rusthorse::protocol::BrokerBinding {
        var: var.into(),
        entry: entry.into(),
        destination: destination.into(),
        url_var: url_var.map(str::to_string),
    }
}

/// A run of `sh -c script` in the harness's directory, with redaction and
/// the default limits (no request limit, 12 hours, `continue`).
fn broker_run_request(
    h: &Harness,
    bindings: Vec<rusthorse::protocol::Binding>,
    brokered: Vec<rusthorse::protocol::BrokerBinding>,
    script: &str,
) -> rusthorse::protocol::BrokerRunRequest {
    rusthorse::protocol::BrokerRunRequest {
        run: rusthorse::protocol::RunRequest {
            bindings,
            argv: vec!["sh".into(), "-c".into(), script.into()],
            cwd: h.dir.path().to_str().expect("utf8").into(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            redact: true,
            forward_stdin: false,
        },
        brokered,
        limits: rusthorse::broker_grant::GrantLimits::default(),
    }
}

/// What a command printed, as the client received it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        text(&self.0.lock().unwrap())
    }
}

/// A broker run under way, sent by a thread of its own.
struct Running {
    answer: std::sync::mpsc::Receiver<rusthorse::protocol::Response>,
    output: Captured,
}

impl Running {
    /// The agent's answer, once the run is over.
    fn wait(&self) -> rusthorse::protocol::Response {
        self.answer
            .recv_timeout(TEST_LIMIT)
            .expect("the run's answer")
    }
}

fn start(h: &Harness, request: rusthorse::protocol::BrokerRunRequest) -> Running {
    use rusthorse::client::{Client, RunIo};
    let client = Client::new(h.socket.clone());
    let output = Captured::default();
    let io = RunIo {
        input: None,
        stdout: Box::new(output.clone()),
        stderr: Box::new(output.clone()),
    };
    let (tx, answer) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok(response) = client.broker_run_with(request, io) {
            let _ = tx.send(response);
        }
    });
    Running { answer, output }
}

/// Send a broker run and wait for its answer.
fn broker_run(
    h: &Harness,
    request: rusthorse::protocol::BrokerRunRequest,
) -> rusthorse::protocol::Response {
    start(h, request).wait()
}

/// A command that writes its environment to `env.txt`, then waits until the
/// test creates `go` (at most 30 seconds).
const WAITS: &str = "env > env.new && mv env.new env.txt; i=0; \
                     while [ ! -e go ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done";

/// The environment the waiting command got, once it has started.
fn command_env(h: &Harness) -> std::collections::BTreeMap<String, String> {
    let path = h.dir.path().join("env.txt");
    let text = eventually("the command to start", || {
        std::fs::read_to_string(&path).ok()
    });
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Let the waiting command finish.
fn go(h: &Harness) {
    std::fs::write(h.dir.path().join("go"), "").expect("go");
}

fn grants(h: &Harness) -> Vec<rusthorse::protocol::GrantInfo> {
    match h.call(&rusthorse::protocol::Request::Grants) {
        rusthorse::protocol::Response::Grants { grants } => grants,
        other => panic!("unexpected {}", other.kind()),
    }
}

/// The state of the grant `id`, or `None` once it has ended.
fn grant_state(h: &Harness, id: &str) -> Option<String> {
    grants(h).into_iter().find(|g| g.id == id).map(|g| g.state)
}

fn status(h: &Harness) -> rusthorse::protocol::StatusInfo {
    match h.call(&rusthorse::protocol::Request::Status) {
        rusthorse::protocol::Response::Status(info) => info,
        other => panic!("unexpected {}", other.kind()),
    }
}

/// The reasons the grants' end records give, by grant ID.
fn grant_ends(h: &Harness) -> std::collections::BTreeMap<String, serde_json::Value> {
    audit_records(h)
        .into_iter()
        .filter(|r| r["action"] == "grant" && r["outcome"] == "ended")
        .map(|r| (r["grant"].as_str().unwrap_or_default().to_string(), r))
        .collect()
}

fn ended_with(h: &Harness, id: &str) -> String {
    eventually("the grant's end record", || {
        grant_ends(h)
            .get(id)
            .map(|r| r["reason"].as_str().unwrap_or_default().to_string())
    })
}

fn error_of(response: &rusthorse::protocol::Response) -> (rusthorse::protocol::ErrorCode, String) {
    match response {
        rusthorse::protocol::Response::Error { code, message } => (*code, message.clone()),
        other => panic!("not an error: {}", other.kind()),
    }
}

/// A run through the broker is refused before any dialog when one of its
/// checks fails (ADR 0013: the broker program, the number of grants, the
/// variables, the entries and their values), and so is a plain `run` that
/// carries broker bindings: no dialog, no command, no grant, no `run`
/// record, no broker started — and never the values instead.
#[test]
fn broker_runs_that_fail_a_check_start_nothing_and_ask_nothing() {
    use rusthorse::protocol::{ErrorCode, Request, Response, read_message, send_frame};
    use std::os::unix::net::UnixStream;
    if !python3() {
        return;
    }
    let h = Harness::new();
    let uuids = seed(
        &h,
        &[
            ("T", "abcdefgh"),
            ("KEY", FAKE_KEY),
            ("SHORT", "sk-1234"),
            ("SPACED", "sk-ant-test 0000"),
        ],
    );
    // Had the agent asked, the run would be allowed, and the command would
    // leave this file behind.
    h.decide(&[Decision::AllowOnce]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    let request = |bindings, brokered| broker_run_request(&h, bindings, brokered, &script);
    let refused = |request, code: ErrorCode, says: &str| {
        let response = broker_run(&h, request);
        let (got, message) = error_of(&response);
        assert_eq!(got, code, "{message}");
        assert!(message.contains(says), "{says:?} not in: {message}");
    };
    let key = || vec![brokered("KEY", "KEY", None)];

    // Before the vault is opened: the broker program, absent and unusable.
    refused(request(vec![], key()), ErrorCode::Internal, "not installed");
    let log = fake_broker(&h, "ready");
    {
        use std::os::unix::fs::PermissionsExt;
        let program = h.broker_program();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        refused(request(vec![], key()), ErrorCode::Internal, "chmod go-w");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    // More grants than an agent serves.
    let many: Vec<_> = (0..17)
        .map(|i| brokered(&format!("KEY{i}"), "KEY", None))
        .collect();
    refused(
        request(vec![], many),
        ErrorCode::InvalidRequest,
        "at most 16 grants",
    );
    // No broker binding at all: that is a plain run.
    refused(
        request(vec![by_value("T", "T")], vec![]),
        ErrorCode::InvalidRequest,
        "at least one broker binding",
    );
    // Variables: valid, distinct across every kind, and not NO_PROXY,
    // which the agent sets itself.
    for (bindings, brokered_now, says) in [
        (vec![], vec![brokered("1KEY", "KEY", None)], "not a valid"),
        (
            vec![],
            vec![brokered("KEY", "KEY", Some("KEY-URL"))],
            "not a valid",
        ),
        (vec![by_value("KEY", "T")], key(), "bound twice"),
        (
            vec![],
            vec![brokered("KEY", "KEY", Some("KEY"))],
            "bound twice",
        ),
        (
            vec![by_value("URL", "T")],
            vec![brokered("KEY", "KEY", Some("URL"))],
            "bound twice",
        ),
        (vec![], vec![brokered("NO_PROXY", "KEY", None)], "NO_PROXY"),
        (vec![by_value("no_proxy", "T")], key(), "no_proxy"),
    ] {
        refused(
            request(bindings, brokered_now),
            ErrorCode::InvalidRequest,
            says,
        );
    }
    assert!(
        h.ui.password_prompts.lock().unwrap().is_empty(),
        "the vault was unlocked for a request refused without it"
    );
    // Entries: the same one both ways or twice (by UUID), or with a value
    // the broker cannot carry.
    let uuid = uuids["KEY"].as_str();
    for (bindings, brokered_now, code, says) in [
        (
            vec![by_value("V", uuid)],
            key(),
            ErrorCode::InvalidRequest,
            "both",
        ),
        (
            vec![],
            vec![brokered("A", "KEY", None), brokered("B", uuid, None)],
            ErrorCode::InvalidRequest,
            "twice",
        ),
        (
            vec![],
            vec![brokered("A", "SHORT", None)],
            ErrorCode::InvalidRequest,
            "8 to 4096",
        ),
        (
            vec![],
            vec![brokered("A", "SPACED", None)],
            ErrorCode::InvalidRequest,
            "8 to 4096",
        ),
        (
            vec![],
            vec![brokered("A", "NOWHERE", None)],
            ErrorCode::NotFound,
            "NOWHERE",
        ),
    ] {
        refused(request(bindings, brokered_now), code, says);
    }
    // A dialog that would show a part too long to read is refused, never
    // shortened.
    let long = "V".repeat(1100);
    refused(
        request(vec![], vec![brokered(&long, "KEY", None)]),
        ErrorCode::InvalidRequest,
        "too long",
    );

    // A plain run that carries broker bindings is refused, not run without
    // them.
    let mut plain = serde_json::to_value(Request::Run(run_request(&h, &["touch", "ran"], false)))
        .expect("json");
    plain["brokered"] = serde_json::to_value(key()).expect("json");
    let stream = UnixStream::connect(&h.socket).expect("connect");
    send_frame(&stream, &plain, &[]).expect("send");
    match read_message::<Response>(&stream).expect("an answer") {
        Response::Error {
            code: ErrorCode::InvalidRequest,
            message,
        } => assert!(message.contains("broker_run_v2"), "{message}"),
        other => panic!("unexpected {}", other.kind()),
    }

    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the command ran");
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.ui.decisions.lock().unwrap().len(),
        1,
        "an approval was used"
    );
    assert!(audit_outcomes(&h, "run").is_empty(), "{}", h.audit_text());
    assert!(audit_outcomes(&h, "grant").is_empty(), "{}", h.audit_text());
    assert!(broker_log(&log).is_empty(), "a broker was started");
    assert!(grants(&h).is_empty());
}

/// The command of a broker run gets a token and the broker's address in the
/// variables it named, never the key (ADR 0013, decisions 1, 2 and 6, and
/// the scope amendment): the broker gets the key, the token, the approved
/// origin the run named, the limits and a listening socket on 127.0.0.1,
/// in an empty environment of its own; the grant is listed while the
/// command runs and ends with it; the tokens are redacted from the output,
/// and every step is in the audit log.
#[test]
fn a_broker_run_gives_the_command_a_token_and_the_brokers_address_never_the_key() {
    use rusthorse::broker_grant::AutomaticLocks;
    use rusthorse::protocol::Response;
    if !python3() {
        return;
    }
    let h = Harness::new();
    let uuids = seed(&h, &[("T", "value-of-t-1234"), ("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    // A long command line: a dialog that scrolls, as rusthorse-dialog's
    // does (that one grant fits zenity's is a unit test of the agent's).
    h.ui.scrolls.store(true, Ordering::SeqCst);
    h.decide(&[Decision::AllowOnce]);
    let script =
        format!("printf 'token=%s value=%s\\n' \"$OPENAI_API_KEY\" \"$T\"; {WAITS}; echo done");
    let mut request = broker_run_request(
        &h,
        vec![by_value("T", "T")],
        vec![brokered_to(
            "OPENAI_API_KEY",
            "KEY",
            "https://api.openai.com/v1",
            Some("OPENAI_BASE_URL"),
        )],
        &script,
    );
    // What the requester sends for those variables is dropped; its
    // NO_PROXY gets 127.0.0.1 added.
    request.run.env.extend([
        ("NO_PROXY".to_string(), "example.com".to_string()),
        (
            "OPENAI_API_KEY".to_string(),
            "from-the-requester".to_string(),
        ),
        (
            "OPENAI_BASE_URL".to_string(),
            "http://elsewhere.example".to_string(),
        ),
    ]);
    let running = start(&h, request);
    if let Ok(early) = running.answer.recv_timeout(Duration::from_secs(5)) {
        panic!("the run ended before its command: {:?}", error_of(&early));
    }
    let env = command_env(&h);

    // The broker: started with nothing of the requester's, in a process
    // group of its own, given the key, a token, the origin and a socket.
    let installed = logged(&log, "install");
    assert_eq!(installed["argv"], serde_json::json!([]));
    assert_eq!(installed["environ"], "");
    assert_eq!(installed["cwd"], "/");
    assert_eq!(installed["stderr"], "/dev/null");
    assert_eq!(installed["pid"], installed["pgid"]);
    assert_eq!(installed["fds"], 1);
    assert_eq!(installed["inet"], true);
    assert_eq!(installed["accepting"], 1);
    assert_eq!(installed["listen"][0], "127.0.0.1");
    let port = installed["listen"][1].as_u64().expect("port");
    let install = &installed["install"];
    assert_eq!(install["type"], "install");
    assert_eq!(install["version"], 2);
    assert_eq!(install["credential"], FAKE_KEY);
    let token = install["token"].as_str().expect("token").to_string();
    assert!(
        rusthorse::broker_protocol::is_well_formed_token(&token),
        "{token}"
    );
    let id = install["grant"].as_str().expect("grant").to_string();
    assert!(
        rusthorse::broker_protocol::is_well_formed_grant_id(&id),
        "{id}"
    );
    // The approved origin, without the base path, which only goes into the
    // command's base URL; no profile.
    assert_eq!(install["origin"], "https://api.openai.com");
    assert!(install.get("profile").is_none(), "{install}");
    assert_eq!(install["max_in_flight"], 16);
    assert_eq!(install["max_connections"], 64);
    let lifetime = install["lifetime_secs"].as_u64().expect("lifetime");
    assert!((720 * 60 - 30..=720 * 60).contains(&lifetime), "{lifetime}");
    assert_eq!(installs_validly(install), Ok(()));

    // The command: the token and the broker's address, never the key.
    assert_eq!(env["OPENAI_API_KEY"], token);
    assert_eq!(
        env["OPENAI_BASE_URL"],
        format!("http://127.0.0.1:{port}/v1")
    );
    assert_eq!(env["T"], "value-of-t-1234");
    assert_eq!(env["NO_PROXY"], "example.com,127.0.0.1");
    assert_eq!(env["no_proxy"], "127.0.0.1");
    let everything = std::fs::read_to_string(h.dir.path().join("env.txt")).expect("env");
    assert!(
        !everything.contains(FAKE_KEY),
        "the key reached the command"
    );
    assert!(!everything.contains("from-the-requester"));
    assert!(!everything.contains("elsewhere.example"));

    // Listed while the command runs; never a token.
    let listed = grants(&h);
    assert_eq!(listed.len(), 1);
    let grant = &listed[0];
    assert_eq!(grant.id, id);
    assert_eq!(grant.var, "OPENAI_API_KEY");
    assert_eq!(grant.destination, "https://api.openai.com");
    assert_eq!(grant.base_path.as_deref(), Some("/v1"));
    assert_eq!(grant.max_requests, None);
    assert!(grant.command.starts_with("sh -c "), "{}", grant.command);
    assert!(grant.entry.starts_with("KEY ("), "{}", grant.entry);
    assert_eq!(grant.state, "active");
    assert_eq!((grant.requests, grant.in_flight), (0, 0));
    assert_eq!(grant.automatic_locks, AutomaticLocks::Continue);
    let listing = serde_json::to_string(&listed).expect("json");
    assert!(
        !listing.contains(&token) && !listing.contains(FAKE_KEY),
        "{listing}"
    );
    let now = status(&h);
    assert_eq!(now.grants, Some(1));
    assert_eq!(
        now.broker.as_deref(),
        Some(
            std::fs::canonicalize(h.broker_program())
                .expect("canonical")
                .to_str()
                .expect("utf8")
        )
    );

    go(&h);
    match running.wait() {
        Response::Exited { code, .. } => assert_eq!(code, Some(0)),
        other => panic!("unexpected {}", other.kind()),
    }
    // Redacted: the token as its variable, the value as its entry.
    let output = running.output.text();
    assert!(
        output.contains("token=[REDACTED:OPENAI_API_KEY] value=[REDACTED:T]"),
        "{output}"
    );
    assert!(
        !output.contains(&token) && !output.contains(FAKE_KEY),
        "{output}"
    );

    // Over: the grant ended with the command, its broker was told and is
    // gone, the port is free again.
    assert!(grants(&h).is_empty());
    assert_eq!(status(&h).grants, Some(0));
    let revoke = logged(&log, "revoke");
    assert_eq!(revoke["message"]["reason"], "command_ended");
    let pid = installed["pid"].as_u64().expect("pid");
    assert!(process_gone(pid), "the broker outlived its run");
    assert!(port_released(port as u16), "port {port} still held");
    // The grant's end is recorded once its broker confirms, possibly after
    // the run's answer.
    assert_eq!(ended_with(&h, &id), "command_ended");

    // The dialog said where the key goes and how the grant ends.
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let detail = |label: &str| approval_detail(&h, label).unwrap_or_default();
    assert!(!asked.can_remember);
    assert!(
        asked.explanation.contains("temporary token, not the key"),
        "{}",
        asked.explanation
    );
    assert!(
        asked.explanation.contains(
            "requests to the approved origin, at any path there: a base path is not a limit"
        ),
        "{}",
        asked.explanation
    );
    assert!(
        asked.explanation.contains("as values"),
        "{}",
        asked.explanation
    );
    assert_eq!(asked.command.as_deref(), Some(grant.command.as_str()));
    let key_identity = grant.entry.clone();
    assert_eq!(
        detail("Grant"),
        format!(
            "OPENAI_API_KEY ← a token for {key_identity}; OPENAI_BASE_URL ← the broker's address"
        )
    );
    assert_eq!(detail("Approved origin"), "https://api.openai.com");
    assert_eq!(detail("Base path"), "/v1 (not a limit)");
    // No profile: nothing about routes or presets.
    for gone in ["Destination", "Allows", "Preset"] {
        assert_eq!(approval_detail(&h, gone), None, "{gone}");
    }
    assert_eq!(
        detail("Ends"),
        "with the command, on rusthorse lock, revocation or a change to the entry, or after \
         12h; not on screen lock, suspend or idle lock"
    );
    assert_eq!(detail("Requests"), "no limit; at most 16 at a time");
    assert!(
        detail("Secrets").starts_with("T ← T ("),
        "{}",
        detail("Secrets")
    );
    assert!(!detail("Program").is_empty() && !detail("Directory").is_empty());
    // The requester's value for the address variable was dropped: it is
    // not a destination of the command's.
    assert_eq!(approval_detail(&h, "Destinations (environment)"), None);
    assert!(!detail("Requested by (unverified)").is_empty());
    let warnings = asked.warnings.join(" ");
    assert!(warnings.contains("can spend credit"), "{warnings}");
    assert!(warnings.contains("not a spending limit"), "{warnings}");
    assert!(warnings.contains("bodies are not inspected"), "{warnings}");
    assert!(
        asked.facts.contains(&(
            "Output".to_string(),
            "secret values and tokens are redacted".to_string()
        )),
        "{:?}",
        asked.facts
    );

    // The audit log: the approval with the grants it creates, the grant's
    // creation before the command ran, its end, the command's exit — and no
    // token or key anywhere.
    let records = audit_records(&h);
    let audit = h.audit_text();
    assert!(!audit.contains(&token) && !audit.contains(FAKE_KEY));
    let position = |action: &str, outcome: &str| {
        records
            .iter()
            .position(|r| r["action"] == action && r["outcome"] == outcome)
            .unwrap_or_else(|| panic!("no {action} {outcome}: {audit}"))
    };
    let approval = &records[position("run", "allowed_once")];
    assert_eq!(
        approval["grants"],
        serde_json::json!([{
            "id": id,
            "entry": key_identity,
            "destination": "https://api.openai.com",
            "base_path": "/v1",
        }])
    );
    assert_eq!(approval["entries"].as_array().map(Vec::len), Some(2));
    assert!(position("run", "allowed_once") < position("grant", "created"));
    assert!(position("grant", "created") < position("run", "exited"));
    let created = &records[position("grant", "created")];
    assert_eq!(created["grant"], id.as_str());
    assert_eq!(created["entries"], serde_json::json!([key_identity]));
    let ended = &records[position("grant", "ended")];
    assert_eq!(ended["reason"], "command_ended");
    assert_eq!(
        ended["requests"],
        serde_json::json!({"admitted": 0, "finished": 0, "unknown": 0, "refused": 0})
    );
    assert!(
        uuids["KEY"].starts_with(&key_identity[5..13]),
        "{key_identity}"
    );
}

/// A broker run's approval is never remembered — each creates its grants
/// once (ADR 0013) — and without redaction its dialog says that the token
/// can reach whoever reads the output.
#[test]
fn a_broker_run_is_never_remembered_and_warns_when_its_output_is_not_filtered() {
    use rusthorse::protocol::{ErrorCode, Request, Response, read_message, send_frame};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let _log = fake_broker(&h, "ready");
    // An answer that allows for a while anyway allows once.
    h.decide(&[
        Decision::AllowFor(Duration::from_secs(600)),
        Decision::AllowOnce,
    ]);
    for _ in 0..2 {
        let request = broker_run_request(
            &h,
            vec![],
            vec![brokered("ANTHROPIC_API_KEY", "KEY", None)],
            "true",
        );
        match broker_run(&h, request) {
            Response::Exited { code, .. } => assert_eq!(code, Some(0)),
            other => panic!("unexpected {}", other.kind()),
        }
        let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
        assert!(!asked.can_remember);
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
    assert_eq!(
        audit_outcomes(&h, "run"),
        ["allowed_once", "exited", "allowed_once", "exited"]
    );

    // Without redaction: the descriptors travel with the request, and the
    // dialog warns. Denied here: nothing runs, no grant is made.
    h.decide(&[Decision::Deny]);
    let mut request = broker_run_request(
        &h,
        vec![],
        vec![brokered("ANTHROPIC_API_KEY", "KEY", None)],
        "true",
    );
    request.run.redact = false;
    let null = std::fs::File::open("/dev/null").expect("null");
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("null");
    let stream = UnixStream::connect(&h.socket).expect("connect");
    send_frame(
        &stream,
        &Request::BrokerRunV2(request),
        &[null.as_fd(), sink.as_fd(), sink.as_fd()],
    )
    .expect("send");
    let response = read_message::<Response>(&stream).expect("an answer");
    assert_eq!(error_of(&response).0, ErrorCode::Denied);
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let warnings = asked.warnings.join(" ");
    assert!(
        warnings.contains(
            "Output is NOT redacted: a token the command prints reaches the requester, who can \
             use it until its grant ends."
        ),
        "{warnings}"
    );
    assert!(
        asked
            .facts
            .contains(&("Output".to_string(), "not redacted".to_string())),
        "{:?}",
        asked.facts
    );
    assert!(grants(&h).is_empty());
    // Two grants, each created and then ended; the denied run made none.
    // Each end is recorded once its broker confirms, so the first one's may
    // come after the second's creation.
    let records = eventually("the grants' end records", || {
        let records: Vec<serde_json::Value> = audit_records(&h)
            .into_iter()
            .filter(|r| r["action"] == "grant")
            .collect();
        (records.iter().filter(|r| r["outcome"] == "ended").count() == 2).then_some(records)
    });
    let ids: std::collections::BTreeSet<&str> =
        records.iter().filter_map(|r| r["grant"].as_str()).collect();
    assert_eq!(ids.len(), 2, "{records:?}");
    for id in ids {
        let outcomes: Vec<&str> = records
            .iter()
            .filter(|r| r["grant"] == id)
            .filter_map(|r| r["outcome"].as_str())
            .collect();
        assert_eq!(outcomes, ["created", "ended"], "{id}: {records:?}");
    }
}

/// A broker that exits at once, never answers, or answers for another grant
/// or in another version fails its run before the command starts (ADR 0013,
/// decision 6: no fallback, 125 for `run`): nothing ran, no grant is left,
/// no broker either, and the log says what happened.
#[test]
fn a_broker_that_does_not_start_serving_fails_the_run_and_leaves_nothing_behind() {
    use rusthorse::protocol::ErrorCode;
    if !python3() {
        return;
    }
    let h = Harness::with_broker_ready_timeout(Duration::from_secs(2));
    seed(&h, &[("KEY", FAKE_KEY)]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    for mode in ["exits", "silent", "wrong_grant", "old_version"] {
        let log = if mode == "exits" {
            write_program(&h.broker_program(), "#!/bin/sh\nexit 3\n");
            None
        } else {
            Some(fake_broker(&h, mode))
        };
        h.decide(&[Decision::AllowOnce]);
        let started = Instant::now();
        let request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script);
        let response = broker_run(&h, request);
        let (code, message) = error_of(&response);
        assert_eq!(code, ErrorCode::Internal, "{mode}: {message}");
        assert!(
            message.contains("could not serve a grant"),
            "{mode}: {message}"
        );
        assert!(message.contains("nothing was run"), "{mode}: {message}");
        assert!(!message.contains(FAKE_KEY));
        let took = started.elapsed();
        if mode == "silent" {
            assert!(took >= Duration::from_secs(2), "{mode}: {took:?}");
        }
        assert!(took < Duration::from_secs(8), "{mode}: {took:?}");
        assert!(!marker.exists(), "{mode}: the command ran");
        assert!(grants(&h).is_empty(), "{mode}");
        if let Some(log) = log {
            let pid = logged(&log, "install")["pid"].as_u64().expect("pid");
            assert!(process_gone(pid), "{mode}: the broker was left running");
        }
    }
    // A program that others can change by the time the run starts: it is
    // checked again, and not started.
    let log = fake_broker(&h, "ready");
    let program = h.broker_program();
    *h.ui.on_approve.lock().unwrap() = Some(Box::new(move || {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o770)).expect("chmod");
    }));
    h.decide(&[Decision::AllowOnce]);
    let request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script);
    let (code, message) = error_of(&broker_run(&h, request));
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("cannot be used"), "{message}");
    assert!(!marker.exists(), "the command ran");
    assert!(broker_log(&log).is_empty(), "the broker was started");
    assert!(grants(&h).is_empty());
    let ends: Vec<String> = grant_ends(&h)
        .values()
        .map(|r| r["reason"].as_str().unwrap_or_default().to_string())
        .collect();
    // Four grants created and ended; the last one never was, on record.
    assert_eq!(ends, ["broker_failed"; 4]);
    assert_eq!(audit_outcomes(&h, "grant").len(), 8);
    assert_eq!(
        audit_outcomes(&h, "run"),
        [
            "allowed_once",
            "aborted",
            "allowed_once",
            "aborted",
            "allowed_once",
            "aborted",
            "allowed_once",
            "aborted",
            "allowed_once",
            "aborted"
        ]
    );
}

/// When one broker of a run with several grants cannot start serving, the
/// whole run fails before anything runs: none of its grants remains, each
/// broker it started is gone and each port it held is free, and the record
/// of its approval is followed by one that says why nothing ran (ADR 0013,
/// preparing a run's grants).
#[test]
fn a_run_whose_broker_fails_to_start_keeps_none_of_its_grants() {
    use rusthorse::protocol::ErrorCode;
    if !python3() {
        return;
    }
    let h = Harness::new();
    // Two grants: a dialog that scrolls, as rusthorse-dialog's does.
    h.ui.scrolls.store(true, Ordering::SeqCst);
    seed(
        &h,
        &[("A", FAKE_KEY), ("B", "sk-ant-test-1111111111111111")],
    );
    // One broker answers ready, the other exits without answering.
    let log = fake_broker(&h, "first_serves");
    h.decide(&[Decision::AllowOnce]);
    let marker = h.dir.path().join("ran");
    let request = broker_run_request(
        &h,
        vec![],
        vec![brokered("KEY_A", "A", None), brokered("KEY_B", "B", None)],
        &format!("touch {}", marker.display()),
    );
    let (code, message) = error_of(&broker_run(&h, request));
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("could not serve a grant"), "{message}");
    assert!(
        message.contains("ended without answering (exit status 5)"),
        "{message}"
    );
    assert!(message.contains("nothing was run"), "{message}");
    assert!(!message.contains(FAKE_KEY), "{message}");
    assert!(!marker.exists(), "the command ran");
    assert!(grants(&h).is_empty(), "a grant was left");
    let installs: Vec<serde_json::Value> = broker_log(&log)
        .into_iter()
        .filter(|e| e["event"] == "install")
        .collect();
    assert_eq!(installs.len(), 2, "{installs:?}");
    for install in &installs {
        let pid = install["pid"].as_u64().expect("pid");
        assert!(process_gone(pid), "a broker was left running");
        let port = install["listen"][1]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .expect("port");
        assert!(port_released(port), "port {port} still held");
    }
    let ends = grant_ends(&h);
    assert_eq!(ends.len(), 2, "{ends:?}");
    for end in ends.values() {
        assert_eq!(end["reason"], "broker_failed", "{end}");
    }
    assert_eq!(audit_outcomes(&h, "run"), ["allowed_once", "aborted"]);
}

/// A run that fails once its grants are active — its command cannot be
/// started — ends them before it records why nothing ran: with the audit
/// log blocked from the moment the brokers have their installs, the broker
/// is told to revoke while that record waits (ADR 0013: revocation never
/// waits for the audit log), and the run fails, nothing run, once the log
/// gives up.
#[test]
fn a_run_whose_command_cannot_start_ends_its_grants_before_it_waits_for_the_audit_log() {
    use rusthorse::protocol::ErrorCode;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "held_ready");
    let ready = log.with_extension("jsonl.ready");
    // A program the agent finds and the human approves, which cannot start:
    // its interpreter does not exist.
    let program = h.dir.path().join("cannot-start");
    write_program(&program, "#!/nonexistent/rusthorse-test-interpreter\n");
    let mut request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], "");
    request.run.argv = vec![program.to_str().expect("utf8").into()];
    h.decide(&[Decision::AllowOnce]);
    let running = start(&h, request);
    // The grant's creation is recorded and its broker has its install: from
    // now on the audit log blocks. Then the broker answers ready.
    let pid = logged(&log, "install")["pid"].as_u64().expect("pid");
    let mut audit = BlockedAudit::new(&h);
    std::fs::write(&ready, "").expect("ready");
    let revoke = logged_within(&log, "revoke", Duration::from_secs(5))
        .expect("the broker was not told while the run's record waited");
    assert_eq!(revoke["message"]["reason"], "command_ended");
    audit.release();
    let (code, message) = error_of(&running.wait());
    assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
    assert!(message.contains("cannot start"), "{message}");
    assert!(process_gone(pid), "the broker was left running");
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    audit.wait_for_end_of(&id);
    drop(audit);
    assert!(grants(&h).is_empty(), "a grant was left");
}

/// A lock while a run's brokers start ends the run's grants, which were
/// entered as starting — a screen lock too, whatever their run says about
/// the automatic locks, since nothing of the run has been used yet —
/// and the run fails before anything runs: a broker that has its install
/// and has not answered ready is killed, and the lock is done only once it
/// is gone (ADR 0013, preparing a run's grants and revocation).
#[test]
fn a_lock_while_the_brokers_start_ends_the_runs_grants_and_nothing_runs() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    // Grants that outlive the automatic locks once active: the default.
    seed(&h, &[("KEY", FAKE_KEY)]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    for (lock, reason) in [("screen lock", "screen_locked"), ("lock", "locked")] {
        let log = fake_broker(&h, "held_ready");
        let ready = log.with_extension("jsonl.ready");
        let _ = std::fs::remove_file(&ready);
        h.decide(&[Decision::AllowOnce]);
        let running = start(
            &h,
            broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script),
        );
        let installed = logged(&log, "install");
        let pid = installed["pid"].as_u64().expect("pid");
        let id = installed["install"]["grant"]
            .as_str()
            .expect("grant")
            .to_string();
        // Its broker has its install and has not answered yet.
        assert_eq!(grant_state(&h, &id).as_deref(), Some("starting"), "{lock}");
        if lock == "screen lock" {
            h.agent.lock_for(SCREEN_LOCK, "test");
        } else {
            match h.call(&Request::Lock) {
                Response::Ok { .. } => {}
                other => panic!("unexpected {}", other.kind()),
            }
        }
        // Done once its broker, which had not answered, is gone.
        assert!(!process_alive(pid), "{lock}: done while the broker ran");
        // Revoked, or ended already: the run, whose broker is gone, fails.
        let state = grant_state(&h, &id);
        assert!(
            matches!(state.as_deref(), Some("revoked") | None),
            "{lock}: {state:?}"
        );
        // An answer now would be too late (nobody is left to give it).
        std::fs::write(&ready, "").expect("ready");
        let (code, message) = error_of(&running.wait());
        assert_eq!(code, ErrorCode::Internal, "{lock}: {message}");
        assert!(
            message.contains("the grant ended while its broker was starting"),
            "{lock}: {message}"
        );
        assert!(message.contains("nothing was run"), "{lock}: {message}");
        assert!(!marker.exists(), "{lock}: the command ran");
        assert!(process_gone(pid), "{lock}: the broker was left running");
        assert!(grants(&h).is_empty(), "{lock}");
        assert_eq!(ended_with(&h, &id), reason, "{lock}");
    }
    assert_eq!(
        audit_outcomes(&h, "run"),
        ["allowed_once", "aborted", "allowed_once", "aborted"]
    );
}

/// `grants` and `revoke_grant` need neither an approval nor an unlocked
/// vault (ADR 0013), and grants can outlive a lock: they are listed and
/// revoked while it is locked. An ID that names no grant is `not_found`; a
/// malformed one is `invalid_request`.
#[test]
fn grants_are_listed_and_revoked_without_a_dialog_locked_or_unlocked() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    // Locked, with no grant and no broker.
    assert!(grants(&h).is_empty());
    let now = status(&h);
    assert!(now.locked);
    assert_eq!(now.grants, Some(0));
    assert!(
        now.broker
            .as_deref()
            .is_some_and(|b| b.starts_with("none: ")),
        "{:?}",
        now.broker
    );
    match h.call(&Request::RevokeGrant { id: None }) {
        Response::Ok { message } => assert_eq!(message, "0 grants revoked"),
        other => panic!("unexpected {}", other.kind()),
    }
    let unknown = h.call(&Request::RevokeGrant {
        id: Some("g0123456789abcdef".into()),
    });
    assert_eq!(error_of(&unknown).0, ErrorCode::NotFound);
    let malformed = h.call(&Request::RevokeGrant {
        id: Some("g-not-an-id".into()),
    });
    assert_eq!(error_of(&malformed).0, ErrorCode::InvalidRequest);
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(h.ui.password_prompts.lock().unwrap().is_empty());

    // Two grants that survive a screen lock (their run says so: `continue`
    // is the default), in a dialog that scrolls, as rusthorse-dialog's
    // does.
    h.ui.scrolls.store(true, Ordering::SeqCst);
    seed(
        &h,
        &[("A", FAKE_KEY), ("B", "sk-ant-test-1111111111111111")],
    );
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let request = broker_run_request(
        &h,
        vec![],
        vec![brokered("KEY_A", "A", None), brokered("KEY_B", "B", None)],
        WAITS,
    );
    let running = start(&h, request);
    command_env(&h);
    let ids: Vec<String> = grants(&h).into_iter().map(|g| g.id).collect();
    assert_eq!(ids.len(), 2);
    h.agent.lock_for(SCREEN_LOCK, "test");
    let prompts = h.ui.password_prompts.lock().unwrap().len();
    let now = status(&h);
    assert!(now.locked);
    assert_eq!(now.grants, Some(2));
    assert_eq!(grant_state(&h, &ids[0]).as_deref(), Some("active"));
    // Revoked by hand, while locked: done once its broker confirmed.
    match h.call(&Request::RevokeGrant {
        id: Some(ids[0].clone()),
    }) {
        Response::Ok { message } => assert_eq!(message, format!("{} revoked", ids[0])),
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &ids[0]).as_deref(), Some("revoked"));
    assert_eq!(grant_state(&h, &ids[1]).as_deref(), Some("active"));
    // `status` counts the grants that can still be used; the listing shows
    // the revoked one too, until its command ends.
    assert_eq!(status(&h).grants, Some(1));
    assert_eq!(grants(&h).len(), 2);
    let revokes: Vec<String> = broker_log(&log)
        .into_iter()
        .filter(|e| e["event"] == "revoke")
        .map(|e| {
            e["message"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(revokes, ["revoked"]);
    match h.call(&Request::RevokeGrant {
        id: Some(ids[0].clone()),
    }) {
        Response::Ok { message } => assert!(message.contains("already ended"), "{message}"),
        other => panic!("unexpected {}", other.kind()),
    }
    match h.call(&Request::RevokeGrant { id: None }) {
        Response::Ok { message } => assert_eq!(message, "1 grant revoked"),
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &ids[1]).as_deref(), Some("revoked"));
    assert_eq!(
        status(&h).grants,
        Some(0),
        "revoked grants counted as usable"
    );
    assert_eq!(grants(&h).len(), 2);
    assert_eq!(
        h.ui.password_prompts.lock().unwrap().len(),
        prompts,
        "unlocked"
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);

    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
    assert!(grants(&h).is_empty());
    for id in &ids {
        assert_eq!(ended_with(&h, id), "revoked");
        let detail = grant_ends(&h)[id]["detail"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(detail.starts_with("revoked by "), "{detail}");
    }
}

/// A broker run of `entry` whose grant has `limits` and whose command
/// waits until the test creates `go_file` (see [`WAITS`]), once it has
/// started. Its approval must be queued.
fn start_waiting(
    h: &Harness,
    var: &str,
    entry: &str,
    limits: rusthorse::broker_grant::GrantLimits,
    go_file: &str,
) -> Running {
    let _ = std::fs::remove_file(h.dir.path().join("env.txt"));
    let script = WAITS.replace("-e go ]", &format!("-e {go_file} ]"));
    let mut request = broker_run_request(h, vec![], vec![brokered(var, entry, None)], &script);
    request.limits = limits;
    let running = start(h, request);
    command_env(h);
    running
}

/// The default limits, except that the automatic locks end the grants.
fn ending_with_the_automatic_locks() -> rusthorse::broker_grant::GrantLimits {
    rusthorse::broker_grant::GrantLimits {
        automatic_locks: rusthorse::broker_grant::AutomaticLocks::End,
        ..rusthorse::broker_grant::GrantLimits::default()
    }
}

/// `rusthorse lock` ends every grant; the screen lock and a suspend end the
/// grants of the runs that said that the automatic locks end them, and keep
/// the others (ADR 0013, decision 8; the run's limits, scope amendment).
#[test]
fn locks_end_the_grants_their_runs_say() {
    use rusthorse::broker_grant::{AutomaticLocks, GrantLimits};
    use rusthorse::protocol::{Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK, SUSPEND};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(
        &h,
        &[
            ("STAYS", FAKE_KEY),
            ("SCREEN", FAKE_KEY),
            ("SLEEP", FAKE_KEY),
        ],
    );
    let _log = fake_broker(&h, "ready");
    h.ui.scrolls.store(true, Ordering::SeqCst);
    // Three runs: the suspend's grant is created after the screen lock.
    h.decide(&[
        Decision::AllowOnce,
        Decision::AllowOnce,
        Decision::AllowOnce,
    ]);
    let first = start_waiting(&h, "A", "STAYS", GrantLimits::default(), "go");
    let second = start_waiting(&h, "B", "SCREEN", ending_with_the_automatic_locks(), "go2");
    // Its dialog said so.
    let ends = approval_detail(&h, "Ends").expect("Ends");
    assert!(
        ends.ends_with("; also on screen lock, suspend or idle lock"),
        "{ends}"
    );
    let id_of = |entry: &str| {
        grants(&h)
            .into_iter()
            .find(|g| g.entry.starts_with(&format!("{entry} (")))
            .expect("a grant")
    };
    assert_eq!(id_of("STAYS").automatic_locks, AutomaticLocks::Continue);
    assert_eq!(id_of("SCREEN").automatic_locks, AutomaticLocks::End);
    let (stays, screen) = (id_of("STAYS").id, id_of("SCREEN").id);
    h.agent.lock_for(SCREEN_LOCK, "test");
    assert_eq!(grant_state(&h, &screen).as_deref(), Some("revoked"));
    assert_eq!(grant_state(&h, &stays).as_deref(), Some("active"));

    let third = start_waiting(&h, "C", "SLEEP", ending_with_the_automatic_locks(), "go3");
    let sleep = id_of("SLEEP").id;
    h.agent.lock_for(SUSPEND, "test");
    assert_eq!(grant_state(&h, &sleep).as_deref(), Some("revoked"));
    assert_eq!(grant_state(&h, &stays).as_deref(), Some("active"));

    // The explicit lock ends everything.
    match h.call(&Request::Lock) {
        Response::Ok { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &stays).as_deref(), Some("revoked"));
    for file in ["go", "go2", "go3"] {
        std::fs::write(h.dir.path().join(file), "").expect("go");
    }
    for running in [first, second, third] {
        assert!(matches!(running.wait(), Response::Exited { .. }));
    }
    assert_eq!(ended_with(&h, &screen), "screen_locked");
    assert_eq!(ended_with(&h, &sleep), "suspend");
    assert_eq!(ended_with(&h, &stays), "locked");
}

/// The idle timeout ends the grants of the runs that said so and keeps the
/// others; requests through the broker do not postpone it (P9).
#[test]
fn the_idle_lock_ends_only_the_grants_whose_run_says_so() {
    use rusthorse::broker_grant::GrantLimits;
    use rusthorse::protocol::Response;
    if !python3() {
        return;
    }
    // Long enough for the runs to start before the vault locks itself.
    // Should it lock between them, the grant that ends has ended already,
    // and the second run unlocks it again.
    let h = Harness::with_idle_timeout(Duration::from_secs(5));
    h.ui.scrolls.store(true, Ordering::SeqCst);
    seed(&h, &[("STAYS", FAKE_KEY), ("ENDS", FAKE_KEY)]);
    let _log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
    let first = start_waiting(&h, "B", "ENDS", ending_with_the_automatic_locks(), "go");
    let second = start_waiting(&h, "A", "STAYS", GrantLimits::default(), "go2");
    let listed = grants(&h);
    let id_of = |entry: &str| {
        listed
            .iter()
            .find(|g| g.entry.starts_with(&format!("{entry} (")))
            .map(|g| g.id.clone())
            .expect("a grant")
    };
    let (stays, ends) = (id_of("STAYS"), id_of("ENDS"));
    eventually("the idle lock", || status(&h).locked.then_some(()));
    eventually("the end of the grant", || {
        (grant_state(&h, &ends).as_deref() == Some("revoked")).then_some(())
    });
    assert_eq!(grant_state(&h, &stays).as_deref(), Some("active"));
    go(&h);
    std::fs::write(h.dir.path().join("go2"), "").expect("go");
    assert!(matches!(first.wait(), Response::Exited { .. }));
    assert!(matches!(second.wait(), Response::Exited { .. }));
    assert_eq!(ended_with(&h, &ends), "idle_timeout");
    assert_eq!(ended_with(&h, &stays), "command_ended");
}

/// A grant ends once its lifetime has passed, while its command still runs:
/// the agent's timer revokes it (`expired`) and tells its broker, so that a
/// stream open then ends too — refusing new requests is not enough (ADR
/// 0013, limits). The broker's install says how long the grant has, never
/// more than its run allows. (Tests shorten the lifetime through
/// `AgentConfig::broker_lifetime`.)
#[test]
fn a_grant_ends_when_its_lifetime_passes_while_its_command_runs() {
    use rusthorse::protocol::Response;
    if !python3() {
        return;
    }
    let lifetime = Duration::from_secs(3);
    let h = Harness::with_broker_lifetime(lifetime);
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let asked = Instant::now();
    let running = start(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], WAITS),
    );
    command_env(&h);
    let installed = logged(&log, "install");
    let install = &installed["install"];
    let id = install["grant"].as_str().expect("grant").to_string();
    let left = install["lifetime_secs"].as_u64().expect("lifetime");
    assert!((1..=3).contains(&left), "{left}");
    assert_eq!(installs_validly(install), Ok(()));
    // The command runs on, and is not told: its grant ends under it.
    let revoke = logged(&log, "revoke");
    let took = asked.elapsed();
    assert_eq!(revoke["message"]["reason"], "expired");
    assert!(took >= lifetime, "{took:?}");
    assert!(took < lifetime + Duration::from_secs(4), "{took:?}");
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    assert!(running.answer.try_recv().is_err(), "the run ended");
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
    assert_eq!(ended_with(&h, &id), "expired");
}

/// Any change to an entry — its user name, its name, its removal, its
/// replacement, an import over it, its tags — ends its grants once it is
/// saved, and its dialog says how many (ADR 0013); an edit that ends none
/// says nothing about grants.
#[test]
fn a_change_to_an_entry_ends_its_grants_and_its_dialog_says_how_many() {
    use rusthorse::protocol::{EntryChanges, NewEntry, Request, Response};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(
        &h,
        &[
            ("KEY", FAKE_KEY),
            ("RENAMED", FAKE_KEY),
            ("REMOVED", FAKE_KEY),
            ("REPLACED", FAKE_KEY),
            ("IMPORTED", FAKE_KEY),
            ("UNTOUCHED", FAKE_KEY),
        ],
    );
    let edit = |request: Request| match h.call(&request) {
        Response::Ok { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    };
    let username = |name: &str, username: &str| Request::Edit {
        name: name.into(),
        changes: EntryChanges {
            username: Some(username.into()),
            ..EntryChanges::default()
        },
    };

    // Before any grant: the dialog says nothing about grants.
    h.decide(&[Decision::AllowOnce]);
    edit(username("KEY", "someone"));
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(asked.warnings.is_empty(), "{:?}", asked.warnings);
    assert!(asked.facts.is_empty(), "{:?}", asked.facts);

    // A run with a grant of each entry, in a dialog that scrolls.
    let log = fake_broker(&h, "ready");
    h.ui.scrolls.store(true, Ordering::SeqCst);
    h.decide(&[Decision::AllowOnce]);
    let names = [
        "KEY",
        "RENAMED",
        "REMOVED",
        "REPLACED",
        "IMPORTED",
        "UNTOUCHED",
    ];
    let bindings = names
        .iter()
        .map(|name| brokered(&format!("V_{name}"), name, None))
        .collect();
    let running = start(&h, broker_run_request(&h, vec![], bindings, WAITS));
    command_env(&h);
    let id_of = |entry: &str| {
        grants(&h)
            .into_iter()
            .find(|g| g.entry.starts_with(&format!("{entry} (")))
            .map(|g| g.id)
            .expect("a grant")
    };
    let ids: Vec<String> = names.iter().map(|name| id_of(name)).collect();

    // Its user name changed: the dialog says that the edit ends its grant.
    h.decide(&[Decision::AllowOnce]);
    edit(username("KEY", "me"));
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert_eq!(
        asked.warnings,
        ["This ends 1 grant of the credential broker at once: the command using it loses access."]
    );
    assert_eq!(grant_state(&h, &ids[0]).as_deref(), Some("revoked"));
    // A rename, a removal, a replacement: each ends the entry's grant.
    h.decide(&[Decision::AllowOnce]);
    edit(Request::Edit {
        name: "RENAMED".into(),
        changes: EntryChanges {
            rename: Some("NEW_NAME".into()),
            ..EntryChanges::default()
        },
    });
    assert_eq!(grant_state(&h, &ids[1]).as_deref(), Some("revoked"));
    h.decide(&[Decision::AllowOnce]);
    edit(Request::Remove {
        name: "REMOVED".into(),
    });
    assert_eq!(grant_state(&h, &ids[2]).as_deref(), Some("revoked"));
    h.decide(&[Decision::AllowOnce]);
    edit(Request::Add {
        entry: NewEntry {
            name: "REPLACED".into(),
            ..NewEntry::default()
        },
        value: Some(SecretString::new("sk-ant-test-2222222222222222".into())),
        generate: None,
        replace: true,
    });
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        asked
            .warnings
            .iter()
            .any(|w| w.starts_with("This ends 1 grant")),
        "{:?}",
        asked.warnings
    );
    assert_eq!(grant_state(&h, &ids[3]).as_deref(), Some("revoked"));
    h.decide(&[Decision::AllowOnce]);
    edit(Request::Import {
        entries: vec![rusthorse::protocol::ImportedEntry {
            entry: NewEntry {
                name: "IMPORTED".into(),
                ..NewEntry::default()
            },
            value: SecretString::new("sk-ant-test-3333333333333333".into()),
        }],
        replace: true,
    });
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        asked
            .warnings
            .iter()
            .any(|w| w.starts_with("This ends 1 grant")),
        "{:?}",
        asked.warnings
    );
    assert_eq!(grant_state(&h, &ids[4]).as_deref(), Some("revoked"));
    // The other entry's grant goes on.
    assert_eq!(grant_state(&h, &ids[5]).as_deref(), Some("active"));
    let revokes = broker_log(&log)
        .into_iter()
        .filter(|e| e["event"] == "revoke")
        .count();
    assert_eq!(revokes, 5);

    // Even a change of its tags ends it.
    h.decide(&[Decision::AllowOnce]);
    edit(Request::Edit {
        name: "UNTOUCHED".into(),
        changes: EntryChanges {
            add_tags: vec!["touched".into()],
            ..EntryChanges::default()
        },
    });
    assert_eq!(grant_state(&h, &ids[5]).as_deref(), Some("revoked"));
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
    for id in &ids {
        assert_eq!(ended_with(&h, id), "entry_changed");
    }
}

/// The unlock barrier (ADR 0013): a grant that survived a lock ends at the
/// next unlock if the vault file was changed by another program meanwhile —
/// even with its times kept, even in another entry — and goes on if the
/// file is as the agent last read or wrote it. A failed unlock keeps the
/// fingerprint the agent had, and the agent's own save updates it.
#[test]
fn grants_that_survive_a_lock_end_when_the_vault_file_changed_meanwhile() {
    use rusthorse::protocol::{EntryChanges, Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY), ("OTHER", "abcdefgh")]);
    let _log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let running = start(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], WAITS),
    );
    command_env(&h);
    let id = grants(&h)[0].id.clone();
    let unlock = || match h.call(&Request::List) {
        Response::Entries { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    };

    // The file as the agent read it: the grant goes on.
    h.agent.lock_for(SCREEN_LOCK, "test");
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));
    unlock();
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));
    // The agent's own save of another entry: the file is as the agent
    // wrote it, and the grant goes on through the next lock.
    h.decide(&[Decision::AllowOnce]);
    match h.call(&Request::Edit {
        name: "OTHER".into(),
        changes: EntryChanges {
            username: Some("someone".into()),
            ..EntryChanges::default()
        },
    }) {
        Response::Ok { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));
    h.agent.lock_for(SCREEN_LOCK, "test");
    unlock();
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));
    // A failed unlock forgets nothing: the file is unchanged at the next.
    h.agent.lock_for(SCREEN_LOCK, "test");
    h.ui.passwords.lock().unwrap().extend([
        Some("wrong one".to_string()),
        Some("wrong two".to_string()),
        Some("wrong three".to_string()),
    ]);
    assert_eq!(
        error_of(&h.call(&Request::List)).0,
        rusthorse::protocol::ErrorCode::UnlockFailed
    );
    unlock();
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));

    // Another program changes another entry while the vault is locked, and
    // puts the file's times back.
    h.agent.lock_for(SCREEN_LOCK, "test");
    let path = h.vault_path();
    let modified = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .expect("mtime");
    {
        let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
        let other = vault.find("OTHER").expect("find");
        let changes = EntryChanges {
            username: Some("someone else".into()),
            ..EntryChanges::default()
        };
        vault.edit(other, &changes, None).expect("edit");
        vault.save().expect("save");
    }
    std::fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(modified))
        .expect("set the time back");
    // A failed unlock: the change is not found yet, nothing ends.
    h.ui.passwords.lock().unwrap().extend([
        Some("wrong one".to_string()),
        Some("wrong two".to_string()),
        Some("wrong three".to_string()),
    ]);
    let failed = h.call(&Request::List);
    assert_eq!(
        error_of(&failed).0,
        rusthorse::protocol::ErrorCode::UnlockFailed
    );
    assert_eq!(grant_state(&h, &id).as_deref(), Some("active"));
    // The next unlock finds it, and ends the grant before it completes.
    unlock();
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    let unlocked = audit_records(&h)
        .into_iter()
        .rev()
        .find(|r| r["action"] == "unlock" && r["outcome"] == "unlocked")
        .expect("the unlock record");
    assert!(
        unlocked["detail"]
            .as_str()
            .is_some_and(|d| d.contains("changed by another program")),
        "{unlocked}"
    );
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
    assert_eq!(ended_with(&h, &id), "vault_changed");
}

/// The unlock barrier tells the brokers before anything waits for the audit
/// log (ADR 0013: revocation never waits for the audit log): with the log
/// blocked, the broker of a grant that survived the lock is told to revoke
/// while the unlock's record still waits; once the log fails, the unlock
/// fails and the vault stays locked.
#[test]
fn the_unlock_barrier_tells_the_brokers_before_it_waits_for_the_audit_log() {
    use rusthorse::protocol::{EntryChanges, ErrorCode, Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY), ("OTHER", "abcdefgh")]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let running = start(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], WAITS),
    );
    command_env(&h);
    let id = grants(&h)[0].id.clone();
    // The grant survives a screen lock; another program changes the file.
    h.agent.lock_for(SCREEN_LOCK, "test");
    {
        let path = h.vault_path();
        let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
        let other = vault.find("OTHER").expect("find");
        let changes = EntryChanges {
            username: Some("someone else".into()),
            ..EntryChanges::default()
        };
        vault.edit(other, &changes, None).expect("edit");
        vault.save().expect("save");
    }
    let mut audit = BlockedAudit::new(&h);
    let socket = h.socket.clone();
    let (answer, unlocked) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer.send(rusthorse::client::Client::new(socket).call(&Request::List));
    });
    let revoke = logged_within(&log, "revoke", Duration::from_secs(5))
        .expect("the broker was not told while the unlock's record waited");
    assert_eq!(revoke["message"]["reason"], "vault_changed");
    assert!(unlocked.try_recv().is_err(), "the unlock was done");
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    // The log fails: so does the unlock, and the vault stays locked.
    audit.release();
    let failed = unlocked
        .recv_timeout(TEST_LIMIT)
        .expect("the unlock's answer")
        .expect("call");
    let (code, message) = error_of(&failed);
    assert_eq!(code, ErrorCode::Internal, "{message}");
    assert!(message.contains("cannot write the audit log"), "{message}");
    assert!(status(&h).locked);
    audit.wait_for_end_of(&id);
    drop(audit);
    // With the log back, the vault unlocks; the grant had ended already.
    match h.call(&Request::List) {
        Response::Entries { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
}

/// No lock waits for the audit record of an unlock: while an unlock that
/// ends no grant (the file is as the agent left it) waits to record itself,
/// `rusthorse lock` still ends every grant and tells its broker at once;
/// the unlock then does not take effect.
#[test]
fn a_lock_does_not_wait_for_the_record_of_an_unlock() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let running = start(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], WAITS),
    );
    command_env(&h);
    let id = grants(&h)[0].id.clone();
    h.agent.lock_for(SCREEN_LOCK, "test");
    let prompts = h.ui.password_prompts.lock().unwrap().len();
    let mut audit = BlockedAudit::new(&h);
    let call = |request: Request| {
        let socket = h.socket.clone();
        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(rusthorse::client::Client::new(socket).call(&request));
        });
        answered
    };
    let unlocked = call(Request::List);
    // The password is typed; the unlock then waits to record itself.
    eventually("the unlock dialog", || {
        (h.ui.password_prompts.lock().unwrap().len() > prompts).then_some(())
    });
    std::thread::sleep(Duration::from_secs(1));
    assert!(unlocked.try_recv().is_err(), "the unlock was done");
    let locked = call(Request::Lock);
    let revoke = logged_within(&log, "revoke", Duration::from_secs(5))
        .expect("the lock waited for the unlock's record");
    assert_eq!(revoke["message"]["reason"], "locked");
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    audit.release();
    let answer = |answered: std::sync::mpsc::Receiver<anyhow::Result<Response>>| -> Response {
        answered
            .recv_timeout(TEST_LIMIT)
            .expect("an answer")
            .expect("call")
    };
    // The unlock's record fails: it does not take effect.
    let (code, message) = error_of(&answer(unlocked));
    assert_eq!(code, ErrorCode::Internal, "{message}");
    // The lock was done before its own record, which fails too. So does
    // the grant's end record, once its broker confirms (the broker's answer
    // is what tells): waited for, so that it is not written once the log is
    // back.
    let _ = answer(locked);
    audit.wait_for_end_of(&id);
    drop(audit);
    assert!(status(&h).locked);
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
}

/// A vault created where the one the agent read was is a changed file too
/// (the unlock barrier): the grants that survived the lock end.
#[test]
fn a_new_vault_file_ends_the_grants_that_survived_the_lock() {
    use rusthorse::protocol::{Request, Response};
    use rusthorse::session_lock::{Locker, SCREEN_LOCK};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let _log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let running = start(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], WAITS),
    );
    command_env(&h);
    let id = grants(&h)[0].id.clone();
    h.agent.lock_for(SCREEN_LOCK, "test");
    std::fs::remove_file(h.vault_path()).expect("rm");
    match h.call(&Request::CreateVault) {
        Response::Ok { .. } => {}
        other => panic!("unexpected {}", other.kind()),
    }
    assert_eq!(grant_state(&h, &id).as_deref(), Some("revoked"));
    go(&h);
    assert!(matches!(running.wait(), Response::Exited { .. }));
    assert_eq!(ended_with(&h, &id), "vault_changed");
}

/// A broker that breaks the conversation is killed and its grant ends
/// (`broker_failed`), and one that does not confirm a revocation is killed
/// within about a second; the command goes on either way, and the run's
/// status is the command's (ADR 0013, failures).
#[test]
fn a_broker_that_breaks_the_conversation_or_ignores_a_revocation_is_killed() {
    use rusthorse::protocol::{Request, Response};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    for mode in ["bad_number", "ignore_revoke"] {
        let log = fake_broker(&h, mode);
        let _ = std::fs::remove_file(h.dir.path().join("env.txt"));
        let _ = std::fs::remove_file(h.dir.path().join("go"));
        h.decide(&[Decision::AllowOnce]);
        let script = format!(
            "touch {}; {WAITS}; exit 7",
            log.with_extension("jsonl.go").display()
        );
        let running = start(
            &h,
            broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script),
        );
        command_env(&h);
        let pid = logged(&log, "install")["pid"].as_u64().expect("pid");
        let id = logged(&log, "install")["install"]["grant"]
            .as_str()
            .expect("grant")
            .to_string();
        let port = logged(&log, "install")["listen"][1]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .expect("port");
        if mode == "bad_number" {
            // It asks for request 5 first: killed, its grant gone.
            assert!(process_gone(pid), "not killed");
            eventually("the grant's end", || {
                grant_state(&h, &id).is_none().then_some(())
            });
        } else {
            let started = Instant::now();
            match h.call(&Request::RevokeGrant {
                id: Some(id.clone()),
            }) {
                Response::Ok { .. } => {}
                other => panic!("unexpected {}", other.kind()),
            }
            let took = started.elapsed();
            assert!(took >= Duration::from_secs(1), "{took:?}");
            assert!(took < Duration::from_secs(4), "{took:?}");
            assert!(process_gone(pid), "not killed");
        }
        // The broker is gone, the command still runs: the agent keeps its
        // own copy of the listening socket until the command ends, so that
        // no other program can take the port the command uses.
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", port)).is_err(),
            "{mode}: port {port} was let go while the command ran"
        );
        go(&h);
        match running.wait() {
            Response::Exited { code, .. } => assert_eq!(code, Some(7), "{mode}"),
            other => panic!("unexpected {}", other.kind()),
        }
        assert!(
            port_released(port),
            "{mode}: port {port} still held after the run"
        );
        let reason = ended_with(&h, &id);
        let expected = if mode == "bad_number" {
            "broker_failed"
        } else {
            "revoked"
        };
        assert_eq!(reason, expected, "{mode}");
    }
}

/// Every request a broker admits is recorded before it is forwarded, with
/// its method's label and nothing of its path, and again when it ends (ADR
/// 0013, decision 9 and the scope amendment); the run's request limit
/// refuses the next one, and the grant's end record counts them all.
#[test]
fn admissions_are_recorded_before_the_broker_forwards_anything() {
    use rusthorse::protocol::Response;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "admit");
    h.decide(&[Decision::AllowOnce]);
    let go_file = log.with_extension("jsonl.go");
    let done = log.with_extension("jsonl.done");
    let script = format!(
        "touch {}; i=0; while [ ! -e {} ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done",
        go_file.display(),
        done.display()
    );
    let mut request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script);
    request.limits.max_requests = Some(1);
    let running = start(&h, request);
    // Its one request answered 200: nothing to report.
    assert!(matches!(
        running.wait(),
        Response::Exited { unauthorized, .. } if unauthorized.is_empty()
    ));
    let answers: Vec<serde_json::Value> = broker_log(&log)
        .into_iter()
        .filter(|e| e["event"] == "answer")
        .map(|e| e["message"].clone())
        .collect();
    assert_eq!(
        answers,
        [
            serde_json::json!({"type": "admitted", "request": 1}),
            serde_json::json!({"type": "refused", "request": 2, "reason": "exhausted"}),
        ]
    );
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    // The records of a grant's requests and its end are written in order by
    // one thread, possibly after the run's answer (request 2 was refused
    // without it): once the end is there, so are they.
    assert_eq!(ended_with(&h, &id), "command_ended");
    let records: Vec<serde_json::Value> = audit_records(&h)
        .into_iter()
        .filter(|r| r["action"] == "broker_request")
        .collect();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["outcome"], "admitted");
    assert_eq!(records[0]["grant"], id.as_str());
    assert_eq!(records[0]["request"], 1);
    assert_eq!(records[0]["method"], "POST");
    assert!(records[0].get("route").is_none(), "{}", records[0]);
    assert_eq!(records[1]["outcome"], "completed");
    assert_eq!(records[1]["status"], 200);
    assert_eq!(records[1]["bytes_sent"], 10);
    assert_eq!(records[1]["bytes_received"], 20);
    let audit = h.audit_text();
    assert!(
        !audit.contains(FAKE_KEY) && !audit.contains("rh_"),
        "{audit}"
    );
    assert_eq!(
        grant_ends(&h)[&id]["requests"],
        serde_json::json!({"admitted": 1, "finished": 1, "unknown": 0, "refused": 1})
    );
}

/// The requests a grant's destination answered with `401 Unauthorized` are
/// counted — whatever became of them after their head — and shown in
/// `grants` while the command runs; when it ends, the run's answer names
/// the grant, its entry and its approved origin (no base path), with the
/// count, so that `rusthorse run` can say that the destination refused the
/// key. Other statuses are not counted.
#[test]
fn a_run_reports_the_grants_whose_destination_answered_401() {
    use rusthorse::protocol::{Response, UnauthorizedGrant};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "unauthorized");
    h.decide(&[Decision::AllowOnce]);
    let go_file = log.with_extension("jsonl.go");
    let script = format!("touch {}; {WAITS}", go_file.display());
    let running = start(
        &h,
        broker_run_request(
            &h,
            vec![],
            vec![brokered_to("K", "KEY", "https://api.example.com/v1", None)],
            &script,
        ),
    );
    // While the command runs: the stand-in reports its three requests, two
    // of them answered 401.
    let listed = eventually("the 401 answers to be counted", || {
        grants(&h).into_iter().find(|g| g.unauthorized == Some(2))
    });
    assert_eq!(listed.requests, 3);
    assert_eq!(listed.destination, "https://api.example.com");
    assert_eq!(listed.base_path.as_deref(), Some("/v1"));
    go(&h);
    let Response::Exited {
        code, unauthorized, ..
    } = running.wait()
    else {
        panic!("the run did not end with the command")
    };
    assert_eq!(code, Some(0));
    assert_eq!(
        unauthorized,
        [UnauthorizedGrant {
            var: "K".into(),
            entry: listed.entry.clone(),
            destination: "https://api.example.com".into(),
            requests: 2,
        }]
    );
    assert!(listed.entry.starts_with("KEY ("), "{}", listed.entry);
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    assert_eq!(listed.id, id);
    assert_eq!(ended_with(&h, &id), "command_ended");
    let statuses: Vec<serde_json::Value> = audit_records(&h)
        .into_iter()
        .filter(|r| r["action"] == "broker_request" && r["outcome"] != "admitted")
        .map(|r| r["status"].clone())
        .collect();
    assert_eq!(statuses, [401, 200, 401]);
}

/// When the command's leader exits, its grants are revoked at once — before
/// its other processes are terminated and its output drained — so that a
/// token kept by a descendant that left its process group (`setsid`) no
/// longer works (ADR 0013, the end of the command; threat model L17).
#[test]
fn the_end_of_the_command_revokes_its_grants_before_its_output_is_drained() {
    use rusthorse::protocol::Response;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    // A descendant in a session of its own goes on printing after the
    // leader exits, and notes when it sees the broker told to revoke.
    let seen = h.dir.path().join("revoked-while-it-ran");
    let descendant = h.dir.path().join("descendant.sh");
    std::fs::write(
        &descendant,
        format!(
            "i=0\nwhile [ $i -lt 100 ]; do\n  if grep -q '\"event\": \"revoke\"' '{}'; then \
             touch '{}'; break; fi\n  echo tick\n  sleep 0.05\n  i=$((i+1))\ndone\necho after\n",
            log.display(),
            seen.display()
        ),
    )
    .expect("write");
    let script = format!("setsid sh '{}' & exit 3", descendant.display());
    let response = broker_run(
        &h,
        broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script),
    );
    match response {
        Response::Exited { code, .. } => assert_eq!(code, Some(3)),
        other => panic!("unexpected {}", other.kind()),
    }
    assert!(
        seen.exists(),
        "the grant was not revoked while the output was drained"
    );
    let revoke = logged(&log, "revoke");
    assert_eq!(revoke["message"]["reason"], "command_ended");
    // Its end is recorded once its broker confirms, possibly after the
    // run's answer.
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    assert_eq!(ended_with(&h, &id), "command_ended");
}

/// A requester that goes away ends the run: its grants first, then its
/// command (ADR 0013, decision 8).
#[test]
fn a_requester_that_goes_away_ends_its_runs_grants() {
    use rusthorse::protocol::{Request, send_frame};
    use std::os::unix::net::UnixStream;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    // A command that ignores SIGTERM, so that terminating it takes a
    // while: its grants end before that.
    let script = format!("trap '' TERM; {WAITS}");
    let request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script);
    let stream = UnixStream::connect(&h.socket).expect("connect");
    send_frame(&stream, &Request::BrokerRunV2(request), &[]).expect("send");
    command_env(&h);
    let id = grants(&h)[0].id.clone();
    let pid = logged(&log, "install")["pid"].as_u64().expect("pid");
    let gone = Instant::now();
    drop(stream);
    let revoke = logged(&log, "revoke");
    assert!(
        gone.elapsed() < Duration::from_secs(2),
        "revoked only after the command: {:?}",
        gone.elapsed()
    );
    assert_eq!(revoke["message"]["reason"], "command_ended");
    eventually("the end of the run", || grants(&h).is_empty().then_some(()));
    assert!(process_gone(pid), "the broker outlived its run");
    assert_eq!(ended_with(&h, &id), "command_ended");
    // The run is recorded as ended once its grants are gone, a moment
    // later: nobody is left to answer.
    wait_for_run_end(&h, "the run did not end after its requester left");
    assert_eq!(
        audit_outcomes(&h, "run").last().map(String::as_str),
        Some("exited")
    );
}

/// A broker run's destination and limits are checked before anything else
/// (ADR 0013, scope amendment). `rusthorse run` refuses a destination that
/// is not `https://`, a host name, an optional port and an optional base
/// path — user information, a query, a fragment, an IP address, a bad base
/// path — and limits out of range before it sends anything (125); the
/// agent refuses them from any other client before any dialog or unlock,
/// without repeating the destination. Nothing runs, no broker starts,
/// nothing is audited; the same run with a valid destination is asked and
/// runs.
#[test]
fn a_broker_runs_destination_and_limits_are_checked_before_any_dialog() {
    use rusthorse::broker_grant::GrantLimits;
    use rusthorse::protocol::ErrorCode;
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(
        &h,
        &[("KEY", FAKE_KEY), ("OTHER", "sk-other-test-0000000000")],
    );
    let log = fake_broker(&h, "ready");
    // Had anyone asked, the run would be allowed, and its command would
    // leave this file behind.
    h.decide(&[Decision::AllowOnce]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());

    // Through `rusthorse run`: refused before anything is sent.
    let valid = "K=KEY@https://api.example.com";
    for (args, says) in [
        (&["--broker", "K=KEY"][..], "name the destination"),
        (
            &["--broker", "K=KEY@api.example.com"][..],
            "must start with https://",
        ),
        (
            &["--broker", "K=KEY@http://api.example.com"][..],
            "must start with https://",
        ),
        // The URL starts after the last `@`: one with user information is
        // left without its https://.
        (
            &["--broker", "K=KEY@https://user@api.example.com"][..],
            "must start with https://",
        ),
        (
            &["--broker", "K=KEY@https://api.example.com?q=1"][..],
            "query or a fragment",
        ),
        (
            &["--broker", "K=KEY@https://api.example.com/v1?q=1"][..],
            "base path is not valid",
        ),
        (
            &["--broker", "K=KEY@https://192.0.2.1"][..],
            "not an IP address",
        ),
        (
            &["--broker", "K=KEY@https://api.example.com/v1/"][..],
            "base path is not valid",
        ),
        (
            &["--broker", valid, "--broker-lifetime", "0"][..],
            "1 to 1440 minutes, not 0",
        ),
        (
            &["--broker", valid, "--broker-lifetime", "1441"][..],
            "1 to 1440 minutes, not 1441",
        ),
        (
            &["--broker", valid, "--broker-requests", "0"][..],
            "1 to 1000000, not 0",
        ),
    ] {
        let mut argv = vec!["run"];
        argv.extend(args);
        argv.extend(["--", "sh", "-c", script.as_str()]);
        let out = h.run(&argv);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(125), "{args:?}: {stderr}");
        assert!(stderr.contains(says), "{args:?}: {says:?} not in {stderr}");
    }

    // From another client: refused by the agent, whole.
    let refused = |brokered: Vec<rusthorse::protocol::BrokerBinding>, limits: GrantLimits| {
        let mut request = broker_run_request(&h, vec![], brokered, &script);
        request.limits = limits;
        let (code, message) = error_of(&broker_run(&h, request));
        assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
        message
    };
    let defaults = GrantLimits::default();
    for (destination, says) in [
        ("", "must start with https://"),
        ("api.example.com", "must start with https://"),
        ("http://api.example.com", "must start with https://"),
        ("https://", "must name a host"),
        ("https://user@api.example.com", "user information"),
        (
            "https://user:FAKE-pw@api.example.com/v1",
            "user information",
        ),
        ("https://api.example.com?q=1", "query or a fragment"),
        ("https://api.example.com#top", "query or a fragment"),
        ("https://api.example.com/v1?q=1", "base path is not valid"),
        ("https://192.0.2.1", "not an IP address"),
        ("https://[2001:db8::1]:8443", "not an IP address"),
        ("https://2130706433", "not an IP address"),
        ("https://API.example.com", "lowercase"),
        ("https://api.example.com:99999", "the port must be a number"),
        ("https://api.example.com/v1/", "base path is not valid"),
        ("https://api.example.com/v1//x", "base path is not valid"),
        ("https://api.example.com/../v1", "base path is not valid"),
        ("https://api.example.com/v1%2Fx", "base path is not valid"),
    ] {
        let message = refused(vec![brokered_to("K", "KEY", destination, None)], defaults);
        assert!(
            message.starts_with("K of KEY: the destination"),
            "{destination}: {message}"
        );
        assert!(
            message.contains(says),
            "{destination}: {says:?} not in {message}"
        );
        // What it refuses is not repeated.
        assert!(
            !message.contains("user@")
                && !message.contains("user:")
                && !message.contains("FAKE")
                && !message.contains("2001"),
            "{destination}: {message}"
        );
    }
    // One destination that does not check out refuses the whole run.
    let message = refused(
        vec![
            brokered("A", "KEY", None),
            brokered_to("B", "OTHER", "http://api.example.com", None),
        ],
        defaults,
    );
    assert!(message.starts_with("B of OTHER: "), "{message}");
    for (limits, says) in [
        (
            GrantLimits {
                max_lifetime_minutes: 0,
                ..defaults
            },
            "1 to 1440 minutes, not 0",
        ),
        (
            GrantLimits {
                max_lifetime_minutes: 1441,
                ..defaults
            },
            "1 to 1440 minutes, not 1441",
        ),
        (
            GrantLimits {
                max_requests: Some(0),
                ..defaults
            },
            "1 to 1000000, not 0",
        ),
        (
            GrantLimits {
                max_requests: Some(1_000_001),
                ..defaults
            },
            "1 to 1000000, not 1000001",
        ),
    ] {
        let message = refused(vec![brokered("K", "KEY", None)], limits);
        assert!(message.starts_with("the grants' limits: "), "{message}");
        assert!(message.contains(says), "{says:?} not in {message}");
    }

    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the command ran");
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(
        h.ui.password_prompts.lock().unwrap().is_empty(),
        "the vault was unlocked for a request refused without it"
    );
    assert_eq!(h.audit_text(), "", "something was audited");
    assert!(broker_log(&log).is_empty(), "a broker was started");
    assert!(grants(&h).is_empty());

    // The same run with a valid destination is asked, and runs.
    let out = h.run(&["run", "--broker", valid, "--", "sh", "-c", &script]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(marker.exists(), "the command did not run");
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
    assert_eq!(audit_outcomes(&h, "run"), ["allowed_once", "exited"]);
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    assert_eq!(ended_with(&h, &id), "command_ended");
}

/// A child process killed, if it still runs, when the test is done with it
/// — a failed assertion included.
struct Reaped(Option<std::process::Child>);

impl Reaped {
    /// Wait for the child's end, within [`TEST_LIMIT`], and take its output.
    fn output(&mut self) -> Output {
        let child = self.0.take().expect("the child");
        within(TEST_LIMIT, move || child.wait_with_output().expect("wait"))
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What a run through the broker shows and records of its destination and
/// limits, end to end through `rusthorse run` (ADR 0013, scope amendment):
/// the dialog shows the approved origin, the base path apart from it, and
/// the limits the run asked for; the broker is given the origin alone; the
/// `--url` variable gets the broker's address with the base path; and the
/// run's audit record, `rusthorse grants` and `rusthorse grants --json`
/// show the origin and the base path apart.
#[test]
fn a_broker_run_shows_and_lists_its_origin_apart_from_its_base_path() {
    if !python3() {
        return;
    }
    let h = Harness::new();
    let uuids = seed(&h, &[("KEY", FAKE_KEY)]);
    let identity = format!("KEY ({})", &uuids["KEY"][..8]);
    let log = fake_broker(&h, "ready");
    h.decide(&[Decision::AllowOnce]);
    let script = format!("printf 'base=%s\\n' \"$BASE\"; {WAITS}");
    let mut client = Reaped(Some(
        h.cmd(&[
            "run",
            "--broker",
            "K=KEY@https://api.example.com:8443/v2",
            "--url",
            "BASE=KEY",
            "--broker-requests",
            "5",
            "--broker-lifetime",
            "30",
            "--broker-locks",
            "end",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rusthorse"),
    ));
    let env = command_env(&h);
    let installed = logged(&log, "install");
    let install = &installed["install"];
    let port = installed["listen"][1].as_u64().expect("port");
    let id = install["grant"].as_str().expect("grant").to_string();
    // The broker: the approved origin alone, and the run's lifetime.
    assert_eq!(install["origin"], "https://api.example.com:8443");
    let lifetime = install["lifetime_secs"].as_u64().expect("lifetime");
    assert!((30 * 60 - 30..=30 * 60).contains(&lifetime), "{lifetime}");
    assert_eq!(installs_validly(install), Ok(()));
    // The command: the token, and the broker's address with the base path.
    assert_eq!(env["K"], install["token"].as_str().expect("token"));
    assert_eq!(env["BASE"], format!("http://127.0.0.1:{port}/v2"));

    // The dialog: the origin, the base path apart, the limits asked for.
    let detail = |label: &str| approval_detail(&h, label).unwrap_or_default();
    assert_eq!(
        detail("Grant"),
        format!("K ← a token for {identity}; BASE ← the broker's address")
    );
    assert_eq!(detail("Approved origin"), "https://api.example.com:8443");
    assert_eq!(detail("Base path"), "/v2 (not a limit)");
    assert_eq!(
        detail("Ends"),
        "with the command, on rusthorse lock, revocation or a change to the entry, or after \
         30m; also on screen lock, suspend or idle lock"
    );
    assert_eq!(detail("Requests"), "at most 5; at most 16 at a time");

    // `rusthorse grants`: the origin and the base path in columns of their
    // own, never joined.
    let out = h.run(&["grants"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let table = text(&out.stdout);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 2, "{table}");
    // (Every cell before the requester's is ASCII: byte positions are
    // character positions.)
    let column = |header: &str| {
        let at = lines[0].find(header).expect("a column");
        lines[1][at..]
            .split("  ")
            .next()
            .expect("a cell")
            .to_string()
    };
    assert_eq!(column("ID"), id);
    assert_eq!(column("ENTRY"), identity);
    assert_eq!(column("APPROVED ORIGIN"), "https://api.example.com:8443");
    assert_eq!(column("BASE PATH (NOT A LIMIT)"), "/v2");
    assert_eq!(column("STATE"), "active");
    assert_eq!(column("REQUESTS"), "0 of 5");
    assert_eq!(column("AUTOMATIC LOCKS"), "end");
    assert!(!table.contains("8443/v2"), "{table}");
    let out = h.run(&["grants", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(listed.len(), 1, "{listed:?}");
    let grant = &listed[0];
    assert_eq!(grant["id"], id.as_str());
    assert_eq!(grant["entry"], identity.as_str());
    assert_eq!(grant["var"], "K");
    assert_eq!(grant["destination"], "https://api.example.com:8443");
    assert_eq!(grant["base_path"], "/v2");
    assert_eq!(grant["max_requests"], 5);
    assert_eq!(grant["automatic_locks"], "end");
    assert!(grant.get("preset").is_none(), "{grant}");
    assert!(
        grant["ends_in_secs"]
            .as_u64()
            .is_some_and(|left| left <= 30 * 60),
        "{grant}"
    );

    go(&h);
    let out = client.output();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(&format!("base=http://127.0.0.1:{port}/v2\n")),
        "{stdout}"
    );
    // The run's record: the origin and the base path apart.
    let approval = audit_records(&h)
        .into_iter()
        .find(|r| r["action"] == "run" && r["outcome"] == "allowed_once")
        .expect("the approval's record");
    assert_eq!(
        approval["grants"],
        serde_json::json!([{
            "id": id,
            "entry": identity,
            "destination": "https://api.example.com:8443",
            "base_path": "/v2",
        }])
    );
    let out = h.run(&["audit", "-n", "20"]);
    let shown = text(&out.stdout);
    assert!(
        shown.contains(&format!(
            " grants: {id} for {identity} to https://api.example.com:8443 (base path /v2, not a \
             limit);"
        )),
        "{shown}"
    );
    assert_eq!(ended_with(&h, &id), "command_ended");
}

/// Send `request` as it is, on a connection of its own, without descriptors,
/// and read the agent's answer.
fn send_raw(h: &Harness, request: &serde_json::Value) -> rusthorse::protocol::Response {
    use rusthorse::protocol::{read_message, send_frame};
    let stream = std::os::unix::net::UnixStream::connect(&h.socket).expect("connect");
    send_frame(&stream, request, &[]).expect("send");
    read_message(&stream).expect("an answer")
}

/// The requests of protocol 8 that knew broker profiles — `broker_run`,
/// whose bindings name no destination, and `broker_edit` — are refused
/// whole by this agent, before any unlock or approval, and so is
/// `--clear broker` in an edit (ADR 0013, scope amendment); a
/// `broker_run_v2` with a field this agent does not know, or without a
/// destination or limits, is refused too, never acted on in part. Nothing
/// runs, no broker starts, the vault file is untouched, nothing is audited;
/// the same run as a well-formed `broker_run_v2` is asked and runs.
#[test]
fn the_agent_refuses_protocol_8s_broker_requests_and_unknown_fields_before_any_approval() {
    use rusthorse::protocol::{ErrorCode, Request, Response};
    if !python3() {
        return;
    }
    let h = Harness::new();
    seed(&h, &[("KEY", FAKE_KEY)]);
    let log = fake_broker(&h, "ready");
    let on_disk = std::fs::read(h.vault_path()).expect("read");
    h.decide(&[Decision::AllowOnce]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    let refused = |request: &serde_json::Value, says: &str| {
        let response = send_raw(&h, request);
        let (code, message) = error_of(&response);
        assert_eq!(code, ErrorCode::InvalidRequest, "{request}: {message}");
        assert!(message.contains(says), "{says:?} not in {message}");
    };

    // Protocol 8's run through the broker, as its clients sent it, and with
    // this protocol's destinations and limits added: unknown either way.
    let mut protocol_8_run = serde_json::json!({
        "type": "broker_run",
        "bindings": [],
        "brokered": [{"var": "K", "entry": "KEY", "url_var": "K_URL"}],
        "argv": ["sh", "-c", &script],
        "cwd": h.dir.path().to_str().expect("utf8"),
        "env": [["PATH", "/usr/bin:/bin"]],
        "redact": true,
        "forward_stdin": false,
    });
    refused(&protocol_8_run, "unknown variant `broker_run`");
    protocol_8_run["brokered"][0]["destination"] = DESTINATION.into();
    protocol_8_run["limits"] =
        serde_json::to_value(rusthorse::broker_grant::GrantLimits::default()).expect("json");
    refused(&protocol_8_run, "unknown variant `broker_run`");
    // Its edit of a profile, setting one or clearing it, and the field to
    // clear in a plain edit.
    for changes in [
        serde_json::json!({"broker": {"preset": "anthropic"}}),
        serde_json::json!({"username": "me", "broker": {"preset": "openai"}}),
        serde_json::json!({"clear": ["broker"]}),
    ] {
        refused(
            &serde_json::json!({"type": "broker_edit", "name": "KEY", "changes": changes}),
            "unknown variant `broker_edit`",
        );
    }
    refused(
        &serde_json::json!({"type": "edit", "name": "KEY", "changes": {"clear": ["broker"]}}),
        "unknown variant `broker`",
    );
    // A plain edit that carries protocol 8's profile: refused whole, its
    // other changes with it.
    refused(
        &serde_json::json!({
            "type": "edit", "name": "KEY",
            "changes": {"username": "me", "broker": {"preset": "anthropic"}}
        }),
        "unknown field `broker`",
    );

    // This protocol's run, with a field it does not know, or without one it
    // needs.
    let valid = serde_json::to_value(Request::BrokerRunV2(broker_run_request(
        &h,
        vec![],
        vec![brokered("K", "KEY", Some("K_URL"))],
        &script,
    )))
    .expect("json");
    let spoiled = |spoil: &dyn Fn(&mut serde_json::Value)| {
        let mut request = valid.clone();
        spoil(&mut request);
        request
    };
    for (request, says) in [
        (
            spoiled(&|r| r["profile"] = "anthropic".into()),
            "unknown field `profile`",
        ),
        (
            spoiled(&|r| r["brokered"][0]["preset"] = "anthropic".into()),
            "unknown field `preset`",
        ),
        (
            spoiled(&|r| r["brokered"][0]["routes"] = serde_json::json!(["POST /v1/messages"])),
            "unknown field `routes`",
        ),
        (
            spoiled(&|r| r["limits"]["max_in_flight"] = 1.into()),
            "unknown field `max_in_flight`",
        ),
        // A binding by value that carries a broker binding's destination is
        // refused, not given by value without it.
        (
            spoiled(&|r| {
                r["bindings"] = serde_json::json!([{
                    "var": "SECOND", "entry": "KEY",
                    "destination": "https://other.example", "max_requests": 1
                }])
            }),
            "unknown field `destination`",
        ),
        (
            spoiled(&|r| {
                r["brokered"][0]
                    .as_object_mut()
                    .expect("binding")
                    .remove("destination");
            }),
            "missing field `destination`",
        ),
        (
            spoiled(&|r| {
                r.as_object_mut().expect("request").remove("limits");
            }),
            "missing field `limits`",
        ),
        (
            spoiled(&|r| r["limits"]["automatic_locks"] = "never".into()),
            "unknown variant `never`",
        ),
    ] {
        refused(&request, says);
    }

    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the command ran");
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(
        h.ui.password_prompts.lock().unwrap().is_empty(),
        "the vault was unlocked"
    );
    assert_eq!(h.audit_text(), "", "something was audited");
    assert!(broker_log(&log).is_empty(), "a broker was started");
    assert_eq!(std::fs::read(h.vault_path()).expect("read"), on_disk);

    // The same run, well formed, is asked and runs.
    let request = broker_run_request(&h, vec![], vec![brokered("K", "KEY", None)], &script);
    match broker_run(&h, request) {
        Response::Exited { code, .. } => assert_eq!(code, Some(0)),
        other => panic!("unexpected {}", other.kind()),
    }
    assert!(marker.exists(), "the command did not run");
    assert_eq!(audit_outcomes(&h, "run"), ["allowed_once", "exited"]);
    let id = logged(&log, "install")["install"]["grant"]
        .as_str()
        .expect("grant")
        .to_string();
    assert_eq!(ended_with(&h, &id), "command_ended");
}

/// Where phase 1 of the credential broker stored an entry's profile.
const PHASE_1_PROFILE: &str = "Rusthorse.Broker";

/// A profile as phase 1 stored it: an origin, a base path and limits other
/// than those of the runs below.
const STORED_PROFILE: &str = r#"{"version":1,"preset":"anthropic","revision":1,"origin":"https://api.anthropic.com","base_path":"/v1","automatic_locks":"end","max_lifetime_minutes":5,"max_requests":1}"#;

/// The field `key` of the entry titled `title`, as another KeePass client
/// reads it from the file: its text, and whether it is protected.
fn field_elsewhere(h: &Harness, title: &str, key: &str) -> Option<(String, bool)> {
    use keepass::{Database, DatabaseKey};
    let db = Database::open(
        &mut std::fs::File::open(h.vault_path()).expect("open"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("decrypt");
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .expect("the entry");
    entry
        .fields
        .get(key)
        .map(|value| (value.get().clone(), value.is_protected()))
}

/// An entry that carries a profile stored by phase 1 (ADR 0013, scope
/// amendment) is an entry like any other: the field is listed by name only;
/// the entry is used through `--broker VAR=ENTRY@URL` whatever the field
/// holds — a profile, something unreadable, a protected field; and the field
/// is never read: each grant goes to the destination its run names, with
/// the run's limits, never the stored origin, base path or limits. The
/// field is kept as it was, byte for byte, through runs and edits.
#[test]
fn an_entry_with_a_phase_1_profile_is_used_like_any_other_and_its_profile_is_never_read() {
    if !python3() {
        return;
    }
    let h = Harness::new();
    let names = ["STORED", "UNREADABLE", "HIDDEN"];
    seed(
        &h,
        &[
            ("STORED", FAKE_KEY),
            ("UNREADABLE", "sk-ant-test-1111111111111111"),
            ("HIDDEN", "sk-ant-test-2222222222222222"),
        ],
    );
    set_field_elsewhere(&h, "STORED", PHASE_1_PROFILE, STORED_PROFILE, false);
    set_field_elsewhere(&h, "UNREADABLE", PHASE_1_PROFILE, r#"{"version":2"#, false);
    set_field_elsewhere(&h, "HIDDEN", PHASE_1_PROFILE, STORED_PROFILE, true);
    let fields = || -> Vec<Option<(String, bool)>> {
        names
            .iter()
            .map(|name| field_elsewhere(&h, name, PHASE_1_PROFILE))
            .collect()
    };
    let before = fields();
    assert_eq!(before[2], Some((STORED_PROFILE.to_string(), true)));

    // Listed by name, its value never shown.
    for name in names {
        let out = h.run(&["show", name, "--json"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(
            json["other_fields"],
            serde_json::json!([PHASE_1_PROFILE]),
            "{name}: {json}"
        );
        assert!(json.get("broker").is_none(), "{name}: {json}");
        assert!(json.get("protected_fields").is_none(), "{name}: {json}");
        let out = h.run(&["show", name]);
        let shown = text(&out.stdout);
        assert!(
            shown.contains("fields:     Rusthorse.Broker\n"),
            "{name}: {shown}"
        );
        assert!(
            !shown.lines().any(|line| line.starts_with("broker:")),
            "{name}: {shown}"
        );
        assert!(
            !shown.contains("anthropic") && !shown.contains("preset"),
            "{name}: {shown}"
        );
    }
    let out = h.run(&["list", "--json"]);
    let listed = text(&out.stdout);
    assert!(
        !listed.contains("\"broker\"") && !listed.contains("anthropic"),
        "{listed}"
    );

    // Each used through the broker, to the destination the run names, with
    // the run's limits: the defaults, not the stored ones.
    let log = fake_broker(&h, "ready");
    h.ui.scrolls.store(true, Ordering::SeqCst);
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "run",
        "--broker",
        "A=STORED@https://a.example.com/v2",
        "--url",
        "A_URL=STORED",
        "--broker",
        "B=UNREADABLE@https://b.example.com",
        "--broker",
        "C=HIDDEN@https://c.example.com:8443",
        "--",
        "sh",
        "-c",
        "printf 'url=%s\\n' \"$A_URL\"",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let installs: Vec<serde_json::Value> = broker_log(&log)
        .into_iter()
        .filter(|e| e["event"] == "install")
        .collect();
    assert_eq!(installs.len(), 3, "{installs:?}");
    let origin_of = |install: &serde_json::Value| {
        install["install"]["origin"]
            .as_str()
            .expect("origin")
            .to_string()
    };
    let mut origins: Vec<String> = installs.iter().map(origin_of).collect();
    origins.sort();
    assert_eq!(
        origins,
        [
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com:8443"
        ]
    );
    for install in &installs {
        let lifetime = install["install"]["lifetime_secs"]
            .as_u64()
            .expect("lifetime");
        assert!(lifetime > 700 * 60, "not the run's lifetime: {lifetime}");
        assert!(
            install["install"].get("profile").is_none(),
            "{}",
            install["install"]
        );
    }
    let a = installs
        .iter()
        .find(|i| origin_of(i) == "https://a.example.com")
        .expect("A's broker");
    let port = a["listen"][1].as_u64().expect("port");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(&format!("url=http://127.0.0.1:{port}/v2\n")),
        "{stdout}"
    );

    // The dialog showed what the run named, nothing of what is stored.
    let asked = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    let shown = |label: &str| -> Vec<String> {
        asked
            .details
            .iter()
            .filter(|(k, _)| k == label)
            .map(|(_, v)| v.clone())
            .collect()
    };
    assert_eq!(
        shown("Approved origin"),
        [
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com:8443"
        ]
    );
    assert_eq!(shown("Base path"), ["/v2 (not a limit)"]);
    assert_eq!(shown("Requests"), ["no limit; at most 16 at a time"; 3]);
    for ends in shown("Ends") {
        assert!(
            ends.ends_with("after 12h; not on screen lock, suspend or idle lock"),
            "{ends}"
        );
    }
    for (label, value) in &asked.details {
        assert!(
            !value.contains("anthropic") && !value.contains("preset"),
            "{label}: {value}"
        );
    }

    // The run's record: the destinations it named.
    let approval = audit_records(&h)
        .into_iter()
        .find(|r| r["action"] == "run" && r["outcome"] == "allowed_once")
        .expect("the approval's record");
    let recorded: Vec<(String, Option<String>)> = approval["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .map(|g| {
            (
                g["destination"].as_str().expect("destination").to_string(),
                g["base_path"].as_str().map(str::to_string),
            )
        })
        .collect();
    assert_eq!(
        recorded,
        [
            ("https://a.example.com".to_string(), Some("/v2".to_string())),
            ("https://b.example.com".to_string(), None),
            ("https://c.example.com:8443".to_string(), None),
        ]
    );
    for install in &installs {
        let id = install["install"]["grant"].as_str().expect("grant");
        assert_eq!(ended_with(&h, id), "command_ended");
    }

    // Kept as it was, byte for byte, protection included, through the run
    // and through edits of its entry.
    assert_eq!(fields(), before);
    h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
    for edit in [
        ["edit", "STORED", "--username", "me"],
        ["edit", "HIDDEN", "--add-tag", "touched"],
    ] {
        let out = h.run(&edit);
        assert!(out.status.success(), "{edit:?}: {}", text(&out.stderr));
    }
    assert_eq!(fields(), before);
}

#[test]
fn read_only_requests_do_not_keep_the_vault_unlocked() {
    let h = Harness::with_idle_timeout(Duration::from_secs(2));
    h.add_secret("T", "abcdefgh", &[]);
    // Polls until the vault locks: 2 seconds of idle time plus the agent's
    // one-second check, with room for a slow, busy machine. If `list` kept
    // the vault unlocked, it would never lock.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        let _ = h.run(&["list"]);
        std::thread::sleep(Duration::from_millis(300));
        let status = h.run(&["status", "--json"]);
        let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("json");
        if status["locked"] == true {
            // The idle lock records itself just after it locks.
            eventually("the idle lock's record", || {
                audit_outcomes(&h, "lock")
                    .iter()
                    .any(|o| o == "idle_timeout")
                    .then_some(())
            });
            return;
        }
    }
    panic!("polling `list` kept the vault unlocked past the idle timeout");
}

/// Whether a process exists and is not a zombie. Uses `kill(pid, 0)` and the
/// raw bytes of `/proc/<pid>/stat`, independently of the agent's own
/// `/proc` parsing.
fn alive(pid: u32) -> bool {
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    if nix::sys::signal::kill(pid, None).is_err() {
        return false;
    }
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
            !matches!(stat.get(close + 2), Some(b'Z' | b'X'))
        }
        Err(_) => false,
    }
}

/// Whether any thread of the process is not a zombie.
fn threads_alive(pid: u32) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.flatten().any(|task| {
        std::fs::read(task.path().join("stat")).is_ok_and(|stat| {
            let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
            !matches!(stat.get(close + 2), Some(b'Z' | b'X'))
        })
    })
}

fn wait_for_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Ok(pid) = content.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "the command never started");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn kinds_are_set_listed_and_cleared_and_run_passes_the_endpoint() {
    let h = Harness::new();
    h.add_secret(
        "OPENAI_API_KEY",
        "sk-kind-test-123456",
        &[
            "--kind",
            "api-key",
            "--url",
            "https://api.example.invalid/v1",
        ],
    );
    h.add_secret(
        "lab-ssh",
        "pi-pass-123456",
        &["--kind", "server", "--host", "10.0.0.5"],
    );
    h.add_secret("plain", "plain-123456", &[]);

    let out = h.run(&["show", "OPENAI_API_KEY"]);
    assert!(
        text(&out.stdout).contains("kind:       api-key (API key)"),
        "{}",
        text(&out.stdout)
    );
    let out = h.run(&["list", "--kind", "api-key"]);
    let listed = text(&out.stdout);
    assert!(
        listed.contains("OPENAI_API_KEY") && !listed.contains("lab-ssh"),
        "{listed}"
    );
    let out = h.run(&["list", "--kind", "other", "--json"]);
    let listed = text(&out.stdout);
    assert!(
        listed.contains("\"plain\"") && !listed.contains("OPENAI_API_KEY"),
        "{listed}"
    );
    let out = h.run(&["list", "--json"]);
    assert!(text(&out.stdout).contains("\"kind\": \"server\""));

    // The URL goes in its own variable; it is not a secret, so it is neither
    // redacted nor a reason for another dialog.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&[
        "run",
        "OPENAI_API_KEY",
        "--url",
        "OPENAI_BASE_URL=OPENAI_API_KEY",
        "--",
        "sh",
        "-c",
        "echo \"base=$OPENAI_BASE_URL\"; echo len=${#OPENAI_API_KEY}",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("base=https://api.example.invalid/v1"),
        "{stdout}"
    );
    assert!(stdout.contains("len=19"), "{stdout}");
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);

    // Mistakes are refused before anything is asked or run.
    for (args, expected) in [
        (vec!["--url", "OPENAI_API_KEY"], "write VAR=ENTRY"),
        (
            vec!["--url", "LD_PRELOAD=OPENAI_API_KEY"],
            "cannot carry a URL",
        ),
        (
            vec!["--url", "OPENAI_API_KEY=OPENAI_API_KEY"],
            "already set by another binding",
        ),
        (vec!["--url", "HOST_URL=lab-ssh"], "lab-ssh has no URL"),
        // Checked before any entry is read (a read may ask to unlock).
        (
            vec!["--url", "A=no-such-entry", "--url", "A=OPENAI_API_KEY"],
            "already set by another binding",
        ),
    ] {
        let mut argv = vec!["run", "OPENAI_API_KEY"];
        argv.extend(args);
        argv.extend(["--", "true"]);
        let out = h.run(&argv);
        assert!(!out.status.success());
        assert!(
            text(&out.stderr).contains(expected),
            "{}",
            text(&out.stderr)
        );
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);

    // `--kind other` takes the kind away; the approval dialog says so.
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "lab-ssh", "--kind", "other"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        request
            .details
            .iter()
            .any(|(k, v)| k == "Clear" && v == "kind"),
        "{:?}",
        request.details
    );
    let out = h.run(&["show", "lab-ssh"]);
    assert!(
        !text(&out.stdout).contains("kind:"),
        "{}",
        text(&out.stdout)
    );
    h.decide(&[Decision::AllowOnce]);
    let out = h.run(&["edit", "lab-ssh", "--kind", "device"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        request
            .details
            .iter()
            .any(|(k, v)| k == "New kind" && v == "Device"),
        "{:?}",
        request.details
    );
}

#[test]
fn the_run_dialog_shows_destination_settings_without_credentials() {
    let h = Harness::new();
    // A dialog that scrolls, as rusthorse-dialog's does: this one shows the
    // test's own environment, directory and process chain, and with a
    // longer TMPDIR (41 characters) zenity's estimate of its height passed
    // the limit, which is tested elsewhere.
    h.ui.scrolls.store(true, Ordering::SeqCst);
    h.add_secret(
        "OPENAI_API_KEY",
        "sk-dest-test-123456",
        &[
            "--kind",
            "api-key",
            "--url",
            "https://api.example.invalid/v1",
        ],
    );
    let run = |decision: Decision, script: &str| {
        h.decide(&[decision]);
        h.cmd(&[
            "run",
            "OPENAI_API_KEY",
            "--url",
            "OPENAI_BASE_URL=OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            script,
        ])
        .env("https_proxy", "http://u:FAKE-proxy-pw@proxy.invalid:3128")
        .env("SSL_CERT_FILE", "/tmp/fake-ca.pem")
        // Node reads `\` as `/` and would connect to 127.0.0.1, while the
        // text after the `@` names another host: never shown.
        .env(
            "ANTHROPIC_BASE_URL",
            "http://127.0.0.1:9\\@provider.invalid/FAKE-path-token",
        )
        .finish()
    };

    // Denied: nothing runs, and the dialog said where it would connect.
    let marker = h.dir.path().join("ran");
    let out = run(
        Decision::Deny,
        &format!("touch {}", marker.to_str().expect("utf8")),
    );
    assert_eq!(out.status.code(), Some(125));
    assert!(!marker.exists());
    let request = h.ui.last_approval.lock().unwrap().clone().expect("asked");
    assert!(
        request
            .details
            .iter()
            .any(|(k, v)| k == "Destinations (environment)"
                && v.contains("ANTHROPIC_BASE_URL=(not shown)")
                && v.contains("OPENAI_BASE_URL=https://api.example.invalid/…")),
        "{:?}",
        request.details
    );
    let warning = request
        .warnings
        .iter()
        .find(|w| w.contains("route the program's connections"))
        .expect("a warning about routes");
    // (Variables of the test's own environment may be listed too.)
    for part in [
        "SSL_CERT_FILE=/tmp/fake-ca.pem",
        "https_proxy=http://…@proxy.invalid:3128",
    ] {
        assert!(warning.contains(part), "{warning}");
    }
    assert!(
        request
            .warnings
            .iter()
            .any(|w| w.contains("so they are not shown") && w.contains("ANTHROPIC_BASE_URL")),
        "{:?}",
        request.warnings
    );
    let shown = format!("{:?}", request);
    assert!(!shown.contains("FAKE"), "{shown}");

    // Allowed: the command gets the variables unchanged.
    let out = run(
        Decision::AllowOnce,
        "echo \"$https_proxy|$OPENAI_BASE_URL|$SSL_CERT_FILE\"",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains(
        "http://u:FAKE-proxy-pw@proxy.invalid:3128|https://api.example.invalid/v1|/tmp/fake-ca.pem"
    ));

    // Both attempts are audited with the same shortened values.
    let audit = h.audit_text();
    let runs: Vec<&str> = audit
        .lines()
        .filter(|l| l.contains(r#""action":"run""#) && !l.contains(r#""outcome":"exited""#))
        .collect();
    assert_eq!(runs.len(), 2, "{audit}");
    for record in runs {
        for part in [
            "destinations: ",
            "ANTHROPIC_BASE_URL=(not shown)",
            "OPENAI_BASE_URL=https://api.example.invalid/…",
            "; routes: ",
            "SSL_CERT_FILE=/tmp/fake-ca.pem",
            "https_proxy=http://…@proxy.invalid:3128",
        ] {
            assert!(record.contains(part), "{record}");
        }
    }
    assert!(!audit.contains("FAKE"), "{audit}");
}

/// Private D-Bus buses and a fake logind and screensaver, to see the agent
/// lock on their signals (ADR 0009). Never the real buses.
#[cfg(feature = "session-lock")]
mod session_lock {
    use super::*;
    use std::io::BufRead;
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::atomic::AtomicU64;

    use rusthorse::session_lock::{Locker, Settings, Triggers};
    use zbus::blocking::{Connection, connection};
    use zbus::zvariant::{OwnedObjectPath, Value};

    const LOGIND: &str = "org.freedesktop.login1";
    const MANAGER_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";
    const SESSION: &str = "org.freedesktop.login1.Session";
    const OURS: &str = "/org/freedesktop/login1/session/_31";
    const OTHERS: &str = "/org/freedesktop/login1/session/_32";
    /// Another user's session, asked about only in the burst below, so that
    /// its first question is still pending while signals pile up.
    const THIRD: &str = "/org/freedesktop/login1/session/_33";

    /// A `dbus-daemon` with a configuration of its own: anyone may own any
    /// name, nothing is activated, it listens in a private directory. (Its
    /// policy must allow receiving too, or replies never arrive.)
    pub(super) struct Bus {
        daemon: Option<std::process::Child>,
        pub(super) address: String,
        dir: tempfile::TempDir,
    }

    impl Bus {
        pub(super) fn available() -> bool {
            let there = Path::new("/usr/bin/dbus-daemon").exists();
            if !there {
                eprintln!("skipped: dbus-daemon is not installed");
            }
            there
        }

        /// A bus at a fixed address, not started yet.
        fn new() -> Bus {
            let dir = tempfile::tempdir().unwrap();
            let address = format!("unix:path={}/bus", dir.path().display());
            Bus {
                daemon: None,
                address,
                dir,
            }
        }

        pub(super) fn started() -> Bus {
            let mut bus = Bus::new();
            bus.start();
            bus
        }

        fn start(&mut self) {
            let config = self.dir.path().join("bus.conf");
            std::fs::write(
                &config,
                format!(
                    "<busconfig><type>session</type><auth>EXTERNAL</auth>\
                     <listen>{}</listen><policy context=\"default\">\
                     <allow send_destination=\"*\" eavesdrop=\"true\"/>\
                     <allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>",
                    self.address
                ),
            )
            .unwrap();
            let mut daemon = Command::new("/usr/bin/dbus-daemon")
                .arg(format!("--config-file={}", config.display()))
                .args(["--nofork", "--print-address=1"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            // It prints its address once it listens.
            let mut line = String::new();
            std::io::BufReader::new(daemon.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.starts_with(&self.address), "{line}");
            self.daemon = Some(daemon);
        }

        fn stop(&mut self) {
            if let Some(mut daemon) = self.daemon.take() {
                let _ = daemon.kill();
                let _ = daemon.wait();
            }
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// logind's manager: every inhibitor handed out is a pipe whose read
    /// end stays here, to see when it is let go; `delay` slows `Inhibit`.
    struct FakeManager {
        inhibitors: Arc<Mutex<Vec<OwnedFd>>>,
        delay: Arc<AtomicU64>,
        uid: u32,
    }

    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl FakeManager {
        fn inhibit(
            &self,
            what: &str,
            _who: &str,
            _why: &str,
            mode: &str,
        ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
            assert_eq!((what, mode), ("sleep", "delay"));
            std::thread::sleep(Duration::from_millis(self.delay.load(Ordering::SeqCst)));
            let (read, write) =
                nix::unistd::pipe().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            self.inhibitors.lock().unwrap().push(read);
            Ok(write.into())
        }

        fn list_sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
            vec![(
                "31".into(),
                self.uid,
                "me".into(),
                "seat0".into(),
                OwnedObjectPath::try_from(OURS).unwrap(),
            )]
        }
    }

    /// A logind session of user `uid`; `slow` delays its answers (who its
    /// user is, whether it is locked), in milliseconds.
    struct FakeSession {
        uid: u32,
        locked: bool,
        slow: u64,
    }

    #[zbus::interface(name = "org.freedesktop.login1.Session")]
    impl FakeSession {
        #[zbus(property)]
        fn user(&self) -> (u32, OwnedObjectPath) {
            std::thread::sleep(Duration::from_millis(self.slow));
            (
                self.uid,
                OwnedObjectPath::try_from("/org/freedesktop/login1/user/_0").unwrap(),
            )
        }

        #[zbus(property)]
        fn locked_hint(&self) -> bool {
            std::thread::sleep(Duration::from_millis(self.slow));
            self.locked
        }
    }

    /// Cinnamon's screensaver, as far as the agent asks it: `slow` delays
    /// the answer to `GetActive` (milliseconds); `refuse` answers that it
    /// cannot tell, as `csd-screensaver` does.
    #[derive(Default)]
    struct FakeScreenSaver {
        active: bool,
        slow: u64,
        refuse: bool,
    }

    #[zbus::interface(name = "org.cinnamon.ScreenSaver")]
    impl FakeScreenSaver {
        fn get_active(&self) -> zbus::fdo::Result<bool> {
            std::thread::sleep(Duration::from_millis(self.slow));
            if self.refuse {
                return Err(zbus::fdo::Error::NotSupported(
                    "This method is not implemented".into(),
                ));
            }
            Ok(self.active)
        }
    }

    /// The fake logind on `bus`.
    fn logind(
        bus: &Bus,
        inhibitors: &Arc<Mutex<Vec<OwnedFd>>>,
        delay: &Arc<AtomicU64>,
    ) -> Connection {
        let uid = nix::unistd::getuid().as_raw();
        connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name(LOGIND)
            .unwrap()
            .serve_at(
                MANAGER_PATH,
                FakeManager {
                    inhibitors: Arc::clone(inhibitors),
                    delay: Arc::clone(delay),
                    uid,
                },
            )
            .unwrap()
            .serve_at(
                OURS,
                FakeSession {
                    uid,
                    locked: false,
                    slow: 0,
                },
            )
            .unwrap()
            .serve_at(
                OTHERS,
                FakeSession {
                    uid: uid + 1,
                    locked: false,
                    slow: 0,
                },
            )
            .unwrap()
            // Slow to say whose it is, so that signals pile up meanwhile.
            .serve_at(
                THIRD,
                FakeSession {
                    uid: uid + 2,
                    locked: false,
                    slow: 500,
                },
            )
            .unwrap()
            .build()
            .unwrap()
    }

    fn screensaver(bus: &Bus, active: bool) -> Connection {
        screensaver_like(
            bus,
            FakeScreenSaver {
                active,
                ..FakeScreenSaver::default()
            },
        )
    }

    fn screensaver_like(bus: &Bus, fake: FakeScreenSaver) -> Connection {
        connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.cinnamon.ScreenSaver")
            .unwrap()
            .serve_at("/org/cinnamon/ScreenSaver", fake)
            .unwrap()
            .build()
            .unwrap()
    }

    fn emit(
        conn: &Connection,
        path: &str,
        interface: &str,
        member: &str,
        body: &(impl serde::Serialize + zbus::zvariant::DynamicType),
    ) {
        conn.emit_signal(
            None::<zbus::names::BusName<'_>>,
            path,
            interface,
            member,
            body,
        )
        .unwrap();
    }

    /// Whether the other end of a pipe has been closed everywhere.
    fn released(fd: &OwnedFd) -> bool {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        poll(&mut fds, PollTimeout::ZERO).unwrap() == 1
            && fds[0]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLHUP))
    }

    fn wait_for(what: &str, check: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(15);
        while !check() {
            assert!(Instant::now() < until, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn status(h: &Harness) -> serde_json::Value {
        serde_json::from_slice(&h.run(&["status", "--json"]).stdout).unwrap()
    }

    fn locked(h: &Harness) -> bool {
        status(h)["locked"] == true
    }

    fn trigger(h: &Harness, event: &str, source: &str) -> Option<serde_json::Value> {
        status(h)["lock_triggers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["event"] == event && t["source"] == source)
            .cloned()
    }

    fn unlock(h: &Harness) {
        assert!(h.run(&["unlock"]).status.success());
        assert!(!locked(h));
    }

    fn lock_records(h: &Harness, outcome: &str) -> usize {
        h.audit_text()
            .lines()
            .filter(|l| {
                l.contains(r#""action":"lock""#) && l.contains(&format!(r#""outcome":"{outcome}""#))
            })
            .count()
    }

    /// The audit record is written after the vault is locked: wait for it.
    fn wait_for_records(h: &Harness, outcome: &str, count: usize) {
        wait_for(&format!("{count} {outcome} record(s)"), || {
            lock_records(h, outcome) == count
        });
    }

    fn settings(system: &Bus, session: &Bus) -> Settings {
        Settings {
            on_suspend: true,
            on_screen_lock: true,
            system_bus: Some(system.address.clone()),
            session_bus: Some(session.address.clone()),
            refresh_every: Some(Duration::from_millis(300)),
        }
    }

    #[test]
    fn the_vault_locks_on_suspend_and_screen_lock_never_unlocks() {
        if !Bus::available() {
            return;
        }
        let (system, mut session) = (Bus::started(), Bus::started());
        let inhibitors = Arc::new(Mutex::new(Vec::new()));
        let delay = Arc::new(AtomicU64::new(0));
        let logind = logind(&system, &inhibitors, &delay);
        let screensaver = screensaver(&session, false);
        let h = Harness::with_session_lock(settings(&system, &session));

        // Every watcher reports itself, and logind was asked to wait.
        wait_for("the watchers", || {
            [
                ("suspend", "logind"),
                ("screen_lock", "logind"),
                ("screen_lock", "org.cinnamon.ScreenSaver"),
            ]
            .iter()
            .all(|(e, s)| trigger(&h, e, s).is_some_and(|t| t["active"] == true))
        });
        assert_eq!(
            trigger(&h, "suspend", "logind").unwrap()["note"],
            "locks before the computer sleeps"
        );
        assert_eq!(inhibitors.lock().unwrap().len(), 1);
        let shown = text(&h.run(&["status"]).stdout);
        assert!(
            shown.contains("locks on:   suspend: logind (locks before the computer sleeps)"),
            "{shown}"
        );
        assert!(shown.contains("org.cinnamon.ScreenSaver"), "{shown}");

        // A `PrepareForSleep` sent to the agent alone by another program,
        // and a malformed one from logind itself, change nothing: no lock,
        // the inhibitor kept, the watcher still there (no new `Inhibit`).
        unlock(&h);
        let forger = connection::Builder::address(system.address.as_str())
            .unwrap()
            .build()
            .unwrap();
        let names: Vec<String> = forger
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "ListNames",
                &(),
            )
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        let mine = [
            forger.unique_name().unwrap().to_string(),
            logind.unique_name().unwrap().to_string(),
        ];
        for name in names
            .iter()
            .filter(|n| n.starts_with(':') && !mine.contains(n))
        {
            forger
                .emit_signal(
                    Some(name.as_str()),
                    MANAGER_PATH,
                    MANAGER,
                    "PrepareForSleep",
                    &(true,),
                )
                .unwrap();
        }
        emit(&forger, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &());
        std::thread::sleep(Duration::from_millis(500));
        assert!(!locked(&h), "a forged or malformed signal locked");
        assert!(!released(&inhibitors.lock().unwrap()[0]));
        assert_eq!(inhibitors.lock().unwrap().len(), 1);

        // Suspend: locked, then the inhibitor is let go so that the
        // computer can sleep; after the resume, logind is asked again.
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the suspend lock", || locked(&h));
        wait_for("the inhibitor's release", || {
            released(&inhibitors.lock().unwrap()[0])
        });
        wait_for_records(&h, "suspend", 1);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        wait_for("a new inhibitor", || inhibitors.lock().unwrap().len() == 2);
        assert!(locked(&h), "a resume never unlocks");

        // logind answers `Inhibit` after 3 s, past the agent's 2-second
        // limit: the next suspend still locks at once, and `status` says the
        // suspend lock is degraded until an inhibitor is had again.
        unlock(&h);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the second suspend lock", || locked(&h));
        delay.store(3000, Ordering::SeqCst);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        unlock(&h);
        let started = Instant::now();
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the suspend lock with a slow inhibitor", || locked(&h));
        assert!(started.elapsed() < Duration::from_millis(1500));
        wait_for("the degraded suspend lock", || {
            trigger(&h, "suspend", "logind").is_some_and(|t| t["degraded"] == true)
        });
        assert!(
            text(&h.run(&["status"]).stdout).contains("logind would not wait"),
            "the reason is shown"
        );
        wait_for("the timed-out inhibitor's reply", || {
            inhibitors.lock().unwrap().len() == 3
        });
        delay.store(0, Ordering::SeqCst);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        wait_for("an inhibitor after the resume", || {
            inhibitors.lock().unwrap().len() == 4
        });
        wait_for("the suspend lock sound again", || {
            trigger(&h, "suspend", "logind").is_some_and(|t| t.get("degraded").is_none())
        });

        // logind answers within the limit, but only once the computer is
        // going to sleep: that inhibitor is let go at once, so the sleep is
        // not held up by it.
        unlock(&h);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the third suspend lock", || locked(&h));
        delay.store(1200, Ordering::SeqCst);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the late inhibitor", || {
            inhibitors.lock().unwrap().len() == 5
        });
        wait_for("its release", || released(&inhibitors.lock().unwrap()[4]));
        delay.store(0, Ordering::SeqCst);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        wait_for("an inhibitor after that resume", || {
            inhibitors.lock().unwrap().len() == 6
        });

        // Our session's `Lock` locks; another user's does not, even many.
        unlock(&h);
        emit(&logind, OTHERS, SESSION, "Lock", &());
        emit(&logind, OURS, SESSION, "Lock", &());
        wait_for("the session lock", || locked(&h));
        wait_for_records(&h, "screen_locked", 1);
        unlock(&h);
        for _ in 0..200 {
            emit(&logind, THIRD, SESSION, "Lock", &());
        }
        std::thread::sleep(Duration::from_millis(500));
        assert!(!locked(&h), "another user's session lock locked this vault");
        emit(&logind, OURS, SESSION, "Lock", &());
        wait_for("the session lock after many others", || locked(&h));
        wait_for_records(&h, "screen_locked", 2);

        // `LockedHint` turning true locks; turning false does not unlock.
        let hint = |on: bool| {
            let changed: std::collections::HashMap<&str, Value<'_>> =
                [("LockedHint", Value::from(on))].into();
            emit(
                &logind,
                OURS,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(SESSION, changed, Vec::<&str>::new()),
            );
        };
        unlock(&h);
        hint(true);
        wait_for("the locked hint", || locked(&h));
        hint(false);

        // The screensaver starting locks; repeated signals record once.
        unlock(&h);
        for _ in 0..3 {
            emit(
                &screensaver,
                "/org/cinnamon/ScreenSaver",
                "org.cinnamon.ScreenSaver",
                "ActiveChanged",
                &(true,),
            );
        }
        wait_for("the screensaver lock", || locked(&h));
        wait_for_records(&h, "screen_locked", 4);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(lock_records(&h, "screen_locked"), 4);
        assert!(h.audit_text().contains("org.cinnamon.ScreenSaver"));
        emit(
            &screensaver,
            "/org/cinnamon/ScreenSaver",
            "org.cinnamon.ScreenSaver",
            "ActiveChanged",
            &(false,),
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(locked(&h), "a screensaver stopping never unlocks");

        // The session bus goes away: the screensaver watcher says so.
        session.stop();
        wait_for("the lost bus to show", || {
            trigger(&h, "screen_lock", "screensaver").is_some_and(|t| {
                t["active"] == false
                    && t["note"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("trying again")
            }) && trigger(&h, "screen_lock", "org.cinnamon.ScreenSaver").is_none()
        });
        // logind still watches the session.
        assert_eq!(
            trigger(&h, "screen_lock", "logind").unwrap()["active"],
            true
        );
    }

    /// The session bus is not there when the agent starts; the vault is
    /// unlocked meanwhile; then the bus comes, with `fake` on it. Whether
    /// the vault ends up locked.
    fn after_the_session_bus_comes(fake: FakeScreenSaver) -> bool {
        let system = Bus::started();
        let mut session = Bus::new();
        let h = Harness::with_session_lock(Settings {
            on_suspend: false,
            ..settings(&system, &session)
        });
        wait_for("the missing bus to show", || {
            trigger(&h, "screen_lock", "screensaver").is_some_and(|t| {
                t["note"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("trying again")
            })
        });
        unlock(&h);
        session.start();
        let _screensaver = screensaver_like(&session, fake);
        wait_for("the screensaver to be seen", || {
            trigger(&h, "screen_lock", "org.cinnamon.ScreenSaver").is_some()
        });
        // Its `GetActive` is asked right after; give a slow one its time.
        std::thread::sleep(Duration::from_millis(2500));
        let locked = locked(&h);
        if locked {
            wait_for_records(&h, "screen_locked", 1);
        }
        locked
    }

    #[test]
    fn a_screensaver_already_on_when_the_bus_comes_back_locks() {
        if !Bus::available() {
            return;
        }
        assert!(after_the_session_bus_comes(FakeScreenSaver {
            active: true,
            ..FakeScreenSaver::default()
        }));
    }

    #[test]
    fn a_screensaver_that_does_not_answer_in_time_counts_as_on() {
        if !Bus::available() {
            return;
        }
        // It would say "on" after 3 s, past the 2-second limit.
        assert!(after_the_session_bus_comes(FakeScreenSaver {
            active: true,
            slow: 3000,
            refuse: false,
        }));
    }

    #[test]
    fn a_screensaver_that_cannot_tell_does_not_lock() {
        if !Bus::available() {
            return;
        }
        assert!(!after_the_session_bus_comes(FakeScreenSaver {
            refuse: true,
            ..FakeScreenSaver::default()
        }));
        assert!(!after_the_session_bus_comes(FakeScreenSaver::default()));
    }

    #[test]
    fn a_screensaver_that_comes_later_already_on_locks() {
        if !Bus::available() {
            return;
        }
        let (system, session) = (Bus::started(), Bus::started());
        let h = Harness::with_session_lock(Settings {
            on_suspend: false,
            ..settings(&system, &session)
        });
        wait_for("no screensaver to show", || {
            trigger(&h, "screen_lock", "screensaver").is_some_and(|t| t["active"] == false)
        });
        unlock(&h);
        // It comes on the bus already on, and sends no signal.
        let _screensaver = screensaver(&session, true);
        wait_for("the lock when it is seen", || locked(&h));
        wait_for_records(&h, "screen_locked", 1);
    }

    #[test]
    fn logind_leaving_or_restarting_is_noticed() {
        if !Bus::available() {
            return;
        }
        let (system, session) = (Bus::started(), Bus::started());
        let inhibitors = Arc::new(Mutex::new(Vec::new()));
        let delay = Arc::new(AtomicU64::new(0));
        let first = logind(&system, &inhibitors, &delay);
        let h = Harness::with_session_lock(Settings {
            on_screen_lock: false,
            ..settings(&system, &session)
        });
        wait_for("the suspend watcher", || {
            trigger(&h, "suspend", "logind").is_some_and(|t| t["active"] == true)
        });
        // logind goes: the suspend lock is no longer promised. The
        // inhibitor is kept — systemd keeps inhibitors when logind restarts,
        // and only a lock lets it go.
        first.close().unwrap();
        wait_for("logind's absence to show", || {
            trigger(&h, "suspend", "logind").is_some_and(|t| {
                t["active"] == false
                    && t["note"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("not on the system bus")
            })
        });
        assert!(!released(&inhibitors.lock().unwrap()[0]));
        // It comes back (a new unique name): watched again, with the same
        // inhibitor.
        let second = logind(&system, &inhibitors, &delay);
        wait_for("the suspend lock watched again", || {
            trigger(&h, "suspend", "logind").is_some_and(|t| t["active"] == true)
        });
        assert_eq!(inhibitors.lock().unwrap().len(), 1);
        assert!(!released(&inhibitors.lock().unwrap()[0]));
        // And the new logind's signal is the one that counts.
        unlock(&h);
        emit(&second, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the suspend lock from the new logind", || locked(&h));
        wait_for("the inhibitor's release", || {
            released(&inhibitors.lock().unwrap()[0])
        });
    }

    /// The system bus is not there when the agent starts; the vault is
    /// unlocked meanwhile; then the bus comes, with logind and its session of
    /// this user `ours` — or without logind. Whether the vault ends up locked.
    fn after_logind_comes(ours: Option<FakeSession>) -> bool {
        let mut system = Bus::new();
        let session = Bus::started();
        let h = Harness::with_session_lock(Settings {
            on_suspend: false,
            ..settings(&system, &session)
        });
        wait_for("the missing bus to show", || {
            trigger(&h, "screen_lock", "logind").is_some_and(|t| {
                t["note"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("trying again")
            })
        });
        unlock(&h);
        system.start();
        let uid = nix::unistd::getuid().as_raw();
        let present = ours.is_some();
        let _logind = ours.map(|ours| {
            connection::Builder::address(system.address.as_str())
                .unwrap()
                .name(LOGIND)
                .unwrap()
                .serve_at(
                    MANAGER_PATH,
                    FakeManager {
                        inhibitors: Arc::default(),
                        delay: Arc::default(),
                        uid,
                    },
                )
                .unwrap()
                .serve_at(OURS, ours)
                .unwrap()
                .build()
                .unwrap()
        });
        wait_for("the bus to be seen", || {
            trigger(&h, "screen_lock", "logind").is_some_and(|t| {
                if present {
                    t["active"] == true
                } else {
                    t["note"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("not on the system bus")
                }
            })
        });
        // `LockedHint` is asked right after; give a slow answer its time.
        std::thread::sleep(Duration::from_millis(2500));
        let locked = locked(&h);
        if locked {
            wait_for_records(&h, "screen_locked", 1);
        }
        locked
    }

    #[test]
    fn a_session_already_locked_when_logind_comes_back_locks() {
        if !Bus::available() {
            return;
        }
        let uid = nix::unistd::getuid().as_raw();
        assert!(after_logind_comes(Some(FakeSession {
            uid,
            locked: true,
            slow: 0
        })));
        // Not answering in time counts as locked: the safe side.
        assert!(after_logind_comes(Some(FakeSession {
            uid,
            locked: false,
            slow: 3000
        })));
        assert!(!after_logind_comes(Some(FakeSession {
            uid,
            locked: false,
            slow: 0
        })));
        // No logind at all: nothing to recover, nothing locked.
        assert!(!after_logind_comes(None));
    }

    #[test]
    fn missing_services_are_reported_inactive() {
        if !Bus::available() {
            return;
        }
        let (system, session) = (Bus::started(), Bus::started());
        let h = Harness::with_session_lock(settings(&system, &session));
        wait_for("the absences to show", || {
            [
                ("suspend", "logind", "logind is not on the system bus"),
                ("screen_lock", "logind", "logind is not on the system bus"),
                (
                    "screen_lock",
                    "screensaver",
                    "no screensaver on the session bus",
                ),
            ]
            .iter()
            .all(|(e, s, why)| {
                trigger(&h, e, s).is_some_and(|t| {
                    t["active"] == false && t["note"].as_str().unwrap_or_default().contains(why)
                })
            })
        });
        let shown = text(&h.run(&["status"]).stdout);
        assert!(
            shown.contains("suspend: not watched — logind is not on the system bus"),
            "{shown}"
        );
    }

    /// Counts the locks it is asked for.
    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Locker for Counter {
        fn lock_for(&self, _: &str, _: &str) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn stopping_the_watchers_lets_go_of_the_inhibitor() {
        if !Bus::available() {
            return;
        }
        let (system, session) = (Bus::started(), Bus::started());
        let inhibitors = Arc::new(Mutex::new(Vec::new()));
        let _logind = logind(&system, &inhibitors, &Arc::new(AtomicU64::new(0)));
        let counter = Arc::new(Counter::default());
        let triggers = Arc::new(Triggers::default());
        let watchers = rusthorse::session_lock::start(
            Arc::downgrade(&counter),
            settings(&system, &session),
            Arc::clone(&triggers),
        );
        wait_for("the inhibitor", || inhibitors.lock().unwrap().len() == 1);
        let started = Instant::now();
        drop(watchers);
        // Stopping waits at most three seconds for the threads, and leaves
        // one still connecting to a bus to end on its own; under load a
        // thread can take that long. More than that, with a margin, would
        // be a stop that hangs.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stopping took too long"
        );
        wait_for("its release", || released(&inhibitors.lock().unwrap()[0]));
        drop(counter);
    }

    /// Holds every lock until opened, like a vault save holding the
    /// agent's state lock.
    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        opened: std::sync::Condvar,
        locks: AtomicUsize,
    }

    impl Gate {
        fn set(&self, open: bool) {
            *self.open.lock().unwrap() = open;
            self.opened.notify_all();
        }
    }

    impl Locker for Gate {
        fn lock_for(&self, _: &str, _: &str) {
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
            self.locks.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn an_inhibitor_that_arrives_while_locking_is_kept_until_locked() {
        if !Bus::available() {
            return;
        }
        let (system, session) = (Bus::started(), Bus::started());
        let inhibitors = Arc::new(Mutex::new(Vec::new()));
        let delay = Arc::new(AtomicU64::new(0));
        let logind = logind(&system, &inhibitors, &delay);
        let gate = Arc::new(Gate::default());
        gate.set(true);
        let _watchers = rusthorse::session_lock::start(
            Arc::downgrade(&gate),
            Settings {
                on_screen_lock: false,
                ..settings(&system, &session)
            },
            Arc::new(Triggers::default()),
        );
        wait_for("the inhibitor", || inhibitors.lock().unwrap().len() == 1);
        // One full suspend and resume; the next inhibitor comes slowly.
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the first lock", || gate.locks.load(Ordering::SeqCst) == 1);
        delay.store(1200, Ordering::SeqCst);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(false,));
        // The next suspend's lock is held up; the inhibitor arrives
        // meanwhile and must be kept until the lock is done.
        gate.set(false);
        emit(&logind, MANAGER_PATH, MANAGER, "PrepareForSleep", &(true,));
        wait_for("the slow inhibitor", || {
            inhibitors.lock().unwrap().len() == 2
        });
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !released(&inhibitors.lock().unwrap()[1]),
            "let go before the vault was locked"
        );
        // Nor when logind's name changes hands meanwhile (a restart).
        logind.close().unwrap();
        let _again = self::logind(&system, &inhibitors, &delay);
        std::thread::sleep(Duration::from_millis(1000));
        assert!(
            !released(&inhibitors.lock().unwrap()[1]),
            "let go on logind's restart, before the vault was locked"
        );
        gate.set(true);
        wait_for("its release once locked", || {
            released(&inhibitors.lock().unwrap()[1])
        });
        assert_eq!(gate.locks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stopping_does_not_wait_for_a_bus_that_never_answers() {
        // A socket that accepts connections and never says a word: the
        // watchers hang in authentication.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mute");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let accepted = Arc::new(Mutex::new(Vec::new()));
        {
            let accepted = Arc::clone(&accepted);
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    accepted.lock().unwrap().push(stream);
                }
            });
        }
        let address = format!("unix:path={}", path.display());
        let counter = Arc::new(Counter::default());
        let watchers = rusthorse::session_lock::start(
            Arc::downgrade(&counter),
            Settings {
                on_suspend: true,
                on_screen_lock: true,
                system_bus: Some(address.clone()),
                session_bus: Some(address),
                refresh_every: None,
            },
            Arc::new(Triggers::default()),
        );
        wait_for("the connections", || accepted.lock().unwrap().len() >= 3);
        let started = Instant::now();
        drop(watchers);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stopping waited for a mute bus"
        );
        // Let the threads left behind fail and end.
        accepted.lock().unwrap().clear();
    }

    #[test]
    fn turned_off_watchers_say_so() {
        let h = Harness::with_session_lock(Settings::default());
        for (event, source) in [("suspend", "logind"), ("screen_lock", "logind")] {
            let t = trigger(&h, event, source).unwrap();
            assert_eq!(
                (t["active"].clone(), t["note"].clone()),
                (false.into(), "turned off".into())
            );
        }
        let shown = text(&h.run(&["status"]).stdout);
        assert!(
            shown.contains("suspend: not watched — turned off"),
            "{shown}"
        );
    }
}

/// Imports that the agent reads itself (ADR 0012).
mod import_from {
    use super::*;
    use rusthorse::protocol::{ErrorCode, ImportSource, Request, Response};

    /// The value of `name` in the vault file (the harness's password).
    fn value_in_file(h: &Harness, name: &str) -> String {
        let vault = Vault::open(&h.vault_path(), SecretString::new(PASSWORD.to_string()))
            .expect("open the vault file");
        let id = vault.find(name).expect("the entry");
        vault.secret(id).expect("a value").to_string()
    }

    fn last_approval(h: &Harness) -> String {
        let request =
            h.ui.last_approval
                .lock()
                .unwrap()
                .clone()
                .expect("a dialog");
        rusthorse::ui::approval_text(&request)
    }

    #[test]
    fn a_dotenv_file_is_read_by_the_agent_after_two_approvals() {
        let h = Harness::new();
        let file = h.dir.path().join("app.env");
        std::fs::write(
            &file,
            "# fake values\nFAKE_ONE=fake-one-value\nexport FAKE_TWO=\"fake two\"\n",
        )
        .unwrap();
        assert!(h.run(&["unlock"]).status.success());
        h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
        let out = h.run(&[
            "import", "dotenv", "app.env", "--prefix", "p_", "--tag", "migrated",
        ]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
        // The second dialog says where the agent read the values.
        let dialog = last_approval(&h);
        assert!(dialog.contains("from a .env file"), "{dialog}");
        assert!(dialog.contains(&file.display().to_string()), "{dialog}");
        assert!(dialog.contains("P_FAKE_ONE, P_FAKE_TWO"), "{dialog}");
        assert!(!dialog.contains("fake-one-value"), "{dialog}");
        assert_eq!(value_in_file(&h, "P_FAKE_ONE"), "fake-one-value");
        assert_eq!(value_in_file(&h, "P_FAKE_TWO"), "fake two");
        let audit = h.audit_text();
        assert!(audit.contains("\"action\":\"dotenv_names\""), "{audit}");
        assert!(audit.contains("\"action\":\"import_from\""), "{audit}");
        assert!(!audit.contains("fake-one-value"));
    }

    #[test]
    fn the_names_of_a_file_never_include_pieces_of_a_value() {
        let h = Harness::new();
        let file = h.dir.path().join("key.env");
        let names = |h: &Harness, text: &str| {
            std::fs::write(&file, text).unwrap();
            h.decide(&[Decision::AllowOnce]);
            h.call(&Request::DotenvNames {
                path: file.display().to_string(),
            })
        };
        // Files the readers do not all read alike are refused, naming the
        // line and nothing of it: a value over several lines, Node's
        // `NAME: value` with `=` in its value, a backslash before a quote.
        for (text, line) in [
            (
                "PRIVATE_KEY=\"-----BEGIN-----\nFAKE_PRIVATE_KEY_MATERIAL==\n-----END-----\"\nNORMAL=x\n",
                "line 1:",
            ),
            (
                "KEY: \"start=value\nFAKE_PRIVATE_MATERIAL==\nend=tail\"\nNORMAL=x\n",
                "line 1:",
            ),
            ("OK=1\nKEY=\"FAKE\\\\\"\n# note \"\nNORMAL=x\n", "line 2:"),
            // A byte-order mark before the quote, a lone carriage return
            // (a line break for the libraries) in a comment, and a line in
            // a form Rusthorse does not read, which is never skipped.
            (
                "KEY=\u{FEFF}\"start\nFAKE_PRIVATE_MATERIAL==\nend=tail\"\nNORMAL=x\n",
                "line 1:",
            ),
            (
                "# comment\rKEY=\"start\nFAKE_PRIVATE_MATERIAL==\nend=tail\"\nNORMAL=x\n",
                "line 1:",
            ),
            ("NAME: FAKE\nX=ok\n", "line 1:"),
        ] {
            match names(&h, text) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
                    assert!(message.contains(line), "{message}");
                    assert!(!message.contains("FAKE"), "{message}");
                }
                other => panic!("{text:?}: unexpected {}", other.kind()),
            }
        }
        // The common dialect.
        let Response::Names { names: found, .. } = names(&h, "A='x'\nexport B=\"y\" # c\nC=z\n")
        else {
            panic!("no names");
        };
        assert_eq!(found, ["A", "B", "C"]);
    }

    #[test]
    fn variables_without_a_value_are_named_not_skipped() {
        let h = Harness::new();
        std::fs::write(h.dir.path().join("app.env"), "EMPTY_ONE=\nFAKE_ONE=fake\n").unwrap();
        assert!(h.run(&["unlock"]).status.success());
        h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
        let out = h.run(&["import", "dotenv", "app.env"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("not imported, because they have no value: EMPTY_ONE"),
            "{}",
            text(&out.stderr)
        );
        let list = text(&h.run(&["list"]).stdout);
        assert!(
            list.contains("FAKE_ONE") && !list.contains("EMPTY_ONE"),
            "{list}"
        );
        // Asked for by name, it is refused once allowed.
        h.decide(&[Decision::AllowOnce]);
        match h.call(&Request::ImportFrom {
            source: ImportSource::Dotenv {
                path: h.dir.path().join("app.env").display().to_string(),
                prefix: None,
                names: vec!["EMPTY_ONE".into()],
            },
            tags: Vec::new(),
            replace: false,
        }) {
            Response::Error { message, .. } => {
                assert!(message.contains("has no value"), "{message}")
            }
            other => panic!("unexpected {}", other.kind()),
        }
    }

    #[test]
    fn a_dry_run_shows_the_names_and_imports_nothing() {
        let h = Harness::new();
        std::fs::write(h.dir.path().join("app.env"), "FAKE_ONE=fake\n").unwrap();
        h.decide(&[Decision::AllowOnce]);
        let out = h.run(&["import", "dotenv", "app.env", "--dry-run"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("FAKE_ONE"));
        assert!(!text(&out.stdout).contains("fake\n"));
        assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 1);
        assert!(!h.audit_text().contains("import_from"));
    }

    #[test]
    fn denied_listings_show_nothing() {
        let h = Harness::new();
        std::fs::write(h.dir.path().join("app.env"), "FAKE_ONE=fake\n").unwrap();
        h.decide(&[Decision::Deny]);
        let out = h.run(&["import", "dotenv", "app.env", "--dry-run"]);
        assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
        assert!(!text(&out.stdout).contains("FAKE_ONE"));
        h.decide(&[Decision::Deny]);
        match h.call(&Request::KeyringItems) {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
            other => panic!("unexpected {}", other.kind()),
        }
    }

    #[test]
    fn the_agent_reads_only_regular_files_by_absolute_path_and_only_names_in_them() {
        let h = Harness::new();
        let fifo = h.dir.path().join("fifo.env");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let file = h.dir.path().join("app.env");
        std::fs::write(&file, "FAKE_ONE=fake\n").unwrap();
        let twice = h.dir.path().join("twice.env");
        std::fs::write(&twice, "FAKE_ONE=fake\nFAKE_ONE=again\n").unwrap();
        let dotenv = |path: &Path, names: &[&str]| Request::ImportFrom {
            source: ImportSource::Dotenv {
                path: path.display().to_string(),
                prefix: None,
                names: names.iter().map(|n| n.to_string()).collect(),
            },
            tags: Vec::new(),
            replace: false,
        };
        let refused = |request: Request, expected: &str| match h.call(&request) {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
                assert!(message.contains(expected), "{message}");
            }
            other => panic!("unexpected {}", other.kind()),
        };
        // Refused before any dialog: what the request itself says.
        refused(dotenv(Path::new("app.env"), &["FAKE_ONE"]), "absolute");
        refused(
            Request::DotenvNames {
                path: "relative.env".into(),
            },
            "absolute",
        );
        assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
        // Anything that depends on the file comes after the dialog: denied,
        // the requester does not learn whether a name is in the file.
        for request in [dotenv(&file, &["FAKE_TWO"]), dotenv(&twice, &["FAKE_ONE"])] {
            h.decide(&[Decision::Deny]);
            match h.call(&request) {
                Response::Error { code, .. } => assert_eq!(code, ErrorCode::Denied),
                other => panic!("unexpected {}", other.kind()),
            }
        }
        // Allowed: a FIFO is refused without waiting for a writer, and the
        // names are checked.
        h.decide(&[Decision::AllowOnce; 3]);
        refused(dotenv(&fifo, &["FAKE_ONE"]), "not a regular file");
        refused(dotenv(&file, &["FAKE_TWO"]), "is not in");
        refused(dotenv(&twice, &["FAKE_ONE"]), "FAKE_ONE is set again");
    }

    #[cfg(all(feature = "fake-keyring", feature = "session-lock"))]
    mod keyring {
        use super::*;
        use crate::session_lock::Bus;
        use rusthorse::keyring::fake::{self, Item};

        fn keyring(items: Vec<Item>) -> Option<(Bus, zbus::blocking::Connection)> {
            if !Bus::available() {
                return None;
            }
            let bus = Bus::started();
            let service = fake::serve(Some(&bus.address), items).expect("serve the fake keyring");
            Some((bus, service))
        }

        fn segredo(name: &str, value: &str) -> Item {
            Item::new(
                &format!("segredo: {name}"),
                &[("aplicacao", "segredo"), ("nome", name)],
                value,
            )
        }

        /// Names from the keyring are shown escaped: in a dry run's list,
        /// and in the error that refuses names given twice.
        #[test]
        fn keyring_names_are_shown_escaped() {
            let Some((bus, _service)) = keyring(vec![
                segredo("FAKE\u{1b}[2J", "fake-value-1"),
                segredo("TWICE\u{1b}]0;x\u{7}", "fake-value-2"),
                segredo("TWICE\u{1b}]0;x\u{7}", "fake-value-3"),
            ]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            assert!(h.run(&["unlock"]).status.success());
            h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
            let import = [
                "import",
                "secret-service",
                "-a",
                "aplicacao=segredo",
                "--name-from",
                "nome",
            ];
            let raw = |out: &str| out.contains('\u{1b}') || out.contains('\u{7}');
            let out = h.run(&[&import[..], &["--dry-run"]].concat());
            assert!(out.status.success(), "{}", text(&out.stderr));
            let shown = text(&out.stdout);
            assert!(!raw(&shown), "{shown:?}");
            assert!(shown.contains("FAKE\\u{1b}[2J"), "{shown}");
            let out = h.run(&import);
            assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
            let stderr = text(&out.stderr);
            assert!(!raw(&stderr), "{stderr:?}");
            assert!(stderr.contains("TWICE\\u{1b}]0;x\\u{7}"), "{stderr}");
        }

        #[test]
        fn the_cli_imports_keyring_items_that_the_agent_reads() {
            let Some((bus, _service)) = keyring(vec![
                segredo("FAKE_A", "fake-a-value"),
                segredo("FAKE_B", "fake-b-value"),
                Item::new("another program", &[("application", "other")], "not-this"),
            ]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            assert!(h.run(&["unlock"]).status.success());
            h.decide(&[Decision::AllowOnce, Decision::AllowOnce]);
            let out = h.run(&[
                "import",
                "secret-service",
                "-a",
                "aplicacao=segredo",
                "--name-from",
                "nome",
                "--tag",
                "migrated",
            ]);
            assert!(out.status.success(), "{}", text(&out.stderr));
            let dialog = last_approval(&h);
            assert!(
                dialog.contains("Import 2 secrets from GNOME Keyring?"),
                "{dialog}"
            );
            // Each entry next to the item its value comes from.
            assert!(
                dialog.contains("← segredo: FAKE_A [aplicacao=segredo, nome=FAKE_A]"),
                "{dialog}"
            );
            assert_eq!(value_in_file(&h, "FAKE_A"), "fake-a-value");
            assert_eq!(value_in_file(&h, "FAKE_B"), "fake-b-value");
            let list = text(&h.run(&["list"]).stdout);
            assert!(!list.contains("another program"), "{list}");
            assert!(!h.audit_text().contains("fake-a-value"));
        }

        /// List the keyring from this test's process (approved), as a
        /// program must before it imports from it.
        fn list(h: &Harness) -> Vec<rusthorse::protocol::KeyringItem> {
            h.decide(&[Decision::AllowOnce]);
            match h.call(&Request::KeyringItems) {
                Response::KeyringItems { items } => items,
                other => panic!("unexpected {}", other.kind()),
            }
        }

        fn pick(id: &str, name: &str) -> Request {
            Request::ImportFrom {
                source: ImportSource::Keyring {
                    items: vec![rusthorse::protocol::KeyringPick {
                        id: id.into(),
                        name: name.into(),
                    }],
                },
                tags: Vec::new(),
                replace: true,
            }
        }

        const FIRST: &str = "/org/freedesktop/secrets/collection/login/1";

        #[test]
        fn the_dialog_shows_which_item_feeds_which_entry() {
            let Some((bus, _service)) = keyring(vec![Item::new(
                "UNRELATED_FAKE_STAGING",
                &[("nome", "OTHER_KEY")],
                "fake-staging",
            )]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            h.add_secret("OPENAI_API_KEY", "fake-original", &[]);
            list(&h);
            h.decide(&[Decision::Deny]);
            let answer = h.call(&pick(FIRST, "OPENAI_API_KEY"));
            assert!(matches!(
                answer,
                Response::Error {
                    code: ErrorCode::Denied,
                    ..
                }
            ));
            let dialog = last_approval(&h);
            // The entry's name is content, as written, after a fixed title.
            assert!(
                dialog.contains("Entry 1")
                    && dialog.contains("OPENAI_API_KEY ← UNRELATED_FAKE_STAGING [nome=OTHER_KEY]"),
                "{dialog}"
            );
            assert!(dialog.contains("Will be replaced"), "{dialog}");
            assert_eq!(value_in_file(&h, "OPENAI_API_KEY"), "fake-original");
        }

        #[test]
        fn an_item_that_changes_while_the_human_decides_is_not_read() {
            let Some((bus, service)) = keyring(vec![segredo("FAKE_A", "fake-a-value")]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            assert!(h.run(&["unlock"]).status.success());
            list(&h);
            // (A clone: the service lives as long as `service`.)
            let relabel = service.clone();
            *h.ui.on_approve.lock().unwrap() = Some(Box::new(move || {
                fake::relabel(&relabel, 0, "segredo: SOMETHING_ELSE").expect("relabel");
            }));
            h.decide(&[Decision::AllowOnce]);
            match h.call(&pick(FIRST, "FAKE_A")) {
                Response::Error { message, .. } => {
                    assert!(message.contains("changed while you decided"), "{message}")
                }
                other => panic!("unexpected {}", other.kind()),
            }
            assert!(!text(&h.run(&["list"]).stdout).contains("FAKE_A"));
        }

        #[test]
        fn only_items_of_a_listing_this_program_was_shown_can_be_imported() {
            let Some((bus, _service)) = keyring(vec![segredo("FAKE_A", "fake-a-value")]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            let refused = |request: &Request, expected: &str| match h.call(request) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::InvalidRequest, "{message}");
                    assert!(message.contains(expected), "{message}");
                    message
                }
                other => panic!("unexpected {}", other.kind()),
            };
            // No listing: refused alike whatever the item, so that nothing —
            // not even the dialog's size — tells what the keyring holds.
            let long: Vec<_> = (0..40)
                .map(|i| rusthorse::protocol::KeyringPick {
                    id: FIRST.into(),
                    name: format!("{}{i:03}", "N".repeat(97)),
                })
                .collect();
            let many = |items| Request::ImportFrom {
                source: ImportSource::Keyring { items },
                tags: Vec::new(),
                replace: false,
            };
            let gone: Vec<_> = long
                .iter()
                .map(|p| rusthorse::protocol::KeyringPick {
                    id: "/org/freedesktop/secrets/collection/login/99".into(),
                    name: p.name.clone(),
                })
                .collect();
            assert_eq!(
                refused(&many(long), "list the keyring first"),
                refused(&many(gone), "list the keyring first")
            );
            // Listed by another program (the CLI): still refused here.
            h.decide(&[Decision::AllowOnce]);
            let out = h.run(&["import", "secret-service", "-a", "nome=FAKE_A", "--dry-run"]);
            assert!(out.status.success(), "{}", text(&out.stderr));
            refused(&pick(FIRST, "FAKE_A"), "list the keyring first");
            // Listed here, but an item that was not in the listing.
            list(&h);
            refused(
                &pick("/org/freedesktop/secrets/collection/login/99", "X"),
                "not in the keyring listing",
            );
            // A lock forgets the listing.
            assert!(h.run(&["lock"]).status.success());
            refused(&pick(FIRST, "FAKE_A"), "list the keyring first");
            assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn a_lock_while_the_keyring_is_listed_keeps_nothing_of_the_listing() {
            let mut slow = segredo("FAKE_A", "fake-a-value");
            slow.delay = Duration::from_millis(400);
            let Some((bus, _service)) = keyring(vec![slow]) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            h.decide(&[Decision::AllowOnce]);
            let socket = h.socket.clone();
            let listing = std::thread::spawn(move || {
                rusthorse::client::Client::new(socket)
                    .call(&Request::KeyringItems)
                    .expect("listing")
            });
            // While the agent waits for the slow keyring.
            std::thread::sleep(Duration::from_millis(150));
            assert!(h.run(&["lock"]).status.success());
            match listing.join().expect("join") {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Locked, "{message}");
                    assert!(!message.contains("FAKE_A"), "{message}");
                }
                other => panic!("unexpected {}", other.kind()),
            }
        }

        #[test]
        fn many_short_items_are_imported_in_batches_whose_dialogs_fit() {
            let items: Vec<Item> = (0..20)
                .map(|i| Item::new(&format!("FAKE_{i}"), &[("a", "b")], "fake-value"))
                .collect();
            let Some((bus, _service)) = keyring(items) else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            assert!(h.run(&["unlock"]).status.success());
            h.decide(&[Decision::AllowOnce; 10]);
            let out = h.run(&["import", "secret-service", "-a", "a=b"]);
            assert!(out.status.success(), "{}", text(&out.stderr));
            let list = text(&h.run(&["list"]).stdout);
            assert_eq!(
                list.lines().filter(|l| l.contains("FAKE_")).count(),
                20,
                "{list}"
            );
            assert!(h.ui.approvals_asked.load(Ordering::SeqCst) >= 3);
        }

        #[test]
        fn listing_shows_metadata_and_a_locked_item_is_refused() {
            let mut locked = segredo("FAKE_LOCKED", "fake-locked");
            locked.locked = true;
            let Some((bus, _service)) = keyring(vec![segredo("FAKE_A", "fake-a-value"), locked])
            else {
                return;
            };
            let h = Harness::with_keyring(&bus.address);
            h.decide(&[Decision::AllowOnce]);
            let Response::KeyringItems { items } = h.call(&Request::KeyringItems) else {
                panic!("no items");
            };
            assert_eq!(items.len(), 2);
            let locked = items.iter().find(|i| i.locked).expect("the locked item");
            assert_eq!(locked.attributes["nome"], "FAKE_LOCKED");
            let serialized = serde_json::to_string(&items).unwrap();
            assert!(!serialized.contains("fake-a-value"), "{serialized}");
            assert!(h.run(&["unlock"]).status.success());
            let request = Request::ImportFrom {
                source: ImportSource::Keyring {
                    items: items
                        .iter()
                        .map(|i| rusthorse::protocol::KeyringPick {
                            id: i.id.clone(),
                            name: i.attributes["nome"].clone(),
                        })
                        .collect(),
                },
                tags: Vec::new(),
                replace: false,
            };
            // The dialog says that an item is locked; denied, the requester
            // learns nothing of it.
            h.decide(&[Decision::Deny]);
            match h.call(&request) {
                Response::Error { code, message } => {
                    assert_eq!(code, ErrorCode::Denied);
                    assert!(!message.contains("FAKE_LOCKED"), "{message}");
                }
                other => panic!("unexpected {}", other.kind()),
            }
            let dialog = last_approval(&h);
            assert!(dialog.contains("locked: cannot be read"), "{dialog}");
            // Allowed, the locked item stops the import.
            h.decide(&[Decision::AllowOnce]);
            match h.call(&request) {
                Response::Error { message, .. } => {
                    assert!(
                        message.contains("is locked; unlock the keyring"),
                        "{message}"
                    )
                }
                other => panic!("unexpected {}", other.kind()),
            }
            assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 3);
            assert!(!text(&h.run(&["list"]).stdout).contains("FAKE_A"));
        }
    }
}

/// The CLI's side of the credential broker (ADR 0013): what `rusthorse`
/// sends for `run --broker`, `edit --broker`, `grants`, and what it shows for
/// `status`, `doctor` and `audit`. Against fake agents that record every
/// request and answer as each test says; the real agent's grants are tested
/// with the agent itself.
mod broker_cli {
    use super::*;
    use rusthorse::broker_grant::AutomaticLocks;
    use rusthorse::protocol::{
        EntryFields, EntryInfo, ErrorCode, GrantInfo, PROTOCOL_VERSION, Request, Response,
        StatusInfo, UnauthorizedGrant, recv_frame, send_frame,
    };
    use serde_json::{Value, json};
    use std::sync::atomic::AtomicBool;

    /// A fake agent on a socket of its own. It records every request — its
    /// JSON, and how many descriptors came with it — answers `status` with
    /// its status, and every other request with what `answer` returns
    /// (`None`: the connection is closed without an answer). A panic in
    /// `answer` (a request no test expects) fails the test when the agent
    /// is dropped.
    struct FakeAgent {
        dir: tempfile::TempDir,
        socket: PathBuf,
        received: Arc<Mutex<Vec<(Value, usize)>>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeAgent {
        fn new(
            status: StatusInfo,
            answer: impl Fn(&Request) -> Option<Response> + Send + 'static,
        ) -> FakeAgent {
            let dir = tempfile::tempdir().expect("tempdir");
            let socket = dir.path().join("agent.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");
            let received = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (received, stop) = (Arc::clone(&received), Arc::clone(&stop));
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let stream = match listener.accept() {
                            Ok((stream, _)) => stream,
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::Interrupted
                                ) =>
                            {
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(e) => panic!("accept: {e}"),
                        };
                        stream.set_nonblocking(false).expect("blocking");
                        // A client that never sends stops nothing else.
                        stream
                            .set_read_timeout(Some(Duration::from_secs(10)))
                            .expect("timeout");
                        let Ok((body, fds)) = recv_frame(&stream) else {
                            continue;
                        };
                        let json: Value = serde_json::from_slice(&body).expect("json");
                        received.lock().unwrap().push((json.clone(), fds.len()));
                        let reply = match serde_json::from_value::<Request>(json) {
                            Ok(Request::Status) => Some(Response::Status(status.clone())),
                            Ok(request) => answer(&request),
                            Err(e) => Some(Response::Error {
                                code: ErrorCode::InvalidRequest,
                                message: format!("malformed request: {e}"),
                            }),
                        };
                        if let Some(reply) = reply {
                            let _ = send_frame(&stream, &reply, &[]);
                        }
                    }
                })
            };
            FakeAgent {
                dir,
                socket,
                received,
                stop,
                thread: Some(thread),
            }
        }

        /// `rusthorse ARGS…` on this agent's socket, with the vault and the
        /// audit log in its directory and no display (no dialog can show).
        fn cmd(&self, args: &[&str]) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_rusthorse"));
            cmd.args(args)
                .env("RUSTHORSE_SOCKET", &self.socket)
                .env("RUSTHORSE_VAULT", self.dir.path().join("vault.kdbx"))
                .env("RUSTHORSE_AUDIT_LOG", self.dir.path().join("audit.jsonl"))
                .current_dir(self.dir.path())
                .stdin(Stdio::null())
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY");
            cmd
        }

        fn run(&self, args: &[&str]) -> Output {
            self.cmd(args).finish()
        }

        /// Every request received so far, `status` included.
        fn requests(&self) -> Vec<Value> {
            let received = self.received.lock().unwrap();
            received.iter().map(|(json, _)| json.clone()).collect()
        }

        /// The requests received so far other than `status`, with the number
        /// of descriptors each carried.
        fn sent(&self) -> Vec<(Value, usize)> {
            let received = self.received.lock().unwrap();
            received
                .iter()
                .filter(|(json, _)| json["type"] != "status")
                .cloned()
                .collect()
        }

        /// The one request received other than `status`.
        fn only_sent(&self) -> (Value, usize) {
            match &self.sent()[..] {
                [one] => one.clone(),
                other => panic!("expected one request, got {other:?}"),
            }
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take()
                && let Err(panic) = thread.join()
                && !std::thread::panicking()
            {
                std::panic::resume_unwind(panic);
            }
        }
    }

    /// The status of an agent of this protocol that reports `broker`.
    fn status(broker: Option<&str>, agent_executable: &str) -> StatusInfo {
        StatusInfo {
            protocol_version: PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            vault: "/nonexistent".into(),
            vault_exists: true,
            audit_log: String::new(),
            locked: false,
            idle_timeout_secs: 0,
            locks_in_secs: None,
            remembered_approvals: 0,
            agent_executable: agent_executable.into(),
            agent_executable_id: None,
            agent_executable_replaced: None,
            dialogs: None,
            lock_triggers: vec![],
            broker: broker.map(Into::into),
            grants: None,
        }
    }

    fn plain_status() -> StatusInfo {
        status(None, "")
    }

    fn exited(code: i32) -> Option<Response> {
        Some(Response::Exited {
            code: Some(code),
            signal: None,
            unauthorized: Vec::new(),
        })
    }

    fn error(code: ErrorCode, message: &str) -> Option<Response> {
        Some(Response::Error {
            code,
            message: message.into(),
        })
    }

    fn ok(message: &str) -> Option<Response> {
        Some(Response::Ok {
            message: message.into(),
        })
    }

    /// An entry as `show` returns it.
    fn entry(id: &str, group: Option<&str>, name: &str, url: Option<&str>) -> EntryInfo {
        EntryInfo {
            id: id.into(),
            name: name.into(),
            group: group.map(Into::into),
            fields: EntryFields {
                url: url.map(Into::into),
                ..EntryFields::default()
            },
            protected_fields: vec![],
            has_password: true,
            has_notes: false,
            other_fields: vec![],
            modified: None,
        }
    }

    /// The value of variable `name` in the environment a run request sends.
    fn env_var<'a>(request: &'a Value, name: &str) -> Option<&'a str> {
        request["env"]
            .as_array()
            .expect("env")
            .iter()
            .rev()
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str().expect("a value"))
    }

    /// A run with a binding by value, two broker bindings, each with its
    /// destination — one with the variable of the broker's address — and a
    /// `--url` of another entry, which still reads that entry's URL.
    const MIXED: &[&str] = &[
        "run",
        "DB_PASSWORD=db",
        "--broker",
        "ANTHROPIC_AUTH_TOKEN=AI/anthropic@https://api.anthropic.com",
        "--broker",
        "OPENAI_API_KEY@https://api.openai.com/v1",
        "--url",
        "ANTHROPIC_BASE_URL=AI/anthropic",
        "--url",
        "DOCS_URL=docs",
    ];

    /// The fake agent of a run: `docs` has a URL, and the run request gets
    /// `answer`.
    fn run_agent(answer: impl Fn() -> Option<Response> + Send + 'static) -> FakeAgent {
        FakeAgent::new(plain_status(), move |request| match request {
            Request::Show { name } if name == "docs" => Some(Response::Entry {
                entry: entry(
                    "11111111-2222-4333-8444-555555555555",
                    None,
                    "docs",
                    Some("https://docs.example.invalid/api"),
                ),
            }),
            Request::Run(_) | Request::BrokerRunV2(_) => answer(),
            other => panic!("unexpected {other:?}"),
        })
    }

    #[test]
    fn run_with_broker_bindings_sends_a_broker_run_with_them() {
        let agent = run_agent(|| exited(7));
        let mut args = MIXED.to_vec();
        args.extend(["--", "sh", "-c", "exit 0"]);
        // What this environment has in the broker's variables is not sent:
        // they are the agent's to set.
        let out = agent
            .cmd(&args)
            .env("ANTHROPIC_AUTH_TOKEN", "FAKE-stale-token-0000")
            .env("ANTHROPIC_BASE_URL", "https://elsewhere.invalid")
            .env("OPENAI_API_KEY", "FAKE-sk-test-0000")
            .env("UNRELATED", "kept")
            .finish();
        // The command's own status, as the agent reports it.
        assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
        let types: Vec<Value> = agent.requests().iter().map(|r| r["type"].clone()).collect();
        assert_eq!(types, ["status", "show", "broker_run_v2"]);
        let (request, fds) = agent.sent().pop().expect("the run");
        assert_eq!(fds, 0, "with redaction, no descriptor goes with it");
        assert_eq!(
            request["bindings"],
            json!([{"var": "DB_PASSWORD", "entry": "db"}])
        );
        // Each with its destination as the command line wrote it, and the
        // default limits: no request limit, 12 hours, `continue`.
        assert_eq!(
            request["brokered"],
            json!([
                {
                    "var": "ANTHROPIC_AUTH_TOKEN",
                    "entry": "AI/anthropic",
                    "destination": "https://api.anthropic.com",
                    "url_var": "ANTHROPIC_BASE_URL"
                },
                {
                    "var": "OPENAI_API_KEY",
                    "entry": "OPENAI_API_KEY",
                    "destination": "https://api.openai.com/v1"
                },
            ])
        );
        assert_eq!(
            request["limits"],
            json!({"automatic_locks": "continue", "max_lifetime_minutes": 720})
        );
        assert_eq!(request["argv"], json!(["sh", "-c", "exit 0"]));
        assert_eq!(request["redact"], true);
        assert_eq!(request["forward_stdin"], false);
        let cwd = std::fs::canonicalize(agent.dir.path()).expect("canonical");
        assert_eq!(request["cwd"], cwd.to_str().expect("utf8"), "{request}");
        // The other --url reads that entry's URL, as without the broker.
        assert_eq!(
            env_var(&request, "DOCS_URL"),
            Some("https://docs.example.invalid/api")
        );
        assert_eq!(env_var(&request, "UNRELATED"), Some("kept"));
        for var in [
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "OPENAI_API_KEY",
        ] {
            assert_eq!(env_var(&request, var), None, "{var}");
        }
        assert!(!request.to_string().contains("FAKE-"), "{request}");

        // Without redaction, the three descriptors go with it, as with run;
        // with --stdin, the input is forwarded.
        for (option, redact, stdin, descriptors) in
            [("--no-redact", false, false, 3), ("--stdin", true, true, 0)]
        {
            let agent = run_agent(|| exited(0));
            let out = agent.run(&[
                "run",
                option,
                "--broker",
                "T=k@https://x.example",
                "--",
                "true",
            ]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
            let (request, fds) = agent.only_sent();
            assert_eq!(request["type"], "broker_run_v2");
            assert_eq!(request["bindings"], json!([]), "through the broker only");
            assert_eq!(
                request["brokered"],
                json!([{"var": "T", "entry": "k", "destination": "https://x.example"}])
            );
            assert_eq!(
                (
                    request["redact"].clone(),
                    request["forward_stdin"].clone(),
                    fds
                ),
                (redact.into(), stdin.into(), descriptors),
                "{option}"
            );
        }

        // The run's limits, as its options give them, for every grant.
        let agent = run_agent(|| exited(0));
        let out = agent.run(&[
            "run",
            "--broker",
            "A=a@https://a.example",
            "--broker",
            "B=b@https://b.example:8443/v2",
            "--broker-requests",
            "5",
            "--broker-lifetime",
            "30",
            "--broker-locks",
            "end",
            "--",
            "true",
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let (request, _) = agent.only_sent();
        assert_eq!(
            request["limits"],
            json!({"automatic_locks": "end", "max_lifetime_minutes": 30, "max_requests": 5})
        );
        assert_eq!(
            request["brokered"][1]["destination"],
            "https://b.example:8443/v2"
        );

        // Without --broker, a plain run, as before.
        let agent = run_agent(|| exited(0));
        let out = agent.run(&["run", "KEY", "--url", "DOCS_URL=docs", "--", "true"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let (request, _) = agent.sent().pop().expect("the run");
        assert_eq!(request["type"], "run");
        assert!(request.get("brokered").is_none(), "{request}");
        assert_eq!(request["bindings"], json!([{"var": "KEY", "entry": "KEY"}]));
        assert_eq!(
            env_var(&request, "DOCS_URL"),
            Some("https://docs.example.invalid/api")
        );
    }

    /// What a fake agent answers a run with.
    type RunAnswer = Box<dyn Fn() -> Option<Response> + Send>;

    #[test]
    fn a_broker_run_exits_as_run_does() {
        let cases: Vec<(RunAnswer, i32, &str)> = vec![
            // Refused or failed before the command started: no fallback.
            (
                Box::new(|| error(ErrorCode::InvalidRequest, "KEY has no value")),
                125,
                "KEY has no value",
            ),
            (
                Box::new(|| error(ErrorCode::Internal, "the broker did not start")),
                125,
                "the broker did not start",
            ),
            (
                Box::new(|| error(ErrorCode::Denied, "denied")),
                125,
                "denied",
            ),
            // The outcome is unknown.
            (
                Box::new(|| error(ErrorCode::OutcomeUnknown, "waiting failed")),
                124,
                "waiting failed",
            ),
            (Box::new(|| None), 124, "may or may not have run"),
            (Box::new(|| ok("?")), 124, "may or may not have run"),
            // The command's own status.
            (
                Box::new(|| {
                    Some(Response::Exited {
                        code: None,
                        signal: Some(9),
                        unauthorized: Vec::new(),
                    })
                }),
                137,
                "",
            ),
            (Box::new(|| exited(3)), 3, ""),
        ];
        for (answer, expected, message) in cases {
            let agent = run_agent(answer);
            let out = agent.run(&["run", "--broker", "T=k@https://x.example", "--", "true"]);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(expected), "{stderr}");
            assert!(stderr.contains(message), "{stderr}");
            assert_eq!(agent.only_sent().0["type"], "broker_run_v2");
        }
    }

    /// How an agent of protocol 8 answers a `broker_run_v2`: a request it
    /// cannot read (`invalid_request`), in the words of `c06af42`'s agent,
    /// the position in the frame aside.
    const REFUSED_BY_PROTOCOL_8: &str = "malformed request: unknown variant `broker_run_v2`, \
        expected one of `status`, `unlock`, `create_vault`, `lock`, `list`, `show`, `add`, \
        `import`, `edit`, `remove`, `change_password`, `reveal`, `backup`, `run`, \
        `keyring_items`, `dotenv_names`, `import_from`, `broker_run`, `broker_edit`, `grants`, \
        `revoke_grant` at line 1 column 23";

    /// The version check and the run are separate connections: an agent
    /// restarted between them may be of protocol 8, which knows no
    /// `broker_run_v2` and refuses it whole (ADR 0013, scope amendment).
    /// The client says so and exits 125, the run not started; it never
    /// sends the run again — not as protocol 8's `broker_run`, which would
    /// ignore its destinations and limits, nor as a plain `run`, nor as
    /// anything else — with redaction or without, with its input or not.
    #[test]
    fn a_broker_run_an_older_agent_refuses_is_never_sent_again_as_another_request() {
        for (options, descriptors) in [
            (&[][..], 0),
            (&["--no-redact"][..], 3),
            (&["--stdin"][..], 0),
        ] {
            // It answers `status` as an agent of this protocol did on the
            // first connection, and the run as protocol 8 does.
            let agent = run_agent(|| error(ErrorCode::InvalidRequest, REFUSED_BY_PROTOCOL_8));
            let mut args = vec!["run"];
            args.extend(options);
            args.extend([
                "DB_PASSWORD=db",
                "--broker",
                "K=KEY@https://api.example.com/v1",
                "--url",
                "K_URL=KEY",
                "--url",
                "DOCS_URL=docs",
                "--",
                "true",
            ]);
            let out = agent.run(&args);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(125), "{options:?}: {stderr}");
            assert_eq!(
                stderr,
                format!("rusthorse: {REFUSED_BY_PROTOCOL_8}\n"),
                "{options:?}"
            );
            assert!(out.stdout.is_empty(), "{options:?}");
            // A request sent after the client left would still be read.
            std::thread::sleep(Duration::from_millis(200));
            let types: Vec<Value> = agent.requests().iter().map(|r| r["type"].clone()).collect();
            assert_eq!(types, ["status", "show", "broker_run_v2"], "{options:?}");
            let (request, fds) = agent.sent().pop().expect("the run");
            assert_eq!(fds, descriptors, "{options:?}");
            assert_eq!(
                request["brokered"][0]["destination"],
                "https://api.example.com/v1"
            );
        }
    }

    fn refused_grant(var: &str, entry: &str, requests: u64) -> UnauthorizedGrant {
        UnauthorizedGrant {
            var: var.into(),
            entry: entry.into(),
            destination: "https://api.anthropic.com".into(),
            requests,
        }
    }

    /// When the agent reports that a grant's destination answered `401`,
    /// `rusthorse run` says so after the command, which keeps its own
    /// status, with or without redaction: the command ran, the broker
    /// accepted its token, and the destination did not accept the key of
    /// the entry the command line named — and how to replace it.
    #[test]
    fn a_refused_key_is_named_after_the_command_which_keeps_its_status() {
        const NOTE: &str = "rusthorse: note: the command ran, and the broker accepted its \
                            token, but the approved origin https://api.anthropic.com answered \
                            401 Unauthorized to 2 requests: it did not accept the key stored \
                            in AI/k. If that key is wrong, revoked, or not of the kind the \
                            destination expects, replace it: rusthorse edit AI/k --value\n";
        for (no_redact, code, signal, expected) in [
            (false, Some(7), None, 7),
            (true, Some(7), None, 7),
            (false, None, Some(9), 137),
            // The command's own 125: the note says that it ran.
            (false, Some(125), None, 125),
        ] {
            let agent = run_agent(move || {
                Some(Response::Exited {
                    code,
                    signal,
                    unauthorized: vec![refused_grant("T", "AI/k (8d2f6c1e)", 2)],
                })
            });
            let mut args = vec!["run"];
            if no_redact {
                args.push("--no-redact");
            }
            args.extend(["--broker", "T=AI/k@https://api.anthropic.com", "--", "true"]);
            let out = agent.run(&args);
            assert_eq!(out.status.code(), Some(expected), "{}", text(&out.stderr));
            assert_eq!(text(&out.stderr), NOTE);
        }
        // A note for each grant the agent names, in its order; a name the
        // shell would split is quoted; one request is singular.
        let agent = run_agent(|| {
            Some(Response::Exited {
                code: Some(0),
                signal: None,
                unauthorized: vec![
                    refused_grant("B", "my key (11111111)", 1),
                    refused_grant("A", "AI/k (8d2f6c1e)", 3),
                ],
            })
        });
        let out = agent.run(&[
            "run",
            "--broker",
            "A=AI/k@https://api.anthropic.com",
            "--broker",
            "B=my key@https://api.anthropic.com",
            "--",
            "true",
        ]);
        assert_eq!(out.status.code(), Some(0));
        let stderr = text(&out.stderr);
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{stderr}");
        assert!(
            lines[0].contains("to 1 request: it did not accept the key stored in my key.")
                && lines[0].ends_with("replace it: rusthorse edit 'my key' --value"),
            "{stderr}"
        );
        assert!(
            lines[1].contains("to 3 requests: it did not accept the key stored in AI/k."),
            "{stderr}"
        );
        // A grant the command line did not give is named as the agent
        // reports it, escaped, without a command to run.
        let agent = run_agent(|| {
            Some(Response::Exited {
                code: Some(0),
                signal: None,
                unauthorized: vec![UnauthorizedGrant {
                    var: "OTHER".into(),
                    entry: "AI/k\u{1b}[2J (8d2f6c1e)".into(),
                    destination: "https://api.example\u{202e}.com".into(),
                    requests: 1,
                }],
            })
        });
        let stderr = text(
            &agent
                .run(&["run", "--broker", "T=AI/k@https://x.example", "--", "true"])
                .stderr,
        );
        assert!(
            !stderr.contains('\u{1b}') && !stderr.contains('\u{202e}'),
            "{stderr:?}"
        );
        assert!(
            stderr.contains("but the approved origin https://api.example\\u{202e}.com answered")
                && stderr.contains("stored in AI/k\\u{1b}[2J (8d2f6c1e).")
                && stderr.trim_end().ends_with("replace the entry's value"),
            "{stderr}"
        );
        // An answer with neither a code nor a signal is an unknown outcome:
        // no note says that the command ran.
        let agent = run_agent(|| {
            Some(Response::Exited {
                code: None,
                signal: None,
                unauthorized: vec![refused_grant("T", "AI/k (8d2f6c1e)", 1)],
            })
        });
        let out = agent.run(&["run", "--broker", "T=AI/k@https://x.example", "--", "true"]);
        assert_eq!(out.status.code(), Some(124));
        let stderr = text(&out.stderr);
        assert!(
            stderr.contains("may or may not have run") && !stderr.contains("note:"),
            "{stderr}"
        );
        // Nothing reported (or an older agent): nothing said.
        let agent = run_agent(|| exited(3));
        let out = agent.run(&["run", "--broker", "T=AI/k@https://x.example", "--", "true"]);
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    }

    #[test]
    fn mistakes_in_broker_options_send_nothing() {
        let agent = FakeAgent::new(plain_status(), |request| {
            panic!("nothing should be sent, got {request:?}")
        });
        // A destination valid for every case but those about it.
        const K: &str = "K=x@https://x.example";
        for (args, expected, message) in [
            // `run`: did not run.
            (
                &[
                    "run", "--broker", K, "--url", "U=x", "--url", "V=x", "--", "true",
                ][..],
                125,
                "x already has --url U",
            ),
            (
                &["run", "--broker", "1K=x@https://x.example", "--", "true"][..],
                125,
                "not a valid environment variable name",
            ),
            (
                &["run", "--broker", "K=@https://x.example", "--", "true"][..],
                125,
                "missing entry name",
            ),
            (
                &["run", "X=x", "--broker", K, "--", "true"][..],
                125,
                "also given by value",
            ),
            (
                &[
                    "run",
                    "--broker",
                    K,
                    "--broker",
                    "L=x@https://x.example",
                    "--",
                    "true",
                ][..],
                125,
                "already given to --broker",
            ),
            (
                &[
                    "run",
                    "--broker",
                    "LD_PRELOAD=x@https://x.example",
                    "--",
                    "true",
                ][..],
                125,
                "cannot carry a token",
            ),
            (
                &[
                    "run",
                    "--broker",
                    "NO_PROXY=x@https://x.example",
                    "--",
                    "true",
                ][..],
                125,
                "the agent adds 127.0.0.1 to this variable",
            ),
            (
                &["run", "--broker", K, "--url", "no_proxy=x", "--", "true"][..],
                125,
                "it cannot carry the broker's address",
            ),
            (
                &["run", "K=y", "--broker", K, "--", "true"][..],
                125,
                "already set by another binding",
            ),
            // Two SECRETs in one variable, with --broker or without it.
            (
                &[
                    "run",
                    "K=a",
                    "K=b",
                    "--broker",
                    "T=x@https://x.example",
                    "--",
                    "true",
                ][..],
                125,
                "K=b: the variable is already set by another binding",
            ),
            (
                &["run", "K=a", "K=b", "--", "true"][..],
                125,
                "K=b: the variable is already set by another binding",
            ),
            // The destination: named, https://, a host name, no user
            // information, query or fragment, a valid base path; there is no
            // default (the entry's URL is not one).
            (
                &["run", "--broker", "K=x", "--", "true"][..],
                125,
                "name the destination",
            ),
            (
                &["run", "--broker", "x", "--", "true"][..],
                125,
                "name the destination",
            ),
            (
                &["run", "--broker", "K=x@http://x.example", "--", "true"][..],
                125,
                "must start with https://",
            ),
            // The URL starts after the last `@`: user information leaves no
            // URL that starts with https://.
            (
                &[
                    "run",
                    "--broker",
                    "K=x@https://user@x.example",
                    "--",
                    "true",
                ][..],
                125,
                "must start with https://",
            ),
            (
                &["run", "--broker", "K=x@https://x.example?q=1", "--", "true"][..],
                125,
                "query or a fragment",
            ),
            (
                &["run", "--broker", "K=x@https://x.example#top", "--", "true"][..],
                125,
                "query or a fragment",
            ),
            (
                &[
                    "run",
                    "--broker",
                    "K=x@https://x.example/v1?q=1",
                    "--",
                    "true",
                ][..],
                125,
                "base path is not valid",
            ),
            (
                &["run", "--broker", "K=x@https://10.0.0.1", "--", "true"][..],
                125,
                "not an IP address",
            ),
            (
                &["run", "--broker", "K=x@https://[::1]:8443", "--", "true"][..],
                125,
                "not an IP address",
            ),
            (
                &["run", "--broker", "K=x@https://x.example/v1/", "--", "true"][..],
                125,
                "base path is not valid",
            ),
            (
                &[
                    "run",
                    "--broker",
                    "K=x@https://x.example/../v1",
                    "--",
                    "true",
                ][..],
                125,
                "base path is not valid",
            ),
            (
                &["run", "--broker", "K=x@https://x.example:0", "--", "true"][..],
                125,
                "the port must be a number from 1 to 65535",
            ),
            // The run's limits.
            (
                &["run", "--broker", K, "--broker-lifetime", "0", "--", "true"][..],
                125,
                "1 to 1440 minutes, not 0",
            ),
            (
                &[
                    "run",
                    "--broker",
                    K,
                    "--broker-lifetime",
                    "1441",
                    "--",
                    "true",
                ][..],
                125,
                "1 to 1440 minutes, not 1441",
            ),
            (
                &["run", "--broker", K, "--broker-requests", "0", "--", "true"][..],
                125,
                "1 to 1000000, not 0",
            ),
            (
                &[
                    "run",
                    "--broker",
                    K,
                    "--broker-locks",
                    "never",
                    "--",
                    "true",
                ][..],
                2,
                "invalid value 'never'",
            ),
            // No secret and no --broker: a usage error; limits without
            // --broker too.
            (
                &["run", "--", "true"][..],
                2,
                "required arguments were not provided",
            ),
            (
                &["run", "--broker", "--", "true"][..],
                2,
                "a value is required",
            ),
            (
                &["run", "K=x", "--broker-requests", "5", "--", "true"][..],
                2,
                "--broker <VAR=ENTRY@URL>",
            ),
            // `edit` has no profile any more.
            (
                &["edit", "KEY", "--broker", "anthropic"][..],
                2,
                "unexpected argument '--broker'",
            ),
            (
                &["edit", "KEY", "--clear", "broker"][..],
                2,
                "invalid value 'broker'",
            ),
            // `grants revoke`: exactly one of an ID and --all, and an ID.
            (&["grants", "revoke"][..], 2, "<ID|--all>"),
            (
                &["grants", "revoke", "g0123456789abcdef", "--all"][..],
                2,
                "cannot be used with",
            ),
            (
                &["grants", "--json", "revoke", "--all"][..],
                2,
                "cannot be used with",
            ),
            (
                &["grants", "revoke", "../g0123"][..],
                1,
                "is not a grant ID",
            ),
            (
                &["grants", "revoke", "G0123456789ABCDEF"][..],
                1,
                "is not a grant ID",
            ),
        ] {
            let out = agent.run(args);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(expected), "{args:?}: {stderr}");
            assert!(stderr.contains(message), "{args:?}: {stderr}");
        }
        assert!(agent.requests().is_empty(), "{:?}", agent.requests());
    }

    #[test]
    fn a_url_for_a_brokered_entry_under_another_name_is_refused() {
        // `anthropic` and the UUID are the entry `AI/anthropic` names: its
        // own URL would send the token straight to the provider, past the
        // broker.
        const ID: &str = "8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12";
        let agent = FakeAgent::new(plain_status(), |request| match request {
            Request::Show { name } if name == "anthropic" || name == ID => Some(Response::Entry {
                entry: entry(
                    ID,
                    Some("AI"),
                    "anthropic",
                    Some("https://api.anthropic.com"),
                ),
            }),
            Request::Show { name } if name == "missing" => {
                error(ErrorCode::NotFound, "no entry named missing")
            }
            other => panic!("unexpected {other:?}"),
        });
        let url_of = |url: &str| {
            agent.run(&[
                "run",
                "--broker",
                "ANTHROPIC_AUTH_TOKEN=AI/anthropic@https://api.anthropic.com",
                "--url",
                url,
                "--",
                "true",
            ])
        };
        for name in ["anthropic", ID] {
            let out = url_of(&format!("ANTHROPIC_BASE_URL={name}"));
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(125), "{stderr}");
            assert!(
                stderr.contains("is the entry of --broker ANTHROPIC_AUTH_TOKEN=AI/anthropic"),
                "{stderr}"
            );
        }
        // An entry the agent does not know: its message, once, and nothing
        // ran.
        let out = url_of("DOCS_URL=missing");
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(125), "{stderr}");
        assert_eq!(stderr, "rusthorse: no entry named missing\n");
        let types: Vec<Value> = agent.requests().iter().map(|r| r["type"].clone()).collect();
        assert_eq!(
            types,
            ["status", "show", "status", "show", "status", "show"],
            "no run was sent"
        );
    }

    fn grant(id: &str) -> GrantInfo {
        GrantInfo {
            id: id.into(),
            entry: "AI/anthropic (8d2f6c1e)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            destination: "https://api.anthropic.com".into(),
            base_path: None,
            command: "claude".into(),
            requester: "rusthorse[4300] ← bash[4242]".into(),
            state: "active".into(),
            started: "2026-11-02T18:00:00-03:00".into(),
            ends_in_secs: 3600,
            requests: 3,
            max_requests: Some(200),
            in_flight: 1,
            unauthorized: Some(0),
            automatic_locks: AutomaticLocks::Continue,
        }
    }

    /// `rusthorse grants` lists each grant's approved origin and, apart from
    /// it, its base path, which is not a limit (ADR 0013, scope amendment).
    #[test]
    fn grants_are_listed_and_revoked_without_approval() {
        let listed = vec![
            grant("g0123456789abcdef"),
            GrantInfo {
                destination: "https://api.openai.com".into(),
                base_path: Some("/v1".into()),
                ..grant("gfedcba9876543210")
            },
        ];
        let shown = listed.clone();
        let agent = FakeAgent::new(plain_status(), move |request| match request {
            Request::Grants => Some(Response::Grants {
                grants: shown.clone(),
            }),
            Request::RevokeGrant { id: Some(id) } if id == "g0000000000000000" => {
                error(ErrorCode::NotFound, "no grant g0000000000000000")
            }
            Request::RevokeGrant { id: Some(id) } => ok(&format!("revoked {id}")),
            Request::RevokeGrant { id: None } => ok("revoked 2 grants"),
            other => panic!("unexpected {other:?}"),
        });
        let out = agent.run(&["grants"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let table = text(&out.stdout);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3, "{table}");
        assert!(
            lines[0].starts_with("ID  ") && lines[0].ends_with("COMMAND"),
            "{table}"
        );
        assert!(
            lines[0].contains("  APPROVED ORIGIN  ")
                && lines[0].contains("  BASE PATH (NOT A LIMIT)  ")
                && !lines[0].contains("DESTINATION")
                && !lines[0].contains("PRESET"),
            "{table}"
        );
        for cell in [
            "g0123456789abcdef",
            "AI/anthropic (8d2f6c1e)",
            "https://api.anthropic.com  ",
            "  none  ",
            "active",
            "2026-11-02T18:00:00-03:00",
            "1h",
            "3 of 200",
            "continue",
            "rusthorse[4300] ← bash[4242]",
        ] {
            assert!(lines[1].contains(cell), "{cell}: {table}");
        }
        assert!(lines[2].starts_with("gfedcba9876543210"), "{table}");
        // The origin and the base path in their own columns: the origin
        // alone, never joined with the base path.
        let column = |line: &str, header: &str| {
            let at = lines[0].find(header).expect("a column");
            line[at..].split("  ").next().expect("a cell").to_string()
        };
        assert_eq!(
            column(lines[2], "APPROVED ORIGIN"),
            "https://api.openai.com"
        );
        assert_eq!(column(lines[2], "BASE PATH (NOT A LIMIT)"), "/v1");
        assert_eq!(column(lines[1], "BASE PATH (NOT A LIMIT)"), "none");
        assert!(!table.contains("api.openai.com/v1"), "{table}");
        // The JSON is the agent's list, as it reports it.
        let out = agent.run(&["grants", "--json"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let back: Vec<GrantInfo> = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(back, listed);
        // One, or all.
        let out = agent.run(&["grants", "revoke", "g0123456789abcdef"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("revoked g0123456789abcdef"));
        let out = agent.run(&["grants", "revoke", "--all"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        // An ID the agent does not know: an error.
        let out = agent.run(&["grants", "revoke", "g0000000000000000"]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("no grant g0000000000000000"));
        let sent: Vec<Value> = agent.sent().into_iter().map(|(json, _)| json).collect();
        assert_eq!(
            sent,
            [
                json!({"type": "grants"}),
                json!({"type": "grants"}),
                json!({"type": "revoke_grant", "id": "g0123456789abcdef"}),
                json!({"type": "revoke_grant"}),
                json!({"type": "revoke_grant", "id": "g0000000000000000"}),
            ]
        );

        // No grant, and an agent that refuses to list them.
        let agent = FakeAgent::new(plain_status(), |request| match request {
            Request::Grants => Some(Response::Grants { grants: vec![] }),
            other => panic!("unexpected {other:?}"),
        });
        let out = agent.run(&["grants"]);
        assert!(out.status.success() && out.stdout.is_empty());
        assert!(text(&out.stderr).contains("No grants."));
        assert_eq!(text(&agent.run(&["grants", "--json"]).stdout).trim(), "[]");
        let agent = FakeAgent::new(plain_status(), |_| {
            error(ErrorCode::InvalidRequest, "broker grants are not available")
        });
        let out = agent.run(&["grants"]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("broker grants are not available"));
    }

    /// What the agent reports in its status is shown escaped.
    #[test]
    fn the_status_is_shown_escaped() {
        let mut info = plain_status();
        info.vault = "/tmp/vault\u{1b}[2J.kdbx".into();
        info.dialogs = Some("rusthorse-dialog\u{7}".into());
        info.agent_executable = "/usr/bin/rusthorse\u{202e}".into();
        let agent = FakeAgent::new(info, |request| panic!("unexpected {request:?}"));
        let out = agent.run(&["status"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let shown = text(&out.stdout);
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{7}') && !shown.contains('\u{202e}'),
            "{shown:?}"
        );
        for escaped in [
            "/tmp/vault\\u{1b}[2J.kdbx",
            "rusthorse-dialog\\u{7}",
            "/usr/bin/rusthorse\\u{202e}",
        ] {
            assert!(shown.contains(escaped), "{escaped}: {shown}");
        }
    }

    /// Whatever the agent says — an answer, an error, the error of a run —
    /// is printed with control and invisible characters escaped.
    #[test]
    fn what_the_agent_says_is_printed_escaped() {
        let agent = FakeAgent::new(plain_status(), |request| match request {
            Request::RevokeGrant { id: Some(_) } => ok("revoked \u{1b}[2J\rX"),
            Request::RevokeGrant { id: None } => {
                error(ErrorCode::NotFound, "no \u{1b}]0;title\u{7}grant")
            }
            Request::BrokerRunV2(_) => error(ErrorCode::InvalidRequest, "K\u{202e} has no value"),
            other => panic!("unexpected {other:?}"),
        });
        for (args, status, says) in [
            (
                &["grants", "revoke", "g0123456789abcdef"][..],
                0,
                "revoked \\u{1b}[2J\\u{d}X",
            ),
            (
                &["grants", "revoke", "--all"][..],
                1,
                "rusthorse: no \\u{1b}]0;title\\u{7}grant",
            ),
            (
                &["run", "--broker", "T=k@https://x.example", "--", "true"][..],
                125,
                "rusthorse: K\\u{202e} has no value",
            ),
        ] {
            let out = agent.run(args);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(status), "{stderr}");
            assert_eq!(stderr.trim_end(), says);
        }
    }

    /// `rusthorse grants` keeps its table, and says under it, on standard
    /// error, which grants' destination answered `401`; its JSON has the
    /// counts as the agent reported them (none from an older agent).
    #[test]
    fn grants_whose_destination_answered_401_get_a_note_under_the_table() {
        let listed = vec![
            grant("g0123456789abcdef"),
            GrantInfo {
                unauthorized: Some(2),
                ..grant("gfedcba9876543210")
            },
            GrantInfo {
                unauthorized: None,
                ..grant("g1111111111111111")
            },
        ];
        let shown = listed.clone();
        let agent = FakeAgent::new(plain_status(), move |request| match request {
            Request::Grants => Some(Response::Grants {
                grants: shown.clone(),
            }),
            other => panic!("unexpected {other:?}"),
        });
        let out = agent.run(&["grants"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(
            text(&out.stdout).lines().count(),
            4,
            "{}",
            text(&out.stdout)
        );
        assert_eq!(
            text(&out.stderr),
            "rusthorse: note: grant gfedcba9876543210: the approved origin \
             https://api.anthropic.com answered 401 Unauthorized to 2 requests: it did not \
             accept the key stored in AI/anthropic (8d2f6c1e). If that key is wrong, revoked, \
             or not of the kind the destination expects, replace the entry's value (rusthorse \
             edit NAME --value)\n"
        );
        let out = agent.run(&["grants", "--json"]);
        assert!(out.status.success() && out.stderr.is_empty());
        let back: Vec<GrantInfo> = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(back, listed);
    }

    #[test]
    fn status_reports_the_broker_and_the_grants_when_the_agent_does() {
        let mut reporting = status(Some("/opt/rusthorse/rusthorse-broker"), "");
        reporting.grants = Some(2);
        let agent = FakeAgent::new(reporting, |request| panic!("unexpected {request:?}"));
        let out = agent.run(&["status"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let shown = text(&out.stdout);
        assert!(
            shown.contains("broker:     /opt/rusthorse/rusthorse-broker\n"),
            "{shown}"
        );
        // Not called active: the agent's count can include a revoked grant
        // whose command still runs, which `rusthorse grants` shows as such.
        let grants = |shown: &str| {
            let line = shown.lines().find(|l| l.starts_with("grants:"));
            line.expect("a grants line").to_string()
        };
        assert_eq!(
            grants(&shown),
            "grants:     2 (`rusthorse grants` shows their state)",
            "{shown}"
        );
        let out = agent.run(&["status", "--json"]);
        let json: Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(json["broker"], "/opt/rusthorse/rusthorse-broker");
        assert_eq!(json["grants"], 2);
        let mut idle = status(Some("/opt/rusthorse/rusthorse-broker"), "");
        idle.grants = Some(0);
        let agent = FakeAgent::new(idle, |request| panic!("unexpected {request:?}"));
        let shown = text(&agent.run(&["status"]).stdout);
        assert_eq!(grants(&shown), "grants:     none", "{shown}");
        // An agent that does not report them: nothing about them.
        let agent = FakeAgent::new(plain_status(), |request| panic!("unexpected {request:?}"));
        let shown = text(&agent.run(&["status"]).stdout);
        assert!(
            !shown.contains("broker:") && !shown.contains("grants:"),
            "{shown}"
        );
    }

    /// `rusthorse doctor` on `agent`, again while a program written for the
    /// test is busy: another test's child may hold it open for writing until
    /// its exec ("Text file busy").
    fn doctor(agent: &FakeAgent) -> String {
        for _ in 0..50 {
            let report = text(&agent.run(&["doctor"]).stdout);
            if !report.contains("Text file busy") {
                return report;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the program stayed busy")
    }

    #[test]
    fn doctor_checks_the_broker_program_and_the_certificate_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join("rusthorse-broker");
        let path = program.to_str().expect("utf8").to_string();
        // The agent's program file is next to it, and in an empty directory.
        let beside = dir
            .path()
            .join("rusthorse")
            .to_str()
            .expect("utf8")
            .to_string();
        let empty = tempfile::tempdir().expect("tempdir");
        let alone = empty
            .path()
            .join("rusthorse")
            .to_str()
            .expect("utf8")
            .to_string();
        let write = |version: &str, mode: u32| {
            std::fs::write(
                &program,
                format!(
                    "#!/bin/sh\necho '{{\"version\":\"{version}\",\"protocol\":{}}}'\n",
                    rusthorse::broker_protocol::VERSION
                ),
            )
            .expect("write");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        let ours = env!("CARGO_PKG_VERSION");
        let report = |status: StatusInfo| {
            doctor(&FakeAgent::new(status, |request| {
                panic!("unexpected {request:?}")
            }))
        };

        // The program the agent reports, of this version: fine.
        write(ours, 0o700);
        let shown = report(status(Some(&path), ""));
        assert!(
            shown.contains(&format!("  ok    broker: rusthorse-broker {ours} ({path})")),
            "{shown}"
        );
        // Of another version: an error.
        write("0.0.0-other", 0o700);
        let shown = report(status(Some(&path), ""));
        assert!(
            shown.contains("  FAIL  rusthorse-broker 0.0.0-other speaks broker protocol"),
            "{shown}"
        );
        assert!(shown.contains("no grant of the credential broker can be served"));
        // Unusable: the agent says why.
        write(ours, 0o770);
        let shown = report(status(
            Some("none: /x/rusthorse-broker can be modified by its group or by others"),
            &beside,
        ));
        assert!(
            shown.contains(
                "  FAIL  no grant of the credential broker can be served (`rusthorse run \
                 --broker` exits with 125 and runs nothing): /x/rusthorse-broker can be modified"
            ),
            "{shown}"
        );
        let installed = shown;
        // Not installed: a warning, which says what it means.
        let shown = report(status(Some("none: it is not installed"), &alone));
        assert!(
            shown.contains(&format!(
                "  warn  {} is not installed: no grant of the credential broker can be served",
                empty.path().join("rusthorse-broker").display()
            )),
            "{shown}"
        );
        let absent = shown;
        // An agent that predates the field: looked for next to its program.
        let shown = report(status(None, &alone));
        assert!(shown.contains("is not installed"), "{shown}");
        let shown = report(status(None, &beside));
        assert!(
            shown.contains("  FAIL  no grant of the credential broker"),
            "{shown}"
        );
        // The certificate file, whatever this computer has: checked as a
        // broker checks it; without it, an error where the broker's
        // program is installed and a warning where it is not.
        match rusthorse::broker_protocol::open_ca_file() {
            Ok(ca) => {
                let line = format!(
                    "  ok    the broker reads its certificate authorities from {}, which only \
                     root can change; it reads the certificates themselves when a grant starts\n",
                    ca.path.display()
                );
                assert!(installed.contains(&line), "{installed}");
                assert!(absent.contains(&line), "{absent}");
            }
            Err(why) => {
                assert!(
                    installed.contains(&format!("  FAIL  {why}: no grant")),
                    "{installed}"
                );
                assert!(
                    absent.contains(&format!("  warn  {why}: no grant")),
                    "{absent}"
                );
            }
        }
    }

    #[test]
    fn the_audit_log_shows_the_records_of_the_broker() {
        use rusthorse::audit::{AuditEvent, AuditGrant, AuditRequestCounts};
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.jsonl");
        let agent = rusthorse::peer::Peer::agent();
        let id = "g0123456789abcdef";
        let mut run = AuditEvent::new("run", &agent)
            .outcome("allowed_once")
            .entries(vec!["AI/anthropic (8d2f6c1e)".into()]);
        run.argv = Some(vec!["claude".into()]);
        run.grants = Some(vec![
            AuditGrant {
                id: id.into(),
                entry: "AI/anthropic (8d2f6c1e)".into(),
                destination: "https://api.anthropic.com".into(),
                base_path: None,
            },
            AuditGrant {
                id: "gfedcba9876543210".into(),
                entry: "AI/openai (11111111)".into(),
                destination: "https://api.openai.com".into(),
                base_path: Some("/v1".into()),
            },
        ]);
        let mut admitted = AuditEvent::new("broker_request", &agent).outcome("admitted");
        admitted.grant = Some(id.into());
        admitted.request = Some(1);
        admitted.method = Some("POST".into());
        let mut finished = AuditEvent::new("broker_request", &agent).outcome("completed");
        finished.grant = Some(id.into());
        finished.request = Some(1);
        finished.status = Some(200);
        finished.bytes_sent = Some(120);
        finished.bytes_received = Some(4096);
        let mut ended = AuditEvent::new("grant", &agent).outcome("ended");
        ended.grant = Some(id.into());
        ended.reason = Some("command_ended".into());
        ended.requests = Some(AuditRequestCounts {
            admitted: 1,
            finished: 1,
            unknown: 0,
            refused: 2,
        });
        let records = [run, admitted, finished, ended];
        let lines: String = records
            .iter()
            .map(|r| serde_json::to_string(r).expect("json") + "\n")
            .collect();
        std::fs::write(&log, &lines).expect("write");
        let audit = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_rusthorse"))
                .args(args)
                .env("RUSTHORSE_AUDIT_LOG", &log)
                .env("RUSTHORSE_SOCKET", dir.path().join("nobody.sock"))
                .stdin(Stdio::null())
                .finish()
        };
        let out = audit(&["audit", "-n", "10"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let shown = text(&out.stdout);
        for part in [
            " grants: g0123456789abcdef for AI/anthropic (8d2f6c1e) to https://api.anthropic.com, \
             gfedcba9876543210 for AI/openai (11111111) to https://api.openai.com (base path /v1, \
             not a limit); $ claude",
            "broker_request admitted",
            " grant g0123456789abcdef #1 POST  by ",
            " grant g0123456789abcdef #1 status 200 (120 bytes sent, 4096 received)  by ",
            " reason: command_ended requests: 1 admitted (1 finished, 0 unknown), 2 refused",
        ] {
            assert!(shown.contains(part), "{part}: {shown}");
        }
        // The JSON is the records as they are.
        let out = audit(&["audit", "-n", "10", "--json"]);
        assert_eq!(text(&out.stdout), lines);
    }

    #[test]
    fn edit_and_grants_refuse_an_agent_of_another_protocol() {
        // An agent one protocol older that would take whatever it is sent:
        // only the version check, which `edit` and `grants` make once their
        // arguments are checked, keeps from it an edit it would misread (an
        // older agent drops a change it does not know) and requests it does
        // not have.
        let mut older = plain_status();
        older.protocol_version = PROTOCOL_VERSION - 1;
        let agent = FakeAgent::new(older, |request| match request {
            Request::Grants => Some(Response::Grants { grants: vec![] }),
            _ => ok("done"),
        });
        let commands: [&[&str]; 6] = [
            &["edit", "KEY", "--username", "x"],
            &["edit", "KEY", "--group", "Work"],
            &["grants"],
            &["grants", "--json"],
            &["grants", "revoke", "--all"],
            &["grants", "revoke", "g0123456789abcdef"],
        ];
        for args in commands {
            let out = agent.run(args);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
            assert!(
                stderr.contains(&format!("speaks protocol {}", PROTOCOL_VERSION - 1))
                    && stderr.contains("restart the agent"),
                "{args:?}: {stderr}"
            );
            assert!(out.stdout.is_empty(), "{args:?}: {}", text(&out.stdout));
        }
        // Each asked for the version, and sent nothing else.
        assert_eq!(agent.requests().len(), commands.len());
        assert!(agent.sent().is_empty(), "{:?}", agent.sent());
    }

    #[test]
    fn doctor_without_an_agent_checks_the_broker_program_next_to_itself() {
        use std::os::unix::fs::PermissionsExt;
        // This rusthorse in a directory of its own — a hard link, in the
        // target directory so that one can be made — next to a broker
        // program of its version; nothing listens on the socket.
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical");
        let binary = root.join("rusthorse");
        if std::fs::hard_link(env!("CARGO_BIN_EXE_rusthorse"), &binary).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_rusthorse"), &binary).expect("copy");
        }
        let program = root.join(rusthorse::broker_protocol::PROGRAM);
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho '{{\"version\":\"{}\",\"protocol\":{}}}'\n",
                env!("CARGO_PKG_VERSION"),
                rusthorse::broker_protocol::VERSION
            ),
        )
        .expect("write");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        // Again while the program is busy: another test's child may hold it
        // open for writing until its exec ("Text file busy").
        let doctor = || {
            for _ in 0..50 {
                let out = Command::new(&binary)
                    .arg("doctor")
                    .env("RUSTHORSE_SOCKET", root.join("nobody.sock"))
                    .env("RUSTHORSE_VAULT", root.join("vault.kdbx"))
                    .env("RUSTHORSE_AUDIT_LOG", root.join("audit.jsonl"))
                    .stdin(Stdio::null())
                    .finish();
                let report = text(&out.stdout);
                if !report.contains("Text file busy") {
                    return (out.status.code(), report);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("the program stayed busy")
        };
        let ca_line = |installed: bool| match rusthorse::broker_protocol::open_ca_file() {
            Ok(ca) => format!(
                "  ok    the broker reads its certificate authorities from {}",
                ca.path.display()
            ),
            Err(why) => format!(
                "  {}  {why}: no grant",
                if installed { "FAIL" } else { "warn" }
            ),
        };

        let (code, report) = doctor();
        assert_eq!(
            code,
            Some(1),
            "an agent that does not answer fails: {report}"
        );
        assert!(
            report.contains(&format!(
                "  ok    broker: rusthorse-broker {} ({})\n",
                env!("CARGO_PKG_VERSION"),
                program.display()
            )),
            "{report}"
        );
        assert!(report.contains(&ca_line(true)), "{report}");
        // Nothing there: not installed, a warning that says where it was
        // looked for.
        std::fs::remove_file(&program).expect("remove");
        let (_, report) = doctor();
        assert!(
            report.contains(&format!(
                "  warn  {} is not installed: no grant of the credential broker can be served",
                program.display()
            )),
            "{report}"
        );
        assert!(report.contains(&ca_line(false)), "{report}");
    }
}
