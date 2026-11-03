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
        )
    }

    fn build(
        idle_timeout: Duration,
        request_timeout: Duration,
        send_buffer: Option<usize>,
        session_lock: rusthorse::session_lock::Settings,
        keyring: rusthorse::keyring::Settings,
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
        };
        let listener = Agent::bind(&socket).expect("bind");
        let agent = Agent::new(config, Box::new(SharedUi(Arc::clone(&ui))));
        std::thread::spawn(move || agent.serve(listener));
        Harness {
            dir,
            socket,
            audit,
            ui,
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

    h.decide(&[Decision::AllowOnce]);
    assert!(h.run(&["remove", "B_KEY"]).status.success());
    let listing = text(&h.run(&["list"]).stdout);
    assert!(listing.contains("A_KEY") && !listing.contains("B_KEY"));
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.audit_text().contains("\"outcome\":\"exited\"") {
        assert!(
            Instant::now() < deadline,
            "the request stayed blocked after the client left"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.audit_text().contains("\"outcome\":\"exited\"") {
        assert!(
            Instant::now() < deadline,
            "the request stayed blocked after cancelling"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
        format!("#!/bin/sh\necho \"$1\" > {}\n", opened.display()),
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.audit_text().contains("\"outcome\":\"exited\"") {
        assert!(
            Instant::now() < deadline,
            "the request stayed pinned by unread acknowledgements"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

/// Whether the agent understood the request and refused it with
/// `invalid_request` (a request it cannot read gets that code too, with a
/// message that says so).
fn is_invalid(response: &rusthorse::protocol::Response) -> bool {
    matches!(
        response,
        rusthorse::protocol::Response::Error {
            code: rusthorse::protocol::ErrorCode::InvalidRequest,
            message,
        } if !message.starts_with("malformed request")
    )
}

/// A run with broker bindings starts nothing until the agent serves grants
/// (ADR 0013), and neither does a plain `run` that carries them: no dialog,
/// no command, no `run` record, and never the values instead.
#[test]
fn runs_with_broker_bindings_start_nothing_until_grants_are_served() {
    use rusthorse::client::{Client, RunIo};
    use rusthorse::protocol::{
        BrokerBinding, BrokerRunRequest, ErrorCode, Request, Response, read_message, send_frame,
    };
    use std::os::unix::net::UnixStream;
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.add_secret("KEY", "key-value-12345678", &[]);
    // Had the agent asked, the run would be allowed, and the command would
    // leave this file behind.
    h.decide(&[Decision::AllowOnce]);
    let marker = h.dir.path().join("ran");
    let script = format!("touch {}", marker.display());
    let argv = ["sh", "-c", script.as_str()];
    let brokered = vec![BrokerBinding {
        var: "KEY".into(),
        entry: "KEY".into(),
        url_var: Some("KEY_URL".into()),
    }];
    let client = Client::new(h.socket.clone());
    let sinks = || RunIo {
        input: None,
        stdout: Box::new(std::io::sink()),
        stderr: Box::new(std::io::sink()),
    };

    // A binding by value beside the broker binding, with redaction.
    let request = BrokerRunRequest {
        run: run_request(&h, &argv, false),
        brokered: brokered.clone(),
    };
    let response = client.broker_run_with(request, sinks()).expect("an answer");
    assert!(is_invalid(&response), "{}", response.kind());
    // Without redaction: the descriptors travel with the request, as with
    // `run`.
    let mut run = run_request(&h, &argv, false);
    run.redact = false;
    let request = BrokerRunRequest {
        run,
        brokered: brokered.clone(),
    };
    let response = client.broker_run(request).expect("an answer");
    assert!(is_invalid(&response), "{}", response.kind());
    // Through the broker only.
    let mut run = run_request(&h, &argv, false);
    run.bindings.clear();
    let request = BrokerRunRequest {
        run,
        brokered: brokered.clone(),
    };
    let response = client.broker_run_with(request, sinks()).expect("an answer");
    assert!(is_invalid(&response), "{}", response.kind());

    // A plain run that carries broker bindings is refused, not run without
    // them.
    let mut plain =
        serde_json::to_value(Request::Run(run_request(&h, &argv, false))).expect("json");
    plain["brokered"] = serde_json::to_value(&brokered).expect("json");
    let stream = UnixStream::connect(&h.socket).expect("connect");
    send_frame(&stream, &plain, &[]).expect("send");
    match read_message::<Response>(&stream).expect("an answer") {
        Response::Error {
            code: ErrorCode::InvalidRequest,
            message,
        } => assert!(message.contains("broker_run"), "{message}"),
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
}

/// Until the agent serves grants, it lists and revokes none, and says so.
/// Neither needs the vault, nor a dialog.
#[test]
fn grant_requests_are_refused_until_grants_are_served() {
    use rusthorse::protocol::Request;
    let h = Harness::new();
    for request in [
        Request::Grants,
        Request::RevokeGrant { id: None },
        Request::RevokeGrant {
            id: Some("g0123456789abcdef".into()),
        },
    ] {
        let response = h.call(&request);
        assert!(is_invalid(&response), "{}", response.kind());
    }
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(
        h.ui.password_prompts.lock().unwrap().is_empty(),
        "the vault was unlocked"
    );
}

/// A change to the broker profile is a request of its own, `broker_edit`
/// (ADR 0013): a plain `edit` that sets or clears the profile is refused
/// before any dialog, and nothing changes. Until the agent serves grants,
/// `broker_edit` clears a profile, once approved, and does not set one yet:
/// its dialog cannot show the profile.
#[test]
fn only_broker_edit_changes_the_broker_profile() {
    use rusthorse::broker_profile::{Preset, ProfileRequest};
    use rusthorse::protocol::{EntryChanges, ErrorCode, Field, NewEntry, Request, Response};
    let h = Harness::new();
    // An entry with a profile, written before the agent opens the vault.
    {
        let mut vault =
            Vault::open(&h.vault_path(), SecretString::new(PASSWORD.into())).expect("open");
        let entry = NewEntry {
            name: "KEY".into(),
            ..NewEntry::default()
        };
        let value = SecretString::new("key-value-12345678".into());
        vault.add(&entry, &value, false).expect("add");
        let id = vault.find("KEY").expect("find");
        let set = EntryChanges {
            broker: Some(ProfileRequest::new(Preset::Anthropic)),
            ..EntryChanges::default()
        };
        vault.edit(id, &set, None).expect("set the profile");
        vault.save().expect("save");
    }
    let on_disk = std::fs::read(h.vault_path()).expect("read");
    let set = || EntryChanges {
        username: Some("me".into()),
        broker: Some(ProfileRequest::new(Preset::Openai)),
        ..EntryChanges::default()
    };
    let clear = || EntryChanges {
        username: Some("me".into()),
        clear: vec![Field::Broker],
        ..EntryChanges::default()
    };

    // An edit that sets or clears the profile, with another change: an
    // older agent would make that change and drop the profile's.
    for changes in [set(), clear()] {
        let request = Request::Edit {
            name: "KEY".into(),
            changes,
        };
        match h.call(&request) {
            Response::Error {
                code: ErrorCode::InvalidRequest,
                message,
            } => assert!(message.contains("broker_edit"), "{message}"),
            other => panic!("unexpected {}", other.kind()),
        }
    }
    // Setting a profile waits for a dialog that can show it.
    let response = h.call(&Request::BrokerEdit {
        name: "KEY".into(),
        changes: set(),
    });
    assert!(is_invalid(&response), "{}", response.kind());
    // Refused before anything: no dialog, not even to unlock, no record,
    // the file as it was.
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    assert!(
        h.ui.password_prompts.lock().unwrap().is_empty(),
        "the vault was unlocked"
    );
    assert!(audit_outcomes(&h, "edit").is_empty());
    assert_eq!(std::fs::read(h.vault_path()).expect("read"), on_disk);

    // `broker_edit` clears it, with the rest of the edit, once approved.
    let show = || match h.call(&Request::Show { name: "KEY".into() }) {
        Response::Entry { entry } => entry,
        other => panic!("unexpected {}", other.kind()),
    };
    let anthropic = ProfileRequest::new(Preset::Anthropic)
        .resolve()
        .expect("profile");
    assert_eq!(show().broker, Some(anthropic));
    h.decide(&[Decision::AllowOnce]);
    let response = h.call(&Request::BrokerEdit {
        name: "KEY".into(),
        changes: clear(),
    });
    assert!(
        matches!(response, Response::Ok { .. }),
        "{}",
        response.kind()
    );
    assert_eq!(approval_detail(&h, "Clear").as_deref(), Some("broker"));
    assert_eq!(approval_detail(&h, "New username").as_deref(), Some("me"));
    let entry = show();
    assert_eq!(entry.broker, None);
    assert!(entry.other_fields.is_empty(), "{:?}", entry.other_fields);
    assert_eq!(entry.fields.username.as_deref(), Some("me"));
    assert_eq!(audit_outcomes(&h, "edit"), ["allowed_once"]);
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
        assert!(
            started.elapsed() < Duration::from_secs(3),
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
    use rusthorse::broker_profile::{AutomaticLocks, Preset, ProfileRequest};
    use rusthorse::protocol::{
        EntryFields, EntryInfo, ErrorCode, GrantInfo, PROTOCOL_VERSION, Request, Response,
        StatusInfo, recv_frame, send_frame,
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
            broker: Some(
                ProfileRequest::new(Preset::Anthropic)
                    .resolve()
                    .expect("profile"),
            ),
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

    /// A run with a binding by value, two broker bindings — one with the
    /// variable of the broker's address — and a `--url` of another entry,
    /// which still reads that entry's URL.
    const MIXED: &[&str] = &[
        "run",
        "DB_PASSWORD=db",
        "--broker",
        "ANTHROPIC_AUTH_TOKEN=AI/anthropic",
        "--broker",
        "OPENAI_API_KEY",
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
                entry: EntryInfo {
                    broker: None,
                    ..entry(
                        "11111111-2222-4333-8444-555555555555",
                        None,
                        "docs",
                        Some("https://docs.example.invalid/api"),
                    )
                },
            }),
            Request::Run(_) | Request::BrokerRun(_) => answer(),
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
        assert_eq!(types, ["status", "show", "broker_run"]);
        let (request, fds) = agent.sent().pop().expect("the run");
        assert_eq!(fds, 0, "with redaction, no descriptor goes with it");
        assert_eq!(
            request["bindings"],
            json!([{"var": "DB_PASSWORD", "entry": "db"}])
        );
        assert_eq!(
            request["brokered"],
            json!([
                {"var": "ANTHROPIC_AUTH_TOKEN", "entry": "AI/anthropic", "url_var": "ANTHROPIC_BASE_URL"},
                {"var": "OPENAI_API_KEY", "entry": "OPENAI_API_KEY"},
            ])
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
            let out = agent.run(&["run", option, "--broker", "T=k", "--", "true"]);
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
            let (request, fds) = agent.only_sent();
            assert_eq!(request["type"], "broker_run");
            assert_eq!(request["bindings"], json!([]), "through the broker only");
            assert_eq!(request["brokered"], json!([{"var": "T", "entry": "k"}]));
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
                Box::new(|| error(ErrorCode::InvalidRequest, "KEY has no broker profile")),
                125,
                "KEY has no broker profile",
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
                    })
                }),
                137,
                "",
            ),
            (Box::new(|| exited(3)), 3, ""),
        ];
        for (answer, expected, message) in cases {
            let agent = run_agent(answer);
            let out = agent.run(&["run", "--broker", "T=k", "--", "true"]);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(expected), "{stderr}");
            assert!(stderr.contains(message), "{stderr}");
            assert_eq!(agent.only_sent().0["type"], "broker_run");
        }
    }

    #[test]
    fn mistakes_in_broker_options_send_nothing() {
        let agent = FakeAgent::new(plain_status(), |request| {
            panic!("nothing should be sent, got {request:?}")
        });
        for (args, expected, message) in [
            // `run`: did not run.
            (
                &[
                    "run", "--broker", "K=x", "--url", "U=x", "--url", "V=x", "--", "true",
                ][..],
                125,
                "x already has --url U",
            ),
            (
                &["run", "--broker", "1K=x", "--", "true"][..],
                125,
                "not a valid environment variable name",
            ),
            (
                &["run", "--broker", "K=", "--", "true"][..],
                125,
                "missing entry name",
            ),
            (
                &["run", "X=x", "--broker", "K=x", "--", "true"][..],
                125,
                "also given by value",
            ),
            (
                &["run", "--broker", "K=x", "--broker", "L=x", "--", "true"][..],
                125,
                "already given to --broker",
            ),
            (
                &["run", "--broker", "LD_PRELOAD=x", "--", "true"][..],
                125,
                "cannot carry a token",
            ),
            (
                &["run", "--broker", "NO_PROXY=x", "--", "true"][..],
                125,
                "the agent adds 127.0.0.1 to this variable",
            ),
            (
                &[
                    "run",
                    "--broker",
                    "K=x",
                    "--url",
                    "no_proxy=x",
                    "--",
                    "true",
                ][..],
                125,
                "it cannot carry the broker's address",
            ),
            (
                &["run", "K=y", "--broker", "K=x", "--", "true"][..],
                125,
                "already set by another binding",
            ),
            // No secret and no --broker: a usage error.
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
            // `edit`: the profile's options need --broker, and a profile is
            // checked as the agent checks it.
            (
                &["edit", "KEY", "--broker-origin", "https://x.example"][..],
                2,
                "--broker <PRESET>",
            ),
            (
                &["edit", "KEY", "--broker-requests", "5"][..],
                2,
                "--broker <PRESET>",
            ),
            (
                &["edit", "KEY", "--broker", "gemini"][..],
                2,
                "invalid value 'gemini'",
            ),
            (
                &["edit", "KEY", "--broker", "anthropic", "--clear", "broker"][..],
                1,
                "give one of them",
            ),
            (
                &["edit", "KEY", "--broker", "openai-compatible"][..],
                1,
                "no default origin",
            ),
            (
                &[
                    "edit",
                    "KEY",
                    "--broker",
                    "openai",
                    "--broker-origin",
                    "https://127.0.0.1",
                ][..],
                1,
                "not an IP address",
            ),
            (
                &[
                    "edit",
                    "KEY",
                    "--broker",
                    "anthropic",
                    "--broker-lifetime",
                    "0",
                ][..],
                1,
                "1 to 1440 minutes",
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
                "ANTHROPIC_AUTH_TOKEN=AI/anthropic",
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

    #[test]
    fn an_edit_that_touches_the_profile_is_a_broker_edit() {
        let answers = Arc::new(Mutex::new(VecDeque::new()));
        let queue = Arc::clone(&answers);
        let agent = FakeAgent::new(plain_status(), move |request| {
            assert!(
                matches!(request, Request::Edit { .. } | Request::BrokerEdit { .. }),
                "{request:?}"
            );
            queue.lock().unwrap().pop_front().expect("an answer")
        });
        let edit = |args: &[&str], answer: Option<Response>| {
            answers.lock().unwrap().push_back(answer);
            let mut argv = vec!["edit", "KEY"];
            argv.extend(args);
            let out = agent.run(&argv);
            (out, agent.sent().pop().expect("a request").0)
        };

        // A profile, with only the options given (the agent fills in the
        // defaults), and another change beside it.
        let (out, request) = edit(
            &[
                "--username",
                "me",
                "--broker",
                "openai-compatible",
                "--broker-origin",
                "https://api.deepseek.com",
                "--broker-requests",
                "200",
            ],
            ok("changed KEY"),
        );
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("changed KEY"));
        assert_eq!(request["type"], "broker_edit");
        assert_eq!(request["name"], "KEY");
        assert_eq!(request["changes"]["username"], "me");
        assert_eq!(
            request["changes"]["broker"],
            json!({"preset": "openai-compatible", "origin": "https://api.deepseek.com", "max_requests": 200})
        );
        // Every option.
        let (out, request) = edit(
            &[
                "--broker",
                "anthropic",
                "--broker-origin",
                "https://gateway.example.com:8443",
                "--broker-base-path",
                "",
                "--broker-locks",
                "end",
                "--broker-lifetime",
                "15",
            ],
            ok("changed KEY"),
        );
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(
            request["changes"]["broker"],
            json!({
                "preset": "anthropic",
                "origin": "https://gateway.example.com:8443",
                "base_path": "",
                "automatic_locks": "end",
                "max_lifetime_minutes": 15,
            })
        );
        // Clearing it.
        let (out, request) = edit(&["--clear", "broker", "--clear", "port"], ok("changed KEY"));
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(request["type"], "broker_edit");
        assert_eq!(request["changes"]["clear"], json!(["broker", "port"]));
        assert!(request["changes"].get("broker").is_none(), "{request}");
        // Any other edit is a plain edit, as before.
        let (out, request) = edit(&["--username", "me", "--clear", "kind"], ok("changed KEY"));
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(request["type"], "edit");
        assert!(request["changes"].get("broker").is_none(), "{request}");
        // Its answers mean what they mean for an edit.
        for (answer, expected) in [
            (error(ErrorCode::Denied, "denied"), 4),
            (error(ErrorCode::Cancelled, "cancelled"), 4),
            (error(ErrorCode::InvalidRequest, "broker profile: …"), 1),
            (error(ErrorCode::OutcomeUnknown, "not durable"), 124),
            (None, 124),
        ] {
            let (out, request) = edit(&["--broker", "anthropic"], answer);
            assert_eq!(out.status.code(), Some(expected), "{}", text(&out.stderr));
            assert_eq!(request["type"], "broker_edit");
        }
    }

    fn grant(id: &str) -> GrantInfo {
        GrantInfo {
            id: id.into(),
            entry: "AI/anthropic (8d2f6c1e)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            destination: "https://api.anthropic.com".into(),
            preset: Preset::Anthropic,
            command: "claude".into(),
            requester: "rusthorse[4300] ← bash[4242]".into(),
            state: "active".into(),
            started: "2026-11-02T18:00:00-03:00".into(),
            ends_in_secs: 3600,
            requests: 3,
            max_requests: Some(200),
            in_flight: 1,
            automatic_locks: AutomaticLocks::Continue,
        }
    }

    #[test]
    fn grants_are_listed_and_revoked_without_approval() {
        let listed = vec![grant("g0123456789abcdef"), grant("gfedcba9876543210")];
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
        for cell in [
            "g0123456789abcdef",
            "AI/anthropic (8d2f6c1e)",
            "https://api.anthropic.com",
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
        assert!(shown.contains("grants:     2 active\n"), "{shown}");
        let out = agent.run(&["status", "--json"]);
        let json: Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(json["broker"], "/opt/rusthorse/rusthorse-broker");
        assert_eq!(json["grants"], 2);
        // An agent that does not report them: nothing about them.
        let agent = FakeAgent::new(plain_status(), |request| panic!("unexpected {request:?}"));
        let shown = text(&agent.run(&["status"]).stdout);
        assert!(
            !shown.contains("broker:") && !shown.contains("grants:"),
            "{shown}"
        );
    }

    #[test]
    fn list_and_show_carry_the_broker_profile() {
        let with_profile = entry(
            "8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12",
            Some("AI"),
            "anthropic",
            None,
        );
        let profile =
            serde_json::to_value(with_profile.broker.as_ref().expect("a profile")).expect("json");
        // How the agent reports a stored profile it cannot read.
        let unusable = EntryInfo {
            id: "11111111-2222-4333-8444-555555555555".into(),
            name: "broken".into(),
            other_fields: vec![rusthorse::vault::FIELD_BROKER.into()],
            broker: None,
            ..with_profile.clone()
        };
        let listed = vec![with_profile.clone(), unusable.clone()];
        let agent = FakeAgent::new(plain_status(), move |request| match request {
            Request::List => Some(Response::Entries {
                entries: listed.clone(),
            }),
            Request::Show { name } if name == "anthropic" => Some(Response::Entry {
                entry: with_profile.clone(),
            }),
            Request::Show { name } if name == "broken" => Some(Response::Entry {
                entry: unusable.clone(),
            }),
            other => panic!("unexpected {other:?}"),
        });
        // The JSON carries the profile as the agent reports it.
        let out = agent.run(&["list", "--json"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let json: Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(json[0]["broker"], profile);
        assert!(json[1].get("broker").is_none(), "{json}");
        assert_eq!(json[1]["other_fields"], json!(["Rusthorse.Broker"]));
        let out = agent.run(&["show", "anthropic", "--json"]);
        let json: Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(json["broker"], profile);
        // The text says what a grant allows, or why there can be none.
        let out = agent.run(&["show", "anthropic"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let shown = text(&out.stdout);
        assert!(
            shown.contains(
                "broker:     anthropic preset, revision 1\n            Destination: \
                 https://api.anthropic.com\n            Allows: POST /v1/messages, "
            ),
            "{shown}"
        );
        let shown = text(&agent.run(&["show", "broken"]).stdout);
        assert!(shown.contains("fields:     Rusthorse.Broker\n"), "{shown}");
        assert!(shown.contains("broker:     unusable: "), "{shown}");
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
                    "  ok    the broker trusts the certificate authorities in {}\n",
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
        run.grants = Some(vec![AuditGrant {
            id: id.into(),
            entry: "AI/anthropic (8d2f6c1e)".into(),
            destination: "https://api.anthropic.com".into(),
        }]);
        let mut admitted = AuditEvent::new("broker_request", &agent).outcome("admitted");
        admitted.grant = Some(id.into());
        admitted.request = Some(1);
        admitted.route = Some("POST /v1/messages".into());
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
            " grants: g0123456789abcdef for AI/anthropic (8d2f6c1e) to https://api.anthropic.com; $ claude",
            "broker_request admitted",
            " grant g0123456789abcdef #1 POST /v1/messages  by ",
            " grant g0123456789abcdef #1 status 200 (120 bytes sent, 4096 received)  by ",
            " reason: command_ended requests: 1 admitted (1 finished, 0 unknown), 2 refused",
        ] {
            assert!(shown.contains(part), "{part}: {shown}");
        }
        // The JSON is the records as they are.
        let out = audit(&["audit", "-n", "10", "--json"]);
        assert_eq!(text(&out.stdout), lines);
    }
}
