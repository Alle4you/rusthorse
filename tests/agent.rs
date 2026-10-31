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
use rusthorse::ui::{ApprovalRequest, Decision, Prompt, Ui};
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
}

impl Ui for ScriptedUi {
    fn master_password(&self, _: &Prompt) -> anyhow::Result<Option<SecretString>> {
        let next = self.passwords.lock().unwrap().pop_front();
        Ok(next
            .unwrap_or(Some(PASSWORD.to_string()))
            .map(SecretString::new))
    }

    fn secret_value(&self, _: &Prompt) -> anyhow::Result<Option<SecretString>> {
        let next = self.values.lock().unwrap().pop_front().flatten();
        Ok(next.map(SecretString::new))
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.approvals_asked.fetch_add(1, Ordering::SeqCst);
        *self.last_approval.lock().unwrap() = Some(request.clone());
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
    fn master_password(&self, p: &Prompt) -> anyhow::Result<Option<SecretString>> {
        self.0.master_password(p)
    }
    fn secret_value(&self, p: &Prompt) -> anyhow::Result<Option<SecretString>> {
        self.0.secret_value(p)
    }
    fn approve(&self, r: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.0.approve(r)
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
            idle_timeout: Duration::ZERO,
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
            .current_dir(self.dir.path())
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("run rusthorse")
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
        child.wait_with_output().expect("wait")
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

    fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit).unwrap_or_default()
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
        details.iter().any(|d| d == "Secrets: API_KEY ← API_KEY"),
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
        .output()
        .expect("run");
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
    h.decide(&[Decision::AllowOnce]);
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
        assert!(Instant::now() < deadline, "the command outlived its client");
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
