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
    /// Runs (once) while the "human" is looking at the next approval dialog.
    on_approve: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Runs (once) while the "human" is typing the next master password.
    on_password: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Ui for ScriptedUi {
    fn master_password(&self, _: &Prompt) -> anyhow::Result<Option<SecretString>> {
        if let Some(hook) = self.on_password.lock().unwrap().take() {
            hook();
        }
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
        Harness::with_timeouts(Duration::ZERO, Duration::from_secs(10))
    }

    fn with_idle_timeout(idle_timeout: Duration) -> Harness {
        Harness::with_timeouts(idle_timeout, Duration::from_secs(10))
    }

    fn with_timeouts(idle_timeout: Duration, request_timeout: Duration) -> Harness {
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
    let h = Harness::new();
    let env_file = h.dir.path().join("many.env");
    let lines: String = (0..60)
        .map(|i| format!("A_VERY_LONG_VARIABLE_NAME_FOR_TESTING_THE_DIALOG_LIMIT_NUMBER_{i:03}_XXXXXXXX=value{i}\n"))
        .collect();
    std::fs::write(&env_file, lines).expect("write");
    assert!(h.run(&["unlock"]).status.success());
    let out = h.run(&["import", "dotenv", env_file.to_str().expect("utf8")]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("too much detail"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
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

#[test]
fn read_only_requests_do_not_keep_the_vault_unlocked() {
    let h = Harness::with_idle_timeout(Duration::from_secs(2));
    h.add_secret("T", "abcdefgh", &[]);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(4) {
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

/// Whether a process exists and is not a zombie.
fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat
                .rfind(')')
                .and_then(|i| stat.get(i + 2..i + 3))
                .unwrap_or("Z");
            state != "Z" && state != "X"
        }
        Err(_) => false,
    }
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
