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
            .env("RUSTHORSE_VAULT", self.dir.path().join("vault.kdbx"))
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
    // Dry run: names and their status, nothing imported, nothing asked.
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
    assert_eq!(h.ui.approvals_asked.load(Ordering::SeqCst), 0);
    // Real run: several batches, one approval each, everything imported.
    h.decide(&[Decision::AllowOnce; 10]);
    let out = h.run(&["import", "dotenv", env_file.to_str().expect("utf8")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(h.ui.approvals_asked.load(Ordering::SeqCst) >= 2);
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
    assert!(request.summary.contains("REVEAL the notes"));
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
    fake.join().expect("fake agent");
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
    fake.join().expect("fake");
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
    // An agent speaking an older protocol.
    let socket = dir.path().join("old.sock");
    let fake = fake_agent(&socket, 1, None, 2);
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
    let h = Harness::new();
    h.add_secret("T", "abcdefgh", &[]);
    h.decide(&[Decision::AllowOnce]);
    let stream = raw_run(&h, &["head", "-c", "1000"], true);
    let sender = stream.try_clone().expect("clone");
    within(Duration::from_secs(20), move || {
        for _ in 0..1000 {
            rusthorse::protocol::send_data(&sender, rusthorse::protocol::STDIN, b"x")
                .expect("the agent stopped reading the connection");
        }
    });
    // The command has read its 1000 bytes and exited; acknowledgements were
    // never read. A half-close must still end the request.
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
