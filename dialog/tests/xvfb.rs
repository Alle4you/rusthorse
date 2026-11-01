//! The dialog program's widgets, driven on a virtual display (Xvfb) with
//! xdotool: default button, Escape, keyboard approval, the approval gate,
//! the timeout and the password field. Never the real display: the program
//! gets only the virtual one. Skipped when xvfb-run or xdotool is missing.

#![allow(clippy::unwrap_used)] // test code

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusthorse::dialog_protocol::{self as wire, Answer, Dialog, Remember, Reply, Request};

/// One virtual display at a time: `xvfb-run -a` can race for a number.
static SERIAL: Mutex<()> = Mutex::new(());

const TITLE: &str = "Rusthorse dialog test";

fn tools_present() -> bool {
    let present = ["/usr/bin/xvfb-run", "/usr/bin/Xvfb", "/usr/bin/xdotool"]
        .iter()
        .all(|p| Path::new(p).exists());
    if !present {
        eprintln!("skipped: xvfb-run, Xvfb or xdotool is not installed");
    }
    present
}

fn approval(rows: usize, remember: bool, timeout_secs: u64) -> Request {
    Request {
        version: wire::VERSION,
        id: "test-id".into(),
        timeout_secs,
        title: TITLE.into(),
        dialog: Dialog::Approval {
            headline: "Run a command with your secrets?".into(),
            explanation: "Read the command before you allow it.".into(),
            warnings: vec!["A warning.".into()],
            command: Some("printf 'hello'".into()),
            details: (0..rows)
                .map(|i| (format!("Row {i}"), format!("value number {i}")))
                .collect(),
            facts: vec![("Input".into(), "none".into())],
            remember: remember.then(|| Remember {
                label: "Allow for 15m".into(),
                note: "A note about remembering.".into(),
            }),
        },
    }
}

fn entry() -> Request {
    Request {
        version: wire::VERSION,
        id: "test-id".into(),
        timeout_secs: 30,
        title: TITLE.into(),
        dialog: Dialog::Entry {
            headline: "Type the master password.".into(),
            explanation: String::new(),
            notice: None,
            details: vec![("Vault".into(), "/tmp/vault.kdbx".into())],
            field: "Master password".into(),
            confirm: "Unlock".into(),
        },
    }
}

/// Show `request` on a virtual display; once its window is up, run the
/// xdotool `actions` on it (for example `key Tab Return`; separate commands
/// with `;`, since `type` takes the rest of its command as text); return the
/// reply.
fn drive(request: &Request, actions: &str) -> Option<Reply> {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let runtime = tempfile::tempdir().unwrap();
    let (mut ours, theirs) = UnixStream::pair().unwrap();
    // A background job of a non-interactive shell reads /dev/null unless told
    // otherwise: the socket is handed over through descriptor 3. xvfb-run
    // sends the command's standard error to its standard output — the
    // socket — so everything but the dialog's answer goes to /dev/null.
    // The actions start 2 seconds after the window appears, once its layout
    // has opened the approval gate even on a busy machine (a human is never
    // faster). xdotool gets a time limit, and so does the dialog (its
    // timeout), so a test never hangs.
    let mut commands = actions.split(';').map(str::trim);
    let first = commands.next().unwrap_or_default();
    let rest: String = commands
        .map(|c| format!("timeout 30 xdotool {c} </dev/null >/dev/null 2>&1\n"))
        .collect();
    let script = format!(
        "exec 3<&0\n\
         \"$1\" <&3 3<&- 2>/dev/null & pid=$!\n\
         timeout 45 xdotool search --sync --onlyvisible --name '^{TITLE}$' windowfocus --sync sleep 2 \
         {first} </dev/null >/dev/null 2>&1\n\
         {rest}\
         wait $pid"
    );
    let mut cmd = Command::new("/usr/bin/xvfb-run");
    cmd.args([
        "-a",
        "-s",
        "-screen 0 1280x1024x24",
        "/bin/sh",
        "-c",
        &script,
        "sh",
    ])
    .arg(env!("CARGO_BIN_EXE_rusthorse-dialog"))
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .env("HOME", runtime.path())
    .env("XDG_RUNTIME_DIR", runtime.path())
    .env("GDK_BACKEND", "x11")
    .env("GSK_RENDERER", "cairo")
    .env("GSETTINGS_BACKEND", "memory")
    .stdin(Stdio::from(OwnedFd::from(theirs.try_clone().unwrap())))
    .stdout(Stdio::from(OwnedFd::from(theirs)))
    .stderr(Stdio::null());
    // Its own process group, so that a hung dialog can be stopped together
    // with the shell, xdotool and the virtual display.
    cmd.process_group(0);
    let child = cmd.spawn();
    drop(cmd);
    let mut child = child.unwrap();
    wire::write_frame(&mut ours, request, wire::MAX_REQUEST).unwrap();
    ours.shutdown(std::net::Shutdown::Write).unwrap();
    ours.set_read_timeout(Some(Duration::from_secs(75)))
        .unwrap();
    let reply = wire::read_frame(&mut ours, wire::MAX_ANSWER)
        .ok()
        .and_then(|body| wire::parse::<Answer>(&body).ok())
        .map(|answer| {
            assert_eq!(answer.id, "test-id");
            answer.reply
        });
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let group = format!("-{}", child.id());
            for signal in ["-TERM", "-KILL"] {
                let _ = Command::new("/bin/kill")
                    .args([signal, "--", &group])
                    .stderr(Stdio::null())
                    .status();
                std::thread::sleep(Duration::from_secs(1));
            }
            let _ = child.wait();
            panic!("the dialog did not finish; its processes were stopped (reply: {reply:?})");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    reply
}

#[test]
fn enter_and_escape_deny() {
    if !tools_present() {
        return;
    }
    assert_eq!(
        drive(&approval(3, false, 30), "key Return"),
        Some(Reply::Deny)
    );
    assert_eq!(
        drive(&approval(3, true, 30), "key Escape"),
        Some(Reply::Deny)
    );
}

#[test]
fn allow_can_be_chosen_with_the_keyboard_when_everything_fits() {
    if !tools_present() {
        return;
    }
    // From Deny, Tab reaches the next button: Allow once.
    assert_eq!(
        drive(&approval(3, false, 30), "key Tab Return"),
        Some(Reply::AllowOnce)
    );
    assert_eq!(
        drive(&approval(3, true, 30), "key Tab Return"),
        Some(Reply::AllowFor)
    );
}

#[test]
fn allow_waits_until_the_end_of_a_long_request_has_been_reached() {
    if !tools_present() {
        return;
    }
    // Too long to fit: Allow is disabled, so the same keys do not approve,
    // and the dialog still answers: Escape denies.
    assert_eq!(
        drive(&approval(80, false, 30), "key Tab Return; key Escape"),
        Some(Reply::Deny)
    );
    // Scrolled to the end with the mouse wheel, it can be approved.
    assert_eq!(
        drive(
            &approval(80, false, 30),
            "mousemove --window %1 330 300 click --repeat 120 --delay 5 5 sleep 0.5 key Tab Return"
        ),
        Some(Reply::AllowOnce)
    );
}

#[test]
fn an_unanswered_dialog_times_out() {
    if !tools_present() {
        return;
    }
    assert_eq!(
        drive(&approval(3, false, 1), "sleep 3"),
        Some(Reply::TimedOut)
    );
}

#[test]
fn the_password_field_has_the_focus_and_enter_submits() {
    if !tools_present() {
        return;
    }
    match drive(&entry(), "type --delay 40 s3cret; key Return") {
        Some(Reply::Typed { text }) => assert_eq!(text.as_str(), "s3cret"),
        other => panic!("{other:?}"),
    }
    assert_eq!(drive(&entry(), "key Escape"), Some(Reply::Cancel));
}
