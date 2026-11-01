//! The real program, on a virtual display: a termination signal ends it
//! through the normal shutdown, which wipes shown and copied values.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_termination_signal_quits_through_the_normal_shutdown() {
    let dir = tempfile::tempdir().expect("isolated runtime");
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private runtime directory");
    // sh is the manager's parent: it signals it and reports how it ended.
    let script = r#""$1" & pid=$!; sleep 3; kill -TERM "$pid"; wait "$pid"; echo "exit=$?""#;
    let mut child = Command::new("/usr/bin/xvfb-run")
        .args([
            "-a",
            "/usr/bin/dbus-run-session",
            "--",
            "/bin/sh",
            "-c",
            script,
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_rusthorse-manager"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", dir.path())
        .env("TMPDIR", dir.path())
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        // No agent answers here: the window shows "Unavailable" and waits.
        .env("RUSTHORSE_SOCKET", dir.path().join("no-agent.sock"))
        .env("GDK_BACKEND", "x11")
        .env("GSK_RENDERER", "cairo")
        .env("GSETTINGS_BACKEND", "memory")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("xvfb-run and dbus-run-session required");
    let until = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() >= until {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .status();
            let _ = child.wait();
            panic!("the manager did not quit after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("output");
    let text = String::from_utf8_lossy(&output.stdout);
    // 143 (128 + SIGTERM) would mean the signal killed it outright.
    assert!(text.contains("exit=0"), "{text}");
}
