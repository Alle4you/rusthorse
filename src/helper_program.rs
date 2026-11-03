//! Finding and checking the helper programs the agent starts, such as
//! `rusthorse-dialog` ([ADR 0006](../docs/adr/0006-own-dialog-program.md)) and
//! `rusthorse-broker` ([ADR 0013](../docs/adr/0013-credential-broker.md)).
//!
//! A helper is looked for next to the agent's own executable, by its file
//! name, and used only if, after resolving links, it is a regular, executable
//! file, owned by this user or root, that nobody else can modify. What a
//! missing helper means is for the caller to decide: dialogs fall back to
//! zenity, the broker has no fallback. `rusthorse doctor` also asks a helper
//! for its version and protocol ([`check_program`]).

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};

use crate::supervise::{Supervised, read_to_end_by};

/// What is where a helper program should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// A usable program, by its resolved path.
    Program(PathBuf),
    /// Nothing at that path, not even a broken link. What that means is for
    /// the caller to decide: dialogs fall back to zenity, the broker has no
    /// fallback.
    Absent(PathBuf),
    /// Something unusable, for this reason: the program is not used.
    Unusable(String),
}

/// Find the helper program `name` next to this process's executable. If that
/// executable was replaced or removed since the process started, nothing is
/// looked for: the directory may hold a newer, incompatible program.
pub fn locate(name: &str) -> Located {
    let exe = match fs::read_link("/proc/self/exe") {
        Ok(exe) => exe,
        Err(e) => return Located::Unusable(format!("cannot find the agent's own program: {e}")),
    };
    let running = crate::util::file_identity(Path::new("/proc/self/exe")).ok();
    if crate::util::replaced(&exe, running) == Some(true) {
        return Located::Unusable(
            "the agent's program was replaced or removed since it started; restart the agent \
             (`systemctl --user restart rusthorse-agent`)"
                .into(),
        );
    }
    match exe.parent() {
        Some(dir) => locate_in(dir, name),
        None => Located::Unusable(format!("{} has no directory", exe.display())),
    }
}

/// Find and check the helper program `name` in `dir`: [`check_file`] of
/// `dir/name`.
pub fn locate_in(dir: &Path, name: &str) -> Located {
    check_file(&dir.join(name))
}

/// Check the program at `path`: after resolving links, a regular, executable
/// file, owned by this user or root, that nobody else can modify: not
/// writable by its group or by others.
pub fn check_file(path: &Path) -> Located {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Located::Absent(path.to_path_buf());
        }
        Err(e) => return Located::Unusable(format!("cannot examine {}: {e}", path.display())),
        Ok(_) => {}
    }
    let real = match fs::canonicalize(path) {
        Ok(real) => real,
        Err(e) => return Located::Unusable(format!("cannot resolve {}: {e}", path.display())),
    };
    let meta = match fs::metadata(&real) {
        Ok(meta) => meta,
        Err(e) => return Located::Unusable(format!("cannot examine {}: {e}", real.display())),
    };
    let me = nix::unistd::geteuid().as_raw();
    let problem = if !meta.is_file() {
        Some("is not a regular file")
    } else if meta.mode() & 0o111 == 0 {
        Some("is not executable")
    } else if meta.uid() != me && meta.uid() != 0 {
        Some("belongs to another user")
    } else if meta.mode() & 0o022 != 0 {
        // Under the umask of Debian, Ubuntu and their derivatives (002),
        // `cargo install` leaves programs group-writable; whether the group
        // has other members cannot be established reliably (users who share
        // it as their primary group are not listed in it), so say how to fix
        // it instead.
        return Located::Unusable(format!(
            "{} can be modified by its group or by others; run `chmod go-w -- {}`",
            real.display(),
            crate::util::shell_quote(&real.to_string_lossy())
        ));
    } else {
        None
    };
    match problem {
        Some(problem) => Located::Unusable(format!("{} {problem}", real.display())),
        None => Located::Program(real),
    }
}

/// Run `program --check` with an empty environment and return the version
/// and protocol it reports, within `limit` for everything — its output, the
/// end of that output and its exit — under the same supervision as dialogs.
pub fn check_program(program: &Path, limit: Duration) -> anyhow::Result<(String, u32)> {
    #[derive(serde::Deserialize)]
    struct Report {
        version: String,
        protocol: u32,
    }
    let deadline = Instant::now() + limit;
    let (ours, theirs) = UnixStream::pair().context("cannot create a socket pair")?;
    let mut cmd = Command::new(program);
    cmd.arg("--check")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(theirs)))
        .stderr(Stdio::null());
    let child = Supervised::spawn(cmd)?;
    let output = read_to_end_by(&ours, 4096, deadline).map_err(|e| match e.kind() {
        io::ErrorKind::TimedOut => anyhow!("no complete answer to --check within {limit:?}"),
        _ => anyhow!("cannot read its answer to --check: {e}"),
    })?;
    match child.exit_by(deadline)? {
        Some(exit) if exit.success() => {}
        Some(exit) => bail!("--check failed ({exit})"),
        None => bail!("it did not exit within {limit:?}"),
    }
    let report: Report = serde_json::from_slice(&output).context("unexpected answer to --check")?;
    Ok((report.version, report.protocol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A helper's name in these tests.
    const NAME: &str = "rusthorse-helper-for-tests";

    #[test]
    fn the_check_run_by_doctor_is_bounded_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join(NAME);
        let write = |script: &str| {
            fs::write(&program, script).expect("write");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("chmod");
        };
        write("#!/bin/sh\necho '{\"version\":\"9.9\",\"protocol\":1}'\n");
        let checked = (0..50)
            .find_map(|_| match check_program(&program, Duration::from_secs(5)) {
                Err(e) if format!("{e:#}").contains("Text file busy") => {
                    std::thread::sleep(Duration::from_millis(20));
                    None
                }
                other => Some(other),
            })
            .expect("ran");
        assert_eq!(checked.expect("report"), ("9.9".to_string(), 1));
        // Its output held open by a descendant: no end, a bounded wait.
        write("#!/bin/sh\necho '{\"version\":\"9.9\",\"protocol\":1}'\n/bin/sleep 30 &\n");
        let started = Instant::now();
        let mut result = check_program(&program, Duration::from_millis(500));
        while matches!(&result, Err(e) if format!("{e:#}").contains("Text file busy")) {
            result = check_program(&program, Duration::from_millis(500));
        }
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_program_is_checked_before_it_is_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join(NAME);
        assert_eq!(
            locate_in(dir.path(), NAME),
            Located::Absent(program.clone())
        );
        assert_eq!(check_file(&program), Located::Absent(program.clone()));
        // A broken link is not "absent".
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &program).expect("symlink");
        assert!(matches!(locate_in(dir.path(), NAME), Located::Unusable(_)));
        fs::remove_file(&program).expect("rm");
        fs::create_dir(&program).expect("mkdir");
        assert!(matches!(locate_in(dir.path(), NAME), Located::Unusable(_)));
        fs::remove_dir(&program).expect("rmdir");
        fs::write(&program, "#!/bin/sh\n").expect("write");
        // The fix it suggests is a command that works on any path.
        let spaced = tempfile::tempdir().expect("tempdir");
        let dir_with_space = spaced.path().join("my tools");
        fs::create_dir(&dir_with_space).expect("mkdir");
        fs::write(dir_with_space.join(NAME), "#!/bin/sh\n").expect("write");
        fs::set_permissions(dir_with_space.join(NAME), fs::Permissions::from_mode(0o775))
            .expect("chmod");
        match locate_in(&dir_with_space, NAME) {
            Located::Unusable(why) => assert!(why.contains("`chmod go-w -- '"), "{why}"),
            other => panic!("{other:?}"),
        }
        for (mode, usable) in [
            (0o644, false),
            (0o775, false),
            (0o757, false),
            (0o777, false),
            (0o755, true),
        ] {
            fs::set_permissions(&program, fs::Permissions::from_mode(mode)).expect("chmod");
            let found = locate_in(dir.path(), NAME);
            assert_eq!(
                matches!(found, Located::Program(_)),
                usable,
                "{mode:o}: {found:?}"
            );
            assert_eq!(check_file(&program), found, "{mode:o}");
        }
        // A link to a good program resolves to it.
        let other = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(&program, other.path().join(NAME)).expect("symlink");
        let real = fs::canonicalize(&program).expect("canonical");
        assert_eq!(locate_in(other.path(), NAME), Located::Program(real));
        // Only that name counts.
        assert!(matches!(
            locate_in(dir.path(), "rusthorse-other-helper"),
            Located::Absent(_)
        ));
    }
}
