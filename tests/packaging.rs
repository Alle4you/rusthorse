//! The files that installations put on the system agree with each other.

use std::fs;
use std::path::Path;

/// The directives of a systemd unit file: its lines without blank lines and
/// comments.
fn directives(relative: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect()
}

fn split_exec(lines: Vec<String>) -> (Vec<String>, Vec<String>) {
    lines
        .into_iter()
        .partition(|line| line.starts_with("ExecStart="))
}

#[test]
fn the_packaged_service_differs_from_the_cargo_one_only_in_the_program_path() {
    let (cargo_exec, cargo) = split_exec(directives("contrib/systemd/rusthorse-agent.service"));
    let (deb_exec, deb) = split_exec(directives("packaging/deb/rusthorse-agent.service"));
    assert_eq!(cargo, deb, "the two service files have different settings");
    assert_eq!(cargo_exec, ["ExecStart=%h/.cargo/bin/rusthorse agent"]);
    assert_eq!(deb_exec, ["ExecStart=/usr/bin/rusthorse agent"]);
}

#[test]
fn the_service_gives_the_socket_a_private_directory_that_goes_away_with_the_agent() {
    // The default socket is $XDG_RUNTIME_DIR/rusthorse/agent.sock; systemd
    // creates %t/rusthorse when the agent starts and removes it when it stops.
    let service = directives("packaging/deb/rusthorse-agent.service");
    for expected in ["RuntimeDirectory=rusthorse", "RuntimeDirectoryMode=0700"] {
        assert!(
            service.iter().any(|line| line == expected),
            "missing {expected}"
        );
    }
}

// The maintainer scripts, run as dpkg would run them. Stand-ins for
// `loginctl`, `id` and `systemctl` record what the scripts ask; nothing
// reaches the computer's real services.

use std::path::PathBuf;
use std::process::{Command, Output};

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packaging/deb")
        .join(name)
}

/// A directory of stand-ins. `loginctl` lists the users of the file `users`
/// (or fails when `loginctl.fails` exists); `id -nu UID` answers `userUID`;
/// `systemctl` writes its arguments to `calls` and answers `is-active` with
/// the number in `active-USER` (3, "not running", by default) and `stop`
/// with the one in `stop-USER` (0 by default).
struct Fakes(tempfile::TempDir);

impl Fakes {
    fn new() -> Fakes {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = |name: &str, body: &str| {
            let path = dir.path().join(name);
            fs::write(
                &path,
                format!("#!/bin/sh\nF={}\n{body}", dir.path().display()),
            )
            .expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        };
        tool(
            "loginctl",
            "[ -e \"$F/loginctl.fails\" ] && exit 1\ncat \"$F/users\" 2>/dev/null\nexit 0\n",
        );
        tool("id", "echo \"user$2\"\n");
        tool(
            "systemctl",
            "echo \"$*\" >> \"$F/calls\"\n\
             user=$(echo \"$*\" | sed -n 's/.*--machine=\\([^@]*\\)@.*/\\1/p')\n\
             case \"$*\" in\n\
             *is-active*) exit \"$(cat \"$F/active-$user\" 2>/dev/null || echo 3)\" ;;\n\
             *' stop '*) exit \"$(cat \"$F/stop-$user\" 2>/dev/null || echo 0)\" ;;\n\
             esac\n",
        );
        Fakes(dir)
    }

    fn set(&self, file: &str, content: &str) {
        fs::write(self.0.path().join(file), content).expect("write");
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.0.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    fn run(&self, name: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new("/bin/sh")
            .arg(script(name))
            .args(args)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.0.path().display()))
            .envs(env.iter().copied())
            .output()
            .expect("run the script")
    }
}

/// `prerm` stops agents only where systemd runs; elsewhere there is nothing
/// to test.
fn systemd_runs() -> bool {
    let runs = Path::new("/run/systemd/system").is_dir();
    if !runs {
        eprintln!("skipped: systemd is not running here");
    }
    runs
}

#[test]
fn removal_stops_the_running_agents_and_says_which_it_cannot() {
    if !systemd_runs() {
        return;
    }
    let f = Fakes::new();
    f.set(
        "users",
        "1001 a no active\n1002 b no active\n1003 c no active\n1004 d no active\n",
    );
    f.set("active-user1001", "0"); // running; stops
    f.set("active-user1002", "3"); // not running
    f.set("active-user1003", "1"); // its session does not answer
    f.set("active-user1004", "0"); // running, but will not stop
    f.set("stop-user1004", "1");
    let out = f.run("prerm", &["remove"], &[]);
    assert!(out.status.success());
    let unit = "rusthorse-agent.service";
    let ask = |n: u32| format!("--user --machine=user{n}@ is-active --quiet {unit}");
    let stop = |n: u32| format!("--user --machine=user{n}@ stop {unit}");
    assert_eq!(
        f.calls(),
        [
            ask(1001),
            stop(1001),
            ask(1002),
            ask(1003),
            ask(1004),
            stop(1004)
        ]
    );
    let warnings = String::from_utf8_lossy(&out.stderr);
    assert!(!warnings.contains("user1001"), "{warnings}");
    assert!(!warnings.contains("user1002"), "{warnings}");
    assert!(
        warnings.contains("cannot ask the session of user1003"),
        "{warnings}"
    );
    assert!(
        warnings.contains("cannot stop the agent of user1004"),
        "{warnings}"
    );
}

#[test]
fn removal_says_so_when_it_cannot_list_the_users() {
    if !systemd_runs() {
        return;
    }
    let f = Fakes::new();
    f.set("loginctl.fails", "");
    let out = f.run("prerm", &["remove"], &[]);
    assert!(out.status.success());
    assert!(f.calls().is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot list the users"));
}

#[test]
fn upgrades_and_other_roots_stop_nothing() {
    let f = Fakes::new();
    f.set("users", "1001 a no active\n");
    f.set("active-user1001", "0");
    for (args, env) in [
        (&["upgrade", "0.1.0-1"][..], &[][..]),
        (&["remove"][..], &[("DPKG_ROOT", "/srv/image")][..]),
    ] {
        let out = f.run("prerm", args, env);
        assert!(out.status.success(), "{args:?}");
        assert!(f.calls().is_empty(), "{args:?} {env:?}: {:?}", f.calls());
        assert!(out.stderr.is_empty(), "{args:?}");
    }
}

/// Install, upgrade, remove and purge in a temporary root (`DPKG_ROOT`),
/// with the real deb-systemd-helper, which works only on files there.
#[test]
fn enabling_follows_the_administrator_and_purge_leaves_nothing() {
    let helper = Path::new("/usr/bin/deb-systemd-helper");
    if !helper.exists() || !Path::new("/usr/bin/systemctl").exists() {
        eprintln!("skipped: no deb-systemd-helper or systemctl here");
        return;
    }
    let root = tempfile::tempdir().expect("root");
    let units = root.path().join("usr/lib/systemd/user");
    let install = || {
        fs::create_dir_all(&units).expect("mkdir");
        fs::copy(
            script("rusthorse-agent.service"),
            units.join("rusthorse-agent.service"),
        )
        .expect("copy the service");
    };
    let link = root
        .path()
        .join("etc/systemd/user/default.target.wants/rusthorse-agent.service");
    let run = |name: &str, args: &[&str]| {
        let out = Command::new("/bin/sh")
            .arg(script(name))
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("DPKG_ROOT", root.path())
            .env("DPKG_MAINTSCRIPT_PACKAGE", "rusthorse")
            .env("DPKG_MAINTSCRIPT_NAME", name)
            .output()
            .expect("run");
        assert!(out.status.success(), "{name} {args:?}: {out:?}");
    };
    let global = |verb: &str| {
        let status = Command::new("/usr/bin/systemctl")
            .arg(format!("--root={}", root.path().display()))
            .args(["--global", verb, "rusthorse-agent.service"])
            .output()
            .expect("systemctl --root");
        assert!(status.status.success(), "{status:?}");
    };

    install();
    run("postinst", &["configure"]);
    assert!(
        link.is_symlink(),
        "a first installation enables the service"
    );
    // The administrator disables it: an upgrade keeps it disabled.
    global("disable");
    run("postinst", &["configure", "0.1.0-1"]);
    assert!(!link.is_symlink(), "an upgrade enabled a disabled service");
    global("enable");
    run("postinst", &["configure", "0.1.0-1"]);
    assert!(link.is_symlink());
    // Remove keeps the choice; installing again keeps it.
    fs::remove_dir_all(root.path().join("usr")).expect("remove the files");
    run("postrm", &["remove"]);
    assert!(
        link.is_symlink(),
        "remove forgot that the service was enabled"
    );
    install();
    run("postinst", &["configure", "0.1.0-1"]);
    assert!(link.is_symlink());
    // Purge leaves no link and no state.
    fs::remove_dir_all(root.path().join("usr")).expect("remove the files");
    run("postrm", &["remove"]);
    run("postrm", &["purge"]);
    let left: Vec<_> = walk(root.path())
        .into_iter()
        .filter(|p| p.is_file() || p.is_symlink())
        .collect();
    assert!(left.is_empty(), "left after purge: {left:?}");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        let path = entry.path();
        if path.is_dir() && !path.is_symlink() {
            out.extend(walk(&path));
        }
        out.push(path);
    }
    out
}
