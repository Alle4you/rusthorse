//! The files that installations put on the system agree with each other,
//! and the Debian package holds what it should: every program of the
//! workspace, never a credential broker built for tests, and the licenses
//! of every crate compiled in.

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
///
/// They are written by another process (`write_program`): one that this
/// process held open for writing could not be run while a child forked
/// meanwhile by another test held that descriptor, and the shell would then
/// run the next one on PATH, the real `/usr/bin/systemctl` included.
struct Fakes(tempfile::TempDir);

impl Fakes {
    fn new() -> Fakes {
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = |name: &str, body: &str| {
            write_program(
                &dir.path().join(name),
                &format!("#!/bin/sh\nF={}\n{body}", dir.path().display()),
            );
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

// What the package holds and how it is built: Cargo.toml read through
// `cargo metadata`, and the scripts of packaging/ run as build-deb.sh runs
// them, on stand-ins where a real build would be needed.

use std::collections::BTreeSet;

use serde_json::Value;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// What `cargo ARGS` prints in the repository; it must succeed.
fn cargo(args: &[&str]) -> String {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args(args)
        .current_dir(root())
        .output()
        .expect("run cargo");
    assert!(
        out.status.success(),
        "cargo {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("UTF-8")
}

/// `cargo metadata` of the workspace's own packages.
fn workspace() -> Value {
    serde_json::from_str(&cargo(&[
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--locked",
    ]))
    .expect("JSON")
}

/// The names of the packages that `meta[key]` lists by ID.
fn package_names(meta: &Value, key: &str) -> BTreeSet<String> {
    let ids: BTreeSet<&str> = meta[key]
        .as_array()
        .expect(key)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|p| ids.contains(p["id"].as_str().unwrap_or_default()))
        .map(|p| p["name"].as_str().expect("name").to_string())
        .collect()
}

/// The programs of the workspace: the binaries of its members.
fn programs(meta: &Value) -> BTreeSet<String> {
    meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .flat_map(|p| p["targets"].as_array().expect("targets"))
        .filter(|t| {
            t["kind"]
                .as_array()
                .is_some_and(|k| k.contains(&"bin".into()))
        })
        .map(|t| t["name"].as_str().expect("name").to_string())
        .collect()
}

/// The workspace's package `name`, as `cargo metadata` describes it.
fn package<'a>(meta: &'a Value, name: &str) -> &'a Value {
    meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("no package {name}"))
}

/// What the Debian package installs: `[source, destination, mode]`.
fn assets(meta: &Value) -> Vec<[String; 3]> {
    package(meta, "rusthorse")["metadata"]["deb"]["assets"]
        .as_array()
        .expect("assets")
        .iter()
        .map(|asset| {
            let field = |i: usize| asset[i].as_str().expect("a string").to_string();
            [field(0), field(1), field(2)]
        })
        .collect()
}

#[test]
fn plain_cargo_commands_cover_the_credential_broker() {
    // The checks of AGENTS.md and the CI's are plain cargo commands: they
    // build, lint, test and document the default members. The dialog and
    // the manager need GTK and are named with -p.
    let meta = workspace();
    assert_eq!(
        package_names(&meta, "workspace_default_members"),
        BTreeSet::from(["rusthorse".to_string(), "rusthorse-broker".to_string()])
    );
    let members = package_names(&meta, "workspace_members");
    for gtk in ["rusthorse-dialog", "rusthorse-manager"] {
        assert!(members.contains(gtk), "{members:?}");
    }
    // Two default members have programs: `cargo run -- ARGS` (as in
    // CONTRIBUTING.md) needs to be told which one to run.
    assert_eq!(package(&meta, "rusthorse")["default_run"], "rusthorse");
}

#[test]
fn the_package_installs_every_program_of_the_workspace() {
    let meta = workspace();
    let programs = programs(&meta);
    assert!(programs.contains("rusthorse-broker"), "{programs:?}");
    let mut packaged = BTreeSet::new();
    for [source, destination, mode] in assets(&meta) {
        match source.strip_prefix("target/release/") {
            // Written there by build-deb.sh: completions, copyright, docs.
            Some(generated) if generated.starts_with("packaging/") => {}
            Some(program) => {
                assert_eq!(
                    [destination.as_str(), mode.as_str()],
                    ["usr/bin/", "755"],
                    "{source}"
                );
                packaged.insert(program.to_string());
            }
            None => assert!(root().join(&source).is_file(), "{source} does not exist"),
        }
    }
    assert_eq!(packaged, programs);
}

#[test]
fn the_packaged_service_starts_a_packaged_program() {
    let assets = assets(&workspace());
    let installed = |source: &str, destination: &str, mode: &str| {
        assets
            .iter()
            .any(|asset| asset == &[source, destination, mode].map(String::from))
    };
    assert!(installed(
        "packaging/deb/rusthorse-agent.service",
        "usr/lib/systemd/user/",
        "644"
    ));
    let (exec, _) = split_exec(directives("packaging/deb/rusthorse-agent.service"));
    let program = exec
        .first()
        .and_then(|line| line.strip_prefix("ExecStart="))
        .and_then(|command| command.split_whitespace().next())
        .expect("ExecStart");
    let name = program
        .strip_prefix("/usr/bin/")
        .expect("a program in /usr/bin");
    assert!(
        installed(&format!("target/release/{name}"), "usr/bin/", "755"),
        "{program}"
    );
}

/// The features for tests only, never in a release: the main package's
/// fake Secret Service and the broker's hooks for its tests (extra
/// certificate authorities and loopback destinations).
const FOR_TESTS: [&str; 2] = ["fake-keyring", "test-upstream"];

#[test]
fn no_release_build_turns_on_a_feature_for_tests() {
    // build-deb.sh names no feature (above); nor may what a release build
    // reads in the manifests: the packages' default features and the normal
    // and build dependencies between them. Dev-dependencies may, since no
    // release builds them.
    let meta = workspace();
    let packages = meta["packages"].as_array().expect("packages");
    for feature in FOR_TESTS {
        assert!(
            packages
                .iter()
                .any(|p| p["features"].get(feature).is_some()),
            "no package has the feature {feature} any more: update FOR_TESTS"
        );
    }
    for package in packages {
        let name = package["name"].as_str().expect("name");
        let features = package["features"].as_object().expect("features");
        // What `default` turns on, through the package's own features; a
        // `crate/feature` or `crate?/feature` turns on a dependency's.
        let mut on = vec!["default"];
        let mut seen = BTreeSet::new();
        while let Some(feature) = on.pop() {
            if !seen.insert(feature) {
                continue;
            }
            let named = feature.rsplit('/').next().unwrap_or(feature);
            assert!(
                !FOR_TESTS.contains(&named),
                "the default features of {name} turn on {feature}"
            );
            if let Some(more) = features.get(feature).and_then(Value::as_array) {
                on.extend(more.iter().filter_map(Value::as_str));
            }
        }
        for dependency in package["dependencies"].as_array().expect("dependencies") {
            if dependency["kind"] == "dev" {
                continue;
            }
            for feature in dependency["features"].as_array().expect("features") {
                assert!(
                    !FOR_TESTS.contains(&feature.as_str().expect("a feature")),
                    "{name} turns on {feature} of {}",
                    dependency["name"]
                );
            }
        }
    }
    // What cargo-deb would build with, were it to build.
    let deb = &package(&meta, "rusthorse")["metadata"]["deb"];
    for feature in deb["features"].as_array().into_iter().flatten() {
        assert!(
            !FOR_TESTS.contains(&feature.as_str().unwrap_or_default()),
            "{deb}"
        );
    }
}

#[test]
fn the_package_recommends_the_certificate_authorities_the_broker_trusts() {
    // The broker reads /etc/ssl/certs/ca-certificates.crt, which
    // ca-certificates installs. Without it no grant can be served and
    // nothing else changes, hence a recommendation (which apt installs by
    // default) rather than a dependency.
    let meta = workspace();
    let deb = &package(&meta, "rusthorse")["metadata"]["deb"];
    let recommends: Vec<&str> = deb["recommends"]
        .as_str()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .collect();
    assert!(recommends.contains(&"ca-certificates"), "{deb}");
}

/// Whether the scripts of packaging/, which are Python, can run. Without
/// `/usr/bin/python3` these tests fail — the package cannot be built without
/// it either — unless `RUSTHORSE_TEST_WITHOUT_PYTHON` is set, which skips
/// them, saying so.
fn python3() -> bool {
    if Path::new("/usr/bin/python3").exists() {
        return true;
    }
    assert!(
        std::env::var_os("RUSTHORSE_TEST_WITHOUT_PYTHON").is_some(),
        "/usr/bin/python3 is needed for the scripts of packaging/; set \
         RUSTHORSE_TEST_WITHOUT_PYTHON=1 to skip the tests that need it"
    );
    eprintln!("skipped: /usr/bin/python3 is needed for the scripts of packaging/");
    false
}

/// Run a Python script with `args`, isolated and without writing bytecode
/// next to it.
fn python(script: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(script)
        .args(args)
        .current_dir(root())
        .output()
        .expect("run python3")
}

/// Write an executable file from another process and put it in place at
/// once: a file this process held open for writing could not be run while
/// a process forked meanwhile by another test still held that descriptor
/// ("Text file busy").
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

/// A stand-in broker at `path` that answers `--check` with `answer`, but
/// only when asked as `rusthorse doctor` asks it: with nothing in its
/// environment and `/` as working directory.
fn write_broker(path: &Path, answer: &str) {
    write_program(
        path,
        &format!(
            "#!/bin/sh\n[ \"$1\" = --check ] && [ -z \"${{HOME-}}\" ] && \
             [ \"$(pwd -P)\" = / ] || exit 9\nprintf '%s\\n' '{answer}'\n"
        ),
    );
}

#[test]
fn only_a_release_build_of_the_broker_is_packaged() {
    if !python3() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let broker = dir.path().join("rusthorse-broker");
    let version = env!("CARGO_PKG_VERSION");
    let check = || {
        python(
            &root().join("packaging/check-broker.py"),
            &[broker.as_os_str(), version.as_ref()],
        )
    };
    let answering = |answer: &str| {
        write_broker(&broker, answer);
        check()
    };
    let release = format!(r#"{{"version":"{version}","protocol":1}}"#);
    let out = answering(&release);
    assert!(out.status.success(), "{out:?}");
    // A relative path names the program from where the check is run, not
    // from `/`, where the program runs.
    let out = Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(root().join("packaging/check-broker.py"))
        .args(["./rusthorse-broker", version])
        .current_dir(dir.path())
        .output()
        .expect("run check-broker.py");
    assert!(out.status.success(), "{out:?}");

    let refused = |out: Output, why: &str| {
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{said}");
        assert!(said.contains(why), "{said}");
        assert!(said.contains("refusing to package it"), "{said}");
    };
    for (answer, why) in [
        // A build with the feature for tests, whatever it says of it.
        (
            format!(r#"{{"version":"{version}","protocol":1,"test_upstream":true}}"#),
            "is a build for tests",
        ),
        (
            format!(r#"{{"version":"{version}","protocol":1,"test_upstream":false}}"#),
            "is a build for tests",
        ),
        (
            format!(r#"{{"version":"{version}","protocol":1,"debug":true}}"#),
            "instead of version and protocol",
        ),
        (
            format!(r#"{{"version":"{version}"}}"#),
            "instead of version and protocol",
        ),
        (
            format!(r#"{{"version":"{version}","protocol":1,"protocol":2}}"#),
            "does not parse",
        ),
        (
            r#"{"version":"0.0.0-other","protocol":1}"#.to_string(),
            "reports version",
        ),
        (
            format!(r#"{{"version":"{version}","protocol":"1"}}"#),
            "protocol that is not a number",
        ),
        (
            format!(r#"{{"version":"{version}","protocol":true}}"#),
            "protocol that is not a number",
        ),
        (format!("rusthorse-broker {version}"), "does not parse"),
        ("[1]".to_string(), "does not parse"),
    ] {
        refused(answering(&answer), why);
    }
    write_program(&broker, &format!("#!/bin/sh\necho '{release}'\nexit 3\n"));
    refused(check(), "failed its --check (exit status 3)");
    // One that does not answer is refused once its time is up (shortened
    // here from five seconds), and killed.
    write_program(&broker, "#!/bin/sh\nexec sleep 30\n");
    let probe = dir.path().join("probe.py");
    fs::write(&probe, CHECK_BROKER_PROBE).expect("write the probe");
    let started = std::time::Instant::now();
    let script = root().join("packaging/check-broker.py");
    refused(
        python(
            &probe,
            &[script.as_os_str(), broker.as_os_str(), version.as_ref()],
        ),
        "did not answer --check within 0.5 seconds",
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    fs::remove_file(&broker).expect("rm");
    refused(check(), "cannot be run");
}

/// packaging/check-broker.py with its time limit shortened to half a
/// second: `probe.py SCRIPT PROGRAM VERSION`.
const CHECK_BROKER_PROBE: &str = r#"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("check_broker", sys.argv[1])
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
check.TIMEOUT_SECONDS = 0.5
sys.argv = sys.argv[1:]
check.main()
"#;

// What ships: packaging/check-broker.py --packages on stand-in packages
// (unpacked by a stand-in `dpkg-deb -x`), on a real package where dpkg-deb
// is installed, and packaging/build-deb.sh run whole on stand-ins for cargo
// and dpkg-deb.

use std::process::Stdio;

/// A stand-in package of the files that the tar archive `tar` holds: an ar
/// archive that begins as a Debian package does, with a member
/// debian-binary, then a member data.tar, the tar archive, which starts
/// `STAND_IN_DATA` bytes in. It has no control member, which only the real
/// dpkg-deb would need.
fn stand_in_package(tar: &[u8]) -> Vec<u8> {
    let mut package = b"!<arch>\n".to_vec();
    package.extend_from_slice(&ar_header("debian-binary", 4));
    package.extend_from_slice(b"2.0\n");
    package.extend_from_slice(&ar_header("data.tar", tar.len()));
    assert_eq!(package.len(), STAND_IN_DATA);
    package.extend_from_slice(tar);
    if tar.len() % 2 == 1 {
        package.push(b'\n');
    }
    package
}

/// Where data.tar starts in a stand-in package: after the ar magic, the
/// header and the contents of debian-binary, and its own header.
const STAND_IN_DATA: usize = 8 + 60 + 4 + 60;

/// The header of a member `name` of `size` bytes in an ar archive, as
/// cargo-deb and dpkg-deb write it.
fn ar_header(name: &str, size: usize) -> Vec<u8> {
    let header = format!(
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
        0, 0, 0, 100644
    );
    assert_eq!(header.len(), 60, "{header}");
    header.into_bytes()
}

/// A directory `bin` in `dir` holding a stand-in `dpkg-deb`: `-x PACKAGE
/// DIR` unpacks the data.tar of a stand-in package into DIR, as dpkg-deb
/// unpacks a package, and anything else fails. It appends its arguments to
/// `dir/dpkg-deb-calls`.
fn dpkg_deb_stand_in(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).expect("mkdir");
    write_program(
        &bin.join("dpkg-deb"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             [ $# = 3 ] && [ \"$1\" = -x ] || {{ echo \"dpkg-deb stand-in: $*\" >&2; exit 2; }}\n\
             mkdir -p \"$3\" && tail -c +{} \"$2\" | tar -xf - -C \"$3\"\n",
            dir.join("dpkg-deb-calls").display(),
            STAND_IN_DATA + 1
        ),
    );
    bin
}

/// A stand-in package at `path` of the files of the directory `stage`.
fn pack(stage: &Path, path: &Path) {
    let out = Command::new("tar")
        .arg("-cf")
        .arg("-")
        .arg("-C")
        .arg(stage)
        .arg(".")
        .output()
        .expect("tar");
    assert!(out.status.success(), "{out:?}");
    fs::write(path, stand_in_package(&out.stdout)).expect("write the package");
}

/// packaging/check-broker.py --packages, with `path` as PATH, the package
/// paths `packages` on its standard input, one per line, and `scratch` as
/// the directory it unpacks them in.
fn check_packages(path: &str, packages: &[&Path], scratch: &Path) -> Output {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(root().join("packaging/check-broker.py"))
        .arg("--packages")
        .arg(env!("CARGO_PKG_VERSION"))
        .arg(scratch)
        .env("PATH", path)
        .current_dir(root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run check-broker.py");
    let mut input = Vec::new();
    for package in packages {
        input.extend_from_slice(package.as_os_str().as_bytes());
        input.push(b'\n');
    }
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(&input).expect("write the paths");
    drop(stdin);
    child.wait_with_output().expect("wait")
}

/// What `--check` answers: a release build of this version, and a build
/// with the broker's feature for tests.
fn release_answer() -> String {
    format!(
        r#"{{"version":"{}","protocol":1}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

fn for_tests_answer() -> String {
    format!(
        r#"{{"version":"{}","protocol":1,"test_upstream":true}}"#,
        env!("CARGO_PKG_VERSION")
    )
}

/// A refusal of check-broker.py: status 1, and a message saying `why`.
fn assert_refused(out: &Output, why: &str) {
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(said.contains(why), "{said}");
    assert!(said.contains("refusing to package it"), "{said}");
}

#[test]
fn a_package_whose_broker_is_not_a_release_build_is_deleted() {
    if !python3() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dpkg_deb_stand_in(dir.path());
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    // A package of the brokers `brokers` (path in the package, --check
    // answer), written to `name` in `dir`.
    let package = |name: &str, brokers: &[(&str, &str)]| {
        let stage = dir.path().join(format!("stage-{name}"));
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(stage.join("usr/share/doc/rusthorse")).expect("mkdir");
        for (inside, answer) in brokers {
            let at = stage.join(inside);
            fs::create_dir_all(at.parent().expect("parent")).expect("mkdir");
            write_broker(&at, answer);
        }
        let deb = dir.path().join(name);
        pack(&stage, &deb);
        deb
    };
    let release = release_answer();
    let for_tests = for_tests_answer();
    let broker = "usr/bin/rusthorse-broker";

    // Accepted: the broker of the package is a release build, and a package
    // of debugging symbols, which has none, may go with it.
    let deb = package("rusthorse.deb", &[(broker, &release)]);
    let ddeb = package("rusthorse-dbgsym.ddeb", &[]);
    let out = check_packages(&path, &[&ddeb, &deb], &scratch);
    assert!(out.status.success(), "{out:?}");
    assert!(deb.exists() && ddeb.exists());
    let calls = fs::read_to_string(dir.path().join("dpkg-deb-calls")).expect("calls");
    for unpacked in [&ddeb, &deb] {
        assert!(
            calls.contains(&format!("-x {} {}/", unpacked.display(), scratch.display())),
            "{calls}"
        );
    }
    // Unpacked in a directory of its own, removed afterwards.
    assert_eq!(fs::read_dir(&scratch).expect("scratch").count(), 0);

    // A build for tests: refused, and every package of the run deleted.
    let deb = package("rusthorse.deb", &[(broker, &for_tests)]);
    let ddeb = package("rusthorse-dbgsym.ddeb", &[]);
    let out = check_packages(&path, &[&ddeb, &deb], &scratch);
    assert_refused(
        &out,
        &format!(
            "{broker} in {} is a build for tests (its --check reports test_upstream)",
            deb.display()
        ),
    );
    assert!(!deb.exists() && !ddeb.exists());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains(&format!("deleted {}, {}", ddeb.display(), deb.display())),
        "{said}"
    );

    // Every broker in the package is checked, wherever it is.
    let deb = package(
        "rusthorse.deb",
        &[
            (broker, &release),
            ("usr/local/bin/rusthorse-broker", &for_tests),
        ],
    );
    assert_refused(
        &check_packages(&path, &[&deb], &scratch),
        "usr/local/bin/rusthorse-broker in",
    );
    assert!(!deb.exists());

    // Something else than a broker, a regular file, under its name.
    for (what, make) in [
        ("a link", "ln -s /bin/true \"$1/usr/bin/rusthorse-broker\""),
        ("a directory", "mkdir \"$1/usr/bin/rusthorse-broker\""),
    ] {
        let stage = dir.path().join("stage-odd");
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(stage.join("usr/bin")).expect("mkdir");
        let made = Command::new("/bin/sh")
            .args(["-c", make, "sh"])
            .arg(&stage)
            .status()
            .expect("sh");
        assert!(made.success(), "{what}");
        let deb = dir.path().join("odd.deb");
        pack(&stage, &deb);
        assert_refused(
            &check_packages(&path, &[&deb], &scratch),
            &format!("{broker} in {} is not a regular file", deb.display()),
        );
        assert!(!deb.exists(), "{what}");
    }

    // No broker at all: a package that does not hold the program checked
    // above; the check would otherwise check nothing.
    let deb = package("rusthorse.deb", &[]);
    assert_refused(
        &check_packages(&path, &[&deb], &scratch),
        &format!("no rusthorse-broker in {}", deb.display()),
    );
    assert!(!deb.exists());

    // A package that cannot be unpacked, or is not there, or none named.
    let deb = dir.path().join("rusthorse.deb");
    fs::write(&deb, "not an archive").expect("write");
    assert_refused(
        &check_packages(&path, &[&deb], &scratch),
        &format!(
            "{} cannot be unpacked (dpkg-deb -x: exit status",
            deb.display()
        ),
    );
    assert!(!deb.exists());
    assert_refused(
        &check_packages(&path, &[&deb], &scratch),
        &format!("{}, which cargo-deb named, is not a file", deb.display()),
    );
    assert_refused(
        &check_packages(&path, &[], &scratch),
        "cargo-deb named no package it wrote",
    );
    // Only packages are deleted: not another file it was given.
    let deb = package("rusthorse.deb", &[(broker, &for_tests)]);
    let other = dir.path().join("notes.txt");
    fs::write(&other, "kept").expect("write");
    let out = check_packages(&path, &[&deb, &other], &scratch);
    assert_refused(&out, "is a build for tests");
    assert!(!deb.exists() && other.exists());
    assert_eq!(fs::read_dir(&scratch).expect("scratch").count(), 0);
    // Whatever stops the check (here, no directory to unpack in), no
    // package is left behind, whatever its name, and it says so.
    let deb = package("rusthorse.deb", &[(broker, &release)]);
    let pkg = package("rusthorse.pkg", &[(broker, &release)]);
    let out = check_packages(&path, &[&deb, &pkg], &dir.path().join("gone"));
    assert!(!out.status.success(), "{out:?}");
    assert!(!deb.exists() && !pkg.exists());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains(&format!(
            "check-broker.py: the packages could not all be checked; deleted {}, {}\n",
            deb.display(),
            pkg.display()
        )),
        "{said}"
    );
}

#[test]
fn a_refused_run_deletes_its_packages_whatever_their_names_and_nothing_else() {
    if !python3() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dpkg_deb_stand_in(dir.path());
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    let broker = "usr/bin/rusthorse-broker";
    // A package at `path` whose broker answers `answer`.
    let package = |path: &Path, answer: &str| {
        let stage = dir.path().join("stage");
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(stage.join("usr/bin")).expect("mkdir");
        write_broker(&stage.join(broker), answer);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        pack(&stage, path);
        path.to_path_buf()
    };
    let at = |name: &str| dir.path().join(name);
    let release = release_answer();
    let for_tests = for_tests_answer();
    let refused = |package: &Path| {
        format!(
            "{broker} in {} is a build for tests (its --check reports test_upstream): \
             refusing to package it; ",
            package.display()
        )
    };

    // cargo-deb's --output can name a package anything: with an extension
    // that is not .deb, without one, in capitals. Each begins as a Debian
    // package does, and is deleted with every other package of the run.
    // So is one called as a package, in any case, that does not begin as
    // one (cut short, say).
    let pkg = package(&at("release.pkg"), &for_tests);
    let bare = package(&at("release"), &release);
    let capitals = package(&at("X.DEB"), &release);
    let short = at("short.DDEB");
    fs::write(&short, "!<arch>\n").expect("write");
    let out = check_packages(&path, &[&pkg, &bare, &capitals, &short], &scratch);
    assert_refused(
        &out,
        &format!(
            "{}deleted {}, {}, {}, {}. A package must",
            refused(&pkg),
            pkg.display(),
            bare.display(),
            capitals.display(),
            short.display()
        ),
    );
    for named in [&pkg, &bare, &capitals, &short] {
        assert!(!named.exists(), "{}", named.display());
    }

    // Nothing else it names is deleted, whatever its name: not a file that
    // is not a package, nor an ar archive that is not one (a library), nor
    // a directory; a path with nothing there is not mentioned.
    let deb = package(&at("rusthorse.deb"), &for_tests);
    let notes = at("notes.pkg");
    fs::write(&notes, "kept").expect("write");
    let library = at("libkept.a");
    let library_bytes = [&b"!<arch>\n"[..], &ar_header("kept.o/", 0)].concat();
    fs::write(&library, &library_bytes).expect("write");
    let directory = at("directory.deb");
    fs::create_dir(&directory).expect("mkdir");
    let nothing = at("nothing.deb");
    let out = check_packages(
        &path,
        &[&deb, &notes, &library, &directory, &nothing],
        &scratch,
    );
    assert_refused(
        &out,
        &format!("{}deleted {}. A package must", refused(&deb), deb.display()),
    );
    assert!(!deb.exists());
    assert_eq!(fs::read_to_string(&notes).expect("notes"), "kept");
    assert_eq!(fs::read(&library).expect("library"), library_bytes);
    assert!(directory.is_dir());

    // A package is emptied before it is deleted: another hard link to it
    // (cargo-deb writes a package in place) does not keep it.
    let linked = package(&at("linked.pkg"), &for_tests);
    let other = at("elsewhere/other-link");
    fs::create_dir_all(other.parent().expect("parent")).expect("mkdir");
    fs::hard_link(&linked, &other).expect("ln");
    let out = check_packages(&path, &[&linked], &scratch);
    assert_refused(
        &out,
        &format!(
            "{}deleted {}. A package must",
            refused(&linked),
            linked.display()
        ),
    );
    assert!(!linked.exists());
    assert_eq!(fs::metadata(&other).expect("other link").len(), 0);

    // A symbolic link is not followed: cargo-deb wrote the package where it
    // leads, which is kept, and the message names the link.
    let target = package(&at("elsewhere/target.pkg"), &for_tests);
    let before = fs::read(&target).expect("target");
    let link = at("link.pkg");
    std::os::unix::fs::symlink(&target, &link).expect("ln -s");
    let out = check_packages(&path, &[&link], &scratch);
    assert_refused(
        &out,
        &format!(
            "{}deleted nothing; not deleted: {} (a symbolic link, not followed: delete by \
             hand the package it leads to). A package must",
            refused(&link),
            link.display()
        ),
    );
    assert!(link.is_symlink());
    assert_eq!(fs::read(&target).expect("target"), before);

    // One that cannot be deleted is named (it is emptied all the same), and
    // the others are deleted.
    if nix::unistd::geteuid().is_root() {
        // Root deletes in any directory.
        return;
    }
    let locked = at("locked");
    let stuck = package(&locked.join("stuck.pkg"), &for_tests);
    let after = package(&at("after.deb"), &release);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).expect("chmod");
    let out = check_packages(&path, &[&stuck, &after], &scratch);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_refused(
        &out,
        &format!(
            "{}deleted {}; not deleted: {} (Permission denied: delete it by hand). A \
             package must",
            refused(&stuck),
            after.display(),
            stuck.display()
        ),
    );
    assert!(!after.exists());
    assert_eq!(fs::metadata(&stuck).expect("stuck").len(), 0);

    // One that cannot be read is deleted if it is called as a package;
    // otherwise it may hold one, and is named.
    let deb = package(&at("refused.deb"), &for_tests);
    let unreadable_deb = package(&at("unreadable.deb"), &release);
    let unreadable_pkg = package(&at("unreadable.pkg"), &release);
    for file in [&unreadable_deb, &unreadable_pkg] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o000)).expect("chmod");
    }
    let out = check_packages(&path, &[&deb, &unreadable_deb, &unreadable_pkg], &scratch);
    assert_refused(
        &out,
        &format!(
            "{}deleted {}, {}; not deleted: {} (Permission denied: delete it by hand). A \
             package must",
            refused(&deb),
            deb.display(),
            unreadable_deb.display(),
            unreadable_pkg.display()
        ),
    );
    assert!(!deb.exists() && !unreadable_deb.exists() && unreadable_pkg.exists());

    // One that cannot be written to, and so cannot be emptied, is deleted
    // all the same when no other hard link would keep it, and named when
    // one would.
    let read_only = package(&at("read-only.pkg"), &for_tests);
    let shared = package(&at("shared.pkg"), &release);
    let shared_link = at("elsewhere/shared-link");
    fs::hard_link(&shared, &shared_link).expect("ln");
    for file in [&read_only, &shared] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o444)).expect("chmod");
    }
    let shared_before = fs::read(&shared).expect("shared");
    let out = check_packages(&path, &[&read_only, &shared], &scratch);
    assert_refused(
        &out,
        &format!(
            "{}deleted {}; not deleted: {} (Permission denied to empty it, and another hard \
             link would keep it: delete them by hand). A package must",
            refused(&read_only),
            read_only.display(),
            shared.display()
        ),
    );
    assert!(!read_only.exists());
    assert_eq!(fs::read(&shared_link).expect("shared link"), shared_before);
}

/// packaging/check-broker.py's deletion of PATH, where another program puts
/// a symbolic link to TARGET in place of the file PATH just after the
/// script examined it (WHEN `examined`: `os.lstat`) or opened it to read
/// its start (WHEN `opened`): `probe.py SCRIPT WHEN PATH TARGET` prints what
/// the deletion says.
const SWAP_PROBE: &str = r#"
import builtins, importlib.util, os, sys
spec = importlib.util.spec_from_file_location("check_broker", sys.argv[1])
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
when, path, target = sys.argv[2:5]
def swap():
    os.remove(path)
    os.symlink(target, path)
def then_swap(call):
    def called(name, *args, **kwargs):
        done = call(name, *args, **kwargs)
        if name == path:
            swap()
        return done
    return called
if when == "examined":
    os.lstat = then_swap(os.lstat)
else:
    check.open = then_swap(builtins.open)
print(check.delete_packages([path]))
"#;

#[test]
fn a_link_put_in_place_of_a_package_once_examined_is_not_followed() {
    if !python3() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let stage = dir.path().join("stage");
    fs::create_dir_all(stage.join("usr/bin")).expect("mkdir");
    write_broker(&stage.join("usr/bin/rusthorse-broker"), &release_answer());
    let path = dir.path().join("swapped.pkg");
    let package = dir.path().join("elsewhere.pkg");
    pack(&stage, &package);
    let other = dir.path().join("elsewhere.txt");
    fs::write(&other, "not a package").expect("write");
    let probe = dir.path().join("probe.py");
    fs::write(&probe, SWAP_PROBE).expect("write the probe");
    let script = root().join("packaging/check-broker.py");
    // The link leads to a package, or to a file that is not one, which
    // would leave nothing to say if it were read through the link.
    for (when, target) in [
        ("examined", &package),
        ("opened", &package),
        ("examined", &other),
    ] {
        let before = fs::read(target).expect("target");
        let _ = fs::remove_file(&path);
        pack(&stage, &path);
        let out = python(
            &probe,
            &[
                script.as_os_str(),
                when.as_ref(),
                path.as_os_str(),
                target.as_os_str(),
            ],
        );
        assert!(out.status.success(), "{when}: {out:?}");
        // Neither read nor emptied through the link: the file it leads to
        // is whole, and the path is named, since it may hold a package.
        assert_eq!(fs::read(target).expect("target"), before, "{when}");
        assert!(path.is_symlink(), "{when}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!(
                "deleted nothing; not deleted: {} (Too many levels of symbolic links: delete \
                 it by hand)\n",
                path.display()
            ),
            "{when}"
        );
    }
}

/// `python3 -c PACK_HIDDEN STAGE`: a tar archive of STAGE, in which
/// usr/lib/hidden has no permissions, on standard output.
const PACK_HIDDEN: &str = r#"
import sys, tarfile
def hide(info):
    if info.name == "./usr/lib/hidden":
        info.mode = 0
    return info
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
    archive.add(sys.argv[1], arcname=".", filter=hide)
"#;

#[test]
fn a_directory_of_the_package_that_cannot_be_read_is_refused() {
    if !python3() || nix::unistd::geteuid().is_root() {
        // Root reads any directory.
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dpkg_deb_stand_in(dir.path());
    let stage = dir.path().join("stage");
    fs::create_dir_all(stage.join("usr/lib/hidden")).expect("mkdir");
    fs::create_dir_all(stage.join("usr/bin")).expect("mkdir");
    write_broker(&stage.join("usr/bin/rusthorse-broker"), &release_answer());
    write_broker(
        &stage.join("usr/lib/hidden/rusthorse-broker"),
        &for_tests_answer(),
    );
    // Recorded with no permissions: tar gives the directory that mode once
    // it has unpacked what is inside.
    let deb = dir.path().join("rusthorse.deb");
    let out = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", PACK_HIDDEN])
        .arg(&stage)
        .output()
        .expect("python3");
    assert!(out.status.success(), "{out:?}");
    fs::write(&deb, stand_in_package(&out.stdout)).expect("write the package");
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    let out = check_packages(
        &format!("{}:/usr/bin:/bin", bin.display()),
        &[&deb],
        &scratch,
    );
    assert_refused(&out, "cannot be read in the unpacked package");
    assert!(!deb.exists());
    // What it unpacked is removed, unreadable directory included.
    assert_eq!(fs::read_dir(&scratch).expect("scratch").count(), 0);
}

#[test]
fn what_ships_is_checked_with_the_real_dpkg_deb() {
    if !python3() {
        return;
    }
    if !Path::new("/usr/bin/dpkg-deb").exists() {
        eprintln!("skipped: /usr/bin/dpkg-deb is not installed here");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let stage = dir.path().join("stage");
    let control = stage.join("DEBIAN");
    fs::create_dir_all(&control).expect("mkdir");
    fs::create_dir_all(stage.join("usr/bin")).expect("mkdir");
    for directory in [&stage, &control, &stage.join("usr"), &stage.join("usr/bin")] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    fs::write(
        control.join("control"),
        format!(
            "Package: rusthorse\nVersion: {}-1\nArchitecture: all\n\
             Maintainer: A Stand-In <stand-in@example.invalid>\n\
             Description: a stand-in package for a test\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .expect("write");
    fs::set_permissions(control.join("control"), fs::Permissions::from_mode(0o644)).expect("chmod");
    let deb = dir.path().join("rusthorse.deb");
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    let build = |answer: &str, package: &Path| {
        write_broker(&stage.join("usr/bin/rusthorse-broker"), answer);
        let out = Command::new("/usr/bin/dpkg-deb")
            .args(["--build", "--root-owner-group"])
            .arg(&stage)
            .arg(package)
            .output()
            .expect("dpkg-deb --build");
        assert!(out.status.success(), "{out:?}");
    };
    build(&release_answer(), &deb);
    let out = check_packages("/usr/bin:/bin", &[&deb], &scratch);
    assert!(out.status.success(), "{out:?}");
    assert!(deb.exists());
    build(&for_tests_answer(), &deb);
    assert_refused(
        &check_packages("/usr/bin:/bin", &[&deb], &scratch),
        "usr/bin/rusthorse-broker in",
    );
    assert!(!deb.exists());
    // Whatever its name: what dpkg-deb writes begins as what cargo-deb
    // writes does.
    let pkg = dir.path().join("rusthorse.pkg");
    build(&for_tests_answer(), &pkg);
    let out = check_packages("/usr/bin:/bin", &[&pkg], &scratch);
    assert_refused(&out, &format!("; deleted {}. ", pkg.display()));
    assert!(!pkg.exists());
}

/// A run of packaging/build-deb.sh on stand-ins, in a temporary directory
/// F. Its `cargo`, first on PATH, appends its arguments to F/cargo-calls:
/// `build` copies the programs of F/built to F/target/release, as a build
/// writes them there; `metadata --no-deps` describes a workspace whose
/// target directory is F/target; `deb` packages F/target/release's broker
/// (or F/shipped-broker, if there is one) as usr/bin/rusthorse-broker, in a
/// stand-in package written to F/target/debian or where `--output` says (the
/// package itself if it has an extension and is no directory, as cargo-deb
/// takes it; a directory otherwise), and prints its path, as cargo-deb does;
/// whatever else it is asked (copyright.py's `metadata` and `tree`) goes to
/// the real cargo. Its `dpkg-deb -x` unpacks those packages. Everything else
/// is real: the checks, the copyright file and the documentation, which are
/// generated in F/target/release/packaging.
struct DebBuild(tempfile::TempDir);

/// The stand-in `cargo` of `DebBuild`; F, REAL_CARGO and DEB are set before
/// it.
const CARGO_STAND_IN: &str = r#"
printf '%s\n' "$*" >> "$F/cargo-calls"
case $1 in
build)
    cp -p "$F/built/rusthorse" "$F/built/rusthorse-broker" "$F/target/release/"
    ;;
metadata)
    case " $* " in
    *" --no-deps "*) cat "$F/metadata.json" ;;
    *) exec "$REAL_CARGO" "$@" ;;
    esac
    ;;
deb)
    out=$F/target/debian
    while [ $# -gt 0 ]; do
        [ "$1" = --output ] && out=$2
        shift
    done
    deb=$out/$DEB
    case ${out##*/} in
    *.*) [ -d "$out" ] || deb=$out ;;
    esac
    broker=$F/target/release/rusthorse-broker
    [ -e "$F/shipped-broker" ] && broker=$F/shipped-broker
    mkdir -p "$F/stage/usr/bin" "${deb%/*}"
    cp -p "$broker" "$F/stage/usr/bin/rusthorse-broker"
    tar -cf "$F/data.tar" -C "$F/stage" .
    size=$(wc -c < "$F/data.tar")
    {
        printf '!<arch>\n%-16s%-12s%-6s%-6s%-8s%-10s`\n2.0\n' debian-binary 0 0 0 100644 4
        printf '%-16s%-12s%-6s%-6s%-8s%-10s`\n' data.tar 0 0 0 100644 $size
        cat "$F/data.tar"
    } > "$deb"
    printf '%s\n' "$deb"
    ;;
*)
    exec "$REAL_CARGO" "$@"
    ;;
esac
"#;

/// The real cargo, for the stand-in to call.
fn real_cargo() -> PathBuf {
    std::env::var_os("CARGO")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO").map(PathBuf::from))
        .expect("CARGO: the path of cargo")
}

/// The name of the package the stand-in `cargo deb` writes.
fn deb_name() -> String {
    format!("rusthorse_{}-1_amd64.deb", env!("CARGO_PKG_VERSION"))
}

impl DebBuild {
    /// Stand-ins whose build writes a broker that answers `--check` with
    /// `built`.
    fn new(built: &str) -> DebBuild {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path();
        for directory in ["built", "target/release"] {
            fs::create_dir_all(f.join(directory)).expect("mkdir");
        }
        dpkg_deb_stand_in(f);
        write_program(
            &f.join("bin/cargo"),
            &format!(
                "#!/bin/sh\nF='{}'\nREAL_CARGO='{}'\nDEB='{}'\n{CARGO_STAND_IN}",
                f.display(),
                real_cargo().display(),
                deb_name()
            ),
        );
        let metadata = serde_json::json!({
            "target_directory": f.join("target"),
            "packages": [{"name": "rusthorse", "version": env!("CARGO_PKG_VERSION")}],
        });
        fs::write(f.join("metadata.json"), metadata.to_string()).expect("write");
        write_program(
            &f.join("built/rusthorse"),
            "#!/bin/sh\n[ \"$1\" = completions ] && echo \"# completions for $2\"\n",
        );
        write_broker(&f.join("built/rusthorse-broker"), built);
        DebBuild(dir)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.path().join(relative)
    }

    /// Run build-deb.sh with `args`, and `env` added to the environment.
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let path = std::env::var("PATH").unwrap_or_default();
        Command::new("/bin/sh")
            .arg(root().join("packaging/build-deb.sh"))
            .args(args)
            .env("PATH", format!("{}:{path}", self.path("bin").display()))
            .env_remove("CARGO_BUILD_TARGET")
            .envs(env.iter().copied())
            .output()
            .expect("run build-deb.sh")
    }

    /// What the stand-in `cargo` was asked, one call a line.
    fn cargo_calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("cargo-calls"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

#[test]
fn the_package_is_built_without_features_and_only_after_the_broker_is_checked() {
    if !python3() {
        return;
    }
    let release = release_answer();
    let for_tests = for_tests_answer();

    // A release build: built without features, checked, packaged, checked
    // again as it ships, and the package's path printed.
    let run = DebBuild::new(&release);
    let output = run.path("out");
    let out = run.run(&["--output", output.to_str().expect("UTF-8")], &[]);
    assert!(out.status.success(), "{out:?}");
    let calls = run.cargo_calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("build --release --locked --workspace"),
        "{calls:#?}"
    );
    assert_eq!(
        calls.last(),
        Some(&format!(
            "deb --no-build --locked -p rusthorse --output {}",
            output.display()
        )),
        "{calls:#?}"
    );
    // The broker's only feature is for tests: no feature is ever turned on.
    for call in &calls {
        assert!(
            !["--features", "--all-features", " -F"]
                .iter()
                .any(|flag| call.contains(flag)),
            "{call}"
        );
    }
    let deb = output.join(deb_name());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", deb.display())
    );
    assert!(deb.exists());
    assert!(
        fs::read_to_string(run.path("dpkg-deb-calls"))
            .expect("the package is checked")
            .starts_with(&format!("-x {} ", deb.display()))
    );
    assert!(run.path("target/release/packaging/copyright").is_file());

    // The build wrote a broker for tests over a release build: refused
    // before anything is packaged.
    let run = DebBuild::new(&for_tests);
    write_broker(&run.path("target/release/rusthorse-broker"), &release);
    let out = run.run(&[], &[]);
    assert_refused(&out, "is a build for tests");
    assert!(
        !run.cargo_calls().iter().any(|call| call.starts_with("deb")),
        "{:#?}",
        run.cargo_calls()
    );
    assert!(!run.path("target/release/packaging").exists());

    // cargo-deb packaged another broker than the one checked: refused once
    // it is written, and the package deleted.
    let run = DebBuild::new(&release);
    write_broker(&run.path("shipped-broker"), &for_tests);
    let out = run.run(&[], &[]);
    let deb = run.path("target/debian").join(deb_name());
    assert_refused(
        &out,
        &format!(
            "usr/bin/rusthorse-broker in {} is a build for tests",
            deb.display()
        ),
    );
    assert!(
        run.cargo_calls().iter().any(|call| call.starts_with("deb")),
        "{:#?}",
        run.cargo_calls()
    );
    assert!(!deb.exists());
    assert!(out.stdout.is_empty(), "{out:?}");
    // Whatever name --output gives that package.
    let run = DebBuild::new(&release);
    write_broker(&run.path("shipped-broker"), &for_tests);
    let named = run.path("out/release.pkg");
    let out = run.run(&["--output", named.to_str().expect("UTF-8")], &[]);
    assert_refused(
        &out,
        &format!(
            "usr/bin/rusthorse-broker in {0} is a build for tests (its --check reports \
             test_upstream): refusing to package it; deleted {0}. ",
            named.display()
        ),
    );
    assert!(!named.exists());
    assert!(out.stdout.is_empty(), "{out:?}");

    // What would install the package before its check, or build it for
    // another target: refused before anything is built.
    for (args, env) in [
        (&["--install"][..], &[][..]),
        (&["--no-install-dbgsym"][..], &[][..]),
        (&["--target", "x86_64-unknown-linux-gnu"][..], &[][..]),
        (&["--target=x86_64-unknown-linux-gnu"][..], &[][..]),
        (
            &[][..],
            &[("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu")][..],
        ),
    ] {
        let run = DebBuild::new(&release);
        let out = run.run(args, env);
        let said = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?} {env:?}: {said}");
        let named = args.first().copied().unwrap_or("CARGO_BUILD_TARGET");
        assert!(
            said.starts_with(&format!("build-deb.sh: {named}")),
            "{said}"
        );
        assert!(run.cargo_calls().is_empty(), "{:#?}", run.cargo_calls());
    }

    // Any step that fails stops the script.
    let run = DebBuild::new(&release);
    write_program(&run.path("built/rusthorse"), "#!/bin/sh\nexit 1\n");
    let out = run.run(&[], &[]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        !run.cargo_calls().iter().any(|call| call.starts_with("deb")),
        "{:#?}",
        run.cargo_calls()
    );
}

/// The copyright file, written by packaging/copyright.py as build-deb.sh
/// runs it.
fn copyright_file() -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = dir.path().join("copyright");
    let out = python(
        &root().join("packaging/copyright.py"),
        &[output.as_os_str()],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read_to_string(&output).expect("the copyright file")
}

#[test]
fn the_copyright_file_covers_every_crate_the_programs_are_built_from() {
    if !python3() {
        return;
    }
    let copyright = copyright_file();
    // The crates of the programs' release build, as `cargo tree` sees them
    // without dev-dependencies: not as copyright.py finds them.
    let tree = cargo(&[
        "tree",
        "--workspace",
        "--locked",
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ]);
    let mut crates = BTreeSet::new();
    for line in tree.lines() {
        // The workspace's own packages are Rusthorse.
        if line.contains(" (/") {
            continue;
        }
        let mut words = line.split_whitespace();
        if let (Some(name), Some(version)) =
            (words.next(), words.next().and_then(|v| v.strip_prefix('v')))
        {
            crates.insert((name.to_string(), version.to_string()));
        }
    }
    for broker_crate in ["hyper", "tokio", "rustls", "ring"] {
        assert!(
            crates.iter().any(|(name, _)| name == broker_crate),
            "{broker_crate} is not compiled in: {crates:?}"
        );
    }
    let lines: Vec<&str> = copyright.lines().collect();
    let shippers: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("Text "))
        .collect();
    for (name, version) in &crates {
        let listed = lines
            .iter()
            .position(|line| line.starts_with(&format!(" {name} {version} — ")))
            .unwrap_or_else(|| panic!("{name} {version} is not listed"));
        let shipped = format!(" {name} {version} (");
        let no_code = lines
            .get(listed + 1)
            .is_some_and(|line| line.trim() == "(no license file; the crate contains no code)");
        assert!(
            no_code || shippers.iter().any(|line| line.contains(&shipped)),
            "no license text of {name} {version}"
        );
    }
    // The programs it names are the workspace's.
    let names: Vec<String> = programs(&workspace()).into_iter().collect();
    let (last, others) = names.split_last().expect("programs");
    let words = copyright.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        words.contains(&format!(
            "{} and {last} are built from these",
            others.join(", ")
        )),
        "{}",
        copyright.chars().take(1500).collect::<String>()
    );

    // ring's licenses are not all at its top: those below it whose code is
    // compiled in, and the notices at the top of its source files, as its
    // LICENSE says.
    let ring = &crates
        .iter()
        .find(|(name, _)| name == "ring")
        .expect("ring")
        .1;
    for file in [
        "src/polyfill/once_cell/LICENSE-MIT",
        "src/polyfill/once_cell/LICENSE-APACHE",
        "third_party/fiat/LICENSE",
    ] {
        assert!(
            shippers
                .iter()
                .any(|line| line.contains(&format!(" ring {ring} ({file})"))),
            "{file}"
        );
    }
    let at = lines
        .iter()
        .position(|line| line.starts_with(&format!(" ring {ring} — ")))
        .expect("ring is listed");
    let entry: Vec<&str> = lines[at + 1..]
        .iter()
        .copied()
        .take_while(|line| line.starts_with("   "))
        .collect();
    assert!(
        entry.contains(&"   Copyright 2015-2020 the fiat-crypto authors (see the AUTHORS file)"),
        "{entry:#?}"
    );
    let sources = entry
        .iter()
        .position(|line| *line == "   At the top of its source files:")
        .expect("the notices of ring's source files");
    let in_sources: BTreeSet<&str> = entry[sources + 1..]
        .iter()
        .map(|line| line.strip_prefix("     ").expect("a notice"))
        .collect();
    let in_license_files: BTreeSet<&str> =
        entry[..sources].iter().map(|line| line.trim()).collect();
    // Every notice of ring's sources, found here by other rules than
    // copyright.py's, is listed; and nothing else is listed as one.
    let expected = ring_notices(&crate_directory("ring", ring));
    assert!(expected.len() > 50, "{expected:#?}");
    let missing: Vec<&String> = expected
        .iter()
        .filter(|notice| {
            !in_sources.contains(notice.as_str()) && !in_license_files.contains(notice.as_str())
        })
        .collect();
    assert!(missing.is_empty(), "not listed: {missing:#?}");
    let unexpected: Vec<&&str> = in_sources
        .iter()
        .filter(|notice| !expected.contains(**notice))
        .collect();
    assert!(unexpected.is_empty(), "not notices: {unexpected:#?}");
    // A file with code of two authors: src/aead/chacha.rs, compiled on every
    // target.
    assert!(
        in_sources.contains("Portions Copyright (c) 2016, Google Inc."),
        "{in_sources:#?}"
    );
}

/// The directory of the crate `name` `version` in Cargo's registry.
fn crate_directory(name: &str, version: &str) -> PathBuf {
    let meta: Value =
        serde_json::from_str(&cargo(&["metadata", "--format-version", "1", "--locked"]))
            .expect("JSON");
    let manifest = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == name && p["version"] == version)
        .and_then(|p| p["manifest_path"].as_str())
        .unwrap_or_else(|| panic!("no {name} {version}"));
    Path::new(manifest)
        .parent()
        .expect("its directory")
        .to_path_buf()
}

/// The copyright notices in ring's sources, found without copyright.py: the
/// lines of the text files below its top directory (but in tests/, which is
/// not compiled in) that start, after the marks of a comment, with
/// "Copyright", "Portions Copyright", "(c)" or "©", and name a year. The
/// license files at its top are read as such, and the sentences of license
/// texts that start with "copyright" name no year.
fn ring_notices(directory: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for top in fs::read_dir(directory).expect("read_dir").flatten() {
        let top = top.path();
        if !top.is_dir() || top.file_name().is_some_and(|name| name == "tests") {
            continue;
        }
        for file in walk(&top) {
            if !file.is_file() {
                continue;
            }
            let bytes = fs::read(&file).expect("read");
            if bytes.contains(&0) {
                continue;
            }
            for line in String::from_utf8_lossy(&bytes).lines() {
                let mut text = line
                    .trim_start_matches(|c: char| c.is_whitespace() || "/*#;@!%-".contains(c))
                    .trim_end();
                if let Some(open) = text.strip_suffix("*/") {
                    text = open.trim_end_matches('*').trim_end();
                }
                let lower = text.to_lowercase();
                if ["copyright", "portions copyright", "(c)", "©"]
                    .iter()
                    .any(|start| lower.starts_with(start))
                    && names_a_year(text)
                {
                    found.insert(text.to_string());
                }
            }
        }
    }
    found
}

/// Whether `text` has four digits, alone, that make a year from 1900 to 2099.
fn names_a_year(text: &str) -> bool {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(3)).any(|i| {
        b[i..i + 4].iter().all(u8::is_ascii_digit)
            && matches!(&b[i..i + 2], b"19" | b"20")
            && (i == 0 || !b[i - 1].is_ascii_digit())
            && b.get(i + 4).is_none_or(|c| !c.is_ascii_digit())
    })
}

/// What copyright.py's own functions find for a stand-in crate, version
/// 1.0.0, in `dir`, listed in NESTED_LICENSE_FILES as `listed` (a JSON
/// object), and with NOTICES_IN_SOURCES naming its `src` directory, as
/// JSON, or why it stops. `licenses`: the files whose texts
/// `license_texts` includes and their notices, in a build with the features
/// `extra` (a JSON array); `sources`: `source_notices`; `checked`:
/// `check_hand_checked`, with the versions `extra` of the crate compiled in;
/// `main`: the whole script on the workspace's crates, with the stand-in
/// added to the crates checked by hand.
const PROBE: &str = r#"
import importlib.util, json, sys
script, directory, what, listed, extra = sys.argv[1:]
spec = importlib.util.spec_from_file_location("copyright", script)
copyright = importlib.util.module_from_spec(spec)
spec.loader.exec_module(copyright)
key = ("stand-in", "1.0.0")
crate = {"name": key[0], "version": key[1], "license_file": None,
         "manifest_path": directory + "/Cargo.toml"}
if what == "main":
    copyright.NOTICES_IN_SOURCES[key] = ["src"]
    sys.argv = [script, directory + "/copyright"]
    copyright.main()
    print(json.dumps("written"))
    sys.exit(0)
copyright.NESTED_LICENSE_FILES = {key: json.loads(listed)}
copyright.NOTICES_IN_SOURCES = {key: ["src"]}
if what == "licenses":
    texts = copyright.license_texts(crate, {key: set(json.loads(extra))})
    print(json.dumps({"files": [name for name, _ in texts],
                      "notices": copyright.notices(texts)}))
elif what == "sources":
    print(json.dumps(copyright.source_notices(crate)))
else:
    copyright.check_hand_checked([{"name": key[0], "version": v} for v in json.loads(extra)])
    print(json.dumps("checked"))
"#;

fn probe(dir: &Path, what: &str, listed: &str, extra: &str) -> Result<Value, String> {
    let probe = dir.join("probe.py");
    fs::write(&probe, PROBE).expect("write the probe");
    let script = root().join("packaging/copyright.py");
    let crate_dir = dir.join("stand-in");
    let out = python(
        &probe,
        &[
            script.as_os_str(),
            crate_dir.as_os_str(),
            what.as_ref(),
            listed.as_ref(),
            extra.as_ref(),
        ],
    );
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).expect("JSON"))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[test]
fn copyright_stops_at_a_license_file_below_a_crate_that_nobody_checked() {
    if !python3() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let stand_in = dir.path().join("stand-in");
    let file = |relative: &str, text: &[u8]| {
        let path = stand_in.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, text).expect("write");
    };
    file("Cargo.toml", b"");
    // A license written as a comment: its notice is found all the same, and
    // the sentences of license texts about notices are not notices.
    file(
        "LICENSE",
        b"// Copyright 2020 A Stand-In\n//\n// Permission to use, copy, modify... provided that the above\n\
          // copyright notice and this permission notice appear in all copies.\n\
          // Copyright [yyyy] [name of copyright owner]\n\
          // COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n\
          // portions of the Software.\n",
    );
    file(
        "vendored/LICENSE-BSD",
        b"Copyright (c) 2019 Vendored Code\nRedistribution and use...\n",
    );

    let refused = |result: Result<Value, String>, why: &str| match result {
        Err(said) => assert!(said.contains(why), "{said}"),
        Ok(found) => panic!("not refused: {found}"),
    };
    // Nobody said whether its code is compiled in.
    refused(
        probe(dir.path(), "licenses", "{}", "[]"),
        "ships vendored/LICENSE-BSD, a license file below its top directory",
    );
    // Compiled in: its text and notice are included.
    let found = probe(
        dir.path(),
        "licenses",
        r#"{"vendored/LICENSE-BSD": true}"#,
        "[]",
    )
    .expect("included");
    assert_eq!(
        found["files"],
        serde_json::json!(["LICENSE", "vendored/LICENSE-BSD"])
    );
    assert_eq!(
        found["notices"],
        serde_json::json!([
            "Copyright 2020 A Stand-In",
            "Copyright (c) 2019 Vendored Code"
        ])
    );
    // Compiled only without a feature: left out while the build enables it.
    let found = probe(
        dir.path(),
        "licenses",
        r#"{"vendored/LICENSE-BSD": "std"}"#,
        r#"["std"]"#,
    )
    .expect("left out");
    assert_eq!(found["files"], serde_json::json!(["LICENSE"]));
    refused(
        probe(
            dir.path(),
            "licenses",
            r#"{"vendored/LICENSE-BSD": "std"}"#,
            "[]",
        ),
        "no longer enables",
    );
    // Never compiled in, whatever the features: left out.
    let found = probe(
        dir.path(),
        "licenses",
        r#"{"vendored/LICENSE-BSD": false}"#,
        "[]",
    )
    .expect("left out");
    assert_eq!(found["files"], serde_json::json!(["LICENSE"]));
    // A file listed but gone: the crate changed, check it again.
    refused(
        probe(
            dir.path(),
            "licenses",
            r#"{"vendored/LICENSE-BSD": true, "gone/LICENSE": true}"#,
            "[]",
        ),
        "has no gone/LICENSE",
    );
    // A directory named like a license file holds license files too.
    file("LICENSES/MIT.txt", b"MIT License\n");
    refused(
        probe(
            dir.path(),
            "licenses",
            r#"{"vendored/LICENSE-BSD": true}"#,
            "[]",
        ),
        "ships LICENSES/MIT.txt",
    );

    // The notices at the top of source files, each once; files that are
    // not text are skipped.
    file(
        "src/a.c",
        b"/* Copyright (c) 2014, Someone Inc.\n *\n * Permission to use...\n */\n",
    );
    // The notice of a second author ("Portions Copyright"), and one in ARM
    // assembly, whose comments start with `@`.
    file(
        "src/deep/b.rs",
        b"// Copyright 2016 Another Author.\n// Portions Copyright (c) 2014, Someone Inc.\n\
          // Copyright (c) 2014, Someone Inc.\n",
    );
    file(
        "src/deep/d.S",
        b"@ Copyright 2012-2016 An Assembler. All Rights Reserved.\n@\n@ Licensed...\n",
    );
    file("src/c.o", b"\x7fELF\0\0\nCopyright 1999 Not Text\n");
    assert_eq!(
        probe(dir.path(), "sources", "{}", "[]").expect("notices"),
        serde_json::json!([
            "Copyright (c) 2014, Someone Inc.",
            "Copyright 2012-2016 An Assembler. All Rights Reserved.",
            "Copyright 2016 Another Author.",
            "Portions Copyright (c) 2014, Someone Inc."
        ])
    );
    // A crate whose source files were checked by hand, replaced by another
    // version: nobody checked that one.
    assert_eq!(
        probe(dir.path(), "checked", "{}", r#"["1.0.0"]"#).expect("checked"),
        "checked"
    );
    refused(
        probe(dir.path(), "checked", "{}", r#"["1.0.1"]"#),
        "stand-in 1.0.0, which NOTICES_IN_SOURCES lists, is no longer compiled in",
    );
    // The script checks it, and writes nothing then.
    refused(
        probe(dir.path(), "main", "{}", "[]"),
        "stand-in 1.0.0, which NOTICES_IN_SOURCES lists, is no longer compiled in",
    );
    assert!(!stand_in.join("copyright").exists());
}
