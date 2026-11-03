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

// What ships: packaging/check-broker.py --staged on stand-in packages
// (unpacked by a stand-in `dpkg-deb -x`) and on a real package where
// dpkg-deb is installed, and packaging/build-deb.sh run whole on stand-ins
// for cargo and dpkg-deb.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Stdio;
use std::time::{Duration, Instant};

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
/// `dir/dpkg-deb-calls`. If `dir/dpkg-deb-interrupts` exists, it interrupts
/// the program that runs it instead (SIGINT, as Ctrl-C does) and waits.
fn dpkg_deb_stand_in(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).expect("mkdir");
    write_program(
        &bin.join("dpkg-deb"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{0}/dpkg-deb-calls'\n\
             [ -e '{0}/dpkg-deb-interrupts' ] && {{ kill -INT \"$PPID\"; exec sleep 10; }}\n\
             [ $# = 3 ] && [ \"$1\" = -x ] || {{ echo \"dpkg-deb stand-in: $*\" >&2; exit 2; }}\n\
             mkdir -p \"$3\" && tail -c +{1} \"$2\" | tar -xf - -C \"$3\"\n",
            dir.display(),
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

/// A stand-in package at `path` of the brokers `brokers` (path in the
/// package, --check answer), built in the directory `tree`.
fn pack_brokers(tree: &Path, path: &Path, brokers: &[(&str, &str)]) {
    let _ = fs::remove_dir_all(tree);
    fs::create_dir_all(tree.join("usr/share/doc/rusthorse")).expect("mkdir");
    for (inside, answer) in brokers {
        let at = tree.join(inside);
        fs::create_dir_all(at.parent().expect("parent")).expect("mkdir");
        write_broker(&at, answer);
    }
    pack(tree, path);
}

/// packaging/check-broker.py --staged: the packages in `staging`, meant for
/// `dest`, unpacked in `scratch`, with `path` as PATH.
fn check_staged(path: &str, staging: &Path, dest: &Path, scratch: &Path) -> Output {
    Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(root().join("packaging/check-broker.py"))
        .arg("--staged")
        .arg(env!("CARGO_PKG_VERSION"))
        .arg(scratch)
        .arg(staging)
        .arg(dest)
        .env("PATH", path)
        .current_dir(root())
        .output()
        .expect("run check-broker.py")
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

/// What check-broker.py says when it stopped before moving anything to
/// `dest`.
fn nothing_moved(dest: &Path) -> String {
    format!(
        "nothing is moved to {}, and what cargo-deb wrote is deleted",
        dest.display()
    )
}

/// The names in the directory `dir`; none if there is no such directory.
fn names(dir: &Path) -> BTreeSet<OsString> {
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .map(|entry| entry.expect("entry").file_name())
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => panic!("{}: {e}", dir.display()),
    }
}

fn set(names: &[&str]) -> BTreeSet<OsString> {
    names.iter().map(OsString::from).collect()
}

#[test]
fn a_package_whose_broker_is_not_a_release_build_never_ships() {
    if !python3() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dpkg_deb_stand_in(dir.path());
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    let staging = dir.path().join("staging");
    let dest = dir.path().join("dest");
    let tree = dir.path().join("tree");
    // A new staging directory holding the packages `packages`: each a name
    // and its brokers.
    let stage = |packages: &[(&str, &[(&str, &str)])]| {
        fs::create_dir(&staging).expect("mkdir staging");
        for (name, brokers) in packages {
            pack_brokers(&tree, &staging.join(name), brokers);
        }
    };
    let release = release_answer();
    let release = release.as_str();
    let for_tests = for_tests_answer();
    let for_tests = for_tests.as_str();
    let broker = "usr/bin/rusthorse-broker";
    // Refused, saying `why`: nothing reaches DEST, and the staging directory
    // is gone with whatever it held, as is what was unpacked.
    let refused = |why: &str| {
        let out = check_staged(&path, &staging, &dest, &scratch);
        assert_refused(&out, &format!("check-broker.py: {why}"));
        assert_refused(
            &out,
            &format!(
                ": refusing to package it; {}. A package must",
                nothing_moved(&dest)
            ),
        );
        assert!(out.stdout.is_empty(), "{out:?}");
        assert!(!staging.exists(), "{why}");
        assert!(names(&dest).is_empty(), "{why}: {:?}", names(&dest));
        assert!(names(&scratch).is_empty(), "{why}");
    };

    // Accepted: the broker of the package is a release build, and a package
    // of debugging symbols, which has none, may go with it. Both are moved,
    // and their new paths printed.
    stage(&[
        ("rusthorse.deb", &[(broker, release)]),
        ("rusthorse-dbgsym.ddeb", &[]),
    ]);
    let wrote = fs::read(staging.join("rusthorse.deb")).expect("the package");
    let out = check_staged(&path, &staging, &dest, &scratch);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "{0}/rusthorse-dbgsym.ddeb\n{0}/rusthorse.deb\n",
            dest.display()
        )
    );
    assert_eq!(
        names(&dest),
        set(&["rusthorse-dbgsym.ddeb", "rusthorse.deb"])
    );
    assert_eq!(fs::read(dest.join("rusthorse.deb")).expect("moved"), wrote);
    assert!(!staging.exists());
    // Each checked where cargo-deb wrote it, unpacked in a directory of its
    // own, removed afterwards.
    let calls = fs::read_to_string(dir.path().join("dpkg-deb-calls")).expect("calls");
    for name in ["rusthorse-dbgsym.ddeb", "rusthorse.deb"] {
        assert!(
            calls.contains(&format!(
                "-x {}/{name} {}/",
                staging.display(),
                scratch.display()
            )),
            "{calls}"
        );
    }
    assert!(names(&scratch).is_empty());
    fs::remove_dir_all(&dest).expect("rm");

    // A build for tests: refused, and neither package moved.
    stage(&[
        ("rusthorse.deb", &[(broker, for_tests)]),
        ("rusthorse-dbgsym.ddeb", &[]),
    ]);
    refused(&format!(
        "{broker} in rusthorse.deb is a build for tests (its --check reports test_upstream)"
    ));

    // Every broker in the package is checked, wherever it is.
    stage(&[(
        "rusthorse.deb",
        &[
            (broker, release),
            ("usr/local/bin/rusthorse-broker", for_tests),
        ],
    )]);
    refused(
        "usr/local/bin/rusthorse-broker in rusthorse.deb is a build for tests (its --check \
         reports test_upstream)",
    );

    // Something else than a broker, a regular file, under its name.
    for (what, make) in [
        ("a link", "ln -s /bin/true \"$1/usr/bin/rusthorse-broker\""),
        ("a directory", "mkdir \"$1/usr/bin/rusthorse-broker\""),
    ] {
        let _ = fs::remove_dir_all(&tree);
        fs::create_dir_all(tree.join("usr/bin")).expect("mkdir");
        let made = Command::new("/bin/sh")
            .args(["-c", make, "sh"])
            .arg(&tree)
            .status()
            .expect("sh");
        assert!(made.success(), "{what}");
        fs::create_dir(&staging).expect("mkdir staging");
        pack(&tree, &staging.join("odd.deb"));
        refused(&format!("{broker} in odd.deb is not a regular file"));
    }

    // No broker at all: a package that does not hold the program checked
    // first; the check would otherwise check nothing.
    stage(&[("rusthorse.deb", &[]), ("rusthorse-dbgsym.ddeb", &[])]);
    refused("no rusthorse-broker in rusthorse-dbgsym.ddeb, rusthorse.deb");

    // A package that cannot be unpacked, and nothing at all.
    fs::create_dir(&staging).expect("mkdir staging");
    fs::write(staging.join("rusthorse.deb"), "not an archive").expect("write");
    refused("rusthorse.deb cannot be unpacked (dpkg-deb -x: exit status");
    stage(&[]);
    refused("cargo-deb wrote no package");

    // Whatever else stops the check (here, no directory to unpack in), it
    // says so, and nothing reaches DEST either.
    stage(&[("rusthorse.deb", &[(broker, release)])]);
    let out = check_staged(&path, &staging, &dest, &dir.path().join("gone"));
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains(&format!(
            "check-broker.py: the packages could not all be checked and moved; {}\n",
            nothing_moved(&dest)
        )),
        "{said}"
    );
    assert!(!staging.exists());
    assert!(names(&dest).is_empty());
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
    let staging = dir.path().join("staging");
    fs::create_dir(&staging).expect("mkdir");
    let out = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", PACK_HIDDEN])
        .arg(&stage)
        .output()
        .expect("python3");
    assert!(out.status.success(), "{out:?}");
    fs::write(staging.join("rusthorse.deb"), stand_in_package(&out.stdout))
        .expect("write the package");
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    let dest = dir.path().join("dest");
    let out = check_staged(
        &format!("{}:/usr/bin:/bin", bin.display()),
        &staging,
        &dest,
        &scratch,
    );
    assert_refused(&out, "cannot be read in the unpacked package");
    assert!(!staging.exists());
    assert!(names(&dest).is_empty());
    // What it unpacked is removed, unreadable directory included.
    assert!(names(&scratch).is_empty());
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
    let staging = dir.path().join("staging");
    let scratch = dir.path().join("scratch");
    fs::create_dir_all(&scratch).expect("mkdir");
    // A new staging directory holding a package whose broker answers
    // `answer`, built by the real dpkg-deb.
    let build = |answer: &str| {
        write_broker(&stage.join("usr/bin/rusthorse-broker"), answer);
        fs::create_dir(&staging).expect("mkdir");
        let out = Command::new("/usr/bin/dpkg-deb")
            .args(["--build", "--root-owner-group"])
            .arg(&stage)
            .arg(staging.join("rusthorse.deb"))
            .output()
            .expect("dpkg-deb --build");
        assert!(out.status.success(), "{out:?}");
    };
    let dest = dir.path().join("dest");
    build(&release_answer());
    let wrote = fs::read(staging.join("rusthorse.deb")).expect("the package");
    let out = check_staged("/usr/bin:/bin", &staging, &dest, &scratch);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read(dest.join("rusthorse.deb")).expect("moved"), wrote);
    assert!(!staging.exists());
    let dest = dir.path().join("refused");
    build(&for_tests_answer());
    assert_refused(
        &check_staged("/usr/bin:/bin", &staging, &dest, &scratch),
        &format!(
            "usr/bin/rusthorse-broker in rusthorse.deb is a build for tests (its --check \
             reports test_upstream): refusing to package it; {}. ",
            nothing_moved(&dest)
        ),
    );
    assert!(!staging.exists());
    assert!(names(&dest).is_empty());
}

/// A run of packaging/build-deb.sh on stand-ins, in a temporary directory
/// F. Its `cargo`, first on PATH, appends its arguments to F/cargo-calls:
/// `build` copies the programs of F/built to F/target/release, as a build
/// writes them there; `metadata --no-deps` describes a workspace whose
/// target directory is F/target; `deb` packages F/target/release's broker
/// (or F/shipped-broker, if there is one) as usr/bin/rusthorse-broker in a
/// stand-in package, and with `--dbgsym` also writes a -dbgsym package
/// without one. It writes them where `--output` says, as cargo-deb does:
/// into that directory if the path ends with / or names one (or has no
/// extension), else at that path; under the name in F/deb-name if there is
/// one. It keeps a copy of each in F/wrote, runs the shell script F/after-deb
/// (if there is one) with that directory and F as arguments, prints the
/// paths of the packages, as cargo-deb does, sends the shell that runs it
/// the signal named in F/deb-signal (TERM, say) if there is one, and exits
/// with the status in F/deb-fails if there is one. Like cargo-deb, it
/// refuses a second `--output` (exit status 2). Whatever else it is asked
/// (copyright.py's `metadata` and `tree`) goes to the real cargo. Its
/// `dpkg-deb -x` unpacks those packages. Everything else is real: the
/// checks, the copyright file and the documentation, which are generated in
/// F/target/release/packaging.
struct DebBuild(tempfile::TempDir);

/// The stand-in `cargo` of `DebBuild`; F, REAL_CARGO, DEB and DDEB are set
/// before it.
const CARGO_STAND_IN: &str = r#"
printf '%s\n' "$*" >> "$F/cargo-calls"
# A stand-in package at $2 of the files of the directory $1.
package() {
    tar -cf "$F/data.tar" -C "$1" .
    size=$(wc -c < "$F/data.tar")
    {
        printf '!<arch>\n%-16s%-12s%-6s%-6s%-8s%-10s`\n2.0\n' debian-binary 0 0 0 100644 4
        printf '%-16s%-12s%-6s%-6s%-8s%-10s`\n' data.tar 0 0 0 100644 $size
        cat "$F/data.tar"
    } > "$2"
    cp -p "$2" "$F/wrote/"
    printf '%s\n' "$2"
}
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
    shift
    out=$F/target/debian/
    outputs=0
    dbgsym=
    while [ $# -gt 0 ]; do
        arg=$1
        shift
        case $arg in
        --) break ;;
        --dbgsym) dbgsym=1 ;;
        --output=*) outputs=$((outputs + 1)); out=${arg#--output=} ;;
        --output) outputs=$((outputs + 1)); out=$1; shift ;;
        -o*)
            outputs=$((outputs + 1))
            out=${arg#-o}
            out=${out#=}
            [ -n "${arg#-o}" ] || { out=$1; shift; }
            ;;
        -[qv]o*)
            outputs=$((outputs + 1))
            out=${arg#-?o}
            out=${out#=}
            [ -n "${arg#-?o}" ] || { out=$1; shift; }
            ;;
        esac
    done
    if [ "$outputs" -gt 1 ]; then
        echo "error: the argument '--output <path>' cannot be used multiple times" >&2
        exit 2
    fi
    name=$DEB
    [ -e "$F/deb-name" ] && name=$(cat "$F/deb-name")
    dir=${out%/}
    deb=$dir/$name
    case $out in
    */) ;;
    *)
        case ${out##*/} in
        *.*)
            if [ ! -d "$out" ]; then
                dir=${out%/*}
                deb=$out
            fi
            ;;
        esac
        ;;
    esac
    broker=$F/target/release/rusthorse-broker
    [ -e "$F/shipped-broker" ] && broker=$F/shipped-broker
    rm -rf "$F/stage"
    mkdir -p "$F/stage/usr/bin" "$F/wrote" "$dir"
    cp -p "$broker" "$F/stage/usr/bin/rusthorse-broker"
    package "$F/stage" "$deb"
    if [ -n "$dbgsym" ]; then
        rm -rf "$F/stage"
        mkdir -p "$F/stage/usr/lib/debug"
        echo "debugging symbols" > "$F/stage/usr/lib/debug/rusthorse.debug"
        package "$F/stage" "$dir/$DDEB"
    fi
    [ ! -e "$F/after-deb" ] || sh "$F/after-deb" "$dir" "$F" || exit 1
    [ ! -e "$F/deb-signal" ] || kill -s "$(cat "$F/deb-signal")" "$PPID"
    [ ! -e "$F/deb-fails" ] || exit "$(cat "$F/deb-fails")"
    exit 0
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

/// The names of the package and of the -dbgsym package the stand-in
/// `cargo deb` writes.
fn deb_name() -> String {
    format!("rusthorse_{}-1_amd64.deb", env!("CARGO_PKG_VERSION"))
}

fn ddeb_name() -> String {
    format!(
        "rusthorse-dbgsym_{}-1_amd64.ddeb",
        env!("CARGO_PKG_VERSION")
    )
}

/// How long a run of build-deb.sh may take before it is taken for one that
/// waits forever (on a FIFO it opened, say), and killed.
const DEB_BUILD_LIMIT: Duration = Duration::from_secs(120);

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
                "#!/bin/sh\nF='{}'\nREAL_CARGO='{}'\nDEB='{}'\nDDEB='{}'\n{CARGO_STAND_IN}",
                f.display(),
                real_cargo().display(),
                deb_name(),
                ddeb_name()
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

    /// Run build-deb.sh with `args`, and `env` added to the environment, in
    /// a process group of its own: killed, with all it started, if it runs
    /// past `DEB_BUILD_LIMIT`, and the test fails. HUP, INT and TERM have
    /// their default action in it, as in a terminal, whatever the tests
    /// inherited (`nohup` ignores HUP; a shell ignores INT in a job it puts
    /// in the background): a shell cannot trap a signal that was ignored when
    /// it started, nor Python turn such an INT into KeyboardInterrupt.
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        use std::os::unix::process::CommandExt;
        let path = std::env::var("PATH").unwrap_or_default();
        let (stdout, stderr) = (self.path("run.stdout"), self.path("run.stderr"));
        let mut child = Command::new("/usr/bin/env")
            .args(["--default-signal=HUP,INT,TERM", "/bin/sh"])
            .arg(root().join("packaging/build-deb.sh"))
            .args(args)
            .env("PATH", format!("{}:{path}", self.path("bin").display()))
            .env_remove("CARGO_BUILD_TARGET")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).expect("create"))
            .stderr(fs::File::create(&stderr).expect("create"))
            .process_group(0)
            .spawn()
            .expect("run build-deb.sh");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if started.elapsed() > DEB_BUILD_LIMIT {
                let group = nix::unistd::Pid::from_raw(child.id() as i32);
                let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                let _ = child.wait();
                panic!(
                    "build-deb.sh {args:?} did not end within {DEB_BUILD_LIMIT:?}: {}",
                    fs::read_to_string(&stderr).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Output {
            status,
            stdout: fs::read(&stdout).expect("stdout"),
            stderr: fs::read(&stderr).expect("stderr"),
        }
    }

    /// What the stand-in `cargo` was asked, one call a line.
    fn cargo_calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("cargo-calls"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    /// The last `cargo deb` call, with STAGING for the staging directory it
    /// names: a new directory in F/target/release/packaging, which mktemp
    /// names staging. and ten characters.
    fn deb_call(&self) -> String {
        let calls = self.cargo_calls();
        let call = calls
            .iter()
            .rev()
            .find(|call| call.starts_with("deb "))
            .unwrap_or_else(|| panic!("no cargo deb: {calls:#?}"));
        let staging = format!(
            "{}/staging.",
            self.path("target/release/packaging").display()
        );
        let at = call
            .find(&staging)
            .unwrap_or_else(|| panic!("no staging directory in {call}"));
        let end = at + staging.len() + 10;
        format!("{}STAGING{}", &call[..at], &call[end..])
    }

    /// The staging directories left in F/target/release/packaging.
    fn staging_left(&self) -> Vec<OsString> {
        names(&self.path("target/release/packaging"))
            .into_iter()
            .filter(|name| name.to_string_lossy().starts_with("staging."))
            .collect()
    }

    /// What the stand-in `cargo deb` wrote under the name `name`.
    fn wrote(&self, name: &str) -> Vec<u8> {
        fs::read(self.path("wrote").join(name)).expect("what cargo-deb wrote")
    }
}

/// A path as an argument of build-deb.sh.
fn arg(path: &Path) -> &str {
    path.to_str().expect("UTF-8")
}

/// A temporary directory on another file system than `run`'s staging
/// directory (in /dev/shm), where there is one; a package goes there as a
/// copy rather than renamed.
fn elsewhere(run: &DebBuild) -> Option<tempfile::TempDir> {
    let here = fs::metadata(run.path("target")).expect("target").dev();
    let other = tempfile::tempdir_in("/dev/shm")
        .ok()
        .filter(|other| fs::metadata(other.path()).expect("/dev/shm").dev() != here);
    if other.is_none() {
        eprintln!("skipped in part: no other file system in /dev/shm");
    }
    other
}

#[test]
fn the_package_is_built_without_features_and_only_after_the_broker_is_checked() {
    if !python3() {
        return;
    }
    let release = release_answer();
    let for_tests = for_tests_answer();

    // A release build: built without features, checked, packaged, checked
    // again as it ships, moved where --output says, and its path printed.
    let run = DebBuild::new(&release);
    fs::write(
        run.path("after-deb"),
        "stat -c %a \"$1\" > \"$2/staging-mode\"\n",
    )
    .expect("write");
    let output = run.path("out");
    let out = run.run(&["--output", arg(&output)], &[]);
    assert!(out.status.success(), "{out:?}");
    // A directory that only this user can enter.
    assert_eq!(
        fs::read_to_string(run.path("staging-mode")).expect("mode"),
        "700\n"
    );
    let calls = run.cargo_calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("build --release --locked --workspace"),
        "{calls:#?}"
    );
    assert!(
        calls.last().is_some_and(|call| call.starts_with("deb ")),
        "{calls:#?}"
    );
    // cargo-deb writes into a new directory of the script's own, never
    // where --output says.
    assert_eq!(
        run.deb_call(),
        "deb --no-build --locked -p rusthorse --output STAGING/"
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
    assert_eq!(fs::read(&deb).expect("the package"), run.wrote(&deb_name()));
    // Checked where cargo-deb wrote it, before it was moved.
    let checked = fs::read_to_string(run.path("dpkg-deb-calls")).expect("the package is checked");
    assert!(
        checked.starts_with(&format!(
            "-x {}/staging.",
            run.path("target/release/packaging").display()
        )) && checked.contains(&format!("/{} ", deb_name())),
        "{checked}"
    );
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
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
    // it is written, and nothing reaches target/debian, where it goes by
    // default.
    let run = DebBuild::new(&release);
    write_broker(&run.path("shipped-broker"), &for_tests);
    let out = run.run(&[], &[]);
    assert_refused(
        &out,
        &format!(
            "usr/bin/rusthorse-broker in {} is a build for tests (its --check reports \
             test_upstream): refusing to package it; {}. A package must",
            deb_name(),
            nothing_moved(&run.path("target/debian"))
        ),
    );
    assert!(
        run.cargo_calls().iter().any(|call| call.starts_with("deb")),
        "{:#?}",
        run.cargo_calls()
    );
    assert!(names(&run.path("target/debian")).is_empty());
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
    assert!(out.stdout.is_empty(), "{out:?}");

    // What would install the package before its check, build it for
    // another target, or package another manifest (cargo-deb names the
    // package after it, unchecked, and could so write it outside the
    // staging directory): refused before anything is built.
    for (args, env) in [
        (&["--install"][..], &[][..]),
        (&["--no-install-dbgsym"][..], &[][..]),
        (&["--target", "x86_64-unknown-linux-gnu"][..], &[][..]),
        (&["--target=x86_64-unknown-linux-gnu"][..], &[][..]),
        (
            &[][..],
            &[("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu")][..],
        ),
        (&["--manifest-path", "elsewhere/Cargo.toml"][..], &[][..]),
        (&["--manifest-path=elsewhere/Cargo.toml"][..], &[][..]),
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

#[test]
fn a_refused_package_never_reaches_its_directory_and_nothing_there_is_touched() {
    if !python3() {
        return;
    }
    let release = release_answer();
    let run = DebBuild::new(&release);
    write_broker(&run.path("shipped-broker"), &for_tests_answer());
    let dest = run.path("out");
    fs::create_dir(&dest).expect("mkdir");
    fs::write(dest.join("notes.txt"), "kept").expect("write");
    let out = run.run(&["--dbgsym", "--output", arg(&dest)], &[]);
    assert_refused(
        &out,
        &format!(
            "usr/bin/rusthorse-broker in {} is a build for tests (its --check reports \
             test_upstream): refusing to package it; {}. A package must",
            deb_name(),
            nothing_moved(&dest)
        ),
    );
    assert!(out.stdout.is_empty(), "{out:?}");
    // cargo-deb wrote both packages; neither reached DEST, and the staging
    // directory went with them. What was in DEST is as it was.
    assert_eq!(names(&run.path("wrote")), set(&[&ddeb_name(), &deb_name()]));
    assert_eq!(names(&dest), set(&["notes.txt"]));
    assert_eq!(
        fs::read_to_string(dest.join("notes.txt")).expect("notes"),
        "kept"
    );
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());

    // cargo-deb failed after it wrote the package: nothing is checked or
    // moved, what it wrote is deleted, and its exit status is the script's.
    let run = DebBuild::new(&release);
    fs::write(run.path("deb-fails"), "3").expect("write");
    let dest = run.path("failed");
    let out = run.run(&["--output", arg(&dest)], &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(
        said.contains("build-deb.sh: cargo-deb failed (exit status 3); what it wrote is deleted"),
        "{said}"
    );
    assert_eq!(names(&run.path("wrote")), set(&[&deb_name()]));
    assert!(!dest.exists());
    assert!(!run.path("dpkg-deb-calls").exists());
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
    assert!(out.stdout.is_empty(), "{out:?}");

    // The script gets a signal that ends it (a hang-up, Ctrl-C, SIGTERM)
    // once cargo-deb has written the package: it ends there, with the status
    // of a shell ended by that signal, and deletes the package unchecked.
    for (signal, status) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let run = DebBuild::new(&release);
        fs::write(run.path("deb-signal"), signal).expect("write");
        let dest = run.path("signalled");
        let out = run.run(&["--output", arg(&dest)], &[]);
        assert_eq!(out.status.code(), Some(status), "{signal}: {out:?}");
        assert_eq!(names(&run.path("wrote")), set(&[&deb_name()]), "{signal}");
        assert!(!dest.exists(), "{signal}");
        assert!(!run.path("dpkg-deb-calls").exists(), "{signal}");
        assert!(
            run.staging_left().is_empty(),
            "{signal}: {:?}",
            run.staging_left()
        );
        assert!(out.stdout.is_empty(), "{signal}: {out:?}");
    }
}

#[test]
fn an_accepted_run_moves_every_package_over_links_without_following_them() {
    if !python3() {
        return;
    }
    let run = DebBuild::new(&release_answer());
    // A third package: a copy of the first, under another name.
    fs::write(
        run.path("after-deb"),
        format!(
            "cp -p \"$1/{}\" \"$1/copy.deb\" && cp -p \"$1/copy.deb\" \"$2/wrote/\"\n",
            deb_name()
        ),
    )
    .expect("write");
    // DEST on the file system of the staging directory, where a package is
    // renamed, and on another one, where it is copied into a new file.
    let other = elsewhere(&run);
    let mut bases = vec![run.path("same")];
    bases.extend(other.iter().map(|other| other.path().join("other")));
    let moved = ["copy.deb".to_string(), ddeb_name(), deb_name()];
    for base in &bases {
        // What has the names of the packages in DEST: a symbolic link to a
        // file, a hard link to another one, and a symbolic link to a
        // directory, all outside DEST.
        let dest = base.join("dest");
        let outside = base.join("outside");
        fs::create_dir_all(&dest).expect("mkdir");
        fs::create_dir_all(outside.join("directory")).expect("mkdir");
        fs::write(outside.join("file"), "a file").expect("write");
        fs::write(outside.join("linked"), "a hard link").expect("write");
        fs::write(dest.join("notes.txt"), "kept").expect("write");
        std::os::unix::fs::symlink(outside.join("file"), dest.join(deb_name())).expect("ln -s");
        fs::hard_link(outside.join("linked"), dest.join(ddeb_name())).expect("ln");
        std::os::unix::fs::symlink(outside.join("directory"), dest.join("copy.deb"))
            .expect("ln -s");

        let out = run.run(&["--dbgsym", "--output", arg(&dest)], &[]);
        assert!(out.status.success(), "{}: {out:?}", dest.display());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            moved
                .iter()
                .map(|name| format!("{}/{name}\n", dest.display()))
                .collect::<String>()
        );
        // Each a file of its own with what cargo-deb wrote, in its mode.
        for name in &moved {
            let at = dest.join(name);
            let found = fs::symlink_metadata(&at).expect("moved");
            assert!(found.file_type().is_file(), "{}", at.display());
            assert_eq!(found.nlink(), 1, "{}", at.display());
            assert_eq!(
                fs::read(&at).expect("read"),
                run.wrote(name),
                "{}",
                at.display()
            );
            let written = fs::metadata(run.path("wrote").join(name)).expect("wrote");
            assert_eq!(
                found.permissions().mode() & 0o7777,
                written.permissions().mode() & 0o7777,
                "{}",
                at.display()
            );
        }
        // What the links led to is as it was, and nothing else is left in
        // DEST (no temporary file).
        assert_eq!(
            fs::read_to_string(outside.join("file")).expect("file"),
            "a file"
        );
        assert_eq!(
            fs::read_to_string(outside.join("linked")).expect("linked"),
            "a hard link"
        );
        assert_eq!(
            fs::metadata(outside.join("linked"))
                .expect("linked")
                .nlink(),
            1
        );
        assert!(names(&outside.join("directory")).is_empty());
        let mut expected = set(&["notes.txt"]);
        expected.extend(moved.iter().map(OsString::from));
        assert_eq!(names(&dest), expected);
        assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
    }
}

#[test]
fn a_name_with_a_newline_is_moved_or_removed_whole() {
    if !python3() {
        return;
    }
    let name = "line\nname.pkg";
    let run = DebBuild::new(&release_answer());
    fs::write(run.path("deb-name"), name).expect("write");
    let dest = run.path("out");
    let out = run.run(&["--output", arg(&dest)], &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}/{name}\n", dest.display())
    );
    assert_eq!(names(&dest), set(&[name]));
    assert_eq!(fs::read(dest.join(name)).expect("moved"), run.wrote(name));
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());

    write_broker(&run.path("shipped-broker"), &for_tests_answer());
    let dest = run.path("refused");
    let out = run.run(&["--output", arg(&dest)], &[]);
    assert_refused(
        &out,
        &format!(
            "usr/bin/rusthorse-broker in {name} is a build for tests (its --check reports \
             test_upstream): refusing to package it; {}",
            nothing_moved(&dest)
        ),
    );
    assert!(names(&dest).is_empty());
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
}

#[test]
fn every_form_of_output_names_the_directory_the_packages_go_to() {
    if !python3() {
        return;
    }
    let run = DebBuild::new(&release_answer());
    let to = |n: usize| run.path(&format!("out{n}"));
    // Each form cargo-deb reads as --output, and what goes on to it: one
    // --output, its own; the one-letter flags before -o stay.
    for (args, dest, forwarded) in [
        (
            vec!["--output".to_string(), arg(&to(0)).into()],
            to(0),
            String::new(),
        ),
        (
            vec![format!("--output={}", arg(&to(1)))],
            to(1),
            String::new(),
        ),
        (
            vec!["-o".to_string(), arg(&to(2)).into()],
            to(2),
            String::new(),
        ),
        (vec![format!("-o{}", arg(&to(3)))], to(3), String::new()),
        (vec![format!("-o={}", arg(&to(4)))], to(4), String::new()),
        (
            vec!["-qo".to_string(), arg(&to(5)).into()],
            to(5),
            " -q".into(),
        ),
        (vec![format!("-vvo={}", arg(&to(6)))], to(6), " -vv".into()),
        // What cargo-deb would take for the name of the package names a
        // directory here.
        (
            vec![
                "--output".to_string(),
                arg(&to(7).join("release.pkg")).into(),
            ],
            to(7).join("release.pkg"),
            String::new(),
        ),
        // After --, nothing is an option: the default directory.
        (
            vec!["--".to_string(), "--output".into(), arg(&to(8)).into()],
            run.path("target/debian"),
            format!(" -- --output {}", arg(&to(8))),
        ),
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run.run(&args, &[]);
        assert!(out.status.success(), "{args:?}: {out:?}");
        assert_eq!(
            run.deb_call(),
            format!("deb --no-build --locked -p rusthorse --output STAGING/{forwarded}"),
            "{args:?}"
        );
        let deb = dest.join(deb_name());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{}\n", deb.display()),
            "{args:?}"
        );
        assert_eq!(names(&dest), set(&[&deb_name()]), "{args:?}");
    }
    assert!(!to(8).exists());

    // A relative DIR is taken from the repository's root, where the script
    // runs cargo-deb, as cargo-deb would take it; so is the path printed.
    // Here a new directory in the repository's target/, which Git ignores:
    // its relative path leads there from the root only.
    let target = root().join("target");
    fs::create_dir_all(&target).expect("mkdir target");
    let inside = tempfile::tempdir_in(&target).expect("tempdir in target");
    let name = inside.path().file_name().expect("a name");
    let relative = format!("target/{}/out", name.to_str().expect("UTF-8"));
    let out = run.run(&["--output", &relative], &[]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{relative}/{}\n", deb_name())
    );
    assert_eq!(names(&inside.path().join("out")), set(&[&deb_name()]));

    // Refused before anything is built: a path that is not a directory (a
    // file, a link to one, a link to nothing), a missing or empty value, a
    // value that cargo-deb reads as an option, and a second --output.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file.deb");
    fs::write(&file, "a file").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link).expect("ln -s");
    let nowhere = dir.path().join("nowhere");
    std::os::unix::fs::symlink(dir.path().join("missing"), &nowhere).expect("ln -s");
    let not_a_directory = |path: &Path| {
        format!(
            "build-deb.sh: {} is not a directory: --output names the directory the packages \
             go to\n",
            path.display()
        )
    };
    for (args, said) in [
        (
            vec!["--output".to_string(), arg(&file).into()],
            not_a_directory(&file),
        ),
        (
            vec![format!("--output={}", arg(&link))],
            not_a_directory(&link),
        ),
        (
            vec!["-o".to_string(), arg(&nowhere).into()],
            not_a_directory(&nowhere),
        ),
        (
            vec!["--output".to_string()],
            "build-deb.sh: --output needs a directory\n".to_string(),
        ),
        (
            vec!["--output=".to_string()],
            "build-deb.sh: --output= needs a directory\n".to_string(),
        ),
        (
            vec!["-qo".to_string()],
            "build-deb.sh: -qo needs a directory\n".to_string(),
        ),
        (
            vec!["--output".to_string(), "-q".into()],
            "build-deb.sh: --output needs a directory, not -q (write --output=DIR for one \
             whose name begins with -)\n"
                .to_string(),
        ),
        (
            vec![
                "--output".to_string(),
                arg(&to(0)).into(),
                "-o".into(),
                arg(&to(1)).into(),
            ],
            "build-deb.sh: -o: --output can be given only once\n".to_string(),
        ),
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = DebBuild::new(&release_answer());
        let out = run.run(&args, &[]);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), said, "{args:?}");
        assert!(run.cargo_calls().is_empty(), "{:#?}", run.cargo_calls());
    }
    assert_eq!(fs::read_to_string(&file).expect("file"), "a file");
}

#[test]
fn what_is_not_a_regular_file_among_the_packages_is_refused_unopened() {
    if !python3() {
        return;
    }
    // Put next to the packages by cargo-deb (the stand-in's after-deb): a
    // FIFO, which an open would wait on; a symbolic link to a package that
    // passes, outside the staging directory; a directory holding one.
    for (made, kind) in [
        ("mkfifo \"$1/odd.deb\"\n", "a FIFO"),
        (
            "cp -p \"$1/DEB\" \"$2/elsewhere.deb\" && ln -s \"$2/elsewhere.deb\" \"$1/odd.deb\"\n",
            "a symbolic link",
        ),
        (
            "mkdir \"$1/odd.deb\" && cp -p \"$1/DEB\" \"$1/odd.deb/\"\n",
            "a directory",
        ),
    ] {
        let run = DebBuild::new(&release_answer());
        fs::write(run.path("after-deb"), made.replace("DEB", &deb_name())).expect("write");
        let dest = run.path("out");
        let out = run.run(&["--output", arg(&dest)], &[]);
        assert_refused(
            &out,
            &format!(
                "odd.deb, in what cargo-deb wrote, is {kind}, not a package: refusing to \
                 package it; {}",
                nothing_moved(&dest)
            ),
        );
        assert!(names(&dest).is_empty(), "{kind}: {:?}", names(&dest));
        assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
        // Nothing was unpacked: the listing stops first.
        assert!(!run.path("dpkg-deb-calls").exists(), "{kind}");
        if kind == "a symbolic link" {
            assert_eq!(
                fs::read(run.path("elsewhere.deb")).expect("the link's target"),
                run.wrote(&deb_name())
            );
        }
    }
}

#[test]
fn a_check_stopped_otherwise_still_removes_what_cargo_deb_wrote() {
    if !python3() {
        return;
    }
    let release = release_answer();
    let stopped = |out: &Output, error: &str, what: &str| {
        let said = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{said}");
        assert!(
            said.contains(&format!(
                "check-broker.py: the packages could not all be checked and moved; {what}\n"
            )),
            "{said}"
        );
        assert!(said.contains(error), "{said}");
        assert!(out.stdout.is_empty(), "{out:?}");
    };

    // Interrupted (Ctrl-C) while it unpacks a package.
    let run = DebBuild::new(&release);
    fs::write(run.path("dpkg-deb-interrupts"), "").expect("write");
    let dest = run.path("out");
    let out = run.run(&["--output", arg(&dest)], &[]);
    stopped(&out, "KeyboardInterrupt", &nothing_moved(&dest));
    assert!(names(&dest).is_empty());
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());

    // A move that fails: what has the name of the second package in DEST is
    // a directory. The first, which passed, stays; the rest goes, and so
    // does the new file a copy to another file system wrote.
    let run = DebBuild::new(&release);
    let other = elsewhere(&run);
    let mut bases = vec![run.path("same")];
    bases.extend(other.iter().map(|other| other.path().join("other")));
    for base in &bases {
        let dest = base.join("out");
        fs::create_dir_all(dest.join(deb_name()).join("inside")).expect("mkdir");
        let out = run.run(&["--dbgsym", "--output", arg(&dest)], &[]);
        stopped(
            &out,
            "IsADirectoryError",
            &format!(
                "moved {}, which passed; the rest of what cargo-deb wrote is deleted",
                dest.join(ddeb_name()).display()
            ),
        );
        assert_eq!(names(&dest), set(&[&ddeb_name(), &deb_name()]));
        assert_eq!(
            fs::read(dest.join(ddeb_name())).expect("moved"),
            run.wrote(&ddeb_name())
        );
        assert_eq!(names(&dest.join(deb_name())), set(&["inside"]));
        assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
    }

    // DEST cannot be written to.
    if nix::unistd::geteuid().is_root() {
        // Root writes in any directory.
        return;
    }
    let run = DebBuild::new(&release);
    let dest = run.path("read-only");
    fs::create_dir(&dest).expect("mkdir");
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o555)).expect("chmod");
    let out = run.run(&["--output", arg(&dest)], &[]);
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).expect("chmod");
    stopped(&out, "PermissionError", &nothing_moved(&dest));
    assert!(names(&dest).is_empty());
    assert!(run.staging_left().is_empty(), "{:?}", run.staging_left());
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
