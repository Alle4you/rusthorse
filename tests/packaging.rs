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

#[test]
fn the_package_is_built_without_features_and_only_after_the_broker_is_checked() {
    let script = fs::read_to_string(root().join("packaging/build-deb.sh")).expect("build-deb.sh");
    let commands: Vec<&str> = script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let at = |start: &str| {
        commands
            .iter()
            .position(|line| line.starts_with(start))
            .unwrap_or_else(|| panic!("build-deb.sh does not run {start}"))
    };
    let strict = at("set -eu");
    let build = at("cargo build --release --locked --workspace");
    let check =
        at(r#"python3 -I packaging/check-broker.py "$target/release/rusthorse-broker" "$version""#);
    let package = at("cargo deb --no-build");
    assert!(strict < build && build < check && check < package);
    // The broker's only feature is for tests: no feature is ever turned on.
    for line in &commands {
        assert!(
            !["--features", "--all-features", " -F"]
                .iter()
                .any(|flag| line.contains(flag)),
            "{line}"
        );
    }
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
    use std::process::Stdio;
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
        // The answer of a broker that is asked --check with nothing in its
        // environment and `/` as working directory, as `rusthorse doctor`
        // asks it.
        write_program(
            &broker,
            &format!(
                "#!/bin/sh\n[ \"$1\" = --check ] && [ -z \"${{HOME-}}\" ] && \
                 [ \"$(pwd -P)\" = / ] || exit 9\nprintf '%s\\n' '{answer}'\n"
            ),
        );
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
    assert!(
        entry[sources + 1..]
            .iter()
            .filter(|line| line.starts_with("     Copyright"))
            .count()
            > 10,
        "{entry:#?}"
    );
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
    // A license written as a comment: its notice is found all the same.
    file(
        "LICENSE",
        b"// Copyright 2020 A Stand-In\n//\n// Permission to use, copy, modify...\n",
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
    file(
        "src/deep/b.rs",
        b"// Copyright 2016 Another Author.\n// Copyright (c) 2014, Someone Inc.\n",
    );
    file("src/c.o", b"\x7fELF\0\0\nCopyright 1999 Not Text\n");
    assert_eq!(
        probe(dir.path(), "sources", "{}", "[]").expect("notices"),
        serde_json::json!([
            "Copyright (c) 2014, Someone Inc.",
            "Copyright 2016 Another Author."
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
