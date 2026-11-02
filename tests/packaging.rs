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
