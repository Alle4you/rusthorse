# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, …) working on this
repository. Human contributors: [CONTRIBUTING.md](CONTRIBUTING.md) has the same
rules in longer form. If this file and the code disagree, stop and ask.

## The project

Rusthorse is a local secrets vault (KeePass KDBX4) with an agent that lets
programs — AI agents above all — **use** a secret without **seeing** it, after
a human approves each use in a dialog. Status: 0.1.0, pre-release, not
published.

Read before changing anything: [README.md](README.md),
[docs/architecture.md](docs/architecture.md) and
[docs/threat-model.md](docs/threat-model.md). The module map is in
[src/lib.rs](src/lib.rs).

## Ground rules

- **Repository content is in English**: code, comments, CLI messages, docs,
  commit messages. (The maintainer may write to you in Portuguese.)
- **Commit locally only.** Never push, tag, publish, or open an issue or a
  pull request without the maintainer's explicit approval.
- **Security problems** follow [SECURITY.md](SECURITY.md). Never publish vault
  files, audit logs or command lines that may contain secrets.
- **Never touch the maintainer's real vault or agent.** Do not open the vault
  file (default `~/.local/share/rusthorse/vault.kdbx`) or its `.bak`, do not
  connect to the running agent's socket (`$XDG_RUNTIME_DIR/rusthorse/`), do
  not read `/proc` of other processes — unless the maintainer asks for that
  specific action. Experiment with separate paths in a `mktemp -d` directory,
  and remove it afterwards:

  ```sh
  export RUSTHORSE_VAULT=$tmp/vault.kdbx RUSTHORSE_SOCKET=$tmp/agent.sock \
         RUSTHORSE_AUDIT_LOG=$tmp/audit.jsonl
  ```

- **No dialogs on the maintainer's screen** (zenity, `rusthorse` commands that
  ask) unless the maintainer is present and agreed.
- **No real secrets** anywhere: tests, logs, docs, commits, chat.
- **No installs, no `sudo`, no lingering processes.**
- **Distribution is native** (Cargo, `.deb`, static binaries). No Flatpak
  ([ADR 0004](docs/adr/0004-native-distribution.md)).

## Checks

All must pass before a commit. Read the full output: piping it through `tail`
has hidden failures before.

```sh
source ~/.cargo/env            # if cargo is not on PATH in your shell
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings     # as released: no feature for tests
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo +1.89 check --all-targets                  # MSRV; CI runs the same,
cargo +1.89 check --all-targets --all-features   # and with the code for tests

# rusthorse-dialog (dialog/): needs libgtk-4-dev and libadwaita-1-dev; its
# widget tests run on a virtual display (xvfb, xdotool), never on yours.
cargo clippy -p rusthorse-dialog --all-targets -- -D warnings
cargo test -p rusthorse-dialog

# The manager uses the same GTK requirements and isolated widget tests.
cargo clippy -p rusthorse-manager --all-targets -- -D warnings
cargo test -p rusthorse-manager
```

The workspace's default members are `rusthorse` and `rusthorse-broker`
(the credential broker, `broker/`), so the plain `cargo` commands above
build, lint, test and document both, and `--all-features` turns on their
features for tests (`fake-keyring`, the broker's `test-upstream`). They do
not build the dialog or the manager, which need GTK; `cargo fmt --all`
formats all members, and `cargo run` runs `rusthorse`.

The broker's tests start the real broker, which reads the system's file of
certificate authorities before it serves anything: the first of
`/etc/ssl/certs/ca-certificates.crt` (from `ca-certificates`),
`/etc/pki/tls/certs/ca-bundle.crt` and `/etc/ssl/ca-bundle.pem` that
exists, a regular file owned by root, in directories owned by root, none of
them writable by group or others. Without such a file they fail; the CI
checks it on its runner first.

Documentation of public items must not link to private ones: `cargo doc`
with `-D warnings` fails on it.

The MSRV is **1.89**, for `rusthorse` and `rusthorse-broker` (the dialog and
the manager need 1.92, for GTK): do not use newer standard-library APIs, and
avoid APIs deprecated in newer releases whose replacements 1.89 lacks (for
example `AtomicUsize::fetch_update`; use a `Mutex`).

## Security invariants

Breaking one of these is a security bug, whatever the tests say.

1. **Only the agent handles secrets taken from the vault.** A client — the
   CLI or the manager — holds a secret only when the user supplies one —
   `init` without an agent (the new master password), `add --stdin` — or
   asked for one: `reveal`, after approval (the manager's Show and Copy are
   reveals). Imports are read by the agent (`import_from`, ADR 0012): the
   CLI and the manager send names, never values; the `import` request, which
   carries values, is left for other clients. The manager's forms carry
   metadata only: they never ask for a master password or a value.
2. **Never** log, audit or put in an error message a secret value, the master
   password or notes. A value leaves a client only where the human asked for
   it: printed by `reveal`, shown in the manager's Show window, or put on the
   clipboard by its Copy ([ADR 0007](docs/adr/0007-visual-manager.md)). Keep
   secrets in `Zeroizing` types; never `Debug` a structure that contains one.
3. **Approval-gated actions record an audit event before acting and fail
   closed** if they cannot.
4. **Approval and secret-entry dialogs are shown by the agent**, never by
   a client — except `init` without a terminal when no agent serves that
   vault, which asks for the new master password itself; with an agent,
   `init` and the manager send `create_vault` and the agent asks. Default
   button **Deny**; only the exact expected zenity results count as approval
   (`ui::decision_from`); an unanswered dialog is `timed_out`, a denial.
5. **Everything a requester controls that a dialog shows goes through
   `ui::dialog_text`** (in markup, through `ui::markup_text`, which calls it).
   Only ordinary characters are drawn as themselves; the rest become
   `\u{…}`. Never truncate what the human approves: refuse a request whose
   dialog is too long or too tall (`MAX_DIALOG_CHARS`, `MAX_DETAIL_CHARS`,
   `ui::metrics::MAX_HEIGHT`).
6. **Dialogs stay portable and plain.** `rusthorse-dialog`
   ([ADR 0006](docs/adr/0006-own-dialog-program.md)) shows plain text only
   (no markup), uses libadwaita's styles and only the theme's standard icons,
   keeps Allow disabled until the end of the content has been reached, and
   writes nothing to standard output but its one answer. With zenity: only
   options that zenity 3 and 4 both have (no `--icon-name`), no colours or
   icons of our own. Verified on zenity 3.44 and GTK 4.14, dark and light.
7. **Error contract** (since protocol 3): every error other than `outcome_unknown`
   means the vault file was not changed and no command was started. Clients
   treat an unknown error code as `outcome_unknown`. CLI exit statuses: `124`
   outcome unknown (any request with effects); `125` `run` did not start
   (including when its dialog was denied, cancelled or not answered); `4` a
   dialog was denied, cancelled or not answered, outside `run`; `1` other
   errors.
   A command started by `run` can exit with 124 or 125 itself; a `rusthorse:`
   message tells them apart. `141`, without a message: `run` could not write
   the redacted output and asked the agent to stop the command, which may
   still be running (`src/guide/ai.md` must say so too).
8. **Protocol changes**: removing or changing the meaning of a field or error
   code — including what an error guarantees — or changing framing bumps
   `PROTOCOL_VERSION` ([docs/protocol.md](docs/protocol.md#compatibility)).
   A field added to an existing message is optional and left out when there
   is no value: older clients may not accept `null` for it.
9. **`unsafe` is denied crate-wide.** If unavoidable: the smallest possible
   function, a `// SAFETY:` comment, and say so in the commit message.
10. **New dependencies need a reason** in the commit message.

## How to make a change

1. **Understand first**: read the code and the docs it affects.
2. **Test every behaviour change.** A policy change gets an end-to-end test in
   `tests/agent.rs` showing the allowed and the denied path.
3. **Prove each fix with a mutation check**, on a temporary copy of the
   repository: revert the fix, see a test fail. A fix no test catches is not
   done; a surviving mutation that is harmless by design is recorded as such
   in the review history.
4. **Update the docs in the same commit** — see the table below.
5. **Run the checks.**
6. **Get an independent review** at each checkpoint (the maintainer uses a
   second AI agent for adversarial review). Record every finding and its
   disposition in the review history of
   [docs/threat-model.md](docs/threat-model.md#11-review-history); fix
   medium and higher findings before moving on.
7. **Commit**: an imperative subject of at most 72 characters, a blank line, a
   body that explains *why*. Unrelated changes go in separate commits.

| When you change… | Also update |
|---|---|
| anything a user notices | `CHANGELOG.md` (*Unreleased*) |
| a command, option or exit status | `docs/cli.md` (and `README.md` if shown there); `src/guide/ai.md`, the guide for AI agents, when they use it |
| a request, response or error code | `docs/protocol.md` |
| components, flows, dialogs, storage | `docs/architecture.md` |
| what is protected or how | `docs/threat-model.md` |
| a significant design decision | a new ADR in `docs/adr/` |
| a planned or proposed feature | `docs/roadmap.md` |
| installation or setup | `docs/installation.md`, `docs/getting-started.md`; the package (`packaging/`) when it installs files or services |
| advice to users of AI agents | `docs/ai-agents.md` |

Documentation must be true and no stronger than the code: state assumptions
(the dialog height is *estimated* for an 11-point font), never promise what is
not guaranteed.

## Tests

- **Unit tests** live in each module; **end-to-end tests** in
  `tests/agent.rs` run a real agent on a temporary socket, driven through the
  real `rusthorse` binary, with a scripted UI (`ScriptedUi`: queued passwords,
  values and decisions; timeouts by prompt index). Automated tests never run
  zenity.
- **Fake agents** that must refuse a later connection remove their socket
  file before their last answer: a child forked by another test keeps a copy
  of the listener until its exec.
- **The broker's tests** (`broker/tests/`) run the real `rusthorse-broker`,
  played by a fake agent, in front of a fake HTTPS destination in the test
  process, with a certificate authority made for the test and fake keys;
  nothing leaves the loopback interface. Those that need the broker to
  reach that destination need its `test-upstream` feature (`--all-features`);
  the others run in both builds.
- **`test-upstream` is for tests only, never in a release**: with it the
  broker trusts certificate authorities and addresses named in its
  environment and may reach loopback destinations. A build without debug
  assertions refuses it (`compile_error!`; the CI checks a release build),
  the broker's `--check` reports it, `rusthorse doctor` fails on such a
  build, and `packaging/build-deb.sh` refuses to package one
  (`packaging/check-broker.py`). Never turn it on outside tests.
- **The packaging tests** (`tests/packaging.rs`) run the scripts of
  `packaging/` with `/usr/bin/python3` (without it they fail, unless
  `RUSTHORSE_TEST_WITHOUT_PYTHON` is set, which skips them), and `cargo
  metadata` and `cargo tree`, which read the crates' sources in Cargo's
  registry (cargo downloads missing ones from crates.io).
- Tests that rely on file permissions skip their check when run as root.
- A test that fails intermittently is a bug: reproduce it under load
  (parallel runs, CPU load) before and after the fix.

## Trying it by hand

Only when the maintainer asks for it. Install as in
[docs/installation.md](docs/installation.md); after changing the agent,
restart it (`systemctl --user restart rusthorse-agent`, which locks the vault)
and run `rusthorse doctor`, which fails while the agent still runs a replaced
binary. To check a dialog's look, show the real dialog with the maintainer
present and capture only its window, in a dark and a light theme
(`GTK_THEME=Adwaita`).

## Where things are

| Path | What |
|---|---|
| `src/agent.rs` | The agent: policy, approvals, dialogs, `run` |
| `src/ui.rs` | The `Ui` trait, `dialog_text`, zenity dialogs and their height estimate |
| `src/dialog_program.rs`, `src/dialog_protocol.rs` | Driving `rusthorse-dialog`; the protocol between them |
| `src/helper_program.rs` | Finding and checking the programs the agent starts next to its own (`rusthorse-dialog`, `rusthorse-broker`) |
| `broker/` | `rusthorse-broker`, the credential broker (ADR 0013): one process per grant, serving it on a loopback port; its tests run it in front of a fake HTTPS destination |
| `src/broker_profile.rs` | Broker profiles and presets: destinations, routes, headers, tokens; shared with the broker |
| `src/broker_protocol.rs` | The control channel between the agent and a broker, tokens and grant IDs, phase 1's limits, the file of certificate authorities |
| `src/broker_host.rs` | The agent's side of the broker: the registry of grants, starting and supervising brokers, admission, revocation, expiry |
| `manager/` | The GTK metadata client; Show requires agent approval (ADR 0007). |
| `manager/src/window.rs`, `manager/src/model.rs` | The manager's window and pages — the grants page among them, which lists the broker's grants and revokes them — and what the pages show |
| `dialog/` | `rusthorse-dialog` (GTK 4) and its tests on a virtual display |
| `src/vault.rs` | KDBX4 storage, atomic saves |
| `src/session_lock.rs` | Locking on suspend and screen lock (D-Bus watchers, ADR 0009) |
| `src/keyring.rs`, `src/import.rs` | Imports the agent reads: GNOME Keyring (and a fake one for tests), `.env` parsing, batches (ADR 0012) |
| `manager/src/import_window.rs` | The manager's import windows |
| `src/protocol.rs`, `src/client.rs` | Wire format, client side |
| `src/main.rs` | The CLI |
| `src/guide/ai.md` | `rusthorse guide ai`, the guide for AI agents; a test checks the commands and options it names |
| `tests/agent.rs` | End-to-end tests |
| `packaging/`, `[package.metadata.deb]` in `Cargo.toml` | The Debian package (ADR 0010): the four programs, service file, maintainer scripts, `build-deb.sh` (which refuses a broker built for tests: `check-broker.py`), the generated copyright file (`copyright.py`, with the crates checked by hand) and documentation (tested in `tests/packaging.rs`) |
| `contrib/systemd/` | The service file for source installations (a test keeps it in step with the package's) |
| `docs/roadmap.md` | Planned work, led by the credential broker |
| `docs/threat-model.md` §11 | Every review finding and what was done about it |
