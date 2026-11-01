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
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo +1.89 check --all-targets    # MSRV; CI runs the same
```

The MSRV is **1.89**: do not use newer standard-library APIs, and avoid APIs
deprecated in newer releases whose replacements 1.89 lacks (for example
`AtomicUsize::fetch_update`; use a `Mutex`).

## Security invariants

Breaking one of these is a security bug, whatever the tests say.

1. **Only the agent handles secrets taken from the vault.** The CLI holds a
   secret only when the user supplies one — `init` (the new master password),
   `add --stdin`, `import` (values read from a `.env` file or the Secret
   Service, sent to the agent) — or asked for one: `reveal`, after approval.
2. **Never** log, audit or put in an error message a secret value, the master
   password or notes; the only place a value is printed is `reveal`'s output.
   Keep secrets in `Zeroizing` types; never `Debug` a structure that contains
   one.
3. **Approval-gated actions record an audit event before acting and fail
   closed** if they cannot.
4. **Dialogs are shown by the agent**, never by the client. Default button
   **Deny**; only the exact expected zenity results count as approval
   (`ui::decision_from`); an unanswered dialog is `timed_out`, a denial.
5. **Everything a requester controls that a dialog shows goes through
   `ui::dialog_text`** (in markup, through `ui::markup_text`, which calls it).
   Only ordinary characters are drawn as themselves; the rest become
   `\u{…}`. Never truncate what the human approves: refuse a request whose
   dialog is too long or too tall (`MAX_DIALOG_CHARS`, `MAX_DETAIL_CHARS`,
   `ui::metrics::MAX_HEIGHT`).
6. **Dialogs stay portable**: pass only zenity options that zenity 3 and 4
   both have (no `--icon-name`), and use no colours or icons of our own, so
   they follow the desktop's theme. Verified on zenity 3.44, dark and light.
7. **Error contract** (protocol 3): every error other than `outcome_unknown`
   means the vault file was not changed and no command was started. Clients
   treat an unknown error code as `outcome_unknown`. CLI exit statuses: `124`
   outcome unknown (any request with effects), `125` `run` did not start, `4`
   an agent dialog was denied, cancelled or not answered, `1` other errors.
   A command started by `run` can exit with 124 or 125 itself; a `rusthorse:`
   message tells them apart.
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
| a command, option or exit status | `docs/cli.md` (and `README.md` if shown there) |
| a request, response or error code | `docs/protocol.md` |
| components, flows, dialogs, storage | `docs/architecture.md` |
| what is protected or how | `docs/threat-model.md` |
| a significant design decision | a new ADR in `docs/adr/` |
| a planned or proposed feature | `docs/roadmap.md` |
| installation or setup | `docs/installation.md`, `docs/getting-started.md` |
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
| `src/ui.rs` | Dialogs, `dialog_text`, markup, height estimate |
| `src/vault.rs` | KDBX4 storage, atomic saves |
| `src/protocol.rs`, `src/client.rs` | Wire format, client side |
| `src/main.rs` | The CLI |
| `tests/agent.rs` | End-to-end tests |
| `docs/roadmap.md` | Planned work, led by the credential broker |
| `docs/threat-model.md` §11 | Every review finding and what was done about it |
