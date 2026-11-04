# Contributing to Rusthorse

Thank you for helping. Rusthorse handles secrets, so the bar for changes is
higher than usual: every change must keep the security properties described
in the [threat model](docs/threat-model.md) and must keep the documentation
true. AI coding agents: read [AGENTS.md](AGENTS.md), which states the same
rules in short form.

## Reporting bugs and proposing features

- **Security issues:** do not open a public issue. Follow
  [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the Rusthorse version (`rusthorse --version`),
  your distribution and desktop (X11 or Wayland), the exact commands you ran,
  and what you expected. Never paste secret values, vault files or audit logs
  that contain sensitive command lines.
- **Features:** open an issue describing the problem first. For anything that
  changes the policy, the protocol or the storage format, expect to write or
  discuss an [ADR](docs/adr/README.md). Rusthorse is a credential vault
  prepared for AI agents: a credential's secret is its value, an agent
  says where it will use it, and you approve that (see "What it is" in the
  [README](README.md)). Features that add controls beyond that — over what a
  credential does, or knowledge of particular APIs — are not taken up.

## Development setup

```sh
git clone https://github.com/Alle4you/rusthorse
cd rusthorse
cargo build
cargo test
```

You need Rust 1.89 or newer (`rustup` is the easiest way) and, to try the
agent by hand, `zenity` and a graphical session.

To experiment without touching your real vault, use separate paths:

```sh
export RUSTHORSE_VAULT=/tmp/rh-dev/vault.kdbx
export RUSTHORSE_SOCKET=/tmp/rh-dev/agent.sock
export RUSTHORSE_AUDIT_LOG=/tmp/rh-dev/audit.jsonl
cargo run -- init
cargo run -- agent &      # in another terminal is better
cargo run -- add TEST
```

## Before opening a pull request

All of these must pass; CI runs them on every pull request:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo +1.89 check --all-targets
cargo +1.89 check --all-targets --all-features
```

The default members are `rusthorse` and `rusthorse-broker`; these commands
cover both, and `cargo run` still runs `rusthorse`. The broker's system tests
need the tools, CA file and short temporary paths listed in
[`broker/tests/system.rs`](broker/tests/system.rs). Run feature sets
sequentially through Cargo: both use `target/debug/rusthorse-broker`.
`test-upstream` is for tests only; never install a broker built with it. The
graphical programs' checks and the complete test requirements are in
[AGENTS.md](AGENTS.md#checks).

And check the following by hand:

- **Tests.** New behaviour has tests. Policy changes have an end-to-end test
  in `tests/agent.rs` that shows both the allowed and the denied path.
- **Documentation.** Update every document the change affects — the README,
  `docs/cli.md`, `docs/protocol.md`, `docs/architecture.md`,
  `docs/threat-model.md`, and `src/guide/ai.md` (the guide that
  `rusthorse guide ai` prints) when AI agents use what changed — in the
  same pull request, and add an entry to `CHANGELOG.md` under *Unreleased*.
- **Decisions.** Significant design decisions get an ADR.

## Rules for security-sensitive code

- Only the agent, and the broker it starts for each grant, handle secrets
  taken from the vault. The agent gives a `rusthorse-broker` process the
  credential of its one grant, with the grant's token, approved origin and
  limits, over the control channel, and nothing else from the vault (ADR
  0013). The broker puts the credential only where the program put the
  token, in the header values of requests it forwards to that origin. A
  command run with `--broker` gets a token for
  that binding, never the credential (ordinary `run` bindings give their
  values to the approved command, as before). A client — the CLI or the
  manager — holds a secret only when the user supplies one — `init` without an
  agent (the new master password), `add --stdin` — or asked for one: `reveal`,
  after approval (the manager's Show and Copy are reveals). Imports are read
  by the agent (`import_from`): the CLI and the manager send names, never
  values. The manager's forms carry metadata only and approve nothing.
- Never log, include in error messages or put in the audit log a secret value,
  a broker token or credential, a master password or notes. A value leaves a
  client only where the human asked for it: printed by `reveal`, shown in the
  manager's Show window, or put on the clipboard by its Copy.
- Keep secret material in `Zeroizing` types where practical, and do not
  `Debug`-print structures that contain it.
- Anything a requester controls that appears in a dialog must go through
  `ui::dialog_text` (in markup, `ui::markup_text`), and a request whose dialog
  would be too long or too tall must be refused — never truncate what the
  human approves. `util::visible` is for validating names, not for dialogs.
- Approval-gated actions must record an audit event *before* acting and fail
  closed if they cannot.
- `unsafe` code is denied crate-wide. If it is unavoidable, confine it to the
  smallest possible function with a `// SAFETY:` comment explaining why it is
  sound, and call it out in the pull request.
- New dependencies need a reason in the pull request. Prefer well-maintained
  crates with a security track record.

## Style

- `cargo fmt` formatting; Clippy clean with `-D warnings`.
- Public items have doc comments (`missing_docs` is enabled).
- Error messages are lower-case sentences that say what went wrong and, when
  possible, what to do about it.
- Commit messages: a short imperative subject line (≤ 72 characters), a blank
  line, and a body explaining *why*. Keep unrelated changes in separate
  commits.

## License

By contributing, you agree that your contributions are licensed under the
GNU General Public License, version 3 or (at your option) any later version,
the same license as the project.

The graphical programs (`dialog/`, `manager/`) need Rust 1.92, GTK 4.12+
and libadwaita 1.4+, and their widget tests need `xvfb-run`,
`dbus-run-session`, `xdotool` and `xclip`; the tests run on a virtual
display, never on yours. Their checks are listed in AGENTS.md.
