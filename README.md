# Rusthorse

**A local KeePass vault whose secrets AI agents can use without seeing them.**

[![CI](https://github.com/Alle4you/rusthorse/actions/workflows/ci.yml/badge.svg)](https://github.com/Alle4you/rusthorse/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

Rusthorse stores your passwords, API keys and access details (URL, host/IP,
port, username) in a standard KeePass KDBX4 file. A small background agent
holds the unlocked vault. When a program — or an AI coding agent such as
Claude Code or Codex — needs a secret, it asks the agent; **you approve the
exact request in a dialog**, and the agent runs the command with the secret in
its environment and scrubs the value from the output. The caller gets the
result, never the secret.

```console
$ rusthorse add OPENAI_API_KEY --kind api-key --url https://api.openai.com/v1 --tag ai
OPENAI_API_KEY added                       # you typed the value in a dialog

$ rusthorse run OPENAI_API_KEY -- python summarize.py
┌ Rusthorse — use a secret ────────────────────────────────────────────┐
│ Run a command with your secrets?                                     │
│ Rusthorse runs it as you, outside any sandbox, with the secrets in   │
│ its environment; programs it starts can use them too. Read the       │
│ command before you allow it.                                         │
│                                                                      │
│ COMMAND                                                              │
│ python summarize.py                                                  │
│ SECRETS                                                              │
│ OPENAI_API_KEY ← OPENAI_API_KEY (2a8f40e5)                           │
│ PROGRAM                                                              │
│ /home/me/project/.venv/bin/python → /usr/bin/python3.12              │
│ DIRECTORY                                                            │
│ /home/me/project                                                     │
│ REQUESTED BY (UNVERIFIED)                                            │
│ rusthorse[8812] ← bash[8790] ← claude[4120]                          │
│                                                                      │
│ Input: none (/dev/null) · Output: secret values are redacted         │
│                                           [ Deny ]  [ Allow once ]   │
└──────────────────────────────────────────────────────────────────────┘
Summary written to out.md
```

> **Status: early development (0.1.0).** The design and code have had
> AI-assisted reviews but no independent security audit. Read the
> [threat model](docs/threat-model.md) before trusting it with anything that
> matters, and keep a backup of your vault.

## Why

AI coding agents increasingly need credentials: an API key to call a model, a
token to open a pull request, a password to log into a router. The usual
options are all bad:

- **Pasting the secret into the chat or a `.env` file** puts it in the model's
  context, in transcripts, in logs and sometimes in commits.
- **The desktop keyring** (GNOME Keyring, KWallet) is unlocked for the whole
  session, and any process running as you — including the agent's shell — can
  read every secret in it without asking.
- **Password managers** are built for humans copying and pasting, not for a
  program that should use a secret without learning it.

Rusthorse puts a human-approved checkpoint between the agent and the secret,
and keeps the value out of the agent's reach in the common case.

## Features

- **Standard, portable storage.** A KDBX4 file (Argon2id, AES-256) that opens
  in [KeePassXC](https://keepassxc.org/), KeePassDX, Strongbox and other
  KeePass clients on any platform. Entries carry a username, URL, host/IP,
  port, tags, notes and history.
- **Approval for every use.** Running a command with a secret, revealing a
  value, editing or deleting an entry all require your approval in a dialog
  shown by the agent — not in the terminal, where a program could answer.
- **The command you approve is the command that starts.** The agent itself
  resolves the program to an absolute path, removes dynamic-loader variables
  (`LD_PRELOAD`, …), warns about variables that can inject code
  (`NODE_OPTIONS`, `PYTHONPATH`, …), checks after your answer that the program
  and directory were not swapped, and starts the command as its own child.
  (What the program then reads — scripts, config files — is up to you to
  trust; see the threat model.)
- **Output redaction.** Secret values printed by the command are replaced with
  `[REDACTED:<entry>]` before they reach the caller; the command only ever
  sees pipes owned by the agent, reads `/dev/null` unless you pass `--stdin`,
  and anything it leaves running in the background is stopped when it exits.
- **The master password never touches the client.** The agent asks for it in
  its own dialog (only `rusthorse init` reads the password of a new vault
  itself) and locks itself after 15 minutes without an approved use.
- **Audit log.** Every unlock, approval, denial and command exit is recorded
  (without values). If the log cannot be written, the vault stays locked and
  approval-gated requests are refused.
- **Migration.** Import from `.env` files and from GNOME Keyring / KWallet.

## Quick start

Requirements: Linux with a graphical session (X11 or Wayland), systemd user
services, GTK 4 and libadwaita for Rusthorse's own dialogs (or `zenity`), and
Rust 1.92 or newer (1.89 without the dialogs). Full instructions, including
uninstalling, are in [docs/installation.md](docs/installation.md).

```sh
# 1. Build and install the binaries into ~/.cargo/bin
cargo install --locked --git https://github.com/Alle4you/rusthorse rusthorse
#    and Rusthorse's own dialogs (without them, the agent uses zenity)
sudo apt install libgtk-4-dev libadwaita-1-dev pkg-config
cargo install --locked --git https://github.com/Alle4you/rusthorse rusthorse-dialog
chmod go-w ~/.cargo/bin/rusthorse ~/.cargo/bin/rusthorse-dialog

# 2. Start the agent as a systemd user service
curl -fsSLo ~/.config/systemd/user/rusthorse-agent.service --create-dirs \
  https://raw.githubusercontent.com/Alle4you/rusthorse/main/contrib/systemd/rusthorse-agent.service
systemctl --user daemon-reload
systemctl --user enable --now rusthorse-agent

# 3. Create the vault (choose a strong master password)
rusthorse init

# 4. Add a secret — the agent asks for the value in a dialog
rusthorse add GITHUB_TOKEN --url https://github.com --username me --tag dev

# 5. Use it
rusthorse run GITHUB_TOKEN -- gh repo list
rusthorse run GH_TOKEN=GITHUB_TOKEN -- gh pr create --fill
```

## Visual manager (first milestone)

`rusthorse-manager` is a window to see and organise your entries: search,
groups, create, edit, delete, generate values, back up. When you approve it
in the agent's dialog, it shows a value for 30 seconds or copies it to the
clipboard. Like the CLI, it never opens the vault and never sees the master
password.

```sh
cargo run --locked -p rusthorse-manager   # Rust 1.92, GTK 4.12+, libadwaita 1.4+
```

This first milestone ([ADR 0007](docs/adr/0007-visual-manager.md)) awaits
independent review. The [manager guide](docs/manager.md) explains every
action, where a shown or copied value can end up, and what comes later.

## Using it with AI agents

Tell the agent that secrets are available through `rusthorse` and that it must
never try to read them. For example, in `CLAUDE.md` or `AGENTS.md`:

```markdown
## Secrets
- Secrets live in Rusthorse. List what exists with `rusthorse list` (names and
  metadata only).
- Use a secret with `rusthorse run NAME -- command` (or `VAR=NAME`); the human
  approves each use in a dialog. Never ask for or print secret values, never
  use `rusthorse reveal`, never write secrets to files.
- If a command is denied, or nobody answers the dialog in time, stop and ask the
  human; do not retry variations.
```

[docs/ai-agents.md](docs/ai-agents.md) covers patterns, approval hygiene and
what Rusthorse can and cannot protect against when the requester is an AI.

## Commands

| Command | What it does | Approval |
|---|---|---|
| `init` | Create a new vault | — |
| `agent` | Run the agent (normally via systemd) | — |
| `status` | Agent and lock state | — |
| `unlock` / `lock` | Unlock (master password dialog) / lock now | — |
| `list`, `show NAME` | Metadata only: name, username, URL, host, port, tags | — |
| `add NAME` | New entry; you type the value in a dialog | the dialog itself |
| `add NAME --stdin` | New entry with a value from standard input | yes |
| `add NAME --generate` | New entry with a random value nobody sees | yes |
| `edit NAME …` | Change fields, tags, name or value | yes |
| `remove NAME` | Delete an entry | yes |
| `run SECRET… -- CMD` | Run `CMD` with secrets in its environment | yes (remembering is opt-in) |
| `reveal NAME [--notes]` | Print a value or the notes (for humans; avoid in automation) | yes (never remembered) |
| `backup DEST` | Copy the encrypted vault and verify the copy opens | — |
| `open NAME` | Open the entry's URL (access link) in the browser | — |
| `passwd` | Change the master password | the dialogs themselves |
| `generate` | Print a random value (nothing stored) | — |
| `import dotenv FILE` | Import `NAME=value` pairs | yes (one for the batch) |
| `import secret-service -a KEY=VALUE` | Import from GNOME Keyring / KWallet | yes (one for the batch) |
| `audit` | Show recent audit records | — |
| `doctor` | Check the installation and environment | — |
| `completions SHELL` | Print a shell completion script | — |

See [docs/cli.md](docs/cli.md) for every option and the exit statuses.

## Security in one paragraph

Rusthorse prevents **accidental** exposure: against a cooperative but
fallible requester — the common case with AI agents — values do not appear in
the caller's process, output, logs or the AI's context, and every use is a
decision you make with the exact command in front of you. It does **not**
resist a requester that deliberately attacks it from your own user account
and desktop session: on X11 such a program can click "Allow" for you, and it
can read the environment of a running approved command. For that, the AI
agent must run isolated from your session. Approving a command means trusting
everything that command does, and it runs outside any sandbox the requester
is in. The [threat model](docs/threat-model.md) lists every assumption and
limitation.

## Documentation

- [Getting started](docs/getting-started.md) — the first ten minutes
- [Installation](docs/installation.md) — build, install, systemd, migration, uninstall
- [CLI reference](docs/cli.md) — commands, options, environment, exit statuses
- [Using Rusthorse with AI agents](docs/ai-agents.md)
- [Architecture](docs/architecture.md) — components, request flow, storage format
- [Threat model](docs/threat-model.md) — what is protected, what is not, and why
- [Protocol](docs/protocol.md) — the agent socket protocol, for client authors
- [Architecture decision records](docs/adr/README.md)
- [Roadmap](docs/roadmap.md) — what comes next, and why

## Roadmap

The main direction is a **credential broker**: instead of the secret, an
approved command receives a short-lived token that only works through
Rusthorse, and the agent uses the real credential on its behalf — an HTTP
proxy for APIs, an `ssh-agent` for SSH keys, then database connectors. The
key never enters the client process at all. Also planned: locking on screen
lock and suspend, packaged releases. Details, status and reasons are in [docs/roadmap.md](docs/roadmap.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md); for
security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.

## License

Copyright © 2026 Alle4you and the Rusthorse contributors.

Rusthorse is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).
