# Rusthorse

**A local KeePass vault whose secrets AI agents can use without seeing them.**

[![CI](https://github.com/Alle4you/rusthorse/actions/workflows/ci.yml/badge.svg)](https://github.com/Alle4you/rusthorse/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

Rusthorse stores your passwords, API keys and access details (URL, host/IP,
port, username) in a standard KeePass KDBX4 file. A small background agent
holds the unlocked vault. When a program — or an AI coding agent such as
Claude Code or Codex — needs a secret, it asks the agent; **you approve the
exact request in a dialog**, and the agent runs the command with the secret in
its environment and redacts literal copies from the output by default. For
an HTTP API that takes its key in a request header, `run --broker` instead
gives the command a temporary token: the agent names the API's origin, you
approve it, and a separate broker puts the real key where the program put
the token, in requests to that origin only. The caller gets the result,
never the secret. Neither mode sandboxes the command.

**What it is.** Rusthorse is a credential vault prepared for AI agents. The
secret in an entry is its value — a key, a password, a token, a
certificate. Its URL, username, host, port and tags are context, for you
and for an AI agent to understand what the credential is for; its notes,
and any field KeePass marks protected, are withheld like the value. When an agent needs a credential, it asks Rusthorse to
use it and says where: the command it will run and, for an API key through
the broker, the destination the key goes to. You see that in a dialog and
allow it or not; that approval is the control. The agent itself never sees
the value: the approved command gets it, or, through the broker, only a
temporary token. Your approval decides which command uses a credential, and
Rusthorse records it. With `run`, the command has the value for as long as
it runs, and Rusthorse cannot limit or count what the command does with it.
Through the broker, the command has only a token, which Rusthorse limits in
time and in requests and can revoke, and each request is recorded.

**What it is not.** It does not decide what a credential can do: that is set
where the credential is issued — give an agent the narrowest key that does
the job, and production its own key. It knows nothing about the APIs it is
used with: the agent knows how to call them, Rusthorse only supplies the
secret. A credential you take out of the vault to run something elsewhere is
your choice, outside what it protects. No other controls are planned: no
authorization of routes or operations, no knowledge of providers, no
destinations or policies stored with an entry, no connectors for other
protocols. (Phase 1's broker profiles and presets were removed for this
reason; see the [roadmap](docs/roadmap.md).)

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
  shown by the agent — not in the terminal, where a program could answer. A
  broker grant permits repeated API calls to its approved origin, at any path
  there, within its limits.
- **The command you approve is the command that starts.** The agent itself
  resolves the program to an absolute path, removes dynamic-loader variables
  (`LD_PRELOAD`, …), warns about variables that can inject code
  (`NODE_OPTIONS`, `PYTHONPATH`, …), shows the destination settings in its
  environment (`OPENAI_BASE_URL`, proxies, certificate authorities), checks
  after your answer that the program
  and directory were not swapped, and starts the command as its own child.
  (What the program then reads — scripts, config files — is up to you to
  trust; see the threat model.)
- **Output redaction.** With redaction on (the default), secret values printed
  by the command are replaced with `[REDACTED:<entry>]` before they reach the
  caller; the command sees pipes owned by the agent and reads `/dev/null`
  unless you pass `--stdin`. Broker tokens are filtered too. `--no-redact`
  passes the caller's input/output descriptors directly, with unfiltered
  output (the terminal in an interactive shell). On exit, remaining members of
  the command's process group are stopped; detached descendants may survive,
  but its broker grants end. Exact-match limits are in threat model L5.
- **The master password never touches the client.** The agent asks for it in
  its own dialog (only `rusthorse init` reads the password of a new vault
  itself) and locks itself after 15 minutes without an approved use, when the
  screen locks, and before the computer sleeps. Locking before sleep depends
  on the desktop's signals and inhibitor deadline; a slow save can delay it
  (threat model L20).
- **Audit log.** Every unlock, approval, denial and command exit is recorded
  (without values). If the log cannot be written, the vault stays locked and
  approval-gated requests are refused. Broker admissions are also recorded
  durably before forwarding. Completion records are best effort: a failed
  command-exit or grant-end record cannot undo what already happened.
- **Migration.** Import from `.env` files and from GNOME Keyring / KWallet,
  in the manager or the CLI; the agent reads the values itself.

## Quick start

Requirements: Linux with a graphical session (X11 or Wayland) and systemd
user services; to build, Rust 1.92 or newer and the GTK 4 and libadwaita
development packages; for the credential broker (`run --broker`), the
system's certificate authorities (`ca-certificates`). On Ubuntu 24.04,
Linux Mint 22, Debian 13 or later, build and install the Debian package;
elsewhere, install from source. Full instructions, including uninstalling,
are in [docs/installation.md](docs/installation.md).

```sh
# 1. Build the Debian package (no release is published yet) and install it:
#    the four programs (the command-line program and agent, its dialogs, the
#    credential broker, the manager) and the agent's service (enabled for
#    every user)
sudo apt install libgtk-4-dev libadwaita-1-dev pkg-config
cargo install --locked cargo-deb
git clone https://github.com/Alle4you/rusthorse && cd rusthorse
./packaging/build-deb.sh
sudo apt install ./target/debian/rusthorse_0.1.0-1_amd64.deb

# 2. Start the agent now (it starts by itself at your next login)
systemctl --user start rusthorse-agent

# 3. Create the vault: open Rusthorse from the applications menu and click
#    Create vault…, or run init — either way the agent asks, in its own
#    dialog, for a strong master password
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

The package puts it in the applications menu as **Rusthorse**. From a
clone, without installing anything:

```sh
cargo run --locked -p rusthorse-manager   # Rust 1.92, GTK 4.12+, libadwaita 1.4+
```

This first milestone ([ADR 0007](docs/adr/0007-visual-manager.md)) is
implemented and reviewed, with the broker Grants page added in phase 1. The
[manager guide](docs/manager.md) explains every action, where a shown or
copied value can end up, and what comes later.

## Using it with AI agents

Tell the agent that secrets are available through `rusthorse`, and point it
to the guide. For example, in `CLAUDE.md` or `AGENTS.md`:

```markdown
## Secrets
- Secrets live in Rusthorse. Before you use one, run `rusthorse guide ai` and
  follow it.
- Never ask for, print or write secret values, and never use
  `rusthorse reveal`. If a request is denied, or nobody answers the dialog in
  time, stop and ask the human.
```

`rusthorse guide ai` prints the rules and the commands an AI agent needs —
finding entries, `run`, the exit statuses, storing secrets — for the version
of `rusthorse` that prints it, so the instructions file stays short and does
not go out of date. [docs/ai-agents.md](docs/ai-agents.md) covers patterns,
approval hygiene and what Rusthorse can and cannot protect against when the
requester is an AI.

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
| `edit NAME …` | Change fields, tags, name, group or value | yes |
| `remove NAME` | Delete an entry | yes |
| `run SECRET… -- CMD` | Run `CMD` with secrets in its environment | yes (remembering is opt-in) |
| `run --broker VAR=NAME@URL… -- CMD` | Run `CMD` with a temporary token instead of an API key; Rusthorse puts the key in its place in requests to the URL's origin, which you approve | yes (never remembered) |
| `grants`, `grants revoke ID` | List the broker's grants (never a token), end one or all | — |
| `reveal NAME [--notes]` | Print a value or the notes (for humans; avoid in automation) | yes (never remembered) |
| `backup DEST` | Copy the encrypted vault and verify the copy opens | — |
| `open NAME` | Open the entry's URL (access link) in the browser | — |
| `passwd` | Change the master password | the dialogs themselves |
| `generate` | Print a random value (nothing stored) | — |
| `import dotenv FILE` | Import `NAME=value` pairs; the agent reads the file | yes (to show the names, then one per batch) |
| `import secret-service -a KEY=VALUE` | Import from GNOME Keyring / KWallet; the agent reads the items | yes (to list the items, then one per batch) |
| `audit` | Show recent audit records | — |
| `doctor` | Check the installation and environment | — |
| `completions SHELL` | Print a shell completion script | — |
| `guide ai` | Print the guide for AI agents | — |

See [docs/cli.md](docs/cli.md) for every option and the exit statuses.

## HTTP APIs through the broker

An SDK can use an API key without receiving it. The run names where the key
may go, after the `@`:

```sh
rusthorse run --broker OPENAI_API_KEY=OPENAI_API_KEY@https://api.openai.com/v1 \
  --url OPENAI_BASE_URL=OPENAI_API_KEY -- python summarize.py
```

The approval shows the approved origin (`https://api.openai.com`), the base
path apart from it (`/v1`, which only sets up the program's base URL and is
not a limit: the key may go to any path at that origin) and the grant's
limits. Nothing fills the destination in: not the entry's URL, not a
default. The program presents the token where it would present the key, in
a request header, and the broker puts the key in its place. `rusthorse
grants` and the manager's **Grants** page list and revoke grants;
`rusthorse lock` ends all of them. Always pair the broker token with its
local base URL. See
[the CLI reference](docs/cli.md#through-the-credential-broker---broker) and
`rusthorse guide ai` for client-specific recipes and limitations.

## Security in one paragraph

Rusthorse prevents **accidental** exposure: against a cooperative but fallible
requester — the common case with AI agents — values do not appear in the
caller's process, output, logs or the AI's context, and every use is a
decision you make with the exact command in front of you. For a broker
binding, the command gets a token instead of the credential: the approval
creates a grant, and its token permits calls to the approved origin — any
path, any operation the key allows there — within the grant's limits while
it lasts. Those calls can spend credit without another dialog.
Ordinary bindings still give their values to the approved command; default
redaction filters literal copies on stdout/stderr. It does **not** resist a
requester that deliberately attacks it from your own user account and desktop
session: on X11 such a program can click "Allow" for you, and it can read the
environment of a running approved command — a value, or a broker token. For
that, the AI agent must run isolated from your session. Approving a command
means trusting everything that command does, and it runs outside any sandbox
the requester is in. The [threat model](docs/threat-model.md) lists every
assumption and limitation.

## Documentation

- [Getting started](docs/getting-started.md) — the first ten minutes
- [Installation](docs/installation.md) — the Debian package, building from source, systemd, migration, uninstall
- [CLI reference](docs/cli.md) — commands, options, environment, exit statuses
- [Using Rusthorse with AI agents](docs/ai-agents.md)
- [Architecture](docs/architecture.md) — components, request flow, storage format
- [Threat model](docs/threat-model.md) — what is protected, what is not, and why
- [Protocol](docs/protocol.md) — the agent socket protocol, for client authors
- [Architecture decision records](docs/adr/README.md)
- [Roadmap](docs/roadmap.md) — what comes next, and why

## Roadmap

The HTTP **credential broker** (unreleased) has no stored profiles or
presets: the agent names the destination in the `run`, you approve its
origin in the dialog, and the broker puts the key in the request header
where the program put the token, knowing nothing about the API. It relays
streamed responses, and the CLI and the manager list and revoke its grants.
Phase 1, with profiles and presets, was reviewed READY, and so was the
broker without them (2026-11-04); in phase 1's manual test with a real key,
the Python SDK worked through the broker, and Claude Code's check was left
for later. The broker without profiles was then tried by hand with `curl` (a
GET and a POST answered, a misplaced token refused) and the Python SDK (a
message and two streams), and Claude Code answered through it in print mode
(`claude -p`) and, run by the maintainer, interactively.
Screen-lock and suspend locking are implemented too. No other connector is
planned: `rusthorse run` serves databases, devices and SSH. Published
packages remain planned. See [docs/roadmap.md](docs/roadmap.md).

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
