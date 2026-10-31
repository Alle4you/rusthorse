# Installation

This guide covers building Rusthorse, running the agent as a systemd user
service, creating or adopting a vault, migrating existing secrets and
uninstalling.

## Requirements

| Requirement | Notes |
|---|---|
| Linux with systemd user services | Tested on Linux Mint 22.3 (Ubuntu 24.04 base). |
| A graphical session (X11 or Wayland) | The agent shows its dialogs on your desktop. |
| `zenity` | Tested with 3.44. Install with `sudo apt install zenity`. |
| Rust 1.89 or newer | Only to build. Install with [rustup](https://rustup.rs). |
| A Secret Service provider (optional) | Only for `rusthorse import secret-service` (GNOME Keyring, KWallet). |

Rusthorse does not need root, does not use Flatpak or Snap, and installs a
single binary.

## 1. Build and install

From a clone:

```sh
git clone https://github.com/Alle4you/rusthorse
cd rusthorse
cargo install --locked --path .
```

Or directly:

```sh
cargo install --locked --git https://github.com/Alle4you/rusthorse
```

Both put the binary at `~/.cargo/bin/rusthorse`. Check it with
`rusthorse --version`.

To build without the Secret Service importer (and its D-Bus dependencies):

```sh
cargo install --locked --path . --no-default-features
```

## 2. Run the agent as a systemd user service

```sh
install -Dm644 contrib/systemd/rusthorse-agent.service \
    ~/.config/systemd/user/rusthorse-agent.service
systemctl --user daemon-reload
systemctl --user enable --now rusthorse-agent
systemctl --user status rusthorse-agent
```

Logs go to the journal: `journalctl --user -u rusthorse-agent`.

> **Start the agent with systemd, not from a terminal an AI agent controls.**
> A process can inspect and manipulate the processes it starts. Started by
> systemd, the agent is outside the AI's process tree. `rusthorse agent`
> prints a warning when its parent is not systemd. See
> [threat model — who starts the agent](threat-model.md#who-starts-the-agent).

### Changing agent options

Use a drop-in so that upgrades keep your settings:

```sh
systemctl --user edit rusthorse-agent
```

```ini
[Service]
# Different vault location
Environment=RUSTHORSE_VAULT=%h/Sync/passwords.kdbx
# Clear the original ExecStart, then set a new one
ExecStart=
ExecStart=%h/.cargo/bin/rusthorse agent --idle-timeout 30m --remember 5m
```

Then `systemctl --user restart rusthorse-agent`. All agent options are listed
in [cli.md](cli.md#rusthorse-agent).

### Dialogs do not appear

The agent needs your session's `DISPLAY` (or `WAYLAND_DISPLAY`). If the
service started before your desktop exported it, the agent reads it from
`systemctl --user show-environment` when it opens a dialog. If that is empty
too, add this to your session startup (most desktops already do it):

```sh
systemctl --user import-environment DISPLAY XAUTHORITY WAYLAND_DISPLAY
```

## 3. Create a vault

```sh
rusthorse init
```

Run it in a terminal: it asks for the new master password twice, without
echoing it. (Without a terminal, it uses dialogs instead.) The vault is
created at `~/.local/share/rusthorse/vault.kdbx` with mode `0600`.

Choose a long master password — a passphrase of five or more random words is a
good choice. Rusthorse refuses passwords shorter than 8 characters and warns
below 12. **There is no recovery:** if you forget the master password, the
vault cannot be opened.

### Using an existing KeePass database instead

Any KDBX4 file protected by a password works. Point the agent at it with
`RUSTHORSE_VAULT` (see above). Notes:

- Key files and hardware keys (YubiKey challenge-response) are not supported
  yet.
- Entries are looked up by title. If two entries share a title, use the
  `Group/Title` path.
- If KeePassXC (or a sync tool) changes the file while the agent has it
  unlocked, the agent refuses to save over those changes. Run
  `rusthorse lock` and try again; the agent reloads the file on unlock.
- KDBX3 (and older) files can be read but not modified: Rusthorse only
  writes KDBX4. Convert the file once in KeePassXC (*Database → Database
  Settings → Encryption → Database format: KDBX 4*). KeePassXC 2.7+ and
  current KeePass clients read KDBX4.

## 4. Check that it works

```sh
rusthorse status
rusthorse add TEST_SECRET          # type any value in the dialog
rusthorse run TEST_SECRET -- sh -c 'echo "value: $TEST_SECRET"'
# → value: [REDACTED:TEST_SECRET]
rusthorse remove TEST_SECRET
rusthorse audit
```

## Migrating existing secrets

From a `.env` file (one approval for the whole file):

```sh
rusthorse import dotenv ~/project/.env --prefix MYAPP_ --tag myapp
```

From GNOME Keyring or KWallet, selecting items by attribute. For example,
items stored with `secret-tool store --label=... service myapp key token`:

```sh
rusthorse import secret-service -a service=myapp --name-from key
```

The importer reads the items in the `rusthorse` process and sends them to the
agent as a single batch for you to approve. After checking the result with
`rusthorse list`, delete the originals with the tool that created them.

## Backups

The vault is a single file. Back it up like any other file (it is encrypted).
Each save also keeps the previous version next to it as `vault.kdbx.bak`.

## Upgrading

```sh
cargo install --locked --git https://github.com/Alle4you/rusthorse --force
systemctl --user restart rusthorse-agent
```

Read [CHANGELOG.md](../CHANGELOG.md) first: protocol changes require the
agent and the CLI to be the same version.

## File locations

| File | Default | Override |
|---|---|---|
| Vault | `$XDG_DATA_HOME/rusthorse/vault.kdbx` (`~/.local/share/…`) | `RUSTHORSE_VAULT`, `--vault` |
| Previous vault | `vault.kdbx.bak`, next to the vault | — |
| Agent socket | `$XDG_RUNTIME_DIR/rusthorse/agent.sock` (`/run/user/<uid>/…`) | `RUSTHORSE_SOCKET`, `--socket` |
| Audit log | `$XDG_STATE_HOME/rusthorse/audit.jsonl` (`~/.local/state/…`) | `RUSTHORSE_AUDIT_LOG`, `--audit-log` |

Directories are created with mode `0700` and files with `0600`.

## Uninstalling

```sh
systemctl --user disable --now rusthorse-agent
rm ~/.config/systemd/user/rusthorse-agent.service
systemctl --user daemon-reload
cargo uninstall rusthorse
```

This leaves your vault and audit log in place. Delete them only once you are
sure you no longer need the secrets:

```sh
rm -r ~/.local/share/rusthorse ~/.local/state/rusthorse
```
