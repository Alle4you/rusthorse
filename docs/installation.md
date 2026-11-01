# Installation

This guide covers building Rusthorse, running the agent as a systemd user
service, creating or adopting a vault, migrating existing secrets and
uninstalling.

## Requirements

| Requirement | Notes |
|---|---|
| Linux with systemd user services | Tested on Linux Mint 22.3 (Ubuntu 24.04 base). |
| A graphical session (X11 or Wayland) | The agent shows its dialogs on your desktop. |
| GTK 4.12 and libadwaita 1.4 or newer (recommended) | For `rusthorse-dialog`, Rusthorse's own dialogs: Ubuntu 24.04, Linux Mint 22, Fedora 39, Debian 13 and later. |
| `zenity` | The fallback when `rusthorse-dialog` is not installed. Tested with 3.44. Install with `sudo apt install zenity`. |
| Rust 1.89 or newer (1.92 for `rusthorse-dialog`) | Only to build. Install with [rustup](https://rustup.rs). |
| A Secret Service provider (optional) | Only for `rusthorse import secret-service` (GNOME Keyring, KWallet). |

Rusthorse does not need root, does not use Flatpak or Snap, and installs two
binaries: `rusthorse` and, if your system has GTK 4, `rusthorse-dialog`.

## 1. Build and install

From a clone:

```sh
git clone https://github.com/Alle4you/rusthorse
cd rusthorse
cargo install --locked --path .
```

Or directly:

```sh
cargo install --locked --git https://github.com/Alle4you/rusthorse rusthorse
```

Both put the binary at `~/.cargo/bin/rusthorse`. Check it with
`rusthorse --version`.

Then install `rusthorse-dialog`, the program that shows the agent's dialogs
([ADR 0006](adr/0006-own-dialog-program.md)). It needs the GTK 4 and
libadwaita development packages to build:

```sh
sudo apt install libgtk-4-dev libadwaita-1-dev pkg-config     # Debian, Ubuntu, Mint
sudo dnf install gtk4-devel libadwaita-devel pkgconf-pkg-config  # Fedora

cargo install --locked --path dialog      # from the clone
# or: cargo install --locked --git https://github.com/Alle4you/rusthorse rusthorse-dialog
chmod go-w ~/.cargo/bin/rusthorse ~/.cargo/bin/rusthorse-dialog
```

It must sit next to `rusthorse` (both in `~/.cargo/bin`): the agent looks for
it there and nowhere else, and refuses it if its group or other users can
modify it. Debian, Ubuntu and their derivatives use a umask of 002, so
`cargo install` leaves the programs group-writable: `chmod go-w` removes
that, and should be run again after every upgrade. Without it, the agent shows its dialogs with
zenity. `rusthorse doctor` says which one the agent uses.

AI agents usually run commands in non-interactive shells, which on many
distributions read neither `~/.bashrc` nor `~/.profile` — where rustup adds
`~/.cargo/bin` to `PATH`. Ask the AI to run `command -v rusthorse` and
`echo "$PATH"` in its own shell. If it finds no `rusthorse`:

- If that `PATH` contains `~/.local/bin`, link the binary there (`ln -s`
  refuses to replace an existing file):

  ```sh
  mkdir -p ~/.local/bin
  ln -s ~/.cargo/bin/rusthorse ~/.local/bin/rusthorse
  ```

  On Debian and Ubuntu, `~/.profile` adds `~/.local/bin` to `PATH` only if
  the directory exists when you log in, so a directory you just created takes
  effect at your next login.
- Otherwise, give the AI the absolute path, `~/.cargo/bin/rusthorse`, in its
  instructions file.

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
ExecStart=%h/.cargo/bin/rusthorse agent --idle-timeout 30m
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
  yet, and neither is a database without a password: Rusthorse always asks for
  one and does not try an empty password.
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

Migrate in four steps, and keep the originals until the last one is done.

1. **Back up** the new vault (see below), so that you can go back.
2. **Preview** what would be imported — names only, which ones already exist
   and which appear twice; nothing is sent to the agent (for Secret Service,
   no secret is even read; a `.env` file is parsed locally):

   ```sh
   rusthorse import dotenv ~/project/.env --prefix MYAPP_ --dry-run
   rusthorse import secret-service -a service=myapp --name-from key --dry-run
   ```

   The Secret Service form selects items by attribute. For example, items
   stored with `secret-tool store --label=... service myapp key token` are
   matched by `-a service=myapp`, and `--name-from key` names each entry
   after its `key` attribute. Check that the preview lists only what you
   mean to move: an attribute that is too broad selects other applications'
   items too.

   **Start with one item.** Add an attribute that selects only it
   (`-a service=myapp -a key=token`), go through steps 3 and 4 with it, and
   import the rest only once it works.
3. **Import**, tagging the result so it is easy to find:

   ```sh
   rusthorse import secret-service -a service=myapp --name-from key --tag migrated
   ```

   The importer reads the items in the `rusthorse` process and sends them to
   the agent in batches small enough for one approval dialog each (at most 50
   names per batch).
4. **Verify each entry by using it**, not just by listing it: run a real,
   harmless command with it — an API call that only reads, a login check —
   for example:

   ```sh
   rusthorse run OPENAI_API_KEY -- sh -c \
       'curl -fsS -o /dev/null -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models'
   ```

   (The single quotes make the command's shell, not yours, expand the
   variable.) If you will also use KeePassXC, open a backup copy in it and
   check that the entries are there. Only when every entry has worked, delete
   the originals with the tool that created them, and update scripts that
   used the old tool.

## Backups and restore

The vault is a single, encrypted file. Make an independent copy with:

```sh
rusthorse backup ~/Backups/rusthorse-$(date +%F).kdbx
```

The agent copies the file and then decrypts the copy with the current master
password, so a backup it reports as written is known to open. Keep backups
somewhere other than the vault's directory. `vault.kdbx.bak`, next to the
vault, only holds the version before the last save and is replaced on every
save — it is not a backup.

To **restore**:

```sh
systemctl --user stop rusthorse-agent
cp ~/.local/share/rusthorse/vault.kdbx ~/.local/share/rusthorse/vault.kdbx.before-restore
cp ~/Backups/rusthorse-2026-11-01.kdbx ~/.local/share/rusthorse/vault.kdbx
chmod 600 ~/.local/share/rusthorse/vault.kdbx
systemctl --user start rusthorse-agent
rusthorse unlock && rusthorse list
```

A backup keeps the master password it was made with: after `rusthorse
passwd`, older backups still open with the old password.

## Changing the master password

`rusthorse passwd` asks for the current password and the new one (twice) in
the agent's dialogs and re-encrypts the vault. It deletes `vault.kdbx.bak`,
which was encrypted with the old password; it cannot change copies made
elsewhere. Changing the password in KeePassXC also works — follow the next
section.

## Editing the vault in KeePassXC

The vault is a normal KeePass file, but only one program should write it at a
time:

1. `rusthorse lock` (or `systemctl --user stop rusthorse-agent`).
2. Open, edit and save the file in KeePassXC, then **close the database** in
   KeePassXC.
3. Use Rusthorse again; the next unlock reads the file KeePassXC wrote.

Fields, groups, tags, attachments and history that Rusthorse does not
manage are kept when Rusthorse saves (a test runs Rusthorse's edits on a file
written by KeePassXC 2.7.12 and checks that every untouched entry is
identical).

## Upgrading

Install a specific release, then restart the agent so that both sides run
the same version:

```sh
cargo install --locked --git https://github.com/Alle4you/rusthorse --tag v0.1.0 --force
systemctl --user restart rusthorse-agent
rusthorse doctor
```

Commands refuse to talk to an agent that speaks another protocol version and
say how to restart it; `rusthorse doctor` also notices an agent that still
runs the build an upgrade replaced, even when the protocol did not change. Read [CHANGELOG.md](../CHANGELOG.md) before
upgrading.

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
