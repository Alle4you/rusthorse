# Installation

This guide covers installing Rusthorse — from the Debian package or from
source —, running the agent as a systemd user service, creating or adopting
a vault, migrating existing secrets and uninstalling.

## Requirements

| Requirement | Notes |
|---|---|
| Linux with systemd user services | Tested on Linux Mint 22.3 (Ubuntu 24.04 base). |
| A graphical session (X11 or Wayland) | The agent shows its dialogs on your desktop. |
| GTK 4.12 and libadwaita 1.4 or newer (recommended) | For `rusthorse-dialog`, Rusthorse's own dialogs: Ubuntu 24.04, Linux Mint 22, Fedora 39, Debian 13 and later. |
| `zenity` | The fallback when `rusthorse-dialog` is not installed. Tested with 3.44. Install with `sudo apt install zenity`. |
| Rust 1.89 or newer (1.92 for `rusthorse-dialog` and the manager) | Only to build from source, or to build the package. Install with [rustup](https://rustup.rs). |
| A Secret Service provider (optional) | Only for `rusthorse import secret-service` (GNOME Keyring, KWallet). |
| The system's certificate authorities | For the credential broker (`rusthorse run --broker`): it trusts the first of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt` and `/etc/ssl/ca-bundle.pem` that exists, links resolved, which must be a regular file owned by root, in directories owned by root, none of them writable by group or others. The `ca-certificates` package installs one (`sudo apt install ca-certificates`); most systems have it already. |

Rusthorse does not use Flatpak or Snap ([ADR 0004](adr/0004-native-distribution.md)).
It installs four programs: `rusthorse` (the command-line program and the
agent), `rusthorse-dialog` (the agent's dialogs), `rusthorse-broker` (the
credential broker, which the agent starts for `rusthorse run --broker`) and
`rusthorse-manager` (the visual manager). Installed from source, it needs
no root.

## 1. Install

### Debian, Ubuntu, Linux Mint: the package

The package installs the four programs, enables the agent for every user
and puts **Rusthorse** in the applications menu; apt removes it again
([ADR 0010](adr/0010-debian-package.md)). It needs Ubuntu 24.04, Linux
Mint 22, Debian 13 or later: it depends on GTK 4.12, libadwaita 1.4 and
glibc 2.39. It recommends `ca-certificates`, which apt installs with it
unless told not to: the credential broker reads the certificate
authorities from it.

No release has been published yet, so build the package from a clone. That
needs what building from source needs (Rust, and the GTK 4 and libadwaita
development packages, below), cargo-deb, and `python3` and `dpkg-deb`, which
Debian, Ubuntu and Linux Mint normally have:

```sh
sudo apt install libgtk-4-dev libadwaita-1-dev pkg-config
cargo install --locked cargo-deb
git clone https://github.com/Alle4you/rusthorse
cd rusthorse
./packaging/build-deb.sh     # → target/debian/rusthorse_0.1.0-1_amd64.deb
```

Install it with apt, or by opening the file in your desktop's package
installer:

```sh
sudo apt install ./target/debian/rusthorse_0.1.0-1_amd64.deb
```

| Installed | What |
|---|---|
| `/usr/bin/rusthorse`, `rusthorse-dialog`, `rusthorse-broker`, `rusthorse-manager` | The programs |
| `/usr/lib/systemd/user/rusthorse-agent.service` | The agent's service, enabled for every user |
| `/usr/share/applications/`, `/usr/share/icons/` | The menu entry and icon of the manager |
| `/usr/share/bash-completion/`, `zsh/`, `fish/` | Shell completions |
| `/usr/share/doc/rusthorse/` | This documentation; `copyright` lists every crate compiled into the programs, with its license |

The agent starts at your next login. To start it now:

```sh
systemctl --user start rusthorse-agent
```

Then [create a vault](#3-create-a-vault) — section 2 is done for you.

- The programs in `/usr/bin` belong to root, so `chmod go-w` is not needed,
  and AI agents' shells find `rusthorse` on their `PATH`.
- `rusthorse doctor` checks the credential broker's program and the file of
  certificate authorities it reads; without either, everything works but
  `rusthorse run --broker`, which then runs nothing.
- If you installed Rusthorse with `cargo` before, [remove that
  installation](#a-source-installation) first: a service file in
  `~/.config/systemd/user/` takes precedence over the package's and would
  keep starting the old program.
- To keep the agent from starting for one user, that user runs
  `systemctl --user mask rusthorse-agent` (`unmask` undoes it).
- Upgrading is installing a newer package the same way. Agents that are
  running keep the program they started with until your next login, or until
  you restart them (which locks the vault and stops the commands the agent
  started); `rusthorse doctor` says when one runs a replaced program:

  ```sh
  systemctl --user daemon-reload     # in case the service file changed
  systemctl --user restart rusthorse-agent
  ```

### From source

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
that, and should be run again after every upgrade. When `rusthorse-dialog`
is not installed, the agent shows its dialogs with zenity; one that is
installed but can be modified by others is refused, with no fallback.
`rusthorse doctor` says which one the agent uses.

Then install `rusthorse-broker`, the credential broker that the agent
starts for `rusthorse run --broker`
([ADR 0013](adr/0013-credential-broker.md)). It needs nothing that
`rusthorse` does not: its cryptography library, ring, compiles C code with
the C compiler that Rust already uses to link programs.

```sh
cargo install --locked --path broker      # from the clone
# or: cargo install --locked --git https://github.com/Alle4you/rusthorse rusthorse-broker
chmod go-w ~/.cargo/bin/rusthorse-broker
```

It too must sit next to `rusthorse`, be of the same version and not be
modifiable by its group or by others (`chmod go-w`, again after every
upgrade). There is no fallback, and everything else works without it: when
it is missing or one the agent refuses, `rusthorse run --broker` fails
before its dialog; when it cannot serve the grant — a broker that speaks
another version of the agent's protocol for brokers, or no usable file of
certificate authorities (see the [requirements](#requirements)) — the run
fails after the approval. Either way it exits with status 125 and runs
nothing. `rusthorse doctor` checks both: it runs the broker the agent uses
with `--check`, and checks the file of certificate authorities, its owner
and its directories as the broker does (the broker reads the certificates
in it when a grant starts).

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

To build without the Secret Service importer:

```sh
cargo install --locked --path . --no-default-features --features session-lock
```

Without `--features session-lock` too, the agent has no D-Bus dependencies,
and does not lock the vault when the screen locks or the computer suspends.

## 2. Run the agent as a systemd user service

The package does this for you. After installing from source:

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

The agent's settings — auto-lock, remembered approvals, the dialog timeout,
locking on suspend and on screen lock — are changed in the manager's
**Settings** page, or in `~/.config/rusthorse/agent.toml` while the agent is
stopped ([cli.md](cli.md#settings)). An option on the service's command line
wins over both, and the manager cannot change it.

For other options — the vault's location, say — use a drop-in so that
upgrades keep your settings:

```sh
systemctl --user edit rusthorse-agent
```

```ini
[Service]
# Different vault location
Environment=RUSTHORSE_VAULT=%h/Sync/passwords.kdbx
# Or clear the original ExecStart, then set a new one
# (with the package, the program is /usr/bin/rusthorse)
#ExecStart=
#ExecStart=%h/.cargo/bin/rusthorse agent --audit-log %h/rusthorse-audit.jsonl
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

Open **Rusthorse** from the applications menu: on a first start it offers
**Start agent** if the agent is not running yet, then **Create vault…**
([manager guide](manager.md#first-start)). Or, in a terminal:

```sh
rusthorse init
```

Either way, when the agent is running, the agent asks for the new master
password twice in its own dialog, and leaves the new vault unlocked. (Without
an agent, `init` asks in the terminal, without echoing it, and only creates
the file.) The vault is created at `~/.local/share/rusthorse/vault.kdbx` with
mode `0600`.

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
- Rusthorse writes KDBX 4.1. A KDBX 4.0 file, which KeePassXC writes when
  nothing in it needs 4.1, is saved as 4.1, which KeePassXC 2.7+ reads; a
  file in a newer KDBX 4 is read but not modified.

## 4. Check that it works

```sh
rusthorse status
rusthorse add TEST_SECRET          # type a value of four characters or more
rusthorse run TEST_SECRET -- sh -c 'echo "value: $TEST_SECRET"'
# → value: [REDACTED:TEST_SECRET]
rusthorse remove TEST_SECRET
rusthorse audit
```

## Migrating existing secrets

Migrate in five steps, and keep the originals until the fourth is done. The
agent reads the values itself, from GNOME Keyring or the `.env` file
([ADR 0012](adr/0012-import-read-by-the-agent.md)): neither the manager nor
the `rusthorse` command ever holds them, and the import dialog says where
the agent read them.

1. **Back up** the new vault (see below), so that you can go back.
2. **Preview** what would be imported — names only, which ones already
   exist and which appear twice. In the manager: **Import & backup → From
   GNOME Keyring…** or **From a .env file…**; the agent asks before it shows
   the items or names, and the window marks each name new, existing, not
   allowed, repeated or locked. Or in a terminal:

   ```sh
   rusthorse import dotenv ~/project/.env --prefix MYAPP_ --dry-run
   rusthorse import secret-service -a service=myapp --name-from key --dry-run
   ```

   No value reaches the window or the command for a preview (a `.env`
   file is read by the agent, which keeps only the names; keyring secrets
   are not read at all). Keyring items are chosen by attribute:
   items stored with `secret-tool store --label=... service myapp key token`
   are matched by `-a service=myapp` (in the manager: type `myapp` in the
   filter), and `--name-from key` (**Names from: Attribute key**) names each
   entry after its `key` attribute. Check that the preview lists only what
   you mean to move: an attribute that is too broad selects other
   applications' items too.

   **Start with one item.** Tick only it (or add an attribute that selects
   only it, `-a service=myapp -a key=token`), go through steps 3 and 4 with
   it, and import the rest only once it works.
3. **Import**, tagging the result so it is easy to find (the manager tags
   with `imported` unless you change it):

   ```sh
   rusthorse import secret-service -a service=myapp --name-from key --tag migrated
   ```

   Names go to the agent in batches small enough for one approval dialog
   each. For keyring items the dialog shows each entry next to the item its
   value comes from: check that each is the one you mean. A locked keyring
   item stops the import (unlock the keyring first).
4. **Verify each entry by using it**, not just by listing it: run a real,
   harmless command with it — an API call that only reads, a login check —
   for example:

   ```sh
   rusthorse run OPENAI_API_KEY -- sh -c \
       'curl -fsS -o /dev/null -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models'
   ```

   (The single quotes make the command's shell, not yours, expand the
   variable.) If you will also use KeePassXC, open a backup copy in it and
   check that the entries are there.
5. **Delete the originals** with the tool that created them, and update the
   scripts that used it. Until then nothing is protected: while a secret is
   still in GNOME Keyring or a `.env` file, any program of your session —
   an AI agent too — can read it there, without asking Rusthorse.

## Backups and restore

The vault is a single, encrypted file. Make an independent copy with:

```sh
rusthorse backup ~/Backups/rusthorse-$(date +%F).kdbx
```

The agent copies the file and then decrypts the copy with the current master
password, so a backup it reports as written is known to open. Keep backups
somewhere other than the vault's directory, and at least one of them off
this computer: a backup that is lost with the computer restores nothing.

A backup holds the vault and nothing else: the entries, with their values,
the fields that say what each is for and the earlier versions the vault
keeps of them. It is the whole KeePass file, so it also carries what a
KeePass program put there that Rusthorse does not show, such as attachments
or a recycle bin. The audit log (`~/.local/state/rusthorse/audit.jsonl`), the
agent's settings (`~/.config/rusthorse/agent.toml`) and what the agent
keeps in memory, such as remembered approvals and the broker's grants, are
not in it. On another computer the agent starts with its own, which is all
a move needs.

A backup is the vault file as it was: encrypted with the master password
the vault had then, and opened with that password, whatever the vault's
password is now. After `rusthorse passwd`, older backups still open with
the old password: make a new one, and if the old password leaked, delete
the backups made with it.

**Restoring is done by hand.** Restoring a backup is putting that file in
the vault's place. Rusthorse has no restore command, and the agent does not
restore: you copy the file, and at the next unlock the agent reads what is
there.

On **another computer** (the first was lost or stolen), install Rusthorse
and put the backup where the vault goes. No `rusthorse init`: the backup is
the vault.

```sh
mkdir -p ~/.local/share/rusthorse
cp /media/usb/rusthorse-2026-11-01.kdbx ~/.local/share/rusthorse/vault.kdbx
chmod 600 ~/.local/share/rusthorse/vault.kdbx
rusthorse unlock && rusthorse list
```

On the **same computer** (an entry was deleted or changed by mistake), lock
the vault, keep the file as it is, put the backup in its place and unlock:

```sh
rusthorse lock
cp ~/.local/share/rusthorse/vault.kdbx ~/.local/share/rusthorse/vault.kdbx.before-restore
cp ~/Backups/rusthorse-2026-11-01.kdbx ~/.local/share/rusthorse/vault.kdbx
rusthorse unlock && rusthorse list
```

`rusthorse lock` makes the agent drop the vault it had open; at the next
unlock it reads the file again. Until the copy is done, do not answer an
unlock dialog: another program may ask for the vault meanwhile, and the
agent would open the file as it is at that moment. If that happened, lock
again after the copy. Everything changed since the backup is gone from the
vault, the master password included: `unlock` asks for the one the backup
was made with. The second line keeps what you had; delete
`vault.kdbx.before-restore` once you are sure. To get one entry back
without losing what changed since, open the backup in KeePassXC instead,
with its master password, and add the entry again with `rusthorse add`.

`vault.kdbx.bak`, next to the vault, only holds the version before the last
save and is replaced on every save — it is not a backup. After a save that
succeeded it can undo that save: if the mistake was the last thing that
changed the vault, put `vault.kdbx.bak` in the vault's place the same way.
Look before you rely on it: there is none before the vault's first change
or after `rusthorse passwd` (which deletes it, and says so if it cannot),
and after a save that failed it may not be the version you want.

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

With the package, install the newer package as in
[section 1](#debian-ubuntu-linux-mint-the-package), then run `systemctl
--user daemon-reload` and restart the agent (or log in again). From source,
install a specific release of the programs the agent uses — `cargo install
--git` needs their names, since the repository holds several — then restart
the agent so that all of them run the same version. No release has been
published yet: `v0.1.0` below stands for the tag of a future one.

```sh
cargo install --locked --git https://github.com/Alle4you/rusthorse --tag v0.1.0 --force \
    rusthorse rusthorse-dialog rusthorse-broker
chmod go-w ~/.cargo/bin/rusthorse ~/.cargo/bin/rusthorse-dialog ~/.cargo/bin/rusthorse-broker
systemctl --user restart rusthorse-agent
rusthorse doctor
```

Commands refuse to talk to an agent that speaks another protocol version and
say how to restart it; `rusthorse doctor` also notices an agent that still
runs the build an upgrade replaced, even when the protocol did not change,
and a broker of another version than `rusthorse`. Read
[CHANGELOG.md](../CHANGELOG.md) before upgrading.

## File locations

| File | Default | Override |
|---|---|---|
| Vault | `$XDG_DATA_HOME/rusthorse/vault.kdbx` (`~/.local/share/…`) | `RUSTHORSE_VAULT`, `--vault` |
| Previous vault | `vault.kdbx.bak`, next to the vault | — |
| Agent socket | `$XDG_RUNTIME_DIR/rusthorse/agent.sock` (`/run/user/<uid>/…`) | `RUSTHORSE_SOCKET`, `--socket` |
| Audit log | `$XDG_STATE_HOME/rusthorse/audit.jsonl` (`~/.local/state/…`) | `RUSTHORSE_AUDIT_LOG`, `--audit-log` |
| Agent settings | `$XDG_CONFIG_HOME/rusthorse/agent.toml` (`~/.config/…`); it exists only once you write it or change a setting in the manager | `RUSTHORSE_AGENT_CONFIG`, `agent --config` |
| Programs | `/usr/bin` (package) or `~/.cargo/bin` (source) | — |
| Service file | `/usr/lib/systemd/user/` (package) or `~/.config/systemd/user/` (source) | A drop-in: `systemctl --user edit rusthorse-agent` |
| Certificate authorities the broker trusts | The first of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt` and `/etc/ssl/ca-bundle.pem` that exists | — (no variable changes it) |

Directories are created with mode `0700` and files with `0600`. systemd
creates the socket's directory when the agent starts and removes it, with the
socket, when the agent stops (`RuntimeDirectory=` in the service file); an
agent started otherwise creates the directory itself and leaves it.

## Uninstalling

Uninstalling never deletes your vault, your audit log or the agent's settings
file.

### The package

```sh
sudo apt remove rusthorse
```

This removes the programs, the service file, the menu entry, the completions
and the documentation. First it tries to stop the agent of every user who is
logged in (which locks their vaults and stops the commands their agents
started), and prints a warning for each one it cannot stop: that agent keeps
running the removed program until its user logs out or runs `systemctl
--user stop rusthorse-agent`.
Like any package, it keeps the record of whether the service is enabled, so
that installing the package again keeps that choice; `sudo apt purge
rusthorse` deletes that record too, and nothing of the package is left
outside home directories.

### A source installation

```sh
systemctl --user disable --now rusthorse-agent
rm ~/.config/systemd/user/rusthorse-agent.service
systemctl --user daemon-reload
cargo uninstall rusthorse rusthorse-dialog rusthorse-broker
rm -f ~/.local/bin/rusthorse       # if you linked it there
```

If you also installed the manager, remove it as in [its
section](#optional-visual-manager).

### Your data

The vault, its previous version, the audit log and the agent's settings file
(if there is one) stay in place. Delete them
only once you are sure you no longer need the secrets — the vault is an
ordinary KeePass file, which KeePassXC opens, so keep a copy if in doubt:

```sh
rm -r ~/.local/share/rusthorse ~/.local/state/rusthorse
rm -rf ~/.config/rusthorse         # the settings file
```

## Optional visual manager

The package includes `rusthorse-manager` ([guide](manager.md)): open
**Rusthorse** from the applications menu. The rest of this section is for
source installations.

`rusthorse-manager` is a separate program, built like
`rusthorse-dialog`: Rust 1.92 or later and the GTK 4 and libadwaita
development packages (`libgtk-4-dev`, `libadwaita-1-dev`). Plain `cargo`
commands in the source tree do not build it.

To try it without installing anything, when you are at the desktop and
ready to answer the agent's dialogs:

```sh
cargo run --locked -p rusthorse-manager
```

To install it, with a menu entry and its icon:

```sh
cargo install --locked --path manager
chmod go-w ~/.cargo/bin/rusthorse-manager
install -Dm644 data/icons/hicolor/scalable/apps/io.github.alle4you.Rusthorse.svg \
    ~/.local/share/icons/hicolor/scalable/apps/io.github.alle4you.Rusthorse.svg
install -Dm644 data/io.github.alle4you.Rusthorse.desktop \
    ~/.local/share/applications/io.github.alle4you.Rusthorse.desktop
```

The menu entry runs `rusthorse-manager` from the `PATH` of your graphical
session, which may not include `~/.cargo/bin` even when your terminal's does.
If the menu entry does nothing, put the full path in its `Exec=` line (for
example `Exec=/home/you/.cargo/bin/rusthorse-manager`). `chmod go-w` keeps
other users of your group from replacing the program; the agent does not run
the manager, so it does not check it as it checks `rusthorse-dialog`.

The manager starts no agent of its own — its **Start agent** button asks
systemd to start the service — and it changes the agent's settings only
through the agent, after your approval. Installing or upgrading it needs no
restart of the agent.

To uninstall it:

```sh
cargo uninstall rusthorse-manager
rm ~/.local/share/applications/io.github.alle4you.Rusthorse.desktop \
   ~/.local/share/icons/hicolor/scalable/apps/io.github.alle4you.Rusthorse.svg
```

This leaves the vault, its backups and the agent as they are.
