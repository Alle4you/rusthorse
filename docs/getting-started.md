# Getting started

The first ten minutes with Rusthorse: from an installed binary to an AI agent
using a credential it never sees. It assumes you have followed
[installation.md](installation.md) up to starting the systemd service.

## 1. Check the installation

```console
$ rusthorse doctor
  ok    rusthorse 0.1.0 (protocol 11)
  ok    agent 0.1.0 is running (locked)
  ok    the agent runs the same program file as this rusthorse (/usr/bin/rusthorse)
  ok    dialogs: rusthorse-dialog 0.1.0 (/usr/bin/rusthorse-dialog)
  ok    broker: rusthorse-broker 0.1.0 (/usr/bin/rusthorse-broker)
  ok    the vault locks when the computer suspends (told by logind)
  ok    the vault locks when the screen locks (told by logind, org.cinnamon.ScreenSaver)
  FAIL  no vault at /home/me/.local/share/rusthorse/vault.kdbx — run `rusthorse init`
  ok    the broker reads its certificate authorities from /etc/ssl/certs/ca-certificates.crt, which only root can change; it reads the certificates themselves when a grant starts
  ok    the systemd user service is enabled
  ok    zenity is installed
  warn  X11 session: any program of your user can click "Allow" or read keystrokes (threat model L2)
  ok    Yama ptrace_scope = 1
  ok    checking the files of the agent's configuration
  ok    /run/user/1000/rusthorse is private (700)
```

A `FAIL` line says what to do. The X11 warning is not an error; it is the most
important limitation to understand (see [§6](#6-know-the-limits)). The
`broker:` line and the one about certificate authorities check what the
credential broker needs — its program, `rusthorse-broker`, and the system's
file of certificate authorities (from `ca-certificates`); without them
everything else works, but `rusthorse run --broker` runs nothing (see
[installation.md](installation.md#requirements)).

## 2. Create the vault

Open **Rusthorse** from the applications menu and click **Create vault…**
(see [the manager guide](manager.md#first-start)), or run:

```sh
rusthorse init
```

Either way, the agent asks for the new master password, twice, in its own
dialog.

Choose a long passphrase. There is no recovery if you forget it. Check again
with `rusthorse doctor`: every line should now be `ok` (or the X11 warning).

## 3. Add a few entries

Type a value yourself — the agent asks for it in a dialog, so it never passes
through your shell history or the terminal:

```sh
rusthorse add OPENAI_API_KEY --kind api-key --url https://api.openai.com/v1 --tag ai
```

`--kind api-key` says what the entry is, and makes its URL the API's
endpoint (see [entry kinds](cli.md#entry-kinds)). A command can get the
endpoint too, in a variable of its own — it is not a secret:

```sh
rusthorse run OPENAI_API_KEY --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
```

Store access details next to a password — URL, host or IP, port, username:

```sh
rusthorse add core-router --kind device --username admin --url https://192.168.1.1/ \
    --host 192.168.1.1 --port 443 --tag network --notes "Rack 2"
```

Or let the agent generate a value nobody will ever see (for a new service
account, a database password, a webhook secret):

```sh
rusthorse add STAGING_DB_PASSWORD --generate --length 40 --tag staging
```

Look around — metadata only, values never appear:

```sh
rusthorse list
rusthorse list --search router
rusthorse list --kind api-key
rusthorse show core-router
rusthorse open core-router        # opens https://192.168.1.1/ in your browser
```

The first command that needs the vault asks for the master password, in a
dialog with a text field (title "Rusthorse — unlock vault"): type it there and
click **Unlock**. This is not an approval dialog — those show a command and
**Allow once** / **Deny**. After 15 minutes without an approved use (the
default; a setting changes it), the vault
locks itself again.

## 4. Use a secret

```sh
rusthorse run OPENAI_API_KEY -- python summarize.py
rusthorse run GH_TOKEN=GITHUB_TOKEN -- gh pr list
```

A dialog shows exactly what will run: the command, the real program file,
the directory, which secret goes into which variable, and who is asking.
Read it, then **Allow once** or **Deny**. If the program prints the secret,
you will see `[REDACTED:OPENAI_API_KEY]` instead.

## 5. Bring your existing secrets

In the manager: **Import & backup → From GNOME Keyring…** or **From a .env
file…**, tick what to import ([manager guide](manager.md#import-from-gnome-keyring-or-a-env-file)).
Or in a terminal — either way the agent reads the values itself, after
asking you. From a `.env` file:

```sh
rusthorse import dotenv ~/project/.env --prefix MYAPP_ --tag myapp
```

From GNOME Keyring or KWallet, by attribute (see
[installation.md](installation.md#migrating-existing-secrets)):

```sh
rusthorse import secret-service -a service=myapp --name-from key
```

Once each entry works, delete the originals: while they stay in the keyring
or the file, any program of your session can still read them there. Then
tell your AI agent how to use them — paste the snippet from
[ai-agents.md](ai-agents.md#setting-up-an-agent) into its `CLAUDE.md` or
`AGENTS.md`. The snippet points the agent to `rusthorse guide ai`, which
explains the rest.

## 6. Know the limits

- Rusthorse keeps secrets out of an AI agent's **sight**: its context, its
  output, its logs. It is not a sandbox. On X11, a program determined to
  attack you could click "Allow" itself.
- Approving a command trusts everything that command does — read the dialog,
  especially for `sh -c` and scripts the agent just edited.
- The full list is in the [threat model](threat-model.md); its first section
  is two paragraphs long and worth reading.

## Everyday commands

| Task | Command |
|---|---|
| Lock now (leaving the desk) | `rusthorse lock` |
| What happened recently | `rusthorse audit` |
| Change the master password | `rusthorse passwd` |
| Rotate a credential | `rusthorse edit NAME --generate` (then update it at the provider) |
| Edit in KeePassXC | `rusthorse lock` first, then open the vault file in KeePassXC |
| Back up | `rusthorse backup DEST` (copies the encrypted vault and checks that the copy opens) |

## Visual entry management

The [manager](manager.md) shows the same vault in a window: **Rusthorse** in
the applications menu when installed from the package (from the source tree,
`cargo run --locked -p rusthorse-manager`). Try it with
a fake entry first: create it, edit it, copy its `rusthorse run` command, and
try **Show** and **Copy**. A copied value stays on the clipboard until you
copy something else, and a clipboard history may keep it even after that. Both are for you at the
desktop and ask for your approval; an AI agent uses `rusthorse run`.
