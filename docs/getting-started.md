# Getting started

The first ten minutes with Rusthorse: from an installed binary to an AI agent
using a credential it never sees. It assumes you have followed
[installation.md](installation.md) up to starting the systemd service.

## 1. Check the installation

```console
$ rusthorse doctor
  ok    rusthorse 0.1.0 (protocol 1)
  ok    agent 0.1.0 is running (locked)
  FAIL  no vault at /home/me/.local/share/rusthorse/vault.kdbx — run `rusthorse init`
  ok    the systemd user service is enabled
  ok    zenity is installed
  warn  X11 session: any program of your user can click "Allow" or read keystrokes (threat model L2)
  ok    Yama ptrace_scope = 1
```

A `FAIL` line says what to do. The X11 warning is not an error; it is the most
important limitation to understand (see [§6](#6-know-the-limits)).

## 2. Create the vault

```sh
rusthorse init
```

Choose a long passphrase. There is no recovery if you forget it. Check again
with `rusthorse doctor`: every line should now be `ok` (or the X11 warning).

## 3. Add a few entries

Type a value yourself — the agent asks for it in a dialog, so it never passes
through your shell history or the terminal:

```sh
rusthorse add OPENAI_API_KEY --url https://platform.openai.com --tag ai
```

Store access details next to a password — URL, host or IP, port, username:

```sh
rusthorse add core-router --username admin --url https://192.168.1.1/ \
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
rusthorse show core-router
rusthorse open core-router        # opens https://192.168.1.1/ in your browser
```

The first command that needs the vault asks for the master password. After 15
minutes without an approved use, the vault locks itself again.

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

From a `.env` file:

```sh
rusthorse import dotenv ~/project/.env --prefix MYAPP_ --tag myapp
```

From GNOME Keyring or KWallet, by attribute (see
[installation.md](installation.md#migrating-existing-secrets)):

```sh
rusthorse import secret-service -a service=myapp --name-from key
```

Then tell your AI agent how to use them — paste the snippet from
[ai-agents.md](ai-agents.md#setting-up-an-agent) into its `CLAUDE.md` or
`AGENTS.md`.

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
| Back up | copy `~/.local/share/rusthorse/vault.kdbx` (it is encrypted) |
