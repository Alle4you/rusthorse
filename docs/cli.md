# CLI reference

```
rusthorse [--socket PATH] <COMMAND> [OPTIONS]
```

Every command except `init`, `agent` and `audit` talks to the agent over its
Unix socket. Run `rusthorse <command> --help` for the same information in the
terminal.

## Global options and environment

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--socket PATH` | `RUSTHORSE_SOCKET` | `$XDG_RUNTIME_DIR/rusthorse/agent.sock` | Agent socket |
| `--vault PATH` (`init`, `agent`) | `RUSTHORSE_VAULT` | `$XDG_DATA_HOME/rusthorse/vault.kdbx` | Vault file |
| `--audit-log PATH` (`agent`) | `RUSTHORSE_AUDIT_LOG` | `$XDG_STATE_HOME/rusthorse/audit.jsonl` | Audit log |

`rusthorse audit` reads `RUSTHORSE_AUDIT_LOG` (or the default location).

## Exit statuses

| Status | Meaning |
|---|---|
| `0` | Success. |
| `1` | Error (agent not running, entry not found, invalid input, …). |
| `2` | Invalid command line. |
| `4` | You denied the request, cancelled a dialog, or a dialog timed out. |
| `124` | The outcome is unknown: the request was sent but no usable answer came back, or the agent could not confirm that it took effect (it could not determine the result of a command it had started, or could not sync a change to disk). For `run`, the command may or may not have run; for a change (`add`, `edit`, `remove`, `import`, `passwd`, `backup`), check with `rusthorse list` or `show` before repeating it. Read-only commands exit with 1 instead. |
| `125` | `run` only: Rusthorse failed or the request was denied; the command did not run. |
| other | `run` only: the command's own exit status (`128 + N` if killed by signal `N`; 141 when the output of `rusthorse run` itself was closed). |

Messages go to standard error; data (listings, JSON, revealed values) goes to
standard output.

## Entry names

An entry name is the KeePass title. Names must be unique, at most 128
characters, without `/`, without leading or trailing spaces and without
control or invisible formatting characters. Where a command takes a `NAME`, a
`Group/Sub/Name` path also works, which is only needed when a database edited
elsewhere has two entries with the same title, and so does the entry's UUID
(shown by `show` and in dialogs). If a name matches more than
one entry in any way (for example a title containing `/` that looks like the
path of another entry), the command fails with an "ambiguous" error listing
the paths.

Using environment-variable-style names (`OPENAI_API_KEY`) lets you write
`rusthorse run OPENAI_API_KEY -- …` instead of `VAR=NAME`.

---

## `rusthorse init`

Create a new, empty vault.

```
rusthorse init [--vault PATH]
```

Asks for the master password twice (in the terminal, or in dialogs without a
terminal) — the only time the CLI itself handles a master password. Fails if
the file exists. New vaults use Argon2id with 64 MiB and
20 passes (about 0.7 s per unlock on a desktop CPU).

## `rusthorse agent`

Run the agent in the foreground. Normally started by the systemd unit
(see [installation.md](installation.md)).

```
rusthorse agent [--vault PATH] [--audit-log PATH]
                [--idle-timeout DURATION] [--remember DURATION]
                [--dialog-timeout DURATION]
```

| Option | Default | Meaning |
|---|---|---|
| `--idle-timeout` | `15m` | Lock after this much inactivity; `0` never locks. |
| `--remember` | `0` (off) | Offer "Allow for DURATION" in `run` dialogs. Off by default; read [ADR 0005](adr/0005-remembered-approvals-opt-in.md) before enabling it. |
| `--dialog-timeout` | `2m` | Unanswered dialogs are denied (or cancelled) after this long. |

Durations are a number followed by `s`, `m` or `h`, or `0`.

## `rusthorse status`

```
rusthorse status [--json]
```

Shows the agent version, the vault path, whether it is locked, when it will
lock itself, how many approvals are remembered, which program shows its
dialogs (the path of `rusthorse-dialog`, `zenity`, or `none:` and why) and
the program file the agent runs (with a note if it was replaced since the
agent started).

## `rusthorse unlock` / `rusthorse lock`

`unlock` makes the agent ask for the master password now (it also asks
whenever a request needs the vault). The dialog has a text field: type the
password there and click **Unlock**. You get three attempts; clicking Unlock
with the field empty asks again without counting as a wrong password, and if
nothing is ever typed the unlock counts as cancelled. Wrong passwords are
recorded in the audit log; after three attempts the request fails. `lock`
discards the decrypted vault and all remembered approvals immediately.

## `rusthorse list`

```
rusthorse list [--tag TAG] [--kind KIND] [--search TEXT] [--json]
rusthorse ls …
```

Lists entries with their username, endpoint (URL, or `host:port`) and tags.
`--kind` keeps entries of one [kind](#entry-kinds) (`other`: entries of no
particular kind); an AI agent looking for an API key can start with
`rusthorse list --kind api-key`. `--search` keeps entries whose name, group,
username, URL, host or tags contain the text (case-insensitive).
Values and notes are never included, nor any field that the KeePass file marks
as protected. JSON output is an array of objects with the fields described in
[protocol.md](protocol.md#entryinfo), including each entry's UUID.

## `rusthorse show`

```
rusthorse show NAME [--json]
```

Shows one entry's metadata: name, group, kind, username, URL, host, port,
tags, whether it has a value and notes, the names of protected and other
fields, and the last modification time.

## Entry kinds

An entry can say what it is for, with `--kind` in `add` and `edit`:

| `--kind` | For | `--url` is |
|---|---|---|
| `api-key` | A key or token for an API | The API's endpoint, e.g. `https://api.openai.com/v1` |
| `login` | A sign-in to a website or web console | The sign-in page |
| `server` | A server reached by host and port (SSH, a database, …) | — |
| `device` | A device such as a router or a camera | Its admin page |
| `other` | No particular kind (the default) | Any access link |

The kind names the fields and decides which ones the manager's form offers
(it never hides a field that has a value); `list --kind` filters by it. It
is stored in the KDBX field `Kind`, which KeePassXC shows as an attribute.
It grants and restricts nothing. See
[ADR 0008](adr/0008-entry-kinds.md).

## `rusthorse add`

```
rusthorse add NAME [--kind KIND] [--username USER] [--url URL] [--host HOST]
                   [--port PORT] [--notes TEXT] [--tag TAG]... [--group PATH]
                   [--stdin | --generate [--length N] [--alphabet KIND]]
                   [--replace]
```

Creates an entry. By default the agent opens a dialog where **you** type the
value, so it never passes through the calling process; this needs no further
approval. With `--stdin` the value is read from standard input (trailing
newlines removed) and the request needs approval, because the caller knows
the value.

With `--generate`, the agent creates a random value itself (from the
operating system's random number generator) after you approve; nobody types
or sees it. This is the way for an AI agent to set up a new credential — for
example a database password it will only ever use through `rusthorse run`.
`--length` (8–1024, default 32) and `--alphabet` (`alnum`, the default;
`symbols`, which adds `-_.:@+=~%^`; or `hex`) shape the value.

`--replace` overwrites an existing entry with the same name (the old version
stays in the entry's history). `--group` places a new entry in a group,
creating it if needed (`Work/Servers`).

Examples — an API key with its endpoint, and a router with its access
details:

```sh
rusthorse add OPENAI_API_KEY --kind api-key --url https://api.openai.com/v1 --tag ai
rusthorse add core-router --kind device --username admin --url https://10.0.0.1/ \
    --host 10.0.0.1 --port 443 --tag network --notes "Rack 2, console on J3"
```

## `rusthorse edit`

```
rusthorse edit NAME [--kind KIND] [--username USER] [--url URL] [--host HOST]
                    [--port PORT] [--notes TEXT] [--rename NEW] [--clear FIELD]...
                    [--add-tag TAG]... [--remove-tag TAG]...
                    [--value | --stdin | --generate [--length N] [--alphabet KIND]]
```

Changes an entry. Requires approval; the dialog lists every change. `--value`
makes the agent ask you for a new value in a dialog; `--stdin` reads it from
standard input; `--generate` replaces it with a new random value (to rotate a
credential: generate, then update it at the provider with `rusthorse run`). `--clear` removes a field: `username`, `url`, `host`, `port`,
`notes` or `kind`; `--kind other` also removes the kind. The previous state is
kept in the entry's KeePass history.

## `rusthorse remove`

```
rusthorse remove NAME
rusthorse rm NAME
```

Deletes an entry permanently. Requires approval. Until the next save, the
previous file is still available as `vault.kdbx.bak`.

## `rusthorse run`

```
rusthorse run [--no-redact] [--stdin] [--url VAR=NAME]... SECRET... -- COMMAND [ARG]...
```

Runs `COMMAND` with secrets in its environment. Each `SECRET` is either
`NAME` (the variable is named like the entry, which must then be a valid
variable name) or `VAR=NAME`.

`--url VAR=NAME` also puts entry `NAME`'s URL — for an API key, its
endpoint — in variable `VAR`. `rusthorse run` reads the URL from the entry's
metadata before sending the request, as `rusthorse show` would, and adds it to
the environment it sends, exactly as if you had written
`VAR=https://… rusthorse run …`. The URL is not a secret: it is not redacted
from the output. Like any variable that names where the program connects, it
appears in the dialog under **Connects to** when its name says so
(`OPENAI_BASE_URL` does; see below).

`--url` is refused before anything is asked when it lacks `=`, when `VAR` is
already the variable of a secret or of another `--url`, and when `VAR` is a
variable that changes how programs start (`LD_*` and the risky variables
listed below). Reading the URL needs the vault open, like `show`: if it is
locked, the agent asks for the master password first. An entry without a URL
(or whose URL the file marks protected) is then refused before the run is
approved.

Requires approval; the dialog shows:

- the command line, the resolved program path (and the real file behind a
  symlink) and the working directory;
- which secret goes into which variable;
- whether output is redacted;
- who is asking (the process chain, e.g. `bash ← claude`);
- what the command reads as input (nothing, or your forwarded input);
- that the command runs as you, outside any sandbox the requester is in;
- warnings about removed variables (`LD_*`) and variables that can make the
  program run other code (`NODE_OPTIONS`, `PYTHONPATH`, `GIT_SSH_COMMAND`, …);
- **Connects to (environment)**: the variables that name where the program
  connects — names ending in `_URL`, `_URI`, `_API_BASE`, `_ENDPOINT`,
  `_HOST`, `_ADDR` or `_REGISTRY` (`OPENAI_BASE_URL`, `DATABASE_URL`,
  `DOCKER_HOST`, `VAULT_ADDR`, …) and `PGHOST`-style names;
- a warning for the variables that route its connections or change which
  servers it trusts: proxies (`HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`,
  `GOPROXY`, …), certificate authorities (`SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, …), switches that turn
  certificate checks off (`NODE_TLS_REJECT_UNAUTHORIZED`, `GIT_SSL_NO_VERIFY`,
  …) and name resolution (`RES_OPTIONS`, `LOCALDOMAIN`). A certificate
  variable that names the system's own store (`/etc/ssl/…`, `/usr/lib/ssl/…`,
  which only root can change) is not listed, nor is `NO_PROXY`.

The requester sets these variables, and with them it can make an approved,
well-known program send your secret to a server of its own: check the host
of every one. A URL is shown by its scheme, host and port only
(`https://…@proxy:3128/…`): user names, passwords, paths and queries —
where credentials and webhook tokens travel — are left out of the dialog and
the audit log. The variables reach the command unchanged. The lists are not
complete; a program can also read an address from a file or its arguments.

Requests whose command line, program path or directory is longer than 1000
characters are refused (put the command in a script): the dialog never
truncates what you approve.

After you answer, the agent checks that the vault was not locked or changed,
that the entries are the same (by UUID) and that the program file and the
directory were not replaced; otherwise nothing runs. The agent then starts the
command itself, in the requested directory, with your environment minus
`LD_*` variables plus the secrets. Unless `--no-redact` is given, the command's
standard output and error are pipes owned by the agent, and every occurrence
of a secret value (4 characters or longer) in them is replaced with
`[REDACTED:<entry>]` before the agent sends the output back to
`rusthorse run`, which prints it. The command's standard input is
`/dev/null`, unless `--stdin` makes `rusthorse run` forward yours. Programs
therefore see pipes rather than a terminal. With `--no-redact`, the command
gets the caller's descriptors directly (including stdin).

If the output of `rusthorse run` is closed early (for example
`rusthorse run … | head`), it stops the command and exits with status 141,
like a program killed by `SIGPIPE`. With `--stdin`, input is read only once
the command has started, so a denied request never consumes it.

When the command exits, anything it left running in its process group (for
example `sleep 30 &`) is terminated; if `rusthorse run` is interrupted before
that, the whole group is terminated too — `SIGTERM`, then `SIGKILL` 3 seconds
later.

If the agent runs with `--remember`, the dialog also offers "Allow for …",
which lets **identical** requests (same vault state, entries, command line,
program, directory, input and output handling, and the complete environment)
run without asking for that long. It does not cover what the command reads, so use it only for commands
whose input you control.

Examples:

```sh
rusthorse run OPENAI_API_KEY -- python app.py
rusthorse run OPENAI_API_KEY --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
rusthorse run GH_TOKEN=github-token -- gh pr create --fill
rusthorse run PGPASSWORD=prod-db -- psql -h db.lan -U app app
rusthorse run TOKEN=cloudflare -- sh -c 'curl -sH "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'
```

Exit status: the command's, `125` if it did not run, or `124` if Rusthorse cannot tell.

## `rusthorse reveal`

```
rusthorse reveal NAME [--notes]
```

Prints the value (or, with `--notes`, the entry's notes) on standard output. Requires approval every time (it is
never remembered). Meant for humans; automation and AI agents should use
`run`.

There is deliberately no `copy` command: on X11 every program of your user
can read the clipboard, including the AI agent the value is being kept from.

## `rusthorse backup`

```
rusthorse backup DEST
```

Copies the encrypted vault file to `DEST` (which must not exist; mode `0600`)
and then decrypts the copy with the current master password to prove it
opens. See [installation.md](installation.md#backups-and-restore) for
restoring.

## `rusthorse open`

```
rusthorse open NAME
```

Opens the entry's URL — its access link — with `xdg-open` (your default
browser). Only `http://` and `https://` links are opened. No secret is
involved, so no approval is needed; log in with the browser's own password
handling or by revealing the value.

## `rusthorse passwd`

```
rusthorse passwd
```

Changes the master password. The agent asks, in its own dialogs, for the
current password and then the new one twice. The vault is re-encrypted with
the new password and the previous file (`vault.kdbx.bak`, encrypted with the
old password) is deleted; if that deletion fails, the command says so and
names the file to delete by hand (the password change itself is kept). Copies
you made elsewhere keep the old password.

## `rusthorse generate`

```
rusthorse generate [--length N] [--alphabet alnum|symbols|hex]
```

Prints a random value; nothing is stored and the agent is not involved. To
store a generated value without seeing it, use `rusthorse add NAME --generate`.

## `rusthorse import dotenv`

```
rusthorse import dotenv FILE [--prefix PREFIX] [--tag TAG]... [--replace] [--dry-run]
```

Imports `NAME=value` lines (optional `export`, `#` comments, quoted values).
`--prefix` is upper-cased and prepended to each name. Existing entries are
skipped unless `--replace` is given. Entries are sent in batches of at most 50
(fewer if the names are long), one approval each; a name that appears twice
stops the import before anything is sent. If a batch fails, the summary says
which batches were imported and whether the failed one was not imported (exit
1, or 4 if denied) or may or may not have been (exit 124: check with
`rusthorse list` before running the import again). `--dry-run` lists the names
and whether each is new, exists or is not allowed, and imports nothing.

## `rusthorse import secret-service`

```
rusthorse import secret-service --attribute KEY=VALUE... [--name-from ATTR]
                                [--tag TAG]... [--replace] [--dry-run]
```

Imports items from the freedesktop Secret Service (GNOME Keyring, KWallet)
whose attributes match all `--attribute` filters. The entry name comes from
the attribute named by `--name-from`, or from the item label. The desktop
keyring may ask you to unlock it. Batches and `--dry-run` work as for
`import dotenv`; a dry run reads only the items' attributes, never their
secrets. See [installation.md](installation.md#migrating-existing-secrets)
for a safe migration procedure.

Not available in builds without the default `secret-service` feature.

## `rusthorse audit`

```
rusthorse audit [-n LINES] [--json]
```

Prints the last records of the audit log (default 20). `--json` prints the
raw JSON Lines. Records contain the time, action, outcome, entry names,
requester chain and, for `run`, the command line and directory — never values.
A `run` record's `detail` names the variables the dialog listed under
**Connects to** and in its routing warning, shortened the same way.
The time is when the record was written, after the decision — for an
approval or a denial, after you answered the dialog, not when the request
arrived. It is usually within a moment of your answer, but can be later when
other records are being written or the disk is slow. It comes from the system
clock, so setting the clock back can make a later record show an earlier
time.

## `rusthorse doctor`

```
rusthorse doctor
```

Checks the installation without touching any secret: the agent is running,
speaks the same protocol version and runs the same program file as this
`rusthorse` — compared by the device and inode the agent reads through its
own `/proc/self/exe`, not by name, so this says "same file", not "same source
code" (an agent still running a file that was since replaced or removed is an
error: restart it; a different file, or one that cannot be compared, is a
warning) — which program shows the agent's dialogs (`rusthorse-dialog` next
to the agent's executable, checked as the agent checks it and by running
`rusthorse-dialog --check`, which opens no window and reports its version and
protocol, under the same supervision as dialogs and a 5-second limit; the
program is the one the agent reports using, run by its path in `doctor`'s own
mount namespace, which is the agent's in a normal installation; missing is a
warning, since zenity then shows the dialogs; unusable
or incompatible is an error), the systemd service is enabled, zenity is
installed (only a warning when `rusthorse-dialog` is), the session type (X11
is reported as a warning — see the threat model), Yama `ptrace_scope`, the
vault's format and permissions, and the socket directory's permissions. Exits
with status 1 if anything failed.

## `rusthorse completions`

```
rusthorse completions bash|zsh|fish|elvish|powershell
```

Prints a completion script. For bash:

```sh
mkdir -p ~/.local/share/bash-completion/completions
rusthorse completions bash > ~/.local/share/bash-completion/completions/rusthorse
```

## Upgrades

Commands that talk to the agent first check that it speaks the same protocol
version (for `run`, a missing or incompatible agent exits with 125: the
command did not run). After upgrading the binary, restart the agent
(`systemctl --user restart rusthorse-agent`); until then those commands stop
with an explanation instead of failing in confusing ways.

## Separate visual manager

`rusthorse-manager` is an optional GTK client, not a `rusthorse` subcommand.
It uses the existing agent protocol and `RUSTHORSE_SOCKET` override. See
[manager.md](manager.md) for its first milestone and pending features. It
does not start the agent or replace the CLI's commands or exit statuses.
