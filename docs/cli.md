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
| `124` | `run` only: the outcome is unknown — the connection to the agent was lost after the request was sent, or the agent could not determine the result of a command it had started. The command may or may not have run. |
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
lock itself and how many approvals are remembered.

## `rusthorse unlock` / `rusthorse lock`

`unlock` makes the agent ask for the master password now (it also asks
whenever a request needs the vault). `lock` discards the decrypted vault and
all remembered approvals immediately.

## `rusthorse list`

```
rusthorse list [--tag TAG] [--search TEXT] [--json]
rusthorse ls …
```

Lists entries with their username, endpoint (URL, or `host:port`) and tags.
`--search` keeps entries whose name, group, username, URL, host or tags
contain the text (case-insensitive).
Values and notes are never included, nor any field that the KeePass file marks
as protected. JSON output is an array of objects with the fields described in
[protocol.md](protocol.md#entryinfo), including each entry's UUID.

## `rusthorse show`

```
rusthorse show NAME [--json]
```

Shows one entry's metadata: name, group, username, URL, host, port, tags,
whether it has a value and notes, the names of protected and other fields,
and the last modification time.

## `rusthorse add`

```
rusthorse add NAME [--username USER] [--url URL] [--host HOST] [--port PORT]
                   [--notes TEXT] [--tag TAG]... [--group PATH]
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

Example — a router with its access details:

```sh
rusthorse add core-router --username admin --url https://10.0.0.1/ \
    --host 10.0.0.1 --port 443 --tag network --notes "Rack 2, console on J3"
```

## `rusthorse edit`

```
rusthorse edit NAME [--username USER] [--url URL] [--host HOST] [--port PORT]
                    [--notes TEXT] [--rename NEW] [--clear FIELD]...
                    [--add-tag TAG]... [--remove-tag TAG]...
                    [--value | --stdin | --generate [--length N] [--alphabet KIND]]
```

Changes an entry. Requires approval; the dialog lists every change. `--value`
makes the agent ask you for a new value in a dialog; `--stdin` reads it from
standard input; `--generate` replaces it with a new random value (to rotate a
credential: generate, then update it at the provider with `rusthorse run`). `--clear` removes a field: `username`, `url`, `host`, `port`
or `notes`. The previous state is kept in the entry's KeePass history.

## `rusthorse remove`

```
rusthorse remove NAME
rusthorse rm NAME
```

Deletes an entry permanently. Requires approval. Until the next save, the
previous file is still available as `vault.kdbx.bak`.

## `rusthorse run`

```
rusthorse run [--no-redact] [--stdin] SECRET... -- COMMAND [ARG]...
```

Runs `COMMAND` with secrets in its environment. Each `SECRET` is either
`NAME` (the variable is named like the entry, which must then be a valid
variable name) or `VAR=NAME`. Requires approval; the dialog shows:

- the command line, the resolved program path (and the real file behind a
  symlink) and the working directory;
- which secret goes into which variable;
- whether output is redacted;
- who is asking (the process chain, e.g. `bash ← claude`);
- what the command reads as input (nothing, or your forwarded input);
- that the command runs as you, outside any sandbox the requester is in;
- warnings about removed variables (`LD_*`) and variables that can make the
  program run other code (`NODE_OPTIONS`, `PYTHONPATH`, `GIT_SSH_COMMAND`, …).

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
rusthorse run GH_TOKEN=github-token -- gh pr create --fill
rusthorse run PGPASSWORD=prod-db -- psql -h db.lan -U app app
rusthorse run TOKEN=cloudflare -- sh -c 'curl -sH "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'
```

Exit status: the command's, or `125` if it did not run.

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
(fewer if the names are long), one approval each. `--dry-run` lists the names
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

## `rusthorse doctor`

```
rusthorse doctor
```

Checks the installation without touching any secret: the agent is running
and speaks the same protocol version, the systemd service is enabled, zenity
is installed, the session type (X11 is reported as a warning — see the threat
model), Yama `ptrace_scope`, the vault's format and permissions, and the
socket directory's permissions. Exits with status 1 if anything failed.

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
