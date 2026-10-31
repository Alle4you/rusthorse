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
| `125` | `run` only: Rusthorse failed or the request was denied; the command did not run. |
| other | `run` only: the command's own exit status (`128 + N` if killed by signal `N`). |

Messages go to standard error; data (listings, JSON, revealed values) goes to
standard output.

## Entry names

An entry name is the KeePass title. Names must be unique, at most 128
characters, without leading or trailing spaces and without control or
invisible formatting characters. Where a command takes a `NAME`, a
`Group/Sub/Name` path also works, which is only needed when a database edited
elsewhere has two entries with the same title.

Using environment-variable-style names (`OPENAI_API_KEY`) lets you write
`rusthorse run OPENAI_API_KEY -- …` instead of `VAR=NAME`.

---

## `rusthorse init`

Create a new, empty vault.

```
rusthorse init [--vault PATH]
```

Asks for the master password twice (in the terminal, or in dialogs without a
terminal). Fails if the file exists. New vaults use Argon2id with 64 MiB and
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
| `--remember` | `10m` | Duration of "Allow for …" in approval dialogs; `0` removes the button. |
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
rusthorse list [--tag TAG] [--json]
rusthorse ls …
```

Lists entries with their username, endpoint (URL, or `host:port`) and tags.
Values and notes are never included. JSON output is an array of objects with
the fields described in [protocol.md](protocol.md#entryinfo).

## `rusthorse show`

```
rusthorse show NAME [--json]
```

Shows one entry's metadata: name, group, username, URL, host, port, tags,
whether it has a value and notes, the names of any other fields, and the last
modification time.

## `rusthorse add`

```
rusthorse add NAME [--username USER] [--url URL] [--host HOST] [--port PORT]
                   [--notes TEXT] [--tag TAG]... [--group PATH]
                   [--stdin] [--replace]
```

Creates an entry. By default the agent opens a dialog where **you** type the
value, so it never passes through the calling process; this needs no further
approval. With `--stdin` the value is read from standard input (trailing
newlines removed) and the request needs approval, because the caller knows
the value.

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
                    [--value | --stdin]
```

Changes an entry. Requires approval; the dialog lists every change. `--value`
makes the agent ask you for a new value in a dialog; `--stdin` reads it from
standard input. `--clear` removes a field: `username`, `url`, `host`, `port`
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
rusthorse run [--no-redact] SECRET... -- COMMAND [ARG]...
```

Runs `COMMAND` with secrets in its environment. Each `SECRET` is either
`NAME` (the variable is named like the entry, which must then be a valid
variable name) or `VAR=NAME`. Requires approval; the dialog shows:

- the command line, the resolved program path (and the real file behind a
  symlink) and the working directory;
- which secret goes into which variable;
- whether output is redacted;
- who is asking (the process chain, e.g. `bash ← claude`);
- warnings about removed variables (`LD_*`) and variables that can make the
  program run other code (`NODE_OPTIONS`, `PYTHONPATH`, `GIT_SSH_COMMAND`, …).

"Allow for 10m" remembers the approval for **exactly** the same secrets,
command line, program, directory, redaction setting and risky variables;
anything else asks again. Locking forgets all remembered approvals. Command
lines longer than 600 characters cannot be remembered.

The agent starts the command itself, in the requested directory, with your
environment minus `LD_*` variables plus the secrets, and connects it to the
caller's standard input, output and error. Unless `--no-redact` is given,
every occurrence of a secret value (4 characters or longer) in the output is
replaced with `[REDACTED:<entry>]`; output therefore goes through a pipe, so
programs see a pipe rather than a terminal. If `rusthorse run` is
interrupted, the command's process group gets `SIGTERM` and, 3 seconds later,
`SIGKILL`.

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
rusthorse reveal NAME
```

Prints the value on standard output. Requires approval every time (it is
never remembered). Meant for humans; automation and AI agents should use
`run`.

## `rusthorse import dotenv`

```
rusthorse import dotenv FILE [--prefix PREFIX] [--tag TAG]... [--replace]
```

Imports `NAME=value` lines (optional `export`, `#` comments, quoted values).
`--prefix` is upper-cased and prepended to each name. One approval covers the
whole batch; existing entries are skipped unless `--replace` is given.

## `rusthorse import secret-service`

```
rusthorse import secret-service --attribute KEY=VALUE... [--name-from ATTR]
                                [--tag TAG]... [--replace]
```

Imports items from the freedesktop Secret Service (GNOME Keyring, KWallet)
whose attributes match all `--attribute` filters. The entry name comes from
the attribute named by `--name-from`, or from the item label. The desktop
keyring may ask you to unlock it. One approval covers the whole batch.

Not available in builds without the default `secret-service` feature.

## `rusthorse audit`

```
rusthorse audit [-n LINES] [--json]
```

Prints the last records of the audit log (default 20). `--json` prints the
raw JSON Lines. Records contain the time, action, outcome, entry names,
requester chain and, for `run`, the command line and directory — never values.
