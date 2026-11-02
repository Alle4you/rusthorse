# CLI reference

```
rusthorse [--socket PATH] <COMMAND> [OPTIONS]
```

Most commands talk to the agent over its Unix socket. `agent`, `audit`,
`generate`, `completions` and `guide` never do, and `init` does when an agent
runs. Run `rusthorse <command> --help` for the same information in the
terminal; `rusthorse --help` ends by pointing AI agents to
[`rusthorse guide ai`](#rusthorse-guide).

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

When the agent is running and serves that vault (the path `rusthorse status`
shows — with the default settings, always; paths are compared after
resolving links, so `--vault ./vault.kdbx` in that directory is the same
file), the agent creates it: it asks
for the master password twice in its own dialogs, so that the password never
enters the `rusthorse` process — which an AI agent may have started — and
leaves the new vault unlocked. The manager's **Create vault…** does the same.

Otherwise — no agent runs, or one serves another vault — `init` creates the
file itself and asks for the master password twice, in the terminal or, without
a terminal, in dialogs: the only time the CLI itself handles a master
password. Run it in your own terminal, not through an AI agent. When an
agent's socket exists but the agent cannot be asked (it does not answer, or
answers something else), `init` stops instead of asking for the password
itself.

Either way it fails if the file exists, and never replaces a file that
appears while it works. Exits 4 when a dialog is cancelled or not answered,
124 when the file was written but its directory could not be synced (it may
not survive a crash).
New vaults use Argon2id with 64 MiB and 20 passes (about 0.7 s per unlock on
a desktop CPU).

## `rusthorse agent`

Run the agent in the foreground. Normally started by the systemd unit
(see [installation.md](installation.md)).

```
rusthorse agent [--vault PATH] [--audit-log PATH]
                [--idle-timeout DURATION] [--remember DURATION]
                [--dialog-timeout DURATION]
                [--no-lock-on-suspend] [--no-lock-on-screen-lock]
```

| Option | Default | Meaning |
|---|---|---|
| `--idle-timeout` | `15m` | Lock after this much inactivity; `0` never locks. |
| `--remember` | `0` (off) | Offer "Allow for DURATION" in `run` dialogs. Off by default; read [ADR 0005](adr/0005-remembered-approvals-opt-in.md) before enabling it. |
| `--dialog-timeout` | `2m` | Unanswered dialogs are denied (or cancelled) after this long. |
| `--no-lock-on-suspend` | off | Do not lock when the computer is about to sleep. |
| `--no-lock-on-screen-lock` | off | Do not lock when the session is locked or its screensaver starts. |

Durations are a number followed by `s`, `m` or `h`, or `0`.

Besides the idle timer, the agent locks the vault when the computer is about
to suspend or hibernate — logind waits for it, thanks to a delay inhibitor
the agent holds, up to logind's `InhibitDelayMaxSec` (5 seconds by default;
a vault save in progress can make the lock later) — and when your session is
locked or its screensaver starts
(logind's session lock, Cinnamon's, GNOME's, MATE's and the freedesktop
screensaver). Nothing ever unlocks the vault but the master password: a
screen unlock or a resume does not. `rusthorse status` and `rusthorse doctor`
say what is being watched. See
[ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md).

## `rusthorse status`

```
rusthorse status [--json]
```

Shows the agent version, the vault path, whether it is locked, when it will
lock itself, how many approvals are remembered, which program shows its
dialogs (the path of `rusthorse-dialog`, `zenity`, or `none:` and why), what
else locks the vault, and the program file the agent runs (with a note if it
was replaced since the agent started). For example:

```
locks on:   suspend: logind (locks before the computer sleeps)
            screen lock: logind (session lock signals of this user), org.cinnamon.ScreenSaver
```

`not watched` and the reason appear when a source is unavailable (no system
bus, no session bus, logind or no screensaver on the bus, turned off, a
build without the `session-lock` feature); a watcher whose bus goes away
connects again every few seconds, and on connecting locks if the session is
locked or a screensaver on already. When logind would not give an
inhibitor, the suspend line says so: the lock may then come only after the
computer wakes.

## `rusthorse unlock` / `rusthorse lock`

`unlock` makes the agent ask for the master password now (it also asks
whenever a request needs the vault). The dialog has a text field: type the
password there and click **Unlock**. You get three attempts; clicking Unlock
with the field empty asks again without counting as a wrong password, and if
nothing is ever typed the unlock counts as cancelled. Wrong passwords are
recorded in the audit log; after three attempts the request fails. `lock`
discards the decrypted vault and all remembered approvals immediately; so do
a suspend and a screen lock (see [`rusthorse agent`](#rusthorse-agent)).

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
appears in the dialog under **Destinations** when its name says so
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
- **Destinations (environment)**: the variables that name where the program
  connects — names ending in `_URL`, `_URI`, `_API_BASE`, `_ENDPOINT`,
  `_HOST`, `_ADDR` or `_REGISTRY` (`OPENAI_BASE_URL`, `DATABASE_URL`,
  `DOCKER_HOST`, `VAULT_ADDR`, …), `AWS_ENDPOINT_URL_<SERVICE>` and
  `PGHOST`-style names. If a name appears twice, the last value — the one
  the command gets — is shown;
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
of every one. They are settings found in the environment, not the
connections the program will make. Only unambiguous values are shown, and
only values of printable ASCII: anything else (U+00A0, which Python splits
at like a space; a control character) is not shown at all. A list variable
is judged item by item, at the separators its program uses — `GOPROXY` at
`,` and `|`, each item trimmed of spaces as Go does; libpq's `PGHOST`,
`PGHOSTADDR` and `PGPORT` at `,`; `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`,
`UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_INSECURE_HOST`, and the resolver's
`LOCALDOMAIN` and `RES_OPTIONS` at spaces — and uv's `name=URL` items keep
their name. Any other value is one item, never split, and is not shown if it
contains a space. Shown:

- a URL by its scheme, host and port (`https://…@proxy:3128/…`): user
  names, passwords, paths and queries — where credentials and webhook
  tokens travel — are left out; `postgres:`, `postgresql:` and `mongodb:`
  URLs may list several hosts (`…@h1:5432,h2:5433/…`);
- `user:password@host` without a scheme as `…@host`; a host name
  (`direct` and `off` read as such), a canonical IPv4 address (`10.0.0.1`)
  or a bracketed IPv6 address as it is;
- the value of a switch or a port — `GIT_SSL_NO_VERIFY`,
  `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `PGPORT` — as it is
  when it is one word or number;
- a local socket, file or database (`unix:///run/docker.sock`,
  `sqlite:///./app.db`, `sqlite:///:memory:`), the paths of certificate
  variables, and absolute paths, as they are.

Anything else appears as `(not shown)`, and a warning names the variable:
a backslash anywhere; two `@`; a `?` and an `@` both before the first `/`
(libpq takes what precedes the `@` for user information, past the `?`, and
connects to the host after it, while URL parsers stop at the `?`); a `#`
(libpq reads it as part of a value and goes on reading parameters); a host
with characters other than letters,
digits, `.`, `-` and `_`; a numeric host other than `a.b.c.d` (`127.1`,
`0x7f.1`, `2130706433`, which resolvers turn into `127.0.0.1` each in its
own way); an empty host outside `unix:`, `file:` and `sqlite:` (`https:///host/…`,
`https:/host`); a path that starts with `//`; and a URL whose query names
another destination (`host`, `hostaddr`, `port`, `service` — libpq connects
to those, not to the URL's host) or has a parameter name with characters
other than letters, digits, `_`, `-` and `.`. Programs read such values differently (a parser
that takes `\` for `/` connects to the host before the `@`, while the text
after it names another), so a host drawn from them could be the wrong one,
and copying them could disclose a credential. The audit log gets the same
shortened text; the variables reach the command unchanged.

These rules were checked, case by case, against the readings of common URL
parsers (WHATWG as in Node, Python's, curl's) and of libpq that reviews
found to differ; tests pin each case down. They are an aid for reading the
dialog, not a proof about every program: another library may read the same
text another way. The lists are not complete either: a program can read an
address from a file or its arguments, and a name outside them
(`MY_SERVICE=https://…`) is not listed.

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

Imports `NAME=value` lines in a small `.env` dialect, chosen so that
python-dotenv and Node's dotenv read every file Rusthorse accepts as it does
(Docker's `--env-file` keeps quotes in the value, and shells take no spaces
around `=`): lines end with LF or CRLF; the only blanks are spaces and
tabs; a line is blank, a `#` comment, or `NAME=value` with an optional
`export` and blanks around `=`, `NAME` made of ASCII letters, digits, `_`,
`.` and `-`; a value is on one line, either in single or double quotes with
neither that quote nor a backslash inside, or unquoted — not starting with a
back quote — where a `#` after a blank starts a comment; no value holds
`${…}` (python-dotenv replaces it by another variable's value, Node's
dotenv does not), no name is set twice, and none is `__proto__` (Node's
dotenv drops it). Any other file is refused as a whole, naming the line
only: nothing in it is skipped, and the whole file is checked before any
name is listed, so a file with an error starts no import. (The import itself
saves batch by batch, as said below.) Add values the dialect cannot hold
(over several lines, with backslashes) with `rusthorse add`. Variables with
an empty value cannot be imported; the command names them.
The agent reads the file itself ([ADR 0012](adr/0012-import-read-by-the-agent.md)):
this command never holds a value. It first asks the agent for the names in
the file — the agent asks you in a dialog before it shows them — then sends
the names to import. `--prefix` is upper-cased and prepended to each name.
Existing entries are skipped unless `--replace` is given. Entries are
imported in batches, one approval each, each as large as fits in one dialog
(estimated as the agent builds it, for the longest dialog it could be); the
dialog says that the agent read the values from the file. A name that
appears twice stops the import before anything is imported. If a batch
fails, the summary says which batches were imported and whether the failed
one was not imported (exit 1, or 4 if denied) or may or may not have been
(exit 124: check with `rusthorse list` before running the import again).
`--dry-run` lists the names and whether each is new, exists or is not
allowed, and imports nothing.

The file must be a regular file of at most 1 MiB, in UTF-8.

## `rusthorse import secret-service`

```
rusthorse import secret-service --attribute KEY=VALUE... [--name-from ATTR]
                                [--tag TAG]... [--replace] [--dry-run]
```

Imports items from the freedesktop Secret Service (GNOME Keyring, KWallet)
whose attributes match all `--attribute` filters. The agent lists the
keyring's items — after asking you, since this command then sees their
labels and attributes — and reads the chosen items' secrets itself: this
command never holds a value. The agent imports only items of that listing,
for the same process, within 10 minutes. The entry name comes from the attribute named
by `--name-from`, or from the item label. The import dialog shows each entry
next to the item it comes from (label and attributes), and the agent reads
an item only if it is still what the dialog showed. A locked item stops the
import: unlock the keyring first. Batches and `--dry-run` work as for `import
dotenv`; a dry run reads no secret. See
[installation.md](installation.md#migrating-existing-secrets) for a safe
migration procedure; the manager's **Import & backup** page does the same
with a window to choose the items.

Not available in builds without the default `secret-service` feature.

## `rusthorse audit`

```
rusthorse audit [-n LINES] [--json]
```

Prints the last records of the audit log (default 20). `--json` prints the
raw JSON Lines. Records contain the time, action, outcome, entry names,
requester chain and, for `run`, the command line and directory — never values.
A `run` record's `detail` names the variables the dialog listed under
**Destinations** and in its routing warning, shortened the same way. A `lock`
record's outcome says why: `requested`, `idle_timeout`, `suspend` or
`screen_locked` (its `detail` naming the source, e.g. `logind` or
`org.cinnamon.ScreenSaver`).
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
or incompatible is an error), whether the vault locks when the computer
suspends and when the screen locks (a warning when nothing watches either:
the idle timer still locks it), the systemd service is enabled, zenity is
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

## `rusthorse guide`

```
rusthorse guide ai
```

Prints a guide in Markdown on standard output; it needs no agent. `ai` is
written for AI agents: the rules they follow (never ask for, print or write
a value; no `reveal`; stop after a denial), how to find entries and read
their metadata, how to use `run`, the exit statuses and what to do about
each, and how to store secrets without seeing them. It is built into the
binary, so it describes the version that prints it; a test checks that every
command and option it names exists. Point an agent to it from its
instructions file ([ai-agents.md](ai-agents.md#setting-up-an-agent)). A
reader that stops early (`rusthorse guide ai | head`) is not an error.

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
