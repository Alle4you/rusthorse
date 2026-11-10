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
| `--config PATH` (`agent`) | `RUSTHORSE_AGENT_CONFIG` | `$XDG_CONFIG_HOME/rusthorse/agent.toml` | The agent's [settings file](#settings) |

`rusthorse audit` reads `RUSTHORSE_AUDIT_LOG` (or the default location).

## Exit statuses

| Status | Meaning |
|---|---|
| `0` | Success. |
| `1` | Error (agent not running, entry not found, invalid input, …). |
| `2` | Invalid command line. |
| `4` | You denied the request, cancelled a dialog, or a dialog timed out. |
| `124` | The outcome is unknown: the request was sent but no usable answer came back, or the agent could not confirm that it took effect (it could not determine the result of a command it had started, or could not sync a change to disk). For `run`, the command may or may not have run; for a change (`add`, `edit`, `remove`, `import`, `passwd`, `backup`), check with `rusthorse list` or `show` before repeating it. Commands that change no file and start no command (listings, `show`, `status`, `reveal`, `unlock`, `lock`, `grants`, `grants revoke`) exit with 1 instead. |
| `125` | `run` only: Rusthorse failed or the request was denied; the command did not run. With `--broker`, also when a grant could not be served (an invalid destination or limit included): there is no fallback to the entry's value. |
| other | `run` only: the command's own exit status (`128 + N` if killed by signal `N`; 141, without a message, when `rusthorse run` could not write the command's output — see [`run`](#rusthorse-run)). |

Messages go to standard error; data (listings, JSON, revealed values) goes to
standard output. For `run`, a message that starts with `rusthorse:` comes with
`124` or `125` and says what went wrong — except a note that starts with
`rusthorse: note:`, which comes only after a command that ran, whose exit
status is then its own ([`--broker`](#through-the-credential-broker---broker)).
Text that the vault, the agent or a keyring supplies — names, fields,
paths, messages — is shown with control and invisible characters escaped
(`\u{…}`), so that a title another program wrote cannot rewrite your
terminal; `--json` and `reveal` give the values as they are, and `open`
hands the browser the URL as stored.

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
rusthorse agent [--vault PATH] [--audit-log PATH] [--config PATH]
                [--idle-timeout DURATION] [--remember DURATION]
                [--dialog-timeout DURATION]
                [--no-lock-on-suspend] [--no-lock-on-screen-lock]
```

| Option | Default | Meaning |
|---|---|---|
| `--config` | `$XDG_CONFIG_HOME/rusthorse/agent.toml` | The settings file (also `RUSTHORSE_AGENT_CONFIG`); see [Settings](#settings). |
| `--idle-timeout` | `15m` | Lock after this much inactivity: `0` (never), or 1s to 24h. |
| `--remember` | `0` (off) | Offer "Allow for DURATION" in `run` dialogs: `0`, or 1s to 8h. Off by default; read [ADR 0005](adr/0005-remembered-approvals-opt-in.md) before enabling it. |
| `--dialog-timeout` | `2m` | Unanswered dialogs are denied (or cancelled) after this long: 15s to 5m. |
| `--no-lock-on-suspend` | off | Do not lock when the computer is about to sleep. |
| `--no-lock-on-screen-lock` | off | Do not lock when the session is locked or its screensaver starts. |

Durations are a number followed by `s`, `m` or `h`, or `0`. A value outside
these bounds stops the agent's start (earlier builds accepted any).

### Settings

The last five options are the agent's settings
([ADR 0007, section 3](adr/0007-visual-manager.md#3-persistent-agent-configuration-m2)).
Each comes from its default, from the settings file, or from an explicit
flag, which wins over the file. The file is TOML with these keys, each
optional; durations are written as the flags take them:

```toml
idle_timeout = "30m"
remember = "0"
dialog_timeout = "1m"
lock_on_suspend = true
lock_on_screen_lock = true
```

The agent reads it when it starts. A missing file means the defaults. A file
it cannot accept stops its start, saying which file, key and values are
allowed: not a regular file, not yours, writable by its group or by others
(the agent cannot tell whether a group is yours alone; with a umask of `002`,
make a file you wrote by hand private with `chmod 600`, as the error says),
under a directory someone else could change (another user's, or one its
group or others can write, without the sticky bit: they could remove or
replace the file) or through another user's link — the path is followed
link by link, and the file read must be the one checked — larger than
64 KiB, an unknown key, a wrong type, or a
value out of bounds. The agent does not fall back to the defaults, which may
protect less than what you set. It cannot tell a missing file from a removed
one, so it saves the file only under directories nobody else can change; if
`~/.config` is writable by its group, the manager's Apply says so and asks
you to `chmod go-w` it.

The manager's **Settings** page changes them while the agent runs: the agent
asks for the master password if the vault is locked, shows each old and new
value in its own dialog, and then saves the file — rewriting it whole,
without comments, mode `0600`; a link at its path is replaced by the file;
missing directories are created private, existing ones are left as they
are — applies the
change at once and forgets remembered approvals. A setting a flag fixes
cannot be changed there: remove the flag from the service and restart the
agent. Edits by hand take effect at the agent's next start. Any program of
yours can edit the file and restart the agent, so the dialog guards the
changes made through the agent, not the file
([threat model L1](threat-model.md#l1--malware-running-as-you-can-defeat-rusthorse)).

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
lock itself, how many approvals are remembered, the agent's settings — the
file, then each setting in effect and where it comes from (`default`,
`settings file`, `set by --remember`) — which program shows its
dialogs (the path of `rusthorse-dialog`, `zenity`, or `none:` and why), what
else locks the vault, and the program file the agent runs (with a note if it
was replaced since the agent started). From an agent that reports them, it
also shows the credential broker's program (the path of `rusthorse-broker`, or
`none:` and why it cannot be used) and the number of grants the agent reports
(see [`run --broker`](#through-the-credential-broker---broker)), which
includes starting, active and exhausted grants, but excludes revoked ones. The
list can still retain a revoked grant whose command runs:
[`rusthorse grants`](#rusthorse-grants) lists each one with its state. For
example:

```
broker:     /usr/bin/rusthorse-broker
grants:     1 (`rusthorse grants` shows their state)
locks on:   suspend: logind (locks before the computer sleeps)
            screen lock: logind (session lock signals of this user), org.cinnamon.ScreenSaver
```

`not watched` and the reason appear when no source of an event is watched,
each one being unavailable (no system bus, no session bus, no logind or no
screensaver on the bus, turned off, a build without the `session-lock`
feature); a source that is unavailable beside one that is watched is not
shown. A watcher whose bus goes away connects again every few seconds, and on
connecting locks if the session is locked or a screensaver on already, or if
logind or a screensaver does not answer that in time. When logind would not
give an inhibitor, the suspend line says so: the lock may then come only after
the computer wakes.

## `rusthorse unlock` / `rusthorse lock`

`unlock` makes the agent ask for the master password now (it also asks
whenever a request needs the vault). The dialog has a text field: type the
password there and click **Unlock**. You get three attempts; clicking Unlock
with the field empty uses one of them — it asks again, while one is left,
without counting as a wrong password — and if
nothing is ever typed the unlock counts as cancelled. Wrong passwords are
recorded in the audit log; after three attempts the request fails. `lock`
discards the decrypted vault and all remembered approvals immediately; so do
a suspend and a screen lock (see [`rusthorse agent`](#rusthorse-agent)).

## `rusthorse list`

```
rusthorse list [--tag TAG] [--kind KIND] [--search TEXT] [--json]
rusthorse ls …
```

`-s` is short for `--search`.

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

Shows one entry's metadata: name, UUID (`id:`), group, kind, username, URL,
host, port, tags, whether it has a value and notes, the names of protected and
other fields, and the last modification time.

An entry carries nothing for the credential broker: where a grant may send
the key is named in each [`run --broker`](#through-the-credential-broker---broker).
A `Rusthorse.Broker` field, where an earlier, unreleased version of the broker
stored a profile, is an ordinary custom field: listed by name under `fields:`
(`other_fields` in `--json`) like any other, its value never shown, read or
interpreted, and kept as it is.

## Entry kinds

An entry can say what it is for, with `--kind` in `add` and `edit`:

| `--kind` | For | `--url` is |
|---|---|---|
| `api-key` | A key or token for an API | The API's endpoint, e.g. `https://api.openai.com/v1` |
| `login` | A sign-in to a website or web console | The sign-in page |
| `server` | A server reached by host and port (SSH, a database, …) | — |
| `device` | A device such as a router or a camera | Its admin page |
| `ssh-key` | A private key for SSH, held as the entry's value; `--username`, `--host` and `--port` say where it logs in | — |
| `other` | No particular kind (the default) | Any access link |

The kind names the fields and decides which ones the manager's form offers
(it never hides a field that has a value); `list --kind` filters by it. It
is stored in the KDBX field `Kind`, which KeePassXC shows as an attribute.
It grants and restricts nothing. See
[ADR 0008](adr/0008-entry-kinds.md).

The kind is a label that you set: nothing checks it against the entry's
value. `ssh-key` tells an AI agent that the value is a private key and not a
password, so that it uses the right recipe of its guide; an entry of another
kind may hold a key too, and the agent is told to ask when it cannot tell.

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

Short forms: `-u` for `--username` and `-t` for `--tag` (`edit` has `-u`
too).

`--replace` overwrites an existing entry with the same name (the old version
stays in the entry's history) and, like any change to an entry, ends its
grants of the credential broker. `--group` places a new entry in a group,
creating it if needed (`Work/Servers`). A path into the recycle bin that
another KeePass client keeps is refused, before the value is asked for: an
entry there would be hidden from every listing, as if deleted.

Examples — an API key with its endpoint, a router with its access details,
and a private key for SSH to that router, read from its file (a key has
several lines, and the dialog's field takes one):

```sh
rusthorse add OPENAI_API_KEY --kind api-key --url https://api.openai.com/v1 --tag ai
rusthorse add core-router --kind device --username admin --url https://10.0.0.1/ \
    --host 10.0.0.1 --port 443 --tag network --notes "Rack 2, console on J3"
rusthorse add core-router-key --kind ssh-key --username admin --host 10.0.0.1 \
    --group Network/core-router --stdin < ~/.ssh/core-router
```

## `rusthorse edit`

```
rusthorse edit NAME [--kind KIND] [--username USER] [--url URL] [--host HOST]
                    [--port PORT] [--notes TEXT] [--rename NEW] [--group PATH]
                    [--clear FIELD]... [--add-tag TAG]... [--remove-tag TAG]...
                    [--value | --stdin | --generate [--length N] [--alphabet KIND]]
```

Changes an entry. Requires approval; the dialog lists every change. `--value`
makes the agent ask you for a new value in a dialog; `--stdin` reads it from
standard input; `--generate` replaces it with a new random value (to rotate a
credential: generate, then update it at the provider with `rusthorse run`). `--clear` removes a field: `username`, `url`, `host`, `port`,
`notes` or `kind`; `--kind other` also removes the kind. The previous state
is kept in the entry's KeePass history. Any change to an entry ends its
grants of the credential broker; when it ends any, the dialog says how
many.

`--group` moves the entry to the group at `PATH` (`Work/Servers`), creating
the group if needed; `/` (or an empty path) moves it to the top level. Spaces
around each part of the path and empty parts are dropped, and each part
follows the rules for names. The agent checks the path before it asks for
approval: an invalid path, one into the recycle bin, or one through two
groups of the same name side by side (another KeePass client allows them;
which one is meant cannot be told) is refused without an approval dialog.
The dialog shows the destination as a path from the top, and which group
that is, since names alone can look alike:

- `/Work/Servers (existing group 8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12)` — an
  existing group, by its whole UUID (names can look alike, and another
  program can give two groups UUIDs that start alike);
- `/Work/Servers (creates Servers in /Work, group 1a2b3c4d-6e7f-4a8b-9c0d-e1f2a3b4c5d6)` or
  `/Work/Servers (creates Work/Servers at the top level)` — what is created,
  and where;
- `/ (the top level)`.

A move to the group the entry is already in — that very group, whatever its
name looks like — is left out of the request (the dialog does not show it);
alone, it is refused with "nothing to change". The audit log records where
the entry moved from and to. The entry records its previous group and when
it moved (the KDBX fields `PreviousParentGroup` and `LocationChanged`), and
its previous version goes to its history, as with every edit.

## `rusthorse remove`

```
rusthorse remove NAME
rusthorse rm NAME
```

Deletes an entry permanently. Requires approval. Until the next save, the
previous file is still available as `vault.kdbx.bak`.

## `rusthorse run`

```
rusthorse run [--no-redact] [--stdin] [--url VAR=NAME]...
              [--broker VAR=NAME@URL]... [--broker-requests N]
              [--broker-lifetime MINUTES] [--broker-locks end|continue]
              [SECRET]... -- COMMAND [ARG]...
```

Runs `COMMAND` with secrets in its environment. Each `SECRET` is either
`NAME` (the variable is named like the entry, which must then be a valid
variable name) or `VAR=NAME`. At least one `SECRET` or `--broker` is needed
(without either, a usage error, exit status 2). `--broker` gives the command
a temporary token instead of an API key: see
[below](#through-the-credential-broker---broker).

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
  `DOCKER_HOST`, `VAULT_ADDR`, …), `AWS_ENDPOINT_URL_<SERVICE>`,
  `CARGO_REGISTRIES_<NAME>_INDEX`, `UV_INDEX`, `UV_DEFAULT_INDEX` and libpq's
  `PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGSERVICE` and `PGSERVICEFILE`. If a name
  appears twice, the last value — the one
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
contains a space (a certificate variable's paths may). Shown:

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
  variables, and absolute paths, as they are; outside certificate variables,
  not a path with `..`.

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
to those, not to the URL's host — and also `servicefile`, `socket`,
`unix_socket`, `server`, `addr`, `address` and `proxy`) or has a parameter
name with characters other than letters, digits, `_`, `-` and `.`. Programs
read such values differently (a parser that takes `\` for `/` connects to the
host before the `@`, while the text after it names another), so a host drawn
from them could be the wrong one, and copying them could disclose a
credential. The audit log gets the same shortened text; the variables reach
the command unchanged.

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
of a secret value (4 bytes or longer) in them is replaced with
`[REDACTED:<entry>]` before the agent sends the output back to
`rusthorse run`, which prints it. The command's standard input is
`/dev/null`, unless `--stdin` makes `rusthorse run` forward yours. Programs
therefore see pipes rather than a terminal. With `--no-redact`, the command
gets the caller's descriptors directly (including stdin).

If `rusthorse run` cannot write the command's output — it was closed early
(for example `rusthorse run … | head`) or the disk is full — it closes its
connection, which makes the agent stop the command, and exits at once with
status 141, like a program killed by `SIGPIPE`, without a message. The agent
stops the command as said below (`SIGTERM`, then `SIGKILL` 3 seconds later),
so it may still be running when `rusthorse run` exits, and it may have done
some or all of its work: 141 does not tell what it did. This is the relay of
redacted output; with `--no-redact` the command writes to your output itself,
and its own exit status comes back. With `--stdin`, input is read only once
the command has started, so a denied request never consumes it.

When the command exits, anything it left running in its process group (for
example `sleep 30 &`) is terminated; if `rusthorse run` is interrupted before
that, the whole group is terminated too — `SIGTERM`, then `SIGKILL` 3 seconds
later. The agent notices an interruption only once the command has started:
interrupted while its dialog is open, `rusthorse run` leaves the dialog there,
and if you then allow it the command starts, with the secrets, and is
terminated in the same way only then.

If remembered approvals are on (`--remember`, the `remember` setting in
`agent.toml`, or the manager's Settings page), the dialog also offers "Allow
for …", which lets **identical** requests (same vault state, entries, command
line, program, directory, input and output handling, and the complete
environment) run without asking for that long. It does not cover what the
command reads, so use it only for commands
whose input you control. It never applies to a run with `--broker`.

Examples:

```sh
rusthorse run OPENAI_API_KEY -- python app.py
rusthorse run OPENAI_API_KEY --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
rusthorse run GH_TOKEN=github-token -- gh pr create --fill
rusthorse run PGPASSWORD=prod-db -- psql -h db.lan -U app app
rusthorse run TOKEN=cloudflare -- sh -c 'curl -sH "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'
```

Exit status: the command's, `125` if it did not run, or `124` if Rusthorse cannot tell.

### Through the credential broker: `--broker`

`--broker VAR=NAME@URL` uses entry `NAME` through the credential broker
([ADR 0013](adr/0013-credential-broker.md)): the command gets, in `VAR`, a
temporary **token** of a grant — never the entry's value — and a broker
process of the agent's puts the real key in its place in the requests the
command sends it, which it forwards to `URL`'s origin and nowhere else.
`--broker NAME@URL` names the variable like the entry. `VAR` ends at the
first `=` and `URL` starts after the last `@`, so in `VAR=NAME@URL` the
entry's name may hold `=`, `@` or a group path
(`--broker KEY=AI/anthropic@https://api.anthropic.com`). Each `--broker` is
one grant, with its own destination, token and local address; `--broker` can
be given several times, and combined with `SECRET`s for other entries, which
the command gets by value as always.

`URL` is `https://`, a host name in lowercase (letters, digits, `-` and `.`;
an international name in its `xn--` form; not an IP address), an optional
port (1 to 65535) and an optional base path: `/` and segments of letters,
digits, `.`, `_`, `~` and `-`, none made only of dots, without a trailing
`/` (`https://HOST/` alone has none). No user information, query or
fragment; at most 1000 characters. There is no default destination, and the
entry's own URL is never used for it: the run says where the key may go, and
you approve it.

You approve the URL's **origin** — scheme, host and port. The broker may send
the key to any path there: the base path only sets up the program's base URL
(`--url`, below) and limits nothing. Nothing narrows the approval further:
at that origin, the command can do through the grant whatever the key
allows.

| Option | Default | Meaning |
|---|---|---|
| `--broker-requests N` | no limit | The most requests each grant of the run admits: 1 to 1000000 |
| `--broker-lifetime MINUTES` | `720` (12 hours) | The longest each grant of the run lasts: 1 to 1440 |
| `--broker-locks end\|continue` | `continue` | Whether the screen locking, a suspend and the idle timeout end the run's grants (`rusthorse lock` always does) |

They apply to every grant of the run, each counted on its own. They need
`--broker`: without it they are a usage error (exit status 2), as are an
unknown policy and a number that is not one; a number out of range is
refused before anything is sent (exit status 125).

`--url URLVAR=NAME` for an entry given with `--broker` puts the broker's
address in `URLVAR`, instead of the entry's own URL:
`http://127.0.0.1:PORT` followed by the destination's base path
(`http://127.0.0.1:PORT/v1` for `…@https://api.openai.com/v1`). Give it for
the variable the program reads its base URL from (`OPENAI_BASE_URL`,
`ANTHROPIC_BASE_URL`):
without it, the program sends the token wherever its environment or its
defaults say, usually to the API's own address, where the token is useless
but which it reaches over the network. An entry given with `--broker` takes
at most one `--url`. For any other entry, `--url` means what it always
means. What the environment of `rusthorse run` has in the variable of a
token or of the broker's address is not sent: the agent sets them.

Before anything is sent — exit status 125, nothing asked, nothing run —
`rusthorse run` refuses a `--broker` without `@URL`, or whose URL breaks the
rules above; a limit out of range; a variable that is not a valid name, that
is set twice (by a `SECRET`, a `--broker` or a `--url`), or that changes how
programs start (`LD_*` and the risky variables above) for a token or an
address; `NO_PROXY`, in any case, for a token or the broker's address, since
the agent adds `127.0.0.1` to it; an entry given to `--broker` twice; an
entry given both with `--broker` and as a `SECRET` (by the name written: the
agent compares UUIDs); and a second `--url` for an entry given with
`--broker`. A `--url` that names a brokered entry by another name
(`AI/anthropic` and `anthropic`, or its UUID) is refused once that entry has
been read: write the same name in both. A run with `--broker` is sent as a
request of its own, `broker_run_v2` ([protocol](protocol.md)), which an agent
of an older protocol refuses whole, instead of running the command without
the destinations and limits you approve; a refused request is never sent
again as another kind of request.

The agent checks, before its dialog, each destination and the limits again,
that each brokered entry has a value the broker can send (8 to 4096 visible
ASCII characters, without spaces), that it would then serve no more than 16
grants at once, and that the broker's program is usable; and it adds
`127.0.0.1` to `NO_PROXY` and `no_proxy` in the command's environment. For
each grant the dialog shows which variables get its token and the broker's
address (`Grant: VAR ← a token for ENTRY; URLVAR ← the broker's address`),
the approved origin, the base path apart from it, marked `(not a limit)`,
when the grant ends and its requests (its request limit, or that there is
none, and at most 16 at a time). It says that the command gets a temporary
token, not the key, and that Rusthorse puts the key in its place in requests
to the approved origin, at any path there; it lists the variables that get
real values in a mixed run; and it warns that the command can spend credit,
that a request limit is not a spending limit and that request bodies are not
inspected. With zenity, a run asking for two or more grants may
exceed the estimated dialog height and be refused before a dialog is shown.
`rusthorse-dialog` scrolls long approvals; the character limits still apply
and nothing is truncated. A revoked grant can still occupy one of the 16
available places while its command runs. Revoking it may therefore not make
room for a new run: check `rusthorse grants` and wait for those commands to
finish.

The program presents the token where it would present the key: as it is,
in a request header, with whatever prefix the API reads
(`Authorization: Bearer TOKEN`, `Authorization: Token TOKEN`,
`x-api-key: TOKEN`, `x-goog-api-key: TOKEN`). The broker replaces each exact
copy of the grant's token in the header values it forwards with the key, in
one pass, and changes nothing else. It refuses with its own `401`, before
anything is sent, a request in which no forwarded header value holds the
token; one with the token in the method, the request target, a header's
name or a header the broker drops or sets itself (`Host`, …); one with any
other token-shaped string (`rh_` and 64 hexadecimal digits, in any case,
anywhere in the request's head), which includes a copy of the token whose
case was changed; one with the key itself; and one whose head, with the key in
the token's place, would exceed 32 KiB. A program that encodes the
token or derives its credential from it, and an API that signs its requests
with the key or takes it in the URL or the body, cannot be used through the
broker: `run` serves them, with the value.

Within the broker's framing rules (HTTP/1.1; no upgrade, `Origin` header
or `Transfer-Encoding` on a request), everything else goes to the approved
origin as the program sent it: any path and query, any method but
`CONNECT`, `TRACE` and `OPTIONS`, a body on any method (at most 16 MiB, with
one `Content-Length`), and its request headers, except the hop-by-hop ones
and `Host`, `Content-Length` and `Accept-Encoding`, which the broker sets — a
credential of the program's own in another header included. The broker
connects only to that origin, over TLS verified against the system's
certificate authorities, to public addresses only; it follows no redirect,
refuses a compressed response and keeps no cookies. Response headers come
back except the hop-by-hop ones (with those the response's `Connection`
names), `Content-Length`, `Transfer-Encoding` and any whose name or value
carries the key or a token, and literal copies of
the key in a response body are redacted. The full rules are in
[ADR 0013](adr/0013-credential-broker.md#the-broker-without-profiles-or-presets).

There is no fallback: if a grant cannot be served before the command
starts, the run fails with 125 and nothing ran; the command never gets the
value instead. Once the command has started, `rusthorse run` exits with its
status as without the broker, or 124 when that cannot be told; what became
of each request is in the [audit log](#rusthorse-audit). The run's grants
end when the command ends, and before on `rusthorse lock`,
[`rusthorse grants revoke`](#rusthorse-grants), a change to the entry, the
end of their lifetime, and the automatic locks with `--broker-locks end`.

When a grant's destination answered requests with `401 Unauthorized`,
`rusthorse run` says so on standard error once the command has ended, after
everything the command wrote: one note per grant, with or without
`--no-redact`, whatever the command's exit status, which stays its own.

```
rusthorse: note: the command ran, and the broker accepted its token, but the approved origin https://api.anthropic.com answered 401 Unauthorized to 1 request: it did not accept the key stored in anthropic. If that key is wrong, revoked, or not of the kind the destination expects, replace it: rusthorse edit anthropic --value
```

A `401` means that the destination did not accept the credential the broker
sent from the entry: the key may be wrong, revoked or expired, or not of the
kind the destination expects (a subscription's OAuth token where it expects
an API key, say), or the program may have presented it in a header or with
a prefix the destination does not read it from. It is the same for every
destination: the note comes from the status alone, never from the body.
Only requests the broker forwarded count — its own `401`, for a request
without the grant's token, never reaches the destination — and only that
status: a destination that answers a bad key with another one is not
detected. `rusthorse edit NAME --value` asks you for the new key in a dialog
(it ends the entry's other grants). The note is printed by `rusthorse run` from
the agent's answer, so a command can print a look-alike; the
[audit log](#rusthorse-audit) has each request's status. While the command
runs, [`rusthorse grants`](#rusthorse-grants) shows the same count.

The broker's own answers — a missing or misplaced token, a request it does
not forward, a grant that has ended — are short JSON errors of type
`rusthorse_broker`, whose message starts with `rusthorse-broker:`; an error
in the destination's own form comes from the destination, passed on as it
came. Two exceptions: the broker's HTTP parser answers a malformed request
itself, with `400` or `431` and an empty body — which a destination can
send too — and a connection can close with no answer at all. A grant that has ended answers `403`, with a message
that says to run the command again with `rusthorse run`. A program that
shows only the message still says who answered: Claude Code showed the
broker's message after its own `Please run /login · API Error: 403`, and its
`/login` does not apply here.

With redaction (the default), the tokens are redacted from the output like
the values, labelled with their variable (`[REDACTED:<VAR>]`). `--no-redact`
is allowed, and the dialog warns about it: the
output is then not filtered, and whoever reads a token can use its grant
until it ends. It is what an interactive program such as Claude Code needs,
since only without redaction does the command get the terminal.

Examples:

```sh
rusthorse run --broker OPENAI_API_KEY@https://api.openai.com/v1 --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
rusthorse run PGPASSWORD=prod-db --broker OPENAI_API_KEY@https://api.openai.com/v1 --url OPENAI_BASE_URL=OPENAI_API_KEY -- python etl.py
rusthorse run --broker DEEPSEEK_API_KEY=deepseek@https://api.deepseek.com --broker-requests 50 \
    --broker-lifetime 60 --broker-locks end --url DEEPSEEK_BASE_URL=deepseek -- python app.py
env -u ANTHROPIC_API_KEY CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 rusthorse run --no-redact \
    --broker ANTHROPIC_AUTH_TOKEN=anthropic@https://api.anthropic.com --url ANTHROPIC_BASE_URL=anthropic -- claude
```

The last one runs Claude Code through the broker, as Claude Code's
documentation describes it. The broker was tried by hand on 2026-11-04 with
`curl`, the Anthropic Python SDK 2.4.0 and Claude Code 2.1.318, in print mode
(`claude -p`) and interactively with this recipe; no client version is claimed
supported, and the record of those trials is in the
[review history](threat-model.md#11-review-history). `ANTHROPIC_AUTH_TOKEN`
makes Claude Code send the token as `Authorization: Bearer`;
`env -u ANTHROPIC_API_KEY` keeps a key your environment may hold out of the
command (Claude Code may send it instead of the token, which the broker
refuses, or beside it, in `x-api-key`, which the broker forwards to the
approved origin as it came unless it is the entry's own key); and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, set in the environment that
`rusthorse run` passes on, turns off its non-essential requests, some of
which would go straight to `api.anthropic.com`. An `env` block in Claude
Code's settings files overrides the variables `run` sets, and an
`apiKeyHelper` there can give it another key: check them first ([guide for
AI agents](#rusthorse-guide)).

## `rusthorse grants`

```
rusthorse grants [--json]
rusthorse grants revoke ID
rusthorse grants revoke --all
```

Lists the grants of the credential broker
([`run --broker`](#through-the-credential-broker---broker)), never a token:
one line each, with its ID (`g` and 16 hexadecimal digits, also in the audit
log), entry, approved origin, base path (`none` when the run named none; it
sets up the program's base URL and is not a limit), state, when it started
and how long its lifetime has left, the requests admitted of those allowed,
the requests in flight, whether the automatic locks end it, the requester
and the command. The state is
`starting` (its run is being prepared: nothing is admitted yet); `active`;
`exhausted` (its request limit is reached: no new request is admitted, those
admitted finish); or `revoked` (it has ended; its broker normally answers
`403` until the command ends, and it stays in the list until then unless its
broker exits sooner). What the agent reports is shown with control and
invisible characters escaped (`\u{…}`), so that a command line or a process
name cannot rewrite the terminal. `--json` prints the agent's list
([protocol](protocol.md#grantinfo)), with the fields this version of
`rusthorse` knows: the approved origin is `destination`, and the base path,
when there is one, `base_path`.

When a grant's destination has answered requests with `401 Unauthorized`, a
note under the table, on standard error, says so, and `--json` has the count
in `unauthorized`:

```
rusthorse: note: grant g3f9a0c1d2e4b5a67: the approved origin https://api.anthropic.com answered 401 Unauthorized to 2 requests: it did not accept the key stored in AI/anthropic (8d2f6c1e). If that key is wrong, revoked, or not of the kind the destination expects, replace the entry's value (rusthorse edit NAME --value)
```

A grant is listed only until its command ends: after a short command, the
note of [`rusthorse run`](#through-the-credential-broker---broker) and the
audit log say it.

```
ID                 ENTRY                    APPROVED ORIGIN            BASE PATH (NOT A LIMIT)  STATE   STARTED                    ENDS IN  REQUESTS      IN FLIGHT  AUTOMATIC LOCKS  REQUESTER                     COMMAND
g3f9a0c1d2e4b5a67  AI/anthropic (8d2f6c1e)  https://api.anthropic.com  none                     active  2026-11-02T18:00:00-03:00  11h59m   3 (no limit)  1          continue         rusthorse[4300] ← bash[4242]  claude
```

`grants revoke ID` ends one grant, and `grants revoke --all` every grant
(one or the other, not both): new requests are refused at once and open ones
are closed — a stream in progress ends — while a request already sent to its
destination may still take effect. Neither needs an approval, like `lock`.
An ID not of the form above is refused before anything is sent; one the agent
does not know is an error.

Exit status: 0, or 1 on an error.

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

`-l` and `-a` are short for `--length` and `--alphabet`.

Prints a random value; nothing is stored and the agent is not involved. To
store a generated value without seeing it, use `rusthorse add NAME --generate`.

## `rusthorse import dotenv`

```
rusthorse import dotenv FILE [--prefix PREFIX] [--tag TAG]... [--replace] [--dry-run]
```

`-t` is short for `--tag`.

Imports `NAME=value` lines in a small `.env` dialect, chosen so that
python-dotenv and Node's dotenv read every file Rusthorse accepts as it does
(Docker's `--env-file` keeps quotes in the value, and shells take no spaces
around `=`): lines end with LF or CRLF; the only blanks are spaces and
tabs; a line is blank, a `#` comment, or `NAME=value` with an optional
`export` and blanks around `=`, `NAME` made of ASCII letters, digits, `_`,
`.` and `-`; a value is on one line, either in single or double quotes with
neither that quote nor a backslash inside and nothing after them but blanks
and a `#` comment, or unquoted — not starting with a back quote or a `#` —
where a `#` after a blank starts a comment and the value itself holds no `#`;
no value holds `${…}` (python-dotenv replaces it by another variable's value,
Node's dotenv does not), no name is set twice, and none is `__proto__` (Node's
dotenv drops it). Any other file is refused as a whole, naming the line, never
a value (a name set twice is named, with the line that set it first, and a
character that readers do not read alike by its code or what it is): nothing
in it is skipped, and the whole file is checked before any
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

`-a` is short for `--attribute` and `-t` for `--tag`.

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

`--lines` is the long form of `-n`.

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

For the credential broker ([`run --broker`](#through-the-credential-broker---broker)),
the `run` record of a run with `--broker` names the grants it creates (`grants:`
each one's ID, entry and approved origin, and its base path when there is
one: `g3f9a0c1d2e4b5a67 for openai (2a8f40e5) to https://api.openai.com (base
path /v1, not a limit)`); a `grant` record is `created` or
`ended`, with the grant's ID and, at its end, the reason (`reason:`
`command_ended`, `locked`, `revoked`, `entry_changed`, `expired`, …) and
what became of its requests (`requests:` admitted, of which finished and
unknown, and refused before admission); a `broker_request` record is
`admitted`, before the request is forwarded, then `completed`,
`not_forwarded`, `client_closed`, `revoked` or `unknown`, with the grant, the
request's number (`#1`), the label of its method (`GET`, `HEAD`, `POST`,
`PUT`, `PATCH`, `DELETE`, or `OTHER` for any other method) and, at its end,
the destination's status and the bytes sent and received. Never the raw
method, a path, a query, a token, a key, a header or a body: which path at
the approved origin a request went to is not recorded. For example:

```
2026-11-02T18:00:05-03:00  broker_request admitted             grant g3f9a0c1d2e4b5a67 #1 POST  by rusthorse[4300] ← bash[4242]
2026-11-02T18:00:09-03:00  broker_request completed            grant g3f9a0c1d2e4b5a67 #1 POST status 200 (1450 bytes sent, 38211 received)  by rusthorse[4300] ← bash[4242]
```

Any program of yours can write to the log (threat model L13): control and
invisible characters in a record are shown escaped (`\u{…}`), so that a
record cannot rewrite the terminal or look like two. `--json` prints the
records as they are. The manager's **History** page shows the same records,
from the file the agent names ([manager guide](manager.md#history)).

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
vault's format and permissions, whether the audit log is readable by others (a
warning), and the socket directory's permissions. Of the rest, these are
warnings: a lock that is watched but degraded, an agent that does not report
its locks, a service that is not enabled, an unknown session type, a system
without Yama, a vault that is not KDBX 4. These are errors: an agent that
cannot be reached, speaks another protocol version or reports no vault file,
`ptrace_scope` 0, a vault file that its group or others can access or that
cannot be read, a socket directory that its group or others can access. Exits
with status 1 if anything failed.

Two checks concern the credential broker
([`run --broker`](#through-the-credential-broker---broker)); without what
they check, no grant can be served, and they say so:

- its program, `rusthorse-broker`: the one the agent reports using, run by
  its path with `--check`, which opens nothing and reports its version and
  broker protocol, under the same supervision and 5-second limit as the
  dialog program; both must be this `rusthorse`'s. When the agent reports
  that it cannot use the program, its reason is the error, unless nothing at
  all is next to the agent's program file: the program is then not
  installed. From an agent that does not report it, the program next to the
  agent's program file is checked as the agent checks it, and run (next to
  this `rusthorse` when no agent answers); from one that does not report its
  own program file either, the check can only warn that it cannot tell which
  broker program the agent uses. Not installed is a warning, since
  everything else works without it; unusable, of another version or not
  running is an error, and so is a broker built for tests (its `--check`
  reports `test_upstream`), whatever its version;
- the file of certificate authorities the broker trusts: the first of
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`
  and `/etc/ssl/ca-bundle.pem` that exists, which must be a regular file
  owned by root, in directories owned by root, none of them writable by its
  group or by others — checked as a broker checks it. Missing or unsafe is an
  error, or a warning when the broker's program is not installed either.
  `doctor` does not read the certificates in it: a broker does, when a grant
  starts, and a file without a usable certificate authority makes that run
  fail with 125.

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
their metadata, how to use `run` (and `run --broker` for an HTTP API that
takes its key in a header, Claude Code included), the exit statuses and what to do about
each, and how to store secrets without seeing them. It is built into the
binary, so it describes the version that prints it. A test parses every
command line it shows with the CLI's own parser — complete, apart from a few
listed mentions of a command in the prose — and checks the exit status
tables row by row. Point an agent to it from its
instructions file ([ai-agents.md](ai-agents.md#setting-up-an-agent)). A
reader that stops early (`rusthorse guide ai | head`) is not an error.

## Upgrades

Commands that talk to the agent first check that it speaks the same protocol
version (for `run`, a missing or incompatible agent exits with 125: the
command did not run). After upgrading the binary, restart the agent
(`systemctl --user restart rusthorse-agent`); until then those commands stop
with an explanation instead of failing in confusing ways. A run with
`--broker` is a request that an agent of an older protocol refuses whole,
should one be met after that check (restarted in between): it never runs
the command without its grants, or with grants that ignore the destinations
and limits you approved. A profile that an earlier, unreleased version of the
broker stored in an entry (`Rusthorse.Broker`) stays there as an ordinary
field and is never used; nothing needs to be done about it.

## Separate visual manager

`rusthorse-manager` is an optional GTK client, not a `rusthorse` subcommand.
It uses the existing agent protocol and `RUSTHORSE_SOCKET` override. See
[manager.md](manager.md) for its first milestone and pending features. It
does not start the agent or replace the CLI's commands or exit statuses.
