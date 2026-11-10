# Agent protocol

This is the protocol between clients and the Rusthorse agent. The `rusthorse`
CLI is the reference client; this document is for anyone writing another one
(a GUI, an editor plugin, a browser bridge).

Protocol version: **10** (`PROTOCOL_VERSION` in
[`src/protocol.rs`](../src/protocol.rs)).

| Version | Changes |
|---|---|
| 1 | First design: descriptors passed for every `run`. Never released. |
| 2 | Data frames and per-channel credit for `run` with redaction (stdin credit granted when the command starts); `add.generate`, `change_password`, `backup`, `reveal.notes`, `status.audit_log`. |
| 3 | Every error other than `outcome_unknown` is definite: the vault file was not changed and no command was started (see [Errors](#errors)); a save that fails after replacing the file is `outcome_unknown`. `status.agent_executable`, `status.agent_executable_id`, `status.agent_executable_replaced`. Added later, optional: `status.dialogs`. |
| 4 | `reveal.purpose` (`show`, `copy`): what the client says it will do with a revealed value, named in the approval dialog and the audit log. Unreleased builds that reported protocol 3 had this field with another meaning for `copy` (one paste, then cleared); clients of protocol 4 refuse those agents. |
| 5 | The entry `kind` (see [Entry kinds](#entry-kinds)): in `NewEntry.fields`, `EntryInfo`, `EntryChanges.kind`, and `"kind"` in `EntryChanges.clear`. An agent of version 4 would silently drop it, so the version changed. |
| 6 | `create_vault`: the agent creates the vault and asks for its master password in its own dialogs. `already_exists` also means that the vault file exists. Imports read by the agent: `keyring_items`, `dotenv_names`, `import_from` (see [Imports read by the agent](#imports-read-by-the-agent)). |
| 7 | `EntryChanges.group` moves an entry to another group (see [EntryChanges](#entrychanges)). An agent of version 6 would silently drop it and report the edit done, so the version changed. |
| 8 | `broker_run`, `broker_edit`, `grants`, `revoke_grant`; optional entry profile and broker status fields. Separate request tags make a protocol-7 agent refuse broker operations whole even if the agent changes between the version check and the request. Added later, optional: `GrantInfo.unauthorized`, `exited.unauthorized`. |
| 9 | The broker without profiles or presets ([ADR 0013](adr/0013-credential-broker.md#the-broker-without-profiles-or-presets)): `broker_run_v2`, whose broker bindings each name their `destination` and whose `limits` set the grants' limits, with unknown fields refused. `broker_run` and `broker_edit` are gone (refused), and so are `EntryInfo.broker`, `EntryChanges.broker`, `"broker"` in `EntryChanges.clear` and `GrantInfo.preset`; `EntryChanges` refuses fields it does not know. `GrantInfo.destination` and `exited.unauthorized[].destination` mean the approved origin, no longer the profile's origin and base path; `GrantInfo.base_path` (optional) is new. A run through the broker is a new request rather than `broker_run` with more fields: a protocol-8 agent would accept that and ignore the destinations and the limits. |
| 10 | The agent's settings ([ADR 0007, section 3](adr/0007-visual-manager.md#3-persistent-agent-configuration-m2)): `configure` (see [Configure](#configure)) and `status.settings` (optional). For `configure`, every error other than `outcome_unknown` also means that the settings file was not replaced and no setting changed. |

Clients should send `status` first and refuse to continue when
`protocol_version` differs from theirs (the `rusthorse` CLI does). Versions
are not negotiated beyond that.

## Transport

- A Unix stream socket, by default `$XDG_RUNTIME_DIR/rusthorse/agent.sock`.
  The directory has mode `0700` and the socket `0600`.
- The agent reads the peer's credentials with `SO_PEERCRED` and silently
  closes connections from other users.
- **One request per connection.** The client connects, sends one request
  message and reads one response message, then closes the connection. During
  a `run` with redaction, data frames flow in both directions before the
  response (see [Framing](#framing)).

## Framing

There are two kinds of frame, told apart by the top bit of the length word:

```
message frame:  | 0 | length: 31 bits | body: `length` bytes of JSON         |
data frame:     | 1 | length: 31 bits | channel: 1 byte | data: length-1 bytes |
                  └── length word: u32, big-endian
```

- A **message** body is a UTF-8 JSON object, at most 4 MiB. Requests and
  responses are messages.
- A **data** frame carries part of a running command's input or output, at
  most 64 KiB of data, on one channel:

  | Channel | Direction | Meaning |
  |---|---|---|
  | `0` | client → agent | The command's stdin; an empty frame means end of input. Only allowed when the request set `forward_stdin`. |
  | `1` | agent → client | The command's (redacted) stdout. |
  | `2` | agent → client | The command's (redacted) stderr. |
  | `0x80` | agent → client | Credit for channel 0: a big-endian `u32` number of input bytes the agent has delivered to the command. |
  | `0x81` | client → agent | Credit for channel 1: a big-endian `u32` number of bytes the client has written out. |
  | `0x82` | client → agent | Credit for channel 2. |

  Data frames are only valid during a `run` with redaction, and never carry
  file descriptors.
- **Flow control.** Every channel has a 1 MiB window. The agent sends at most
  1 MiB on each output channel beyond what the client has acknowledged with
  credit frames, and the client grants credit as it writes data out. The
  client sends at most 1 MiB of input beyond what the agent has acknowledged;
  sending more cancels the request only when the input the agent holds for the
  command, not yet delivered, would pass 1 MiB (input delivered but not yet
  acknowledged does not count). The client starts with no stdin credit:
  the agent grants the whole window when the command starts, so input given
  to a request that is denied or fails is never read. Input waiting for the
  command is buffered within the window, so the agent keeps reading the
  connection; its stdin acknowledgements are written by a separate thread, so
  a client that does not read them cannot stop the agent from noticing closes
  and violations.
- A `run` request **without redaction** carries exactly three file
  descriptors — the client's stdin, stdout and stderr, in that order — as
  `SCM_RIGHTS` ancillary data on the **first byte** of the frame (send the
  whole frame with one `sendmsg` call; if it is short, write the rest
  normally). A `run` with redaction carries none: its input and output travel
  as data frames, so the agent never touches the client's own descriptors.
  Any request with the wrong number of descriptors is rejected with
  `invalid_request`.
- The whole request must arrive within 10 seconds of connecting (a deadline,
  not a per-read timeout). The agent handles
  at most 64 connections at a time — it closes a further one without a
  response — and refuses (with `denied`) requests when
  8 are already waiting for the human.
- While a `run` request is in progress, the client must keep the connection
  open. With redaction the agent sends the command's output as data frames
  (channels 1 and 2) and finally the `exited` (or `error`) message, which
  always comes after the last data frame; the client writes the data to its
  own stdout and stderr and grants credit. If `forward_stdin` is set, the
  client sends its input as channel-0 data frames, then an empty one at end
  of input.
- **Cancellation.** Closing the connection, half-closing it
  (`shutdown(SHUT_WR)`), or sending anything not listed above (a message, an
  unknown channel, unrequested input, an oversized or truncated frame)
  cancels the request: the agent shuts the socket down and terminates the
  command's process group. The agent watches the connection only once the
  command has started. Before that — while a dialog is open — a close or a
  violation is not noticed: the dialog stays until it is answered or times
  out, and if the human allows the request, the approval is recorded and
  the command is started with the secrets. Only then does the agent notice
  and cancel: the command has started, and its process group gets `SIGTERM`,
  then `SIGKILL` 3 seconds later. As for any cancelled run, the audit log
  records the command's end (`exited`, for example `killed by signal 15`),
  not that the client had gone. The other requests are not watched at all
  while a dialog is open: one that the human allows after its client has
  gone is carried out (an `edit`, a `remove`, an `add`), with nobody to
  read the answer.

The same run framing, descriptor rules, flow control and cancellation apply to
`broker_run_v2`. Cancelling it also ends its grants; after a close while a
dialog was open they too are created, recorded and served first.

## Requests

Every request is an object with a `type` field.

| `type` | Fields | Response |
|---|---|---|
| `status` | — | `status` |
| `unlock` | — | `ok` |
| `create_vault` | — | `ok` |
| `lock` | — | `ok` |
| `list` | — | `entries` |
| `show` | `name` | `entry` |
| `add` | `entry` ([NewEntry](#newentry)), `value` (string or `null`), `generate` (optional, see below), `replace` (bool) | `ok` |
| `import` | `entries` (array of `{entry, value}`), `replace` (bool) | `ok` |
| `edit` | `name`, `changes` ([EntryChanges](#entrychanges)) | `ok` |
| `remove` | `name` | `ok` |
| `reveal` | `name`, `notes` (bool, optional), `purpose` (optional, see [Reveal](#reveal)) | `secret` |
| `change_password` | — | `ok` |
| `backup` | `path` (absolute, must not exist) | `ok` |
| `run` | see [Run](#run) | `exited` |
| `broker_run_v2` | Run fields plus non-empty `brokered` and `limits` (see [below](#broker-requests-protocol-9)) | `exited` |
| `grants` | — | `grants` |
| `revoke_grant` | `id` (optional; absent revokes all) | `ok` |
| `keyring_items` | — | `keyring_items` |
| `dotenv_names` | `path` (absolute) | `names` |
| `import_from` | `source` (see [Imports read by the agent](#imports-read-by-the-agent)), `tags` (array, optional), `replace` (bool, optional) | `ok` |
| `configure` | `settings` (see [Configure](#configure)) | `ok` |

Any request can also be answered with an [`error`](#errors).

`name` is an entry title, a `Group/Sub/Title` path, or the entry's UUID.

### Examples

```json
{"type": "status"}
{"type": "show", "name": "core-router"}
{"type": "add", "entry": {"name": "GITHUB_TOKEN", "fields": {"url": "https://github.com", "tags": ["dev"]}}, "value": null, "replace": false}
{"type": "edit", "name": "core-router", "changes": {"host": "10.0.0.2", "clear": ["url"], "value": "prompt"}}
{"type": "edit", "name": "core-router", "changes": {"group": "Network/Core"}}
```

With `"value": null`, `add` makes the agent ask the human for the value. A
string value is accepted only after approval. Instead of a value, `add` may
carry `"generate": {"length": 32, "alphabet": "alnum"}` (alphabets `alnum`,
`symbols`, `hex`; length 8–1024): the agent generates the value after
approval; a request with both a string value and `generate` is refused
(`invalid_request`). `change_password` makes the agent ask for the current and
the new master password in its own dialogs.

`create_vault` creates the vault file at the agent's vault path (the one
`status` reports, absolute), which must not exist: if it does, the answer is
`already_exists` and no dialog is shown. While a vault is unlocked whose
file is gone (moved or deleted), it is refused with `invalid_request`: lock
first. Otherwise the agent asks the human
for the new master password twice, in its own dialogs, so that it never
passes through a client; at least 8 characters, and both must match
(`invalid_request` otherwise, `cancelled` when a dialog is cancelled or not
answered). It records the attempt in the audit log (`create_vault`, outcome
`created`, `cancelled`, `timed_out`, `mismatch`, `too_short` or `failed`)
before the file is written, never replaces a file that appears meanwhile,
and leaves the new vault unlocked — unless the vault was locked while the
dialogs were open (by `lock`, a screen lock or a suspend),
in which case it is created locked and the `ok` message says so. Requests
are handled one at a time: of two, the second gets `already_exists`.

### Imports read by the agent

`import` carries the values: the client read them, and the dialog says that
the requester supplied them. `import_from` carries only *where* the values
are and the entry names; the agent reads the values itself, so no client
holds them, and its dialog names the source
([ADR 0012](adr/0012-import-read-by-the-agent.md)). Both import at most 100
entries per request, and both refuse, with `invalid_request` and before any
dialog, a request with more, with none, with an invalid name or with a name
given twice.

```json
{"type": "keyring_items"}
{"type": "dotenv_names", "path": "/home/me/app/.env"}
{"type": "import_from", "source": {"keyring": {"items": [{"id": "/org/freedesktop/secrets/collection/login/7", "name": "OPENAI_API_KEY"}]}}, "tags": ["migrated"]}
{"type": "import_from", "source": {"dotenv": {"path": "/home/me/app/.env", "prefix": "APP_", "names": ["APP_TOKEN"]}}}
```

- `keyring_items` answers `{"type": "keyring_items", "items": [...]}`: for
  each item of GNOME Keyring (any freedesktop Secret Service), its `id` (the
  D-Bus object path), `label`, `attributes` (object of strings) and `locked`.
  No secret is read and nothing is unlocked. The agent asks the human first
  — the requester learns the labels and attributes — and refuses a keyring
  of more than 10 000 items (`internal`) and a listing that does not fit in
  one message (`invalid_request`).
- `dotenv_names` answers `{"type": "names", "names": [...], "empty": [...]}`:
  the names of the file's variables with a value, in its order, and, when
  there are any, those with an empty value, which cannot be imported (a
  file that sets a name twice is refused). The agent asks the human first, then reads the file
  and drops the values.
- `import_from` imports its entries after one approval. Keyring
  items can be imported only from the last `keyring_items` listing that
  the human allowed **this program** (the same process) to see, in the last
  10 minutes and since the vault was last locked (a lock while the listing
  is under way makes it fail with `locked` and keeps nothing of it); other
  items, or no such listing, are refused before any dialog, alike whatever
  the keyring holds. The dialog shows one row per entry — "Entry 1", "Entry
  2", … — with the entry's name and the item it comes from as that listing
  showed it (label and attributes, or "locked"), so nothing in it, not even
  its size, is news to the requester. For a `.env` file only what the request
  says (the path, the names) is shown and checked before the dialog. After the
  approval, keyring items are read by `id` and imported under `name`; an
  item that is locked, gone, or no longer what the listing showed (label,
  attributes), or a secret that is not UTF-8 text, refuses the whole
  request. For a `.env` file, `prefix` (upper-cased) is put before every
  variable name, and each of `names` must appear exactly once in the file,
  as it is after the approval. Tags apply to every new entry; existing
  entries are skipped unless `replace`.
- A `.env` path must be absolute and name a regular file of at most 1 MiB,
  in UTF-8. The agent opens it without waiting (a FIFO is refused, not
  waited on) and reads it as the user it runs as, in the small dialect
  described in [cli.md](cli.md#rusthorse-import-dotenv), which python-dotenv
  and Node's dotenv read as Rusthorse does; any other file is refused as a
  whole (`invalid_request`, naming the line only), nothing in it skipped.
- A request uses the Secret Service once — the listing, or the reading
  after the approval — and each call is limited to 10 seconds, the whole
  use, connecting and authenticating included, to 30; past them the agent
  shuts the connection down and answers within 5 more seconds. Without the
  `secret-service` build feature, the keyring requests fail with
  `internal`.

### Reveal

```json
{"type": "reveal", "name": "8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f", "notes": false, "purpose": "copy"}
```

`purpose` says what the client will do with the value:

| `purpose` | Meaning | Dialog asks | Audit `detail` |
|---|---|---|---|
| absent | The client prints it (`rusthorse reveal`). | "Reveal the value of an entry?" | `value` |
| `"show"` | It shows the value in its own window for a short time, from where the human may copy it. | "Show the value of an entry on screen?" | `value, to show` |
| `"copy"` | It puts the value on the clipboard. | "Copy the value of an entry to the clipboard?" | `value, to copy to the clipboard` |

(`notes` instead of `value` with `"notes": true`.) The purpose is the
client's own statement: the agent cannot enforce it, the dialog labels it
"Stated purpose (unverified)", and its warnings hold whatever the client
does. An approval for one purpose is never remembered and never reused for
another. Clients leave the field out when they have no purpose to state.

### Configure

`configure` changes the agent's settings
([ADR 0007, section 3](adr/0007-visual-manager.md#3-persistent-agent-configuration-m2)).
`settings` names only the settings to change, each optional; unknown fields
are refused:

| Field | Value |
|---|---|
| `idle_timeout_secs` | Lock after this many seconds without use: `0` (never), or 1 to 86400 |
| `remember_secs` | How long "Allow for …" lasts in `run` dialogs: `0` (off), or 1 to 28800 |
| `dialog_timeout_secs` | How long a dialog waits for an answer: 15 to 300 |
| `lock_on_suspend` | Lock when the computer is about to sleep (bool) |
| `lock_on_screen_lock` | Lock when the session is locked or its screensaver starts (bool) |

```json
{"type": "configure", "settings": {"idle_timeout_secs": 300, "lock_on_screen_lock": false}}
```

Refused with `invalid_request`, before anyone is asked: no setting, a value
out of bounds, settings that all already have those values, a setting a
flag of `rusthorse agent` fixes (`status.settings` says which), or an agent
started without a settings file. Otherwise the agent needs the vault
unlocked — it asks for the master password first when it is locked — and
asks the human in its own dialog, showing each old and new value and a
warning for each change that protects less; there is no "Allow for…". It
records the human's answer in the audit log (`internal`, and nothing
changed, if it cannot). After Allow, it acts only if the vault was not
locked or changed meanwhile (`locked` otherwise, and nothing changed), then
replaces the settings file, applies the change at once and forgets
remembered approvals. A failure before the file is replaced is `internal`,
and nothing changed; once it is replaced, the change is applied, and a
failure to sync its directory is `outcome_unknown`.

### NewEntry

```json
{
  "name": "core-router",
  "group": "Network/Core",
  "fields": {
    "kind": "device",
    "username": "admin",
    "url": "https://10.0.0.1/",
    "host": "10.0.0.1",
    "port": 443,
    "tags": ["network"]
  },
  "notes": "Rack 2"
}
```

Every field except `name` is optional. `group` places a new entry; it is a
path as in [`EntryChanges.group`](#entrychanges), created if missing, and
refused if it leads into the recycle bin — for a new entry, before any
dialog. An entry overwritten with `replace` stays in its group.

### Entry kinds

`kind` says what an entry is for. It is one of:

| `kind` | For | What the `url` is |
|---|---|---|
| `api-key` | A key or token for an API | The API's endpoint, e.g. `https://api.openai.com/v1` |
| `login` | A sign-in to a website or web console | The sign-in page |
| `server` | A server reached by host and port (SSH, a database, …) | — |
| `device` | A device such as a router or a camera | Its admin page |

An entry without `kind` is of no particular kind. The kind changes how
clients label and offer the fields; the agent attaches no meaning to it — it
grants nothing, restricts nothing and is not checked against the other
fields. It is metadata like the URL: readable without approval.

The vault stores it in the KDBX custom field `Kind`, as the text above. A
`Kind` field holding anything else (written by another KeePass client, say) is
not a kind: `EntryInfo` has no `kind`, and `Kind` appears in `other_fields`.
Surrounding spaces and letter case are ignored when reading it.

### EntryChanges

All fields are optional; omitted fields are left unchanged. A field not
listed here is refused (since protocol 9), and the edit with it.

| Field | Type | Meaning |
|---|---|---|
| `rename` | string | New name. |
| `username`, `url`, `host`, `notes` | string | New value (an empty string removes the field). |
| `port` | integer 0–65535 | New port. |
| `kind` | `"api-key"`, `"login"`, `"server"` or `"device"` | New kind (protocol 5). To remove the kind, put `"kind"` in `clear`. |
| `group` | string | Move the entry to the group at this path (protocol 7), e.g. `"Work/Servers"`, created if missing; `""` or `"/"` is the top level. See below. |
| `clear` | array of `"username"`, `"url"`, `"host"`, `"port"`, `"notes"`, `"kind"` | Fields to remove. Since protocol 9, `"broker"` is not one of them: a request that names it is refused. |
| `add_tags`, `remove_tags` | array of strings | Tag changes. |
| `value` | `"prompt"`, `{"provided": "…"}` or `{"generate": {"length": N, "alphabet": "…"}}` | New secret value: ask the human, use the given one, or generate one. |

`group` is split at `/`; spaces around each part and empty parts are
dropped, and each part must be a valid entry name (no control or invisible
formatting characters, at most 128 characters). The path is followed from
the top through the existing groups, creating what is missing. The agent
checks it before the approval dialog: an invalid path, one that leads into
the recycle bin (where an entry would be hidden from every listing), or one
through two groups of the same name side by side is refused with
`invalid_request` without an approval dialog. The dialog shows the
destination normalized and from the top, with the whole UUID of the deepest
existing group and what would be created (`/Work/Servers (existing group
8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12)`, `/Work/Servers (creates Servers in
/Work, group 1a2b3c4d-6e7f-4a8b-9c0d-e1f2a3b4c5d6)`, `/ (the top level)`, and,
without a UUID when no group of the path exists, `/New/Deeper (creates
New/Deeper at the top level)`). A path that leads to the group the entry
is already in — compared by identity, not by how its path reads — is
dropped from the request before the dialog; if nothing else changes, the
request fails with `invalid_request` ("nothing to change"). The audit
record's `detail` says from where to where. A move records the previous group and the
time of the move in the entry (KDBX `PreviousParentGroup`,
`LocationChanged`), and the entry's previous version goes to its history, as
with every edit.

### Run

```json
{
  "type": "run",
  "bindings": [{"var": "OPENAI_API_KEY", "entry": "OPENAI_API_KEY"}],
  "argv": ["python", "app.py"],
  "cwd": "/home/me/project",
  "env": [["PATH", "/home/me/project/.venv/bin:/usr/bin:/bin"], ["HOME", "/home/me"]],
  "redact": true,
  "forward_stdin": false
}
```

- `bindings`: at least one; variable names must match `[A-Za-z_][A-Za-z0-9_]*`
  and be unique.
- `argv[0]` is resolved by the agent like `execvp` would, using the `PATH`
  from `env` and `cwd`.
- `cwd` must be an absolute path to an existing directory.
- `env` is the client's environment. The agent removes every variable whose
  name starts with `LD_` and those that a binding overrides.
- Command lines, paths and environment must be valid UTF-8. The command line,
  the resolved program path and `cwd` must each fit in 1000 characters.
- With `redact: true`, the command's stdin is `/dev/null` unless
  `forward_stdin` is `true` (optional, default `false`), in which case the
  agent feeds it from the client's channel-0 data frames. With
  `redact: false`, the three descriptors sent with the request are given to
  the command as they are.

### Broker requests (protocol 9)

```json
{"type":"broker_run_v2","bindings":[],"brokered":[{"var":"ANTHROPIC_API_KEY","entry":"anthropic","destination":"https://api.anthropic.com","url_var":"ANTHROPIC_BASE_URL"},{"var":"OPENAI_API_KEY","entry":"openai","destination":"https://api.openai.com/v1"}],"limits":{"automatic_locks":"continue","max_lifetime_minutes":720,"max_requests":200},"argv":["python","app.py"],"cwd":"/home/me/project","env":[["PATH","/usr/bin:/bin"]],"redact":true,"forward_stdin":false}
{"type":"grants"}
{"type":"revoke_grant","id":"g0123456789abcdef"}
{"type":"revoke_grant"}
```

`broker_run_v2` has the fields of `run` (`bindings`, `argv`, `cwd`, `env`,
`redact`, optional `forward_stdin`), plus a non-empty `brokered` array of
`{var, entry, destination, url_var?}` and `limits`. Nothing else is
accepted: an unknown field in the request, in a binding of either list
(a `destination` in `bindings` too) or in `limits` — a `profile`, a
`preset`, `routes` — makes it `invalid_request`, before any dialog. A plain
`run` refuses an unknown field in a binding the same way. `bindings` may be empty or give other entries by value. The agent
resolves entries by UUID: an entry cannot be brokered twice or be given both
ways. All value, token and URL variables must be distinct; `NO_PROXY` and
`no_proxy` are reserved. `url_var` is omitted when absent.

- `destination` (required) is where the grant sends the entry's value:
  `https://`, a lowercase host name (letters, digits, `-` and `.`; labels of
  1 to 63 characters that neither start nor end with `-`, at most 253 in
  all, the last one starting with a letter: no IP address in any form; an
  international name in its `xn--` form), an optional port (1 to 65535, no
  leading zero) and an optional base path (`/` and segments of letters,
  digits, `.`, `_`, `~` and `-`, none made only of dots, no trailing `/`;
  `https://HOST/` has none). No user information, query or fragment; at
  most 1000 characters. The approval covers its **origin** — scheme, host
  and port — at any path: the base path only goes into `url_var`'s value,
  and limits nothing. There is no default destination: the agent never uses
  the entry's URL for it.
- `limits` (required) applies to every grant of the run, each counted on its
  own: `automatic_locks` (`end` or `continue`: whether screen lock, suspend
  and the idle lock end the grants), `max_lifetime_minutes` (1–1440) and
  `max_requests` (1–1,000,000; omitted for no limit). The agent fills in
  nothing: `automatic_locks` and `max_lifetime_minutes` are required. (The
  `rusthorse` CLI sends `continue`, 720 and no request limit unless told
  otherwise.)
- Invalid destinations and limits are `invalid_request`, before the vault is
  read and before any dialog.

The agent puts the generated token in `var` and its own loopback base URL
(`http://127.0.0.1:PORT` and the destination's base path) in `url_var`; the
values the requester's `env` has for those variables are dropped. It adds
`127.0.0.1` to both proxy-bypass variables. The requester cannot supply a
token. Approval is never remembered, even when the agent was started with
`--remember`. The broker's rules for the requests it forwards to the
approved origin — the token presented in a header and replaced by the key,
what is refused, forwarded and relayed — are in
[ADR 0013](adr/0013-credential-broker.md#the-broker-without-profiles-or-presets).

A plain `run` with non-empty `brokered` is refused during parsing; an absent,
empty or null list carries no broker binding. An agent of protocol 9 refuses
protocol 8's `broker_run` and `broker_edit` whole, before any approval, as
unknown request types (`invalid_request`). An agent of protocol 8 refuses
`broker_run_v2` whole in the same way, so a client that checked the version
on one connection and meets an older agent on the next one (after a
restart) still runs nothing. A client must never retry a refused
`broker_run_v2` as `broker_run` or as a plain `run`; the `rusthorse` CLI
never does. An `edit` whose `changes` carry a field the agent does not
know — protocol 8's `broker` profile among them — is refused whole as
`invalid_request`, before any approval: nothing of it is applied.

`grants` and `revoke_grant` need neither an unlocked vault nor a dialog. A
malformed grant ID is `invalid_request`; an unknown well-formed ID is
`not_found`. Revoking an already-revoked grant is safe. `ok` means the brokers
concerned have confirmed containment or are killed and reaped; requests
already sent upstream may still take effect. A lost reply is not proof of
revocation: listing again or repeating a revocation is safe.

### GrantInfo

`grants` returns `{"type":"grants","grants":[...]}`, never a token or a
credential. Each element has:

| Field | Meaning |
|---|---|
| `id`, `entry`, `var` | Public grant ID; entry identity as shown in dialogs; command variable holding the token. |
| `destination` | The approved origin (`https://`, the host and the port if the run named one), where the broker may send the key at any path. Since protocol 9; before, the profile's origin and base path. |
| `base_path` | Optional, omitted when the run named none: the base path of the run's destination (`/v1`), which sets up the program's base URL and limits nothing. Since protocol 9. |
| `command`, `requester` | Command text and unverified requester description. Treat both as untrusted display text. |
| `state` | `starting` (preparation, no admission), `active`, `exhausted` (no new admission, existing requests finish), or `revoked`. |
| `started`, `ends_in_secs` | Creation time in RFC 3339 with local offset; seconds left to the maximum lifetime. |
| `requests`, `max_requests` | Admitted count; optional maximum (the run's request limit), omitted for no limit. |
| `in_flight` | Occupied request slots, including reservations waiting for their admission record. |
| `unauthorized` | Optional: admitted requests the destination answered with `401 Unauthorized` — it did not accept the credential the broker sent from the entry. Counted when the broker reports a request's end, whatever its outcome; the broker's own `401` (no token, or another grant's) is never counted. A current agent always reports it, `0` included; omitted by an older agent. |
| `automatic_locks` | `end` or `continue`, as the run set it. |

Revoked grants can remain listed until their command ends, still occupying one
of the agent's 16 grant slots. Broker exit removes the registry entry sooner;
the run still retains its listener until cleanup. `ended` is not a wire state:
a removed grant disappears; the manager may retain an ended row locally.

## Responses

| `type` | Fields |
|---|---|
| `ok` | `message` (string) |
| `status` | see [StatusInfo](#statusinfo) |
| `grants` | `grants`: array of [GrantInfo](#grantinfo), oldest first |
| `entries` | `entries`: array of [EntryInfo](#entryinfo), sorted by group and name |
| `entry` | `entry`: [EntryInfo](#entryinfo) |
| `secret` | `value` (string) |
| `keyring_items` | `items`: array of `{id, label, attributes, locked}`, sorted by label |
| `names` | `names`: array of strings; `empty` (array, optional): names with an empty value |
| `exited` | `code` (integer or `null`), `signal` (integer or `null`); exactly one is set — a client treats an answer with neither as an unknown outcome. `unauthorized` (optional, omitted when empty): the run's grants whose destination answered requests with `401 Unauthorized`, each `{var, entry, destination, requests}` — the token's variable, the entry's identity as dialogs show it, the approved origin (as in `GrantInfo.destination`, since protocol 9), and how many requests (at least 1). It counts every request whose end the grant's broker reported before it confirmed its revocation or exited; one killed before that may leave some out. The `rusthorse` CLI prints a note for each after the command ([cli.md](cli.md#through-the-credential-broker---broker)). |
| `error` | `code` (see [Errors](#errors)), `message` (string) |

### StatusInfo

```json
{
  "type": "status",
  "protocol_version": 10,
  "agent_version": "0.1.0",
  "vault": "/home/me/.local/share/rusthorse/vault.kdbx",
  "vault_exists": true,
  "audit_log": "/home/me/.local/state/rusthorse/audit.jsonl",
  "locked": false,
  "idle_timeout_secs": 900,
  "locks_in_secs": 812,
  "remembered_approvals": 1,
  "agent_executable": "/home/me/.cargo/bin/rusthorse",
  "agent_executable_id": [66306, 1835012],
  "agent_executable_replaced": false,
  "dialogs": "/home/me/.cargo/bin/rusthorse-dialog",
  "broker": "/home/me/.cargo/bin/rusthorse-broker",
  "grants": 1,
  "lock_triggers": [
    {"event": "screen_lock", "source": "logind", "active": true,
     "note": "session lock signals of this user"},
    {"event": "screen_lock", "source": "org.cinnamon.ScreenSaver", "active": true},
    {"event": "suspend", "source": "logind", "active": true,
     "note": "locks before the computer sleeps"}
  ],
  "settings": {
    "file": "/home/me/.config/rusthorse/agent.toml",
    "idle_timeout_secs": {"value": 900, "source": "default"},
    "remember_secs": {"value": 0, "source": "default"},
    "dialog_timeout_secs": {"value": 60, "source": "file"},
    "lock_on_suspend": {"value": true, "source": "default"},
    "lock_on_screen_lock": {"value": false, "source": "flag"}
  }
}
```

`settings` (optional; left out by agents that predate it and by an agent
started without a settings file) holds the agent's settings in effect: for
each, its `value` and its `source` — `default`, `file` (the settings file
at `file`, an absolute path) or `flag` (an explicit flag of `rusthorse
agent`, which wins over the file and which `configure` cannot change).
`idle_timeout_secs` at the top level is the same idle timeout.

`lock_triggers` (optional; left out by agents that predate it) lists what
else locks the vault ([ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md)):
`event` is `suspend` or `screen_lock`, `source` where the agent learns of it
(`logind`, a screensaver's D-Bus name, `screensaver` standing for all of them
while none is watched, or `D-Bus` for either event in a build without the
`session-lock` feature), `active` whether it is watched now (the service is
there, not merely the subscription), `degraded` (optional, left out when
false) whether it is watched less well than it should be — logind would not
give a delay inhibitor, so the lock may come after the computer wakes — and
`note` why not or a remark (`turned off`, `connecting`, the bus error).
Clients that find it missing should say it is not reported, not that nothing
locks.

`locks_in_secs` is omitted when the vault is locked or auto-lock is off.
`agent_executable` is the program file the agent runs, as the kernel reports
it (`/proc/self/exe`), and `agent_executable_id` its device and inode, read
through `/proc/self/exe` itself, so a client can compare it with its own
without relying on names (the same name can lead to different files in
different mount namespaces). `agent_executable_replaced` says whether that
name no longer leads to the running file — it was replaced or removed after
the agent started, as an upgrade without a restart does — judged by file
identity, not by the ` (deleted)` the kernel appends to the name, which a
real file name could also end with; it is left out when the agent cannot tell
(for example, without permission to examine the path), as is
`agent_executable_id` when the agent cannot read its own identity.
`dialogs` names what shows the agent's dialogs: the path of
`rusthorse-dialog`, `zenity` when that program is not installed, or `none: `
followed by why neither can be used; agents that predate it leave it out.
Clients should check `protocol_version` and refuse to continue on a mismatch.

`broker` is optional: the resolved helper path, or `none: ` and its reason.
`grants` is optional: the count of `starting`, `active` and `exhausted`
grants, excluding revoked grants. It therefore differs from the length of
`grants.grants` and from the 16-slot limit, both of which include revoked
grants still held. Missing fields mean not reported, not zero or unavailable;
new optional fields are omitted, never emitted as null when absent.

### EntryInfo

```json
{
  "id": "8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f",
  "name": "core-router",
  "group": "Network/Core",
  "kind": "device",
  "username": "admin",
  "url": "https://10.0.0.1/",
  "host": "10.0.0.1",
  "port": 443,
  "tags": ["network"],
  "has_password": true,
  "has_notes": true,
  "other_fields": ["Serial"],
  "modified": "2026-10-31T18:02:11Z"
}
```

`id` is the entry's KeePass UUID. Optional fields are omitted when empty.
`protected_fields` lists metadata fields (`UserName`, `URL`, `Host`, `Port`,
`Kind`) that the file marks as protected; their values are withheld.
`other_fields` lists the names of custom fields other than `Host`, `Port` and
a valid `Kind`; their values are not disclosed. Since protocol 9 an entry has
no `broker`: a `Rusthorse.Broker` field, where an agent of protocol 8 stored
a broker profile, is listed in `other_fields` like any custom field. The
agent never reads or interprets it, and keeps it as it is, also when the
entry is replaced (`add` or `import` with `replace`).

## Errors

| `code` | Meaning |
|---|---|
| `denied` | The human denied the request, an approval dialog was not answered in time, or too many requests were waiting. |
| `cancelled` | The human cancelled a password or value dialog, or did not answer it in time. |
| `locked` | The vault was locked or changed while the request was waiting; try again. |
| `unlock_failed` | No answer gave the right master password. An unlock asks up to three times, and an empty answer uses one of them (when nothing was ever typed the error is `cancelled`); `change_password` asks for the current password once. |
| `vault_missing` | There is no vault file yet. |
| `vault_changed` | Another program changed the vault file since it was unlocked. |
| `not_found` | No such entry, the entry has no value, or no such grant. |
| `already_exists` | An entry with that name exists (use `replace`); for `create_vault`, the vault file exists. |
| `ambiguous` | Several entries match; use a `Group/Name` path. |
| `invalid_request` | Malformed or disallowed request (bad name, missing fds, details too long, program replaced after approval, …). |
| `outcome_unknown` | The request may have taken effect, but the agent cannot confirm it: a `run` command started but its result could not be determined, or a change was written to the vault file but the file's directory could not be synced, so it may not survive a crash (the vault is then locked; unlocking reads what the file holds). Do not simply retry. |
| `internal` | Anything else, including an unwritable audit log or a save that failed before the file was replaced (after which the vault is locked). |

**Every error other than `outcome_unknown` means that the vault file was not
changed and no command was started.** (The audit log may record the attempt,
the vault may have been locked, and a `backup` whose copy does not verify
leaves that copy, which the message names.) A client that sends a request with
effects — `create_vault`, `add`, `import`, `import_from`, `edit`, `remove`,
`change_password`, `backup`, `run`, `broker_run_v2`, `configure` — and gets
no answer, or one it cannot parse, must likewise treat the outcome as
unknown. For `configure`, an error other than `outcome_unknown` also means
that the settings file was not replaced and no setting changed; after
`outcome_unknown`, or no answer, the change may be in effect.

`revoke_grant`, like `lock`, is safe to repeat and is not classified as a
request with effects by `Request::has_effects`. A lost reply is a regular
client error (CLI exit 1), not proof that revocation completed.

For `broker_run_v2`, definite errors before command start map to CLI exit 125;
`outcome_unknown` or a lost/malformed reply maps to 124. An unknown field,
an invalid destination or invalid limits, a value the broker cannot send, and
no room for the run's grants (16 at a time) use `invalid_request`; a
missing/unusable broker, startup failure or failed
grant-creation record uses `internal`. There are no new error codes.
Once the command starts, its exit status is reported normally: an HTTP failure
or revocation does not retroactively make it a did-not-run result. These
guarantees concern vault writes and command start, not absence of all effects:
grants may have been revoked even when a later audit write fails.

## Compatibility

- Within a protocol version, new optional request fields, new response fields
  and new error codes may be added. Clients must ignore unknown response
  fields and treat an unknown error code like `outcome_unknown`. Added
  optional fields are left out when absent, not serialized as null.
- Removing or changing the meaning of a field or of an error code —
  including what an error guarantees about the request's effects — or
  changing framing, bumps `PROTOCOL_VERSION`.
- Protocol 10 added `configure`. A client of protocol 10 refuses an agent of
  protocol 9 at its version check, and an agent of protocol 9 refuses
  `configure`, which it does not know.
- Protocol 9 removed fields and changed what `destination` means in
  `grants` and `exited.unauthorized`. A client of protocol 9 refuses an agent
  of protocol 8 at its version check, and an agent of protocol 8 refuses
  `broker_run_v2`, which it does not know, whole. A request type that can be
  refused for being unknown is never resent as an older one: a client that
  gets an error for `broker_run_v2` reports it, and does not try
  `broker_run` or a plain `run` with the values.

## Visual manager client

`rusthorse-manager` uses the version-10 requests above, with the same approvals
as the CLI. It targets entries by UUID, sends `reveal` with purpose `show` or
`copy` for its Show and Copy actions, sends `create_vault` when there is no
vault yet, imports with `keyring_items`, `dotenv_names` and `import_from`, and
never sends a master password or a value it read. See
[ADR 0007](adr/0007-visual-manager.md). Its Grants page uses `grants` and
`revoke_grant`; its Settings page shows `status.settings` and sends
`configure`, only while the vault is unlocked; its History page reads the
audit log at `status.audit_log` and sends no request of its own. No restore
request exists yet. It sends no broker run itself: its command
templates for `rusthorse run --broker` are text for the human to fill in
and run.

## Agent–broker control channel (broker protocol 2)

This is a separate socket pair, not the client socket or HTTP interface. The
exact schemas and constants are in
[`src/broker_protocol.rs`](../src/broker_protocol.rs). Frames have a four-byte
big-endian length followed by UTF-8 JSON, at most 64 KiB of JSON; unknown
fields are refused. There are no data frames. `install` carries exactly one
`SCM_RIGHTS` descriptor on the first byte: a listening TCP socket on
`127.0.0.1`. No other message carries descriptors; unexpected descriptors are
owned and closed on refusal, and received descriptors are close-on-exec.

| Direction | Message | Fields |
|---|---|---|
| Agent → broker | `install` | `version` (2), `grant`, secret `token` and `credential`, the approved `origin` (`https://`, a host name and an optional port; no base path, which only the command's base URL holds), `max_in_flight`, `max_connections`, `lifetime_secs`; listening fd. |
| Broker → agent | `ready` | `version`, `grant`, matching the installation. |
| Broker → agent | `admit` | Consecutive `request` numbers from 1 (each one more than the last; a gap or a repeat is a violation), and the label of its `method`: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OTHER` for any other method. Never the raw method, the path or the query. |
| Agent → broker | `admitted` / `refused` | Same `request`; refusal also carries `reason`. |
| Broker → agent | `finished` | Same `request`, `outcome`, optional `status`, `bytes_sent`, `bytes_received`. |
| Agent → broker | `revoke` | End `reason`. |
| Broker → agent | `revoked` | `refused`: count refused locally before asking the agent. |

Version 2 replaced version 1's `profile` in `install` with `origin`, and
`admit`'s `method` and `route` with the method's label: both sides refuse
any other version, before a grant is served, and a version-1 message (a
`profile`, a `route`) is refused as an unknown field. The broker validates
`origin` as the agent did (`https://` and a host name, optional port, no IP
address) and connects there and nowhere else, taking the TLS server name and
`Host` from it.

`ready` follows validation, CA parsing, TLS setup and runtime registration,
within the agent's 10-second preparation deadline. The process is registered
before `install`; the state check and non-blocking send share the registry
lock. A send that cannot complete fails preparation closed; `write_all` can
finish a partial `sendmsg` without waiting while the socket has room.

An `admit` follows the broker's HTTP framing and token checks and a
reservation of the declared body size. The agent reserves a use and slot, records admission
durably, rechecks state and lifetime, then answers exactly once. Only
`admitted` permits body reading and forwarding. Refusals are `revoked`,
`expired`, `exhausted` (HTTP 403), `too_many_in_flight` (429) or
`audit_failed` (503). Each admitted attempt spends its use, including a failed
request or an SDK retry. `finished` frees the slot; numbering violations and
messages that do not parse (an `admit` with a route, a path or a method that
is not one of the labels) end the grant as `broker_failed` without changing
counters for the offending message.

`finished.outcome` is `completed`, `not_forwarded`, `client_closed`, `revoked`
or `unknown`. Once a response head arrived, `status` is the upstream status
even if the broker substitutes 502; otherwise it is the local status, or
absent when no status was obtained. Sizes count body bytes handed to the
destination connection and received before redaction, not proof of an upstream
operation's success.

On `revoke`, the broker closes existing exchanges and connections, drops the
credential and refuses later requests with 403. The agent immediately answers
waiting admissions with `refused: revoked`, without waiting for audit. The
broker's confirmation follows every admission answer and every admitted
request's `finished`; a late `admitted` is not forwarded and finishes
`revoked`. Nothing follows confirmation. The agent also tolerates an early
`revoked`, counting outstanding admitted requests as `unknown`; any subsequent
message is a violation. It waits for confirmation or process termination,
including kill and reap, before reporting revocation done.

The broker independently expires its grant on `CLOCK_BOOTTIME`, counted from
receipt of `install`, rereading at least once per second while scheduled and
at forwarding/relay checkpoints. It closes existing work and drops the
credential even without the agent's word. It still takes replies to pending
admissions and sends their `finished` when applicable, but sends no
unsolicited `revoked`; it confirms a later `revoke` normally. EOF exits
immediately, without waiting for blocked DNS work. No grant is restored.

The agent writes `grant` and `broker_request` audit records. A failed
completion record revokes the grant. Completion and end records are best
effort and may follow the run's reply; the grant's end record follows its
request records. End counts distinguish `finished` from admitted requests
whose completion was never reported (`unknown`); locally refused requests are
counted only up to confirmation. A request recorded as admitted but refused at
the recheck gets a second `not_forwarded` record and counts as refused, not
admitted.
