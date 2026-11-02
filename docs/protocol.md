# Agent protocol

This is the protocol between clients and the Rusthorse agent. The `rusthorse`
CLI is the reference client; this document is for anyone writing another one
(a GUI, an editor plugin, a browser bridge).

Protocol version: **6** (`PROTOCOL_VERSION` in
[`src/protocol.rs`](../src/protocol.rs)).

| Version | Changes |
|---|---|
| 1 | First design: descriptors passed for every `run`. Never released. |
| 2 | Data frames and per-channel credit for `run` with redaction (stdin credit granted when the command starts); `add.generate`, `change_password`, `backup`, `reveal.notes`, `status.audit_log`. |
| 3 | Every error other than `outcome_unknown` is definite: the vault file was not changed and no command was started (see [Errors](#errors)); a save that fails after replacing the file is `outcome_unknown`. `status.agent_executable`, `status.agent_executable_id`, `status.agent_executable_replaced`. Added later, optional: `status.dialogs`. |
| 4 | `reveal.purpose` (`show`, `copy`): what the client says it will do with a revealed value, named in the approval dialog and the audit log. Unreleased builds that reported protocol 3 had this field with another meaning for `copy` (one paste, then cleared); clients of protocol 4 refuse those agents. |
| 5 | The entry `kind` (see [Entry kinds](#entry-kinds)): in `NewEntry.fields`, `EntryInfo`, `EntryChanges.kind`, and `"kind"` in `EntryChanges.clear`. An agent of version 4 would silently drop it, so the version changed. |
| 6 | `create_vault`: the agent creates the vault and asks for its master password in its own dialogs. `already_exists` also means that the vault file exists. Imports read by the agent: `keyring_items`, `dotenv_names`, `import_from` (see [Imports read by the agent](#imports-read-by-the-agent)). |

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
  sending more cancels the request. The client starts with no stdin credit:
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
  at most 64 connections at a time and refuses (with `denied`) requests when
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
  command's process group.

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
| `add` | `entry` ([NewEntry](#newentry)), `value` (string or `null`), `replace` (bool) | `ok` |
| `import` | `entries` (array of `{entry, value}`), `replace` (bool) | `ok` |
| `edit` | `name`, `changes` ([EntryChanges](#entrychanges)) | `ok` |
| `remove` | `name` | `ok` |
| `reveal` | `name`, `notes` (bool, optional), `purpose` (optional, see [Reveal](#reveal)) | `secret` |
| `change_password` | — | `ok` |
| `backup` | `path` (absolute, must not exist) | `ok` |
| `run` | see [Run](#run) | `exited` |
| `keyring_items` | — | `keyring_items` |
| `dotenv_names` | `path` (absolute) | `names` |
| `import_from` | `source` (see [Imports read by the agent](#imports-read-by-the-agent)), `tags` (array, optional), `replace` (bool, optional) | `ok` |

Any request can also be answered with an [`error`](#errors).

`name` is an entry title, a `Group/Sub/Title` path, or the entry's UUID.

### Examples

```json
{"type": "status"}
{"type": "show", "name": "core-router"}
{"type": "add", "entry": {"name": "GITHUB_TOKEN", "fields": {"url": "https://github.com", "tags": ["dev"]}}, "value": null, "replace": false}
{"type": "edit", "name": "core-router", "changes": {"host": "10.0.0.2", "clear": ["url"], "value": "prompt"}}
```

With `"value": null`, `add` makes the agent ask the human for the value. A
string value is accepted only after approval. Instead of a value, `add` may
carry `"generate": {"length": 32, "alphabet": "alnum"}` (alphabets `alnum`,
`symbols`, `hex`; length 8–1024): the agent generates the value after
approval. `change_password` makes the agent ask for the current and the new
master password in its own dialogs.

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
holds them, and its dialog names the source ([ADR 0012](adr/0012-import-read-by-the-agent.md)).

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
  of more than 10 000 items.
- `dotenv_names` answers `{"type": "names", "names": [...], "empty": [...]}`:
  the names of the file's variables with a value, in its order, and, when
  there are any, those with an empty value, which cannot be imported (a
  file that sets a name twice is refused). The agent asks the human first, then reads the file
  and drops the values.
- `import_from` imports at most 100 entries, after one approval. Keyring
  items can be imported only from the last `keyring_items` listing that
  the human allowed **this program** (the same process) to see, in the last
  10 minutes and since the vault was last locked (a lock while the listing
  is under way makes it fail with `locked` and keeps nothing of it); other
  items, or no such listing, are refused before any dialog, alike whatever
  the keyring holds. At most 100 entries per request.
  The dialog shows one row per entry — "Entry 1", "Entry 2", … — with the
  entry's name and the item it comes from as that listing showed it (label
  and attributes, or "locked"), so nothing in it, not even its size, is
  news to the requester. For a `.env` file only what the request says (the
  path, the names) is shown and checked before the dialog. After the
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

Every field except `name` is optional.

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

All fields are optional; omitted fields are left unchanged.

| Field | Type | Meaning |
|---|---|---|
| `rename` | string | New name. |
| `username`, `url`, `host`, `notes` | string | New value (an empty string removes the field). |
| `port` | integer 0–65535 | New port. |
| `kind` | `"api-key"`, `"login"`, `"server"` or `"device"` | New kind (protocol 5). To remove the kind, put `"kind"` in `clear`. |
| `clear` | array of `"username"`, `"url"`, `"host"`, `"port"`, `"notes"`, `"kind"` | Fields to remove. |
| `add_tags`, `remove_tags` | array of strings | Tag changes. |
| `value` | `"prompt"`, `{"provided": "…"}` or `{"generate": {"length": N, "alphabet": "…"}}` | New secret value: ask the human, use the given one, or generate one. |

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

## Responses

| `type` | Fields |
|---|---|
| `ok` | `message` (string) |
| `status` | see [StatusInfo](#statusinfo) |
| `entries` | `entries`: array of [EntryInfo](#entryinfo), sorted by group and name |
| `entry` | `entry`: [EntryInfo](#entryinfo) |
| `secret` | `value` (string) |
| `keyring_items` | `items`: array of `{id, label, attributes, locked}`, sorted by label |
| `names` | `names`: array of strings; `empty` (array, optional): names with an empty value |
| `exited` | `code` (integer or `null`), `signal` (integer or `null`); exactly one is set — a client treats an answer with neither as an unknown outcome |
| `error` | `code` (see [Errors](#errors)), `message` (string) |

### StatusInfo

```json
{
  "type": "status",
  "protocol_version": 6,
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
  "lock_triggers": [
    {"event": "screen_lock", "source": "logind", "active": true,
     "note": "session lock signals of this user"},
    {"event": "screen_lock", "source": "org.cinnamon.ScreenSaver", "active": true},
    {"event": "suspend", "source": "logind", "active": true,
     "note": "locks before the computer sleeps"}
  ]
}
```

`lock_triggers` (optional; left out by agents that predate it) lists what
else locks the vault ([ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md)):
`event` is `suspend` or `screen_lock`, `source` where the agent learns of it,
`active` whether it is watched now (the service is there, not merely the
subscription), `degraded` (optional, left out when false) whether it is
watched less well than it should be — logind would not give a delay
inhibitor, so the lock may come after the computer wakes — and `note` why
not or a remark (`turned off`, `connecting`, the bus error). Clients that find it missing
should say it is not reported, not that nothing locks.

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
a valid `Kind`; their values are not disclosed.

## Errors

| `code` | Meaning |
|---|---|
| `denied` | The human denied the request, the dialog timed out, or too many requests were waiting. |
| `cancelled` | The human cancelled a password or value dialog. |
| `locked` | The vault was locked or changed while the request was waiting; try again. |
| `unlock_failed` | Wrong master password three times. |
| `vault_missing` | There is no vault file yet. |
| `vault_changed` | Another program changed the vault file since it was unlocked. |
| `not_found` | No such entry, or the entry has no value. |
| `already_exists` | An entry with that name exists (use `replace`); for `create_vault`, the vault file exists. |
| `ambiguous` | Several entries match; use a `Group/Name` path. |
| `invalid_request` | Malformed or disallowed request (bad name, missing fds, details too long, program replaced after approval, …). |
| `outcome_unknown` | The request may have taken effect, but the agent cannot confirm it: a `run` command started but its result could not be determined, or a change was written to the vault file but the file's directory could not be synced, so it may not survive a crash (the vault is then locked; unlocking reads what the file holds). Do not simply retry. |
| `internal` | Anything else, including an unwritable audit log or a save that failed before the file was replaced (after which the vault is locked). |

**Every error other than `outcome_unknown` means that the vault file was not
changed and no command was started.** (The audit log may record the attempt,
the vault may have been locked, and a `backup` whose copy does not verify
leaves that copy, which the message names.) A client that sends a request
with effects — `create_vault`, `add`, `import`, `import_from`, `edit`,
`remove`, `change_password`, `backup`, `run` — and gets no answer, or one it cannot parse, must likewise
treat the outcome as unknown.

## Compatibility

- Within a protocol version, new optional request fields, new response
  fields and new error codes may be added. Clients must ignore unknown
  response fields and treat an unknown error code like `outcome_unknown`.
- Removing or changing the meaning of a field or of an error code —
  including what an error guarantees about the request's effects — or
  changing framing, bumps `PROTOCOL_VERSION`.

## Visual manager client

`rusthorse-manager` uses the version-6 requests above, with the same
approvals as the CLI. It targets entries by UUID, sends `reveal` with purpose
`show` or `copy` for its Show and Copy actions, sends `create_vault` when
there is no vault yet, imports with `keyring_items`, `dotenv_names` and
`import_from`, and never sends a master password or a value it read. See [ADR 0007](adr/0007-visual-manager.md); the configuration,
grant, history and restore requests it proposes for later milestones do not
exist yet.
