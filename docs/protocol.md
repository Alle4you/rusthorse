# Agent protocol

This is the protocol between clients and the Rusthorse agent. The `rusthorse`
CLI is the reference client; this document is for anyone writing another one
(a GUI, an editor plugin, a browser bridge).

Protocol version: **1** (`PROTOCOL_VERSION` in
[`src/protocol.rs`](../src/protocol.rs)).

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
  | `0x81` | client → agent | Credit for channel 1: a big-endian `u32` number of bytes the client has written out. |
  | `0x82` | client → agent | Credit for channel 2. |

  Data frames are only valid during a `run` with redaction, and never carry
  file descriptors.
- **Flow control.** The agent sends at most 1 MiB on each output channel
  beyond what the client has acknowledged with credit frames. The client
  grants credit as it writes data out. Each channel has its own window, so a
  client whose stdout is stuck still receives stderr.
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
| `lock` | — | `ok` |
| `list` | — | `entries` |
| `show` | `name` | `entry` |
| `add` | `entry` ([NewEntry](#newentry)), `value` (string or `null`), `replace` (bool) | `ok` |
| `import` | `entries` (array of `{entry, value}`), `replace` (bool) | `ok` |
| `edit` | `name`, `changes` ([EntryChanges](#entrychanges)) | `ok` |
| `remove` | `name` | `ok` |
| `reveal` | `name` | `secret` |
| `run` | see [Run](#run) | `exited` |

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
string value is accepted only after approval.

### NewEntry

```json
{
  "name": "core-router",
  "group": "Network/Core",
  "fields": {
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

### EntryChanges

All fields are optional; omitted fields are left unchanged.

| Field | Type | Meaning |
|---|---|---|
| `rename` | string | New name. |
| `username`, `url`, `host`, `notes` | string | New value (an empty string removes the field). |
| `port` | integer 0–65535 | New port. |
| `clear` | array of `"username"`, `"url"`, `"host"`, `"port"`, `"notes"` | Fields to remove. |
| `add_tags`, `remove_tags` | array of strings | Tag changes. |
| `value` | `"prompt"` or `{"provided": "…"}` | New secret value: ask the human, or use the given one. |

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
| `exited` | `code` (integer or `null`), `signal` (integer or `null`) |
| `error` | `code` (see [Errors](#errors)), `message` (string) |

### StatusInfo

```json
{
  "type": "status",
  "protocol_version": 1,
  "agent_version": "0.1.0",
  "vault": "/home/me/.local/share/rusthorse/vault.kdbx",
  "vault_exists": true,
  "locked": false,
  "idle_timeout_secs": 900,
  "locks_in_secs": 812,
  "remembered_approvals": 1
}
```

`locks_in_secs` is omitted when the vault is locked or auto-lock is off.
Clients should check `protocol_version` and refuse to continue on a mismatch.

### EntryInfo

```json
{
  "id": "8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f",
  "name": "core-router",
  "group": "Network/Core",
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
`protected_fields` lists metadata fields (`UserName`, `URL`, `Host`, `Port`)
that the file marks as protected; their values are withheld. `other_fields`
lists the names of custom fields other than `Host` and `Port`; their values
are not disclosed.

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
| `already_exists` | An entry with that name exists (use `replace`). |
| `ambiguous` | Several entries match; use a `Group/Name` path. |
| `invalid_request` | Malformed or disallowed request (bad name, missing fds, details too long, program replaced after approval, …). |
| `internal` | Anything else, including an unwritable audit log or a failed save (after which the vault is locked). |

## Compatibility

- Within a protocol version, new optional request fields, new response
  fields and new error codes may be added. Clients must ignore unknown
  response fields and treat unknown error codes like `internal`.
- Removing or changing the meaning of a field, or changing framing, bumps
  `PROTOCOL_VERSION`.
