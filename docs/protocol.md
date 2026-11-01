# Agent protocol

This is the protocol between clients and the Rusthorse agent. The `rusthorse`
CLI is the reference client; this document is for anyone writing another one
(a GUI, an editor plugin, a browser bridge).

Protocol version: **3** (`PROTOCOL_VERSION` in
[`src/protocol.rs`](../src/protocol.rs)).

| Version | Changes |
|---|---|
| 1 | First design: descriptors passed for every `run`. Never released. |
| 2 | Data frames and per-channel credit for `run` with redaction (stdin credit granted when the command starts); `add.generate`, `change_password`, `backup`, `reveal.notes`, `status.audit_log`. |
| 3 | Every error other than `outcome_unknown` is definite: the vault file was not changed and no command was started (see [Errors](#errors)); a save that fails after replacing the file is `outcome_unknown`. `status.agent_executable`, `status.agent_executable_id`, `status.agent_executable_replaced`. Added later, optional: `status.dialogs`, `reveal.purpose`. |

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

### Reveal

```json
{"type": "reveal", "name": "8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f", "notes": false, "purpose": "copy"}
```

`purpose` says what the client will do with the value:

| `purpose` | Meaning | Dialog asks | Audit `detail` |
|---|---|---|---|
| absent | The client prints it (`rusthorse reveal`). | "Reveal the value of an entry?" | `value` |
| `"show"` | It shows the value in its own window for a short time. | "Show the value of an entry on screen?" | `value, to show` |
| `"copy"` | It puts the value on the clipboard for one paste, then clears it. | "Copy the value of an entry to the clipboard?" | `value, to copy to the clipboard` |

(`notes` instead of `value` with `"notes": true`.) The purpose is the
client's own statement: the agent cannot enforce it, the dialog labels it
"Stated purpose (unverified)", and its warnings hold whatever the client
does. An approval for one purpose is never remembered and never reused for
another. The field was added within protocol 3: clients leave it out when
they have no purpose to state, and an agent that predates it ignores it and
shows the wording for printing.

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
| `exited` | `code` (integer or `null`), `signal` (integer or `null`); exactly one is set — a client treats an answer with neither as an unknown outcome |
| `error` | `code` (see [Errors](#errors)), `message` (string) |

### StatusInfo

```json
{
  "type": "status",
  "protocol_version": 3,
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
  "dialogs": "/home/me/.cargo/bin/rusthorse-dialog"
}
```

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
| `outcome_unknown` | The request may have taken effect, but the agent cannot confirm it: a `run` command started but its result could not be determined, or a change was written to the vault file but the file's directory could not be synced, so it may not survive a crash (the vault is then locked; unlocking reads what the file holds). Do not simply retry. |
| `internal` | Anything else, including an unwritable audit log or a save that failed before the file was replaced (after which the vault is locked). |

**Every error other than `outcome_unknown` means that the vault file was not
changed and no command was started.** (The audit log may record the attempt,
the vault may have been locked, and a `backup` whose copy does not verify
leaves that copy, which the message names.) A client that sends a request
with effects — `add`, `import`, `edit`, `remove`, `change_password`,
`backup`, `run` — and gets no answer, or one it cannot parse, must likewise
treat the outcome as unknown.

## Compatibility

- Within a protocol version, new optional request fields, new response
  fields and new error codes may be added. Clients must ignore unknown
  response fields and treat an unknown error code like `outcome_unknown`.
- Removing or changing the meaning of a field or of an error code —
  including what an error guarantees about the request's effects — or
  changing framing, bumps `PROTOCOL_VERSION`.
