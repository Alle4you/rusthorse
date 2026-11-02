# 0008. Entry kinds, and an API key's endpoint for `run`

- Status: Proposed
- Date: 2026-11-01

## Context

Every entry has the same fields: username, URL, host, port, tags and notes,
next to its value. They suit a router or a server well, but the owner,
storing an API key in the manager, found a form of Host and Port rows that
mean nothing for it, and no hint that the URL is where the API lives. Tags
could say "this is an API key", but tags are free text for people (`prod`,
`client-x`): a program cannot rely on them, and they say nothing about what
each field means.

An API key also needs its endpoint at run time. Programs read it from a
variable (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`), and `rusthorse run` put
only the value in the environment: the endpoint had to be typed again in the
shell, though the vault already held it.

Constraints: the file must stay a plain KDBX4 file that KeePassXC opens and
shows sensibly ([ADR 0001](0001-kdbx4-storage.md)); metadata is readable
without approval, values are not ([threat model L6](../threat-model.md));
nothing in the vault may grant or widen access by being labelled.

## Decision

### 1. A kind per entry

An entry may have one **kind**: `api-key`, `login`, `server` or `device`. An
entry without one is of no particular kind ("Other"), which is what every
existing entry is.

| Kind | For | Fields a form offers | The URL is called |
|---|---|---|---|
| `api-key` | A key or token for an API | Username, URL | Endpoint URL |
| `login` | A sign-in to a website or web console | Username, URL | URL |
| `server` | A server reached by host and port (SSH, a database, …) | Username, Host, Port | — |
| `device` | A device such as a router or a camera | Username, URL, Host | Admin page |
| (none) | Anything else | all | URL |

The kind is **presentation only**. It decides which fields a form offers and
how they are labelled, and it is shown with the entry. No policy reads it: it
grants nothing, restricts nothing, and is not checked against the other
fields. A form never hides a field that has a value, whatever the kind says,
so a kind can neither hide nor drop data.

The KeePass `URL` field keeps holding the address — the endpoint of an API
key, the admin page of a device — so that KeePassXC and other clients see it
where they expect it, and `rusthorse open` keeps working.

### 2. Storage

The kind is stored in the custom KDBX field **`Kind`**, unprotected, as the
text above (`api-key`). KeePassXC shows it as an attribute. When reading,
surrounding spaces and letter case are ignored, since a person may have typed
it in another client. A `Kind` field with any other text is not a kind: the
entry has none, and `Kind` is listed among the other fields (name only), so
that nothing is silently ignored. A `Kind` field the file marks as protected
is withheld, like any protected metadata field. Setting a kind in Rusthorse
replaces whatever `Kind` held; removing it deletes the field.

The name is plain, like `Host` and `Port` before it, rather than prefixed
(`Rusthorse.Kind`): it reads well in KeePassXC, and a foreign value is never
misread — only the four exact words count.

### 3. Protocol 5

`kind` is a new optional field of `EntryFields` (in `NewEntry`, `EntryInfo`),
of `EntryChanges`, and a new value of `EntryChanges.clear`. An agent of
protocol 4 would ignore it without a word, and a client could believe a kind
was stored when it was not, so the protocol version becomes **5**; clients
refuse an agent of another version.

### 4. The CLI

`add --kind KIND` and `edit --kind KIND` set it; `--kind other` and
`--clear kind` remove it. `show` prints it; `list --kind KIND` filters by it
(`other` keeps the entries without one), so that an AI agent can start with
`rusthorse list --kind api-key`.

### 5. `run --url VAR=ENTRY`

`run` gains `--url VAR=ENTRY`: the command also gets the entry's URL in
variable `VAR`. The client reads the URL from the entry's metadata (a `show`
request, which needs no approval) and adds `VAR=URL` to the environment it
sends with the run request — exactly what typing `VAR=https://… rusthorse
run …` does. The agent needs no change for it.

The URL is not a secret: it is not redacted, and the approval dialog does not
list it any more than it lists the rest of the requester's environment.
`--url` is refused before anything is asked when the entry has no URL (or
the file marks it protected), when `VAR` is already the variable of a
secret, and when `VAR` is one of the variables that change how programs start
(`LD_*`, the risky list).

### 6. The manager

The entry form starts with a Kind row and shows the fields of that kind; the
details call the URL by its kind's name and show the kind under the entry's
name. For an API key with an endpoint, the command snippet passes the endpoint
too, in a variable named after the key's (`OPENAI_API_KEY` →
`OPENAI_BASE_URL`, which the OpenAI and Anthropic libraries read; `NAME_URL`
otherwise), one option per line:

```sh
rusthorse run OPENAI_API_KEY=<uuid> \
  --url OPENAI_BASE_URL=<uuid> \
  -- your-command
```

## Alternatives considered

- **Tags only** (a tag `api`). Free text that a person may also use for
  other things; a program cannot rely on it, and it cannot rename a field.
  Rejected.
- **A field per purpose** (a new `Endpoint` custom field next to `URL`). Two
  addresses for one thing, and KeePassXC users would not find the endpoint
  where they look. Rejected: the URL field already means "where this
  credential is used".
- **KeePass 2 entry templates** (`_etm_template_uuid`, pointing to a template
  entry). Heavier — template entries in a hidden group — and KeePassXC does
  not use them. Rejected for now; the kind can be mapped to templates later if
  someone needs it.
- **Have the agent resolve `--url`** (a new field of the run request, listed
  in the dialog). It would show the endpoint in the dialog, but the
  requester's environment already sets any variable it likes, so a listed
  endpoint would suggest a control that does not exist. The real gap is the
  general one: the dialog lists no variable that redirects where a program
  sends its credentials (see Consequences). Rejected in favour of a
  client-side option and fixing that gap for every variable.
- **More kinds** (database, SSH key, certificate, note). They can be added
  later — each is a new word in the same field, under a protocol bump. Four
  cover the entries the owner has today.

## Consequences

- Forms fit what an entry is; an API key's endpoint is labelled as such and
  reaches the program without retyping. AI agents can find API keys by kind.
- Files gain a `Kind` attribute that other KeePass clients show and keep;
  older Rusthorse builds list it as an unknown field.
- Protocol 5: the agent and its clients must be upgraded together (as for
  every protocol change before 1.0).
- The kind is unverified metadata. An entry labelled `api-key` is not more
  trustworthy than another, and nothing may ever base a decision on it
  without a new ADR.
- **Gap made visible, not created:** an approved, well-known program sends a
  key wherever its environment tells it to (`OPENAI_BASE_URL`,
  `HTTPS_PROXY`, …), and the run dialog does not list those variables; the
  requester controls them ([threat model L4](../threat-model.md#l4--approving-a-command-trusts-everything-it-executes)).
  `--url` takes the endpoint from the vault instead of the requester, but
  the dialog does not tell them apart. Listing such variables in the dialog
  is on the [roadmap](../roadmap.md#hardening).
- The endpoint stored with an API key is what the planned
  [credential broker](../roadmap.md#credential-broker-secrets-that-never-enter-the-client)
  could check a destination against; that use needs its own design.
