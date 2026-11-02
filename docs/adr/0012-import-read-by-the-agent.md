# 0012. Imports are read by the agent, and the manager can start them

- Status: Proposed
- Date: 2026-11-02
- Amends: [ADR 0007](0007-visual-manager.md), section 5 (M3: the manager
  would read the sources itself and send the values).
- Amended: 2026-11-02, after review — nothing of the source before the
  approval, the dialog's item-to-entry rows, items checked unchanged, a
  deadline for the whole keyring operation, multi-line `.env` values.

## Context

`rusthorse import dotenv` and `rusthorse import secret-service` read the
values in the CLI process and send them to the agent in `import` requests.
The approval dialog can then only say "the program that asked supplied
these names and values": a requester could send a value of its own under a
name the human expects (an `OPENAI_API_KEY` that is the requester's key,
with `--replace`), and the dialog could not tell. ADR 0007 planned the same
for the manager (M3): the window would read GNOME Keyring or a `.env` file
and hold the values on their way to the agent.

The maintainer wants to import from the manager — the migration from the
`segredo` tool (GNOME Keyring) is the first real use — and the window should
not be another place that holds secrets.

## Decision

1. **The agent reads the source.** A client names what to import — Secret
   Service items by their D-Bus object path, or a `.env` file by its
   absolute path — and the entry name for each; the agent reads the values
   itself, after approval. No client holds the values. The dialog says where
   they come from, because the agent reads them there: for keyring items,
   one row per entry with the item the agent found at that path (label and
   attributes, or "no such keyring item", or "locked"); for a file, its
   path.
2. **Nothing of the source before the approval.** What the request says by
   itself is checked first (names, a count, an absolute path); everything
   that depends on the source comes after the human allows the import — a
   variable missing from the file, a locked item, a value — so that a
   request does not tell its sender what the keyring or a file holds. Item
   metadata is read before the dialog only to show it to the human. After
   the approval, an item is read only if it is still what the dialog showed
   (same label and attributes), so that the approval covers what is read.
3. **Requests** (protocol 6, not yet released):
   - `keyring_items` → the metadata of the Secret Service's items: object
     path, label, attributes, whether locked. No secret is read.
   - `dotenv_names` (`path`, `prefix`) → the names in the file. The agent
     parses it and drops the values at once.
   - `import_from` (`source`, `tags`, `replace`) → `ok`. The source is
     `keyring` with a list of `{id, name}`, or `dotenv` with `path`,
     `prefix` and the `names` to import. At most 100 entries, one dialog per
     request; clients split larger imports into batches, as the CLI does.
4. **What the agent refuses.** A locked item (unlock the keyring first: a
   keyring prompt would hold the agent's request for as long as nobody
   answers it), an item whose secret is not UTF-8 text, a `.env` path that
   is not absolute, not a regular file or larger than 1 MiB, a name that is
   not in the source, and the usual: invalid or duplicate names. A `.env`
   value in quotes may span several lines; a quote that is never closed
   refuses the whole file, rather than reading the rest of the value as more
   variables. Every call to the Secret Service is bounded (10 seconds), and
   so is the whole operation, connecting and authenticating included (30
   seconds): past it, the agent shuts the connection's socket down, which
   ends it.
5. **The CLI uses the same requests**, so that `rusthorse import` no longer
   holds values either. The `import` request (values from the client) stays
   for other clients; its dialog keeps saying that the requester supplied
   the values.
6. **The manager.** *Import & backup* gets **Import from GNOME Keyring…**
   (the items, which can be filtered and ticked; names from the label or an
   attribute; each name marked new, existing, invalid or repeated) and
   **Import from a .env file…** (a file chooser, an optional prefix, the
   names to tick). Importing sends one `import_from` per batch and
   summarises what was imported, refused and uncertain, as the CLI does.

## Alternatives considered

- **The manager reads the sources (ADR 0007's M3).** Less protocol, but the
  window would hold every imported value, and the dialog could not say where
  the values come from.
- **The agent unlocks locked items.** The keyring's prompt has no time
  limit; the request would wait on it. Unlocking the keyring is one click in
  Seahorse or the keyring's own prompt.
- **One `import_from` that splits itself into several dialogs.** Fewer
  round trips, but one request would then ask several questions, and an
  answer lost halfway would leave its outcome harder to state.

## Consequences

- Any program of the session that reaches the agent can list the keyring's
  item metadata through it. Such a program can already list it, and read
  the secrets too, on the session bus directly; the agent adds nothing to
  what it can learn.
- A `.env` file is read by the agent, as the user: the requester names the
  file, so it cannot make the agent read anything the user could not.
- While the originals stay in GNOME Keyring, any program of the session can
  still read them there. Importing protects nothing until the originals are
  deleted (the guide's migration steps say so).
