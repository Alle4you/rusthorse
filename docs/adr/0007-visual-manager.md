# 0007. A visual manager that remains a client of the agent

- Status: Proposed
- Date: 2026-11-01
- Amended: 2026-11-01 — Copy of a value (section 2), at the maintainer's
  request: without it, long random keys had to be retyped. A first design
  served the value to a single paste; trying it on Cinnamon showed that the
  desktop itself defeats that, and the maintainer chose a plain copy.

## Context

The owner needs to browse, organise and edit entries before entrusting real
credentials to Rusthorse. The approved [HTML prototype](../design/manager/index.html)
defines the visual direction: a sidebar, searchable entry list, details,
ordinary libadwaita cards and explicit actions. It contains fake data and
simulated behaviour, not promises about the implementation. The Abrigo icon
is preserved under `data/icons/hicolor/scalable/apps/`.

## Decision

### 1. Trust boundary and first milestone (M1)

`rusthorse-manager` is a separate GTK 4 + libadwaita client. It never opens,
decrypts or saves a vault, and never asks for the master password. Approval,
unlock and value-entry dialogs remain agent-owned. The manager's metadata
forms are not approval dialogs. It cannot turn a click on Save into an
approval. It connects to `RUSTHORSE_SOCKET` or the usual XDG socket and checks
protocol compatibility before operations. No service is started or restarted.

M1 implements status, explicit unlock/lock, metadata list/search/group
filter, details, create (including group), edit/rename/delete, generated
values, approved Show and Copy of password/notes, a safely
quoted UUID-based command snippet, password change and verified backup
through existing requests.
Existing groups cannot be changed by `edit`; M1 says so instead of emulating
a move with delete/add (which would lose identity/history). (Since protocol
7, `edit.group` moves an entry for real — same UUID, history kept — and the
manager's Edit form uses it.) Notes can be
shown but not edited in M1. Protected metadata is displayed as withheld and
left untouched by forms. Only fields the user changes are sent.

The manager does not embed a command runner in M1: the snippet uses
`rusthorse run SECRET=<uuid> -- your-command` in the terminal/AI shell, keeping
secrets in the approved child and redacting its output as today. No subprocess
shell evaluates entry names. Search is local, over metadata already obtained.

One user operation runs at a time on a worker, never on the GTK thread. A
bounded wait and connection shutdown on window close prevent indefinite
client workers. Closing a window or losing a reply does not prove a pending
change was cancelled: report unknown outcomes, never automatically retry.
Status polling is read-only and does not extend the agent's idle timeout.
Metadata and shown secrets are cleared on observed lock/disconnection; there
is no synchronous push notification of external locks in the protocol.

### 2. Show, Copy and memory

Some uses of a secret need it outside a command: pasting an API key into a
provider's web console or a CI settings page, signing in to a web interface
(a router, an intranet), a graphical program that asks for a password, a
prompt that reads no environment variable (`ssh`, `mysql -p`). A long random
key cannot reasonably be retyped from the screen. So the manager offers two
ways to get a value out — Show and Copy — each after its own approval in the
agent's dialog. They are for the human at the desktop; an AI agent uses
`rusthorse run`, which keeps the value inside the approved command.

#### The stated purpose

`reveal` gains an optional `purpose` field: `show` or `copy`
([protocol.md](../protocol.md#requests)). The agent cannot verify it — the
requester receives the value and can do anything with it — so the dialog
labels it **"Stated purpose (unverified)"** and its explanation says so. The
purpose changes the dialog's title, question and warning, and is written in
the audit record (`value, to copy to the clipboard`), so the log tells a
copy from a display. Without the field (the CLI), nothing changes. The field
came with protocol 4: its meaning for `copy` changed before any release
(from "one paste, then cleared" to a plain copy), so the version was bumped
and a client of protocol 4 refuses an agent that could show the old wording.

#### Show

Each Show sends a fresh `reveal` with purpose `show` and waits for an
approval that is never remembered. The value appears in a window of its own:

- plain text, not selectable, so it never reaches the primary selection;
- as one piece of plain text in the monospace font, wrapped at the line's
  end with no hyphen added, and never split into groups (an earlier version grouped it by four
  characters; with a Copy button next to it, reading it in chunks no longer
  pays for the clutter); characters outside the dialogs' allow-list appear
  as `\u{…}` escapes, as in the agent's dialogs;
- hidden after 30 seconds, when the window loses focus, on close, on a lock
  the manager observes, and before any other request; its labels are emptied
  when it closes;
- with a Copy button that copies the value shown (see Copy below).

It is not cached in entry models. Rust-owned value buffers are zeroizing;
GTK, accessibility, display and allocator copies cannot be reliably wiped.
Disable core dumps and mark the manager non-dumpable before GTK starts; this
does not protect its screen from X11 or its accessibility tree. A reveal
authorizes this extra exposure, as it does with the CLI.

#### Copy

Copy sends a `reveal` with purpose `copy`; the agent's dialog asks "Copy the
value of an entry to the clipboard?" and warns that the value stays on the
clipboard until something else is copied and that a clipboard history may
keep it even after that, that
other programs of the session can read it, and that it must never be pasted
into a chat with an AI. After approval, the manager puts the value on the
clipboard **as plain text, like any copy**: it can be pasted any number of
times and stays until something else is copied. The manager says so after
each copy, and so do the Secret rows and the Help page.

The Show window has a **Copy** button that copies the value it shows,
exactly (escapes undone), without asking again: the `show` dialog says "you
can copy it from there" and warns of the clipboard history. Copying from the
Show window is therefore not a separate entry in the audit log; Copy from
the entry is (`value, to copy to the clipboard`).

**Why not more.** A first version served the value to a **single paste**: a
content provider of its own delivered the text to the first request only,
cleared it after 20 seconds, on lock and at exit, and announced
`x-kde-passwordManagerHint: secret` for clipboard histories. Two reviews
tightened it. Then the maintainer's first try on Cinnamon (Muffin 6.6)
showed what the desktop does with any copy:

- Muffin keeps its own copy of the clipboard (Mutter, which it derives from,
  is understood to do the same in GNOME; not verified): it
  fetches the text **the instant** an application copies — before any paste
  — and ignores `x-kde-passwordManagerHint` (it does not even ask for it).
  The single delivery went to the desktop, and the human's paste came back
  empty, every time.
- When the application that owns the clipboard exits, the desktop puts its
  copy back on the clipboard. Wiping the value inside the manager does not
  reach that copy; only a new owner with no text makes the desktop forget it.
- On X11, GTK 4 cannot deliver `x-kde-passwordManagerHint` at all (it serves
  only formats whose name contains a slash).

So that single-paste design cannot work on Cinnamon. Other protections may
be possible (clearing on a timer, as KeePassXC does), but the maintainer
judged that more would not be worth it: a
user who cannot copy a value will photograph or screenshot it, which is
worse. The protection that matters is that nothing gets a value without the
human's approval in the agent's dialog, and that the human is told where a
copied value goes.

Not chosen, for now: **drag and drop** of the value onto a field (only the
drop target receives it, no clipboard involved — an idea for a later
milestone); **auto-type** into the focused window (KeePassXC's approach;
X11 only, and it can type into the wrong window); the **primary selection**
(filled by any text selection, cleared by none).

### 3. Persistent agent configuration (M2)

Add `$XDG_CONFIG_HOME/rusthorse/agent.toml` (default `~/.config/...`), owned by
the user, mode 0600, parent 0700. Defaults stay remember=0, idle=15 minutes,
dialog=120 seconds. CLI flags override the file and status identifies the
source. M1 has no pretend settings switches.

The agent owns validation and atomic writes for a future `configure`
request; the manager edits through that request, after an agent approval
showing old and new values. Hand editing is permitted while stopped. No file
watcher and no automatic reload: an explicit `reload_config` parses and
validates the whole file, asks approval for changed security settings, then
applies one snapshot. Invalid startup configuration stops startup with an
actionable error; invalid reload keeps the old snapshot. Unknown fields are
errors. Zero disables remembering; disabling idle lock requires an explicit
warning. Bounds must be specified and tested before M2 implementation.
Changing settings clears remembered approvals, bumps generation, and adjusts
the idle deadline conservatively (it does not count as using a secret).

### 4. Remembered approvals and history (M2)

New requests list unexpired grants and revoke a public random grant ID or all
grants. Never expose the full effective environment or a capability token:
those can themselves contain credentials. Return safe metadata (entry UUIDs,
command, directory, expiry); process names remain unverified. Revocation is
atomic with grant consumption, audited, and stops future uses, not commands
already started. Lock remains the M1 way to forget all grants.

History will use a bounded agent request, not a guessed client-side log path.
Page by file identity plus byte offset, cap bytes and records per page, stop
at the last complete JSONL record, and handle rotation/truncation explicitly.
Do not load an unbounded file, hold the audit write lock while rendering, or
claim audit timestamps cannot move backwards. Render command lines as plain
escaped text; they can contain sensitive information the caller supplied.

### 5. Import, backup and restoration (M1/M3)

M1 uses existing `backup`: absolute new destination, no overwrite, agent
verifies the encrypted copy. No backup catalogue is fabricated. A failed
verification can leave an unverified copy; say so. Keep independent copies.

M3 reuses `import`'s readers and batch planning for `.env` and Secret Service.
Preview names/duplicates first; `.env` parsing necessarily reads values even
for a preview, whereas Secret Service discovery can avoid reading values.
Require explicit attributes, begin with one item, retain originals. Values
then pass through zeroizing client buffers only for the chosen import. Each
batch needs agent approval; summarize confirmed, refused and uncertain
batches separately. Never silently retry or replace duplicates.

Restoration needs a new agent-owned `restore` operation and CLI command:
approve source/destination and loss of newer entries, ask for the source
password only in the agent, validate a bounded source snapshot before
replacement, preserve a uniquely named verified pre-restore copy, then use
the atomic-save durability contract. Stop concurrent writes, bump generation,
clear grants and lock. A post-rename fsync failure is `outcome_unknown`.
Do not claim restore is implemented; M1 links to the existing manual procedure.

### 6. Screen lock, suspend and KeePassXC (M2/M3)

Implement lock-on-screen-lock/suspend **in the agent**, so closing the manager
cannot disable it. Observe the session's logind and supported screensaver
D-Bus signals; use a delay inhibitor to lock before suspend where available.
Status must report unavailable backends instead of promising protection.
Test duplicate signals, resume, bus loss and pending unlock cancellation.
(Specified and implemented by [ADR 0009](0009-lock-on-screen-lock-and-suspend.md).)

A plain `lock` does not reserve the vault: another requester can unlock it.
Therefore automatic KeePassXC handoff waits for an agent maintenance mode
that refuses unlock/writes until explicitly released, with recovery after a
manager crash. It must still document non-cooperating external writers (L15).
M1 recommends opening a **backup copy** in KeePassXC and offers no automatic
launch of the live vault. The manager never writes a KDBX itself.

### 7. Protocol, packaging and tests

M1 adds one optional field, `reveal.purpose` (section 2), with protocol 4;
no other request or response changes, and the field is omitted when absent,
so the CLI's requests are unchanged. Future requests in M2/M3 need documented
capabilities or a version bump before a new client uses them. Changes to meaning, framing or error guarantees always
bump `PROTOCOL_VERSION`; new fields are optional and omitted when absent.
All clients preserve definite versus uncertain outcomes, even for unknown
error codes or unexpected response kinds.

`manager/` is a non-default workspace member, Rust 1.92, gtk4 0.11 (`v4_12`)
and libadwaita 0.9 (`v1_4`), like `dialog/`. No new GTK requirement for the
CLI/agent (MSRV 1.89). Install explicitly, with an optional desktop entry and
scalable icon; no autostart and no background service of its own. UI strings,
documentation and code stay in English; respect system styles and theme.

Test request construction, protected-field preservation, UUID targeting,
quoting, error classification and cancellation without GTK. Exercise widgets
only on an isolated Xvfb/session bus with fake paths and a scripted agent.
Mutation checks run on a copy. Policy/protocol changes in later milestones
require allowed and denied end-to-end tests in `tests/agent.rs` as well.

## Alternatives considered

- Embed KeePass decoding: would create another holder of the master password
  and bypass the agent's policy and concurrency checks.
- Launch CLI shell commands from button text: quoting and output parsing are
  unnecessary when the library's protocol types already exist.
- Implement all prototype pages immediately: would hide new policy and
  persistence mechanisms inside a GUI change. Milestones keep them reviewable.
- No Copy at all (the first version of this ADR): long random keys had to be
  retyped, or revealed in a terminal, whose scrollback keeps them, or
  photographed.
- Copy for a single paste, cleared after 20 seconds (built and reviewed,
  then dropped): the desktop's own clipboard manager takes the single paste
  and keeps a copy that it restores at exit; see section 2.
- Copy with a timer that clears the clipboard (KeePassXC's way): it would
  make the desktop forget the value after a while, but histories and other
  programs copy it in the first second, and a cleared clipboard surprises a
  user who copied something else meanwhile; the maintainer preferred a
  predictable plain copy and an honest note.
- A new approval for Copy in the Show window: the user had just approved
  seeing the value, and asking twice looked like a loop. The `show` dialog
  says instead that the value can be copied from there.

## Consequences

The first milestone is useful but does not reproduce every prototype control.
No persistent settings, grants/history viewer, import UI, restoration,
automatic screen/suspend lock or exclusive KeePassXC handoff is claimed yet.
Copy puts a value where other programs and clipboard histories can keep it;
the threat model (L14) records it.
Before real credentials, the maintainer must review the reveal exposure,
the Copy design, milestones and manual-lock limitations. ADR and M1 remain
**awaiting independent review**, not Accepted by their implementer.
