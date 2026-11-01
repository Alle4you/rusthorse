# 0007. A visual manager that remains a client of the agent

- Status: Proposed
- Date: 2026-11-01

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
values, approved Show of password/notes, a safely quoted UUID-based command
snippet, password change and verified backup through existing requests.
Existing groups cannot be changed by `edit`; M1 says so instead of emulating
a move with delete/add (which would lose identity/history). Notes can be
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
is no synchronous push notification of external locks in protocol 3.

### 2. Show, Copy and memory

**Show is included, secret Copy is not.** Each Show sends a fresh `reveal`
request (password or notes) and waits for the agent's non-rememberable
approval. The result appears in a non-selectable, plain-text window for at
most 30 seconds, cleared on close/focus loss, local lock or observed external
lock. It is not cached in entry models. Rust-owned value buffers are
zeroizing; GTK, accessibility, display and allocator copies cannot be
reliably wiped. Disable core dumps and mark the manager non-dumpable before
GTK starts; this does not protect its screen from X11 or its accessibility
tree. A reveal authorizes this extra exposure, as it does with the CLI.

X11 clipboard managers can retain values forever, and clearing the clipboard
does not recall those copies. A timer therefore cannot justify a promise of
safe secret Copy. M1 copies **only the command snippet**, containing a UUID,
never a secret. There is no selectable secret label that quietly exports to
the primary selection. A future opt-in secret Copy requires an explicit
agent-side purpose/warning, ownership-aware best-effort clearing, and wording
that clipboard history remains outside our control, on Wayland too.

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

A plain `lock` does not reserve the vault: another requester can unlock it.
Therefore automatic KeePassXC handoff waits for an agent maintenance mode
that refuses unlock/writes until explicitly released, with recovery after a
manager crash. It must still document non-cooperating external writers (L15).
M1 recommends opening a **backup copy** in KeePassXC and offers no automatic
launch of the live vault. The manager never writes a KDBX itself.

### 7. Protocol, packaging and tests

M1 uses existing protocol 3 without changing any request/response. Future
requests in M2/M3 need documented capabilities or a version bump before a
new client uses them. Changes to meaning, framing or error guarantees always
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
- Use a clipboard timer as a security boundary: cannot revoke clipboard
  histories or copies; explicitly rejected above.

## Consequences

The first milestone is useful but does not reproduce every prototype control.
No persistent settings, grants/history viewer, import UI, restoration,
automatic screen/suspend lock or exclusive KeePassXC handoff is claimed yet.
Before real credentials, the maintainer must review the reveal exposure,
clipboard choice, milestones and manual-lock limitations. ADR and M1 remain
**awaiting independent review**, not Accepted by their implementer.
