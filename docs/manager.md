# Rusthorse Manager

`rusthorse-manager` is the window where you see and organise your entries:
names, logins, addresses, groups and tags, and — when you approve it — the
values themselves. It is a client of the Rusthorse agent, exactly like the
`rusthorse` command: it never opens the vault file, never sees your master
password, and every change and every value goes through the agent's own
approval dialog.

This is the first milestone of the manager
([ADR 0007](adr/0007-visual-manager.md), Proposed). It is a pre-release
awaiting an independent review: try it with fake entries first.

## What it does today

| Available | Comes later (ADR 0007) |
|---|---|
| First start: start the agent, create the vault | |
| Status of the agent, including what else locks it; unlock and lock | |
| Browse, search and filter entries by group | Editing notes |
| Create, edit, rename, move and delete entries; generate a random value | |
| Show a value or notes, after approval | Listing and revoking single remembered approvals (M2) |
| Copy a value to the clipboard, after approval | |
| Two commands to copy for an entry: one that gives its value to a program (`rusthorse run`), and a template that gives the program a temporary token through the credential broker instead (`rusthorse run --broker`) | Restore a backup, a safe hand-off to KeePassXC (M3) |
| Import from GNOME Keyring or a `.env` file; the agent reads the values | |
| Verified backup of the vault; change of the master password | |
| The grants of the credential broker: list them, revoke one or all, also while the vault is locked | |
| The history: what the agent recorded in its audit log, newest first, while the vault is unlocked | |
| The agent's settings — auto-lock, remembered approvals, the dialog timeout, locking on suspend and on screen lock — changed with the agent's approval while the vault is unlocked | |

Pages for the later features are in the window already; they say what is
missing and what to do meanwhile. An entry has no broker profile: the run
names where a key goes, and you approve it in the agent's dialog
([ADR 0013](adr/0013-credential-broker.md#scope-amendment-2026-11-04)).

## Before you start

- Nothing else: on a first start the window starts the agent and creates
  the vault ([First start](#first-start)). It never installs or restarts
  anything, and never starts the agent's program itself.
- The Debian package installs it: open **Rusthorse** from the applications
  menu. Building it from source needs Rust 1.92 or later and the GTK 4.12+
  and libadwaita 1.4+ development packages — the same as `rusthorse-dialog`
  ([installation.md](installation.md#optional-visual-manager)).

To try it without installing, from the source tree, when you are at the
desktop and ready to answer dialogs:

```sh
cargo run --locked -p rusthorse-manager
```

## The window

The window has three columns: a sidebar of fixed width, the entry list, and
the details, which take any extra width. It fits a screen 1024 pixels wide
(about 950 at its narrowest, measured with the default font).

- **Sidebar.** The state of the vault (Locked, Unlocked, Unavailable), the
  pages, and one button that unlocks or locks. Under it, when the vault is
  open, the time left before the agent locks it by itself.
- **Entries.** The list, grouped by KeePass group, with a search field and a
  group filter. Search looks at names, UUIDs, groups, logins, URLs, hosts and
  tags — only metadata the manager already has.
- **Details.** The selected entry: its actions (Edit, Delete), the
  **Secret** rows (Value and Notes, each with **Show…** and **Copy…**, and
  the two ways to change the value: **Change the value…** and **Replace
  with a random value…**), the
  **Details** (login, URL, host, port, tags, the names of other fields, the
  UUID), and the two commands that use it (see
  [Give a secret to a program](#give-a-secret-to-a-program)).
  Each row has its name on the left and
  its content on the right (screen readers name the row by it); the details
  can be selected and copied, since none of them is secret. No hyphen is
  added where a long value, URL or command wraps.
- **Bottom line.** The result of the last action, and a spinner while the
  agent is waiting for you to answer one of its dialogs.

Selecting an entry fetches nothing secret. The manager checks the agent's
status every five seconds in the background; that does not count as using
the vault, so it never postpones the automatic lock.

## First start

What the window shows depends on what is missing
([ADR 0011](adr/0011-first-start-from-the-manager.md)):

- **Not running** in the sidebar, and "The agent is not running": nothing
  answers on the agent's socket — after installing the package, the agent
  starts only at your next login. **Start agent** asks systemd to start the
  service (`systemctl --user start rusthorse-agent.service`), so the agent
  runs outside the manager, as at login. If systemctl fails, the window
  shows why (one that has not finished after 30 seconds is stopped); a source installation needs the service file of the
  [installation guide](installation.md#2-run-the-agent-as-a-systemd-user-service).
- **No vault**, and "Create your vault" with the file's path: **Create
  vault…** makes the agent ask you, in its own dialog, to choose the master
  password, then to type it again. The manager never sees it. Choose a long
  passphrase and keep it somewhere safe: it cannot be recovered. The vault
  is then open, with no entries. Cancelling either dialog creates nothing.

To use an existing KeePass file instead of creating one, point the agent at
it before the first start ([installation guide](installation.md#using-an-existing-keepass-database-instead)).

## Everyday tasks

### Unlock and lock

**Unlock** makes the agent ask for the master password in its own dialog.
**Lock now** makes the agent forget the decrypted vault and every remembered
approval, and ends every grant of the credential broker (see
[Grants](#grants-of-the-credential-broker)); commands already running keep
the values they were given, but a token stops working. Closing
the manager does **not** lock the vault. The agent itself also locks it when
the screen locks or the computer suspends, whether the manager is open or
not; the Status page shows what it watches ("Also locks on"), see
[ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md). Those automatic
locks end a grant only if its run asked for it
(`rusthorse run --broker-locks end`).

If the vault is locked by something else — the agent's idle timer,
`rusthorse lock` — the manager notices at its next check (every five
seconds, also while one of the agent's dialogs waits for you) and clears
what it shows; a value that arrives after such a lock is neither shown nor
copied. (A value you already copied stays on the clipboard: see
[Copy a value](#copy-a-value).) If you unlock with the CLI, the list appears by
itself.

### Create an entry

**New entry** opens a form for the kind, name, group, username, URL, host,
port and tags. These are metadata, not secrets: never type a secret in them.

The **Kind** row says what the entry is for, and the form offers the fields
that kind uses:

| Kind | Fields offered | The URL is called |
|---|---|---|
| API key | Username, URL | Endpoint URL — e.g. `https://api.openai.com/v1` |
| Website login | Username, URL | URL |
| Server | Username, Host, Port | — |
| Device | Username, URL, Host | Admin page |
| Other | all of them | URL |

A field that already has a value stays in the form whatever the kind, so
changing the kind never hides or removes anything. For an entry that needs
one more field — an API key reached through a host and port, say — turn on
**Show all fields**: every field appears and the kind stays as it is. The
switch is not stored; the form always opens with it off. The kind is stored in the
vault (the KeePass field `Kind`) and shown under the entry's name; see
[ADR 0008](adr/0008-entry-kinds.md). Tags stay free, for projects or
environments (`prod`, `test`) and for search.

Under **Value**, choose how the value is made; every choice is in view,
one row each:

- **Type the value** (chosen at first) — after you click *Send to agent*,
  the agent's own password-style dialog asks for it;
- **Generate a random value** — 32 letters and digits, generated by the
  agent; the manager never receives it.

### Change the value

The **Secret** section has a row for each way to change the value:

- **Change the value…** opens the agent's dialog for the new value at once:
  type it there and click *Save*. A change of the value alone asks for no
  approval before that dialog, as with `rusthorse edit NAME --value`; the
  dialog names the entry, and cancelling it changes nothing.
- **Replace with a random value…** asks for your approval, and the agent
  generates 32 letters and digits that nobody sees. Change it at the
  provider too.

Either way the previous value stays in the entry's KeePass history, and a
shown value is hidden.

### Edit, rename, move, delete

**Edit** sends only the fields you changed, after the agent's approval.
Emptying a field removes it. Renaming keeps the entry's UUID and its KeePass
history. A field the file marks as *protected* is withheld from the manager
and cannot be edited here. The form's **Value** rows keep the current value
unless you choose **Type a new value** or **Generate a random value**. With
other changes, the agent asks for your approval of all of them first, then,
for a typed value, for the value; **Type a new value** alone opens the
agent's dialog for the value at once, like **Change the value…**. Choosing
another **Group** moves the entry (see [Choose a group](#choose-a-group)).
Any change to an entry — its value, name, group or fields — ends its grants
of the credential broker, if it has any; the **Edit** form says so.
**Delete** removes the entry and its history from the vault — it does not
revoke the credential at its provider.

### Choose a group

The form's **Group** is a list, so that a typo does not make a new group
(names are case-sensitive: `home` and `Home` are two groups). It offers
**No group** (the top level), every group that holds an entry and the groups
above it — `home/routers` also brings `home` — and, last, **New group…**,
which opens a row for a path such as `home/firewalls`: `/` separates the
groups, and the ones that do not exist yet are created inside the ones that
do. Spaces around each name and empty names are left out, so
` home / firewalls ` is `home/firewalls`. A name follows the rules for an
entry's name (at most 128 characters, no control or invisible characters):
the form says which rule a name breaks before it sends anything, and warns
when a new path differs from an existing group only in case. A group that
holds no entry, and has none in the groups below it, is not in the list;
type its path after **New group…**.

A new entry starts in the group the entry list is filtered on, or in **No
group**. To **move** an entry, choose another group in **Edit**; **No
group** moves it to the top level. Left as it is, the list moves nothing,
even for a group named by another KeePass client with spaces or a `/` in its
name. A group chosen or typed is sent, and the agent decides whether it is a
move by the group itself: a group named `Work/Servers` by another client is
not the nested `Work` → `Servers`, though both read the same, and the group
the entry is already in moves nothing. The agent's approval dialog shows the
destination as a path from the top and says which group it is —
`/home/routers (existing group 8d2f6c1e-5b7a-4c3e-9f10-2a4b6c8d0e12)`, by its
whole UUID, or what it creates, `/home/firewalls (creates firewalls in /home,
group 1a2b3c4d-6e7f-4a8b-9c0d-e1f2a3b4c5d6)` — or `/ (the top level)`. A
path through two groups of the same name side by side is refused, since
which one is meant cannot be told. A move keeps the entry's UUID, so the
commands of the details ([Give a secret to a program](#give-a-secret-to-a-program)),
which name the entry by UUID, still work; a command that names it by its
old `Group/Name` path no longer finds it. The agent refuses to move an entry
into the recycle bin; use **Delete** to remove it.

### Give a secret to a program

The details of an entry end with two commands, each in a card of its own
with its **Copy** button. Both name the entry by its UUID, so a rename or a
duplicate title elsewhere cannot make them point to another entry, and
neither holds a secret: copying them is safe. Nothing in them comes from the
entry's kind, its URL or its other fields, and nothing is stored with the
entry.

**Give the value to a command** gives the program the value:

```sh
rusthorse run OPENAI_API_KEY=8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f -- your-command
```

Replace `your-command`. After your approval the program receives the value
in that environment variable and its output is redacted. The variable takes
the entry's name when that is a valid variable name, `SECRET` otherwise. If
your program also needs the entry's URL, add `--url VAR=ENTRY` yourself (see
the [CLI reference](cli.md)); the URL is not a secret, and it is not
redacted. **This is the way to give an AI agent a secret** when the broker
cannot serve it: the agent never sees the value, though the program it runs
does.

**Give a token to a command, through the broker** is a template for the
credential broker ([ADR 0013](adr/0013-credential-broker.md)):

```sh
rusthorse run \
  --broker TOKEN_VAR=8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f@https://HOST/BASE_PATH \
  --url BASE_URL_VAR=8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f \
  -- your-command
```

Fill it in before you run it:

- `HOST`: the host of the destination, the API your program talks to, in
  lowercase, with `:PORT` if it needs one. `BASE_PATH`: the path your
  program's base URL needs after the host, such as `v1`; or remove
  `/BASE_PATH`. (A `BASE_PATH` left in place is taken as that path.)
- `TOKEN_VAR`: the variable your program reads its key from;
  `BASE_URL_VAR`: the one it reads its base URL from.
- `your-command`: the program.

Until its destination is filled in, `rusthorse run` refuses the command:
`https://HOST/BASE_PATH` is no destination, since a host name is written in
lowercase.

After your approval the program gets a temporary token in the first
variable — never the key — and the broker's local address
(`http://127.0.0.1:PORT` and the base path) in the second; its output is
redacted. The program presents the token as it would present the key, in a
request header (`Authorization: Bearer TOKEN`, `x-api-key: TOKEN`, …), and
the broker puts the key in its place, only in requests to the destination's
origin — its scheme, host and port — at any path there. That origin is what
the agent's dialog shows you to approve; the base path only sets up the
program's base URL and is not a limit. The token stops working when the
command ends; meanwhile its grant is on the [Grants
page](#grants-of-the-credential-broker). A program that encodes the token
or derives its credential from it, or an API that signs its requests with
the key or takes it in the URL or the body, cannot be used through the
broker: give the program the value with the first command. Options of
`run` set the grant's request limit, lifetime and automatic locks;
`rusthorse guide ai` and the [CLI reference](cli.md) say more.

An entry that phase 1 of the broker gave a profile keeps it, as a custom
field named `Rusthorse.Broker`: the details list it by name among the other
fields, like any other, and Rusthorse never interprets it.

### Grants of the credential broker

The **Grants** page lists the grants in use: one for each entry that a command
started with `rusthorse run --broker` uses through the broker. For each, under
its ID: the entry; its **Approved origin**, the scheme, host and port the run
named and you approved, where the broker may send the key at any path; apart
from it, its **Base path** when the run named one, which sets up the
program's base URL and is not a limit; the command, who asked for it
(process names, which any program chooses: unverified, as in the agent's
dialogs), the variable that holds its token, its state, when it started, when
it ends at the latest (its maximum lifetime, in whole minutes rounded up), the
requests admitted (of the limit, if there is one) and those in flight now,
whether its destination refused the key (**Key refused**, below), and
whether the automatic locks end it. Never the token: the agent does not send
it. The states are *Starting*, while the run it belongs to is prepared (no
request is admitted yet); *Active*; *Exhausted*, when its request limit is
reached (requests already admitted finish); and *Revoked*, when it has ended —
normally it stays listed until its command ends, and its broker refuses every
request meanwhile. If that broker exits sooner, the grant disappears from the
agent's list. A state the manager does not know is shown as the agent sends
it. The grants are listed when you open the page, after a revocation, and
while the page is shown every five seconds and after each of your requests to
the agent (Lock now ends every grant; a change to an entry ends its grants).

A refresh keeps each grant where it was, with the same **Revoke** button: a
new grant comes last, and only the texts that changed are redrawn, so a
selection and the keyboard focus stay. A grant the agent no longer lists has
ended; while
the page is shown it stays where it was, dimmed and marked *Ended*, with
what was last listed and nothing to revoke, so that the grants below it do
not move up and put another grant's **Revoke** button under the pointer. It
goes when you leave the page. The line above the grants counts those that
ended while the page was shown.

**Key refused** counts the grant's requests that its destination answered
with `401 Unauthorized`: the destination did not accept the entry's value,
which the broker sent with them — a wrong, revoked or expired key, for
example, or one of another kind than the destination expects. It says *No*
while there are none, and *Not reported* with an agent that does not count
them. When there are some, it says how many, in the warning colour, and what
to do: if the value is wrong, revoked, or not of the kind the destination
expects, replace it with **Change the value…** in the entry's details. That
ends the entry's grants, this one included; run the command again for a
grant that uses the new value. What the count leaves out:

- Only requests the broker forwarded are counted. The broker's own `401`,
  for a request without the grant's token, is not: such a request never
  reaches the destination.
- A destination that answers a key it does not accept with another status
  (`403`, say) is not detected.
- The count is the one of the page's last listing, which names only the
  grants the agent still has. The agent stops listing a grant when its
  command ends; the page keeps an ended grant, with the count last listed,
  only if it listed that grant while it was shown, and only until you leave
  the page. So the page may never show the count of a short command, or of
  one that ended while the page was not shown: `rusthorse run` notes such
  answers on standard error when the command ends, and the `broker_request`
  records of `rusthorse audit` show each request's status.

**Revoke** ends one grant, **Revoke all** every grant, at once and without a
dialog, as **Lock now** does: the token stops working and the open requests
and streams are closed; the command keeps running, without that access. A
request the broker had already sent may still take effect at its
destination; the audit log records its outcome as unknown. The manager sends
a revocation at once, even while one of the agent's dialogs is waiting for
you, and one revocation at a time: the buttons are off until the agent
answers. The agent's answer appears at the bottom of the window, as for
other actions, and the page lists the grants again.

The page works while the vault is locked, and then says so: unless its run
asked otherwise (`rusthorse run --broker-locks end`), a grant is not ended by
the automatic locks — the screen locking, suspend, the idle timeout — and
keeps working while the vault is locked, until it ends. **Lock now** ends
every grant.

When the grants cannot be listed, the page says why in place of the list,
and **Revoke all** stays available: it may work all the same, and it only
takes away. A listing or a revocation takes 30 seconds at most, from
reaching the agent to its answer; after that the page says so, and can be
used again. Since a revocation only takes away, trying it again is safe.

### History

The **History** page shows the agent's audit log: what the agent recorded —
approvals and denials (and dialogs nobody answered), unlocks and locks, the
commands it started and how they ended, the credential broker's grants and
requests — newest first. Each record shows its time, action and outcome, in
green when you approved, in the warning colour when you denied, cancelled
or did not answer; then what else it says: the entries, the command line
and directory, the grant, the detail, and the requester (process names,
unverified). Values are never recorded; a command line holds whatever the
requester put in it.

The manager reads the file the agent names in its status ("Read from …"),
as `rusthorse audit` reads it in a terminal; it asks the agent nothing for
it, and you nothing. It reads 200 records at a time, from at most 256 KiB of
the file: **Load older** reads the records before them, **Refresh** reads
the newest again. The list (**All records**, **Allowed**, **Denied or not
answered**, **Unlock and lock**, **Credential broker**) chooses among the
records read. Lines that are not records are counted and left out. A line
longer than 256 KiB stops the reading there; in a terminal, `rusthorse audit
-n COUNT` reads past it. If, since it was read, the file was rotated or
truncated, or the line where **Load older** would go on changed, the page
says so and offers no Load older: **Refresh** reads it again from its end.
Other changes to lines already read go unnoticed.

The history is shown only while the vault is unlocked, and forgotten when
it locks, like the entry list: at once on **Lock now**, and for a lock made
elsewhere when the manager sees it, at its next status check (every five
seconds). The log names your entries and the commands that used them. That keeps it off the screen, not out of reach:
any program of yours can read the file, and write to it
([threat model L13](threat-model.md#l13--the-audit-log-is-not-tamper-proof)),
so it is a record of what happened, not proof. Times are when a record was
written — for an approval, after you answered — by the system clock.
Everything a record says is drawn as plain text, with control and invisible
characters shown as `\u{…}`, as in the agent's dialogs.

### Show a value

**Show…** in the Value row (or in the Notes row) asks the agent; its dialog says
"Show the value of an entry on screen?". After you allow it, the value
appears in a small window:

- as plain text in the monospace font, which tells `0` from `O` and `l`
  from `1`, wrapped where the line ends, with no hyphen added at the break
  and no grouping. Characters that the agent's dialogs would not draw appear
  as `\u{…}` escapes;
- not selectable, so that it never lands in the X11 primary selection;
- for 30 seconds at most, and it closes as soon as the window loses focus,
  when you click **Hide now**, or when the vault is locked.

Its **Copy** button copies the value you are looking at — exactly, even
where the window shows an escape — without asking again; the agent's dialog
for Show told you that you could. What happens to a copied value is
explained in the next section.

Anyone who can see your screen, and other programs of your desktop session,
can see a shown value. Never ask an AI agent to use Show.

### Copy a value

For a key you need to paste into a web console, a sign-in form or a
program's password prompt, use **Copy…** in the Value row (or **Copy** in
the Show window).

1. The agent asks "**Copy the value of an entry to the clipboard?**".
2. After you allow it, the value is on the clipboard like any text you copy:
   paste it where it belongs, as many times as you need.

> **Note: a copied value stays on the clipboard until you copy something
> else, and a clipboard history may keep it even after that.** Cinnamon
> keeps its own copy of whatever is on the clipboard — it takes it the
> moment you copy and puts it back if the program that copied it closes
> (GNOME probably does the same; not verified) — and clipboard managers (CopyQ, Klipper, GPaste, …) may keep a list of
> past copies. Rusthorse cannot take a copied value back. When you are done,
> copy something harmless to replace it, and delete it from your clipboard
> history if you use one.

Other programs of your desktop session can read the clipboard, and a value
pasted into the wrong window is gone — a chat with an AI sends it to the
AI's provider. Paste only where the value belongs. If a value may have gone
somewhere it should not, rotate it (**Replace with a random value…**, then update
it at the provider).

Why no stricter Copy: a first version gave the value to a single paste and
cleared it after 20 seconds, but Cinnamon takes every copy at once (so the
single paste was always the desktop's) and restores it later anyway; and a
user who cannot copy a long key will photograph it, which is worse. See
[ADR 0007](adr/0007-visual-manager.md#copy).

### Import from GNOME Keyring or a .env file

**Import & backup → From GNOME Keyring…** or **From a .env file…** (with the
vault unlocked, so that the window can tell which names exist). The agent
asks you before it shows this window the keyring's items or the file's
names; the window then lists them, with what each would become:

- **GNOME Keyring**: each item's label and attributes, never its secret.
  **Names from** chooses where the entry names come from — the label or an
  attribute (for items of a tool that names them by attribute, choose that
  attribute). Type in **Filter** to show some items only, **Tick shown** to
  tick them. A locked item cannot be ticked: unlock the keyring first.
- **A .env file**: the variable names, and an optional **Prefix**.
- For both: a **Tag** for the new entries (`imported` unless you change it),
  and **Replace entries that already exist** (off: they are skipped).
  Replacing an entry ends its grants of the credential broker, if it has
  any; its other fields stay, as other KeePass clients keep them. Each
  ticked name is marked new, existing, not allowed or repeated; **Import**
  stays off while a ticked one cannot be imported.

**Import N** sends the names in batches, one dialog each: the agent reads
the values itself — from the keyring or the file — and its dialog says
where; for keyring items, each entry next to the item it comes from. The window never holds a value. When a batch fails, the message says
which batches were imported and whether that one was not imported or may
have been (look at the entries before importing again). Follow the
[migration steps](installation.md#migrating-existing-secrets): one item
first, use each entry, then delete the originals.

### Back up the vault

**Import & backup → Create verified backup…** asks for a new absolute path
(`~` is not expanded; an existing file is never replaced). The agent copies
the encrypted vault and checks that the copy opens with the current master
password. A copy whose check fails is left in place, and the message names
it. Keep backups somewhere else as well.

To look at the vault in KeePassXC, open a **backup copy**: locking is not
exclusive — another program can ask the agent to unlock the live vault while
KeePassXC writes it ([threat model L15](threat-model.md)).

### Agent settings

**Settings → Agent settings** shows the agent's five settings, each with
where it comes from (its default, the settings file, or an option on the
agent's command line), and the settings file's path:

- **Lock after inactivity**: never, or from a minute to 24 hours (default 15
  minutes);
- **Remembered approvals**: how long "Allow for …" lasts in the dialogs of
  `rusthorse run`, off by default — read
  [ADR 0005](adr/0005-remembered-approvals-opt-in.md) before turning it on;
- **Dialog timeout**: how long the agent's dialogs wait for an answer (default
  2 minutes);
- **Lock on suspend** and **Lock on screen lock** (both on by default).

Choose new values, then **Apply…**; **Revert** puts back what is in effect.
Apply works only while the vault is unlocked. The agent shows each old and
new value in its own dialog, with a warning for each change that protects
less; if you approve, it saves the settings file, applies the change at once
and forgets remembered approvals. A shorter auto-lock counts from the last
time a secret was used, so it may lock the vault right away. A setting set by
an option on the agent's command line (`--remember`, say) cannot be changed
here: remove the option from the service (`systemctl --user edit
rusthorse-agent`) and restart the agent. The page keeps your choice while
you make it, until the agent reports other settings.

The settings file is `~/.config/rusthorse/agent.toml`; you can also edit it
while the agent is stopped ([cli.md](cli.md#settings)). Any program of yours
can edit that file and restart the agent: the dialog guards the changes made
through the agent, not the file.

### Change the master password

**Settings → Change master password…**: the agent asks for the current and
the new password in its own dialogs. The manager never receives them.

## When something goes wrong

| What you see | What it means and what to do |
|---|---|
| **Not running** in the sidebar | Nothing listens on the agent's socket. Click **Start agent** ([First start](#first-start)). |
| **Unavailable** in the sidebar | The agent does not answer as it should (it is busy, or something else listens on its socket). `rusthorse status` in a terminal says why; `systemctl --user status rusthorse-agent` shows the service. |
| "The agent could not be started (…)" | `systemctl --user start rusthorse-agent.service` failed; its message is in the parentheses. Without the package, install the service file as the installation guide says. |
| "Outcome unknown. The operation may have taken effect…" | The answer to a change was lost. The change may have happened: refresh and look before trying again. Never repeat it blindly. |
| A master-password dialog you did not expect | The vault locked between two of the manager's requests (for example the idle timer fired just then), and listing needs it open. Answer it, or cancel it. |
| A dialog stays open after you closed the manager | Closing the manager does not cancel a dialog the agent already shows: answer it there (Deny or Cancel). |
| "Incompatible agent protocol" | The agent and the manager come from different versions. Upgrade both and restart the agent yourself. |
| A message in red on the Grants page, in place of the list | The agent could not list the grants, or did not answer within 30 seconds (for example "No complete answer arrived from the agent"); the message says why. **Revoke all** still tries, and **Lock now** ends every grant. |
| **Key refused** on the Grants page, in the warning colour ("… answered 401 Unauthorized …") | The grant's destination did not accept the entry's value. If it is wrong, revoked, or not of the kind the destination expects, replace it with **Change the value…** in the entry's details, which ends the entry's grants, and run the command again. [Grants](#grants-of-the-credential-broker) says what the count leaves out. |
| "Restart needed" on the Status page | The agent's program file was replaced after it started (an upgrade). Restart the service before using dialogs. |
| "The vault was locked while the agent was asking you, so the value was neither shown nor copied" | The manager saw the vault locked while a Show or Copy was waiting — for example, the vault locked itself just before you clicked and the agent asked for the master password first. For safety, a value that arrives after a lock is dropped. Your approval was used up; click Show or Copy again. |

## Security notes

- The manager is non-dumpable and keeps values in buffers that are wiped;
  GTK's own copies (labels) are emptied when no longer needed but cannot be
  wiped reliably, and on X11 other programs of your session can capture
  windows. A copied value is out of Rusthorse's hands (see the note above).
- Show and Copy are for you at the desktop. An AI agent uses
  `rusthorse run`, which keeps the value inside the approved command — or,
  better, `rusthorse run --broker`, which gives the command a token instead.
- The Grants page and the two commands of an entry hold no secret: the
  agent sends neither a token nor a value with the grants, and the commands
  name the entry by its UUID. What a requester chose — the command, the
  process names — is drawn as plain text, through the same character filter
  as the agent's dialogs.
- The full analysis is in [threat model L14](threat-model.md#l14--some-flows-move-values-through-the-client)
  and [ADR 0007](adr/0007-visual-manager.md#2-show-copy-and-memory).

## For developers: tests

`cargo test -p rusthorse-manager` runs logic tests, and runs its widget test
again under `xvfb-run` with a private D-Bus session, a UTF-8 locale and a
private runtime directory — never on your display. Nothing can be activated
on that session, and GVfs, the accessibility bus, the settings portal and
Mesa's shader cache are turned off, so that no desktop service starts for
the test, outlives it or writes into its directory. The widget test starts a
real agent in the test process, on a fake vault, socket and audit log, with
scripted dialogs; it drives the window, reads the clipboard with `xclip` as
another program would, and focuses windows with `xdotool`. Missing tools
(`xvfb-run`, `dbus-run-session`, `xclip`, `xdotool`) make it fail rather than
pass untested. The widget test also checks that the History page shows the
unlock that agent recorded. The Grants page, the History page and an entry's
two commands are tested against a fake agent in the test process instead —
a test agent cannot start a broker, and the history needs a log written for
the test: it answers from a script, records every request, and can hold an
answer back. Set `MANAGER_TEST_SCREENSHOTS=/some/dir` to save
screenshots of the window in the light and dark styles, of the Show window,
of the Grants page (also with a grant that ended while it was shown, and
with a key the destination refused), of the History page and of an entry's
two commands.
