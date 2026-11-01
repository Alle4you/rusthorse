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
| Status of the agent; unlock and lock | Lock when the screen locks or the computer suspends (M2) |
| Browse, search and filter entries by group | Moving an entry to another group; editing notes |
| Create, edit, rename and delete entries; generate a random value | Settings for auto-lock and remembered approvals (M2) |
| Show a value or notes, after approval | Listing and revoking single remembered approvals (M2) |
| Copy a value for a single paste, after approval | A history view of the audit log (M2) |
| The command that gives a value to a program (`rusthorse run`) | Import from `.env` or GNOME Keyring, restore a backup, a safe hand-off to KeePassXC (M3) |
| Verified backup of the vault; change of the master password | |

Pages for the later features are in the window already; they say what is
missing and what to do meanwhile.

## Before you start

- The agent must be running (`rusthorse status` answers) and the vault must
  exist (`rusthorse init`). The manager does not install, start or restart
  anything.
- Building needs Rust 1.92 or later and the GTK 4.12+ and libadwaita 1.4+
  development packages — the same as `rusthorse-dialog`
  ([installation.md](installation.md#optional-visual-manager)).

To try it without installing, from the source tree, when you are at the
desktop and ready to answer dialogs:

```sh
cargo run --locked -p rusthorse-manager
```

## The window

- **Sidebar.** The state of the vault (Locked, Unlocked, Unavailable), the
  pages, and one button that unlocks or locks. Under it, when the vault is
  open, the time left before the agent locks it by itself.
- **Entries.** The list, grouped by KeePass group, with a search field and a
  group filter. Search looks at names, UUIDs, groups, logins, URLs, hosts and
  tags — only metadata the manager already has.
- **Details.** The selected entry: its actions (Edit, New random value,
  Delete), the **Secret** rows (Value and Notes, with Show and Copy), the
  **Details** (login, URL, host, port, tags, the names of other fields, the
  UUID) and the command to use it.
- **Bottom line.** The result of the last action, and a spinner while the
  agent is waiting for you to answer one of its dialogs.

Selecting an entry fetches nothing secret. The manager checks the agent's
status every five seconds in the background; that does not count as using
the vault, so it never postpones the automatic lock.

## Everyday tasks

### Unlock and lock

**Unlock** makes the agent ask for the master password in its own dialog.
**Lock now** makes the agent forget the decrypted vault and every remembered
approval; commands already running keep the secrets they were given. Closing
the manager does **not** lock the vault.

If the vault is locked by something else — the agent's idle timer,
`rusthorse lock` — the manager notices at its next check (every five
seconds, also while one of the agent's dialogs waits for you) and clears
what it shows and what it copied; a value that arrives after such a lock is
neither shown nor copied. If you unlock with the CLI, the list appears by
itself.

### Create an entry

**New entry** opens a form for the name, group, username, URL, host, port and
tags. These are metadata, not secrets: never type a secret in them. Choose how
the value is made:

- **Type it in the agent's dialog** — after you click *Send to agent*, the
  agent's own password-style dialog asks for it;
- **Generate 32 random letters and digits** — the agent generates it; the
  manager never receives it.

### Edit, rename, generate, delete

**Edit** sends only the fields you changed, after the agent's approval.
Emptying a field removes it. Renaming keeps the entry's UUID and its KeePass
history. A field the file marks as *protected* is withheld from the manager
and cannot be edited here. **New random value** replaces the value with a
generated one; remember to change it at the provider too. **Delete** removes
the entry and its history from the vault — it does not revoke the credential
at its provider.

### Give a secret to a program

The **Use it from a command** card holds a ready command, for example:

```sh
rusthorse run OPENAI_API_KEY=8d2f6c1e-3b0a-4f7e-9c55-0a1b2c3d4e5f -- your-command
```

Replace `your-command`. After your approval the program receives the value in
that environment variable and its output is redacted. The entry is named by
its UUID, so a rename or a duplicate title elsewhere cannot make it point to
another entry; the variable takes the entry's name when that is a valid
variable name, `SECRET` otherwise. **This is the way to give an AI agent a
secret**: it never sees the value. The snippet holds no secret; copying it is
safe.

### Show a value

**Show value…** (or **Show notes…**) asks the agent; its dialog says
"Show the value of an entry on screen?". After you allow it, the value
appears in a small window:

- in groups of four characters, easier to read and compare —
  `abcd ef12 …` — when the value is made of letters, digits and symbols
  without spaces; otherwise as it is. Characters that the agent's dialogs
  would not draw appear as `\u{…}` escapes;
- not selectable, so that it never lands in the X11 primary selection;
- for 30 seconds at most, and it closes as soon as the window loses focus,
  when you click **Hide now**, or when the vault is locked.

Anyone who can see your screen, and other programs of your desktop session,
can see a shown value. Never ask an AI agent to use Show.

### Copy a value — for one paste

For a long key you need to paste into a web console, a sign-in form or a
program's password prompt, use **Copy value…** (in the Secret rows, or in the
Show window).

1. The agent asks "**Copy the value of an entry to the clipboard?**" — a
   separate approval, even if you just approved Show.
2. A banner at the top says what is on the clipboard and counts down:
   *"… is on the clipboard for one paste · cleared in 20 s"*, with
   **Clear now**.
3. **Paste it once**, right away. The first program that asks for the
   clipboard gets the value — normally your paste — and nothing after it:
   the manager says *"The value was pasted once and is no longer on the
   clipboard"*. A second paste, from any program, gets nothing. (A program
   that asks twice for a single paste gets nothing the second time: copy
   again.)
4. Without a paste, the value is wiped after **20 seconds**. It is also
   wiped when you lock, when the vault is locked elsewhere, when the agent
   becomes unreachable, and when you close the manager or it is stopped
   (Ctrl+C, a logout). If you copy something else meanwhile, the manager
   does not touch it.

**Why one paste and not a timer.** The clipboard is where values leak: on
X11 every program of your session can read it, a clipboard history can keep
it for ever, a phone link (GSConnect, KDE Connect) can send it to your phone,
and a value pasted into the wrong window is gone — a chat with an AI sends it
to the AI's provider. These copies happen in the first second; a timer that
clears the clipboard later cannot undo them. Rusthorse therefore delivers
the value **once**: whatever reads it first uses it up. If a program got
there before you, your own paste usually comes back empty, and you notice
instead of the value leaking silently. Not always: a program that took the
value could put it back on the clipboard as its own (some clipboard tools
do), and then your paste works; Rusthorse cannot see that.

**If your paste comes back empty**, one of these happened:

- the value had already been wiped — 20 seconds passed, the vault was
  locked, or you clicked **Clear now**; the bottom line says which;
- the program you paste into asked twice for one paste and got nothing the
  second time — copy again;
- another program read the clipboard before you. If the manager said
  *"Another program took the value as soon as it was copied — probably a
  clipboard history"*, that is the likely case.

When another program may have read it, assume a clipboard history keeps the
value: open it and delete the item, or turn its history off, and consider
rotating the secret (**New random value**, then update the provider). The manager marks the value with `x-kde-passwordManagerHint:
secret`, which Klipper, KDE Connect and some other histories honour, but on
X11 GTK 4 cannot deliver that mark, so on X11 no history is told.

What Copy does **not** protect against: a program of your session that reads
the clipboard during those seconds; the program you paste into. Paste only
where the value belongs.

### Back up the vault

**Import & backup → Create verified backup…** asks for a new absolute path
(`~` is not expanded; an existing file is never replaced). The agent copies
the encrypted vault and checks that the copy opens with the current master
password. A copy whose check fails is left in place, and the message names
it. Keep backups somewhere else as well.

To look at the vault in KeePassXC, open a **backup copy**: locking is not
exclusive — another program can ask the agent to unlock the live vault while
KeePassXC writes it ([threat model L15](threat-model.md)).

### Change the master password

**Settings → Change master password…**: the agent asks for the current and
the new password in its own dialogs. The manager never receives them.

## When something goes wrong

| What you see | What it means and what to do |
|---|---|
| **Unavailable** in the sidebar | The agent does not answer. `rusthorse status` in a terminal says why; `systemctl --user status rusthorse-agent` shows the service. The manager does not start it. |
| "Outcome unknown. The operation may have taken effect…" | The answer to a change was lost. The change may have happened: refresh and look before trying again. Never repeat it blindly. |
| A master-password dialog you did not expect | The vault locked between two of the manager's requests (for example the idle timer fired just then), and listing needs it open. Answer it, or cancel it. |
| A dialog stays open after you closed the manager | Closing the manager does not cancel a dialog the agent already shows: answer it there (Deny or Cancel). |
| "Incompatible agent protocol" | The agent and the manager come from different versions. Upgrade both and restart the agent yourself. |
| "Restart needed" on the Status page | The agent's program file was replaced after it started (an upgrade). Restart the service before using dialogs. |
| Your paste comes back empty | See [Copy a value](#copy-a-value--for-one-paste) for the possible causes. |
| "The vault was locked while the agent was asking you, so the value was neither shown nor copied" | The manager saw the vault locked while a Show or Copy was waiting — for example, the vault locked itself just before you clicked and the agent asked for the master password first. For safety, a value that arrives after a lock is dropped. Your approval was used up; click Show or Copy again. |

## Security notes

- The manager is non-dumpable and keeps values in buffers that are wiped;
  GTK's own copies (labels, clipboard transfers) are emptied when no longer
  needed but cannot be wiped reliably, and on X11 other programs of your
  session can capture windows.
- Show and Copy are for you at the desktop. An AI agent uses
  `rusthorse run`, which keeps the value inside the approved command.
- The full analysis is in [threat model L14](threat-model.md#l14--some-flows-move-values-through-the-client)
  and [ADR 0007](adr/0007-visual-manager.md#2-show-copy-and-memory).

## For developers: tests

`cargo test -p rusthorse-manager` runs logic tests, and runs its widget test
again under `xvfb-run` with a private D-Bus session, a UTF-8 locale and a
private runtime directory — never on your display. The widget test starts a
real agent in the test process, on a fake vault, socket and audit log, with
scripted dialogs; it drives the window, reads the clipboard with `xclip` as
another program would, and focuses windows with `xdotool`. Missing tools
(`xvfb-run`, `dbus-run-session`, `xclip`, `xdotool`) make it fail rather than
pass untested. Set `MANAGER_TEST_SCREENSHOTS=/some/dir` to save screenshots of
the window in the light and dark styles and of the Show window.
