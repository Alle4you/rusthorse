# Why Rusthorse, not just KeePassXC

Rusthorse keeps its secrets in a KeePass file, which raises a question at
once: KeePassXC already exists and is a complete password manager. Why
Rusthorse?

Rusthorse is not a better password manager. KeePassXC is a complete and
mature one, and Rusthorse does far less: for your own passwords, KeePassXC
is the tool. The two share the file: Rusthorse's vault is a KDBX 4 file
that KeePassXC opens, and both can be used on it, one writer at a time.
Rusthorse answers a narrower question: how a program acting for you — an
AI coding agent above all — can use a credential without the AI agent
receiving the value from the vault, with you deciding in a dialog which
command gets it, and with a record kept.

This compares two versions of KeePassXC with Rusthorse 0.1.0. KeePassXC
2.7.6 is the version that Ubuntu 24.04 and Linux Mint 22 package; 2.8.0 was
released on 2026-10-21. Their documentation, source and issue tracker were
read on 2026-11-20. KeePassXC's window and its integrations were not run for
this: what is said of them here was read, not tried. Rusthorse 0.1.0 is
unreleased: its source is published, no release is. [Sources](#sources) says
what each claim rests on.

## What they share

Rusthorse's vault is one KeePass KDBX 4 file. Rusthorse writes KDBX 4.1,
which KeePassXC has implemented since 2.7.0, and saves a KDBX 4.0 file as
4.1. A new vault uses AES-256 outer encryption, a ChaCha20 inner stream,
GZip compression and Argon2id key derivation (64 MiB, 20 passes, 2 lanes);
an existing file keeps its own cipher and parameters. KeePassXC offers
AES-256, Twofish and ChaCha20, and AES-KDF, Argon2d and Argon2id; its User
Guide recommends Argon2id. KeePassXC shows each Rusthorse field as the
KeePass field it is:

| Rusthorse | In the file | In KeePassXC |
|---|---|---|
| name, username, URL | `Title`, `UserName`, `URL` | the standard fields |
| value; notes | `Password`; `Notes`, written protected when Rusthorse creates or replaces them | the password; the notes |
| host, port, kind | custom fields `Host`, `Port`, `Kind` | additional attributes |
| tags; group | `Tags`; the entry's group | tags; nested groups |
| earlier versions | the entry's history, added on each edit | the entry's history |

Rusthorse lists other custom fields by name only and does not show
attachments. Only one program should write the file at a time; see
[Using both on one file](#using-both-on-one-file).

## What KeePassXC does that Rusthorse does not

| Feature | KeePassXC | Rusthorse |
|---|---|---|
| Platforms | Windows, macOS and Linux, with AppImage, Snap and distribution packages | Linux with a graphical session and systemd user services; no version for other systems or for phones |
| One-time codes (TOTP) | TOTP storage, codes, a QR view, `{TOTP}` in Auto-Type | None |
| Passkeys | Through the browser extension, with import and export, since 2.7.7; not in 2.7.6 | None |
| Attachments | Stored as encrypted binaries; a preview dialog since 2.7.10, with text editing in it since 2.7.11 | Not shown |
| Browser integration | KeePassXC-Browser, paired with the database, with a confirmation per site and entry | None; an idea on the roadmap. `rusthorse open NAME` opens an entry's `http://` or `https://` URL in the browser, unless the file marks the URL protected |
| Auto-Type | Types an entry's fields into the focused window, asking first by default (settings). On Linux, 2.7.6 disables it under Wayland; 2.8.0 supports Wayland through XDG Desktop Portals, without window title matching or tracking of the active window | None; an idea on the roadmap |
| Secret Service | Can be the desktop's Secret Service for one group, once enabled | A client only, to import from it |
| SSH agent | Adds keys from entries to the running `ssh-agent`, once enabled | None; `run` serves SSH, and the built-in guide's recipe starts a temporary `ssh-agent` inside the approved command |
| Unlocking | Password, key file, YubiKey or OnlyKey challenge-response; Quick Unlock on Windows and macOS, and on Linux through Polkit in 2.8.0 | A password, always; key files and hardware keys are on the roadmap for later |
| Merging and sharing | Merges databases by UUID and modification time; KeeShare shares groups through container files; 2.8.0 adds remote synchronisation through external tools | No merging: a save is refused when Rusthorse's checks find that another program changed the file, though a write between the last check and the replacement can still be lost; no sharing or sync; one user, one writer at a time |
| Password health | Password health, HIBP and statistics reports; `keepassxc-cli analyze` with an offline HIBP file | None |
| Clipboard | Cleared after 10 seconds, by default (per its settings) | The manager's Copy stays until something else is copied, by decision; the CLI has no copy command |
| Generator | Passwords and passphrases, in the window and the CLI (`generate`, `diceware`) | Random values of 8 to 1024 characters from three alphabets; no passphrases |
| Entry history | Keeps a copy of an entry before each change and shows them | Records the previous version on each edit; shows and restores none |
| Security audit | An external audit, completed on 2023-01-19, according to its FAQ | AI-assisted reviews; no independent security audit |

If what you need is a password manager, use KeePassXC.

## How a secret reaches a program in KeePassXC

| Channel | Who starts it | What the receiving program gets | Confirmation, and what it shows | Record kept |
|---|---|---|---|---|
| Clipboard | You, by copying a field | The value, as does any program that reads the clipboard (a property of the desktop clipboard) | Your copy; the User Guide describes no other. Cleared after 10 s by default (settings) | The User Guide describes none |
| Auto-Type | You (hotkey or window), or the browser extension's `request-autotype` | The typed characters | On by default: you pick the entry, or confirm "Perform Auto-Type into the previously active window?", which does not name that window (source) | The User Guide describes none |
| Browser extension, for logins | The extension, paired once with the database, for a site; the FAQ points third-party programs to this API | The username and password | On by default, unless the entries are already allowed for that site (in 2.7.6, also when the extension added them): the site's origin (and, since 2.7.12, its full URL in a tooltip) and each entry's title and username; **Remember** starts unchecked (source) | The User Guide describes none |
| Secret Service | Any client on your session bus, once enabled | The value | On by default: the client's executable and the entries; under Details, the process tree with command lines (source) | A desktop notification for 10 s; no lasting log |
| SSH agent | Any process that reaches `ssh-agent`'s socket (`ssh-agent` behaviour) | Signatures, not the key (`ssh-agent` behaviour) | Off by default (source); when set for a key, shown by `ssh-askpass`, not by KeePassXC | The User Guide describes none |
| `keepassxc-cli` | Whoever runs it and can unlock the file | What it prints (`show`, `export`) or copies (`clip`) | None per use that the man page and help describe. It opens the file itself: the database password is read from standard input (source), a key file or a hardware key is named by option, and `open` keeps a database open for an interactive session | The man page and help describe none |
| `cmd://` URL | You, opening the entry's URL in KeePassXC | The resolved placeholders, `{PASSWORD}` included, as arguments | "Execute command?", the command with `{PASSWORD}` masked, **No** by default; can be remembered in the entry (source) | The User Guide describes none |

**Secret Service.** Once enabled, KeePassXC serves one group you choose,
with its subgroups, to Secret Service clients such as `secret-tool` (the
2.8.0 User Guide documents this; for 2.7.6, the Getting Started guide lists
the integration among the features). Confirmation is on by default: per the
source, the dialog names the client's executable and the entries, its
**Details** show the process tree with command lines, and it guards against
PID reuse. The client then receives the value. **Remember** starts checked
and lasts "for the duration while both the requesting client AND KeePassXC
are running". The confirmation "only covers the access to the password of an
entry. Clients can always enumerate the items of exposed databases and query
their attributes" (its tooltip). Per the source, those attributes are the
title, username, URL and notes, each unless the file marks it protected, the
current TOTP code, and the custom attributes that are not protected (in
2.7.6, the protected ones too); the password is not among them: a client
gets it by a separate request, which is what the confirmation covers while
that setting is on, and what a remembered decision lets through. By default
(source) each retrieval shows a desktop notification for 10 seconds; there
is no lasting log ([#9024] asks for one).

**SSH agent.** KeePassXC "does not provide an agent itself but works as a
client for any agent implementation that is OpenSSH compatible". Off by
default, it can add keys from entries to the running `ssh-agent` on
unlock, remove them on lock and give them a lifetime. SSH clients get
signatures, not the key (`ssh-agent`'s manual: "the result is returned to
the requester"): genuine use without seeing, for SSH keys. Confirmation of
each use is a per-key option, off by default (source), shown by
`ssh-askpass`.

**`cmd://` URLs.** An entry's URL can be a command line (the 2.7.6 User
Guide does not document it; the code is there). When you open it from
KeePassXC's window, KeePassXC resolves every placeholder, `{PASSWORD}`
included, into the command's arguments (source), after asking "Do you
really want to execute the following command?" — **No** by default — with
`{PASSWORD}` masked and the text cut at 400 characters. **Remember my
choice** stores the answer in the entry; a source comment says the flag
"is not security feature" and is there "to prevent accidental execution
of commands". The browser protocol and the Secret Service code, as read
for this document, describe no request that opens an entry's URL. The
output is not captured or filtered (source), and the User Guide describes
no record.

**What is not there.** The User Guide, the command-line help and the FAQ
describe no request by which a program has KeePassXC run a named command
that then gets the secret, the value going to that command and not to the
program that asked; no filtering of a command's output; and no lasting
record of each use. The record is a choice the KeePassXC project has stated:
asked for a log of uses, a KeePassXC maintainer answered that it "is not
present *by design*" and that "Our philosophy is privacy and minimal
footprint" ([#10582], closed as not planned). The command is an open
request: asked for `keepassxc-cli` to run programs with entries in
environment variables, a maintainer wrote "I doubt this will ever get
implemented" and, asked whether a pull request would help, "Yes it would!"
([#11206]). The project's answers there, and to an earlier request to give
the CLI the database password in an environment variable ([#3934]), call
credentials in environment variables insecure.

Rusthorse's `run` does what those answers warn against: it puts the value in
the approved command's environment. Its documented limits say what follows
from that: any process of your user can read a running command's environment
([L3][limits]), what the command starts holds the value too ([L4][limits]),
and only exact copies are removed from its output ([L5][limits]). That is
why `run --broker` exists for HTTP APIs: there the command gets a token
instead of the key.

## What Rusthorse adds

### A program asks, you decide, the command gets the value

An AI agent, or any program of yours, runs `rusthorse run NAME -- COMMAND`.
Rusthorse's agent, the background program that holds the unlocked vault,
shows the dialog itself, as a separate program on your desktop: the exact
command line, the resolved program (and the real file behind a symlink), the
directory, which entry goes into which variable, the input and whether
output is redacted, the chain of processes that asked (marked unverified),
the variables that name where the program connects, and warnings for
variables that can make it run other code or route its connections. **Deny**
is the default, a dialog nobody answers is denied after 2 minutes by
default, and only exact, expected answers approve. After your answer,
Rusthorse's agent checks again before anything runs: that the vault it holds
was not locked, reloaded or changed while the dialog was open, that the
entries are the same (by UUID), and that the program file and the directory
are the ones it examined before the dialog (same device and inode). If one
of these fails, nothing runs. It then starts the command itself, with the
values in its environment; the program that asked gets the output and exit
status, not the value from the vault (the [README](../README.md) shows an
example dialog).

**Where it stops.** Approving a command trusts everything it executes, and
an approval is only as good as what you read. The dialog shows a script's
name, not its contents or the files and plugins it loads, and its lists of
destination and risky variables cannot be complete. The check after your
answer compares which file and which directory they are, not what they
contain, and a swap in the instant between that check and the start of the
command is not prevented ([L4][limits]). Remembered approvals, off by
default, run identical requests without a dialog ([L8][limits]).

### Output with the value removed

Unless `--no-redact` is given, the command's standard output and error are
pipes owned by Rusthorse's agent, and every copy of a secret value of 4
bytes or more in them becomes `[REDACTED:<entry>]` before `rusthorse run`
prints it; the command reads `/dev/null` unless `--stdin` forwards your
input, and the requester's descriptors never reach it. This prevents
accidental exposure through output that happens to contain the value.

**Where it stops.** Matching is exact. A value split across two reads of the
same stream is still caught, but an encoded, reversed or partial copy is
not, nor one with other bytes between its parts or divided between standard
output and standard error; shorter values never are (nothing warns about
them); and what the command sends over the network, writes to a file or logs
does not pass through it: it is not a defense against a command written to
leak ([L5][limits]). A program that needs your terminal needs `--no-redact`,
which gives it the requester's descriptors directly and leaves its output
unfiltered, and the dialog says so; a program that only needs input can take
it through `--stdin` and keep redaction.

### A token instead of the key, for HTTP APIs

`rusthorse run --broker VAR=NAME@URL` gives the command a temporary token in
`VAR`, never the entry's value, and with `--url` the local address of a
`rusthorse-broker` process, one per grant. That process puts the real key in
place of the token in the request headers it receives and forwards them to
the URL's origin, which you approve in the dialog, and nowhere else. A grant
ends with the command, or before: on `rusthorse lock`, `rusthorse grants
revoke`, a change to the entry, the end of its lifetime (12 hours by
default, at most 24), or an automatic lock with `--broker-locks end`; a
request limit is optional. Grants are never remembered; each admitted
request is recorded before it is forwarded.

**Where it stops.** You approve an origin, not paths or operations, so the
command can do whatever the key allows there, through any path and any
method the broker accepts, and a request limit is not a spending limit
([L25][limits]); the token is a bearer capability while the grant lives
([L3][limits], [L21][limits]). The broker fits programs that present the
token literally in a request header and whose base URL can be redirected, to
HTTPS addresses on the public internet; APIs that sign requests with the key
or take it in the URL or the body, devices on your network and other
protocols need ordinary `run`. It was tried by hand on 2026-11-04 with
`curl`, the Anthropic Python SDK 2.4.0 and Claude Code 2.1.318; no client
version is claimed supported ([L24][limits]).

### What an AI agent can read without asking

While the vault is unlocked, any process of your user can list entries and
read their metadata without a dialog — name, group, kind, username, URL,
host, port, tags, whether a value and notes exist, the names of other and of
protected fields — which is how an AI agent finds the entry it needs;
`rusthorse guide ai` prints the rules and commands for the installed
version. The value, the notes, other fields' values and every field the file
marks protected are withheld, and a kind is a label: nothing grants or
restricts access by it.

**Where it stops.** Metadata is visible by design, so secrets do not belong
in those fields ([L6][limits]), and the guide is advice that binds nothing:
any client, an AI agent too, can ask for a value with `rusthorse reveal`,
which prints it once you approve (never remembered). In both programs,
metadata is readable without a prompt while the database is unlocked, though
KeePassXC's Secret Service exposes only the group you chose and the sets
differ: Rusthorse withholds notes and every protected field, while
KeePassXC, per its source, returns notes that are not protected and the
current TOTP code, and from 2.8.0 leaves protected custom attributes out.

### Dialogs meant to be read

Approval and secret-entry dialogs come from Rusthorse's agent, never from
the client that asks (the one exception, `rusthorse init`, is below).
Nothing is truncated to fit: a `run` is refused when its command line,
program path or directory has more than 1000 characters, counted before
escaping (and so is each detail of a broker run), and a request is refused
when its dialog's text, after escaping, would have more than 4000. Every
string the requester controls passes through one function: characters with
predictable glyphs are drawn as themselves, every other one (controls,
invisible characters, other scripts, emoji) as a `\u{…}` escape. In
`rusthorse-dialog`, Rusthorse's own dialog program, when the content does
not fit, **Allow** stays disabled until its end has been in view once.
With zenity, used only when that program does not exist at its expected
path, dialogs do not scroll, so there Rusthorse also refuses, before showing
anything, a request whose dialog it estimates too tall to read at once.

**Where it stops.** Reaching the end is not proof of reading; literal
`\u{…}` text looks like an escape; ASCII look-alikes such as `l`, `I` and
`1` remain; and the zenity height is estimated for an 11-point font, which
larger fonts or a small screen can exceed ([L9][limits]).

### A record of each use

Rusthorse's agent writes a JSON Lines audit log (created with mode `0600`).
Its records cover unlocks and locks, approvals and denials, each `run` and
its exit, reveals, changes, backups, imports, broker grants and each
admitted broker request: the time, the action and outcome, the entries, the
requester's process chain and, for `run`, the command line and directory. A
record has no field for a secret value, a token or a credential, and a
broker request's record leaves out its path, headers and body. Unlocking and
approval-gated actions fail closed when their record cannot be written, and
a broker request is recorded durably before it is forwarded. `rusthorse
audit` and the manager's History page read the log; `list` and `show` are
not recorded.

**Where it stops.** Exit, completion and grant-end records are best effort,
and an abrupt stop of Rusthorse's agent can leave grant-end records
unwritten ([L23][limits]); a lock takes effect even when its record cannot
be written, and a broker request refused before admission need not leave
one; command lines and metadata are recorded as they are, with whatever a
requester put in them ([L11][limits]); and any process of your user can edit
or delete the log, which helps you notice misuse by a cooperative but wrong
AI agent and is not evidence against a hostile one ([L13][limits]).

### The master password and locking

Rusthorse's agent asks for the master password in its own dialog; the
protocol has no field for it, so no requester handles it, except `rusthorse
init` when no Rusthorse agent serves the vault, which reads the new password
itself. `keepassxc-cli`, for comparison, opens the file itself and reads the
database password from whoever runs it (source). Locking is not a
difference: by default (settings) KeePassXC locks when the session is locked
or the lid is closed, and after inactivity (off in 2.7.6, on at 900 seconds
since 2.7.11); Rusthorse's agent, by default, after 15 minutes without an
approved use, when the desktop signals a screen lock, and when logind
announces that the computer is about to sleep.

**Where it stops.** On X11 a program of your user can log the master
password as you type it ([L2][limits]); memory is not locked ([L7][limits]);
a running command keeps its values after a lock, and by default broker
grants survive automatic locks ([L22][limits]). Locking with the screen
depends on the desktop's signals, and locking before sleep on logind, which
waits for it only so long: a save in progress or a slow disk can make the
lock come after the computer has gone to sleep, and without logind's delay
only after it wakes ([L20][limits]).

### Importing without the values passing through the AI agent

`rusthorse import dotenv FILE` and `rusthorse import secret-service -a
KEY=VALUE` (GNOME Keyring, KWallet) have Rusthorse's agent read the values
itself, after one approval to list the names or items and one per batch; the
command that asks never holds a value.

**Where it stops.** Importing leaves the originals where they were and puts
no approval in front of them: a program that can read them there, an AI
agent too, still can, by that source's own rules, until you delete them. The
tests use a fake Secret Service, and no import from KWallet is recorded.

### At a glance

| | KeePassXC Secret Service | KeePassXC `cmd://` | KeePassXC SSH agent | Rusthorse `run` | Rusthorse `run --broker` |
|---|---|---|---|---|---|
| Who asks? | Any client on your session bus, once enabled | You, from KeePassXC's window | Any process that reaches `ssh-agent`'s socket | Any process of your user, through Rusthorse's agent | The same |
| What does the asker receive? | The value | Not applicable; the started command gets the placeholders, `{PASSWORD}` included, as arguments | Signatures, not the key (`ssh-agent` behaviour) | The command's output (redacted by default) and exit status; the command gets the value | The same; the command gets a token |
| What does the human see before deciding? | The client's executable and the entries; under Details, the process tree with command lines (source) | The command, `{PASSWORD}` masked, other placeholders resolved, cut at 400 characters (source) | Off by default (source); when on, what `ssh-askpass` shows, which the User Guide does not describe | Command line, program, directory, entries and variables, requester chain (unverified), destination variables, warnings | The same, and each grant's origin, base path (not a limit), end and request limit |
| Can the decision be remembered, and for how long? | Yes, checked by default (source); while the client process and KeePassXC both run | Yes, in the entry; later launches start without a prompt | Not applicable; a key stays in `ssh-agent` until it is removed, on lock or after a lifetime if set | Only with **Allow for N** turned on (off by default, at most 8 hours), for identical requests | Never; one grant permits many requests until it ends |
| Is the command's output filtered? | Not applicable | No (source) | Not applicable | Yes by default: exact copies of values of 4 bytes or more | Yes by default, tokens included |
| Is the use recorded? | A desktop notification for 10 s; no lasting log | The User Guide describes no record | The User Guide describes no record | Yes, in a log your user can edit; the exit record is best effort | Yes: the grant before the command starts, and each admitted request before it is forwarded (method label, never the path); completion and grant-end records are best effort |
| What can it be used for? | Programs that read secrets through the Secret Service | A command you start yourself | SSH keys | A command that reads a secret from its environment | HTTPS APIs at public addresses that take the key literally in a request header |

## What Rusthorse does not protect

The [threat model](threat-model.md) has every limit; these matter most here.

- **It is not a sandbox**: it prevents accidental exposure to a
  cooperative but fallible requester, not deliberate attacks from your own
  user account ([§1][scope]) or malware running as you ([L1][limits]), and
  approved commands run outside the requester's sandbox ([L16][limits]).
- **The approved command holds what it was given**, a value or, with
  `--broker`, a token, and any process of your user can read that from its
  environment while it runs ([L3][limits]); descendants that leave its
  process group keep values
  ([L17][limits]); redaction catches only exact copies in the command's
  output ([L5][limits]).
- **You approve a command line, not what the program reads** (scripts,
  configuration files, plugins), and an approval is only as good as what
  you read ([L4][limits]).
- **On X11, any program of your user can press Allow** and log keystrokes,
  the master password included; on Wayland, accessibility can still
  activate dialog buttons ([L2][limits]).
- **The requester is not verified**: the socket admits any process of your
  user, and the process chain shows names processes choose ([L9][limits]).
- **Not every use gets a dialog**: remembered approvals, when on, repeat
  without one, and a broker grant permits many requests after its one
  ([L8][limits], [L25][limits]).
- **The broker fixes the origin, nothing narrower**; the token admits
  whoever holds it, it fits only clients that send it in a header, and by
  default automatic locks leave grants running ([L21][limits],
  [L22][limits], [L24][limits], [L25][limits]).
- **Any process of your user can edit or delete the audit log**
  ([L13][limits]), which, like `rusthorse grants`, shows command lines;
  metadata is readable without a dialog ([L6][limits], [L11][limits]).
- **The project is young**: 0.1.0, no release, AI-assisted reviews, no
  independent security audit; Linux only, tried by hand on Linux Mint 22.3
  (Cinnamon, X11), tested automatically on Ubuntu 24.04, with no recorded
  run on Wayland, GNOME or KDE.

Some of these are properties of the desktop rather than of one program;
this document states them for Rusthorse because that is the program it can
speak for.

## Using both on one file

To edit the vault in KeePassXC:

1. `rusthorse lock` (or `systemctl --user stop rusthorse-agent`).
2. Open, edit and save the file in KeePassXC, then close the database there.
3. If you stopped the service, start it again (`systemctl --user start
   rusthorse-agent`). Use Rusthorse again; the next unlock reads the file
   KeePassXC wrote.

A lock does not reserve the vault: until KeePassXC has closed it, do not
answer an unlock dialog. Rusthorse does not merge. Before saving, it
compares the file's device, inode, size and modification time with what it
loaded and refuses with `vault_changed` if another program changed it, but
the check and the rename are not atomic, so a program saving at that
moment can lose its change ([L15][limits]). While unlocked, Rusthorse's
agent works from the copy it loaded: `list`, `show` and `run` see a change
KeePassXC saved only after a lock and an unlock. To look without editing,
open a copy made with `rusthorse backup DEST`.

Rusthorse opens a vault with a password only: not with a key file or a
hardware key, and not a database without a password. It reads KDBX 3
files, and KDBX 4 files newer than 4.1, but does not write them. Its
tests use a KDBX 4.1 file written by KeePassXC 2.7.12 and a KDBX 4.0 file
saved by 2.7.6: one test checks on the 2.7.12 file that Rusthorse's edits
leave every untouched entry identical, another that a custom field is kept
byte for byte. A round trip through `keepassxc-cli` does not run by default;
no 2.8.0 file is tested.

KeePassXC's side comes from reading its source and default settings; the
two programs were not tested writing the same file. By default KeePassXC
reloads a database another program changed; with unsaved changes of its
own it offers to merge, and a save refuses to overwrite changes it has not
merged (unless, in 2.8.0, you chose to ignore or overwrite them). It keeps
string fields it did not create, such as `Host`, `Port` and `Kind`, and
custom data it does not know. An open issue ([#13704]) reports that after
such a reload, locking leaves the database's keys in `ssh-agent`. If you
turn on KeePassXC's integrations for the group that holds Rusthorse's
entries, KeePassXC serves them by its own rules, outside what Rusthorse
protects or records, like any credential taken out of the vault.

## Which one, when

- **Your own passwords, websites, other operating systems:** KeePassXC,
  and on a phone a KeePass program that runs there (not tested here).
- **A program that reads the Secret Service and that you trust with the
  value, or SSH keys through `ssh-agent`:** KeePassXC's integrations.
- **An AI agent or a script that should use a credential without learning
  it, with your decision on the command and a record of the use:**
  Rusthorse, with the limits above.
- **Both on the same file:** one writer at a time, as above.

## Not compared here

Other KeePass programs (the original KeePass for Windows and its plugins,
KeePassDX, Strongbox), the desktop keyring and `.env` files (see the
README's [Why](../README.md#why)), and other tools that run a command with
secrets were not studied for this document. The README says the file opens
in KeePassDX, Strongbox and other KeePass clients; only files written by
KeePassXC are tested. The [roadmap](roadmap.md#prior-art-secretless-broker)
discusses CyberArk's Secretless Broker as prior art.

## Sources

KeePassXC:

- the [User Guide][kpxc-guide] 2.8.0 (last updated 2026-10-22) and its
  [Getting Started guide][kpxc-start]; the User Guide 2.7.6 (last updated
  2024-04-01), the man pages and `keepassxc-cli --help` of Ubuntu 24.04's
  package, listed at 2.7.6 on packages.ubuntu.com;
- the [FAQ][kpxc-faq], unversioned (its Auto-Type answer on Wayland is out
  of date for 2.8.0), the [changelog][kpxc-changelog] and the browser
  [protocol document][kpxc-proto];
- issues [#3934], [#9024], [#10582], [#11206] and [#13704], and OpenSSH
  9.6's `ssh-agent(1)` and `ssh-add(1)` manuals;
- the [source][kpxc-repo] at the tags 2.7.6 and 2.8.0, among it
  [`Config.cpp`][Config.cpp] (defaults), the Secret Service's
  [`AccessControlDialog.cpp`][AccessControlDialog] and `Item.cpp`,
  `BrowserAccessControlDialog.cpp`, `DatabaseWidget.cpp`, `Database.cpp`,
  `FileWatcher.cpp`, [`EntryAttributes.cpp`][EntryAttributes] and the
  CLI's [`Utils.cpp`][Utils.cpp].

KeePassXC's defaults, its dialogs, what a Secret Service client reads
without confirmation, how `cmd://` runs a command, how KeePassXC reloads
and saves a changed file and which fields it keeps come from the source
and settings (marked "source" or "settings"); the rest, from the
documentation, changelog, protocol and issues.

Rusthorse: the [README](../README.md), [threat model](threat-model.md),
[CLI reference](cli.md), [architecture](architecture.md),
[installation](installation.md), [ADR 0013](adr/0013-credential-broker.md).

This was checked on 2026-11-20, and KeePassXC changes. Anything here that
is out of date or unfair to KeePassXC is a mistake in this document:
please [report it](https://github.com/Alle4you/rusthorse/issues).

[limits]: threat-model.md#7-known-limitations-and-residual-risks
[scope]: threat-model.md#1-scope-and-the-exact-guarantee
[kpxc-guide]: https://keepassxc.org/docs/KeePassXC_UserGuide
[kpxc-start]: https://keepassxc.org/docs/KeePassXC_GettingStarted
[kpxc-faq]: https://keepassxc.org/docs/
[kpxc-changelog]: https://github.com/keepassxreboot/keepassxc/blob/latest/CHANGELOG.md
[kpxc-proto]: https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md
[kpxc-repo]: https://github.com/keepassxreboot/keepassxc
[Config.cpp]: https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/Config.cpp
[AccessControlDialog]: https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/fdosecrets/widgets/AccessControlDialog.cpp
[EntryAttributes]: https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/core/EntryAttributes.cpp
[Utils.cpp]: https://github.com/keepassxreboot/keepassxc/blob/2.8.0/src/cli/Utils.cpp
[#3934]: https://github.com/keepassxreboot/keepassxc/issues/3934
[#9024]: https://github.com/keepassxreboot/keepassxc/issues/9024
[#10582]: https://github.com/keepassxreboot/keepassxc/issues/10582
[#11206]: https://github.com/keepassxreboot/keepassxc/issues/11206
[#13704]: https://github.com/keepassxreboot/keepassxc/issues/13704
