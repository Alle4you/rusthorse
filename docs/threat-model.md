# Threat model

This document states what Rusthorse protects, against whom, how, and — just
as important — what it does not protect. If you find a gap between this
document and the code, that is a bug; please report it
([SECURITY.md](../SECURITY.md)).

- Applies to: Rusthorse 0.1.x
- Last reviewed: 2026-10-31 (see [review history](#11-review-history))

## 1. Scope and the exact guarantee

Rusthorse is a local, single-user secrets vault for Linux desktops. A
long-running agent holds the decrypted KeePass database; clients (the CLI, the visual manager,
scripts, AI coding agents) ask it to *use* secrets. Two different guarantees
are easy to confuse, so they are stated separately:

1. **Preventing accidental exposure — provided.** A requester that is
   cooperative but fallible (an AI agent that makes mistakes, over-shares or
   follows instructions planted in what it reads) can use a secret for a
   purpose you approved without the value entering its memory, output, logs
   or context, and without being able to use it for something you did not
   see.
2. **Resisting a hostile requester that runs code as your user — not
   provided on a normal desktop.** A requester that deliberately attacks
   Rusthorse from a shell running as your user, in your graphical session,
   can defeat it: on X11 it can click "Allow" or log the master password as
   you type it ([L2](#l2--x11-lets-any-program-act-on-your-dialogs)), and it
   can read the environment of approved commands while they run
   ([L3](#l3--the-environment-of-a-running-approved-command-is-readable)).
   Rusthorse raises the cost and leaves a trail, but it is not a sandbox.

To get the second guarantee, the AI agent must run **isolated** from your
session: as a different Unix user (or in a container/VM) without access to
your X11/Wayland display, your session D-Bus, your processes in `/proc`, your
home directory and the agent's files — with only the Rusthorse socket made
available to it. [Section 8](#8-running-ai-agents-in-isolation) describes
this setup. It is outside what Rusthorse can enforce on its own.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Secret values (`Password` field) | The thing being protected. |
| Notes and other protected fields | Often contain recovery codes or secondary secrets. |
| The master password | Unlocks everything, including copies of the vault elsewhere. |
| Approval decisions | The human's control over *what* a secret is used for. |
| Metadata (names, usernames, URLs, hosts, ports, tags) | Reveals what you have access to; useful for targeting. Treated as low sensitivity unless the file marks a field protected. |
| The vault file and its backups | Encrypted at rest; exposed to offline guessing if copied. |
| The audit log | Lets you notice misuse after the fact. |

## 3. Adversaries

| # | Adversary | Capabilities | Design target? |
|---|---|---|---|
| A1 | **Fallible AI agent** — cooperative, but makes mistakes, or follows instructions planted in content it reads (prompt injection) | Runs commands as you through its shell tool; reads and edits files; sees command output | **Primary** |
| A2 | **Hostile requester as the same user** — a fully hijacked agent or a malicious script deliberately trying to obtain secrets | Everything A1 can do, deliberately: writes its own socket client, races files, uses `/proc`, synthesizes X11 input | Only when isolated (§8); otherwise raise cost and leave a trail |
| A3 | **Malware running as you** with persistence | Modifies your files, binaries, shell startup, systemd units | No — see L1 |
| A4 | **Other local users** | Their own uid; no root | Yes |
| A5 | **Someone with a copy of the vault file** (backup, sync service, stolen disk) | Offline computation | Yes |
| A6 | **Root, the kernel, hardware, physical access to an unlocked session** | Everything | No |

## 4. Trusted computing base

Rusthorse's guarantees hold only if all of the following are trustworthy:

- the `rusthorse` binary, the systemd unit and the session that starts it;
- the libraries it links (notably the `keepass` crate, which implements the
  file format and its cryptography) and the Rust toolchain that built it;
- `zenity` and the GTK stack it uses, the X server or Wayland compositor that
  displays dialogs and delivers your keystrokes;
- the kernel (Yama `ptrace_scope ≥ 1`, which is the default on Ubuntu, Mint,
  Debian and Fedora) and the file system holding the vault;
- **every program you approve**, for the secrets you approve it for, and
  everything that program loads or executes (L4).

## 5. Trust boundaries

```mermaid
flowchart LR
    subgraph user["Your user account (same uid)"]
        subgraph untrusted["Requesters — not trusted with values"]
            AI["AI agent / shell / scripts"]
        end
        subgraph trusted["Trusted computing base"]
            AG["rusthorse agent<br/>(started by systemd, non-dumpable)"]
            DLG["zenity dialogs"]
            BIN["binary, unit file, session"]
        end
        CMD["approved command<br/>(trusted by your approval)"]
    end
    HUMAN(("you"))
    FILE[("vault.kdbx")]
    AI -- "socket requests" --> AG
    AG -- "asks (socket pair)" --> DLG -- "shown to" --> HUMAN
    AG -- "spawns with secrets" --> CMD
    AG <--> FILE
```

The boundary that matters is between **requesters** and the **agent**.

## 6. Security properties and mechanisms

| # | Property | Mechanism | Holds against |
|---|---|---|---|
| P1 | A requester never receives a secret value, notes or a protected field without an approval for that specific request. | Only `reveal` returns a value, after a non-rememberable approval. `list`/`show` return metadata only, and withhold any field the KDBX file marks as protected — including a protected title, which is shown as `[protected title]` and matched only by UUID — reporting only the field's name. | A1, A2 |
| P2 | The approved command line, program, directory and environment are the ones used. | The agent resolves the program to a canonical path, fixes arguments, directory and environment, shows them, checks the program's and directory's identity (device and inode) again after you answer, and spawns the command itself ([ADR 0002](adr/0002-agent-mediated-execution.md)). A custom client cannot substitute another command. A swap in the instant between that check and the start of the program, and changes to file *contents*, are not prevented (L4). | A1, A2 |
| P3 | An approval is acted on only if the vault did not change while you decided. | A vault *generation* counter is bumped on unlock, lock and every saved change. The generation is checked under the same lock that reads the values, so an edit, lock or reload while the dialog was open cancels the request. Reading the values *consumes* the approval: a `lock` after that point does not stop the command. A `lock` while the master password is being typed cancels the unlock. | A1, A2 |
| P4 | Secrets used by `run` are not placed in a process the requester can inspect with a debugger. | The command is a child of the agent, not of the requester; Yama blocks `ptrace` from outside its ancestry. See L3 for `/proc/<pid>/environ`. | A1, A2 (partially) |
| P5 | Secret values printed by an approved command do not reach the requester verbatim. | With redaction (the default), the command's stdout and stderr are pipes owned by the agent; the filtered output travels to the requester as data frames over the socket, and the requester writes it itself. The command's stdin is `/dev/null`, or an agent-owned pipe fed from the requester's data frames with `run --stdin`. The requester's own descriptors never reach the command or the agent, so there is no unfiltered way back. Exact-match only (L5). | A1 |
| P6 | The master password and new secret values never pass through a requester. | The agent asks for them in its own dialogs; the protocol has no field for the master password. Imports from GNOME Keyring and `.env` files are read by the agent (`import_from`, [ADR 0012](adr/0012-import-read-by-the-agent.md)): the requester names items and entry names, and the dialog names the source; only the older `import` request carries values from a client, and its dialog says so. zenity's answer comes back over a socket pair, which other processes cannot open through `/proc/<pid>/fd` (a pipe could be). A *new* vault's password is asked by the agent too (`create_vault`, sent by `rusthorse init` and the manager's Create vault…, [ADR 0011](adr/0011-first-start-from-the-manager.md)); the one exception is `rusthorse init` when no agent serves that vault, which reads it in the CLI (terminal or dialog). | A1, A2 (not on X11, L2) |
| P7 | Dialogs are not answered by the requester and say what they mean. | Separate processes on the desktop, not in the terminal: `rusthorse-dialog` ([ADR 0006](adr/0006-own-dialog-program.md)) or, when it is not installed, zenity — started from an absolute path with a minimal environment and `/` as working directory, answering through a socket pair; `rusthorse-dialog` also gets its request through that socket (framed, versioned, with an identifier the answer must repeat), runs under a deadline after which it is killed, reads no per-user GTK configuration, shows plain text only, and keeps **Allow** disabled until the end of a request that does not fit has been in view; requester-controlled text is escaped (only ordinary characters are drawn as themselves, every other one as a `\u{…}` escape; markup characters for zenity's question dialog, backslashes and underscores for its entry dialog); entries are identified by full path and UUID, so two entries with the same title never look alike; requests whose dialog text would exceed 4000 characters (or 1000 for one field) are refused, never truncated, and with zenity also those too tall to read at once (estimated for an 11-point font); default button **Deny**; unanswered dialogs are denied; only exact, expected answers count as approval. | A1, A2 (not on X11 or through accessibility, L2) |
| P8 | Only your user can talk to the agent. | Socket in a `0700` directory, mode `0600`, `SO_PEERCRED` uid check. | A4 |
| P9 | The decrypted vault is not held longer than needed. | Auto-lock after 15 minutes without an *approved* use — `status`, `list`, `show` and denied requests do not postpone it; `rusthorse lock`; lock on any save failure. | A1, A2, A6 (window) |
| P10 | The agent's memory is not readable by other same-user processes and is not dumped. | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the agent. Dialogs and approved commands inherit `RLIMIT_CORE=0`, but `execve` makes them dumpable again, and with a piped `core_pattern` (systemd-coredump) whether a crash is stored is up to that handler. | A1, A2 |
| P11 | The vault is confidential at rest. | KDBX4: AES-256, Argon2id (64 MiB, 20 passes for new vaults); files `0600`, directories `0700`. | A4, A5 |
| P12 | Every decision leaves a record. | JSON Lines audit log, `fsync`ed per record. Unlocking and approval-gated actions fail closed: if the record cannot be written, the vault stays locked or the action does not happen. | A1 (detection; L13) |
| P13 | The agent stays available under request floods. | The whole request must arrive within 10 s of connecting (a deadline, not a per-read timeout); at most 64 connections and 8 requests waiting for a dialog at once; frames ≤ 4 MiB; imports ≤ 100 entries; vault files ≤ 128 MiB. | A1, A2 (availability) |
| P14 | Approved changes are all-or-nothing and match the disk. | Every change runs as a transaction that is rolled back if any part fails (for example one invalid entry in an import); if saving fails, the vault is locked so memory never holds unsaved changes. A save that fails after the file was replaced (syncing the directory) is reported as an unknown outcome, never as "not saved". | Accidents |

### The guide for AI agents is advice

`rusthorse guide ai` tells a cooperative agent (A1) how to work with
Rusthorse: never ask for or print a value, no `reveal`, stop after a denial,
read the metadata before asking. It is not a mechanism. Its rules bind
nothing, an agent that follows planted instructions may ignore them, and
every property above holds whether or not the agent has read it. It makes
the common mistakes of a cooperative agent less likely; the dialog stays
the control.

### Who starts the agent

A process can read the memory of the processes it starts (with the default
Yama setting), preload code into them (`LD_PRELOAD`) and change their
environment. If an AI agent's shell started `rusthorse agent`, it could do all
of that before the agent protected itself. The agent must therefore be started
by systemd, outside every requester's process tree. `rusthorse agent` prints a
warning when its parent is not systemd. The agent marks itself non-dumpable at
startup, which blocks inspection by any other unprivileged process from then
on.

### What an approval means

| Answer | What it authorizes |
|---|---|
| **Allow once** | This one request, exactly as shown. |
| **Allow for N** (opt-in, `--remember`, off by default) | A reusable capability: for N minutes, any request with the same entries (by UUID), the same vault generation, command line, program, directory, redaction setting and environment runs **without asking**. It does not cover what the command reads — its standard input, files, network responses — which can differ on each run (L8). |
| **Deny**, closing the dialog, timeout | Nothing. The command does not run. |

Locking, unlocking and any saved change invalidate remembered approvals.

## 7. Known limitations and residual risks

### L1 — Malware running as you can defeat Rusthorse

It can replace the `rusthorse` binary, the systemd unit or your shell startup
files, wait for you to unlock, and capture the master password or the
decrypted data. No program running with your privileges can prevent this.
The Debian package's programs belong to root, but that does not change it: a
service file of the user's in `~/.config/systemd/user/` takes precedence over
the package's ([ADR 0010](adr/0010-debian-package.md)).
*Mitigation:* keep the account clean; run AI agents isolated (§8).

### L2 — X11 lets any program act on your dialogs

On X11, every client can synthesize keyboard and mouse input (XTEST,
`xdotool`) and read other windows and keystrokes. A hostile requester in your
session can press "Allow once" on the approval dialog, or log the master
password as you type it. A dialog answer is therefore **not proof that a human
decided** against such a requester. *Mitigation:* prefer a Wayland session,
where clients are isolated; isolate the AI from your display entirely (§8).
The default button is **Deny** and dialogs time out, which only helps against
accidents. This is the most important limitation on X11 desktops such as
Cinnamon and MATE.

Wayland does not close every path: dialogs expose their buttons through the
accessibility API (AT-SPI) so that screen readers work, and a program of the
same user that can reach the accessibility bus can activate them on X11 and
Wayland alike. zenity's GTK 3 dialogs do so today, and so will the dialog
program of [ADR 0006](adr/0006-own-dialog-program.md).

### L3 — The environment of a running approved command is readable

While an approved command runs, any process of the same user can read
`/proc/<pid>/environ`, which contains the secret. Marking the process
non-dumpable would prevent that, but `execve` resets the flag. *Mitigation:*
short-lived commands; the planned SSH agent and HTTP broker keep secrets out
of the environment altogether.

### L4 — Approving a command trusts everything it executes

If you approve `python deploy.py`, the secret goes to whatever `deploy.py`
contains when it runs — and an AI agent can edit that file, even between your
answer and the start of the command. Rusthorse checks the identity (device and
inode) of the program and of the working directory again after you answer,
which catches a file swapped for another while the dialog was open. It does
not pin them — a swap in the instant between that check and the start is
still possible — and it does not notice a file rewritten in place, nor the scripts,
modules, configuration files (`~/.gitconfig`, `.curlrc`, `.npmrc`) and
plugins the program loads. The same applies to `sh -c '…'` and interpreters
with inline code. The agent removes `LD_*` variables and warns about a list
of variables that change what programs execute (`NODE_OPTIONS`,
`PYTHONPATH`, `GIT_SSH_COMMAND`, …), but such a list cannot be complete.

A well-known program can also be pointed elsewhere. Libraries read the
address they send a key to from the environment (`OPENAI_BASE_URL`,
`ANTHROPIC_BASE_URL`, `HTTPS_PROXY`, …), and the requester's environment is
passed to the command: a requester can make an approved `python app.py` send
the key to a server of its choosing. The dialog therefore lists, under
**Destinations**, the variables whose names say where a program connects
(`*_URL`, `*_BASE_URL`, `*_HOST`, …), and warns about proxies, certificate
authorities, switches that disable certificate checks, and name resolution
([cli.md](cli.md#rusthorse-run)); the audit record names them too. A value
that programs could read differently — a backslash, two `@`, an unusual
host, a numeric host other than `a.b.c.d`, a query naming another server
(libpq's `hostaddr`), a `#`, anything outside printable ASCII — is not
shown but warned about. The aim is that the dialog never names a host other
than the one the program uses. It has been checked against the readings of
common URL parsers and libpq that four rounds of review found to differ,
each pinned down by a test; it is not a guarantee for every program, and
each round found narrower cases. Limits: the lists go
by name and cannot be complete (`MY_SERVICE=https://…`, a configuration file
or an argument escape them); a URL is shown by scheme, host and port only,
so a different path on the same host is not visible; the forms judged
unambiguous are those known for common URL parsers and libpq, not a proof
about every program, which may take its destination from elsewhere; and
`run --url`, which
takes the address from the entry's metadata, looks the same as a variable
the requester set ([ADR 0008](adr/0008-entry-kinds.md)).
*Mitigation:* read the dialog — check the host of every destination; prefer
well-known binaries with explicit arguments; review recent changes to scripts
before approving them. The planned credential broker would remove the
problem for HTTP APIs: the real key would only travel to its own provider.

### L5 — Redaction only catches exact copies in the command's output

A command that prints the secret encoded (base64, hex, URL-encoded), split,
reversed or partially is not redacted, and secrets shorter than 4 characters
never are. A command can also send the secret over the network, write it to a
file, or put it in its own logs — none of which pass through the redactor.
Redaction prevents *accidental* disclosure on stdout/stderr; it is not a
defense against exfiltration by a command written to leak.

### L6 — Metadata is visible without approval

While the vault is unlocked, any process of your user can list entry names,
kinds, usernames, URLs, hosts, ports and tags (fields marked protected in the
KDBX file are withheld). This is deliberate — an agent needs to know what
exists and where it points — but do not put secrets in those fields. A kind
is a label: nothing grants or restricts access by it
([ADR 0008](adr/0008-entry-kinds.md)).

### L7 — Memory hygiene is best effort

Rusthorse wipes the buffers it controls (`Zeroizing`), but copies made by JSON
parsing, the KeePass library, zenity/GTK and the standard library's process
spawning are not all wiped. Memory is not locked, so secrets can reach swap or
a hibernation image. *Mitigation:* full-disk encryption (which covers swap).

### L8 — Remembered approvals are a capability, not a decision per use

When enabled, "Allow for N" approves identical requests without asking, even
when they read different input. For example, `curl --config -` with a
remembered approval sends the token wherever the next request's standard input
says. This is why remembering is **off by default** and should only be enabled
for commands whose inputs you control. See [ADR 0005](adr/0005-remembered-approvals-opt-in.md).

### L9 — Dialog information can mislead

Process names in the requester chain are chosen by the processes themselves,
pids can be reused, and a socket can be handed to another process, so the
chain is informative only. A flood of requests can cause approval fatigue.
Text the requester controls is shown literally: dialogs use formatting, but
every value is escaped before it is placed in it, so a command line cannot
make part of itself bold or tiny, and only ordinary characters (ASCII, Latin
letters, a little punctuation) are drawn as themselves: everything else —
line separators, invisible and combining characters, other scripts such as
the Cyrillic `а` that looks like a Latin `a`, emoji — appears as a `\u{…}`
escape. `rusthorse-dialog` scrolls a long request and keeps Allow disabled
until its end has been in view — which does not prove it was read; with
zenity, requests whose dialog would be too tall to read at once are refused,
by an estimate made for an 11-point font, and larger fonts or a smaller screen
can still make a dialog taller than the screen. ASCII itself has characters
some fonts draw alike (`l`, `I`, `1`). A name drawn as an escape and a name
that holds those characters literally (`東京` and `\u{6771}\u{4eac}`) look
the same; dialogs add the entry's UUID (its first 8 characters) and a
destination group's whole UUID, but a file written by another program can
give two entries UUIDs that start alike. The requester chain is made of
process names any program can choose — the dialog labels it "unverified".
*Mitigation:* treat unexpected dialogs as a warning sign; deny when in doubt.

### L10 — The vault can be attacked offline

Anyone with a copy of the file or one of its backups can try passwords at a
cost set by Argon2id. A weak master password will fall. Old values remain in
entry history, in `vault.kdbx.bak` and in any copies you made. *Mitigation:* a
long, unique passphrase (`rusthorse passwd` changes it and deletes the
`.bak` file encrypted with the old one — but not copies made elsewhere);
rotate credentials at the provider when they may have leaked — deleting an
entry does not revoke anything (`rusthorse edit NAME --generate` makes the
new value).

### L11 — Command lines are not secret

Arguments are shown in dialogs, stored in the audit log and visible to other
processes. Never put a secret on a command line; pass it through `run`.

### L12 — Denial of service

Any process of your user can lock the vault, keep dialogs coming (one at a
time, at most eight waiting), or stop the agent. Opening a crafted vault file
with extreme KDF parameters can make unlocking very slow (files over 128 MiB
are refused, but KDF parameters are not yet bounded). These are annoyances,
not disclosures. Under extreme resource exhaustion — the agent cannot create
the threads that relay a command's output after the command has started —
the request fails without an answer (the client reports exit 124, outcome
unknown) and the command is left to finish on its own (it gets `SIGPIPE` if
it writes output, and stays a zombie until the agent restarts); the agent
itself keeps serving other requests.

### L13 — The audit log is not tamper-proof

Any process of your user can edit or delete it. It helps you notice misuse by
a cooperative-but-wrong agent; it is not evidence against a hostile one. It
records command lines, which may contain sensitive data if you put it there.

### L14 — Some flows move values through the client

`reveal` returns the value to the requesting process (its purpose; never
remembered). A client may state what it will do with it — `purpose`: `show`
or `copy` ([protocol](protocol.md#reveal)) — and the dialog and the audit log
say so, but the agent cannot enforce it: the requester has the value. The
visual manager uses both:

- **Show** displays the value in a window of its own. GTK, the screen and
  accessibility tools then hold copies, which cannot all be wiped; on X11,
  other programs of the session can capture the window. The manager is
  non-dumpable, keeps the value in zeroizing buffers, and hides it after 30
  seconds, on focus loss, on close and on an observed lock, emptying the
  labels.
- **Show** also offers Copy (below) of what it shows, without a new
  approval; the `show` dialog says so.
- **Copy** puts the value on the clipboard as plain text, like any copy. It
  stays there until something else is copied; other programs of the session
  can read it (on X11 any of them; on Wayland those using a data-control
  protocol); the desktop keeps its own copy — Cinnamon fetches it the moment it is
  copied and restores it when the copying program exits (verified with
  Muffin 6.6.3; GNOME's Mutter is understood to do the same, not verified)
  — and a clipboard history may keep it for ever; and the program it
  is pasted into receives it, so a value pasted into the wrong window (a
  chat with an AI) is gone. Rusthorse cannot take a copied value back. What
  it does: Copy needs its own approval, whose dialog says all this; the
  audit log records it (`value, to copy to the clipboard`); and the manager
  repeats the note after every copy. A stricter single-paste design was
  built and dropped: the desktop's own copy defeats it ([ADR 0007](adr/0007-visual-manager.md#copy)).

Status polling is not an immediate signal of a lock made elsewhere: the
manager checks every five seconds, also while a request waits for the
human, and drops what a waiting request returns after it saw a lock — a
value, a list, an "unlocked" status read before the lock. `import` reads values in the client
before sending them to the agent; `add --stdin` sends a value the client
already has. None of these should be run by an AI agent. Importing also does
not remove the original copies (for example in GNOME Keyring).

### L15 — Concurrent edits by other programs

The agent refuses to save if the vault file changed since it was loaded and
checks again right before replacing it, but the check and the rename are not
atomic: KeePassXC or a sync client saving at that exact moment can lose its
change. Only one program should write the vault at a time — lock the agent
(`rusthorse lock`) before editing in KeePassXC.

### L16 — Approved commands run outside the requester's sandbox

The command is started by the agent, as you, with the agent's privileges —
not inside whatever sandbox (container, seccomp policy, network restrictions)
the requester runs in. Approving a command from a sandboxed AI agent grants
that command your full access. The dialog states this.

### L17 — Descendants that leave the process group outlive the command

When the command exits — or the requester disconnects first — every remaining
process in its process group is terminated (SIGTERM, then SIGKILL after 3
seconds), so background jobs started by the command do not keep the secret.
A process counts as alive while any of its threads is (its main thread may
already have exited).
A descendant that started a new session or group (`setsid`, `setpgid`)
escapes this and keeps the secret in its environment; stopping the agent's
systemd service kills all of them (cgroup). *Planned:* one cgroup per command.

### L19 — A connected client that does not read holds the request open

Output is delivered like in a pipeline: while the requester stays connected,
the agent waits for it to read, however long that takes, and keeps the copy
of the secret values that the redactor needs. Meanwhile the command may
itself be blocked writing its output, exactly as it would be in a pipeline
whose reader stopped. Stdout and stderr have separate 1 MiB flow-control
windows, so one stuck channel does not stop the other. The request ends as
soon as the requester reads its output, or closes, half-closes or breaks the
connection (each of which cancels it: the agent shuts the socket down, which
fails a pending send at once). A requester that does neither ties up one of
the agent's 64 connections.

### L18 — Forwarded input races the end of the command

With `run --stdin`, the `rusthorse run` process reads its own stdin and sends
it to the agent while the command runs. Input typed in the instant the command
finishes may be read by `rusthorse run` — which exits right after — and lost
instead of reaching the next program that reads the terminal. Programs using
the library API (`Client::run_with`) get the same behaviour: the input reader
reads only after `poll` reports data and normally stops within about 100 ms
after the call returns. If another process reads the same input at the same
moment — between that `poll` and the `read` — the reader stays blocked in
`read` and may later consume input meant for someone else; interrupting it
would require changing file flags shared with the caller. Without `--stdin`
(the default), the requester's input is never read. With `--stdin`,
nothing is read before the command has started: a denied request leaves the
input untouched.

### L20 — Locking with the screen depends on the desktop's signals

The agent locks the vault when the computer is about to sleep and when the
session is locked or its screensaver starts, told over D-Bus by logind and
the Cinnamon, GNOME, MATE and freedesktop screensavers
([ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md)). It cannot lock on
what it is not told: a locker that emits none of these signals (some
standalone X11 lockers such as `i3lock` or `slock`), a system without logind,
or a missing bus leave only the idle timer; `rusthorse status` and `doctor`
say which sources are watched. logind waits for the lock only up to its
`InhibitDelayMaxSec` (5 seconds by default): a vault save in progress or a
slow disk can make the lock come after the computer has gone to sleep, and
without a delay inhibitor (logind refusing it, which `status` reports as
degraded) it may come only after the computer wakes. A suspend is noticed by
logind's signal only, accepted as a broadcast from the owner of logind's
name. A dialog already on the screen when the vault
locks stays until it is answered or times out; whatever it would approve then
finds the vault locked and does nothing. Hibernation writes RAM to disk: the
agent locks the vault on logind's signal, within the limits above, and memory
that held it is not guaranteed to have been overwritten (L7). Forged signals — any program of the session can emit a
screensaver's — can only lock: nothing unlocks but the master password.
*Mitigation:* keep both behaviours on; check `rusthorse doctor`; with a
locker that emits no signal, run `rusthorse lock` from its hook, and keep
`--idle-timeout` short.

## 8. Running AI agents in isolation

To make Rusthorse resist a hostile requester (A2), deny the AI everything that
L2, L3 and L16 rely on. A practical setup:

- Run the AI agent as a separate Unix user (or in a container or VM).
- Do not give it your display: no `DISPLAY`/`WAYLAND_DISPLAY`, no access to
  your X authority file or Wayland socket, no session D-Bus.
- With `hidepid=2` on `/proc` (or a separate PID namespace) it cannot see your
  processes; as another user it cannot read their environment anyway.
- Expose only the Rusthorse socket to it (for example with a group-owned
  socket path), and accept that approved commands then run as *you* — keep
  them narrow.

Rusthorse 0.1 checks that the peer has the **same** uid, so this setup needs
a small extension (an allow-list of uids) that is on the roadmap.

## 9. Recommendations

- Start the agent only through the systemd unit.
- Prefer a Wayland session; use full-disk encryption.
- Give AI agents narrowly scoped, revocable credentials (per-repository
  tokens, API keys with spending limits), stored as separate entries.
- Keep `--idle-timeout` short; lock the screen when you step away (the agent
  locks with it, L20); leave `--remember` off unless you need it.
- Read every dialog; be suspicious of `sh -c`, scripts the agent just edited,
  unexpected programs or directories, and risky-variable warnings.
- Edit the vault in other programs only while the agent is locked.
- Look at `rusthorse audit` from time to time.

## 10. Planned improvements

- **SSH agent and local HTTP broker**: secrets used *by the agent* for a
  typed operation (destination, method) instead of being placed in a
  command's environment — addresses L3, L5 and most of L4 for those cases.
- **Isolation support** (§8): uid allow-list on the socket and documentation
  for running agents as a separate user.
- **One cgroup per approved command** (L17), with resource limits.
- **Bounded KDF parameters** before unlocking (L12).
- **Per-entry policies**: restrict an entry to listed programs or hosts.
- **A grants panel** in `rusthorse-dialog`, to inspect and revoke remembered
  approvals (and, later, broker tokens).
- **A "waiting for your answer" hint** in the terminal while a dialog is
  open, driven by an explicit event from the agent.
- Signed release artifacts.

## 11. Review history

| Date | Review | Outcome |
|---|---|---|
| 2026-10-31 | Initial threat model, written with the first implementation. | — |
| 2026-10-31 | Adversarial design and code review (AI-assisted, Codex). | See below. |
| 2026-10-31 | Second review of the code and of the fixes (AI-assisted, Codex). | See the second table. |
| 2026-10-31 | Third review: verification of the second round (AI-assisted, Codex). | See the third table. |
| 2026-10-31 | Fourth review: verification of the third round (AI-assisted, Codex). | See the fourth table. |
| 2026-10-31 | Fifth review: verification of the new I/O design (AI-assisted, Codex). | See the fifth table. |
| 2026-10-31 | Sixth review: verification of flow control and cancellation (AI-assisted, Codex). | See the sixth table. |
| 2026-11-01 | Seventh review: verification and readiness for a first real use (AI-assisted, Codex). | See the seventh table. |
| 2026-11-01 | Eighth review: verification of the new features (AI-assisted, Codex). | See the eighth table. |
| 2026-11-01 | Ninth review: verification of the eighth round (AI-assisted, Codex). | See the ninth table. |

Findings of the 2026-10-31 review and what was done:

| Finding | Disposition |
|---|---|
| zenity's stdout pipe could be opened through `/proc/<pid>/fd` by another process, racing for the master password | **Fixed:** a socket pair replaces the pipe (P6). |
| Remembered approvals authorize different behaviour (stdin, config files) | **Mitigated:** off by default, bound to vault generation, entry UUIDs and the full environment, explained in the dialog; documented as a capability (L8, ADR 0005). |
| Resolved paths do not pin executed code (TOCTOU) | **Partly fixed:** program and directory inodes re-checked after approval; content changes documented (L4). |
| `list`/`show` disclosed fields the KDBX file marks protected | **Fixed:** withheld, only the field name is reported (P1). |
| zenity's entry dialog interprets `\` escape sequences, so a name like `prod\000…` could hide text | **Fixed:** backslashes escaped; names with control characters already refused; overlong details now refused instead of truncated (P7). |
| A writable socket passed as stdin bypassed redaction | **Fixed:** stdin goes through an agent-owned pipe when redacting (P5). |
| Descriptors beyond the expected count leaked on truncated messages | **Fixed:** room for the kernel's maximum, all taken into ownership, counts validated. |
| Concurrent saves by KeePassXC could be overwritten | **Mitigated:** second check right before rename, fingerprint taken from the written file; documented (L15). |
| `setsid` descendants escape process-group termination | **Documented** (L17); cgroups planned. |
| A title such as `Prod/API` could shadow the path `Prod/API` | **Fixed:** title and path matches are merged and any overlap is ambiguous; new names cannot contain `/`; UUIDs in responses and approval keys. |
| Deletions were not recorded for KeePass synchronization | **Fixed:** `DeletedObjects` is updated. |
| Crafted KDBX files can impose an expensive KDF | **Partly fixed:** 128 MiB file limit; KDF bounds planned (L12). |
| zenity exit statuses can be remapped by `ZENITY_*` variables; UI files are looked up relative to the working directory | **Fixed:** absolute path, minimal environment, `/` as working directory; only exact expected results approve. |
| Read-only or denied requests kept the vault unlocked | **Fixed:** only approved uses postpone the idle lock (P9). |
| Unsaved changes could survive a failed save in memory | **Fixed:** the vault is locked when saving fails. |
| Lock, edit or removal while a dialog is open | **Fixed:** generation check before acting (P3). |
| Approved commands run outside the requester's sandbox | **Documented** (L16) and stated in the dialog. |
| Protocol had no limits on slow clients or floods | **Fixed:** timeouts and caps (P13). |

Findings of the second review (of the code after the fixes above):

| Finding | Disposition |
|---|---|
| N1 — a failing import left part of the batch in memory, saved later by an unrelated change | **Fixed:** changes are transactions, rolled back on failure (P14). |
| N2 — the generation check and the read of values were not atomic; a `lock` during the password prompt was undone by the pending unlock | **Fixed:** checked under the same lock; unlock cancelled by a lock (P3). |
| N3 — `OLDPWD` and `_` were left out of the approval key but passed to the command | **Fixed:** the key is the whole effective environment in canonical order. |
| N4 — a protected `Title` was disclosed | **Fixed:** shown as `[protected title]`, matched only by UUID (P1). |
| N5 — two entries with the same title in different groups looked identical in dialogs | **Fixed:** entries are shown as `Group/Title (uuid)` in dialogs and the audit log (P7). |
| N6 — descriptors still leaked when the open-file limit truncated a message | **Fixed:** the control buffer is parsed directly and every installed descriptor is owned and closed. |
| N7 — stdin forwarding consumed input after the command ended and could block | **Fixed:** stdin is `/dev/null` unless `--stdin`; forwarding stops before reading; residual race documented (L18). (The claim that forwarding "never blocks" made here was wrong; see N12 in the third review.) |
| N8 — descendants in the same process group survived | **Fixed:** the group is terminated when the command ends or the client disconnects; `setsid` escapes documented (L17). |
| N9 — an unwritable audit log failed the unlock but left the vault open | **Fixed:** recorded before publishing (P12). |
| N10 — per-field limits did not bound the whole dialog | **Fixed:** whole-dialog limit (P7). |
| N11 — the request timeout was per read, so a slow drip could exceed it | **Fixed:** a deadline for the whole request (P13). |
| Tests did not fail when several fixes were reverted | **Fixed:** new tests for each fix. A mutation run then reverted each of the 15 fixes in turn; the test suite failed every time (tests now have deadlines, so a regression that hangs fails instead of blocking). |

Findings of the third review (verification of the second round; N1–N6, N9 and
N11 were confirmed fixed):

| Finding | Disposition |
|---|---|
| N7 (partial) — the input worker could stay blocked in `read` if another process drained the requester's input | **Mitigated:** it holds no secrets and is no longer waited for indefinitely. |
| N8 (partial) / N13 — a process whose name is not UTF-8 made `/proc` parsing fail, and the group was then treated as dead and not signalled | **Fixed:** `/proc` is parsed as bytes; anything that cannot be inspected counts as alive. |
| N10 (partial) — the "Allow for" note was added after the length check; the unlock prompt was not checked | **Fixed:** room is reserved for the note; the unlock prompt is checked. |
| N12 — writing to a client descriptor that was not being read blocked the request even after the client left | **Fixed:** writes never block indefinitely (sockets with `MSG_DONTWAIT`, other descriptors in `PIPE_BUF` chunks after `poll`), and a disconnect aborts them at once. A connected client that does not read still holds the request (L19). |
| N14 — the `SCM_RIGHTS` control buffer was a byte vector, not aligned for `cmsghdr` (undefined behaviour with an unusual allocator) | **Fixed:** u64-backed buffers on receive *and* send. The test written for this showed that `nix`'s own `sendmsg` has the same latent problem, so Rusthorse no longer uses it. |
| Coverage — reverting only the `_` variable in the approval key passed all tests | **Fixed:** dedicated test; a mutation run reverting each of 21 fixes in turn is described in the commit history. |

Findings of the fourth review (verification of the third round; N10, N13 and
N14 were confirmed fixed):

| Finding | Disposition |
|---|---|
| N15 — a concurrent writer could fill the requester's pipe between `poll` and `write`, so a write the agent made could still block after a disconnect; the same applied to the input worker's reads | **Fixed by design:** with redaction the agent no longer reads or writes the requester's descriptors at all. Output and input travel as data frames over the agent's own socket, whose writes fail at once when the peer goes away; `rusthorse run` relays them to its own stdio. |
| N7 / N12 (partial) — a detached input worker could consume input after the result | **Fixed:** there is no input worker in the agent any more; `rusthorse run` reads its own stdin only with `--stdin` and exits right after the result (L18). |
| N16 — a process whose main thread called `pthread_exit()` shows as a zombie while other threads run, so it was not signalled | **Fixed:** a process counts as alive while any thread in `/proc/<pid>/task` is (L17). |
| Docs overclaimed that writes never block and that the command is always already terminated in L19 | **Fixed** (architecture, L19). |
| Coverage | A mutation run after this round reverted each of 23 fixes from all four rounds in turn; the test suite failed for every one. |

While implementing this round, a test caught that `nix`'s `PollFd::revents()`
returns nothing at all when the kernel reports a bit `nix` does not name
(`POLLRDHUP`), which made disconnects invisible; the agent relies on
`POLLHUP` instead.

Findings of the fifth review (verification of the new I/O design; N8, N15 and
N16 were confirmed fixed):

| Finding | Disposition |
|---|---|
| N17 — cancelling (on a protocol violation or a half-close) killed the command but left the socket open, so a blocked send kept the request stuck; a half-close went unnoticed while input was pending | **Fixed** (completed in the sixth round, N20): one cancellation path shuts the socket down (failing any pending send without taking the send lock) and terminates the group; the watcher polls with `POLLRDHUP` through raw `poll(2)`, so a half-close is seen even with input pending; half-close and any protocol violation are defined as cancellation. |
| N18 — the CLI relayed stdout and stderr in order, so a stuck stdout held stderr back | **Fixed:** per-channel writer threads and per-channel credit windows (1 MiB). |
| N19 — the library's `Client::run` left a stdin reader running after it returned | **Mostly fixed** (residual race documented in L18): `Client::run_with` takes the input and outputs explicitly; its reader reads only after `poll` and stops within ~100 ms of the return. |
| Docs: "one response frame", "the client only receives the exit status", cancellation states | **Fixed** (protocol, ADR 0002, architecture, L18, L19). |
| Coverage | A mutation run after this round reverted each of 27 fixes from all five rounds in turn; the test suite failed for every one (one test had a race that let its mutation pass; it now waits long enough to be deterministic). |

Findings of the sixth review (verification of flow control and cancellation;
N12 and N18 were confirmed fixed):

| Finding | Disposition |
|---|---|
| N20 — input pending for the command stopped the agent from reading the connection, so output credit could not arrive: a command that writes a lot before reading its input deadlocked (and a protocol violation queued behind the input went unnoticed) | **Fixed:** stdin has its own credit window (`0x80`); the agent buffers pending input within it and reads the connection continuously. |
| N21 — the client's cancellation waited for the send lock, which a blocked send could hold | **Fixed:** cancellation uses a separate handle that needs no lock. |
| N22 — a destination blocked forever kept `run_with` from returning after the other destination failed | **Fixed:** after a failure, writers are awaited for at most half a second; one still blocked in its destination is left detached (documented on `run_with`). |
| N7 / N19 — a concurrent reader of the same input between `poll` and `read` leaves the input reader blocked | **Documented** (L18): cannot be interrupted without changing flags shared with the caller. |
| The client trusts the agent's credit window (its queues are unbounded) | **Accepted:** the agent is part of the trusted computing base (§4). |
| Coverage | A mutation run after this round reverted each of 32 fixes in turn. 30 made the suite fail (one only after a new test for end-of-input with pending input was added). Two are not caught by the suite: the lock-free client cancellation and requesting `POLLRDHUP`. The second is redundant while the watcher always reads the socket (a half-close then arrives as end-of-file and cancels). The first was described here as equivalent because "sends can no longer block"; the seventh review showed that a client's sends *can* still block transiently (for example while the approval dialog is open), so it is a coverage gap kept as defence in depth, not a proven equivalence. |

Findings of the seventh review (N20–N22 confirmed fixed), and the readiness
gaps it listed:

| Finding | Disposition |
|---|---|
| N23 — the watcher wrote stdin acknowledgements to the socket itself; a client that never read them blocked that write, and the watcher stopped noticing half-closes and violations | **Fixed:** acknowledgements are written by a separate thread; the watcher never writes to the socket (completed in the eighth round: the watcher now outlives that thread). |
| Input read before approval | **Fixed:** the client starts with no stdin credit; the agent grants it when the command starts. |
| "125 means the command did not run" was not always true | **Fixed:** 124 now means the connection was lost after the request was sent (outcome unknown); 125 is kept for refusals and failures before the command ran. |
| Migration could only be checked with `list` | **Fixed:** `import --dry-run`, batching, and a documented procedure that verifies each entry by using it. |
| No verified backup or restore procedure | **Fixed:** `rusthorse backup` (verified copy) and a restore procedure. |
| Master password change, KeePassXC coexistence | **Fixed:** `rusthorse passwd`; documented KeePassXC procedure; a test runs Rusthorse's edits on a KeePassXC 2.7.12 file and checks untouched entries are identical. |
| Notes could be stored but not read | **Fixed:** `reveal --notes` (approval). |
| Search, `open`, generated values, `doctor`, completions, protocol-version check | **Done.** |
| Clipboard, lock on screen lock or suspend, man page, packages | **Later** (clipboard deliberately omitted on X11; see the roadmap). Lock on screen lock and suspend came later: [ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md). |
| CI never ran; no rehearsal on the real desktop | **Open:** runs once the repository is published; the desktop rehearsal is the owner's first test. |
| MSRV | The declared minimum Rust version (1.89) was checked with that toolchain. |
| Coverage | A mutation run reverted each of 41 fixes in turn: 39 make the suite fail (one only after a test that corrupts a backup before it is verified was added); the two not caught are the ones described in the sixth table. |

Findings of the eighth review (generate, open, search, notes, completions and
backup were confirmed; the reviewer listed N23, N24 and N25 as blockers for
a first real test):

| Finding | Disposition |
|---|---|
| N23 (residual) — after the command exited, the watcher stopped before the acknowledgement writer; a client that never read acknowledgements left the request pinned, and a half-close was no longer noticed | **Fixed:** the acknowledgement writer is stopped and joined first; the watcher keeps supervising (and can cancel, releasing it) until then. |
| N24 — `passwd` said the old-password backup was deleted even when the deletion failed | **Fixed:** a failed deletion is reported with the file to delete by hand; the directory is synced after a successful one. |
| N25 — exit 125 was still possible after the command started (local setup failures after sending, malformed results), and a missing agent gave 1 | **Fixed** (completed in the ninth round, where an agent-side failure after the command started still gave 125): the client creates its connection clones and relay threads before the request is sent, and the agent clones its sockets before the command starts (creating the agent's relay threads can still fail after the command has started; see L12); a lost connection, a malformed result or an agent that cannot determine the result of a started command is 124; the version check for `run` is part of its error handling (125). |
| N26 — the protocol version stayed 1 across incompatible changes, so an older agent passed the check and then deadlocked | **Fixed:** protocol version 2; a check that gets anything but a status answer fails. |
| N27 — `doctor` checked the vault named in the client's environment, not the one the agent uses | **Fixed:** it checks the vault and audit log the agent reports (new `status.audit_log`). |
| Partial imports were not summarised; duplicates were not shown in the preview | **Fixed.** |
| KeePassXC round trip is checked with the same parser, not by opening the result in KeePassXC | **Open:** part of the owner's first test (open the vault in KeePassXC after using Rusthorse). |
| Coverage | A mutation run reverted each of 46 fixes in turn: 44 make the suite fail. The test for the N23 shutdown order only became effective after its command stopped producing output (output workers blocked by the unread output had masked the order) and with a small agent-side send buffer, a test-only setting. The two not caught are those described in the sixth table. |

Findings of the ninth review (N23, N26 and N27 confirmed fixed; verdict: not
ready, because of N25 and N28):

| Finding | Disposition |
|---|---|
| N25 (remaining) — the agent cloned a socket after starting the command; a failure there was reported as "did not run" (125) and left the command unreaped | **Fixed:** both clones are made before the command starts; after it has started, a failure to determine its result is reported as `outcome_unknown` (exit 124) and the command is terminated and reaped. |
| N28 — `passwd` read the cleanup result after releasing the lock, so a concurrent `lock` could make a failed deletion look like a success | **Fixed:** the cleanup result is read under the same lock as the save. |
| N29 — when a batch's answer was lost, the import summary said that batch had not been imported | **Fixed:** a lost answer is reported as "may or may not have been imported"; the advice for running again accounts for `--replace`. |
| N30 — the preview said only the first of two duplicate names would be imported, but `--replace` stored the second | **Fixed:** duplicate names are refused, by the CLI before anything is sent and by the agent. |
| Coverage | A mutation run reverted each of 50 fixes in turn: 48 make the suite fail (one only after its test was made to approve, so that the refusal it checks is not masked by a denial). The two not caught are those described in the sixth table. Two fixes of this round (socket clones before the command starts; reading the cleanup result under the lock) remove races that the tests cannot trigger deterministically and are verified by review. |

Findings of the tenth review (N25 and N28 confirmed fixed, N30 confirmed;
verdict: ready for a first real test with revocable credentials, keeping the
originals and an independent backup):

| Finding | Disposition |
|---|---|
| N29 (residual) — a save can fail after the new file has replaced the vault (syncing the directory); the agent answered `internal` and the import summary said the batch was not imported, although it was in the file | **Fixed:** that failure is a distinct error, answered as `outcome_unknown` (the vault is locked, so the next unlock reads the file); the vault records the new file as its own, and an old-password backup is kept until a save completes. The protocol now states that every other error means the vault file was not changed and no command was started, and the import summary relies on exactly that. |
| The ninth table overstated N25: "everything that can fail" was prepared before the command started, but the agent's relay threads are created afterwards | **Fixed** (the entry now says what is prepared when; L12 covers the rest). |
| Found while fixing N29: `add`, `edit`, `remove`, `passwd` and `backup` reported a lost answer as an ordinary error (exit 1); an unexpected answer to `run` gave 125; the client created its relay threads after sending a `run`, so failing to create one aborted the CLI | **Fixed:** for requests with effects, a lost or unreadable answer and `outcome_unknown` exit with 124 (read-only commands keep 1); an unexpected answer to `run` is 124; the client's relay threads are created before the request is sent. |
| Coverage | A mutation run reverted each of 61 fixes in turn: 59 make the suite fail (one of them by hanging a test, which counts as a failure). The two not caught are those described in the sixth table. Creating the client's relay threads before the request is sent is verified by review: the tests cannot make thread creation fail. |

Findings of the eleventh review (the N29 residual, the error classification,
the relay-thread preparation and the N25 wording confirmed fixed — the
reviewer repeated the directory-sync failure and made each relay thread fail
to start; verdict: ready for a first real test with revocable credentials,
originals kept and an independent backup, with client and agent from the
same build):

| Finding | Disposition |
|---|---|
| N31 — the CLI relied on the new "definite errors" contract while still accepting an agent of the same protocol version built before it, so upgrading the CLI without restarting the agent brought N29 back | **Fixed:** protocol version 3; the compatibility rules now say that changing what an error guarantees bumps the version. `status` reports the agent's program file and `doctor` fails when the agent still runs a build that was replaced, so a skipped restart is noticed even when the protocol does not change. |
| An `exited` answer with neither a code nor a signal gave 125; an answer of the wrong kind to a change gave 1 | **Fixed:** both are unknown outcomes (124). |
| Ideas: show which build the agent runs; a migration guide that starts with one item; a short acceptance test | **Done:** `status`/`doctor` (above); [installation.md](installation.md#migrating-existing-secrets) now starts with one item, warns about broad attributes and ends with opening a backup copy in KeePassXC. |
| Idea: exercise relay-thread creation failures in the regression tests (the reviewer did so by interposing `pthread_create`) | **Later:** it needs a preloaded C shim; until then it is verified by review. |
| Coverage | Reverting each fix of this round makes the suite fail; going back to protocol version 2 does not compile (a compile-time check). |

Findings of the twelfth review (N31 and the two low findings of the eleventh
review confirmed fixed; no new finding of medium or higher severity; verdict:
ready for the first real test):

| Finding | Disposition |
|---|---|
| `doctor` took any program name ending in ` (deleted)` for a replaced file; a real file can have such a name | **Fixed:** the agent reports `agent_executable_replaced`, judged by file identity: the name is followed and compared, by device and inode, with the file `/proc/self/exe` leads to. |
| "The agent runs this build" claimed more than a comparison of path strings shows (symlinks, renamed files, `cargo run`) | **Fixed:** the two files are compared by device and inode, and the message says "the same program file". That is not proof of the same source code if a file is rewritten in place, which installers do not do. |
| Ideas: a build identifier in `status`; tests for symlinks and renames in the diagnosis | **Later:** a build identifier needs the build to embed one (a build script); the identity checks have unit tests with a file named like the kernel's marker, a replaced file and a removed one. |
| Coverage | Reverting each fix of this round makes the suite fail. |

Findings of the thirteenth review (the name-suffix false positive and the
"same build" overclaim confirmed fixed, including a path reused by a new
file; no new finding of medium or higher severity; verdict: ready for the
first real test):

| Finding | Disposition |
|---|---|
| A path the agent could not examine (no permission, an I/O error) was reported as replaced | **Fixed:** only a missing path or a different identity counts as replaced; otherwise the answer is "cannot tell" (the field is left out), never a failure. A first version sent `null`, which a client that knows the field as a plain boolean cannot read (fourteenth review); unknown values are now left out. |
| `doctor` looked up the agent's path in its own mount namespace, where the same name can lead to another file, and could report "the same program file" for different files | **Fixed:** the agent reports the device and inode of the file it runs, read through its own `/proc/self/exe`, and `doctor` compares that with its own. |
| Coverage | Reverting each fix of this round makes the suite fail (the permission case is skipped when the tests run as root, which ignores directory modes). |

The fourteenth review found the `null` field above; the fifteenth confirmed
it fixed and found nothing new (verdict: ready for the first real test).

Findings of the first real test, on the owner's desktop with a vault of fake
entries, Claude Code and Codex acting as the AI agents. Using a secret
through `run` worked as designed from both agents — the command received the
value, the agents saw `[REDACTED:…]` — and denial, the audit log's requester
chain (`… ← codex ← claude ← …`), `backup` and an `import secret-service
--dry-run` of 34 items behaved as documented. What it found:

| Finding | Disposition |
|---|---|
| R1 — an approval's audit record carried the time the request arrived, 23 seconds before the owner answered | **Fixed:** records are dated when they are written, after the decision. |
| R2 — the AI's non-interactive shell did not have `~/.cargo/bin` on its `PATH`, so it could not find `rusthorse` | **Fixed (documentation):** [installation.md](installation.md#from-source) explains the check and the fix; the last setup step in [ai-agents.md](ai-agents.md#setting-up-an-agent) is `rusthorse doctor` from the AI's own shell. |
| R3 — the owner took the master-password dialog for an approval and clicked Unlock three times with the field empty, which was recorded and reported as three wrong passwords | **Fixed:** the dialog starts with "Type the master password"; an empty field asks again without counting as wrong, and an unlock where nothing was typed is cancelled. [getting-started.md](getting-started.md) tells the two kinds of dialog apart. |
| R4 — a dialog nobody answered was reported as a denial or a cancellation by the human | **Fixed:** it is `timed_out` in the audit log and "nobody answered … in time" in the message, so "nobody looked" is not mistaken for "the human said no". Exit statuses are unchanged. |
| R5 — a backup to an existing file failed with "File exists (os error 17)" | **Fixed:** the message says a backup never replaces a file and asks for a new name. |
| Not covered by this test | "Allow for …" (off by default) and opening a backup copy in KeePassXC; both are left to the owner. |

Findings of the sixteenth review (R1–R5 confirmed fixed; no finding of medium
or higher severity; verdict: ready to continue the real tests):

| Finding | Disposition |
|---|---|
| A regression test ("a batch never sent is not imported") failed about once in thirty full-suite runs: its fake agent closed its listener after answering, but the next connection could still be queued — by the listener, or by the copy a child forked by another test holds until its exec — and was reset after its request was sent | **Fixed:** the fake removes the socket file before its last answer, so later connections fail at once (0 failures in 80 full-suite runs, 40 of them under CPU load). |
| The documentation said audit times keep the file in order and equal the moment of the answer | **Fixed:** they come from the system clock, after the decision, and can go backwards if the clock is set back. |
| The `PATH` advice assumed `~/.local/bin` exists and is on the AI's `PATH` | **Fixed:** check first, create the directory, fall back to the absolute path. |
| Idea: test that each `passwd` dialog, cancelled or unanswered, is recorded once and changes nothing | **Done.** |
| Idea: a "waiting for you to answer a dialog" hint in the terminal; the reviewer recommends an explicit event from the agent rather than a client-side timer, synchronised with the start of a command's output | **Later.** |
| Coverage | Reverting each code fix of R1, R3, R4 and R5 makes the suite fail; reverting the test fix brings the intermittent failure back (5 failures in 800 runs of that test under load). |

Findings of the seventeenth review (all of the above confirmed fixed; no new
finding of medium or higher severity; verdict: ready to continue the real
tests):

| Finding | Disposition |
|---|---|
| An audit time can trail the answer while other records are being written | **Fixed (documentation).** |
| Ideas: check the in-memory password after a cancelled `passwd`; back up to symbolic links and to a directory without write permission | **Done:** a change applied only in memory, or a followed link, makes the suite fail. |

Findings of the eighteenth review, of the new approval-dialog layout (Pango
markup; markup escaping confirmed correct, including zenity's escape
processing; verdict: not ready until the first finding is fixed):

| Finding | Disposition |
|---|---|
| U+2028 and U+2029 passed through unescaped and became real line breaks: a 279-character command made a dialog 1,416 pixels high, able to push the start of a command or the warnings out of sight | **Fixed**, first by escaping them, then for good by the allow-list of the nineteenth review. |
| The `run` explanation said the secrets go only to that command (the programs it starts receive them too); "nobody sees it" overstated what `--generate` guarantees | **Fixed:** "programs it starts can use them too", "outside any sandbox"; "the value is not returned to the program that asked". |
| Ideas: show the requester chain as unverified; test the layout with the real renderer | **Done:** "Requested by (unverified)" in every dialog. **Later:** Pango-based tests ([roadmap](roadmap.md)). |

Findings of the nineteenth review (the wording and the separators confirmed
fixed; verdict: not ready until the first two findings are fixed):

| Finding | Disposition |
|---|---|
| The height limit counted characters: with wide ASCII, CJK, fullwidth characters or emoji, dialogs of 1,053 to 1,313 pixels passed it, against the "about 700 pixels" the documentation promised | **Fixed:** dialogs draw only ordinary characters (ASCII, Latin letters, a little punctuation), so widths are known; the height is estimated in pixels for an 11-point font, wrapping word by word, with requester text in warnings measured at the widest character; the limit is 880 pixels, and the documentation states the assumptions instead of a promise. `import` batches are sized in lines. |
| Combining marks outside the listed blocks (U+08F0) piled up and were drawn hundreds of pixels outside their line | **Fixed:** no combining mark is drawn in a dialog any more; each is a `\u{…}` escape. |
| U+2800 (blank Braille pattern) is drawn as nothing | **Fixed:** escaped in dialogs and refused in entry names. |
| Coverage | Reverting each fix makes the suite fail. One mutation survives by design: shrinking the room reserved for the "Allow for" note to the two lines the note needs. Tests that waited on a fake agent without a limit now fail after 60 seconds instead of hanging. |

Findings of the twentieth review (the nineteenth review's findings confirmed
fixed: nearly two thousand dialogs built to be as tall as possible, measured
with the real renderer, all stayed below the estimate; verdict: ready to
continue the real tests):

| Finding | Disposition |
|---|---|
| The roadmap's broker design audited "the token" — a bearer credential that anyone reading the log could use | **Fixed (design):** uses are audited under the grant's public identifier, never the token. The roadmap now lists what the broker's ADR must settle: revoking open sessions, counting uses atomically, HTTP redirects and routing, binding a token to the command's processes, binding SSH signatures to a destination. |
| `Ĳ`, `ĳ` and `ŉ` were drawn as themselves and pass for `IJ`, `ij` and `'n` | **Fixed:** escaped like the other look-alikes. |
| The documentation said dialogs cannot impersonate text, ignored that a literal `\u{…}` looks like an escape, and gave a "1.4 to 1.6 times" margin that one ordinary dialog did not reach (1.16) | **Fixed:** the claims now match what was measured, and the user documentation says to take any `\u{…}` for the character it names. |
| AGENTS.md stated invariants that intentional behaviour contradicts (the CLI handles secrets in `init`, `import` and `--stdin`; `reveal` prints a value), omitted the disclosure rules, and told agents to install and restart without asking | **Fixed:** exceptions listed, SECURITY.md referenced, hands-on testing only when the maintainer asks; also the exit statuses a run command can produce itself, the rule for new optional fields, mutation checks on a copy. CONTRIBUTING.md now names `ui::dialog_text`. |
| Coverage | Reverting the look-alike fix makes the suite fail (checked on a copy of the repository). |

Findings of the twenty-first review (the twentieth review's findings
confirmed fixed, two of them partly; verdict: ready to continue the real
tests):

| Finding | Disposition |
|---|---|
| AGENTS.md still said dialogs never come from the client (`init` without a terminal asks for the master password itself) and gave exit status 4 for denials without excepting `run` (125); CONTRIBUTING.md kept the old rules without the exceptions | **Fixed:** both files state the same exceptions and statuses. |
| The roadmap said peer credentials make a copied token useless elsewhere; a process can hand a connected socket to another, and loopback TCP has no peer credentials | **Fixed (design):** the claim is limited to new Unix connections, and both gaps are listed as questions for the ADR. |

Findings of the twenty-second and twenty-third reviews, of the design of
[ADR 0006](adr/0006-own-dialog-program.md) before any code (verdicts:
implement after changes; then change first; accepted after the changes
below):

| Finding | Disposition |
|---|---|
| The request was to go to the dialog program on standard input, which as a pipe another process could read or rewrite through `/proc`: the dialog could show one request while the agent ran another | **Fixed (design):** one socket pair for both directions, length-framed JSON with size limits, a request identifier echoed in the answer, a private protocol version checked before anything is shown. |
| The agent would have relied on the program to time out and to answer sensibly | **Fixed (design):** one external deadline covers the whole exchange, after which the agent kills and reaps the program; a partial, oversized or contradictory answer, or a failure after a valid answer, is a denial. |
| "Nobody approves what they could not see" overclaimed | **Fixed (design):** an obligation to reach the end of the content, checked after layout and on every resize, for every way to approve; one scroll, no truncation. |
| Environment, per-user GTK configuration (a `gtk.css` could hide text), the Inspector and the accessibility API were not settled | **Fixed (design):** an enumerated environment, a fresh private configuration directory per dialog, in-memory settings; the accessibility path documented in L2, as it already applies to zenity. |
| No compatibility contract between an agent and a program installed later | **Fixed (design):** protocol version, `--check`, `status` and `doctor` report the program. |
| Replacing `HOME` would have hidden `~/.Xauthority` from X11 sessions that do not export `XAUTHORITY`, making every dialog fail | **Fixed (design):** the authority file is resolved before `HOME` is replaced and passed explicitly; tested with and without `XAUTHORITY`. |
| Lesser points: the `init` exception, theme wording, icons, when zenity is the fallback, the private directory's lifetime, the light/dark preference depending on the portal | **Fixed (design).** |

Findings of the twenty-fourth to twenty-sixth reviews, of the implementation
of [ADR 0006](adr/0006-own-dialog-program.md) (verdicts: not ready, not
ready, then ready for the owner to try it); and of its first installation:

| Finding | Disposition |
|---|---|
| An answer sent a byte at a time stretched the deadline: each read renewed the timeout | **Fixed:** every read and write is bounded by the time left before one absolute deadline. |
| zenity had no external deadline, though the ADR said it had; `doctor`'s `--check` read its output without one | **Fixed:** both run under the same supervision (process group, deadline, output limit). |
| A descendant of the dialog program outlived it, holding the socket; a program that moved itself to another process group escaped the kill and kept the agent waiting | **Fixed:** the group is killed, then the program itself, and only then is it reaped, so neither id can have been reused. Tests cover both. |
| First installation: `cargo install` under umask 002 left the program group-writable, the agent refused it, and no dialog could be shown | **Fixed:** the installation guide runs `chmod go-w`, and the agent's and `doctor`'s messages give the command. A first fix that accepted the user's "private group" was withdrawn: users sharing a group as their primary group are not listed among its members. |
| Lesser points: typed text that JSON escaping made too large for an answer frame, height limits applied to dialogs that scroll, a race between the height check and the choice of program, bytes after the request accepted, a test that took a crash for a denial, `doctor` checking a path in its own mount namespace, a suggested command without shell quoting | **Fixed**, except the namespace point, which is documented. |
| Coverage | Reverting each fix makes the suite fail; widget tests for resizing, scaling and accessibility actions are not written yet ([roadmap](roadmap.md)). |

### ADR 0007 and manager milestone 1

The first implementation of milestone 1 was written by Codex and reviewed by
Claude (AI-assisted) on 2026-11-01, before any commit of the code. Findings
and what was done:

| Finding | Disposition |
|---|---|
| The widget test failed: in the test's empty environment (C locale), `xdotool` could not read the window title, which contains "—", so it never found the window; the runtime directory was group-writable (umask 002) | **Fixed:** the test sets `LANG=C.UTF-8` and creates the directory `0700`; a failed search prints the display's window tree. |
| Any failed request — a denial included — cleared the entry list and the details | **Fixed:** a failure keeps what is shown; a background status check decides whether the vault was locked meanwhile. Tested. |
| The five-second status check disabled every control and showed "Waiting for the agent" each time; a click during it was silently ignored | **Fixed:** the status check runs apart from the human's requests, never touches the controls, and is cancelled when the human starts a request. |
| Long random values could be shown but not copied, so they had to be retyped | **Changed by the maintainer's decision:** single-paste Copy after its own approval ([ADR 0007](adr/0007-visual-manager.md#2-show-copy-and-memory), L14); `reveal` gains an optional `purpose`, shown in the dialog and audited. End-to-end and widget tests cover the allowed and denied paths, one paste, expiry, a later copy left alone, and clearing on lock. |
| `AGENTS.md`: invariant 1 had been reworded so that its rule ("only the agent handles secrets taken from the vault") disappeared | **Fixed:** the rule is back, extended to the manager. |
| The interface was far from the approved prototype; the command snippet named the variable `SECRET`; install commands had lost their line continuations; the guide was dense | **Fixed:** sidebar with icons, grouped list with avatars, Secret and Details rows, the app's accent; the variable takes the entry's name when that is a valid variable name; commands and guide rewritten. |

Open risks, by design or for later milestones:

- Show and Copy put copies of a value where Rusthorse cannot wipe them (L14).
- Closing a client during a change does not undo it; lost or unexpected
  replies are reported as uncertain outcomes, without automatic retries.
- Status polling observes locks after a delay; there is no push notification.
  A lock between a status check and the listing makes the agent ask for the
  master password; the manager does not answer or retry it.
- A plain lock is not exclusive access for KeePassXC; an automated handoff
  waits for a maintenance mode (ADR 0007, M3). Locking on screen lock and
  suspend was not implemented yet (M2); it is now, in the agent
  ([ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md), L20).
- No keyboard and accessibility review yet, and no tests at other display
  scales.

Review of milestone 1 with Copy (Codex, AI-assisted, 2026-11-01; verdict: not
ready), and what was done:

| Finding | Disposition |
|---|---|
| Clearing could destroy what another program had just copied: when it took the clipboard before GTK processed the change of owner, GTK still believed it owned it, and emptying the clipboard claimed it back (reproduced on Xvfb) | **Fixed:** clearing wipes the value inside the provider and never claims the clipboard. A widget test lets `xclip` take the clipboard without GTK noticing, clears, and checks that `xclip`'s content survives. |
| "One paste" was not what the code did: during a one-second grace, two different programs both got the value, and a reader 600 ms after the copy got the plain "Pasted once" message | **Fixed:** a single delivery, no grace; a second reader, however soon, gets nothing (tested with two `xclip` readers). The message no longer claims the paste was the human's. Programs that ask twice for one paste get nothing the second time; documented. |
| While a request waited for the human, status checks stopped, so a lock made elsewhere went unseen and a copied value stayed available (6.2 s after the lock, in the reviewer's run) | **Fixed:** checks continue during a request; a result older than the request is ignored (tested: an "unlocked" read before Lock now does not make the manager list again and the agent ask for the password); a lock seen meanwhile wipes the copied value at once, and a value the request returns afterwards is dropped. Tested with an approval held open while another client locks. |
| Declaring no storable format does not stop GTK 4.14 from offering the clipboard to a clipboard manager (`SAVE_TARGETS`) at exit, unlike what the code and the ADR said | **Fixed:** the value is wiped on window close and on application shutdown, and SIGINT, SIGTERM and SIGHUP quit through that path (a test sends SIGTERM to the real program on Xvfb and checks a normal exit). Comments, ADR and L14 corrected. |
| The guide promised that a lock elsewhere is noticed "within five seconds" | **Fixed:** worded as a check every five seconds, also during requests. |

Each fix was reverted in a copy of the tree to see a test fail.

Verification of those fixes (Codex, AI-assisted, 2026-11-01; verdict: not
ready): the clipboard race, the single delivery and the shutdown wipe were
confirmed fixed; new findings and what was done:

| Finding | Disposition |
|---|---|
| Answers already on their way when a lock was seen could undo it on screen: a refresh's "unlocked" status, processed after a lock seen by a check of the same epoch, restored "Unlocked" and listed again, which made the agent ask for the master password; a pending list put entries back while the window said "Locked" (reproduced; no unlock without the password) | **Fixed:** after a lock is seen during a request, a returned value, list or "unlocked" status is dropped and the status asked again. Two widget tests queue each answer before the lock and check that the agent stays locked and the list empty. |
| The SIGTERM test passed with the shutdown wipe disconnected | **Fixed:** the program and the widget test share the shutdown wiring (`wipe_at_shutdown`); the widget test copies a value, emits the application's shutdown, and checks the value is gone. The SIGTERM test checks that a signal quits normally. |
| The guide and the ADR promised that a reader's copy is always noticed, and that an empty paste means another program read the clipboard | **Fixed:** the guarantee is stated as one delivery by Rusthorse's provider (a program can put the value back on the clipboard itself); an empty paste lists its possible causes. |

Each fix was reverted in a copy of the tree to see a test fail (3 of 3).

Verification of those fixes (Codex, AI-assisted, 2026-11-01): **ready for the
maintainer to try with fake entries.** Both findings confirmed fixed; the
three targeted mutations fail their tests; a late `Ok` after a lock, an
approved unlock during a check that saw the lock, and repeated refreshes
behave. One conservative effect, by design and now in the guide: when a Show
or Copy has to unlock the vault first, a check during the password dialog
sees the vault locked and the approved value is dropped; asking again works.

**Copy redesigned after the maintainer's first try (2026-11-01).** On
Cinnamon, every Copy came back empty when pasted. The logs showed every
`reveal` approved; a probe on the maintainer's display showed why: Cinnamon's
window manager (Muffin 6.6.3) fetches the clipboard text the instant an
application copies — ignoring `x-kde-passwordManagerHint` — so it always took
the single paste; and it puts its copy back on the clipboard when the copying
program exits, which wiping inside the manager cannot reach. The maintainer
chose a plain copy with an honest note over a stricter design that cannot
work on the target desktops and would push users to photograph values. The
single-paste provider, the clipboard banner, the termination-signal handling
that existed for it and their tests were removed; Copy is now plain text
after its own approval, Copy in the Show window copies what is shown
without a new approval (the `show` dialog says so), and the grouping of a
shown value is decided on the value itself, not on its escaped form (a test
caught an escape being cut into groups). L14, ADR 0007, the guide and the
agent's dialog texts say where a copied value goes.

Review of the redesign (Codex, AI-assisted, 2026-11-01; verdict: not ready),
and what was done:

| Finding | Disposition |
|---|---|
| The meaning of `reveal.purpose` changed under the same protocol version: the new manager, talking to an agent built before the change, got an approval whose dialog promised "one paste, then clear it" and copied plainly; and copied from Show though that dialog did not say it could | **Fixed:** protocol 4. Clients refuse an agent of another version, so a manager never relies on a dialog of another meaning. The manager's test of an older agent now uses the version before the current one. |
| Copying a value with a NUL character crashed the manager (GTK text cannot hold a NUL) | **Fixed:** the value is not copied, in part or whole, and the manager says why without showing it; tested from the entry and from the Show window. |
| "Stays on the clipboard, and in a clipboard history, until something else is copied" suggested that copying something else also clears a history | **Fixed:** the dialogs, the window and the docs now say that it stays on the clipboard until something else is copied, and that a clipboard history may keep it even after that. The end-to-end test checks the agent's wording. |
| `RevealPurpose::Copy`'s documentation still promised a single paste; GNOME's behaviour was stated as fact though only Cinnamon was tested; the ADR said no stricter Copy could work at all; a comment said the shutdown cleanup runs "however it quits" | **Fixed:** documentation corrected; GNOME marked as not verified; the ADR says the single-paste design cannot work on Cinnamon and that the maintainer chose not to add other protections; the comment says a signal skips it. |

Each fix was reverted in a copy of the tree to see a test fail (3 of 3;
the documentation fixes have no test).

Verification (Codex, 2026-11-01): **ready to keep trying with fake entries.** Two low points followed and were fixed: the tests of an older agent now pin protocol 3 (and the version may not go below 4, checked at compile time), and the remaining texts that called protocol 3 current were corrected.

**Layout as in the prototype (2026-11-01).** The maintainer found the
details squeezed and the grouped, bold value of the Show window pointless
now that it can be copied. The sidebar took half of any spare width (a
child's `hexpand` propagated to it); it now has a fixed width, the details
take the rest, rows are key/value lines, and Show draws the value as one
plain label.

Review of that change (Codex, AI-assisted, 2026-11-01; verdict: not ready;
no new way for a value to leave, no authorization change), and what was
done:

| Finding | Disposition |
|---|---|
| Medium — the window's minimum width grew from 985 to 1121 pixels: a 1024-pixel screen no longer held it (the key column, the bullets that could not shrink, and the long Show and Copy labels) | **Fixed:** a 120-pixel key column as in the prototype, bullets that shrink, buttons labelled **Show…** and **Copy…** (the row says Value or Notes; the full action is in the tooltip and the accessible name), and a list that narrows to 260. The narrowest layout is now 941 pixels, 951 with the window's frame; the widget test measures it. |
| Medium — the key/value rows had lost their accessible names (AT-SPI showed them unnamed, without a labelled-by relation) | **Fixed:** each row is labelled by its key label; the Show and Copy buttons carry "Show the value", "Copy the value to the clipboard", …. The widget test checks the relation and the names. |
| Low — Pango drew a hyphen where a long value wrapped in the Show window (`W-` with a value of `W`s), and the guide said the value is never changed | **Fixed:** no hyphens in the Show window, the command snippet or any metadata label; the guide says so. The widget test checks the attribute. |

Each fix was reverted in a copy of the tree to see a test fail (5 of 5).
Ideas from the same review, not adopted yet: fold the UUID and technical
fields into "Advanced details", tags as separate chips, a list that can be
collapsed, Show and Copy beside their field in a compact layout.

**Entry kinds (2026-11-01).** At the maintainer's request:
[ADR 0008](adr/0008-entry-kinds.md) (kinds, protocol 5, `run --url`).
Writing it made one existing gap visible, now in L4: variables that redirect
where an approved program sends a key (`OPENAI_BASE_URL`, `HTTPS_PROXY`)
come from the requester and are not listed in the run dialog. Ten mutations
of the new behaviour, and one of a fix made before review (a kind hid a row
whose field the file withholds), each made a test fail.

Review of the kinds, `run --url` and the layout fixes (Codex, AI-assisted,
2026-11-01): **ready to keep trying with fake entries.** The three layout
findings above are confirmed fixed (reverting each fix made its test fail).
No high or medium finding. Also checked: `--url` replaces an inherited
variable and refuses collisions and risky names; an identical URL reuses a
remembered approval and another URL asks again; a denied edit keeps the old
kind; a foreign `Kind` is listed by name and a protected one withheld; edits
and `--replace` keep the previous state in the history; a protected URL is
refused without being printed; the manager refuses a protocol-4 agent; the
snippet stays literal shell for hostile names and ids.

| Finding | Disposition |
|---|---|
| Low — the CLI reference and ADR 0008 said `--url` is refused "before anything is asked", but with the vault locked the master-password dialog comes first (reading the URL needs the vault open) | **Fixed** in both: refused before the run is approved; the unlock may come first. |

Ideas from the same review, not adopted yet: list destination and proxy
variables in the run dialog (already planned under L4), a kind filter in the
manager, a "show all fields" switch in the form, and end-to-end tests for a
changed URL under a remembered approval and for the manager against a
protocol-4 agent (both checked by hand in this review).

A follow-up checked every `--url` option before reading any entry: with
several, a later option's name clash was found only after an earlier read,
which may ask for the master password. The maintainer then asked for the
"show all fields" switch, which shows every row without changing the kind
(tested; reverting it made the test fail).

**Destinations in the run dialog (2026-11-01).** At the maintainer's
request, closing the L4 gap above as far as a dialog can: the run dialog
lists, under "Connects to" (renamed "Destinations" after review), the variables whose names say where the program
connects (`*_URL`, `*_URI`, `*_API_BASE`, `*_ENDPOINT`, `*_HOST`, `*_ADDR`,
`*_REGISTRY`, `PGHOST`…), and warns about proxies, certificate authorities,
disabled certificate checks and name resolution. Values are shortened to
scheme, host and port (user, password, path and query left out), in the
dialog and in the audit record; the command gets them unchanged. Two
choices made against warning fatigue, both tested: a certificate variable
that names the system's own store (`SSL_CERT_DIR=/usr/lib/ssl/certs`, which
Claude Code's environment sets) is not listed — judged on the text, absolute
and without `..`; what lies inside a store only root can change — and
`NO_PROXY`, which only bypasses a proxy, is not either. Rendering the real
dialog on a virtual display showed a defect of `rusthorse-dialog` that
predates this change: keys of detail rows broke inside words with a hyphen
("Dire-ctory"), and Pango may draw such a hyphen in any wrapped text,
including a command or a path being approved. Keys now break between words
only, a parenthesized qualifier moves under its key, and no dialog label
inserts hyphens; a widget test on Xvfb checks it. Thirteen mutations each
made a test fail.

Review of the destinations, the "show all fields" switch and the `--url`
ordering (Codex, AI-assisted, 2026-11-01; verdict: not ready), and what was
done:

| Finding | Disposition |
|---|---|
| High — a backslash made the dialog name the wrong host: with `OPENAI_BASE_URL=http://127.0.0.1:PORT\@provider.invalid/v1` it showed `provider.invalid`, while Node, which reads `\` as `/`, sent the (fake) token to the local server (reproduced end to end) | **Fixed:** only unambiguous forms are shown. A backslash or a control character anywhere, two `@`, a host with characters other than letters, digits, `.`, `-` and `_`, or a malformed URL (`https:/host`) makes the value `(not shown)`, and a warning names the variable. |
| High — lists and malformed values leaked credentials: `GOPROXY=user:PASSWORD@private,https://proxy.golang.org` kept the password (the scheme of the second item was taken for the whole), and `https:/hooks…/TOKEN?key=…` kept its path and query — in the dialog and, after a denial, in the audit log | **Fixed:** the values of list variables (`GOPROXY`, the extra indexes of pip and uv) are read item by item, each shortened on its own; any other value is one item, so that a comma inside a URL's path cannot pass part of it off as an item (found while fixing); an item without an unambiguous form is not shown at all. |
| Medium — `SSL_CERT_DIR=/etc/ssl/certs:/tmp/fake-ca` counted as the system store, though OpenSSL then trusts the second directory (verified with a fake authority) | **Fixed:** every `:`-separated element must lie inside a store; certificate variables are shown as paths. |
| Medium — `AWS_ENDPOINT_URL_S3`, which the AWS SDKs prefer to `AWS_ENDPOINT_URL`, was not listed | **Fixed:** `AWS_ENDPOINT_URL_<SERVICE>` is an endpoint. |
| Medium — the entry form's Kind and switch rows kept each other alive through their handlers: twelve forms opened and closed left twelve pairs alive | **Fixed:** the handler holds weak references; the widget test checks that the closed form's rows are freed once another form replaces it. |
| Low — a variable given twice was shown twice, sorted, though the command gets only the last value | **Fixed:** the dialog is built from the same last-wins view as the environment. |
| Documentation — "credentials are left out" was false in those cases; "no symlink can be swapped" claimed more than a text check; "shows where the program will connect" overstated what the dialog knows; ADR 0008 still said the dialog lists no such variable | **Fixed:** each statement corrected; the row is now called **Destinations**, settings found in the environment, not connections. |

Each fix was reverted in a copy of the tree to see a test fail.

Verification of those fixes (Codex, AI-assisted, 2026-11-01; verdict: not
ready). Confirmed fixed: the backslash case, `SSL_CERT_DIR` lists,
`AWS_ENDPOINT_URL_S3`, the manager form's cycle. (A first request for this
verification was refused by the reviewer's provider as a possible
cybersecurity risk, being phrased as a search for bypasses; it was asked
again as a verification of the display's correctness.) New findings, and
what was done:

| Finding | Disposition |
|---|---|
| High — list separators were the same for every list variable: pip reads `PIP_EXTRA_INDEX_URL` at spaces only, so `https://user:1234,5678@packages/…` is one URL whose password contains a comma, and the dialog and the audit log showed part of it | **Partly fixed:** each list variable has the separators its program uses (`GOPROXY`: `,` and `|`; pip and uv: spaces); Unicode spaces, which pip also splits at, were left (completed in the next round). |
| High — an empty authority was taken for a local path: `https:///hooks.invalid/TOKEN` was shown whole (Node and curl connect to `hooks.invalid`), and so was `//TOKEN@host/path` | **Fixed:** an empty authority is shown only for `unix:` and `file:`; a path starting with `//` is not shown. |
| High — libpq takes its server from the query: a `DATABASE_URL` showing `…@expected.invalid` connected, with the fake `PGPASSWORD`, to the server in `?hostaddr=…&port=…` (reproduced end to end) | **Partly fixed:** a URL whose query has `host`, `hostaddr`, `port`, `service`, `servicefile`, a socket or server parameter, or a parameter name with `%`, is not shown, and the warning names it; `?sslmode=require` and the like stay shown. Parameters after a `#`, which libpq still reads, were missed (completed in the next round). |
| Medium — `UV_INDEX` was in the list of list variables but not recognised as a destination, so it never reached the dialog (uv queried the index it named first) | **Fixed:** `UV_INDEX` and `UV_DEFAULT_INDEX` are endpoints, their `name=URL` items keep the name. |
| Low — when a later `SSL_CERT_DIR` named the system store, the warning still showed the earlier, replaced value | **Fixed:** the environment is consolidated (last value wins) before anything is classified. |
| Low — numeric IPv4 forms (`0x7f.1`, `127.1`, `2130706433`, `0177.0.0.1`) were shown literally, though parsers read them as `127.0.0.1` | **Partly fixed:** inside a URL, a host whose last label is a number must be a canonical `a.b.c.d`; but a lone word was still shown in any variable, so `PGHOST=2130706433` passed (completed in the next round). |
| Noise — `PIP_TRUSTED_HOST="pypi.org files.pythonhosted.org"` and a certificate path with a space were `(not shown)` | **Fixed:** `PIP_TRUSTED_HOST` and `UV_INSECURE_HOST` are trust settings (a warning) split at spaces; certificate paths may contain spaces. |
| Documentation — "the dialog never names a host the program will not use", "credentials are left out", and the description of list separators said more than the code | **Fixed:** the docs list the forms shown and not shown, and say that the rules cover the known readings of common parsers and libpq, not every program. |

Each fix was reverted in a copy of the tree to see a test fail.

Second verification (Codex, AI-assisted, 2026-11-01; verdict: not ready).
Confirmed fixed: the empty authority, `UV_INDEX`, the consolidation of
duplicates, both noise cases. The remaining findings were narrower readings
of the same kind, so the rules were made more general rather than closer
imitations of each program:

| Finding | Disposition |
|---|---|
| High — libpq reads a `#` in the query as part of a value and goes on reading parameters: `…?application_name=x#y&hostaddr=127.0.0.1&port=…` showed the URL's host, without a warning, and the fake `PGPASSWORD` reached the local server | **Fixed:** an item with a `#` anywhere is not shown, and a query parameter name of other characters than letters, digits, `_`, `-` and `.` makes the URL not shown. |
| Medium — pip splits `PIP_EXTRA_INDEX_URL` at Unicode spaces too (`str.split`): with U+00A0 between two URLs, the second index disappeared into the first one's hidden path, without a warning | **Fixed:** a value with anything outside printable ASCII is not shown at all; a space is accepted only where it separates items or pads them. |
| Low — a bare number passed as a word in any variable: `PGHOST=2130706433` (libpq connected to 127.0.0.1), `HTTPS_PROXY=0x7f000001` | **Fixed:** words and numbers are shown as they are only for switches and ports (`GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `PGPORT`); elsewhere a bare number is a host and must be `a.b.c.d`. |
| Low (noise) — `GOPROXY=https://proxy.golang.org, direct` warned, though Go trims each item | **Fixed:** `GOPROXY` items are trimmed of spaces. |
| Documentation — "does not name a host that common parsers would not use" was false for the `#` case; "split as the program splits it" did not hold for Unicode spaces or `GOPROXY` padding; F1, F3 and F6 were recorded as fixed | **Fixed:** the docs state the aim and what it is checked against; the previous table records those three as partly fixed. |

Each fix was reverted in a copy of the tree to see a test fail.

Third verification (Codex, AI-assisted, 2026-11-01; verdict: not ready).
Confirmed fixed: the `#` case, Unicode spaces, bare numbers in host
variables, `GOPROXY` padding, the partial records. New findings:

| Finding | Disposition |
|---|---|
| High — libpq looks for the `@` of user information up to the first `/`, past a `?`, where URL parsers stop: `postgresql://expected.invalid?x=fake@127.0.0.1:PORT/postgres` showed `expected.invalid`, and the fake `PGPASSWORD` reached 127.0.0.1; `postgresql://fake:12345?x=rest@db.invalid/app` showed part of the password, also after a denial | **Fixed:** a `?` and an `@` both before the first `/` make the value not shown. |
| Low (noise) — several hosts in PostgreSQL and MongoDB URLs, and in `PGHOST`/`PGPORT`, were not shown | **Fixed:** `postgres:`, `postgresql:` and `mongodb:` authorities may list plain hosts separated by `,`; `PGHOST`, `PGHOSTADDR` and `PGPORT` are lists at `,`. |
| Low (noise) — `sqlite:///./development.db` was not shown | **Fixed:** `sqlite` is a local scheme (judged by the part before a `+`; four slashes for an absolute path accepted). |
| Low (noise) — `LOCALDOMAIN` and `RES_OPTIONS` lists were not shown | **Fixed:** both are lists at spaces; the warning stays. |
| Low — `CARGO_REGISTRIES_<NAME>_INDEX` was not classified | **Fixed:** it is an endpoint. |
| Documentation — "are left out" and "the aim … is met" were contradicted by the `?` case | **Fixed:** the docs say the rules were checked against the readings found to differ, case by case, and are an aid, not a guarantee. |

Each fix was reverted in a copy of the tree to see a test fail.

Fourth verification (Codex, AI-assisted, 2026-11-01): **ready, as an aid
for reading the dialog.** Every finding of the third verification
confirmed fixed; 135 PostgreSQL cases compared with libpq and 62 HTTP and
FTP cases compared with Node, urllib, requests and libcurl showed no shown
host that differs from the one used, and no fake credential, path or query
marker in what is shown — which is not exhaustive. The reviewer's opinion:
sufficient for its limited role, with conservative omissions warned about
and incomplete coverage documented; a guarantee of destination needs
control where the credential is sent (the planned credential broker). One
low finding, noise: `sqlite:///:memory:` was not shown — **fixed**
(`sqlite://` and `sqlite:///:memory:` are in-memory databases; tested,
and reverting it made the test fail).

**Lock on screen lock and suspend (2026-11-02).** At the maintainer's
request, as planned by ADR 0007 (section 6):
[ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md), `session_lock`, L20.
Tested end to end on two private `dbus-daemon` buses with a fake logind (its
inhibitor a pipe, to see the agent release it before the "suspend" and take
a new one after the "resume"; sessions of two users) and a fake Cinnamon
screensaver: each source locks; another user's session lock does not;
`LockedHint` turning false, `ActiveChanged(false)` and a resume never
unlock; repeated signals record one lock; the loss of the session bus shows
in `status`. A unit test checks that a lock from a signal changes the
generation of a vault already locked (an unlock under way does nothing) and
records nothing then. Building the test showed that a `dbus-daemon` policy
without receive rules accepts connections but never delivers replies.
Eleven mutations each made a test fail.

Review (Codex, AI-assisted, 2026-11-02; verdict: not ready; no way found for
a signal to unlock), and what was done:

| Finding | Disposition |
|---|---|
| Medium — logind's sender was not authenticated: `zbus` does not check a well-known sender name locally, and a signal sent to the agent alone bypasses the bus's matching. A program that does not own `org.freedesktop.login1` sent a `PrepareForSleep` with an empty body: deserialising it failed, the watcher ended — letting go of the inhibitor — and waited to reconnect, so a real signal right after did not lock | **Fixed:** logind's signals count only as broadcasts whose sender is the current unique owner of its name (asked again when it differs); malformed signals are ignored; nothing but a lost connection ends a watcher. The end-to-end test sends both and checks: no lock, the same inhibitor held, no reconnection, and the real signal after them locks. |
| Medium — blocking questions on the signal connection: with `Inhibit` pending, a `PrepareForSleep(true)` locked only 5.2 s later; with 100 signals queued while a session's user was asked, the reply never arrived (the bounded queue blocked the reader that would deliver it) | **Fixed:** each watcher asks its questions on a second connection, each limited to 2 seconds; the inhibitor is asked for on a helper thread, and one that arrives during a suspend is let go at once. Tested: a 3-second `Inhibit` does not delay the next suspend's lock; 200 other users' `Lock` signals before ours do not stop ours from locking. |
| Medium — `status` and `doctor` promised protection that did not exist: on buses without logind or a screensaver, all three sources were active and `doctor` said OK; a refused inhibitor was OK too | **Fixed:** a source is active only when its service is there; a refused inhibitor is *degraded*; `doctor` warns on both, with the reason. Tested on buses without those services. |
| Low — the watchers outlived the agent: dropped, it kept its threads, connections and inhibitor until a message came | **Fixed:** `start` returns a handle that the agent keeps; dropping it closes the connections, which lets go of the inhibitor, and joins the threads (never the current one). Tested. |
| Low — the test checked the audit record as soon as it saw the vault locked, though the record is written after | **Fixed:** the test waits for the record. |
| Documentation — "takes far less than the delay", "accepted only from logind", no word of the unknown-user rule, the inhibitor's limit, `doctor` warnings the code did not give | **Fixed** in ADR 0009, cli.md, architecture.md, protocol.md and L20. |

Ideas from the same review, adopted: on connecting again, a watcher locks if
a session of the agent's user is already locked or a screensaver is already
on (tested: a screensaver on when the session bus comes back locks);
permanent tests for a forged sender, a saturated queue and missing services.
Not adopted yet: recording when each source last fired. Each fix was
reverted in a copy of the tree to see a test fail (12 of 12, plus one for
the recovery through logind). Two mutations survived at first and showed
weak tests: the fake logind answered `Inhibit` after 3 s, past the 2-second
limit, so the "inhibitor that arrives during the sleep" path was never
taken — the test now has both cases, a timed-out answer (the suspend lock
reported degraded) and a late one within the limit (let go at once); and
the fake answered whose a session is so fast that signals never piled up —
it now takes 500 ms for the other user's session, which made the shared-
connection deadlock show. A check of the real buses, read only, found the
same signals and properties as the design assumed.

Verification of those fixes (Codex, AI-assisted, 2026-11-02; verdict: not
ready). Confirmed fixed: the forged and malformed signals, the original
blocking cases, missing services at start, a refused inhibitor, the audit
race. New findings, and what was done:

| Finding | Disposition |
|---|---|
| Medium — the inhibitor could be let go before the lock was done: the watcher marked "going to sleep" before locking, and an inhibitor that arrived while the lock waited for the agent's state lock (a vault save) was closed at once | **Fixed:** three phases — awake, locking, locked. An inhibitor that arrives while locking is kept and let go once the lock is done; one that arrives after it is let go at once. Tested with a locker that holds the lock until released. |
| Medium — stopping the watchers had no limit while a bus accepted the connection but never answered its authentication: `method_timeout` does not cover it, and the connection was not yet known, so it could not be closed | **Fixed:** each connection is kept for closing as soon as it exists, and stopping waits at most 3 seconds for the threads; one still connecting is left to end on its own, holding nothing. Tested with a socket that never answers. |
| Medium — recovery took "no answer in time" for "not locked": a screensaver that said "on" after 3 s left the vault open, and only presence was refreshed | **Fixed:** without an answer in time, a watcher locks; a definite "cannot tell" (no logind, a screensaver that does not implement `GetActive`, as Cinnamon's `csd-screensaver` does not) locks nothing; a screensaver that appears later is asked too. Tested: a slow `GetActive` and a slow `LockedHint` lock; a refusal, no logind, and a screensaver off do not; one that appears already on locks. |
| Medium — after logind left, the suspend lock still showed as watched (the refresh asked only when no inhibitor was held) | **Fixed:** the refresh checks the owner of logind's name and lets go of an inhibitor given by a logind that left or restarted, then asks again — which reports logind's absence. Tested: logind leaving and coming back. |
| Low — the saturated-queue test asked about the other user's session before the burst, so the answer was cached and the queue never filled while waiting | **Fixed:** the burst is about a session not asked about before, whose answer takes 500 ms. Reverting the separate connection now makes the test fail. |
| Documentation — "a slow one never delays a lock" (questions about logind's owner and a session's user are asked in the watcher's thread, within the limit), "a signal sent to the agent alone is ignored" (one from logind itself is not), "the vault is locked first" | **Fixed** in architecture.md, ADR 0009 and L20. |

Each fix was reverted in a copy of the tree to see a test fail (10 of 10;
an eleventh mutation found a redundant status update, removed).

Second verification (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Confirmed fixed: the late inhibitor during a lock, stopping with a mute bus,
recovery without an answer, logind's absence in `status`, the saturated
queue (reverting the separate connection now fails the test). One new
finding, from the previous fix:

| Finding | Disposition |
|---|---|
| Medium — the refresh let go of the inhibitor when logind's name changed hands, without looking at the phase: with a lock held up (a vault save) and logind restarting, the inhibitor was let go with no lock done. A failed `GetNameOwner` led there too. And the premise was wrong: systemd keeps inhibitors when logind restarts, so a new unique name does not make the descriptor useless | **Fixed:** only a completed lock lets the inhibitor go. logind's presence (asked with `NameHasOwner`; no answer is not absence) changes only `status`; when logind is there and no inhibitor is held, one is asked for. Tested: logind's name changing hands while a lock is held up keeps the inhibitor until the lock is done; logind leaving keeps it, shows in `status`, and coming back is watched again with the same inhibitor, whose next suspend lock lets it go. The earlier disposition ("lets go of an inhibitor given by a logind that left or restarted") is replaced by this one. |

Each fix was reverted in a copy of the tree to see a test fail (3 of 3). A
mutation script had counted syntax errors as failing tests; the one earlier
mutation that might have been such a case was redone as valid code and
still failed the test.

Third verification (Codex, AI-assisted, 2026-11-02): **ready.** The finding
is confirmed fixed — the reproduction (a lock held up, `PrepareForSleep`,
logind's name changing hands) keeps the inhibitor until the lock completes,
and restoring the previous code makes both it and the project's test fail.
No new medium or high finding. The reviewer's opinion: sufficient for the
documented use, accepting the dependence on the desktop's signals and buses
and logind's maximum delay (L20).

**Debian package (2026-11-02).** At the maintainer's request — Rusthorse
should be as easy to install and remove as any desktop application:
[ADR 0010](adr/0010-debian-package.md), `packaging/`. The maintainer
scripts were first simulated by hand in a temporary root (`DPKG_ROOT`)
with stand-ins for `loginctl` and `systemctl`.

Review (Codex, AI-assisted, 2026-11-02; verdict: not ready), and what was
done:

| Finding | Disposition |
|---|---|
| Medium — `prerm` ignored `DPKG_ROOT`: removing the package from another root (a system image built with `--root`) would have stopped the agents of this computer's users | **Fixed:** nothing is stopped when `DPKG_ROOT` is set, nor where systemd does not run. Tested: no call with `DPKG_ROOT` set, none on upgrade. |
| Medium — the copyright file had only Rusthorse's license, not the notices of the crates compiled into the programs (the `keepass` crate's MIT notice, among others), which their licenses require to go with the binaries | **Fixed:** `packaging/copyright.py` lists every crate that Cargo.lock resolves for the three programs (173), with version, license, source and copyright notices, and the license texts they ship, each once; it fails on a crate with no text it can give. |
| Low — `prerm` hid every failure, while the guide said removal stops every agent | **Fixed:** it asks each session whether its agent runs, stops it, and warns on standard error when the users cannot be listed, a session does not answer or an agent does not stop; the guide says it tries, and what to do. Tested with stand-ins for each case. |
| Low — after an upgrade that changes the service file, a restart without `systemctl --user daemon-reload` keeps the old definition | **Fixed (documentation):** the guide and ADR 0010 say to reload before restarting; agents are still never restarted by the package. |
| Low — no Debian changelog and no manual pages | **Fixed** for the changelog (`changelog.Debian.gz`). **Open:** manual pages (roadmap). |
| Low — links of the installed documentation led nowhere (`LICENSE`, `CONTRIBUTING.md`, the manager prototype, source files) | **Fixed:** `packaging/docs.py` installs those documents and points links to the source code to GitHub at the revision built; it fails on any link that leads nowhere. |

Ideas from the same review, adopted: the maintainer scripts are now tested
automatically (`tests/packaging.rs`: stand-ins for `prerm`, and the real
`deb-systemd-helper` in a temporary root for installation, an
administrator's `--global disable` kept across upgrades and a reinstall,
removal and purge). Not adopted yet: a virtual machine test with a logged-in
user, Lintian in CI (there is no CI yet). Debhelper's mask on removal,
which the reviewer also mentioned, is no longer created by current debhelper
and is not used. Each fix was reverted in a copy of the tree to see a test
fail (8 of 9). The survivor is harmless by design: `postinst`'s `was-enabled`
check follows debhelper's template, but `deb-systemd-helper enable` already
skips a unit whose state file exists, so an administrator's choice is kept
either way.

**First start from the manager (2026-11-02).** At the maintainer's
request — install, open Rusthorse, start the agent if needed, create the
vault: [ADR 0011](adr/0011-first-start-from-the-manager.md),
`create_vault` (protocol 6). The master password of a new vault is now
asked by the agent whenever one serves the vault, also for `rusthorse init`,
which closes a gap: an AI that ran `init` had the password typed into a
process it started. A new vault is linked into place, so one created
meanwhile is never replaced. Tested end to end (creation through the
agent's two dialogs, cancel at each, mismatch, too short, an existing vault
without a dialog, a lock while typing, two requests at once, an unwritable
audit log) and on Xvfb (Start agent with a stand-in `systemctl` that fails,
then works; Create vault; a status check does not repaint the page). End-to-
end commands now run without `DISPLAY`, so a command that tried to show a
dialog itself would fail instead of reaching the desktop. Each fix was
reverted in a copy of the tree to see a test fail (13 of 14); the survivor,
the "vault exists" check before waiting for the dialog lock, is redundant
by design — the check after the lock decides.

**Import read by the agent (2026-11-02).** At the maintainer's request —
an Import button in the manager, for the migration from GNOME Keyring:
[ADR 0012](adr/0012-import-read-by-the-agent.md), `keyring_items`,
`dotenv_names`, `import_from` (protocol 6). The agent reads GNOME Keyring
and `.env` files itself; the CLI and the manager send names only, and no
longer hold imported values (AGENTS.md invariant 1 narrowed). The import
dialog names the source, which the older `import` request could not: there
the requester supplies the values. Listing the keyring or a file's names
asks for approval, so that a requester that reaches only the agent — a
future isolated AI (§8) — cannot use it to learn what the keyring or a file
holds; for the same reason `import_from` answers nothing that depends on the
source before the human allows it. A `.env` path must be absolute and a
regular file (opened without waiting: a FIFO is refused at once); a locked
keyring item is refused rather than unlocked, because the keyring's prompt
has no time limit; every call to the Secret Service is bounded (10 s), and
so is a whole request's use of it (30 s, then the socket is shut down). Tested end to end with a fake Secret
Service on a private bus (`fake-keyring` feature, never in a release): the
CLI's keyring import, metadata only in the listing, a locked item refused
before any dialog; `.env` imports with a prefix, a dry run, denied
listings, a FIFO, a relative path, missing and repeated names. On Xvfb: the
manager's two import windows (names from an attribute, the filter, a locked
item that cannot be ticked, repeated names that keep Import off, a denied
batch reported as not imported, the values in the vault file). Building the
test found that the manager erased what a change reported at the status
check that follows it (for example a warning of `passwd`); fixed. Each
check was reverted in a copy of the tree to see a test fail (14 of 14; one
passed at first because the test looked for "from GNOME Keyring" anywhere in
the dialog, where the explanation says it too — the test now checks the
summary).

Second review of the package and the first start (Codex, AI-assisted,
2026-11-02; verdict: not ready). Confirmed fixed: `prerm` and `DPKG_ROOT`,
the warnings of removal, `daemon-reload`, the Debian changelog (manual pages
left open, as decided) and the links of the installed documentation; the
crates' licenses, but for one point below. New findings:

| Finding | Disposition |
|---|---|
| Medium — `init` compared its path with the agent's as text: `init --vault vault.kdbx` in the vault's directory showed its own dialog, so the password would have entered the requester's process although the agent served that file | **Fixed:** the agent reports an absolute path, and `init` compares paths after making them absolute and resolving the links of their nearest existing directory; when an agent's socket answers with an error (not "nothing listens"), `init` stops instead of asking itself. Tested: `vault.kdbx` and `./sub/../vault.kdbx` use the agent's dialogs; unit tests for links, `.`, `..`, directories not created yet, and which errors mean that no agent runs. |
| Medium — `create_vault` with a vault open whose file had been moved away created an empty file and said the vault was "locked meanwhile", while the old one stayed open with its entries | **Fixed:** refused while a vault is unlocked (`invalid_request`, lock first); the "locked meanwhile" answer now depends only on a lock. Tested: refused with the file moved, accepted after `lock`, and the old entries are gone. |
| Medium — `init` without an agent exited 1 when its dialog was cancelled and when the file was written but not synced, against the documented 4 and 124 | **Fixed:** 4 for a cancelled or unanswered dialog, 124 for `NotDurable`, as for requests to the agent; a unit test checks the mapping (the dialog path itself needs a desktop). |
| Low — for `blake2b_simd`, which ships no license file, the copyright file made up "Copyright (c) the blake2b_simd authors: Jack O'Connor" instead of the original notice | **Fixed:** no notice is made up any more. The crate's license file from the upstream revision it was published from (`Copyright (c) 2018 Jack O'Connor`) is kept in `packaging/licenses/`; `block-modes` 0.9.1 contains no code (its source is one doc comment); any other crate without a license file stops the build. The list of notices no longer picks up sentences of license texts ("the copyright notice …"). |

Ideas from the same review, adopted: the reproductions are now tests (above),
with two more — the real `rusthorse agent` started with a relative `--vault`
reports it absolute, and `init` stops when something listens on the socket
but does not answer; **Start agent** stops a `systemctl` that has not
finished after 30 seconds (tested with a stand-in that hangs). Not adopted
yet: a test of the built package's contents. Each fix was reverted in a copy
of the tree to see a test fail (8 of 8, two of them only once the two tests
above were added).

Review of the agent-read imports (Codex, AI-assisted, 2026-11-02; verdict:
not ready). Confirmed fixed: `create_vault` beside an open vault, the exit
statuses of `init` without an agent, the copyright notices, the deadline of
Start agent; the path comparison of `init`, but for one case below. New
findings:

| Finding | Disposition |
|---|---|
| High — the `.env` parser read each line on its own, also inside an open quote: in a file with a multi-line PEM key, `dotenv_names` — approved to show names only — returned a line of the key as a name | **Fixed:** a quoted value may span lines up to its closing quote, after which only a comment may follow; a quote never closed refuses the whole file, with an error that names the line and nothing of it. Tested: unit cases, and `dotenv_names` on such files returns only the real names. |
| High — `init --vault new/sub/../vault.kdbx` with no `new` directory yet: the comparison gave up, which counted as "another file", and the CLI asked for the password itself | **Fixed:** paths are resolved component by component — links of what exists, `.` and `..` applied, the rest as written — and a comparison that cannot be made (a directory that cannot be examined) stops `init`. Tested: unit cases and an end-to-end `new/sub/../../vault.kdbx`. |
| Medium — `import_from` answered before the approval with what the source held: a locked item's label, whether a name was in a `.env` file | **Fixed:** only what the request says by itself is checked before the dialog; everything that depends on the source comes after the human allows it. Tested: a locked item, an unknown item and missing or repeated names are denied without a word about them, and refused with their reason only once allowed. |
| Medium — connecting to the bus was not bounded: `method_timeout` does not cover authentication, and a socket that accepted and said nothing held the request past 12 s | **Fixed:** the agent connects the socket itself (without waiting), and every keyring operation runs within a deadline (30 s); past it the socket is shut down, which makes the connection's pending reads fail, so the thread ends. Tested with a socket that never answers (a 0.5 s deadline). |
| Medium — the dialog did not show which keyring item would feed which entry: a requester could present another item under the expected name | **Fixed:** one row per entry with the item the agent found at that path (label and attributes); after the approval an item is read only if it is still what was shown. Tested: an unrelated item under `OPENAI_API_KEY` is shown as such; an item relabelled while the human decides is not read. |
| Medium — the import windows kept themselves alive: rows' handlers held the refresh, which held the state and the Import button, whose handler held the state | **Fixed:** the refresh holds weak references only. Tested on Xvfb: a box of a closed window is freed. |
| Low — a local `init` whose directory could not be synced said "no usable answer from the agent" | **Fixed:** its own message (the file is in place but may not survive a crash), still exit 124. |
| Low — the documentation said "after approval" and "no secret is read for a preview" where the code read before, and "the same values" for a repeated import | **Fixed** with the order above; a preview reads a `.env` file in the agent and sends only names; a repeated import takes what the source holds then. |

Each fix was reverted in a copy of the tree to see a test fail (11 of 11);
for one of them, `init` stopping when it cannot tell, an end-to-end test was
added first (a directory that cannot be examined).

Fourth review (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Confirmed fixed: the keyring deadline (a mute bus, a full backlog, abstract
addresses), the GTK cycle, the local outcome message; the others in part:

| Finding | Disposition |
|---|---|
| High — a single quote with a backslash before it (`'start\'`) still closed the value, so the next line came back as a name; python-dotenv reads it as still open | **Fixed:** `.env` files are read as python-dotenv and Node's dotenv read them — single, double and back quotes, a quote with a backslash before it never closes, python-dotenv's escapes — and a file that could hide a value from that reading is refused (a quote never closed, text after a closing quote, a quote on a line that is not `NAME=value`, which also covers Node's `NAME: value`). Tested with each quote, two backslashes, a value whose name is not allowed. |
| High — `init` still took equivalent paths for different ones when a link came after a missing directory (`missing/../link/…`) or pointed to a directory not created yet | **Fixed:** paths are resolved as the system would — every link followed, also one to something that does not exist yet, `..` climbing back resolves links again — and compared by the device and inode of their deepest existing directory and the names below it (also bind mounts); a loop of links or a directory that cannot be examined stops `init`. Unit-tested with each case. |
| Medium — the dialog's size, refused or shown, depended on the item's metadata before any approval | **Fixed:** keyring imports take items only from a listing the human allowed the same program (process id and start time) to see, within 10 minutes and since the last lock; the dialog shows that listing's metadata. Without such a listing every request is refused alike. Tested: forty long names on an existing and on a missing item give the same refusal; a listing by another program, an item not in the listing, and a lock all refuse. |
| Medium — entry names were the titles of dialog rows: zenity's markup changed their case, and a long name made the grid wider than the screen | **Fixed:** fixed titles ("Entry 1", …) and the name as content, which wraps. |
| Medium — batches counted lines of names, not the dialog: twenty short keyring items made a dialog too tall for zenity | **Fixed:** the dialog is built by one function, `import::approval`, which the agent shows and the clients use to size batches (`import::fits`, for the longest dialog a batch could have: every entry existing, a long requester chain). Tested: every batch fits and one more entry would not; twenty short items import in batches. |
| Low — the documentation claimed more than the code (nothing before the approval; 30 s for a whole request; text after a closing quote) | **Fixed** with the changes above: a request uses the keyring once, within 30 s plus 5 to end it; the `.env` rules are written out. |

Each fix was reverted in a copy of the tree to see a test fail (12 of 13).
The survivor: comparing `init`'s paths by device and inode instead of by
resolved path differs only for bind mounts, which the tests cannot create
without privileges; it is kept for them, checked by review only.

Fifth review (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Confirmed fixed: `init`'s paths (also a bind mount, which the reviewer made
in an unprivileged namespace; reverting to comparison by path made it fail),
the dialog rows, the refusal alike without a listing; the normal flow —
create from the manager, import 34 fake items, reopen the file and compare
every value — passed. Findings:

| Finding | Disposition |
|---|---|
| High — Node's `NAME: value` with an `=` inside the value got past the check for lines that are not `NAME=value`, and `dotenv_names` returned lines of the value | **Fixed** by giving up on following each library: `.env` files are read in the one dialect python-dotenv and Node's dotenv both read alike (one-line values; in quotes without a backslash or their own quote; unquoted with `#` only after a space), and any other line refuses the file, naming the line. Values over several lines are added with `rusthorse add`. Tested with both reproductions. |
| Medium — two backslashes before a quote: python-dotenv and Node read it differently, so the imported value could differ from the program's | **Fixed** by the same rule: a backslash in a quoted value refuses the file. |
| Medium — batches could hold more than the 100 entries the agent takes | **Fixed:** `import::MAX_ENTRIES`, shared by the agent and the batch planner. Tested with 250 tiny entries. |
| Medium — a lock while the keyring was being listed left that listing usable for imports | **Fixed:** a lock counter is taken before listing and checked, under the same lock, before the listing is kept; a lock meanwhile fails the listing with `locked`. Tested with a keyring slowed down during the listing. |
| Low — the room kept for the requester chain was not the longest possible | **Fixed:** eight 15-byte names of invalid UTF-8 (each byte shown as `\u{fffd}`) and the longest process ids; the height limit is applied only when the agent's dialogs are zenity's (`status.dialogs`). |
| Low — ADR 0012 named a dialog row for missing items and a `prefix` for `dotenv_names` | **Fixed.** |

Each fix was reverted in a copy of the tree to see a test fail (9 of 9; for
the requester's room, a test with the longest chain the agent can describe
was added first).

Sixth review (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Confirmed fixed: the batch cap, a lock during a listing, the requester's
room, the ADR's rows; the normal flow — create, import 34 fake items,
compare every value, back up, reopen the backup — passed. Findings:

| Finding | Disposition |
|---|---|
| High — characters the libraries treat as blanks or line breaks where Rusthorse did not: a byte-order mark before a quote (Rust's `trim` keeps it, so the value was read unquoted) and a lone carriage return ending a comment (a line break for Node) still let lines of a value come back as names | **Fixed:** the characters of a file are checked first: lines end with LF or CRLF, the only blanks are spaces and tabs, and a byte-order mark, a lone carriage return, a control character or any other blank or separator refuses the file, naming the line. Tested with both reproductions, end to end. |
| Medium — lines Rusthorse does not read (`NAME: fake`) were skipped without a word: an import said it succeeded and held part of the file | **Fixed:** every line that is not blank or a comment must be a `NAME=value` line of the dialect, or the file is refused; variables with an empty value are named (`empty` in `dotenv_names`, "not imported, because they have no value" in the CLI, "no value" in the manager), and asking for one is refused. |
| Documentation — "both read alike" and "any other file is refused" were not true | **Fixed** with the above, and checked: some 31,000 generated fake files, of which about 5,300 accepted (without repeated names), are read with the same names and values by python-dotenv 1.2.2 and Node's dotenv 17.4.2. The check found one more difference — python-dotenv keeps back quotes that Node's dotenv takes off — so a value in back quotes is refused too. |

Each fix was reverted in a copy of the tree to see a test fail (8 of 9;
the survivor, refusing a lone carriage return as a control character, is
redundant: Rust counts it as a blank too, which the next check refuses).

Seventh review (Codex, AI-assisted, 2026-11-02; verdict: not ready). No
value came back as a name; the earlier fixes held; the keyring flow —
create, import 34 fake items, compare every value, back up, reopen the
backup and compare again — passed. Findings, all in `.env` files:

| Finding | Disposition |
|---|---|
| Medium — `KEY=${PART}-suffix` was imported as written, while python-dotenv, by default, replaces `${PART}` (also in single quotes) | **Fixed:** a value holding `${` refuses the file; Rusthorse does not expand variables, from the file or from its own environment. |
| Medium — names were checked for repetition only among those with a value: with `DUP=` and `DUP=x`, batches were saved before the second one was refused | **Fixed:** a name set twice refuses the file when it is read — before any listing or import — so such a file starts no import. (An import still saves batch by batch; batches allowed before a denied or failed one stay saved, and the CLI and the manager say which.) |
| Low — the name `__proto__`, which Node's dotenv drops, was accepted | **Fixed:** refused. |
| Low — a carriage return at the very end of a file, without a line feed, was taken for a line end | **Fixed:** only a carriage return before a line feed ends a line. |

The differential check, run again with python-dotenv as programs use it by
default (replacing `${…}`) and new cases (`${…}`, `$NAME`, `__proto__`,
`constructor`, a final carriage return): of 31,290 generated fake files,
5,029 are accepted, none with a repeated name, and both libraries read them
with Rusthorse's names and values.

Each fix was reverted in a copy of the tree to see a test fail (4 of 4).

Eighth review (Codex, AI-assisted, 2026-11-02): **ready.** The four
findings are confirmed fixed; a differential check of 79,434 fake files, of
which 8,558 accepted, found no difference in names or values between
Rusthorse, python-dotenv 1.2.2 (interpolating, as by default) and Node's
dotenv 17.4.2, and no value coming back as a name or in an error. The
maintainer's flow — create the vault from the manager, import 34 fake items
of the `segredo` tool's form, compare every value, back up, reopen the
backup and compare again — passed. One low finding, documentation: "a file
is imported whole or not at all" suggested that all batches are one
transaction — **fixed**: the whole file is checked before any name is
listed, so a file with an error starts no import, and the import saves
batch by batch. The reviewer's opinion: ready for the planned first real
use; deleting the originals stays the last step, after each entry is used
and an independent backup is checked.

**Guide for AI agents (2026-11-02).** At the maintainer's request — an AI
agent should learn how to use Rusthorse from the `rusthorse` it runs, not
from a pasted snippet that goes out of date — `rusthorse guide ai` prints a
guide built into the binary ([§6](#the-guide-for-ai-agents-is-advice): it is
advice, not a mechanism). The instructions file only points to it.

Review of the guide (Codex, AI-assisted, 2026-11-02; verdict: not ready).
No new way for a value to leave the agent; the metadata, `--url`, the
approval of a dry run and the quoting of the `sh -c` example matched the
code. Findings:

| Finding | Disposition |
|---|---|
| Medium — "the dialog approves what the script contains at that moment": the agent checks the identity of the program and the directory, not the contents of what the command reads (L4); the reviewer replaced a script after its approval and the new version ran | **Fixed:** the guide says that the dialog shows the script's name, not its contents, that the approval trusts the script and every file the command reads as they are when it reads them, to show the script to the human, and not to change these files while a request is waiting or running. |
| Medium — "processes it leaves in the background are stopped": descendants that leave the process group (`setsid`) keep running (L17) | **Fixed:** the guide limits it to the process group, says that a program that detaches itself keeps running with the secret, and not to start servers or daemons with `run`. |
| Medium — the exit status table gave `2` as an invalid command line for every command, while `run` passes on any status of the command (the reviewer ran commands that exited with 1, 2 and 4 after doing their work) | **Fixed:** `run` has its own section: once the command has started, any status is the command's, `1`, `2`, `4`, `124` and `125` included, and a status from Rusthorse comes with a `rusthorse:` (or, for an invalid command line, `error:`) message; its table lists `125`, `124` and `2`. The other commands have their own table, with `0`. |
| Medium — the tests let wrong examples through (a code-block line continued with `\`, `--length nope`, `--alphabet invented`, `guide nope`, an extra status row) and refused a valid one (`rusthorse --socket PATH list`) | **Fixed:** every command line the guide shows, inline or in a code block (continued lines joined), is split as the shell splits it and parsed by the CLI's own parser, which checks subcommands, options and their values; a mention of a command may only leave a required argument out. Each status table must have exactly the expected rows. The reproductions are test cases. |
| Low — the closed-pipe test raced the write: the guide fits in a pipe's buffer, so `guide` could finish before the reader was closed | **Fixed:** the reader is closed before `guide` starts; a write to `/dev/full` is tested to be an error. |
| Low — "each run asks once" left out remembered approvals and unlocking; "the command reads nothing unless `--stdin`" holds only with redaction | **Fixed:** the guide states both conditions. |

Each test fix was checked against the mistakes it must catch, made in a copy
of the tree (12 of 12: the reviewer's examples, a dropped or made-up status
row, an unknown command, option or guide, a closed pipe taken for an error
and the opposite); the wording fixes are documentation, checked by review.

Second review of the guide (Codex, AI-assisted, 2026-11-02; verdict: not
ready). Confirmed fixed: scripts, the process group, the closed-pipe test,
remembered approvals and input; the reviewer ran commands that exited with
1, 2, 4, 124 and 125 after doing their work, and each status was passed on
without a message. Findings:

| Finding | Disposition |
|---|---|
| Medium — "Rusthorse's own statuses are the three below" left out `141`, which `rusthorse run` returns without a message when it cannot write the command's output; the reviewer sent the output to `/dev/full`: 141, no message, the command's work done and audited as `exited (exit code 0)` | **Fixed:** the guide lists `141` among Rusthorse's own statuses, says the command may have done some or all of its work, that a command killed by `SIGPIPE` exits with 141 too, and to let `run` write its whole output. `docs/cli.md` and the invariants in `AGENTS.md` say the same. |
| Medium — the tests still let wrong examples through: a code-block example without its required name, and `rusthorse show ';' --kind api-key`, whose quoted `;` the test took for a separator | **Fixed:** an example in a code block must be complete; only a mention in inline code may leave out a required argument. The shell split ends a command only at an unquoted `|`, `;`, `&`, `<` or `>`. A `--help` line is checked without its `--help`, since clap stops reading there (`list --help --kind invented` is refused). |
| Low — the exact comparison of the status rows skipped rows without backquotes (`\| 77 \| …`) | **Fixed:** every data row is read, and its first cell must be a status in backquotes. |
| Low — the audit log was said to show how a command ended "when the agent knows", but the agent goes on when it cannot write the record of the end | **Fixed:** the guide says that an approval in the audit log does not prove that the command ran, and that a missing record of its end does not prove that it did not. |

Each test fix was checked against the mistakes it must catch, made in a copy
of the tree (7 of 7: the reviewer's examples, a row without backquotes, the
`141` row changed, options after `--help`, a mention in a code block).

Third review of the guide (Codex, AI-assisted, 2026-11-02; verdict: not
ready). Confirmed fixed: the status rows, the audit log, the reviewer's
earlier examples. Findings:

| Finding | Disposition |
|---|---|
| Medium — `141` was said to mean that Rusthorse had stopped the command, but the client closes its connection and exits at once; the reviewer's command, which ignored `SIGTERM`, acted after `rusthorse run` had returned 141 and ended about 3 seconds later (the `SIGKILL`). With `--no-redact` there is no relay, and the command's own status came back | **Fixed:** the guide, `docs/cli.md` and `AGENTS.md` say that `run` asks the agent to stop the command and returns at once, that the command may go on for a few seconds, and that this is the relay of redacted output; the guide says to wait before checking the command's effects. |
| Medium — the tests let wrong examples through: options after a redirection (`list >/dev/null --kind invented`: the split ended at `>`), and an example in inline code without its required name (any inline code could be a mention) | **Fixed:** the split leaves out a redirection and its target and goes on reading; only the mentions listed in the test (`run`, `reveal`, `add --stdin`, `edit --stdin`) may leave out an argument, and each must appear in the guide. |
| Low — `eprintln!` panics when standard error cannot be written, so `rusthorse run … 2>/dev/full` without an agent exited with 101 instead of 125 | **Fixed:** the CLI's `eprintln!` drops a message it cannot write; an end-to-end test checks 125. The guide also says that a crash of `rusthorse` (101) tells as little as 124. |
| Low — the test refused `-h`, which clap reads like `--help` | **Fixed:** `-h` is checked like `--help`, without stopping there. |

Each fix was checked against the mistake it must catch, made in a copy of
the tree (5 of 5); the 141 wording is documentation, checked by review.

Fourth review of the guide (Codex, AI-assisted, 2026-11-02): **ready.** The
four findings are confirmed fixed: the reviewer's command acted after
`rusthorse run` had returned 141 and died by `SIGKILL` about 3 seconds
later, as the guide now says; with `--no-redact` its own status came back;
a run without an agent and with standard error on `/dev/full` exits with
125. Two low findings, both fixed: the test took a quoted number before a
redirection (`'2'>/dev/null`) for a descriptor, which the shell passes as an
argument — a quoted word now stays an argument (checked against the mistake,
2 of 2); and the guide said that 125 and 124 come with a message, which
holds only when standard error can be written — it now says so.

**Change the value from the manager (2026-11-02).** At the maintainer's
request: changing a value was hidden in **Edit**, behind a drop-down that
kept the current value. The **Secret** section now has **Change the
value…** — a prompt-only edit, so the agent opens its dialog for the new
value at once, as `rusthorse edit NAME --value` does — and **Replace with a
random value…**; the form shows the value choices as one row each. The
agent's policy is unchanged.

Review (Codex, AI-assisted, 2026-11-02): **ready.** No security finding:
the rows act on the entry shown (the panel is rebuilt on each selection),
not while a request runs, and a prompt-only edit asks for no approval
before the agent's own value dialog, which names the entry and the
requester. One low finding: the tests set the choices and activated the
rows in code, so rows that a click or a key no longer activates passed —
**fixed**: the widget test chooses with Space and Enter and changes the
value with Enter, through the X server of its virtual display (2 of 2
mutations caught). The reviewer also saw a test of the run dialog's height
fail when the temporary directory's path is long (889 estimated pixels
against 880); it passes with the usual short path, and is recorded as such.

**Move entries between groups (2026-11-02).** At the maintainer's request —
groups keep related entries together, a device's API token and its web
login, say — `edit.group` (protocol 7) moves an entry; the CLI has
`edit --group` and the manager's Group field is editable. Built by two
agents in parallel and reviewed once, as a whole.

Review (Codex, AI-assisted, 2026-11-02; verdict: not ready). No value
leaves the agent and no approval is bypassed; a nested recycle bin is
refused even when the bin is turned off, a partly invalid import leaves no
group behind, and a moved entry opens in KeePassXC 2.7.6. Findings:

| Finding | Disposition |
|---|---|
| Medium — the destination did not identify one group: with two sibling groups named `Shared` (another KeePass client allows them), the dialog showed `/Shared` and the entry went to the first; a group named `東京` and one named literally `\u{6771}\u{4eac}` were two destinations drawn alike | **Fixed:** a path through two groups of the same name side by side is refused, before any dialog (also for `add --group`); the dialog says which group the destination is — the UUID of the deepest existing group — and what is created: `/Work/Servers (existing group 8d2f6c1e-…)`, `/Work/Servers (creates Servers in /Work, group 1a2b3c4d-…)`, `/ (the top level)`. Names that look alike stay a limit of every dialog (L9); the UUID tells existing groups apart (the whole UUID since the next review). The audit record says from where to where. |
| Medium — whether a move was needed was decided by comparing paths as text: an entry in a group named `Work/Servers` (with a `/` in its name) was taken to be in the nested `Work` → `Servers` already, so a move there was dropped and the edit reported done | **Fixed:** the path is resolved to a group and compared with the entry's group by identity, in the agent before the dialog and in the vault when saving. |
| Low — the manager's form compared normalized paths on both sides, so changing a group named ` Work ` to `Work` (another group) changed nothing | **Fixed:** a row left as it is moves nothing; an edited row is compared, normalized, with the group's exact name. |
| Low — `docs/architecture.md` and `docs/getting-started.md` still said protocol 6 | **Fixed.** |

Each fix was checked against the mistake it must catch, made in a copy of
the tree (5 of 5: the first of two same-named groups taken, a move decided
by the path's text, the destination shown without its group, no audit of
the move, the manager comparing normalized names).

Second review of the group move (Codex, AI-assisted, 2026-11-02; verdict:
not ready). Confirmed fixed: same-named siblings, the move decided by
identity in the agent and the vault, the manager's groups with spaces, the
protocol version in the docs. An external write during the approval made
the request fail (exit 1) and left the other program's file whole (L15).
Findings:

| Finding | Disposition |
|---|---|
| Medium — the 8-character start of a UUID did not tell groups apart: a file prepared by another program can give two groups UUIDs that start alike (`deadbeef-1111-…`, `deadbeef-2222-…`); with names drawn alike (`東京`, and literally `\u{6771}\u{4eac}`) both destinations read `/\u{6771}\u{4eac} (existing group deadbeef)` | **Fixed:** the dialog and the audit record show the whole UUID. Entries are still identified by the start of theirs in dialogs (`Group/Name (8d2f6c1e)`); two entries with look-alike names and UUIDs that start alike can only come from a file written by another program (the agent chooses the UUIDs of what it creates) — a limit noted under L9. |
| Medium — the manager still decided by text: with the entry in a group named `Work/Servers`, editing the row to `/Work/Servers` (meaning the nested groups) sent no move | **Fixed:** an edited row is always sent, normalized, and the agent decides by the group itself; an untouched row is not sent. |

Each fix was checked against the mistake it must catch, made in a copy of
the tree (2 of 2: a short UUID in the dialog, the manager deciding by text).
