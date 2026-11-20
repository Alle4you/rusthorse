# Threat model

This document states what Rusthorse protects, against whom, how, and — just
as important — what it does not protect. If you find a gap between this
document and the code, that is a bug; please report it
([SECURITY.md](../SECURITY.md)).

- Applies to: Rusthorse 0.1.x
- Last reviewed: 2026-11-09 (an audit of every document against the code;
  before that, on 2026-11-05, the manager's History page and the agent's
  settings; see [review history](#11-review-history))

## 1. Scope and the exact guarantee

Rusthorse is a local, single-user secrets vault for Linux desktops. A
long-running agent holds the decrypted KeePass database; clients (the CLI, the
visual manager, scripts, AI coding agents) ask it to *use* secrets. Two
different guarantees are easy to confuse, so they are stated separately:

1. **Preventing accidental exposure — provided.** A requester that is
   cooperative but fallible (an AI agent that makes mistakes, over-shares or
   follows instructions planted in what it reads) can use a secret for a
   purpose you approved without the value entering its memory, output, logs
   or context, and without being able to use it for something you did not
   see.

   Ordinary `run` gives the approved command the value and redacts literal
   copies of it by default. For each `run --broker` binding, the command gets
   a token, never the source credential; the broker puts that credential only
   where the command put the token, in the header values of requests it
   forwards to the origin the run named and the human approved, over verified
   TLS. A grant approves a capability, not each API call: requests to any
   path at that origin can spend credit, access data or do whatever else the
   key allows there without another dialog (L25). Mixed runs still deliver
   values for their ordinary bindings. Neither mode makes a hostile approved
   command harmless (L3–L5, L16).
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
| The agent's settings (`agent.toml`) | They decide how long the vault stays unlocked without use, whether approvals can be remembered and for how long, how long a dialog waits, and whether the vault locks on suspend and on screen lock. |
| Metadata (names, usernames, URLs, hosts, ports, tags) | Reveals what you have access to; useful for targeting. Treated as low sensitivity unless the file marks a field protected. |
| The vault file and its backups | Encrypted at rest; exposed to offline guessing if copied. |
| Broker tokens | Bearer capabilities usable through the local listener until the grant ends, for any path at its approved origin, within its limits. |
| A grant's credential in broker memory | Each broker holds only its own grant's credential; memory disclosure there must not expose the whole vault. |
| Approved origins and HTTP traffic | The origin a run names and the human approves decides where a credential goes; any path there is allowed. Prompts, responses and opaque bodies may contain sensitive data. The broker does not interpret them. |
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

- the `rusthorse` and `rusthorse-broker` binaries, the systemd unit and the
  session that starts them;
- the libraries it links (notably the `keepass` crate, which implements the
  file format and its cryptography) and the Rust toolchain that built it;
- the broker's HTTP/TLS dependencies (`hyper`, `tokio`, `rustls` with `ring`,
  `tokio-rustls`, `rustls-pki-types`) and the system CA file: the first
  existing of the three paths in `broker_protocol::open_ca_file`, a regular
  root-owned file with root-owned parent directories, none writable by group
  or others; the broker parses its certificates;
- `rusthorse-dialog`, `zenity` and the GTK stack they use, the X server or
  Wayland compositor that displays dialogs and delivers your keystrokes;
- the packaging checks used to distribute the programs: `build-deb.sh` checks
  the built broker, has cargo-deb write the packages into a new staging
  directory that only the user can enter (it refuses another manifest, whose
  package name cargo-deb would put unchecked in their file names), checks
  every broker in them there, and moves them to the output directory only if
  all pass, replacing rather than following a link at their names; otherwise
  it deletes the staging directory, and nothing reaches the output
  directory. Outside `target/release/packaging`, which it makes again on
  each run, the script removes only what a package that passed replaces at
  its name and the new file of a copy that fails (cargo-deb itself deletes
  the packages of rusthorse it finds in `target/debian`). This checks
  trusted build artifacts; it does not authenticate a malicious replacement
  binary, and it assumes that no other process of the user changes the
  staging directory between the check and the move;
- the kernel (Yama `ptrace_scope ≥ 1`, which is the default on Ubuntu, Mint,
  Debian and Fedora) and the file system holding the vault;
- **every program you approve**, for the secrets you approve it for, and
  everything that program loads or executes (L4). With a broker binding, this
  trust concerns what the key allows at the approved origin (L25), not
  direct receipt of the credential. The broker is trusted with that
  credential and runs as the same user; it is not a code-execution sandbox
  (L16).

## 5. Trust boundaries

```mermaid
flowchart LR
    subgraph user["Your user account (same uid)"]
        subgraph untrusted["Requesters — not trusted with values"]
            AI["AI agent / shell / scripts"]
        end
        subgraph trusted["Trusted computing base"]
            AG["rusthorse agent<br/>(started by systemd, non-dumpable)"]
            DLG["rusthorse-dialog / zenity"]
            BR["rusthorse-broker<br/>one process per grant"]
            BIN["binary, unit file, session"]
        end
        CMD["approved command<br/>(trusted by your approval)"]
    end
    HUMAN(("you"))
    FILE[("vault.kdbx")]
    AI -- "socket requests" --> AG
    AG -- "asks (socket pair)" --> DLG -- "shown to" --> HUMAN
    AG -- "spawns with values and/or broker tokens" --> CMD
    AG -- "private socketpair: grant and admission" --> BR
    CMD -- "HTTP on 127.0.0.1 + token" --> BR
    BR -- "verified TLS, credential where the token was" --> API["approved origin"]
    AG <--> FILE
```

The requester–agent boundary gates approval. The agent–broker socketpair
carries one grant and mediates every admission; it never carries the vault.
The command–broker hop is clear text HTTP with token authentication, and the
broker–destination hop is TLS to an address the broker resolved and checked.
The agent retains the listening socket to prevent port reuse while the run
still holds the grant, including after revocation.

## 6. Security properties and mechanisms

| # | Property | Mechanism | Holds against |
|---|---|---|---|
| P1 | A requester never receives a secret value, notes or a protected field without an approval for that specific request. | Only `reveal` returns a value, after a non-rememberable approval. `list`/`show` return metadata only, and withhold any field the KDBX file marks as protected — including a protected title, which is shown as `[protected title]` and matched only by UUID — reporting only the field's name. | A1, A2 |
| P2 | The approved command line, program, directory and environment are the ones used. | The agent resolves the program to a canonical path, fixes arguments, directory and environment, shows the command line, the program and the directory — and of the environment only the variables on its lists (L4) —, checks the program's and directory's identity (device and inode) again after you answer, and spawns the command itself ([ADR 0002](adr/0002-agent-mediated-execution.md)). A custom client cannot substitute another command. A swap between that check and the start of the program (an instant; for a run with `--broker`, the time its brokers take to start), and changes to file *contents*, are not prevented (L4). | A1, A2 |
| P3 | An approval is acted on only if the vault did not change while you decided. | A vault *generation* counter is bumped on unlock, lock, every saved change and every approved change of the agent's settings (P15). The generation is checked under the same lock that reads the values, so an edit, lock or reload while the dialog was open cancels the request. For ordinary `run`, reading the values *consumes* the approval: a `lock` after that point does not stop the command. A `lock` while the master password is being typed cancels the unlock. For `broker_run_v2`, the same state lock also registers grants as `starting`; any lock ends starting grants, and all grants must still be starting before the command starts. Automatic locks can preserve already active grants when the run says so (L22). | A1, A2 |
| P4 | Secrets used by `run` are not placed in a process the requester can inspect with a debugger. | The command is a child of the agent, not of the requester; Yama blocks `ptrace` from outside its ancestry. See L3 for `/proc/<pid>/environ`. | A1, A2 (partially) |
| P5 | Secret values printed by an approved command do not reach the requester verbatim. | With redaction (the default), the command's stdout and stderr are pipes owned by the agent; the filtered output travels to the requester as data frames over the socket, and the requester writes it itself. The command's stdin is `/dev/null`, or an agent-owned pipe fed from the requester's data frames with `run --stdin`. The requester's own descriptors never reach the command or the agent, so there is no unfiltered way back. Exact-match only (L5). Broker tokens are filtered from command output too. Independently, the broker redacts literal copies of its credential from response bodies and drops relayed response headers whose name or value carries it or a token. With `--no-redact`, the command instead gets the requester's input/output descriptors directly and its output is unfiltered; HTTP response redaction stays on. | A1 |
| P6 | The master password never passes through a requester, nor does a new secret value, unless the requester itself supplies it. | The agent asks for them in its own dialogs; the protocol has no field for the master password. Imports from GNOME Keyring and `.env` files are read by the agent (`import_from`, [ADR 0012](adr/0012-import-read-by-the-agent.md)): the requester names items and entry names, and the dialog names the source; only the older `import` request carries values from a client, and its dialog says so, as do those of `add --stdin` and `edit --stdin`, whose value the requester supplies and already knows. zenity's answer comes back over a socket pair, which other processes cannot open through `/proc/<pid>/fd` (a pipe could be). A *new* vault's password is asked by the agent too (`create_vault`, sent by `rusthorse init` and the manager's Create vault…, [ADR 0011](adr/0011-first-start-from-the-manager.md)); the one exception is `rusthorse init` when no agent serves that vault, which reads it in the CLI (terminal or dialog). | A1, A2 (not on X11, L2) |
| P7 | Dialogs are not answered by the requester and say what they mean. | Separate processes on the desktop, not in the terminal: `rusthorse-dialog` ([ADR 0006](adr/0006-own-dialog-program.md)) or, when it is not installed, zenity — started from an absolute path with a minimal environment and `/` as working directory, answering through a socket pair; `rusthorse-dialog` also gets its request through that socket (framed, versioned, with an identifier the answer must repeat), runs under a deadline after which it is killed, reads no per-user GTK configuration, shows plain text only, and keeps **Allow** disabled until the end of a request that does not fit has been in view; requester-controlled text is escaped (only ordinary characters are drawn as themselves, every other one as a `\u{…}` escape; markup characters for zenity's question dialog, backslashes and underscores for its entry dialog); entries are identified by full path and the start of their UUID in the dialogs of `run`, `reveal`, `edit` and `remove`, so two entries with the same title in different groups do not look alike (unless a file written by another program gave them UUIDs that start alike, L9), while those of `add` and of an import show the name the requester gave, without group or UUID; requests whose dialog text would exceed 4000 characters (or 1000 for the command line, program path or directory of a `run`, and for each detail of a run with `--broker`) are refused, never truncated, and with zenity also those too tall to read at once (estimated for an 11-point font); default button **Deny**; unanswered dialogs are denied; only exact, expected answers count as approval. | A1, A2 (not on X11 or through accessibility, L2) |
| P8 | Only your user can talk to the agent. | Socket in a `0700` directory, mode `0600`, `SO_PEERCRED` uid check. The broker's separate loopback HTTP listener requires its grant's token in a header value it forwards: every token-shaped string there (`rh_` and 64 hexadecimal digits, in any case) must be that token byte for byte, compared in constant time, and one anywhere else in the request's head is refused, the token itself included; it validates Host and refuses Origin. TCP has no Unix peer credentials (L21). | A4 |
| P9 | The decrypted vault is not held longer than needed. | Auto-lock after a time without an *approved* use — 15 minutes by default; the `idle_timeout` setting changes it, up to 24 hours, and `0` turns it off (P15) — which `status`, `list`, `show` and denied requests do not postpone; `rusthorse lock`; lock on any save failure; lock when the computer is about to sleep and when the screen locks, unless those two settings are switched off, and within the limits of L20. Broker requests do not postpone the idle lock. A FIFO that a program puts in place of the vault file or of a directory that a save, a backup or a save of the settings syncs is not waited on (the step that would open it fails, or, once a backup has checked the vault file, goes on with that file), so it does not make the agent wait with its state held, which would hold off these locks (L12). The decrypted vault is dropped at lock, but a grant whose run says `continue` keeps its credential in its broker through automatic locks (L22). | A1, A2, A6 (window) |
| P10 | The agent's memory is not readable by other same-user processes and is not dumped. | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the agent. Dialogs and approved commands inherit `RLIMIT_CORE=0`, but `execve` makes them dumpable again, and with a piped `core_pattern` (systemd-coredump) whether a crash is stored is up to that handler. Each broker applies the same hardening before reading Install. Zeroizing buffers do not erase every library or allocator copy (L7). | A1, A2 |
| P11 | The vault is confidential at rest. | KDBX4: AES-256, Argon2id (64 MiB, 20 passes for new vaults); files `0600`, directories `0700`. | A4, A5 |
| P12 | Every decision leaves a record. | JSON Lines audit log, each record synced to disk when it is written (the file's data, `fdatasync`), after the names that lead to it: at every record the agent opens the log file without waiting and writes to it only if it is a regular file, and opens the directory that holds it as a directory only (a FIFO or other file put in place of either fails the record at once, nothing written, instead of making the agent wait for a reader or a writer with the log held), checks through it that it holds the file the record goes into, by the name the log's path leads to, and only then syncs it; it also syncs the parent of each directory it makes for the log, at every record until that sync succeeds (an agent process started later does not know of a directory that an earlier one made and could not sync). If one of these syncs or the check fails, the record fails and is not written; if writing the record or `fdatasync` fails, the record fails too, but part or all of it may be in the file: the record of an action that was refused. A rename, replacement or removal by another program that still stands at the check fails the record; one undone before the check goes unnoticed, and the sync that follows covers the name put back. A program that renames, replaces or removes the log after that check takes the record with the file (out of the log, if it removes or replaces it), and the names it gives are its own to sync. The names of directories the agent did not make are taken as durable and as not changing, and so, for a log reached through a symbolic link (the directory synced is then that of the file the link leads to), are the link and the directories on the way to it. Unlocking and approval-gated actions fail closed: if the record cannot be written, the vault stays locked or the action does not happen. Broker admission also requires a durable record before forwarding, and grant creation before command start. Completion and grant-end records are best effort; a failed request-completion record revokes the grant. Revocation contains the broker before waiting for audit, and abrupt process death can leave missing end records (L23). | A1 (detection; L13) |
| P13 | The agent stays available under request floods. | The whole request must arrive within 10 s of connecting (a deadline, not a per-read timeout); at most 64 connections and 8 requests waiting for a dialog at once; frames ≤ 4 MiB; imports ≤ 100 entries; vault files ≤ 128 MiB. | A1, A2 (availability) |
| P14 | Approved changes are all-or-nothing and match the disk. | Every change runs as a transaction that is rolled back if any part fails (for example one invalid entry in an import); if saving fails, the vault is locked so memory never holds unsaved changes. A save that fails after the file was replaced (syncing the directory) is reported as an unknown outcome, never as "not saved". Creating a vault syncs, before writing it, the directory that holds each directory it makes for it, and fails, writing nothing, if a sync fails; a later attempt does not know of a directory an earlier one made and could not sync, and the names of directories it did not make are taken as durable. | Accidents |
| P15 | The agent's settings change only as the human decided, short of an edit of their file. | Five settings — the idle lock, remembered approvals, the dialog timeout, locking on suspend and on screen lock — come from defaults, then the settings file (`agent.toml`), then the flags of `rusthorse agent`, within fixed bounds. While the agent runs only `configure` changes them, sent by the manager's Settings page: the vault must be unlocked (the master password is asked first when it is not); the agent's dialog shows each old and new value, warns of each change that protects less, and cannot be remembered; the approval is recorded before the file is written; one change at a time; a setting a flag fixes and a value out of bounds are refused; a lock or another change while the dialog was open cancels it; an approved change applies at once and forgets remembered approvals. The file is replaced whole (old settings or new, never part), and a failure after the replacement is reported as an unknown outcome; the directories made for it have their names synced first, as for a new vault (P14). The agent does not start with a settings file that is not a regular file of the user's, that its group or others can write, or that is reached through a directory or a link that would let someone other than the user and root remove or replace it (one of theirs, or one that its group or others can write to and that is not sticky), and it saves only where nobody else can remove or replace the file; a missing file means the defaults. None of this guards the file against a program running as the user, which can edit it and restart the agent (L1). | A1; A4 (the file); not A2 or A3 (L1, L2) |
| P16 | A request is not carried out for a requester that has gone. | From the moment a request is read, the agent watches its connection for a close by the requester — also a shutdown both ways, as the manager cancels — and, for a `run` or `broker_run_v2`, a half-close, which cancels a run; it polls the connection, never reads it. A dialog open for the request is taken down, its program killed as at the dialog's deadline, and recorded as `requester_gone`; a dialog the request waits for, or a later one of the same request, is not shown. After the dialogs, the last check of the requester before an effect comes after every wait the agent makes on the way to it for a dialog's turn, for the lock of its state (which a save or a backup holds for a while), for an audit record, for brokers to end or to start, and for a read from outside (the keyring, a file). The registry of grants has a lock of its own, held only for short work in memory (on the grants and their counters, reading the clocks, writing a new broker's install without waiting); a wait for it is not followed by a check (L26). What remains unguarded is a departure during the effect (L26). The effects so checked: the vault file or the settings file written, a backup written, a value read for the answer, a run's values read, each grant's `created` record and then its brokers started, a command started (with grants, once they are ready, ending them first), the vault an unlock opened put in use (it stays locked), a vault created and then put in use, an import's values read, a `.env` file or the keyring read, a keyring listing kept for the program that asked. A `backup`, which has no dialog of its own, is checked the same way. It then records `aborted`, does nothing more, and sends no answer, even when it cannot record that. An unlock, a password change and the creation of a vault write their `unlocked`, `changed` or `created` record before they act, and are checked right before that record and again right before they act: only a requester that leaves between those two checks leaves that record, followed by `aborted` (the vault stays locked, the password unchanged, no vault created). Between them the record waits for the audit log and is written, and, for an unlock and a password change, the agent then waits for the lock of its state, under which the second check is made. So does a grant, followed by `ended`, whose requester leaves between the check before its `created` record and the next check: the record, then a wait for the registry's lock to note it, and, after the last grant's record, the tokens drawn and the installs prepared (the registry's lock again). Grants created for a run whose requester leaves while their brokers start are recorded `created`, then `ended`. A requester that leaves after the last check, or whose connection another process still holds, is served as before; what a wait for the registry's lock, the human's answer and a missing `aborted` leave behind is in L26. | Accidents (a requester interrupted, timed out or closed); not a control against A1 or A2, which can stay |

Broker-specific bounds are in [ADR 0013](adr/0013-credential-broker.md): 16
entries in the grant registry per agent (normally revoked brokers stay listed
and count until run cleanup; broker exit removes the entry sooner), 16
admitted/reserved requests and 64 connections per broker, 16 MiB per request
body, 64 MiB of retained request bodies and 64 MiB of upstream body per
response, before redaction. There is no route check: any path at the
approved origin passes (L25). The broker connects to that origin only,
taking SNI and Host from it; it sets `Content-Length` and `Accept-Encoding`,
drops hop-by-hop headers, forwards the program's other request headers,
puts the credential only where the token was in the header values it
forwards, and refuses redirects and encoded responses. Its own lifetime task and forwarding checks use
`CLOCK_BOOTTIME`; the agent also expires grants and serves none if its expiry
timer cannot start. These are bounded resources and scheduled checks, not a
guarantee of availability under arbitrary same-user denial of service.

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
| **Allow for N** (opt-in: the `remember` setting, off by default, set by the `--remember` flag, in `agent.toml` or on the manager's Settings page) | A reusable capability: for N minutes, any request with the same variables and entries (by UUID), the same vault generation, command line, program, directory, redaction and `--stdin` settings and environment runs **without asking**. Program and directory are compared as paths, so it covers whatever file is at that path at each use; and it does not cover what the command reads — its standard input, files, network responses — which can differ on each run (L8). |
| **Deny**, closing the dialog, timeout | Nothing. The command does not run. |

Locking, unlocking, any saved change and an approved change of the agent's
settings invalidate remembered approvals.
A run with `--broker` (`broker_run_v2`) never uses them. Its approval
creates a grant for the approved origin whose individual requests — to any
path there — need admission and an audit record, but no new human dialog.

## 7. Known limitations and residual risks

### L1 — Malware running as you can defeat Rusthorse

It can replace the `rusthorse` binary, the systemd unit or your shell startup
files, wait for you to unlock, and capture the master password or the
decrypted data. No program running with your privileges can prevent this.
It can also edit the agent's settings file (`agent.toml`) — turning off the
idle lock, turning on remembered approvals — and restart the agent: the
agent's dialog guards a change made through it (`configure`), not the file.
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
Wayland alike. zenity's GTK 3 dialogs do so, and so do those of
`rusthorse-dialog` ([ADR 0006](adr/0006-own-dialog-program.md)), a GTK 4
program in which nothing turns accessibility off.

### L3 — The environment of a running approved command is readable

While an approved command runs, any process of the same user can read
`/proc/<pid>/environ`. Ordinary bindings contain the secret; broker bindings
contain a token. Marking the command non-dumpable would prevent that, but
`execve` resets the flag. A stolen broker token still works through its
listener while the grant lives, for any path at its approved origin, within
its limits. *Mitigation:* short-lived commands, short lifetimes and request
limits, narrow keys and isolation (§8). The broker keeps the source
credential out of that binding's environment; it does not hide the token.

### L4 — Approving a command trusts everything it executes

If you approve `python deploy.py`, the secret goes to whatever `deploy.py`
contains when it runs — and an AI agent can edit that file, even between your
answer and the start of the command. Rusthorse checks the identity (device and
inode) of the program and of the working directory again after you answer,
which catches a file swapped for another while the dialog was open. It does
not pin them — a swap between that check and the start is still possible (an
instant; for a run with `--broker`, the time its brokers take to start) — and
it does not notice a file rewritten in place, nor the scripts,
modules, configuration files (`~/.gitconfig`, `.curlrc`, `.npmrc`) and
plugins the program loads. The same applies to `sh -c '…'` and interpreters
with inline code. The agent removes `LD_*` variables and warns about a list
of variables that change what programs execute (`NODE_OPTIONS`,
`PYTHONPATH`, `GIT_SSH_COMMAND`, …), but such a list cannot be complete.

A well-known program can also be pointed elsewhere. Libraries read the address
they send a key to from the environment (`OPENAI_BASE_URL`,
`ANTHROPIC_BASE_URL`, `HTTPS_PROXY`, …), and the requester's environment is
passed to the command: a requester can make an approved `python app.py` send
the key to a server of its choosing. The dialog therefore lists, under
**Destinations**, the variables whose names say where a program connects
(`*_URL`, `*_BASE_URL`, `*_HOST`, …), and warns about proxies, certificate
authorities, switches that disable certificate checks, and name resolution
([cli.md](cli.md#rusthorse-run)); the audit record names them too. A value
that programs could read differently — a backslash, two `@`, an unusual host,
a numeric host other than `a.b.c.d`, a query naming another server (libpq's
`hostaddr`), a `#`, anything outside printable ASCII — is not shown but warned
about. The aim is that the dialog never names a host other than the one the
program uses. It has been checked against the readings of common URL parsers
and libpq that four rounds of review found to differ, each pinned down by a
test; it is not a guarantee for every program, and each round found narrower
cases. Limits: the lists go by name and cannot be complete
(`MY_SERVICE=https://…`, a configuration file or an argument escape them); a
URL is shown by scheme, host and port only, so a different path on the same
host is not visible; the forms judged unambiguous are those known for common
URL parsers and libpq, not a proof about every program, which may take its
destination from elsewhere; and `run --url`, which takes the address from the
entry's metadata, looks the same as a variable the requester set
([ADR 0008](adr/0008-entry-kinds.md)). *Mitigation:* read the dialog — check
the host of every destination; prefer well-known binaries with explicit
arguments; review recent changes to scripts before approving them. For a
broker binding, the run names the credential's destination, and the dialog
shows its approved origin apart from everything else: the broker connects
there and nowhere else, whatever the request's target or headers say, and
there is no default or fallback (not the entry's URL). The requester chose
that origin, so check its host as you would a destination variable's; it is
lowercase ASCII (an international name in its `xn--` form), so letters of
other scripts cannot imitate a known host, but ASCII lookalikes can (L9).
Requester proxy/CA settings do not configure the broker, which starts with
an empty environment. The command can still use any operation the key
allows at that origin (L25), send the token or other data in an opaque
body, send credentials of its own in other headers, or send its token
elsewhere without using the broker. `NO_PROXY` helps cooperative clients
reach loopback; it is not enforcement.

### L5 — Redaction only catches exact copies in the command's output

A command that prints the secret encoded (base64, hex, URL-encoded), split,
reversed or partially is not redacted, and secrets shorter than 4 bytes
never are. A command can also send the secret over the network, write it to a
file, or put it in its own logs — none of which pass through the redactor.
Redaction prevents *accidental* disclosure on stdout/stderr; it is not a
defense against exfiltration by a command written to leak.

For a broker binding the command does not receive the source credential. The
broker's response redactor matches its literal bytes across chunks, using a
bounded look-behind buffer; compressed responses are refused and response
headers whose name or value carries the credential are dropped. Encoded or
transformed copies returned
by the destination are not caught. Output redaction filters the token by
default; `--no-redact` exposes anything the command prints, including that
token. HTTP response redaction stays on in either mode.

### L6 — Metadata is visible without approval

While the vault is unlocked, any process of your user can list entry names,
kinds, usernames, URLs, hosts, ports and tags (fields marked protected in the
KDBX file are withheld). This is deliberate — an agent needs to know what
exists and where it points — but do not put secrets in those fields. A kind
is a label: nothing grants or restricts access by it, and nothing checks it
against the value — the kind `ssh-key` says that a value is a private key
because someone set it so ([ADR 0008](adr/0008-entry-kinds.md)).

### L7 — Memory hygiene is best effort

Rusthorse wipes the buffers it controls (`Zeroizing`), but copies made by JSON
parsing, the KeePass library, zenity/GTK and the standard library's process
spawning are not all wiped. The broker uses zeroizing token/credential and
control-frame buffers, but HTTP header, TLS and allocator copies are not all
wiped, and immediate process exit does not run every destructor. Memory is not
locked, so secrets can reach swap or a hibernation image. *Mitigation:*
full-disk encryption (which covers swap).

### L8 — Remembered approvals are a capability, not a decision per use

When enabled, "Allow for N" approves identical requests without asking, even
when they read different input. For example, `curl --config -` with a
remembered approval sends the token wherever the next request's standard input
says. This is why remembering is **off by default** and should only be enabled
for commands whose inputs you control. A remembered approval names the program
and the directory by their paths, not by the files that were there: a program
replaced at the same path between two uses runs without asking, as one whose
contents changed does (L4). See
[ADR 0005](adr/0005-remembered-approvals-opt-in.md). Remembered approvals
are not listed, and one cannot be revoked alone: `status` counts them and
`rusthorse lock` forgets them all. Broker grants are a
separate capability: no `--remember`, but each grant permits multiple API
calls, to any path at its approved origin, until its limit or end (L25). A
request count is not a spending limit, and the broker does not inspect
prompts or other bodies.

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
the same; the dialogs of `run`, `reveal`, `edit` and `remove` add the entry's
UUID (its first 8 characters) and a destination group's whole UUID, but a file
written by another program can give two entries UUIDs that start alike. The
requester chain is made of process names any program can choose — the dialog
labels it "unverified". *Mitigation:* treat unexpected dialogs as a warning
sign; deny when in doubt.

### L10 — The vault can be attacked offline

Anyone with a copy of the file or one of its backups can try passwords at a
cost set by Argon2id. A weak master password will fall. Old values remain in
entry history, in `vault.kdbx.bak` and in any copies you made. *Mitigation:* a
long, unique passphrase (`rusthorse passwd` changes it and deletes the `.bak`
file encrypted with the old one — but not copies made elsewhere); rotate
credentials at the provider when they may have leaked — deleting an entry does
not revoke the source credential at its provider
(`rusthorse edit NAME --generate` makes the new value).

### L11 — Command lines are not secret

Arguments are shown in dialogs, stored in the audit log and visible to other
processes. Never put a secret on a command line; pass it through `run`.

### L12 — Denial of service

Any process of your user can lock the vault, keep dialogs coming (one at a
time, at most eight waiting), or stop the agent. Opening a crafted vault file
with extreme KDF parameters can make unlocking very slow (files over 128 MiB
are refused, but KDF parameters are not yet bounded). A save or a backup on
a file system that stops answering holds the agent's state until it
returns, and with it every lock, the vault unlocked; a FIFO put in place of
the vault file or of a directory they sync does not (P9). These are annoyances,
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
The manager's History page reads it at the path the agent reports, and shows
it only while the vault is unlocked (that keeps it off the screen, not out
of reach), drawing every text as plain text through the dialogs' character
filter: no markup, and no line break or invisible character of its own.

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
value, a list, an "unlocked" status read before the lock. `add --stdin` and
`edit --stdin` send a value the client already has, as would the older
`import` request, which the CLI and the manager no longer send: their imports
name the source, and the agent reads the values (P6). None of these should be
run by an AI agent. Importing also does not remove the original copies (for
example in GNOME Keyring).

### L15 — Concurrent edits by other programs

The agent refuses to save if the vault file changed since it was loaded and
checks again right before replacing it, but the check and the rename are not
atomic: KeePassXC or a sync client saving at that exact moment can lose its
change. Only one program should write the vault at a time — lock the agent
(`rusthorse lock`) before editing in KeePassXC. A lock does not reserve
the vault: another program can ask the agent to unlock it while KeePassXC
has the file, and the agent mode that would have refused that (ADR 0007's
hand-off) will not be built.

### L16 — Approved commands run outside the requester's sandbox

The command is started by the agent, as you, with the agent's privileges — not
inside whatever sandbox (container, seccomp policy, network restrictions) the
requester runs in. Approving a command from a sandboxed AI agent grants that
command your full access. The dialog states this. A broker also runs as your
user. One process per grant limits the credential present in its memory; it
does not contain arbitrary code execution there or prevent the process from
attacking other user resources.

### L17 — Descendants that leave the process group outlive the command

When the command exits — or the requester disconnects first — every remaining
process in its process group is terminated (SIGTERM, then SIGKILL after 3
seconds), so background jobs started by the command do not keep the secret. A
process counts as alive while any of its threads is (its main thread may
already have exited). A descendant that started a new session or group
(`setsid`, `setpgid`) escapes this and keeps ordinary values in its
environment; stopping the agent's systemd service kills all of them (cgroup).
For broker bindings, once the agent sees the leader exit or the requester
disconnect, it revokes all of the run's grants before terminating the group
and before draining output. After confirmation or broker death, escaped
descendants hold dead tokens. Requests already sent may still take effect at
the destination. *Planned:* one cgroup per command.

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
(the default) and with redaction, the requester's input is never read; with
`--no-redact` the command holds the requester's standard input itself. With
`--stdin`, nothing is read before the command has started: a denied request
leaves the input untouched.

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
the idle lock short (the `idle_timeout` setting: the `--idle-timeout` flag,
`agent.toml` or the manager's Settings page).

### L21 — A loopback token is a bearer capability

Any local user can connect to a broker's TCP listener; knowing its port is not
enough, but possession of the token is. There are no peer credentials on that
HTTP hop and it is not encrypted. The fixed Host check and rejection of Origin
limit browser/DNS-rebinding uses; they do not isolate a hostile process with
the token. The agent holds the port until the run releases it, so a
replacement process cannot claim that port while the grant is retained. A
client can put its token in an opaque request body, which is forwarded; in
the request's head the broker never sends it upstream: it replaces it with
the credential in the header values it forwards and refuses a request that
holds it anywhere else there. Whoever holds the token can also learn the
key's length, by padding requests until the broker refuses one as too large
once the key is in; never the key itself, which the grant already lets them
use.

### L22 — Automatic locks can leave grant credentials in brokers

A run's grants default to `--broker-locks continue`, with a 12-hour maximum
lifetime (`--broker-lifetime 720`). Screen lock, suspend and idle lock drop
the decrypted vault but leave already active/exhausted grants running. All
starting grants end on any lock; explicit `rusthorse lock`, entry changes,
failed saves, manual revocation, command end and expiry end grants
regardless of this policy. Use `--broker-locks end` for runs whose grants
must stop with the desktop; the dialog says which the run chose. L20's
signal and inhibitor limits still apply; revocation cannot promise to beat
suspend.

Across locks the agent retains a keyed fingerprint of the encrypted vault
content. A valid unlock compares it before publishing the unlocked state: a
difference (or no previous fingerprint) revokes all surviving grants, even if
another entry changed. It decides under the state lock, contains the brokers,
writes the unlock record outside that lock, then checks the generation again
before publishing. A lock before comparison cancels the attempt and keeps the
previous fingerprint; a subsequent valid attempt still detects the change. A
lock after the revocation decision cannot undo it. Failed unlocks do not
replace the fingerprint. Successful saves made by the agent update it;
changing an unrelated entry does not revoke a grant.

The fingerprint uses one randomly keyed `RandomState` created on its own
thread when possible (otherwise on the caller's), with two domain-separated
64-bit outputs. This is an in-memory change detector, not authenticated
storage or a proof of 128-bit cryptographic collision resistance. It sees
external edits only on unlock (or a conflicting save); unchanged encrypted
content leaves grants alive.

### L23 — Abrupt shutdown cannot guarantee grant-end audit records

Control-channel EOF makes each broker exit immediately; the systemd unit also
kills the service cgroup. An ordinary SIGTERM terminates the agent without
unwinding Rust stack guards, so it writes no `agent_stopped` end records for
those grants. The `StopGrants` guard covers a return/unwind from `serve`, not
signals. Its removal survived mutation V20: no test forces that return path
with live grants. Direct `stop_all` tests and broker EOF and service-cgroup
containment cover related mechanisms, not that guard. This remains an
acknowledged coverage gap; it is not proof the guard is unnecessary. Grant-end
records are best effort.

### L24 — Parser and client compatibility have explicit limits

Hyper drops a request target's `#` fragment before the broker sees it; the
broker cannot reject that spelling, and never forwards the fragment.
Hyper-generated malformed/framing errors can also precede the broker's JSON
errors and retry hints.

The fake HTTPS tests cover the protocol, not every SDK's behaviour. By hand,
with a real key (2026-11-04), the broker was tried with `curl` (a GET and a
POST answered, a token in the URL refused by the broker), with the Anthropic
Python SDK 2.4.0 (a message and two streams) and with Claude Code 2.1.318,
which answered in print mode (`claude -p`) and interactively; the
[review history](#11-review-history) has the whole account, including the
earlier test of phase 1's broker. No client version is claimed supported. A
program works through it only if it presents the token literally in a header:
one that encodes the token or derives its credential from it, and an API that
signs requests with the key or takes it in the URL or the body, cannot use it.
SDK configuration can override environment variables, or send a key of its
own beside the token in another header, which the broker forwards to the
approved origin as it came unless it is the entry's own key or
token-shaped. With zenity, a run requesting two or more grants may exceed
the dialog height estimate and be refused before asking. `rusthorse-dialog`
scrolls long approvals; character limits still apply, and no approval is
truncated.

### L25 — A grant covers its whole approved origin

The human approves an origin — scheme, host and port — that the requester
named in the run. Through the grant, the command can send the key to any
path there, with any method the broker accepts and a body on any of them,
and so do whatever the key allows at that origin: an administration or key
management endpoint as much as a model call. The base path the dialog shows
apart from the origin only sets up the program's base URL; it limits
nothing. Rusthorse knows nothing about the API and does not narrow what a
key can do there: that is scoped where the key is issued
([ADR 0013](adr/0013-credential-broker.md#scope-amendment-2026-11-04)). The
broker forwards the program's request headers as they came, apart from
those it sets or drops, so credentials of the program's own in other
headers reach the origin too. The audit log records each request's method
label, never its path, so it does not tell which operation was used.
*Mitigation:* give an agent the narrowest key that does the job, with a
spending limit at the provider; check the origin in the dialog as you would
any destination (L4, L9); keep lifetimes and request limits short for keys
that can do more than the task needs.

### L26 — A requester that leaves late, or does not seem to leave, is served

The agent stops a request whose requester went away only while a dialog for
it is open or waited for, and at its checks before each effect, the last of
them after the waits that P16 names. What remains unguarded is a departure
during the effect. A requester that leaves after the last
check is too late: a save, a backup or a vault's creation under way is
completed (a vault created so is not put in use: it stays locked), or the
value, names or listing put in an answer nobody reads (and a keyring listing
kept for that program); a command has started — with the secrets in its
environment — and is then stopped by the run's own watch (`SIGTERM`,
`SIGKILL` 3 seconds later), its grants ended first. A record written before
its effect — an unlock's `unlocked`, a password change's `changed`, a vault's
`created`, a grant's `created` — has a check right before it and another
right before its effect (for a grant, the next check): it stays when the
requester leaves between the two, and the second then stops the request
before it acts: `aborted` follows (for a grant, `ended`). Between them the
record waits for the audit log and is written; then, for an unlock and a
password change, the agent waits for the lock of its state, which a save or a
backup can hold for a while; for a grant, it waits for the registry's lock to
note the record and, after the last grant's, draws the tokens and prepares
the installs, waiting for that lock again. The registry of grants has a lock
of its own, held only for short work in memory (on the grants and their
counters, reading the clocks, writing a new broker's install without
waiting), and a wait for it is not followed by a check: a requester that
leaves during such a wait after the last check is noticed only at the next
one. That leaves two things done: the grants that an unlock or a new vault
ends because the vault's file changed stay ended (a protection, like `lock`
and `revoke_grant`, carried out once decided; the vault stays locked), and a
run's grants are entered in the registry, which the next check ends before
any is recorded or started. Three more things stand for a requester that
left. The human's answer: an "Allow for N" given as the requester left is
remembered, and an approval postpones the idle lock (`allowed_for_…`, then
`aborted`). The start of a run's brokers, which is one step: the credentials
reach the agent's own brokers after the check before it, and the tokens leave
only with the command, after the last check. And, when the `aborted` record
cannot be written — it is written best effort — the earlier record
(`unlocked`, `changed`, `created`, a grant's `created`) alone. An import read
by the agent is checked before its values are read and again before it is
saved, so a requester that leaves while the keyring or the `.env` file is
read is noticed only then. A connection is
not closed while another process holds it — a descriptor inherited without
close-on-exec, for example — and a half-close of a request other than a run,
or a `shutdown(SHUT_RD)` alone, is not taken for a departure: such a client
can still read, or chose not to. A requester that stays connected but no
longer waits (stopped, hung) keeps its dialog until the dialog's timeout. A
request waiting for its turn keeps its place among the 8 that may wait (P13)
until its turn comes; it is then dropped without a dialog. A failure to poll
the connection counts as not gone. Before a run's command starts, the agent
watches only for a close or a half-close: a protocol violation is noticed
once the command has started, as before. The dialog closes without telling
the human why. None of this bypasses an approval: what runs or changes is
what the human allowed.

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
- Keep the idle lock short (`idle_timeout`); lock the screen when you step
  away (the agent locks with it, L20); leave remembered approvals (`remember`)
  off unless you need them. Both are settings of the agent: a flag of
  `rusthorse agent`, `agent.toml` or the manager's Settings page (P15).
- Read every dialog; be suspicious of `sh -c`, scripts the agent just edited,
  unexpected programs or directories, and risky-variable warnings.
- Edit the vault in other programs only while the agent is locked.
- Prefer broker bindings for HTTP APIs that take their key in a request
  header. Check the approved origin in the dialog; set provider-side
  spending limits and use narrow keys (L25); give the run a short
  `--broker-lifetime` and a `--broker-requests` limit, and disable SDK
  retries where practical: every admitted attempt spends a use.
- Use `rusthorse grants` to inspect grants, `rusthorse grants revoke ID` for
  one, and explicit `rusthorse lock` to end all grants. Screen lock alone
  preserves `continue` grants.
- Look at `rusthorse audit` from time to time.

## 10. Planned improvements

The roadmap's [Hardening](roadmap.md#hardening) table lists the same items
and carries their status:

- **Isolation support** (§8): uid allow-list on the socket and documentation
  for running agents as a separate user. Planned.
- **One cgroup per approved command** (L17), with resource limits. Planned.
- **Bounded KDF parameters** before unlocking (L12). Planned.
- **Key files and hardware keys** (YubiKey challenge-response), which
  KeePassXC vaults can use. Later.
- Done: the run dialog lists the variables that redirect a program's
  requests (L4).

Other planned work in the [roadmap](roadmap.md) touches this model without
being hardening: a "waiting for your answer" hint in the terminal while
a dialog is open, driven by an explicit event from the agent, and signed
checksums for published releases. A manager page that lists and revokes
remembered approvals one by one is no longer planned (2026-11-19; the
manager already lists and revokes broker grants; remembered approvals
remain separate, L8), nor is an exclusive hand-off of the vault to
KeePassXC (L15).

Per-entry policies that restrict an entry to listed programs or hosts are
outside the product's scope and not planned; L3 and L4 remain limits.
Nothing more is planned for the credential broker, which no longer has
profiles or presets: the run names the destination, the human approves its
origin, and the broker puts the key where the program put the token (L25).
Narrower operations per API are not planned (L25), nor other connectors
(`ssh-agent`, databases, private devices with pinned TLS): `run` serves
those uses, with L3–L5 ([ADR 0013](adr/0013-credential-broker.md#scope-amendment-2026-11-04)).

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
| 2026-11-02 | Broker foundation: independent verification V01–V07, then Codex B01/S1–S3 (AI-assisted). | Fixed; foundation ready. See the phase 1 entries below. |
| 2026-11-02 | Broker shared helpers: implementer's checks (AI-assisted). | Reviewed with the whole; mutation limits recorded below. |
| 2026-11-02–03 | Phase 1 pieces B–E: implementation checks, independent verification and fixes (AI-assisted). | Fixed or explicitly documented; whole review still required. |
| 2026-11-03 | Whole phase 1 at `189703f` (Codex, AI-assisted). | Not ready: P01–P06; fixes below. |
| 2026-11-03 | Pieces F and G: system tests and packaging, independent verification and fixes (AI-assisted). | Coverage and packaging fixes, accepted test gaps and incident below. |
| 2026-11-03 | Re-review at `38ef1f0` (Codex, AI-assisted). | Ready: no medium or higher finding left; Q01/Q02 low, dispositions below. |
| 2026-11-03 | Documentation consolidation at `70ad512` (Codex, AI-assisted). | Body and history aligned to the implementation; Q01 was pending then and is recorded below as fixed in `2dabbff` and `96e7e43` (merged in `d1cab93`). Manual SDK validation remained pending then (since done on 2026-11-04; see the manual tests below). |
| 2026-11-03 | Documentation revision at `d1cab93` (maintainer's agent review; Codex corrections, AI-assisted). | Ten requested corrections and reread dispositions below; reviewed guarantees restored and Q01's exact cleanup recorded. |
| 2026-11-03 | Final review at `c599800`: independent Q01 verification, Q02 and documentation (Codex, AI-assisted). | Not ready: R01 medium and R02–R04 low. Q01 partly resolved; Q02 confirmed resolved. Fixed in `a65dca3` (packaging through a private staging directory); see below. |
| 2026-11-03 | Re-review at `72494de`: private staging, R01–R04, manifest-path guard and history (Codex, AI-assisted). | Ready: R01–R04 and the manifest-path finding confirmed resolved; S01 low (a mutation-coverage gap) fixed in `1eb2e3b`. |
| 2026-11-03 | Test hygiene and behaviour under load: the maintainer's agent's T01–T05, fixed in `a0594f4` and `1001e1e`, then their review (Codex, AI-assisted). | Ready: no medium or higher finding; T01, T03–T05 confirmed for the reported cases, T02 partly resolved; U01–U03 low, fixed in `a3d66b0`. |
| 2026-11-04 | Confirmation of `a3d66b0` and its history at `897700e` (Codex, AI-assisted). | Ready: U01–U03 confirmed resolved and the history accurate; V01 low and V02 low, fixed in `8726b17`. |
| 2026-11-04 | The feedback for a key the destination refused, and an edit's answer, at `cf28a7c` and `0060692`, with the maintainer's manual test so far (Codex, AI-assisted). | Not ready: W01 medium (an edit's answer printed a title from the vault unescaped), W02 and W03 low; W01 and W02 fixed in `59735de`, W03 partly, completed in `1ec2af1` (X02). The count of 401 answers held under every probe. |
| 2026-11-04 | Confirmation of `59735de` and its history at `7397634` (Codex, AI-assisted). | Not ready: W01 and W02 confirmed resolved, W03 partly; X01 medium (older than this work: `list` and `show` printed what the vault holds unescaped), X02 and X03 low; X02 and X03 fixed in `1ec2af1`, X01 partly, completed in `6cb4f53` (Y01, Y02). |
| 2026-11-04 | Confirmation of `1ec2af1` and its history at `2de6b34` (Codex, AI-assisted). | Not ready: X02 and X03 confirmed resolved, X01 partly; Y01 medium (`open` printed a URL from the vault unescaped) and Y02 low, both older than this work, fixed in `6cb4f53`. |
| 2026-11-04 | Confirmation of `6cb4f53` and its history at `7a0f7be`, with a last sweep of what the CLI shows (Codex, AI-assisted). | Ready: Y01 and Y02 confirmed resolved; no other output shows supplied text unescaped; Z01 low (a test's stand-in script broke with a TMPDIR holding a space), fixed in `e5de2c2`. |
| 2026-11-04 | The guide for AI agents and the documents after the maintainer left Claude Code's manual check for later, at `cb9ef8d` (Codex, AI-assisted). | Ready: no finding; the guide and documents match the code (`list`, `show` and `grants`) and the recorded evidence, and the deferred check is not taken for compatibility. |
| 2026-11-04 | The product's scope and the broker's dropped phases, at `4f9fe79` (Codex, AI-assisted). | Not ready: S01 medium (the scope statement promised more control over ordinary `run` than it has), S02–S04 low; all four fixed in `85fb56f`, on the documents as `b91fc92` and `8eab1d3` had rewritten them. |
| 2026-11-04 | The product's definition, S01–S04 and the design of the broker without profiles, `4f9fe79..dd81cc2` (Codex, AI-assisted). | Not ready: S01–S04 confirmed resolved; D01–D04 and D06 medium, D05 and D07 low. D01–D04, D06 and D07 were fixed in `9c0efd8`; D05 was partly fixed there, and completed by E02 (below). These are design and documentation changes; the code is unchanged. |
| 2026-11-04 | Confirmation of the broker design at `8089080` (Codex, AI-assisted). | Not ready: D01–D04, D06 and D07 confirmed resolved, D05 partly; E01 medium (a new request type, so that an older agent refuses it), E02–E04 low; all fixed in `1c2923a`, with D05 completed by E02. Design and documents only. |
| 2026-11-04 | Confirmation of E01–E04 at `92b0f78` (Codex, AI-assisted). | Ready: E01–E04 and D05 confirmed resolved; the design of the broker without profiles is complete enough to implement, within what protects the key and the approval. The ready applies to the design; its implementation is to be tested and reviewed. |
| 2026-11-04 | The implementation of the broker without profiles, reviewed as `9c069d4` and squashed into `93848a9` with the same tree (Codex, AI-assisted). | Not ready: G01 medium (response headers that a destination's `Connection` names were relayed), G02 low (bindings by value accepted unknown fields); both fixed in `1edafe7`. |
| 2026-11-04 | Confirmation of G01 and G02 and their record, `93848a9..0ec231b` (Codex, AI-assisted). | Ready: G01 and G02 confirmed resolved, no new finding; `93848a9`'s tree is the one reviewed as `9c069d4`, and the record is accurate. |
| 2026-11-04 | Saving a vault that KeePassXC wrote as KDBX 4.0, `935743b` (Codex, AI-assisted). | Ready: no finding. |
| 2026-11-04 | Manual test of the broker without profiles, with a real key (the maintainer and the maintainer's agent; a test, not a review). | `curl`, the Anthropic Python SDK 2.4.0 and Claude Code 2.1.318 worked through it for what was tried; see below. No client version is claimed supported. |
| 2026-11-05 | The manager's History page (Codex, AI-assisted). | Not ready, then ready: the first review's findings fixed; see below. |
| 2026-11-05 | The agent's settings and the manager's Settings page: design opinion, reviews and confirmations (Codex, AI-assisted). | Not ready until the last confirmation, then ready: R1–R7 fixed; see below. |
| 2026-11-09 | Documentation audit: every document against the code at `1061b89`, in two rounds (eleven read-only audits by the maintainer's agent, AI-assisted). | Corrected in the same change; three behaviours of the code stated as they are and left to the maintainer; see below. |
| 2026-11-09 | The SSH recipes of the guide for AI agents, `5cb9117` and `da0737f` (Codex, AI-assisted). | Not ready: SSH01 medium (the probe "without a secret" offered the human's own keys), SSH02–SSH05 low; fixed in the same change; see below. |
| 2026-11-09 | The documentation correction, whole, and the SSH fixes (Codex, AI-assisted). | Not ready: SSH01–SSH05 confirmed fixed; DOC01–DOC06 low, fixed. Confirmation the same day: ready, no new finding; see below. |
| 2026-11-10 | The SSH recipes tried against servers, by hand (the maintainer and the maintainer's agent; a test, not a review). | The probe, the key recipe and the password recipe worked for what was tried, on two routers; SSH06 low (nothing tells a password from a private key, and the agent first chose the wrong recipe), fixed in the guide, with a design decision left to the maintainer. The record and the fix reviewed the same day (Codex, AI-assisted): not ready with T01–T04 low, fixed, then ready; see below. |
| 2026-11-10 | The entry kind `ssh-key` and protocol 11, the maintainer's answer to SSH06 ([ADR 0008, amended](adr/0008-entry-kinds.md#amendment-2026-11-10-the-kind-ssh-key)). | A label, like the other kinds: no policy reads it and nothing checks it against the value. Reviewed the same day (Codex, AI-assisted): not ready with K01–K03 low, fixed; the confirmation found K04 and K05 low, in the record, fixed; then ready; see below. |
| 2026-11-10 | Set the broker's limit of 100 request headers itself (Codex, AI-assisted). | Ready, no findings: the third behaviour left to the maintainer by the documentation audit of 2026-11-09 is closed; the explicit limit and its boundary tests are in place. Response limits and two older issues remain for the maintainer; see below. |
| 2026-11-10 | Sync the audit log's directory entries before its records: three reviews (Codex, AI-assisted). | Not ready with AUD01–AUD04; those confirmed fixed, then not ready with AUD05; that confirmed fixed, then ready, with no new finding. The second behaviour left by the documentation audit is closed within P12's stated limits, whose acceptance remains the maintainer's. The twelve checks passed again on main with the broker's header-limit change; see below. |
| 2026-11-10 | Stop a request whose requester goes away during its dialog: four reviews and a final confirmation (Codex, AI-assisted). | Not ready with CON01–CON04, then CON05–CON07, then CON08, then CON09 low; the final confirmation is ready within P16 and L26's limits, whose acceptance remains the maintainer's. The twelve checks passed on main with the staged change; see below. |
| 2026-11-10 | Keep restoring a backup a manual procedure (Codex, AI-assisted). | Not ready with RST01 and RST02 low; both confirmed fixed, then ready. The maintainer dropped restore through the agent; the manual procedure, its tests and the review's limits are recorded below. |
| 2026-11-19 | The limits that the two reviews of 2026-11-10 left to the maintainer's acceptance, in P12 and in P16 and L26 (the maintainer's decision; not a review). | Accepted as stated; no code, property or limit changed. The reviewers' recommendations remain open; see the entry of that date below. |
| 2026-11-19 | Drop the manager's three unbuilt features: listing and revoking single remembered approvals, the KeePassXC hand-off and editing notes (the maintainer's decision). | Nothing of ADR 0007 is left to build. Three messages in the manager and the documents changed; no code of the agent, the vault or the CLI. See below. Reviewed the same day (Codex, AI-assisted): not ready with MGR01 low, fixed, then ready. |
| 2026-11-19 | The history rewritten before publication, at the maintainer's decision (rewritten by Gemini, AI-assisted; specified and verified by the maintainer's agent). | The same 221 commits and content, less a list of example names in the prototype, the session links of commit messages and a personal e-mail address. The commit ids this history cites were mapped to the rewritten commits. See below. Reviewed the same day (Codex, AI-assisted): not ready with HIS01 low, fixed, then ready. |
| 2026-11-19 | The first run of the CI, at publication: two end-to-end tests failed on the runner (diagnosed by a Claude Opus 5.5 subagent, fixed by Gemini, both AI-assisted; specified and checked by the maintainer's agent). | The tests assumed an environment; the agent's refusal was right. Tests only changed. See below. Reviewed the same day (Codex, AI-assisted): not ready with CI01–CI03 low, fixed, then ready. |
| 2026-11-20 | The second run of the CI: the two corrected tests passed on the runner, and a third failed intermittently (diagnosed by a Claude Opus 5.5 subagent, fixed by Gemini, both AI-assisted; specified and checked by the maintainer's agent). | A race in the test's own command, not in the agent: the grant was revoked first, as it must be. Tests only changed. See below. Reviewed (Codex, AI-assisted): not ready with CI04 medium and CI05–CI06 low; CI04 and CI05 fixed, CI06 left as a follow-up; CI07 low found on confirmation and fixed; then ready. |
| 2026-11-20 | The third run of the CI: the corrected test passed on the runner, and two tests of the broker's dialog failed for their height (designed by a Claude Opus 5.5 subagent, applied by Gemini, both AI-assisted; specified and checked by the maintainer's agent). | The cause of the first run's failures again: the client of the end-to-end tests inherited the machine's environment. It now has an environment of the tests' own. Tests only changed. See below. Reviewed (Codex, AI-assisted): not ready with CI08–CI12 low, fixed, then ready. |
| 2026-11-20 | The fourth run of the CI (a record of its result; not a review). | All three jobs passed on `742a8ff`, the later steps of the test job for the first time on the runner. One passing run; see below for what it does not show. |

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
| KeePassXC round trip is checked with the same parser, not by opening the result in KeePassXC | **Open** then (since closed: an ignored round-trip test was run with KeePassXC 2.7.6, `e4920e4`, S2 below; and KeePassXC 2.7.6 reopened the results of the KDBX 4.0 fix, `935743b`). |
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

Third review of the group move (Codex, AI-assisted, 2026-11-02): **ready.**
Both findings are confirmed fixed: look-alike destinations with UUIDs that
start alike are told apart in the dialog and the audit log; the manager
sends an edited row and a move to the entry's own group ends with "nothing
to change", the form and the list as they were. Two low findings, both
documentation, fixed: P7 and the comment of `EntryInfo::identity` still
said two entries with the same title never look alike (they are shown with
the start of their UUID, L9); and P7 promised a 1000-character limit for
every field, which applies to a run's command line, program path and
directory (other details count towards the dialog's total and, with zenity,
its height; a destination is never truncated).

**Choose the group from a list (2026-11-02).** At the maintainer's request:
a typed group path invites typos, and names are case-sensitive. The
manager's forms offer No group, the groups in use and the groups above
them, and "New group…" for a path, with a warning for a new path that
differs from an existing group only in case; the form tells the model
whether the human chose another group, so a chosen group is sent and the
agent still decides by the group itself.

Review (Codex, AI-assisted, 2026-11-02): **ready.** Searching, refreshing
the list, renaming without a new choice, choosing another group and back,
escaped labels and groups of the same name behaved as they should; a group
of another client named `Work/Servers` offers an inferred `Work`, which the
agent's dialog then shows as "creates Work at the top level". Two low
findings, fixed and checked against the mistake (2 of 2): the case warning
did not come back when "New group…" was chosen again with the text still
there; and a new entry's group was checked by the agent only, after the form
had closed — the form now checks it as it does for an edit. The guide now
says that a group is left out of the list only when neither it nor any
group below it holds an entry.

**Credential broker design (2026-11-02).** At the maintainer's request,
before writing [ADR 0013](adr/0013-credential-broker.md): an independent
analysis (Codex, AI-assisted) of the roadmap's broker sketch against
CyberArk's Secretless Broker and the maintainer's real uses. Its
conclusions are in the ADR's context: worth doing, HTTP and the AI APIs
first; a grant limits but does not remove the trust in the operations it
allows; a same-user process can steal a token while it is valid (A2 needs
isolation); private devices need pinned TLS; administration APIs need
narrow operations; SSH with a password cannot be brokered (the maintainer
moves the routers to SSH keys). Three overstatements in the roadmap and in
L4 were corrected. The four reviews of the ADR itself are recorded below.

**Credential broker ADR reviews (2026-11-02).** At the maintainer's
request: four adversarial reviews of [ADR 0013](adr/0013-credential-broker.md)
before it becomes the basis for phase 1, checked against the agent, vault,
execution, redaction, audit, protocol and supervision code and the security
invariants. This entry was written by Codex (AI-assisted), at the
maintainer's request on 2026-11-02, to record the dispositions before
implementation; there is no phase 1 broker code yet, and its implementation
will be reviewed separately. **Fixed (design)** below means specified in
the amended ADR, not implemented or proved by running broker tests. The
tables give the final dispositions; later rounds record the cases where
earlier amendments had not yet closed a finding.

Review (Codex, AI-assisted, 2026-11-02; verdict: not ready). The proposed
ADR at `24db2f6` left 25 findings (F01–F25), ten open questions and further
questions needed to implement phase 1 without inventing security policy.

| Finding | Disposition |
|---|---|
| High — F01: a separate process was said to contain a compromised HTTP/TLS stack to one credential | **Fixed (design):** decisions 1 and 4 distinguish credentials present in one broker's memory from arbitrary code execution with the user's powers; the broker hardens itself before reading secrets (Components and processes). |
| High — F02: broker cardinality, supervision, control-channel failure and restart behavior were unspecified | **Fixed (design):** one broker per grant; a bounded startup transaction, control-channel EOF and process-group termination govern its lifetime; no grant is restored after restart (Components and processes; Admission, revocation and the agent's registry). |
| High — F03: admission, audit and revocation could race without one authority | **Fixed (design):** the agent's registry reserves uses and slots, records durably, rechecks before admission, and serializes revocation; ACK or kill marks completed revocation, with the earlier-admitted-request window documented (Admission, revocation and the agent's registry). |
| High — F04: a grant could remain usable after its command leader exited while output or descendants kept the run alive | **Fixed (design):** detecting leader exit or requester disconnection revokes before process-group termination and output draining; the test includes a descendant that called `setsid` (The end of the command; Tests before real credentials). |
| Medium — F05: exhausting the use count could revoke the request that consumed the last use | **Fixed (design):** `exhausted` differs from `revoked`; admitted requests finish, and the N-th request must complete in the limit test (decision 8; Admission, revocation and the agent's registry). |
| High — F06: remembered approval could mint fresh grants and budgets without another decision | **Fixed (design):** a run with broker bindings never offers `--remember`; each approval creates its grants once (`run`, `grants` and the protocol). |
| High — F07: route prefixes could admit batches, files or administrative operations beyond inference | **Fixed (design):** built-in presets have exact routes; batches, uploads, files and administration are excluded from phase 1 (Presets). |
| High — F08: path normalization could make the checked path differ from the forwarded path | **Fixed (design):** one restricted path grammar, exact matching and the same path upstream; escapes, empty and dot segments, semicolons and backslashes are refused (Requests and responses). |
| High — F09: HTTP framing and hop-by-hop handling did not define a safe forwarding boundary | **Fixed (design):** the final policy accepts Hyper's identical-length normalization, rejects conflicting lengths and every request transfer coding, restricts `Connection`, rebuilds framing and drops trailers (Requests and responses; N11 below). |
| High — F10: local token authentication and upstream credentials could be confused or forwarded together | **Fixed (design):** each preset defines token headers and upstream authentication; conflicting token headers fail, other credentials are discarded, and queries are allowlisted (Presets; Requests and responses). |
| High — F11: compressed responses, framing changes and short or transformed credentials defeated the proposed redaction guarantee | **Fixed (design):** only uncompressed response content and the permitted transfer coding are accepted; credential-bearing header values are dropped, output is chunked, credentials have a supported length/alphabet and HTTP redaction uses a fixed marker. Transformed echoes remain a documented limit; Basic is deferred (decision 1; Requests and responses). |
| Medium — F12: passing redirects to an SDK could bypass the fixed destination | **Fixed (design):** every upstream `3xx` becomes a local `502` without `Location`; neither broker nor client follows an upstream redirect through this response (Requests and responses). |
| Medium — F13: SDK retries could repeat charged or non-idempotent operations without a clear use count | **Fixed (design):** every admitted attempt consumes a use, regardless of outcome; local errors control retry advice and the guide recommends disabling SDK retries (Requests and responses; Answers 1 and 9). |
| Medium — F14: a client's environment proxy could receive the loopback token and traffic | **Fixed (design):** both `NO_PROXY` and `no_proxy` include `127.0.0.1`; the broker has an empty environment and fixed CA-file policy. Custom client transports remain outside this environment guarantee (Components and processes; `run`, `grants` and the protocol). |
| High — F15: using exit 125 after the command started would break the no-start error contract | **Fixed (design):** 125 applies only before command start; afterward the command's status is returned and individual HTTP outcomes are audited (decision 6; Answer 6). |
| Medium — F16: edits, replacement, failed saves and external reloads lacked complete grant invalidation rules | **Fixed (design):** entry changes end its grants, replacement removes the profile, failed saves end all grants, and the final unlock barrier compares encrypted-file content and revokes all survivors on change (Profiles; Admission, revocation and the agent's registry; N01 below). |
| Medium — F17: profile storage, validation and preset evolution were not specified | **Fixed (design):** the unprotected `Rusthorse.Broker` field holds strict versioned JSON; invalid or protected profiles are unusable, preset revisions stay fixed, and the base-path grammar is canonical (Profiles). |
| Medium — F18: broker bindings, URL routing, mixed execution and protocol compatibility lacked an enforceable wire contract | **Changed by the maintainer's decision:** mixed bindings are allowed for different entry UUIDs, never the same entry in both modes; `--no-redact` is allowed with a warning. Agent-side validation and protocol 8's distinct `broker_run` and `broker_edit` requests close silent downgrade paths (`run`, `grants` and the protocol). |
| Medium — F19: recording raw paths or queries could put credentials or tokens in the audit log | **Fixed (design):** audit records contain the grant ID, method and route template, never raw paths, queries, header values or bodies (Audit records). |
| Medium — F20: one audit event could not distinguish permission to forward from the request's eventual outcome | **Fixed (design):** durable admission and completion are separate records; failed completion recording revokes the grant, while revocation never waits for audit I/O (Audit records; Admission, revocation and the agent's registry). |
| Medium — F21: missing resource budgets and deadlines left streaming and concurrent requests unbounded | **Fixed (design):** phase 1 specifies grant, connection, request, body-memory, DNS and time limits; body capacity is reserved before admission and reading (Requests and responses; Limits). |
| Medium — F22: a reused loopback port, DNS rebinding or browser access could undermine the local endpoint | **Fixed (design):** the agent retains the listener, publishes a literal loopback address and validates `Host`; `Origin` is refused. The absence of server authentication on the plaintext local hop is **documented** (Components and processes; Requests and responses; Consequences). |
| Medium — F23: DNS and TLS policy could allow credentials to reach private or unverified destinations | **Fixed (design):** only checked public addresses are connected to, without resolving again; Host/SNI come from the profile, TLS verification uses the fixed trust policy, and redirects are not followed (Requests and responses). |
| Medium — F24: guarantees exceeded the design and conflicted with the existing agent-only secret invariant | **Fixed (design):** guarantees apply to brokered bindings, state same-user and transformed-echo limits, and distinguish memory separation from code-execution containment; Consequences requires updating invariant 1 with implementation. Later wording residuals are recorded below. |
| Medium — F25: approval did not expose the grant's effective authority and limits | **Fixed (design):** decision 7 requires destination, every route, termination policy, duration, request limit or its absence, concurrency, real-value bindings, cost and opaque-body warnings; existing dialog escaping and refusal-on-size invariants still apply. |
| Medium — further questions: states, token format, IPC contents, quota authority, completed revocation, clocks and idle, cookies/cache, Basic, preset evolution, invalid/protected profiles, manual revocation, traffic assets, body handling and audit-independent revocation | **Answered (design):** Phase 1 specification assigns these contracts to the registry, token, control-channel, profile, HTTP, audit and manager sections; Consequences adds the assets. Basic is explicitly deferred to phase 2 rather than left implicit in phase 1. |

On 2026-11-02 the maintainer accepted the ten recommended answers (the
ADR's Answers section) and chose the following policy changes: profiles
select `automatic_locks: end` or `continue`; AI presets default to
`continue` and 12 hours, while device profiles in phase 2 default to `end`
and 15 minutes. Command end, explicit lock, manual revocation, relevant
entry changes, failed saves, broker failure, agent stop and expiry still
end grants. `--broker` with `--no-redact` is allowed with an approval
warning for interactive clients; mixed runs are allowed for different
entries. Basic and generic profiles move to phase 2; the manager's grants
panel belongs to phase 1, with profile editing in the CLI. These are
maintainer decisions, not unresolved findings demanding the earlier policy.

Second review (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Rechecked F01–F25 and the further questions against the rewritten ADR;
identified 11 concrete cases (N01–N11) and eight inconsistencies
(C01–C08), including residuals of the first review.

| Finding | Disposition |
|---|---|
| High — N01: `continue` grants could survive loading an externally changed entry | **Fixed (design), after the third review:** the final unlock barrier keeps a keyed fingerprint of the encrypted file across locks and ends all surviving grants on a difference or absent reference, with reason `vault_changed`; an unchanged file preserves them (Admission, revocation and the agent's registry; Audit records). |
| Medium — N02: reading bodies before admission allowed up to 32 GiB across the stated connection and grant limits | **Fixed (design):** each body is at most 16 MiB, its declared length is reserved against 64 MiB per broker before admission, and only admitted bodies are read (Requests and responses). |
| Medium — N03: checking only `Content-Encoding` missed compressed `Transfer-Encoding` responses | **Fixed (design):** unsupported content encodings and any transfer coding other than exactly `chunked` produce a local 502 before response forwarding (Requests and responses). |
| Medium — N04: the existing redactor skips short credentials that the profile still allowed | **Fixed (design):** credentials must contain 8 to 4096 visible ASCII characters without spaces, checked before approval; HTTP redaction uses `[REDACTED:credential]` rather than an entry-derived label (Requests and responses; `run`, `grants` and the protocol). |
| Medium — N05: preparation lacked atomic publication, a startup deadline and rollback of all grants if spawn failed | **Fixed (design):** `starting` grants are registered with the generation check and credential read, installation has a ten-second deadline, and any failure stops all prepared brokers and releases their ports before returning 125 (Preparing a run's grants). |
| Medium — N06: concurrent IPC requests and completions had no specified correlation or duplicate handling | **Fixed (design):** increasing request numbers correlate both directions; reused or invalid transitions end the grant and kill the broker without applying the offending message to counters (Request numbers; The control channel). |
| Medium — N07: DNS and initial headers lacked deadlines, and blocking resolution could prevent shutdown on EOF | **Fixed (design):** the whole header block has a 30-second deadline, resolution plus connection has ten seconds and at most four resolutions run concurrently; process exit must not wait for pending resolution (Requests and responses; Leaving). |
| Medium — N08: profile validation accepted dot-segment base paths that request validation refused | **Fixed (design):** the profile and request grammars exclude empty, `.` and `..` segments and a trailing slash (Profiles; Tests before real credentials). |
| Medium — N09: an agent 7 encountered after the version check could ignore optional broker bindings in a mixed `run` | **Fixed (design):** `broker_run` is a new request discriminator, refused whole by agent 7; plain `run` cannot carry broker bindings (`run`, `grants` and the protocol). |
| Medium — N10: registry revocation and effective cancellation were conflated, particularly for automatic locks | **Fixed (design):** every revocation awaits ACK or kill before reporting completion, documents the previously admitted request window, and retains L20's limits on when a suspend lock can begin (Revocation; R02 below). |
| Medium — N11: Hyper removes CL when TE is present and merges identical CL headers before the handler can inspect them | **Changed (design):** the policy accepts identical CL normalization, rejects conflicting lengths and refuses every request TE; it no longer requires detecting headers the parser has discarded. This was a feasibility finding, not demonstrated request smuggling (Requests and responses). |
| Low — C01: the containment claim still covered arbitrary code execution despite its caveat | **Fixed (design):** decisions 1 and 4 explicitly separate a leak of one process's memory from execution with the user's powers. |
| Low — C02: token-only delivery and output redaction were stated without the mixed-run and `--no-redact` qualifications | **Fixed (design):** decisions 1 and 2 scope the promises to brokered bindings and enabled output filtering. |
| Medium — C03: an opaque client body could contain the token despite the test's universal claim that the destination never receives it | **Fixed (design), through later reviews:** decision 1 acknowledges client-controlled body contents; the header guarantee is enforced by dropping allowed headers whose name or value contains the token (Requests and responses; R03 below). |
| Medium — C04: saying a run's grants always end together contradicted per-entry and per-profile termination | **Fixed (design):** decision 8 and Answer 10 distinguish shared events from individual termination; the unlock barrier separately specifies conservative revocation of all survivors after an external vault change. |
| Low — C05: `audit_failed` was used but missing from the audit reason list | **Fixed (design):** the Audit records table includes it. |
| Low — C06: the ADR pointed to dispositions in this history before they had been recorded | **Recorded:** the history was written after the fourth verdict, as planned; this entry records all four rounds and replaces the earlier pending-review sentence. |
| Low — C07: environment proxy behavior was presented as universal across SDK runtimes | **Fixed (design):** What the clients do distinguishes Python's transport behavior from Node configured to use environment proxies. |
| Low — C08: approval could omit the absence of a request limit, concurrency or the raw-value part of a mixed run | **Fixed (design):** decision 7 requires all three explicitly. |

Third review (Codex, AI-assisted, 2026-11-02; verdict: not ready).
Most amendments were confirmed; N01 and C03 remained partial, and two new
findings, R01 and R02, exposed a downgrade path for editing and an
overstatement of suspend timing. R02 also explains the remaining N10
qualification; these follow-ups are not additional first-round findings.

| Finding | Disposition |
|---|---|
| High — N01, still partial: UUID, last-modification time and profile do not identify entry content; an external move can change only `location_changed`, and value edits can preserve timestamps | **Fixed (design):** the unlock barrier now compares the encrypted file's keyed content fingerprint, not entry timestamps, and conservatively ends every surviving grant on change. Its test includes a move and a value change with modification time preserved. |
| Medium — R01: adding a profile to the existing `edit` let an agent 7 apply known fields, such as username, and silently ignore a more restrictive profile after a restart between connections | **Fixed (design):** every edit that sets or clears a profile uses `broker_edit`, including combined edits; plain `edit` refuses profile operations. The protocol test meets an agent 7 after checking version 8 (`run`, `grants` and the protocol; Tests before real credentials). |
| Medium — R02, residual N10: a one-second broker cancellation budget did not guarantee that the whole lock fits logind's delay, since a save can hold the agent's state first | **Documented:** Revocation measures the approximate second after revocation starts and explicitly preserves L20's delayed-start and logind limits; no new guarantee of completing before suspend is made. |
| Low — C03, still partial: an allowed `User-Agent` value could contain the token despite the header guarantee | **Fixed (design):** forwarded headers containing the token are dropped; the test includes `User-Agent`. The fourth review checked the remaining header-name case (Requests and responses; Tests before real credentials). |

The third review also requested consistent wording for the 16-grant
limit, `Connection` handling and observing leader exit. The ADR now says
"no more than 16", refuses a request whose `Connection` names anything
except `close` or `keep-alive`, and ties command-end detection to the
agent observing the leader exit, before output draining.

Fourth review (Codex, AI-assisted, 2026-11-02; verdict: ready).
Confirmed N01, N10, R01, R02, F16 and F18 resolved in the design and the
three wording suggestions incorporated. No critical, high or medium
blocker remained. C03 and F24 retained one low case, R03, which did not
expose the source credential or expand the grant's authority; the client
already holds its token and can deliberately put it in an opaque body.

| Finding | Disposition |
|---|---|
| Low — R03, residual C03/F24: filtering only header values still let `x-stainless-` followed by the token carry it in an allowed header name | **Fixed (design), after the fourth verdict:** Requests and responses now drops an allowed header when its name or value contains the token; the test includes both a token-bearing `User-Agent` and an `x-stainless-` header named after the token. C03 and F24 are closed at the design level. |

The fourth review's additional checks are now in the test matrix: a failed
unlock preserves the previous fingerprint, and the agent's successful
save of another entry updates the fingerprint without ending unaffected
grants. The fingerprint must describe the bytes actually read or written;
comparison precedes replacing its reference. These are implementation
checks, not claims that broker tests have already run.

Final disposition: **READY as the design basis for phase 1**, with R03
corrected in the ADR after the fourth review. Implementation, its tests
and the corresponding changes to the security invariants and protection
claims still require their own review.


**2026-11-02–03 — Credential broker phase 1: implementation reviews.**

At the maintainer's request, the foundation and each parallel piece were
checked before integration, then the whole was reviewed against ADR 0013. This
history was consolidated by Codex (AI-assisted) on 2026-11-03 from the
implementers' notes, independent Claude verifier reports, Codex reviews and
commits, initially checked against code at `70ad512`. Q01's follow-up and this
documentation revision use `d1cab93`, which includes its two fixes. It records
historical results, not a fresh rerun of every reported mutation.
Finding/mutation names below are scoped by piece to avoid collisions. Severity
is the reviewer's; notes without one remain observations rather than invented
security findings. Earlier design-review entries above remain historical.

**2026-11-02 — Foundation (`24c59b9`, then `d654f5e`).**

Review (Claude independent verifier, AI-assisted, 2026-11-02; verdict: needs
fixes), requested before the broker, agent, CLI and manager depended on the
shared types and wire shapes. The original implementation had 16 mutation
checks, all caught; the seven fixes had 27, all caught.

| Finding | Disposition |
|---|---|
| High — V01: optional fields on plain run/edit let a protocol-7 agent silently drop broker authority after a restart between connections. | **Fixed in `d654f5e`:** separate `broker_run` and `broker_edit`; plain run/edit refuse broker fields; protocol-7 decoding and real old-agent probes refuse the new requests whole. |
| Medium — V02: credentials of 1–8192 bytes were accepted, including values below the redactor's minimum. | **Fixed in `d654f5e`:** 8–4096 visible ASCII characters; compile-time relation to the redactor minimum and boundary tests. |
| Medium — V03: request-body limit was 32 MiB and the aggregate budget was missing. | **Fixed in `d654f5e`:** 16 MiB per body, 64 MiB budget constants. |
| Medium — V04: the control channel could not express `vault_changed`. | **Fixed in `d654f5e`:** the end reason and its serialization tests. |
| Low — V05: malformed/disallowed routes returned 400 rather than the specified 404. | **Fixed in `d654f5e`:** route/query failures are 404; non-origin-form targets remain a framing 400. |
| Low — V06: header, Ready, resolver and control-EOF deadlines lacked shared constants. | **Fixed in `d654f5e`:** phase 1 constants in `broker_protocol.rs`. |
| Low — V07: the temporary agent refusals and plain-edit clear guard had no policy tests. | **Fixed in `d654f5e`:** end-to-end refusal tests, later replaced/extended as the real handlers arrived. |

Review (Codex, AI-assisted, 2026-11-02; verdict: ready), requested on the
fixed foundation against ADR 0013, before the parallel pieces used it.

| Finding or suggestion | Disposition |
|---|---|
| Low — B01: cursor syntax, ID length and all-dot segments differed from the ADR. | **Fixed in `623589c`:** cursors accept the same colon-bearing ID syntax; 128-character IDs/cursors, 1–4-digit limit and rejection of all-dot segments are explicit in the ADR. Five mutations for this commit, including S3 below, all caught. |
| Suggestion — S1: Admit's documentation implied the body was already read. | **Fixed in `623589c`:** declared length and budget are checked before admission; body reading follows it. |
| Suggestion — S2: prove preservation through KeePassXC itself, not only a compatible fixture. | **Deferred, then tested in `e4920e4`:** an ignored round-trip test was run with KeePassXC 2.7.6; it is not required in CI where that program may be absent. |
| Suggestion — S3: cap Install's lifetime by the stored profile too. | **Fixed in `623589c`:** validation rejects an excessive lifetime, with a mutation check. Independent enforcement at runtime was still incomplete until P02. |

**2026-11-02 — Shared helpers (`8873451`).**

Implementation checks (Claude, AI-assisted, 2026-11-02), requested to settle
helper lookup, CA trust and optional audit fields before parallel work. There
was no separate independent verdict for this commit: the whole reviews below
include it. `helper_program` generalized the dialog's lookup; `open_ca_file`
validates the opened regular root-owned file and its parent directories, using
O_NONBLOCK so a FIFO cannot hang the check; new audit fields are omitted when
absent.

Mutation checks: 29 (20 CA, 4 helper, 5 audit), 25 caught. The four survivors
are named here by operation because the commit supplies no IDs:

| Surviving mutation | Disposition |
|---|---|
| SH-CLOEXEC: remove explicit O_CLOEXEC. | **Accepted:** Rust's file opening sets it already. |
| SH-ANCESTOR-TYPE: remove the ancestor-is-directory check. | **Accepted under the root-owned-path assumption:** replacing such an ancestor requires root; a symlink also fails the mode check. |
| SH-FD-RACE: check by path instead of the open descriptor. | **Documented coverage gap:** the unit tests do not force a replacement race; this is not evidence that path checking is equivalent. The implementation still checks the descriptor. |
| SH-OPTION-DEFAULT: remove serde(default) from an Option field. | **Accepted:** an absent optional field already deserializes to None. |

**2026-11-03 — Piece B: the broker program.**

Implementation checks (Claude, AI-assisted, 2026-11-03) in `8f01426` and
`7b0fb51`, requested for the HTTP process and fake HTTPS tests. The WIP checks
corrected pending-admission outcomes, revocation/counting races, lifetime
starting at Install, Ready after runtime setup, bounded buffers and panic/exit
handling. They reported 60 mutations, 57 caught. Three independent deletions
survived behind other checks: B-F2 (Transfer-Encoding alone: Hyper's unknown
body length is still refused), B-E1 (pre-forward revocation check: the
connection is closed and credential dropped), and B-E11 (relay revocation
branch: the client connection is closed). Removing each together with its
backup was caught. The notes also name B-M60 as an earlier survivor without
describing it; it cannot be independently classified from the supplied reports
and is not counted as an extra proof. The missing-system-CA startup case was
not mutated end-to-end (the system file cannot be removed by a test); the
shared CA unit tests cover its validation. The panic-hook gap was closed in
the following verification.

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: needs
fixes), requested before integration. Fixes are in `6ad1bdb` unless another
commit is named.

| Finding | Disposition |
|---|---|
| Medium — B-V1: the body budget was released while Hyper still retained unwritten bytes. | **Fixed in `6ad1bdb`:** the reservation is shared by forwarding until the response head and by the owned Bytes until Hyper releases them; writev avoids an unaccounted copy. Tests cover a stalled reader, no response and an early response. |
| Low — B-V2: no test proved an active stream survives the connection idle timeout. | **Fixed in `6ad1bdb`:** a stream four times longer than the idle limit completes; dropping its busy guard fails the test. |
| Low — B-V3: TLS/client-pause deadlines, resolver wiring, panic exit and several revocation races lacked tests. | **Fixed in `6ad1bdb`:** targeted tests, biased revocation branches and a test-only panic trigger. |
| Low — B-V4: “never reads the environment” was stronger than the dependencies permit. | **Fixed in `6ad1bdb`, documented here:** the broker's own production code reads none; loader/resolver/runtime variables are unset by the agent. An explicit resolver-thread stack size avoids RUST_MIN_STACK. |
| Low — B-V5: Revoked's ordering did not state that all admission answers must arrive first. | **Fixed in `6ad1bdb` and `6885f24`:** broker waits for every answer/Finished; agent refuses pending admissions immediately on revoke. Early-ack tolerance is documented in `db91106`. |
| Low — B-V6: a test-upstream build could look like a production helper. | **Fixed in `6ad1bdb` and `d5691ff`:** compile-time release guard, check marker, doctor refusal. Runtime use with an empty environment was revisited and fixed as P05. |

The fix report enumerates checks rather than a unique aggregate: B-MB1–MB4 all
caught, each budget holder by its applicable test; B-M48 (busy), B-M1 (TLS),
B-M3 (client pause), B-M2 (resolver wiring, unit test), B-MR1–MR6
(revocation), B-M61/M61b (panic) and B-M6/M6r (check reports) caught. B-M6u is
the same mutation as B-M6 run against a unit test, not another variant.
Removing each of six `biased` directives was caught 20, 20, 19, 20, 19 and 20
times in 20 runs: probabilistic race coverage, not a proof that every run
detects it. B-M2b (remove the blocking-pool limit) survived behind the
resolver's four retained slots. B-MB2/B-MB4 surviving the other budget
scenarios is expected; each fails its own scenario. Release-feature
compilation was refused, and a getenv probe logged names only.

**2026-11-03 — Piece C: agent integration and the unlock fingerprint.**

Implementation checks (Claude, AI-assisted, 2026-11-03), requested for the
registry, preparation transaction and every grant-ending event (`9e6d598`,
`d7bfbcc`). WIP findings and their subsequent status:

| Finding | Disposition |
|---|---|
| High — C-W1: a grant revoked while starting could attach an unrevoked broker and hang cleanup. | **Fixed in `d7bfbcc`, strengthened by P03 in `7ac4c15`:** reject attachment after starting ends; register before credential delivery. |
| Medium — C-W2: a stuck broker writer could delay revocation under the writer lock. | **Fixed in `d7bfbcc`:** bounded/non-blocking writer acquisition and forced cleanup. |
| Medium — C-W3: one realistic broker grant did not fit zenity's approval estimate. | **Fixed in `d7bfbcc`:** shorter factual dialog text and a height test; multiple grants can still be too tall. |
| Low — C-W4: late admission refusals could be missing from end counts. | **Fixed in `d7bfbcc` and refined in `6885f24`:** registry accounting and answer ordering. |
| Low — C-W5: the unlock barrier waited on the unlock audit record. | **Initially reported fixed in `d7bfbcc`; reopened as P01:** deciding revocation alone did not contain the broker. Actual containment before audit is fixed in `0932d31`. |
| Low — C-W6: control work needed a bounded queue. | **Fixed in `d7bfbcc`:** JOB_QUEUE 256 and violation/cleanup tests. |

Initial checks reported 56 mutations, 53 caught. Survivors were the serialized
request-limit recheck, an unused broker remembering key (the non-rememberable
approval guard was caught), and a missing fingerprint branch unreachable after
the vault has opened. The later admission refactor made the
pending-reservation mutation C-B9a detectable; the old “survives by design”
disposition no longer applies. The boot-time versus monotonic-clock mutation
was caught on a machine that had suspended; those clocks coincide before its
first suspend.

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: needs
fixes), requested before integrating the agent with the broker.

| Finding | Disposition |
|---|---|
| Medium — C-F1: no test proved a failed grant-created record prevents the credential handoff. | **Fixed in `6885f24`:** unit test rejects the run, starts no broker and leaves no grant; C-M1 catches ignoring that write error. |
| Low — C-F2: audit work could delay pending admission answers needed for Revoked. | **Fixed in `6885f24`:** the reader reserves admissions, revoke answers them at once, and containment work does not block the audit worker. |
| Low — C-F3: retained-listener protection against port reuse was untested. | **Fixed in `6885f24`:** binding the port fails until the run releases it. |
| Low — C-F4: activation's starting-state guard was untested. | **Fixed in `6885f24`:** a revoked preparation never becomes active. |
| Low — C-F5: expiry timer and StopGrants were not exercised. | **Partly fixed in `6885f24`:** timer tests added; timer-start failure later fixed by P02. **Accepted coverage gap:** C-V20/C-M8 removes StopGrants and survives; direct stop_all is tested, but serve returning/unwinding with grants needs a test seam. SIGTERM does not run that guard (L23). |
| Low — C-F6: starting state and status/capacity counts were unclear. | **Fixed in `6885f24`, documented here:** status counts starting/active/exhausted; listing and capacity also retain revoked grants. |
| Low — C-F7: automatic locks preserved starting continue grants contrary to the ADR. | **Fixed in `6885f24`:** every lock ends all starting grants. |
| Low — C-F8: fingerprint keys and collision claims exceeded what RandomState promises. | **Fixed in `5654dcc`, documented in L22:** one key drawn on its own thread (fallback to the caller if spawning fails), domain-separated outputs; no unconditional cryptographic 128-bit claim. |
| Low — C-F9: the manager's AgentConfig literals would not compile after integration. | **Fixed in `189703f`:** new test configuration fields supplied at the merge. |
| Low — C-F10: failures after approval could lack an aborted record. | **Fixed in `6885f24`:** shared best-effort aborted recording, including plain runs; P01 subsequently ensured cleanup precedes that audit. |
| Low — C-F11: missing Python silently skipped policy tests. | **Fixed in `6885f24`:** fail unless the explicit RUSTHORSE_TEST_WITHOUT_PYTHON opt-out is set. |
| Low — C-F12: multi-broker preparation failure and a lock during startup lacked end-to-end tests. | **Fixed in `6885f24`:** stand-in brokers force both failure paths and verify complete cleanup. |

The fix report says “31 mutations and one control”, but its detailed list
contains 30 distinct variants: 27 caught, three surviving; C-M3r/C-M11r are
reruns of C-M3/C-M11 after selecting the wrong tests. This history does not
turn that inconsistent aggregate into 31 distinct successful checks. C-M13b is
the explicit-Python-skip control. Surviving variants:

| Surviving mutation | Disposition |
|---|---|
| C-M8 (the verifier's V20), remove StopGrants. | **Accepted coverage gap:** as C-F5 and L23, not declared redundant. |
| C-M11b, draw the fingerprint key on the caller's thread. | **Accepted:** related HashMap seed alone exposes no key or hash outputs through the agent's API; separate-thread creation remains best effort. |
| C-B12b, omit the early admission-state check. | **Accepted:** the post-record check still refuses forwarding; a redundant admitted/not_forwarded audit pair can result. |

Checks caught only at the appropriate unit boundary include the fail-closed
creation record, profile lifetime clamps and fingerprint domain separation;
they are not presented as full-system proofs.

**2026-11-02–03 — Piece D: CLI and guide.**

Implementation checks (Claude, AI-assisted, 2026-11-02), requested for the
commands clients would use (`3f687b5`, `5d92a0e`, `6e956ba`). Audit output was
escaped because same-user editable records could forge terminal lines (one
mutation caught); the CLI's 29 mutations were all caught. A later independent
review found these six low findings (Claude, AI-assisted, 2026-11-03; verdict:
ready):

| Finding | Disposition |
|---|---|
| Low — D-V1: grant-table escaping tests missed most agent-controlled cells. | **Fixed in `3faa4d8`:** hostile values in every cell and order are tested. |
| Low — D-V2: duplicate ordinary bindings could reach the agent unnecessarily. | **Fixed in `3faa4d8`:** early CLI refusal, no request sent. |
| Low — D-V3: status called every retained grant active. | **Fixed in `3faa4d8`/`6885f24`, documented here:** label/count semantics distinguish starting/exhausted from revoked listings. |
| Low — D-V4: the Claude Code recipe and compatible-origin wording promised unverified support. | **Fixed in `3faa4d8`, documented here:** explicit origin and pending manual validation; no claim of testing with a real key. |
| Low — D-V5: version checks and doctor-without-agent tests missed paths. | **Fixed in `3faa4d8`:** checks before edit/grants effects and targeted fake-agent/doctor tests. |
| Low — D-V6: doctor wording implied it parsed and validated the CA certificates. | **Fixed in `3faa4d8` and installation docs in `d7c83a1`:** doctor checks the file; the broker parses certificates at grant startup. |

The fixes had 15 mutations, all caught; prose is supported by code review, not
counted as mutation-tested behaviour. CLI broker operations refuse old agents
and never fall back to a value binding. Q02 later clarified SDK
variable/header wording further.

**2026-11-02–03 — Piece E: manager.**

Implementation checks (Claude, AI-assisted, 2026-11-02) completed the WIP in
`c023127`, at the maintainer's request for a metadata-only grants page and
profile display. All 24 implementation mutations were caught.

| Finding or observation | Disposition |
|---|---|
| Low — E-F1: maximum lifetime rounded down despite “at the latest”. | **Fixed in `c023127`:** round up, with boundary tests. |
| Low — E-F2: “unverified” was appended to requester-controlled text. | **Fixed in `c023127`:** put it in the fixed field label. |
| Low — E-F3: listing/revocation could leave controls waiting ten minutes. | **Fixed in `c023127`:** 30-second limit; whole-job enforcement refined below. |
| Low — E-F4: lifetime display arithmetic could overflow. | **Fixed in `c023127`:** saturating arithmetic and u64 boundary test. |
| Info — E-F5: listing epochs changed redundantly at request start and end. | **Changed in `c023127`:** invalidate at completion; both remaining invalidations tested. |
| Low — E-F6: manager docs attributed agent enforcement to the manager. | **Fixed in `c023127`:** describe the client's behaviour and the agent's authority separately. |
| Low — E-F7: a partial list of end reasons looked exhaustive. | **Fixed in `c023127`:** qualified wording and warning about already-sent requests. |
| Info — E-F8: replacing an imported entry removed its profile without a manager note. | **Fixed in `c023127`:** import warning. |
| Test-gap observation — E-F9: missing refused/unanswered requests, empty/no-agent and stale-listing cases. | **Fixed in `c023127`:** fake-agent widget scenarios, never real credentials. |

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: ready),
requested before integration; six low findings:

| Finding | Disposition |
|---|---|
| Low — E-V1: refreshed rows could move a different grant under a Revoke click. | **Fixed in `0b7787b`:** stable keyed rows, disappeared grants shown ended in place, tests bind the clicked ID. |
| Low — E-V2: error-text filtering lacked a widget test. | **Fixed in `0b7787b`:** hostile listing/revocation messages tested through dialog_text. |
| Low — E-V3: missing-vault note, unreported status and refresh-after-request paths were untested. | **Fixed in `0b7787b`:** fake-agent and first-start coverage. |
| Low — E-V4: the stated 30-second bound actually allowed about 50 seconds across job stages. | **Fixed in `0b7787b`:** one deadline from the start of the whole job, also for human requests. |
| Low — E-V5: starting grants lacked their intended description and count semantics. | **Fixed in `0b7787b` and `6885f24`:** starting label and status count aligned. |
| Low — E-V6: shared architecture/changelog/invariant docs lagged the feature. | **Documented in this 2026-11-03 consolidation:** protocol 8, grants page, profiles and ownership of secrets. |

All 11 verification-fix mutations were caught; parallel load checks and
private-Xvfb light/dark inspection used fake data. Grants carries no token;
profile forms stay read-only and the manager never sends broker_edit.

**2026-11-03 — Whole phase 1 at `189703f`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: not ready), requested by the
maintainer to examine the seams after pieces B–E were integrated, before
system tests and packaging were finished.

| Finding | Disposition |
|---|---|
| Medium — P01: unlock decided revocation but waited for audit before containing brokers. | **Fixed in `0932d31`:** contain first, record outside the state lock, recheck generation before publishing; aborted-run cleanup also precedes its audit. |
| Medium — P02: expiry depended on an agent timer that could fail to start, and the broker did not independently end open work. | **Fixed in `a23450c` and `38ddb0b`:** refuse grants without the agent timer; broker boot-time task and per-step deadline checks drop credentials/work without an unsolicited Revoked. |
| Medium — P03: Install could deliver the credential before the process was registered for revocation. | **Fixed in `7ac4c15`:** register Link and non-blocking Install under one registry lock, only while starting; failures kill/reap. |
| Medium — P04: another revoker could treat a requested kill as completed containment. | **Fixed in `7ac4c15`:** Running/Ending/Gone; publish Gone only after kill/reap; waiters share confirmed/dead state. |
| Medium — P05: a test build started by the production agent could reach loopback. | **Fixed in `ea3e3c8`:** absent RUSTHORSE_BROKER_TEST_ROOTS selects production settings before other hooks are read; agent env_clear is the runtime boundary. |
| Low — P06: the manager's Anthropic snippet bound the wrong variable for the library recipe. | **Fixed in `f8c6554`:** ANTHROPIC_API_KEY and BASE_URL, note to leave AUTH_TOKEN out, separate Claude Code recipe. |
| Suggestion — document early Revoked tolerance. | **Fixed in `db91106`:** the agent's tolerance is explicit; the real broker still orders its acknowledgement after all answers/Finished. |
| Suggestion — test P01–P05 with both real components. | **Partly covered and accepted:** F tests P01, expiry and production settings with real components. Deterministic registry/stand-in tests force P03/P04 interleavings; doing so in a full-system test would require new agent test hooks. |

Fix verification (Claude, AI-assisted, 2026-11-03), requested for these
findings: the agent branch tip is `db91106`, not the superseded `36db9c3`; 11
mutations all caught. Install/check atomicity is by one critical section, not
by a test interrupting inside it. A non-blocking Install relies on room for
the <=64 KiB frame in the Unix socket send buffer; an incomplete write or
WouldBlock fails closed (a short sendmsg may be completed by the remaining
write_all). Broker/manager fixes end at `f8c6554`: 16 mutations all caught,
with 36 loaded lifetime-test runs. A long-sleep mutation first survived; a
paused-clock suspend test then caught removal of periodic CLOCK_BOOTTIME
rereads. No claim of a real-time scheduling bound follows from these tests.

**2026-11-03 — Piece F: full-system tests.**

Implementation checks (Claude, AI-assisted, 2026-11-03), requested to prove
ADR 0013 with the real library agent and broker, fake HTTPS and scripted UI
(`5041e19`, `e4920e4`). WIP checks corrected false-positive stream-cut
assertions, reading records before the final grant record, an idle test with
no actual requests, a vacuous SSL_CERT_FILE check, a Finished branch that
never ran and named-pipe interference. The supplied implementation notes do
not give a complete unique mutation total; none is inferred. The request-limit
extra-reservation mutation is named **F-M15-limit** here; the report's other
use of M15 is **F-M15-other** (its operation is not given in the consolidated
inputs). F-M15-limit survives the system test because the serialized admission
recheck refuses it before recording/forwarding; C's
`a_request_beyond_the_limit_is_refused_while_earlier_ones_are_recorded` unit
test catches that reservation error. This is not a second full-system proof.
The real KeePassXC round trip is a separately run ignored test.

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: needs
fixes), requested before merging the system suite.

| Finding | Disposition |
|---|---|
| Medium — F-V1: failed unlock coverage never reached a cancelled unlock that had already read a new fingerprint. | **Fixed in `101b1f2`:** automatic-lock password hook, surviving stream, cancelled attempt preserving the old fingerprint, then a valid unlock revoking it; F-N27 caught. |
| Low — F-V2: Lock and RevokeAll tested only one grant. | **Fixed in `101b1f2`:** two concurrent runs/streams for all-grant ends and a one-grant-only control; F-N29/N30/N31 caught. |
| Low — F-V3: failing tests could leave late-writing agents/brokers and temporary files. | **Fixed in `101b1f2`:** System Drop locks, releases gates, signals command loops and waits for runs/registry/end records before TempDir destruction; F-N32/N33/N36 caught. F-N34 remains a gap below. |
| Low — F-V4: one route could not prove completion records belonged to the right request number. | **Fixed in `101b1f2`:** alternate two routes and compare each numbered admission/finish; F-N28 caught. |
| Low — F-V5: environment requirements were incomplete and pipe synchronization depended on kernel wchan names. | **Fixed in `101b1f2`:** module requirements, full pipes and owned-descriptor observation; nix mkfifo replaces the external command, no wchan; F-N38 caught. |
| Low — F-V6: default workspace/CI checks omitted the broker. | **Fixed in `d7c83a1`:** broker is a default member; feature/no-feature checks and CA preflight cover it. |
| Low — F-V7: report claims overstated moved-entry streaming, profile ALPN, branch tip and mutation names. | **Corrected here:** the moved entry gets its own stream only in `101b1f2`; ALPN http/1.1 is fixed by the broker, not its profile; agent-fix tip is `db91106`; F-M15-limit and F-M15-other are distinct, with the latter's missing description explicit. |
| Low — F-V8: a failing mutation assertion printed the development session's environment, including a real development-tool session token, into that agent's log. | **Code fixed in `101b1f2`:** assertions check variable names before any fixed test-value comparison. **Maintainer notified:** deleting the log does not undo transcript exposure; review/rotation of that token is the maintainer's action and is not claimed complete here. No value is reproduced. |

The verification summary reports 11 checks, 10 caught; its detailed list names
only ten variants (F-N27/N28/N29/N30/N31/N32/N33/N36/N34/N38), nine caught and
one survivor. The missing eleventh variant is not inferred. **F-N34
survives:** removing the cleanup wait for grant-end records leaves a narrow
race after a run has answered and the registry emptied but the audit worker
has not written its last record. No outside test widens it without an agent
hook; no product behaviour changes, but a failed test could rarely leave its
directory. This is an accepted harness-coverage gap, not an assertion that
files cannot ever be left. `38ef1f0` enabled the previously ignored P01/P05
tests after their fixes merged; the system suite then had 35 passing tests.

**2026-11-03 — Piece G: packaging and release checks.**

Implementation checks (Claude, AI-assisted, 2026-11-03), requested for the
fourth program, feature-safe builds and licence completeness (`d7c83a1`,
`ecb3720`). The report records 25 mutation checks; the negative-protocol check
mutation survived because the runtime protocol is unsigned and the runtime
would reject that value anyway. It is a defensive packaging check, not a
release-feature bypass; the strict check remains. The supplied summary does
not give a trustworthy caught total, so none is invented. The original
three-program/173-crate packaging entry above describes its 2026-11-02 state:
this extension covers four programs and 195 crates, including ring's nested
licences and source notices. tracing-core's vendored spin licence is excluded
because that code is compiled only without std, while this build enables std.

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: ready),
requested before integration. Five low findings and one additional fixer's
test-safety finding:

| Finding | Disposition |
|---|---|
| Low — G-V1: text-only tests could miss a disabled build-deb refusal. | **Fixed in `a9017d1`:** run the whole script against stand-in cargo/dpkg, prove no packaging after refusal; explicit `|| exit 1` guards. |
| Low — G-V2: the checked release binary could differ from the one cargo-deb packaged via --profile/--target. | **Fixed in `a9017d1`:** unpack and check every packaged broker; reject pre-check install and alternate-target paths; refuse and delete the packages of that run on failure. The remaining output-name cleanup gap was found as Q01. |
| Low — G-V3: ring's Portions Copyright notices were omitted. | **Fixed in `089d7ea`:** recognize the prefix and include the four notices, including the ARM line. |
| Low — G-V4: a notice-count test did not detect missing ring source directories. | **Fixed in `089d7ea`:** independent expected-notice oracle, not just a count. |
| Low — G-V5: test docs implied feature-only execution covered every broker test. | **Fixed in `9ad5da2`:** some production-configuration tests run only without features; run both configurations. |
| Low — G-V6 (fixer): stand-in executables could hit ETXTBSY under load and dash could fall through to real system tools. | **Fixed in `28f4025`:** child-created file and rename before execution. Real loginctl was observed in 2/96 pre-fix runs; a real systemctl stop was a possible consequence, not an observed one. Post-fix: 0/96. |

Fix mutations: 30, 27 caught. **G-M06** (append `|| true` after `|| exit 1`)
survives because the failing command still exits first. **G-M28/G-M29** (omit
ring's pregenerated/third_party notice scans) survive because their notices
duplicate others in the pinned ring version; the output is identical. Both
scans remain and need review on dependency updates. The old script was also
shown packaging a test build with cargo-deb 3.8.0 and --profile dev; the fixed
script refused and removed it. No package was installed. Hosted CI and a
manual installed-broker check remain separate from these local checks.

**2026-11-03 — Codex re-review at `38ef1f0`; Q02 at `70ad512`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer after the four merges and P01–P06 fixes, with F and G included.
P01–P06 were confirmed resolved; early-Revoked documentation resolved;
real-component coverage of P03/P04 partly resolved and accepted for the
reasons above. No medium or higher finding remained.

| Finding | Disposition |
|---|---|
| Low — Q01: a refused package whose filename did not end in .deb/.ddeb survived cleanup (release.pkg reproduced it). | **Fixed in `2dabbff` and `96e7e43` (merged in `d1cab93`); reopened by R01–R04 of the final review and replaced in `a65dca3` (merged in `23b8f52`), which packages into a private staging directory instead (see the final review below).** As first fixed, cleanup recognized reported regular files by their Debian-package prefix or case-insensitive .deb/.ddeb suffix. Content-recognized packages are emptied, then unlinked; a permission failure permits unlinking only without another hard link. Extension-only candidates are unlinked without emptying. Nothing else is deleted. Symbolic links are named, not followed; unreadable or undeletable candidates are reported and do not stop other cleanup. |
| Low — Q02: the manager docs universally attributed one Anthropic header to SDKs, contradicting the dated ADR survey. | **Fixed in `70ad512`:** describe ANTHROPIC_API_KEY and the preset's two accepted headers; leave competing AUTH_TOKEN unset; no universal SDK precedence/header claim. |

Q01 follow-up (2026-11-03): the two fix commit messages report 24 mutation
checks, all caught (22 in `2dabbff`, two in `96e7e43`). These are attributed
results, not a new mutation run by this documentation task. The separate
Claude subagent verification was interrupted by a usage limit and did not
complete; the final review of the whole implementation is still to come.

Two explicit decisions were accepted. For P05 the agent need not execute
`--check` on every start: a trusted helper with an empty environment selects
production settings even when built for tests; doctor, compile-error and
packaging checks are independent defences, not a sandbox for a tampered
binary. For unlock, cancellation **before** fingerprint comparison keeps the
old fingerprint and grants under their continue policy; once comparison has
decided revocation, a later lock cannot undo it. Revoking at every
authenticated read would be stricter, but was not required for readiness.

Optional follow-ups: synchronization hooks for real-component P03/P04
interleavings and retaining the empty-environment regressions in both feature
sets (already exercised separately). Neither changes the verdict.

Codex ran 182 passing test executions on an isolated git-archive export: 34
registry unit tests, two agent units, 34 broker units, 71 feature-enabled and
26 feature-disabled broker integration tests, 14 packaging tests (excluding
maintainer-script tests), and the KeePassXC round trip; diff whitespace check
passed. It did not run system.rs/full agent tests, GTK, MSRV, clippy, docs or
a full package build in that review: it had interpreted the earlier /proc
restriction as excluding product ancestry reads. The maintainer's agent
separately reported all AGENTS.md checks passing at `38ef1f0`; that report is
attributed, not presented as Codex's execution. The current documentation task
explicitly permits the normal test suites. The phase remains unreleased; live
Claude Code/SDK validation is pending (since done on 2026-11-04; see the
manual tests below).


**2026-11-03 — Documentation checkpoint at `70ad512` (uncommitted).**

Review (Codex subagents, AI-assisted, 2026-11-03), requested as AGENTS.md's
independent checkpoint for this documentation update. Read-only checks against
code and the supplied reports found documentation inaccuracies; the following
are corrected in this patch, with no runtime changes.

| Finding | Disposition |
|---|---|
| Documentation — revoke_grant was included among requests whose lost replies imply outcome_unknown. | **Fixed (docs):** protocol.md follows Request::has_effects: revocation is repeatable, a lost reply is a regular error, not proof of completion. |
| Documentation — package cleanup was described as complete before Q01 merged. | **Fixed (docs):** the initial draft qualified the remaining output-name gap. After Q01 merged, architecture, changelog and ADRs were updated to the exact cleanup rules in `2dabbff` and `96e7e43` (merged in `d1cab93`), as was the Q01 disposition above. |
| Documentation — ADR audit fields named a separate method field. | **Fixed (docs):** the method is part of the route template, as AuditEvent stores it. |
| Documentation — response limit could be read as bounding the expanded redacted body. | **Fixed (docs):** 64 MiB bounds upstream bytes before replacement. |
| Documentation — fingerprint thread creation omitted its fallback. | **Fixed (docs):** caller-thread fallback is stated; no stronger hash guarantee added. |
| Documentation — registry retention was conflated with listener retention. | **Fixed (docs):** broker exit can remove the registry entry before run cleanup, while the run still holds its listener. |
| Documentation — unredacted execution always “gave the terminal”. | **Fixed (docs):** it passes the requester's descriptors, which may instead be pipes or files. |
| Documentation — any short sendmsg was said to fail Install. | **Fixed (docs):** write_all can finish a short send; incomplete/non-blocking failure is what fails closed. |
| Documentation — a heading anchor did not match its title. | **Fixed (docs):** the dated implementation-amendments heading and link agree. |
| Documentation — README promised universal redaction, descendant termination and exit auditing. | **Fixed (docs):** default-only literal filtering, process-group limitation, best-effort completion records and suspend timing limits. |
| Low — guide said bodies were not read. | **Fixed (docs):** bodies are read/buffered but not semantically inspected. |
| Low — roadmap said one broker per entry. | **Fixed (docs):** one per grant; concurrent runs of one entry have separate grants. |
| Low — README still called manager M1 unreviewed. | **Fixed (docs):** status matches the recorded reviews and roadmap. |
| Low — deleting an entry was said not to revoke anything. | **Fixed (docs):** it does revoke its grants, but not the provider's source credential. |
| Low — B01's five mutations appeared to exclude the S3 lifetime check. | **Fixed (history):** five for the whole 623589c commit, including S3. |
| Documentation — piece F's aggregate did not match its detailed mutation list. | **Documented:** summary 11/10 versus ten named variants/nine caught; no extra result inferred. Piece C's analogous discrepancy is also explicit above. |

Checks for this documentation task: `cargo fmt --all --check`,
`cargo test --all-features` (551 passed, two opt-in tests ignored),
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`, manager clippy with warnings
denied and `cargo test -p rusthorse-manager` (38 passed, private virtual
display). After the final prose changes, the four CLI guide tests, the
manager's guide/snippet test and all 18 packaging tests passed again;
`git diff --check` passed. No dependencies or services were installed or
changed. Live SDK checks, hosted CI, full packaging and the optional
KeePassXC/KDF runs were not repeated for this documentation-only change.


**2026-11-03 — Documentation revision at `d1cab93` (uncommitted).**

Review (the maintainer's agent, AI-assisted, 2026-11-03), requested to check
that the phase 1 draft retained true, reviewed guarantees as well as adding
its limits. Codex made these corrections at the maintainer's request; Q01's
merged code and commit messages supplied its final disposition. This is a
documentation revision, not the pending final implementation review.

| Finding | Disposition |
|---|---|
| Documentation — item 1: scope replaced the accidental-exposure guarantee with caveats. | **Fixed (docs):** restore the reviewed guarantee in §1, then distinguish ordinary, broker and mixed bindings and hostile approved commands. |
| Documentation — item 2: P3/P5/P8/P9/P10/P12 lost existing guarantees. | **Fixed (docs):** restore their reviewed mechanisms, adding grant preparation, token filtering, HTTP authentication, automatic-lock policy, broker hardening and admission auditing beside them. P3 distinguishes ordinary value delivery from broker preparation. |
| Documentation — item 3: README weakened the security, approval and audit statements. | **Fixed (docs):** restore the positive guarantees and isolation/trust explanation; add capability, literal-redaction, process-group, completion-record and suspend limits where they apply. |
| Documentation — item 4: the AI guide addressed the maintainer and lost its protection list. | **Fixed (docs):** address the human reader, restore the protection list and hostile-agent explanation, keep mode-specific caveats, and show request and output directions separately. |
| Documentation — item 5: roadmap removed still-planned connectors, reasons and prior art. | **Fixed (docs):** restore Why, Design, Connectors, Secretless Broker and Limits; distinguish completed HTTP phase 1 from later device, SSH, database and signed-request work. |
| Documentation — item 6: invariant 1 narrowed ownership to broker credentials. | **Fixed (docs):** AGENTS.md and CONTRIBUTING.md cover all vault secrets, with the one-grant handoff, ordinary-run delivery and unchanged client exceptions. |
| Documentation — item 7: new prose had overlong and uneven lines. | **Fixed (docs):** reflow changed prose across the 14-file draft, preserving code spans, links, tables and examples. |
| Documentation — item 8: Q01's integration was still pending in the draft. | **Fixed (docs):** record `2dabbff` and `96e7e43` (merged in `d1cab93`), exact content-versus-extension cleanup and all 24 reported mutation checks caught. The interrupted independent verification and pending final review remain explicit. |
| Documentation — item 9: CLI grant capacity was explained in registry/listener terms. | **Fixed (docs):** explain that revocation may not free a place while its command runs; list grants and wait for commands to finish. Broker exit can remove a revoked grant sooner. |
| Documentation — item 10: CHANGELOG's approval, auditing and redaction claims needed checking. | **Confirmed and clarified:** broker approvals have no remembering key and cannot be remembered; the agent durably records admission before authorizing forwarding; response bodies lose literal copies of the credential and credential-bearing headers are dropped. |
| Documentation — reread: protocol.md still said any short Install send failed. | **Fixed (docs):** a partial sendmsg can be completed by write_all; failure to complete the non-blocking send fails preparation closed. |
| Documentation — reread: two true component/caller statements were omitted. | **Fixed (docs):** architecture again says only the agent decrypts the vault and that helpers are optional; README again states that the caller receives the result, never the secret, beside the mode-specific limits. |

Checks for this revision at `d1cab93`: `cargo fmt --all --check`,
`cargo test --all-features` (553 passed; two opt-in tests ignored),
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`, and
`cargo test -p rusthorse-manager` (38 passed; private virtual displays).
The all-feature run was repeated with a temporary log because the tool had
truncated its first output; the complete second output was read. Cargo used
four build jobs and offline mode; the tests inherited no session environment
beyond HOME and PATH. All 42 actual commit references in this history resolve
with `git show --stat`; example UUID fragments and numeric IPv4 spellings
are not commit references. Changed prose fits 78 columns except indivisible
links, tables and examples; `git diff --check` passed. No runtime code,
dependency, installed package or service was changed, and nothing was
committed. Live SDK validation and the final implementation review remain
separate pending work (both since done: the reviews and the manual tests of
2026-11-04, below).

**2026-11-03 — Final phase 1 review at `c599800`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: not ready), requested by
the maintainer to verify Q01's fixes in `2dabbff` and `96e7e43` (merged in
`d1cab93`) independently, confirm Q02 in `70ad512`, and check the
documentation in `c599800` against the code and the review records. The
reviewed range was `38ef1f0..c599800`; no repository file was changed.

Q02 is confirmed resolved: the documentation names the Anthropic key
variable and both accepted token headers without asserting which header
the SDKs choose or which variable they prefer. Q01's cleanup worked for
packages with other extensions and for a debug-symbol package, but the
cases below reopened it. No other material discrepancy was found in the
changed documentation; the history's 42 commit references resolved.

| Finding | Disposition |
|---|---|
| Medium — R01: the cleanup classified, emptied and unlinked a file through separate operations on its name. A package replaced by a hard link to another file after the read open had that file emptied, and an installable alias of the package survived without a warning; a file swapped in before the unlink was deleted; a FIFO swapped in after the lstat blocked the cleanup. | **Fixed in `a65dca3` (merged in `23b8f52`):** cargo-deb no longer writes where the user asked. `build-deb.sh` takes `--output DIR` itself and has cargo-deb write into a new private staging directory (mode 0700) inside `target/release/packaging`; `check-broker.py --staged` checks every entry there, refusing anything that is not a regular file without opening it, and only when all pass moves the packages into DIR, by a rename or, between file systems, a new `O_EXCL` file renamed over the final name, so that a file or link at that name is replaced, never followed or written through. Whatever stops the check removes the staging directory whole. Nothing outside it is classified, emptied or deleted. |
| Low — R02: the package prefix also matched an ar archive whose first member is `debian-binary.o`, which was deleted although dpkg-deb refuses it. | **Fixed in `a65dca3`:** no file is taken for a package by its first bytes any more; everything in the staging directory belongs to the run, and nothing else is deleted. |
| Low — R03: a read error on a `.deb`/`.ddeb` took the name-only path, unlinking it without emptying it, so another hard link kept an installable package, unreported. | **Fixed in `a65dca3`:** a refused package never leaves the staging directory, and removing that directory leaves nothing in DIR. |
| Low — R04: the package list was split on newlines, but cargo-deb accepts a newline in its output name: a refused `line\nname.pkg` survived and the cleanup said "deleted nothing". | **Fixed in `a65dca3`:** the staging directory is listed with `os.scandir`, never parsed from cargo-deb's output; a name with a newline is moved or removed whole (tested). |
| Low — found while fixing R01: with `--manifest-path` to another manifest whose package name holds `../`, cargo-deb 3.8.0 wrote the package outside the staging directory, where no check would see it (reproduced). | **Fixed in `a65dca3`:** `build-deb.sh` refuses `--manifest-path`, as it refuses `--target`. |

The fix was implemented by a Claude subagent (AI-assisted) and was not
separately verified by another; Codex's re-review of it follows. Its
mutation checks: 33 mutations of the guards, each caught by the 24
packaging tests; two survived: removing the `fsync` of a copy between file
systems, recorded here at first as harmless (durability across a crash,
which no test can observe) — the re-review below showed it also loses the
detection of a write that fails late, and a test now catches it (S01) —
and copying on any rename error rather than only `EXDEV`, harmless by
design (the copy also writes only a new `O_EXCL` file and renames it over
the final name, and removes it if that fails). Residual assumptions, stated
in §4 and ADR 0010: no other process of the user changes the private
staging directory between the check and the move; a `SIGKILL` leaves the
staging directory until the next run, which removes
`target/release/packaging` (and, during a copy between file systems, a
hidden `.check-broker-*.tmp` in DIR); two runs at once on one target
directory are not supported.

Checks after the merge (`23b8f52`), whole output read: every check of
AGENTS.md passed — fmt; clippy with all features and as released; `cargo
test --all-features` and `--no-default-features` (packaging 24, system 35,
`tests/agent.rs` 158 and 139); rustdoc with warnings denied; MSRV 1.89 both
ways; the dialog's and the manager's clippy and tests; the KeePassXC round
trip.

**2026-11-03 — Re-review of private staging at `72494de`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer to verify the staging design in `a65dca3` (merged in `23b8f52`)
and its history in `72494de`. The reviewed range was `c599800..72494de`. No
medium or higher finding remained.

R01–R04 are confirmed resolved: cargo-deb writes into a fresh private
staging directory, every package is checked before it is published, and
publishing replaces directory entries without following a link at the
final name. The cleanup no longer classifies or empties files outside the
staging directory, and listing that directory keeps names that hold a
newline whole. The `--manifest-path` escape was reproduced with cargo-deb
3.8.0, and both forms of the script's refusal were confirmed.

| Finding | Disposition |
|---|---|
| Low — S01: the surviving mutation that removes the `fsync` was justified only as durability across a crash, which no test can observe. Without the `fsync` a write that fails late also goes unnoticed: with an injected `EIO`, the current code refused the copy, while the mutation published the package. | **Fixed in `1eb2e3b`:** a test runs `check-broker.py --staged` with an `fsync` that fails, copying to another file system: nothing is published, the file already at the package's name is unchanged, the copy's new file and the staging directory are deleted. Without the `fsync` the test fails (mutation check on a copy with its own target directory). The final review's section above now says so. |

The other surviving mutation, copying after any rename error and not only
`EXDEV`, keeps the check before publication and the publication without
following links under the stated assumptions, although it is not
behaviourally identical; the code falls back to a copy only on `EXDEV`.

A `SIGTERM` sent to `check-broker.py` during a copy between file systems
left a hidden, partial `.check-broker-*.tmp` in DIR; the script's traps
removed the staging directory and no package was published. So an abrupt
end of the helper, not only a `SIGKILL`, can leave that file of a checked
copy, as the helper's documentation says of an interrupted copy.

Codex's checks: the 24 packaging tests in an isolated export; probes with
the real cargo-deb 3.8.0 and dpkg-deb 1.22.6 (another manifest, version
overrides with path separators, a repeated `--output`, names with a
newline, accepted and refused runs, links and files in DIR left as they
were); the injected `EIO` against the mutation; the copy fallback after
`EPERM`; `git diff --check`. The maintainer's agent then ran the 25
packaging tests, clippy and the MSRV check on `1eb2e3b`.

**2026-11-03 — Test hygiene and behaviour under load at `1001e1e`.**

The maintainer asked for the old tests that left files behind to be fixed.
The maintainer's agent ran the end-to-end suite in four parallel copies next
to eight CPU burners, each copy with a `TMPDIR` of its own, and then every
test binary alone in a `TMPDIR` of its own. Every loaded run of the suite
left directories behind, and 7 of 56 failed. Five problems were found, all
in the tests: T01–T04 were fixed in `a0594f4` and T05 in `1001e1e`.

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer to verify those fixes: whether they prevent late writes and
load-dependent failures without hiding a product defect or weakening the
intended checks. The reviewed range was `7e8d602..1001e1e`. No medium or
higher finding, or product defect behind the reported failures, was
identified.

| Finding | Disposition |
|---|---|
| T01 — Tests returned before the agent recorded a disconnected run's end, allowing the audit log to recreate the removed temporary directory. | **Fixed in `a0594f4` for the reported cases:** `wait_for_run_end` shares three existing waits and is added to nine further tests. The prior process and cancellation assertions remain. Removing the `exited` outcome makes all 13 callers, including T04, fail. Other asynchronous records still needed synchronization: U02 and U03 below. |
| T02 — An immediate port check could observe a descriptor inherited by another test's child between fork and exec. | **Partly fixed in `a0594f4`:** two checks retry for up to five seconds; both still fail with a leaked listener. Source review confirms `RunGrants::stop` clears its listeners before the run answers. A third immediate check remained: U01 below. |
| T03 — The watcher-stop test required less than three seconds although shutdown deliberately waits up to three seconds for its threads. | **Fixed in `a0594f4`:** the assertion allows five seconds, matching the companion test's scheduling margin, and still checks the inhibitor's release. An injected six-second delay is rejected. This no longer detects a regression that merely makes every stop consume the allowed three-second wait; it does not establish that normal stops are prompt. |
| T04 — A requester-disconnection test inspected the run outcome after the grants disappeared but before `run/exited` was recorded. | **Fixed in `a0594f4`:** it waits for the run's end record before inspecting that outcome, retaining its revocation-order and broker-exit assertions. |
| T05 — GTK widget tests activated desktop services that outlived them, and Xvfb could write Mesa's cache after cleanup. | **Fixed in `1001e1e`:** the tests use private D-Bus sessions without service activation, disable GVfs, the settings portal and Mesa's shader cache, and use GTK's test accessibility backend. Accessible properties and relations, clipboard access through xclip and dialog assertions remain checked. The dialog skips with a diagnostic when required tools are absent; the manager requires them. CI installs dbus-daemon, which supplies dbus-run-session. |
| Low — U01: the successful broker-run test still checked port release with an immediate bind. | **Fixed in `a3d66b0`:** it uses `port_released`, and keeps the broker-exit assertion. |
| Low — U02: some tests inspected grant-end records or removed their directory before asynchronous grant auditing finished; one also required an unnecessary global created/ended alternation across grants. | **Fixed in `a3d66b0`:** the tests wait for each grant's end record by ID and check the order per grant. Where the audit log is a FIFO that fails every record, they wait until the end record has been written into it before they put the log back, without requiring a successful record. The same probe found a fourth test that returned before a grant's end record. |
| Low — U03: the read-only polling test returned when status became locked, before the idle-lock audit record necessarily finished. | **Fixed in `a3d66b0`:** it waits for `lock/idle_timeout` before it returns. |

Codex's checks used an isolated export with its own target directory and
short TMPDIRs. Four concurrent runs of the 158 agent tests, alongside eight
CPU burners, passed and left their TMPDIRs empty. The dialog's four unit
tests and five Xvfb tests, and the manager's 38 tests, passed without
residue. A direct activation request on the private test bus returned
ServiceUnknown.

Independent mutation checks reproduced all three reported detections:
13 failures without `exited`, two failures with a leaked listener, and
one failure with a six-second watcher-stop delay. Scheduling probes with
500 ms pauses before grant-end and idle-lock records exposed U02/U03:
two tests failed and six temporary directories were recreated. A narrower
probe also confirmed residue from tests that passed. These probes changed
only the temporary copy.

The maintainer's supplied results additionally record 32 successful loaded
runs and the complete AGENTS.md checks. Those complete checks were not
repeated by Codex. The range's diff check and formatting check passed.
No repository file was changed by this review.

The maintainer's agent then fixed U01–U03 in `a3d66b0` and checked the
fix with the same probe, in a copy with its own target directory: with
the pauses, each run of the suite had failed two tests and left six
directories; after the fix, two runs passed and left nothing. Without the
agent's grant end records, the six tests that now wait for them fail,
each with its message; without the idle lock's record, the polling test
fails. Twelve loaded runs (four copies next to eight CPU burners) passed
with nothing left; formatting, both clippy runs, the end-to-end tests
without default features and the MSRV checks passed.

**2026-11-04 — Confirmation of the test fixes at `897700e`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of `a3d66b0` and
of the history entry above, in `897700e`. U01–U03 were confirmed resolved:
a retained listener fails the port check; replacing the `grant/ended`
outcome fails the six tests that wait for it, and replacing
`lock/idle_timeout` fails the polling test. `BlockedAudit::wait_for_end_of`
needs a complete record of that grant read from the FIFO, so it does not
pass on the broker's confirmation alone; a missing record makes it fail
after its time limit instead of hanging, and making the FIFO's reader
non-blocking does not affect the agent's own opening of the FIFO. The
history entry was found accurate. No product defect was found.

| Finding | Disposition |
|---|---|
| Low — V01: `admissions_are_recorded_before_the_broker_forwards_anything` read the records of the grant's requests before waiting for the grant's end. The second request is refused without the agent's audit thread, so the first one's `completed` record can come after the run's answer: a 500 ms pause before it left the test with only `admitted`, and the late records recreated its directory. Found by extending the probe to the records of requests' ends and of automatic locks. | **Fixed in `8726b17`:** it waits for the grant's end record first, which the same thread writes after the records of the grant's requests. |
| Low — V02 (from a note of the review's): `the_run_dialog_shows_destination_settings_without_credentials` shows the test's own environment, directory and process chain, and with a 41-character TMPDIR zenity's height estimate of its dialog was 889 pixels, over the 880-pixel limit, so the agent refused the request (as it must) and the test failed. | **Fixed in `8726b17`:** the test, which is about what the dialog shows, uses a dialog that scrolls, as `rusthorse-dialog`'s does; the height limit keeps tests of its own. |

Codex's checks: an isolated export; the 158 end-to-end tests without
pauses, with the earlier pauses and with the extended probe (with V01's
fix applied in its copy); the mutations above; a probe of the FIFO's
behaviour; formatting and `git diff --check`. The maintainer's agent then
checked `8726b17`: with pauses before the records of a grant's end, a
request's end, the idle lock and an automatic lock, two runs passed and
left nothing; with TMPDIRs of 19, 41 and 75 characters, and three more
shell levels in the process chain, the suite passed; eight loaded runs
passed with nothing left; both clippy runs, the end-to-end tests without
default features and the MSRV checks passed.

**2026-11-04 — A key the destination refused, and the manual test so far.**

The maintainer's first manual test with a real key (ADR 0013, answer 9)
found four things. First, the key stored in the entry was one the
destination did not accept: `run --broker` passed on its `401`
(`authentication_error`, `invalid x-api-key`), which reads as the token's
fault, and only the audit log's `status 401` said otherwise. Second, Claude
Code's requests went through the broker, and the API answered two
`POST /v1/messages` with `400` "credit balance is too low"; after
`rusthorse grants revoke --all`, Claude Code showed
`Please run /login · API Error: 403 the grant has ended`. Third, after a
change of the entry's value, the manager's message named the entry's UUID.
Fourth, at the maintainer's request and with the maintainer's approval of
each run, the maintainer's agent compared the Anthropic Python SDK 2.4.0
with the key by value and through the broker. With Sonnet 5.5 — create with
`max_tokens` 200, streaming with 200 and 32000 — the answers, usage and
rate-limit values matched, with similar times, and the broker relayed 16–17
of the API's 29–30 response headers, as its list allows. Separate scripts
sent Haiku 5.5 streaming requests with a minimal input: plain ones worked
both ways; with some of Claude Code 2.1.317's parameters (its betas,
adaptive thinking, context management, effort) they drew the same `400`
both ways, and with this key the beta `claude-code-20250219` alone drew it.
These were not full reproductions of Claude Code's requests. So the tested
Python SDK requests work through the broker, and Claude Code's own requests
reach the API through it, but no answer from Claude Code through the
broker has been seen yet.

`0060692` names the entry in an edit's answer (its title, or the new name
after a rename). `cf28a7c` counts per grant the requests whose destination
answered `401`, once the report matches an open request; reports the count
in `grants`, and in `exited` once the run's grants are gone, from which
`rusthorse run` prints a note after the command with its status unchanged;
adds the manager's **Key refused** fact; and starts the message of the JSON
errors the broker writes with `rusthorse-broker:`, that of a grant that has
ended saying to run the command again. The feedback comes from the status
alone, never from a provider's body, so it is the same for every
destination.

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `0060692`
and `cf28a7c` against `47cd529`. No defect was found in the count: two
grants kept separate counts, the report of a command that ended at once
after its last request stayed complete with a 500 ms pause before the audit
thread's records, and the broker's own `401` was never counted.

| Finding | Disposition |
|---|---|
| Medium — W01: since `0060692`, an edit's answer names the entry by the title stored in the vault, which another KeePass program can write with terminal controls in it, and the CLI printed the agent's messages as they came: editing by UUID an entry titled `SAFE\u{1b}[2J\rFORGED` sent ESC and CR to the terminal. | **Fixed in `59735de`:** the CLI escapes the messages of the agent's answers and errors, a run's errors and an import's per-batch results, as it already escaped the grants; the vault keeps the title as it is. Tested with such a title written into the file, then edited and removed by UUID, and with a fake agent's answer, error and run error; without the escaping, both tests fail. `1ec2af1` and `6cb4f53` escaped the rest of what the CLI shows from the vault, the agent or a keyring (X01, Y01 and Y02, below). |
| Low — W02: the command the note suggests, `rusthorse edit NAME --value`, reads a name that starts with `-` as an option (for `--help`, it shows the help). | **Fixed in `59735de`:** for such a name the note suggests `rusthorse edit --value -- NAME`; a test parses the suggested command for `KEY`, a name the shell would split, `-k` and `--help`, and fails without the fix. |
| Low — W03: the CLI's documentation and the guide said that every error without the broker's prefix comes from the destination, but the broker's HTTP parser answers a malformed request itself, with `400` or `431` and an empty body, and a connection can close with no answer. | **Partly fixed in `59735de`:** `docs/cli.md`, the guide, `docs/ai-agents.md`, the ADR's amendment and the CHANGELOG limit the prefix to the JSON errors the broker writes, and name these exceptions; but the guide then said that every empty `400` or `431` is the broker's, which a destination can send too. Completed in `1ec2af1` (X02, below). |

Codex's checks: an isolated export with offline builds and fake
credentials; targeted tests of the destination's and the broker's `401`, a
grant's removal, duplicate or invalid end reports, the protocol's defaults
and omissions, the CLI's statuses and output, the broker's messages, and
the manager's model and widgets on their own Xvfb display; probes of two
grants and of a command that ends at once, with a 500 ms pause before the
audit thread's records; formatting and `git diff --check`. The maintainer's
agent had checked `cf28a7c` with all of AGENTS.md's checks and with twelve
mutations, each failing a test — no count, every status counted, a
violation counted, the count made late by the audit thread, no listing, no
run note, a note on an unknown outcome, the agent's identity for the typed
name, no grants note, the edit's answer echoing the request's name, no
prefix, no hint — and three of the manager's (a fact that always says *No*,
the warning never added, never removed); then `59735de` with all of the checks
again and the mutations of W01 and W02, each failing its test.

**2026-11-04 — Confirmation of the fixes at `7397634`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `59735de`
and of the history above, in `7397634`. W01 and W02 were confirmed
resolved: the agent's messages are escaped, the title stays as stored, and
the suggested command parses as an edit of the named entry for `-k` and
`--help`; reverting either fix fails its tests. W03 was confirmed partly
resolved (X02).

| Finding | Disposition |
|---|---|
| Medium — X01, older than this work: `list` and `show` printed what the vault holds as it came, so a title or a username another KeePass program wrote with terminal controls reached the terminal: the review's probe with the title `SAFE\u{1b}[2J\rFORGED\u{202e}` sent ESC and CR to the standard output of both. The import preview and the text of `status` did the same with what a keyring or the agent supplies. | **Partly fixed in `1ec2af1`:** `list` and `show` (before a table's widths are measured), `status`, `doctor`'s lines, the import preview and the CLI's own errors (names given twice in a keyring import, for one) have their control and invisible characters escaped; `--json` gives the values as they are, and what `reveal` prints and a command's output are not touched. Tested with a title and a username written into the file (`list`, `show`, and `show --json` as stored), a status with controls in its vault, dialogs and program, keyring names in a dry run and in the error that refuses names given twice, and `doctor`'s lines; without the escaping in any one of these places, a test fails. `open`'s notice and an import's transport and decoding errors were completed in `6cb4f53` (Y01, Y02, below). |
| Low — X02: the guide said that an empty `400` or `431` is the broker's answer to a malformed request; the review's probe had a destination send both, relayed by the real broker with one admission and its status in the request's end, besides the broker's own empty `400` with no admission. | **Fixed in `1ec2af1`:** the guide says that the broker's HTTP parser can answer that way and that a destination can too, so such an answer alone does not tell who answered; `docs/cli.md` says the same. |
| Low — X03: the documents said that the account refused "the same requests" of Claude Code with the key by value, and grouped the Sonnet and Haiku comparisons. Claude Code's own requests went through the broker only; the comparisons both ways were SDK requests: create and streaming to Sonnet 5.5, and streaming to Haiku 5.5 with a minimal input, plain or with some of Claude Code's parameters. | **Fixed in `1ec2af1`:** answer 9 of ADR 0013 and its amendment, `docs/cli.md`, the guide, `docs/ai-agents.md`, the roadmap, the threat model and the CHANGELOG say what was tried, and the fourth paragraph of the entry above was reworded the same way. |

Codex's checks: the diff and the commit messages; the escaping tests, the
binary's tests (the suggested command, the guide), the edit test; its own
probes of a title written elsewhere (edit escaped, title kept; `list` and
`show` raw, X01), of an import's success, error, denial and unknown result
and of an unknown error of `run` (escaped, statuses `0`, `1`, `4` and
`124` kept), and of empty `400` and `431` answers from the broker and from
a destination (X02); the reverted escape and `--` form, each failing its
tests; formatting and `git diff --check`. It did not rerun the comparison
scripts, which need the maintainer's key and dialogs. The maintainer's
agent then checked `1ec2af1` with all of AGENTS.md's checks, and with six
mutations — no escaping in `list`, `show`, `status`, the import preview,
the main error printer or `doctor`'s lines — each failing a test.

**2026-11-04 — Confirmation of the fixes at `2de6b34`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `1ec2af1`
and of the history above, in `2de6b34`. X02 and X03 were confirmed
resolved: the documents no longer tell who answered by an empty `400` or
`431`, and they keep the SDK comparisons apart from Claude Code's own
requests. X01 was confirmed partly resolved: the review's probe found
titles, usernames and URLs escaped in `list` and `show`, the values kept
in `--json`, and nothing else in the grants table, the `401` note,
`reveal` or a command's output changed; but two paths, older than this
work, still printed supplied text as it came. Help, completions and the
prompts quote nothing from the vault; the messages that create the vault
or start the agent name paths of the local configuration.

| Finding | Disposition |
|---|---|
| Medium — Y01: `open` printed `Opening URL` with the URL from the vault as it came, so a URL another KeePass program wrote, such as `https://example.invalid/\u{1b}[2J\rFORGED`, sent ESC and CR to the terminal after passing the check of its scheme. | **Fixed in `6cb4f53`:** the notice shows the URL escaped, and the browser gets the URL as stored. Tested with such a URL written into the file and a stand-in for `xdg-open` that records what it is given; without the escaping, the test fails. |
| Low — Y02: an import's transport and decoding errors printed the error as it came, which quotes an answer the client could not read: an answer of an unknown type holding ESC and CR reached the terminal, though the exit status was rightly `124`. | **Fixed in `6cb4f53`:** both arms escape the error, with exit statuses `124` and `1` unchanged. Tested with a scripted agent whose `import_from` answer has such a type; without the escaping, the test fails. |

Codex's checks: the diff, the commits and the history; the escaping tests
(the fake keyring's included), the binary's tests, the CLI tests of the
broker (statuses, grants, notes) and `open`'s test; its own probes of the
metadata and of the output contracts (`--json`, `reveal`, a command's
output), of `open` with a stand-in browser (Y01) and of an import answer
that cannot be read (Y02), both of which passed with the fix applied in
its copy; formatting and `git diff --check`. The maintainer's agent then
checked `6cb4f53` with all of AGENTS.md's checks, and reverting either fix
failed its test.

**2026-11-04 — Confirmation of the fixes at `7a0f7be`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of `6cb4f53` and
of the history above, in `7a0f7be`. Y01 and Y02 were confirmed resolved:
`open`'s notice is escaped and a stand-in browser gets the stored URL; an
import's errors are escaped, with `124` for an answer that cannot be read
after the request was sent and `1` for a failure before it. A sweep of
every place where `src/main.rs`, and what it calls, prints — `list`,
`show`, `status`, `doctor`, `grants`, the audit log, imports, answers,
errors, help and prompts — found no other text from the vault, the agent
or a keyring shown unescaped; the messages that create the vault or start
the agent print paths of the local configuration. `--json`, `reveal`, a
command's output and the URL given to the browser keep the values as they
are. The history entries above were found consistent with the commits.

| Finding | Disposition |
|---|---|
| Low — Z01: the stand-in for `xdg-open` in `open_shows_a_url_written_elsewhere_escaped` wrote to a path it did not quote, so with a TMPDIR holding a space the script failed (`xdg-open failed (exit status: 2)`) though the product was right; `open_hands_only_http_links_to_the_browser`, older, had the same script. | **Fixed in `e5de2c2`:** both scripts quote the path (`util::shell_quote`). With a TMPDIR holding a space, both tests failed before and pass after; with an ordinary one, they pass. |

Codex's checks: the escaping tests (six), the binary's tests, the CLI
tests of the broker and the tests of an import's batches; its own probes
of the output and its contracts and of both of an import's errors; the
mutations that remove Y01's and Y02's fixes, each caught; the `open` test
with a TMPDIR holding a space (Z01); formatting and `git diff --check`.
The maintainer's agent then checked `e5de2c2` with all of AGENTS.md's checks.

**2026-11-04 — The product's scope at `4f9fe79`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `4f9fe79`,
which stated the product's scope after phase 1's manual test and dropped
the broker's later phases (documents only). Before the review ended, the
maintainer defined the product more precisely — the only secret is a
credential's value, the agent says where it uses it, the human approves —
and `b91fc92` and `8eab1d3` rewrote several of the passages reviewed
(ADR 0013 now specifies a broker without profiles or presets); the
findings were fixed on those documents.

| Finding | Disposition |
|---|---|
| Medium — S01: "Rusthorse controls who uses a credential, when, for how long and how often, and records each use" was stronger than ordinary `run`, which gives the approved command the value: Rusthorse approves and records the run but cannot limit or count what the command does with the value, and a later lock does not stop it; limits of time and requests, revocation and per-request records belong to broker grants, and the requester's process chain is not verified. | **Fixed in `85fb56f`:** the README, AGENTS.md, `docs/ai-agents.md` and ADR 0013's scope amendment say what each mode does: the approval decides which command uses a credential and is recorded; with `run` the command has the value while it runs; through the broker it has a token limited in time and requests, revocable and recorded request by request; the process chain is shown, not verified. |
| Low — S02: dropped plans still read as future work: ADR 0005's typed operations and SSH agent, ADR 0013's WebSocket, Unix socket listener, phase 3's `ssh-agent` and sandboxed clients, the roadmap's Unix socket, and an entry of the manager guide's "Comes later" column. | **Fixed in `85fb56f`:** each is marked as superseded (not planned) or moved out of the column. |
| Low — S03: the roadmap and ADR 0013 said the dropped items could be proposed again on a concrete need, against AGENTS.md and CONTRIBUTING.md. | **Fixed in `85fb56f`:** both say they are outside the product's scope and not on the roadmap. |
| Low — S04: "any HTTP API" was stronger than a broker that presents the key in a request header: an API that signs its requests with the key, or takes it in the URL or the body, cannot use it. | **Fixed in `85fb56f`:** the roadmap, the README, the threat model and ADR 0013 limit it to APIs that take the key in a request header, and send the others to `run`. |

Codex's checks: the commit's diff, a search of the 106 tracked text files
(ADRs, the design prototype, the code, the tests and the guide), the code
that gives a value to a command, admits broker requests and identifies the
requester, `git diff --check`, and the summary of all of AGENTS.md's
checks on that tree. The maintainer's agent then checked `85fb56f`: the
documents only changed, the formatting check and the packaging tests (the
links of the packaged documents) passed.

**2026-11-04 — The design of the broker without profiles, at `dd81cc2`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `b91fc92`,
`8eab1d3`, `85fb56f` and `dd81cc2`: the maintainer's definition of the
product, the fixes of S01–S04, and the design that replaces phase 1's
profiles and presets (ADR 0013's scope amendment), before any code. S01–S04
were confirmed resolved. The findings concern the design and the documents;
none adds a control beyond what protects the key and the approval.

| Finding | Disposition |
|---|---|
| Medium — D01: a token-shaped HTTP method passes the inherited framing (a probe confirmed it), and the design would have recorded it; raw paths can carry data (as F19 found). | **Fixed in `9c0efd8`:** the token is refused in the method too, and an admitted request is recorded with its method's label only (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OTHER`), never a raw method, path, query, header or body. |
| Medium — D02: the design relayed the destination's `Content-Length`, which no longer matches a body that redaction changed (a probe showed the length change). | **Fixed in `9c0efd8`:** `Content-Length` and `Transfer-Encoding` are never relayed; the broker frames the body itself, chunked where HTTP allows a body. |
| Medium — D03: the dialog would show a base path as if it limited the requests, which go to any path of the origin. | **Fixed in `9c0efd8`:** the approval covers the whole origin; the base path only sets up the program's base URL; the dialog shows them apart and says that the key may be sent to any path at the origin. |
| Medium — D04: phase 1's framing allows a body only on `POST` (a probe confirmed a refused `PATCH`), an assumption about APIs. | **Fixed in `9c0efd8`:** a body is allowed on any accepted method, within the existing size, room, timeout and admission rules. |
| Low — D05: a token in a header the broker drops or rebuilds would have satisfied the check without the key reaching the destination; the replacement, duplicates and other grants' tokens were not specified. | **Partly fixed in `9c0efd8`:** only forwarded values count; the replacement is exact and in one pass; the forbidden places are refused; the header block's limit holds after the key is in; the value's 8–4096 visible ASCII rule stays. What a token-shaped string is, its case variants and every duplicate header value were left to E02 (below). |
| Medium — D06: per-entry policies (programs or hosts) were still planned in the roadmap and the threat model; ADR 0013 kept a stale mark and called them worth having; ADR 0008 said a stored endpoint could check a destination. | **Fixed in `9c0efd8`:** they are outside the scope and not planned; the marks are corrected; ADR 0008 says the endpoint is context and gives the broker no default. |
| Low — D07: the definition called notes context, but notes and the fields KeePass marks protected are withheld like the value. | **Fixed in `9c0efd8`:** the definition says that the URL, username, host, port and tags are context and that notes and protected fields stay withheld. |

Codex's checks: the diff and the 106 tracked text files; the design against
phase 1's framing, forwarding, validation, storage and protocol code; the
guide's tests; three probes in an isolated copy (a token-shaped method
accepted by the framing, a refused `PATCH` body, a length change after
redaction), which test phase 1, not a broker without profiles; `git diff
--check`. The maintainer's agent then ran all of AGENTS.md's checks on
`9c0efd8`; the code is unchanged.

**2026-11-04 — Confirmation of the broker design at `8089080`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `9c0efd8`
and its record in `8089080`. D01–D04, D06 and D07 were confirmed resolved
in the design; D05 partly. It checked, without finding a new defect, how
`--url` pairs with `VAR=ENTRY@URL`, several entries in one run, the same
entry twice, the run's limits, the phase 1 profile field and the error
contracts.

| Finding | Disposition |
|---|---|
| Medium — E01: adding the destination and the limits to protocol 8's `broker_run` would let an agent of protocol 8, met after the client's version check, accept the request and ignore them: a probe showed that its parser drops the new fields, and that it refuses an unknown request type. | **Fixed in `1c2923a`:** a run through the broker is a new request, `broker_run_v2`; agents of protocol 9 refuse `broker_run` and `broker_edit` before any approval; a client never retries a refused request as an older type or an ordinary `run`; a test must switch the agent's version between the client's two connections. |
| Low — E02 (completes D05): "a token-shaped string" had no grammar, and its case and the duplicate header values were not stated. | **Fixed in `1c2923a`:** `rh_` and 64 hexadecimal digits, in any ASCII case, at any byte position of the method, the target, the header names and every header value; each must equal the grant's token byte for byte, so a case variant is refused, not replaced; no other grant's token is looked up. |
| Low — E03: the design did not say what the manager's command for an entry becomes without a profile. | **Fixed in `1c2923a`:** two labelled templates, one giving the value (`run`), one through the broker with the destination and the variables left to fill in; nothing is inferred and nothing is stored. |
| Low — E04: listings, the manager and the `401` note showed the origin with the base path, as if the base path limited the requests. | **Fixed in `1c2923a`:** they show the approved origin; a base path is shown apart, as setup of the program's base URL; `GrantInfo` gets an optional `base_path` and loses `preset`. |

Codex's checks: the diff, the related code and the record; the 106 tracked
text files; `git diff --check`; two deserialisation probes and the guide's
tests in an isolated copy; the summary of all of AGENTS.md's checks. The
maintainer's agent then ran the packaging tests on `1c2923a`; the code is
unchanged.

**2026-11-04 — The implementation of the broker without profiles at
`9c069d4`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of the whole
implementation of the scope amendment against `broker-phase1`: the core
crate (`src/broker_grant.rs` in place of `src/broker_profile.rs`, client
protocol 9, control channel 2, the agent, the registry, the audit, the
vault, the CLI and the guide), the broker crate (`broker/src/token.rs`, the
header rules, the server and the exchange), the manager, the tests and the
documents, the removed lines of the documents included. The work commits
were then squashed into `93848a9`, whose tree is `9c069d4`'s.

| Finding | Disposition |
|---|---|
| Medium — G01: the broker dropped a fixed list of hop-by-hop headers from a response but relayed the headers its `Connection` names, which are hop-by-hop too (RFC 9110, section 7.6.1): a probe with `Connection: X-Hop` and `X-Hop: private-to-this-hop` saw `X-Hop` reach the client. | **Fixed in `1edafe7`:** the names in every `Connection` header of a response, whatever their case and spacing, are dropped with the other hop-by-hop headers; a unit test and the broker's test of relayed response headers cover them, and the latter fails without the fix (mutation on a copy with its own target directory). A client's `Connection` that names anything but `close` and `keep-alive` was already refused by the framing (`400`). |
| Low — G02: `broker_run_v2` refused unknown fields in its broker bindings and its limits, but not in its bindings by value: a binding there with a `destination` and a `max_requests` was read as a plain binding, and the entry would have been given by value, contrary to `docs/protocol.md`. | **Fixed in `1edafe7`:** `Binding` refuses unknown fields, in `run` too, before any dialog; the protocol's test and the agent's end-to-end test of refused requests cover it, and both fail without the fix (mutation). |

Codex's checks, in an isolated copy with its own target and temporary
directories: `cargo test --all-features` and `--no-default-features` of the
workspace (170 tests of the agent, 78 of the broker, 35 system tests), the
manager's and the dialog's tests, `cargo fmt --all --check`, `git diff
--check`, and two probes that reproduced G01 and G02; a mutation that
replaced only the first occurrence of the token was caught by the existing
tests. It found no other defect in the approved origin, `Host`, SNI and
port, the base path, the limits shown and installed, the one-pass
substitution and the refusals, admission and audit before forwarding,
protocols 9 and 2 and the refusal of the old requests, the CLI's refusal to
resend a request as another type, the phase 1 field, the manager's
templates, the guide and the documents.

The implementers' own checks before the review: the broker's agent killed
15 mutations of its rules (single-pass substitution, each refusal class,
response header filtering, the method label, bodies on any method); the
end-to-end tests' agent killed 5 (destinations and limits checked before the
dialog, no resend as another type, the phase 1 field kept, the origin and
the base path apart, no alias for `broker_run`), and ran `tests/agent.rs`
under load; the manager's agent killed 8. Noted by the broker's
implementer and recorded in L21: a token holder can learn the key's length
from the size limit; accepted, since the grant already lets them use the
key. Noted by the end-to-end tests' implementer, older than this work and
outside it: a vault that KeePassXC 2.7 saved as KDBX 4.0 cannot be saved by
Rusthorse again (`keepass` 0.17 writes KDBX 4.1 only), and the error does not
say so; left for the maintainer to decide.

**2026-11-04 — Confirmation of G01 and G02, `93848a9..0ec231b`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of `1edafe7` and
the record in `0ec231b`. G01 is resolved: every `Connection` header of a
response, its comma-separated members trimmed and compared without regard
to case, names headers that are dropped in every occurrence, at the only
place where response headers are relayed, bodiless responses included; the
framing refuses a client's `Connection` with any member but `close` and
`keep-alive`. G02 is resolved: `Binding` refuses unknown fields in
`broker_run_v2` and in `run`, and the CLI and the manager's templates send
only `var` and `entry`. `93848a9`'s tree is `9c069d4`'s; the record above and
the sentence added to L21 are accurate.

Codex's checks, offline in an isolated copy with its own target and
temporary directories: `cargo test --all-features` (170 tests of the agent,
78 of the broker, 35 system tests) and `--no-default-features` (150 and
29), the manager's 38 tests, `cargo fmt --all --check`, `git diff --check`;
and four mutations, each fix removed in turn, which failed the unit and
integration tests of G01 and the protocol and end-to-end tests of G02 by
their assertions.

**2026-11-04 — Saving a vault that KeePassXC wrote as KDBX 4.0, `935743b`.**

Noted by the end-to-end tests' implementer during the review of the broker
without profiles, and older than that work: KeePassXC 2.7 writes KDBX 4.0
when nothing in a file needs 4.1, and `keepass` 0.17 writes 4.1 only, so
every change to such a vault failed with an unexplained error. `935743b`
writes a 4.0 file back as 4.1 and refuses, saying why, to write a newer
KDBX 4; a fixture saved by `keepassxc-cli` 2.7.6 as 4.0 tests it, and both
mutations of the fix fail its tests.

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of the commit:
only 4.0 is promoted, and a newer minor version is refused before a
temporary file is made or the file or its `.bak` changes; the library reads
4.0 and 4.1 alike, and the fix changes only the version it writes. On the
fixture and on a sample with custom data, a protected field, history and
an attachment, under Argon2id and AES-KDF, the conversion kept the content
and the key derivation parameters, and KeePassXC 2.7.6 reopened the
results. The `.bak` stayed identical; the fingerprint after the save matched
the reopened file's; a save failed before the replacement left the file and
the fingerprint as they were, and the next one worked; a failed save still
locks the vault, and the error contract and the unlock barrier are
unchanged. Codex's checks, offline in an isolated copy: `cargo test
--all-features` and `--no-default-features`, the ignored KeePassXC test,
`cargo fmt --all --check`, `git diff --check`, a temporary probe, and the
two mutations, which failed by their assertions.

**2026-11-04 — Manual tests of the broker without profiles.**

Not a review: what was tried by hand, with a real key of the maintainer's,
through the broker without profiles (`93848a9`, `1edafe7`) at
`https://api.anthropic.com`, after the test of phase 1's broker recorded
above ("A key the destination refused, and the manual test so far"). From
2026-11-09 this history is the one place that holds the whole account; the
other documents state only what was tried last.

- **`curl`, by the maintainer** (recorded in `2e059c3`), the token in
  `x-api-key`: a `GET /v1/models` was answered `200`, and the audit recorded
  it with the method's label only; a `POST /v1/messages` was answered by
  Claude Haiku 5.5; a request with the token in its URL was refused by the
  broker itself, and nothing was sent.
- **The Anthropic Python SDK 2.4.0, by the maintainer's agent at the
  maintainer's request** (`a90f191`), the token in `ANTHROPIC_API_KEY` and
  the broker's address in `ANTHROPIC_BASE_URL`: a message and two streams
  were answered `200`, and the audit recorded three `POST` admissions by
  label only.
- **Claude Code 2.1.318 in print mode** (`claude -p`), by the maintainer's
  agent at the maintainer's request (`4e0caf1`), with a home directory of
  its own and so no login, the token in `ANTHROPIC_AUTH_TOKEN` and the
  broker's address in `ANTHROPIC_BASE_URL`: it answered, in one `POST` that
  the destination answered `200`.
- **Claude Code interactively, by the maintainer** (`72bf636`), with the
  guide's recipe: it worked. The `400` "credit balance is too low" that
  phase 1's test met, which the API gave to requests with Claude Code's
  beta whether or not they went through the broker, did not recur.

These are the requests that were tried, on one account and one day. No
client version is claimed supported, and the limits of L24 stand: a program
works through the broker only if it presents the token literally in a
request header.

**2026-11-05 — The manager's History page.**

Manager milestone item History (ADR 0007 section 4, amended on 2026-11-05
at the maintainer's choice): the manager reads the audit log directly, as
`rusthorse audit` does, at the path in `status.audit_log`. Any program of
the user can read that file (L13), so a new agent request would protect
nothing. The library's `audit::read_page` reads bounded pages from the end,
at most 256 KiB and 200 records each, complete lines only. The manager
shows them only while the vault is unlocked and clears them on Lock now
or an observed lock; that protects the screen, not the file. No protocol
change.

Before review, the implementer's own widget test found a double
`RefCell` borrow when a page read arrived: the job's mutable borrow lived
through the `if let` that showed the result. Taking the job into a local
first ends that borrow before the page is shown.

First review (Codex, AI-assisted, 2026-11-05; verdict: not ready) of the
uncommitted change found four defects:

| Finding | Disposition |
|---|---|
| **Medium — Truncation keeping the cursor's line went unnoticed.** Truncating the same file after that line let Load older combine records already removed with the remaining log, without reporting a change. | Fixed: `Cursor.size` records the file's size at the read, and a smaller file gives `PageRead::Changed`; the agent only appends. The new case in `a_log_changed_under_a_cursor_is_read_again_from_its_end` truncates after the cursor's line. The reader's docs and the page's docs describe the checks and their limits: a rewrite keeping that line and the size goes unnoticed. |
| **Medium — Refresh after Lock now could show history again while the lock answer was held.** Clearing the page left the last status unlocked, so Refresh or re-entering History could start another read. | Fixed: `lock_sent` is set before clearing, makes `vault_unlocked()` false, and is cleared by `apply_status` or `unreachable`. The widget test holds the lock answer, checks that Refresh is insensitive, and checks that clicking it or re-entering the page starts no read. |
| **Low — The stale-result test did not prove that a pending read was discarded.** Removing the receiver's discard survived: the test did not make a result arrive after the manager saw the lock, nor process it then. | Fixed: the test-only `history_gate` holds the read thread after reading and before sending. The test waits for the manager to observe the lock, opens the gate, processes events for 500 ms, and checks that no records were shown or stored and no read remains pending. |
| **Low — “Within five seconds” in the manager guide promised more than status polling guarantees.** A status answer can arrive after the polling interval. | Fixed: the guide says clearing happens “at once on **Lock now**, and for a lock made elsewhere when the manager sees it, at its next status check (every five seconds)”. This wording correction was checked by reading the docs against the code; it has no executable mutation test. |

The implementer's mutation checks ran on a copy with its own target
directory. Removing each guard in turn made a test fail by its assertion:
the newline before the cursor, the line hash, file identity, ending the
first page at the last complete line, the regular-file check, the
non-blocking open, clearing history with the entries, reading only while
unlocked, and drawing record values through the dialogs' character filter.
For the first three review findings, four code mutations also failed by
their assertions: removing the `size < cursor.size` check, the assignment
`self.lock_sent.set(true)`, the `!self.lock_sent.get()` check, or the
`history_job` discard in `clear_history`.

Two earlier mutations survived and are harmless by design: removing the
`fits` check before reading the cursor's line (a short file already gives
`Changed` when that read fails), and removing `&& !history.changed` from
Load older's visibility (a changed file clears the cursor). The redundant
visibility condition was removed.

Re-review (Codex, AI-assisted, 2026-11-05; verdict: ready): all four
findings fixed, no new finding. Codex repeated the four code mutations
above in separately compiled variants supplied through standard input,
without editing repository files. Removing the size check failed the
truncation assertion; removing either part of `lock_sent` failed the
assertion that Refresh was insensitive; keeping the receiver failed the
assertion that the history stayed empty after lock. Each failed by an
assertion, not a compiler error or a timeout. The wording fix was checked
separately.

Codex's checks passed in both reviews: `cargo fmt --all --check`,
`git diff HEAD --check`, `cargo test --locked -p rusthorse-manager`
(42 tests, including History and the real-agent desktop flow on Xvfb with
a private D-Bus session), and `cargo clippy --locked -p rusthorse-manager
--all-targets -- -D warnings`. The first review also ran `cargo test
--locked -p rusthorse --lib audit::tests` (10 passed), reader boundary
probes (CRLF, empty lines, an exact byte limit and an incomplete last
line), and the truncation and held-lock reproductions. The re-review ran
`cargo test --locked -p rusthorse --lib --no-default-features --features
fake-keyring audit::tests` (10 passed). Builds used a fresh temporary
`CARGO_TARGET_DIR`; the temporary artifacts were removed.

The implementer ran the full `AGENTS.md` check matrix before the review
and again after the fixes, before the commit; both runs passed. Codex did
not rerun the full matrix.

**2026-11-05 — The agent's settings and the manager's Settings page.**

Manager item 2/6 (ADR 0007 section 3, rewritten on 2026-11-05): the human
administers their own agent. The five existing settings now come from
defaults, `agent.toml`, then explicit flags; status reports their values
and sources. Protocol 10 adds `configure`: at the maintainer's choice it
needs an unlocked vault, asking for the master password first if needed,
then the agent's approval of old and new values, with warnings for weaker
protection. It saves and applies the change at once and forgets remembered
approvals. The manager's Settings page sends the request; there is no
`reload_config` or new CLI command for changing settings.

Design opinion (Codex, AI-assisted, 2026-11-05; recommendation: build with
changes): apply immediately, with fixed operational bounds. Adopted: idle
off or 1 s to 24 h, remembering off or 1 s to 8 h, and dialog timeout 15 s
to 5 min. These are operational limits, not security guarantees.

The other design recommendations were followed: serialize configuration
requests through approval and application; audit the answer first and
fail closed; recheck the vault generation under the state lock; preserve
the failure contract across the atomic replacement. Before replacement, a
definite error leaves the settings file and effective settings unchanged;
after replacement, a directory-sync failure still applies the settings
and reports `outcome_unknown`. The saved layer contains the file's values
and approved changes, never values copied from overriding flags.

An approval to configure does not touch the idle timer. A shorter timeout
counts from the last use and is checked immediately; the timer keeps
running while idle locking is off. Only a changed lock trigger's watchers
are restarted, preserving the suspend inhibitor when suspend is unchanged.
Dialogs already open keep their timing. Flag-fixed rows show their source
and cannot be edited; the refusal and docs explain removing the flag from
the service and restarting. An existing file that fails validation stops
startup instead of silently selecting defaults.

Before independent review, the implementer's own tests and checks exposed
four implementation issues. Under umask `002`, a hand-made `0664` file
would stop startup: an initial primary-group exception was added, then
removed after R1 below. The harness gained an `Options` struct for clippy.
A test could no longer use `Arc::get_mut` after the agent gained its weak
self-reference and was adjusted. Dropping the watchers could wait twice;
`stop_all` now signals both first and waits within one shared time limit.

The code reviews and confirmations below were by Codex, AI-assisted, on
2026-11-05. The successive findings are grouped as R1–R7; verdicts remained
not ready until the final confirmation. Each disposition describes the
fix and, where necessary, the later correction to an incomplete fix.

| Finding | Disposition |
|---|---|
| **Medium — R1: the primary group need not be private.** Accepting a group-writable settings file let another member weaken it. | Fixed: `load` refuses any group/other write bit (`mode & 0o022`), including the primary group, and says `chmod 600`. Tests cover `0664`, `0620` and `0646`; fixtures use `write_private`. The docs explain umask `002`. |
| **Medium — R1: duration labels dropped seconds.** A value such as 3659 s could appear as 1 h in the approval or manager. | Fixed: `exact_duration`, used by `Value::describe`, shows every part: `1h59s`. Unit and manager-model tests distinguish it from `1h`. |
| **Medium — R1: saving changed existing directory permissions.** `ensure_private_dir` could chmod an existing configuration directory. | Fixed: `DirBuilder` creates missing directories privately and leaves existing modes alone. A test preserves `0755`; later checks refuse unsafe directories without chmod-ing them. |
| **Medium — R1: the protocol wording overstated what an error guarantees.** It included `outcome_unknown` in the promise that nothing changed. | Fixed: only other errors guarantee no settings replacement or application; after `outcome_unknown` or no answer, the change may be in effect. Checked against the code; this wording fix has no executable mutation. |
| **Low — R1: the docs promised a dialog within the manager's wait.** Unlocking first or waiting behind other dialogs can exceed ten minutes. | Fixed: one dialog lasts at most five minutes; the complete request can outlast the manager's wait and be reported as unknown. ADR 0007, architecture and `MAX_DIALOG` state the distinction. |
| **Medium — R2: another user could remove a private file through its writable parent.** A later start could then use weaker defaults. | Fixed through the subsequent path checks: directories must belong to the user or root and not be group/other-writable unless sticky. Saving refuses an unsafe path before writing; reading an existing file refuses it too. Initially absent files still select defaults, as clarified in R7. |
| **Medium — R3: checking the written and canonical paths missed an intermediate link.** `safe/chain -> open/bounce -> target`, with `open` writable by others, hid a replaceable component. | Fixed: walk each name and link as resolution proceeds, including relative targets, `..` and absolute targets restarting at `/`; refuse more than 40 links. Existing files reached through an unsafe component remain refused. |
| **Medium — R4: a missing component ended validation too early.** Both `missing/../open/agent.toml` and a directory made by someone else before `mkdir` could lead to an unsafe write. | Fixed: walk again after making directories, before opening the temporary file. Tests preserve the existing file in `open` and leave the directory made meanwhile empty. R5 makes this second walk strict. An empty private directory created before refusal may remain. |
| **R4 — Link-owner coverage initially seemed to require root.** Another user could replace their own link in a sticky directory. | Tested without privileges: a link owned by the test user is accepted as that user and refused with a simulated different uid. The final tests cover an existing target and the final link in all three walk modes; reading a nonexistent target follows the accepted missing-file rule. |
| **Medium — R5: putting a parent aside during the second walk bypassed it.** An attacker could hide their `0777` directory while it was checked and restore it before the temporary file was opened. | Fixed: `BeforeWrite` requires every parent to exist. Hooks reproduce create, put aside and restore; the save is refused before anything is written. Removing this requirement fails the test. |
| **R5 — The surviving non-strict `load` mutation was not harmless.** The implementer had claimed that an already-open file implied its parents were safe. | Corrected by the review: an unvalidated parent could belong to another user and disappear after opening. Codex's counterexample passed with the strict check and failed without it. It must not be recorded as a harmless survivor. R6 moves validation before opening and checks the opened file's identity. |
| **Medium — R6: removing or replacing the final link after opening hid an unsafe read path.** The walk could accept the missing final name or validate an entry different from the open descriptor. | Fixed: walk before opening, retain device/inode and compare them with `fstat`; disappearance after a successful walk is an error. Link ownership is checked during the walk. Tests replace the file by rename with a distinct inode and put its parent aside between walk and open. |
| **Low — R6: a dangling final link could not be replaced.** A missing directory in its target made a safe save fail, although rename replaces the link itself. | Fixed: both save walks check the final link's owner but do not follow it. The test replaces `config/dangling.toml -> absent/agent.toml` without creating `absent`; the saved settings read back correctly. |
| **Medium — R7: walking first broke startup with no settings file under a `0775` configuration directory.** The directory error arrived before absence was discovered. | Fixed: `Read` keeps the first directory/link problem and rejects it if resolution reaches an existing file or directory; absence gives defaults. Save walks still refuse immediately. Unit cases and a real-agent startup test cover the absent file under writable directories without writing settings or using the real buses. |
| **Low — R7: paths leading to directories were treated as missing files.** `/`, `child/..` and links to `.` or `/` silently selected defaults. | Fixed: a completed read walk returns the directory's identity, or its kept error, and `load` refuses a non-regular file. Save walks refuse directory destinations, including a trailing `.`; a final symlink itself remains replaceable. `a_directory_is_not_a_settings_file` covers these cases. |

The implementer reported an initial batch of 15 mutation checks on a copy
with its own target directory. Removing the effective guards made tests
fail by their assertions: flag refusal, unlock required, a lock meanwhile,
not touching the idle timer, clearing remembered approvals, checking idle
at once, `set_timing`, save failure, switching a watcher, file permissions,
bounds, Apply only while unlocked, keeping a choice across status, and
not sending a flag's setting. The last was caught by the manager model
test once the correct filter ran.

One mutation survived because the assignment was dead:
`config.idle_timeout = settings.idle_timeout` in `Agent::new`. The idle
timer and status use `State.settings`; the assignment was removed.
The overrides used to start the session-lock watchers remain necessary.

The implementer's later mutations removed each fix in turn and failed by
test assertions: the group rule, exact durations, leaving directories'
modes alone, directory checks in load and save, resolved links, the sticky
exception, checking each directory, following links, restarting at root
for absolute targets, the second walk, link ownership, the strict final
walk, file identity, not following the final link on save, refusing a
missing parent before writing, reading deferral (also in the end-to-end
startup test), and directory refusals. Intermediate canonical-path and
strict-read checks were superseded by the final walk modes; their results
do not replace tests of the final implementation.

Accepted limits: absence cannot distinguish a file never written from one
removed. It means defaults, while the agent saves only through paths that
other users cannot replace; an existing unsafe file is refused. A program
running as the user can still edit the file or systemd unit and restart
the agent (L1). The dialog protects changes through `configure`, not the
file against its owner. After a valid walk to a file that passes the
descriptor checks, the device/inode comparison is defense in depth, not
isolation from the user or root.

The temporary file is synced before rename. That durability step has no
deterministic failure or crash assertion in the current test harness; it
was not proved by mutation. This is an accepted testing limit, not a
reason to omit the sync.

Final re-review (Codex, AI-assisted, 2026-11-05; verdict: READY): the two
regressions fixed, no new finding, and the earlier protections checked
still working. Codex ran `cargo fmt --all --check`, `git diff HEAD --check`
and, under umask `002`, `cargo test --locked -p rusthorse --all-features
--lib --test agent settings::`: 11 unit and 8 integration tests passed,
again after restoring the temporary copy. Separate starts with missing
files under configuration directories `0755` and `0775`, and a relative
path, used defaults and wrote no settings; `--config /` was refused.

Codex's final nine mutation runs failed by assertions: no reading deferral
(unit and end-to-end), a directory treated as missing, removing early
directory refusal on save, discarding the deferred error for a file or a
directory, removing identity comparison, following the final link on
save, and accepting a missing parent before writing. The save-directory
mutation failed on the expected diagnostic; the operating system also
refused that operation. Earlier re-reviews separately reproduced the
unsafe-path races and checked the fixes in temporary copies. Builds used
fresh target directories; the copies, targets and probes were removed,
and the test agents were stopped. Repository files were not edited by
these reviews.

The implementer reports that the full `AGENTS.md` matrix passed after the
last code fix. Codex did not rerun that full matrix or the GTK suites in
the final re-review.

**2026-11-09 — Documentation audit against the code at `1061b89`.**

At the maintainer's request, the maintainer's agent ran seven read-only
audits (AI-assisted; nothing was built, run or changed by them), each
comparing a set of documents with the code: the command line (`docs/cli.md`,
the guide for AI agents, the README), the protocol, the architecture and
the contributor instructions, the manager and the dialog program,
installation and packaging, this threat model, and the credential broker
with the CHANGELOG and the roadmap. No audit built or ran the programs;
each reported what it did not check. What they found, by class:

| Class of finding | Disposition |
|---|---|
| Statements the code contradicts: a protocol version in an example, the error an unanswered password dialog gives, the size of the dialog program's answer, how imports are split into batches, what the manager starts and changes, what a build without default features lacks, a line the run dialog does not have, the package's description. | **Corrected** in the documents concerned (and in the package's description and in comments in the code). |
| The agent's settings of 2026-11-05 not carried through: remembered approvals and the idle lock named as flags only, the idle lock's 15 minutes stated without saying it is a default that can be turned off, the settings file absent from the assets and from the file locations. | **Corrected:** here, the settings file is an asset, P15 states what guards a change, P9 states the default and what can be switched off, and P3 and "What an approval means" say that an approved settings change forgets remembered approvals; the other documents name the settings. |
| ADR 0013's text outside its scope amendment still described phase 1's profiles, routes and audit records as what is built. | **Corrected** by marking those passages superseded; the ADR remains the record of both decisions. |
| Status that had not followed the work: ADRs still "Proposed", the manager's first milestone "awaiting review", the CI workflow "planned", two findings of this history still "Open". | **Corrected:** the statuses, and the two entries above, which now say when they were closed. The summary table of this history gained the rows of 2026-11-05. |
| The manual tests of the broker told in five documents, mixed with phase 1's. | **Corrected:** the whole account is in this history ("A key the destination refused, and the manual test so far" and "Manual tests of the broker without profiles"); L24 and the other documents state the last result. |
| Omissions: options, fields, refusals and pages the documents did not mention; code maps without the newer modules; §10 and the roadmap's Hardening table listing different items. | **Corrected.** §10 and the Hardening table now list the same items, and the roadmap carries their status. |
| L18 and L19 out of order; L2 spoke of `rusthorse-dialog` in the future. | **Corrected.** |
| No review recorded for the SSH recipes of the guide (`5cb9117`, `da0737f`). | **Reviewed on 2026-11-09:** see the next entry. |

No finding of this first round changed what the code does or what this
model's sections 1 to 9 guarantee; P9 was stated more strongly than the code
(an unqualified 15 minutes), and is now exact. Each audit said what it had
not traced, and a second round, the same day, traced those parts line by
line (four more read-only audits; for the broker, also the HTTP library's
source where the broker inherits its behaviour). Each finding was then
checked in the code before a sentence changed:

| What the second round traced | Found and corrected |
|---|---|
| The broker's internals (ADR 0013, the protocol, the CLI reference). | Nine statements. Only a `101` from the destination is refused with `502`: the HTTP library discards other `1xx` responses — the first round had this wrong, and its correction of that day was corrected. A connection waiting for a request is normally closed after 30 seconds, by the deadline for a request's head, before the idle limit of 60. Only HTTP/1.0 gets `505`. The limit of 100 headers is the library's default, not set by the broker and not covered by a test of its own. Request numbers are consecutive, not merely increasing. A token-shaped string in a forwarded header value is compared with the token, a copy in another case included; one anywhere else is refused as it stands. A `414` cannot occur. `100 Continue` is sent only after admission. A head that the key would make longer than 32 KiB gets `401`. |
| This model's properties and limits (P1, P2, P4–P7, P12, P14, P15, L3–L20). | Eleven statements, none of them an invariant broken. L14 said that `import` reads values in the client: the CLI and the manager send names, and the agent reads the values. A remembered approval names the program and the directory by path, so a program replaced at that path between two uses runs without asking (L8). The run dialog shows of the environment only the variables on its lists, and for a run with `--broker` the time between the re-check and the start is the time its brokers take to start (P2, L4). `add --stdin` and `edit --stdin` pass a value through the requester (P6). The dialogs of `add` and of an import show the name as given, without group or UUID (P7, L9). With `--no-redact` the command holds the requester's standard input (L18). Redaction's minimum is 4 bytes (L5). Which directories the settings file may be under (P15); what is synced when a record is written (P12). |
| The CLI reference and the protocol where the first round had not looked. | Fifteen statements, among them: the agent watches a connection only once the command has started (below); an empty click on Unlock uses one of the three attempts; `not watched` appears only when no source of an event is watched; which of `doctor`'s checks warn and which fail, a broker built for tests among the failures; the full lists of destination variables and of connection-string parameters; two rules of the `.env` dialect about `#`. |
| The lifecycle of a `run`, the dialog programs, storage, the package, the manager, ADR 0009. | Eleven statements: the `run` diagram unlocked before it resolved the program (the code resolves first); for the broker's grants a lock on suspend or screen lock is not what `rusthorse lock` is; the settings also turn those locks on and off; when the suspend inhibitor is let go and asked for again; the cipher and compression are those of new vaults, and an existing file keeps its own; what the package's link check covers; the two statements of the KDF's cost now agree on about 0.7 s (the ignored timing test, built for release, opened a new vault in 0.67 s on the maintainer's machine). |

What the documents now state as it is, and the maintainer may want to
change in the code — none was changed here:

- **A connection is not watched while a dialog is open.** A requester that
  goes away then is not noticed: the dialog stays, and what the human
  allows is done — a `run`'s command is started with the secrets, and its
  broker grants served, before the agent notices and stops them; an `edit`,
  a `remove` or an `add` is carried out with nobody to read the answer. The
  human approved what the dialog showed, so no approval is bypassed; the
  protocol had said that closing the connection cancels the request.
- **The first records of a new audit log** are synced as data, but the
  directory entry of the file just created is not: a crash right after may
  lose them (P12 says so now).
- **The limit of 100 request headers** is the HTTP library's default, which
  a new version of the library could change unnoticed.

One test changed with the documents: the guide's list of JSON fields gained
`has_notes`, which `list --json` always carries, so the test that reads that
list counts it among the fields that are always there. Still not confirmed
by these audits: the unlock barrier and the first step of a broker run's
preparation, the HTTP library's handling of a `#` fragment (L24), how other
programs read a `.env` file or a connection string, the measured heights of
dialogs, the dependencies the package computes when it is built, and the
entries of this history before 2026-11-04.

**2026-11-09 — The SSH recipes of the guide for AI agents (`5cb9117`,
`da0737f`).**

The two commits of 2026-11-04 added to `rusthorse guide ai` a recipe for
SSH with a password (`sshpass -e`) and one with a private key from the vault
(a temporary `ssh-agent`), and mentioned them in `docs/ai-agents.md` and the
CHANGELOG. They changed no code and had no review on record; the
documentation audit above found that. Review of the text at `1061b89`
(Codex, AI-assisted, 2026-11-09; verdict: **not ready**, one medium and four
low findings), and what was done:

| Finding | Disposition |
|---|---|
| Medium — SSH01: the probe "without a secret" (`ssh -o BatchMode=yes … true`) was not without one. `BatchMode` only turns the questions off: ssh still offered the human's own keys, from their files and from the session's ssh-agent, and where the host accepts one it ran `true` logged in, outside any approval or record of Rusthorse. | **Fixed:** the probe reads no ssh configuration (`-F /dev/null`) and offers no key, agent or password (`PreferredAuthentications=none`, `IdentityAgent=none`), with `StrictHostKeyChecking=yes` and the port given; the guide says why, what its two answers mean, and that a host reached only through the human's ssh configuration cannot be probed this way. |
| Low — SSH02: "for the command only" promised a cleanup that an interruption skipped: `ssh-agent -k` ran only when the shell reached the end of its line, and the agent, in a session of its own, is not in the group that `run` stops (L17). | **Fixed:** the recipe sets its traps before it loads the key — one ends the agent whenever the shell exits, one makes the shell exit on `HUP`, `INT` and `TERM` — and the guide says what is left: a shell killed with `SIGKILL` cannot clean up, and the agent then keeps the key until it notices that the shell is gone. |
| Low — SSH03: the guide gave the wrong reason for an unknown host key failing (no terminal; `sshpass` gives ssh one, and itself refuses to confirm a key), and its examples left `StrictHostKeyChecking` to the human's configuration, where `accept-new` trusts a new key unseen. | **Fixed:** both recipes and the probe pass `-o StrictHostKeyChecking=yes`, which wins over the configuration; the guide says that ssh then refuses a host it does not know, forbids `accept-new` beside turning the check off, and gives `ssh-keygen -F '[HOST]:PORT'` for a port other than 22. |
| Low — SSH04: nothing said that the key recipe needs a key without a passphrase; with one, `ssh-add` asks for it, in the terminal or through an askpass program. | **Fixed:** the guide and `docs/ai-agents.md` say so, and that a passphrase never goes in a command line or a file. |
| Low — SSH05: "a test checks every command and option it names" read as covering the recipes' other programs; the test gives the CLI's parser the `rusthorse` command lines, and what follows `--` is the command's own words, unchecked. | **Fixed** in `docs/ai-agents.md`, the CHANGELOG, the roadmap and AGENTS.md: the test checks that the CLI accepts every `rusthorse` command line the guide shows, not the other programs of its recipes. |

Also checked by the review and found correct: the commits add no feature;
`sshpass -e` keeps the password out of the arguments; the single quotes
keep `$SSH_KEY` for the approved shell, whose `printf` is a builtin, so the
key goes to `ssh-add` through a pipe and into no file; the dialog and the
audit hold the command line as written, not its expansion; output redaction
is literal (L3–L5).

How the corrected recipe was checked, on the maintainer's machine, with
OpenSSH 9.6, a key made for the test and a stand-in for the `ssh` command —
no host was contacted, and neither recipe has been tried against a server
since it was changed: the agent is gone when the shell ends after a
success, after a command that failed (its status, 7, was the shell's) and
after `ssh-add` refused what was not a key (status 1); half a second after a
`SIGTERM` sent to the command's process group, the shell and the agent were
both gone; after a `SIGKILL` sent to that group, the agent, which is in
another group, ended by itself 9 seconds later. `ssh -G`, which connects to
nothing, showed that `BatchMode=yes` leaves public-key authentication on,
that the probe's options are accepted as written, and that
`StrictHostKeyChecking=yes` on the command line wins over a configuration
that says `accept-new`; `ssh-keygen -F` found a host stored with a port only
as `[HOST]:PORT`. Not checked: that a server answers the probe `Permission
denied` without being offered a key, which rests on OpenSSH's documentation
of `PreferredAuthentications`; `sshpass` with a real server; an interactive
session.

Confirmation (Codex, AI-assisted, 2026-11-09): SSH01 to SSH05 confirmed
fixed, with no new finding in the recipes, and this record found accurate.
The reviewer repeated the local checks with dash and with bash — the shell's
status 0 after a success, 7 after a command that failed, 1 after a key that
was none, 143 after `HUP`, `INT` or `TERM`, the agent's socket gone each
time, and about 9.8 seconds after a `SIGKILL` — and noted that this repeats
the checks, not who first ran them. No server was contacted.

**2026-11-09 — Review of the documentation correction.**

Review of the whole uncommitted change — the corrections of the audit above,
both rounds, with the SSH fixes — by Codex (AI-assisted, 2026-11-09; verdict:
**not ready**, six low findings; no high or medium finding, and none in the
SSH recipes or in what the programs do). The reviewer read the whole diff and,
for this model, the README, `docs/ai-agents.md` and ADR 0013, the removed
lines alone: no true reviewed guarantee was found dropped. What it found, and
what was done:

| Finding | Disposition |
|---|---|
| Low — DOC01: the audit's second round had said that the broker's idle limit of 60 seconds "never comes first", and ADR 0013 that the 30-second deadline for a request's head "always comes before" it. It can come first: the broker counts a request as over when its response's body is handed over, and the HTTP library waits for the next request only once that response is written, so a connection whose client does not read stays open past 30 seconds and is closed by the idle limit (reproduced by the reviewer with the library and the broker's counter over an in-memory pipe). | **Fixed:** ADR 0013 says that the head's deadline normally comes first and when the idle limit still does; the audit's record no longer lists the limit among the behaviours left to the maintainer — it is not redundant, and is kept. |
| Low — DOC02: "any other version … answered with an empty `400`" (ADR 0013, a note of this day): an HTTP/2 connection preface closes the connection with no response at all. | **Fixed:** the note says both. |
| Low — DOC03: "every token-shaped string … is compared … in constant time" (ADR 0013, a note of this day; P8 said the same of "the request's head"). One in the method, the target, a header's name or a header that is not forwarded is refused without being compared; in a forwarded value each is compared, and the first that differs refuses the request. | **Fixed** in ADR 0013, in P8 and in the audit's record. The refusals themselves were right. |
| Low — DOC04: the protocol's error table still gave `unlock_failed` as "Wrong master password three times", after the CLI reference had been corrected: an empty answer uses an attempt, and `change_password` answers it after one wrong current password. | **Fixed** in the table. |
| Low — DOC05: the guide for AI agents and the CLI reference still said that values of "4 characters or longer" are redacted, after L5 was corrected to bytes. | **Fixed** in both: 4 bytes or longer. |
| Low — DOC06: the package's description said that the agent asks "before each use" and locks the vault when the screen locks or the computer suspends, without saying that remembered approvals skip the dialog and that those locks are defaults which depend on the desktop. | **Fixed** in `Cargo.toml`. |

The reviewer's opinion on the behaviours that the audit left to the
maintainer, each verified in the code — the decisions remain the
maintainer's, and nothing was changed: the connection that is not watched
while a dialog is open, **fix later** (no approval is bypassed, and the
documents now say it; watch for a disconnection while waiting, and check
again before the effects); the directory entry of a new audit log that is
not synced, **fix now, in a change of its own** (a crash could keep the
approved effect and lose the log's name; sync the directory, and any parent
just created, before the effect is released, and fail closed); the limit of
100 headers inherited from the HTTP library, **fix later** (set it
explicitly and test 101 headers; the 32 KiB limit stands by itself).

After the fixes of the first audit round, the maintainer's agent had run
the whole matrix of `AGENTS.md`'s checks, and one test failed: the guide's
list of JSON fields now named `has_notes`, which the test did not count
among the fields always present. With that line corrected, the twelve steps
passed on the tree the reviewer read — `cargo fmt`, both `clippy` runs, the
tests with and without features, `cargo doc`, both MSRV checks, and the
`clippy` and tests of the dialog program and of the manager. The reviewer
did not run that matrix.

Confirmation (Codex, AI-assisted, 2026-11-09): **ready.** DOC01 to DOC06
confirmed fixed, each against the code, with no new finding and nothing made
stronger or weaker by the fixes; this record and the SSH one found accurate.
The reviewer did not repeat its experiments or run the checks. The
maintainer's agent ran the whole matrix once more after these fixes: the
twelve steps passed. Left as they were, as said above: no recipe was tried
against a server after it changed, and the three behaviours of the code
await the maintainer's decision.

**2026-11-10 — The SSH recipes tried against servers.**

A test by hand, not a review. With the package built from `837eeb0`
installed, the maintainer's agent followed the built-in guide on the
maintainer's machine (OpenSSH 9.6, sshpass 1.09), and the maintainer
answered each dialog. The servers were three devices of the maintainer's
network: two routers whose SSH server is Dropbear, and a firewall, used for
the probe only. What worked, for what was tried:

- **The probe.** Each of the three devices answered `Permission denied
  (publickey,password)`, with status 255. With `-v` added, on each router,
  ssh offered and tried no key and stopped at "No more authentication
  methods to try". On one router, with empty files of known hosts for that
  call, the answer was `Host key verification failed`, status 255. That a
  server answers the probe so without being offered a key is what the entry
  of 2026-11-09 listed as not checked.
- **The key recipe**, on each router, with an entry that holds a private
  key without a passphrase: `uptime` answered, with status 0.
  `pgrep -c -x ssh-agent` reported 0 before and right after the first
  router's run, and 0 right after the second's. On the second router `-v`
  was added and its output filtered: the server accepted the Ed25519 key
  that the temporary agent offered, and the login was by public key.
- **The password recipe**, on each router, with an entry that holds root's
  password: `uptime` answered, with status 0.

Not tried: the two recipes with a server other than Dropbear; a port other
than 22, and the `[HOST]:PORT` form of `ssh-keygen -F`; a command stopped
while it runs (checked on 2026-11-09 without a server only); a key with a
passphrase; an interactive session.

One finding, from the first run of the test:

| Finding | Disposition |
|---|---|
| Low — SSH06: nothing tells a password from a private key. The agent ran the password recipe with an entry that holds a private key: it had taken the entry for a password from notes of 2026-11-04, the entry's metadata is the same for both (`kind` `server`, `has_password`), and the guide did not say to check. The maintainer approved the dialog, which showed the command and the entry's name; the login attempt as root failed with `Permission denied, please try again.` (`sshpass` status 5). The maintainer denied the agent's next request, said which entries hold what, and the test went on with the right ones. | **Fixed in the guide and in `docs/ai-agents.md`:** the guide says that the metadata does not tell the two apart, to ask the human when the entry's name, kind or tags do not, and which recipe a private key takes; `docs/ai-agents.md` tells the human to say it in the entry's name or in a tag; the CHANGELOG says what the guide gained. **Left to the maintainer:** how an entry should say what its value is — a kind for SSH keys (ADR 0008 foresees more kinds), a group for each device, or one entry with several secrets (planned in the roadmap). |

What `sshpass` typed at the server's prompt in that run was not seen. A
local check afterwards, with no server, a key and a text of four lines made
for it (`ssh-add` asking for a passphrase on the terminal that `sshpass`
gives it, under `strace`): OpenSSH read the first line, restored the
terminal's settings with the call that discards input not yet read, and at
its second prompt read nothing, `sshpass` having closed the terminal
(status 5). ssh's password prompt itself was not measured, which needs a
server: if it reads as `ssh-add` does, the router was sent the first line of
the key's file, which in OpenSSH's format is the same for every key.

Review of this record and of the guide's new paragraph (Codex, AI-assisted,
2026-11-10; verdict: **not ready**, four low findings, none high or medium),
and what was done:

| Finding | Disposition |
|---|---|
| Low — T01: the guide's new paragraph turned one observed failure into a rule ("the password recipe below fails", "the server refuses the login"), and "types the key at the server's password prompt" suggested a transfer that was not observed. | **Fixed:** the guide says what the recipe does — it gives the entry's value to `sshpass` as the password to type — and which recipe a private key takes. |
| Low — T02: "no `ssh-agent` process was running right after (nor before)" was said of each router; the count before was taken for the first router's run only. | **Fixed:** the record says what was counted, and when. |
| Low — T03: "one failed password attempt for root" stated a count that was not measured: one run, its message and `sshpass`'s status were observed. | **Fixed:** the record gives the message and the status. |
| Low — T04: the CHANGELOG did not say what the guide gained. | **Fixed** in the guide's entry under *Unreleased*. |

The reviewer checked in the code that `has_password` is true for any value
that is not empty, and that no kind or field of the metadata says what the
value is; ran the guide's three tests; and repeated the local measurement,
with a key and a text made for it, with the same result, checking apart
that restoring the terminal's settings discards the input not yet read. It
did not check the devices, the installed package or the matrix of
`AGENTS.md`'s checks. The maintainer's agent ran that matrix after these
fixes: the twelve steps passed.

Confirmation (Codex, AI-assisted, 2026-11-10): **ready.** T01 to T04
confirmed fixed, with no new finding, and this record found accurate. The
reviewer ran the guide's three tests again; it did not repeat the local
measurement or run the matrix.

**2026-11-10 — The entry kind `ssh-key` (ADR 0008, amended).**

SSH06 left a decision to the maintainer, who took it the same day: a fifth
kind, `ssh-key`, for an entry whose value is a private key, so that an AI
agent can tell it from a password by the entry's metadata; and one group for
each device, which needs no code. What was built: the word in the protocol,
where it is stored, sent and parsed, with protocol 11; `--kind ssh-key` in
the CLI; the Kind row of the manager's form, which offers Username, Host and
Port for it; the guide's rule — the kind names the key recipe, and the agent
asks about an entry that does not say what it holds; the documents.

What it does not do, by design: it is a label, as every kind is. No policy
depends on it, and nothing checks it against the value — an entry of kind
`ssh-key` may hold anything, and an entry of another kind may hold a key. The
dialogs of `add` and `edit` show its name, as they show any kind's; what
needs approval and what is recorded did not change. Rusthorse does not look
at a value to find out what it is, which would put a fact about a secret in
metadata that is read without approval (L6). A label that is wrong misleads
as the old notes did; the guide tells the agent to ask when an entry does not
say.

Tests: one end to end (an entry added with the kind, shown, found by
`list --kind ssh-key` and not by `list --kind server`, and an existing entry
given the kind with `edit`, whose dialog names it), and unit tests of the
words as stored and sent, of a `Kind` typed in another client, and of the
manager's form. Eight mutations, on a copy of the repository with a target
directory of its own, each failed a test or the build: the CLI's option
giving another kind; the stored word changed; the form offering the URL for
the kind; the kind missing from the form's choices; the protocol version
back at 10 (an assertion at compile time, moved to 11); the kind missing
from the guide's list; its name for people changed; the kind not read from
a file.

Review (Codex, AI-assisted, 2026-11-10; verdict: **not ready**, three low
findings; none high or medium, and no defect of security or of
compatibility in the implementation), its confirmation (K01 to K03
confirmed fixed; **not ready** again, with two low findings in this
record), and what was done:

| Finding | Disposition |
|---|---|
| Low — K01: two statements of the current version in `docs/protocol.md` still said 10: its heading, and the requests the manager uses. | **Fixed:** both say 11; the history of the versions keeps its 10. |
| Low — K02: this record said that no dialog reads the kind. The dialogs of `add` and `edit` show its name; the end-to-end test checks the dialog of `edit`. | **Fixed:** the record says what the dialogs show, and that what needs approval and what is recorded did not change. |
| Low — K03: no widget test chose the new kind in the manager's form: a mutation that gave it another kind's name for the URL ("Endpoint URL") passed the manager's 45 tests. The code was right; the gap was in the tests. | **Fixed:** the manager's widget test of the form chooses "SSH key" and checks its rows and the URL's plain name. With the reviewer's mutation, on a copy with a target directory of its own, that test fails. |
| Low — K04, from the confirmation: this record said that `--stdin` keeps a value of several lines whole. It keeps the line breaks inside the value and removes those at its end, as the CLI reference says. | **Fixed** in the record. |
| Low — K05, from the confirmation: this record said that the end-to-end test checks the dialogs of `add` and `edit`. It checks the dialog of `edit`; that the dialog of `add` shows the kind's name was read in the code. | **Fixed** in the record. |

Also checked by the reviewer, and found right: no decision about access, no
behaviour of the broker and no generated command depends on the kind; with
the protocol's types as they were before this change, `ssh-key` is refused in
`add`, in `edit` and in an entry read, and the agent answers
`invalid_request` before it acts, so the version had to change; an unknown
`Kind` is listed by name, and a protected one withheld; the new example of
the CLI reference runs, and `--stdin` keeps the line breaks inside a value
and removes those at its end. The maintainer's agent ran the whole matrix of
`AGENTS.md`'s checks after the fixes: the twelve steps passed. The reviewer
did not run that matrix, or repeat the eight mutations.

Second confirmation (Codex, AI-assisted, 2026-11-10): **ready.** K04 and K05
confirmed fixed, with no new finding, and the whole record found accurate.
The reviewer ran no test in that round. The maintainer's agent ran the
matrix once more on the tree as committed: the twelve steps passed.

**2026-11-10 — Set the broker's limit of 100 request headers itself.**

The third behaviour that the documentation audit of 2026-11-09 left to the
maintainer is closed. The limit of 100 request headers was hyper's default,
neither set nor tested by the broker. The broker now passes its own
`MAX_REQUEST_HEADERS` (100), in `src/broker_protocol.rs`, to
`http1::Builder::max_headers`. The number, the empty `431`, the connection
being closed and what is recorded did not change; no CHANGELOG line was
needed. The dated note in ADR 0013 states the change.

Tests in both builds send 100 header lines on to admission and refuse 101
before asking the agent. With `test-upstream`, 100 reach the fake HTTPS
destination whole, with the credential in the token's place, and 101 reach
nothing. The system test checks that the refused request has no
`broker_request` record and contributes to the grant's end count. That
count reaches the end record when the agent receives the broker's
`revoked`; without it, `broker_refused.unwrap_or(0)` contributes zero.
End records are best effort. ADR 0013's note is made precise on those two
conditions with this record.

The implementer's mutations, on temporary copies with their own target
directories:

- `MAX_REQUEST_HEADERS = 99` fails
  `more_than_100_header_lines_get_431_before_anything_is_asked` (both
  builds), `a_head_of_100_header_lines_is_forwarded_and_one_of_101_is_not`
  and `the_limits_are_those_of_phase_1`.
- `MAX_REQUEST_HEADERS = 101` fails the same three tests and
  `badly_framed_requests_are_refused_and_any_path_goes_as_sent`.
- Removing the `max_headers` call survives every test in both builds,
  harmless by design: hyper's default is the same 100 today. Keeping the
  now-unused import makes clippy fail, but no behaviour test distinguishes
  the default from the explicit setting. This surviving mutation is
  recorded as such, as `AGENTS.md` requires.

Review (Codex, AI-assisted, 2026-11-10; verdict: **ready**, no findings):

| Finding | Disposition |
|---|---|
| None in this change. | **Ready.** The unchanged response limits, wording and test-helper issue below are left to the maintainer, not fixes claimed by this change. |

The reviewer read hyper 1.12.0 and httparse 1.10.1 in Cargo's registry:
the parser counts header lines, including `Host` and each occurrence of a
repeated name, but not the request line; too many become a parse error,
answered with an empty `431` and a closed connection. It traced that error
to the broker's count of refusals before admission. It checked the helper's
count: one `Host`, one `x-api-key` and the remaining padding lines, with
exactly two more CRLFs than header lines (the request line and the empty
line). It checked the forwarding and refusal assertions and the system
test's end record.

The reviewer ran the whole matrix of `AGENTS.md`'s checks: formatting,
clippy with and without the test features, both test suites, documentation
with warnings denied, both MSRV 1.89 checks, and clippy and tests for the
dialog and the manager; all twelve steps passed. It reproduced the limit
mutations and the harmless surviving removal on temporary copies. An
extra probe sent 101 header lines without a token and got `431`, confirming
that parsing precedes the token check. The library source and a separate
probe confirmed that an explicit 100 keeps hyper's temporary header
storage inline; it does not force those arrays onto the heap.

Not checked: real destinations or credentials, fuzzing or a sustained load
test, allocation or throughput benchmarks, or future library versions.
The destination-response limits below were read in the code and the
library's sources, not exercised with oversized responses.

Left to the maintainer; nothing in these three areas changed:

- **Destination responses.** `broker/src/exchange.rs` leaves the client's
  `max_headers`, `max_header_size` and `max_buf_size` unset. It inherits
  hyper's limit of 100 header lines and its default read buffer of 417792
  bytes (about 418 kB), rather than a head-size limit set by the broker;
  exceeding those inherited bounds makes the broker answer its own `502`.
  The documents state no response limit. The reviewer's recommendation is
  to set, test and document these limits in a change of their own.
- **"A malformed request"** in `docs/cli.md` and `src/guide/ai.md` predates
  this change. A request that only exceeds a size or count limit need not
  be malformed; the wording should distinguish those cases.
- **The fake agent's `wait_for`** in `broker/tests/support/mod.rs` asserts
  while holding its lock. A failed assertion can make its reader thread
  panic with `PoisonError`: noise after a test failure, not a broker defect.

**2026-11-10 — Sync the audit log's directory entries before its records.**

The second behaviour that the documentation audit of 2026-11-09 left to
the maintainer is closed, within P12's limits below. A new audit log's data
was synced, but its directory entry was not: a crash could keep an approved
effect and lose the log's name and records. At every record the agent now
opens the directory that holds the log file, checks through that descriptor
that the resolved name holds the opened file (device and inode, `fstatat`
with `AT_SYMLINK_NOFOLLOW`), and then syncs that same directory. For a
symbolic link to the log, this is the target file's directory. It also syncs
the parent of each directory made for the log, keeping each pending until
its sync succeeds, including directories made before a later creation
failed. Only then does it write the record and run `fdatasync`. A failed
directory sync or check fails the record before any record bytes are
written, and refuses the gated action. A failed write or `fdatasync` also
refuses the action, but may leave part or all of its record in the file.

The first version, "Sync the audit log's directory entries before its
records", remembered the file's device and inode so as to sync its
directory once per process and per file. The maintainer's coordinating
agent had accepted that design on a cost argument it had not measured.
The first review (Codex, AI-assisted) found AUD01 to AUD04 and preferred
syncing at every record. "Sync the audit log's directory at every record,
bound to the file" removed the cache and fixed those four findings. The
second review confirmed them fixed and found AUD05. "Check the audit log's
directory before syncing it, not after" changed the order to check, then
sync. The third review found the whole change **ready**. All three versions,
their fixes and their reviews were made on 2026-11-10.

Cost was measured only after the first review. The implementer reported a
throwaway benchmark that day on this machine: 300 records per run, ext4 on
NVMe, a debug build, the median of eight interleaved runs under load
(load average 4 to 6). The rounded figures were about 0.90 ms per record
before the change, 0.92 ms with the cache and 0.98 ms with a sync at every
record: about 0.08 ms above the base and 0.06 ms above the cache, as the
last version's message clarified. The final order still has one sync of
the file's directory per record. These are that day's measurements, not a
performance promise; the reviewer read the report and did not repeat the
benchmark.

Findings and their dispositions:

| Finding | Disposition |
|---|---|
| Medium — AUD01: making the log's directories could fail after making some of them, losing the list of names still needing a sync. A later record found those directories already there and could skip their parents. | **Fixed in the fix of AUD01 to AUD04:** `make_private_dir` adds each directory to the caller's list as soon as it is made; `record` queues their parents even when creation fails. Each stays pending until its sync succeeds. Confirmed in the second review. |
| Medium — AUD02: another program could remove and recreate the log with the same device and inode; the cache then skipped the new name's sync. Inode reuse occurred on ext4 at the first try. | **Fixed in the fix of AUD01 to AUD04:** the identity cache and the creation flag are gone; the log's directory is synced at every record, including after an earlier success in the same agent. Confirmed in the second review. |
| Medium — AUD03: a rotation between opening the log and resolving its path could sync the substitute's directory while writing into the moved file. | **Fixed in the fix of AUD01 to AUD04:** the name is checked through the opened directory's descriptor against the opened file, rather than trusted from a new path lookup. A mismatch refuses the record before writing. Confirmed in the second review; the ordering defect below was separate. |
| Low — AUD04: the documents said that a record whose sync failed was not written, which was false for a failed write or `fdatasync`. | **Fixed in the fix of AUD01 to AUD04:** the no-write statement is limited to directory syncs and the check; a failed write or `fdatasync` may leave the record of a refused action. Confirmed in the second review. |
| Medium — AUD05: syncing before checking did not prove the matching name had been synced. Another process could substitute a file before `fsync`, then restore the original before the comparison; all changes preceded the check, and `record` still returned `Ok`. | **Fixed in the fix of AUD05:** check through the directory descriptor first, then sync that descriptor. A substitution still present is refused; one undone before the check is covered by the following sync. Changes after the check remain the other program's to sync. Confirmed by the third review's external probe, within that contract. |

First review (Codex, AI-assisted; **not ready**, three medium findings and
one low): the reviewer read the durability and error paths and reproduced
the partial-directory-creation failure, inode reuse, the open/path rotation
and the failed-data-sync case behind AUD01 to AUD04. It checked the callers
of `record` and their fail-closed handling, the directory helper against
the old helper, and the documents. The cache's complexity was not justified
by a measured cost; syncing at every record was the reviewer's preference.

Second review (Codex, AI-assisted; **not ready**, AUD01 to AUD04 confirmed
fixed, AUD05 medium): the reviewer reran the probes for the four findings,
then interposed `fsync` and coordinated a second process to take the file
away, put a substitute in place for the sync and restore the file before
the check. In four runs out of four, the record succeeded although no sync
had covered the restored name. The reviewer suggested another sync after
the comparison. The final fix instead moves the comparison before the one
sync: an earlier extra sync adds nothing to the contract for changes after
the check.

Third review (Codex, AI-assisted; **ready**, no new finding): the reviewer
read the whole change and the fix of AUD05, confirmed that the callers,
dependencies and protocol were unchanged and no `unsafe` was added, and
checked P12, the architecture, the CHANGELOG and the comments against the
code. An external probe used interposed `fstatat` and `fsync`, a second
process changing names, and socket handshakes rather than sleeps. Each of
these cases ran four times with the same result:

- A substitute present at the check was refused, with no record written.
- The original taken away and restored before the check was accepted,
  with a following sync covering the restored name.
- A directory replaced while the path still led to the opened file was
  refused: the check used the opened directory, not the path again.
- A substitution and restoration only around `fsync` still returned `Ok`;
  those changes now happened after the check and fell under the stated
  responsibility of the other program.

The normal trace was `fstatat`, `fsync` of that directory, `write` of the
record, then `fdatasync` of the file. Injecting `EIO` at `fsync` refused the
record without writing; injecting it at `fdatasync` refused it after the
bytes were written, as AUD04's corrected wording allows. Two additional
tests on the temporary copy checked that hooks are confined to their thread
and removed on unwinding. The hooks, their types and both calls are under
`cfg(test)`. The whole twelve-step matrix passed on the reviewed branch,
including the dialog and manager. The third round did not repeat the
individual probes for AUD01 to AUD04; their regression tests passed.

Mutation checks reported by the implementer in the three messages, all on
temporary copies with their own target directories:

- **The first version:** eleven mutations caught by tests: omitting the
  log-directory sync; syncing only on creation and forgetting a failure
  (the trap); forgetting a failure while keeping the identity check;
  syncing only on creation while keeping failed syncs pending; omitting
  the identity reset on creation or delaying it until the directory was
  found; omitting the parents' sync or reporting no directories made;
  writing before syncing; syncing the path's directory instead of the
  link target's; and never reporting that opening created the file. The
  creation-only variant with pending syncs kept passed the end-to-end
  test but failed unit tests. The cache-specific tests went away with
  the cache.
- **The fix of AUD01 to AUD04:** tests caught omitting the directory sync
  or the file check, syncing the wrong directory for a link, forgetting
  failed parent syncs, noting made directories only after total success,
  listing them only after making or checking them all, not queuing their
  parents, and writing before the syncs. Looking up the entry by its path
  and checking before syncing survived. Those survivors were not accepted
  as harmless: the former gained a test with the seam; the latter became
  the fix of AUD05.
- **The fix of AUD05:** tests caught syncing before checking, removing
  the sync step, looking up by path and leaving `ENOENT` unmapped. Moving
  a hook call outside `cfg(test)` failed to compile with and without
  features. Removing only the `fsync` call while keeping the step marker
  survived the repository's tests.

The reviewer reproduced the final round's mutations with
`cargo test -p rusthorse --all-features --lib <test>` on a temporary copy:
the old order failed
`a_substitute_at_the_check_is_refused_though_the_file_is_put_back_after`;
removing the sync step failed
`a_file_put_back_before_the_check_is_synced_after_it`; lookup by path and
unmapped `ENOENT` each failed
`a_file_moved_out_of_the_opened_directory_is_refused_though_the_path_finds_it`.
The unguarded hook call failed library builds with both feature sets.

Removing only `fsync` survived every test in the repository according to
the implementer; the reviewer reproduced its survival in the audit unit
suite (22 tests, including the two added probes). It is **not harmless by
design**. Only the reviewer's external probe caught that mutation: the
trace lacked `fsync`, and with
`strace -e inject=fsync:error=EIO:when=1` the original refused without
writing while the mutant returned `Ok` and wrote 125 bytes. The markers
alone do not prove a system call happened. Making an equivalent external
check permanent is the reviewer's recommendation, left to the maintainer.

The final end-to-end test covers a user-visible change: a log directory
the agent can write and search but cannot read (mode `0300`) now refuses
every gated action. After an initial successful run, it checks four
approved requests refused, including one into the existing log and three
after its removal, with no command started, the vault unchanged and no
record appended; after mode `0700` is restored, the run and removal succeed.
Another visible change is that a rename, replacement or removal of the log
by another program that still stands at the check refuses that action.
On a file system whose directories cannot be synced, the agent likewise
refuses gated actions and keeps an attempted unlock locked, following the
vault saves' treatment of sync errors.

**Checks on main before this record was added.** The reviewer ran all
twelve steps again on the staged audit-log change combined with "Set the
broker's limit of 100 request headers itself", rather than relying on the
branch's earlier results. All passed, with `CARGO_BUILD_JOBS=5`,
`RUST_TEST_THREADS=5`, the feature sets run in sequence and the GTK tests
using their virtual displays:

| Step | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all --check` | Passed. |
| 2 | `cargo clippy --all-targets --all-features -- -D warnings` | Passed. |
| 3 | `cargo clippy --all-targets -- -D warnings` | Passed. |
| 4 | `cargo test --all-features` | 616 passed, 2 ignored. |
| 5 | `cargo test --no-default-features` | 509 passed, 2 ignored. |
| 6 | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | Passed. |
| 7 | `cargo +1.89 check --all-targets` | Passed. |
| 8 | `cargo +1.89 check --all-targets --all-features` | Passed. |
| 9 | `cargo clippy -p rusthorse-dialog --all-targets -- -D warnings` | Passed. |
| 10 | `cargo test -p rusthorse-dialog` | 4 unit and 5 virtual-display tests passed. |
| 11 | `cargo clippy -p rusthorse-manager --all-targets -- -D warnings` | Passed. |
| 12 | `cargo test -p rusthorse-manager` | 45 passed. |

With and without features respectively: 225/224 library tests, 20/20 CLI
tests, 181/160 agent tests, 1/1 descriptor-alignment tests, 4/4 KeePass
compatibility tests, 25/25 packaging tests, 45/45 broker unit tests, 80/30
broker integration tests and 35/0 system tests passed. The descriptor-limit
test's child rerun is not counted twice. The two existing ignored tests
were the real KDF timing and the test requiring `keepassxc-cli`; they were
not run. Tests ran as uid 1000, so the permission checks did not skip as
root. The suites' temporary directory was empty afterwards.

Not checked by these reviews: power loss or physical file-system recovery.
The traces establish the calls and their order, not what the hardware
persists. The third round did not force a change inside the kernel while
`fsync` was running. No general guarantee for other file systems or for an
uncooperative program rotating the log follows from these probes. The
benchmark was reported by the implementer, not independently measured.

Left to the maintainer, with no acceptance or further fix recorded here:

- **P12's residual across restarts.** A later agent process does not know
  of a directory an earlier process made and could not sync. The reviewer
  asks for the maintainer's explicit acceptance of that limit.
- **P12's contract for other programs and paths.** After the check, the
  names another program gives the file are its own to sync. Directories
  the agent did not make, and a symbolic link to the log with the
  directories on the way to it, are taken as durable and not changing.
  These assumptions also need the maintainer's explicit acceptance; the
  ready verdict is within them.
- **The same gap elsewhere, outside this change.** Read in the code, not
  exercised by a crash test: creating a vault (`Vault::unsaved`, then
  `ensure_private_dir`) and `settings::save` make missing directories but
  sync only the file's own directory, not each newly made directory's
  parent. Nothing in these paths was changed to close that gap.

**2026-11-10 — Stop a request whose requester goes away during its dialog.**

The first behaviour that the documentation audit of 2026-11-09 left to the
maintainer is closed, within P16 and L26's limits below. A connection was
not watched while a dialog was open: the dialog stayed when the requester
left, and what the human allowed was done. The agent now polls the borrowed
connection, never reads it. A close or shutdown both ways counts as a
departure for any request; a half-close counts only for `run` and
`broker_run_v2`. Unread bytes, including a
run's empty stdin frame, are left for the run's watch. While waiting for a
dialog's answer, the agent watches both sockets under the same deadline;
a departure wins over an answer noticed with it. The dialog's process group
is killed and its leader reaped by the same path as at its deadline. A
request that left while waiting for its turn gets no dialog when its turn
comes, and no later dialog of that request is shown.

After the dialogs, checks precede the effects according to P16's final
rule: after waiting for a dialog's turn, the agent's state lock, an audit
record, brokers to end or start, or a read from outside. The registry's own
lock is a stated exception, not a claim that every wait is followed by a
check. The dialog path records `requester_gone`; a check before an effect
records `aborted`. A stopped request gets no answer even if that record
fails. The connection is shut down; no new cancellation error is sent.
There is no protocol bump: no wire message, field, framing or error-code
guarantee changed; a half-close already cancelled a run. The outcomes are
strings in the audit log. The existing `poll_raw` unsafe block and its
`SAFETY` comment moved to `supervise`; the fix of CON02 made the wrapper a
single system call, smaller than before. No unsafe block or dependency was
added.

The work began with the implementer's design proposal (Claude Opus 5.5,
AI-assisted), which the maintainer's coordinating agent approved with
conditions: no duplicated descriptor outliving the request; a narrow
`Connection` parameter for the `Ui` methods rather than the requester's
identity; a vault kept locked when the requester left after the right
password; and a dated amendment to ADR 0006, not a new ADR. The five commit
messages are all dated 2026-11-10; this entry records the four reviews and
the final confirmation of that work.

The first review (Codex, AI-assisted) found CON01 to CON04. Before the
second review, the coordinating agent sent an intermediate fix back: the
unlock still recorded `unlocked` for a requester it already knew was gone,
and the message claimed mutations that had not run. The final fix, "Check
for a departed requester after every wait, not only dialogs", put the
checks under the state lock where needed, added checks before and after the
unlock and password-change records, and reported the completed mutations
below. The work was rebased onto main after the audit-log directory-sync
change; the test-only count of records waiting for the audit log was
adapted to that implementation. The second review confirmed CON01 to CON04
fixed and found CON05 to CON07.

The coordinating agent then asked for a rule and a table of every effect.
Preparing the table found another defect: a run's grants' `created`
records had no departure check. "Check the requester after every wait on
the way to each effect" added those checks and fixed CON05 to CON07. The
third review confirmed those fixes but found CON08: waits for the grant
registry still followed the last check, contradicting the proposed rule.
The coordinating agent chose to name the waits covered, leave the
registry's lock as a stated limit and narrow that limit where cheap.
"Bound the departure checks by what they cover (CON08)" moved the check
before broker start past token and install preparation, checked again
after a new vault's barrier before publishing it, and checked after an
unlock's grants ended before writing `unlocked`.

The reviewer considered that a defensible choice of scope, pending the
maintainer's acceptance, but disagreed with its justification as a
technical impossibility: a check could be made inside the registry, and
"short work" does not bound the time waiting for its lock. The fourth
review confirmed the functional fixes and the remaining limit, but found
CON09 low in the wording of the audit window. "State the window of a
record without its effect exactly (CON09)" corrected it and added the
recommended behavioural test of the unlock's check before its barrier.
The final confirmation found the whole change **ready**, within the
limits whose acceptance remains the maintainer's below.

Findings and their dispositions:

| Finding | Disposition |
|---|---|
| Medium — CON01: a backup whose requester left while queued behind another request's unlock was still written; the early return from `ensure_unlocked` bypassed the dialog checks. | **Fixed:** backup checks after acquiring the state lock. The same rule was applied to vault writes, settings, reveals, run values and unlock publication through `state_unless_gone`, `with_vault_unless_gone` and the commit helpers. Confirmed in the second review. |
| Medium — CON02: `poll_raw` retried an interrupted poll with its original timeout, allowing interruptions to extend the deadline without bound. | **Fixed:** one poll call returns `Interrupted`; `poll_by` recalculates the remaining time, and `read_by` stops at its deadline. `Watch` and the zero-time connection check retry interruptions themselves. Confirmed in the second review; the external checks and remaining test gap are below. |
| Low — CON03: a failed `requester_gone` record turned a stopped request into an error reply. | **Fixed:** `dialog_abandoned` preserves the unanswered result when recording fails. Confirmed in the second review, including the fail-closed audit path. |
| Low — CON04: zenity's two surviving mutations were called harmless, but mapping a taken-down dialog to a timeout also answered the stopped request with `cancelled` or `denied`. | **Fixed:** `typed_from` and `approval_from` preserve `RequesterGone` and have unit coverage. Confirmed in the second review; the original harmless-survivor claim is withdrawn. |
| Medium — CON05: `create_vault` waited for its `created` record after its last check, then created and unlocked the vault for a requester that had left. | **Fixed:** check after the record before creating the file, and under the state lock before publication. A departure during creation leaves a file on disk, locked. Confirmed in the third review; CON08 subsequently covered the registry wait after that state check. |
| Medium — CON06: `keyring_items` waited for the state lock after checking the connection, then asked the keyring; a completed listing could also be stored after its requester left. | **Fixed:** check under the state lock before asking, release it for the keyring call, and check again under the lock before keeping the listing. The requester's start time is read before that last lock. Confirmed in the third review. |
| Low — CON07: the documents limited a record without its effect to a departure after the record had been written, omitting earlier waits and the possibility that best-effort `aborted` is missing. | **Fixed, with the final boundary corrected by CON09:** the window is between the checks, and the earlier record can stand alone. The third review confirmed the then-described wider window; the fourth found the later wording too narrow again. |
| Medium — CON08: the registry's mutex could be waited for after the last check, allowing a new vault to be published or a broker to start after departure; an unlock's barrier could revoke a grant too. The rule promised more than the code guaranteed. | **Narrowed in code and bounded in the contract:** check immediately before broker start after preparation, after the new vault's barrier before publication, and after unlock containment before `unlocked`. The fourth review's probes confirmed no broker start, a created vault kept locked, and a grant still revoked by the unlock barrier. That protective revocation and provisional run-grant registration remain stated limits requiring acceptance. |
| Low — CON09: the revised documents said a record without its effect remained only when departure occurred while waiting for the audit log. An unlock or password change could also wait for the state lock after the record was complete. | **Fixed and confirmed:** P16, L26, the protocol and comments bound the window by the check before the record and the check before the effect (for a grant, the next check), naming the intervening waits. No production logic changed in this final fix. |

**First review: not ready.** The reviewer traced the approval and effect
paths, borrowed descriptors, dialog supervision, audit failures and the
error contract. A channel and the queue's counter placed the backup behind
an unlock; it still wrote after its requester left (CON01). With
`strace -f -e trace=poll -e inject=poll:error=EINTR:delay_enter=10ms:when=1..10`,
ten interruptions made a 50 ms deadline take about 155 ms in three runs,
against 50.15 ms without injection (CON02). A run half-closing while its
audit path became invalid got `internal` instead of an unanswered close
(CON03). The queue test's 200 ms sleep did not prove the position
deterministically; the fix replaced it with a channel and the queue's
counter.

On a temporary copy the reviewer disabled `stop_if_gone` (the table's
late-departure test failed), treated every half-close as a departure
(`only_a_run_is_ended_by_a_half_close` failed), removed the second run
check (the departure-during-broker-start test failed), and removed the
watching in `read_by` (the dialog take-down test failed). M38 and M39,
zenity's two `None` conversions changed from `RequesterGone` to a timeout,
survived the 20 existing UI tests. Two additional tests with a stand-in
executable and no display passed on the original and caught M38 and M39
respectively, establishing CON04. Twelve runs of the end-to-end filters
(`requester_leaves` and `the_keyring_is_not_listed_for_a_requester_that_left`,
three runs at a time, `--test-threads=4`) passed 120 tests; six runs of the
unit filters, three at a time, passed 42. No flake was found. The whole
matrix passed.

**Second review: not ready.** CON01 to CON04 were confirmed fixed.
Interposing 20 poll interruptions made a 200 ms deadline finish at
202.5 ms with decreasing timeouts. The failed-record test was repeated
with the audit directory at mode `0300`. Probes held the audit log before
`create_vault`, held the state mutex before a keyring query whose stand-in
service socket observed the connection, and held the log and confirmed it
empty before disconnecting an unlock or password change. These exposed
CON05 to CON07. The reviewer also checked a zero deadline, an answer and a
departure available together, and failure of the audit's sync.

The reviewer reproduced R01, R14, R15, R17, R18, R20 and R21, each failing
as expected: R01 restored the backup defect; R14 answered an error again;
R15 made 101 calls all with 200 ms; R17 and R18 failed
`zenity_answers_mean_what_they_say_and_a_dialog_taken_down_none`; R20
removed the unlock's check after its record and R21 the password change's
check before its record. R16 hung a read probe whose deadline had passed;
the reviewer stopped and reaped it after three seconds. Counting that as
a detection is valid with a bounded watchdog, not an unbounded test run.
External interposition also confirmed the retries in `Connection::gone`
and `Watch`; removing each made its probe fail.

The range-diff of the original first version against its rebased version
showed only a CHANGELOG context change; section 11 was identical to main,
and the audit-log waiting count was wholly under `cfg(test)`. Ten rounds
of 14 selected unit tests and nine `requester_leaves::` tests, with three
CPU-load processes, passed 230 executions. The whole matrix passed,
including 640 tests with all features and 532 without default features.

**Third review: not ready.** CON05 to CON07 were confirmed fixed. The
reviewer traced the effect table and held the actual registry mutex in
independent probes, each repeated five times under load. `create_vault`
answered successfully with the vault unlocked and only `created` on
record. The unlock barrier changed a grant from `starting` to `revoked`
after departure, leaving the vault locked and `unlocked`, then `aborted`.
A broker started and its grant ended with `created`, then `ended`; no
command ran. These were CON08. A private FIFO named by `TZ` showed that
`chrono::Local::now()` held the registry lock while waiting to read the
timezone. Another probe left `allowed_for_1m`, then `aborted`, one remembered
approval and the idle lock postponed. A vault created and kept locked was
recoverable: another creation returned `AlreadyExists`, and a later unlock
worked.

The reviewer reproduced five mutations, each killed with exit status 101:

- M1, no check after `created`:
  `a_vault_whose_requester_left_while_its_creation_was_recorded_is_not_created`.
- M2, publication with a plain state lock:
  `a_vault_created_for_a_requester_that_left_meanwhile_stays_locked`.
- M3, the keyring's first check replaced with a plain lock:
  `the_keyring_is_not_asked_for_a_requester_that_left_while_it_waited`.
- M5, no check before each grant's record:
  `no_grant_is_recorded_as_created_for_a_requester_already_gone`.
- M6, no check after the grant records:
  `no_broker_is_started_for_a_requester_that_left_while_its_grants_were_recorded`.

M4 and M7 to M9 were not independently reproduced in that round. Fifteen
rounds of 19 unit and 10 integration tests with three CPU-load processes
passed 435 executions. The whole matrix passed, including 646 tests with
all features and 536 without default features.

**Fourth review: not ready only for CON09.** The reviewer read all 24 rows
of the final table, the registry's critical sections and the test gate
under `cfg(test)`. Probes again held the actual registry mutex: no broker
started; the created vault stayed locked; the unlock's grant was revoked
but only `aborted`, not `unlocked`, was written. The `TZ` FIFO probe
confirmed that the registry lock was now available during that read.
Another probe completed the `unlocked` record while the requester was
still connected, held the state lock, then closed the connection:
`unlocked`, `aborted`, and a locked vault proved CON09.

The reviewer independently reproduced N1, N2 and N3: the selected
regression tests failed with exit status 101. An independent behavioural
probe also caught M13, the unlock's pre-barrier check changed to a plain
lock: the original left the grant `starting`, the mutant made it
`revoked`. Fifteen rounds of 22 unit and 10 integration tests passed under
three CPU-load processes (480 executions); five rounds of five independent
probes passed too (25 executions). All twelve checks passed: 649 tests
with all features, 539 without default features, two existing ignored
tests in each, 9 dialog tests and 45 manager tests.

**Final confirmation: ready.** The reviewer compared every changed
sentence and both comments against the unlock, password change, vault
creation and grant preparation paths. The new
`an_unlock_whose_requester_left_before_its_barrier_ends_no_grant`
passed on a temporary copy. Replacing the check before the barrier with a
plain state lock (M13) failed it with `["revoked"]` instead of
`["starting"]`, not merely a different audit detail. The test also checks
that the vault remains locked, the generation unchanged, the result
unanswered and the unlock outcomes just `aborted`. This closes the fourth
review's recommendation for a permanent behavioural test. The reviewer
ran `cargo test -p rusthorse --all-features --lib <test>` for the original
and mutant with a target directory and private `TMPDIR` of their own,
then ran the whole matrix on main as recorded below. Copies and temporary
targets were removed; no real vault, audit log or keyring was used.

The implementer's mutation reports, read in the five commit messages,
are separate from the reviewer's reproductions above:

- **The first version:** 37 of 39 caught. They covered watching the
  requester in the shared wait and both dialog drivers, close and
  half-close handling, the pre-dialog and pre-effect checks, outcome
  mappings, suppressing replies, carrying the connection in `Peer`, and
  the manager's refused tone. The two zenity timeout conversions survived;
  CON04 showed that they were not harmless and added direct coverage.
- **The fix of CON01 to CON04:** R01 to R21 reported caught, covering the
  checks after waits, the failed-audit unanswered path, deadline handling,
  zenity conversions, and checks on both sides of the unlock and password
  records. The implementer detected R16 by two dialog tests hanging until
  an external 300-second limit; the reviewer's three-second probe above
  was a separate run.
- **The fix of CON05 to CON07:** M1 to M9 reported caught: checks after
  `created`, before publishing the vault, before asking and keeping a
  keyring listing, before each grant's record and before broker start;
  the final run check, its values check and the early vault-creation
  check were retested. M8 initially survived until the broker-run test
  asserted the stopping point. Its removal on an ordinary run without
  grants was harmless by design because the final check follows without
  an intervening wait; that is not a claim about the broker-run path.
- **The fix of CON08:** N1 to N3 reported caught, respectively moving the
  broker-start check back before preparation, removing the new publication
  check, and removing the check before `unlocked`. M2, M5, M6 and the
  unlock's pre-barrier check, called M13 in this round, were rerun too.
- **The fix of CON09:** no production logic changed. The new behavioural
  test caught M13, replacing the unlock's pre-barrier check with a plain
  state lock.

The two `Interrupted` retries, in `Watch` and `Connection::gone`, still lack
repository mutation coverage. The reviewer checked them by external
interposition; they are not harmless omissions by design, nor impossible
to test. Without the former retry a signal can cancel a live run; without
the latter a departure can be missed by that check. A permanent equivalent
check, by a test seam or an external harness, remains the reviewer's
recommendation for the maintainer, not work claimed done here.

Users can see a dialog disappear when they stop `rusthorse`, close the
manager's window or abandon a tool call that closes its connection. A
stopped request gets no reply; an existing client cannot infer from that
alone that no effect happened, and retains its unknown-outcome handling.
`rusthorse audit` shows the recorded outcome. In the manager's History,
`requester_gone` has the refused tone and appears in **Denied or not
answered**; `aborted` is plain text in **All records**, and in the
applicable action filters, not in that refusal filter. A vault created
while its requester left remains on disk, locked; a later request may
unlock it, and another creation does not replace it.

Wire compatibility does not mean library source compatibility: `Peer`
now has a lifetime parameter, `Failure` has a private `unanswered` field
(preventing external struct literals), the three dialog methods of `Ui`
take `Connection`, and `Decision` and `Typed` gained `RequesterGone`.
Implementations and exhaustive matches using those public items must adapt.
The borrowed descriptor's lifetime is checked by a compile-fail doctest.

**Checks on main before this record was added.** The staged tree was
verified identical to the reviewed branch's tip. All twelve steps ran on
that working tree, including the broker header-limit and audit-log changes
already on main, with `CARGO_BUILD_JOBS=5`, `RUST_TEST_THREADS=5`, a private
`TMPDIR` of mode `0700`, the feature sets in sequence and GTK tests on
their virtual displays. All output was read; all steps passed:

| Step | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all --check` | Passed. |
| 2 | `cargo clippy --all-targets --all-features -- -D warnings` | Passed. |
| 3 | `cargo clippy --all-targets -- -D warnings` | Passed. |
| 4 | `cargo test --all-features` | 650 passed, 2 ignored. |
| 5 | `cargo test --no-default-features` | 540 passed, 2 ignored. |
| 6 | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | Passed. |
| 7 | `cargo +1.89 check --all-targets` | Passed. |
| 8 | `cargo +1.89 check --all-targets --all-features` | Passed. |
| 9 | `cargo clippy -p rusthorse-dialog --all-targets -- -D warnings` | Passed. |
| 10 | `cargo test -p rusthorse-dialog` | 4 unit and 5 virtual-display tests passed. |
| 11 | `cargo clippy -p rusthorse-manager --all-targets -- -D warnings` | Passed. |
| 12 | `cargo test -p rusthorse-manager` | 45 passed. |

With and without features respectively: 247/245 library tests, 20/20 CLI
tests, 192/169 agent tests, 1/1 descriptor-alignment tests, 4/4 KeePass
compatibility tests, 25/25 packaging tests, 45/45 broker unit tests, 80/30
broker integration tests, 35/0 system tests and 1/1 compile-fail doctests
passed. The descriptor-limit test's child rerun is not counted twice.
The two existing ignored tests are the real KDF timing and the test
requiring `keepassxc-cli`; neither was run. Tests ran as uid 1000, so
permission checks did not skip as root. The temporary directory was empty
afterwards. No package was installed or service changed. The confirmation
and matrix preceded this documentation-only recording step; they were not
rerun merely to add the history.

Not checked: every possible interleaving, formal liveness or timing bounds,
real secrets or the real keyring, or dialogs on the maintainer's screen.
The GTK suites use virtual displays; stand-in dialog processes and unit
mappings do not constitute a new manual zenity compatibility test. The
final confirmation reran M13 and the complete matrix, not every earlier
mutation, external interposition probe or load experiment. Its production
code was unchanged from the fourth review; only documentation, comments
and the new test differed. The older dated history, including the broker
and audit-log entries, is left intact.

Left to the maintainer's explicit acceptance; no acceptance is recorded
by the ready verdict:

- **The registry lock is outside the guarantee.** A barrier may end grants
  after the requester left; those protective revocations stand. A run's
  grants can be entered provisionally and then ended by the next check,
  before being recorded or started. The reviewer considers this a
  defensible scope choice, not a technical impossibility of checking more;
  short critical sections do not bound lock acquisition time.
- **The human's answer stands.** An "Allow for N" can be remembered, and
  the idle lock postponed, for a requester that left as the human answered.
  Its approval record can be followed by `aborted`.
- **Broker start and activation are one step.** Credentials can reach the
  agent's own brokers after departure during that step. The next check
  ends them before starting the command; tokens leave only with the
  command.
- **An effect under way is not undone.** A save or backup can complete;
  a vault created during departure stays on disk, locked. A departure
  after the final command check is handled by the running command's watch.
- **`aborted` is best effort.** A preceding `unlocked`, `changed` or
  `created` record may stand alone without the corresponding effect.
  The relevant departure window is between the checks, including the
  intervening audit operation, subsequent state-lock wait or grant
  preparation as CON09 now states; not only the wait for the audit log.

**2026-11-10 — Keep restoring a backup a manual procedure.**

ADR 0007 section 5 planned an agent-owned `restore` operation, a CLI
command and a manager button ("Manager 3/6"). A design had been made,
estimated at about 2,100 lines over the vault, the agent, the CLI and the
manager, with protocol 12, and the maintainer had answered its two open
questions. Before any code was written, the maintainer asked what it gave
that KeePass and the file itself do not, and decided: no restore through
the agent. Restoring stays a simple, direct manual procedure for two
cases: bringing a backup up on another computer after a theft, and
putting one back after a key was deleted by mistake. The maintainer's
agent had carried the planned item forward without asking that question
first. The maintainer also observed that the master password is what
encrypts and decrypts a backup: that was already the code's behaviour,
since a backup is a byte copy of the encrypted KDBX file.

The change was written by the maintainer's agent (Claude Fable 5.2), not
by a subagent. No code of the agent, the vault or the CLI changed.
`docs/installation.md` now gives the two procedures: on another computer,
put the backup at the vault's path, set mode `0600` and unlock, without
`init`; on the same computer, lock, keep the current file, copy the backup
over it and unlock. `rusthorse lock` and `rusthorse unlock` replace
stopping and starting the service. The guide explains when
`vault.kdbx.bak` can undo a save, the password a backup needs, and
recovering one entry by opening a backup copy in KeePassXC and adding it
again. It now says to make a new backup after changing the password and,
if the old password leaked, delete backups made with it.

The manager's Import & backup page describes manual restoration instead
of promising a later restore feature. The decision is also in
`docs/roadmap.md`, ADR 0007 (dated additions, leaving the original decision
readable), `docs/manager.md`, `docs/protocol.md`, `docs/cli.md`,
`docs/getting-started.md`, `docs/design/manager/README.md` and the
CHANGELOG. The prototype's simulated restore remains a historical
reference; its README says that it will not be built.

Three end-to-end tests in `tests/agent.rs` pin what the procedure relies on:

- `a_backup_put_back_by_hand_is_the_vault_at_the_next_unlock`: lock,
  preserve the current file, put the backup back and unlock without
  restarting the agent. The old password and removed entry work again,
  another entry can be saved, and the preserved file opens with the newer
  password and keeps its later state.
- `the_file_from_before_the_last_save_undoes_that_save`: the `.bak` of a
  successful removal brings the removed entry back after lock and unlock.
- `a_backup_put_where_no_vault_is_opens_as_the_vault`: an agent with no
  vault opens the backup put at its path, without `init` or a restart.

No mutation check applies to this change, since no runtime behaviour was
changed. The new tests pin existing behaviour; they do not promise that
every failed save leaves a usable `.bak`, or that `lock` is exclusive.
The reviewer did not run mutations.

The first review (Codex, AI-assisted) was **not ready**, with two low
findings and no medium or higher finding. After the wording was changed,
the confirmation on the same day is **ready**, with both findings fixed
and no new finding:

| Finding | Severity | Disposition |
|---|---|---|
| RST01 — The `.bak` paragraph promised to undo the last change without the failure cases, and said `passwd` deletes it without the cleanup exception. | Low | **Fixed:** the guide limits undo to a successful save, asks the reader to check the file, says when it is absent and that a failed save may leave a different version, and says `passwd` reports a failure to delete it. The CHANGELOG now says when `.bak` *can* undo the last save. Confirmed against the initial write, hard-link and rename order, cleanup and the agent's warning. |
| RST02 — The guide said `lock` leaves the agent holding nothing of the old file and saving nothing during the copy, although another approved unlock can reopen it. | Low | **Fixed:** the guide says the open vault is dropped, requires that no unlock dialog be answered until the copy is done, and tells the reader to lock again after copying if one was answered. Confirmed against `State::lock`, `ensure_unlocked` and the file open at unlock. It no longer promises exclusivity or the removal of every retained copy. |

The reviewer read lock and unlock, the content fingerprint and unlock
barrier, remembered approvals, grants, the keyring listing, backup and
save, and the service's startup paths. Lock drops the open vault and
clears remembered approvals and the keyring listing; explicit lock ends
all grants. The last content fingerprint is kept for the next unlock.
A new unlock reads the file; an already unlocked vault is used from
memory. A missing settings file uses defaults, and socket and audit
directories are prepared independently. A repository search found no
other current promise of restore through the agent; the superseded ADR
text and the identified prototype remain historical.

The first review's external probes, using only temporary files and fake
values, checked the cases the normal-path tests do not cover:

- Interposing `rename` to fail with `EIO` after the backup hard link left
  `.bak` and the vault at the same inode. The entry recoverable from the
  former `.bak` was no longer there, and `cp vault.kdbx.bak vault.kdbx`
  refused with exit 1 because they were the same file.
- Interposing `unlink` to refuse the cleanup after a password change let
  the save succeed with a warning. The `.bak` remained and opened with
  the old password; the live file opened with the new one.
- With a scripted agent, `lock`, then another request whose unlock was
  answered, then the copy and the final `unlock` left reads using the old
  in-memory vault. A later save was refused because the file had changed
  and locked the vault; the next unlock read the restored file.
- With umask `002`, `mkdir -p` made mode `0775` and `cp` made a new file
  of mode `0664`. The agent accepted that file; the documented `chmod 600`
  also worked. Copying over an existing `0600` file with `cp` kept that
  mode, unlike `std::fs::copy`, which copies the source permissions.
  The guide's commands therefore do not rely on the tests' copy semantics.
  By reading the code, `doctor` fails the file at `0664`, accepts its mode
  at `0600`, and does not check the vault directory's mode; `doctor` was
  not run.

**Checks by the reviewer.** The first review used `CARGO_BUILD_JOBS=5`
and a private `TMPDIR` of mode `0700`; feature sets ran in sequence.
Formatting, `git diff --check` and manager clippy with warnings denied
passed. These test runs all passed, 92 executions in total:

| Command | Tests selected | Result |
|---|---|---|
| `cargo test --all-features --test agent -- ...` | The three new tests named above. | 3 passed. |
| `cargo test --no-default-features --test agent -- ...` | The same three tests. | 3 passed. |
| `cargo test --all-features --lib vault::tests` | The vault module, including outside changes, failed sync and cleanup. | 34 passed. |
| `cargo test --all-features --test agent -- ...` | Password change; a lock during approval; explicit grant revocation; changed-file unlock and its barrier before audit; the two keyring-listing cancellation tests. | 7 passed. |
| `cargo test -p rusthorse-manager` | The manager, including its isolated widget tests. | 45 passed. |

The probes linked the compiled library and used scripted dialogs; they
made no source changes. Their files were removed, and no package or
service was changed. This confirmation reread the corrected sentences
against `src/vault.rs` and `src/agent.rs`, including the cleanup warning
and backup's unchanged encrypted bytes, and reran `cargo fmt --all --check`
and `git diff --check`, both passing. It did not rerun the earlier probes
or behaviour tests for these text changes.

**Checks reported by the maintainer's agent.** Before the three wording
corrections, its initial formatting check failed on one line of a new
test; it formatted that line before running the full matrix successfully.
All twelve `AGENTS.md` steps passed with a private `TMPDIR`: formatting,
both default-member clippy configurations, both feature-set test suites,
documentation with warnings denied, both MSRV 1.89 checks, and clippy and
tests for the dialog and manager. Its reported totals were 654 tests with
all features and 544 without, counting the descriptor test's child rerun,
9 for the dialog and 45 for the manager. After the wording corrections,
it reported `git diff --check`, `cargo fmt --all --check` and all 25 tests
of `cargo test --all-features --test packaging` passing. These are the
maintainer's agent's runs, not a full matrix repeated by the reviewer.

Not checked by the reviewer: a real systemd installation, KeePassXC,
`doctor` at runtime, power loss, or every filesystem failure and concurrent
writer interleaving. No real vault, audit log, socket or keyring was used,
and no dialog was shown on the maintainer's screen. The remaining matrix
steps were not repeated by the reviewer. L10 and L15 already cover old
copies and concurrent writers; no new protection is claimed for manual
restoration, and no property or limit was changed to record this review.

Left to the maintainer; no further decision is recorded here:

- The two manager items still planned in ADR 0007 deserve the same
  question: listing and revoking single remembered approvals, and an
  exclusive hand-off to KeePassXC. Individual revocation offers something
  more precise than `lock`; an exclusive hand-off could solve the
  concurrent-writer problem that `lock` does not. Neither was changed.
- Restoring a backup also restores its master password. Changing the
  current password does not protect older copies (L10); deleting a local
  backup cannot take back a copy someone else already has.
- Lock is not exclusive (L15). Keeping the service running is reasonable
  for this short manual procedure only with no other unlock answered
  during the copy. It also does not stop ordinary approved commands as
  stopping the service does.

After this review and its confirmation, the maintainer asked whether a
backup carries only the keys and the vault's password. A paragraph on
what it holds and excludes was added to `docs/installation.md`. The code
already copied the whole encrypted KDBX and no external agent state.
Codex (AI-assisted) confirmed this by reading `Vault::backup_to`, history
and removal in `src/vault.rs` and keepass 0.17.0, the default paths in
`src/paths.rs`, initialization in `src/agent.rs` and `src/broker_host.rs`,
and settings loading and audit creation in `src/settings.rs` and
`src/audit.rs`. The copied file also keeps groups, custom fields,
attachments, KDF parameters, deletion records and any recycle bin; values
in history or that bin are included even when Rusthorse does not list
them. Deletion records themselves hold identifiers and times, not the
removed values. Missing settings use defaults; a missing audit log is
created at the first record; approvals and grants start empty. The
maintainer's agent reported `git diff --check` and all 25 packaging tests
passing after the addition. This confirmation read the code and ran
`git diff --check`; it did not build or run tests.

**2026-11-11 — Choose where a backup goes in the manager.**

The maintainer asked to choose the backup's folder instead of typing an
absolute path. The form now has **Choose…**, which opens
`gtk::FileDialog::save` over it. It starts at a typed absolute path with a
file name, or offers `rusthorse-YYYY-MM-DD.kdbx`
(`rusthorse-backup.kdbx` if the date is unavailable). The chosen file fills
the field; cancellation leaves it unchanged. A selected file without a
local UTF-8 path shows an error. The request remains
`Request::Backup { path }`: no protocol, agent or security invariant changed.
`Vault::backup_to` still refuses existing files with `create_new(true)`,
even when the file dialog offers to replace one.

**Implementer's checks (Claude Code, AI-assisted).** Mutations ran in a
temporary copy with its own target directory, against
`window::tests::desktop_flow`:

- M1: do not put the chosen path in the field — caught.
- M2: do not start at the typed path — caught.
- M3: omit the form as the dialog's parent — caught.
- M5: offer a name without the date — caught.
- M4: clear the field on cancellation — survived the first version of
  the test.

A click emitted by the test outside the main loop makes FileDialog's
GTask deliver its callback from an idle. The old assertion ran before
that callback. With `drain()` before the assertion, M4 fails. All five
mutations were rerun after that correction and caught; the unmutated
version passed. Under load, 12 executions of `desktop_flow`, four at a
time with two processes occupying CPUs, all passed. These are the
implementer's results, not mutation runs repeated by the reviewer.

**Independent review (Codex, AI-assisted, 2026-11-11).** One low finding,
fixed during review; no medium or higher finding or outstanding finding
in the final version:

| Finding | Severity | Disposition |
|---|---|---|
| T01: cancellation checked too early. | Low | Fixed: `drain()`; M4 fails. |

The reviewer's standalone GTK 4.14.5 probe used a deliberately faulty
callback that cleared the field on cancellation. Before `drain()`, the
callback had not run and the unchanged-field assertion passed; afterwards,
it had run and the field was empty. Production cancellation already left
the field unchanged. Six additional `desktop_flow` executions, three
simultaneously, passed before the test correction. Formatting, manager
clippy and its 45 tests passed before and after it; their private
temporary directories were empty afterwards. Reading the handlers found
no new reference cycle; reading GTK 4.14.5's portal implementation
checked the parent, modality and returned file handling. This was not a
runtime test with a real portal or instrumentation for widget leaks.

**Final checks by the reviewer.** The working tree matched the staged tree
`e86de9e37794381b5d9407c176e9a4431639a4f2` on `main` throughout the matrix.
All twelve `AGENTS.md` checks passed: formatting; both workspace clippy
configurations; both feature-set test suites; documentation with warnings
denied; both MSRV 1.89 checks; and clippy and tests for the dialog and
manager. Commands ran sequentially with `CARGO_BUILD_JOBS=5`,
`RUST_TEST_THREADS=5` and a private `TMPDIR` of mode `0700`; GTK tests
used their virtual displays. All output was read.

| Test command | Passed | Ignored |
|---|---|---|
| `cargo test --all-features` | 653 | 2 |
| `cargo test --no-default-features` | 543 | 2 |
| `cargo test -p rusthorse-dialog` | 9 (4 unit, 5 Xvfb) | 0 |
| `cargo test -p rusthorse-manager` | 45 | 0 |

The descriptor-limit test's child rerun is not counted twice. The two
existing ignored tests are the real KDF timing and the one requiring
`keepassxc-cli`; neither was run. The suites included the agent's
end-to-end tests (195 with all features, 172 without) and the broker's
system tests (35 with all features, none without). The temporary directory
was empty after every step. No package was installed or service changed.
The matrix preceded this documentation-only record, left unstaged.

Not verified: a real `xdg-desktop-portal` (the widget test uses GTK's own
dialog because no portal serves its session), or a non-UTF-8 selection in
the manager. No dialog was shown on the maintainer's screen, and no real
vault, socket or keyring was used.

**2026-11-11 — Tell the broker parser's 400 and 431 apart.**

Closes the wording recommendation in the header-limit review of
2026-11-10. `docs/cli.md` and `src/guide/ai.md` called even a head that
only exceeds a limit "a malformed request". They now distinguish an
unparseable request (`400`) from a head over 32 KiB or 100 header lines
(`431`), both with empty bodies. Broker behaviour did not change.

**Independent review (Codex, AI-assisted, 2026-11-11): ready.**

| Finding | Severity | Disposition |
|---|---|---|
| None | — | Ready. |

The reviewer read the configured limits and Hyper 1.12.0 in Cargo's
registry: both header-size and buffer-size errors map to `TooLarge`,
answered with `431`. A probe drove the real broker through a simulated
control channel, with a fake credential. Requests lacked a token except
the last case, which supplied the grant's valid token:

| Input | Status | Body |
|---|---|---|
| Malformed request | 400 | Empty |
| Complete head, 32,768 bytes | 401 | Broker JSON |
| Complete head, 32,769 bytes | 431 | Empty |
| Incomplete head, 32,768 bytes | 431 | Empty |
| Incomplete head, 65,536 bytes | 431 | Empty |
| 100 header lines | 401 | Broker JSON |
| 101 header lines | 431 | Empty |
| Small head, 70,000-byte body | 401 | Broker JSON |
| Head exceeding 32 KiB after token-to-key expansion | 401 | Broker JSON |

The expansion refusal remains the broker's own `401`, not a parser
`431`. The reviewer ran
`cargo test -p rusthorse --all-features --bin rusthorse -- the_ai_guide`
(3 passed) and
`cargo test -p rusthorse-broker --all-features --test broker`
(80 passed). These probes and tests ran in the first review of this change.

**2026-11-11 — Sync the directories made for a new vault or the settings.**

Closes "The same gap elsewhere" in the audit-sync review of 2026-11-10.
`make_dirs` is public, and `util::sync_parents` syncs the parent of each
directory made. `Vault::unsaved` and `settings::save` call it before
writing, including for directories made before creation fails. A sync
error takes precedence over the creation error. A failed parent sync
writes no vault or settings file; the error contract is unchanged.

**Implementer's checks (Claude Code, AI-assisted).** Mutations ran in a
temporary copy with its own target directory, using
`cargo test --all-features --lib -- vault:: settings:: util::`:

- V1: omit the vault's parent syncs — caught.
- V2: sync only after all vault directories were made — caught.
- S1 and S2: the corresponding settings mutations — both caught.
- U1: sync each directory itself rather than its parent — caught.
- U2: sync only the first parent — caught by a test added afterwards.
- U3: open the parents without calling `fsync` — survived.

U3 is not harmless. As with the audit log's missing-`fsync` mutation,
coverage of the actual syscall is still external: the reviewer's
`strace` and `EIO` probes below. Making that check permanent remains
with the maintainer. The reviewer did not rerun these mutations.

**Independent review (Codex, AI-assisted, 2026-11-11).** D01 exposed a
parent replaced by a FIFO: opening it blocked before `BeforeWrite`,
while `configure` held the state mutex. The fix opens parents with
`O_DIRECTORY`. The implementer's mutation removing that flag makes
`util::tests::the_directory_holding_each_one_made_is_synced` time out.

| Finding | Severity | Disposition |
|---|---|---|
| D01: opening a parent FIFO blocked. | Medium | Fixed: `O_DIRECTORY`. |

The reviewer confirmed the fix with interposed directory replacements:
settings and vault creation returned `NotADirectory` without writing;
settings reported `replaced=false`. Directories and links to directories
still worked. Earlier traces confirmed parent syncs before opening the
temporary file. Injecting `EIO` at either of two parent syncs wrote no
file; at the final directory sync, after publication, the vault returned
`NotDurable` and settings returned `replaced=true`. The existing mappings
preserve `outcome_unknown`, and local `init` exits 124 for `NotDurable`.
The filtered vault/settings/util suites passed in both feature builds:
58 passed and one KDF benchmark ignored in each. No power-loss test ran.

Remaining limit (P14): a later attempt does not know of a directory an
earlier attempt made and failed to sync. Names of directories the agent
did not make are taken as durable. The final review found the change ready
within those limits; A01, found in existing audit code, is recorded next.

**2026-11-11 — Open the audit log's directories as directories only.**

A01 was found during the 7f9 review in code from `18bb564`.
`audit::open_directory` used `File::open`: a FIFO replacing the log's
directory or a parent awaiting sync blocked a record while holding the
log mutex. It now delegates to `util::open_directory` (`O_DIRECTORY`),
also used by `sync_parents`; links to directories are followed.

The test-only `Step::Resolved` runs after canonicalization and before
opening the log's directory.
`audit::tests::a_fifo_in_place_of_a_directory_fails_records_at_once`
covers both paths, including two refusals for a FIFO kept pending. A
pending path is removed only after its sync succeeds: while it remains a
FIFO, every record fails without writing, rather than waiting for a
writer. This preserves fail-closed behaviour.

**Implementer's checks (Claude Code, AI-assisted).** In a temporary copy
with its own target directory, all four mutations were caught by
`cargo test --all-features --lib -- audit:: util:: vault:: settings::`:

- A1: restore `File::open` in the audit helper.
- A2: open the log's directory directly with `File::open`.
- A3: open a pending directory directly with `File::open`.
- A4: remove `O_DIRECTORY` from `util::open_directory`.

**Independent review (Codex, AI-assisted, 2026-11-11).**

| Finding | Severity | Disposition |
|---|---|---|
| A01: directory FIFOs held the log. | Medium | Fixed: shared helper. |
| A02: architecture overstated the flag's scope. | Low | Fixed: narrowed. |

Before the fix, the reviewer's probes blocked in both directory-opening
paths and held up a second record until a FIFO writer released them.
With the fix, two injected replacements in each path returned
`NotADirectory` without writing. A third record without replacement
succeeded, confirming lock release and retry of the pending sync.
The reviewer ran the 80 selected tests: 79 passed and one KDF benchmark
was ignored. The implementer's mutations were not repeated.

A02 extended `O_DIRECTORY` to the final vault/settings directory sync.
The architecture now limits that comparison to parents synced for newly
made directories. Left to the maintainer: the final directory syncs in
vault `write_file`, its `.bak` cleanup, settings `save` and
`backup_to` still use `File::open`. Those existing paths were not changed.

**Final matrix (Codex, AI-assisted, 2026-11-11).** The working tree
matched staged tree `04c9e7ca02989a5f98fbcff27a19a2066eed2ab4` throughout
all twelve checks. Commands ran sequentially with `CARGO_BUILD_JOBS=5`,
`RUST_TEST_THREADS=5` and a private `TMPDIR`; GTK tests used their own
virtual displays. All output was read. The matrix preceded these three
documentation-only records, left unstaged.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |
| `cargo clippy --all-targets -- -D warnings` | Pass |
| `cargo test --all-features` | 657 passed, 2 ignored |
| `cargo test --no-default-features` | 547 passed, 2 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | Pass |
| `cargo +1.89 check --all-targets` | Pass |
| `cargo +1.89 check --all-targets --all-features` | Pass |
| `cargo clippy -p rusthorse-dialog --all-targets -- -D warnings` | Pass |
| `cargo test -p rusthorse-dialog` | 9 passed (4 unit, 5 Xvfb) |
| `cargo clippy -p rusthorse-manager --all-targets -- -D warnings` | Pass |
| `cargo test -p rusthorse-manager` | 45 passed |

All steps exited zero. The descriptor-limit test's child rerun is counted
only once. The two existing ignored tests are the real KDF timing and the
one requiring `keepassxc-cli`; neither was run. Agent end-to-end tests
passed (195 with all features, 172 without), as did the 35 broker system
tests enabled with all features. The private temporary directory was
empty after every step. No package was installed or service changed.
A02 was confirmed corrected before this matrix; all three changes are
ready within the limits and maintainer follow-ups recorded above.

**2026-11-11 — Do not wait on a FIFO in place of the vault's directories
or files.**

Follow-up of A02: the final directory syncs of `Vault::write_file`, its
old-password `.bak` cleanup, `settings::save` and `Vault::backup_to`
used `File::open`. All of them run under the agent's state lock, which
`lock_if_idle`, `Request::Lock` and `lock_for` (suspend, screen lock)
take: a FIFO put in place of the directory made the save wait for a
writer, with the vault unlocked and no lock possible (P9). They now go
through `util::sync_directory` (`util::open_directory`, `O_DIRECTORY`),
which `sync_parents` uses too. The same class was found in two more
places under that lock. `Vault::backup_to` checked the vault file by
name and read it again by name: a FIFO swapped in between made the read
wait, and a backup needs no approval, so a requester could repeat it. It
now checks the fingerprint on the descriptor it reads, opened with
`O_NONBLOCK`. The backup's verification reopened the copy with
`File::open`; `Vault::open_with`, used by it and by unlock, now opens
with `O_NONBLOCK` and refuses anything but a regular file
(`invalid_request`; a directory failed later before, as `internal`). Test-only
hooks (`Vault::at`, and `before_dir_sync` in the settings) run at each
point; four tests put a FIFO there and require an answer within 10 s.

**Implementer's checks (Claude Code, AI-assisted).** In temporary copies,
each with its own target directory, every mutation was caught by
`cargo test --all-features --lib -- vault:: settings:: util::`:

- M1, M2, M3: `File::open` at the vault's sync after the rename, after
  the `.bak` cleanup, and at the backup's directory.
- M4: `File::open` at the settings' final sync.
- M5: no `O_NONBLOCK` in `Vault::open_with`.
- M6: no regular-file check in `Vault::open_with`.
- M7: `File::open` inside `util::sync_directory`.
- M8: the backup's check and read by name again (hook kept between).
- M9: no `O_NONBLOCK` on the backup's source.

On the tree reviewed below, before the records: `cargo fmt --all
--check`, both clippy runs, `cargo doc` with `-D warnings` and both MSRV
checks passed; `cargo test --all-features` passed 661 tests (2 ignored)
and `cargo test --no-default-features` 551 (2 ignored).

**Independent review (Codex, AI-assisted, 2026-11-11).**

| Finding | Severity | Disposition |
|---|---|---|
| K01: the audit log file is opened without `O_NONBLOCK`, under the log's lock: a FIFO in its place made every record wait for a reader. Pre-existing. | Medium | Fixed next, in its own change (below). |
| K02: the docs said that a FIFO fails the step at once; a backup that has checked the vault file copies it whatever is put in its place later, and a failed sync after the `.bak` cleanup is a warning. | Low | Fixed: the architecture and P9 say that a FIFO is not waited on, and what each case gives. |
| K03: an interposed `fsync` that did nothing on directories suppressed 137 calls, and the 83 selected tests still passed. | Info | Known (the surviving U3 mutation of the audit-log change); a permanent external check is a maintainer follow-up. |

The reviewer enumerated the opens under the state lock or the log's
lock: none of those in this change can wait on a FIFO (exclusive
creations fail on an existing name). Under the log's lock, the log file
itself could (K01), and so could the time zone file that
`chrono::Local::now()` reads when `TZ` names a FIFO (as in CON08): only
where the agent was started with such a `TZ`, which whoever starts it
chooses, as the rest of its environment. Under the state lock, a time
zone read when a grant is entered was not shown to wait with a constant
`TZ`. Probes: backups with a missing source (`vault_changed`),
the same bytes under another inode (`vault_changed`), an unreadable
source (an I/O error), FIFOs, directories and links to FIFOs at the
vault path, the directory and the backup's destination (all refused at
once). The error contract holds: after the vault or the settings file is
replaced, a failed sync is still `outcome_unknown`; a backup that fails
can leave its copy at the destination, as before. `O_NONBLOCK` left on a
regular file's descriptor does not change reads on Linux, and does not
keep a file system from stalling (L12).

**2026-11-11 — Refuse a FIFO in place of the audit log at once.**

K01, found in the review above, in code older than it: `open_log` opened
the log for appending without `O_NONBLOCK`, and with no check of what it
opened, under the log's lock. A FIFO put in place of the log made a record wait for a
reader — and every other record behind it, so every approval-gated
request and unlock — and, once it had one, wait again while the FIFO was
full. No record is made under the state lock, so the vault's locks still
took effect. The log is now opened with `O_NONBLOCK` (cleared once it is
open), `ENXIO` (a FIFO nobody reads) is reported as not a regular file,
and a descriptor that is not a regular file is refused before anything
is written. `audit::tests::a_fifo_in_place_of_the_log_fails_records_at_once`
covers a FIFO without and with a reader (nothing reaches it) and the
record that follows once the log is back.

Ten end-to-end tests (the three of `BlockedAudit` in `tests/agent.rs`,
the seven of `break_audit` and `hold_audit` in `broker/tests/system.rs`)
and one unit test used such a FIFO on purpose, for a disk that holds
records up or fails their sync after writing them. They keep it through
`AgentConfig::audit_fifo_waits` (`AuditLog::waiting_on_a_fifo`), which
restores the old open; `Harness::with_audit_fifo` and
`System::with_audit_pipe` set it, and every other agent, `rusthorse
agent` included, leaves it off. It is a field of the library's
configuration, like the other settings only tests use (`send_buffer`,
`broker_program`), not a flag, variable or setting the program reads.
The unit test now reads its FIFO without waiting, so that a knob that
does nothing fails it instead of hanging it.

**Implementer's checks (Claude Code, AI-assisted).** In temporary copies,
each with its own target directory: N1 (no `O_NONBLOCK`), N2 (no
regular-file check), N3 (no `ENXIO` mapping) and N5 (the knob ignored in
`open_log`) were caught by `cargo test --all-features --lib -- audit::`;
N6 (the knob ignored in `Agent::new`) by the three tests of
`BlockedAudit` (Cargo stopped there, before the broker's); N7
(`rusthorse agent` turning the knob on) by the test added for L01. N4
(`O_NONBLOCK` left set) survives, harmless by design: on Linux it does
not change writes to a regular file, and the flag is cleared only so
that the descriptor is the one an ordinary open gives.

**Independent review (Codex, AI-assisted, 2026-11-11).**

| Finding | Severity | Disposition |
|---|---|---|
| L01: no test kept `rusthorse agent` from turning the knob on; with `main.rs` changed to `true`, the 195 end-to-end tests passed while a FIFO log held up `rusthorse lock`. | Low | Fixed: `the_agent_program_refuses_a_fifo_in_place_of_its_audit_log_at_once` starts the real program on private paths, puts a FIFO in place of its log, and requires `rusthorse lock` to fail within the tests' limit, then to succeed once the FIFO is gone. |

The reviewer found K01 fixed and no way for the released program to turn
the knob on: `--audit-fifo-waits` is refused (exit 2), no environment
variable turns it on, and `audit_fifo_waits` in the settings file is an
unknown key. Probes against the library, traced with `strace -f`: a FIFO
without and with a reader, a link to a FIFO, a socket and a pseudo
terminal were refused (`InvalidInput`) with nothing written, a directory
with `IsADirectory`; after a refusal the same log wrote two records. A
reader that appears between the open and `fstat` does not make a FIFO a
regular file. The ten tests that use the knob still exercise waiting,
sync failure, revocation, limits and recovery; no other test writes to a
FIFO log without it. Clearing `O_NONBLOCK` is correct but not needed on
Linux regular files, and neither it nor the check bounds a stalled file
system or driver (L12). The reviewer ran `cargo test --all-features
--lib -- audit::` (22 passed), `--test agent` (195) and the broker's
system tests (35), and `cargo doc` with `-D warnings`; the error contract
is unchanged.

**Final matrix (Codex, AI-assisted, 2026-11-11).** The working tree
matched staged tree `fe82d669ecd593eba6f3e7620557c376f35ea76b` before and
after each of the twelve checks. This matrix covers the code of both
kuz (committed as `1b8862d`, included in this tree) and this K01 fix with
the L01 regression test. Commands ran sequentially after
`source ~/.cargo/env`, with `CARGO_BUILD_JOBS=5`, `RUST_TEST_THREADS=5`
and a private `TMPDIR` of mode 0700; GTK tests used their own virtual
displays. All output was read and all steps exited zero. Agent
end-to-end tests passed (196 with all features, 173 without), as did the
35 broker system tests enabled with all features. The descriptor-limit
test's child rerun is counted only once. The two existing ignored tests
are the real KDF timing and the one requiring `keepassxc-cli`; neither
was run. The private temporary directory was empty after every step.
No package was installed or service changed. This record was appended
after the checks and left unstaged.

| Command | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |
| `cargo clippy --all-targets -- -D warnings` | Pass |
| `cargo test --all-features` | 663 passed, 2 ignored |
| `cargo test --no-default-features` | 553 passed, 2 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | Pass |
| `cargo +1.89 check --all-targets` | Pass |
| `cargo +1.89 check --all-targets --all-features` | Pass |
| `cargo clippy -p rusthorse-dialog --all-targets -- -D warnings` | Pass |
| `cargo test -p rusthorse-dialog` | 9 passed (4 unit, 5 Xvfb) |
| `cargo clippy -p rusthorse-manager --all-targets -- -D warnings` | Pass |
| `cargo test -p rusthorse-manager` | 45 passed |

**2026-11-19 — The maintainer accepts the limits left by the reviews of
2026-11-10.**

A decision of the maintainer's, not a review: no code, property or limit
changed. Two reviews of 2026-11-10 found their changes ready within
limits that they left to the maintainer's explicit acceptance, and
recorded none. On 2026-11-19 the maintainer's agent (Claude Code,
AI-assisted) listed those limits to the maintainer, who accepted all of
them, as P12, P16 and L26 state them:

- From "Sync the audit log's directory entries before its records" (P12).
  An agent process started later does not know of a directory that an
  earlier one made for the log and could not sync. After the agent's
  check, the names another program gives the log are its own to sync; the
  directories the agent did not make, and a symbolic link to the log with
  the directories on the way to it, are taken as durable and as not
  changing.
- From "Stop a request whose requester goes away during its dialog" (P16
  and L26). A wait for the lock of the registry of grants is not followed
  by a check: the grants a barrier ended stay ended, and a run's grants
  can be entered and then ended by the next check, before any is recorded
  or started. The human's answer stands for a requester that left: an
  "Allow for N" can be remembered, and the idle lock postponed. The start
  of a run's brokers is one step, in which credentials can reach the
  agent's own brokers after the departure; the next check ends them
  before the command starts, and tokens leave only with the command. An
  effect under way is not undone. `aborted` is written best effort, so a
  record written before its effect can stand alone.

The acceptance is of these limits as the properties state them, no wider.
It does not make them impossible to narrow: the reviewer's remark stands
that a check inside the registry is a choice of scope, not a technical
impossibility. It does not cover the reviewers' recommendations, which
remain open and are not work claimed done: setting, testing and
documenting the broker's limits on a destination's response; a permanent
outside check that the `fsync` calls are made; and a permanent check of
the `Interrupted` retries in `Watch` and `Connection::gone`.

**2026-11-19 — Drop the manager's three unbuilt features.**

The review of 2026-11-10 that kept restoring a backup manual left a
question to the maintainer: whether the two manager items ADR 0007 still
planned deserved the same answer. On 2026-11-19 the maintainer's agent
(Claude Code, AI-assisted) put that question to them and to a third item,
which the manager's Edit form announced, said what each would add to what
is there already, and recommended dropping the three; the maintainer
agreed.

- **Listing and revoking single remembered approvals** (ADR 0007, section
  4). Remembered approvals are off by default; `status` and the manager's
  Status page count them, and a lock forgets them all. The requests would
  have added a way to forget one instead of all.
- **The exclusive hand-off to KeePassXC** (section 6): a mode of the agent
  that refuses to unlock and to save until released. Editing in KeePassXC
  stays the manual procedure of the installation guide. The reviewer's
  remark of 2026-11-10 stands: such a mode could solve the concurrent
  writer that a lock does not (L15). That limit is kept, not closed.
- **Editing notes in the manager.** `rusthorse edit --notes` and KeePassXC
  change them. The manager's forms carry metadata only, and notes are
  withheld like a value.

What changed: the manager's page of remembered approvals and the note of
its Edit form say this instead of announcing a later version, and its
message for a protected field no longer names a hand-off. The roadmap,
ADR 0007 (a dated amendment, with the original text left readable), the
manager's guide, the prototype's note, the README and the CHANGELOG say
the same. L8 now says that remembered approvals are not listed and that
one cannot be revoked alone, and L15 that a lock does not reserve the
vault and that no mode of the agent will; section 10 no longer plans the
page. The installation guide's steps for editing in KeePassXC gained what
the hand-off was for: do not answer an unlock dialog until the database
is closed. No property changed, and no code of the agent, the vault, the
CLI or the protocol. The three texts are fixed strings with no test of
their own, as the restore note of 2026-11-10 was: no behaviour changed,
so no mutation applies.

**Independent review (Codex, AI-assisted, 2026-11-19).**

The initial review was **not ready**, with MGR01 low and no serious
correctness, security, concurrency or regression finding. Confirmation of
the staged tree at HEAD `f20ecd9` is **ready**: MGR01 is fixed and there is
no new finding. After undoing that wording correction in memory, the
aggregate SHA-256 of the 110 inventoried files matches the reviewed tree.
There was no other difference and no unstaged change before this record.

| Finding | Severity | Disposition |
|---|---|---|
| MGR01 — The new summary row said that two manager texts changed, but the diff changes three messages: the remembered-approvals description and Edit caption in `manager/src/window.rs`, and the protected-field error in `manager/src/model.rs`. | Low | **Fixed and confirmed:** the staged row says "Three messages in the manager and the documents changed". |

The reviewer read the full diff (10 files, 145 insertions, 39 deletions,
no new files) and the removed lines with `git diff HEAD -U0 -- | rg '^-'`.
No true, reviewed guarantee was lost or weakened. The code comparison
found only the three messages and the helper's rename in the two Rust
files; the agent, vault, CLI and protocol were unchanged.

For L8, the reviewer read `State::lock`, `status`, approval handling and
request dispatch in `src/agent.rs`, defaults in `src/settings.rs`, the
requests and status fields in `src/protocol.rs`, and the manager's Status
page. Lock clears remembered approvals; status counts unexpired ones;
the protocol's individual revocation belongs to broker grants, not
remembered approvals. Remembering is off by default.

For L15 and the installation paragraph, the reviewer read
`ensure_unlocked` and `Vault::write_file`, the CLI's initialization and
connection paths, and both supplied systemd units. Lock permits a new
unlock request. The two external-change checks remain, but the last
check and rename are not atomic. The paragraph preserves that limit.
"Nothing asks while the agent's service is stopped" was accepted in the
documented service setup: clients do not start an agent automatically.
It was not read as a guarantee against another agent started separately.

For notes, the reviewer followed `EntryArgs.notes` through the CLI's
`edit`, the agent's approval and commit, and `Vault::edit`: the supplied
text replaces the protected `Notes` field. It is a command-line argument,
so the guide's exposure warning is appropriate. The manager's forms leave
notes untouched, and metadata omits their contents. The three messages
match those paths; the StatusPage title and description contain none of
`<`, `>` or `&`.

Repository searches used `rg -n --hidden`, excluding `.git`, `target`
and `.env*`: feature references matched 124 lines in 27 files, KeePassXC
158 in 23, and future/planning wording 250 in 39. The relevant contexts
were checked across code, docs, packaging, the AI guide, AGENTS.md,
CONTRIBUTING.md, desktop files and the prototype. No current promise of
the three dropped features remained. Historical entries, superseded ADR
text and the explicitly identified prototype remain. The prototype
simulates restoration, remembered approvals and opening KeePassXC; it
does not edit notes. No other implementation commitment remained in
ADR 0007's milestones, and no control or feature was added.

A programmatic comparison confirmed that section 11's earlier content
was unchanged apart from the stated table pointer, excluding the new
row and entry. The new entry claimed neither an independent review nor
test results before this record was added.

**Checks run by the reviewer during the initial review.** Cargo commands
ran sequentially with a private `TMPDIR`; the test directories were empty
afterwards. Formatting and whitespace checks passed:

| Command | Result |
|---|---|
| `git diff HEAD --check` | Exit 0; no whitespace errors. |
| `cargo fmt --all --check` | Exit 0. |
| `cargo test -p rusthorse-manager` | 45 passed, 0 failed, 0 ignored, including isolated widget tests. |
| `cargo test --all-features --test agent -- ...` | The four filters below: 4 passed, 0 failed, 0 ignored, 192 filtered out. |
| `cargo build -p rusthorse --lib --all-features --message-format=json` | Exit 0; library used by the temporary probe. |

The four integration-test filters were:

- `remembered_approval_skips_the_dialog_for_identical_requests_only`;
- `notes_can_be_revealed_with_approval`;
- `a_backup_put_back_by_hand_is_the_vault_at_the_next_unlock`;
- `a_lock_while_the_password_is_typed_keeps_the_vault_locked`.

These were 49 test executions, plus a separate temporary probe compiled
with `rustc` against the library. It used a real agent, scripted UI,
temporary vault/socket/audit paths, fake values and the real CLI. A denied
`edit --notes` exited 4 and preserved the original notes; an allowed edit
persisted the replacement across reopening and preserved the password.
`show` withheld the notes. After lock, another request asked for an
unlock; an approved `reveal --notes` returned the persisted text. The
audit log omitted that text. With no agent at the private socket,
`unlock`, `edit --notes` and `list` each exited 1 with a connection error.
The probe process exited and its temporary files were removed.

The reviewer accepts no test of the three fixed messages themselves and
no mutation for this change, as for the restore note: request construction,
authorization and persistence did not change. Comparing the code against
HEAD confirmed only the messages and helper rename; a test repeating the
wording would not prove its truth. No mutation was performed.

**Checks reported by the implementer, not repeated as a full matrix by
the reviewer.** All twelve AGENTS.md checks exited zero: formatting,
both default-member clippy runs, both feature-set test suites, docs with
warnings denied, both MSRV checks, and clippy and tests for the dialog
and manager. Reported totals: 663 passed and 2 ignored with all features
(counting the descriptor-limit test's child rerun once), 553 passed and
2 ignored without default features, 9 passed for the dialog and 45 for
the manager. These runs preceded the two-line re-wrap of
`docs/manager.md` (words unchanged) and the MGR01 wording correction.

Not checked by the reviewer: KeePassXC itself, a real systemd installation,
manual visual inspection, power loss, every concurrent-writer interleaving
or mutations. No real vault, socket, audit log or keyring was used, and no
dialog appeared on the maintainer's screen. The reviewer did not inspect
other processes through /proc; the agents under test use their normal
requester-identification code. The initial review changed no repository
file. This confirmation did not rerun Cargo checks or the probe; it adds
only this record and the summary sentence above, left unstaged for the
implementer to read.

**Final matrix (the maintainer's agent, Claude Code, AI-assisted,
2026-11-19).** After the reviewer's record above, the twelve checks of
AGENTS.md ran again on the tree as committed, less this paragraph, one
after another, and all exited zero: `cargo test --all-features` passed
663 tests with 2 ignored (the descriptor-limit test's child rerun counted
once), `cargo test --no-default-features` 553 with 2 ignored, the dialog's
9 and the manager's 45. The two ignored tests are the real KDF timing and
the one that needs `keepassxc-cli`. No package was built or installed and
no service changed: the installed manager still shows the earlier texts
until the next package.

**2026-11-19 — The history rewritten before publication.**

The repository had never been published and had no remote. Before its
first publication the maintainer's agent (Claude Code, AI-assisted) read
everything a push would publish — the 221 commits of `main`, every
version of every file (1,420 blobs) and every commit message — for
credentials and private data. It found no credential: every key-shaped
string is a made-up test value, the private-key PEM examples contain only
dummy test material, and the two
KDBX fixtures hold test data (both were opened with the password their
test names). It found three things that the maintainer decided to remove
from the whole history, as old material not meant for publication:

- a list of example names in the reference prototype's simulated keyring
  import (`docs/design/manager/index.html`), with the name of one of its
  fake entries, and an example in the roadmap taken from that list:
  replaced by made-up names;
- the `Claude-Session:` line of 199 commit messages, a link to the
  session that made the commit: removed;
- the maintainer's personal e-mail address, in the identity of every
  commit and in `Cargo.toml`, `packaging/copyright.py` and
  `packaging/deb/changelog`: replaced by the account's GitHub noreply
  address.

A backup of the repository was made first. Gemini (AI-assisted), given
the exact replacements, rewrote a separate clone in one run of
`git filter-repo`; nothing else was asked of it. The maintainer's agent
then compared the backup with the result, with a program of its own:

- the same 221 commits in the same order, each with the same parent,
  author and committer names and dates;
- each message equal to the old one without its session line and with
  the commit ids it cites mapped (71 ids in 40 messages), ending with one
  newline;
- each tree different from the old one only in the five files named
  above, and each of the 56 distinct changed blobs equal to the old blob
  with the decided replacements applied and nothing else;
- no session link, old address or old name in any commit or message, and
  `git fsck` without errors.

Every commit id changed. The ids cited in the files — 335 references to
88 commits, in this document, in ADR 0013 and in three comments of the
code — were mapped by a script to the commits that took their place, in
the commit that adds this entry. So the ids this history cites, in
entries of any date, are those of the published history, not the ones
written at the time. Left as recorded, because they name objects that
were never part of `main`: the commits `9c069d4` and `36db9c3`, and the
ids of the staged trees in the "Final matrix" records. The published
repository does not have them.

Not changed: the products that ADR 0013 and earlier versions of the
roadmap name as technical examples. The rewrite changes no behaviour:
the code differs from the reviewed tree only in the maintainer's address
that the package carries and in the commit ids of three comments.

**Independent review (Codex, AI-assisted, 2026-11-19).**

The initial verdict was **not ready**, with HIS01 low and no serious
correctness, security, concurrency or regression finding. Confirmation of
the staged correction at HEAD `37c2b12` is **ready**: HIS01 is fixed and
there is no new finding. Reversing only that wording correction in memory
reproduces the saved SHA-256 of the reviewed index's path, mode, stage and
blob-ID entries. There was no other staged difference and no unstaged
change before this record.

| Finding | Severity | Disposition |
|---|---|---|
| HIS01 — The record said "no private key has a body", but the PEM examples have dummy bodies: `AAAA` in `broker/src/setup.rs:255` and fake key material in `3294e0b:src/import.rs`. This was an inaccurate description, not an exposed private key. | Low | **Fixed and confirmed:** the staged record says "the private-key PEM examples contain only dummy test material". |

The following checks belong to the initial review; this confirmation did
not repeat them. The reviewer read AGENTS.md, the repository's context
documents and the complete staged diff, including the summary row, the
last entry and the prototype README addition. Independent Python scripts,
run in memory, compared objects read with `git rev-list`,
`git cat-file --batch` and `git show`; the implementer's comparison
program was not used.

The backup and clone each had 221 commits, matched by all 221 rows of the
commit map, in the same topological order, with all 230 parent links
mapped correctly and no commit pruned. All 221 raw headers and subjects
were compared. Author and committer names, dates and time zones were
preserved; all 442 author/committer identities used the decided noreply
address. No header was lost: the original headers contained only tree,
parent, author and committer fields, with no encoding or signature header.

The scripts recomputed Git object hashes for 1,420 distinct blobs and
889 tree nodes, rebuilding the trees of all 221 commits with only the
decided replacements. File paths and modes were unchanged. All 56
distinct changed blobs were in the five authorised files and equalled
the original bytes with exactly those replacements; no other difference
was found.

The two KDBX fixtures were byte-for-byte unchanged. The reviewer opened
both with `keepassxc-cli export --quiet` and their documented test
password, capturing XML in memory with isolated temporary directories.
Both commands exited zero; the contents were test data, with no
attachments and no removed term in the XML. The files' hashes remained
unchanged, and the temporary directory was removed.

All 221 messages were compared byte for byte: exactly 199 session lines
were removed from 199 commits, and 71 commit-ID occurrences were mapped
in 40 messages. There was no other difference, including final newlines.
The contexts of the 71 substitutions were commit references, not
unrelated hexadecimal tokens.

The staged files mapped exactly 335 references to 88 old commits, with
the same number of digits and the correct replacement: 316 references
in this document, 16 in ADR 0013, two in `src/protocol.rs` and one in
`tests/agent.rs`. Outside those substitutions, only the specified record
and prototype README additions differed. No old-main commit-ID token
remained in the staged files; no new abbreviation was ambiguous among
the commits of main.

The unmapped message references `10fa623`, `888fe95` and `9c069d4`
correctly remained: they name backup commits outside the old main.
The files' `9c069d4` and `36db9c3` have the same justification. The
three hashes in earlier "Final matrix" records name trees, not commits:

- `e86de9e37794381b5d9407c176e9a4431639a4f2`;
- `04c9e7ca02989a5f98fbcff27a19a2066eed2ab4`;
- `fe82d669ecd593eba6f3e7620557c376f35ea76b`.

The fixture NOTICE's `26cb076aa5cbbe36e175326dfdaf5a19799c4085`
references upstream. The other retained tokens were a UUID fragment
(`c5f546e5`), a numeric address test (`2130706433`), a date
(`20250219`) and an algorithm name (`ed25519`), not commits to map.

Case-insensitive privacy searches covered all 1,420 reachable blobs,
221 messages and their headers, 113 historical paths, and the initial
staged files. There were no hits for the removed example names, personal
address or session links in the rewritten history. The initial staged
record contained one explanatory occurrence of the removed session-line
label, without a link or session identifier.

The `session_` searches found 2,550 occurrences in 349 historical blobs
and 115 occurrences in 18 initial staged files: code, D-Bus, configuration
and example identifiers, not private session identifiers. Other e-mail
matches were the authorised noreply identity, 219 public noreply
coauthor trailers, test examples or parser false positives. Home paths
were examples or vault-group paths; hosts and IP addresses were examples,
documented public destinations or test vectors. The reviewer examined
credential-shaped patterns, PEM delimiters and 415 distinct long quoted
literals, including 11 candidates selected by an additional entropy
filter. These were test data, examples, UUIDs, widget names, paths or
build options; no real credential was identified. The technical product
examples deliberately retained by the maintainer were unchanged.

`git fsck --full --strict --no-reflogs`, `git diff --check` and
`git diff --cached --check` exited zero without output. The clone had
only `refs/heads/main`; filter-repo's local metadata is not included
in an ordinary push of main. The backup and old objects in the real
repository remain local; their presence alone does not publish them.
The initial review left the index and files unchanged, verified against
its starting hashes, and found the real repository clean.

The reviewer ran no Cargo checks, application tests or mutations.
Since that review, the implementer reports that all twelve AGENTS.md
checks passed sequentially from a cold build in this clone, before the
HIS01 wording correction: `cargo test --all-features` passed 663 tests
with 2 ignored (the descriptor-limit test's child rerun counted once),
`cargo test --no-default-features` passed 553 with 2 ignored, and the
dialog and manager passed 9 and 45 respectively. These are the
implementer's results, not checks run or independently validated by
the reviewer.

The reviewer did not establish that the repository had never been
published, observe Gemini's original run or Claude's original checks,
verify the fixtures' provenance externally, or prove that no arbitrary
string had ever been used as a secret. The material results were
checked; the reported execution history was not independently observed.
No network, real vault, running agent, on-screen dialog, installation or
inspection of other processes through /proc was used.

No further obstacle was found in the transfer plan. Before
`git reset --hard`, check again that the real repository is clean and
that the fetched commit is the approved final commit. Push only main,
only with the maintainer's explicit approval. The reviewer performed
none of the planned commit, fetch, reset, branch deletion or push steps.
This confirmation adds only this record and the summary sentence above,
left unstaged for the implementer to read.

**Final checks (the maintainer's agent, Claude Code, AI-assisted,
2026-11-19).** The matrix that the reviewer's record attributes to the
implementer ran in the rewritten clone from a cold build, on the staged
tree before the HIS01 wording change. After that change and the
reviewer's record, which touch this document only, `git diff --check`,
`cargo fmt --all --check` and the 25 packaging and documentation tests
(`cargo test --all-features --test packaging`) passed again on the tree
as committed, less this paragraph. The whole matrix was not repeated
for those two additions.

**2026-11-19 — The first CI run: two tests that depended on the runner's
environment.**

The repository was published on GitHub on 2026-11-19, on the maintainer's
explicit approval, and its workflow ran for the first time, on the push of
`bc71509` (2026-11-20 01:23 UTC). Two of its three jobs passed: the GTK
clients and the minimum supported Rust version. The third failed at
`cargo test --all-features`: 194 of the 196 end-to-end tests passed, and
`a_request_too_tall_to_read_at_once_is_refused` and
`a_dialog_that_scrolls_takes_what_is_too_tall_for_zenity` failed with
"this request has too much detail to show in one dialog (4031
characters, limit 4000)", 4037 for the second. The job's later steps
(the tests without default features, the documentation, the release
build that must refuse the broker's feature for tests) did not run.

The cause was diagnosed by a subagent of the maintainer's agent (Claude
Opus 5.5, AI-assisted), which changed no file; the maintainer's agent
(Claude Code, AI-assisted) then read the three facts it rests on in the
code and repeated its reproduction. Both tests gave the command a
`GIT_SSH_COMMAND` of 600 line breaks, 3,000 characters as the dialog
shows them, which left the dialog about 120 characters under its limit
of 4,000 on the maintainer's machine (3,879 and 3,885, measured by the
subagent). `Harness::cmd` lets the client inherit the environment of the
test process; the agent lists in the dialog every variable whose name
ends as an endpoint's does (`_URL` and the others, L4); and every step
of GitHub Actions sets `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL` and
`GITHUB_SERVER_URL`, 149 characters in the dialog. The character limit,
which the agent checks before the height, refused the request first.
With those three variables set, both tests failed in the same way on the
maintainer's machine. The agent was right to refuse: the tests assumed
an environment.

The fix is in the tests only, made by Gemini (AI-assisted) from the
exact edits: 300 line breaks instead of 600, which is 1,500 characters,
far from the character limit, and still a dialog far taller than zenity
allows (estimated at 1,349 pixels against 880 in the second test); and
the second test now also requires that the approval it was asked be one
that `ui::approval_too_tall` refuses, so that it cannot pass with a
request that zenity could have shown.

**Implementer's checks (Gemini, AI-assisted).** Before the change, with
the three variables set, both tests failed; after it, both pass with and
without them. Mutations, in a temporary copy with its own target
directory, each caught:

- M1: the height check removed from the agent — the first test fails
  ("the request was denied").
- M2: only `&& self.ui.limits_height()` removed — the second test fails
  ("too tall to read at once").
- M3: 3 line breaks instead of 300 in the second test — it fails at the
  new assertion.

`cargo fmt --all --check` and both clippy runs passed;
`cargo test --all-features` passed 663 tests with 2 ignored, and again
with the three variables set; `cargo test --no-default-features` passed
553 with 2 ignored. The maintainer's agent read the diff, which is the
specified one, and ran the two tests with the variables set: both pass.

Left as they are. The diagnosis reports other tests whose margin the
ambient environment narrows, none failing, and the maintainer's agent
did not verify these figures: two tests of the broker's run dialog
(`a_broker_runs_destination_and_limits_are_checked_before_any_dialog`,
measured 207 pixels under zenity's height limit on the maintainer's
machine and derived at about 125 on the runner, and
`a_broker_run_shows_and_lists_its_origin_apart_from_its_base_path`, not
measured), and `the_allow_for_note_counts_toward_the_height_limit`,
whose one-character boundary a longer process id could move. An
environment of the tests' own for the client, instead of the inherited
one, would remove the variation that inherited variables bring; the test
of the height boundary also has to allow for the requester's process ids
and the layout of its process chain. Both are follow-up work, not done
here.

The publication and this first, failed run are recorded now, in the
roadmap and in AGENTS.md as well; a run that passes will be recorded
after it completes. GitHub's private vulnerability reporting, which
SECURITY.md points to, was enabled on the repository the same day. The
clean reinstall that the roadmap planned before publication was left to
the maintainer, and nothing here records it as done.

**Independent review (Codex, AI-assisted, 2026-11-19).** Recorded by the
maintainer's agent from the reviewer's two deliverables: the reviewer
confirmed the corrections and its verdict, and its own attempt to add
this record stopped on a patch that did not apply.

The initial verdict was **not ready**, with CI01–CI03 low, no serious
defect in the product and no regression from the change. The
confirmation on the staged tree is **ready**: the three are fixed and
there is no new finding.

| Finding | Severity | Disposition |
|---|---|---|
| CI01 — The new comment promised a margin "whatever the requester's environment": the client still inherits it, and with the runner's three variables and six more endpoint variables the changed test failed again ("4138 characters, limit 4000"). | Low | **Fixed and confirmed:** the comment claims room for the runner's three variables only, and says that the client still inherits the test process's environment. |
| CI02 — The record said that an environment of the tests' own would remove the cause for all the other tests. The height-boundary test also varies with the requester's process ids: in a probe on a captured request, one id going from five to six digits moved the estimate from 880 to 899 pixels. | Low | **Fixed and confirmed:** the record says what such an environment removes, and that the follow-up must also cover process ids and the layout of the process chain. |
| CI03 — Waiting for a run that passes before correcting the documents kept statements known to be false: the repository was published and its workflow had run. | Low | **Fixed and confirmed:** the roadmap and AGENTS.md record the publication and the first, failed run now; a run that passes is recorded after it completes. |

The reviewer ran 33 cargo commands, one after another, in a temporary
copy of the index with its own target directory and `TMPDIR`, offline,
with Rust 1.99.1, `RUSTFLAGS="-D warnings"` and `CARGO_INCREMENTAL=0`,
in an environment without the variables the agent's lists recognise. It
reproduced the failure its own way: with the three variables the earlier
tests failed (4,036 and 4,042 characters there), and the staged ones
pass with and without them. The whole suites passed in that copy: 663
tests with 2 ignored with all features, the 196 end-to-end tests among
them, and 553 with 2 ignored without default features, with nothing left
in `TMPDIR`. `cargo doc` with warnings denied exited zero for both
feature sets, and a release check of the broker with its feature for
tests was refused with the expected message.

Measured by the reviewer's instrumentation, in characters and estimated
pixels of height:

| Request | Controlled environment | With the runner's three variables |
|---|---|---|
| First changed test | 2,387 / 1,349 | 2,536 / 1,431 |
| Second changed test | 2,393 / 1,349 | 2,542 / 1,431 |
| `a_broker_runs_destination_and_limits_are_checked_before_any_dialog` | 1,045 / 673 | 1,194 / 755 |
| `a_broker_run_shows_and_lists_its_origin_apart_from_its_base_path` | 1,213 / 755 | 1,362 / 837 |

So the three variables add 149 characters, the first broker test keeps
125 pixels under zenity's 880 on the runner, and the second 43. The
reviewer reran the three mutations in a temporary copy: M1 failed the
first test with "the request was denied", M2 the second with "too tall
to read at once", M3 the second at the new assertion; restored, both
passed. It also showed what stays fragile: with the three variables,
two more endpoint variables and a proxy, the first broker test failed
at 935 pixels; and the process-id probe of CI02.

The reviewer accepts leaving the other three tests to a follow-up, which
must cover inherited variables and the requester's identity and process
chain. Not checked by the reviewer: GitHub Actions itself, the runner's
exact compiler and cache; formatting, clippy, the GTK and MSRV jobs;
`cargo doc` with the workflow's exact flags; a real change of process
id; Gemini's original runs. Its confirmation ran no cargo.

**Final matrix (the maintainer's agent, Claude Code, AI-assisted,
2026-11-19).** After the three corrections, the twelve checks of
AGENTS.md ran on the staged tree, one after another, and all exited
zero: `cargo test --all-features` passed 663 tests with 2 ignored (the
descriptor-limit test's child rerun counted once),
`cargo test --no-default-features` 553 with 2 ignored, the dialog's 9
and the manager's 45. Whether the runner agrees is what the next run of
the CI says.

**2026-11-20 — The second CI run: a race in the test of revocation at the
leader's exit.**

The second run, on the push of `f7ad355` (2026-11-20 02:22 UTC), passed
the two tests corrected above: they no longer depend on the runner's
three variables. The same job failed again at `cargo test
--all-features`, in another end-to-end test, 195 of 196 passing:
`the_end_of_the_command_revokes_its_grants_before_its_output_is_drained`,
with "the grant was not revoked while the output was drained". That test
had passed in the first run; a second attempt of the same job, asked for
by the maintainer's agent, failed in the same way. The job's later steps
have still never run on the runner. The GTK and MSRV jobs passed again.

The failing assertion is about a security property (ADR 0013, the end
of the command; L17): a grant must end when the command's leader exits,
before its output is drained. So the diagnosis had to say whether the
agent had failed to revoke. It was made by a subagent of the
maintainer's agent (Claude Opus 5.5, AI-assisted), which changed no file
of the repository; the maintainer's agent (Claude Code, AI-assisted)
read in the code the order it rests on.

The cause is in the test's own command, `setsid sh '<descendant>' & exit
3`. The leader forks the background child and exits at once. The agent,
told of that exit, ends the run's grants and waits for the broker's
confirmation, then terminates what is left of the command's process
group, then drains the output (`src/agent.rs`, after the `waitid` loop).
A child that has not yet returned from `setsid()` is still in that group
and is terminated with it: the descendant that the test relies on never
runs, and never writes the marker the test looks for. The subagent
traced nine failing runs (with `strace`, the test pinned to one CPU with
four busy loops on it: 9 failures in 60 runs): in each the fake broker
had logged the revoke 0.3 to 3.8 ms after the leader's exit, the group
was signalled at 11.0 to 16.5 ms, and the child was killed before it
ran the descendant's script. In an isolated measurement of the window
on the maintainer's idle machine, a group signalled 0.25 ms after the
leader's exit kept 4 of 200 descendants, and one signalled after 1 ms or
more kept all 200: there the child wins by about a millisecond.

What this does and does not establish. In every failure reproduced, the
grant was revoked first, and the code has no path that skips the revoke
when the leader exits. The failure was not reproduced without `strace`
on the maintainer's machine (0 failures in about 450 runs under several
loads), and the run on the runner cannot be observed: its log has no
output of the command. The subagent's argument for the runner is one of
timing: the test ended there as soon as on a run that passes, where a
revoke that never came would have kept the descendant printing for five
seconds. A descendant that had escaped and then stalled for half a
second is not excluded by that argument.

The fix is in the test only, made by Gemini (AI-assisted) from exact
edits, in two steps. First the race: the descendant notes that it runs,
by which time `setsid` has moved it out of the group, and the leader
polls for that note for up to 600 iterations, sleeping 50 ms each time,
then exits with status 3 (an iteration bound, not a deadline of 30
seconds); the test rejects a missing note. Then, after the review below
(CI04), the proof: the marker alone shows that the descendant saw a
revoke at some time, so the test now also requires, in the run's output,
the line that the descendant prints last. The marker shows that it saw
the revoke; that line, printed next, reaches the output only while it
is still being drained. Both are needed: a descendant that gives up
without seeing a revoke prints the line too. The
system test of the same property with the real broker
(`a_stolen_token_stops_working_once_the_commands_leader_exits`) already
waited for its descendant in this way and is not affected.

**Implementer's checks (Gemini, AI-assisted).** These are the runs
made on the test as it is committed, after both steps; the first step
alone had been checked in the same way before the review. The test
passed 20 of 20 runs on the idle machine and 20 of 20 pinned to one CPU
with four busy loops on it, the condition under which the earlier one
failed when traced. Mutations, in a temporary copy with its own target
directory:

- M1: the revoke moved to after the output is drained — caught: the
  test fails at "the grant was not revoked while the output was
  drained", after 5.7 seconds (the descendant prints its hundred lines
  and never sees a revoke).
- M2: the descendant never notes that it runs — caught: the test fails
  at "the descendant did not start", after 31.5 seconds.
- M3, the reviewer's survivor: M1 with a pause of 0.75 seconds in the
  descendant right after its note — caught 6 times out of 6, at the new
  requirement ("what the descendant printed after the revoke is not in
  the output"). Before that requirement the test passed under it.
- M4, the pause alone, with the agent unchanged: the test fails 6 times
  out of 6 at the same requirement. This is not a mutation to catch but
  the measure of a margin, stated below.

`cargo fmt --all --check` and both clippy runs passed;
`cargo test --all-features` passed 663 tests with 2 ignored, and again
with the runner's three variables set; `cargo test --no-default-features`
passed 553 with 2 ignored. The maintainer's agent compared the first
step with the diff that the diagnosis proposed (identical) and the
second with the edits it had specified, ran the test, and checked that
no load process was left.

Left as they are:

- The test does not tell a revoke before the group is terminated from
  one between that and the drain: an escaped descendant sees the same
  (the reviewer confirmed it with that mutation, which passes). The
  test's comment now says which part of the order it checks.
- The drain ends after 500 ms without output once the leader is gone, so
  a descendant kept from running for that long between two lines, which
  it prints 50 ms apart, fails the test without a defect in the agent:
  M4 above. With the new requirement such a stall fails the test, where
  before it could hide a late revoke; the margin is that of the agent's
  drain, some ten times the descendant's pace.
- `processes_with_non_utf8_names_are_terminated_too` forks and exits in
  the same way. Its assertion holds whichever side wins, but it can pass
  without testing what it means to (a child killed before it changes its
  name), its own check relies on a fixed sleep of 300 ms, and, as the
  reviewer found (CI06), that check kills only its shell and leaves a
  `sleep 30` running for some 29 seconds after the tests have ended,
  which an empty `TMPDIR` does not show. It is older than this change
  and is a follow-up of its own.

**Independent review (Codex, AI-assisted, 2026-11-20).** My initial
verdict was **not ready**, with CI04 medium and CI05–CI06 low. At the
first confirmation I found CI04 and CI05 fixed and accepted CI06 as a
separate follow-up, but found CI07 low in the new explanation, so the
verdict remained **not ready**. I have now confirmed CI07 fixed in both
places on the staged tree. The final verdict is **ready**, with CI06
remaining a separate follow-up.

| Finding | Severity | Disposition |
|---|---|---|
| CI04 — the marker could be created after the drain ended, allowing a late revoke to pass. | Medium | Fixed: the test retains the captured output through `start` and `running.wait()`, checks the marker, and also requires the line `after`. The doc comment now distinguishes its coverage from group termination and real-token rejection. |
| CI05 — the record promised a 30-second deadline and an exit only after the start note. | Low | Fixed: it describes 600 iterations with 50 ms sleeps, followed by exit status 3, and the assertion that rejects a missing note. |
| CI06 — the non-UTF-8 sibling test leaves its sanity check's `sleep 30` alive after killing only its shell. | Low | Open as a separate follow-up, an acceptable disposition for this pre-existing issue. It needs whole-group cleanup, including failure paths, and readiness after the relevant exec instead of a fixed sleep. |
| CI07 — the new explanation said the descendant prints `after` only after seeing a revoke. | Low | Fixed and confirmed in both places: the marker shows that a revoke was seen; the final line, printed next, reaches the run's output only while it is still being drained. The wording now explicitly requires both, since a descendant that gives up without seeing a revoke also prints `after`. |

I compared the staged correction with the previously reviewed state.
Replacing only the two changed blobs in memory reproduced the previous
index signature across all 110 tracked files. Only the specified test
correction and rewritten entry differed; the roadmap and table row
were unchanged. The working tree equalled the index. I did not repeat
the experiments or run Cargo for either confirmation. At the first
confirmation this record was supplied but not appended because CI07
was new. At the final confirmation I checked that only its two wording
corrections differed from that state, again across all 110 tracked
files. I then appended this record and extended the table's outcome
cell, leaving both additions unstaged.

In the original review I read the diff, AGENTS.md, the workflow, the
relevant documentation, the harness and fake broker, and the end-of-run
path in `src/agent.rs` and `src/broker_host.rs`. The inspected path calls
`end(CommandEnded)` before `terminate_group`, `leader_done` and the
pump joins. `tell` and `wait_confirmed` wait for confirmation or contain
the broker, killing and reaping it when necessary. Previously revoked
grants are also waited for when needed. The connection watcher preserves
revocation before group termination. The fake broker closes its log
write before sending confirmation.

I found no product revocation defect in those paths. The startup race
explains the local failures I reproduced, but this does not directly
establish the cause of each runner failure. I read the three supplied
CI logs, containing 727, 719 and 719 lines. They show the earlier two
tests passing in both attempts of the second run and the revocation
test failing, with 195 of 196 end-to-end tests passing. Their aggregate
timestamps are consistent with the diagnosis; they contain neither the
command's output nor individual start times sufficient to exclude all
other scheduling explanations on the runner.

I independently recomputed the nine supplied failure traces. The fake
broker logged the revoke 0.262–3.803 ms after the leader's exit; the group
was signalled at 10.954–16.496 ms. The descendant's script did not execute
in those cases. These are my readings of supplied traces, not nine
additional reproductions of my own.

My experiments used 71 sequential Cargo commands, including three
`--no-run` builds, in a temporary copy of the index with its own target
directory and private TMPDIR. I used Rust 1.99.1, offline mode and
`RUSTFLAGS=-D warnings` only in that copy. The principal command was:

```sh
cargo test --offline --all-features --test agent \
  the_end_of_the_command_revokes_its_grants_before_its_output_is_drained \
  -- --exact --nocapture
```

For load I pinned the command to CPU 0 with four busy processes on that
CPU and used `strace -f --seccomp-bpf`. A separate controlled-delay probe
added `-e inject=setsid:delay_enter=100ms`. The times below are test times,
excluding compilation.

| My experiment | Result |
|---|---|
| Startup fix, idle | 5/5 passed, 0.33–0.35 s. |
| Old test, one CPU, four busy processes and trace | 5/20 failed with the original marker assertion. |
| Startup fix, the same load and trace | 20/20 passed, 0.37–0.60 s. |
| Old test, 100 ms injected delay in setsid | 5/5 failed, 0.30–0.32 s. |
| Startup fix, the same injected delay | 5/5 passed, 0.24–0.48 s. |
| M1: revoke after the pump joins | Failed in 5.87 s: "the grant was not revoked while the output was drained". |
| M2: no start note | Failed in 32.11 s: "the descendant did not start". |
| Revoke after group termination but before the drain | Passed in 0.41 s, confirming the stated coverage limit. |
| M1 plus a 0.75 s pause immediately after the start note | Passed incorrectly in 6/6 runs, 0.88–0.91 s. |
| Proposed output assertion, with M1 and that pause | Failed in 0.91 s: "the descendant final output was not received". |
| Proposed output assertion, original agent and no pause | Passed in 0.35 s. |

In my five traced failures under load, the fake broker logged the revoke
0.202–0.859 ms after the leader exited, before signals to the group at
12.996–17.340 ms. In the six false positives, the descendant created the
marker after the pumps had ended; its final `echo after` failed with
`EPIPE`. Requiring receipt of that line, together with the marker, caught
this survivor. The current staged code implements that requirement.

I also ran the real-broker test:

```sh
cargo test --offline --all-features -p rusthorse-broker --test system \
  a_stolen_token_stops_working_once_the_commands_leader_exits \
  -- --exact --nocapture
```

It passed: one test, 34 filtered out, 0.41 s. It waits for the
descendant's pid before releasing the leader and holds the client's
drain while checking that the token no longer works.

The start note is a valid startup barrier: the script creates it after
`setsid` has established the new session, including when the utility
forks. It does not eliminate later scheduling sensitivity. The test
still cannot distinguish revocation before group termination from
revocation immediately after it. A sufficiently long pause can also
exhaust the output pumps' quiet timeout and fail the test without a
product defect. I accept those stated limits for this correction; they
do not justify claiming a universal timing guarantee.

I searched background launches, setsid and forks in the tests and related
modules, and read the relevant siblings in `src/supervise.rs`,
`src/dialog_program.rs` and `src/ui.rs`. In ordinary cleanup tests,
killing the forked child before exec still satisfies the property.
The non-UTF-8 test additionally needs the child to reach its changed
name, so it can pass without exercising that condition. Its own sanity
check also leaked a live sleep: the test passed in 0.61 s, but that child
exited 29.406 s after the test process. An empty TMPDIR did not reveal it.

The maintainer reports Gemini's post-correction checks: 20/20 idle and
20/20 under CPU load; M1 caught at the marker after 5.67 s; M2 caught at
the missing-note assertion after 31.53 s; M3, the late revoke plus pause,
caught 6/6 at the new output assertion; and M4, the pause with the agent
unchanged, failing 6/6 at that assertion. These reports do not contradict
my experiments. I did not run M4 myself. Gemini's reported fmt and both
clippy runs passed, as did the all-features suite with 663 passed and
2 ignored, again with the runner's three variables, and the suite
without default features with 553 passed and 2 ignored. Those results
belong to Gemini, not to me. The maintainer's agent reports that the
separate full AGENTS.md matrix completed before the CI07 wording change:
all twelve steps ran sequentially and exited zero. It reports 663 passed
and 2 ignored with all features (counting the descriptor-limit test's
child rerun once), 553 passed and 2 ignored without default features,
9 passed for the dialog and 45 for the manager. After the CI07 comment
and documentation change, it reports that `git diff --check`,
`cargo fmt --all --check` and one run of the changed test passed. These
are reports of the implementer's executions, which I did not observe.
I did not repeat Cargo checks or tests for either confirmation.

I did not run GitHub Actions, reproduce its exact toolchain or cache,
run the full matrix, fmt, clippy, GTK, MSRV or the full suites for this
review. I did not observe Gemini's original runs, repeat the diagnosis's
approximately 450 runs or execute its isolated `window.py` experiment.

All recorded runtime TMPDIR checks were empty. I terminated and waited
for all eight load processes and reaped the probes' adopted descendants.
The temporary copy, targets, scripts, traces and logs were removed.
No repository file or index entry was changed by the review or the first
confirmation. No real vault, running agent or external network was used.

**2026-11-20 — The third CI run: an environment of the tests' own for
their client.**

The third run, on the push of `99e6b85` (2026-11-20 03:51 UTC), passed
the test of revocation corrected above. The same job failed again at
`cargo test --all-features`, 194 of 196 end-to-end tests passing, in the
two tests of the broker's dialog that the first review had named as
close to a limit: `a_broker_runs_destination_and_limits_are_checked_before_any_dialog`
was refused with "too tall to read at once (estimated 897 pixels, limit
880)", and `a_broker_run_shows_and_lists_its_origin_apart_from_its_base_path`
"waited too long for the command to start". Both had passed on the
runner in the first two runs. The GTK and MSRV jobs passed again; the
job's later steps have still never run there.

Three runs had failed in different tests, two of them for one cause:
`Harness::cmd` started the client with the environment of the test
process, the client sends its environment with a run, and the agent's
dialog lists parts of it. The maintainer's agent (Claude Code,
AI-assisted) decided to correct that cause instead of another test's
margin, and had the change designed and validated in a copy by a
subagent (Claude Opus 5.5, AI-assisted), which changed no file of the
repository.

The change, in `tests/agent.rs` only:

- `Harness::cmd` clears the inherited environment first and then sets
  six variables: `RUSTHORSE_SOCKET`, `RUSTHORSE_AUDIT_LOG` and
  `RUSTHORSE_VAULT` as before; `XDG_RUNTIME_DIR`, the test's directory;
  `PATH`, `/usr/bin:/bin`, as the tests' requests sent through the
  library already had; and `TMPDIR`, that of the test process. The clear
  comes first because it also drops what was set before it. A test that
  needs a variable sets it. Clients that talk to a fake agent or to none
  are started elsewhere and were left as they were.
- Clearing the environment would also clear the socket's variable, and
  the client's default is the user's own agent. The three variables are
  set after the clear in the same expression, and `XDG_RUNTIME_DIR` is a
  second defence: with it the default socket is in the test's directory.
- `the_allow_for_note_counts_toward_the_height_limit` sends its three
  requests from the test process, through the library's client, so that
  the requester's process chain, which the dialog shows, is the same in
  each: a client started for each request could have a process id one
  digit longer than the first one's (CI02 above).
- Three comments that the change made false are corrected. No test
  failed with the change: none relied on an inherited variable.

**The subagent's findings**, which the maintainer's agent did not
repeat beyond what is said below. Under an ambient environment made
hostile on purpose (the runner's three variables, ten more endpoint
variables, three proxies, a risky and a loader variable), 32 of the 196
end-to-end tests failed before the change, each with an approval refused
as too tall, and `input_is_not_read_before_the_command_starts` passed
without exercising its scripted denial: the request was refused for
height instead. It still checked that stdin remained untouched. With the
change all tests pass. The third run's exact
pattern, 897 pixels and these two tests, was reproduced on the
maintainer's machine with the runner's three variables and
`SGX_AESM_ADDR=1`, a variable some hosted runners are said to set; what
the runner really held is not known, and the first run's numbers fit
the three variables alone. With the change, the first broker test's
dialog measured 626 to 683 pixels and the second's 708 to 727, for
TMPDIR paths of 19 to 70 characters. For a 70-character TMPDIR and an
eight-process chain with 15-letter ASCII names and seven-digit pids, the
derived heights are 702 and 746 pixels, leaving margins of 178 and 134
pixels. These two requests have character margins above 2,300 in those
configurations. These are estimates for the stated configurations, not
minimum margins for every test or machine.

**Implementer's checks (Gemini, AI-assisted).** The two diffs applied
as they were, and the file has the checksum of the one validated.
`cargo fmt --all --check` and both clippy runs passed;
`cargo test --all-features` passed 663 tests with 2 ignored, and again
under the hostile environment; `cargo test --no-default-features`
passed 553 with 2 ignored. Mutations, in a temporary copy with its own
target directory, each caught:

- H1: the clear removed — under the hostile environment 31 of the 196
  end-to-end tests fail, the two broker tests among them (one fewer than
  the subagent's 32: the boundary test no longer goes through
  `Harness::cmd`).
- H2: `loader_variables_are_stripped` without its own
  `LD_LIBRARY_PATH` — it fails: before the change, the one cargo gives
  the test process satisfied it.
- H3: the height of the "Allow for" note ignored in
  `ui::approval_too_tall` — the boundary test fails.
- H4: the socket's variable removed, one test run
  (`status_works_while_locked`) — the client fails with "cannot reach
  the agent at" a socket in the test's own temporary directory, not the
  user's.

The maintainer's agent read both diffs, checked that they apply to the
repository and give the validated file, and compared the checksum after
Gemini applied them.

What the change does not do, and its side effects:

- For `doctor` started through `Harness::cmd`, `systemctl --user` no
  longer reaches the user's systemd; no test asserts on that line.
  `FakeAgent::cmd` and the standalone `doctor` constructor still inherit
  the test process's environment. Coverage-tool environment variables
  are no longer inherited by clients started through `Harness::cmd`.
- If the test process can start `python3` through its PATH but the
  command cannot find it in `/usr/bin:/bin`,
  `a_process_whose_main_thread_exited_is_still_terminated` now fails. If
  its preliminary check cannot start `python3`, the test is skipped.
- For the same projected configuration, the library request in
  `a_run_reports_the_grants_whose_destination_answered_401` has an
  estimated height of 784 pixels, leaving 96 pixels. This change does
  not affect that request.
- A test that calls `env_clear()` again on a harness command would drop
  both defences. AGENTS.md now says not to.
- CI06, the process left by an older sibling test, is still a follow-up
  of its own.

**Independent review (Codex, AI-assisted, 2026-11-20).** My initial
verdict was **not ready**, with CI08–CI12 low, all wording findings.
I have now confirmed all five corrections on the staged tree. The final
verdict is **ready**. I found no serious product defect, new route to the
maintainer's real agent, or demonstrated loss of test coverage caused by
this change.

| Finding | Severity | Disposition |
|---|---|---|
| CI08 — the record generalized measured and projected margins to every affected request. | Low | Fixed and confirmed: the two broker requests' margins are limited to the stated configurations. The library request's 784-pixel height and 96-pixel margin are identified as a projection for the same configuration, not an unconditional minimum. |
| CI09 — the record said the input test passed without testing anything. | Low | Fixed and confirmed: it missed its scripted denial because height refusal came first, but still checked that stdin remained untouched. |
| CI10 — the systemd and coverage statements also appeared to cover unchanged client constructors. | Low | Fixed and confirmed: the effects are scoped to `Harness::cmd`; `FakeAgent::cmd` and the standalone `doctor` constructor still inherit the test process's environment. |
| CI11 — absence of `/usr/bin/python3` was said to make the main-thread test fail unconditionally. | Low | Fixed and confirmed: failure requires the preliminary PATH check to start Python while `/usr/bin:/bin` cannot find it; inability to start Python in that preliminary check skips the test. |
| CI12 — a comment described physical screen capacity instead of the height estimate. | Low | Fixed and confirmed: 300 escaped line breaks contribute 1500 characters and push the request above zenity's estimated height limit while staying below the character limit. |

For this confirmation I compared the staged files with the Git blobs
read in the original review. Only the five wording corrections and their
line wrapping differed; AGENTS.md and the roadmap were unchanged. The
working tree equalled the index. I did not repeat experiments or run
Cargo. This record and the sentence extending the table's outcome cell
are the only additions I made, and are left unstaged.

In the original review I read the diff, AGENTS.md, the relevant README,
architecture and threat-model text, the workflow, and the affected code
in `tests/agent.rs`, `tests/*.rs`, `broker/tests/` and
`manager/src/widget_tests.rs`. I also read the relevant paths in
`src/paths.rs`, `src/client.rs`, `src/main.rs`, `src/exec.rs`,
`src/peer.rs`, `src/ui.rs` and `src/agent.rs`. My inventory of
`tests/agent.rs` found 25 direct constructions of the rusthorse binary,
15 calls to `Client::new`, one `env_clear()`, 66 `.env()` calls and
eight `env_remove()` calls.

The call order preserves the private paths: `Harness::cmd` clears first,
then sets its six variables. I found no later call that drops those
protections. `XDG_RUNTIME_DIR` is a second defence for the socket only;
it does not redirect the vault or audit log. Reading `src/paths.rs`,
without their RUSTHORSE overrides, their XDG base variables and HOME,
the defaults are `/.local/share/rusthorse/vault.kdbx` and
`/.local/state/rusthorse/audit.jsonl`; the code does not look up the
login user's home. I reasoned about those defaults from the code and
did not try them. The other clients I examined use explicit private
sockets. H4 below exercised only removal of the socket override while
keeping the private `XDG_RUNTIME_DIR`.

I checked the assertions and inputs for OLDPWD, `_`, loader variables,
destinations, PATH, remembered approvals, doctor, init without an agent
and program resolution. The environment-sensitive tests supply the
values they check. I found no dependency on HOME or LANG whose removal
made an assertion vacuous. I found these 18 tools locally in
`/usr/bin:/bin`: sh, true, printenv, python3, setsid, sleep, grep, cat,
env, touch, head, tr, ln, readlink, chmod, mv, cp and mkdir. This was a
local check, not an inventory of the runner. The boundary test still
checks refusal with the note and a dialog request with one character
less. `a_request_too_tall_to_read_at_once_is_refused` still checks the
CLI's status 125 and its height-refusal message.

My experiments used a temporary copy of all 110 indexed files, its own
target directory, private paths and offline Cargo, with local Rust and
Cargo 1.99.1. I ran 13 build/test commands sequentially. The hostile
ambient environment contained the three GitHub URL variables, ten fake
endpoint variables, HTTPS_PROXY, HTTP_PROXY, NO_PROXY, PYTHONPATH and
LD_RUSTHORSE_HOSTILE. The following are my executions on the tree before
the five wording corrections, not Gemini's or the subagent's runs.

| Check | Command or temporary variant | Result and time |
|---|---|---|
| Build | `cargo test --all-features --no-run` | Passed; 126.76 s total. |
| Initial setup error | `cargo test --all-features`, hostile environment | Six settings-permission tests failed because I created the TMPDIR subdirectory with mode 0775; 1.91 s total. This did not reach the end-to-end suite. |
| Staged tree, private TMPDIR | `cargo test --all-features`, hostile environment | 663 passed, 2 ignored; 61.42 s total; TMPDIR empty. |
| First instrumentation run | `cargo test --all-features --test agent`, hostile environment | 196 passed; 40.01 s total. I discarded its interleaved metric records. |
| Corrected instrumentation | `cargo test --all-features --test agent`, hostile environment | 196 passed; 39.89 s total; the measurements below come from this run and the next. |
| Long-directory measurements | `cargo test --all-features --test agent -- --exact` with the two broker tests, the 401-report test and the height-boundary test | Four passed, 192 filtered out; 8.34 s total. |
| Old code | `cargo test --all-features --test agent`, hostile environment | 164 passed, 32 failed; 61.90 s in the tests, 69.46 s total. All 32 had an instrumented height refusal. |
| Old code, runner-shaped example | The two broker tests selected with `--exact`, all features, the three GitHub URL variables and `SGX_AESM_ADDR=1` | Both failed; 60.04 s in the tests, 60.13 s total. |
| H1 | Remove only `env_clear()`; `cargo test --all-features --test agent`, hostile environment | 165 passed, 31 failed; 61.90 s in the tests, 69.19 s total. |
| H2 | Remove the loader test's own `LD_LIBRARY_PATH`; select `loader_variables_are_stripped` with all features and `--exact` | Failed at the assertion requiring the LD_LIBRARY_PATH warning; 0.26 s in the test. |
| H3 | Ignore the note's height in `approval_too_tall`; select the height-boundary test with all features and `--exact` | Failed: Denied instead of InvalidRequest, "the request was denied"; 0.08 s in the test. |
| H4 | Remove only `RUSTHORSE_SOCKET`; select `status_works_while_locked` with all features and `--exact` | Failed with "cannot reach the agent at" the test's temporary `rusthorse/agent.sock`; 0.01 s in the test. |
| Staged tree, no default features | `cargo test --no-default-features`, hostile environment | 553 passed, 2 ignored; 77.64 s total including compilation; TMPDIR empty. |

The suite counts count the descriptor-limit test's child rerun only
once. H1's failure set differed from the old code's by exactly the
height-boundary test, now sent through the library. In the runner-shaped
example, the first broker test reported 897 pixels against the limit of
880; the second ended with "waited too long for the command to start",
and its instrumented request measured 979 pixels. This independently
reproduced the reported pattern without establishing which variables
the runner actually held.

I recorded 244 approval evaluations associated with 216 harness
instances. Heights below are estimates and include the note reservation
when applicable. The first broker row is
`a_broker_runs_destination_and_limits_are_checked_before_any_dialog`;
the second is
`a_broker_run_shows_and_lists_its_origin_apart_from_its_base_path`.
The library row is
`a_run_reports_the_grants_whose_destination_answered_401`.

| Request | TMPDIR length 23: characters / pixels | TMPDIR length 70: characters / pixels | Projected height with TMPDIR length 70 and eight 15-letter ASCII names with seven-digit pids |
|---|---|---|---|
| Broker destination and limits | 1019 / 626 | 1113 / 683 | 702 pixels |
| Broker origin and base path | 1184 / 708 | 1231 / 727 | 746 pixels |
| Library request reporting 401 responses | 1180 / 727 | 1274 / 765 | 784 pixels |

The projection replaced the requester's displayed chain in a copy of
an approval request; it did not create that process chain. The boundary
pair measured 884 pixels for the refused request and 865 pixels for the
one-character-shorter request that reached the dialog. These figures
support the stated configurations, not universal margins. Deliberately
near-limit or over-limit tests and dialogs that scroll cannot be included
in a claim that every request has those margins.

Two limitations of my preparation are included in the command count.
The first run's six permission failures came from my mode-0775 TMPDIR
subdirectory. I corrected that temporary directory to 0700 and removed
its residue before rerunning; it was not a product failure. My first
metric logger interleaved concurrent writes. I discarded that collection
and repeated it with one write per record. Neither correction changed a
repository file.

I read the saved logs of the first three CI runs and the supplied
investigation's results and measurements. I checked that the original
staged test file matched the final validated copy's checksum. I also
verified that the earlier threat-model history was unchanged apart from
the new row and appended entry, and both unstaged and staged
`git diff --check` passed during the original review. Those readings do
not make the supplied executions my own.

I could not determine the runner's actual environment. Directory paths,
process ancestry and scheduling still vary. I found no reason introduced
by this change for the later no-default-features run or TMPDIR cleanup
to fail; my two full suites passed under the hostile environment.
An empty TMPDIR does not establish that no process survives. CI06 remains
an accepted separate follow-up. I accept the plan to commit with the
noreply identity and no session link, push main with the maintainer's
authorization, and mark CI done only after all three jobs pass.

I did not run GitHub Actions, use the external network, run fmt, clippy,
GTK, MSRV, `cargo doc` or the release-build refusal for this review. I did
not reproduce the runner's exact toolchain or cache, a real transition
in pid digits, or the dialogs' appearance. I did not observe Gemini's or
the subagent's original executions. After the wording corrections, the
maintainer's agent reports that `git diff --check` and
`cargo fmt --all --check` passed; those are its results. Its full matrix
in progress is not part of my results, and I do not state its outcome.

The original review's temporary copy, target, scripts and logs were
removed. Its supervisor reaped 87 adopted descendant statuses; no review
process was left running. No real vault, running agent or manual reading
of another process's /proc was used. The original review changed no
repository file or index entry. This confirmation changes only the two
unstaged additions to this history; it does not change the index.

**Final matrix (the maintainer's agent, Claude Code, AI-assisted,
2026-11-20).** After the five corrections and before the reviewer's
record above, the twelve checks of AGENTS.md ran on the staged tree, one
after another, and all exited zero: `cargo test --all-features` passed
663 tests with 2 ignored (the descriptor-limit test's child rerun
counted once), `cargo test --no-default-features` 553 with 2 ignored,
the dialog's 9 and the manager's 45. Whether the runner agrees is what
the next run of the CI says.

**2026-11-20 — The fourth CI run passed.**

A record of a result, read by the maintainer's agent (Claude Code,
AI-assisted) from GitHub; not a review. The fourth run of the workflow,
on the push of `742a8ff` (2026-11-20 05:24 to 05:34 UTC), passed all
three jobs:

- the GTK clients: clippy, and the widget tests of the dialog and the
  manager on a virtual display;
- the minimum supported Rust version: both checks;
- the default members: formatting, both clippy runs, and
  `cargo test --all-features`, which had failed in each of the first
  three runs; then, for the first time on the runner,
  `cargo test --no-default-features`, the documentation with warnings
  denied, and the release build that must refuse the broker's feature
  for tests. Each test step ends by requiring an empty `TMPDIR`, and
  passed.

So the corrections of the three earlier entries hold on the runner for
this run: the two tests of a request too tall, the test of revocation at
the leader's exit, and the two tests of the broker's dialog, with the
client of the end-to-end tests in an environment of the tests' own.

What one passing run does not show. It is one run: the second run's
failure was intermittent, and nothing here measures how often a test
may still fail there. What the runner's environment holds is still not
known. CI06, the process an older test leaves running for some thirty
seconds, is open, and an empty `TMPDIR` does not show such a process.
The directory and the process chain of a request still vary from
machine to machine, within the margins recorded above. The roadmap now
gives the CI as done, with these limits.
