# Threat model

This document states what Rusthorse protects, against whom, how, and — just
as important — what it does not protect. If you find a gap between this
document and the code, that is a bug; please report it
([SECURITY.md](../SECURITY.md)).

- Applies to: Rusthorse 0.1.x
- Last reviewed: 2026-11-03 (broker phase 1 implementation and documentation;
  see [review history](#11-review-history))

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
   in the authentication header it builds for the profile's destination and
   routes, over verified TLS. A grant approves a capability, not each API
   call: allowed requests can spend credit or access data without another
   dialog. Mixed runs still deliver values for their ordinary bindings.
   Neither mode makes a hostile approved command harmless (L3–L5, L16).
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
| Broker tokens | Bearer capabilities usable through the local listener until the grant ends, within its routes and limits. |
| A grant's credential in broker memory | Each broker holds only its own grant's credential; memory disclosure there must not expose the whole vault. |
| Broker profiles and HTTP traffic | Profiles determine authority; prompts, responses and opaque bodies may contain sensitive data. The broker does not interpret them. |
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
  trust concerns the granted API operations, not direct receipt of the
  credential. The broker is trusted with that credential and runs as the same
  user; it is not a code-execution sandbox (L16).

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
    BR -- "verified TLS + credential header" --> API["profile destination"]
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
| P2 | The approved command line, program, directory and environment are the ones used. | The agent resolves the program to a canonical path, fixes arguments, directory and environment, shows them, checks the program's and directory's identity (device and inode) again after you answer, and spawns the command itself ([ADR 0002](adr/0002-agent-mediated-execution.md)). A custom client cannot substitute another command. A swap in the instant between that check and the start of the program, and changes to file *contents*, are not prevented (L4). | A1, A2 |
| P3 | An approval is acted on only if the vault did not change while you decided. | A vault *generation* counter is bumped on unlock, lock and every saved change. The generation is checked under the same lock that reads the values, so an edit, lock or reload while the dialog was open cancels the request. For ordinary `run`, reading the values *consumes* the approval: a `lock` after that point does not stop the command. A `lock` while the master password is being typed cancels the unlock. For `broker_run`, the same state lock also registers grants as `starting`; any lock ends starting grants, and all grants must still be starting before the command starts. Automatic locks can preserve already active grants by profile (L22). | A1, A2 |
| P4 | Secrets used by `run` are not placed in a process the requester can inspect with a debugger. | The command is a child of the agent, not of the requester; Yama blocks `ptrace` from outside its ancestry. See L3 for `/proc/<pid>/environ`. | A1, A2 (partially) |
| P5 | Secret values printed by an approved command do not reach the requester verbatim. | With redaction (the default), the command's stdout and stderr are pipes owned by the agent; the filtered output travels to the requester as data frames over the socket, and the requester writes it itself. The command's stdin is `/dev/null`, or an agent-owned pipe fed from the requester's data frames with `run --stdin`. The requester's own descriptors never reach the command or the agent, so there is no unfiltered way back. Exact-match only (L5). Broker tokens are filtered from command output too. Independently, the broker redacts literal copies of its credential from response bodies and drops relayed headers whose values contain it. With `--no-redact`, the command instead gets the requester's input/output descriptors directly and its output is unfiltered; HTTP response redaction stays on. | A1 |
| P6 | The master password and new secret values never pass through a requester. | The agent asks for them in its own dialogs; the protocol has no field for the master password. Imports from GNOME Keyring and `.env` files are read by the agent (`import_from`, [ADR 0012](adr/0012-import-read-by-the-agent.md)): the requester names items and entry names, and the dialog names the source; only the older `import` request carries values from a client, and its dialog says so. zenity's answer comes back over a socket pair, which other processes cannot open through `/proc/<pid>/fd` (a pipe could be). A *new* vault's password is asked by the agent too (`create_vault`, sent by `rusthorse init` and the manager's Create vault…, [ADR 0011](adr/0011-first-start-from-the-manager.md)); the one exception is `rusthorse init` when no agent serves that vault, which reads it in the CLI (terminal or dialog). | A1, A2 (not on X11, L2) |
| P7 | Dialogs are not answered by the requester and say what they mean. | Separate processes on the desktop, not in the terminal: `rusthorse-dialog` ([ADR 0006](adr/0006-own-dialog-program.md)) or, when it is not installed, zenity — started from an absolute path with a minimal environment and `/` as working directory, answering through a socket pair; `rusthorse-dialog` also gets its request through that socket (framed, versioned, with an identifier the answer must repeat), runs under a deadline after which it is killed, reads no per-user GTK configuration, shows plain text only, and keeps **Allow** disabled until the end of a request that does not fit has been in view; requester-controlled text is escaped (only ordinary characters are drawn as themselves, every other one as a `\u{…}` escape; markup characters for zenity's question dialog, backslashes and underscores for its entry dialog); entries are identified by full path and the start of their UUID, so two entries with the same title in different groups do not look alike (unless a file written by another program gave them UUIDs that start alike, L9); requests whose dialog text would exceed 4000 characters (or 1000 for the command line, program path or directory of a `run`) are refused, never truncated, and with zenity also those too tall to read at once (estimated for an 11-point font); default button **Deny**; unanswered dialogs are denied; only exact, expected answers count as approval. | A1, A2 (not on X11 or through accessibility, L2) |
| P8 | Only your user can talk to the agent. | Socket in a `0700` directory, mode `0600`, `SO_PEERCRED` uid check. The broker's separate loopback HTTP listener requires its grant's token, checks its exact form and compares it in constant time; it validates Host and refuses Origin. TCP has no Unix peer credentials (L21). | A4 |
| P9 | The decrypted vault is not held longer than needed. | Auto-lock after 15 minutes without an *approved* use — `status`, `list`, `show` and denied requests do not postpone it; `rusthorse lock`; lock on any save failure. Broker requests do not postpone the idle lock. The decrypted vault is dropped at lock, but a profile can keep its grant credential in its broker through automatic locks (L22). | A1, A2, A6 (window) |
| P10 | The agent's memory is not readable by other same-user processes and is not dumped. | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the agent. Dialogs and approved commands inherit `RLIMIT_CORE=0`, but `execve` makes them dumpable again, and with a piped `core_pattern` (systemd-coredump) whether a crash is stored is up to that handler. Each broker applies the same hardening before reading Install. Zeroizing buffers do not erase every library or allocator copy (L7). | A1, A2 |
| P11 | The vault is confidential at rest. | KDBX4: AES-256, Argon2id (64 MiB, 20 passes for new vaults); files `0600`, directories `0700`. | A4, A5 |
| P12 | Every decision leaves a record. | JSON Lines audit log, `fsync`ed per record. Unlocking and approval-gated actions fail closed: if the record cannot be written, the vault stays locked or the action does not happen. Broker admission also requires a durable record before forwarding, and grant creation before command start. Completion and grant-end records are best effort; a failed request-completion record revokes the grant. Revocation contains the broker before waiting for audit, and abrupt process death can leave missing end records (L23). | A1 (detection; L13) |
| P13 | The agent stays available under request floods. | The whole request must arrive within 10 s of connecting (a deadline, not a per-read timeout); at most 64 connections and 8 requests waiting for a dialog at once; frames ≤ 4 MiB; imports ≤ 100 entries; vault files ≤ 128 MiB. | A1, A2 (availability) |
| P14 | Approved changes are all-or-nothing and match the disk. | Every change runs as a transaction that is rolled back if any part fails (for example one invalid entry in an import); if saving fails, the vault is locked so memory never holds unsaved changes. A save that fails after the file was replaced (syncing the directory) is reported as an unknown outcome, never as "not saved". | Accidents |

Broker-specific bounds are in [ADR 0013](adr/0013-credential-broker.md): 16
entries in the grant registry per agent (normally revoked brokers stay listed
and count until run cleanup; broker exit removes the entry sooner), 16
admitted/reserved requests and 64 connections per broker, 16 MiB per request
body, 64 MiB of retained request bodies and 64 MiB of upstream body per
response, before redaction. Only exact preset routes pass; the broker drops
other headers, refuses redirects and encoded responses, and builds Host, SNI
and authentication itself. Its own lifetime task and forwarding checks use
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
| **Allow for N** (opt-in, `--remember`, off by default) | A reusable capability: for N minutes, any request with the same entries (by UUID), the same vault generation, command line, program, directory, redaction setting and environment runs **without asking**. It does not cover what the command reads — its standard input, files, network responses — which can differ on each run (L8). |
| **Deny**, closing the dialog, timeout | Nothing. The command does not run. |

Locking, unlocking and any saved change invalidate remembered approvals.
`broker_run` never uses them. Its approval creates a grant whose individual
requests need admission and an audit record, but no new human dialog.

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
`/proc/<pid>/environ`. Ordinary bindings contain the secret; broker bindings
contain a token. Marking the command non-dumpable would prevent that, but
`execve` resets the flag. A stolen broker token still works through its
listener while the grant lives, within its routes and limits. *Mitigation:*
short-lived commands, narrow grants and isolation (§8). Broker phase 1 keeps
the source credential out of that binding's environment; it does not hide the
token.

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
broker binding, the stored profile fixes the credential's destination and
routes. Requester proxy/CA settings do not configure the broker, which starts
with an empty environment. The command can still misuse allowed operations,
send the token or other data in an opaque body, or send its token elsewhere
without using the broker. `NO_PROXY` helps cooperative clients reach loopback;
it is not enforcement.

### L5 — Redaction only catches exact copies in the command's output

A command that prints the secret encoded (base64, hex, URL-encoded), split,
reversed or partially is not redacted, and secrets shorter than 4 characters
never are. A command can also send the secret over the network, write it to a
file, or put it in its own logs — none of which pass through the redactor.
Redaction prevents *accidental* disclosure on stdout/stderr; it is not a
defense against exfiltration by a command written to leak.

For a broker binding the command does not receive the source credential. The
broker's response redactor matches its literal bytes across chunks, using a
bounded look-behind buffer; compressed responses are refused and headers with
credential-bearing values are dropped. Encoded or transformed copies returned
by the destination are not caught. Output redaction filters the token by
default; `--no-redact` exposes anything the command prints, including that
token. HTTP response redaction stays on in either mode.

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
for commands whose inputs you control. See
[ADR 0005](adr/0005-remembered-approvals-opt-in.md). Broker grants are a
separate capability: no `--remember`, but each grant permits multiple API
calls until its limit or end. A request count is not a spending limit, and the
broker does not inspect prompts or other bodies.

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

### L21 — A loopback token is a bearer capability

Any local user can connect to a broker's TCP listener; knowing its port is not
enough, but possession of the token is. There are no peer credentials on that
HTTP hop and it is not encrypted. The fixed Host check and rejection of Origin
limit browser/DNS-rebinding uses; they do not isolate a hostile process with
the token. The agent holds the port until the run releases it, so a
replacement process cannot claim that port while the grant is retained. A
client can put its token in an opaque request body, which is forwarded; the
broker only excludes it from the headers it builds or relays upstream.

### L22 — Automatic locks can leave grant credentials in brokers

AI profiles default to `automatic_locks: continue`, with a 12-hour maximum
lifetime. Screen lock, suspend and idle lock drop the decrypted vault but
leave already active/exhausted grants running. All starting grants end on any
lock; explicit `rusthorse lock`, entry changes, failed saves, manual
revocation, command end and expiry end grants regardless of this policy. Use
`end` for profiles that must stop with the desktop. L20's signal and inhibitor
limits still apply; revocation cannot promise to beat suspend.

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
broker cannot reject that spelling, but never forwards the fragment and still
checks the resulting path. Hyper-generated malformed/framing errors can also
precede the broker's JSON errors and retry hints.

The fake HTTPS tests cover the protocol, not every SDK's behaviour. By hand,
with a real key (2026-11-04), the Anthropic Python SDK 2.4.0 worked through
the broker for the requests tried; Claude Code's requests went through it,
and the API answered them `400`, as it answered SDK requests with some of
Claude Code's parameters sent with the key by value, so no Claude Code
answer through the broker has been seen yet. SDK configuration can
override environment variables or send both Anthropic token headers; both
must match. With zenity, a run requesting two or more grants may exceed the
dialog height estimate and be refused before asking. `rusthorse-dialog`
scrolls long approvals; character limits still apply, and no approval is
truncated.

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
- Prefer broker bindings for the supported HTTP routes. Set provider-side
  spending limits, narrow the profile's lifetime/request count, and disable
  SDK retries where practical: every admitted attempt spends a use.
- Use `rusthorse grants` to inspect grants, `rusthorse grants revoke ID` for
  one, and explicit `rusthorse lock` to end all grants. Screen lock alone
  preserves `continue` grants.
- Look at `rusthorse audit` from time to time.

## 10. Planned improvements

- **Broker phase 2**: pinned TLS and private devices, Basic authentication,
  generic profiles, narrow administrative operations and more presets. Phase
  1's Anthropic/OpenAI-compatible HTTP broker is implemented.
- **SSH agent**, then database connectors: see
  [ADR 0013](adr/0013-credential-broker.md) for their scope.
- **Isolation support** (§8): uid allow-list on the socket and documentation
  for running agents as a separate user.
- **One cgroup per approved command** (L17), with resource limits.
- **Bounded KDF parameters** before unlocking (L12).
- **Per-entry policies**: restrict an entry to listed programs or hosts.
- **Remembered-approval management**: the manager already lists and revokes
  broker grants; remembered approvals remain separate.
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
| 2026-11-02 | Broker foundation: independent verification V01–V07, then Codex B01/S1–S3 (AI-assisted). | Fixed; foundation ready. See the phase 1 entries below. |
| 2026-11-02 | Broker shared helpers: implementer's checks (AI-assisted). | Reviewed with the whole; mutation limits recorded below. |
| 2026-11-02–03 | Phase 1 pieces B–E: implementation checks, independent verification and fixes (AI-assisted). | Fixed or explicitly documented; whole review still required. |
| 2026-11-03 | Whole phase 1 at `0d71da0` (Codex, AI-assisted). | Not ready: P01–P06; fixes below. |
| 2026-11-03 | Pieces F and G: system tests and packaging, independent verification and fixes (AI-assisted). | Coverage and packaging fixes, accepted test gaps and incident below. |
| 2026-11-03 | Re-review at `9f7599b` (Codex, AI-assisted). | Ready: no medium or higher finding left; Q01/Q02 low, dispositions below. |
| 2026-11-03 | Documentation consolidation at `4ff834a` (Codex, AI-assisted). | Body and history aligned to the implementation; Q01 was pending then and is recorded below as fixed in `b999e72` and `3953912` (merged in `453e772`). Manual SDK validation remains pending. |
| 2026-11-03 | Documentation revision at `453e772` (maintainer's agent review; Codex corrections, AI-assisted). | Ten requested corrections and reread dispositions below; reviewed guarantees restored and Q01's exact cleanup recorded. |
| 2026-11-03 | Final review at `4b0186d`: independent Q01 verification, Q02 and documentation (Codex, AI-assisted). | Not ready: R01 medium and R02–R04 low. Q01 partly resolved; Q02 confirmed resolved. Fixed in `17c1965` (packaging through a private staging directory); see below. |
| 2026-11-03 | Re-review at `88b9ea4`: private staging, R01–R04, manifest-path guard and history (Codex, AI-assisted). | Ready: R01–R04 and the manifest-path finding confirmed resolved; S01 low (a mutation-coverage gap) fixed in `3ca5ebb`. |
| 2026-11-03 | Test hygiene and behaviour under load: the maintainer's agent's T01–T05, fixed in `d8f2eb9` and `e86e6bd`, then their review (Codex, AI-assisted). | Ready: no medium or higher finding; T01, T03–T05 confirmed for the reported cases, T02 partly resolved; U01–U03 low, fixed in `7a1d63b`. |
| 2026-11-04 | Confirmation of `7a1d63b` and its history at `4ef519f` (Codex, AI-assisted). | Ready: U01–U03 confirmed resolved and the history accurate; V01 low and V02 low, fixed in `49bf590`. |
| 2026-11-04 | The feedback for a key the destination refused, and an edit's answer, at `c0aebc0` and `4fefa4c`, with the maintainer's manual test so far (Codex, AI-assisted). | Not ready: W01 medium (an edit's answer printed a title from the vault unescaped), W02 and W03 low; W01 and W02 fixed in `2fafe05`, W03 partly, completed in `f51391c` (X02). The count of 401 answers held under every probe. |
| 2026-11-04 | Confirmation of `2fafe05` and its history at `db0af0e` (Codex, AI-assisted). | Not ready: W01 and W02 confirmed resolved, W03 partly; X01 medium (older than this work: `list` and `show` printed what the vault holds unescaped), X02 and X03 low; X02 and X03 fixed in `f51391c`, X01 partly, completed in `f20d7d0` (Y01, Y02). |
| 2026-11-04 | Confirmation of `f51391c` and its history at `5dd639a` (Codex, AI-assisted). | Not ready: X02 and X03 confirmed resolved, X01 partly; Y01 medium (`open` printed a URL from the vault unescaped) and Y02 low, both older than this work, fixed in `f20d7d0`. |
| 2026-11-04 | Confirmation of `f20d7d0` and its history at `df52e23`, with a last sweep of what the CLI shows (Codex, AI-assisted). | Ready: Y01 and Y02 confirmed resolved; no other output shows supplied text unescaped; Z01 low (a test's stand-in script broke with a TMPDIR holding a space), fixed in `2a4549d`. |

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
ADR at `aff56e1` left 25 findings (F01–F25), ten open questions and further
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
commits, initially checked against code at `4ff834a`. Q01's follow-up and this
documentation revision use `453e772`, which includes its two fixes. It records
historical results, not a fresh rerun of every reported mutation.
Finding/mutation names below are scoped by piece to avoid collisions. Severity
is the reviewer's; notes without one remain observations rather than invented
security findings. Earlier design-review entries above remain historical.

**2026-11-02 — Foundation (`e9f0b46`, then `a7e26b5`).**

Review (Claude independent verifier, AI-assisted, 2026-11-02; verdict: needs
fixes), requested before the broker, agent, CLI and manager depended on the
shared types and wire shapes. The original implementation had 16 mutation
checks, all caught; the seven fixes had 27, all caught.

| Finding | Disposition |
|---|---|
| High — V01: optional fields on plain run/edit let a protocol-7 agent silently drop broker authority after a restart between connections. | **Fixed in `a7e26b5`:** separate `broker_run` and `broker_edit`; plain run/edit refuse broker fields; protocol-7 decoding and real old-agent probes refuse the new requests whole. |
| Medium — V02: credentials of 1–8192 bytes were accepted, including values below the redactor's minimum. | **Fixed in `a7e26b5`:** 8–4096 visible ASCII characters; compile-time relation to the redactor minimum and boundary tests. |
| Medium — V03: request-body limit was 32 MiB and the aggregate budget was missing. | **Fixed in `a7e26b5`:** 16 MiB per body, 64 MiB budget constants. |
| Medium — V04: the control channel could not express `vault_changed`. | **Fixed in `a7e26b5`:** the end reason and its serialization tests. |
| Low — V05: malformed/disallowed routes returned 400 rather than the specified 404. | **Fixed in `a7e26b5`:** route/query failures are 404; non-origin-form targets remain a framing 400. |
| Low — V06: header, Ready, resolver and control-EOF deadlines lacked shared constants. | **Fixed in `a7e26b5`:** phase 1 constants in `broker_protocol.rs`. |
| Low — V07: the temporary agent refusals and plain-edit clear guard had no policy tests. | **Fixed in `a7e26b5`:** end-to-end refusal tests, later replaced/extended as the real handlers arrived. |

Review (Codex, AI-assisted, 2026-11-02; verdict: ready), requested on the
fixed foundation against ADR 0013, before the parallel pieces used it.

| Finding or suggestion | Disposition |
|---|---|
| Low — B01: cursor syntax, ID length and all-dot segments differed from the ADR. | **Fixed in `f600896`:** cursors accept the same colon-bearing ID syntax; 128-character IDs/cursors, 1–4-digit limit and rejection of all-dot segments are explicit in the ADR. Five mutations for this commit, including S3 below, all caught. |
| Suggestion — S1: Admit's documentation implied the body was already read. | **Fixed in `f600896`:** declared length and budget are checked before admission; body reading follows it. |
| Suggestion — S2: prove preservation through KeePassXC itself, not only a compatible fixture. | **Deferred, then tested in `beaf9af`:** an ignored round-trip test was run with KeePassXC 2.7.6; it is not required in CI where that program may be absent. |
| Suggestion — S3: cap Install's lifetime by the stored profile too. | **Fixed in `f600896`:** validation rejects an excessive lifetime, with a mutation check. Independent enforcement at runtime was still incomplete until P02. |

**2026-11-02 — Shared helpers (`625df43`).**

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

Implementation checks (Claude, AI-assisted, 2026-11-03) in `a28b83b` and
`18689b4`, requested for the HTTP process and fake HTTPS tests. The WIP checks
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
fixes), requested before integration. Fixes are in `256f805` unless another
commit is named.

| Finding | Disposition |
|---|---|
| Medium — B-V1: the body budget was released while Hyper still retained unwritten bytes. | **Fixed in `256f805`:** the reservation is shared by forwarding until the response head and by the owned Bytes until Hyper releases them; writev avoids an unaccounted copy. Tests cover a stalled reader, no response and an early response. |
| Low — B-V2: no test proved an active stream survives the connection idle timeout. | **Fixed in `256f805`:** a stream four times longer than the idle limit completes; dropping its busy guard fails the test. |
| Low — B-V3: TLS/client-pause deadlines, resolver wiring, panic exit and several revocation races lacked tests. | **Fixed in `256f805`:** targeted tests, biased revocation branches and a test-only panic trigger. |
| Low — B-V4: “never reads the environment” was stronger than the dependencies permit. | **Fixed in `256f805`, documented here:** the broker's own production code reads none; loader/resolver/runtime variables are unset by the agent. An explicit resolver-thread stack size avoids RUST_MIN_STACK. |
| Low — B-V5: Revoked's ordering did not state that all admission answers must arrive first. | **Fixed in `256f805` and `d0c4acb`:** broker waits for every answer/Finished; agent refuses pending admissions immediately on revoke. Early-ack tolerance is documented in `6ed1ad7`. |
| Low — B-V6: a test-upstream build could look like a production helper. | **Fixed in `256f805` and `095414b`:** compile-time release guard, check marker, doctor refusal. Runtime use with an empty environment was revisited and fixed as P05. |

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
registry, preparation transaction and every grant-ending event (`ac0bfc7`,
`d29ec09`). WIP findings and their subsequent status:

| Finding | Disposition |
|---|---|
| High — C-W1: a grant revoked while starting could attach an unrevoked broker and hang cleanup. | **Fixed in `d29ec09`, strengthened by P03 in `d8c8fe3`:** reject attachment after starting ends; register before credential delivery. |
| Medium — C-W2: a stuck broker writer could delay revocation under the writer lock. | **Fixed in `d29ec09`:** bounded/non-blocking writer acquisition and forced cleanup. |
| Medium — C-W3: one realistic broker grant did not fit zenity's approval estimate. | **Fixed in `d29ec09`:** shorter factual dialog text and a height test; multiple grants can still be too tall. |
| Low — C-W4: late admission refusals could be missing from end counts. | **Fixed in `d29ec09` and refined in `d0c4acb`:** registry accounting and answer ordering. |
| Low — C-W5: the unlock barrier waited on the unlock audit record. | **Initially reported fixed in `d29ec09`; reopened as P01:** deciding revocation alone did not contain the broker. Actual containment before audit is fixed in `c1249d5`. |
| Low — C-W6: control work needed a bounded queue. | **Fixed in `d29ec09`:** JOB_QUEUE 256 and violation/cleanup tests. |

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
| Medium — C-F1: no test proved a failed grant-created record prevents the credential handoff. | **Fixed in `d0c4acb`:** unit test rejects the run, starts no broker and leaves no grant; C-M1 catches ignoring that write error. |
| Low — C-F2: audit work could delay pending admission answers needed for Revoked. | **Fixed in `d0c4acb`:** the reader reserves admissions, revoke answers them at once, and containment work does not block the audit worker. |
| Low — C-F3: retained-listener protection against port reuse was untested. | **Fixed in `d0c4acb`:** binding the port fails until the run releases it. |
| Low — C-F4: activation's starting-state guard was untested. | **Fixed in `d0c4acb`:** a revoked preparation never becomes active. |
| Low — C-F5: expiry timer and StopGrants were not exercised. | **Partly fixed in `d0c4acb`:** timer tests added; timer-start failure later fixed by P02. **Accepted coverage gap:** C-V20/C-M8 removes StopGrants and survives; direct stop_all is tested, but serve returning/unwinding with grants needs a test seam. SIGTERM does not run that guard (L23). |
| Low — C-F6: starting state and status/capacity counts were unclear. | **Fixed in `d0c4acb`, documented here:** status counts starting/active/exhausted; listing and capacity also retain revoked grants. |
| Low — C-F7: automatic locks preserved starting continue grants contrary to the ADR. | **Fixed in `d0c4acb`:** every lock ends all starting grants. |
| Low — C-F8: fingerprint keys and collision claims exceeded what RandomState promises. | **Fixed in `e729ebd`, documented in L22:** one key drawn on its own thread (fallback to the caller if spawning fails), domain-separated outputs; no unconditional cryptographic 128-bit claim. |
| Low — C-F9: the manager's AgentConfig literals would not compile after integration. | **Fixed in `0d71da0`:** new test configuration fields supplied at the merge. |
| Low — C-F10: failures after approval could lack an aborted record. | **Fixed in `d0c4acb`:** shared best-effort aborted recording, including plain runs; P01 subsequently ensured cleanup precedes that audit. |
| Low — C-F11: missing Python silently skipped policy tests. | **Fixed in `d0c4acb`:** fail unless the explicit RUSTHORSE_TEST_WITHOUT_PYTHON opt-out is set. |
| Low — C-F12: multi-broker preparation failure and a lock during startup lacked end-to-end tests. | **Fixed in `d0c4acb`:** stand-in brokers force both failure paths and verify complete cleanup. |

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
commands clients would use (`d13f237`, `948234a`, `a54cb22`). Audit output was
escaped because same-user editable records could forge terminal lines (one
mutation caught); the CLI's 29 mutations were all caught. A later independent
review found these six low findings (Claude, AI-assisted, 2026-11-03; verdict:
ready):

| Finding | Disposition |
|---|---|
| Low — D-V1: grant-table escaping tests missed most agent-controlled cells. | **Fixed in `cad9d14`:** hostile values in every cell and order are tested. |
| Low — D-V2: duplicate ordinary bindings could reach the agent unnecessarily. | **Fixed in `cad9d14`:** early CLI refusal, no request sent. |
| Low — D-V3: status called every retained grant active. | **Fixed in `cad9d14`/`d0c4acb`, documented here:** label/count semantics distinguish starting/exhausted from revoked listings. |
| Low — D-V4: the Claude Code recipe and compatible-origin wording promised unverified support. | **Fixed in `cad9d14`, documented here:** explicit origin and pending manual validation; no claim of testing with a real key. |
| Low — D-V5: version checks and doctor-without-agent tests missed paths. | **Fixed in `cad9d14`:** checks before edit/grants effects and targeted fake-agent/doctor tests. |
| Low — D-V6: doctor wording implied it parsed and validated the CA certificates. | **Fixed in `cad9d14` and installation docs in `7dc27dc`:** doctor checks the file; the broker parses certificates at grant startup. |

The fixes had 15 mutations, all caught; prose is supported by code review, not
counted as mutation-tested behaviour. CLI broker operations refuse old agents
and never fall back to a value binding. Q02 later clarified SDK
variable/header wording further.

**2026-11-02–03 — Piece E: manager.**

Implementation checks (Claude, AI-assisted, 2026-11-02) completed the WIP in
`af6f830`, at the maintainer's request for a metadata-only grants page and
profile display. All 24 implementation mutations were caught.

| Finding or observation | Disposition |
|---|---|
| Low — E-F1: maximum lifetime rounded down despite “at the latest”. | **Fixed in `af6f830`:** round up, with boundary tests. |
| Low — E-F2: “unverified” was appended to requester-controlled text. | **Fixed in `af6f830`:** put it in the fixed field label. |
| Low — E-F3: listing/revocation could leave controls waiting ten minutes. | **Fixed in `af6f830`:** 30-second limit; whole-job enforcement refined below. |
| Low — E-F4: lifetime display arithmetic could overflow. | **Fixed in `af6f830`:** saturating arithmetic and u64 boundary test. |
| Info — E-F5: listing epochs changed redundantly at request start and end. | **Changed in `af6f830`:** invalidate at completion; both remaining invalidations tested. |
| Low — E-F6: manager docs attributed agent enforcement to the manager. | **Fixed in `af6f830`:** describe the client's behaviour and the agent's authority separately. |
| Low — E-F7: a partial list of end reasons looked exhaustive. | **Fixed in `af6f830`:** qualified wording and warning about already-sent requests. |
| Info — E-F8: replacing an imported entry removed its profile without a manager note. | **Fixed in `af6f830`:** import warning. |
| Test-gap observation — E-F9: missing refused/unanswered requests, empty/no-agent and stale-listing cases. | **Fixed in `af6f830`:** fake-agent widget scenarios, never real credentials. |

Review (Claude independent verifier, AI-assisted, 2026-11-03; verdict: ready),
requested before integration; six low findings:

| Finding | Disposition |
|---|---|
| Low — E-V1: refreshed rows could move a different grant under a Revoke click. | **Fixed in `a22687f`:** stable keyed rows, disappeared grants shown ended in place, tests bind the clicked ID. |
| Low — E-V2: error-text filtering lacked a widget test. | **Fixed in `a22687f`:** hostile listing/revocation messages tested through dialog_text. |
| Low — E-V3: missing-vault note, unreported status and refresh-after-request paths were untested. | **Fixed in `a22687f`:** fake-agent and first-start coverage. |
| Low — E-V4: the stated 30-second bound actually allowed about 50 seconds across job stages. | **Fixed in `a22687f`:** one deadline from the start of the whole job, also for human requests. |
| Low — E-V5: starting grants lacked their intended description and count semantics. | **Fixed in `a22687f` and `d0c4acb`:** starting label and status count aligned. |
| Low — E-V6: shared architecture/changelog/invariant docs lagged the feature. | **Documented in this 2026-11-03 consolidation:** protocol 8, grants page, profiles and ownership of secrets. |

All 11 verification-fix mutations were caught; parallel load checks and
private-Xvfb light/dark inspection used fake data. Grants carries no token;
profile forms stay read-only and the manager never sends broker_edit.

**2026-11-03 — Whole phase 1 at `0d71da0`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: not ready), requested by the
maintainer to examine the seams after pieces B–E were integrated, before
system tests and packaging were finished.

| Finding | Disposition |
|---|---|
| Medium — P01: unlock decided revocation but waited for audit before containing brokers. | **Fixed in `c1249d5`:** contain first, record outside the state lock, recheck generation before publishing; aborted-run cleanup also precedes its audit. |
| Medium — P02: expiry depended on an agent timer that could fail to start, and the broker did not independently end open work. | **Fixed in `c14c4f9` and `24bea7e`:** refuse grants without the agent timer; broker boot-time task and per-step deadline checks drop credentials/work without an unsolicited Revoked. |
| Medium — P03: Install could deliver the credential before the process was registered for revocation. | **Fixed in `d8c8fe3`:** register Link and non-blocking Install under one registry lock, only while starting; failures kill/reap. |
| Medium — P04: another revoker could treat a requested kill as completed containment. | **Fixed in `d8c8fe3`:** Running/Ending/Gone; publish Gone only after kill/reap; waiters share confirmed/dead state. |
| Medium — P05: a test build started by the production agent could reach loopback. | **Fixed in `4c2c5d4`:** absent RUSTHORSE_BROKER_TEST_ROOTS selects production settings before other hooks are read; agent env_clear is the runtime boundary. |
| Low — P06: the manager's Anthropic snippet bound the wrong variable for the library recipe. | **Fixed in `37e97c6`:** ANTHROPIC_API_KEY and BASE_URL, note to leave AUTH_TOKEN out, separate Claude Code recipe. |
| Suggestion — document early Revoked tolerance. | **Fixed in `6ed1ad7`:** the agent's tolerance is explicit; the real broker still orders its acknowledgement after all answers/Finished. |
| Suggestion — test P01–P05 with both real components. | **Partly covered and accepted:** F tests P01, expiry and production settings with real components. Deterministic registry/stand-in tests force P03/P04 interleavings; doing so in a full-system test would require new agent test hooks. |

Fix verification (Claude, AI-assisted, 2026-11-03), requested for these
findings: the agent branch tip is `6ed1ad7`, not the superseded `36db9c3`; 11
mutations all caught. Install/check atomicity is by one critical section, not
by a test interrupting inside it. A non-blocking Install relies on room for
the <=64 KiB frame in the Unix socket send buffer; an incomplete write or
WouldBlock fails closed (a short sendmsg may be completed by the remaining
write_all). Broker/manager fixes end at `37e97c6`: 16 mutations all caught,
with 36 loaded lifetime-test runs. A long-sleep mutation first survived; a
paused-clock suspend test then caught removal of periodic CLOCK_BOOTTIME
rereads. No claim of a real-time scheduling bound follows from these tests.

**2026-11-03 — Piece F: full-system tests.**

Implementation checks (Claude, AI-assisted, 2026-11-03), requested to prove
ADR 0013 with the real library agent and broker, fake HTTPS and scripted UI
(`1117cb8`, `beaf9af`). WIP checks corrected false-positive stream-cut
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
| Medium — F-V1: failed unlock coverage never reached a cancelled unlock that had already read a new fingerprint. | **Fixed in `170ea78`:** automatic-lock password hook, surviving stream, cancelled attempt preserving the old fingerprint, then a valid unlock revoking it; F-N27 caught. |
| Low — F-V2: Lock and RevokeAll tested only one grant. | **Fixed in `170ea78`:** two concurrent runs/streams for all-grant ends and a one-grant-only control; F-N29/N30/N31 caught. |
| Low — F-V3: failing tests could leave late-writing agents/brokers and temporary files. | **Fixed in `170ea78`:** System Drop locks, releases gates, signals command loops and waits for runs/registry/end records before TempDir destruction; F-N32/N33/N36 caught. F-N34 remains a gap below. |
| Low — F-V4: one route could not prove completion records belonged to the right request number. | **Fixed in `170ea78`:** alternate two routes and compare each numbered admission/finish; F-N28 caught. |
| Low — F-V5: environment requirements were incomplete and pipe synchronization depended on kernel wchan names. | **Fixed in `170ea78`:** module requirements, full pipes and owned-descriptor observation; nix mkfifo replaces the external command, no wchan; F-N38 caught. |
| Low — F-V6: default workspace/CI checks omitted the broker. | **Fixed in `7dc27dc`:** broker is a default member; feature/no-feature checks and CA preflight cover it. |
| Low — F-V7: report claims overstated moved-entry streaming, profile ALPN, branch tip and mutation names. | **Corrected here:** the moved entry gets its own stream only in `170ea78`; ALPN http/1.1 is fixed by the broker, not its profile; agent-fix tip is `6ed1ad7`; F-M15-limit and F-M15-other are distinct, with the latter's missing description explicit. |
| Low — F-V8: a failing mutation assertion printed the development session's environment, including a real development-tool session token, into that agent's log. | **Code fixed in `170ea78`:** assertions check variable names before any fixed test-value comparison. **Maintainer notified:** deleting the log does not undo transcript exposure; review/rotation of that token is the maintainer's action and is not claimed complete here. No value is reproduced. |

The verification summary reports 11 checks, 10 caught; its detailed list names
only ten variants (F-N27/N28/N29/N30/N31/N32/N33/N36/N34/N38), nine caught and
one survivor. The missing eleventh variant is not inferred. **F-N34
survives:** removing the cleanup wait for grant-end records leaves a narrow
race after a run has answered and the registry emptied but the audit worker
has not written its last record. No outside test widens it without an agent
hook; no product behaviour changes, but a failed test could rarely leave its
directory. This is an accepted harness-coverage gap, not an assertion that
files cannot ever be left. `9f7599b` enabled the previously ignored P01/P05
tests after their fixes merged; the system suite then had 35 passing tests.

**2026-11-03 — Piece G: packaging and release checks.**

Implementation checks (Claude, AI-assisted, 2026-11-03), requested for the
fourth program, feature-safe builds and licence completeness (`7dc27dc`,
`e418949`). The report records 25 mutation checks; the negative-protocol check
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
| Low — G-V1: text-only tests could miss a disabled build-deb refusal. | **Fixed in `7f113fb`:** run the whole script against stand-in cargo/dpkg, prove no packaging after refusal; explicit `|| exit 1` guards. |
| Low — G-V2: the checked release binary could differ from the one cargo-deb packaged via --profile/--target. | **Fixed in `7f113fb`:** unpack and check every packaged broker; reject pre-check install and alternate-target paths; refuse and delete the packages of that run on failure. The remaining output-name cleanup gap was found as Q01. |
| Low — G-V3: ring's Portions Copyright notices were omitted. | **Fixed in `5fdcb19`:** recognize the prefix and include the four notices, including the ARM line. |
| Low — G-V4: a notice-count test did not detect missing ring source directories. | **Fixed in `5fdcb19`:** independent expected-notice oracle, not just a count. |
| Low — G-V5: test docs implied feature-only execution covered every broker test. | **Fixed in `8946ec5`:** some production-configuration tests run only without features; run both configurations. |
| Low — G-V6 (fixer): stand-in executables could hit ETXTBSY under load and dash could fall through to real system tools. | **Fixed in `ca393fb`:** child-created file and rename before execution. Real loginctl was observed in 2/96 pre-fix runs; a real systemctl stop was a possible consequence, not an observed one. Post-fix: 0/96. |

Fix mutations: 30, 27 caught. **G-M06** (append `|| true` after `|| exit 1`)
survives because the failing command still exits first. **G-M28/G-M29** (omit
ring's pregenerated/third_party notice scans) survive because their notices
duplicate others in the pinned ring version; the output is identical. Both
scans remain and need review on dependency updates. The old script was also
shown packaging a test build with cargo-deb 3.8.0 and --profile dev; the fixed
script refused and removed it. No package was installed. Hosted CI and a
manual installed-broker check remain separate from these local checks.

**2026-11-03 — Codex re-review at `9f7599b`; Q02 at `4ff834a`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer after the four merges and P01–P06 fixes, with F and G included.
P01–P06 were confirmed resolved; early-Revoked documentation resolved;
real-component coverage of P03/P04 partly resolved and accepted for the
reasons above. No medium or higher finding remained.

| Finding | Disposition |
|---|---|
| Low — Q01: a refused package whose filename did not end in .deb/.ddeb survived cleanup (release.pkg reproduced it). | **Fixed in `b999e72` and `3953912` (merged in `453e772`); reopened by R01–R04 of the final review and replaced in `17c1965` (merged in `dbf6a4b`), which packages into a private staging directory instead (see the final review below).** As first fixed, cleanup recognized reported regular files by their Debian-package prefix or case-insensitive .deb/.ddeb suffix. Content-recognized packages are emptied, then unlinked; a permission failure permits unlinking only without another hard link. Extension-only candidates are unlinked without emptying. Nothing else is deleted. Symbolic links are named, not followed; unreadable or undeletable candidates are reported and do not stop other cleanup. |
| Low — Q02: the manager docs universally attributed one Anthropic header to SDKs, contradicting the dated ADR survey. | **Fixed in `4ff834a`:** describe ANTHROPIC_API_KEY and the preset's two accepted headers; leave competing AUTH_TOKEN unset; no universal SDK precedence/header claim. |

Q01 follow-up (2026-11-03): the two fix commit messages report 24 mutation
checks, all caught (22 in `b999e72`, two in `3953912`). These are attributed
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
separately reported all AGENTS.md checks passing at `9f7599b`; that report is
attributed, not presented as Codex's execution. The current documentation task
explicitly permits the normal test suites. The phase remains unreleased; live
Claude Code/SDK validation is pending.


**2026-11-03 — Documentation checkpoint at `4ff834a` (uncommitted).**

Review (Codex subagents, AI-assisted, 2026-11-03), requested as AGENTS.md's
independent checkpoint for this documentation update. Read-only checks against
code and the supplied reports found documentation inaccuracies; the following
are corrected in this patch, with no runtime changes.

| Finding | Disposition |
|---|---|
| Documentation — revoke_grant was included among requests whose lost replies imply outcome_unknown. | **Fixed (docs):** protocol.md follows Request::has_effects: revocation is repeatable, a lost reply is a regular error, not proof of completion. |
| Documentation — package cleanup was described as complete before Q01 merged. | **Fixed (docs):** the initial draft qualified the remaining output-name gap. After Q01 merged, architecture, changelog and ADRs were updated to the exact cleanup rules in `b999e72` and `3953912` (merged in `453e772`), as was the Q01 disposition above. |
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
| Low — B01's five mutations appeared to exclude the S3 lifetime check. | **Fixed (history):** five for the whole f600896 commit, including S3. |
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


**2026-11-03 — Documentation revision at `453e772` (uncommitted).**

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
| Documentation — item 8: Q01's integration was still pending in the draft. | **Fixed (docs):** record `b999e72` and `3953912` (merged in `453e772`), exact content-versus-extension cleanup and all 24 reported mutation checks caught. The interrupted independent verification and pending final review remain explicit. |
| Documentation — item 9: CLI grant capacity was explained in registry/listener terms. | **Fixed (docs):** explain that revocation may not free a place while its command runs; list grants and wait for commands to finish. Broker exit can remove a revoked grant sooner. |
| Documentation — item 10: CHANGELOG's approval, auditing and redaction claims needed checking. | **Confirmed and clarified:** broker approvals have no remembering key and cannot be remembered; the agent durably records admission before authorizing forwarding; response bodies lose literal copies of the credential and credential-bearing headers are dropped. |
| Documentation — reread: protocol.md still said any short Install send failed. | **Fixed (docs):** a partial sendmsg can be completed by write_all; failure to complete the non-blocking send fails preparation closed. |
| Documentation — reread: two true component/caller statements were omitted. | **Fixed (docs):** architecture again says only the agent decrypts the vault and that helpers are optional; README again states that the caller receives the result, never the secret, beside the mode-specific limits. |

Checks for this revision at `453e772`: `cargo fmt --all --check`,
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
separate pending work.

**2026-11-03 — Final phase 1 review at `4b0186d`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: not ready), requested by
the maintainer to verify Q01's fixes in `b999e72` and `3953912` (merged in
`453e772`) independently, confirm Q02 in `4ff834a`, and check the
documentation in `4b0186d` against the code and the review records. The
reviewed range was `9f7599b..4b0186d`; no repository file was changed.

Q02 is confirmed resolved: the documentation names the Anthropic key
variable and both accepted token headers without asserting which header
the SDKs choose or which variable they prefer. Q01's cleanup worked for
packages with other extensions and for a debug-symbol package, but the
cases below reopened it. No other material discrepancy was found in the
changed documentation; the history's 42 commit references resolved.

| Finding | Disposition |
|---|---|
| Medium — R01: the cleanup classified, emptied and unlinked a file through separate operations on its name. A package replaced by a hard link to another file after the read open had that file emptied, and an installable alias of the package survived without a warning; a file swapped in before the unlink was deleted; a FIFO swapped in after the lstat blocked the cleanup. | **Fixed in `17c1965` (merged in `dbf6a4b`):** cargo-deb no longer writes where the user asked. `build-deb.sh` takes `--output DIR` itself and has cargo-deb write into a new private staging directory (mode 0700) inside `target/release/packaging`; `check-broker.py --staged` checks every entry there, refusing anything that is not a regular file without opening it, and only when all pass moves the packages into DIR, by a rename or, between file systems, a new `O_EXCL` file renamed over the final name, so that a file or link at that name is replaced, never followed or written through. Whatever stops the check removes the staging directory whole. Nothing outside it is classified, emptied or deleted. |
| Low — R02: the package prefix also matched an ar archive whose first member is `debian-binary.o`, which was deleted although dpkg-deb refuses it. | **Fixed in `17c1965`:** no file is taken for a package by its first bytes any more; everything in the staging directory belongs to the run, and nothing else is deleted. |
| Low — R03: a read error on a `.deb`/`.ddeb` took the name-only path, unlinking it without emptying it, so another hard link kept an installable package, unreported. | **Fixed in `17c1965`:** a refused package never leaves the staging directory, and removing that directory leaves nothing in DIR. |
| Low — R04: the package list was split on newlines, but cargo-deb accepts a newline in its output name: a refused `line\nname.pkg` survived and the cleanup said "deleted nothing". | **Fixed in `17c1965`:** the staging directory is listed with `os.scandir`, never parsed from cargo-deb's output; a name with a newline is moved or removed whole (tested). |
| Low — found while fixing R01: with `--manifest-path` to another manifest whose package name holds `../`, cargo-deb 3.8.0 wrote the package outside the staging directory, where no check would see it (reproduced). | **Fixed in `17c1965`:** `build-deb.sh` refuses `--manifest-path`, as it refuses `--target`. |

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

Checks after the merge (`dbf6a4b`), whole output read: every check of
AGENTS.md passed — fmt; clippy with all features and as released; `cargo
test --all-features` and `--no-default-features` (packaging 24, system 35,
`tests/agent.rs` 158 and 139); rustdoc with warnings denied; MSRV 1.89 both
ways; the dialog's and the manager's clippy and tests; the KeePassXC round
trip.

**2026-11-03 — Re-review of private staging at `88b9ea4`.**

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer to verify the staging design in `17c1965` (merged in `dbf6a4b`)
and its history in `88b9ea4`. The reviewed range was `4b0186d..88b9ea4`. No
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
| Low — S01: the surviving mutation that removes the `fsync` was justified only as durability across a crash, which no test can observe. Without the `fsync` a write that fails late also goes unnoticed: with an injected `EIO`, the current code refused the copy, while the mutation published the package. | **Fixed in `3ca5ebb`:** a test runs `check-broker.py --staged` with an `fsync` that fails, copying to another file system: nothing is published, the file already at the package's name is unchanged, the copy's new file and the staging directory are deleted. Without the `fsync` the test fails (mutation check on a copy with its own target directory). The final review's section above now says so. |

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
packaging tests, clippy and the MSRV check on `3ca5ebb`.

**2026-11-03 — Test hygiene and behaviour under load at `e86e6bd`.**

The maintainer asked for the old tests that left files behind to be fixed.
The maintainer's agent ran the end-to-end suite in four parallel copies next
to eight CPU burners, each copy with a `TMPDIR` of its own, and then every
test binary alone in a `TMPDIR` of its own. Every loaded run of the suite
left directories behind, and 7 of 56 failed. Five problems were found, all
in the tests: T01–T04 were fixed in `d8f2eb9` and T05 in `e86e6bd`.

Review (Codex, AI-assisted, 2026-11-03; verdict: ready), requested by the
maintainer to verify those fixes: whether they prevent late writes and
load-dependent failures without hiding a product defect or weakening the
intended checks. The reviewed range was `99bda92..e86e6bd`. No medium or
higher finding, or product defect behind the reported failures, was
identified.

| Finding | Disposition |
|---|---|
| T01 — Tests returned before the agent recorded a disconnected run's end, allowing the audit log to recreate the removed temporary directory. | **Fixed in `d8f2eb9` for the reported cases:** `wait_for_run_end` shares three existing waits and is added to nine further tests. The prior process and cancellation assertions remain. Removing the `exited` outcome makes all 13 callers, including T04, fail. Other asynchronous records still needed synchronization: U02 and U03 below. |
| T02 — An immediate port check could observe a descriptor inherited by another test's child between fork and exec. | **Partly fixed in `d8f2eb9`:** two checks retry for up to five seconds; both still fail with a leaked listener. Source review confirms `RunGrants::stop` clears its listeners before the run answers. A third immediate check remained: U01 below. |
| T03 — The watcher-stop test required less than three seconds although shutdown deliberately waits up to three seconds for its threads. | **Fixed in `d8f2eb9`:** the assertion allows five seconds, matching the companion test's scheduling margin, and still checks the inhibitor's release. An injected six-second delay is rejected. This no longer detects a regression that merely makes every stop consume the allowed three-second wait; it does not establish that normal stops are prompt. |
| T04 — A requester-disconnection test inspected the run outcome after the grants disappeared but before `run/exited` was recorded. | **Fixed in `d8f2eb9`:** it waits for the run's end record before inspecting that outcome, retaining its revocation-order and broker-exit assertions. |
| T05 — GTK widget tests activated desktop services that outlived them, and Xvfb could write Mesa's cache after cleanup. | **Fixed in `e86e6bd`:** the tests use private D-Bus sessions without service activation, disable GVfs, the settings portal and Mesa's shader cache, and use GTK's test accessibility backend. Accessible properties and relations, clipboard access through xclip and dialog assertions remain checked. The dialog skips with a diagnostic when required tools are absent; the manager requires them. CI installs dbus-daemon, which supplies dbus-run-session. |
| Low — U01: the successful broker-run test still checked port release with an immediate bind. | **Fixed in `7a1d63b`:** it uses `port_released`, and keeps the broker-exit assertion. |
| Low — U02: some tests inspected grant-end records or removed their directory before asynchronous grant auditing finished; one also required an unnecessary global created/ended alternation across grants. | **Fixed in `7a1d63b`:** the tests wait for each grant's end record by ID and check the order per grant. Where the audit log is a FIFO that fails every record, they wait until the end record has been written into it before they put the log back, without requiring a successful record. The same probe found a fourth test that returned before a grant's end record. |
| Low — U03: the read-only polling test returned when status became locked, before the idle-lock audit record necessarily finished. | **Fixed in `7a1d63b`:** it waits for `lock/idle_timeout` before it returns. |

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

The maintainer's agent then fixed U01–U03 in `7a1d63b` and checked the
fix with the same probe, in a copy with its own target directory: with
the pauses, each run of the suite had failed two tests and left six
directories; after the fix, two runs passed and left nothing. Without the
agent's grant end records, the six tests that now wait for them fail,
each with its message; without the idle lock's record, the polling test
fails. Twelve loaded runs (four copies next to eight CPU burners) passed
with nothing left; formatting, both clippy runs, the end-to-end tests
without default features and the MSRV checks passed.

**2026-11-04 — Confirmation of the test fixes at `4ef519f`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of `7a1d63b` and
of the history entry above, in `4ef519f`. U01–U03 were confirmed resolved:
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
| Low — V01: `admissions_are_recorded_before_the_broker_forwards_anything` read the records of the grant's requests before waiting for the grant's end. The second request is refused without the agent's audit thread, so the first one's `completed` record can come after the run's answer: a 500 ms pause before it left the test with only `admitted`, and the late records recreated its directory. Found by extending the probe to the records of requests' ends and of automatic locks. | **Fixed in `49bf590`:** it waits for the grant's end record first, which the same thread writes after the records of the grant's requests. |
| Low — V02 (from a note of the review's): `the_run_dialog_shows_destination_settings_without_credentials` shows the test's own environment, directory and process chain, and with a 41-character TMPDIR zenity's height estimate of its dialog was 889 pixels, over the 880-pixel limit, so the agent refused the request (as it must) and the test failed. | **Fixed in `49bf590`:** the test, which is about what the dialog shows, uses a dialog that scrolls, as `rusthorse-dialog`'s does; the height limit keeps tests of its own. |

Codex's checks: an isolated export; the 158 end-to-end tests without
pauses, with the earlier pauses and with the extended probe (with V01's
fix applied in its copy); the mutations above; a probe of the FIFO's
behaviour; formatting and `git diff --check`. The maintainer's agent then
checked `49bf590`: with pauses before the records of a grant's end, a
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

`4fefa4c` names the entry in an edit's answer (its title, or the new name
after a rename). `c0aebc0` counts per grant the requests whose destination
answered `401`, once the report matches an open request; reports the count
in `grants`, and in `exited` once the run's grants are gone, from which
`rusthorse run` prints a note after the command with its status unchanged;
adds the manager's **Key refused** fact; and starts the message of the JSON
errors the broker writes with `rusthorse-broker:`, that of a grant that has
ended saying to run the command again. The feedback comes from the status
alone, never from a provider's body, so it is the same for every
destination.

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `4fefa4c`
and `c0aebc0` against `4c7e2eb`. No defect was found in the count: two
grants kept separate counts, the report of a command that ended at once
after its last request stayed complete with a 500 ms pause before the audit
thread's records, and the broker's own `401` was never counted.

| Finding | Disposition |
|---|---|
| Medium — W01: since `4fefa4c`, an edit's answer names the entry by the title stored in the vault, which another KeePass program can write with terminal controls in it, and the CLI printed the agent's messages as they came: editing by UUID an entry titled `SAFE\u{1b}[2J\rFORGED` sent ESC and CR to the terminal. | **Fixed in `2fafe05`:** the CLI escapes the messages of the agent's answers and errors, a run's errors and an import's per-batch results, as it already escaped the grants; the vault keeps the title as it is. Tested with such a title written into the file, then edited and removed by UUID, and with a fake agent's answer, error and run error; without the escaping, both tests fail. `f51391c` and `f20d7d0` escaped the rest of what the CLI shows from the vault, the agent or a keyring (X01, Y01 and Y02, below). |
| Low — W02: the command the note suggests, `rusthorse edit NAME --value`, reads a name that starts with `-` as an option (for `--help`, it shows the help). | **Fixed in `2fafe05`:** for such a name the note suggests `rusthorse edit --value -- NAME`; a test parses the suggested command for `KEY`, a name the shell would split, `-k` and `--help`, and fails without the fix. |
| Low — W03: the CLI's documentation and the guide said that every error without the broker's prefix comes from the destination, but the broker's HTTP parser answers a malformed request itself, with `400` or `431` and an empty body, and a connection can close with no answer. | **Partly fixed in `2fafe05`:** `docs/cli.md`, the guide, `docs/ai-agents.md`, the ADR's amendment and the CHANGELOG limit the prefix to the JSON errors the broker writes, and name these exceptions; but the guide then said that every empty `400` or `431` is the broker's, which a destination can send too. Completed in `f51391c` (X02, below). |

Codex's checks: an isolated export with offline builds and fake
credentials; targeted tests of the destination's and the broker's `401`, a
grant's removal, duplicate or invalid end reports, the protocol's defaults
and omissions, the CLI's statuses and output, the broker's messages, and
the manager's model and widgets on their own Xvfb display; probes of two
grants and of a command that ends at once, with a 500 ms pause before the
audit thread's records; formatting and `git diff --check`. The maintainer's
agent had checked `c0aebc0` with all of AGENTS.md's checks and with twelve
mutations, each failing a test — no count, every status counted, a
violation counted, the count made late by the audit thread, no listing, no
run note, a note on an unknown outcome, the agent's identity for the typed
name, no grants note, the edit's answer echoing the request's name, no
prefix, no hint — and three of the manager's (a fact that always says *No*,
the warning never added, never removed); then `2fafe05` with all of the checks
again and the mutations of W01 and W02, each failing its test.

**2026-11-04 — Confirmation of the fixes at `db0af0e`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `2fafe05`
and of the history above, in `db0af0e`. W01 and W02 were confirmed
resolved: the agent's messages are escaped, the title stays as stored, and
the suggested command parses as an edit of the named entry for `-k` and
`--help`; reverting either fix fails its tests. W03 was confirmed partly
resolved (X02).

| Finding | Disposition |
|---|---|
| Medium — X01, older than this work: `list` and `show` printed what the vault holds as it came, so a title or a username another KeePass program wrote with terminal controls reached the terminal: the review's probe with the title `SAFE\u{1b}[2J\rFORGED\u{202e}` sent ESC and CR to the standard output of both. The import preview and the text of `status` did the same with what a keyring or the agent supplies. | **Partly fixed in `f51391c`:** `list` and `show` (before a table's widths are measured), `status`, `doctor`'s lines, the import preview and the CLI's own errors (names given twice in a keyring import, for one) have their control and invisible characters escaped; `--json` gives the values as they are, and what `reveal` prints and a command's output are not touched. Tested with a title and a username written into the file (`list`, `show`, and `show --json` as stored), a status with controls in its vault, dialogs and program, keyring names in a dry run and in the error that refuses names given twice, and `doctor`'s lines; without the escaping in any one of these places, a test fails. `open`'s notice and an import's transport and decoding errors were completed in `f20d7d0` (Y01, Y02, below). |
| Low — X02: the guide said that an empty `400` or `431` is the broker's answer to a malformed request; the review's probe had a destination send both, relayed by the real broker with one admission and its status in the request's end, besides the broker's own empty `400` with no admission. | **Fixed in `f51391c`:** the guide says that the broker's HTTP parser can answer that way and that a destination can too, so such an answer alone does not tell who answered; `docs/cli.md` says the same. |
| Low — X03: the documents said that the account refused "the same requests" of Claude Code with the key by value, and grouped the Sonnet and Haiku comparisons. Claude Code's own requests went through the broker only; the comparisons both ways were SDK requests: create and streaming to Sonnet 5.5, and streaming to Haiku 5.5 with a minimal input, plain or with some of Claude Code's parameters. | **Fixed in `f51391c`:** answer 9 of ADR 0013 and its amendment, `docs/cli.md`, the guide, `docs/ai-agents.md`, the roadmap, the threat model and the CHANGELOG say what was tried, and the fourth paragraph of the entry above was reworded the same way. |

Codex's checks: the diff and the commit messages; the escaping tests, the
binary's tests (the suggested command, the guide), the edit test; its own
probes of a title written elsewhere (edit escaped, title kept; `list` and
`show` raw, X01), of an import's success, error, denial and unknown result
and of an unknown error of `run` (escaped, statuses `0`, `1`, `4` and
`124` kept), and of empty `400` and `431` answers from the broker and from
a destination (X02); the reverted escape and `--` form, each failing its
tests; formatting and `git diff --check`. It did not rerun the comparison
scripts, which need the maintainer's key and dialogs. The maintainer's
agent then checked `f51391c` with all of AGENTS.md's checks, and with six
mutations — no escaping in `list`, `show`, `status`, the import preview,
the main error printer or `doctor`'s lines — each failing a test.

**2026-11-04 — Confirmation of the fixes at `5dd639a`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: not ready) of `f51391c`
and of the history above, in `5dd639a`. X02 and X03 were confirmed
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
| Medium — Y01: `open` printed `Opening URL` with the URL from the vault as it came, so a URL another KeePass program wrote, such as `https://example.invalid/\u{1b}[2J\rFORGED`, sent ESC and CR to the terminal after passing the check of its scheme. | **Fixed in `f20d7d0`:** the notice shows the URL escaped, and the browser gets the URL as stored. Tested with such a URL written into the file and a stand-in for `xdg-open` that records what it is given; without the escaping, the test fails. |
| Low — Y02: an import's transport and decoding errors printed the error as it came, which quotes an answer the client could not read: an answer of an unknown type holding ESC and CR reached the terminal, though the exit status was rightly `124`. | **Fixed in `f20d7d0`:** both arms escape the error, with exit statuses `124` and `1` unchanged. Tested with a scripted agent whose `import_from` answer has such a type; without the escaping, the test fails. |

Codex's checks: the diff, the commits and the history; the escaping tests
(the fake keyring's included), the binary's tests, the CLI tests of the
broker (statuses, grants, notes) and `open`'s test; its own probes of the
metadata and of the output contracts (`--json`, `reveal`, a command's
output), of `open` with a stand-in browser (Y01) and of an import answer
that cannot be read (Y02), both of which passed with the fix applied in
its copy; formatting and `git diff --check`. The maintainer's agent then
checked `f20d7d0` with all of AGENTS.md's checks, and reverting either fix
failed its test.

**2026-11-04 — Confirmation of the fixes at `df52e23`.**

Review (Codex, AI-assisted, 2026-11-04; verdict: ready) of `f20d7d0` and
of the history above, in `df52e23`. Y01 and Y02 were confirmed resolved:
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
| Low — Z01: the stand-in for `xdg-open` in `open_shows_a_url_written_elsewhere_escaped` wrote to a path it did not quote, so with a TMPDIR holding a space the script failed (`xdg-open failed (exit status: 2)`) though the product was right; `open_hands_only_http_links_to_the_browser`, older, had the same script. | **Fixed in `2a4549d`:** both scripts quote the path (`util::shell_quote`). With a TMPDIR holding a space, both tests failed before and pass after; with an ordinary one, they pass. |

Codex's checks: the escaping tests (six), the binary's tests, the CLI
tests of the broker and the tests of an import's batches; its own probes
of the output and its contracts and of both of an import's errors; the
mutations that remove Y01's and Y02's fixes, each caught; the `open` test
with a TMPDIR holding a space (Z01); formatting and `git diff --check`.
The maintainer's agent then checked `2a4549d` with all of AGENTS.md's checks.
