# Threat model

This document states what Rusthorse protects, against whom, how, and — just
as important — what it does not protect. If you find a gap between this
document and the code, that is a bug; please report it
([SECURITY.md](../SECURITY.md)).

- Applies to: Rusthorse 0.1.x
- Last reviewed: 2026-10-31 (see [review history](#11-review-history))

## 1. Scope and the exact guarantee

Rusthorse is a local, single-user secrets vault for Linux desktops. A
long-running agent holds the decrypted KeePass database; clients (the CLI,
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
| P6 | The master password and new secret values never pass through a requester. | The agent asks for them in its own dialogs; the protocol has no field for the master password. zenity's answer comes back over a socket pair, which other processes cannot open through `/proc/<pid>/fd` (a pipe could be). The one exception is `rusthorse init`, which reads the password of a *new* vault in the CLI (terminal or dialog) before any agent is involved. | A1, A2 (not on X11, L2) |
| P7 | Dialogs are not answered by the requester and say what they mean. | Separate processes on the desktop, not in the terminal; zenity runs from an absolute path with a minimal environment and `/` as working directory; requester-controlled text is escaped (control, bidirectional and zero-width characters; backslashes and underscores for zenity's entry dialog); entries are identified by full path and UUID, so two entries with the same title never look alike; requests whose dialog text would exceed 4000 characters (or 1000 for one field), or be too tall to read at once (estimated for an 11-point font), are refused, never truncated; only ordinary characters are drawn as themselves, every other one as a `\u{…}` escape; default button **Deny**; unanswered dialogs are denied; only exact, expected zenity results count as approval. | A1, A2 (not on X11, L2) |
| P8 | Only your user can talk to the agent. | Socket in a `0700` directory, mode `0600`, `SO_PEERCRED` uid check. | A4 |
| P9 | The decrypted vault is not held longer than needed. | Auto-lock after 15 minutes without an *approved* use — `status`, `list`, `show` and denied requests do not postpone it; `rusthorse lock`; lock on any save failure. | A1, A2, A6 (window) |
| P10 | The agent's memory is not readable by other same-user processes and is not dumped. | `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` on the agent. Dialogs and approved commands inherit `RLIMIT_CORE=0`, but `execve` makes them dumpable again, and with a piped `core_pattern` (systemd-coredump) whether a crash is stored is up to that handler. | A1, A2 |
| P11 | The vault is confidential at rest. | KDBX4: AES-256, Argon2id (64 MiB, 20 passes for new vaults); files `0600`, directories `0700`. | A4, A5 |
| P12 | Every decision leaves a record. | JSON Lines audit log, `fsync`ed per record. Unlocking and approval-gated actions fail closed: if the record cannot be written, the vault stays locked or the action does not happen. | A1 (detection; L13) |
| P13 | The agent stays available under request floods. | The whole request must arrive within 10 s of connecting (a deadline, not a per-read timeout); at most 64 connections and 8 requests waiting for a dialog at once; frames ≤ 4 MiB; imports ≤ 100 entries; vault files ≤ 128 MiB. | A1, A2 (availability) |
| P14 | Approved changes are all-or-nothing and match the disk. | Every change runs as a transaction that is rolled back if any part fails (for example one invalid entry in an import); if saving fails, the vault is locked so memory never holds unsaved changes. A save that fails after the file was replaced (syncing the directory) is reported as an unknown outcome, never as "not saved". | Accidents |

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
*Mitigation:* read the dialog; prefer well-known binaries with explicit
arguments; review recent changes to scripts before approving them.

### L5 — Redaction only catches exact copies in the command's output

A command that prints the secret encoded (base64, hex, URL-encoded), split,
reversed or partially is not redacted, and secrets shorter than 4 characters
never are. A command can also send the secret over the network, write it to a
file, or put it in its own logs — none of which pass through the redactor.
Redaction prevents *accidental* disclosure on stdout/stderr; it is not a
defense against exfiltration by a command written to leak.

### L6 — Metadata is visible without approval

While the vault is unlocked, any process of your user can list entry names,
usernames, URLs, hosts, ports and tags (fields marked protected in the KDBX
file are withheld). This is deliberate — an agent needs to know what exists
and where it points — but do not put secrets in those fields.

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
escape. Requests whose dialog would be too tall to read at once are refused,
by an estimate made for an 11-point font; larger fonts or a smaller screen
can still make a dialog taller than the screen. ASCII itself has characters
some fonts draw alike (`l`, `I`, `1`). The requester chain is made of process
names any program can choose — the dialog labels it "unverified".
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
remembered); `import` reads values in the client before sending them to the
agent; `add --stdin` sends a value the client already has. None of these
should be run by an AI agent. Importing also does not remove the original
copies (for example in GNOME Keyring).

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
- Keep `--idle-timeout` short; lock when you step away; leave `--remember`
  off unless you need it.
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
- **An in-process GUI** (instead of zenity) with scrollable details and a
  grants panel to inspect and revoke remembered approvals.
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
| Clipboard, lock on screen lock or suspend, man page, packages | **Later** (clipboard deliberately omitted on X11; see the roadmap). |
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
| R2 — the AI's non-interactive shell did not have `~/.cargo/bin` on its `PATH`, so it could not find `rusthorse` | **Fixed (documentation):** [installation.md](installation.md#1-build-and-install) explains the check and the fix; the last setup step in [ai-agents.md](ai-agents.md#setting-up-an-agent) is `rusthorse doctor` from the AI's own shell. |
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
