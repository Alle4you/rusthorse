# Roadmap

What Rusthorse plans to do next, and why. Items carry no dates. Anything that
changes the security model — what a client can obtain, what the human
approves, what is stored — gets an [ADR](adr/README.md) and an update to the
[threat model](threat-model.md) before it is built.

Status: **Done**, **In progress**, **Planned** (agreed direction), **Idea**
(worth exploring, not designed), **Later** (accepted, not a priority).

## Visual manager

**M1 done, M2 and M3 in progress** ([ADR 0007](adr/0007-visual-manager.md),
[guide](manager.md)). M1 (done, reviewed): metadata browsing, search and
groups, agent-approved edits, generated values, Show and Copy, command
snippets, status, locking and verified backup; since then, first start,
changing the value and moving entries between groups. M2: persistent agent
configuration, bounded history, remembered-approval revocation, and
screen/suspend locking (done in the agent,
[ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md)). M3: import UI (done,
[ADR 0012](adr/0012-import-read-by-the-agent.md)), safe restoration and
exclusive KeePassXC handoff. The
[reference prototype](design/manager/index.html) uses fake data and simulates
features not yet implemented.

## Credential broker: secrets that never enter the client

**Phase 1 implemented, tested and reviewed READY (2026-11-03), unreleased.**
[ADR 0013](adr/0013-credential-broker.md) defines the implemented HTTP broker
and the later phases. The manual check with the maintainer's credentials
began on 2026-11-04: the Anthropic Python SDK worked through the broker;
Claude Code's requests went through it, but the account used refused them,
with or without the broker, so its check is still pending. No client
version is claimed supported yet.

### Why

Ordinary `rusthorse run` puts the secret in the approved command's
environment. The command — and every program it starts — can read it, print it
in a way redaction does not recognise (encoded, split, transformed), write it
to a file or send it anywhere (threat model [L3, L4 and L5](threat-model.md)).
Redaction only catches the literal value in the output, and approval only
helps if the human reads the command.

For a broker binding, phase 1 removes the secret from the approved command:
the command receives a **temporary token** that no provider accepts — it works
only through the Rusthorse broker, within its scope and while it is valid (a
stolen token still works there until then) — and the broker uses the real
credential on the command's behalf.

### Design

1. **Approval mints a capability token.** In phase 1,
   `rusthorse run --broker VAR=ENTRY --url URLVAR=ENTRY -- command` gives the
   approved command a random token (`rh_…`, 256 bits) in the variable where
   the secret would have gone, and the broker's address. The token is bound to
   one entry, a snapshot of its stored profile (HTTPS origin, base path and
   exact preset routes), a maximum lifetime and an optional request count. One
   `rusthorse-broker` process serves each grant. Command end always revokes
   its grants; no grant outlives that run.
2. **The broker checks the token on every request** and refuses anything
   outside its scope. `rusthorse lock` revokes every grant at once. Automatic
   locks follow the profile (`continue`, 12 hours by default for AI presets),
   except that every lock ends grants still being prepared. Revocation ends
   open streams as well as new admissions; requests already sent can still
   take effect at the destination.
3. **The broker listens on loopback TCP (`127.0.0.1`)**, requiring the token.
   The supported clients can select a base URL but not a Unix socket from
   their environment. TCP carries no peer credentials; a same-user process can
   steal a command's token and use it while valid. A Unix socket is a later
   option, not phase 1's listener.
4. **Every admitted request is audited** under the grant's public ID, before
   forwarding — never the token itself. The record contains the method and
   route template, not a raw path, query or body. The agent serializes
   admission so concurrent requests cannot exceed the request limit; exhausted
   grants let admitted requests finish. Phase 1 allows 16 requests in flight
   per grant and at most 16 grants in the registry. Refusals are counted;
   completion/end records are best effort.
5. **The dialog says what the token allows**: destination, every route,
   lifetime, automatic-lock policy, request count and concurrency, with the
   exact command. It warns that allowed calls can spend credit and bodies are
   not inspected. The CLI and manager list and revoke grants even while the
   vault is locked. Profiles are edited through an approved CLI request; there
   is no fallback to the real key when a grant cannot start.

### Connectors

Authentication usually happens at the start of a connection: the broker
performs that part with the real credential, then relays bytes. HTTP carries a
credential with each request, so its connector checks every request. The later
connectors remain planned; phase 1 implements HTTP only.

| Connector | How it works | Phase/status |
|---|---|---|
| **HTTP APIs** | The client's base URL points to the loopback broker and its API key is the token. The broker constructs authentication, Host and SNI for the profile's fixed origin, connects over verified TLS, follows no redirects and permits only the preset's exact routes. Literal copies of the credential in response bodies are redacted; credential-bearing response header values are dropped. Anthropic, OpenAI and OpenAI-compatible presets, with SSE. | 1 — implemented, reviewed; manual check under way (Python SDK worked; Claude Code pending) |
| **Device and generic HTTP profiles** | Pinned TLS for private devices such as FortiGate; Basic authentication, custom routes, Gemini and Hugging Face presets, narrow administrative operations for Palo Alto/Panorama. Profile editing in the manager. | 2 — planned |
| **SSH agent** | Rusthorse speaks the `ssh-agent` protocol (`SSH_AUTH_SOCK`). Private keys stay in the vault; each signature or session is approved, with OpenSSH destination constraints. KeePassXC SSH-key storage compatibility where practical. | 3 — planned |
| **PostgreSQL, then MySQL** | A local listener verifies the grant token, authenticates to the real server (SCRAM for PostgreSQL) over TLS and relays the session, with the database fixed. The token is the password of the local hop only. | 4 — planned |
| **Signed requests (AWS SigV4 and similar)** | The secret signs each request instead of travelling in it; the broker signs with the real key. Provider-issued short-lived credentials (STS) can complement it. | Later, on concrete demand |
| **WebSocket, Unix socket listener, sandboxed clients** | Streaming protocols and transports beyond phase 1; grants usable by clients that stay in their own sandbox. | Later, on concrete demand |

### Prior art: Secretless Broker

CyberArk's [Secretless Broker](https://github.com/cyberark/secretless-broker)
follows the same principle: applications connect to a local listener without
credentials and the broker authenticates to the target — for databases by
replacing the authentication handshake and then relaying traffic, for HTTP by
acting as a proxy over plain HTTP locally and injecting headers, with TLS to
the upstream (its `forceSSL`, on by default since 2.0).

It deliberately performs **no client authentication**: any process that can
reach its listener gets an authenticated session, so access to the listener
must be isolated (in its deployments, a sidecar sharing a pod's network
namespace). On a desktop, where every program of the user can reach a local
port, that is not enough. Rusthorse adds what is missing there: a human
approval per grant and tokens that are scoped, short-lived and revoked with
the approved command.

### Limits

- **A token is usable while it is valid.** Whoever holds it can call the
  allowed destination within its scope and lifetime. The broker removes direct
  delivery of the credential and fixes its destination; it does not prevent
  misuse of permitted operations during the window. Keep scopes narrow,
  lifetimes short and provider-side spending limits in place: a request count
  is not a spending limit.
- **The client must be redirectable**: a configurable base URL, an
  `SSH_AUTH_SOCK` or a database host, depending on the connector. Phase 1 is a
  reverse HTTP proxy, not a generic forward proxy. Intercepting TLS with a
  local certificate authority stays out of scope: fragile and invasive.
- **Secrets used locally** — decrypting a file, a password typed into a
  program, a signing key used offline — still need ordinary `run`, with its
  existing limits. It remains available; it is never an automatic fallback
  after a broker refusal.
- **SSH with a password cannot be brokered**: the password is what `ssh`
  sends, so whoever runs `ssh` must have it. Devices reached by SSH should use
  keys, which the planned `ssh-agent` connector keeps in the vault; until
  then, password SSH goes through `run` with its limits (L3–L5).
- **A broker is not a sandbox.** Commands and brokers run as the user, outside
  the requester's sandbox. One process per grant limits which vault credential
  is in that process's memory, not arbitrary code execution there. Bodies are
  opaque, the local HTTP hop is clear text, and response redaction cannot
  catch transformed credentials returned by a destination. See the
  [threat model](threat-model.md).

### Decisions and next steps

ADR 0013 answers phase 1's original questions: revocation cuts open streams;
the agent serializes counted admissions; routing and DNS are constrained; and
the local hop authenticates a token, not a process identity. Phase 1 is
implemented and reviewed; its manual check is under way (Claude Code
pending). Next are phase
2's device/generic HTTP profiles, phase 3's SSH agent and phase 4's database
connectors. Each needs its own design, review and tests, including its
session-revocation and destination-binding rules before implementation.

## Desktop and usability

| Item | Status | Notes |
|---|---|---|
| **Rusthorse's own dialog program instead of zenity** (GTK 4 + libadwaita) | Done — [ADR 0006](adr/0006-own-dialog-program.md) | `rusthorse-dialog`, a separate process started like zenity: two-column details, scrolling with the buttons always visible and Allow disabled until the end of a long request has been reached (no height limit), a distinct password dialog. The manager now has a broker Grants page; a page for remembered approvals remains planned. |
| **Lock on screen lock and suspend** | Done — [ADR 0009](adr/0009-lock-on-screen-lock-and-suspend.md) | The agent watches logind (with a delay inhibitor before a suspend) and the Cinnamon, GNOME, MATE and freedesktop screensavers over D-Bus. |
| **"Waiting for your answer" hint** in the terminal | Later | Driven by an explicit event from the agent, not a client-side timer, and synchronised with the start of a command's output. |
| **Entry kinds** | Done — [ADR 0008](adr/0008-entry-kinds.md) | `api-key`, `login`, `server`, `device`: labels and form fields, never policy. `run --url` passes an API key's endpoint. More kinds (database, SSH key) can follow. |
| **Move entries between groups** | Done (unreleased) | `edit --group` and the manager's Edit form; protocol 7. Groups (KeePass folders) keep related entries together — a device's API token and its web login, say — until one entry can hold several secrets. |
| **Entries with several secrets** | Planned | Extra protected fields on one entry (a device's web password and API token); `run` names the field (`VAR=ENTRY:field`, syntax to be decided), and the dialog and the audit log say which. Designed with the credential broker, whose tokens would point to a field. Needs an ADR. |
| **Group related entries on import** | Idea | `DDNS_HOST`, `DDNS_USER`, `DDNS_KEY` become one entry with host, username and password; `run` gains access to an entry's username and host as variables, as `--url` does for the URL. |
| **Visual manager** | M1 done; M2, M3 in progress | ADR 0007 and milestones above; broker Grants page done (ADR 0013); manager stays an agent client. |
| **Browser integration** through native messaging | Idea | Needs its own threat analysis: the browser is a large, exposed client. |
| **Copy a value** | Done (manager M1) | After its own approval, as plain text: it stays on the clipboard until something else is copied, and a clipboard history may keep it even after that. A single-paste design was dropped: the desktop keeps its own copy ([ADR 0007](adr/0007-visual-manager.md#copy)). |
| **Drag a value onto a field** | Idea | Only the drop target receives it; no clipboard. Needs its own approval wording and a test on Xvfb. |
| **Auto-type into the focused window** | Idea | KeePassXC's approach; X11 only, and it can type into the wrong window. |

## Hardening

From the [threat model](threat-model.md#10-planned-improvements):

| Item | Status | Addresses |
|---|---|---|
| Isolation support: uid allow-list on the socket, documentation for running AI agents as a separate user | Planned | §8 |
| One cgroup per approved command, with resource limits | Planned | L17 |
| Bounded KDF parameters checked before unlocking | Planned | L12 |
| Per-entry policies: restrict an entry to listed programs or hosts | Planned | L3, L4 |
| List the variables that redirect a program's requests (`*_BASE_URL`, `*_API_BASE`, `HTTPS_PROXY`, …) in the run dialog (a remembered approval already requires the same environment) | Done | L4 |
| Key files and hardware keys (YubiKey challenge-response) | Later | Compatibility with KeePassXC vaults |

## Packaging and project

| Item | Status | Notes |
|---|---|---|
| Publish on GitHub, CI on every pull request | Planned | After the clean reinstall and the owner's approval. |
| Debian package (`.deb`): programs, user service enabled for every user, menu entry, completions, documentation | Done (unreleased) | [ADR 0010](adr/0010-debian-package.md); four programs including the broker; built from a clone with `packaging/build-deb.sh` until releases are published. |
| Published releases: the `.deb`, static binaries, signed checksums; `.rpm` | Planned | Static binaries with `install.sh` / `uninstall.sh` (or `rusthorse setup`) for other distributions. |
| First start from the manager: start the agent, create the vault | Done (unreleased) | [ADR 0011](adr/0011-first-start-from-the-manager.md); the agent asks for the master password (`create_vault`). |
| Import from the manager (GNOME Keyring, `.env`), read by the agent | Done (unreleased) | [ADR 0012](adr/0012-import-read-by-the-agent.md). |
| Socket activation of the agent | Idea | Would start the agent on first use without a button; the agent must still run before anything connects, to lock on screen lock and suspend (ADR 0011). |
| Guide for AI agents built into the binary (`rusthorse guide ai`) | Done (unreleased) | A test checks every command and option it names; the instructions file of an AI agent only points to it. |
| Man page | Planned | Generated from the CLI definition; the Debian package has none yet. |
| Examples and the exit statuses in `--help` | Idea | `rusthorse guide ai` has them for AI agents today. |
| Build identifier in `status` and `doctor` | Later | Needs a build script to embed it. |
| Tests for relay-thread creation failures | Later | Needs a preloaded `pthread_create` shim; verified by review until then. |
| Dialog layout tests with the real Pango renderer | Idea | Would check the height estimate and drawn extents against real fonts. |
| Widget tests of `rusthorse-dialog` for resizing, scaling and accessibility actions | Later | Focus, keyboard approval, the approval gate, timeouts and the password field are tested on Xvfb today. |
