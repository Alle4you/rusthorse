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

**Done, unreleased.** Phase 1 was reviewed READY on 2026-11-03, and the
broker without profiles that replaced it on 2026-11-04.
[ADR 0013](adr/0013-credential-broker.md) defines the HTTP broker; its later
phases are dropped, and its
[scope amendment](adr/0013-credential-broker.md#scope-amendment-2026-11-04)
(2026-11-04) replaced phase 1's profiles and presets with a destination named
in each run (below). The manual check with the maintainer's credentials began
on 2026-11-04, with phase 1's broker: the Anthropic Python SDK worked through
the broker for the requests tried; Claude Code's requests went through it,
and the API answered them `400`, as it answered SDK requests with some of
Claude Code's parameters sent with the key by value; the maintainer left its
check for later. On 2026-11-04 the maintainer also tried the broker without
profiles by hand, with a real key and `curl` through
`https://api.anthropic.com`, the token in `x-api-key`: a `GET /v1/models` was
answered `200`, as the audit recorded with the method's label only, and a
`POST /v1/messages`, which Claude Haiku 5.5 answered; a request with the
token in its URL was refused by the broker itself, and nothing was sent.
The Anthropic Python SDK 2.4.0, given the token in `ANTHROPIC_API_KEY`, then
worked through it for a message and two streams. Claude Code has not been
tried through it yet.
No client version is claimed supported yet.

### Why

Ordinary `rusthorse run` puts the secret in the approved command's
environment. The command — and every program it starts — can read it, print it
in a way redaction does not recognise (encoded, split, transformed), write it
to a file or send it anywhere (threat model [L3, L4 and L5](threat-model.md)).
Redaction only catches the literal value in the output, and approval only
helps if the human reads the command.

For a broker binding, the broker removes the secret from the approved
command: the command receives a **temporary token** that no provider
accepts — it works only through the Rusthorse broker, at the approved origin
and while it is valid (a stolen token still works there until then) — and
the broker uses the real credential on the command's behalf.

### Design

1. **Approval mints a capability token.**
   `rusthorse run --broker VAR=ENTRY@URL --url URLVAR=ENTRY -- command` gives
   the approved command a random token (`rh_…`, 256 bits) in the variable
   where the secret would have gone, and the broker's address with the URL's
   base path. The token is bound to one entry, the URL's origin as the human
   approved it, a maximum lifetime and an optional request count, which the
   run sets (`--broker-lifetime`, `--broker-requests`, `--broker-locks`; no
   limit, 12 hours and `continue` unless it says otherwise). Nothing is
   stored with the entry, and nothing fills the destination in: there is no
   default and no fallback to the entry's URL. One `rusthorse-broker` process
   serves each grant. Command end always revokes its grants; no grant
   outlives that run.
2. **The broker checks the token on every request.** The program presents
   it where it would present the key, in a request header; the broker puts
   the key in its place and forwards the request to the approved origin,
   at any path there, over verified TLS, and redacts the key from what comes
   back. It refuses a request without the token in a header it forwards,
   with the token anywhere else in the head, with another token or with the
   key itself. It knows nothing about the API: no presets, routes or header
   lists. An API that signs its requests with the key, or takes it in the
   URL or the body, is used with `run` instead. `rusthorse lock` revokes
   every grant at once. Automatic locks follow the run's policy, except that
   every lock ends grants still being prepared. Revocation ends open streams
   as well as new admissions; requests already sent can still take effect at
   the destination.
3. **The broker listens on loopback TCP (`127.0.0.1`)**, requiring the token.
   The supported clients can select a base URL but not a Unix socket from
   their environment. TCP carries no peer credentials; a same-user process can
   steal a command's token and use it while valid. A Unix socket listener is
   not planned.
4. **Every admitted request is audited** under the grant's public ID, before
   forwarding — never the token itself. The record contains the method's
   label (`GET`, `POST`, …, `OTHER`), not the raw method, path, query or
   body. The agent serializes admission so concurrent requests cannot exceed
   the request limit; exhausted grants let admitted requests finish. 16
   requests may be in flight per grant and at most 16 grants in the
   registry. Refusals are counted; completion/end records are best effort.
5. **The dialog says what the token allows**: the approved origin, the base
   path apart from it (not a limit: the key may go to any path at the
   origin), lifetime, automatic-lock policy, request count and concurrency,
   with the exact command. It warns that allowed calls can spend credit and
   bodies are not inspected. The CLI and manager list and revoke grants even
   while the vault is locked. There is no fallback to the real key when a
   grant cannot start.

Phase 1's broker had per-entry profiles and built-in presets (routes and
header lists for Anthropic, OpenAI and OpenAI-compatible APIs). The
[scope amendment](adr/0013-credential-broker.md#scope-amendment-2026-11-04)
removed them: the secret in an entry is its value, its other fields are
context, and the agent says where it will use a key, which the human
approves. A profile phase 1 stored in an entry (`Rusthorse.Broker`) stays
there as an ordinary custom field, never read, migrated or widened.

### Not planned

Operations narrowed for administration APIs, presets per provider,
destinations or policies stored with an entry, configuration of how a key
is presented, private devices with pinned TLS, and connectors for other
protocols (`ssh-agent`,
PostgreSQL, MySQL, WebSocket, request signing, a Unix socket listener,
grants for sandboxed clients). Ordinary `rusthorse run` already serves
databases, devices, SSH and web logins: the approved command gets the value,
its output is redacted, and the use is approved and recorded, with the
limits the [threat model](threat-model.md) states (L3–L5). These are
outside the product's scope and are not on the roadmap.

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

- **A token is usable while it is valid.** Whoever holds it can call any
  path at the approved origin within its limits and lifetime. The broker
  removes direct delivery of the credential and fixes its destination to the
  approved origin; it does not narrow what the key can do there (threat
  model L25). Keep keys narrow, lifetimes short and provider-side spending
  limits in place: a request count is not a spending limit.
- **The client must be redirectable**: a configurable base URL. The broker
  is a reverse HTTP proxy, not a generic forward proxy. Intercepting TLS with a
  local certificate authority stays out of scope: fragile and invasive.
- **Secrets used locally** — decrypting a file, a password typed into a
  program, a signing key used offline — still need ordinary `run`, with its
  existing limits. It remains available; it is never an automatic fallback
  after a broker refusal.
- **Only HTTP is brokered.** SSH, databases, device logins and every other
  use go through ordinary `run`, with its limits (L3–L5): the approved
  command gets the value.
- **A broker is not a sandbox.** Commands and brokers run as the user, outside
  the requester's sandbox. One process per grant limits which vault credential
  is in that process's memory, not arbitrary code execution there. Bodies are
  opaque, the local HTTP hop is clear text, and response redaction cannot
  catch transformed credentials returned by a destination. See the
  [threat model](threat-model.md).

### Decisions and next steps

ADR 0013 answers phase 1's original questions: revocation cuts open streams;
the agent serializes counted admissions; the destination and DNS are
constrained; and the local hop authenticates a token, not a process
identity. Phase 1 was implemented and reviewed; in its manual check the
Python SDK worked, and Claude Code's check was left for later. The broker
without profiles or presets (above) replaced it; tried by hand with `curl`
and the Anthropic Python SDK, it served a GET, POSTs and streams and refused
a misplaced token, and a check of it with Claude Code remains. Nothing else is planned for the broker.

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
| Per-entry policies: restrict an entry to listed programs or hosts | Not planned: outside the product's scope | L3 and L4 remain limits |
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
