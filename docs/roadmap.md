# Roadmap

What Rusthorse plans to do next, and why. Items carry no dates. Anything that
changes the security model — what a client can obtain, what the human
approves, what is stored — gets an [ADR](adr/README.md) and an update to the
[threat model](threat-model.md) before it is built.

Status: **Done**, **In progress**, **Planned** (agreed direction), **Idea**
(worth exploring, not designed), **Later** (accepted, not a priority).

## Credential broker: secrets that never enter the client

**Status: Planned.** The most important direction after the first release.

### Why

Today `rusthorse run` puts the secret in the approved command's environment.
The command — and every program it starts — can read it, print it in a way
redaction does not recognise (encoded, split, transformed), write it to a file
or send it anywhere (threat model [L3, L4 and L5](threat-model.md)). Redaction
only catches the literal value in the output, and approval only helps if the
human reads the command.

A broker removes the secret from the client entirely: the client receives a
**temporary token** that is worthless outside Rusthorse, and the agent uses
the real credential on the client's behalf.

### Design

1. **Approval mints a capability token.** Instead of the value, the approved
   command receives a random token (`rh_…`, 256 bits) in the variable where
   the secret would have gone, and the broker's address. The token is bound
   to:
   - one entry;
   - a destination (host and port, or a database or SSH target);
   - optionally methods and paths (`GET` only, `/v1/models` only);
   - an expiry (minutes) and a maximum number of uses;
   - the approved command: it is revoked when the command ends, unless the
     human approved a longer lifetime; while it runs, the broker can also
     refuse new connections on its Unix socket from processes outside the
     command (peer credentials). That does not stop a process of the command
     from handing a connected socket to another one, and a loopback TCP
     connection carries no peer credentials: questions for the ADR.
2. **The broker checks the token on every use** and refuses anything outside
   its scope. `rusthorse lock` revokes every token at once.
3. **The broker listens on a private Unix socket** (mode `0600`, same-user
   peer check, as the agent's socket does today). A loopback TCP port is
   offered only to clients that cannot use a Unix socket, and still requires
   the token.
4. **Every use is audited** under the grant's public identifier — never the
   token itself, which is a bearer credential — with the entry and what was
   done (`POST api.openai.com/v1/chat/completions`), not only "a command
   ran".
5. **The dialog says what the token allows**: "This command may call
   **api.openai.com** for 10 minutes", instead of "this command receives the
   key".

### Connectors

Authentication usually happens at the start of a connection: the broker
performs that part with the real credential, then only relays bytes. HTTP is
the exception — the credential travels with every request — so the broker must
see each request.

| Connector | How it works | Phase |
|---|---|---|
| **HTTP APIs** | The client's base URL points to the broker (`OPENAI_BASE_URL=http://127.0.0.1:…/openai`, or a Unix socket), and its API key is the token. The broker validates the token, replaces it with the real key in the header (`Authorization`, `x-api-key`, …), and connects to the upstream **over TLS only**, checking the destination against the token's scope rather than trusting the request's `Host` header. Presets for common providers (OpenAI, Anthropic, Google, GitHub, Hugging Face) and a generic header rule. The real value is still redacted from responses, as a second line of defence. | 1 |
| **SSH agent** | Rusthorse speaks the `ssh-agent` protocol (`SSH_AUTH_SOCK`). Private keys stay in the vault; the agent signs, each signature or session approved; the key never leaves. Compatible with how KeePassXC stores SSH keys, if practical. | 2 |
| **PostgreSQL, MySQL** | A local listener speaks the database's wire protocol. The client connects with the token as its password (over the private local socket); the broker verifies it, authenticates to the real server with the real password (SCRAM for PostgreSQL) over TLS, then relays the session. The token becomes the password of the local hop only. | 3 |
| **Signed requests (AWS SigV4 and similar)** | The secret signs each request instead of travelling in it, so the broker re-signs requests with the real key. | Idea |

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
approval per use and tokens that are scoped, short-lived and revoked with the
approved command.

### Limits

- **A token is usable while it is valid.** Whoever holds it can call the
  allowed destination within its scope and lifetime. The broker prevents the
  credential from *leaving* and being reused later; it does not prevent misuse
  during the window — keep scopes narrow and lifetimes short.
- **The client must be redirectable**: a configurable base URL, a proxy
  setting, an `SSH_AUTH_SOCK`, a database host. Intercepting TLS with a local
  certificate authority is out of scope: it is fragile and invasive.
- **Secrets used locally** — decrypting a file, a password typed into a
  program, a signing key used offline — still need `run`, which stays as the
  general fallback.

### Questions the ADR must answer

- **Revocation of open sessions**: does revoking or expiring a token end
  database sessions and HTTP streams already open, or only refuse new ones?
- **Counting uses atomically**, so that concurrent requests cannot exceed the
  limit.
- **HTTP routing**: redirects (never followed with the credential unless the
  new destination is in scope, checked at every hop), path normalisation,
  duplicate headers, the destination resolved and pinned by the broker.
- **Binding to the command**: whether to require peer credentials from the
  command's process group, and what happens with programs that hand
  connections to helpers.
- **SSH**: binding signatures to a destination (OpenSSH's session binding and
  destination constraints), since the basic agent protocol does not say what a
  signature is for.

### Steps

1. ADR and threat-model update (token format, grant identifier, scope,
   lifetime, revocation, audit, dialog wording, the questions above).
2. HTTP connector with provider presets; `rusthorse run --broker` (name to be
   decided) chooses the broker over environment injection.
3. `ssh-agent`.
4. PostgreSQL, then MySQL.

## Desktop and usability

| Item | Status | Notes |
|---|---|---|
| **Rusthorse's own dialog program instead of zenity** (GTK 4 + libadwaita) | Done — [ADR 0006](adr/0006-own-dialog-program.md) | `rusthorse-dialog`, a separate process started like zenity: two-column details, scrolling with the buttons always visible and Allow disabled until the end of a long request has been reached (no height limit), a distinct password dialog. Next: a grants panel to inspect and revoke remembered approvals and broker tokens. |
| **Lock on screen lock and suspend** | Planned | Listen to logind and the screensaver over D-Bus. |
| **"Waiting for your answer" hint** in the terminal | Later | Driven by an explicit event from the agent, not a client-side timer, and synchronised with the start of a command's output. |
| **Group related entries on import** | Idea | `DDNS_HOST`, `DDNS_USER`, `DDNS_KEY` become one entry with host, username and password; `run` gains access to an entry's username and host as variables. |
| **Small GTK interface for browsing and editing entries** | Idea | KeePassXC already covers this well; only if it adds something Rusthorse-specific. |
| **Browser integration** through native messaging | Idea | Needs its own threat analysis: the browser is a large, exposed client. |
| **Clipboard copy with a timeout** | Later | Deliberately left out on X11, where any program can read the clipboard. |

## Hardening

From the [threat model](threat-model.md#10-planned-improvements):

| Item | Status | Addresses |
|---|---|---|
| Isolation support: uid allow-list on the socket, documentation for running AI agents as a separate user | Planned | §8 |
| One cgroup per approved command, with resource limits | Planned | L17 |
| Bounded KDF parameters checked before unlocking | Planned | L12 |
| Per-entry policies: restrict an entry to listed programs or hosts | Planned | L3, L4 |
| Key files and hardware keys (YubiKey challenge-response) | Later | Compatibility with KeePassXC vaults |

## Packaging and project

| Item | Status | Notes |
|---|---|---|
| Publish on GitHub, CI on every pull request | Planned | After the clean reinstall and the owner's approval. |
| Packaged releases: `.deb`, static binaries, signed checksums | Planned | |
| Man page | Planned | Generated from the CLI definition. |
| Build identifier in `status` and `doctor` | Later | Needs a build script to embed it. |
| Tests for relay-thread creation failures | Later | Needs a preloaded `pthread_create` shim; verified by review until then. |
| Dialog layout tests with the real Pango renderer | Idea | Would check the height estimate and drawn extents against real fonts. |
