# 0013. A credential broker: approved programs get a grant, not the secret

- Status: Proposed
- Date: 2026-11-02
- Refines: the "Credential broker" sketch in [the roadmap](../roadmap.md#credential-broker-secrets-that-never-enter-the-client).
- Preceded by: an independent design analysis (Codex, AI-assisted,
  2026-11-02), summarized under [Context](#the-analysis-before-this-adr).
  A full review of this ADR is still to come, before any code.

## Context

### The problem

`rusthorse run` puts the real secret in the environment of the approved
command ([ADR 0002](0002-agent-mediated-execution.md)). The human approves
what the dialog shows, and the agent redacts the literal value from the
output — but once the command runs, it and every program it starts hold the
value. They can encode it, split it, write it to a file or send it anywhere
([threat model](../threat-model.md) L3, L4, L5). A live test with a
router's password confirmed both halves: redaction worked, and nothing but
the human's reading of the command stood between an approved script and the
value.

Rusthorse exists so that AI agents and scripts can **use** credentials
without **knowing** them. For the most common case — an API key sent with
every HTTP request — that goal can be met far more strongly than by
redaction: the approved program can be given a short-lived **grant** to use
the key through Rusthorse, and never the key itself.

### Prior art: CyberArk's Secretless Broker

[Secretless Broker](https://github.com/cyberark/secretless-broker) follows
the same principle. Applications connect to a local listener (`listenOn`, a
TCP port or a Unix socket) without credentials; Secretless fetches the
credentials from a provider (CyberArk Secrets Manager / Conjur, a keychain,
files, the environment, literals) and authenticates to the target, then
relays the connection. It is configured per service in `secretless.yml`
(`connector`, `listenOn`, `credentials`). Its connectors:

| Secretless connector | Notes from its documentation |
|---|---|
| PostgreSQL (socket and TCP) | Replaces the authentication handshake, then relays; a `database` credential pins the database the client may use. |
| MySQL (socket and TCP) | Same principle; pinning only reduces the blast radius. |
| HTTP (beta) | Injects authorization: Basic auth, Conjur, AWS (re-signs with SigV4). `forceSSL` (TLS to the upstream) became the default in 2.0, and `upstreamURL` was added to stop credentials from being sent to a destination the client chose. |
| SSH (beta) | Proxies SSH with a private key. |
| SSH agent (beta) | Speaks the `ssh-agent` protocol; keys stay in Secretless. |
| Plugins | A connector plugin interface for other protocols. |

Its security model says it plainly: it performs **no client
authentication** — any client that can open a connection to its listener
gets a fully authenticated session — so network isolation (a sidecar in a
pod, a private socket) is a hard deployment requirement.

On a desktop that requirement cannot be met: every program of the user can
reach every local port and the user's sockets. Using Secretless itself would
give an authenticated session to anything the AI agent can run. What
Rusthorse must add is exactly what Secretless leaves out: a human approval,
a token that authenticates the client, a scope and a lifetime, revocation,
and an audit record per use.

### The analysis before this ADR

An independent analysis (Codex, 2026-11-02) of the roadmap sketch, the
threat model and the maintainer's real uses concluded:

- **Worth doing, small first.** The broker removes the long-lived
  credential from the client: against a cooperative but fallible agent (A1)
  — mistakes, prompt injection — it closes L3, L5 and most of L4 for HTTP
  APIs. It does not stop misuse of the operations a grant allows, and it
  does not make a hostile agent running as the same user (A2) harmless: a
  same-user process can read a token from another process's environment
  and use it within its scope. Isolation (another user, §8) is the
  complement for A2.
- **HTTP first, AI APIs first.** Anthropic (`x-api-key`) and the
  OpenAI-compatible APIs (OpenAI, DeepSeek, Experiential Labs: Bearer)
  accept another base URL; Claude Code documents LLM gateways. Streaming
  (server-sent events) is needed from the start. WebSocket (Deepgram's
  streaming) comes later.
- **Private devices need pinned TLS.** The FortiGate's REST API on the LAN
  has a self-signed certificate: the broker must trust that certificate (or
  its public key) explicitly, per profile, never skip verification.
- **Administration APIs need narrow operations.** A Palo Alto `/api` call
  can commit configuration or export keys depending on its parameters, and
  Panorama's `target` selects another firewall; "GET on `/api`" is not
  read-only. An organisation key (Experiential Labs) may administer the
  organisation as well as run inference. Host and path alone are not a
  scope for them.
- **SSH with passwords is out of reach.** Neither an HTTP proxy nor an
  `ssh-agent` authenticates with a password, and giving the password to the
  `ssh` process (`SSH_ASKPASS`) is giving it to the approved command. The
  maintainer's routers will use SSH keys instead (see decision 11).
- **Three statements were stronger than the design** — "approval per use"
  (a 10-minute grant is an approval per grant), a token "worthless outside
  Rusthorse" (a stolen token still works through the broker while it is
  valid), and that the broker would "remove the problem" of L4 (it removes
  the direct delivery of the key and fixes its destination, not the trust
  in the operations allowed). They are corrected with this ADR.

## Decision

1. **What the broker guarantees.** The approved program receives a
   **grant**, never the source credential: the broker uses the credential
   only towards the grant's destination, authenticated and within its
   scope. Not guaranteed: what the program does with the operations it is
   allowed (it can spend credit, read data, change what the API lets it
   change); that a same-user process cannot steal the token and use it
   while it is valid; that a response from the destination does not echo a
   credential (responses are still redacted, as a second line, not as
   proof).

2. **A grant** is created by an approval and has a public **grant ID**
   (audit, revocation, the manager's grants panel) and a secret **token**
   (`rh_` and 256 random bits, given to the command). It is bound to: one
   entry; that entry's **profile** (decision 3); the operations allowed; a
   lifetime (minutes); a maximum number of requests and of concurrent
   requests; and the approved command — it ends when the command ends. The
   token is a secret like a value: never logged, never in an error, and
   redacted from the command's output.

3. **Profiles fix the destination.** A profile belongs to an entry and is
   set by the human (CLI or manager, with approval): scheme, host and port;
   how the credential is presented (`Authorization: Bearer`, `x-api-key`,
   another header, Basic); TLS trust (the system's roots, or a pinned
   certificate or public key for a private device); and the routes allowed
   (methods and path prefixes). Built-in presets cover common providers
   (Anthropic, OpenAI-compatible inference). The client never chooses the
   destination: the broker builds the request line, `Host` and SNI itself,
   ignores the requester's proxy and CA variables, and does not follow
   redirects. Changing an entry's profile or URL revokes its grants.

4. **The broker is its own process.** `rusthorse-broker` is started and
   supervised by the agent, as `rusthorse-dialog` is
   ([ADR 0006](0006-own-dialog-program.md)), and receives over a socket
   pair only what an active grant needs — the one credential and its
   profile — never the vault. A bug in the network code (HTTP parsing, TLS)
   then exposes at most the credentials of active grants, not every entry.
   New dependencies for HTTP and TLS (a mature HTTP library and `rustls`)
   live in that process only.

5. **The HTTP connector (first phase)** is a reverse proxy with a fixed
   origin per profile. The client points its base URL at the broker — a
   private Unix socket where the client supports one, otherwise a loopback
   TCP port that still requires the token — and sends the token as its API
   key. The broker checks the token, the route and the limits; removes any
   credential the client sent; adds the real one; connects to the
   destination over TLS only; and relays the response, server-sent events
   included, with limits on size, time and concurrency. No `CONNECT`, no
   generic forward proxy, no automatic retries (a lost answer is an unknown
   outcome, as elsewhere in Rusthorse), no TLS interception.

6. **`run` asks for it explicitly.** `rusthorse run --broker VAR=ENTRY
   [--url URLVAR=ENTRY] -- command` puts the token in `VAR` and, with
   `--url`, the broker's address for that entry in `URLVAR` (instead of the
   entry's own URL). The exact option names are settled in the
   implementation. **There is no fallback**: if the broker cannot serve the
   grant, the run fails (125, nothing ran) — it never silently gives the
   real key instead. `run` without `--broker` stays as it is, with its
   documented limits.

7. **The dialog says what the grant allows**, from the profile and the
   request: "This command may call **api.anthropic.com** (`POST
   /v1/messages`) for **10 minutes**, at most **200** requests. It receives
   a temporary token, not the key." — with the command, the program, the
   directory and the requester as today.

8. **Revocation** happens on `rusthorse lock` (and on every lock: screen
   lock, suspend, idle), when the command ends, at expiry, when the request
   limit is reached, when the entry's profile changes, and by hand in the
   manager. It refuses new requests **and closes open ones** (a stream in
   progress ends). A request already sent upstream may still take effect:
   its outcome is reported as unknown.

9. **Audit.** The grant's creation is recorded with the approval, as other
   approvals are; every request is recorded under the grant ID — method,
   host, path without the query, status, size, outcome — before it is
   forwarded (fail closed: no record, no request) and when it ends. Never
   the token, a credential, a header value or a body.

10. **Phases.** Each phase gets its own review and tests:

    | Phase | What | Notes |
    |---|---|---|
    | 1 | HTTP: Bearer, `x-api-key`, Basic; server-sent events; Anthropic and OpenAI-compatible presets | The minimum: the AI APIs used every day. |
    | 2 | HTTP with pinned TLS for private devices (FortiGate); Gemini and Hugging Face presets; narrow operations for administration APIs (Palo Alto, Panorama) | Operations, not "the whole `/api`". |
    | 3 | `ssh-agent`: keys stay in the vault, each signature or session approved, with OpenSSH's destination constraints | Replaces password SSH for the routers. |
    | 4 | PostgreSQL, then MySQL: the broker answers the authentication handshake (SCRAM for PostgreSQL) and relays, with the database pinned | As Secretless does. |
    | Later | WebSocket (Deepgram streaming); AWS SigV4 or short-lived STS credentials | Only on concrete demand. |
    | Not planned | Connector plugins; credential providers other than the vault | Fixed connectors keep the code reviewable; the vault is the provider (imports cover keyrings and `.env` files). |

    With phases 1 to 4, Rusthorse covers what Secretless offers — HTTP,
    PostgreSQL, MySQL, SSH keys and `ssh-agent` — and adds client
    authentication, approval, scope, lifetime, revocation and audit.

11. **SSH with passwords is a documented limit.** No phase gives a
    password-only SSH server a credential the client does not see: the
    password is what `ssh` sends, so whoever runs `ssh` must have it.
    Devices reached by SSH should use keys (phase 3, `ssh-agent`); until
    then, `run` with `SSH_ASKPASS` remains possible, with the limits of
    `run` (L3–L5). The maintainer's routers move to SSH keys.

12. **Before real credentials**, tests must show: a malicious client never
    receives the key; a changed destination (URL, `Host`, proxy variables,
    redirects) is refused; concurrent requests cannot exceed a grant's
    limits; a lock ends open streams; a failed audit write stops
    forwarding; responses and errors do not expose authentication; a
    stolen token stops working when its command ends.

## Alternatives considered

- **Only `run`, with per-entry policies** (allowed programs and hosts).
  Cheap, and still worth having against mistakes, but the program still
  receives the secret: it does not stop exfiltration after the approval.
- **Secretless Broker itself.** No client authentication, and credentials
  from a configuration file or a provider rather than the vault; wrapping it
  with approval, tokens and revocation would be most of the work, plus a
  second runtime (Go) to ship and review.
- **A local certificate authority and TLS interception**, to proxy clients
  that cannot change their base URL. Fragile, invasive, and a new
  authority the whole system would trust; rejected, as in the roadmap.
- **Short-lived credentials issued by the provider** (AWS STS, Deepgram's
  temporary tokens). Better wherever they exist with a fitting scope — no
  proxy in the data path — and a complement to the broker, not a
  replacement: few providers offer them, and they cannot be revoked by a
  lock (a WebSocket can outlive a Deepgram token).
- **Specific operations instead of a generic proxy** ("show the firewall's
  interfaces"). The right shape for administration APIs; it enters through
  phase 2's narrow operations rather than as a separate mechanism.
- **Running the AI agent as another user.** The answer to a hostile agent
  (A2), already planned (§8); it complements the broker, which mainly
  protects against a fallible one (A1).

## Consequences

- **The threat model changes**: L3, L4 and L5 get a "with the broker"
  paragraph (the key is not in the client; the destination is fixed; the
  operations allowed remain trusted), a new limit records that a token can
  be stolen and used by a same-user process while it is valid, and L16 is
  revisited — a client that no longer receives the secret could stay in the
  requester's sandbox.
- **New process, new dependencies**: `rusthorse-broker`, with an HTTP
  library and `rustls`, each justified in its commit; the trusted computing
  base grows, which decision 4 contains.
- **Protocol**: new requests for grants and their revocation; a protocol
  version bump.
- **Manager**: the grants panel planned in M2 (inspect and revoke grants);
  profile settings on an entry.
- **Documentation**: the CLI reference, `rusthorse guide ai` (AI agents
  should prefer `run --broker` where a profile exists), the supported SDKs
  and how to point each at the broker.
- **What it does not change**: an approval still trusts the program it
  approves for the operations it allows; a careless approval of a broad
  grant is still a careless approval.

## Open questions (for the review of this ADR)

1. What is a "use": a request, a stream, a retry by the client's SDK?
2. Who edits profiles, and which changes to an entry revoke its grants?
3. How does the dialog express cost and administrative power, not just a
   host and a time?
4. Where does the client run — can it stay in the requester's sandbox now
   that it does not receive the secret, and later as another user?
5. How does a client find the broker after a restart; what if a loopback
   port is reused by another program?
6. How is a revoked request that the destination already accepted shown in
   the CLI and the audit log?
7. Certificates of private devices: how are they enrolled, checked through
   another channel, renewed, and what happens when one changes?
8. Which endpoints are refused for every grant (creating keys, exporting
   credentials, changing permissions)?
9. Which SDKs and versions are supported, given their own retries, proxy
   variables and secondary endpoints?
10. Can one grant cover several entries (a script that needs an API key and
    a database)?
