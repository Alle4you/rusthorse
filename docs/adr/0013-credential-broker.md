# 0013. A credential broker: approved programs get a grant, not the secret

- Status: Accepted
- Accepted: 2026-11-04, by the maintainer, after the broker without profiles
  or presets was reviewed ready
- Implementation: phase 1 implemented and reviewed ready, unreleased, then
  replaced by the broker without profiles or presets, implemented and
  reviewed ready on 2026-11-04, unreleased; the other phases dropped
  ([scope amendment](#scope-amendment-2026-11-04))
- Date: 2026-11-02
- Refines: the "Credential broker" sketch in [the roadmap](../roadmap.md#credential-broker-secrets-that-never-enter-the-client).
- Preceded by: an independent design analysis (Codex, AI-assisted,
  2026-11-02), summarized under [Context](#the-analysis-before-this-adr).
- Amended: 2026-11-02, after four reviews of this ADR (Codex,
  AI-assisted: not ready with 25 findings, then 11 more and 8
  inconsistencies, then 3 more; the fourth: ready, its one low finding
  fixed) and the maintainer's answers to its open questions.
  The amendment specifies phase 1 in full
  ([Phase 1 specification](#phase-1-specification)), makes the end of a
  grant a per-profile policy, and answers the open questions
  ([Answers](#answers-to-the-open-questions)). The findings and what was
  done about each are recorded in the
  [threat model's review history](../threat-model.md#11-review-history).

- Amended: 2026-11-03, to match the reviewed phase 1 implementation at
  `4ff834a`. The dated
  [implementation amendments](#implementation-amendments-2026-11-03) below
  explain each change; the review history records the findings, fixes and
  coverage gaps. Manual SDK validation with the maintainer is still pending.
  (Done on 2026-11-04: see [answer 9](#answers-to-the-open-questions).)

- Amended: 2026-11-04, after the maintainer's first manual test with a real
  key: `run` names the grants whose destination answered `401
  Unauthorized`, `grants` and the manager show the count, and the broker's
  own answers say that they are its own
  ([2026-11-04 amendments](#implementation-amendments-2026-11-04)); answer 9
  records the manual test so far.

- Amended: 2026-11-04, by the maintainer's definition of the product: the
  secret is a credential's value, the agent says where it uses it and
  the human approves. The broker loses its profiles and presets — the
  destination is named in the run and approved in the dialog, and the
  broker puts the key where the program put the token — and the other
  phases are dropped ([scope amendment](#scope-amendment-2026-11-04)).

- Amended: 2026-11-09, after an audit of the documents against the code:
  the passages of phase 1 that the scope amendment replaced are marked
  where they stand, and six statements of the specification are made
  exact — which `1xx` responses the broker refuses, when a connection
  without a request is closed, what an HTTP version other than 1.1 gets,
  where the limit of 100 headers comes from, that request numbers are
  consecutive, and how a token-shaped string is compared. What the code
  does did not change.

- Amended: 2026-11-10: the broker sets its limit of 100 request headers
  itself instead of inheriting the HTTP library's default, and its tests
  cover it ([Requests and responses](#requests-and-responses), step 1).
  The limit and the answer did not change.

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
- **HTTP first, AI APIs first.** Anthropic and the OpenAI-compatible APIs
  (OpenAI, DeepSeek, Experiential Labs) accept another base URL; Claude
  Code documents LLM gateways. Streaming (server-sent events) is needed from
  the start. WebSocket (Deepgram's streaming) comes later (superseded
  2026-11-04: not planned).
- **Private devices need pinned TLS** (superseded: not planned, see the
  [scope amendment](#scope-amendment-2026-11-04)). The FortiGate's REST API on the LAN
  has a self-signed certificate: the broker must trust that certificate (or
  its public key) explicitly, per profile, never skip verification.
- **Administration APIs need narrow operations** (superseded: what a
  credential can do is scoped where it is issued, see the
  [scope amendment](#scope-amendment-2026-11-04)). A Palo Alto `/api` call
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
  (a grant is an approval per grant), a token "worthless outside
  Rusthorse" (a stolen token still works through the broker while it is
  valid), and that the broker would "remove the problem" of L4 (it removes
  the direct delivery of the key and fixes its destination, not the trust
  in the operations allowed). They were corrected with this ADR.

### What the clients do

A survey of the clients' sources and documentation (2026-11-02; Anthropic
Python SDK 2.4.0 and TypeScript SDK 1.4.0, OpenAI Python SDK 3.42.1 and
Node SDK 7.47.0, Claude Code's gateway documentation) shaped phase 1:

- Every client takes another base URL from its environment
  (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), as `http://` too. None can
  reach a Unix socket through its environment.
- Anthropic base URLs have no `/v1` (the clients append `/v1/messages`);
  OpenAI base URLs end in `/v1`.
- Since API version 2026-10-21 the Anthropic SDKs send the key as
  `Authorization: Bearer`; Claude Code sends `ANTHROPIC_API_KEY` as
  `x-api-key` and `ANTHROPIC_AUTH_TOKEN` as `Authorization: Bearer`.
- The SDKs retry (2 times by default, Claude Code 10 times) on 408, 409,
  429, 5xx and dropped connections, POSTs included, unless the response
  carries `x-should-retry: false`; they follow redirects. They can send
  requests for `http://127.0.0.1` through a proxy named in the environment
  unless `NO_PROXY` names that address (the Python SDKs' HTTP library does;
  Node does when it is configured to use the environment's proxy).
- Claude Code also calls `api.anthropic.com` directly for a few
  non-essential features (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` turns
  them off), and an `env` block in its settings files overrides the
  variables `run` sets.
- `messages.batches.results()` fetches an absolute URL returned by the API,
  around any base URL.

## Decision

(Read with the [scope amendment](#scope-amendment-2026-11-04) of 2026-11-04:
the decisions below are kept as they were taken, for phase 1. Where they
speak of a profile, a preset or a route, the amendment replaced it — the
destination and the limits come with each run, and there is no route check.
Each such passage is marked, and the amendment's closing paragraph lists
them.)

1. **What the broker guarantees.** In phase 1, for each entry a run binds
   with `--broker`, the approved command receives a **token**, never the
   source credential (entries bound by value in the same run are delivered
   as `run` always did). The credential leaves the broker only in the
   authentication header the broker builds, in requests to the profile's
   destination, over TLS verified against the system's certificate
   authorities, and only for the profile's routes. Every request is
   recorded before it is forwarded. A grant ends as decision 8 says.
   (Superseded 2026-11-04 where it names a profile: the destination is the
   origin approved for the run, at any path there; the credential goes where
   the program put the token, in the request headers the broker forwards.)

   Not guaranteed: what the program does with the operations it is allowed
   (it can spend credit, read data, change what the API lets it change, and
   put anything it holds, the token included, in a request body, which the
   broker does not inspect); that a same-user process cannot read the token
   and use it while the grant lasts; that the destination does not return
   the credential in another form (literal copies in responses are
   redacted, as a second line, not as proof); the confidentiality of the
   requests and responses (prompts, data) against processes of the same
   user. Running each grant in its own process limits which credential is
   in that process's memory; it does not contain code execution there — the
   broker runs as the user, with the user's other powers.

2. **A grant** is created by an approval and has a public **grant ID**
   (audit, revocation, the grants panel) and a secret **token**, given to
   the command. It is bound to one entry, a snapshot of that entry's
   profile taken when the grant is created, the approved command, and the
   profile's limits. The token is a secret like a value: never logged,
   audited, put in an error or in a `Debug` output, and redacted from the
   command's output when output redaction is on (the default; decision 6
   says when it is off). (Superseded 2026-11-04 where it names a profile: a
   grant carries the destination and the limits its run named.)

3. **Profiles fix the destination.** (Superseded 2026-11-04: there are no
   profiles; the destination is named in the run and approved in the
   dialog — see the [scope amendment](#scope-amendment-2026-11-04).) A profile belongs to an entry and is
   set only by the human, through an approved edit: a preset (the routes,
   how the client presents the token, how the credential is presented to
   the destination) with its revision, the destination's origin and base
   path, and the grant policy (decision 8). Presets are built into the
   program. The client never chooses the destination: the broker builds the
   request line, `Host` and SNI itself, connects only to addresses it
   resolved and checked, ignores the requester's proxy and certificate
   variables, follows no redirect and passes none on. Any change to an
   entry ends its grants.

4. **The broker is its own process, one per grant.** The agent starts
   `rusthorse-broker` for each grant and supervises it, as it does
   `rusthorse-dialog` ([ADR 0006](0006-own-dialog-program.md)), and gives it
   over a socket pair only what that grant needs — its credential, token,
   profile snapshot (superseded 2026-11-04: its destination), limits and
   listening socket — never the vault. A bug
   in the network code (HTTP parsing, TLS) that leaks memory then leaks at
   most the credential of that one grant; a bug that lets an attacker run
   code there gives the attacker the user's powers, which the separation
   does not contain. The new dependencies for HTTP and TLS live in that
   program's package only.

5. **The HTTP connector (phase 1)** is a reverse proxy with a fixed origin
   per profile, listening on a loopback TCP port (`127.0.0.1`) that still
   requires the token. It checks the token, the route (superseded
   2026-11-04: no routes), the framing and the limits; builds the request to the destination from the parts it
   accepted, with the credential added; connects over TLS only; and relays
   the response, server-sent events included, unbuffered. No `CONNECT`, no
   generic forward proxy, no upgrades, no automatic retries (a lost answer
   is an unknown outcome, as elsewhere in Rusthorse), no TLS interception,
   no cookies or cache. A Unix socket listener is left for later
   (superseded 2026-11-04: not planned): no
   supported client can use one from its environment.

6. **`run` asks for it explicitly.** `rusthorse run --broker VAR=ENTRY
   [--url URLVAR=ENTRY] -- command` puts the token in `VAR` and, when
   `--url` names the same entry, the broker's address in `URLVAR` (instead
   of the entry's own URL). `--broker` combines with ordinary `VAR=ENTRY`
   bindings for other entries in the same run; one entry cannot be both.
   **There is no fallback**: if a grant cannot be served before the
   command starts, the run fails (125, nothing ran) — it never gives the
   real key instead. After the command has started, `run` reports its exit
   status as today; the outcome of each HTTP request is in the audit log.
   (Amended 2026-11-04: after the command, `run` also names each grant
   whose destination answered `401 Unauthorized`, its status unchanged.)
   `run` without `--broker` stays as it is, with its documented limits.
   (Superseded 2026-11-04 in its syntax: the binding is
   `--broker VAR=ENTRY@URL`, which names the destination, and `--url` gives
   the broker's address with that URL's base path; `--broker-requests`,
   `--broker-lifetime` and `--broker-locks` set the limits.)

7. **The dialog says what the grant allows**, from the profile and the
   request: the entry, the destination, every route (superseded 2026-11-04:
   no routes), how and when the grant
   ends, the request limit (or that there is none) and the number of requests
   at a time, that the command receives a temporary token and not the key,
   which other variables receive real values in a mixed run, that the command
   can spend credit, that a request count is not a spending limit and that
   request bodies are not inspected — with the command, the program, the
   directory and the requester as today. With zenity, two or more grants may
   exceed the estimated height and be refused before the dialog;
   `rusthorse-dialog` scrolls, still subject to character limits.

8. **A grant ends** on any of these, whatever the profile says: the command
   ends (its leader exits, or the requester disconnects); `rusthorse lock`
   (the explicit lock, which stays the way to stop everything at once);
   revocation by hand (`rusthorse grants revoke`, the manager's grants panel);
   any change to its entry; any change to the vault file made by another
   program while the vault was locked, found when it is unlocked again; a
   failed save; its broker process failing; the agent stopping; its maximum
   lifetime passing. Each profile also says whether the **automatic locks** —
   screen lock, suspend, idle timeout — end its grants (`end`) or not
   (`continue`). The built-in AI presets default to `continue` and 12 hours: a
   long session of an AI agent survives the screen locking. Device profiles
   (phase 2) will default to `end` and 15 minutes (superseded: device
   profiles are not planned). Reaching the request limit
   stops new requests and lets those already admitted finish. Ending a grant
   refuses new requests at once **and closes the open ones** (a stream in
   progress ends); a request already sent to the destination may still take
   effect, and its outcome is recorded as unknown. The command's end, the
   explicit lock and the agent stopping end all of a run's grants together;
   the other events end the grants they concern (an entry's, one revoked by
   hand, those whose profile says `end`). Every automatic lock also ends
   grants still being prepared (`starting`), even with `continue`. (Superseded
   2026-11-04 where it names a profile or a preset: the run sets the policy,
   with `--broker-locks end|continue` and `--broker-lifetime`; `continue` and
   12 hours unless it says otherwise.)

9. **Audit.** The grant's creation is recorded before the command starts;
   every request is recorded under the grant ID — method and route, never the
   raw path — before it is forwarded (fail closed: no record, no request), and
   again when it ends, with its status, size and outcome; the grant's end is
   recorded best effort with its reason (an abrupt agent SIGTERM does not
   write `agent_stopped` records). Never the token, a credential, a header
   value, a query or a body. The agent writes every record: the broker asks
   it, and waits for the answer. (Superseded 2026-11-04 in "method and route":
   the record holds the method's label only — `GET`, `HEAD`, `POST`, `PUT`,
   `PATCH`, `DELETE` or `OTHER` — and no route.)

10. **Phases.** Each phase gets its own review and tests (superseded on
    2026-11-04: the next broker has no profiles or presets, and the other
    phases and the "Later" row are dropped — see the
    [scope amendment](#scope-amendment-2026-11-04)):

    | Phase | What | Notes |
    |---|---|---|
    | 1 | HTTP: Anthropic, OpenAI and OpenAI-compatible presets; server-sent events; per-profile grant policy; `run --broker`; `rusthorse grants`; the manager's grants panel | The minimum: the AI APIs used every day. Specified below. |
    | 2 | HTTP with pinned TLS for private devices (FortiGate); Basic authentication; profiles with their own routes; Gemini and Hugging Face presets; narrow operations for administration APIs (Palo Alto, Panorama); profile editing in the manager | Operations, not "the whole `/api`". |
    | 3 | `ssh-agent`: keys stay in the vault, each signature or session approved, with OpenSSH's destination constraints | Replaces password SSH for the routers. |
    | 4 | PostgreSQL, then MySQL: the broker answers the authentication handshake (SCRAM for PostgreSQL) and relays, with the database pinned | As Secretless does. |
    | Later | WebSocket (Deepgram streaming); AWS SigV4 or short-lived STS credentials; a Unix socket listener; grants for clients that run in their own sandbox | Only on concrete demand. |
    | Not planned | Connector plugins; credential providers other than the vault | Fixed connectors keep the code reviewable; the vault is the provider (imports cover keyrings and `.env` files). |

    (Superseded with the table.) With phases 1 to 4, Rusthorse covers what Secretless offers — HTTP,
    PostgreSQL, MySQL, SSH keys and `ssh-agent` — and adds client
    authentication, approval, scope, lifetime, revocation and audit.

11. **SSH with passwords is a documented limit.** No phase gives a
    password-only SSH server a credential the client does not see: the
    password is what `ssh` sends, so whoever runs `ssh` must have it.
    Devices reached by SSH should use keys (phase 3, `ssh-agent`); until
    then, `run` with `SSH_ASKPASS` remains possible, with the limits of
    `run` (L3–L5). The maintainer's routers move to SSH keys. (Superseded
    2026-11-04: the `ssh-agent` connector is not planned; SSH uses `run`,
    with L3–L5.)

12. **Before real credentials**, end-to-end tests with a fake destination
    and fake keys must show everything listed under
    [Tests](#tests-before-real-credentials).

## Phase 1 specification

This section is normative for phase 1. Where a number is given, it is the
phase 1 value; changing it changes this ADR.

(Since 2026-11-04 the broker that is built is the one of the
[scope amendment](#scope-amendment-2026-11-04), which keeps this section's
processes, tokens, framing, admission, revocation, limits and audit, and
replaces its profiles, presets, routes and header lists. Passages that the
amendment replaced are marked where they stand.)

### Components and processes

- **`rusthorse-broker`**, a new member of the workspace (`broker/`), built for
  Rust 1.89 like the main package. It depends on the `rusthorse` library
  (without default features) for the agent–broker protocol, the profile types
  (superseded 2026-11-04: the grant's destination and limits) and the
  redactor, and on `hyper` 1 (HTTP/1.1 server and client), `tokio`
  (current-thread runtime), `rustls` 0.23 with the `ring` provider,
  `tokio-rustls` and `rustls-pki-types` (to parse the fixed CA file; no
  `rustls-native-certs`). Their default features are off where those would add
  another cryptography library, proxy support or connection pools.
- **Where it is found.** Next to the agent's executable, with the checks
  `rusthorse-dialog` gets (a regular executable owned by the user or root,
  not writable by group or others, refused when the agent's own executable
  was replaced since it started). There is no fallback: when the program is
  absent or unusable, `run --broker` fails before the dialog is shown.
- **How it is started.** One process per grant, started after the approval
  and before the command: an empty environment, `/` as working directory,
  its own process group, standard input and output one end of a socket
  pair (the control channel), standard error `/dev/null`. Before it reads
  anything it makes itself non-dumpable and disables core files (`execve`
  undid the agent's protection, threat model P10). It exits as soon as the
  control channel ends, so a dead agent leaves no broker behind; under
  systemd, stopping the agent's service kills it too.
- **The listening socket** is created by the agent (`127.0.0.1`, a port
  chosen by the kernel) and passed to the broker over the control channel.
  The agent keeps its own copy until the command ends, so the port cannot
  be taken by another program while the command may still use it, even if
  the broker fails. The command gets `http://127.0.0.1:PORT` plus the
  profile's base path (superseded 2026-11-04: the base path of the run's URL)
  — never `localhost`, which can resolve to an IPv6
  address another program listens on.
- **Trust.** The broker reads its certificate authorities from the first
  existing file of a fixed list (`/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`), which must be
  a regular root-owned file in root-owned directories, none writable by group
  or others. The first existing file decides; an unsafe file is not skipped.
  `open_ca_file` checks the opened descriptor; the broker parses its PEM
  certificates and requires usable trust before Ready. `doctor` checks file
  availability and ownership/mode, not PEM contents. The broker's own
  production code reads no environment variables; its dependencies may read
  theirs, unset because the agent uses an empty environment. No requester
  proxy, CA or resolver variables reach it.
- **Tests only:** a feature of the broker package that is never enabled in a
  release (like `fake-keyring`) lets end-to-end tests add a test certificate
  authority and reach a loopback destination. The release build,
  `packaging/build-deb.sh`, enables no feature. `test-upstream` is a compile
  error without debug assertions and is reported by `--check`; `doctor`
  refuses that marker. Even a test build uses production settings unless
  `RUSTHORSE_BROKER_TEST_ROOTS` is set before startup; only then does it read
  its other test hooks and permit loopback. The agent does not run `--check`
  before each grant: its empty environment gives that trusted helper
  production settings. Packaging checks the built broker and every packaged
  broker. cargo-deb writes the packages into a private staging directory;
  they are moved to the output directory only if every broker in them passes,
  and otherwise the staging directory is deleted, so a refused package never
  reaches the output directory. The exact rules are in ADR 0010, decision 9
  (R01–R04 in the review history; they replaced the cleanup of refused
  packages that Q01 had extended).

### The token and the grant ID

- The **token** is `rh_` followed by 64 lowercase hexadecimal digits (32
  bytes from the operating system's random generator). The agent creates
  it, puts it in the command's environment and in the redactor, and gives
  it to the broker. The broker compares it in constant time; anything not
  of that exact form is refused before comparison. (Since the scope amendment:
  a token-shaped string — `rh_` and 64 hexadecimal digits, in any case — in
  the method, the target, a header's name or a header the broker drops or sets
  itself is refused as it stands, the token itself included; in a header value
  the broker forwards, each one is compared with the token byte for byte, in
  constant time, and the first that differs, a copy of the token in another
  case included, refuses the request.)
- The **grant ID** is `g` followed by 16 lowercase hexadecimal digits,
  random. It is public: the audit log, `rusthorse grants` and the manager
  show it.

### Profiles

(Superseded 2026-11-04 with the presets below: see the [scope amendment](#scope-amendment-2026-11-04).)

A profile is stored in the entry's custom string field
`Rusthorse.Broker`, unprotected, as one line of JSON:

```json
{"version":1,"preset":"anthropic","revision":1,"origin":"https://api.anthropic.com","base_path":"","automatic_locks":"continue","max_lifetime_minutes":720}
```

| Field | Meaning |
|---|---|
| `version` | The format: `1`. |
| `preset`, `revision` | The preset and the revision of it the human approved. A newer Rusthorse keeps old revisions as they were: it never widens a stored profile. |
| `origin` | `https://` and a host name, with an optional port. No IP address, user information, path, query or fragment in phase 1. |
| `base_path` | What the client's base URL adds after the origin: empty, or one or more segments, each `/` followed by letters, digits, `.`, `_`, `~` and `-`, never a segment made only of dots (`.`, `..`, `...`), with no trailing `/` — the same rules as a request's path. |
| `automatic_locks` | `end` or `continue`: whether screen lock, suspend and the idle timeout end the entry's grants (decision 8). |
| `max_lifetime_minutes` | 1 to 1440. |
| `max_requests` | Optional, 1 to 1,000,000: the most requests one grant admits. |

Rules:

- The agent stores the profile with every field written out, so a later
  default never changes it. It reads it strictly: an unknown `version`,
  preset, revision or field, a value out of range, or more than 1000
  characters makes the profile **unusable** — `show` reports it, and
  `run --broker` refuses the entry; nothing guesses. A protected field is
  withheld like any protected field and is unusable for the broker.
- A profile is set or cleared only by `rusthorse edit` (`--broker PRESET`
  with `--broker-origin`, `--broker-base-path`, `--broker-locks`,
  `--broker-lifetime`, `--broker-requests`; `--clear broker`), approved in
  a dialog that shows the whole new profile and how many grants it ends.
  `add` and `import` cannot set one, and replacing an entry (`add
  --replace`, `import --replace`) removes it.
- A profile is metadata (threat model L6): it holds no credential, token or
  other secret. `show`, `list --json` and the manager display it.
- It is read only from the agent's copy of the vault. A profile or entry
  edited by another program while the agent is unlocked is not seen: the
  agent's next save fails (L15), and a failed save ends every grant. A
  vault file changed while the vault is locked is noticed at the next
  unlock, which then ends the grants that survived the lock (below).

### Presets

(Superseded 2026-11-04: no presets, routes or header lists; see the
[scope amendment](#scope-amendment-2026-11-04).)

| Preset (revision 1) | Default origin, base path | Client presents the token as | Credential sent to the destination as | Routes (after the base path) |
|---|---|---|---|---|
| `anthropic` | `https://api.anthropic.com`, empty | `x-api-key: TOKEN` or `Authorization: Bearer TOKEN` | `x-api-key: KEY` | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models`, `GET /v1/models/{id}` |
| `openai` | `https://api.openai.com`, `/v1` | `Authorization: Bearer TOKEN` | `Authorization: Bearer KEY` | `POST /chat/completions`, `POST /responses`, `POST /responses/input_tokens`, `POST /embeddings`, `GET /models`, `GET /models/{id}` |
| `openai-compatible` | none (the profile names it), `/v1` | `Authorization: Bearer TOKEN` | `Authorization: Bearer KEY` | `POST /chat/completions`, `POST /embeddings`, `GET /models`, `GET /models/{id}` |

- Routes are exact. `{id}` is one segment of 1 to 128 letters, digits,
  `.`, `_`, `:`, `~` and `-`. Message batches, files, administration, key and
  organisation management, fine-tuning, uploads and everything else are
  not routes of any phase 1 preset; they answer `404` from the broker and
  are never forwarded.
- Query parameters: `beta` (value `true`) on the Anthropic routes, and
  `limit` (1 to 4 digits), `before_id` and `after_id` (each a model ID, in
  the form of an `{id}`) on `GET /v1/models`; none elsewhere.
- Request headers forwarded (all others are dropped): `content-type`,
  `accept`, `user-agent`, and those starting with `anthropic-`,
  `x-stainless-` or `x-claude-code-` (Anthropic), or `openai-beta` and
  those starting with `x-stainless-` (OpenAI and compatible).
  `OpenAI-Organization` and `OpenAI-Project` are dropped: the key decides
  the account.
- Response headers relayed (all others are dropped): `content-type`,
  `date`, `cache-control`, `retry-after`, `x-should-retry`, `request-id`,
  `x-request-id`, `openai-processing-ms`, `openai-version`, and those
  starting with `anthropic-ratelimit-` or `x-ratelimit-`.
- When both token headers arrive (Anthropic), both must carry the token;
  any other credential the client sends is dropped, never forwarded.

### Requests and responses

The broker serves HTTP/1.1 and speaks HTTP/1.1 to the destination. For each
request, in order:

1. **Framing**: the HTTP library refuses malformed messages, conflicting
   `Content-Length` values and lines folded over several lines; identical
   duplicate `Content-Length` headers are merged by it, which leaves no
   ambiguity. The broker then refuses (`400`) any request with a
   `Transfer-Encoding` header (a request body must be sent with
   `Content-Length`, as the supported clients do), an `Upgrade` header, a
   `Connection` header naming anything but `close` or `keep-alive`, a request
   target that is not in origin form, a `Host` other than `127.0.0.1:PORT`, an
   `Origin` header (browsers have no business here), a method `CONNECT`,
   `TRACE` or `OPTIONS`, or a body on a route without one; HTTP versions other
   than 1.1 get `505`; headers larger than 32 KiB or more than 100 headers get
   `431`. The whole header block must arrive within 30 seconds of the
   connection being opened or of the previous response on it. (Stated exactly
   on 2026-11-09: HTTP/1.0 gets `505`; any other version in a request line is
   a parse error of the HTTP library, normally answered with an empty `400`,
   and an HTTP/2 connection preface closes the connection without a response;
   the limit of 100 headers is that library's default, which the broker does
   not set itself and no test of the broker covers.) (Changed on 2026-11-10:
   the broker sets the limit of 100 headers itself, and its tests send 100
   and 101. The library counts header lines, `Host` and each line of a
   repeated name included; it answers a request with more than 100 with an
   empty `431` and closes the connection, before the token is checked or
   anything is asked of the agent. Such a request has no number and no
   `broker_request` record: it counts among the broker's refusals before
   admission, which its `revoked` reports. The grant's end record includes
   that count if the agent receives `revoked`; end records are best effort.)
2. **Token**: missing or wrong → `401`.
3. **Route** (superseded 2026-11-04: no route check; the path and query go
   as the program sent them): the path must be in the exact form above, without `%` escapes,
   empty segments or segments made only of dots, `;`, `\` or `#` in the target
   seen by the broker, and match a route of the preset after the base path,
   with only the allowed query parameters (each at most once); otherwise
   `404`. The path the broker checks is the path it sends. Hyper strips a `#`
   fragment before this check, so its original presence cannot be refused; the
   fragment is not forwarded.
4. **Room for the body**: a body may be at most 16 MiB (`413`). A broker
   holds at most 64 MiB of request bodies at once: it reserves the
   declared length before it asks for admission, and a request that does
   not fit gets `503` with `retry-after: 1` — nothing was admitted or sent.
5. **Admission** (below): the grant's state, the request limit, the number
   of requests in flight and the audit record. Only an admitted request is
   read further; a grant that has ended or is exhausted is refused before
   its body is received.
6. **Body**: read whole into memory before anything is sent, within 60
   seconds; a body that does not arrive in full is not forwarded (outcome
   `not_forwarded`; the use is spent). A body timeout returns `408`. A client
   that sent `Expect: 100-continue` gets its `100 Continue` only once the
   request is admitted.
7. **Forwarding**: the broker resolves the origin's host, keeps only public
   addresses (no loopback, private, link-local, unique-local, shared,
   multicast, unspecified or IPv4-mapped forms of them) and connects to one of
   those it checked, without re-resolving for the connection. It resolves once
   per admitted request, tries retained addresses in order within a shared
   10-second resolution/connect deadline, and keeps at most 4 resolver calls
   running. A blocked system resolver may outlive the cancelled request, but
   retains its slot until it returns; it does not delay broker exit.
   IPv4-mapped/compatible IPv6 is refused outright. IPv6 allows global
   `2000::/3`, except `2001::/23`, `2001:db8::/32`, `2002::/16` and
   `3fff::/20`; the well-known NAT64 `64:ff9b::/96` prefix is allowed only for
   an embedded public IPv4 address. The IPv4 exclusions are in
   `broker/src/destination.rs`. TLS 1.2 or 1.3 with the host as SNI, ALPN
   `http/1.1` only, no early data, no key log. The request line, `Host`,
   `Content-Length` and the credential header are its own;
   `Accept-Encoding: identity` replaces the client's. Only the headers listed
   for the preset pass, so hop-by-hop headers (`Connection`, `Keep-Alive`,
   `TE`, `Trailer`, `Upgrade`, `Proxy-*`) never do; a listed header whose name
   or value contains the token is dropped too, so the broker never sends the
   token in a header; trailers are dropped in both directions. One connection
   per request; nothing is shared between grants. (Superseded 2026-11-04 for
   the headers: there is no credential header of the broker's own and no list
   per preset. Every request header is forwarded except the hop-by-hop ones
   and `Host`, `Content-Length` and `Accept-Encoding`, and the key replaces
   the token in the values forwarded.)
8. **Response**: refused with a local `502`, before anything is passed to the
   client, when it is a `101` (stated here on 2026-11-09, as the broker has
   done since phase 1; the HTTP library discards a destination's other `1xx`
   responses, such as `100 Continue` and `103 Early Hints`, with their
   headers, and the broker checks and relays the final response), a `3xx` (no
   `Location` reaches the client), has a
   `Content-Encoding` other than `identity` (in any of its occurrences), or a
   `Transfer-Encoding` other than exactly `chunked` (a compressed transfer
   coding would hide the credential from the redactor). Otherwise the status
   and the relayed headers are passed on and the body is streamed with chunked
   framing where HTTP permits a body, through a bounded look-behind redactor
   that replaces literal copies of the credential with
   `[REDACTED:credential]`, a fixed text that is safe inside JSON. A header
   whose value contains the credential is dropped. At most 64 MiB of upstream
   body per response, before redaction.

A credential must be at least 8 and at most 4096 characters, all visible ASCII
without spaces, or the entry cannot be used with the broker. This minimum
exceeds the output redactor's minimum, and the credential must be
representable in an HTTP header.

Local answers produced by the broker carry a short JSON error (amended
2026-11-04: of type `rusthorse_broker`, with a fixed message that starts
with `rusthorse-broker:`; that of a grant that has ended says to run the
command again with `rusthorse run`) and, except
`429` and `503`, `x-should-retry: false`, so that the clients' own retries do
not repeat what cannot succeed. A failure to resolve, connect or complete TLS,
before anything was sent, is a `502` without that header: nothing reached the
destination, so the client may retry (as a new request, which counts). A
response-head timeout returns `504`; a failure after sending can return `502`
with outcome `unknown` and `x-should-retry: false`. Once response headers have
gone to the client, a body failure cuts the stream. Hyper's own parse/framing
errors precede this logic: they can have an empty body and no retry hint
(including its `400` and `431`).

### Admission, revocation and the agent's registry

- The **agent** keeps a registry of grants and is the one authority for their
  state and limits. Every request the broker accepts goes through it over the
  control channel: `admit` (request number, method and route; superseded
  2026-11-04: the method's label, no route) → the agent
  checks that the grant is active and within its limits, reserves a use and a
  slot, writes the admission record (durably), checks again that the grant is
  still active, and answers `admitted` or `refused` with the same request
  number. On revocation, the agent answers pending admissions immediately;
  their audit work may finish later. The broker reads the body and forwards
  only after `admitted`, and only if it has not been told to revoke meanwhile;
  it reports `finished` with the number and the outcome, which frees the slot
  and is recorded. A `refused` admission releases its reservation; an admitted
  request spends its use whatever its outcome.
- **Request numbers** are chosen by the broker, consecutive from 1 within a
  grant (each one more than the last: a gap is a violation, like a repeat).
  The agent accepts each number once in `admit` and once in
  `finished`, after `admitted`; anything else — a number reused, a
  `finished` for a number not admitted or already finished, an unknown
  message — is a broken broker: the agent ends the grant (`broker_failed`)
  and kills the broker, and changes no counter for the offending message.
- **States**: `starting` (the broker is being prepared; no request admitted),
  `active`, `exhausted` (no new admission; admitted requests finish),
  `revoked` (nothing new; open requests closed) and `ended` (the broker has
  exited). A grant never becomes active again. The public list includes
  `starting` and retained `revoked` grants; `ended` is not a `GrantState` on
  the client wire. Status counts starting, active and exhausted grants; the
  16-grant capacity also includes retained revoked ones while their brokers
  remain registered. Broker exit removes the registry entry sooner; the run
  still holds its listener until cleanup.
- **Preparing a run's grants** is one transaction. The grants are entered in
  the registry as `starting` under the same lock that checks the vault
  generation and reads the credentials, so a lock is either before (the run
  fails, nothing was read) or after (it ends the `starting` grants). Then, for
  each grant, the agent binds the port and starts the broker. Under the
  registry lock, and only while still starting, it registers the control Link
  and sends `install` non-blockingly; there is no credential handoff before
  the Link is subject to revocation. A failed or incomplete send kills and
  reaps the child. It waits for `ready`, at most 10 seconds. Last, under the
  registry's lock, it checks that every grant of the run is still `starting`
  and makes them all `active`; only then does it start the command. If
  anything fails — a broker that does not start or answer, a grant ended
  meanwhile, the command that cannot be started — every grant of the run is
  ended, its broker stopped and its port released, and only then does `run`
  fail (125, nothing ran).
- **Revocation** is decided in the registry, so no request is admitted after
  that moment. The agent then tells the broker to revoke: it closes every open
  request and stream, drops the credential, confirms, and from then on answers
  `403` until the command ends. A broker that does not confirm within one
  second is killed. Every revocation waits for that confirmation or confirmed
  process death — a requested kill alone does not count. Concurrent revokers
  wait for the same Link to be confirmed or Gone; Gone is published only after
  kill/reap. Control writes have their own short deadline (250 ms);
  confirmation has a one-second deadline, then process cleanup. Brokers of a
  lock are told together. These are scheduling-dependent bounds, not a
  real-time deadline. Only then is the lock, the edit or the revocation
  reported done. A lock before suspend keeps the limits of L20: it can start
  late (a save in progress holds the agent's state), and logind waits only so
  long. Between the decision and the confirmation, a request admitted just
  before the decision may still be sent; after it, nothing more is. Revocation
  never waits for the audit log.
- **The unlock barrier**: a grant can outlive a lock (`continue`), and another
  program may change the vault file while it is locked — move an entry, change
  its value — without touching the times KeePass records. The agent therefore
  keeps, in memory only, a fingerprint of the vault file's encrypted content
  as it last read or wrote it (a hash keyed with a random key the agent
  chooses at start), and keeps it across a lock. The implementation uses one
  `RandomState` created on its own thread when that thread can be started
  (otherwise on the caller's), with two domain-separated outputs, not a claim
  of cryptographic 128-bit collision resistance. After an authenticated read
  and a generation check under the state lock, it compares the file
  fingerprint: if they differ, or the agent has none, every grant that
  survived the lock ends (`vault_changed`). An unchanged file leaves them
  running; a changed file ends them even if the change concerned other
  entries. The agent decides under the state lock, contains the brokers,
  writes the unlock record outside that lock, then checks the generation again
  before publishing the unlocked state. A lock before comparison cancels the
  attempt and preserves the old fingerprint; the next valid attempt detects
  the change. Once comparison decides revocation, a later lock does not undo
  it. Failed unlocks keep the previous fingerprint; successful saves by the
  agent update it.
- **The end of the command** is noticed when its leader exits (or the
  requester disconnects): the run's grants are revoked then — before the
  command's other processes are terminated and before its output is
  drained — and their brokers are stopped and the port released once the
  command is over. A process that escaped the command's process group
  (L17) keeps only a token that no longer works.
- **Limits** in phase 1: at most 16 grants at once per agent; per grant, 16
  requests in flight (more get `429` with `retry-after: 1`) and 64 open
  connections; idle connections are closed after 60 seconds (stated exactly on
  2026-11-09: a connection with no request in progress is closed, unanswered,
  30 seconds after it was opened or after its last response — the deadline for
  a request's head, which normally comes first; the broker's own idle limit of
  60 seconds can still close a connection whose response is not being read,
  once that response's body has been handed over); the destination
  must be resolved and connected within 10 seconds, complete TLS within 10
  seconds and answer with its headers within 10 minutes, and the response body
  may not pause for more than 5 minutes. The maximum lifetime is measured on
  the boot-time clock, so time spent suspended counts. The agent refuses
  grants if its expiry timer could not start. The broker also expires
  independently: a scheduled task drops its credential and work, and
  forwarding/body checks enforce the deadline even before that task runs. It
  sends no unrequested `revoked` at expiry; it still answers a later agent
  `revoke`.
- **Leaving**: a broker exits at once when its control channel ends,
  without waiting for work in progress (a name resolution that hangs
  included); the agent kills its process group if it is still there a
  second later.
- **The idle timer**: requests through the broker are not approvals and do
  not postpone the idle lock (P9 unchanged). Whether that lock ends a
  grant is the profile's `automatic_locks` (superseded 2026-11-04: the run's
  `--broker-locks`).

### The control channel

Framed like the dialog protocol (a 4-byte big-endian length, then JSON,
unknown fields refused), with its own version number, frames of at most 64 KiB
and the listening socket passed as file-descriptor data. Agent to broker:
`install` (version, grant ID, token, credential, profile snapshot, limits;
amended 2026-11-04: the destination instead of a profile, and an
admission carries the method's label instead of the route),
`admitted` and `refused` (request number), `revoke`. Broker to agent: `ready`,
`admit` (request number, method, route; amended 2026-11-04 as above),
`finished` (request number, outcome, status, sizes), `revoked`, with a count
of the requests it refused before admission (its own refusals, not the
agent's). The normal broker sends `revoked` after every admission answer and
every admitted request's `finished`. The agent tolerates an early
acknowledgement and finishes outstanding admitted requests as unknown rather
than hanging; see
[the control-channel contract](../protocol.md#agentbroker-control-channel-broker-protocol-2).
The credential and the token are kept in zeroizing buffers and never printed.
Nothing else crosses: no vault, no master password, no requester environment.

### Audit records

| Action | When | Fields beyond the usual ones |
|---|---|---|
| `run` | the approval, as today | the grants it creates, by ID, entry and destination |
| `grant` | created (before the command starts; fail closed), ended (best effort) | grant ID; at the end: the reason (`command_ended`, `locked`, `screen_locked`, `suspend`, `idle_timeout`, `revoked`, `entry_changed`, `vault_changed`, `expired`, `broker_failed`, `save_failed`, `agent_stopped`, `audit_failed`), requests admitted, finished and unknown, requests refused before admission |
| `broker_request` | admitted (before forwarding; fail closed) | grant ID, request number, route template including the method (`POST /v1/messages`); amended 2026-11-04: the method's label only (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OTHER`), never the path |
| `broker_request` | finished (best effort) | grant ID, request number, outcome (`completed`, `not_forwarded`, `client_closed`, `revoked`, `unknown`), status, bytes each way |

Refused requests are counted, not recorded one by one, so a client cannot
flood the log. If a `finished` record cannot be written, the grant admits
nothing more (it is revoked with reason `audit_failed`).

### `run`, `grants` and the protocol

(Amended 2026-11-04: no profiles, `edit --broker` or `broker_edit`; the
destination and the limits come with the run, and the protocol becomes 9 —
see the [scope amendment](#scope-amendment-2026-11-04).)

- `rusthorse run --broker VAR=ENTRY` (repeatable; superseded 2026-11-04:
  `VAR=ENTRY@URL`) and `--url URLVAR=ENTRY` as
  in decision 6. The agent checks that the variables are valid and distinct,
  that no entry is both brokered and given by value (by UUID), that each
  brokered entry has a usable profile (superseded 2026-11-04: that each
  binding names a valid destination) and a value the broker can carry (8 to
  4096 visible ASCII characters), that no more than 16 grants would then be
  retained, and that the broker program is usable — all before the dialog —
  and adds `127.0.0.1` to `NO_PROXY` and `no_proxy` in the command's
  environment. The token and URL variables the requester sent are dropped.
- `--remember` is not offered for a run with `--broker`: each approval
  creates its grants once.
- `--no-redact` is allowed with `--broker`, with a warning in the dialog:
  the output is not filtered, so the token can reach whoever reads it, who
  can use the grant until it ends. It is what an interactive program such
  as Claude Code needs, since `run` gives it the terminal only without
  redaction.
- `rusthorse grants [--json]` lists retained grants (ID, entry, destination,
  command, requester, start, end, requests used and allowed, policy, and —
  amended 2026-11-04 — the requests the destination answered with `401`) —
  never a token — and `rusthorse grants revoke ID|--all` ends them. Neither
  needs an approval, like `lock`.
- `rusthorse status` reports the broker program and the number of active
  grants (starting and exhausted included, revoked excluded);
  `rusthorse doctor` checks the broker program and the certificate file.
- **Protocol 8.** (Superseded 2026-11-04: protocol 9 and `broker_run_v2`,
  which an agent of protocol 8 refuses; `broker_run` and `broker_edit` are
  refused. The protocol has since moved on for other work: see
  [protocol.md](../protocol.md).) A run with broker bindings is a new request,
  `broker_run`: the run request's fields plus the list of broker bindings
  (variable, entry, URL variable). An agent of protocol 7 does not know
  that request and refuses it whole, so a client that checked the version
  on one connection and meets an older agent on the next one (after a
  restart) still runs nothing; a plain `run` carrying broker bindings is
  refused by the agent. In the same way, an edit that sets or clears a
  profile is a new request, `broker_edit` (the fields of `edit`, profile
  included), and a plain `edit` that carries a profile, or names `broker`
  among the fields to clear, is refused — an older agent would apply the
  other changes and drop the profile; entries report their profile; `grants` and `revoke_grant` are new
  requests; `status` gains optional fields. No error code is added: a grant
  that cannot be served before the command starts is `internal` or
  `invalid_request`, which `run` reports as 125. A client of protocol 8
  refuses an agent of protocol 7 before it sends anything else.

### The manager

The manager's grants page lists the retained grants with their entry,
destination, command, start, end and requests (amended 2026-11-04: and the
requests their destination answered with `401`), and revokes one or all — also
while the vault is locked, which the page says, since grants can outlive a
lock. It shows an entry's profile, read-only. Editing a profile stays in the
CLI until phase 2. (Amended 2026-11-04: there are no profiles to show or
edit.)

### Tests before real credentials

End-to-end, with a fake HTTPS destination in the test process and fake
keys, showing the allowed and the refused path of each:

(This is phase 1's list. Superseded 2026-11-04 where a row names routes,
query parameters, a profile, protocol 7, `broker_edit` or the headers a
preset lists, and its "Profiles" row whole: the broker without profiles
has its own tests, in `broker/tests/` and `tests/agent.rs`, for the
destination named in the run, the token's place in the request head and
the method's label in the audit.)

| Area | Must show |
|---|---|
| The key | Never in the command's environment, output, files it can write from what it receives, error bodies, response headers, the audit log, `grants` or `status`; the destination receives exactly one credential header, built by the broker, and the broker never sends the token in a header it builds or passes on (a `User-Agent` carrying it, or an `x-stainless-` header named after it, is dropped). |
| Tokens | Missing, malformed, wrong, another grant's, or conflicting token headers → `401`, nothing forwarded. |
| Routes and framing | `/v1/messages/batches`, unknown methods, `%2e%2e`, `//`, `;`, `\`, absolute-form targets, a foreign `Host`, `Origin`, `CONNECT`, `TRACE`, upgrades, any `Transfer-Encoding` on a request (alone and with `Content-Length`), conflicting lengths, `Connection` naming a forwarded header, a query parameter twice, oversized headers and bodies, headers that trickle in → refused, nothing forwarded. |
| Destination | `Host` and SNI from the profile; the requester's proxy and certificate variables, and the agent's, have no effect on the broker; private addresses refused; a `3xx` with `Location` reaches the client as `502` without it; a response with a compressed `Content-Encoding` or `Transfer-Encoding` refused before anything reaches the client; a stalled resolution does not hold the HTTP request beyond its deadline (the system resolver call may finish later). |
| Redaction | The credential echoed in a response body, split across chunks, and in headers, is removed; `Content-Length` is not passed on; a credential shorter than 8 characters is refused before the dialog. |
| Limits | With a request limit of N, at most N requests reach the destination however many arrive at once; the N-th finishes; the limit of requests in flight and the 64 MiB of bodies hold under load; refused admissions free their slots; requests finishing in another order than they started are counted right. |
| Revocation | `rusthorse lock`, `grants revoke`, the automatic locks with `end` (and not with `continue`), an entry edit, expiry: open streams end; once the revocation is reported done nothing new is forwarded; an admission waiting for its audit record is refused if the grant was revoked meanwhile; a vault file changed by another program while locked — an entry moved, a value changed, its modification time kept — ends the grants that survived the lock at the next unlock, and an unchanged file keeps them; a failed unlock keeps the previous fingerprint, so the change is still found at the next attempt; the agent's own successful save of another entry updates the fingerprint and ends no grant. |
| The command's end | A stolen token stops working once the agent sees the command's leader exit — before its output is drained, and for a descendant that called `setsid`. |
| Failures | Broker program missing or unusable → `run` exits 125 before the dialog and the key is nowhere; one broker of a run failing to start → none of the run's grants remains and nothing ran; the broker dying mid-request → the outcome recorded as unknown, the run's status still the command's; a broker that ignores `revoke`, or breaks the request numbering, is killed; a broker whose control channel ends exits even with a name resolution in progress. |
| Audit | A failed admission record stops forwarding (the destination counts no request); a failed `finished` record ends the grant; revocation still works when the audit log cannot be written. |
| Protocol | A protocol 7 agent and client refuse each other, a protocol 7 agent refuses `broker_run` and `broker_edit` whole (a version checked on one connection, an older agent met on the next), and a plain `run` with broker bindings or a plain `edit` with a profile is refused; `--remember` is not offered; mixed runs; the same entry both ways refused; `--no-redact` warns. |
| Profiles | Unknown version, preset, revision or field, a `base_path` with `.` or `..`, protected or too long → unusable; replace removes the profile; a profile survives a round trip through a KeePassXC-compatible file; an edit ends the entry's grants. |

## Answers to the open questions

Closed with the maintainer on 2026-11-02, after the first review (the
second review's corrections are folded in):

1. **What is a "use"?** One HTTP request the broker admits for forwarding.
   A server-sent event stream is one request and holds a concurrency slot
   until it ends; each retry by the client's SDK is another request;
   requests refused before admission do not count. An admitted request is
   never given back, whatever its outcome.
2. **Who edits profiles, and which changes end grants?** (Superseded
   2026-11-04: there are no profiles; any change to an entry still ends its
   grants.) The human, through
   an approved `edit` (the CLI in phase 1, the manager in phase 2). Any
   change to the entry — value, user name, URL, profile, group, replacement,
   removal — ends its grants.
3. **How does the dialog express cost and power?** By stating facts the
   broker enforces (destination, every route, the end of the grant, the
   request limit) and those it does not: the command can spend credit, a
   request count is not a spending limit, the bodies are not inspected.
   (Superseded 2026-11-04 in "every route": the dialog shows the approved
   origin and says that the key may be sent to any path there.)
4. **Where does the client run?** The command is still started by the
   agent, outside the requester's sandbox (L16 unchanged in phase 1).
   Grants for a client that stays in its own sandbox come later
   (superseded 2026-11-04: not planned).
5. **How does a client find the broker after a restart?** It does not: a
   grant dies with its broker and with the agent, and a new run asks again.
   The address is `127.0.0.1` with a port the agent holds while the command
   runs.
6. **How is a revoked request that the destination accepted shown?** In the
   audit log, as outcome `unknown`; the client sees an error or a stream
   cut short; `run`'s exit status stays the command's (125 only before the
   command starts).
7. **Certificates of private devices?** (Superseded 2026-11-04: private
   devices are not planned.) Not in phase 1. Phase 2: enrolled by
   fingerprint, approved by the human after checking it through another
   channel; a changed certificate fails closed until a new approval.
8. **Which endpoints are refused for every grant?** Everything that is not
   an exact route of the profile's preset; `CONNECT`, `TRACE`, `OPTIONS`
   and upgrades always. (Superseded 2026-11-04 in its first half: there is no
   route check, and any path at the approved origin is forwarded; `CONNECT`,
   `TRACE`, `OPTIONS` and upgrades are still refused.)
9. **Which SDKs are supported?** Phase 1 is tested with requests in the
   form the Anthropic and OpenAI SDKs and Claude Code send; Claude Code
   2.1.316 and the Python SDKs are tried by hand with the maintainer before
   any version is called supported. The guide recommends turning the SDKs'
   retries off. (Amended 2026-11-04: the manual check began, with the
   maintainer's key and approval. The Anthropic Python SDK 2.4.0 worked
   through the broker as with the key by value — create and streaming
   requests to Sonnet 5.5, and streaming requests to Haiku 5.5 with a
   minimal input. Claude Code 2.1.317's own requests went through the
   broker to the API, which answered `400` "credit balance is too low".
   SDK requests with a minimal input and some of Claude Code's parameters
   (its betas, adaptive thinking, context management, effort) drew the
   same answer with the key by value and through the broker, and with that
   key the beta `claude-code-20250219` alone drew it; they were not full
   reproductions of Claude Code's requests. No answer from Claude Code
   through the broker has been seen yet, and no version is called
   supported yet; the maintainer left Claude Code's check for later, since
   the account, with or without the broker, refuses requests that carry
   that beta. Amended 2026-11-09, to record what followed on 2026-11-04, with
   the broker without profiles: the maintainer tried it with `curl` — a `GET`
   and a `POST` answered, a token in the URL refused by the broker — the
   Anthropic Python SDK 2.4.0 worked through it for a message and two streams,
   and Claude Code 2.1.318 answered through it in print mode (`claude -p`) and
   interactively. No client version is called supported yet.)
10. **Can one grant cover several entries?** No: one grant, token, broker
    and port per entry; one run may hold several, approved in one dialog
    and prepared together before the command starts. They end together
    when the command ends, on the explicit lock and when the agent stops;
    each also ends on its own (its entry changed, revoked by hand, its
    profile's policy, its lifetime). (Superseded 2026-11-04 in "its profile's
    policy": the policy its run set.)

## Alternatives considered

- **Only `run`, with per-entry policies** (allowed programs and hosts).
  Cheap, and still worth having against mistakes, but the program still
  receives the secret: it does not stop exfiltration after the approval.
  (Superseded 2026-11-04: per-entry policies are outside the product's
  scope and not planned; ordinary `run` keeps the limits L3–L5.)
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
- **Specific operations instead of a generic proxy** (superseded: not
  planned, see the [scope amendment](#scope-amendment-2026-11-04)) ("show the firewall's
  interfaces"). The right shape for administration APIs; it enters through
  phase 2's narrow operations rather than as a separate mechanism.
- **Running the AI agent as another user.** The answer to a hostile agent
  (A2), already planned (§8); it complements the broker, which mainly
  protects against a fallible one (A1).
- **One long-lived broker for every grant**, or one per run. Fewer
  processes, but a bug in the network code would expose every active
  credential, and revocation and accounting would be shared between
  grants. One process per grant costs a process start per grant.
- **Every lock ends every grant**, as this ADR first said. Simpler, but a
  long session of an AI agent would stop whenever the screen locks, which
  would push users back to `run` without the broker. The profile decides
  instead, and the explicit lock still ends everything. (Superseded
  2026-11-04: the run decides, with `--broker-locks`.)
- **The broker as the authority for limits**, with the agent only told the
  results. It would save a round trip per request, but the agent must
  record each request before it is forwarded anyway, and two counters
  would have to agree.
- **Refusing `--broker` with `--no-redact`.** It would keep the token out
  of unfiltered output, but interactive programs, Claude Code first, could
  not use the broker at all.

## Consequences

(As written for phase 1. Superseded 2026-11-04 where they name a profile —
as an asset, in an entry's details, in the guide's advice — and in
"Protocol 8": the scope amendment made it 9. The guide's Claude Code recipe
is the one `rusthorse guide ai` prints.)

- **Invariant 1 changes**: a broker process handles the credential of its
  one grant, as the agent hands it over; the CLI and the manager still
  never hold a value they did not ask for. AGENTS.md is updated with the
  implementation.
- **The threat model changes**: new assets (tokens, profiles, the traffic
  through the broker), the broker and its libraries and the certificate
  file in the trusted computing base, new properties (the command gets a
  token; the destination is fixed; revocation; per-request audit), "with
  the broker" paragraphs in L3, L4 and L5, L8 and L17 revisited, and new
  limits: a token can be stolen and used by a same-user process while the
  grant lasts; the loopback hop authenticates the client, not the server,
  and carries the traffic in clear text to same-user processes that can
  reach it; a grant set to survive automatic locks keeps working while the
  screen is locked.
- **New program, new dependencies**: `rusthorse-broker`, with an HTTP
  library, an async runtime, rustls and ring, each justified in its commit;
  the trusted computing base grows, which decision 4 contains. The checks
  in AGENTS.md and the CI gain the new package; the Debian package installs
  a fourth program.
- **Protocol 8**, and a new protocol between the agent and the broker.
- **The manager**: the grants page (until now planned for remembered
  approvals, which keep their own name) and the profile in an entry's
  details.
- **Documentation**: the CLI reference, the protocol, the architecture, the
  AI-agent guide (`rusthorse guide ai`: prefer `run --broker` where a
  profile exists; Claude Code with `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, and
  its settings files checked), `docs/ai-agents.md`, installation and the
  roadmap.
- **What it does not change**: an approval still trusts the program it
  approves for the operations it allows; a careless approval of a broad
  grant is still a careless approval.

## Implementation amendments (2026-11-03)

These amendments record what was implemented and reviewed at `4ff834a`, at the
maintainer's request, after the phase 1 implementation reviews (AI-assisted).
They correct the normative specification above; the 2026-11-02 client survey
remains a dated observation, not a guarantee about all installed SDK versions.
The guide uses the library's key variable and leaves a competing
`ANTHROPIC_AUTH_TOKEN` unset (Q02, `4ff834a`). The package cleanup description
was updated on the same date for Q01's fixes in `b999e72` and `3953912`,
merged in `453e772`; that cleanup was then replaced by a staging directory
that only checked packages leave (R01–R04).

| Area amended | Why and implementation evidence |
|---|---|
| Components, CA file and test feature | `broker/src/config.rs`, `destination.rs`, `broker_protocol::open_ca_file`: PEM parsing through `rustls-pki-types`, descriptor/ancestor checks, and production settings unless the test roots variable is present. P05 fixed in `4c2c5d4`; package and doctor checks are separate controls. |
| HTTP handling and bounds | `broker/src/framing.rs`, `exchange.rs`, `destination.rs`: OPTIONS refused, Hyper's fragment normalization and parser errors, 408/504/505 and unknown outcomes after sending, bounded redaction, ordered resolution with retained resolver slots, explicit IPv6 exclusions. No promise to cancel a blocking libc resolver or to inspect opaque bodies. |
| Registry and Install | P03/P04, `d8c8fe3`: register and send under one lock; confirmation or actual death before reporting containment. `broker_host.rs` counts all retained grants for capacity, including revoked ones, and every lock ends starting grants (`d0c4acb`). |
| Unlock barrier | P01, `c1249d5`: contain before audit, audit outside the state lock, then generation recheck. Cancellation before comparison preserves the old fingerprint; cancellation after the decision never undoes revocation. Fingerprint implementation clarified in `e729ebd`. |
| Lifetime and control contract | P02, `c14c4f9` and `24bea7e`: no serving without the agent timer, independent broker expiry. `6ed1ad7` documents early-Revoked tolerance; the broker sends no unsolicited acknowledgement on expiry. |
| User-visible state, audit and approvals | `grants` includes retained revoked entries; status excludes them. End records are best effort and SIGTERM does not unwind `StopGrants`. The zenity height estimate can refuse multi-grant runs. Manual SDK support validation is pending, as answer 9 requires (done on 2026-11-04: see answer 9). |

The review history records remaining coverage gaps and accepted limitations; a
passing fake-destination test is not evidence of live SDK compatibility.

## Implementation amendments (2026-11-04)

The maintainer's first manual test with a real key, on 2026-11-04, began with
a key the destination did not accept: `run --broker` passed on the
destination's `401` (`authentication_error`, `invalid x-api-key`), which a
command that presented a token reads as the token's fault, and only the audit
log's `status 401` said otherwise. The same test showed that Claude Code shows
the broker's message after its own `Please run /login · API Error: 403`.

| Area amended | Why and implementation evidence |
|---|---|
| `run`'s report after the command (decision 6) | The agent counts, per grant, the admitted requests whose destination answered `401` — from the status in `FromBroker::Finished`, whatever the request's outcome, under the registry's lock (`broker_host.rs`); the broker's own `401`, before admission, never reaches that count. `exited` gains an optional `unauthorized` list, filled once the run's grants are gone; every request whose end a broker reported before it confirmed its revocation or exited is in it. `rusthorse run` prints a `rusthorse: note:` for each after the command, its exit status unchanged; `141` made by the client stays without one. The note comes from the status alone, never from the body, so it is the same for every destination; a destination that answers a bad key with another status is not detected. No error code is added and the protocol version is unchanged: both fields are optional. |
| `grants`, `status` and the manager | `GrantInfo.unauthorized` (optional; a current agent always reports it, `0` included). `rusthorse grants` keeps its table and adds a note on standard error; the manager shows a fact for it. A grant leaves the list when its command ends, so after a short command only `run`'s note and the audit log show it. |
| Local answers | Their message starts with `rusthorse-broker:`, so that a program that shows only an error's message (Claude Code) still says that the broker answered, and the `403` of a grant that has ended says to run the command again with `rusthorse run`. Statuses, headers and the JSON shape are unchanged. This holds for the JSON errors the broker writes: its HTTP parser still answers a malformed request with an empty `400` or `431`, as before. |

The manual check of answer 9 then went on: the Anthropic Python SDK worked
through the broker for the requests tried, and Claude Code's requests went
through it to an API that answered them `400` (see answer 9). A key the
destination refused shows nothing about whether a client works through the
broker.

## Scope amendment (2026-11-04)

After phase 1's manual test the maintainer defined the product. Rusthorse is
a credential vault prepared for AI agents. The secret in an entry is its
value — a key, a password, a token, a certificate. Its URL, username,
host, port and tags are context, for the human and the agent; its notes
and the fields KeePass marks protected stay withheld, like the value. An agent that uses a
credential says where: the command it runs and, through the broker, the
destination the key goes to. The human sees that in a dialog and approves;
that approval is the control, and Rusthorse records it. With ordinary `run`
the approved command gets the value, and Rusthorse cannot limit or count
what the command does with it; through the broker the command gets a token
that Rusthorse limits in time and requests, revokes, and records request by
request. The requester's process chain is shown, not verified. Rusthorse
does not control what a credential can do — that is scoped where the
credential is issued —
and it knows nothing about APIs or providers. A credential taken out of the
vault to run something elsewhere is the human's choice, outside what
Rusthorse protects. No further controls are planned.

### The broker without profiles or presets

This replaces phase 1's profiles and presets. It was reviewed before any code,
and phase 1 stayed as it was until it was built: implemented in `2df51fd` and
`d84f014`, and reviewed ready on 2026-11-04.

- **No profile.** An entry carries no broker profile, and the code knows no
  preset, route or header of any API. `rusthorse edit --broker`,
  `--clear broker` and the `broker_edit` request go. A profile stored by
  phase 1 stays in its entry as an ordinary custom field, which Rusthorse
  ignores: kept as it is, shown by name only, never interpreted, read,
  migrated or widened; a field that cannot be read stops no grant.
- **The destination is named in the run.** `rusthorse run --broker
  VAR=ENTRY@URL` names each grant's destination. The variable ends at the
  first `=` and the URL starts after the last `@`, so an entry's name may
  hold `@` or a group path. The URL is `https://`, a host name with an
  optional port, and an optional base path, under phase 1's rules for an
  origin and a base path: no user information, query or fragment. There is
  no default destination and no fallback to the entry's URL: the agent
  says where. `--url URLVAR=ENTRY` gives the program the broker's address
  with that base path, as before. Options of the run set its grants'
  request limit, lifetime and automatic locks, with phase 1's defaults (no
  limit, 12 hours, `continue`).
- **Approval covers the whole origin** — scheme, host and port. The base
  path only sets up the program's base URL; it limits nothing. The broker
  connects to the approved origin only, and takes the TLS server name and
  `Host` from it; no request target or header can change it.
- **The dialog shows it**: the entry; the approved origin, and the base
  path apart from it, with "The key may be sent to any path at this
  origin; the base path is not a limit"; the lifetime, the request limit
  and the automatic locks; that the command gets a temporary token, not
  the key; and phase 1's warnings — the command can spend credit, a
  request count is not a spending limit, the bodies are not inspected. The
  human allows or denies.
- **The token stands for the key where the program puts it.** The program
  presents the token literally wherever it would present the key — in a
  request header, with any prefix (`Authorization: Bearer TOKEN`,
  `Authorization: Token TOKEN`, `x-api-key: TOKEN`,
  `x-goog-api-key: TOKEN`). Only the header values the broker forwards
  count. The broker replaces each exact occurrence of the grant's token in
  them with the key, in one pass, inside larger values too, without
  decoding the values, folding their case or scanning what it inserted,
  and changes nothing else. A request is refused (`401`, before admission,
  nothing forwarded) when no forwarded header value holds the token; when
  the method, a header name, the request target or a header the broker
  drops or rebuilds holds it (ASCII case ignored); when a token-shaped
  string other than this grant's token appears anywhere in the request
  head; when the key itself appears in it; or when the header block, once
  the key is in, exceeds phase 1's limit. A token-shaped string is `rh_`
  followed by 64 hexadecimal digits, prefix and digits recognised without
  regard to ASCII case, at any byte position, without word boundaries, in
  the method, the request target, the header names and every header
  value, duplicates included. Each one must equal this grant's token byte
  for byte; a case variant of it is refused, not replaced. No other
  grant's token is looked up for this check. A program that encodes the token
  or derives its credential from it, an API that signs its requests with
  the key, or takes the key in the URL or the body, cannot be used through
  the broker: `run` serves them. The value must still be 8 to 4096 visible
  ASCII characters, without spaces or controls.
- **Any request goes to the approved origin**, under phase 1's framing,
  admission and forwarding rules — HTTP/1.1; no `CONNECT`, `TRACE`,
  `OPTIONS`, upgrades or `Origin`; verified TLS against the system's
  certificate authorities; public addresses only; no redirect followed; no
  compressed response; no cookie jar — without its route check, and
  without its rule that only `POST` has a body: a body, within 16 MiB and
  with one unambiguous `Content-Length`, is allowed on any accepted method,
  under the existing room, timeout and admission rules. The origin-form
  path and query go as the program sent them. Request headers are
  forwarded except the hop-by-hop ones and `Host`, `Content-Length` and
  `Accept-Encoding`, which the broker sets. Response headers are relayed
  except the hop-by-hop ones, `Content-Length` and `Transfer-Encoding` —
  the broker frames the body itself, chunked where HTTP allows a body,
  since redaction changes its length — those a `Connection` header of the
  response names, and any header whose name or value
  carries the key or a token; literal copies of the key in a response body
  are redacted. A `101` response is refused with a local `502`, like a `3xx`;
  the HTTP library discards a destination's other `1xx` responses, and the
  final response is the one checked and relayed.
- **Audit**: an admitted request is recorded, before it is forwarded, with
  the grant ID, its number and its method's label — `GET`, `HEAD`, `POST`,
  `PUT`, `PATCH`, `DELETE`, or `OTHER` for any other method — and its end
  with the outcome, the status and the bytes each way. No raw method, path,
  query, header or body is recorded or sent to the agent.
- **Protocol**: the client protocol becomes 9. A run through the broker is
  a new request, `broker_run_v2`; it does not extend protocol 8's
  `broker_run`, which an agent of protocol 8 would accept while ignoring
  the destination and the limits. Each of its broker bindings needs a
  destination; unknown fields, invalid destinations and invalid limits are
  refused before the dialog. An agent of protocol 9 refuses `broker_run`
  and `broker_edit` before any approval, and a client never retries a
  refused request with an older type or as an ordinary `run`, so an agent
  of protocol 8 met after the client's version check, on the next
  connection, refuses the new request instead of running it. A refusal
  before the command starts exits 125; an answer lost after sending, 124.
  The entry's profile goes from `show` and `list`, and a grant has no
  preset. The control channel becomes 2, still checked strictly before a
  grant is served: the install carries the destination instead of a
  profile, and an admission carries the method's label, no route or path.
- **Listings and notes**: in `grants`, in the manager and in the note after
  a run whose destination answered `401`, the destination is the approved
  origin only, labelled as such; a base path, when there is one, is shown
  apart, as setup of the program's base URL and not a limit (in protocol 9,
  `GrantInfo.destination` and `UnauthorizedGrant.destination` hold the
  origin, and `GrantInfo` has an optional `base_path`, left out when
  empty).
- **The manager** offers two command templates for an entry, each labelled:
  one gives the value to the command (`run`), the other goes through the
  broker and leaves the destination, the token's variable and the base
  URL's variable for the user to fill in. Nothing is inferred from the
  entry's kind, its URL or a phase 1 profile, a template left unfilled is
  not a valid command, and no template is stored with the entry.
- **Kept from phase 1**: one broker process per grant; tokens and grant
  IDs; revocation, expiry and the locks; the request and in-flight limits;
  the audit; `grants` and the manager's grants page; the note after a run
  whose destination answered `401`; and no fallback to the key.

**Not planned:** operations narrowed for administration APIs; presets per
provider; destinations or policies stored with an entry; configuration of
how a key is presented; private devices with pinned TLS; the connectors of
phases 3 and 4 and of the "Later" row (`ssh-agent`, PostgreSQL, MySQL,
WebSocket, request signing, a Unix socket listener, grants for sandboxed
clients); profile editing in the manager. Ordinary `rusthorse run` serves
databases, devices, SSH and web logins, with its documented limits (threat
model L3–L5). These are outside the product's scope and are not on the
roadmap.

Superseded where they say otherwise: decisions 1 and 2 where they name a
profile, decisions 3, 5 and 7 (profiles and routes), decision 6's
`--broker VAR=ENTRY`, decision 8's per-profile policy, preset defaults and
device defaults, decision 9's "method and route", decision 10's table, answers
2 and 7, answer 3's "every route", answer 8's exact routes and answer 10's
"profile's policy", the context's notes on private devices and administration
APIs, the alternatives "Specific operations instead of a generic proxy" and
"Every lock ends every grant" where it says that the profile decides, the
consequences that name a profile or protocol 8, and the phase
1 specification's profiles, presets, route check, header lists, profile
types and snapshot, the profile's base path and `automatic_locks`, the route
in `admit`, the route template, `run --broker VAR=ENTRY`, protocol 8 with
`broker_run`, `edit --broker`, `broker_edit`, the manager's profile view, and
in its list of tests the rows and clauses about routes, profiles, protocol 7
and `broker_edit`.
