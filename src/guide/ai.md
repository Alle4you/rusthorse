# Rusthorse @VERSION@: guide for AI agents

Rusthorse keeps this computer's secrets (API keys, passwords, tokens) in an
encrypted KeePass vault. You never see a value. You find entries by their
metadata and run commands through `rusthorse run`. The human approves each
use in a dialog on their screen, and the command gets the secret in its
environment, or, through the broker, a temporary token that works only
through Rusthorse.

The secret in an entry is its value. Its URL, username, host, port and
tags are context, for you to understand what it is for; its notes and any
protected field are withheld like the value, and you do not ask for them.
The
human sees in the dialog the command you will run with a credential and,
through the broker, where the key goes, and decides: make the command do
exactly what you say.

This guide is built into the `rusthorse` that printed it, so it matches that
version. Each command also has `--help`, for example `rusthorse run --help`.

## Rules

- Never ask the human for a secret value. Never print, echo or log a value,
  and never write one to a file, a commit, code or a test.
- Never use `rusthorse reveal`. It is for humans; use `rusthorse run`.
- Do not transform a secret (encode, split, hash, reverse it) or send it
  anywhere the task does not need. Redaction catches only the value as it
  is. The human approves what the command line appears to do, so make it do
  just that.
- Never read the vault file, another process's environment
  (`/proc/<pid>/environ`) or the agent's memory. Never answer or automate the
  dialogs (with xdotool, screenshots or accessibility tools). They belong to
  the human.
- If a request is denied or times out, stop and ask the human. Do not retry
  a variation of it.
- Do not start, stop, restart or reconfigure the agent (`rusthorse agent`,
  `systemctl --user … rusthorse-agent`), and do not change the master
  password. Ask the human instead.
- You never need `rusthorse unlock`. When a request needs the vault and it is
  locked, the agent asks the human for the master password, so the request
  may take a moment.
- `rusthorse generate` prints a random value, which you would then see. To
  create a credential, use `rusthorse add NAME --generate` instead.

## Finding entries

None of these commands shows a value, and none needs approval:

```sh
rusthorse list                    # name, username, endpoint (URL or host:port), tags
rusthorse list --kind api-key     # kinds: api-key, login, server, device, ssh-key, other
rusthorse list --search github    # name, group, username, URL, host or tags contain it
rusthorse list --tag ai
rusthorse list --json             # the same as a JSON array
rusthorse show NAME --json        # one entry's metadata
```

The JSON objects have `name`, `group`, `kind`, `username`, `url`, `host`,
`port`, `tags`, `has_password`, `has_notes`, `other_fields` (names only),
`modified` and `id`. The `id` is a UUID, which also
works as `NAME`. Fields without a value are left out. A field named in
`protected_fields` is withheld like a secret.

The text output (`list` and `show` without `--json`) shows control and
invisible characters in what the vault holds as `\u{…}` escapes, so that a
name another program wrote cannot rewrite the terminal. `--json` gives the
exact values: read a name from it before you pass it back to Rusthorse.

Use the metadata before you ask the human anything. An entry often already
has the address, port and username you need (a router's IP address, an SSH
user). For an API key, `url` is the API's endpoint.

## Using a secret: `rusthorse run`

```sh
rusthorse run NAME -- COMMAND [ARG]...         # variable NAME holds entry NAME's value
rusthorse run VAR=NAME -- COMMAND [ARG]...     # variable VAR holds entry NAME's value
rusthorse run A=ONE B=TWO -- COMMAND [ARG]...  # several secrets in one dialog
rusthorse run OPENAI_API_KEY --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
```

`--url VAR=NAME` also passes entry `NAME`'s URL in variable `VAR`. The URL is
not a secret and is not redacted.

- Your own shell expands `$VAR` before `rusthorse` starts, while the
  variable is not set yet: `rusthorse run TOKEN=x -- curl -H "Bearer $TOKEN" …`
  sends an empty token. When an argument needs the secret, run a shell
  inside `rusthorse run` and keep its program in single quotes:

  ```sh
  rusthorse run TOKEN=cloudflare -- sh -c 'curl -sH "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'
  ```

- Prefer programs that read the credential from their environment
  (`GH_TOKEN`, `PGPASSWORD`, `OPENAI_API_KEY`). Other processes can see
  command-line arguments.
- Each run asks the human once, so put all the work that needs the secret
  into one command. (A locked vault asks for the master password first. If
  the human turned on remembered approvals, an identical run may not ask at
  all.) Before you run it, tell the human in one line what it does and which
  secret it uses, so they recognise the dialog.
- The dialog shows the command line, the program, the directory, the
  secrets, and the variables that name where the program connects
  (`*_URL`, `*_HOST`, …). It warns about proxies, certificate settings and
  variables that make a program run other code (`NODE_OPTIONS`,
  `PYTHONPATH`, …). Set such variables only when the task needs them, and
  say why.
- Output is redacted. Every occurrence of a secret value (4 bytes or
  longer) in the command's standard output and error becomes
  `[REDACTED:NAME]`. Do not add `--no-redact` unless the human asks for it.
- With redaction (the default), the command reads nothing (`/dev/null`)
  unless you add `--stdin`, and it sees pipes, not a terminal. (With
  `--no-redact` it gets your standard input, output and error as they are.)
  A program that prompts for a password on the terminal cannot get one
  there. Use its way of taking it from the environment instead:
  `sshpass -e` reads `SSHPASS`, and ssh can use `SSH_ASKPASS` with
  `SSH_ASKPASS_REQUIRE=force`.
- The command runs as the human, outside any sandbox you are in, in your
  current directory. When it exits, the processes it left in its process
  group are stopped, but a program that detaches itself (a daemon, `setsid`)
  keeps running with the secret. Do not start servers or daemons with
  `rusthorse run`.
- A command line, program path or directory longer than 1000 characters is
  refused. Put a long command in a script and show it to the human. The
  dialog shows the script's name, not its contents: the approval trusts the
  script, and every file the command reads, as they are when the command
  reads them. Do not change them while a request is waiting or running.

### SSH

An entry's value may be a password or a private key: `has_password` is true
for both. The kind `ssh-key` says that an entry's value is a private key:
use the key recipe below for it (`rusthorse list --kind ssh-key` finds such
entries). The kind is a label that a person sets, and an entry of another
kind, or of none, may hold a key too: if its name or tags do not tell you,
ask the human before you choose a recipe. The password recipe gives the
entry's value to `sshpass` as the password to type.

ssh reads no password from the environment: `sshpass -e` passes it the one
in `SSHPASS`. Take the username, the host and the port (`-p PORT`, when it is
not 22) from `rusthorse show NAME --json`.

```sh
rusthorse run SSHPASS=NAME -- sshpass -e ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=yes USER@HOST 'uptime'
```

- `StrictHostKeyChecking=yes` makes ssh refuse a host whose key it does not
  know, whatever the ssh configuration says: the connection fails instead of
  trusting a key that nobody checked. Check first with `ssh-keygen -F HOST`
  (`ssh-keygen -F '[HOST]:PORT'` when the port is not 22). If the host is
  unknown, ask the human to connect once and check its fingerprint. Never turn
  host key checking off, and never use `accept-new`.
- To see whether a host answers, without a secret, offer it nothing:

  ```sh
  ssh -F /dev/null -o BatchMode=yes -o PreferredAuthentications=none -o IdentityAgent=none -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -p PORT USER@HOST true
  ```

  It reads no ssh configuration and offers no key and no password;
  `BatchMode=yes` alone would still try the human's own keys, and could log
  in with them. A `Permission denied` means that the host answers; a
  `Host key verification failed`, that it answers with a key ssh does not
  know. A host reached only through the human's ssh configuration (an
  alias, a jump host) cannot be probed this way. Do not wait for a banner
  on a bare TCP connection: some SSH servers speak only after the client.
- If `sshpass` is not installed, tell the human; do not install it.
- If the password is refused, stop and tell the human: a device's web and
  SSH passwords may differ, and repeated failures can lock the account.
- An interactive session is the human's to start, with `--no-redact`.

With a private key stored as an entry's value, a temporary ssh-agent holds
it while the command runs. The key must have no passphrase: `ssh-add` would
ask for it, and this recipe does not supply one. Tell the human instead,
and never put a passphrase in a command line or a file.

```sh
rusthorse run SSH_KEY=NAME -- ssh-agent sh -c 'trap "ssh-agent -k >/dev/null" EXIT; trap "exit 143" HUP INT TERM; printf "%s\n" "$SSH_KEY" | ssh-add -q - && ssh -o StrictHostKeyChecking=yes USER@HOST uptime'
```

The first `trap` ends the agent when the shell exits, with the command's
status or `ssh-add`'s; the second makes the shell exit, and so end the
agent, when `run` stops the command. The agent is in a session of its own,
which `run` does not stop: if the shell is killed before it can do that
(`SIGKILL`), the agent keeps the key until it notices that the shell is
gone, and then ends: within about ten seconds with OpenSSH 9.6.

## Using an API key through the broker: `run --broker`

For an HTTPS API that takes its key in a request header, prefer `--broker`
to giving the command the value: the command gets a temporary token instead
of the key, you name where the key may go, the human approves that in the
dialog, and the grant ends with the command.

```sh
rusthorse run --broker OPENAI_API_KEY@https://api.openai.com/v1 --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py
env -u ANTHROPIC_AUTH_TOKEN rusthorse run --broker ANTHROPIC_API_KEY=anthropic@https://api.anthropic.com --url ANTHROPIC_BASE_URL=anthropic -- python app.py
rusthorse run PGPASSWORD=app-db --broker OPENAI_API_KEY@https://api.openai.com/v1 --url OPENAI_BASE_URL=OPENAI_API_KEY -- python app.py   # one by value, one through the broker
rusthorse run --broker DEEPSEEK_API_KEY=deepseek@https://api.deepseek.com --broker-requests 50 --broker-lifetime 60 --url DEEPSEEK_BASE_URL=deepseek -- python app.py
```

- `--broker VAR=NAME@URL` puts the token in `VAR`, never the key, and
  `--broker NAME@URL` puts it in a variable named like the entry. The
  variable ends at the first `=` and the URL starts after the last `@`, so
  a name may hold either. The URL is `https://`, a host name, an optional
  port and an optional base path, with no user, query or fragment: the
  API the program calls. Nothing fills it in for you, not even the entry's
  `url`: say it, and the human checks it in the dialog.
- `--url` for the same entry, named the same way, puts the broker's
  address in its variable (`http://127.0.0.1:PORT` and the URL's base path)
  instead of the entry's URL. Always give it, for the variable the program
  reads its base URL from: without it, the program sends the token to the
  API's own address, where it does not work.
- The human approves the URL's origin: scheme, host and port. The broker
  may send the key to any path there; the base path only sets up the
  program's base URL, and limits nothing.
- The program presents the token where it would present the key, in a
  request header, as it is: `Authorization: Bearer TOKEN`,
  `x-api-key: TOKEN`, `x-goog-api-key: TOKEN` or any other. The broker puts
  the key in its place and sends the request to the approved origin. It
  refuses with its own `401`, before anything is sent, a request with no
  header holding the token, with the token anywhere else (the URL, a
  header's name, `Host`), with any other token or a token whose case was
  changed, or with the key itself. A program that signs its requests with
  the key, encodes or derives from the token, or sends the key in the URL
  or the body cannot use the broker: tell the human, who decides whether
  to give it the value with `run`.
- `--broker-requests N` (no limit unless given),
  `--broker-lifetime MINUTES` (720, 12 hours, unless given) and
  `--broker-locks end` or `continue` (`continue` unless given: the grants go
  on through a screen lock, a suspend and the idle lock) set the limits of
  every grant of the run, each counted on its own. Explicit
  `rusthorse lock` ends all grants.
- The grant ends when the command ends, or before: for example on
  `rusthorse lock`, when the human revokes it, when the entry changes or when
  its lifetime is over. Requests after that fail.
- The token is a secret too. Do not print, log or store it, and send it only
  to the broker's address. Output is redacted as with `run`, the token
  included. With `--no-redact` it is not, and whoever reads the token can use
  the grant until it ends.
- The dialog shows each grant's entry, the approved origin and the base path
  apart from it, when it ends and how many requests it admits. A request
  limit is not a spending limit, and the broker does not inspect request
  bodies: at that origin, the command can still spend credit and send what
  it wants.
- With zenity, two or more grants in one run may make the approval too tall,
  so the agent refuses it. `rusthorse-dialog` scrolls; character limits still
  apply. Never work around a refusal by passing the real key.
- There is no fallback. When a grant cannot be served (no broker program, an
  invalid URL, a value the broker cannot send), `rusthorse run` exits with
  `125` and nothing ran. Never retry with the key by value: tell the human.
- After the command, a note that starts with `rusthorse: note:` and says
  that the approved origin answered `401 Unauthorized` means that it did not
  accept the key stored in the entry; the broker accepted the command's
  token. Tell the human: replacing the key is theirs to do, in a dialog
  where they type it (`rusthorse edit NAME --value`). Never ask for the key,
  and never try another entry or the key by value.
- The broker's own errors have the type `rusthorse_broker` and a message
  that starts with `rusthorse-broker:` (a missing or wrong token: `401`; a
  grant that has ended: `403`). An error in the destination's own form comes
  from the destination. The broker's HTTP parser can answer a malformed
  request with an empty `400` or `431`; a destination can answer so too, so
  such an answer alone does not say who answered.
- Every retry of an SDK is a new request: it counts against the grant's
  limit, and a retried POST may be acted on twice. Turn the retries off in
  code you write (`max_retries=0` in Python, `maxRetries: 0` in TypeScript).
- A key that your own environment holds in another variable the program
  reads reaches the command like the rest of your environment: leave it out
  of the run with `env -u NAME` before `rusthorse run`. For an Anthropic
  SDK given the token in `ANTHROPIC_API_KEY`, that is
  `ANTHROPIC_AUTH_TOKEN`: an SDK that finds both variables may send both.
  The broker puts the entry's key in place of the token and forwards any
  other key as it is, so the destination may take the other one; without
  the token in any header, the broker refuses the request.
- `rusthorse grants` lists the grants, each with its state, never a token:
  their ID, entry, approved origin, base path, command, requester, requests
  and when they end. A revoked grant can stay in the list until its command
  ends. Under the table, a note names each grant whose approved origin
  answered `401`, as after a run. `rusthorse grants revoke ID` ends one.

### Claude Code through the broker

This recipe follows what Claude Code's documentation says. Tried on 2026-11-04
with Claude Code 2.1.318: run in print mode (`claude -p`) with a home
directory of its own, and so no login, it answered through the broker in one
request, and the maintainer then used it interactively with the recipe below.
No version is claimed supported. An account once answered `400` ("credit
balance is too low") to every request tried that carried Claude Code's beta
`claude-code-20250219`, with the key by value as through the broker, while
other requests with the same key worked. If Claude Code shows
`Credit balance is too low`, tell the human that the account refused the
request, not the broker. If it does not work, tell the human: never fall
back to the key, and do not try another key or other betas on your own.

```sh
env -u ANTHROPIC_API_KEY CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 rusthorse run --no-redact \
  --broker ANTHROPIC_AUTH_TOKEN=anthropic@https://api.anthropic.com --url ANTHROPIC_BASE_URL=anthropic -- claude
```

- `ANTHROPIC_AUTH_TOKEN` makes Claude Code send the token as
  `Authorization: Bearer`, and `ANTHROPIC_BASE_URL` sends its requests to the
  broker. `env -u ANTHROPIC_API_KEY` keeps a key your environment may hold
  out of the command: Claude Code may send it instead of the token, which
  the broker refuses, or beside it, which the broker forwards as it is, so
  that the destination may take that key instead of the entry's.
- `--no-redact` gives Claude Code the terminal; with redaction it would get
  pipes. The dialog warns that its output is not filtered.
- `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` turns off its non-essential
  requests, some of which would go straight to `api.anthropic.com` instead
  of through the broker. A variable set before `rusthorse run` reaches the
  command, like the rest of your environment.
- Check Claude Code's settings files first: `~/.claude/settings.json`, and
  `.claude/settings.json` and `.claude/settings.local.json` in the project.
  An `env` block there overrides the variables `rusthorse run` sets, so it
  must not set `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_API_KEY`, a proxy (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`) or
  `NO_PROXY`, and there must be no `apiKeyHelper`. Any of these can make
  Claude Code use another key, or send the token past the broker.
- Claude Code retries failed requests by itself; each retry counts as a
  request of the grant.
- Once the grant has ended (revoked, locked, expired), Claude Code shows
  `Please run /login · API Error: 403` and the broker's message. Its
  `/login` does not apply: the human starts it again with `rusthorse run`.

## Exit statuses

### `rusthorse run`

Once the command has started, `rusthorse run` exits with the command's own
status, whatever it is: `0` for success, `128 + N` if signal `N` killed it,
and any other number the command chooses, `1`, `2`, `4`, `124` and `125`
included. Rusthorse's own statuses are the four below. When standard error
can be written, `125` and `124` come with a message that starts with
`rusthorse:`, and `2` with `error:` and the usage; `141` comes with no
message. A note that starts with `rusthorse: note:` comes only after a
command that ran, whatever its status, which is then the command's own.
(A crash of `rusthorse` itself, status `101` with a `panicked` message,
tells as little as `124`.)

| Status | Meaning | What to do |
|---|---|---|
| `125` | Rusthorse refused or failed before the command started (denied, timed out, the agent is not running or is out of date, the entry is missing, with `--broker` a grant that cannot be served). The command did not run. | Read the message. If it was denied or timed out, stop and ask the human. |
| `124` | The outcome is unknown: the command may or may not have run. | Check whether its effects happened before you repeat anything that is not idempotent. `rusthorse audit -n 5` can help, but an approval there does not prove that the command ran, and a missing record of its end does not prove that it did not. |
| `2` | Invalid command line, with `error:` and the usage. Nothing was asked and nothing ran. | Check `rusthorse run --help`. |
| `141` | With redaction, Rusthorse could not write the command's output: whatever read it stopped early (such as `head`), or the disk is full. It asks the agent to stop the command and returns at once, so the command may go on for a few seconds, and it may have done some or all of its work. A command killed by `SIGPIPE` exits with `141` too. | Do not take it for the command's result. Wait a few seconds, check its effects before you repeat it, and let `rusthorse run` write its whole output (to a file, if it is long). |

### Other commands

| Status | Meaning | What to do |
|---|---|---|
| `0` | Success. | |
| `1` | An error: the agent is not running, the entry or grant was not found, the input is invalid, … | Read the message. |
| `2` | Invalid command line. | Check the command's `--help`. |
| `4` | The human denied or cancelled the request, or the dialog timed out. | Stop and ask the human. |
| `124` | The outcome is unknown: a change may or may not have been saved. | Check with `rusthorse list` or `rusthorse show NAME` before you repeat it. |

## Storing secrets

The human types each value in a dialog, or the agent generates it. You never
see it.

```sh
rusthorse add OPENAI_API_KEY --kind api-key --url https://api.openai.com/v1 --tag ai
rusthorse add core-router --kind device --username admin --host 10.0.0.1 --url https://10.0.0.1/
rusthorse add app-db --kind server --host db.lan --port 5432 --username app --generate
rusthorse edit core-router --host 10.0.0.2 --port 2222   # metadata (needs approval)
rusthorse edit core-router --value                       # the human types a new value
rusthorse edit app-db --generate                         # rotate: a new random value
rusthorse import dotenv .env                             # the agent reads the file
```

- Name an API key after the variable its programs read (`OPENAI_API_KEY`).
  Then `rusthorse run OPENAI_API_KEY -- …` works without `VAR=`.
- Never pipe a value into `rusthorse add --stdin` or `rusthorse edit --stdin`,
  and never put one in `--notes` or any other argument. A value you could
  pass there is one you have already seen. Tell the human and let them store
  it.
- Do not open a `.env` file to move its secrets. `rusthorse import dotenv
  FILE --dry-run` lists its names after the human approves, and
  `rusthorse import dotenv FILE` imports them. The agent reads the file
  itself.
- `rusthorse add NAME --generate --length 48 --alphabet symbols` sets the
  length (8–1024, default 32) and the characters (`alnum`, the default;
  `symbols`; `hex`).

## When something is wrong

```sh
rusthorse status    # is the agent running? is the vault locked?
rusthorse doctor    # checks the installation from your shell and explains each problem
```

- If the agent is not running, ask the human to start it: open Rusthorse from
  the applications menu, or `systemctl --user start rusthorse-agent`.
- If the agent is out of date after an upgrade, ask the human to restart it.

The full documentation is in `/usr/share/doc/rusthorse/` (the Debian package)
and at https://github.com/Alle4you/rusthorse/tree/main/docs. The file
`docs/ai-agents.md` explains what the human checks in each dialog.
