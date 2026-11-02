# Rusthorse @VERSION@: guide for AI agents

Rusthorse keeps this computer's secrets (API keys, passwords, tokens) in an
encrypted KeePass vault. You never see a value. You find entries by their
metadata and run commands through `rusthorse run`. The human approves each
use in a dialog on their screen, and the command gets the secret in its
environment.

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
rusthorse list --kind api-key     # kinds: api-key, login, server, device, other
rusthorse list --search github    # name, group, username, URL, host or tags contain it
rusthorse list --tag ai
rusthorse list --json             # the same as a JSON array
rusthorse show NAME --json        # one entry's metadata
```

The JSON objects have `name`, `group`, `kind`, `username`, `url`, `host`,
`port`, `tags`, `has_password` and `id`. The `id` is a UUID, which also works
as `NAME`. Fields without a value are left out. A field named in
`protected_fields` is withheld like a secret.

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
- Each run asks once. Put all the work that needs the secret into one
  command. Before you run it, tell the human in one line what it does and
  which secret it uses, so they recognise the dialog.
- The dialog shows the command line, the program, the directory, the
  secrets, and the variables that name where the program connects
  (`*_URL`, `*_HOST`, …). It warns about proxies, certificate settings and
  variables that make a program run other code (`NODE_OPTIONS`,
  `PYTHONPATH`, …). Set such variables only when the task needs them, and
  say why.
- Output is redacted. Every occurrence of a secret value (4 characters or
  longer) in the command's standard output and error becomes
  `[REDACTED:NAME]`. Do not add `--no-redact` unless the human asks for it.
- The command reads nothing (`/dev/null`) unless you add `--stdin`, and it
  sees pipes, not a terminal. A program that prompts for a password on the
  terminal cannot get one there. Use its way of taking it from the
  environment instead: `sshpass -e` reads `SSHPASS`, and ssh can use
  `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`.
- The command runs as the human, outside any sandbox you are in, in your
  current directory. Processes it leaves in the background are stopped when
  it exits, so do not use `rusthorse run` to start a server that should keep
  running.
- A command line, program path or directory longer than 1000 characters is
  refused. Put a long command in a script, and tell the human that the dialog
  approves what the script contains at that moment.

## Exit statuses

| Status | Meaning | What to do |
|---|---|---|
| `125` | `run` only: Rusthorse refused or failed before the command started (denied, timed out, the agent is not running or is out of date, the entry is missing). The command did not run. | Read the `rusthorse:` message on standard error. If it was denied or timed out, stop and ask the human. |
| `124` | The outcome is unknown. The command may or may not have run, and a change may or may not have been saved. | Check (`rusthorse list`, `rusthorse audit -n 5`) before you repeat anything that is not idempotent. |
| `4` | Every other command: the human denied or cancelled the request, or the dialog timed out. | Stop and ask the human. |
| `1` | Every other command: an error (the agent is not running, the entry was not found, the input is invalid, …). | Read the message. |
| `2` | Invalid command line. | Check `--help`. |
| other | `run` only: the command's own status (`128 + N` if signal `N` killed it). | |

A command can also exit with `124` or `125` itself. A `rusthorse:` message on
standard error tells the two apart.

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
