# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain incompatible changes; they are listed
under **Changed** and protocol changes always bump `PROTOCOL_VERSION`.

## [Unreleased]

### Added

- **Move an entry to another group**: `rusthorse edit NAME --group PATH`
  (`/` for the top level) and the **Group** field of the manager's **Edit**
  form, which used to be locked. The group is created if needed, and the
  agent's approval dialog shows the destination as a path from the top with
  the group's UUID, or what it creates (`/Work/Servers (existing group
  8d2f6c1e-…)`, `/ (the top level)`); a path through two
  groups of the same name is refused. The UUID stays the same, and the entry
  records the group it came from.
- **Change the value from the manager**: the **Secret** section has a row
  **Change the value…**, which opens the agent's dialog for the new value
  at once, and **Replace with a random value…** (before, **New random
  value** in the entry's toolbar). Typing a new value used to be hidden in
  **Edit**, behind a drop-down that kept the current value.
- **`rusthorse guide ai`** prints a guide for AI agents, built into the
  binary: the rules, how to find entries and use `run`, what each exit
  status means and what to do, and how to store secrets without seeing
  them. A test checks every command and option it names. The instructions
  for `CLAUDE.md` or `AGENTS.md` in the README and
  [ai-agents.md](docs/ai-agents.md) now point to it, and `rusthorse --help`
  ends with a pointer for AI agents.
- **Import from the manager** ([ADR 0012](docs/adr/0012-import-read-by-the-agent.md)):
  **Import & backup → From GNOME Keyring…** and **From a .env file…** list
  the items or names (after the agent asks you), mark each name new,
  existing, not allowed, repeated or locked, and import the ticked ones in
  batches.
- **Imports are read by the agent**: new requests `keyring_items`,
  `dotenv_names` and `import_from`. The client names keyring items or
  variables and the entry names; the agent reads the values, and its dialog
  says from where. `rusthorse import dotenv` and `import secret-service` use
  them, so they no longer hold values; listing the keyring or a file's names
  now asks for approval.
- **First start from the manager**
  ([ADR 0011](docs/adr/0011-first-start-from-the-manager.md)): with no
  vault, the window offers **Create vault…**; with no agent running, **Start
  agent**, which asks systemd to start the service (the manager never starts
  the agent itself). A new request, `create_vault`, makes the agent create
  the vault and ask for its master password in its own dialogs; the new vault
  is left unlocked.
- `rusthorse init` uses `create_vault` when the agent serves that vault, so
  the new master password never enters the `rusthorse` process; it creates
  the file itself only without such an agent.
- A **Debian package** ([ADR 0010](docs/adr/0010-debian-package.md)),
  built with `packaging/build-deb.sh` (cargo-deb) for Ubuntu 24.04, Linux
  Mint 22, Debian 13 or later: the three programs in `/usr/bin`, the agent's
  user service enabled for every user, the manager in the applications menu,
  shell completions and the documentation, and a copyright file with the
  license of every crate compiled in. `apt remove` stops the agents of
  logged-in users (and says which it could not stop) and removes everything
  but users' vaults and audit logs; upgrades do not restart running agents.
- The agent **locks the vault when the screen locks or the computer
  suspends** ([ADR 0009](docs/adr/0009-lock-on-screen-lock-and-suspend.md)):
  it watches logind — holding a delay inhibitor so that the lock happens
  before the computer sleeps — and the Cinnamon, GNOME, MATE and
  freedesktop screensavers over D-Bus. No signal ever unlocks. `status`,
  `doctor` and the manager's Status page say what is watched;
  `--no-lock-on-suspend` and `--no-lock-on-screen-lock` turn it off. Builds
  without the new default feature `session-lock` have no D-Bus watchers.
- Entry **kinds** ([ADR 0008](docs/adr/0008-entry-kinds.md)): `api-key`,
  `login`, `server` or `device`, set with `add --kind` and `edit --kind`
  (`--kind other` or `--clear kind` removes it), shown by `show`, filtered by
  `list --kind`, and stored in the KDBX field `Kind`. The kind names the
  fields — the URL of an API key is its endpoint — and decides which ones the
  manager's form offers, never hiding one that has a value ("Show all
  fields" shows every one). It grants nothing.
- `run --url VAR=ENTRY` also gives the command an entry's URL, such as an
  API's endpoint, in variable `VAR`. The URL is not a secret: it is not
  redacted. The manager's command for an API key with an endpoint includes
  it.
- The `run` dialog shows the destination settings of the environment: a
  **Destinations** row for the variables that name an endpoint
  (`OPENAI_BASE_URL`, `DATABASE_URL`, `DOCKER_HOST`, …), and a warning for
  proxies, certificate authorities, disabled certificate checks and name
  resolution — with which a requester could send a secret to a server of its
  own. URLs are shown by scheme, host and port only; a value that programs
  could read differently is not shown and is warned about; the audit record
  names the same variables.
- `rusthorse-manager`, first milestone ([ADR 0007](docs/adr/0007-visual-manager.md),
  [guide](docs/manager.md)): a GTK 4 and libadwaita window, client of the
  agent, to browse, search and filter entries by group; create, edit, rename
  and delete them; generate values; **Show** a value in a window that hides
  after 30 seconds or on focus loss; **Copy** a value to the clipboard (it
  stays there until something else is copied, and a clipboard history may
  keep it even after that — the window says so); copy the `rusthorse run`
  command for an entry; lock and unlock; back up; change the master password.
  Every change and every value still goes through the agent's approval.
  Awaiting independent review.
- `reveal` takes an optional `purpose` (`show` or `copy`): the approval
  dialog asks the matching question, labels it as stated by the requester,
  warns accordingly, and the audit record names it. Requests without it — the
  CLI's — are unchanged.
- `rusthorse-dialog`, Rusthorse's own dialog program (GTK 4 and libadwaita,
  [ADR 0006](docs/adr/0006-own-dialog-program.md)): approvals with the command
  in its own card and the details in two columns, content that scrolls while
  the buttons stay in view, **Allow** disabled until the end of a long request
  has been reached (with a hint saying so), and a password dialog with a
  labelled field. The agent
  uses it when it is installed next to `rusthorse`, zenity otherwise; it
  talks to it over one socket with a framed, versioned protocol under a
  deadline, and starts it with no per-user GTK configuration. `status` and
  `doctor` report it. It must not be writable by its group or by others: on
  systems whose umask is 002 (Debian, Ubuntu, Mint), run `chmod go-w` on it
  after `cargo install`.
- KeePass KDBX4 vault with username, URL, host, port, tags, notes and groups;
  Argon2id (64 MiB, 20 passes) for new vaults; atomic saves with a `.bak`
  copy; refusal to overwrite changes made by other programs.
- Agent (`rusthorse agent`) on a private Unix socket with peer-credential
  checks, master password and approval dialogs (zenity), idle auto-lock,
  remembered approvals keyed on the exact request, and a fail-closed audit
  log.
- `rusthorse run`: the agent resolves the program, removes `LD_*` variables,
  flags risky ones, starts the approved command as its own child connected to
  the caller's stdio and redacts secret values from its output.
- Commands: `init`, `agent`, `status`, `unlock`, `lock`, `list`, `show`, `add`,
  `edit`, `remove`, `reveal`, `run`, `import dotenv`, `import secret-service`,
  `audit`.
- systemd user unit, documentation (getting started, installation, CLI, AI
  agents, architecture, threat model, protocol, ADRs) and CI.
- `add --generate` / `edit --generate` (the agent creates a random value
  nobody sees), `generate`, `passwd`, `open` (an entry's URL in the
  browser), `list --search`, `doctor` and `completions`.
- Commands check that the agent speaks the same protocol version and explain
  how to restart it after an upgrade.
- `backup DEST` (verified copy), `reveal --notes`, `import --dry-run` and
  automatic import batches.
- Exit status 124 (outcome unknown) when a request with effects was sent but
  no usable answer came back, or the agent could not confirm it; `run` keeps
  125 for "did not run".

### Changed

- The manager's entry form shows how the value is made as one row per
  choice (keep it, type a new one, generate one), the first one chosen,
  instead of a drop-down.
- A message that cannot be written to standard error (`2>/dev/full`) no
  longer makes the CLI crash with status 101: the message is dropped and
  the exit status keeps its meaning (125: the run did not start).
- `.env` files are read in a small dialect that python-dotenv and Node's
  dotenv read alike (one-line values, in single or double quotes without
  backslashes, or unquoted with a ` #` comment; no `${…}`, no name set
  twice), and any other file is refused as a whole, naming the line;
  variables with an empty value are named, not skipped. Before, each line was read on its own and quotes were
  only stripped, so a value over several lines could be taken for more
  variables.

- The manager keeps showing what a change reported (for example a warning
  of `passwd`) after the status check that follows it; before, that check
  erased the message at once.
- Creating a vault never replaces a file that appeared meanwhile (another
  `init` or agent): the file is linked into place instead of renamed.
- The service file (`contrib/systemd/rusthorse-agent.service`) lets systemd
  create the socket's directory and remove it, with the socket, when the
  agent stops (`RuntimeDirectory=rusthorse`); before, a stopped agent left
  its socket file behind. Copy it again over an installed one.
- The installation guide puts the package first; uninstalling a source
  installation now also removes `rusthorse-dialog` and the `~/.local/bin`
  link, which the guide forgot.
- The crate's one-line description is shorter (it is also the package's).

- `rusthorse-dialog` draws no hyphen where it wraps a long word (a hyphen
  that is not in a command or a path could mislead), and the keys of detail
  rows no longer break inside words ("Dire-ctory").

- **Protocol 7** (versions 2 to 6 existed only during development): data
  frames and credits, new requests (among them `create_vault`), definite
  errors, `reveal.purpose`, the entry `kind` and `edit.group` (see Added);
  `already_exists` also means that the vault file exists. Upgrade the agent
  together with its clients and restart it: clients refuse an agent that
  speaks another version.
- `add --group` refuses a path into the recycle bin: an entry there is
  hidden from every listing, as if deleted.
- `passwd` reports when the old-password backup could not be deleted.
- `doctor` checks the files the agent actually uses, and notices an agent
  still running a build that an upgrade replaced; `status` shows the agent's
  program file.
- Imports report which batches were imported when a later one fails — or
  that a batch's outcome is unknown when its answer is lost — and imports
  with duplicate names are refused.
- New error code `outcome_unknown` (exit 124) when the agent cannot determine
  the result of a command it started, or a change was written but could not
  be synced to disk. Every other error means nothing was changed.
- Audit records are dated when they are written: an approval or denial
  carries the time the human answered, not the time the request arrived.
- A dialog nobody answered is reported and audited as `timed_out` ("nobody
  answered … in time"), no longer as a denial or cancellation by the human;
  exit statuses are unchanged.
- The unlock dialog starts with "Type the master password"; clicking Unlock
  with an empty field asks again instead of counting as a wrong password, and
  an unlock where nothing was typed is cancelled (exit 4), not failed. Every
  cancelled or unanswered `passwd` dialog is now audited.
- `backup` to a file that exists says so and asks for a new name, instead of
  "File exists (os error 17)".
- Approval dialogs are easier to read: a short headline and an explanation,
  one block per detail with the values in a monospaced font, context in one
  quieter line and warnings in bold. They follow the desktop's light or dark
  theme (no colours or icons of their own) and use only options that zenity 3
  and 4 share. Values are escaped before formatting, so they are shown
  literally. The password prompts are worded more clearly, and the requester
  chain is labelled "unverified".
- Dialogs draw only ordinary characters as themselves (ASCII, Latin letters,
  a little punctuation) and every other one as a `\u{…}` escape, so a value
  cannot hide, reorder or overlap text, nor pass letters of other scripts for
  Latin ones; requests whose dialog
  would be too tall to read at once are refused (an estimate in pixels for an
  11-point font), so a long or crafted value cannot push the rest of a dialog
  out of sight. `import` batches are sized to fit (24 lines of names).

### Security

Changes from the adversarial review of 2026-10-31 (details in
[docs/threat-model.md](docs/threat-model.md#11-review-history)):

- zenity's answer (master password, new values) is read through a socket pair
  instead of a pipe, which other processes could open via `/proc/<pid>/fd`.
- zenity runs from an absolute path with a minimal environment and `/` as its
  working directory; only exact expected results count as approval; text for
  the entry dialog escapes backslashes.
- With redaction, an approved command's stdin is an agent-owned pipe: a
  writable descriptor passed as stdin is no longer a way around redaction.
- Approvals are acted on only if the vault generation, the entries (by UUID)
  and the program's and directory's inodes are unchanged after the dialog.
- Remembered approvals are off by default (`--remember 0`), and when enabled
  are bound to the vault generation, entry UUIDs and the full environment.
- Details too long to show (command line, program, directory over 1000
  characters) are refused instead of truncated; imports are capped at 100
  entries, all listed.
- Fields that the KDBX file marks as protected are withheld from `list` and
  `show`; responses include entry UUIDs and `protected_fields`.
- Received file descriptors are never leaked; descriptors on requests other
  than `run` are rejected.
- Names cannot contain `/`; a title that matches another entry's path is
  ambiguous.
- Deletions are recorded in KDBX `DeletedObjects`.
- Saves re-check the file right before replacing it; a failed save locks the
  vault; vault files over 128 MiB are refused before decryption.
- Only approved uses postpone the idle lock.
- Request timeouts and limits on connections and pending dialogs.
- Audit records are `fsync`ed.

From the second review (of the code after those fixes):

- Approved changes are transactions, rolled back if any part fails.
- The vault generation is checked under the same lock that reads values; a
  lock during the password prompt cancels the unlock; unlocking is audited
  before it takes effect.
- The remembered-approval key covers the whole effective environment.
- Protected titles are hidden; dialogs and the audit log show
  `Group/Title (uuid)`; entries can be addressed by UUID.
- Descriptors are never leaked, even when the open-file limit truncates a
  message.
- `run` gives the command `/dev/null` as input unless `--stdin` is passed;
  forwarding never blocks and stops when the command ends.
- Background processes left in the command's process group are terminated
  when it exits.
- Whole-dialog length limit; a real deadline for receiving requests.

From the third review:

- Writes to the requester's output never block indefinitely and stop at once
  when it disconnects; slow readers still get all output.
- `/proc` is parsed as bytes: processes with non-UTF-8 names are terminated
  with their group.
- `SCM_RIGHTS` control buffers are aligned for `cmsghdr` on receive and
  send; `nix::sys::socket::sendmsg` is no longer used.
- The dialog limit counts the "Allow for" note; the unlock prompt is checked.

From the fourth review:

- With redaction, the agent no longer touches the requester's descriptors:
  output and input travel as data frames over the socket and `rusthorse run`
  relays them to its own stdio (protocol: data frames; descriptors only for
  `--no-redact`).
- `rusthorse run` exits with 141 and stops the command when its own output is
  closed.
- A process whose main thread exited while other threads run is terminated
  with its group.

From the fifth review:

- Per-channel flow control (credit frames, 1 MiB windows) and per-channel
  writer threads in the client: a stuck stdout no longer holds up stderr.
- Cancellation (close, half-close, protocol violation) shuts the socket down
  and terminates the command; half-closes are detected with `POLLRDHUP`.
- `Client::run_with` with explicit I/O for library users; its input reader
  stops when the call returns.

From the sixth review:

- Stdin has its own credit window; the agent reads the connection at all
  times, so large input plus large output no longer deadlocks.
- The client cancels through a lock-free handle, and returns `SIGPIPE` within
  about half a second even when its other destination is stuck.

[Unreleased]: https://github.com/Alle4you/rusthorse/commits/main
