# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain incompatible changes; they are listed
under **Changed** and protocol changes always bump `PROTOCOL_VERSION`.

## [Unreleased]

### Added

- **HTTP credential broker**
  ([ADR 0013](docs/adr/0013-credential-broker.md)):
  `run --broker VAR=ENTRY@URL --url URLVAR=ENTRY` gives the approved command
  a temporary token instead of the key, and a local base URL. The run names
  where the key may go — `https://`, a host name, an optional port and base
  path; there is no default and no fallback to the entry's URL — and the
  dialog shows the approved origin, the base path apart from it (not a
  limit: the key may go to any path at the origin) and the grant's limits.
  The program presents the token in a request header, as it would the key;
  one broker per grant puts the key in its place and forwards the request to
  the approved origin only, over verified TLS, streams server-sent events,
  redacts literal copies of the key in response bodies, drops response
  headers carrying it or a token and those the response's `Connection` names,
  refuses a request with the token misplaced, another
  token or the key itself, and records each admission durably before
  forwarding, with the method's label, never the path. The broker knows
  nothing about any API: there are no profiles, presets or routes (phase
  1's, set with `edit --broker`, were removed before any release; a
  `Rusthorse.Broker` field it stored stays in the entry as an ordinary
  field, never read). `--broker-requests`, `--broker-lifetime` and
  `--broker-locks` set the run's limits (no request limit, 12 hours and
  `continue` unless given); the explicit lock and command end always end
  grants. No automatic fallback to the real key; no remembered broker
  approvals.
- **Grants**: `grants [--json]`, with the approved origin and the base path
  in columns of their own, and `grants revoke ID|--all`. `status` reports
  the broker and live grant count; `doctor` checks the broker and the CA
  file; `audit` shows grant and request records. `rusthorse guide ai`
  includes SDK recipes and a Claude Code recipe. The broker was tried by hand
  on 2026-11-04 with `curl`, the Anthropic Python SDK 2.4.0 and Claude Code
  2.1.318 (print mode and interactively); no client version is claimed
  supported.
- **A key the destination refused is named**: when a grant's approved origin
  answers `401 Unauthorized`, `rusthorse run` says so after the command
  (`rusthorse: note:`, naming the entry and `rusthorse edit NAME --value`),
  its exit status unchanged; `grants` (a note under the table, and
  `unauthorized` in `--json`) and the manager's Grants page show the count
  while the command runs. Status only, never the body: the same for every
  destination. The JSON errors the broker writes itself now start their
  message with `rusthorse-broker:`, and that of a grant that has ended says
  to run the command again.
- **Manager broker controls**: a Grants page lists the grants, each with its
  approved origin and its base path apart, and revokes one or all, also
  while locked. Ended rows retain their place while the page is shown.
  Entry details offer two labelled command templates: one gives the value
  to the command (`run`), the other goes through the broker and leaves the
  destination and the variables for you to fill in. Edit and import notes
  explain grant revocation.
- **Agent settings** ([ADR 0007](docs/adr/0007-visual-manager.md#3-persistent-agent-configuration-m2)):
  the idle timeout, remembered approvals, the dialog timeout and locking on
  suspend and on screen lock can be kept in `~/.config/rusthorse/agent.toml`
  (`--config` or `RUSTHORSE_AGENT_CONFIG` name another file), read when the
  agent starts; the flags win over it, and `status` shows each setting and
  where it comes from. The manager's **Settings** page changes them through
  the new `configure` request: only while the vault is unlocked, after the
  agent shows each old and new value in its own dialog — warning when a
  change protects less — and then the agent saves the file, applies the
  change at once and forgets remembered approvals. A setting a flag fixes
  cannot be changed that way. The `toml` crate is now a dependency of
  `rusthorse`, to read the file.
- **History in the manager** ([ADR 0007](docs/adr/0007-visual-manager.md#4-remembered-approvals-and-history-m2)):
  the **History** page shows the agent's audit log, newest first, 200
  records at a time (**Load older** reads the ones before them), with a
  filter: allowed, denied or not answered, unlock and lock, credential
  broker. It reads the file the agent's status names, as `rusthorse audit`
  does — complete lines only, at most 256 KiB a page — and says when the
  file was rotated or truncated under it, and when a line longer than a page
  stops the reading. Shown only while the vault is unlocked and
  forgotten when it locks: the log names entries and the commands that used
  them. Everything a record says is drawn as plain text through the
  dialogs' character filter. No protocol change.
- **Broker distribution**: the package installs `/usr/bin/rusthorse-broker` as
  its fourth program and recommends `ca-certificates`. The build script checks
  both the built broker and every broker in the packages it produces, and
  refuses test builds and the options that would install the package before
  that check, build it for another target or package another manifest
  (`--manifest-path`). cargo-deb writes the packages into a private staging
  directory; only if every one passes are they moved to the output directory
  (`--output DIR`, which the script takes itself; `target/debian` by
  default), replacing a file or a link already at their names there without
  following it or writing through it. A refused package never reaches it:
  the staging directory is deleted instead. The package's copyright file
  covers all four programs, including ring's nested license texts and source
  notices. Default Cargo commands now cover the main package and the broker;
  `cargo run` still runs `rusthorse`.
- **Move an entry to another group**: `rusthorse edit NAME --group PATH`
  (`/` for the top level) and the **Group** of the manager's **Edit** form,
  which used to be locked. In the manager's forms the group is chosen from a
  list (No group, the groups in use and the groups above them, **New
  group…** to type a path), with a warning for a new path that differs from
  an existing group only in case; a new entry starts in the group the list
  is filtered on. The group is created if needed, and the
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
  binary: the rules, how to find entries and use `run` (SSH included, with
  `sshpass` or a key in a temporary `ssh-agent` that the recipe ends with the
  command; both refuse a host whose key ssh does not know, and a probe shows
  whether a host answers without offering it any key; it says that
  `has_password` does not tell an SSH password from a private key, and to
  ask the human when an entry's metadata does not say which recipe to use),
  what each exit status
  means and what to do, and how to store secrets without seeing them. A test
  checks that the CLI accepts every `rusthorse` command line it shows (not the
  other programs of its recipes, such as `ssh`). The instructions
  for `CLAUDE.md` or `AGENTS.md` in the README and
  [ai-agents.md](docs/ai-agents.md) now point to it, and `rusthorse --help`
  ends with a pointer for AI agents.
- **Import from the manager** ([ADR 0012](docs/adr/0012-import-read-by-the-agent.md)):
  **Import & backup → From GNOME Keyring…** and **From a .env file…** list
  the items or names (after the agent asks you), mark each name new,
  existing, not allowed, repeated or locked, and import the ticked ones in
  batches.
- **Choose where a backup goes**: the manager's **Create verified backup…**
  form has **Choose…**, which opens a file dialog to pick the folder and the
  file name (it offers `rusthorse-YYYY-MM-DD.kdbx`), instead of only a field
  for an absolute path, which can still be typed. An existing file is still
  never replaced.
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
- A **Debian package** ([ADR 0010](docs/adr/0010-debian-package.md)), built
  with `packaging/build-deb.sh` (cargo-deb) for Ubuntu 24.04, Linux Mint 22,
  Debian 13 or later: the four programs in `/usr/bin`, the agent's user
  service enabled for every user, the manager in the applications menu, shell
  completions and the documentation, and a copyright file with the license of
  every crate compiled in. `apt remove` stops the agents of logged-in users
  (and says which it could not stop) and removes everything but users' vaults
  and audit logs; upgrades do not restart running agents.
- The agent **locks the vault when the screen locks or the computer suspends**
  ([ADR 0009](docs/adr/0009-lock-on-screen-lock-and-suspend.md)): it watches
  logind — holding a delay inhibitor to allow locking before sleep, subject to
  the signal and disk delays in threat model L20 — and the Cinnamon, GNOME,
  MATE and freedesktop screensavers over D-Bus. No signal ever unlocks.
  `status`, `doctor` and the manager's Status page say what is watched;
  `--no-lock-on-suspend` and `--no-lock-on-screen-lock` turn it off. Builds
  without the new default feature `session-lock` have no D-Bus watchers.
- Entry **kinds** ([ADR 0008](docs/adr/0008-entry-kinds.md)): `api-key`,
  `login`, `server`, `device` or `ssh-key` (an entry whose value is a private
  key for SSH: the guide for AI agents names the recipe for it), set with
  `add --kind` and `edit --kind`
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

- **Restoring a backup is done by hand, by decision.** A backup is the
  vault file as it was, encrypted with the master password it had then, so
  restoring it is putting that file in the vault's place. The installation
  guide gives the steps for another computer (put the backup where the vault
  goes, `chmod 600`, unlock; no `init`) and for the same one (`rusthorse
  lock`, keep the file as it is, put the backup in its place, unlock), with
  the agent running, and when `vault.kdbx.bak` can undo the last save. The
  restore through the agent that ADR 0007 planned will not be built; the
  manager's Import & backup page now says how to restore instead of
  announcing it.
- **Protocol 11**: the entry kind `ssh-key`. Clients and agents of protocol
  10 refuse each other at the version check.
- **Protocol 10**: `configure` and `status.settings` (the agent's settings).
  Clients and agents of protocol 9 refuse each other at the version check.
- **The agent's duration options have bounds**: `--idle-timeout` `0` or 1s
  to 24h, `--remember` `0` or 1s to 8h, `--dialog-timeout` 15s to 5m. A value
  outside them, or a settings file the agent cannot accept, stops its start
  instead of being used.
- **Protocol 9** (protocol 8, with broker profiles, existed only during
  development): a run through the broker is a request of its own,
  `broker_run_v2`, whose bindings each name their destination and whose
  `limits` set the grants' limits, with unknown fields refused, so that an
  older agent refuses it whole instead of ignoring them; a refused request
  is never sent again as another type. A binding by value refuses unknown
  fields too, in a plain `run` as well, before any dialog. Added `grants`,
  `revoke_grant`, optional broker status fields, `GrantInfo.unauthorized` and
  `exited.unauthorized`; `GrantInfo.destination` is the approved origin, and
  `GrantInfo.base_path` the base path apart. The control channel between
  the agent and a broker is at version 2.
- An edit's answer names the entry (`NAME updated`) even when the request
  names it by its UUID, as the manager does: the manager showed the UUID.
- The CLI shows what the vault, the agent or a keyring supplies with control
  and invisible characters escaped everywhere it shows text to people
  (`list`, `show`, `status`, `doctor`, `open`, import previews, messages
  and errors), so that a title another program wrote cannot rewrite the
  terminal; `--json` and `reveal` are unchanged.
- Human-readable `audit` output escapes control and invisible characters
  throughout each record. JSON output remains machine-readable.
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

### Fixed

- The audit log's name is synced, not only its data: before each record,
  and so before its action goes ahead, the agent checks that the directory
  that holds the log holds the file the record goes into, then syncs it, and
  syncs the parent of each directory it makes for the log. Before, a
  crash right after the first records of a new log could keep their approved
  effects and lose the log's name, records and all. A sync or a check that
  fails fails the record, and the action is refused, as when the log cannot
  be written; on a file system whose directories cannot be synced, or with a
  log directory the agent cannot read, the vault now stays locked. Each
  directory is opened as a directory only: a FIFO that a program put in
  place of one fails the record at once, instead of making the agent wait
  for a writer with the log held.
- Creating a vault and saving the agent's settings sync the directory that
  holds each directory they make, before the file goes into it, as the
  audit log does. Before, only the file's own directory was synced, so a
  crash right after `init` or a first save of the settings could lose the
  new file with the name of a directory made for it. A sync that fails
  fails the creation or the save, which writes nothing: a directory in
  which a new vault's or the settings' directory can be made, but which
  cannot be read, now refuses them.
- Saving the vault or the agent's settings, and making a backup, no longer
  wait on a FIFO that a program put in place of a directory or of the vault
  file: the directory each syncs is opened as a directory only, a backup
  checks and reads the vault file through one descriptor, and opening a
  vault file — to unlock it, or a backup's copy to verify it — does not wait
  and reads only a regular file. Before, such a FIFO made the agent wait for
  a writer with its state held, and so held off every lock (idle, `rusthorse
  lock`, suspend, screen lock) with the vault unlocked. A FIFO in place of
  a directory now fails the sync at once, as any other failure of that sync
  would; a vault path that is not a regular file is refused (until now a
  directory there failed later, when read).
- A FIFO put in place of the audit log fails each record at once, with
  nothing written to it. Before, opening it made the record wait for a
  reader, with every other record behind it, and so every approval-gated
  request and unlock, until a program read it. The log file is opened
  without waiting and written to only if it is a regular file; as when the
  log cannot be written, the action is refused.
- A request whose requester goes away — `rusthorse` interrupted or killed,
  the manager's window closed, an AI agent's tool call stopped — while a
  dialog for it is open is cancelled, as the protocol had said: the dialog
  is taken down, a request still waiting for its dialog never gets one, and
  the agent checks again right before the effect, after the waits on the
  way to it but the grant registry's own short lock (also for a `backup`,
  which asks nothing itself). What it asked for is not done, the audit log
  records `requester_gone` (or `aborted`, when the dialog had been answered)
  and the request gets no answer. A half-close
  cancels a `run` this way too, not the other requests. Before, the dialog
  stayed, and what the human then allowed was done: a `run`'s command
  started with the secrets (and its broker grants were served) before the
  agent noticed and stopped it, and an `edit`, a `remove` or an `add` was
  carried out with nobody to read the answer.
- A vault that KeePassXC saved as KDBX 4.0 (as it does when nothing in the
  file needs 4.1) can be saved again: Rusthorse writes it back as KDBX 4.1,
  the version it writes. Before, every change to it failed with an
  unexplained error. A vault in a newer KDBX 4 is read but not written, and
  the message says why.

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
