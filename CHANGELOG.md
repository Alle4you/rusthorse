# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain incompatible changes; they are listed
under **Changed** and protocol changes always bump `PROTOCOL_VERSION`.

## [Unreleased]

- Propose ADR 0007 for a visual manager that remains an agent client; preserve
  the approved reference prototype and Abrigo app icon.

### Added

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

- Protocol version 3 (data frames and credits, new requests, definite
  errors); clients refuse an agent that speaks another version.
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
