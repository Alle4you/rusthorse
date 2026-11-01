# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain incompatible changes; they are listed
under **Changed** and protocol changes always bump `PROTOCOL_VERSION`.

## [Unreleased]

### Added

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
- systemd user unit, documentation (installation, CLI, AI agents,
  architecture, threat model, protocol, ADRs) and CI.

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

[Unreleased]: https://github.com/Alle4you/rusthorse/commits/main
