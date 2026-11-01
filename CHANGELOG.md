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

[Unreleased]: https://github.com/Alle4you/rusthorse/commits/main
