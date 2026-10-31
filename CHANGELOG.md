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

[Unreleased]: https://github.com/Alle4you/rusthorse/commits/main
