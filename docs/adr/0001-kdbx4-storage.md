# 0001. KeePass KDBX4 as the storage format

- Status: Accepted
- Date: 2026-10-31

## Context

Rusthorse needs an encrypted file for passwords, API keys and access details
(username, URL, host, port, notes, tags). Two requirements shape the choice:

- **Portability.** The owner must be able to take the vault elsewhere — another
  machine, another operating system, a phone — and open it without Rusthorse.
- **Trustworthy cryptography.** Inventing a file format means inventing (and
  maintaining) the cryptography around it.

## Decision

Store the vault as a standard KeePass **KDBX 4** file, read and written with
the [`keepass`](https://crates.io/crates/keepass) crate. Rusthorse-specific
data uses ordinary KDBX features: `Host` and `Port` are custom string fields,
tags and groups are native, the value is the protected `Password` field and
notes are stored protected. New vaults use Argon2id (64 MiB, 20 passes).

## Alternatives considered

- **The desktop keyring (Secret Service / GNOME Keyring).** Integrated and
  unlocked at login, but any process of the user can read every item once the
  keyring is unlocked, items have no structure beyond flat string attributes
  (which the specification says are not secret), and exporting is awkward.
- **A custom format (e.g. age- or libsodium-encrypted JSON).** Simple and
  flexible, but no other application could open it, and the format, KDF
  choices and migration story would be ours to get right.
- **`pass` (GPG-encrypted files in git).** Portable and scriptable, but it
  depends on a GPG setup, leaks entry names as file names and has no standard
  structure for URL, host or port.

## Consequences

- The vault opens in KeePassXC, KeePassDX, Strongbox and other clients;
  backups and sync are just file copies.
- Rusthorse inherits KDBX's limits and the `keepass` crate's coverage: key
  files and challenge-response keys are not supported yet, and KDBX3 files can
  be read but not saved (see [installation.md](../installation.md)).
- Other programs may change the file. The agent detects this before saving
  and refuses to overwrite (`vault_changed`) rather than merging.
- Correctness of encryption and parsing depends on the `keepass` crate, which
  becomes a security-critical dependency to track.
