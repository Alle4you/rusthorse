# Security policy

Rusthorse holds secrets, so security reports are taken seriously and handled
privately first.

## Supported versions

Rusthorse is in early development. Only the latest release (and the `main`
branch) receive security fixes.

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/Alle4you/rusthorse/security/advisories/new)
("Report a vulnerability" on the Security tab).

Include, as far as you can:

- the version or commit, distribution and desktop (X11 or Wayland);
- what an attacker needs (same user? a malicious AI agent? local access?);
- steps to reproduce, ideally with a test vault and fake secrets;
- the impact: which secret or decision is exposed or bypassed.

Never include real secrets or real vault files.

You can expect an acknowledgement within 7 days and an assessment within 14.
Fixes are released as soon as they are ready, with a security advisory that
credits the reporter unless they prefer otherwise.

## Scope

In scope: anything that lets a client obtain a secret value, master password
or notes without a corresponding approval; approve something different from
what the dialog showed; bypass redaction through the protocol; read or modify
the vault without unlocking it; or avoid the audit log.

Known limitations are documented in the [threat model](docs/threat-model.md)
— for example, malware running as the same user replacing the binary, or
synthetic input on X11. Reports that only restate a documented limitation are
welcome as documentation feedback but are not treated as vulnerabilities,
unless they show the limitation is worse than documented.
