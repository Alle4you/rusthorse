# Architecture decision records

An architecture decision record (ADR) captures one significant decision: the
context, the decision, the alternatives that were considered and the
consequences. ADRs are not rewritten when a decision changes; a new ADR
supersedes the old one, which is marked as such.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-kdbx4-storage.md) | KeePass KDBX4 as the storage format | Accepted |
| [0002](0002-agent-mediated-execution.md) | The agent, not the client, runs approved commands | Accepted |
| [0003](0003-agent-side-dialogs.md) | Approvals are dialogs shown by the agent | Accepted |
| [0004](0004-native-distribution.md) | Native binary and systemd user service, no Flatpak | Accepted |
| [0005](0005-remembered-approvals-opt-in.md) | Remembered approvals are opt-in and bound to the vault generation | Accepted |
| [0006](0006-own-dialog-program.md) | Rusthorse's own dialog program replaces zenity | Accepted |
| [0007](0007-visual-manager.md) | A visual manager that remains a client of the agent | Proposed |
| [0008](0008-entry-kinds.md) | Entry kinds, and an API key's endpoint for `run` | Proposed |
| [0009](0009-lock-on-screen-lock-and-suspend.md) | The agent locks when the screen locks or the computer suspends | Proposed |
| [0010](0010-debian-package.md) | A Debian package that installs and removes cleanly | Proposed |

## Writing a new ADR

Copy the template below to `NNNN-short-title.md` with the next number, fill it
in, and add it to the table in the same pull request as the change it
describes.

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by [NNNN](NNNN-….md)
- Date: YYYY-MM-DD

## Context

What problem are we solving? What constraints and forces apply?

## Decision

What we decided, stated plainly.

## Alternatives considered

Each serious alternative and why it was not chosen.

## Consequences

What becomes easier or harder, including security consequences and
follow-up work.
```
