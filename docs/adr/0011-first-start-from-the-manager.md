# 0011. The first start happens in the manager; the agent creates the vault

- Status: Accepted
- Accepted: 2026-11-09, when the maintainer asked that the ADRs' statuses be
  brought in step with what is built and reviewed
- Implementation: implemented, unreleased; reviewed ready on 2026-11-02 (the
  eighth review of that day in the
  [review history](../threat-model.md#11-review-history)).
- Date: 2026-11-02
- Amends: [ADR 0007](0007-visual-manager.md) ("The manager does not
  install, start or restart anything"; the vault must exist).
- Amended: 2026-11-02, after review — how `init` decides that the agent
  serves the vault, a vault open in memory whose file is gone, the exit
  statuses of `init` without an agent, a deadline for Start agent.

## Context

With the Debian package ([ADR 0010](0010-debian-package.md)) a person
installs Rusthorse with a double click and then opens **Rusthorse** from the
applications menu. Until now the manager could do nothing on a first start:
the agent might not be running yet (it starts at the next login), and the
vault had to be created first with `rusthorse init` in a terminal. A first
start should not need a terminal.

`init` created the vault in the CLI process, which asked for the master
password itself — in the terminal, or in its own dialogs without one. That
was the one exception to "secret-entry dialogs are shown by the agent"
(AGENTS.md, invariant 4), and when an AI agent ran `init`, the master
password entered a process the AI started and, as its parent, could
inspect.

## Decision

1. **A `create_vault` request** (protocol 6). The agent creates the vault
   file at its own vault path, which must not exist, after asking the human
   for the master password twice in its own dialogs; the password never
   passes through a client. The attempt is recorded in the audit log before
   the file is written. The new vault is left unlocked, as after an unlock —
   unless a lock happened while the dialogs were open, in which case it is
   created locked. One creation runs at a time; a second request finds the
   vault and gets `already_exists` without a dialog.
2. **A new vault never replaces a file.** The file is put in place with a
   hard link, which fails if the name exists, instead of a rename, which
   would replace a vault that another `init` or agent created meanwhile.
3. **`rusthorse init` uses the agent when one serves that vault**, and keeps
   creating the file itself only when no agent runs (nothing listens on its
   socket) or one serves another path. The paths are compared after making
   them absolute and resolving the links of their existing directories (the
   agent reports an absolute path); an agent that cannot be asked stops
   `init` rather than letting it read the password. The exception of
   invariant 4 is narrowed to that case. Without an agent, a cancelled or
   unanswered dialog exits 4 and a file written but not synced exits 124,
   as for requests to the agent.
4. **Never beside an open vault.** While a vault is unlocked whose file is
   gone (moved or deleted), `create_vault` is refused: creating one would
   leave the old vault open in memory beside an empty new one.
5. **The manager's first start.** When `status` says the vault does not
   exist, the window shows what Rusthorse will create, and where, with a
   **Create vault…** button (also in the sidebar) that sends `create_vault`.
   When nothing listens on the agent's socket, it says so and offers
   **Start agent**, which runs `systemctl --user start
   rusthorse-agent.service`: systemd starts the agent, outside the
   manager's process tree, exactly as at login. The manager never starts
   the agent's program itself, and never restarts it. If `systemctl` fails —
   a source installation without the service file — the window shows its
   message and points to the installation guide; one that has not finished
   after 30 seconds is stopped.

## Alternatives considered

- **The manager asks for the master password and sends it.** Rejected: the
  manager would then hold a master password (invariant 1), and every other
  password dialog is the agent's.
- **The manager runs `rusthorse init`.** The CLI would show its own dialog,
  as a child of the manager: the same exception, in one more process.
- **The manager starts `rusthorse agent` directly.** The agent would be a
  child of the manager, inside the process tree that the threat model keeps
  it out of ("Who starts the agent"), and would stop with it.
- **Socket activation** (a `rusthorse-agent.socket` unit). It would start
  the agent on the first connection without a button, but the agent must
  also run before anything connects — it locks the vault on screen lock and
  suspend — and it needs code to take over the listening socket. A possible
  later addition.

## Consequences

- From the package to an open vault takes no terminal: install, open
  Rusthorse, Start agent (only before the next login), Create vault….
- Any program of the session that can reach the agent can make it show the
  "create a vault" dialog while no vault exists; the human can cancel it,
  and nothing is created unless they type a password twice. That is the
  same exposure as the unlock dialog.
- The protocol changes to version 6: an upgraded CLI or manager refuses an
  agent that still runs the old program, and says to restart it.
