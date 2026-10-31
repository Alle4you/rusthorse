# 0003. Approvals are dialogs shown by the agent

- Status: Accepted
- Date: 2026-10-31

## Context

Every use of a secret needs a human decision, and the master password must
reach the agent. The requester may be an automated program that controls a
terminal (an AI agent's shell tool), so any prompt it can see or answer is
worthless as a control.

## Decision

The agent shows all prompts itself, as desktop dialogs (`zenity`), and the
client never handles the master password:

- Approval dialogs list the command, resolved program, directory, secrets,
  redaction setting, requester process chain and warnings. All requester-
  supplied text is rendered with control characters, line breaks and Unicode
  bidirectional/zero-width characters escaped, so a request cannot forge
  extra lines or reorder what the human reads. The default button is
  **Deny**, and an unanswered dialog is denied after a timeout.
- The master password and new secret values are typed into the agent's own
  hidden-input dialogs.
- One dialog is shown at a time.

The `Ui` trait abstracts the dialogs so that tests (and future front ends,
such as a GTK application) can provide their own implementation.

## Alternatives considered

- **Terminal prompts in the CLI.** The requester controls the terminal (or
  has none), so it could answer or never show them.
- **Desktop notifications with action buttons.** Easy to miss, easy to click
  by accident, and their content is truncated.
- **A dedicated GTK application from day one.** Better presentation, but much
  more code before the core was proven. It remains on the roadmap.

## Consequences

- Rusthorse needs a graphical session and `zenity`; headless use (SSH
  sessions, servers) is not supported yet.
- On X11, any program of the same user can synthesize input or read the
  screen, so a malicious local process could click a dialog. Wayland
  isolates clients; the threat model documents the difference.
- Dialog text is limited to what zenity can display: very long command lines
  are truncated and such requests can never be remembered.
