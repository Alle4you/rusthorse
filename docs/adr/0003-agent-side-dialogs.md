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
- Dialog text is limited to what zenity can display. Requests whose details
  are too long to show in full are refused rather than truncated.
- zenity is a separate, ordinary process: its standard output could be opened
  by other processes of the same user through `/proc/<pid>/fd` if it were a
  pipe, so the agent reads the answer through a socket pair (which cannot be
  opened that way), runs zenity from an absolute path with a minimal
  environment (zenity lets `ZENITY_*` variables remap its exit statuses) and
  `/` as working directory, and escapes text for the entry dialog, which
  interprets backslash sequences. An in-process GUI would remove this class of
  problems and is on the roadmap.
