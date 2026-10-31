# 0004. Native binary and systemd user service, no Flatpak

- Status: Accepted
- Date: 2026-10-31

## Context

Rusthorse has to start commands in the user's real environment (their `PATH`,
virtualenvs, project directories, `/tmp`), connect them to the caller's
terminal descriptors and show dialogs on the desktop. It also has to start at
login, outside any terminal an AI agent controls.

## Decision

Ship a single native binary (built with `cargo install`, later also as
`.deb` and static release binaries) and run the agent as a **systemd user
service**. The service file sets no sandboxing options, because they would
also apply to approved commands.

## Alternatives considered

- **Flatpak.** The sandbox would hide the user's programs and files from the
  agent, so `run` could not start the commands it exists to start without
  escaping the sandbox (`flatpak-spawn --host`), which defeats the purpose.
  It would also add a runtime download for a small CLI.
- **Snap.** Same problems as Flatpak, plus confinement rules that do not fit
  a tool that runs arbitrary user commands.
- **XDG autostart instead of systemd.** Works on most desktops, but gives no
  restart on failure, no journal integration and no clean way to change
  options. It remains a fallback for systems without systemd user services.

## Consequences

- Installation is `cargo install` plus copying one unit file; no root needed.
- systemd hardening directives (`PrivateTmp=`, `NoNewPrivileges=`,
  `ProtectHome=`, …) are deliberately absent; the agent hardens its own
  process instead (non-dumpable, no core dumps).
- The agent depends on the session exporting `DISPLAY`/`WAYLAND_DISPLAY` to
  systemd; it falls back to `systemctl --user show-environment` and the
  installation guide explains the fix when dialogs do not appear.
