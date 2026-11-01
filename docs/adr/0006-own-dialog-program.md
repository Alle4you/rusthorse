# 0006. Rusthorse's own dialog program replaces zenity

- Status: Accepted
- Date: 2026-11-01

## Context

[ADR 0003](0003-agent-side-dialogs.md) made the agent show every prompt as a
`zenity` dialog and anticipated a GTK front end. The first real test, with the
owner at the desk, showed the limits of zenity:

- **The approval dialog is one text label.** Pango markup gives it a headline,
  bold and monospaced text, but no columns, no indentation for wrapped lines
  and no scrolling. The owner found it hard to read even after the layout was
  reworked.
- **The buttons sit below all the content**, so a long request can push them —
  or the part of the command that matters — off the screen. Keeping that from
  happening took an allow-list of drawable characters and a height estimate
  ([architecture](../architecture.md#dialogs)), which depends on the font,
  the scale and the screen, and refuses requests that would not fit.
- **The password dialog looks like any other dialog**: the owner took it for
  an approval and clicked Unlock three times with nothing typed (threat model,
  finding R3). zenity's forms dialog, which has a labelled field, does not
  submit on Enter.

What must not change:

- dialogs are shown by the agent, never by the client (except `init` without
  a terminal, which runs before any agent exists);
- the channel between the agent and the dialog cannot be opened by other
  processes through `/proc/<pid>/fd` (today: a socket pair), the program is
  started from an absolute path, with a minimal environment and `/` as
  working directory;
- **Deny** is the default, an unanswered dialog is a denial, and only exact,
  expected answers approve;
- requester-controlled text cannot change how the dialog reads;
- the agent, which holds the decrypted vault, stays small;
- `rusthorse` itself builds without graphical libraries, and distribution
  stays native ([ADR 0004](0004-native-distribution.md)).

## Decision

### 1. A separate program

`rusthorse-dialog`, written in Rust with GTK 4 and libadwaita, lives in this
repository as a Cargo workspace member and is installed next to `rusthorse`.
As with zenity, the agent starts one process per dialog. GTK is a dependency
of this program only; the `Ui` trait stays, a new implementation drives the
program, and `ZenityUi` remains.

### 2. Finding and starting it

- The agent resolves its own executable through `/proc/self/exe` and looks
  for `rusthorse-dialog` in the same directory, never through `PATH`. If its
  own executable was replaced or deleted since it started (the check `status`
  already makes), it refuses to show dialogs and asks for a restart.
- The program must be a regular file (after resolving symbolic links),
  executable, owned by the user or by root and not writable by group or
  others. Otherwise the dialog is refused with an explanation.
- Working directory `/`; standard error discarded; one socket (below) as both
  standard input and standard output.

### 3. One socket for the request and the answer

- The agent creates a socket pair and gives one end to the program as its
  standard input and output; no pipe is used in either direction, so neither
  the request nor the answer can be read or injected through `/proc/<pid>/fd`.
- Both directions carry one frame each: a 4-byte big-endian length and a
  UTF-8 JSON object. The request is at most 64 KiB; the answer at most 8 KiB.
- The request carries the protocol version, a random request identifier, the
  kind of dialog (approval, master password, secret value), the title,
  headline, explanation, warnings, command, details, facts, whether "Allow
  for N" is offered and its label, and the timeout. The agent passes every
  requester-controlled string through `ui::dialog_text` first.
- The answer carries the protocol version, the same identifier and either a
  decision (`allow-once`, `allow-for`, `deny`) or, for password and value
  dialogs, the typed text (at most 4 KiB) or `cancel`. `timed-out` reports a
  timeout.
- **An approval requires all of**: one well-formed answer frame with the
  expected version and identifier, a decision that was offered (`allow-for`
  only when "Allow for" was), end of stream after the frame, and exit status
  0 — all within the deadline. Anything else is a denial: a crash, a partial
  or oversized frame, extra bytes, an unknown field value, a status that does
  not match, a valid answer followed by a failure.

### 4. The agent supervises the program

The agent does not rely on the program's own timeout: one monotonic deadline
(the dialog timeout plus a few seconds) covers writing the request, reading
the answer and the program's exit. When it passes, the agent kills and reaps
the program and records `timed_out`. The dialog lock is released in every
case. The same supervision applies to zenity.

### 5. Environment and configuration

The program receives only these variables, taken from the agent's own
environment (the desktop session's, through systemd), never from a request:
`DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR` (the real one:
Wayland and the session's services live there), `DBUS_SESSION_BUS_ADDRESS`,
`LANG`, `LC_*` and `LANGUAGE`. The agent adds:

- `XAUTHORITY`, when it is not set and `DISPLAY` is: the X authority file is
  resolved **before** `HOME` is replaced (`$HOME/.Xauthority` of the real
  home), so an X11 session that keeps it in the default place still reaches
  the display;
- `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` and `XDG_CACHE_HOME` pointing to
  a private directory, and `XDG_DATA_DIRS=/usr/local/share:/usr/share`, so the
  program reads no per-user GTK configuration, style sheet, theme or icon: a
  file such as `~/.config/gtk-4.0/gtk.css`, which any program of the user can
  write, could otherwise hide or restyle text in the dialog. The agent
  creates a new, empty directory for every dialog (mode `0700`, writable by
  the program, for GTK's caches) and removes it once the program has been
  reaped, also after errors, so nothing one dialog writes reaches the next.
  This keeps the user's files out of the dialog; it is not isolation from
  malware running as the same user;
- `GSETTINGS_BACKEND=memory`, so per-user settings — including the one that
  enables the GTK Inspector's keyboard shortcut — keep their defaults.

Nothing that loads code into GTK is passed (`GTK_MODULES`,
`GIO_EXTRA_MODULES`, `GTK_IM_MODULE`, `GTK_DEBUG`, `GDK_*`, `LD_*`). The light
or dark preference still arrives through the desktop portal on D-Bus when the
desktop provides one; otherwise libadwaita's default applies.
Accessibility stays enabled, so screen readers work; its consequence is
below.

### 6. Layout and the approval gate

- A header bar names Rusthorse and the dialog's purpose. Below: the headline,
  the explanation, warnings in a card with the theme's standard warning icon,
  the command in a monospaced card, the details in a two-column card (label |
  value), the facts, the "Allow for" note.
- All text is **plain text** — no markup — selectable, and wraps within the
  available width, long words included: one vertical scroll for the whole
  content, no scrolling inside the command card, no ellipsis, nothing reachable
  only by scrolling sideways. The content never changes after the window is
  shown.
- The buttons sit in a bar that never scrolls: **Deny** on the left, and
  **Allow for N** (when offered) and **Allow once** on the right. Deny has the
  initial focus and is the default for Enter; Escape and closing the window
  mean Deny. Nothing is approved by the window appearing.
- **Approval waits until the end of the content has been reached.** After the
  first layout — and again whenever the size changes — the program checks
  whether the content fits; if it does not, the Allow buttons stay disabled
  until the scroll position has reached the end once. This is an obligation
  to reach the end, not proof that everything was read: a reader can jump to
  the end. Every way to approve — mouse, keyboard, accessibility actions —
  goes through the same check.
- The master password dialog states that it asks for the master password; it
  has a labelled password field with show/hide, which has the initial focus;
  Enter in the field submits. The value dialog is the same with its own
  wording.

### 7. Fallback to zenity

zenity is used only when `rusthorse-dialog` **does not exist** at the expected
path (not even as a broken link). Every other problem — permission denied, an
invalid or incompatible program, missing libraries, a crash — makes that
dialog a denial with an explanation; a failure never switches to zenity. When
zenity is used, today's layout, allow-list and height limit apply.

A program of the user that deletes `rusthorse-dialog` makes the agent fall
back to zenity; one that can do that can also replace `rusthorse` itself,
which the threat model already treats as out of scope.

### 8. Compatibility and diagnosis

- The request and answer carry a private protocol version. The program
  refuses a request of a version it does not speak, before showing anything,
  and the agent reports that the program must be updated or the agent
  restarted.
- `rusthorse-dialog --check` prints its version and protocol version and
  exits without opening a window.
- `status` reports the dialog program the agent will use (path, or zenity);
  `rusthorse doctor` checks it — file, ownership and mode, `--check`, protocol
  compatibility — without opening a window.

### 9. Versions, build and CI

- Minimum versions: GTK 4.12 and libadwaita 1.4 (`AdwToolbarView` appeared in
  1.4). Ubuntu 24.04 and Linux Mint 22 ship GTK 4.14 and libadwaita 1.5; the
  bindings (`gtk4`, `libadwaita` crates) are pinned with the `v4_12` and
  `v1_4` features. Distributions with older libraries do not get the program
  and use zenity.
- `cargo install --locked --path .` keeps installing `rusthorse` only; the
  program is installed with `cargo install --locked --path dialog`, and the
  installation guide and packages cover both.
- CI keeps checking `rusthorse` without graphical libraries at its MSRV
  (1.89), and builds and tests the program in a separate job with the GTK 4
  and libadwaita development packages. The program may need a newer Rust
  than 1.89 if its bindings do; `rusthorse`'s MSRV does not change.

## Alternatives considered

- **Keep zenity and refine the markup.** Done over four review rounds; it
  reached what a single label can do (no columns, no scrolling) and needs a
  height estimate that depends on fonts and screens.
- **zenity's list dialog** (a real two-column table). Each cell is one line,
  so a long command is cut or needs horizontal scrolling — the human could
  approve without seeing all of it.
- **zenity's HTML text view** (WebKit). A browser engine to show a security
  prompt, and not available in every build of zenity.
- **GTK inside the agent.** One process fewer, but it would load GTK, input
  method, GIO and accessibility modules into the process that holds the
  decrypted vault, need a display and a main loop when the agent starts
  (often before the desktop has exported its variables), and let a crash in
  the interface take the agent down.
- **Other toolkits.** egui and iced draw their own widgets and do not follow
  the desktop's light or dark preference as GTK does; Qt is a large C++
  dependency that looks foreign on GTK desktops; yad is another external
  program with zenity's limits for questions.

## Consequences

- **Readability**: real columns, scrolling with fixed buttons, a distinct
  password dialog — shown to the owner as a prototype, light and dark. The
  look is libadwaita's: it follows the desktop's light or dark preference
  when the desktop portal provides it (libadwaita's default otherwise), not
  every GTK theme, and uses only the theme's standard icons.
- **Security, kept**: the process model of ADR 0003 (separate process,
  absolute path, minimal environment, default Deny, exact answers), now with
  a socket in both directions, a request identifier, a size-limited framed
  protocol and supervision by the agent.
- **Security, improved**: plain text, so no markup injection; per-user GTK
  configuration is ignored; approval waits until the end of the request has
  been reached; the answer format is ours, with no equivalent of the
  `ZENITY_*` variables that remap zenity's exit statuses.
- **Security, unchanged and now documented**: a program of the same user can
  still activate a dialog's buttons — on X11 by synthesizing input (threat
  model L2), and on X11 or Wayland through the accessibility API, which
  zenity's GTK 3 dialogs expose as well. Disabling accessibility would close
  that path only for users who need no screen reader; it may become an
  option. GTK does not let the program erase the typed password from its
  buffers, as zenity did not; the program never logs it, sends it once and
  exits.
- **Build and packaging**: building the dialog program needs the GTK 4 and
  libadwaita development packages; `rusthorse` still builds without them.
- **Testing**: the agent's side is tested with fake dialog programs that
  hang, answer partially or too much, answer with another version or
  identifier, or answer and then fail; the environment it builds is tested
  with and without `XAUTHORITY`, and the private directory's removal after
  every outcome. The program's request parsing and
  decision logic are tested without a display; its widgets — focus, the
  approval gate, resizing, scaling, long strings, accessibility — are tested
  on an isolated virtual display, never on the maintainer's screen. The look
  is checked by hand, in light and dark themes.
- **Follow-up**: the same program can later show the grants panel and the
  credential broker's approvals ([roadmap](../roadmap.md)).
