# 0006. Rusthorse's own dialog program replaces zenity

- Status: Proposed
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

- dialogs are shown by the agent, never by the client;
- the answer cannot be read or forged by other processes (today: a socket
  pair, an absolute program path, a minimal environment, `/` as working
  directory);
- **Deny** is the default, an unanswered dialog is a denial, and only exact,
  expected answers approve;
- requester-controlled text cannot change how the dialog reads;
- the agent, which holds the decrypted vault, stays small;
- `rusthorse` itself builds without graphical libraries, and distribution
  stays native ([ADR 0004](0004-native-distribution.md));
- dialogs follow the desktop's theme on any distribution.

## Decision

1. **A separate program, `rusthorse-dialog`**, written in Rust with GTK 4 and
   libadwaita, lives in this repository as a Cargo workspace member and is
   installed next to `rusthorse`. As with zenity, the agent starts one process
   per dialog.
2. **It is started the way zenity is**: from the directory of the agent's own
   executable (never through `PATH`), with `/` as working directory and an
   allow-listed environment — the display, Wayland and D-Bus session variables
   (the last for the light or dark preference), the XDG directories GTK needs
   for themes and icons, and the locale. Variables that load code into GTK
   (`GTK_MODULES`, `GIO_EXTRA_MODULES`, `GTK_IM_MODULE`, `LD_*`) are not
   passed.
3. **The request goes in on standard input as JSON**: the kind of dialog
   (approval, master password, secret value), title, headline, explanation,
   warnings, command, details, facts, the "Allow for" label and the timeout.
   The agent passes every requester-controlled string through
   `ui::dialog_text` first, so the allow-list of drawable characters still
   applies. The program shows every string as **plain text** — no markup — so
   nothing a requester sends can add formatting.
4. **The answer comes back through the socket pair**, as today. An approval
   dialog answers exactly `allow-once`, `allow-for` or `deny`; a password or
   value dialog answers the typed text. Exit statuses distinguish an answer,
   a cancellation or denial, and a timeout. Anything else — a crash, an
   unknown status, unexpected output — is a denial, as in
   `ui::decision_from`.
5. **Layout.** A header bar names Rusthorse and the dialog's purpose. Below:
   the headline, the explanation, warnings in a card with a warning icon, the
   command in a monospaced card, the details in a two-column card (label |
   value, values wrapping in their column), the facts, the "Allow for" note.
   The buttons sit in a bar that never scrolls: **Deny** on the left — the
   default for Enter, and what Escape and closing the window mean — and
   **Allow for N**, **Allow once** on the right. The content scrolls; **when it
   does not fit, the Allow buttons stay disabled until its end has been
   scrolled into view**, so nobody approves what they could not see. The
   master password dialog has a labelled password field (show/hide, Enter
   submits) and says plainly that it asks for the master password.
6. **Height and length.** With the program, the height estimate no longer
   limits requests: the content scrolls and approval waits for it to be seen.
   The character limits (`MAX_DIALOG_CHARS`, `MAX_DETAIL_CHARS`) stay.
7. **Fallback.** If `rusthorse-dialog` is not installed, the agent uses zenity
   with today's layout, allow-list and height limit. If it is installed but
   fails, that dialog is a denial: a crash never switches to the other
   program. `rusthorse doctor` reports which program the agent uses.
8. **Minimum versions**: GTK 4.12 and libadwaita 1.4 (Ubuntu 24.04 and Linux
   Mint 22, Fedora 39, Debian 13 and later). Older systems use zenity.
9. **Code structure.** The `Ui` trait stays; a new implementation drives
   `rusthorse-dialog`, and `ZenityUi` remains. GTK is a dependency of the
   dialog program only.

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
  the desktop's theme; Qt is a large C++ dependency that looks foreign on
  GTK desktops; yad is another external program with zenity's limits for
  questions.

## Consequences

- **Readability**: real columns, scrolling with fixed buttons, a distinct
  password dialog — shown to the owner as a prototype, light and dark.
- **Security**: the process model of ADR 0003 is kept (separate process,
  socket pair, absolute path, minimal environment, default Deny, exact
  answers). Two things improve: the text is plain, so markup injection
  disappears, and approval waits until the whole request has been shown.
  The program's answer format is ours, so there is no equivalent of the
  `ZENITY_*` variables that remap zenity's exit statuses. Unchanged: on X11
  any program of the same user can still click a dialog (threat model L2).
  Replacing `rusthorse-dialog` takes write access to the directory of the
  agent's executable, as replacing `rusthorse` itself does.
- **Build and packaging**: building the dialog program needs the GTK 4 and
  libadwaita development packages; CI installs them; `rusthorse` still
  builds without them. Packages ship both programs. The dialog program may
  need a newer Rust than `rusthorse`'s MSRV if its bindings do; the MSRV of
  `rusthorse` does not change.
- **Testing**: two dialog paths. The program's request parsing and decision
  logic are tested without a display; end-to-end tests use a fake dialog
  program; the zenity path keeps its tests. The look is checked by hand, in
  light and dark themes.
- **Follow-up**: the same program can later show the grants panel and the
  credential broker's approvals ([roadmap](../roadmap.md)).
