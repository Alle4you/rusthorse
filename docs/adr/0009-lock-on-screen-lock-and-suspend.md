# 0009. The agent locks when the screen locks or the computer suspends

- Status: Proposed
- Date: 2026-11-01
- Amended: 2026-11-02, after review — how signals are trusted, a second
  connection per watcher for questions, the inhibitor taken on a thread of
  its own, what `status` reports, recovery on reconnecting.

## Context

The agent keeps the vault decrypted in memory until it is locked: by
`rusthorse lock`, the manager's **Lock now**, or the idle timer (15 minutes
by default). A person who walks away and locks the screen, or closes the
laptop lid, leaves the vault open until that timer fires — while every
program of the session that can reach the agent's socket can still ask it
for things, and a suspended machine holds the decrypted vault in RAM.

[ADR 0007](0007-visual-manager.md#6-screen-lock-suspend-and-keepassxc-m2m3)
(section 6) decided where this belongs: **in the agent**, so that closing
the manager cannot turn it off; that it should observe logind and the
screensavers over D-Bus, take a delay inhibitor to lock before the computer
sleeps, report unavailable sources instead of promising protection, and be
tested for duplicate signals, resume, bus loss and a pending unlock. This
ADR settles the details.

What the desktops offer (checked on Linux Mint 22.3, Cinnamon on X11):

- **logind** (system bus, `org.freedesktop.login1`): the manager's
  `PrepareForSleep(true)` signal before a suspend or hibernation and
  `PrepareForSleep(false)` after it; `Inhibit("sleep", …, "delay")`, which
  makes logind wait — up to `InhibitDelayMaxSec`, 5 s by default — until
  the returned descriptor is closed; and, per session, a `Lock` signal
  (`loginctl lock-session`, sent to the screen locker) and a `LockedHint`
  property that some lockers set.
- **Screensavers** (session bus): an `ActiveChanged(b)` signal on
  `org.cinnamon.ScreenSaver` (Cinnamon's locker), `org.gnome.ScreenSaver`,
  `org.mate.ScreenSaver` and `org.freedesktop.ScreenSaver` (KDE, and
  `csd-screensaver` on Cinnamon).

The agent runs as a systemd user service: outside the graphical session,
with the session bus of `user@.service` and the system bus.

## Decision

### 1. Three watchers in the agent

When it starts, the agent watches, each in a thread of its own:

| Event | Source | Reaction |
|---|---|---|
| The computer is about to sleep | logind `PrepareForSleep(true)` | Lock, then release the delay inhibitor taken beforehand |
| The session is locked | logind `Lock` on a session of the agent's user; `LockedHint` turning true on one | Lock |
| The screensaver starts | `ActiveChanged(true)` on one of the four screensaver interfaces | Lock |

"Lock" is the same as `rusthorse lock`: the decrypted vault and every
remembered approval are forgotten and the vault's generation changes, so an
unlock whose password is being typed, or an approval being answered, does
nothing when it completes. Commands already running keep the secrets they
were given. The audit log records a `lock` with outcome `suspend` or
`screen_locked` (and the source) when the vault was unlocked.

The delay inhibitor is taken at start and again after each resume
(`PrepareForSleep(false)`), on a thread of its own so that a slow answer
never holds up a lock; one that arrives while the computer goes to sleep is
let go at once. While it is held, logind waits for the agent to lock — but
only up to its `InhibitDelayMaxSec` (5 seconds by default), not forever.
Locking drops the decrypted vault from memory; it waits for the agent's
state lock, so a vault save in progress, or a slow disk under the audit
record written before the inhibitor is let go, can make it take longer than
logind waits.

Each watcher reads signals on one connection and asks its questions — who
owns logind's name, whose a session is, the inhibitor — on a second one,
each question limited to 2 seconds, so that an answer never waits behind
queued signals. When a watcher connects, or connects again, it also asks
whether a session of the agent's user is locked already (`LockedHint`) or a
screensaver is on (`GetActive`), and locks if so: a lock that happened while
it was not listening is not missed.

### 2. Signals only ever lock

No signal unlocks, ever: `ActiveChanged(false)`, `PrepareForSleep(false)`,
an `Unlock` or `LockedHint` turning false change nothing but the inhibitor.
Any program of the session can emit a screensaver signal, and a program of
another user could make a logind session lock; the worst a forged signal
can do is lock the vault, which the human unlocks again with the master
password. logind's signals count only as broadcasts from the current owner
of `org.freedesktop.login1` (its unique name, asked again when a sender
differs, since logind may restart): a signal sent to the agent alone, or by
anyone else, is ignored, and so is a malformed one — none of them can make
the agent let go of the inhibitor or stop watching. Session signals count
only for sessions whose user is the agent's, asked of logind, so that
another user locking their screen does not lock this vault; when logind does
not answer within the limit, the session counts as the agent's — locking is
the safe side — and the answer is asked again next time. Screensaver signals
are accepted from any sender: they can only lock.

A screensaver that starts without locking the screen still locks the vault:
the person is likely away.

### 3. Options

Both behaviours are on by default. `rusthorse agent --no-lock-on-suspend`
and `--no-lock-on-screen-lock` turn them off (for example on a machine that
nobody else can touch). There is no option to unlock automatically.

### 4. Reporting

`status` gains an optional `lock_triggers` list: for each event, the source,
whether it is being watched now, whether it is *degraded* (watched, but
logind would not give an inhibitor, so the lock may come after the computer
wakes), and why not (no system bus, no session bus, logind or no screensaver
on the bus, turned off, not built in). A source counts as watched only when
the service is there, not merely when the subscription is in place.
`rusthorse status`, `rusthorse doctor` and the manager's Status page show
it; `doctor` warns when nothing watches suspend or screen lock, and when the
suspend lock is degraded. A watcher whose bus goes away reports itself
inactive and reconnects every few seconds.

The agent holds a handle on its watchers: dropping it closes their
connections — letting go of the inhibitor — and joins their threads.

The field is optional within protocol 5: older agents leave it out, and
clients say "not reported".

### 5. Build

The watchers use `zbus` with its blocking API, already in the dependency
tree for `import secret-service`. They are behind a default Cargo feature,
`session-lock`; a build without it (`--no-default-features`, for a server)
has no watchers and its status says so.

## Alternatives considered

- **Lock from the manager.** Rejected by ADR 0007: closing the manager
  would turn the protection off.
- **Poll `loginctl` or `LockedHint`.** Slower, misses screensavers that do
  not set the hint, and cannot lock *before* a suspend.
- **systemd user units on `sleep.target` or a hook in
  `/usr/lib/systemd/system-sleep/`.** User units cannot order themselves
  before a system suspend, and system hooks need root and an installation
  step per distribution.
- **`xss-lock`-style helpers.** One more program to install and supervise,
  for what three D-Bus subscriptions do.
- **The `dbus` crate (libdbus).** A C library and its headers as a build
  dependency; `zbus` is pure Rust and already built for the Secret Service
  import.

## Consequences

- After a screen lock or a suspend, the next use of a secret asks for the
  master password again. That is the intended cost.
- On desktops whose locker emits none of these signals, and without
  logind, the vault does not lock with the screen; `status` and `doctor`
  say so, and the idle timer still applies.
- A suspend without logind (rare on systemd distributions) is not noticed.
- A dialog already on screen when the vault locks stays until it is
  answered or times out, but whatever it would approve finds the vault
  locked and does nothing.
- Hibernation writes RAM to disk: the vault is locked first, as for a
  suspend, but freed memory is not guaranteed to have been overwritten
  (threat model L7).
