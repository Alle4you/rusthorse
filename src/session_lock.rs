//! Locking the vault when the screen locks or the computer suspends
//! ([ADR 0009](https://github.com/Alle4you/rusthorse/blob/main/docs/adr/0009-lock-on-screen-lock-and-suspend.md)).
//!
//! Three watchers, each in a thread of its own, tell the agent to lock:
//!
//! - **suspend**: logind's `PrepareForSleep(true)` on the system bus. A
//!   delay inhibitor, taken beforehand and again after each resume, makes
//!   logind wait until the vault is locked;
//! - **screen lock (logind)**: a session's `Lock` signal, or its
//!   `LockedHint` turning true, for sessions of the agent's own user;
//! - **screen lock (screensavers)**: `ActiveChanged(true)` from Cinnamon's,
//!   GNOME's, MATE's or the freedesktop screensaver on the session bus.
//!
//! Signals only ever lock: nothing here unlocks, so a forged signal can at
//! worst lock the vault. A watcher whose bus goes away reports itself
//! inactive and connects again every few seconds.

use std::sync::{Mutex, MutexGuard};

use crate::protocol::LockTrigger;

/// `LockTrigger::event` of a suspend.
pub const SUSPEND: &str = "suspend";
/// `LockTrigger::event` of a screen lock.
pub const SCREEN_LOCK: &str = "screen_lock";
/// `LockTrigger::source` of logind.
pub const LOGIND: &str = "logind";

/// The screensavers whose `ActiveChanged(true)` locks the vault. Each one's
/// D-Bus name is also the interface of its signal.
pub const SCREENSAVERS: &[&str] = &[
    "org.cinnamon.ScreenSaver",
    "org.gnome.ScreenSaver",
    "org.mate.ScreenSaver",
    "org.freedesktop.ScreenSaver",
];

/// What the watchers need from the agent.
pub trait Locker: Send + Sync + 'static {
    /// Lock now, because of `event` (`suspend`, `screen_lock`) reported by
    /// `source`.
    fn lock_for(&self, event: &str, source: &str);
}

/// Which watchers run, and on which buses.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Lock when the computer is about to sleep.
    pub on_suspend: bool,
    /// Lock when the session is locked or its screensaver starts.
    pub on_screen_lock: bool,
    /// Address of the system bus; `None` for the usual one. (Tests use a
    /// private bus.)
    pub system_bus: Option<String>,
    /// Address of the session bus; `None` for the usual one.
    pub session_bus: Option<String>,
}

/// The watchers' state, as `status` reports it.
#[derive(Debug, Default)]
pub struct Triggers(Mutex<Vec<LockTrigger>>);

impl Triggers {
    fn entries(&self) -> MutexGuard<'_, Vec<LockTrigger>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// All triggers, in a stable order.
    pub fn snapshot(&self) -> Vec<LockTrigger> {
        let mut all = self.entries().clone();
        all.sort_by(|a, b| (&a.event, &a.source).cmp(&(&b.event, &b.source)));
        all
    }

    /// Record the state of the trigger for `event` from `source`.
    pub fn set(&self, event: &str, source: &str, active: bool, note: Option<String>) {
        let mut entries = self.entries();
        entries.retain(|t| !(t.event == event && t.source == source));
        entries.push(LockTrigger {
            event: event.into(),
            source: source.into(),
            active,
            note,
        });
    }

    /// Forget the trigger for `event` from `source`.
    pub fn remove(&self, event: &str, source: &str) {
        self.entries()
            .retain(|t| !(t.event == event && t.source == source));
    }
}

/// Start the watchers that `settings` asks for; report each in `triggers`.
#[cfg(feature = "session-lock")]
pub fn start<L: Locker>(
    locker: std::sync::Weak<L>,
    settings: Settings,
    triggers: std::sync::Arc<Triggers>,
) {
    watch::start(locker, settings, triggers);
}

/// Without D-Bus support, only report that nothing is watched.
#[cfg(not(feature = "session-lock"))]
pub fn start<L: Locker>(
    _locker: std::sync::Weak<L>,
    settings: Settings,
    triggers: std::sync::Arc<Triggers>,
) {
    let why = "this build has no D-Bus support (Cargo feature session-lock)";
    for (event, on) in [
        (SUSPEND, settings.on_suspend),
        (SCREEN_LOCK, settings.on_screen_lock),
    ] {
        let note = if on { why } else { "turned off" };
        triggers.set(event, "D-Bus", false, Some(note.into()));
    }
}

/// What else locks the vault, one line per event — `suspend: logind (locks
/// before the computer sleeps)`, `screen lock: logind, org.cinnamon.ScreenSaver`
/// — or why nothing watches it. For `rusthorse status` and the manager.
pub fn summary(triggers: &[LockTrigger]) -> Vec<String> {
    if triggers.is_empty() {
        return vec!["not reported (the agent predates it; restart it after an upgrade)".into()];
    }
    [(SUSPEND, "suspend"), (SCREEN_LOCK, "screen lock")]
        .into_iter()
        .map(|(event, label)| {
            let of_event: Vec<_> = triggers.iter().filter(|t| t.event == event).collect();
            let active: Vec<String> = of_event
                .iter()
                .filter(|t| t.active)
                .map(|t| match &t.note {
                    Some(note) => format!("{} ({note})", t.source),
                    None => t.source.clone(),
                })
                .collect();
            if active.is_empty() {
                let mut why: Vec<&str> =
                    of_event.iter().filter_map(|t| t.note.as_deref()).collect();
                why.sort_unstable();
                why.dedup();
                format!("{label}: not watched — {}", why.join("; "))
            } else {
                format!("{label}: {}", active.join(", "))
            }
        })
        .collect()
}

/// Whether a logind `PropertiesChanged` body for a session reports that it
/// became locked.
pub fn locked_hint_set(interface: &str, changed: &[(String, bool)]) -> bool {
    interface == "org.freedesktop.login1.Session"
        && changed
            .iter()
            .any(|(name, value)| name == "LockedHint" && *value)
}

#[cfg(feature = "session-lock")]
mod watch {
    use std::collections::HashMap;
    use std::sync::{Arc, Weak};
    use std::thread;
    use std::time::Duration;

    use zbus::blocking::{Connection, MessageIterator, connection};
    use zbus::message::Type;
    use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue};
    use zbus::{MatchRule, Message};

    use super::{LOGIND, Locker, SCREEN_LOCK, SCREENSAVERS, SUSPEND, Settings, Triggers};

    /// How long a watcher waits before connecting again.
    const RETRY: Duration = Duration::from_secs(5);
    /// How often the screensavers' presence is checked for `status`.
    const PRESENCE: Duration = Duration::from_secs(30);

    const LOGIND_NAME: &str = "org.freedesktop.login1";
    const LOGIND_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";
    const SESSION: &str = "org.freedesktop.login1.Session";
    const SESSIONS: &str = "/org/freedesktop/login1/session";
    const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

    pub(super) fn start<L: Locker>(locker: Weak<L>, settings: Settings, triggers: Arc<Triggers>) {
        let off = |event: &str, source: &str| {
            triggers.set(event, source, false, Some("turned off".into()));
        };
        // Until each watcher has connected.
        let connecting = Some("connecting".to_string());
        if settings.on_suspend {
            triggers.set(SUSPEND, LOGIND, false, connecting.clone());
        }
        if settings.on_screen_lock {
            triggers.set(SCREEN_LOCK, LOGIND, false, connecting.clone());
            triggers.set(SCREEN_LOCK, "screensaver", false, connecting);
        }
        if settings.on_suspend {
            let watcher = Watcher {
                name: "rusthorse-suspend",
                system: true,
                once: watch_suspend::<L>,
                lost: |t: &Triggers, note: String| t.set(SUSPEND, LOGIND, false, Some(note)),
            };
            watcher.spawn(&locker, &triggers, settings.system_bus.clone());
        } else {
            off(SUSPEND, LOGIND);
        }
        if settings.on_screen_lock {
            let sessions = Watcher {
                name: "rusthorse-session",
                system: true,
                once: watch_sessions::<L>,
                lost: |t: &Triggers, note: String| t.set(SCREEN_LOCK, LOGIND, false, Some(note)),
            };
            sessions.spawn(&locker, &triggers, settings.system_bus.clone());
            let screensavers = Watcher {
                name: "rusthorse-screensaver",
                system: false,
                once: watch_screensavers::<L>,
                lost: |t: &Triggers, note: String| {
                    for name in SCREENSAVERS {
                        t.remove(SCREEN_LOCK, name);
                    }
                    t.set(SCREEN_LOCK, "screensaver", false, Some(note));
                },
            };
            screensavers.spawn(&locker, &triggers, settings.session_bus);
        } else {
            off(SCREEN_LOCK, LOGIND);
            off(SCREEN_LOCK, "screensaver");
        }
    }

    /// One watcher: what it runs while connected, and how `status` shows it
    /// when the bus is gone.
    struct Watcher<L> {
        name: &'static str,
        system: bool,
        once: fn(&Weak<L>, &Arc<Triggers>, &Connection) -> zbus::Result<()>,
        lost: fn(&Triggers, String),
    }

    impl<L: Locker> Watcher<L> {
        /// Run `once` in a thread, again after `RETRY` whenever it returns,
        /// until the agent is gone.
        fn spawn(self, locker: &Weak<L>, triggers: &Arc<Triggers>, bus: Option<String>) {
            let locker = locker.clone();
            let triggers = Arc::clone(triggers);
            let _ = thread::Builder::new()
                .name(self.name.into())
                .spawn(move || {
                    while locker.strong_count() > 0 {
                        let result = connect(bus.as_deref(), self.system)
                            .and_then(|conn| (self.once)(&locker, &triggers, &conn));
                        if let Err(e) = result {
                            (self.lost)(
                                &triggers,
                                format!("{}; trying again", describe(&e, self.system)),
                            );
                        }
                        thread::sleep(RETRY);
                    }
                });
        }
    }

    fn describe(error: &zbus::Error, system: bool) -> String {
        let bus = if system { "system" } else { "session" };
        format!("no {bus} bus or no answer ({error})")
    }

    fn connect(address: Option<&str>, system: bool) -> zbus::Result<Connection> {
        match address {
            Some(address) => connection::Builder::address(address)?.build(),
            None if system => Connection::system(),
            None => Connection::session(),
        }
    }

    fn lock<L: Locker>(locker: &Weak<L>, event: &str, source: &str) {
        if let Some(locker) = locker.upgrade() {
            locker.lock_for(event, source);
        }
    }

    /// Ask logind to wait, before a suspend, until the returned descriptor is
    /// closed.
    fn inhibit(conn: &Connection) -> zbus::Result<OwnedFd> {
        conn.call_method(
            Some(LOGIND_NAME),
            LOGIND_PATH,
            Some(MANAGER),
            "Inhibit",
            &(
                "sleep",
                "Rusthorse",
                "Lock the vault before the computer sleeps",
                "delay",
            ),
        )?
        .body()
        .deserialize()
    }

    fn signals(conn: &Connection, rule: MatchRule<'static>) -> zbus::Result<MessageIterator> {
        MessageIterator::for_match_rule(rule, conn, None)
    }

    fn watch_suspend<L: Locker>(
        locker: &Weak<L>,
        triggers: &Arc<Triggers>,
        conn: &Connection,
    ) -> zbus::Result<()> {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND_NAME)?
            .interface(MANAGER)?
            .member("PrepareForSleep")?
            .build();
        // Subscribe first, so that no suspend falls between the two.
        let iter = signals(conn, rule)?;
        let mut held = take_inhibitor(conn, triggers);
        for message in iter {
            let sleeping: bool = message?.body().deserialize()?;
            if sleeping {
                lock(locker, SUSPEND, LOGIND);
                // Closing it lets the computer sleep now.
                held = None;
            } else if held.is_none() {
                held = take_inhibitor(conn, triggers);
            }
            if locker.strong_count() == 0 {
                return Ok(());
            }
        }
        drop(held);
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    /// Take the delay inhibitor and report the result.
    fn take_inhibitor(conn: &Connection, triggers: &Triggers) -> Option<OwnedFd> {
        match inhibit(conn) {
            Ok(fd) => {
                triggers.set(
                    SUSPEND,
                    LOGIND,
                    true,
                    Some("locks before the computer sleeps".into()),
                );
                Some(fd)
            }
            Err(e) => {
                triggers.set(
                    SUSPEND,
                    LOGIND,
                    true,
                    Some(format!(
                        "logind refused to wait ({e}): the lock may come only after the computer wakes"
                    )),
                );
                None
            }
        }
    }

    fn watch_sessions<L: Locker>(
        locker: &Weak<L>,
        triggers: &Arc<Triggers>,
        conn: &Connection,
    ) -> zbus::Result<()> {
        // Both `Lock` and `PropertiesChanged` come from logind on a session's
        // path; the rest is sorted out below.
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND_NAME)?
            .path_namespace(SESSIONS)?
            .build();
        let iter = signals(conn, rule)?;
        triggers.set(
            SCREEN_LOCK,
            LOGIND,
            true,
            Some("session lock signals of this user".into()),
        );
        for message in iter {
            let message = message?;
            if session_locked(&message) && ours(conn, &message) {
                lock(locker, SCREEN_LOCK, LOGIND);
            }
            if locker.strong_count() == 0 {
                return Ok(());
            }
        }
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    /// A `Lock` signal, or `LockedHint` turning true.
    fn session_locked(message: &Message) -> bool {
        let header = message.header();
        let interface = header.interface().map(|i| i.as_str()).unwrap_or_default();
        let member = header.member().map(|m| m.as_str()).unwrap_or_default();
        match (interface, member) {
            (SESSION, "Lock") => true,
            (PROPERTIES, "PropertiesChanged") => {
                let Ok((iface, changed, _)) =
                    message
                        .body()
                        .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                else {
                    return false;
                };
                let flags: Vec<(String, bool)> = changed
                    .into_iter()
                    .filter_map(|(name, value)| bool::try_from(value).ok().map(|v| (name, v)))
                    .collect();
                super::locked_hint_set(&iface, &flags)
            }
            _ => false,
        }
    }

    /// Whether the session the signal is about belongs to the agent's user.
    /// When logind cannot tell, it counts as ours: locking is the safe side.
    fn ours(conn: &Connection, message: &Message) -> bool {
        let Some(path) = message.header().path().map(|p| p.to_owned()) else {
            return true;
        };
        let user = conn
            .call_method(
                Some(LOGIND_NAME),
                &path,
                Some(PROPERTIES),
                "Get",
                &(SESSION, "User"),
            )
            .and_then(|reply| reply.body().deserialize::<OwnedValue>())
            .ok()
            .and_then(|value| <(u32, OwnedObjectPath)>::try_from(value).ok());
        match user {
            Some((uid, _)) => uid == nix::unistd::getuid().as_raw(),
            None => true,
        }
    }

    fn watch_screensavers<L: Locker>(
        locker: &Weak<L>,
        triggers: &Arc<Triggers>,
        conn: &Connection,
    ) -> zbus::Result<()> {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .member("ActiveChanged")?
            .build();
        let iter = signals(conn, rule)?;
        report_screensavers(conn, triggers);
        // Keep `status` current as screensavers come and go, while this
        // connection lasts.
        let connected = Arc::new(());
        let _ = thread::Builder::new()
            .name("rusthorse-screensaver-presence".into())
            .spawn({
                let (conn, triggers) = (conn.clone(), Arc::clone(triggers));
                let connected = Arc::downgrade(&connected);
                move || {
                    loop {
                        thread::sleep(PRESENCE);
                        if connected.strong_count() == 0 {
                            return;
                        }
                        report_screensavers(&conn, &triggers);
                    }
                }
            });
        for message in iter {
            let message = message?;
            let interface = message
                .header()
                .interface()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let Some(source) = SCREENSAVERS.iter().find(|s| **s == interface) else {
                continue;
            };
            if message.body().deserialize::<bool>().unwrap_or(false) {
                lock(locker, SCREEN_LOCK, source);
            }
            if locker.strong_count() == 0 {
                return Ok(());
            }
        }
        drop(connected);
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    /// One entry per screensaver present on the bus; one saying none is,
    /// when none is.
    fn report_screensavers(conn: &Connection, triggers: &Triggers) {
        let mut present = 0;
        for name in SCREENSAVERS {
            let has_owner: bool = conn
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "NameHasOwner",
                    &(*name,),
                )
                .and_then(|reply| reply.body().deserialize())
                .unwrap_or(false);
            if has_owner {
                present += 1;
                triggers.set(SCREEN_LOCK, name, true, None);
            } else {
                triggers.remove(SCREEN_LOCK, name);
            }
        }
        if present == 0 {
            triggers.set(
                SCREEN_LOCK,
                "screensaver",
                true,
                Some("no screensaver on the session bus now; watching for one".into()),
            );
        } else {
            triggers.remove(SCREEN_LOCK, "screensaver");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_session_whose_hint_turns_true_counts_as_locked() {
        let session = "org.freedesktop.login1.Session";
        assert!(locked_hint_set(session, &[("LockedHint".into(), true)]));
        assert!(!locked_hint_set(session, &[("LockedHint".into(), false)]));
        assert!(!locked_hint_set(session, &[("Active".into(), true)]));
        assert!(!locked_hint_set(
            "org.example.Other",
            &[("LockedHint".into(), true)]
        ));
    }

    #[test]
    fn triggers_replace_their_own_entry_and_sort() {
        let t = Triggers::default();
        t.set(SCREEN_LOCK, LOGIND, false, Some("connecting".into()));
        t.set(SUSPEND, LOGIND, true, None);
        t.set(SCREEN_LOCK, LOGIND, true, None);
        let all = t.snapshot();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].event.as_str(), all[0].active), (SCREEN_LOCK, true));
        assert_eq!(all[1].event, SUSPEND);
        t.remove(SUSPEND, LOGIND);
        assert_eq!(t.snapshot().len(), 1);
    }
}
