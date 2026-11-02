//! Locking the vault when the screen locks or the computer suspends
//! ([ADR 0009](https://github.com/Alle4you/rusthorse/blob/main/docs/adr/0009-lock-on-screen-lock-and-suspend.md)).
//!
//! Three watchers, each in a thread of its own, tell the agent to lock:
//!
//! - **suspend**: logind's `PrepareForSleep(true)` on the system bus. A
//!   delay inhibitor, taken beforehand and again after each resume, makes
//!   logind wait — up to its `InhibitDelayMaxSec` — until the vault is
//!   locked;
//! - **screen lock (logind)**: a session's `Lock` signal, or its
//!   `LockedHint` turning true, for sessions of the agent's own user;
//! - **screen lock (screensavers)**: `ActiveChanged(true)` from Cinnamon's,
//!   GNOME's, MATE's or the freedesktop screensaver on the session bus.
//!
//! Each watcher reads signals on one connection and asks its questions
//! (who owns logind's name, whose session this is, the inhibitor) on
//! another, with a time limit, so that a slow answer never holds up a lock.
//! logind's signals count only from the current owner of its name, as
//! broadcasts; a malformed one is ignored. Signals only ever lock: nothing
//! here unlocks, so a forged signal can at worst lock the vault. A watcher
//! whose bus goes away reports itself inactive and connects again every few
//! seconds; on connecting it also asks whether the session is locked already.

use std::sync::{Mutex, MutexGuard};

use crate::protocol::LockTrigger;

/// `LockTrigger::event` of a suspend.
pub const SUSPEND: &str = "suspend";
/// `LockTrigger::event` of a screen lock.
pub const SCREEN_LOCK: &str = "screen_lock";
/// `LockTrigger::source` of logind.
pub const LOGIND: &str = "logind";
/// `LockTrigger::source` standing for every screensaver, when none is there.
pub const ANY_SCREENSAVER: &str = "screensaver";

/// The screensavers whose `ActiveChanged(true)` locks the vault. Each one's
/// D-Bus name is also the interface of its signal and, with dots turned into
/// slashes, its object's path.
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

/// The state of one trigger, as `status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Watched, and nothing is missing.
    Watching,
    /// Watched, but not as well as it should be (logind refused to wait
    /// before a suspend).
    Degraded,
    /// Not watched: off, unavailable, or not connected yet.
    Inactive,
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
    pub fn set(&self, event: &str, source: &str, state: State, note: Option<String>) {
        let mut entries = self.entries();
        entries.retain(|t| !(t.event == event && t.source == source));
        entries.push(LockTrigger {
            event: event.into(),
            source: source.into(),
            active: state != State::Inactive,
            degraded: state == State::Degraded,
            note,
        });
    }

    /// Forget the trigger for `event` from `source`.
    pub fn remove(&self, event: &str, source: &str) {
        self.entries()
            .retain(|t| !(t.event == event && t.source == source));
    }
}

/// The running watchers. Dropping it stops them: their connections are
/// closed — which also lets go of the inhibitor — and their threads joined.
#[derive(Default)]
pub struct Watchers {
    /// Kept for its `Drop`.
    #[cfg(feature = "session-lock")]
    _inner: Option<watch::Handle>,
}

/// Start the watchers that `settings` asks for; report each in `triggers`.
#[cfg(feature = "session-lock")]
pub fn start<L: Locker>(
    locker: std::sync::Weak<L>,
    settings: Settings,
    triggers: std::sync::Arc<Triggers>,
) -> Watchers {
    Watchers {
        _inner: Some(watch::start(locker, settings, triggers)),
    }
}

/// Without D-Bus support, only report that nothing is watched.
#[cfg(not(feature = "session-lock"))]
pub fn start<L: Locker>(
    _locker: std::sync::Weak<L>,
    settings: Settings,
    triggers: std::sync::Arc<Triggers>,
) -> Watchers {
    let why = "this build has no D-Bus support (Cargo feature session-lock)";
    for (event, on) in [
        (SUSPEND, settings.on_suspend),
        (SCREEN_LOCK, settings.on_screen_lock),
    ] {
        let note = if on { why } else { "turned off" };
        triggers.set(event, "D-Bus", State::Inactive, Some(note.into()));
    }
    Watchers::default()
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, Weak};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use zbus::blocking::{Connection, MessageIterator, connection};
    use zbus::message::Type;
    use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue};
    use zbus::{MatchRule, Message};

    use super::{
        ANY_SCREENSAVER, LOGIND, Locker, SCREEN_LOCK, SCREENSAVERS, SUSPEND, Settings, State,
        Triggers,
    };

    /// How long a watcher waits before connecting again.
    const RETRY: Duration = Duration::from_secs(5);
    /// How often a watcher checks that its services are there, for `status`.
    const REFRESH: Duration = Duration::from_secs(30);
    /// The longest a question to the bus may take.
    const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
    /// How often a sleeping thread looks whether it should stop.
    const STEP: Duration = Duration::from_millis(50);

    const BUS_NAME: &str = "org.freedesktop.DBus";
    const BUS_PATH: &str = "/org/freedesktop/DBus";
    const LOGIND_NAME: &str = "org.freedesktop.login1";
    const LOGIND_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";
    const SESSION: &str = "org.freedesktop.login1.Session";
    const SESSIONS: &str = "/org/freedesktop/login1/session";
    const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

    fn lock_of<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// What every thread shares: whether to stop, the connections to close
    /// and the helper threads to join when stopping.
    #[derive(Default)]
    struct Shared {
        stopped: AtomicBool,
        next_id: AtomicU64,
        connections: Mutex<Vec<(u64, Connection)>>,
        helpers: Mutex<Vec<JoinHandle<()>>>,
    }

    impl Shared {
        fn stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }

        /// Sleep for `duration`, or less when stopping; whether to go on.
        fn pause(&self, duration: Duration) -> bool {
            let until = Instant::now() + duration;
            while !self.stopped() {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return true;
                }
                thread::sleep(left.min(STEP));
            }
            false
        }

        /// Keep `connection` to close it when stopping.
        fn keep(&self, connection: &Connection) -> u64 {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            lock_of(&self.connections).push((id, connection.clone()));
            if self.stopped() {
                self.close_all();
            }
            id
        }

        fn forget(&self, id: u64) {
            lock_of(&self.connections).retain(|(i, _)| *i != id);
        }

        fn close_all(&self) {
            let connections: Vec<_> = lock_of(&self.connections).drain(..).collect();
            for (_, connection) in connections {
                let _ = connection.close();
            }
        }

        fn helper(&self, name: &str, run: impl FnOnce() + Send + 'static) {
            if let Ok(handle) = thread::Builder::new().name(name.into()).spawn(run) {
                let mut helpers = lock_of(&self.helpers);
                helpers.retain(|h| !h.is_finished());
                helpers.push(handle);
            }
        }
    }

    /// The running watchers: stops them when dropped.
    pub(super) struct Handle {
        shared: Arc<Shared>,
        threads: Vec<JoinHandle<()>>,
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            self.shared.stopped.store(true, Ordering::SeqCst);
            self.shared.close_all();
            // The last reference to the agent may go away in one of these
            // threads (it holds one while locking): never join oneself.
            let me = thread::current().id();
            let helpers: Vec<_> = lock_of(&self.shared.helpers).drain(..).collect();
            for handle in self.threads.drain(..).chain(helpers) {
                if handle.thread().id() != me {
                    let _ = handle.join();
                }
            }
        }
    }

    /// What a watcher needs to run.
    struct Ctx<L> {
        locker: Weak<L>,
        triggers: Arc<Triggers>,
        shared: Arc<Shared>,
        bus: Option<String>,
        system: bool,
    }

    impl<L: Locker> Ctx<L> {
        fn going(&self) -> bool {
            !self.shared.stopped() && self.locker.strong_count() > 0
        }

        fn lock(&self, event: &str, source: &str) {
            if let Some(locker) = self.locker.upgrade() {
                locker.lock_for(event, source);
            }
        }

        /// A new connection; `timeout` bounds its method calls.
        fn connect(&self, timeout: Option<Duration>) -> zbus::Result<Connection> {
            let builder = match self.bus.as_deref() {
                Some(address) => connection::Builder::address(address)?,
                None if self.system => connection::Builder::system()?,
                None => connection::Builder::session()?,
            };
            match timeout {
                Some(timeout) => builder.method_timeout(timeout).build(),
                None => builder.build(),
            }
        }

        fn describe(&self, error: &zbus::Error) -> String {
            let bus = if self.system { "system" } else { "session" };
            format!("no {bus} bus or no answer ({error})")
        }
    }

    /// One watcher: its thread's name, which bus, what it runs while
    /// connected (given a connection for signals and one for questions), and
    /// how `status` shows it when the bus is gone.
    struct Watcher<L> {
        name: &'static str,
        system: bool,
        once: fn(&Ctx<L>, &Connection, &Connection) -> zbus::Result<()>,
        lost: fn(&Triggers, String),
    }

    impl<L: Locker> Watcher<L> {
        fn spawn(
            self,
            locker: &Weak<L>,
            triggers: &Arc<Triggers>,
            shared: &Arc<Shared>,
            bus: Option<String>,
        ) -> Option<JoinHandle<()>> {
            let ctx = Ctx {
                locker: locker.clone(),
                triggers: Arc::clone(triggers),
                shared: Arc::clone(shared),
                bus,
                system: self.system,
            };
            thread::Builder::new()
                .name(self.name.into())
                .spawn(move || {
                    while ctx.going() {
                        let result = (|| {
                            let signals = ctx.connect(None)?;
                            let queries = ctx.connect(Some(QUERY_TIMEOUT))?;
                            let ids = [ctx.shared.keep(&signals), ctx.shared.keep(&queries)];
                            let result = (self.once)(&ctx, &signals, &queries);
                            for id in ids {
                                ctx.shared.forget(id);
                            }
                            result
                        })();
                        if !ctx.going() {
                            return;
                        }
                        if let Err(e) = result {
                            (self.lost)(
                                &ctx.triggers,
                                format!("{}; trying again", ctx.describe(&e)),
                            );
                        }
                        if !ctx.shared.pause(RETRY) {
                            return;
                        }
                    }
                })
                .ok()
        }
    }

    pub(super) fn start<L: Locker>(
        locker: Weak<L>,
        settings: Settings,
        triggers: Arc<Triggers>,
    ) -> Handle {
        let shared = Arc::new(Shared::default());
        let mut threads = Vec::new();
        let connecting = Some("connecting".to_string());
        if settings.on_suspend {
            triggers.set(SUSPEND, LOGIND, State::Inactive, connecting.clone());
            let watcher = Watcher {
                name: "rusthorse-suspend",
                system: true,
                once: watch_suspend::<L>,
                lost: |t: &Triggers, note| t.set(SUSPEND, LOGIND, State::Inactive, Some(note)),
            };
            threads.extend(watcher.spawn(&locker, &triggers, &shared, settings.system_bus.clone()));
        } else {
            triggers.set(SUSPEND, LOGIND, State::Inactive, Some("turned off".into()));
        }
        if settings.on_screen_lock {
            triggers.set(SCREEN_LOCK, LOGIND, State::Inactive, connecting.clone());
            triggers.set(SCREEN_LOCK, ANY_SCREENSAVER, State::Inactive, connecting);
            let sessions = Watcher {
                name: "rusthorse-session",
                system: true,
                once: watch_sessions::<L>,
                lost: |t: &Triggers, note| t.set(SCREEN_LOCK, LOGIND, State::Inactive, Some(note)),
            };
            threads.extend(sessions.spawn(
                &locker,
                &triggers,
                &shared,
                settings.system_bus.clone(),
            ));
            let screensavers = Watcher {
                name: "rusthorse-screensaver",
                system: false,
                once: watch_screensavers::<L>,
                lost: |t: &Triggers, note| {
                    for name in SCREENSAVERS {
                        t.remove(SCREEN_LOCK, name);
                    }
                    t.set(SCREEN_LOCK, ANY_SCREENSAVER, State::Inactive, Some(note));
                },
            };
            threads.extend(screensavers.spawn(&locker, &triggers, &shared, settings.session_bus));
        } else {
            for source in [LOGIND, ANY_SCREENSAVER] {
                triggers.set(
                    SCREEN_LOCK,
                    source,
                    State::Inactive,
                    Some("turned off".into()),
                );
            }
        }
        Handle { shared, threads }
    }

    fn signals(conn: &Connection, rule: MatchRule<'static>) -> zbus::Result<MessageIterator> {
        MessageIterator::for_match_rule(rule, conn, None)
    }

    /// Whether `error` says that nobody owns the name called.
    fn absent(error: &zbus::Error) -> bool {
        matches!(error, zbus::Error::MethodError(name, _, _)
            if name.as_str().ends_with(".ServiceUnknown") || name.as_str().ends_with(".NameHasNoOwner"))
    }

    /// The unique name that owns `name` now, if any.
    fn owner_of(queries: &Connection, name: &str) -> Option<String> {
        queries
            .call_method(
                Some(BUS_NAME),
                BUS_PATH,
                Some(BUS_NAME),
                "GetNameOwner",
                &(name,),
            )
            .ok()?
            .body()
            .deserialize::<String>()
            .ok()
    }

    /// The owner of logind's name, asked again when a signal's sender is
    /// not the one known (logind may have restarted).
    struct Owner {
        unique: Option<String>,
    }

    impl Owner {
        fn new(queries: &Connection) -> Owner {
            Owner {
                unique: owner_of(queries, LOGIND_NAME),
            }
        }

        /// Whether `message` comes from the owner of logind's name: a signal
        /// from anyone else — even one sent to the agent alone, which the
        /// bus's matching does not filter — is not logind's.
        fn sent(&mut self, queries: &Connection, message: &Message) -> bool {
            let header = message.header();
            let Some(sender) = header.sender().map(|s| s.as_str().to_owned()) else {
                return false;
            };
            if self.unique.as_deref() != Some(sender.as_str()) {
                self.unique = owner_of(queries, LOGIND_NAME);
            }
            self.unique.as_deref() == Some(sender.as_str())
        }
    }

    /// The delay inhibitor. It is asked for on a thread of its own, so that
    /// a slow answer never holds up a lock; one that arrives while the
    /// computer goes to sleep is let go at once.
    #[derive(Default)]
    struct Inhibitor {
        fd: Mutex<Option<OwnedFd>>,
        sleeping: AtomicBool,
        asking: AtomicBool,
    }

    impl Inhibitor {
        fn acquire(
            self: &Arc<Self>,
            triggers: &Arc<Triggers>,
            shared: &Shared,
            queries: &Connection,
        ) {
            if self.sleeping.load(Ordering::SeqCst)
                || lock_of(&self.fd).is_some()
                || self.asking.swap(true, Ordering::SeqCst)
            {
                return;
            }
            let (me, queries, triggers) = (Arc::clone(self), queries.clone(), Arc::clone(triggers));
            shared.helper("rusthorse-inhibit", move || {
                let answer = queries
                    .call_method(
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
                    )
                    .and_then(|reply| reply.body().deserialize::<OwnedFd>());
                me.asking.store(false, Ordering::SeqCst);
                match answer {
                    Ok(fd) => {
                        if !me.sleeping.load(Ordering::SeqCst) {
                            lock_of(&me.fd).get_or_insert(fd);
                        }
                        triggers.set(
                            SUSPEND,
                            LOGIND,
                            State::Watching,
                            Some("locks before the computer sleeps".into()),
                        );
                    }
                    Err(e) if absent(&e) => triggers.set(
                        SUSPEND,
                        LOGIND,
                        State::Inactive,
                        Some("logind is not on the system bus".into()),
                    ),
                    Err(e) => triggers.set(
                        SUSPEND,
                        LOGIND,
                        State::Degraded,
                        Some(format!(
                            "logind would not wait ({e}): the lock may come only after the computer wakes"
                        )),
                    ),
                }
            });
        }

        fn release(&self) {
            lock_of(&self.fd).take();
        }
    }

    fn watch_suspend<L: Locker>(
        ctx: &Ctx<L>,
        signals_conn: &Connection,
        queries: &Connection,
    ) -> zbus::Result<()> {
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND_NAME)?
            .interface(MANAGER)?
            .member("PrepareForSleep")?
            .build();
        // Subscribe first, so that no suspend falls between the two.
        let iter = signals(signals_conn, rule)?;
        let mut owner = Owner::new(queries);
        let inhibitor = Arc::new(Inhibitor::default());
        inhibitor.acquire(&ctx.triggers, &ctx.shared, queries);
        // Ask again from time to time while there is none (logind may come
        // later, or have refused).
        let alive = Arc::new(());
        {
            let (inhibitor, triggers, shared, queries) = (
                Arc::clone(&inhibitor),
                Arc::clone(&ctx.triggers),
                Arc::clone(&ctx.shared),
                queries.clone(),
            );
            let alive = Arc::downgrade(&alive);
            ctx.shared.helper("rusthorse-refresh", move || {
                while shared.pause(REFRESH) && alive.strong_count() > 0 {
                    inhibitor.acquire(&triggers, &shared, &queries);
                }
            });
        }
        for message in iter {
            let message = message?;
            if !ctx.going() {
                return Ok(());
            }
            if !owner.sent(queries, &message) {
                continue;
            }
            let Ok(sleeping) = message.body().deserialize::<bool>() else {
                continue;
            };
            if sleeping {
                inhibitor.sleeping.store(true, Ordering::SeqCst);
                ctx.lock(SUSPEND, LOGIND);
                // Letting it go lets the computer sleep now.
                inhibitor.release();
            } else {
                inhibitor.sleeping.store(false, Ordering::SeqCst);
                inhibitor.acquire(&ctx.triggers, &ctx.shared, queries);
            }
        }
        drop(alive);
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    fn watch_sessions<L: Locker>(
        ctx: &Ctx<L>,
        signals_conn: &Connection,
        queries: &Connection,
    ) -> zbus::Result<()> {
        // Both `Lock` and `PropertiesChanged` come from logind on a session's
        // path; the rest is sorted out below.
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(LOGIND_NAME)?
            .path_namespace(SESSIONS)?
            .build();
        let iter = signals(signals_conn, rule)?;
        let mut owner = Owner::new(queries);
        report_logind(&ctx.triggers, owner.unique.is_some());
        // A lock that happened while the agent was not listening.
        if any_session_locked(queries) {
            ctx.lock(SCREEN_LOCK, LOGIND);
        }
        let alive = Arc::new(());
        refresh(ctx, queries, &alive, |queries, triggers| {
            report_logind(triggers, owner_of(queries, LOGIND_NAME).is_some());
        });
        let mut users: HashMap<String, bool> = HashMap::new();
        for message in iter {
            let message = message?;
            if !ctx.going() {
                return Ok(());
            }
            if !owner.sent(queries, &message) || !session_locked(&message) {
                continue;
            }
            let Some(path) = message.header().path().map(|p| p.to_string()) else {
                continue;
            };
            // Asked once per session; when logind cannot tell in time, the
            // session counts as ours (locking is the safe side) but the
            // answer is not kept.
            let ours = match users.get(&path) {
                Some(ours) => *ours,
                None => match session_is_ours(queries, &path) {
                    Some(ours) => *users.entry(path).or_insert(ours),
                    None => true,
                },
            };
            if ours {
                ctx.lock(SCREEN_LOCK, LOGIND);
            }
        }
        drop(alive);
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    fn report_logind(triggers: &Triggers, present: bool) {
        if present {
            triggers.set(
                SCREEN_LOCK,
                LOGIND,
                State::Watching,
                Some("session lock signals of this user".into()),
            );
        } else {
            triggers.set(
                SCREEN_LOCK,
                LOGIND,
                State::Inactive,
                Some("logind is not on the system bus; watching for it".into()),
            );
        }
    }

    /// Run `check` every `REFRESH` on a helper thread, while `alive` is.
    fn refresh<L: Locker>(
        ctx: &Ctx<L>,
        queries: &Connection,
        alive: &Arc<()>,
        check: fn(&Connection, &Triggers),
    ) {
        let (queries, triggers, shared) = (
            queries.clone(),
            Arc::clone(&ctx.triggers),
            Arc::clone(&ctx.shared),
        );
        let alive = Arc::downgrade(alive);
        ctx.shared.helper("rusthorse-refresh", move || {
            while shared.pause(REFRESH) && alive.strong_count() > 0 {
                check(&queries, &triggers);
            }
        });
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

    fn property(queries: &Connection, path: &str, name: &str) -> Option<OwnedValue> {
        queries
            .call_method(
                Some(LOGIND_NAME),
                path,
                Some(PROPERTIES),
                "Get",
                &(SESSION, name),
            )
            .ok()?
            .body()
            .deserialize::<OwnedValue>()
            .ok()
    }

    /// Whether the session at `path` belongs to the agent's user; `None` when
    /// logind does not tell in time.
    fn session_is_ours(queries: &Connection, path: &str) -> Option<bool> {
        let (uid, _) = <(u32, OwnedObjectPath)>::try_from(property(queries, path, "User")?).ok()?;
        Some(uid == nix::unistd::getuid().as_raw())
    }

    /// Whether a session of the agent's user is locked already.
    fn any_session_locked(queries: &Connection) -> bool {
        let Ok(reply) = queries.call_method(
            Some(LOGIND_NAME),
            LOGIND_PATH,
            Some(MANAGER),
            "ListSessions",
            &(),
        ) else {
            return false;
        };
        let Ok(sessions) = reply
            .body()
            .deserialize::<Vec<(String, u32, String, String, OwnedObjectPath)>>()
        else {
            return false;
        };
        let uid = nix::unistd::getuid().as_raw();
        sessions
            .iter()
            .filter(|(_, owner, _, _, _)| *owner == uid)
            .any(|(_, _, _, _, path)| {
                property(queries, path.as_str(), "LockedHint")
                    .and_then(|v| bool::try_from(v).ok())
                    .unwrap_or(false)
            })
    }

    fn watch_screensavers<L: Locker>(
        ctx: &Ctx<L>,
        signals_conn: &Connection,
        queries: &Connection,
    ) -> zbus::Result<()> {
        // Any sender: a forged signal can only lock.
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .member("ActiveChanged")?
            .build();
        let iter = signals(signals_conn, rule)?;
        // A screensaver that started while the agent was not listening.
        for name in report_screensavers(queries, &ctx.triggers) {
            if screensaver_active(queries, name) {
                ctx.lock(SCREEN_LOCK, name);
            }
        }
        let alive = Arc::new(());
        refresh(ctx, queries, &alive, |queries, triggers| {
            report_screensavers(queries, triggers);
        });
        for message in iter {
            let message = message?;
            if !ctx.going() {
                return Ok(());
            }
            let interface = message
                .header()
                .interface()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let Some(source) = SCREENSAVERS.iter().find(|s| **s == interface) else {
                continue;
            };
            if message.body().deserialize::<bool>().unwrap_or(false) {
                ctx.lock(SCREEN_LOCK, source);
            }
        }
        drop(alive);
        Err(zbus::Error::Failure("the bus closed the connection".into()))
    }

    fn screensaver_active(queries: &Connection, name: &str) -> bool {
        let path = format!("/{}", name.replace('.', "/"));
        queries
            .call_method(Some(name), path.as_str(), Some(name), "GetActive", &())
            .and_then(|reply| reply.body().deserialize::<bool>())
            .unwrap_or(false)
    }

    /// One entry per screensaver present on the bus, or one saying that
    /// none is; the names present.
    fn report_screensavers(queries: &Connection, triggers: &Triggers) -> Vec<&'static str> {
        let present: Vec<&'static str> = SCREENSAVERS
            .iter()
            .copied()
            .filter(|name| {
                queries
                    .call_method(
                        Some(BUS_NAME),
                        BUS_PATH,
                        Some(BUS_NAME),
                        "NameHasOwner",
                        &(*name,),
                    )
                    .and_then(|reply| reply.body().deserialize::<bool>())
                    .unwrap_or(false)
            })
            .collect();
        for name in SCREENSAVERS {
            if present.contains(name) {
                triggers.set(SCREEN_LOCK, name, State::Watching, None);
            } else {
                triggers.remove(SCREEN_LOCK, name);
            }
        }
        if present.is_empty() {
            triggers.set(
                SCREEN_LOCK,
                ANY_SCREENSAVER,
                State::Inactive,
                Some("no screensaver on the session bus; watching for one".into()),
            );
        } else {
            triggers.remove(SCREEN_LOCK, ANY_SCREENSAVER);
        }
        present
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
        t.set(
            SCREEN_LOCK,
            LOGIND,
            State::Inactive,
            Some("connecting".into()),
        );
        t.set(
            SUSPEND,
            LOGIND,
            State::Degraded,
            Some("would not wait".into()),
        );
        t.set(SCREEN_LOCK, LOGIND, State::Watching, None);
        let all = t.snapshot();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].event.as_str(), all[0].active), (SCREEN_LOCK, true));
        assert_eq!((all[1].active, all[1].degraded), (true, true));
        t.remove(SUSPEND, LOGIND);
        assert_eq!(t.snapshot().len(), 1);
    }
}
