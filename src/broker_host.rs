//! The agent's side of the credential broker
//! ([ADR 0013](../docs/adr/0013-credential-broker.md)): the registry of
//! grants, one `rusthorse-broker` process per grant, admission, revocation
//! and expiry.
//!
//! The [`Registry`] is the one authority for each grant's state, counters
//! and limits. It lives as long as the agent, outside the vault's state, so
//! that grants can outlive a lock and be listed and revoked while the vault
//! is locked. Lock order: the agent's state lock, then the registry's, never
//! the reverse; admission and the end of a request never take the state
//! lock.
//!
//! A grant is `starting` while its run is prepared ([`Registry::enter`],
//! [`RunGrants::start`]), `active` once every grant of its run is ready
//! ([`RunGrants::activate`]), `exhausted` once it has admitted its request
//! limit, `revoked` once something ended it ([`Registry::decide`]), and ended
//! — removed from the registry — once its broker has exited. A grant never
//! becomes active again.
//!
//! A broker is entered in the registry as soon as its process exists, and
//! sent its install under the same hold of the registry's lock, only while
//! its grant is still starting: a grant that has ended gets no install, so
//! no credential. From then on a revocation contains it: a broker that has
//! not answered ready yet, and so has served nothing, is killed; one that
//! has is told to revoke.
//!
//! Containing a broker means that it confirmed the revocation, or that its
//! process is gone: killed and reaped. Asking for a kill is not containing
//! it: every revocation that finds a kill asked for and not done yet does it
//! itself, or waits for whoever is doing it, before it is done.
//!
//! Each broker is read by a thread of its own, which checks every message
//! against the conversation of [`crate::broker_protocol`] — anything else is
//! a broken broker, which ends its grant (`broker_failed`) and is killed,
//! and the message changes no counter — and answers at once each admission
//! it refuses: a refusal needs no record. An admission it allows holds a use
//! and a slot, and goes to a second thread per grant, which writes the audit
//! records of the grant's requests in the order the broker sent them and
//! answers that admission once its record is written.
//!
//! Revocation is decided in the registry first, so that nothing is admitted
//! after that moment; the brokers concerned are then told at once, each with
//! the refusal of every admission still waiting (for its record or for its
//! turn), and waited for together: a broker that cannot be told within
//! [`REVOKE_SEND_TIMEOUT`], or does not confirm within
//! [`REVOKE_CONFIRM_TIMEOUT`] after that, is killed. A broker confirms only
//! once every admission it asked for is answered, so this is what keeps a
//! slow audit log from delaying a confirmation: such a log delays only the
//! admissions it records, never a refusal, a revocation or its
//! confirmation. No thread that writes records waits for a broker's
//! confirmation (only, at most [`ANSWER_TIMEOUT`], for it to take an
//! answer), and a grant's end record is best effort.
//!
//! Lifetimes are checked by a timer thread ([`Registry::start_timer`]).
//! Should it not start, nothing would end a grant when its lifetime passes:
//! the registry then refuses to enter any grant.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{Ipv4Addr, Shutdown, TcpListener};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use crate::audit::{AuditEvent, AuditRequestCounts};
use crate::broker_profile::{AutomaticLocks, BrokerProfile};
use crate::broker_protocol::{
    self, AdmissionRefusal, EXIT_KILL_DELAY, EndReason, FromBroker, Install, MAX_GRANTS,
    MAX_IN_FLIGHT, REVOKE_CONFIRM_TIMEOUT, RequestOutcome, ToBroker,
};
use crate::peer::Peer;
use crate::protocol::GrantInfo;
use crate::supervise::{Exit, Supervised, write_all_by};

/// How long a broker has to take an answer to one of its admissions off the
/// control channel. A broker that reads its channel takes it at once; one
/// that does not read it is broken, and killed.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a broker has to take [`ToBroker::Revoke`] off its control
/// channel: a broker that reads its channel takes it at once, so one that
/// does not within this time is killed rather than waited for.
pub(crate) const REVOKE_SEND_TIMEOUT: Duration = Duration::from_millis(250);

/// How often the expiry of grants is checked.
const EXPIRY_CHECK: Duration = Duration::from_secs(1);

/// How long, beyond [`EXIT_KILL_DELAY`], the end of a run waits for its
/// brokers' threads to see them gone before it kills what is left.
const STOP_MARGIN: Duration = Duration::from_secs(1);

/// Most messages of one broker waiting for its audit thread. A broker that
/// keeps to its own limits never has more than a few dozen there (one per
/// request in flight and one per end); the reader waits when it is full.
const JOB_QUEUE: usize = 256;

/// A moment on the boot-time clock (`CLOCK_BOOTTIME`), which keeps counting
/// while the computer is suspended: a grant's lifetime includes time spent
/// asleep (ADR 0013, limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BootInstant(Duration);

impl BootInstant {
    /// Now. Should the clock ever be unreadable, now is the end of time, and
    /// every grant counts as expired.
    pub(crate) fn now() -> Self {
        use nix::time::{ClockId, clock_gettime};
        match clock_gettime(ClockId::CLOCK_BOOTTIME) {
            Ok(now) => {
                let secs = u64::try_from(now.tv_sec()).unwrap_or(0);
                let nanos = u32::try_from(now.tv_nsec()).unwrap_or(0).min(999_999_999);
                BootInstant(Duration::new(secs, nanos))
            }
            Err(_) => BootInstant(Duration::MAX),
        }
    }

    fn after(self, duration: Duration) -> Self {
        BootInstant(self.0.saturating_add(duration))
    }

    /// The time from `self` until `later`; zero once it has passed.
    fn until(self, later: BootInstant) -> Duration {
        later.0.saturating_sub(self.0)
    }
}

/// Where the registry writes its audit records: the agent's log, or a
/// test's.
pub(crate) trait Recorder: Send + Sync {
    /// Write one record durably, or fail.
    fn record(&self, event: &AuditEvent) -> io::Result<()>;
}

impl Recorder for crate::audit::AuditLog {
    fn record(&self, event: &AuditEvent) -> io::Result<()> {
        crate::audit::AuditLog::record(self, event)
    }
}

/// A grant's state (ADR 0013, "States").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Its run is being prepared; nothing is admitted.
    Starting,
    /// Requests are admitted.
    Active,
    /// Its request limit is reached: nothing new is admitted; the requests
    /// admitted finish.
    Exhausted,
    /// Ended: nothing is admitted, and its broker was told to close every
    /// open request (or killed). Its broker answers `403` until the command
    /// ends.
    Revoked,
}

impl State {
    /// As [`GrantInfo::state`] writes it.
    fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Active => "active",
            State::Exhausted => "exhausted",
            State::Revoked => "revoked",
        }
    }

    /// Whether the grant has not been ended yet.
    fn live(self) -> bool {
        !matches!(self, State::Revoked)
    }
}

/// A grant to enter in the registry ([`Registry::enter`]). Never its token:
/// the agent gives that to the broker and the command, and keeps no copy.
#[derive(Debug, Clone)]
pub(crate) struct NewGrant {
    /// Its public ID ([`broker_protocol::new_grant_id`]).
    pub(crate) id: String,
    /// The UUID of its entry.
    pub(crate) entry_uuid: String,
    /// Its entry, as dialogs and the audit log identify it.
    pub(crate) entry: String,
    /// The variable that holds the token in the command.
    pub(crate) var: String,
    /// The entry's profile, as it was when the grant was created.
    pub(crate) profile: BrokerProfile,
    /// The command, as a shell would read it.
    pub(crate) command: String,
    /// Who asked for it, as dialogs describe the requester.
    pub(crate) requester: String,
    /// How long it may last: the profile's maximum lifetime (shorter only in
    /// tests).
    pub(crate) lifetime: Duration,
}

/// What does not change during a grant's life, shared with its threads.
#[derive(Debug)]
struct GrantMeta {
    id: String,
    entry_uuid: String,
    entry: String,
    requester: String,
}

impl GrantMeta {
    /// An audit record about this grant: its ID, its entry, and its
    /// requester (the one who asked for the run).
    fn event(&self, action: &str, outcome: &str) -> AuditEvent {
        let mut event = AuditEvent::new(action, &Peer::agent())
            .outcome(outcome)
            .entries(vec![self.entry.clone()]);
        event.requester = self.requester.clone();
        event.grant = Some(self.id.clone());
        event
    }
}

/// A broker's process, as its [`Link`] knows it.
enum Broker {
    /// Running, or exited and not reaped yet.
    Running(Supervised),
    /// No process: in tests, a thread plays the broker, and is cut off once
    /// its channel is shut down.
    Thread,
    /// A thread is killing and reaping it ([`Link::kill`], [`Link::close`]).
    Ending,
    /// Gone: killed or exited, and reaped — or, for a [`Broker::Thread`],
    /// its channel shut down.
    Gone,
}

/// The agent's end of a broker's control channel, and its process.
struct Link {
    /// Written under `send`, read by the grant's reader thread (through a
    /// copy), shut down to end the conversation.
    channel: UnixStream,
    /// Writes from several threads go through this one lock.
    send: Mutex<()>,
    /// The broker's process. Its lock is held only for a moment: never while
    /// the process is killed or waited for, and never together with the
    /// registry's lock.
    broker: Mutex<Broker>,
    /// Notified when the broker is gone.
    ended: Condvar,
    /// The broker is gone ([`Broker::Gone`]), readable without its lock.
    gone: AtomicBool,
}

impl Link {
    fn new(channel: UnixStream, process: Option<Supervised>) -> Link {
        Link {
            channel,
            send: Mutex::new(()),
            broker: Mutex::new(process.map_or(Broker::Thread, Broker::Running)),
            ended: Condvar::new(),
            gone: AtomicBool::new(false),
        }
    }

    fn broker(&self) -> MutexGuard<'_, Broker> {
        self.broker.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the broker is gone: its process killed or exited, and
    /// reaped. Only then is it contained without its confirmation.
    fn is_gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    /// Note that the broker is gone, and wake whoever waits for that.
    fn mark_gone(&self, mut broker: MutexGuard<'_, Broker>) {
        *broker = Broker::Gone;
        self.gone.store(true, Ordering::SeqCst);
        drop(broker);
        self.ended.notify_all();
    }

    /// Send one message, whole by `deadline` (see [`Link::send_all`]).
    fn send(&self, message: &ToBroker, deadline: Instant) -> io::Result<()> {
        self.send_all(std::slice::from_ref(message), deadline)
    }

    /// Send messages in this order, whole by `deadline`, with no other
    /// writer's message between them. The lock that orders the writers is
    /// tried rather than waited for, until `deadline`: a writer stuck on a
    /// broker that does not read holds up no other writer past that writer's
    /// own deadline.
    fn send_all(&self, messages: &[ToBroker], deadline: Instant) -> io::Result<()> {
        let frames = messages
            .iter()
            .map(broker_protocol::encode)
            .collect::<io::Result<Vec<_>>>()?;
        let _turn = loop {
            match self.send.try_lock() {
                Ok(turn) => break turn,
                Err(TryLockError::Poisoned(turn)) => break turn.into_inner(),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "another message to the broker was still being written",
                    ));
                }
            }
        };
        frames
            .iter()
            .try_for_each(|frame| write_all_by(&self.channel, frame, deadline))
    }

    /// End the conversation: the broker exits at once when its channel ends.
    fn shutdown(&self) {
        let _ = self.channel.shutdown(Shutdown::Both);
    }

    /// Kill the broker now: its channel ends, and its process group is killed
    /// and the leader reaped. Returns once the broker is gone, whoever ends
    /// it: a kill or a close already under way on another thread is waited
    /// for, and a close still waiting for the broker to exit is cut short.
    fn kill(&self) {
        self.shutdown();
        let mut broker = self.broker();
        loop {
            match std::mem::replace(&mut *broker, Broker::Ending) {
                Broker::Running(process) => {
                    drop(broker);
                    // Kills the group, then reaps the leader.
                    drop(process);
                    self.mark_gone(self.broker());
                    return;
                }
                Broker::Thread | Broker::Gone => {
                    self.mark_gone(broker);
                    return;
                }
                Broker::Ending => {
                    broker = self.ended.wait(broker).unwrap_or_else(|p| p.into_inner());
                }
            }
        }
    }

    /// End the conversation and wait for the broker to exit, killing its
    /// process group if it is still there [`EXIT_KILL_DELAY`] later. Returns
    /// once the broker is gone, as [`Link::kill`] does.
    fn close(&self) {
        self.shutdown();
        let deadline = Instant::now() + EXIT_KILL_DELAY;
        let mut broker = self.broker();
        loop {
            match &*broker {
                Broker::Gone => return,
                Broker::Thread => {
                    self.mark_gone(broker);
                    return;
                }
                Broker::Ending => {
                    broker = self.ended.wait(broker).unwrap_or_else(|p| p.into_inner());
                }
                Broker::Running(process) => {
                    // An error says nothing more will be learnt by waiting.
                    let exited = !matches!(process.exited(), Ok(None));
                    if exited || Instant::now() >= deadline {
                        let Broker::Running(process) =
                            std::mem::replace(&mut *broker, Broker::Ending)
                        else {
                            unreachable!("matched as running");
                        };
                        drop(broker);
                        drop(process);
                        self.mark_gone(self.broker());
                        return;
                    }
                    // Look again in a moment; a kill may come meanwhile.
                    broker = self
                        .ended
                        .wait_timeout(broker, Duration::from_millis(10))
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
            }
        }
    }

    /// How the broker's process ended, once it has, by `deadline`; `None`
    /// when it has not, or is no longer this link's to look at (killed, or
    /// being killed).
    fn exit_by(&self, deadline: Instant) -> Option<Exit> {
        loop {
            match &*self.broker() {
                Broker::Running(process) => {
                    if let Ok(Some(exit)) = process.exited() {
                        return Some(exit);
                    }
                }
                _ => return None,
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// One grant, as the registry knows it. A grant that has ended is no longer
/// in the registry.
struct Grant {
    meta: Arc<GrantMeta>,
    /// Order of creation, for listings.
    seq: u64,
    /// The run it belongs to.
    run: u64,
    var: String,
    profile: BrokerProfile,
    command: String,
    /// When it was created, RFC 3339, local time.
    started: String,
    /// When its maximum lifetime passes.
    deadline: BootInstant,
    state: State,
    /// Why it ended (the first reason wins).
    reason: Option<EndReason>,
    /// Who ended it, for its end record, when someone did by hand.
    ended_by: Option<String>,
    /// Requests admitted: each spent a use.
    admitted: u64,
    /// Admitted requests whose end the broker reported.
    finished: u64,
    /// Requests the agent refused.
    refused: u64,
    /// Requests the broker refused before asking, as its confirmation of a
    /// revocation reports them.
    broker_refused: Option<u64>,
    /// Admissions asked for and not answered yet, by number: each holds a
    /// use and a slot. The audit thread answers each once its record is
    /// written; a revocation answers those still waiting at once.
    waiting: BTreeSet<u64>,
    /// Admitted requests whose end is not reported yet, by number: their
    /// route.
    open: BTreeMap<u64, String>,
    /// The number of the last request the broker asked to admit.
    last_admit: u64,
    /// Its broker, from the moment its process exists: entered, and sent its
    /// install, under the registry's lock ([`Registry::register`]).
    link: Option<Arc<Link>>,
    /// Its broker answered ready and its conversation is served
    /// ([`Registry::attach`]): a revocation tells it, and its reader thread
    /// removes the grant once the broker has exited. A broker that has not
    /// is killed by a revocation, and the grant is removed by its run.
    attached: bool,
    /// When the confirmation of its revocation is due: set when the
    /// revocation is decided for a grant that has a broker.
    revoke_due: Option<Instant>,
    /// [`ToBroker::Revoke`] was written to its broker, or is being written:
    /// only then may the broker confirm.
    told: bool,
    /// Its broker confirmed the revocation: it sends nothing more.
    confirmed: bool,
    /// Its broker is to be killed: its confirmation is no longer waited for,
    /// but its end is ([`Link::kill`]). A request, not the kill itself.
    kill_requested: bool,
    /// Its `created` record was written: its end is recorded too.
    created_recorded: bool,
    end_recorded: bool,
}

impl Grant {
    /// Requests in flight: admitted and not finished, or being admitted.
    fn in_flight(&self) -> usize {
        self.open.len() + self.waiting.len()
    }

    /// Whether a new request may be admitted now, and why not: the grant is
    /// still admitting ([`Grant::admitting`]), and the uses and slots that
    /// the admitted and waiting requests hold leave one for it.
    fn admissible(&self, now: BootInstant) -> Result<(), AdmissionRefusal> {
        self.admitting(now)?;
        if let Some(limit) = self.profile.max_requests
            && self.admitted + self.waiting.len() as u64 >= limit
        {
            return Err(AdmissionRefusal::Exhausted);
        }
        if self.in_flight() >= MAX_IN_FLIGHT as usize {
            return Err(AdmissionRefusal::TooManyInFlight);
        }
        Ok(())
    }

    /// Whether the grant admits requests at all now: it is active and its
    /// lifetime has not passed. A waiting admission, which holds its use and
    /// slot already, is checked against this alone.
    fn admitting(&self, now: BootInstant) -> Result<(), AdmissionRefusal> {
        match self.state {
            State::Active => {}
            State::Exhausted => return Err(AdmissionRefusal::Exhausted),
            // Before the command starts nobody can hold the token; a broker
            // that asks then is answered as for a grant that ended.
            State::Starting | State::Revoked => return Err(AdmissionRefusal::Revoked),
        }
        if now >= self.deadline {
            return Err(AdmissionRefusal::Expired);
        }
        Ok(())
    }

    /// The end record, if one is due: once, for a grant whose creation was
    /// recorded. Admissions still waiting — their broker is gone — count as
    /// refused.
    fn end_record(&mut self) -> Option<EndRecord> {
        if !self.created_recorded || self.end_recorded {
            return None;
        }
        self.end_recorded = true;
        Some(EndRecord {
            reason: self.reason.unwrap_or(EndReason::BrokerFailed),
            counts: AuditRequestCounts {
                admitted: self.admitted,
                finished: self.finished,
                unknown: self.admitted.saturating_sub(self.finished),
                refused: self.refused
                    + self.waiting.len() as u64
                    + self.broker_refused.unwrap_or(0),
            },
            detail: self.ended_by.clone(),
        })
    }
}

/// A grant's end, as its record says it.
#[derive(Debug)]
struct EndRecord {
    reason: EndReason,
    counts: AuditRequestCounts,
    detail: Option<String>,
}

/// Work for a grant's audit thread, in the order the broker's messages
/// arrived.
enum Job {
    /// Record an admission the reader reserved, then decide on it and
    /// answer it — unless a revocation answered it meanwhile.
    Admit { request: u64, route: String },
    /// Record the end of an admitted request.
    Finished {
        request: u64,
        route: String,
        outcome: RequestOutcome,
        status: Option<u16>,
        bytes_sent: u64,
        bytes_received: u64,
    },
    /// Record the grant's end.
    End(EndRecord),
    /// The broker confirmed the revocation: record the grant's end, with
    /// what its requests became once every message before the confirmation
    /// was dealt with.
    Confirmed,
}

/// What a grant's reader does with a message that keeps to the
/// conversation, once it is counted.
enum Next {
    /// Hand it to the grant's audit thread.
    Job(Job),
    /// Send this answer now: a refused admission needs no record.
    Answer(ToBroker),
}

/// Which grants an event ends.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Which<'a> {
    /// Every grant.
    All,
    /// Those an automatic lock — the screen lock, a suspend, the idle
    /// timeout — ends: those whose profile says that the automatic locks
    /// end them, and every grant still starting, whatever its profile. A
    /// run's grants are entered under the lock that reads its credentials,
    /// so a lock comes either before (the run fails, nothing was read) or
    /// after, and then ends them (ADR 0013, preparing a run's grants).
    AutomaticLock,
    /// Those of one run.
    Run(u64),
    /// Those of these entries, by UUID.
    Entries(&'a [String]),
    /// The one with this ID.
    Grant(&'a str),
    /// Those whose lifetime has passed by then.
    ExpiredAt(BootInstant),
}

impl Which<'_> {
    fn selects(&self, grant: &Grant) -> bool {
        match self {
            Which::All => true,
            Which::AutomaticLock => {
                grant.state == State::Starting
                    || grant.profile.automatic_locks == AutomaticLocks::End
            }
            Which::Run(run) => grant.run == *run,
            Which::Entries(uuids) => uuids.iter().any(|uuid| *uuid == grant.meta.entry_uuid),
            Which::Grant(id) => grant.meta.id == *id,
            Which::ExpiredAt(now) => grant.state.live() && grant.deadline <= *now,
        }
    }
}

struct Inner {
    /// Every grant that has not ended (its broker has not exited), by ID.
    grants: BTreeMap<String, Grant>,
    next_seq: u64,
    next_run: u64,
}

/// [`Registry::room_for`], under the registry's lock. The refusal says how
/// many of the grants held are revoked: revoking frees no room, since a
/// revoked grant keeps its broker and its port until its command ends.
fn room(inner: &Inner, asked: usize) -> Result<(), String> {
    let held = inner.grants.len();
    if held + asked <= MAX_GRANTS {
        return Ok(());
    }
    if asked > MAX_GRANTS {
        return Err(format!(
            "a run can have at most {MAX_GRANTS} grants; this one asks for {asked}"
        ));
    }
    let revoked = inner.grants.values().filter(|g| !g.state.live()).count();
    Err(format!(
        "at most {MAX_GRANTS} grants can exist at once, and {held} do, {revoked} of them \
         revoked: a grant is kept until its command ends, even once revoked; this run asks for \
         {asked} more, so wait for some of those commands to end (`rusthorse grants` lists them)"
    ))
}

/// The registry of grants: the one authority for their states, counters and
/// limits (see the module's documentation).
pub(crate) struct Registry {
    inner: Mutex<Inner>,
    /// Notified when a grant confirms a revocation or ends, or its broker is
    /// killed.
    changed: Condvar,
    audit: Arc<dyn Recorder>,
    /// The timer was started, or its start tried ([`Registry::start_timer`]).
    timer: AtomicBool,
    /// The timer could not start: no grant is entered.
    no_timer: AtomicBool,
}

/// Why a broker does not serve its grant once the grant ended while the
/// broker was being started.
const ENDED_WHILE_STARTING: &str = "the grant ended while its broker was starting";

impl Registry {
    /// An empty registry that writes its records to `audit`.
    pub(crate) fn new(audit: Arc<dyn Recorder>) -> Arc<Registry> {
        Arc::new(Registry {
            inner: Mutex::new(Inner {
                grants: BTreeMap::new(),
                next_seq: 0,
                next_run: 0,
            }),
            changed: Condvar::new(),
            audit,
            timer: AtomicBool::new(false),
            no_timer: AtomicBool::new(false),
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Refused when the timer that ends grants could not start: a grant
    /// whose lifetime nothing would end is not served (fail closed).
    fn timer_running(&self) -> Result<(), String> {
        if self.no_timer.load(Ordering::SeqCst) {
            return Err(
                "the agent could not start the timer that ends grants when their lifetime \
                 passes, so it serves no grant; restart the agent"
                    .into(),
            );
        }
        Ok(())
    }

    /// Whether the grant `id` is still starting.
    fn starting(&self, id: &str) -> bool {
        self.inner()
            .grants
            .get(id)
            .is_some_and(|g| g.state == State::Starting)
    }

    /// `why` a broker of the grant `id` failed to start serving — or, when
    /// the grant is no longer starting, that it ended meanwhile: whatever
    /// else went wrong then (a revocation kills such a broker) follows from
    /// that.
    fn ended_or(&self, id: &str, why: String) -> String {
        if self.starting(id) {
            why
        } else {
            ENDED_WHILE_STARTING.into()
        }
    }

    /// The grants that have not ended, revoked ones whose broker still runs
    /// included: each holds a broker and a port.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.inner().grants.len()
    }

    /// The grants that can still be used — starting, active or exhausted —
    /// as `status` counts them: not the revoked ones, whose brokers answer
    /// `403` until their commands end.
    pub(crate) fn count_live(&self) -> usize {
        self.inner()
            .grants
            .values()
            .filter(|g| g.state.live())
            .count()
    }

    /// Whether `asked` more grants fit within [`MAX_GRANTS`], which counts
    /// every grant that has not ended: a revoked one too holds a broker and
    /// a port until its command ends. The refusal says how many are revoked.
    /// None fits when the timer could not start.
    pub(crate) fn room_for(&self, asked: usize) -> Result<(), String> {
        self.timer_running()?;
        room(&self.inner(), asked)
    }

    /// The grants of the entry with this UUID that a change to it would end
    /// now.
    pub(crate) fn count_for_entry(&self, uuid: &str) -> usize {
        self.inner()
            .grants
            .values()
            .filter(|g| g.state.live() && g.meta.entry_uuid == uuid)
            .count()
    }

    /// The grants that have not ended, oldest first; never a token.
    pub(crate) fn list(&self) -> Vec<GrantInfo> {
        let now = BootInstant::now();
        let inner = self.inner();
        let mut grants: Vec<&Grant> = inner.grants.values().collect();
        grants.sort_by_key(|g| g.seq);
        grants
            .into_iter()
            .map(|g| GrantInfo {
                id: g.meta.id.clone(),
                entry: g.meta.entry.clone(),
                var: g.var.clone(),
                destination: g.profile.destination(),
                preset: g.profile.preset,
                command: g.command.clone(),
                requester: g.meta.requester.clone(),
                state: g.state.as_str().to_string(),
                started: g.started.clone(),
                ends_in_secs: now.until(g.deadline).as_secs(),
                requests: g.admitted,
                max_requests: g.profile.max_requests,
                in_flight: u32::try_from(g.in_flight()).unwrap_or(u32::MAX),
                automatic_locks: g.profile.automatic_locks,
            })
            .collect()
    }

    /// Enter a run's grants, as `starting`. The agent calls it under the
    /// same lock that checks the vault's generation and reads the
    /// credentials, so that a lock comes either before (nothing was read)
    /// or after (it ends them). Refused when more than [`MAX_GRANTS`] grants
    /// would then not have ended, and when the timer could not start.
    pub(crate) fn enter(self: &Arc<Self>, grants: Vec<NewGrant>) -> Result<RunGrants, String> {
        self.timer_running()?;
        let mut inner = self.inner();
        room(&inner, grants.len())?;
        let mut ids: Vec<&str> = grants.iter().map(|g| g.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != grants.len() || ids.iter().any(|id| inner.grants.contains_key(*id)) {
            return Err("a grant ID is already in use; try again".into());
        }
        let run = inner.next_run;
        inner.next_run += 1;
        let now = BootInstant::now();
        let started = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
        let mut ids = Vec::with_capacity(grants.len());
        for new in grants {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            ids.push(new.id.clone());
            let grant = Grant {
                meta: Arc::new(GrantMeta {
                    id: new.id.clone(),
                    entry_uuid: new.entry_uuid,
                    entry: new.entry,
                    requester: new.requester,
                }),
                seq,
                run,
                var: new.var,
                profile: new.profile,
                command: new.command,
                started: started.clone(),
                deadline: now.after(new.lifetime),
                state: State::Starting,
                reason: None,
                ended_by: None,
                admitted: 0,
                finished: 0,
                refused: 0,
                broker_refused: None,
                waiting: BTreeSet::new(),
                open: BTreeMap::new(),
                last_admit: 0,
                link: None,
                attached: false,
                revoke_due: None,
                told: false,
                confirmed: false,
                kill_requested: false,
                created_recorded: false,
                end_recorded: false,
            };
            inner.grants.insert(new.id, grant);
        }
        Ok(RunGrants {
            registry: Arc::clone(self),
            run,
            ids,
            listeners: Vec::new(),
            done: false,
        })
    }

    /// Decide that the grants `which` selects end, for `reason`: from this
    /// moment nothing is admitted for them. The [`Ending`] then tells their
    /// brokers and waits for them ([`Ending::complete`]), which the caller
    /// does once it has released the agent's state lock.
    pub(crate) fn decide(self: &Arc<Self>, which: Which<'_>, reason: EndReason) -> Ending {
        self.decide_with(which, reason, None)
    }

    /// [`Registry::decide`], saying in the grants' end records who ended
    /// them.
    pub(crate) fn decide_with(
        self: &Arc<Self>,
        which: Which<'_>,
        reason: EndReason,
        by: Option<String>,
    ) -> Ending {
        let mut ending = Ending {
            registry: Arc::clone(self),
            reason,
            tell: Vec::new(),
            wait: Vec::new(),
            matched: 0,
            newly: 0,
            done: false,
        };
        let now = Instant::now();
        let mut inner = self.inner();
        for grant in inner.grants.values_mut() {
            if !which.selects(grant) {
                continue;
            }
            ending.matched += 1;
            if grant.state == State::Revoked {
                // Ended by an earlier event, perhaps not contained yet: this
                // ending waits for it too (it skips one that is).
                if grant.link.is_some() && !grant.confirmed {
                    ending.wait.push(grant.meta.id.clone());
                }
                continue;
            }
            grant.state = State::Revoked;
            grant.reason = Some(reason);
            grant.ended_by = by.clone();
            ending.newly += 1;
            if let Some(link) = &grant.link {
                if grant.attached {
                    grant.revoke_due = Some(now + REVOKE_SEND_TIMEOUT + REVOKE_CONFIRM_TIMEOUT);
                    ending.tell.push((grant.meta.id.clone(), Arc::clone(link)));
                } else {
                    // Its broker has not answered ready, and has served
                    // nothing: it is killed, not told.
                    grant.kill_requested = true;
                }
                ending.wait.push(grant.meta.id.clone());
            }
        }
        drop(inner);
        self.changed.notify_all();
        ending
    }

    /// End the grants whose lifetime has passed.
    pub(crate) fn expire(self: &Arc<Self>) {
        self.decide(Which::ExpiredAt(BootInstant::now()), EndReason::Expired)
            .complete();
    }

    /// Check the grants' lifetimes every second, on a thread of its own
    /// (once; later calls do nothing). Should that thread not start, the
    /// error is returned and no grant is entered from then on
    /// ([`Registry::enter`] and [`Registry::room_for`] refuse): nothing would
    /// end one when its lifetime passes.
    pub(crate) fn start_timer(self: &Arc<Self>) -> io::Result<()> {
        self.start_timer_with(|timer| {
            thread::Builder::new()
                .name("rusthorse-grants".into())
                .spawn(timer)
                .map(drop)
        })
    }

    /// [`Registry::start_timer`], with the thread started by `spawn`.
    fn start_timer_with(
        self: &Arc<Self>,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.timer.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let weak = Arc::downgrade(self);
        let timer = Box::new(move || {
            loop {
                thread::sleep(EXPIRY_CHECK);
                let Some(registry) = weak.upgrade() else {
                    return;
                };
                registry.expire();
            }
        });
        spawn(timer).inspect_err(|_| self.no_timer.store(true, Ordering::SeqCst))
    }

    /// End every grant for `reason`, then end the conversation with every
    /// broker and wait for them to be gone (the agent is stopping).
    pub(crate) fn stop_all(self: &Arc<Self>, reason: EndReason) {
        self.decide(Which::All, reason).complete();
        let (ids, links): (Vec<String>, Vec<Arc<Link>>) = {
            let inner = self.inner();
            inner
                .grants
                .values()
                .filter_map(|g| g.link.as_ref().map(|l| (g.meta.id.clone(), Arc::clone(l))))
                .unzip()
        };
        for link in &links {
            link.shutdown();
        }
        self.wait_gone(&ids, EXIT_KILL_DELAY + STOP_MARGIN);
    }

    /// Tell the brokers of `links` to revoke, each within
    /// [`REVOKE_SEND_TIMEOUT`], and refuse at once every admission each
    /// still waits for: its broker confirms only once all are answered, and
    /// they must not wait for their records. A broker that cannot be told —
    /// gone, or not reading its channel — is killed.
    fn tell(&self, links: &[(String, Arc<Link>)], reason: EndReason) {
        for (id, link) in links {
            let now = Instant::now();
            let (due, messages) = {
                let mut inner = self.inner();
                let Some(grant) = inner.grants.get_mut(id) else {
                    continue;
                };
                if grant.kill_requested || grant.told || !grant.attached {
                    continue;
                }
                grant.told = true;
                // Answered here, so the audit thread answers none of them;
                // one whose admission record is being written gets a second
                // record saying that it was not forwarded.
                let waiting = std::mem::take(&mut grant.waiting);
                grant.refused += waiting.len() as u64;
                let messages: Vec<ToBroker> = std::iter::once(ToBroker::Revoke { reason })
                    .chain(waiting.into_iter().map(|request| ToBroker::Refused {
                        request,
                        reason: AdmissionRefusal::Revoked,
                    }))
                    .collect();
                (grant.revoke_due.unwrap_or(now), messages)
            };
            let deadline = due.min(now + REVOKE_SEND_TIMEOUT);
            if link.send_all(&messages, deadline).is_err() {
                self.kill(id, link);
            }
        }
    }

    /// Wait until the broker of each of the grants `ids` is contained: it
    /// confirmed the revocation, or it is gone (killed or exited, and
    /// reaped). A broker whose confirmation is overdue, or whose kill was
    /// asked for (by this revocation or another), is killed here — or, when
    /// another thread is killing it already, waited for: a kill that was only
    /// asked for is not taken as done.
    fn wait_confirmed(&self, ids: &[String]) {
        let mut inner = self.inner();
        loop {
            let now = Instant::now();
            let mut kill = Vec::new();
            let mut next: Option<Instant> = None;
            for id in ids {
                let Some(grant) = inner.grants.get_mut(id) else {
                    // Removed: its broker exited and was reaped.
                    continue;
                };
                let Some(link) = grant.link.clone() else {
                    continue;
                };
                if grant.confirmed || link.is_gone() {
                    continue;
                }
                // A broker that was told has a due time from its decision;
                // one that was not is killed at once.
                let due = grant.revoke_due.unwrap_or(now);
                if grant.kill_requested || now >= due {
                    grant.kill_requested = true;
                    kill.push(link);
                } else {
                    next = Some(next.map_or(due, |n| n.min(due)));
                }
            }
            if !kill.is_empty() {
                drop(inner);
                for link in kill {
                    // Returns once it is gone, whoever kills it.
                    link.kill();
                }
                self.changed.notify_all();
                inner = self.inner();
                continue;
            }
            let Some(next) = next else {
                return;
            };
            inner = self
                .changed
                .wait_timeout(inner, next.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Wait until none of the grants `ids` is left with a broker, at most
    /// `limit`; then kill the brokers of those left, and wait a moment for
    /// their threads. A grant whose broker never answered ready has no
    /// thread to remove it: its broker being gone is enough.
    fn wait_gone(&self, ids: &[String], limit: Duration) {
        let left = |inner: &Inner| -> Vec<Arc<Link>> {
            ids.iter()
                .filter_map(|id| inner.grants.get(id))
                .filter(|g| g.attached || g.link.as_ref().is_some_and(|l| !l.is_gone()))
                .filter_map(|g| g.link.clone())
                .collect()
        };
        let deadline = Instant::now() + limit;
        let mut inner = self.inner();
        loop {
            let left = left(&inner);
            if left.is_empty() {
                return;
            }
            let now = Instant::now();
            if now >= deadline {
                drop(inner);
                for link in &left {
                    link.kill();
                }
                // Their reader threads remove them as soon as they see the
                // channels end.
                let until = Instant::now() + STOP_MARGIN;
                let mut inner = self.inner();
                while ids
                    .iter()
                    .any(|id| inner.grants.get(id).is_some_and(|g| g.attached))
                    && Instant::now() < until
                {
                    inner = self
                        .changed
                        .wait_timeout(inner, until.saturating_duration_since(Instant::now()))
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                return;
            }
            inner = self
                .changed
                .wait_timeout(inner, deadline - now)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Kill a grant's broker: it is broken, or did not take or confirm a
    /// revocation in time. A grant not ended yet ends (`broker_failed`).
    /// The kill is asked for first, so that a revocation meanwhile kills the
    /// broker too or waits for it ([`Registry::wait_confirmed`]); this
    /// returns once the broker is gone.
    fn kill(&self, id: &str, link: &Link) {
        if let Some(grant) = self.inner().grants.get_mut(id) {
            grant.kill_requested = true;
            if grant.state.live() {
                grant.state = State::Revoked;
                grant.reason = Some(EndReason::BrokerFailed);
            }
        }
        link.kill();
        self.changed.notify_all();
    }

    /// A broken broker: its grant ends (`broker_failed`), it is killed.
    fn violation(&self, id: &str) {
        let link = self.inner().grants.get(id).and_then(|g| g.link.clone());
        if let Some(link) = link {
            self.kill(id, &link);
        }
    }

    /// Enter the broker being started for the grant `id`, and send it its
    /// `install` with the listening socket, both under the registry's lock,
    /// which every revocation takes to decide: a revocation comes either
    /// before — the grant is no longer starting, so the broker gets nothing,
    /// no credential, and is killed — or after, and then kills the broker
    /// and waits for it to be gone ([`Registry::decide`]), whether it has
    /// answered ready or not. The install is written without waiting
    /// ([`send_install`]), so that the lock is never held over a wait. A
    /// broker whose install cannot be sent is killed, and stays entered
    /// until it is gone, so that a revocation meanwhile waits for it too. In
    /// tests, where a thread plays the broker, `process` and `install` are
    /// `None`.
    fn register(
        &self,
        id: &str,
        channel: UnixStream,
        process: Option<Supervised>,
        install: Option<(ToBroker, &TcpListener)>,
    ) -> Result<Arc<Link>, String> {
        let link = Arc::new(Link::new(channel, process));
        let mut inner = self.inner();
        let entered = match inner.grants.get_mut(id) {
            Some(grant) if grant.state == State::Starting && grant.link.is_none() => {
                grant.link = Some(Arc::clone(&link));
                let sent = install.map_or(Ok(()), |(install, listener)| {
                    send_install(&link.channel, listener, install)
                });
                if sent.is_err() {
                    grant.kill_requested = true;
                }
                sent
            }
            _ => Err(ENDED_WHILE_STARTING.into()),
        };
        drop(inner);
        if entered.is_err() {
            link.kill();
            self.changed.notify_all();
        }
        entered.map(|()| link)
    }

    /// Serve the conversation with the broker of the grant `id`, entered
    /// with [`Registry::register`], which answered [`FromBroker::Ready`]:
    /// start the thread that reads it and the thread that writes its
    /// records. Refused — and the broker killed — when the grant is no
    /// longer starting: it ended meanwhile, and its broker must not serve it.
    fn attach(self: &Arc<Self>, id: &str, link: &Arc<Link>) -> Result<(), String> {
        let refuse = |why: String| {
            if let Some(grant) = self.inner().grants.get_mut(id) {
                grant.attached = false;
                grant.kill_requested = true;
            }
            link.kill();
            self.changed.notify_all();
            Err(why)
        };
        let reader = match link.channel.try_clone() {
            Ok(reader) => reader,
            Err(e) => return refuse(format!("cannot copy its channel: {e}")),
        };
        let meta = {
            let mut inner = self.inner();
            match inner.grants.get_mut(id) {
                Some(grant)
                    if grant.state == State::Starting
                        && !grant.kill_requested
                        && grant.link.as_ref().is_some_and(|l| Arc::ptr_eq(l, link)) =>
                {
                    grant.attached = true;
                    Arc::clone(&grant.meta)
                }
                _ => {
                    drop(inner);
                    return refuse(ENDED_WHILE_STARTING.into());
                }
            }
        };
        let (jobs, queue) = mpsc::sync_channel(JOB_QUEUE);
        let started = (|| -> io::Result<()> {
            let (registry, recorded, recording) =
                (Arc::clone(self), Arc::clone(&meta), Arc::clone(link));
            thread::Builder::new()
                .name("rusthorse-grant-audit".into())
                .spawn(move || registry.record_jobs(&recorded, &recording, queue))?;
            let (registry, grant, answering) = (Arc::clone(self), id.to_string(), Arc::clone(link));
            thread::Builder::new()
                .name("rusthorse-grant".into())
                .spawn(move || registry.read_broker(&grant, &reader, &answering, jobs))?;
            Ok(())
        })();
        if let Err(e) = started {
            return refuse(format!("cannot start a thread for it: {e}"));
        }
        Ok(())
    }

    /// [`Registry::register`] and [`Registry::attach`] at once, for a
    /// broker played by a thread of the test.
    #[cfg(test)]
    fn attach_channel(self: &Arc<Self>, id: &str, channel: UnixStream) -> Result<(), String> {
        let link = self.register(id, channel, None, None)?;
        self.attach(id, &link)
    }

    /// Read a broker until its channel ends, checking every message, and
    /// answer at once the admissions it refuses.
    fn read_broker(
        self: &Arc<Self>,
        id: &str,
        channel: &UnixStream,
        link: &Link,
        jobs: mpsc::SyncSender<Job>,
    ) {
        loop {
            match broker_protocol::read_message::<FromBroker>(channel, None) {
                // A broker never sends descriptors.
                Ok((message, fds)) if fds.is_empty() => match self.on_message(id, message) {
                    Ok(Next::Job(job)) => {
                        let _ = jobs.send(job);
                    }
                    Ok(Next::Answer(answer)) => {
                        // A broker that does not take it is broken.
                        if link.send(&answer, Instant::now() + ANSWER_TIMEOUT).is_err() {
                            self.violation(id);
                            break;
                        }
                    }
                    Err(()) => {
                        self.violation(id);
                        break;
                    }
                },
                // Descriptors (closed as they are dropped), a frame too
                // large, a message that does not decode.
                Ok(_) => {
                    self.violation(id);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    self.violation(id);
                    break;
                }
                // The channel ended.
                Err(_) => break,
            }
        }
        if let Some(end) = self.channel_ended(id) {
            let _ = jobs.send(Job::End(end));
        }
    }

    /// Check one message of a grant's broker against the conversation, and
    /// count it. An admission is refused at once, or reserved — a use and a
    /// slot — for the audit thread to record and answer. `Err` is a
    /// violation: nothing was counted.
    fn on_message(&self, id: &str, message: FromBroker) -> Result<Next, ()> {
        let mut inner = self.inner();
        let grant = inner.grants.get_mut(id).ok_or(())?;
        // Nothing comes after the confirmation of a revocation.
        if grant.confirmed {
            return Err(());
        }
        match message {
            // The first was the answer to the install.
            FromBroker::Ready { .. } => Err(()),
            FromBroker::Admit {
                request,
                method,
                route,
            } => {
                if Some(request) != grant.last_admit.checked_add(1) {
                    return Err(());
                }
                // Only a route of the grant's own profile, written as audit
                // records write it: never a raw path.
                let known = grant
                    .profile
                    .spec()
                    .route(&route)
                    .is_some_and(|r| r.method == method);
                if !known {
                    return Err(());
                }
                grant.last_admit = request;
                match grant.admissible(BootInstant::now()) {
                    Ok(()) => {
                        grant.waiting.insert(request);
                        Ok(Next::Job(Job::Admit { request, route }))
                    }
                    Err(reason) => {
                        grant.refused += 1;
                        Ok(Next::Answer(ToBroker::Refused { request, reason }))
                    }
                }
            }
            FromBroker::Finished {
                request,
                outcome,
                status,
                bytes_sent,
                bytes_received,
            } => {
                let route = grant.open.remove(&request).ok_or(())?;
                grant.finished += 1;
                Ok(Next::Job(Job::Finished {
                    request,
                    route,
                    outcome,
                    status,
                    bytes_sent,
                    bytes_received,
                }))
            }
            FromBroker::Revoked { refused } => {
                if !grant.told {
                    return Err(());
                }
                grant.confirmed = true;
                grant.broker_refused = Some(refused);
                drop(inner);
                self.changed.notify_all();
                Ok(Next::Job(Job::Confirmed))
            }
        }
    }

    /// A broker's channel ended: wait for it to exit (killing its group if
    /// it is still there [`EXIT_KILL_DELAY`] later), and remove its grant.
    /// Returns its end record, if one is due.
    fn channel_ended(&self, id: &str) -> Option<EndRecord> {
        let link = self.inner().grants.get(id).and_then(|g| g.link.clone());
        if let Some(link) = link {
            link.close();
        }
        let mut inner = self.inner();
        let mut grant = inner.grants.remove(id)?;
        drop(inner);
        if grant.state.live() {
            // Nobody asked: the broker failed.
            grant.state = State::Revoked;
            grant.reason = Some(EndReason::BrokerFailed);
        }
        self.changed.notify_all();
        grant.end_record()
    }

    /// Write the records of a grant's requests and end, and decide its
    /// admissions, in the order its broker sent them. It never waits for a
    /// broker's confirmation.
    fn record_jobs(self: &Arc<Self>, meta: &GrantMeta, link: &Link, queue: mpsc::Receiver<Job>) {
        for job in queue {
            match job {
                Job::Admit { request, route } => self.admit(meta, link, request, &route),
                Job::Finished {
                    request,
                    route,
                    outcome,
                    status,
                    bytes_sent,
                    bytes_received,
                } => {
                    let mut event = meta.event("broker_request", outcome.as_str());
                    event.request = Some(request);
                    event.route = Some(route);
                    event.status = status;
                    event.bytes_sent = Some(bytes_sent);
                    event.bytes_received = Some(bytes_received);
                    if self.audit.record(&event).is_err() {
                        // Without the records of its requests, the grant
                        // admits nothing more: decided now, and its broker
                        // told and waited for by another thread.
                        self.decide(Which::Grant(&meta.id), EndReason::AuditFailed)
                            .complete_elsewhere();
                    }
                }
                Job::End(end) => self.record_end(meta, end),
                Job::Confirmed => {
                    let end = self
                        .inner()
                        .grants
                        .get_mut(&meta.id)
                        .and_then(Grant::end_record);
                    if let Some(end) = end {
                        self.record_end(meta, end);
                    }
                }
            }
        }
    }

    /// Decide on an admission the reader reserved, and answer it: check that
    /// it is still waiting and the grant still admitting; write the
    /// admission record durably; check both again; answer. A revocation may
    /// answer it at any moment before the last check, and then nothing more
    /// is sent.
    fn admit(&self, meta: &GrantMeta, link: &Link, request: u64, route: &str) {
        // Ended or expired since it was reserved: refused, and not recorded.
        let early = {
            let mut inner = self.inner();
            let Some(grant) = inner.grants.get_mut(&meta.id) else {
                return;
            };
            if !grant.waiting.contains(&request) {
                // A revocation answered it already.
                return;
            }
            grant.admitting(BootInstant::now()).err().map(|reason| {
                grant.waiting.remove(&request);
                grant.refused += 1;
                ToBroker::Refused { request, reason }
            })
        };
        if let Some(answer) = early {
            self.answer(meta, link, &answer);
            return;
        }
        let mut event = meta.event("broker_request", "admitted");
        event.request = Some(request);
        event.route = Some(route.to_string());
        let recorded = self.audit.record(&event).is_ok();
        let answer = self.admission(meta, request, route, recorded);
        if recorded && !matches!(answer, Some(ToBroker::Admitted { .. })) {
            // Its admission was recorded, and then the grant ended: the
            // record of its end says that it was not forwarded.
            let mut event = meta
                .event("broker_request", RequestOutcome::NotForwarded.as_str())
                .detail("refused: the grant ended while its admission was being recorded");
            event.request = Some(request);
            event.route = Some(route.to_string());
            let _ = self.audit.record(&event);
        }
        if let Some(answer) = answer {
            self.answer(meta, link, &answer);
        }
    }

    /// The answer to a waiting admission once its record was written, or
    /// could not be (see [`Registry::admit`]); `None` when it has none to
    /// get from here: a revocation answered it meanwhile, or its broker is
    /// gone.
    fn admission(
        &self,
        meta: &GrantMeta,
        request: u64,
        route: &str,
        recorded: bool,
    ) -> Option<ToBroker> {
        let mut inner = self.inner();
        let grant = inner.grants.get_mut(&meta.id)?;
        if !grant.waiting.remove(&request) {
            return None;
        }
        let refused = |reason| Some(ToBroker::Refused { request, reason });
        if !recorded {
            grant.refused += 1;
            return refused(AdmissionRefusal::AuditFailed);
        }
        // Ended while the record was written: refused, though recorded.
        if let Err(reason) = grant.admitting(BootInstant::now()) {
            grant.refused += 1;
            return refused(reason);
        }
        grant.admitted += 1;
        grant.open.insert(request, route.to_string());
        if grant
            .profile
            .max_requests
            .is_some_and(|limit| grant.admitted >= limit)
        {
            grant.state = State::Exhausted;
        }
        Some(ToBroker::Admitted { request })
    }

    /// Send the answer to an admission; a broker that does not take it is
    /// broken.
    fn answer(&self, meta: &GrantMeta, link: &Link, answer: &ToBroker) {
        if link.send(answer, Instant::now() + ANSWER_TIMEOUT).is_err() {
            self.violation(&meta.id);
        }
    }

    /// Write a grant's end record (best effort).
    fn record_end(&self, meta: &GrantMeta, end: EndRecord) {
        let mut event = meta.event("grant", "ended");
        event.reason = Some(end.reason.as_str().to_string());
        event.requests = Some(end.counts);
        event.detail = end.detail;
        let _ = self.audit.record(&event);
    }
}

/// Grants an event ended, whose brokers are still to be told and waited for.
/// Dropping it does that too.
#[must_use = "an ending must be completed once the state lock is released"]
pub(crate) struct Ending {
    registry: Arc<Registry>,
    reason: EndReason,
    tell: Vec<(String, Arc<Link>)>,
    wait: Vec<String>,
    matched: usize,
    newly: usize,
    done: bool,
}

impl Ending {
    /// The grants it concerns: those it ended, and those ended before.
    pub(crate) fn matched(&self) -> usize {
        self.matched
    }

    /// The grants it ended (the others were ended before).
    pub(crate) fn ended(&self) -> usize {
        self.newly
    }

    /// Tell the brokers at once, then wait for them together until each is
    /// contained: it has confirmed, or it is gone, killed and reaped — when
    /// it cannot be told within [`REVOKE_SEND_TIMEOUT`], has not confirmed
    /// within [`REVOKE_CONFIRM_TIMEOUT`] after that, or never answered ready
    /// (it is killed at once). A kill under way on another thread is waited
    /// for.
    pub(crate) fn complete(mut self) {
        self.finish();
    }

    /// [`Ending::complete`] on a thread of its own, for a thread that must
    /// never wait for a broker's confirmation: a grant's audit thread, which
    /// may have to answer the admissions that the broker waits for before it
    /// confirms. The grants have ended already, so nothing is admitted for
    /// them meanwhile. Should no thread start, the brokers still to be told
    /// are killed.
    fn complete_elsewhere(mut self) {
        self.done = true;
        let tell = std::mem::take(&mut self.tell);
        let wait = std::mem::take(&mut self.wait);
        // Nothing to tell: each broker it concerns was told by an earlier
        // ending, which waits for it.
        if tell.is_empty() {
            return;
        }
        let (registry, reason, telling) = (Arc::clone(&self.registry), self.reason, tell.clone());
        let started = thread::Builder::new()
            .name("rusthorse-revoke".into())
            .spawn(move || {
                registry.tell(&telling, reason);
                registry.wait_confirmed(&wait);
            });
        if started.is_err() {
            for (id, link) in &tell {
                self.registry.kill(id, link);
            }
        }
    }

    fn finish(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let tell = std::mem::take(&mut self.tell);
        self.registry.tell(&tell, self.reason);
        let wait = std::mem::take(&mut self.wait);
        self.registry.wait_confirmed(&wait);
    }
}

impl Drop for Ending {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Ends the grants of one run, for the thread that watches its connection.
#[derive(Clone)]
pub(crate) struct RunEnder {
    registry: Arc<Registry>,
    run: u64,
}

impl RunEnder {
    /// End the run's grants (those not ended yet) and wait for their
    /// brokers.
    pub(crate) fn end(&self, reason: EndReason) {
        self.registry
            .decide(Which::Run(self.run), reason)
            .complete();
    }
}

/// The grants of one run, from their entry to the end of the command: it
/// holds the run's listening sockets, so that their ports cannot be taken by
/// another program while the command may use them, even after a broker
/// failed. Finishing it — or dropping it, on any way out of the run — ends
/// the grants, stops their brokers and releases the ports.
pub(crate) struct RunGrants {
    registry: Arc<Registry>,
    run: u64,
    ids: Vec<String>,
    listeners: Vec<TcpListener>,
    done: bool,
}

impl RunGrants {
    /// Something that ends these grants from another thread.
    pub(crate) fn ender(&self) -> RunEnder {
        RunEnder {
            registry: Arc::clone(&self.registry),
            run: self.run,
        }
    }

    /// Note that the `created` record of the grant `id` was written: its
    /// end is recorded too.
    pub(crate) fn mark_created(&self, id: &str) {
        if let Some(grant) = self.registry.inner().grants.get_mut(id) {
            grant.created_recorded = true;
        }
    }

    /// The seconds the grant `id` has left, for its install: at least 1, at
    /// most its profile's maximum lifetime.
    pub(crate) fn lifetime_secs(&self, id: &str) -> u64 {
        let inner = self.registry.inner();
        let Some(grant) = inner.grants.get(id) else {
            return 1;
        };
        let left = BootInstant::now().until(grant.deadline);
        let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
        secs.clamp(1, u64::from(grant.profile.max_lifetime_minutes) * 60)
    }

    /// Start a broker for each of `installs` (one per grant of the run, in
    /// any order), as ADR 0013 says: a listening socket on 127.0.0.1 at a
    /// port the kernel chooses, a socket pair for the control channel, the
    /// program with no arguments, an empty environment, `/` as working
    /// directory, its own process group, standard input and output the
    /// channel and standard error `/dev/null`; then [`ToBroker::Install`]
    /// with the socket attached, and [`FromBroker::Ready`] from each by one
    /// deadline, `ready_timeout` from now. Returns each grant's port, in the
    /// order of `installs`.
    ///
    /// Each broker is entered in the registry and sent its install under the
    /// registry's lock, only if its grant is still starting
    /// ([`Registry::register`]): a grant that ended before gets no install,
    /// and one that ends later has its broker killed and waited for by the
    /// revocation that ends it, whether it answered ready or not. On a
    /// failure, every broker started is left for [`RunGrants::finish`] (or
    /// the drop), which the run calls at once: it tells those serving to
    /// revoke and stops them, and kills the others. The error never holds a
    /// secret.
    pub(crate) fn start(
        &mut self,
        program: &Path,
        installs: Vec<Install>,
        ready_timeout: Duration,
    ) -> Result<Vec<u16>, String> {
        struct Pending {
            id: String,
            link: Arc<Link>,
            listener: TcpListener,
            port: u16,
        }
        let deadline = Instant::now() + ready_timeout;
        let mut pending = Vec::with_capacity(installs.len());
        for install in installs {
            let id = install.grant.clone();
            let started = (|| {
                if Instant::now() >= deadline {
                    return Err("no time was left to start it".to_string());
                }
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .map_err(|e| format!("cannot listen on 127.0.0.1: {e}"))?;
                let port = listener
                    .local_addr()
                    .map_err(|e| format!("cannot read the port it listens on: {e}"))?
                    .port();
                let (ours, theirs) =
                    UnixStream::pair().map_err(|e| format!("cannot create a socket pair: {e}"))?;
                let process = spawn(program, theirs)
                    .map_err(|e| format!("cannot start {}: {e}", program.display()))?;
                // Entered in the registry and given its install at once,
                // under its lock; refused, and killed, if the grant is no
                // longer starting.
                let install = (ToBroker::Install(install), &listener);
                let link = self
                    .registry
                    .register(&id, ours, Some(process), Some(install))?;
                Ok(Pending {
                    id: id.clone(),
                    link,
                    listener,
                    port,
                })
            })();
            pending.push(started.map_err(|why| self.registry.ended_or(&id, why))?);
        }
        let mut ports = Vec::with_capacity(pending.len());
        for started in pending {
            await_ready(&started.link, &started.id, deadline)
                .and_then(|()| self.registry.attach(&started.id, &started.link))
                .map_err(|why| self.registry.ended_or(&started.id, why))?;
            self.listeners.push(started.listener);
            ports.push(started.port);
        }
        Ok(ports)
    }

    /// Make every grant of the run active, if every one is still starting
    /// with its broker ready; otherwise none.
    pub(crate) fn activate(&self) -> Result<(), String> {
        let mut inner = self.registry.inner();
        let ready = self.ids.iter().all(|id| {
            inner
                .grants
                .get(id)
                .is_some_and(|g| g.state == State::Starting && g.attached)
        });
        if !ready {
            return Err(
                "a grant of the run ended while it was being prepared (the vault was locked, or \
                 a grant was revoked)"
                    .into(),
            );
        }
        for id in &self.ids {
            if let Some(grant) = inner.grants.get_mut(id) {
                grant.state = State::Active;
            }
        }
        Ok(())
    }

    /// The command is over: end the grants not ended yet for `reason`, stop
    /// their brokers (each exits once its channel ends; its group is killed
    /// if it is still there [`EXIT_KILL_DELAY`] later), and release the
    /// ports.
    pub(crate) fn finish(mut self, reason: EndReason) {
        self.stop(reason);
    }

    fn stop(&mut self, reason: EndReason) {
        if self.done {
            return;
        }
        self.done = true;
        // Kills the brokers that never answered ready, and waits for them.
        self.registry
            .decide(Which::Run(self.run), reason)
            .complete();
        let mut links = Vec::new();
        let mut orphans = Vec::new();
        {
            let mut inner = self.registry.inner();
            for id in &self.ids {
                let Some(grant) = inner.grants.get(id) else {
                    continue;
                };
                match &grant.link {
                    // Its reader thread removes it once its broker exits.
                    Some(link) if grant.attached => links.push(Arc::clone(link)),
                    // No broker, or one that never served and is gone: no
                    // thread removes it, so it is removed here.
                    _ => {
                        if let Some(mut grant) = inner.grants.remove(id)
                            && let Some(end) = grant.end_record()
                        {
                            orphans.push((Arc::clone(&grant.meta), end));
                        }
                    }
                }
            }
        }
        self.registry.changed.notify_all();
        // The brokers are told first; the records can wait.
        for link in &links {
            link.shutdown();
        }
        for (meta, end) in orphans {
            self.registry.record_end(&meta, end);
        }
        self.registry
            .wait_gone(&self.ids, EXIT_KILL_DELAY + STOP_MARGIN);
        self.listeners.clear();
    }
}

impl Drop for RunGrants {
    fn drop(&mut self) {
        self.stop(EndReason::CommandEnded);
    }
}

/// Start the broker program with `channel` as its standard input and output.
fn spawn(program: &Path, channel: UnixStream) -> io::Result<Supervised> {
    let output = channel.try_clone()?;
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(channel)))
        .stdout(Stdio::from(OwnedFd::from(output)))
        .stderr(Stdio::null());
    Supervised::spawn(cmd)
}

/// Send a broker its install, with the listening socket attached, without
/// waiting: the registry's lock is held ([`Registry::register`]). The
/// channel is new and empty, and a frame is at most
/// [`broker_protocol::MAX_FRAME`] bytes, which a socket buffer of the
/// usual size (Linux's default is about 200 KiB) takes at once; a channel
/// that does not take it whole is a failure — the broker is not served —
/// never a wait.
fn send_install(
    channel: &UnixStream,
    listener: &TcpListener,
    install: ToBroker,
) -> Result<(), String> {
    let sent = channel
        .set_nonblocking(true)
        .and_then(|()| broker_protocol::write_message(channel, &install, &[listener.as_fd()]));
    drop(install);
    let blocking = channel.set_nonblocking(false);
    sent.and(blocking)
        .map_err(|e| format!("cannot send it its grant: {e}"))
}

/// Read a broker's [`FromBroker::Ready`] by `deadline`, and check it.
fn await_ready(link: &Link, grant: &str, deadline: Instant) -> Result<(), String> {
    match broker_protocol::read_message::<FromBroker>(&link.channel, Some(deadline)) {
        Ok((_, fds)) if !fds.is_empty() => Err("it sent descriptors with its answer".into()),
        Ok((
            FromBroker::Ready {
                version,
                grant: got,
            },
            _,
        )) => {
            if version != broker_protocol::VERSION {
                return Err(format!(
                    "it speaks version {version} of the control protocol, not {}",
                    broker_protocol::VERSION
                ));
            }
            if got != grant {
                return Err("it answered for another grant".into());
            }
            Ok(())
        }
        Ok(_) => Err("its first answer was not ready".into()),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Err("it did not answer in time".into()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            let exit = link.exit_by(Instant::now() + Duration::from_millis(500));
            Err(match exit {
                Some(exit) => format!("it ended without answering ({exit})"),
                None => "it closed its channel without answering".into(),
            })
        }
        Err(e) => Err(format!("cannot read its answer: {e}")),
    }
}

/// What a broker run's approval dialog shows for one grant (ADR 0013,
/// decision 7): which variables get the token and the broker's address, for
/// which entry, then the whole profile ([`BrokerProfile::describe`]).
pub(crate) fn grant_details(
    var: &str,
    url_var: Option<&str>,
    entry: &str,
    profile: &BrokerProfile,
) -> Vec<(String, String)> {
    let mut receives = format!("{var} ← a token for {entry}");
    if let Some(url_var) = url_var {
        receives.push_str(&format!("; {url_var} ← the broker's address"));
    }
    let mut details = vec![("Grant".to_string(), receives)];
    details.extend(profile.describe());
    details
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_profile::{Preset, ProfileRequest};
    use std::os::fd::AsFd;

    /// How long a test waits for something that should happen at once.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// A function run once, inside the next matching record.
    type Hook = Box<dyn FnOnce() + Send>;

    /// An audit log in memory, which refuses the records whose outcome is
    /// listed in `refuse`, and runs `hook` (once) inside the next record of
    /// the outcome `hook_on`, before it is written.
    #[derive(Default)]
    struct Log {
        records: Mutex<Vec<AuditEvent>>,
        refuse: Mutex<Vec<String>>,
        hook_on: Mutex<Option<String>>,
        hook: Mutex<Option<Hook>>,
    }

    impl Recorder for Log {
        fn record(&self, event: &AuditEvent) -> io::Result<()> {
            let hook = {
                let on = self.hook_on.lock().expect("lock");
                if on.as_deref() == Some(event.outcome.as_str()) {
                    self.hook.lock().expect("lock").take()
                } else {
                    None
                }
            };
            if let Some(hook) = hook {
                hook();
            }
            if self.refuse.lock().expect("lock").contains(&event.outcome) {
                return Err(io::Error::other("the test refuses this record"));
            }
            self.records.lock().expect("lock").push(event.clone());
            Ok(())
        }
    }

    impl Log {
        fn refuse(&self, outcome: &str) {
            self.refuse.lock().expect("lock").push(outcome.into());
        }

        fn accept_all(&self) {
            self.refuse.lock().expect("lock").clear();
        }

        fn records(&self) -> Vec<AuditEvent> {
            self.records.lock().expect("lock").clone()
        }

        fn of(&self, action: &str) -> Vec<AuditEvent> {
            self.records()
                .into_iter()
                .filter(|e| e.action == action)
                .collect()
        }

        /// The end record of the grant `id`, once it is written.
        fn end_of(&self, id: &str) -> AuditEvent {
            wait_for(|| {
                self.of("grant")
                    .into_iter()
                    .find(|e| e.outcome == "ended" && e.grant.as_deref() == Some(id))
            })
        }
    }

    /// Hold the next record of `outcome` inside `log`, as a slow disk
    /// would, until the first returned end sends (or is dropped: then for at
    /// most [`PATIENCE`]); the second end says when the record is held.
    fn hold_next(log: &Log, outcome: &str) -> (mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (release, released) = mpsc::channel::<()>();
        let (entered, held) = mpsc::channel::<()>();
        *log.hook_on.lock().expect("lock") = Some(outcome.into());
        *log.hook.lock().expect("lock") = Some(Box::new(move || {
            let _ = entered.send(());
            let _ = released.recv_timeout(PATIENCE);
        }));
        (release, held)
    }

    /// Wait until `f` gives something, at most [`PATIENCE`].
    fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> T {
        let until = Instant::now() + PATIENCE;
        loop {
            if let Some(found) = f() {
                return found;
            }
            assert!(Instant::now() < until, "waited too long");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn anthropic() -> BrokerProfile {
        ProfileRequest::new(Preset::Anthropic)
            .resolve()
            .expect("profile")
    }

    fn new_grant(id: &str, entry: &str, profile: BrokerProfile, lifetime: Duration) -> NewGrant {
        NewGrant {
            id: id.into(),
            entry_uuid: format!("uuid-of-{entry}"),
            entry: format!("{entry} (uuid-of-)"),
            var: "ANTHROPIC_API_KEY".into(),
            profile,
            command: "claude".into(),
            requester: "rusthorse[1] ← bash[2]".into(),
            lifetime,
        }
    }

    /// When a [`FakeBroker`] confirms a revocation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Confirm {
        /// Never: it ignores revocations.
        Never,
        /// As soon as it is told.
        AtOnce,
        /// As `rusthorse-broker` does: once every admission it asked for is
        /// answered, after reporting each request admitted and not finished
        /// as closed by the revocation; and it asks for no admission once
        /// told.
        AfterAnswers,
    }

    /// What a [`FakeBroker`] knows of its conversation.
    #[derive(Default)]
    struct Book {
        /// Admissions asked for and not answered yet.
        asked: BTreeSet<u64>,
        /// Requests admitted and not reported finished.
        open: BTreeSet<u64>,
        /// Told to revoke.
        told: bool,
        /// Confirmed the revocation.
        confirmed: bool,
    }

    /// The broker's side of a control channel, played by the test: a
    /// thread reads what the agent sends, and confirms revocations as
    /// `confirm` says, reporting `refused` requests refused before
    /// admission.
    struct FakeBroker {
        confirm: Confirm,
        /// Taken before `writer` when both are.
        book: Arc<Mutex<Book>>,
        writer: Arc<Mutex<UnixStream>>,
        received: mpsc::Receiver<ToBroker>,
        ended: Arc<AtomicBool>,
    }

    impl FakeBroker {
        fn new(channel: UnixStream, confirm: Confirm, refused: u64) -> FakeBroker {
            let reader = channel.try_clone().expect("clone");
            let writer = Arc::new(Mutex::new(channel));
            let book = Arc::new(Mutex::new(Book::default()));
            let (tx, received) = mpsc::channel();
            let ended = Arc::new(AtomicBool::new(false));
            let (answer, kept, done) = (Arc::clone(&writer), Arc::clone(&book), Arc::clone(&ended));
            thread::spawn(move || {
                while let Ok((message, _)) =
                    broker_protocol::read_message::<ToBroker>(&reader, None)
                {
                    {
                        let mut book = kept.lock().expect("lock");
                        match &message {
                            ToBroker::Admitted { request } => {
                                book.asked.remove(request);
                                book.open.insert(*request);
                            }
                            ToBroker::Refused { request, .. } => {
                                book.asked.remove(request);
                            }
                            ToBroker::Revoke { .. } => book.told = true,
                            ToBroker::Install(_) => {}
                        }
                        let now = match confirm {
                            Confirm::Never => false,
                            Confirm::AtOnce => matches!(message, ToBroker::Revoke { .. }),
                            Confirm::AfterAnswers => {
                                book.told && !book.confirmed && book.asked.is_empty()
                            }
                        };
                        if now {
                            book.confirmed = true;
                            let closed = if confirm == Confirm::AfterAnswers {
                                std::mem::take(&mut book.open)
                            } else {
                                BTreeSet::new()
                            };
                            let writer = answer.lock().expect("lock");
                            for request in closed {
                                let _ = broker_protocol::write_message(
                                    &writer,
                                    &FromBroker::Finished {
                                        request,
                                        outcome: RequestOutcome::Revoked,
                                        status: None,
                                        bytes_sent: 0,
                                        bytes_received: 0,
                                    },
                                    &[],
                                );
                            }
                            let _ = broker_protocol::write_message(
                                &writer,
                                &FromBroker::Revoked { refused },
                                &[],
                            );
                        }
                    }
                    if tx.send(message).is_err() {
                        break;
                    }
                }
                done.store(true, Ordering::SeqCst);
            });
            FakeBroker {
                confirm,
                book,
                writer,
                received,
                ended,
            }
        }

        /// Send `message` — except, from a broker that confirms only once
        /// answered, an admission asked for once it was told to revoke.
        fn send(&self, message: &FromBroker) {
            let mut book = self.book.lock().expect("lock");
            match message {
                FromBroker::Admit { .. } if self.confirm == Confirm::AfterAnswers && book.told => {
                    return;
                }
                FromBroker::Admit { request, .. } => {
                    book.asked.insert(*request);
                }
                FromBroker::Finished { request, .. } => {
                    book.open.remove(request);
                }
                _ => {}
            }
            let writer = self.writer.lock().expect("lock");
            // The agent may have shut the channel down already.
            let _ = broker_protocol::write_message(&writer, message, &[]);
        }

        /// The next message from the agent.
        fn next(&self) -> ToBroker {
            self.received.recv_timeout(PATIENCE).expect("a message")
        }

        fn admit(&self, request: u64, route: &str) -> ToBroker {
            let method = route.split(' ').next().unwrap_or_default().to_string();
            self.send(&FromBroker::Admit {
                request,
                method,
                route: route.into(),
            });
            self.next()
        }

        fn finish(&self, request: u64, outcome: RequestOutcome) {
            self.send(&FromBroker::Finished {
                request,
                outcome,
                status: Some(200),
                bytes_sent: 100 + request,
                bytes_received: 1000 + request,
            });
        }

        /// Whether the agent ended the channel (killed the broker, or
        /// stopped it), by `PATIENCE`.
        fn sees_the_end(&self) -> bool {
            let until = Instant::now() + PATIENCE;
            while Instant::now() < until {
                if self.ended.load(Ordering::SeqCst) {
                    return true;
                }
                thread::sleep(Duration::from_millis(5));
            }
            false
        }
    }

    /// A registry with one active grant of `profile`, whose broker the
    /// returned [`FakeBroker`] plays.
    struct Setup {
        log: Arc<Log>,
        registry: Arc<Registry>,
        run: Option<RunGrants>,
        id: String,
        broker: FakeBroker,
    }

    fn setup_with(
        profile: BrokerProfile,
        lifetime: Duration,
        confirm: Confirm,
        refused: u64,
    ) -> Setup {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(&id, "KEY", profile, lifetime)])
            .expect("enter");
        run.mark_created(&id);
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        registry.attach_channel(&id, agent_end).expect("attach");
        run.activate().expect("activate");
        Setup {
            log,
            registry,
            run: Some(run),
            id,
            broker: FakeBroker::new(broker_end, confirm, refused),
        }
    }

    fn setup() -> Setup {
        setup_with(anthropic(), Duration::from_secs(3600), Confirm::AtOnce, 0)
    }

    fn admitted(request: u64) -> String {
        format!("{:?}", ToBroker::Admitted { request })
    }

    fn refused(request: u64, reason: AdmissionRefusal) -> String {
        format!("{:?}", ToBroker::Refused { request, reason })
    }

    fn info(registry: &Registry, id: &str) -> GrantInfo {
        registry
            .list()
            .into_iter()
            .find(|g| g.id == id)
            .expect("listed")
    }

    #[test]
    fn requests_are_admitted_in_order_within_the_limit_in_flight() {
        let s = setup();
        let route = "POST /v1/messages";
        for n in 1..=u64::from(MAX_IN_FLIGHT) {
            assert_eq!(format!("{:?}", s.broker.admit(n, route)), admitted(n));
        }
        let info_now = info(&s.registry, &s.id);
        assert_eq!(info_now.in_flight, MAX_IN_FLIGHT);
        assert_eq!(info_now.requests, u64::from(MAX_IN_FLIGHT));
        // One more is refused, and costs nothing.
        let next = u64::from(MAX_IN_FLIGHT) + 1;
        assert_eq!(
            format!("{:?}", s.broker.admit(next, route)),
            refused(next, AdmissionRefusal::TooManyInFlight)
        );
        assert_eq!(info(&s.registry, &s.id).requests, u64::from(MAX_IN_FLIGHT));
        // Finishing in another order than they started frees their slots.
        for n in [5, 2, 16, 9] {
            s.broker.finish(n, RequestOutcome::Completed);
        }
        wait_for(|| (info(&s.registry, &s.id).in_flight == MAX_IN_FLIGHT - 4).then_some(()));
        // The numbering goes on from the refused one.
        assert_eq!(
            format!("{:?}", s.broker.admit(next + 1, "GET /v1/models")),
            admitted(next + 1)
        );
        assert_eq!(info(&s.registry, &s.id).in_flight, MAX_IN_FLIGHT - 3);
        // The other requests end, one of them never reported.
        for n in (1..=u64::from(MAX_IN_FLIGHT))
            .chain([next + 1])
            .filter(|n| ![5, 2, 16, 9, 3].contains(n))
        {
            s.broker.finish(n, RequestOutcome::ClientClosed);
        }
        wait_for(|| (info(&s.registry, &s.id).in_flight == 1).then_some(()));
        let Setup {
            log,
            registry,
            mut run,
            id,
            broker,
        } = s;
        run.take().expect("run").finish(EndReason::CommandEnded);
        assert!(matches!(
            broker.next(),
            ToBroker::Revoke {
                reason: EndReason::CommandEnded
            }
        ));
        assert!(broker.sees_the_end());
        assert_eq!(registry.count(), 0);
        let end = log.end_of(&id);
        assert_eq!(end.reason.as_deref(), Some("command_ended"));
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 17,
                finished: 16,
                unknown: 1,
                refused: 1,
            })
        );
        // One record per admission, before its answer, and one per end.
        let requests = log.of("broker_request");
        let admissions: Vec<u64> = requests
            .iter()
            .filter(|e| e.outcome == "admitted")
            .filter_map(|e| e.request)
            .collect();
        assert_eq!(
            admissions,
            (1..=u64::from(MAX_IN_FLIGHT))
                .chain([next + 1])
                .collect::<Vec<_>>()
        );
        let finished = requests.iter().filter(|e| e.outcome != "admitted").count();
        assert_eq!(finished, 16);
        let first = requests
            .iter()
            .find(|e| e.outcome == "completed" && e.request == Some(5))
            .expect("the end of request 5");
        assert_eq!(first.grant.as_deref(), Some(id.as_str()));
        assert_eq!(first.route.as_deref(), Some(route));
        assert_eq!(first.status, Some(200));
        assert_eq!(first.bytes_sent, Some(105));
        assert_eq!(first.bytes_received, Some(1005));
        assert_eq!(first.requester, "rusthorse[1] ← bash[2]");
        assert_eq!(first.entries, vec!["KEY (uuid-of-)".to_string()]);
    }

    #[test]
    fn a_request_limit_exhausts_the_grant_and_lets_admitted_requests_finish() {
        let profile = ProfileRequest {
            max_requests: Some(2),
            ..ProfileRequest::new(Preset::Anthropic)
        }
        .resolve()
        .expect("profile");
        let s = setup_with(profile, Duration::from_secs(3600), Confirm::AtOnce, 4);
        let route = "POST /v1/messages/count_tokens";
        assert_eq!(format!("{:?}", s.broker.admit(1, route)), admitted(1));
        assert_eq!(info(&s.registry, &s.id).state, "active");
        assert_eq!(format!("{:?}", s.broker.admit(2, route)), admitted(2));
        let exhausted = info(&s.registry, &s.id);
        assert_eq!(exhausted.state, "exhausted");
        assert_eq!(exhausted.requests, 2);
        assert_eq!(exhausted.max_requests, Some(2));
        assert_eq!(
            format!("{:?}", s.broker.admit(3, route)),
            refused(3, AdmissionRefusal::Exhausted)
        );
        // The admitted ones finish, the second first.
        s.broker.finish(2, RequestOutcome::Completed);
        s.broker.finish(1, RequestOutcome::NotForwarded);
        wait_for(|| (info(&s.registry, &s.id).in_flight == 0).then_some(()));
        assert_eq!(info(&s.registry, &s.id).state, "exhausted");
        let ending = s.registry.decide(Which::Grant(&s.id), EndReason::Revoked);
        assert_eq!((ending.matched(), ending.ended()), (1, 1));
        ending.complete();
        let end = s.log.end_of(&s.id);
        assert_eq!(end.reason.as_deref(), Some("revoked"));
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 2,
                finished: 2,
                unknown: 0,
                refused: 1 + 4,
            })
        );
    }

    #[test]
    fn a_broker_that_breaks_the_conversation_is_killed_and_counts_nothing() {
        type Break = fn(&FakeBroker);
        let cases: &[(&str, Break)] = &[
            ("a number that skips", |b| {
                b.send(&FromBroker::Admit {
                    request: 3,
                    method: "POST".into(),
                    route: "POST /v1/messages".into(),
                })
            }),
            ("a number used again", |b| {
                b.send(&FromBroker::Admit {
                    request: 1,
                    method: "POST".into(),
                    route: "POST /v1/messages".into(),
                })
            }),
            ("a number from zero", |b| {
                b.send(&FromBroker::Admit {
                    request: 0,
                    method: "POST".into(),
                    route: "POST /v1/messages".into(),
                })
            }),
            ("a route of no preset", |b| {
                b.send(&FromBroker::Admit {
                    request: 2,
                    method: "POST".into(),
                    route: "POST /v1/messages/batches".into(),
                })
            }),
            ("a raw path", |b| {
                b.send(&FromBroker::Admit {
                    request: 2,
                    method: "GET".into(),
                    route: "GET /v1/models/claude-x".into(),
                })
            }),
            ("another method", |b| {
                b.send(&FromBroker::Admit {
                    request: 2,
                    method: "GET".into(),
                    route: "POST /v1/messages".into(),
                })
            }),
            ("a finished request not admitted", |b| {
                b.finish(7, RequestOutcome::Completed)
            }),
            ("a request finished twice", |b| {
                b.finish(1, RequestOutcome::Completed);
                b.finish(1, RequestOutcome::Completed);
            }),
            ("a second ready", |b| {
                b.send(&FromBroker::Ready {
                    version: broker_protocol::VERSION,
                    grant: "g0123456789abcdef".into(),
                })
            }),
            ("a confirmation of no revocation", |b| {
                b.send(&FromBroker::Revoked { refused: 0 })
            }),
            ("a frame that is not a message", |b| {
                let writer = b.writer.lock().expect("lock");
                use std::io::Write;
                let _ = (&*writer).write_all(b"\x00\x00\x00\x02{]");
            }),
            ("a frame too large", |b| {
                let writer = b.writer.lock().expect("lock");
                use std::io::Write;
                let _ =
                    (&*writer).write_all(&(broker_protocol::MAX_FRAME as u32 + 1).to_be_bytes());
            }),
            ("descriptors", |b| {
                let writer = b.writer.lock().expect("lock");
                let devnull = std::fs::File::open("/dev/null").expect("devnull");
                let _ = broker_protocol::write_message(
                    &writer,
                    &FromBroker::Admit {
                        request: 2,
                        method: "POST".into(),
                        route: "POST /v1/messages".into(),
                    },
                    &[devnull.as_fd()],
                );
            }),
        ];
        for (what, spoil) in cases {
            let s = setup();
            // One request admitted and still open before the breach.
            assert_eq!(
                format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
                admitted(1),
                "{what}"
            );
            spoil(&s.broker);
            assert!(s.broker.sees_the_end(), "{what}: not killed");
            wait_for(|| (s.registry.count() == 0).then_some(()));
            let end = s.log.end_of(&s.id);
            assert_eq!(end.reason.as_deref(), Some("broker_failed"), "{what}");
            // The offending message changed no counter: the request admitted
            // before it is open, its end unknown — unless the broker reported
            // it before breaking the conversation.
            let finished = u64::from(*what == "a request finished twice");
            assert_eq!(
                end.requests,
                Some(AuditRequestCounts {
                    admitted: 1,
                    finished,
                    unknown: 1 - finished,
                    refused: 0,
                }),
                "{what}"
            );
        }
    }

    #[test]
    fn nothing_may_follow_the_confirmation_of_a_revocation() {
        let s = setup_with(anthropic(), Duration::from_secs(3600), Confirm::AtOnce, 2);
        s.registry.decide(Which::All, EndReason::Locked).complete();
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::Locked
            }
        ));
        let end = s.log.end_of(&s.id);
        assert_eq!(end.reason.as_deref(), Some("locked"));
        // A message after it: killed, and the reason stays the revocation's.
        s.broker.send(&FromBroker::Admit {
            request: 1,
            method: "POST".into(),
            route: "POST /v1/messages".into(),
        });
        assert!(s.broker.sees_the_end());
        wait_for(|| (s.registry.count() == 0).then_some(()));
        assert_eq!(
            s.log
                .of("grant")
                .iter()
                .filter(|e| e.outcome == "ended")
                .count(),
            1
        );
    }

    #[test]
    fn an_admission_that_cannot_be_recorded_is_refused_and_counts_nothing() {
        let s = setup();
        s.log.refuse("admitted");
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
            refused(1, AdmissionRefusal::AuditFailed)
        );
        let now = info(&s.registry, &s.id);
        assert_eq!(
            (now.requests, now.in_flight, now.state.as_str()),
            (0, 0, "active")
        );
        assert!(s.log.of("broker_request").is_empty());
        // Once the log works again, so does the grant.
        s.log.accept_all();
        assert_eq!(
            format!("{:?}", s.broker.admit(2, "POST /v1/messages")),
            admitted(2)
        );
        assert_eq!(info(&s.registry, &s.id).requests, 1);
    }

    #[test]
    fn an_end_that_cannot_be_recorded_revokes_the_grant() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
            admitted(1)
        );
        s.log.refuse("completed");
        s.broker.finish(1, RequestOutcome::Completed);
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::AuditFailed
            }
        ));
        let end = s.log.end_of(&s.id);
        assert_eq!(end.reason.as_deref(), Some("audit_failed"));
        // It admits nothing more (its broker, which confirmed, asks for
        // nothing more either).
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
    }

    #[test]
    fn a_revocation_does_not_need_the_audit_log() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
            admitted(1)
        );
        for outcome in ["ended", "admitted", "completed", "revoked", "unknown"] {
            s.log.refuse(outcome);
        }
        let started = Instant::now();
        s.registry
            .decide(Which::Grant(&s.id), EndReason::Revoked)
            .complete();
        assert!(
            started.elapsed() < REVOKE_CONFIRM_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::Revoked
            }
        ));
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
        // Its end could not be recorded: it ended all the same.
        assert!(s.log.of("grant").is_empty());
    }

    #[test]
    fn an_admission_whose_grant_ends_while_it_is_recorded_is_refused() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        let registry = Arc::clone(&s.registry);
        *s.log.hook_on.lock().expect("lock") = Some("admitted".into());
        *s.log.hook.lock().expect("lock") = Some(Box::new(move || {
            registry.decide(Which::All, EndReason::Revoked).complete();
        }));
        // The revocation comes first, then the refusal of the admission
        // that was waiting for its record.
        let first = s.broker.admit(1, "POST /v1/messages");
        assert!(
            matches!(
                first,
                ToBroker::Revoke {
                    reason: EndReason::Revoked
                }
            ),
            "{first:?}"
        );
        assert_eq!(
            format!("{:?}", s.broker.next()),
            refused(1, AdmissionRefusal::Revoked)
        );
        // The revocation answered it, before its record was written; the
        // grant's end is recorded after that record.
        let end = s.log.end_of(&s.id);
        let outcomes: Vec<String> = s
            .log
            .of("broker_request")
            .into_iter()
            .map(|e| e.outcome)
            .collect();
        assert_eq!(outcomes, ["admitted", "not_forwarded"]);
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 0,
                finished: 0,
                unknown: 0,
                refused: 1,
            })
        );
    }

    /// An admission whose grant's lifetime passes while its record is being
    /// written is refused once the record is written (`expired`), and that
    /// record is followed by one that says it was not forwarded: nothing is
    /// admitted after a grant's lifetime, even before the timer ends it.
    #[test]
    fn an_admission_whose_grant_expires_while_it_is_recorded_is_refused() {
        let s = setup_with(
            anthropic(),
            Duration::from_millis(400),
            Confirm::AfterAnswers,
            0,
        );
        let (release, held) = hold_next(&s.log, "admitted");
        s.broker.send(&FromBroker::Admit {
            request: 1,
            method: "POST".into(),
            route: "POST /v1/messages".into(),
        });
        held.recv_timeout(PATIENCE).expect("the record");
        thread::sleep(Duration::from_millis(500));
        release.send(()).expect("release");
        assert_eq!(
            format!("{:?}", s.broker.next()),
            refused(1, AdmissionRefusal::Expired)
        );
        let recorded: Vec<(Option<u64>, String)> = s
            .log
            .of("broker_request")
            .into_iter()
            .map(|e| (e.request, e.outcome))
            .collect();
        assert_eq!(
            recorded,
            [
                (Some(1), "admitted".to_string()),
                (Some(1), "not_forwarded".to_string())
            ]
        );
        let now = info(&s.registry, &s.id);
        assert_eq!((now.requests, now.in_flight), (0, 0));
    }

    /// A revocation answers at once every admission still waiting — for its
    /// record, or behind it — without waiting for the audit log: a broker
    /// that confirms only once every admission it asked for is answered, as
    /// `rusthorse-broker` does, confirms in time and is not killed, and
    /// nothing is admitted after the decision.
    #[test]
    fn a_revocation_answers_at_once_the_admissions_waiting_for_their_records() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        let (release, held) = hold_next(&s.log, "admitted");
        for request in [1, 2] {
            s.broker.send(&FromBroker::Admit {
                request,
                method: "POST".into(),
                route: "POST /v1/messages".into(),
            });
        }
        held.recv_timeout(PATIENCE).expect("the first record");
        // Both hold a slot: the first waits for its record, the second for
        // its turn.
        wait_for(|| (info(&s.registry, &s.id).in_flight == 2).then_some(()));
        let started = Instant::now();
        s.registry
            .decide(Which::Grant(&s.id), EndReason::Revoked)
            .complete();
        let took = started.elapsed();
        assert!(took < REVOKE_CONFIRM_TIMEOUT, "{took:?}");
        let told: Vec<String> = (0..3).map(|_| format!("{:?}", s.broker.next())).collect();
        assert_eq!(
            told,
            [
                format!(
                    "{:?}",
                    ToBroker::Revoke {
                        reason: EndReason::Revoked
                    }
                ),
                refused(1, AdmissionRefusal::Revoked),
                refused(2, AdmissionRefusal::Revoked),
            ]
        );
        // The first record is written at last: nothing more is sent, and
        // it is followed by one that says it was not forwarded.
        release.send(()).expect("release");
        let end = s.log.end_of(&s.id);
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 0,
                finished: 0,
                unknown: 0,
                refused: 2,
            })
        );
        assert!(
            s.broker
                .received
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "a second answer"
        );
        let recorded: Vec<(Option<u64>, String)> = s
            .log
            .of("broker_request")
            .into_iter()
            .map(|e| (e.request, e.outcome))
            .collect();
        assert_eq!(
            recorded,
            [
                (Some(1), "admitted".to_string()),
                (Some(1), "not_forwarded".to_string())
            ]
        );
        assert!(!s.broker.ended.load(Ordering::SeqCst), "killed");
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
    }

    /// A finished request whose record cannot be written revokes its grant
    /// (`audit_failed`) at once, and an admission asked for while that
    /// record was being written is refused with the revocation: a broker
    /// that confirms only once every admission it asked for is answered
    /// confirms in time, and is not killed.
    #[test]
    fn an_end_that_cannot_be_recorded_holds_up_no_answer() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
            admitted(1)
        );
        s.log.refuse("completed");
        let (release, held) = hold_next(&s.log, "completed");
        s.broker.finish(1, RequestOutcome::Completed);
        held.recv_timeout(PATIENCE).expect("the record of the end");
        s.broker.send(&FromBroker::Admit {
            request: 2,
            method: "POST".into(),
            route: "POST /v1/messages".into(),
        });
        wait_for(|| (info(&s.registry, &s.id).in_flight == 1).then_some(()));
        let started = Instant::now();
        release.send(()).expect("release");
        // In either order: the revocation is told by a thread of its own,
        // and the audit thread may refuse that admission first.
        let mut told = [
            format!("{:?}", s.broker.next()),
            format!("{:?}", s.broker.next()),
        ];
        told.sort();
        let mut expected = [
            format!(
                "{:?}",
                ToBroker::Revoke {
                    reason: EndReason::AuditFailed
                }
            ),
            refused(2, AdmissionRefusal::Revoked),
        ];
        expected.sort();
        assert_eq!(told, expected);
        let end = s.log.end_of(&s.id);
        let took = started.elapsed();
        assert!(took < REVOKE_CONFIRM_TIMEOUT, "{took:?}");
        assert_eq!(end.reason.as_deref(), Some("audit_failed"));
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 1,
                finished: 1,
                unknown: 0,
                refused: 1,
            })
        );
        assert!(!s.broker.ended.load(Ordering::SeqCst), "killed");
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
    }

    /// A grant's audit thread never waits for its broker's confirmation:
    /// once a record that failed has revoked the grant, the next ones are
    /// written at once, while the broker has still not confirmed; a broker
    /// that never does is killed all the same.
    #[test]
    fn records_go_on_while_a_broker_is_revoked() {
        let s = setup_with(anthropic(), Duration::from_secs(3600), Confirm::Never, 0);
        for request in [1, 2] {
            assert_eq!(
                format!("{:?}", s.broker.admit(request, "POST /v1/messages")),
                admitted(request)
            );
        }
        s.log.refuse("completed");
        let started = Instant::now();
        s.broker.finish(1, RequestOutcome::Completed);
        s.broker.finish(2, RequestOutcome::ClientClosed);
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::AuditFailed
            }
        ));
        wait_for(|| {
            s.log
                .of("broker_request")
                .into_iter()
                .find(|e| e.outcome == "client_closed")
        });
        let took = started.elapsed();
        assert!(took < REVOKE_CONFIRM_TIMEOUT / 2, "{took:?}");
        assert!(!s.broker.ended.load(Ordering::SeqCst));
        // Its confirmation overdue: killed.
        assert!(s.broker.sees_the_end(), "not killed");
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("audit_failed"));
    }

    /// Refusals never wait for the audit log: while an admission's record
    /// is being written, a request beyond the grant's limit is refused at
    /// once — the uses held by the admissions still waiting count — and
    /// only the admissions within the limit are recorded.
    #[test]
    fn a_request_beyond_the_limit_is_refused_while_earlier_ones_are_recorded() {
        let profile = ProfileRequest {
            max_requests: Some(2),
            ..ProfileRequest::new(Preset::Anthropic)
        }
        .resolve()
        .expect("profile");
        let s = setup_with(profile, Duration::from_secs(3600), Confirm::AfterAnswers, 0);
        let (release, held) = hold_next(&s.log, "admitted");
        for request in 1..=3 {
            s.broker.send(&FromBroker::Admit {
                request,
                method: "POST".into(),
                route: "POST /v1/messages".into(),
            });
        }
        held.recv_timeout(PATIENCE).expect("the first record");
        let first = s
            .broker
            .received
            .recv_timeout(Duration::from_secs(2))
            .expect("an answer while the record is held");
        assert_eq!(
            format!("{first:?}"),
            refused(3, AdmissionRefusal::Exhausted)
        );
        release.send(()).expect("release");
        assert_eq!(format!("{:?}", s.broker.next()), admitted(1));
        assert_eq!(format!("{:?}", s.broker.next()), admitted(2));
        let now = info(&s.registry, &s.id);
        assert_eq!((now.state.as_str(), now.requests), ("exhausted", 2));
        let recorded: Vec<Option<u64>> = s
            .log
            .of("broker_request")
            .into_iter()
            .map(|e| e.request)
            .collect();
        assert_eq!(recorded, [Some(1), Some(2)]);
    }

    #[test]
    fn a_revocation_is_confirmed_or_the_broker_is_killed_within_the_deadline() {
        // Confirmed: done as soon as the broker says so, with its count of
        // refused requests and who revoked it; the request it closed is
        // finished (`revoked`).
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            3,
        );
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "GET /v1/models")),
            admitted(1)
        );
        let started = Instant::now();
        s.registry
            .decide_with(
                Which::Grant(&s.id),
                EndReason::Revoked,
                Some("revoked by rusthorse[9]".into()),
            )
            .complete();
        assert!(
            started.elapsed() < REVOKE_CONFIRM_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        assert!(
            !s.broker.ended.load(Ordering::SeqCst),
            "a confirming broker is not killed"
        );
        let end = s.log.end_of(&s.id);
        assert_eq!(end.reason.as_deref(), Some("revoked"));
        assert_eq!(end.detail.as_deref(), Some("revoked by rusthorse[9]"));
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 1,
                finished: 1,
                unknown: 0,
                refused: 3,
            })
        );
        // A second revocation finds it ended already, and waits for nothing.
        let again = s.registry.decide(Which::Grant(&s.id), EndReason::Revoked);
        assert_eq!((again.matched(), again.ended()), (1, 0));
        again.complete();

        // Not confirmed: killed once the confirmation is overdue.
        let s = setup_with(anthropic(), Duration::from_secs(3600), Confirm::Never, 0);
        let started = Instant::now();
        s.registry.decide(Which::All, EndReason::Locked).complete();
        let took = started.elapsed();
        assert!(took >= REVOKE_CONFIRM_TIMEOUT, "{took:?}");
        assert!(
            took < REVOKE_SEND_TIMEOUT + REVOKE_CONFIRM_TIMEOUT + Duration::from_millis(500),
            "{took:?}"
        );
        assert!(matches!(s.broker.next(), ToBroker::Revoke { .. }));
        assert!(s.broker.sees_the_end(), "not killed");
        wait_for(|| (s.registry.count() == 0).then_some(()));
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("locked"));
    }

    #[test]
    fn a_broker_that_does_not_read_its_channel_holds_up_no_revocation() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        // A small buffer, which the agent's answers fill at once.
        nix::sys::socket::setsockopt(&agent_end, nix::sys::socket::sockopt::SndBuf, &1)
            .expect("buffer");
        registry.attach_channel(&id, agent_end).expect("attach");
        run.activate().expect("activate");
        // The broker asks and asks, and never reads the answers: the agent's
        // threads that answer are soon stuck writing one, the first holding
        // the lock that orders the writers, until it gives up on the broker;
        // the agent stops reading meanwhile, and then the broker's own
        // writes wait too, until the agent ends the channel.
        let asking = thread::spawn(move || {
            for n in 1..=400u64 {
                let asked = broker_protocol::write_message(
                    &broker_end,
                    &FromBroker::Admit {
                        request: n,
                        method: "POST".into(),
                        route: "POST /v1/messages".into(),
                    },
                    &[],
                );
                if asked.is_err() {
                    break;
                }
            }
            broker_end
        });
        thread::sleep(Duration::from_millis(100));
        // That broker is killed, by the writer or by a revocation that
        // cannot tell it, and the revocation is done within its bounds.
        let started = Instant::now();
        registry.decide(Which::All, EndReason::Revoked).complete();
        let took = started.elapsed();
        assert!(
            took < ANSWER_TIMEOUT + REVOKE_SEND_TIMEOUT + Duration::from_millis(500),
            "{took:?}"
        );
        wait_for(|| (registry.count() == 0).then_some(()));
        drop(asking.join().expect("the broker's writes end"));
        drop(run);
    }

    #[test]
    fn a_revocation_does_not_wait_for_another_writer() {
        let s = setup();
        let link = s
            .registry
            .inner()
            .grants
            .get(&s.id)
            .and_then(|g| g.link.clone())
            .expect("a broker");
        // Another writer has the turn and keeps it, as one stuck writing to
        // a broker that does not read would, until that writer gives up.
        let turn = link.send.lock().expect("lock");
        let registry = Arc::clone(&s.registry);
        let (done, finished) = mpsc::channel();
        let started = Instant::now();
        thread::spawn(move || {
            registry.decide(Which::All, EndReason::Revoked).complete();
            let _ = done.send(started.elapsed());
        });
        let took = finished.recv_timeout(REVOKE_SEND_TIMEOUT + Duration::from_millis(500));
        drop(turn);
        let took = took.expect("the revocation waited for the other writer");
        assert!(took >= REVOKE_SEND_TIMEOUT, "{took:?}");
        // The broker could not be told: killed.
        assert!(s.broker.sees_the_end());
        wait_for(|| (s.registry.count() == 0).then_some(()));
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("revoked"));
    }

    #[test]
    fn a_grant_expires_and_admits_nothing_after_its_lifetime() {
        let s = setup_with(
            anthropic(),
            Duration::from_millis(300),
            Confirm::AfterAnswers,
            0,
        );
        assert_eq!(
            format!("{:?}", s.broker.admit(1, "POST /v1/messages")),
            admitted(1)
        );
        thread::sleep(Duration::from_millis(400));
        assert_eq!(info(&s.registry, &s.id).ends_in_secs, 0);
        assert_eq!(
            format!("{:?}", s.broker.admit(2, "POST /v1/messages")),
            refused(2, AdmissionRefusal::Expired)
        );
        // Refused at once: only the first was recorded as admitted.
        let recorded: Vec<Option<u64>> = s
            .log
            .of("broker_request")
            .into_iter()
            .map(|e| e.request)
            .collect();
        assert_eq!(recorded, [Some(1)]);
        s.registry.expire();
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::Expired
            }
        ));
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("expired"));
        // A grant that has time left is not touched.
        let t = setup();
        t.registry.expire();
        assert_eq!(info(&t.registry, &t.id).state, "active");
    }

    #[test]
    fn the_lifetime_given_to_the_broker_is_what_is_left() {
        let s = setup_with(anthropic(), Duration::from_secs(90), Confirm::AtOnce, 0);
        let run = s.run.as_ref().expect("run");
        let left = run.lifetime_secs(&s.id);
        assert!((89..=90).contains(&left), "{left}");
        // Never more than the profile allows, never less than a second.
        let t = setup_with(
            anthropic(),
            Duration::from_secs(720 * 60 + 500),
            Confirm::AtOnce,
            0,
        );
        assert_eq!(t.run.as_ref().expect("run").lifetime_secs(&t.id), 720 * 60);
        let u = setup_with(anthropic(), Duration::ZERO, Confirm::AtOnce, 0);
        assert_eq!(u.run.as_ref().expect("run").lifetime_secs(&u.id), 1);
    }

    #[test]
    fn an_agent_holds_at_most_the_grants_it_may_serve() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(log as Arc<dyn Recorder>);
        let many: Vec<NewGrant> = (0..MAX_GRANTS)
            .map(|i| {
                new_grant(
                    &broker_protocol::new_grant_id(),
                    &format!("KEY{i}"),
                    anthropic(),
                    Duration::from_secs(60),
                )
            })
            .collect();
        let run = registry.enter(many).expect("as many as allowed");
        assert_eq!(registry.count(), MAX_GRANTS);
        let one = || {
            vec![new_grant(
                &broker_protocol::new_grant_id(),
                "MORE",
                anthropic(),
                Duration::from_secs(60),
            )]
        };
        let err = registry.enter(one()).err().expect("one too many");
        assert!(err.contains("at most 16 grants"), "{err}");
        assert!(err.contains("16 do, 0 of them revoked"), "{err}");
        // Revoked ones still hold a broker and a port until their run ends:
        // the refusal says so, and `status` no longer counts them.
        assert_eq!(registry.count_live(), MAX_GRANTS);
        registry.decide(Which::All, EndReason::Revoked).complete();
        assert_eq!(registry.count_live(), 0);
        let err = registry.enter(one()).err().expect("still too many");
        assert!(err.contains("16 do, 16 of them revoked"), "{err}");
        assert!(
            err.contains("wait for some of those commands to end"),
            "{err}"
        );
        assert_eq!(registry.room_for(1), Err(err));
        // A run that asks for more than any agent serves is told so.
        let all: Vec<NewGrant> = (0..=MAX_GRANTS).map(|_| one().remove(0)).collect();
        run.finish(EndReason::CommandEnded);
        let err = registry
            .enter(all)
            .err()
            .expect("more than any run may have");
        assert_eq!(
            err,
            "a run can have at most 16 grants; this one asks for 17"
        );
        assert_eq!(registry.count(), 0);
        let again = registry.enter(one()).expect("room again");
        // Two grants with the same ID are never entered.
        let id = broker_protocol::new_grant_id();
        let twice = vec![
            new_grant(&id, "A", anthropic(), Duration::from_secs(60)),
            new_grant(&id, "B", anthropic(), Duration::from_secs(60)),
        ];
        assert!(registry.enter(twice).is_err());
        drop(again);
        assert_eq!(registry.count(), 0, "dropping a run ends its grants");
    }

    #[test]
    fn a_grant_that_ends_while_it_starts_never_gets_a_broker() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        assert_eq!(info(&registry, &id).state, "starting");
        // A lock while the broker starts: nothing to tell or wait for yet.
        let started = Instant::now();
        registry.decide(Which::All, EndReason::Locked).complete();
        assert!(started.elapsed() < Duration::from_millis(500));
        // The broker answers ready after that: it is not attached, and is
        // killed (its channel ends).
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        let broker = FakeBroker::new(broker_end, Confirm::AtOnce, 0);
        let err = registry.attach_channel(&id, agent_end).expect_err("ended");
        assert!(err.contains("ended while its broker was starting"), "{err}");
        assert!(broker.sees_the_end());
        assert!(run.activate().is_err(), "none of the run becomes active");
        // The run ends at once: nothing waits for a broker that never was.
        let started = Instant::now();
        run.finish(EndReason::CommandEnded);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(registry.count(), 0);
        assert_eq!(log.end_of(&id).reason.as_deref(), Some("locked"));
    }

    #[test]
    fn a_run_becomes_active_only_whole() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let (a, b) = (
            broker_protocol::new_grant_id(),
            broker_protocol::new_grant_id(),
        );
        let run = registry
            .enter(vec![
                new_grant(&a, "A", anthropic(), Duration::from_secs(60)),
                new_grant(&b, "B", anthropic(), Duration::from_secs(60)),
            ])
            .expect("enter");
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        let broker_a = FakeBroker::new(broker_end, Confirm::AtOnce, 0);
        registry.attach_channel(&a, agent_end).expect("attach");
        // B has no broker yet: neither becomes active.
        assert!(run.activate().is_err());
        assert_eq!(info(&registry, &a).state, "starting");
        // An admission before the command starts is refused, at once:
        // nothing is recorded as admitted.
        assert_eq!(
            format!("{:?}", broker_a.admit(1, "POST /v1/messages")),
            refused(1, AdmissionRefusal::Revoked)
        );
        assert!(log.of("broker_request").is_empty());
        // Not created on record: no end record either.
        run.finish(EndReason::BrokerFailed);
        assert!(broker_a.sees_the_end());
        assert_eq!(registry.count(), 0);
        assert!(log.of("grant").is_empty());
    }

    /// A grant ended after its broker was attached and before its run was
    /// made active — a lock, a revocation, a change to its entry while the
    /// run's other brokers start — never becomes active: the run fails
    /// whole.
    #[test]
    fn a_grant_ended_before_its_run_is_active_never_becomes_active() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        let broker = FakeBroker::new(broker_end, Confirm::AfterAnswers, 0);
        registry.attach_channel(&id, agent_end).expect("attach");
        registry.decide(Which::All, EndReason::Locked).complete();
        assert!(matches!(
            broker.next(),
            ToBroker::Revoke {
                reason: EndReason::Locked
            }
        ));
        assert!(run.activate().is_err());
        assert_eq!(info(&registry, &id).state, "revoked");
        run.finish(EndReason::CommandEnded);
        assert!(broker.sees_the_end());
        assert_eq!(log.end_of(&id).reason.as_deref(), Some("locked"));
    }

    /// The timer ends a grant whose lifetime has passed, and tells its
    /// broker, within about a second.
    #[test]
    fn the_timer_ends_the_grants_whose_lifetime_has_passed() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(1),
            Confirm::AfterAnswers,
            0,
        );
        let started = Instant::now();
        s.registry.start_timer().expect("the timer");
        // Once: a second call starts no other timer.
        s.registry.start_timer().expect("the timer");
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::Expired
            }
        ));
        let took = started.elapsed();
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert_eq!(info(&s.registry, &s.id).state, "revoked");
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("expired"));
        // Grants are still served.
        assert_eq!(s.registry.room_for(1), Ok(()));
    }

    /// Without the timer, nothing would end a grant when its lifetime
    /// passes: when its thread cannot start, no grant is served from then
    /// on (fail closed) — `room_for`, which a run checks before its dialog,
    /// and `enter` refuse, saying why.
    #[test]
    fn no_grant_is_served_when_the_timer_cannot_start() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(log as Arc<dyn Recorder>);
        let err = registry
            .start_timer_with(|_| Err(io::Error::other("no thread for the test")))
            .expect_err("the timer did not start");
        assert_eq!(err.to_string(), "no thread for the test");
        let refused = registry.room_for(1).expect_err("room without a timer");
        assert!(
            refused.contains("could not start the timer that ends grants"),
            "{refused}"
        );
        let entered = registry.enter(vec![new_grant(
            &broker_protocol::new_grant_id(),
            "KEY",
            anthropic(),
            Duration::from_secs(60),
        )]);
        assert_eq!(entered.err(), Some(refused));
        assert_eq!(registry.count(), 0);
        // A later call starts nothing, and changes nothing.
        assert!(registry.start_timer().is_ok());
        assert!(registry.room_for(1).is_err());
    }

    /// A process that plays a broker's process (the conversation is played
    /// by a [`FakeBroker`] on the channel): it runs until it is killed.
    fn helper_process() -> Supervised {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Supervised::spawn(cmd).expect("spawn")
    }

    /// A kill that was asked for is not a kill done: when one revocation
    /// has decided to kill a broker (its confirmation overdue) and has not
    /// killed it yet, a second revocation does not report itself done while
    /// that broker still runs — it kills it, or waits for the kill, and its
    /// process is gone by the time it returns.
    #[test]
    fn a_revocation_racing_another_waits_until_the_broker_is_gone() {
        use crate::supervise::tests::alive;
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        let process = helper_process();
        let pid = process.id();
        let link = registry
            .register(&id, agent_end, Some(process), None)
            .expect("register");
        registry.attach(&id, &link).expect("attach");
        run.activate().expect("activate");
        let broker = FakeBroker::new(broker_end, Confirm::Never, 0);
        // The first revocation will find the process held, as a thread
        // delayed just before the kill would.
        let held = link.broker();
        let first = {
            let registry = Arc::clone(&registry);
            let id = id.clone();
            thread::spawn(move || {
                registry
                    .decide(Which::Grant(&id), EndReason::Revoked)
                    .complete()
            })
        };
        assert!(matches!(broker.next(), ToBroker::Revoke { .. }));
        // Its broker never confirms: the first revocation asks for the kill
        // once the confirmation is overdue.
        wait_for(|| {
            registry
                .inner()
                .grants
                .get(&id)
                .is_some_and(|g| g.kill_requested)
                .then_some(())
        });
        let (done, second) = mpsc::channel();
        {
            let registry = Arc::clone(&registry);
            thread::spawn(move || {
                registry.decide(Which::All, EndReason::Locked).complete();
                let _ = done.send(());
            });
        }
        assert!(
            second.recv_timeout(Duration::from_millis(500)).is_err(),
            "the lock was done while the broker ran"
        );
        assert!(alive(pid), "the broker was killed while held");
        drop(held);
        second.recv_timeout(PATIENCE).expect("the lock is done");
        assert!(!alive(pid), "the lock was done before the broker was gone");
        first.join().expect("the first revocation is done");
        wait_for(|| (registry.count() == 0).then_some(()));
        assert_eq!(log.end_of(&id).reason.as_deref(), Some("revoked"));
        drop(run);
    }

    /// A grant served by a [`FakeBroker`] that never confirms, with
    /// [`helper_process`] as its broker's process: the registry, the run,
    /// the grant, its link, the broker and the process ID.
    fn setup_with_process() -> (
        Arc<Log>,
        Arc<Registry>,
        RunGrants,
        String,
        Arc<Link>,
        FakeBroker,
        u32,
    ) {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        let (agent_end, broker_end) = UnixStream::pair().expect("pair");
        let process = helper_process();
        let pid = process.id();
        let link = registry
            .register(&id, agent_end, Some(process), None)
            .expect("register");
        registry.attach(&id, &link).expect("attach");
        run.activate().expect("activate");
        let broker = FakeBroker::new(broker_end, Confirm::Never, 0);
        (log, registry, run, id, link, broker, pid)
    }

    /// A kill under way on another thread — the process taken, not reaped
    /// yet — is waited for: a revocation that finds it is done only once the
    /// process is gone.
    #[test]
    fn a_revocation_waits_for_a_kill_under_way_on_another_thread() {
        use crate::supervise::tests::alive;
        /// The kill under way on another thread: the process taken out of
        /// the link, not reaped yet. Dropped — also when the test fails, so
        /// that nothing waits for it forever — it kills and reaps the
        /// process, and says so.
        struct KillUnderWay(Option<Supervised>, Arc<Link>);
        impl Drop for KillUnderWay {
            fn drop(&mut self) {
                drop(self.0.take());
                self.1.mark_gone(self.1.broker());
            }
        }
        let (_log, registry, run, _id, link, _broker, pid) = setup_with_process();
        // Another thread has taken the process to kill it, and is slow.
        let Broker::Running(process) = std::mem::replace(&mut *link.broker(), Broker::Ending)
        else {
            panic!("the process runs");
        };
        let under_way = KillUnderWay(Some(process), Arc::clone(&link));
        let (done, revoked) = mpsc::channel();
        {
            let registry = Arc::clone(&registry);
            thread::spawn(move || {
                registry.decide(Which::All, EndReason::Locked).complete();
                let _ = done.send(());
            });
        }
        // A kill of its own returns only once the broker is gone, too.
        let (done, killed) = mpsc::channel();
        {
            let link = Arc::clone(&link);
            thread::spawn(move || {
                link.kill();
                let _ = done.send(());
            });
        }
        // Its confirmation is overdue after REVOKE_SEND_TIMEOUT and
        // REVOKE_CONFIRM_TIMEOUT; it waits for the kill under way after that.
        assert!(
            revoked
                .recv_timeout(
                    REVOKE_SEND_TIMEOUT + REVOKE_CONFIRM_TIMEOUT + Duration::from_millis(500)
                )
                .is_err(),
            "the lock was done while the broker ran"
        );
        assert!(killed.try_recv().is_err(), "a kill returned while it ran");
        assert!(alive(pid));
        // The other thread kills and reaps it, and says so.
        drop(under_way);
        revoked.recv_timeout(PATIENCE).expect("the lock is done");
        killed.recv_timeout(PATIENCE).expect("the kill is done");
        assert!(!alive(pid));
        drop(run);
        assert_eq!(registry.count(), 0);
    }

    /// A broker that closes its channel and does not exit is given a moment
    /// to exit ([`Link::close`]); a revocation meanwhile does not wait for
    /// that moment, nor take it as the end: it kills the broker at once, and
    /// is done once the process is gone.
    #[test]
    fn a_revocation_while_a_broker_is_given_time_to_exit_kills_it_at_once() {
        use crate::supervise::tests::alive;
        let (_log, registry, run, id, _link, broker, pid) = setup_with_process();
        // The broker's channel ends; its process goes on.
        let _ = broker.writer.lock().expect("lock").shutdown(Shutdown::Both);
        thread::sleep(Duration::from_millis(200));
        assert!(alive(pid));
        let started = Instant::now();
        registry
            .decide(Which::Grant(&id), EndReason::Revoked)
            .complete();
        let took = started.elapsed();
        assert!(!alive(pid), "the revocation was done while the broker ran");
        assert!(took < EXIT_KILL_DELAY / 2, "{took:?}");
        drop(run);
        assert_eq!(registry.count(), 0);
    }

    /// A stand-in broker program that writes its process ID to `pid` and
    /// copies whatever it is sent to `received`, and never answers.
    fn copying_broker(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let (program, pid, received) = (
            dir.join("rusthorse-broker"),
            dir.join("pid"),
            dir.join("received"),
        );
        write_program(
            &program,
            &format!(
                "#!/bin/sh\necho $$ > '{pid}.new' && /bin/mv '{pid}.new' '{pid}'\n\
                 exec /bin/cat > '{received}'\n",
                pid = pid.display(),
                received = received.display()
            ),
        );
        (program, pid, received)
    }

    /// Write an executable file from another process, and put it in place at
    /// once: a file that this process held open for writing could not be run
    /// while a process forked meanwhile by another test still held that
    /// descriptor ("Text file busy").
    fn write_program(path: &Path, text: &str) {
        use std::io::Write;
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "cat > \"$1.new\" && chmod 700 \"$1.new\" && mv -f \"$1.new\" \"$1\"",
                "sh",
            ])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .expect("sh");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write");
        assert!(child.wait().expect("wait").success());
    }

    /// An install for the grant `id`, with a fake credential.
    fn install(id: &str) -> Install {
        Install {
            version: broker_protocol::VERSION,
            grant: id.into(),
            token: broker_protocol::new_token(),
            credential: crate::protocol::SecretString::new("sk-ant-test-0000000000000000".into()),
            profile: anthropic(),
            max_in_flight: MAX_IN_FLIGHT,
            max_connections: broker_protocol::MAX_CONNECTIONS,
            lifetime_secs: 60,
        }
    }

    /// A grant that ended before its broker was started — a lock while its
    /// run recorded its creation — gets no install: the broker is entered
    /// in the registry only while its grant is starting, which is checked
    /// before anything is sent to it, so no credential reaches it.
    #[test]
    fn a_grant_that_ended_before_its_broker_started_gets_no_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (program, _, received) = copying_broker(dir.path());
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let mut run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        registry.decide(Which::All, EndReason::Locked).complete();
        let err = run
            .start(&program, vec![install(&id)], Duration::from_secs(2))
            .expect_err("the grant ended");
        assert_eq!(err, ENDED_WHILE_STARTING);
        // Time for a broker that got an install to write it down.
        thread::sleep(Duration::from_millis(300));
        let got = std::fs::read(&received).unwrap_or_default();
        assert!(got.is_empty(), "a broker received {} bytes", got.len());
        assert!(run.activate().is_err());
        run.finish(EndReason::CommandEnded);
        assert_eq!(registry.count(), 0);
        assert_eq!(log.end_of(&id).reason.as_deref(), Some("locked"));
    }

    /// A revocation while a broker has its install and has not answered
    /// ready kills it, and is done only once its process is gone; the run's
    /// start fails at once, saying that the grant ended, without waiting for
    /// the answer that will never come.
    #[test]
    fn a_revocation_kills_a_broker_that_has_not_answered_ready() {
        use crate::supervise::tests::alive;
        let dir = tempfile::tempdir().expect("tempdir");
        let (program, pid_file, received) = copying_broker(dir.path());
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let id = broker_protocol::new_grant_id();
        let mut run = registry
            .enter(vec![new_grant(
                &id,
                "KEY",
                anthropic(),
                Duration::from_secs(60),
            )])
            .expect("enter");
        run.mark_created(&id);
        let started = thread::scope(|scope| {
            let starting =
                scope.spawn(|| run.start(&program, vec![install(&id)], Duration::from_secs(30)));
            // The broker has its install, and does not answer.
            let pid: u32 = wait_for(|| {
                std::fs::read(&received)
                    .ok()
                    .filter(|got| !got.is_empty())?;
                std::fs::read_to_string(&pid_file).ok()?.trim().parse().ok()
            });
            assert!(alive(pid));
            let revoking = Instant::now();
            registry.decide(Which::All, EndReason::Locked).complete();
            assert!(!alive(pid), "the lock was done while the broker ran");
            assert!(
                revoking.elapsed() < Duration::from_secs(2),
                "{:?}",
                revoking.elapsed()
            );
            starting.join().expect("the start ends")
        });
        assert_eq!(started.expect_err("the grant ended"), ENDED_WHILE_STARTING);
        assert!(run.activate().is_err());
        let finishing = Instant::now();
        run.finish(EndReason::CommandEnded);
        assert!(finishing.elapsed() < Duration::from_secs(1));
        assert_eq!(registry.count(), 0);
        assert_eq!(log.end_of(&id).reason.as_deref(), Some("locked"));
    }

    #[test]
    fn each_event_ends_the_grants_it_concerns() {
        let log = Arc::new(Log::default());
        let registry = Registry::new(Arc::clone(&log) as Arc<dyn Recorder>);
        let ending = ProfileRequest {
            automatic_locks: Some(AutomaticLocks::End),
            ..ProfileRequest::new(Preset::Openai)
        }
        .resolve()
        .expect("profile");
        let ids: Vec<String> = (0..6).map(|_| broker_protocol::new_grant_id()).collect();
        // Two runs whose grants are active, and one whose grants are still
        // starting.
        let first = registry
            .enter(vec![
                new_grant(&ids[0], "A", anthropic(), Duration::from_secs(60)),
                new_grant(&ids[1], "B", ending.clone(), Duration::from_secs(60)),
            ])
            .expect("enter");
        let second = registry
            .enter(vec![
                new_grant(&ids[2], "C", anthropic(), Duration::from_secs(60)),
                new_grant(&ids[3], "A", ending.clone(), Duration::from_secs(60)),
            ])
            .expect("enter");
        let mut brokers = Vec::new();
        for (run, served) in [(&first, &ids[..2]), (&second, &ids[2..4])] {
            for id in served {
                let (agent_end, broker_end) = UnixStream::pair().expect("pair");
                brokers.push(FakeBroker::new(broker_end, Confirm::AtOnce, 0));
                registry.attach_channel(id, agent_end).expect("attach");
            }
            run.activate().expect("activate");
        }
        let third = registry
            .enter(vec![
                new_grant(&ids[4], "D", anthropic(), Duration::from_secs(60)),
                new_grant(&ids[5], "E", ending, Duration::from_secs(60)),
            ])
            .expect("enter");
        let state = |id: &str| info(&registry, id).state;
        // The automatic locks: the profiles that say so, and every grant
        // still starting, whatever its profile.
        let e = registry.decide(Which::AutomaticLock, EndReason::ScreenLocked);
        assert_eq!(e.ended(), 4);
        e.complete();
        assert_eq!(
            ids.iter().map(|id| state(id)).collect::<Vec<_>>(),
            [
                "active", "revoked", "active", "revoked", "revoked", "revoked"
            ]
        );
        assert!(third.activate().is_err(), "a run that a lock ended starts");
        // An entry, by UUID: its grants in every run.
        assert_eq!(registry.count_for_entry("uuid-of-A"), 1);
        let uuids = ["uuid-of-A".to_string()];
        let e = registry.decide(Which::Entries(&uuids), EndReason::EntryChanged);
        assert_eq!((e.matched(), e.ended()), (2, 1));
        e.complete();
        assert_eq!(state(&ids[0]), "revoked");
        assert_eq!(registry.count_for_entry("uuid-of-A"), 0);
        // A run: its own grants only.
        let e = registry.decide(Which::Run(second.run), EndReason::CommandEnded);
        assert_eq!((e.matched(), e.ended()), (2, 1));
        e.complete();
        assert_eq!(state(&ids[2]), "revoked");
        third.finish(EndReason::CommandEnded);
        // One grant by its ID, and an ID that names none.
        let e = registry.decide(Which::Grant("g0000000000000000"), EndReason::Revoked);
        assert_eq!(e.matched(), 0);
        e.complete();
        // Who ended it first decides its reason.
        first.finish(EndReason::CommandEnded);
        second.finish(EndReason::CommandEnded);
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn stopping_ends_every_grant_and_its_broker() {
        let s = setup_with(
            anthropic(),
            Duration::from_secs(3600),
            Confirm::AfterAnswers,
            0,
        );
        s.registry.stop_all(EndReason::AgentStopped);
        assert!(matches!(
            s.broker.next(),
            ToBroker::Revoke {
                reason: EndReason::AgentStopped
            }
        ));
        assert!(s.broker.sees_the_end());
        assert_eq!(s.registry.count(), 0);
        assert_eq!(s.log.end_of(&s.id).reason.as_deref(), Some("agent_stopped"));
    }

    #[test]
    fn requests_closed_by_a_revocation_are_counted_as_their_broker_reports_them() {
        let s = setup_with(anthropic(), Duration::from_secs(3600), Confirm::Never, 0);
        for n in 1..=3 {
            assert_eq!(
                format!("{:?}", s.broker.admit(n, "POST /v1/messages")),
                admitted(n)
            );
        }
        // The broker closes them when told to revoke, then confirms.
        let registry = Arc::clone(&s.registry);
        let revoking =
            thread::spawn(move || registry.decide(Which::All, EndReason::Revoked).complete());
        assert!(matches!(s.broker.next(), ToBroker::Revoke { .. }));
        s.broker.finish(2, RequestOutcome::Revoked);
        s.broker.finish(1, RequestOutcome::Unknown);
        s.broker.send(&FromBroker::Revoked { refused: 1 });
        revoking.join().expect("revoked");
        assert!(!s.broker.ended.load(Ordering::SeqCst));
        let end = s.log.end_of(&s.id);
        assert_eq!(
            end.requests,
            Some(AuditRequestCounts {
                admitted: 3,
                finished: 2,
                unknown: 1,
                refused: 1,
            })
        );
        let outcomes: Vec<(Option<u64>, String)> = s
            .log
            .of("broker_request")
            .into_iter()
            .filter(|e| e.outcome != "admitted")
            .map(|e| (e.request, e.outcome))
            .collect();
        assert_eq!(
            outcomes,
            [
                (Some(2), "revoked".to_string()),
                (Some(1), "unknown".to_string())
            ]
        );
    }

    #[test]
    fn listings_show_what_a_grant_allows_and_never_a_token() {
        let s = setup();
        let listed = info(&s.registry, &s.id);
        assert_eq!(listed.entry, "KEY (uuid-of-)");
        assert_eq!(listed.var, "ANTHROPIC_API_KEY");
        assert_eq!(listed.destination, "https://api.anthropic.com");
        assert_eq!(listed.preset, Preset::Anthropic);
        assert_eq!(listed.command, "claude");
        assert_eq!(listed.state, "active");
        assert_eq!(listed.automatic_locks, AutomaticLocks::Continue);
        assert_eq!(listed.max_requests, None);
        assert!(
            (3599..=3600).contains(&listed.ends_in_secs),
            "{}",
            listed.ends_in_secs
        );
        let json = serde_json::to_string(&s.registry.list()).expect("json");
        assert!(!json.contains("rh_"), "{json}");
        assert!(chrono::DateTime::parse_from_rfc3339(&listed.started).is_ok());
    }

    #[test]
    fn the_boot_time_clock_is_the_one_read() {
        use nix::time::{ClockId, clock_gettime};
        let read = |id| {
            let t = clock_gettime(id).expect("clock");
            Duration::new(t.tv_sec() as u64, t.tv_nsec() as u32)
        };
        let before = read(ClockId::CLOCK_BOOTTIME);
        let now = BootInstant::now().0;
        let after = read(ClockId::CLOCK_BOOTTIME);
        assert!(
            before <= now && now <= after,
            "{before:?} {now:?} {after:?}"
        );
    }
}
