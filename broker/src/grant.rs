//! The one grant a broker serves: its token and credential, the requests it
//! asked the agent to admit, those it admitted and has not finished, the
//! requests it refused itself, the body budget, and its revocation.
//!
//! The agent is the authority on the grant's state and limits; this side
//! keeps the conversation of the control channel exact (ADR 0013, "The
//! control channel"): request numbers count from 1 without gaps; each
//! `admit` gets exactly one answer, and only a number that is waiting may be
//! answered; each admitted request gets exactly one `finished`; and once
//! the agent says `revoke`, nothing more is admitted, every open request is
//! closed, the credential is dropped, and `revoked` is sent once every
//! `admit` has been answered and every admitted request has finished —
//! after which nothing else is sent.
//!
//! It also refuses by itself, as a backstop to the agent: a grant being
//! revoked, a grant past its lifetime (on the boot-time clock, so time spent
//! suspended counts), and more requests in flight than the install allows.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusthorse::broker_profile::{BrokerProfile, PresetSpec};
use rusthorse::broker_protocol::{AdmissionRefusal, FromBroker, Install, RequestOutcome};
use rusthorse::protocol::SecretString;
use tokio::sync::{mpsc, oneshot, watch};

use crate::answer::Refusal;

/// The agent's answer to an `admit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Forward the request.
    Admitted,
    /// Do not; answer it locally.
    Refused(AdmissionRefusal),
}

/// Why the broker did not even ask the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// The grant is being revoked, or was.
    Revoked,
    /// The grant's lifetime has passed.
    Expired,
    /// As many requests are in flight as the install allows.
    TooManyInFlight,
}

impl From<Held> for Refusal {
    fn from(held: Held) -> Refusal {
        match held {
            Held::Revoked => Refusal::Revoked,
            Held::Expired => Refusal::Expired,
            Held::TooManyInFlight => Refusal::TooManyInFlight,
        }
    }
}

/// The agent broke the conversation: the broker stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Violation(pub &'static str);

/// How an admitted request ended, as `finished` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ended {
    /// The outcome.
    pub outcome: RequestOutcome,
    /// The destination's status, else the broker's own answer's.
    pub status: Option<u16>,
    /// Bytes of the request body sent to the destination.
    pub bytes_sent: u64,
    /// Bytes of the response body received from the destination.
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Serving,
    /// Told to revoke; `revoked` not sent yet.
    Revoking,
    /// `revoked` sent: nothing more goes to the agent.
    Revoked,
}

struct State {
    /// The number the next `admit` gets.
    next: u64,
    /// Requests whose `admit` is not answered yet.
    waiting: HashMap<u64, oneshot::Sender<Answer>>,
    /// Requests admitted and not finished.
    admitted: BTreeSet<u64>,
    /// Requests refused before their admission was asked.
    refused: u64,
    phase: Phase,
}

/// The grant, shared by every connection and request of the broker.
pub struct Grant {
    token: SecretString,
    /// Dropped, and so wiped, when the grant is revoked.
    credential: Mutex<Option<SecretString>>,
    profile: BrokerProfile,
    spec: &'static PresetSpec,
    max_in_flight: usize,
    /// When the lifetime ends, on the boot-time clock; `None` if that clock
    /// could not be read, which counts as expired.
    expires: Option<Duration>,
    state: Mutex<State>,
    revoked: watch::Sender<bool>,
    to_agent: mpsc::UnboundedSender<FromBroker>,
}

/// The boot-time clock (`CLOCK_BOOTTIME`), which keeps counting while the
/// computer is suspended; `None` if it cannot be read.
pub fn boot_time() -> Option<Duration> {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).ok()?;
    Some(Duration::new(
        u64::try_from(now.tv_sec()).ok()?,
        u32::try_from(now.tv_nsec()).ok()?,
    ))
}

impl Grant {
    /// The grant of a checked `install`, received at `received` on the
    /// boot-time clock ([`boot_time`]; `None` if it could not be read, which
    /// makes the grant expired): its lifetime counts from then. Messages for
    /// the agent go to `to_agent`, in order.
    pub fn new(
        install: Install,
        received: Option<Duration>,
        to_agent: mpsc::UnboundedSender<FromBroker>,
    ) -> Arc<Grant> {
        let lifetime = Duration::from_secs(install.lifetime_secs);
        let expires = received.and_then(|at| at.checked_add(lifetime));
        Self::with_expiry(install, to_agent, expires)
    }

    fn with_expiry(
        install: Install,
        to_agent: mpsc::UnboundedSender<FromBroker>,
        expires: Option<Duration>,
    ) -> Arc<Grant> {
        let Install {
            token,
            credential,
            profile,
            max_in_flight,
            ..
        } = install;
        let spec = profile.spec();
        Arc::new(Grant {
            token,
            credential: Mutex::new(Some(credential)),
            profile,
            spec,
            max_in_flight: max_in_flight as usize,
            expires,
            state: Mutex::new(State {
                next: 1,
                waiting: HashMap::new(),
                admitted: BTreeSet::new(),
                refused: 0,
                phase: Phase::Serving,
            }),
            revoked: watch::Sender::new(false),
            to_agent,
        })
    }

    /// The token clients must present.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The profile, as the grant was created with it.
    pub fn profile(&self) -> &BrokerProfile {
        &self.profile
    }

    /// The preset revision the profile names.
    pub fn spec(&self) -> &'static PresetSpec {
        self.spec
    }

    /// A copy of the credential (wiped when dropped), unless the grant was
    /// revoked.
    pub fn credential(&self) -> Option<SecretString> {
        lock(&self.credential).clone()
    }

    /// Whether the agent said `revoke`.
    pub fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    /// A receiver that sees the revocation.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.revoked.subscribe()
    }

    fn expired(&self) -> bool {
        match (self.expires, boot_time()) {
            (Some(expires), Some(now)) => now >= expires,
            _ => true,
        }
    }

    fn send(&self, state: &State, message: FromBroker) {
        debug_assert!(state.phase != Phase::Revoked, "nothing after revoked");
        // A closed queue means the channel ended: the broker is leaving.
        let _ = self.to_agent.send(message);
    }

    /// Count a request refused before its admission was asked.
    pub fn count_refusal(&self) {
        let mut state = lock(&self.state);
        state.refused = state.refused.saturating_add(1);
    }

    /// Ask the agent to admit a request (`method`, the route it matched):
    /// its number and where the answer will come, or why the broker did not
    /// ask.
    pub fn ask_admission(
        &self,
        method: &str,
        route: &str,
    ) -> Result<(u64, oneshot::Receiver<Answer>), Held> {
        let mut state = lock(&self.state);
        if state.phase != Phase::Serving {
            return Err(Held::Revoked);
        }
        if self.expired() {
            return Err(Held::Expired);
        }
        if state.waiting.len() + state.admitted.len() >= self.max_in_flight {
            return Err(Held::TooManyInFlight);
        }
        let request = state.next;
        state.next += 1;
        let (answer, receiver) = oneshot::channel();
        state.waiting.insert(request, answer);
        self.send(
            &state,
            FromBroker::Admit {
                request,
                method: method.into(),
                route: route.into(),
            },
        );
        Ok((request, receiver))
    }

    /// The agent's answer to request `request`'s `admit`.
    pub fn on_answer(&self, request: u64, answer: Answer) -> Result<(), Violation> {
        let mut state = lock(&self.state);
        let Some(waiter) = state.waiting.remove(&request) else {
            return Err(Violation("an answer for a request that is not waiting"));
        };
        if answer == Answer::Admitted {
            state.admitted.insert(request);
        }
        if let Err(Answer::Admitted) = waiter.send(answer) {
            // Nobody waits for it any more (its client went away, or a
            // revocation closed it): it ends here, unsent.
            let outcome = if state.phase == Phase::Serving {
                RequestOutcome::NotForwarded
            } else {
                RequestOutcome::Revoked
            };
            self.finish_locked(
                &mut state,
                request,
                Ended {
                    outcome,
                    status: None,
                    bytes_sent: 0,
                    bytes_received: 0,
                },
            );
        }
        self.confirm_if_done(&mut state);
        Ok(())
    }

    /// An admitted request ended.
    pub fn finish(&self, request: u64, ended: Ended) {
        let mut state = lock(&self.state);
        self.finish_locked(&mut state, request, ended);
        self.confirm_if_done(&mut state);
    }

    fn finish_locked(&self, state: &mut State, request: u64, ended: Ended) {
        if state.admitted.remove(&request) {
            self.send(
                state,
                FromBroker::Finished {
                    request,
                    outcome: ended.outcome,
                    status: ended.status,
                    bytes_sent: ended.bytes_sent,
                    bytes_received: ended.bytes_received,
                },
            );
        }
    }

    /// The agent said `revoke`: admit nothing more, drop the credential, and
    /// tell every open request and connection to close.
    pub fn on_revoke(&self) -> Result<(), Violation> {
        let mut state = lock(&self.state);
        if state.phase != Phase::Serving {
            return Err(Violation("a second revoke"));
        }
        state.phase = Phase::Revoking;
        drop(lock(&self.credential).take());
        self.revoked.send_replace(true);
        self.confirm_if_done(&mut state);
        Ok(())
    }

    /// Send `revoked` once every `admit` is answered and every admitted
    /// request has finished.
    fn confirm_if_done(&self, state: &mut State) {
        if state.phase == Phase::Revoking && state.waiting.is_empty() && state.admitted.is_empty() {
            let refused = state.refused;
            self.send(state, FromBroker::Revoked { refused });
            state.phase = Phase::Revoked;
        }
    }
}

/// Lock `mutex`; a panic ends the broker (its hook exits), so a poisoned
/// lock is never seen in practice.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The broker's budget of request bodies held in memory
/// (`REQUEST_BODY_BUDGET_BYTES`): each request reserves its declared length
/// before its admission is asked.
pub struct Budget {
    held: Mutex<usize>,
    limit: usize,
}

/// Bytes reserved in a [`Budget`], given back when dropped.
pub struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Budget {
    /// A budget of `limit` bytes.
    pub fn new(limit: usize) -> Arc<Budget> {
        Arc::new(Budget {
            held: Mutex::new(0),
            limit,
        })
    }

    /// Reserve `bytes`, if they fit.
    pub fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        let bytes = usize::try_from(bytes).ok()?;
        let mut held = lock(&self.held);
        if bytes > self.limit - *held {
            return None;
        }
        *held += bytes;
        Some(Reservation {
            budget: Arc::clone(self),
            bytes,
        })
    }

    /// Bytes reserved now.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        *lock(&self.held)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        *lock(&self.budget.held) -= self.bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusthorse::broker_profile::{Preset, ProfileRequest};
    use rusthorse::broker_protocol::{VERSION, new_grant_id, new_token};

    const FAKE_CREDENTIAL: &str = "sk-ant-test-0000000000000000";

    fn install(max_in_flight: u32) -> Install {
        Install {
            version: VERSION,
            grant: new_grant_id(),
            token: new_token(),
            credential: SecretString::new(FAKE_CREDENTIAL.into()),
            profile: ProfileRequest::new(Preset::Anthropic)
                .resolve()
                .expect("profile"),
            max_in_flight,
            max_connections: 4,
            lifetime_secs: 60,
        }
    }

    fn grant(max_in_flight: u32) -> (Arc<Grant>, mpsc::UnboundedReceiver<FromBroker>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Grant::new(install(max_in_flight), boot_time(), tx), rx)
    }

    fn sent(rx: &mut mpsc::UnboundedReceiver<FromBroker>) -> Vec<FromBroker> {
        let mut messages = Vec::new();
        while let Ok(message) = rx.try_recv() {
            messages.push(message);
        }
        messages
    }

    fn admit(request: u64) -> FromBroker {
        FromBroker::Admit {
            request,
            method: "POST".into(),
            route: "POST /v1/messages".into(),
        }
    }

    fn ended(outcome: RequestOutcome) -> Ended {
        Ended {
            outcome,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 3,
        }
    }

    fn finished(request: u64, outcome: RequestOutcome) -> FromBroker {
        FromBroker::Finished {
            request,
            outcome,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 3,
        }
    }

    #[test]
    fn requests_are_numbered_from_one_and_answered_once() {
        let (grant, mut rx) = grant(4);
        let (one, mut answer_one) = grant.ask_admission("POST", "POST /v1/messages").expect("1");
        let (two, _answer_two) = grant.ask_admission("POST", "POST /v1/messages").expect("2");
        assert_eq!((one, two), (1, 2));
        assert_eq!(sent(&mut rx), vec![admit(1), admit(2)]);
        // Answers may come in any order; each number once.
        assert_eq!(
            grant.on_answer(2, Answer::Refused(AdmissionRefusal::Exhausted)),
            Ok(())
        );
        assert!(
            grant.on_answer(2, Answer::Admitted).is_err(),
            "answered twice"
        );
        assert!(grant.on_answer(3, Answer::Admitted).is_err(), "never asked");
        assert!(grant.on_answer(0, Answer::Admitted).is_err(), "never asked");
        assert_eq!(grant.on_answer(1, Answer::Admitted), Ok(()));
        assert_eq!(answer_one.try_recv(), Ok(Answer::Admitted));
        // Each admitted request finishes once; a refused one never does.
        grant.finish(2, ended(RequestOutcome::Completed));
        grant.finish(1, ended(RequestOutcome::Completed));
        grant.finish(1, ended(RequestOutcome::Unknown));
        assert_eq!(sent(&mut rx), vec![finished(1, RequestOutcome::Completed)]);
        // The numbers go on without gaps.
        let (three, _) = grant.ask_admission("GET", "GET /v1/models").expect("3");
        assert_eq!(three, 3);
    }

    #[test]
    fn requests_in_flight_are_limited_and_refusals_free_their_slots() {
        let (grant, mut rx) = grant(2);
        let (one, _a) = grant.ask_admission("POST", "POST /v1/messages").expect("1");
        let (two, _b) = grant.ask_admission("POST", "POST /v1/messages").expect("2");
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::TooManyInFlight)
        );
        // Admitted and unfinished still counts; refused frees its slot.
        grant.on_answer(one, Answer::Admitted).expect("answer");
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::TooManyInFlight)
        );
        grant
            .on_answer(two, Answer::Refused(AdmissionRefusal::TooManyInFlight))
            .expect("answer");
        let (three, _c) = grant.ask_admission("POST", "POST /v1/messages").expect("3");
        assert_eq!(three, 3);
        grant.finish(one, ended(RequestOutcome::Completed));
        let (four, _d) = grant.ask_admission("POST", "POST /v1/messages").expect("4");
        assert_eq!(four, 4);
        assert_eq!(
            sent(&mut rx),
            vec![
                admit(1),
                admit(2),
                admit(3),
                finished(1, RequestOutcome::Completed),
                admit(4)
            ]
        );
    }

    #[test]
    fn revocation_waits_for_every_answer_and_every_finish() {
        let (grant, mut rx) = grant(8);
        let (one, _a) = grant.ask_admission("POST", "POST /v1/messages").expect("1");
        let (two, mut answer_two) = grant.ask_admission("POST", "POST /v1/messages").expect("2");
        grant.on_answer(one, Answer::Admitted).expect("answer");
        grant.count_refusal();
        grant.count_refusal();
        let watcher = grant.subscribe();
        assert!(!grant.is_revoked());
        assert!(grant.credential().is_some());
        assert_eq!(grant.on_revoke(), Ok(()));
        assert!(grant.is_revoked());
        assert!(watcher.has_changed().expect("watch"));
        assert!(grant.credential().is_none(), "the credential is dropped");
        assert_eq!(grant.on_revoke(), Err(Violation("a second revoke")));
        // Nothing more is asked.
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::Revoked)
        );
        assert_eq!(sent(&mut rx), vec![admit(1), admit(2)]);
        // The waiting admit is answered (here: admitted, after the revoke):
        // it must finish too before `revoked`.
        grant.on_answer(two, Answer::Admitted).expect("answer");
        assert_eq!(answer_two.try_recv(), Ok(Answer::Admitted));
        grant.finish(two, ended(RequestOutcome::Revoked));
        assert_eq!(sent(&mut rx), vec![finished(2, RequestOutcome::Revoked)]);
        grant.finish(one, ended(RequestOutcome::Unknown));
        // Then `revoked`, with the refusals counted before admission.
        assert_eq!(
            sent(&mut rx),
            vec![
                finished(1, RequestOutcome::Unknown),
                FromBroker::Revoked { refused: 2 }
            ]
        );
        // Nothing after it.
        grant.finish(one, ended(RequestOutcome::Unknown));
        grant.count_refusal();
        assert!(grant.on_answer(one, Answer::Admitted).is_err());
        assert_eq!(sent(&mut rx), vec![]);
    }

    #[test]
    fn a_revocation_with_nothing_open_is_confirmed_at_once() {
        let (grant, mut rx) = grant(8);
        let (one, _a) = grant.ask_admission("GET", "GET /v1/models").expect("1");
        grant
            .on_answer(one, Answer::Refused(AdmissionRefusal::AuditFailed))
            .expect("answer");
        grant.on_revoke().expect("revoke");
        assert_eq!(
            sent(&mut rx),
            vec![
                FromBroker::Admit {
                    request: 1,
                    method: "GET".into(),
                    route: "GET /v1/models".into()
                },
                FromBroker::Revoked { refused: 0 }
            ]
        );
    }

    fn unsent(request: u64, outcome: RequestOutcome) -> FromBroker {
        FromBroker::Finished {
            request,
            outcome,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    #[test]
    fn an_admission_nobody_waits_for_ends_unsent() {
        let (grant, mut rx) = grant(8);
        let (one, answer) = grant.ask_admission("POST", "POST /v1/messages").expect("1");
        drop(answer);
        grant.on_answer(one, Answer::Admitted).expect("answer");
        assert_eq!(
            sent(&mut rx),
            vec![admit(1), unsent(1, RequestOutcome::NotForwarded)]
        );
        // After a revocation, it ends revoked, and then the revocation is
        // confirmed.
        let (two, answer) = grant.ask_admission("POST", "POST /v1/messages").expect("2");
        grant.on_revoke().expect("revoke");
        drop(answer);
        grant.on_answer(two, Answer::Admitted).expect("answer");
        assert_eq!(
            sent(&mut rx),
            vec![
                admit(2),
                unsent(2, RequestOutcome::Revoked),
                FromBroker::Revoked { refused: 0 }
            ]
        );
    }

    #[test]
    fn a_grant_past_its_lifetime_admits_nothing() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let past = boot_time()
            .expect("clock")
            .saturating_sub(Duration::from_secs(1));
        let grant = Grant::with_expiry(install(4), tx.clone(), Some(past));
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::Expired)
        );
        // An unreadable clock counts as expired, at the start or later.
        let grant = Grant::with_expiry(install(4), tx.clone(), None);
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::Expired)
        );
        let grant = Grant::new(install(4), None, tx);
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::Expired)
        );
        // The lifetime counts from when the install was received.
        let (tx, _rx2) = mpsc::unbounded_channel();
        let long_ago = boot_time()
            .expect("clock")
            .saturating_sub(Duration::from_secs(61));
        let grant = Grant::new(install(4), Some(long_ago), tx);
        assert_eq!(
            grant
                .ask_admission("POST", "POST /v1/messages")
                .map(|(n, _)| n),
            Err(Held::Expired),
            "a lifetime of 60 s, received 61 s ago"
        );
        assert_eq!(sent(&mut rx), vec![]);
        // A fresh grant does.
        let (grant, _rx) = self::grant(4);
        assert!(grant.ask_admission("POST", "POST /v1/messages").is_ok());
        assert!(boot_time().is_some());
    }

    #[test]
    fn the_body_budget_holds_and_gives_back() {
        let budget = Budget::new(100);
        let a = budget.reserve(60).expect("fits");
        assert!(budget.reserve(41).is_none());
        let b = budget.reserve(40).expect("fits exactly");
        assert_eq!(budget.held(), 100);
        assert!(budget.reserve(1).is_none());
        let empty = budget.reserve(0).expect("nothing always fits");
        drop(a);
        assert_eq!(budget.held(), 40);
        let c = budget.reserve(60).expect("fits again");
        drop((b, c, empty));
        assert_eq!(budget.held(), 0);
        assert!(budget.reserve(u64::MAX).is_none());
        assert!(budget.reserve(101).is_none());
    }
}
