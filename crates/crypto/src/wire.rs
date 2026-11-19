//! Framing that carries handshakes and sealed messages over any transport.
//!
//! One leading byte says what a frame is. The initiator knows the
//! recipient's transport address; the responder only ever sees an opaque
//! reply handle `T` (on Nym: an anonymous sender tag backed by single-use
//! reply blocks), so it can answer without learning where the caller is.
//!
//! # Handshake attempts (design review M3)
//!
//! This is a prototype; the handshake will be replaced (spec question 11).
//! The rules, using `snow`'s public API only:
//!
//! * **Framing rejects are ignored.** An empty frame, an unknown type or a
//!   wrong length for its type is refused before any cryptography and
//!   changes nothing.
//! * **A cryptographic failure ends the attempt** (the Noise rule): a
//!   handshake message that does not decrypt, or a peer that proves the
//!   wrong identity, ends that handshake. The initiator then starts a new
//!   attempt with a fresh ephemeral key, after a backoff, up to
//!   [`RetryPolicy::attempts`] times.
//! * **Timeouts resend the exact bytes** already sent for a still-valid
//!   attempt, up to [`RetryPolicy::resends`] times; then the attempt is
//!   abandoned and a fresh one starts. The responder answers an identical
//!   repeat with its cached reply.
//! * **Stale frames are ignored.** Every handshake frame carries a random
//!   *call id* (one per [`Initiator`]) and an attempt number. The responder
//!   keeps one pending handshake per caller and call id, never goes back to
//!   a lower attempt, and ignores frames for attempts it has moved past or
//!   already finished; the initiator ignores frames for any attempt but its
//!   current one. A frame from an older attempt therefore cannot displace
//!   or corrupt a newer one.
//! * **The session is not established until the responder confirms.** After
//!   message 3 the responder sends a confirmation sealed in the new session
//!   (a valid data frame counts too). Until it arrives the initiator resends
//!   message 3, and gives up within a bounded time. A responder whose
//!   caller never sends message 3 drops the half-finished handshake after
//!   [`Responder::tick`] has been called [`PENDING_TICKS`] times.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use anonymum_core::Address;
use rand_core::{OsRng, RngCore};

use crate::identity::Identity;
use crate::session::{
    Handshake, Session, SessionError, MAX_NOISE_MESSAGE, MESSAGE1_LEN, MESSAGE2_LEN, MESSAGE3_LEN,
    MIN_SEALED, NONCE_LEN,
};

const HANDSHAKE_1: u8 = 1;
const HANDSHAKE_2: u8 = 2;
const HANDSHAKE_3: u8 = 3;
const DATA: u8 = 4;
const CONFIRM: u8 = 5;

/// Type byte, call id (4 bytes), attempt number (4 bytes, big-endian).
const HEADER_LEN: usize = 1 + 4 + 4;
/// What a confirmation decrypts to.
const CONFIRM_MARKER: &[u8] = b"anonymum/confirm/v1";

/// The longest valid frame: a data frame carrying [`crate::MAX_PLAINTEXT`].
pub const MAX_FRAME: usize = 1 + NONCE_LEN + MAX_NOISE_MESSAGE;

/// Cap on half-finished handshakes a responder keeps, so strangers cannot
/// exhaust memory by starting handshakes and never finishing.
const MAX_PENDING: usize = 1_024;

/// How many [`Responder::tick`] calls a half-finished handshake survives.
pub const PENDING_TICKS: u32 = 3;

#[derive(Debug)]
pub enum WireError {
    Session(SessionError),
    /// Empty frame or unknown type byte. Ignored; nothing changed.
    UnknownFrame,
    /// Wrong length for its type. Ignored; nothing changed.
    Malformed,
    /// Longer than any valid frame; refused before anything is allocated.
    Oversized,
    /// For an attempt or call that is not the current one, or a type that
    /// makes no sense at this point. Ignored; nothing changed.
    Stale,
    /// Data arrived (or was to be sent) without an established session.
    NoSession,
    Busy,
    /// The handshake attempt failed cryptographically and has ended. The
    /// initiator retries after [`Initiator::wait`].
    AttemptFailed(SessionError),
    /// No attempts left.
    GaveUp,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WireError {}

impl From<SessionError> for WireError {
    fn from(e: SessionError) -> Self {
        WireError::Session(e)
    }
}

/// Which attempt of which call a handshake frame belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Attempt {
    call: u32,
    number: u32,
}

fn data_frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(DATA);
    out.extend_from_slice(body);
    out
}

fn handshake_frame(kind: u8, at: Attempt, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(kind);
    out.extend_from_slice(&at.call.to_be_bytes());
    out.extend_from_slice(&at.number.to_be_bytes());
    out.extend_from_slice(body);
    out
}

enum Frame<'a> {
    Handshake { kind: u8, at: Attempt, body: &'a [u8] },
    Data(&'a [u8]),
}

/// Outer framing only: type and exact length per type. Nothing here
/// touches any state.
fn parse(frame: &[u8]) -> Result<Frame<'_>, WireError> {
    if frame.len() > MAX_FRAME {
        return Err(WireError::Oversized);
    }
    let (&kind, body) = frame.split_first().ok_or(WireError::UnknownFrame)?;
    let body_len = match kind {
        DATA => {
            return if body.len() < MIN_SEALED { Err(WireError::Malformed) } else { Ok(Frame::Data(body)) };
        }
        HANDSHAKE_1 => MESSAGE1_LEN,
        HANDSHAKE_2 => MESSAGE2_LEN,
        HANDSHAKE_3 => MESSAGE3_LEN,
        CONFIRM => MIN_SEALED + CONFIRM_MARKER.len(),
        _ => return Err(WireError::UnknownFrame),
    };
    if frame.len() != HEADER_LEN + body_len {
        return Err(WireError::Malformed);
    }
    let word = |at: usize| u32::from_be_bytes(frame[at..at + 4].try_into().expect("4 bytes"));
    Ok(Frame::Handshake { kind, at: Attempt { call: word(1), number: word(5) }, body: &frame[HEADER_LEN..] })
}

// ---- initiator -------------------------------------------------------------

/// How hard an [`Initiator`] tries before it gives up.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Fresh handshakes (fresh ephemeral keys) in total, the first included.
    pub attempts: u32,
    /// How often one attempt's last frame is resent unchanged on timeout.
    pub resends: u32,
    /// How long to wait for an answer. After a failed attempt the wait
    /// before the next doubles each time (capped at 64 times this).
    pub base_wait: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(30) }
    }
}

/// The calling side of one conversation.
pub struct Initiator {
    peer: Address,
    call: u32,
    policy: RetryPolicy,
    attempt: u32,
    state: State,
}

enum State {
    /// Message 1 sent; waiting for message 2.
    Handshaking { handshake: Handshake, sent: Vec<u8>, resends: u32 },
    /// Message 3 sent; waiting for the responder's confirmation.
    Confirming { session: Session, sent: Vec<u8>, resends: u32 },
    Established(Session),
    /// The last attempt failed; the next starts after [`Initiator::wait`].
    Waiting,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitiatorEvent {
    /// Send this frame to the peer (message 3).
    Send(Vec<u8>),
    /// The responder confirmed; [`Initiator::seal`] is usable.
    Established,
    /// A message. If it arrived before the confirmation, it confirmed the
    /// session too.
    Message(Vec<u8>),
}

impl Initiator {
    /// Begin talking to `peer` with the default [`RetryPolicy`]. Returns the
    /// first frame to send.
    pub fn start(me: &Identity, peer: Address) -> Result<(Initiator, Vec<u8>), WireError> {
        Self::start_with(me, peer, RetryPolicy::default())
    }

    pub fn start_with(me: &Identity, peer: Address, policy: RetryPolicy) -> Result<(Initiator, Vec<u8>), WireError> {
        let mut initiator = Initiator { peer, call: OsRng.next_u32(), policy, attempt: 0, state: State::Waiting };
        let first = initiator.new_attempt(me)?;
        Ok((initiator, first))
    }

    /// A fresh handshake (fresh ephemeral key), if attempts remain.
    fn new_attempt(&mut self, me: &Identity) -> Result<Vec<u8>, WireError> {
        if self.attempt >= self.policy.attempts {
            self.state = State::Failed;
            return Err(WireError::GaveUp);
        }
        self.attempt += 1;
        let (handshake, message1) = Handshake::initiate(me, self.peer)?;
        let sent = handshake_frame(HANDSHAKE_1, self.current(), &message1);
        self.state = State::Handshaking { handshake, sent: sent.clone(), resends: 0 };
        Ok(sent)
    }

    fn current(&self) -> Attempt {
        Attempt { call: self.call, number: self.attempt }
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established(_))
    }

    /// The current attempt number (1 for the first).
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// How long to wait for the next frame before calling
    /// [`Initiator::on_timeout`]; `None` once established or given up.
    pub fn wait(&self) -> Option<Duration> {
        match self.state {
            State::Handshaking { .. } | State::Confirming { .. } => Some(self.policy.base_wait),
            State::Waiting => Some(self.policy.base_wait * (1u32 << self.attempt.saturating_sub(1).min(6))),
            State::Established(_) | State::Failed => None,
        }
    }

    /// Nothing usable arrived within [`Initiator::wait`]. Returns the frame
    /// to send: the same bytes again while the attempt has resends left,
    /// otherwise the first frame of a fresh attempt. `Ok(None)` once
    /// established; [`WireError::GaveUp`] when no attempts remain.
    pub fn on_timeout(&mut self, me: &Identity) -> Result<Option<Vec<u8>>, WireError> {
        let max = self.policy.resends;
        match &mut self.state {
            State::Handshaking { sent, resends, .. } | State::Confirming { sent, resends, .. } if *resends < max => {
                *resends += 1;
                Ok(Some(sent.clone()))
            }
            State::Established(_) => Ok(None),
            State::Failed => Err(WireError::GaveUp),
            _ => self.new_attempt(me).map(Some),
        }
    }

    pub fn handle(&mut self, incoming: &[u8]) -> Result<InitiatorEvent, WireError> {
        let frame = parse(incoming)?;
        let current = self.current();
        match (frame, std::mem::replace(&mut self.state, State::Failed)) {
            (Frame::Handshake { kind: HANDSHAKE_2, at, body }, State::Handshaking { handshake, sent, resends }) => {
                if at != current {
                    self.state = State::Handshaking { handshake, sent, resends };
                    return Err(WireError::Stale);
                }
                match handshake.initiator_finish(body) {
                    Ok((session, message3)) => {
                        let sent = handshake_frame(HANDSHAKE_3, current, &message3);
                        self.state = State::Confirming { session, sent: sent.clone(), resends: 0 };
                        Ok(InitiatorEvent::Send(sent))
                    }
                    Err(error) => {
                        self.state = State::Waiting;
                        Err(WireError::AttemptFailed(error))
                    }
                }
            }
            (Frame::Handshake { kind: CONFIRM, at, body }, State::Confirming { mut session, sent, resends }) => {
                // A transport message: a bad one is dropped, as Noise does
                // for transport messages, and the attempt stays valid.
                let confirmed = at == current && session.open(body).map_or(false, |p| p == CONFIRM_MARKER);
                if confirmed {
                    self.state = State::Established(session);
                    Ok(InitiatorEvent::Established)
                } else {
                    self.state = State::Confirming { session, sent, resends };
                    Err(WireError::Stale)
                }
            }
            (Frame::Data(body), State::Confirming { mut session, sent, resends }) => match session.open(body) {
                Ok(plaintext) => {
                    self.state = State::Established(session);
                    Ok(InitiatorEvent::Message(plaintext))
                }
                Err(error) => {
                    self.state = State::Confirming { session, sent, resends };
                    Err(error.into())
                }
            },
            (Frame::Data(body), State::Established(mut session)) => {
                let result = session.open(body);
                self.state = State::Established(session);
                Ok(InitiatorEvent::Message(result?))
            }
            (Frame::Data(_), state) => {
                self.state = state;
                Err(WireError::NoSession)
            }
            (Frame::Handshake { .. }, state) => {
                self.state = state;
                Err(WireError::Stale)
            }
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let State::Established(session) = &mut self.state else { return Err(WireError::NoSession) };
        Ok(data_frame(&session.seal(plaintext)?))
    }
}

// ---- responder -------------------------------------------------------------

/// The answering side, serving many callers at once.
pub struct Responder<T> {
    /// Half-finished handshakes, one per caller and call id.
    pending: HashMap<(T, u32), Pending>,
    sessions: HashMap<T, Live>,
}

/// A half-finished handshake, with the frame that started it and our reply.
/// A caller who is not answered (e.g. we were offline) sends the same first
/// frame again; when both copies arrive, we answer the repeat with the same
/// reply, so there is still exactly one handshake to finish.
struct Pending {
    attempt: u32,
    first: Vec<u8>,
    reply: Vec<u8>,
    handshake: Handshake,
    age: u32,
}

/// An established session, with the message 3 that finished it and our
/// confirmation, so a lost confirmation can be resent.
struct Live {
    at: Attempt,
    last: Vec<u8>,
    confirm: Vec<u8>,
    session: Session,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponderEvent {
    /// Send this frame back to the caller.
    Reply(Vec<u8>),
    /// A caller proved it is `peer`. Decide now whether to keep talking
    /// (check the chain for an open channel): if so, send `reply` (the
    /// confirmation); if not, call [`Responder::forget`] and send nothing.
    Established { peer: Address, reply: Vec<u8> },
    Message { peer: Address, plaintext: Vec<u8> },
}

impl<T: Hash + Eq + Clone> Default for Responder<T> {
    fn default() -> Self {
        Responder { pending: HashMap::new(), sessions: HashMap::new() }
    }
}

impl<T: Hash + Eq + Clone> Responder<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle(&mut self, me: &Identity, from: T, incoming: &[u8]) -> Result<ResponderEvent, WireError> {
        let (kind, at, body) = match parse(incoming)? {
            Frame::Data(body) => {
                let live = self.sessions.get_mut(&from).ok_or(WireError::NoSession)?;
                let plaintext = live.session.open(body)?;
                return Ok(ResponderEvent::Message { peer: live.session.peer(), plaintext });
            }
            Frame::Handshake { kind, at, body } => (kind, at, body),
        };
        // Attempts of a call we already finished are over.
        let finished = self.sessions.get(&from).filter(|live| live.at.call == at.call);
        match kind {
            HANDSHAKE_1 => {
                if finished.map_or(false, |live| at.number <= live.at.number) {
                    return Err(WireError::Stale);
                }
                let key = (from, at.call);
                if let Some(pending) = self.pending.get(&key) {
                    if at.number < pending.attempt || (at.number == pending.attempt && pending.first != incoming) {
                        return Err(WireError::Stale);
                    }
                    if at.number == pending.attempt {
                        return Ok(ResponderEvent::Reply(pending.reply.clone()));
                    }
                } else if self.pending.len() >= MAX_PENDING {
                    return Err(WireError::Busy);
                }
                let (handshake, message2) = Handshake::respond(me, body)?;
                let reply = handshake_frame(HANDSHAKE_2, at, &message2);
                let pending = Pending { attempt: at.number, first: incoming.to_vec(), reply: reply.clone(), handshake, age: 0 };
                self.pending.insert(key, pending);
                Ok(ResponderEvent::Reply(reply))
            }
            HANDSHAKE_3 => {
                if let Some(live) = finished {
                    // Our confirmation was lost: send it again.
                    return if live.at == at && live.last == incoming {
                        Ok(ResponderEvent::Reply(live.confirm.clone()))
                    } else {
                        Err(WireError::Stale)
                    };
                }
                let key = (from.clone(), at.call);
                if self.pending.get(&key).map_or(true, |p| p.attempt != at.number) {
                    return Err(WireError::Stale);
                }
                let pending = self.pending.remove(&key).expect("checked above");
                let mut session = pending.handshake.responder_finish(body).map_err(WireError::AttemptFailed)?;
                // This caller is now talking to us: its other half-finished
                // handshakes, if any, are over.
                self.pending.retain(|(t, _), _| *t != from);
                let confirm = handshake_frame(CONFIRM, at, &session.seal(CONFIRM_MARKER)?);
                let peer = session.peer();
                self.sessions.insert(from, Live { at, last: incoming.to_vec(), confirm: confirm.clone(), session });
                Ok(ResponderEvent::Established { peer, reply: confirm })
            }
            _ => Err(WireError::Stale),
        }
    }

    pub fn seal(&mut self, to: &T, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let live = self.sessions.get_mut(to).ok_or(WireError::NoSession)?;
        Ok(data_frame(&live.session.seal(plaintext)?))
    }

    /// Age half-finished handshakes; drop those that have seen
    /// [`PENDING_TICKS`] ticks without a message 3. Returns the callers whose
    /// handshake was dropped. Call it at a steady pace (e.g. once per
    /// initiator wait).
    pub fn tick(&mut self) -> Vec<T> {
        let mut expired = Vec::new();
        self.pending.retain(|(from, _), pending| {
            pending.age += 1;
            let keep = pending.age < PENDING_TICKS;
            if !keep {
                expired.push(from.clone());
            }
            keep
        });
        expired
    }

    /// How many half-finished handshakes are waiting.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Drop a caller, e.g. because they have no open channel.
    pub fn forget(&mut self, from: &T) {
        self.pending.retain(|(t, _), _| t != from);
        self.sessions.remove(from);
    }
}
