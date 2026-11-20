//! Framing that carries handshakes and sealed messages over any transport.
//!
//! One leading byte says what a frame is. The initiator knows the
//! recipient's transport address; the responder only ever sees an opaque
//! reply handle `T` (on Nym: an anonymous sender tag backed by single-use
//! reply blocks), so it can answer without learning where the caller is.
//!
//! # Handshake (Noise IK, spec v0.7 section 2a)
//!
//! Four frames: HELLO (IK message 1), WELCOME (IK message 2), the caller's
//! CONFIRM sealed in the new session, and the answerer's ACK. This is an
//! unreviewed prototype (spec question 11). The rules, using `snow`'s public
//! API only:
//!
//! * **Authorise before replying.** The responder reads the caller's key and
//!   reference from HELLO and asks its [`Gate`]. An unauthorised caller gets
//!   nothing: no WELCOME, no error, no frame of any kind. Every `Err` from
//!   [`Responder::handle`] means "send nothing".
//! * **Grants are committed only after a fresh confirmation.** HELLO can be
//!   replayed; CONFIRM cannot, because it is sealed under keys that depend on
//!   the responder's fresh ephemeral key. The responder counts an invitation
//!   as used, or a caller as present, only when CONFIRM arrives, and checks
//!   the gate again then.
//! * **Framing rejects are ignored.** An empty frame, an unknown type or a
//!   wrong length for its type is refused before any cryptography and
//!   changes nothing.
//! * **A cryptographic failure ends the attempt** (the Noise rule): a WELCOME
//!   that does not decrypt ends the caller's handshake, which then starts a
//!   new attempt with a fresh ephemeral key, after a backoff, up to
//!   [`RetryPolicy::attempts`] times. A sealed CONFIRM or ACK that fails to
//!   open is a transport message and is dropped, as Noise does for those.
//! * **Timeouts resend the exact bytes** already sent for a still-valid
//!   attempt, up to [`RetryPolicy::resends`] times; then a fresh attempt
//!   starts. The responder answers an identical repeat with its cached
//!   reply.
//! * **Stale frames are ignored.** Every handshake frame carries a random
//!   *call id* (one per [`Initiator`]) and an attempt number in clear. The
//!   reference to an invitation or request travels only inside the encrypted
//!   HELLO. The responder keeps one pending handshake per caller and call id,
//!   never goes back to a lower attempt, and ignores frames for attempts it
//!   has moved past or finished.
//! * **Both sides confirm.** The caller is established only after the ACK
//!   (or a valid data frame); it resends CONFIRM until then. The responder
//!   drops a handshake whose CONFIRM never comes after [`PENDING_TICKS`]
//!   calls to [`Responder::tick`].

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use rand_core::{OsRng, RngCore};

use crate::contact::{Network, StaticKey};
use crate::gate::{Gate, Grant};
use crate::session::{
    Handshake, Incoming, Session, SessionError, MAX_NOISE_MESSAGE, MESSAGE1_LEN, MESSAGE2_LEN, MIN_SEALED,
    NONCE_LEN, REFERENCE_LEN,
};

const HELLO: u8 = 1;
const WELCOME: u8 = 2;
const CONFIRM: u8 = 3;
const DATA: u8 = 4;
const ACK: u8 = 5;

/// Type byte, call id (4 bytes), attempt number (4 bytes, big-endian).
const HEADER_LEN: usize = 1 + 4 + 4;
/// What the caller's confirmation and the answerer's ack decrypt to.
const CONFIRM_MARKER: &[u8] = b"anonymum/confirm/v2";
const ACK_MARKER: &[u8] = b"anonymum/acknowledge/v2";

/// The longest valid frame: a data frame carrying [`crate::MAX_PLAINTEXT`].
pub const MAX_FRAME: usize = 1 + NONCE_LEN + MAX_NOISE_MESSAGE;

/// Cap on half-finished handshakes a responder keeps.
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
    /// The caller is not authorised. Nothing is sent and nothing stored.
    Unauthorised,
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
    [&[DATA], body].concat()
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

/// Outer framing only: type and exact length per type. Touches no state.
fn parse(frame: &[u8]) -> Result<Frame<'_>, WireError> {
    if frame.len() > MAX_FRAME {
        return Err(WireError::Oversized);
    }
    let (&kind, body) = frame.split_first().ok_or(WireError::UnknownFrame)?;
    let body_len = match kind {
        DATA => {
            return if body.len() < MIN_SEALED { Err(WireError::Malformed) } else { Ok(Frame::Data(body)) };
        }
        HELLO => MESSAGE1_LEN,
        WELCOME => MESSAGE2_LEN,
        CONFIRM => MIN_SEALED + CONFIRM_MARKER.len(),
        ACK => MIN_SEALED + ACK_MARKER.len(),
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
    me: StaticKey,
    peer: [u8; 32],
    network: Network,
    reference: [u8; REFERENCE_LEN],
    call: u32,
    policy: RetryPolicy,
    attempt: u32,
    state: State,
}

enum State {
    /// HELLO sent; waiting for WELCOME.
    Handshaking { handshake: Handshake, sent: Vec<u8>, resends: u32 },
    /// CONFIRM sent; waiting for the answerer's ACK.
    Confirming { session: Session, sent: Vec<u8>, resends: u32 },
    Established(Session),
    /// The last attempt failed; the next starts after [`Initiator::wait`].
    Waiting,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitiatorEvent {
    /// Send this frame to the peer (the CONFIRM).
    Send(Vec<u8>),
    /// The answerer acknowledged; [`Initiator::seal`] is usable.
    Established,
    /// A message. If it arrived before the ACK, it established the session.
    Message(Vec<u8>),
}

impl Initiator {
    /// Call the holder of handshake key `peer` as `me` (a caller key scoped
    /// to this relationship or request), naming `reference` inside the
    /// encrypted first message. Returns the first frame to send.
    pub fn start(
        me: &StaticKey,
        peer: [u8; 32],
        network: Network,
        reference: [u8; REFERENCE_LEN],
    ) -> Result<(Initiator, Vec<u8>), WireError> {
        Self::start_with(me, peer, network, reference, RetryPolicy::default())
    }

    pub fn start_with(
        me: &StaticKey,
        peer: [u8; 32],
        network: Network,
        reference: [u8; REFERENCE_LEN],
        policy: RetryPolicy,
    ) -> Result<(Initiator, Vec<u8>), WireError> {
        let mut initiator = Initiator {
            me: me.clone(),
            peer,
            network,
            reference,
            call: OsRng.next_u32(),
            policy,
            attempt: 0,
            state: State::Waiting,
        };
        let first = initiator.new_attempt()?;
        Ok((initiator, first))
    }

    /// A fresh handshake (fresh ephemeral key), if attempts remain.
    fn new_attempt(&mut self) -> Result<Vec<u8>, WireError> {
        if self.attempt >= self.policy.attempts {
            self.state = State::Failed;
            return Err(WireError::GaveUp);
        }
        self.attempt += 1;
        let (handshake, message1) = Handshake::initiate(&self.me, &self.peer, &self.network, &self.reference)?;
        let sent = handshake_frame(HELLO, self.current(), &message1);
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
    pub fn on_timeout(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        let max = self.policy.resends;
        match &mut self.state {
            State::Handshaking { sent, resends, .. } | State::Confirming { sent, resends, .. } if *resends < max => {
                *resends += 1;
                Ok(Some(sent.clone()))
            }
            State::Established(_) => Ok(None),
            State::Failed => Err(WireError::GaveUp),
            _ => self.new_attempt().map(Some),
        }
    }

    pub fn handle(&mut self, incoming: &[u8]) -> Result<InitiatorEvent, WireError> {
        let frame = parse(incoming)?;
        let current = self.current();
        match (frame, std::mem::replace(&mut self.state, State::Failed)) {
            (Frame::Handshake { kind: WELCOME, at, body }, State::Handshaking { handshake, sent, resends }) => {
                if at != current {
                    self.state = State::Handshaking { handshake, sent, resends };
                    return Err(WireError::Stale);
                }
                match handshake.finish(body) {
                    Ok(mut session) => {
                        let sent = handshake_frame(CONFIRM, current, &session.seal(CONFIRM_MARKER)?);
                        self.state = State::Confirming { session, sent: sent.clone(), resends: 0 };
                        Ok(InitiatorEvent::Send(sent))
                    }
                    Err(error) => {
                        self.state = State::Waiting;
                        Err(WireError::AttemptFailed(error))
                    }
                }
            }
            (Frame::Handshake { kind: ACK, at, body }, State::Confirming { mut session, sent, resends }) => {
                let acknowledged = at == current && session.open(body).map_or(false, |p| p == ACK_MARKER);
                if acknowledged {
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

/// The answering side, serving many callers at once. It holds the handshake
/// key callers reach and the [`Gate`] that decides who is answered.
pub struct Responder<T> {
    me: StaticKey,
    network: Network,
    gate: Gate,
    /// Answered but unconfirmed handshakes, one per reply handle and call id.
    pending: HashMap<(T, u32), Pending>,
    sessions: HashMap<T, Live>,
}

/// An answered HELLO, with the frame that started it and our WELCOME. A
/// repeat of the same HELLO gets the same WELCOME, so there is still exactly
/// one handshake to finish.
struct Pending {
    attempt: u32,
    first: Vec<u8>,
    reply: Vec<u8>,
    session: Session,
    reference: [u8; REFERENCE_LEN],
    grant: Grant,
    age: u32,
}

/// An established session, with the CONFIRM that finished it and our ACK,
/// so a lost ACK can be resent.
struct Live {
    at: Attempt,
    last: Vec<u8>,
    ack: Vec<u8>,
    session: Session,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponderEvent {
    /// Send this frame back to the caller.
    Reply(Vec<u8>),
    /// The caller with key `peer` confirmed a fresh session and the grant is
    /// committed. Send `reply` (the ACK).
    Established { peer: [u8; 32], grant: Grant, reply: Vec<u8> },
    Message { peer: [u8; 32], plaintext: Vec<u8> },
}

impl<T: Hash + Eq + Clone> Responder<T> {
    pub fn new(me: &StaticKey, network: Network, gate: Gate) -> Self {
        Responder { me: me.clone(), network, gate, pending: HashMap::new(), sessions: HashMap::new() }
    }

    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    pub fn gate_mut(&mut self) -> &mut Gate {
        &mut self.gate
    }

    /// Handle one frame at time `now` (seconds, for invitation expiry).
    /// `Err` always means: send nothing.
    pub fn handle(&mut self, from: T, incoming: &[u8], now: u64) -> Result<ResponderEvent, WireError> {
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
            HELLO => {
                if finished.map_or(false, |live| at.number <= live.at.number) {
                    return Err(WireError::Stale);
                }
                let key = (from, at.call);
                if let Some(pending) = self.pending.get(&key) {
                    if at.number < pending.attempt || (at.number == pending.attempt && pending.first != incoming) {
                        return Err(WireError::Stale);
                    }
                    if at.number == pending.attempt {
                        // A repeat gets the cached answer, but only while the
                        // caller is still authorised (not blocked, invitation
                        // not used up meanwhile).
                        if self.gate.authorise(&pending.session.peer(), &pending.reference, now) != Some(pending.grant) {
                            self.pending.remove(&key);
                            return Err(WireError::Unauthorised);
                        }
                        return Ok(ResponderEvent::Reply(pending.reply.clone()));
                    }
                } else if self.pending.len() >= MAX_PENDING {
                    return Err(WireError::Busy);
                }
                let incoming_hello = Incoming::read(&self.me, &self.network, body)?;
                let (caller, reference) = (incoming_hello.caller(), incoming_hello.reference());
                // The decision, before anything is written.
                let grant = self.gate.authorise(&caller, &reference, now).ok_or(WireError::Unauthorised)?;
                let (session, message2) = incoming_hello.accept()?;
                let reply = handshake_frame(WELCOME, at, &message2);
                let pending = Pending {
                    attempt: at.number,
                    first: incoming.to_vec(),
                    reply: reply.clone(),
                    session,
                    reference,
                    grant,
                    age: 0,
                };
                self.pending.insert(key, pending);
                Ok(ResponderEvent::Reply(reply))
            }
            CONFIRM => {
                if let Some(live) = finished {
                    // Our ACK was lost: send it again.
                    return if live.at == at && live.last == incoming {
                        Ok(ResponderEvent::Reply(live.ack.clone()))
                    } else {
                        Err(WireError::Stale)
                    };
                }
                let key = (from.clone(), at.call);
                let pending = self.pending.get_mut(&key).filter(|p| p.attempt == at.number).ok_or(WireError::Stale)?;
                // A transport message: a bad one is dropped; the attempt stays.
                if pending.session.open(body).ok().as_deref() != Some(CONFIRM_MARKER) {
                    return Err(WireError::Stale);
                }
                let mut pending = self.pending.remove(&key).expect("found above");
                let peer = pending.session.peer();
                if !self.gate.commit(&peer, &pending.reference, pending.grant, now) {
                    return Err(WireError::Unauthorised); // blocked or used meanwhile
                }
                // This caller is now talking to us: its other half-finished
                // handshakes, if any, are over.
                self.pending.retain(|(t, _), _| *t != from);
                let ack = handshake_frame(ACK, at, &pending.session.seal(ACK_MARKER)?);
                let grant = pending.grant;
                let live = Live { at, last: incoming.to_vec(), ack: ack.clone(), session: pending.session };
                self.sessions.insert(from, live);
                Ok(ResponderEvent::Established { peer, grant, reply: ack })
            }
            _ => Err(WireError::Stale),
        }
    }

    pub fn seal(&mut self, to: &T, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let live = self.sessions.get_mut(to).ok_or(WireError::NoSession)?;
        Ok(data_frame(&live.session.seal(plaintext)?))
    }

    /// Block a caller key: refused from now on, and any session or pending
    /// handshake with it is dropped.
    pub fn block(&mut self, caller: [u8; 32]) {
        self.gate.block(caller);
        self.pending.retain(|_, p| p.session.peer() != caller);
        self.sessions.retain(|_, live| live.session.peer() != caller);
    }

    /// End a relationship without blocking: the caller key is no longer a
    /// contact, and any session or pending handshake with it is dropped.
    pub fn remove_contact(&mut self, caller: [u8; 32]) {
        self.gate.remove_contact(&caller);
        self.pending.retain(|_, p| p.session.peer() != caller);
        self.sessions.retain(|_, live| live.session.peer() != caller);
    }

    /// Age answered handshakes; drop those that have seen [`PENDING_TICKS`]
    /// ticks without a CONFIRM. Returns the callers whose handshake was
    /// dropped. Call it at a steady pace (e.g. once per initiator wait).
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

    /// How many answered handshakes are waiting for a CONFIRM.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Drop a caller's reply handle (its sessions and pending handshakes).
    pub fn forget(&mut self, from: &T) {
        self.pending.retain(|(t, _), _| t != from);
        self.sessions.remove(from);
    }
}
