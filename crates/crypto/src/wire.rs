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
//!   [`Responder::handle`] means "send nothing". There is no other public way
//!   to build a WELCOME: the handshake types that read a HELLO and write a
//!   WELCOME are private to the crate.
//!
//!   ```compile_fail
//!   use anonymum_crypto::Incoming;
//!   ```
//! * **Grants are committed only after a fresh confirmation.** HELLO can be
//!   replayed; CONFIRM cannot, because it is sealed under keys that depend on
//!   the responder's fresh ephemeral key. The responder counts an invitation
//!   as used, or a caller as present, only when CONFIRM arrives, and checks
//!   the gate again then.
//! * **Revocation is atomic.** The gate can only be changed through the
//!   responder ([`Responder::block`], [`Responder::remove_contact`]), which
//!   ends that peer's sessions and drops its cached replies at the same
//!   time; and every use of a live session checks the gate again.
//! * **Header and record type are authenticated.** The call id and attempt
//!   number are bound into the IK prologue (both sides know them from the
//!   header before decrypting HELLO). Every sealed record carries its type,
//!   and CONFIRM and ACK also carry the call id and attempt, inside the
//!   ciphertext; a record whose inner type or labels do not match the frame
//!   is refused without using up its counter.
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
//!   reply, after checking the gate again.
//! * **Stale frames are ignored.** The responder keeps one pending handshake
//!   per caller and call id and never goes back to a lower attempt. A
//!   CONFIRM is matched first against the exact attempt that is already
//!   live (a lost ACK: resend it), then against the newer pending attempt
//!   (which replaces the old session without using a grant twice).
//! * **Deadlines.** An answered handshake whose CONFIRM never comes expires
//!   [`PENDING_TIMEOUT`] after it was answered; a session expires after
//!   [`SESSION_IDLE_TIMEOUT`] without traffic; a callback grant expires at
//!   the deadline it was given. All are checked against the injected
//!   monotonic clock on every operation.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::contact::{ContactError, ContactIdentity, Invitation, Network, StaticKey};
use crate::gate::{Gate, Grant, Now};
use crate::session::{
    Handshake, Incoming, Session, SessionError, MAX_NOISE_MESSAGE, MAX_PLAINTEXT, MESSAGE1_LEN, MESSAGE2_LEN,
    MIN_SEALED, NONCE_LEN, REFERENCE_LEN,
};

const HELLO: u8 = 1;
const WELCOME: u8 = 2;
const CONFIRM: u8 = 3;
const DATA: u8 = 4;
const ACK: u8 = 5;

/// Type byte, call id (4 bytes), attempt number (4 bytes, big-endian).
const HEADER_LEN: usize = 1 + 4 + 4;
/// What the caller's confirmation and the answerer's ack carry, after their
/// record type and the call id and attempt.
const CONFIRM_MARKER: &[u8] = b"anonymum/confirm/v3";
const ACK_MARKER: &[u8] = b"anonymum/acknowledge/v3";
/// Inner record: type byte, then call id and attempt for control records.
const CONTROL_LEN: usize = 1 + 8;

/// The longest valid frame: a data frame carrying [`MAX_DATA`].
pub const MAX_FRAME: usize = 1 + NONCE_LEN + MAX_NOISE_MESSAGE;
/// Largest message one data frame carries (one byte goes to the inner
/// record type).
pub const MAX_DATA: usize = MAX_PLAINTEXT - 1;

/// Default cap on answered, unconfirmed handshakes a responder keeps.
pub const MAX_PENDING: usize = 1_024;
/// Default cap on answered, unconfirmed handshakes for one caller key.
pub const MAX_PENDING_PER_CALLER: usize = 4;
/// Default cap on live sessions (one per caller key).
pub const MAX_SESSIONS: usize = 1_024;

/// How long an answered handshake waits for its CONFIRM.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a session may sit without traffic before it is dropped.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug)]
pub enum WireError {
    Session(SessionError),
    /// Empty frame or unknown type byte. Ignored; nothing changed.
    UnknownFrame,
    /// Wrong length for its type. Ignored; nothing changed.
    Malformed,
    /// Longer than any valid frame; refused before anything is allocated.
    Oversized,
    /// For an attempt or call that is not the current one, a type that makes
    /// no sense at this point, or a record whose authenticated type or labels
    /// do not match its frame. Ignored; nothing changed.
    Stale,
    /// The caller is not (or no longer) authorised, or its grant or session
    /// expired. Nothing is sent.
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

impl Attempt {
    fn label(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.call.to_be_bytes());
        out[4..].copy_from_slice(&self.number.to_be_bytes());
        out
    }
}

/// The plaintext of a CONFIRM or ACK record for `at`.
fn control(kind: u8, at: Attempt, marker: &[u8]) -> Vec<u8> {
    [&[kind], at.label().as_slice(), marker].concat()
}

fn data_frame(session: &mut Session, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
    if plaintext.len() > MAX_DATA {
        return Err(SessionError::TooLarge.into());
    }
    let sealed = session.seal(&[&[DATA], plaintext].concat())?;
    Ok([&[DATA], sealed.as_slice()].concat())
}

/// Open a data frame's body: the inner type must be DATA.
fn open_data(session: &mut Session, body: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut plaintext = session.open_if(body, |p| p.first() == Some(&DATA)).map_err(|e| match e {
        SessionError::Refused => WireError::Stale,
        other => WireError::Session(other),
    })?;
    plaintext.remove(0);
    Ok(plaintext)
}

fn handshake_frame(kind: u8, at: Attempt, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(kind);
    out.extend_from_slice(&at.label());
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
            return if body.len() < MIN_SEALED + 1 { Err(WireError::Malformed) } else { Ok(Frame::Data(body)) };
        }
        HELLO => MESSAGE1_LEN,
        WELCOME => MESSAGE2_LEN,
        CONFIRM => MIN_SEALED + CONTROL_LEN + CONFIRM_MARKER.len(),
        ACK => MIN_SEALED + CONTROL_LEN + ACK_MARKER.len(),
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

    /// As [`Initiator::start`] with a retry policy. Refuses a `peer` key
    /// whose key agreement would not depend on our secret.
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
        let at = self.current();
        let (handshake, message1) =
            Handshake::initiate(&self.me, &self.peer, &self.network, &at.label(), &self.reference)?;
        let sent = handshake_frame(HELLO, at, &message1);
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
                        let record = session.seal(&control(CONFIRM, current, CONFIRM_MARKER))?;
                        let sent = handshake_frame(CONFIRM, current, &record);
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
                let expected = control(ACK, current, ACK_MARKER);
                let acknowledged = at == current && session.open_if(body, |p| p == expected).is_ok();
                if acknowledged {
                    self.state = State::Established(session);
                    Ok(InitiatorEvent::Established)
                } else {
                    self.state = State::Confirming { session, sent, resends };
                    Err(WireError::Stale)
                }
            }
            (Frame::Data(body), State::Confirming { mut session, sent, resends }) => match open_data(&mut session, body) {
                Ok(plaintext) => {
                    self.state = State::Established(session);
                    Ok(InitiatorEvent::Message(plaintext))
                }
                Err(error) => {
                    self.state = State::Confirming { session, sent, resends };
                    Err(error)
                }
            },
            (Frame::Data(body), State::Established(mut session)) => {
                let result = open_data(&mut session, body);
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
        data_frame(session, plaintext)
    }
}

// ---- responder -------------------------------------------------------------

/// Caps a responder enforces, so no caller can exhaust its tables. The
/// defaults are the named constants [`MAX_PENDING`],
/// [`MAX_PENDING_PER_CALLER`] and [`MAX_SESSIONS`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Answered, unconfirmed handshakes in total.
    pub pending: usize,
    /// Answered, unconfirmed handshakes for one authenticated caller key.
    pub pending_per_caller: usize,
    /// Live sessions in total (one per caller key).
    pub sessions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { pending: MAX_PENDING, pending_per_caller: MAX_PENDING_PER_CALLER, sessions: MAX_SESSIONS }
    }
}

/// The answering side, serving many callers at once. It holds the handshake
/// key callers reach and the [`Gate`] that decides who is answered; both are
/// built from one network id. Live sessions are keyed by the caller's
/// authenticated key, one per caller; the reply handle a session answers on
/// is updated when the caller's transport handle changes (2026-11-20 audit
/// HIGH-02).
pub struct Responder<T> {
    me: StaticKey,
    gate: Gate,
    limits: Limits,
    /// Answered but unconfirmed handshakes, one per reply handle and call id.
    pending: HashMap<(T, u32), Pending>,
    /// Live sessions by caller key.
    sessions: HashMap<[u8; 32], Live<T>>,
    /// Reply handle -> the caller key whose session answers on it.
    routes: HashMap<T, [u8; 32]>,
    /// A new handle a caller repeated its CONFIRM from, at most one per
    /// caller (a newer one replaces it). The session moves there only when a
    /// fresh data frame from it decrypts, so a replayed CONFIRM cannot
    /// redirect anyone's replies, and replaying it from many handles cannot
    /// grow this table.
    candidates: HashMap<T, [u8; 32]>,
}

/// An answered HELLO, with the frame that started it and our WELCOME. A
/// repeat of the same HELLO gets the same WELCOME (after a fresh gate
/// check), so there is still exactly one handshake to finish.
struct Pending {
    attempt: u32,
    first: Vec<u8>,
    reply: Vec<u8>,
    session: Session,
    reference: [u8; REFERENCE_LEN],
    grant: Grant,
    deadline: Instant,
}

/// An established session, with the CONFIRM that finished it and our ACK,
/// so a lost ACK can be resent, and the reply handle it currently uses.
struct Live<T> {
    handle: T,
    at: Attempt,
    last: Vec<u8>,
    ack: Vec<u8>,
    session: Session,
    reference: [u8; REFERENCE_LEN],
    idle_deadline: Instant,
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

/// What [`Responder::expire`] dropped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Expired<T> {
    /// Answered handshakes whose CONFIRM never came.
    pub pending: Vec<T>,
    /// Sessions idle for longer than [`SESSION_IDLE_TIMEOUT`] (by the reply
    /// handle they last used).
    pub sessions: Vec<T>,
}

impl<T: Hash + Eq + Clone> Responder<T> {
    /// A responder for a contact identity: callers reach its handshake key,
    /// and it may record invitations its signing key issued.
    pub fn for_identity(me: &ContactIdentity, network: Network) -> Self {
        Self::build(me.handshake_key().clone(), Gate::new(network, Some(me.signing_key())))
    }

    /// A stranger's callback listener (reverse rendezvous): answers only
    /// `caller` naming `reference`, until `deadline`.
    pub fn for_callback(
        callback: &StaticKey,
        network: Network,
        caller: [u8; 32],
        reference: [u8; REFERENCE_LEN],
        deadline: Instant,
    ) -> Result<Self, ContactError> {
        let mut gate = Gate::new(network, None);
        gate.expect_callback(caller, reference, deadline)?;
        Ok(Self::build(callback.clone(), gate))
    }

    fn build(me: StaticKey, gate: Gate) -> Self {
        Responder {
            me,
            gate,
            limits: Limits::default(),
            pending: HashMap::new(),
            sessions: HashMap::new(),
            routes: HashMap::new(),
            candidates: HashMap::new(),
        }
    }

    /// Replace the default caps.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn network(&self) -> Network {
        self.gate.network()
    }

    /// Read-only view of the gate.
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// Let the holder of an invitation we issued call us. The invitation is
    /// checked here: our signing key, signature, network, holder key, expiry.
    pub fn record_invitation(&mut self, invitation: Invitation, now: Now) -> Result<(), ContactError> {
        self.gate.record_invitation(invitation, now)
    }

    /// Block a caller key: refused from now on. In the same step its
    /// sessions, pending handshakes and cached replies are dropped and its
    /// unused invitation and outstanding callback grant are cancelled;
    /// unblocking restores none of them.
    pub fn block(&mut self, caller: [u8; 32]) {
        self.gate.block(caller);
        self.drop_peer(&caller);
    }

    pub fn unblock(&mut self, caller: &[u8; 32]) {
        self.gate.unblock(caller);
    }

    /// End a relationship without blocking: the caller key is no longer a
    /// contact, and in the same step its sessions, pending handshakes and
    /// cached replies are dropped and its unused invitation and outstanding
    /// callback grant are cancelled. Reopening needs a new invitation.
    pub fn remove_contact(&mut self, caller: [u8; 32]) {
        self.gate.remove_contact(&caller);
        self.drop_peer(&caller);
    }

    fn drop_peer(&mut self, caller: &[u8; 32]) {
        self.pending.retain(|_, p| &p.session.peer() != caller);
        self.sessions.remove(caller);
        self.routes.retain(|_, c| c != caller);
        self.candidates.retain(|_, c| c != caller);
    }

    /// Drop answered handshakes past their deadline and sessions idle past
    /// theirs. Runs at the start of every operation; drivers may also call
    /// it on a timer.
    pub fn expire(&mut self, now: Now) -> Expired<T> {
        let mut out = Expired { pending: Vec::new(), sessions: Vec::new() };
        self.pending.retain(|(from, _), p| {
            let keep = now.mono < p.deadline;
            if !keep {
                out.pending.push(from.clone());
            }
            keep
        });
        let mut gone = Vec::new();
        self.sessions.retain(|caller, live| {
            let keep = now.mono < live.idle_deadline;
            if !keep {
                out.sessions.push(live.handle.clone());
                gone.push(*caller);
            }
            keep
        });
        if !gone.is_empty() {
            self.routes.retain(|_, c| !gone.contains(c));
            self.candidates.retain(|_, c| !gone.contains(c));
        }
        out
    }

    /// The live session answering on `from`, if it is still admitted by the
    /// gate; one that is not is dropped.
    fn live(&mut self, from: &T) -> Result<&mut Live<T>, WireError> {
        let caller = *self.routes.get(from).ok_or(WireError::NoSession)?;
        self.admitted(caller)
    }

    fn admitted(&mut self, caller: [u8; 32]) -> Result<&mut Live<T>, WireError> {
        let admitted = match self.sessions.get(&caller) {
            None => return Err(WireError::NoSession),
            Some(live) => self.gate.admits(&caller, &live.reference),
        };
        if !admitted {
            self.drop_peer(&caller);
            return Err(WireError::Unauthorised);
        }
        Ok(self.sessions.get_mut(&caller).expect("checked above"))
    }

    /// Point `caller`'s session at reply handle `to`.
    fn reroute(&mut self, caller: [u8; 32], to: T) {
        self.candidates.remove(&to);
        if let Some(live) = self.sessions.get_mut(&caller) {
            if live.handle != to {
                self.routes.remove(&live.handle);
                live.handle = to.clone();
            }
            self.routes.insert(to, caller);
        }
    }

    /// A data frame: on the session's own handle, or on a candidate handle,
    /// which then becomes the session's handle once the frame decrypts.
    fn data(&mut self, from: T, body: &[u8], now: Now) -> Result<ResponderEvent, WireError> {
        let (caller, moving) = match self.routes.get(&from) {
            Some(c) => (*c, false),
            None => (*self.candidates.get(&from).ok_or(WireError::NoSession)?, true),
        };
        let live = self.admitted(caller)?;
        let plaintext = open_data(&mut live.session, body)?;
        live.idle_deadline = now.mono + SESSION_IDLE_TIMEOUT;
        let peer = live.session.peer();
        if moving {
            self.reroute(caller, from);
        }
        Ok(ResponderEvent::Message { peer, plaintext })
    }

    /// Handle one frame at `now`. `Err` always means: send nothing.
    pub fn handle(&mut self, from: T, incoming: &[u8], now: Now) -> Result<ResponderEvent, WireError> {
        self.expire(now);
        let (kind, at, body) = match parse(incoming)? {
            Frame::Data(body) => return self.data(from, body, now),
            Frame::Handshake { kind, at, body } => (kind, at, body),
        };
        match kind {
            HELLO => self.hello(from, at, body, incoming, now),
            CONFIRM => self.confirm(from, at, body, incoming, now),
            _ => Err(WireError::Stale),
        }
    }

    fn hello(&mut self, from: T, at: Attempt, body: &[u8], incoming: &[u8], now: Now) -> Result<ResponderEvent, WireError> {
        // Attempts of a call we already finished are over.
        let finished = self.routes.get(&from).and_then(|c| self.sessions.get(c));
        if finished.map_or(false, |live| live.at.call == at.call && at.number <= live.at.number) {
            return Err(WireError::Stale);
        }
        let key = (from, at.call);
        let replacing = if let Some(pending) = self.pending.get(&key) {
            if at.number < pending.attempt || (at.number == pending.attempt && pending.first != incoming) {
                return Err(WireError::Stale);
            }
            if at.number == pending.attempt {
                // A repeat gets the cached answer, but only while the caller
                // is still authorised for the same grant.
                if self.gate.authorise(&pending.session.peer(), &pending.reference, now) != Some(pending.grant) {
                    self.pending.remove(&key);
                    return Err(WireError::Unauthorised);
                }
                return Ok(ResponderEvent::Reply(pending.reply.clone()));
            }
            true
        } else {
            if self.pending.len() >= self.limits.pending {
                return Err(WireError::Busy);
            }
            false
        };
        let hello = Incoming::read(&self.me, &self.gate.network(), &at.label(), body)?;
        let (caller, reference) = (hello.caller(), hello.reference());
        // The decision, before anything is written.
        let grant = self.gate.authorise(&caller, &reference, now).ok_or(WireError::Unauthorised)?;
        // One caller may not hold more than its share of answered handshakes.
        let held = self.pending.values().filter(|p| p.session.peer() == caller).count();
        if !replacing && held >= self.limits.pending_per_caller {
            return Err(WireError::Busy);
        }
        let (session, message2) = hello.accept()?;
        let reply = handshake_frame(WELCOME, at, &message2);
        let pending = Pending {
            attempt: at.number,
            first: incoming.to_vec(),
            reply: reply.clone(),
            session,
            reference,
            grant,
            deadline: now.mono + PENDING_TIMEOUT,
        };
        self.pending.insert(key, pending);
        Ok(ResponderEvent::Reply(reply))
    }

    fn confirm(&mut self, from: T, at: Attempt, body: &[u8], incoming: &[u8], now: Now) -> Result<ResponderEvent, WireError> {
        // 1. The exact attempt that is already live: our ACK was lost. If it
        //    comes from a new handle, answer there and note the handle as a
        //    candidate; the session moves only on fresh data from it.
        let repeat = self.sessions.iter().find(|(_, live)| live.at == at && live.last == incoming).map(|(c, _)| *c);
        if let Some(caller) = repeat {
            let live = self.admitted(caller)?;
            let (ack, handle) = (live.ack.clone(), live.handle.clone());
            if handle != from {
                self.candidates.retain(|_, c| *c != caller);
                self.candidates.insert(from, caller);
            }
            return Ok(ResponderEvent::Reply(ack));
        }
        // 2. The matching pending attempt (possibly newer than a live one).
        let key = (from.clone(), at.call);
        let peer = self.pending.get(&key).filter(|p| p.attempt == at.number).ok_or(WireError::Stale)?.session.peer();
        // At the session cap a new caller is refused before its CONFIRM is
        // opened, so the same CONFIRM still counts once a place is free.
        if !self.sessions.contains_key(&peer) && self.sessions.len() >= self.limits.sessions {
            return Err(WireError::Busy); // nothing committed
        }
        let pending = self.pending.get_mut(&key).expect("found above");
        // A transport message: a bad one is dropped; the attempt stays.
        let expected = control(CONFIRM, at, CONFIRM_MARKER);
        if pending.session.open_if(body, |p| p == expected).is_err() {
            return Err(WireError::Stale);
        }
        let mut pending = self.pending.remove(&key).expect("found above");
        if !self.gate.commit(&peer, &pending.reference, pending.grant, now) {
            return Err(WireError::Unauthorised); // blocked, used or expired meanwhile
        }
        // This caller is now talking to us: its other half-finished
        // handshakes (on any handle) are over, and an older session of its
        // is replaced, on whatever handle it used.
        self.pending.retain(|(t, _), p| *t != from && p.session.peer() != peer);
        if let Some(old) = self.sessions.remove(&peer) {
            self.routes.remove(&old.handle);
        }
        self.candidates.retain(|t, c| *c != peer && *t != from);
        if let Some(other) = self.routes.insert(from.clone(), peer) {
            if other != peer {
                // A handle answers one caller: the other caller's session
                // and candidate handles go.
                self.sessions.remove(&other);
                self.candidates.retain(|_, c| *c != other);
            }
        }
        let ack = handshake_frame(ACK, at, &pending.session.seal(&control(ACK, at, ACK_MARKER))?);
        let grant = pending.grant;
        let live = Live {
            handle: from,
            at,
            last: incoming.to_vec(),
            ack: ack.clone(),
            session: pending.session,
            reference: pending.reference,
            idle_deadline: now.mono + SESSION_IDLE_TIMEOUT,
        };
        self.sessions.insert(peer, live);
        Ok(ResponderEvent::Established { peer, grant, reply: ack })
    }

    pub fn seal(&mut self, to: &T, plaintext: &[u8], now: Now) -> Result<Vec<u8>, WireError> {
        self.expire(now);
        let live = self.live(to)?;
        let frame = data_frame(&mut live.session, plaintext)?;
        live.idle_deadline = now.mono + SESSION_IDLE_TIMEOUT;
        Ok(frame)
    }

    /// How many answered handshakes are waiting for a CONFIRM.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// How many candidate handles are remembered (at most one per caller).
    pub fn candidate_handles(&self) -> usize {
        self.candidates.len()
    }

    /// How many live sessions there are (one per caller key).
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Is there a live session answering on this reply handle?
    pub fn is_live(&self, from: &T) -> bool {
        self.routes.get(from).is_some_and(|c| self.sessions.contains_key(c))
    }

    /// Drop a caller's reply handle: the session answering on it and the
    /// pending handshakes that arrived on it.
    pub fn forget(&mut self, from: &T) {
        self.pending.retain(|(t, _), _| t != from);
        self.candidates.remove(from);
        if let Some(caller) = self.routes.remove(from) {
            self.sessions.remove(&caller);
            self.candidates.retain(|_, c| *c != caller);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Rules that the public API cannot reach on its own: they back up the
    //! public guarantees if the crate's internals change.

    use super::*;
    use crate::contact::Purpose;

    const NET: Network = [9; 32];

    fn now() -> Now {
        Now { unix: 1_000, mono: Instant::now() }
    }

    fn setup() -> (Responder<u32>, Initiator, Vec<u8>) {
        let bob = ContactIdentity::generate();
        let mut side = Responder::for_identity(&bob, NET);
        let key = StaticKey::generate();
        let invitation = bob.invite(NET, key.public(), Purpose::Contact, 5_000);
        let id = invitation.id;
        side.record_invitation(invitation, now()).unwrap();
        let (call, hello) =
            Initiator::start_with(&key, bob.handshake_key().public(), NET, id, RetryPolicy::default()).unwrap();
        (side, call, hello)
    }

    fn welcome(side: &mut Responder<u32>, hello: &[u8]) -> Vec<u8> {
        match side.handle(1, hello, now()).unwrap() {
            ResponderEvent::Reply(f) => f,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_live_session_checks_the_gate_on_every_use() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        let ResponderEvent::Established { peer, reply, .. } = side.handle(1, &confirm, now()).unwrap() else { panic!() };
        call.handle(&reply).unwrap();
        // Change the gate alone, without the responder's revocation path.
        side.gate.block(peer);
        assert!(matches!(side.handle(1, &confirm, now()), Err(WireError::Unauthorised)), "no cached ACK");
        let frame = call.seal(b"x").unwrap();
        assert!(side.handle(1, &frame, now()).is_err(), "no data in");
        assert!(side.seal(&1, b"y", now()).is_err(), "no data out");
    }

    #[test]
    fn a_record_of_another_type_in_a_confirm_frame_is_refused() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        // Seal a DATA-typed record of CONFIRM size in the caller's session.
        let State::Confirming { session, .. } = &mut call.state else { panic!() };
        let mut inner = vec![DATA];
        inner.resize(CONTROL_LEN + CONFIRM_MARKER.len(), 0x55);
        let forged = [&confirm[..HEADER_LEN], session.seal(&inner).unwrap().as_slice()].concat();
        assert_eq!(forged.len(), confirm.len());
        assert!(matches!(side.handle(1, &forged, now()), Err(WireError::Stale)));
        assert!(matches!(side.handle(1, &confirm, now()), Ok(ResponderEvent::Established { .. })));
    }
}
