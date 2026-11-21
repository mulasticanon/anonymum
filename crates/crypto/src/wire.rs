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
//! * **Data frames use a Double Ratchet** ([`crate::ratchet`], unreviewed).
//!   CONFIRM carries the caller's fresh 32-byte seed and a fresh ephemeral
//!   ratchet public key (`dh_i0`); ACK carries the answerer's fresh seed
//!   and its first ratchet public key (`dh_r0`). Either key is refused if
//!   small-order. Both sides derive the first root key from the two seeds
//!   and the IK handshake hash. The answerer starts the ratchet ("Alice")
//!   against `dh_i0`, never the caller's static key, so it can send at
//!   once; the caller takes the first ratchet step when the ACK arrives. Data frames that
//!   reach the caller before the ACK are held ([`MAX_EARLY_DATA`]) and
//!   opened afterwards ([`Initiator::take_early`]). The Noise session
//!   carries only CONFIRM and ACK.
//!
//! * **Handshake keys rotate with the identity's epochs.** A responder
//!   holds the active epoch's handshake key and, during the draining
//!   epoch's grace ([`crate::contact::DRAIN_GRACE`] past its end), the
//!   draining one. A HELLO is read with the active key first; the draining
//!   key is tried only if that read fails as a Noise decryption error (so a
//!   HELLO the active key opened but the gate refuses is never retried).
//!   The draining key is dropped (wiped) once its grace ends, judged by the
//!   gate's clock floor, or when [`Responder::refresh_keys`] is given an
//!   identity that purged it; a recorded HELLO to it then fails. Unreviewed.
//! * **Contacts roll their keys forward.** A contact recorded with its
//!   signing key ([`Responder::bind_contact_card`]) can present a new card
//!   from the same signing key ([`Responder::roll_contact_key`]); its grant
//!   moves to the new handshake key, and the old key stays admitted for
//!   [`crate::contact::DRAIN_GRACE`] so calls already in flight finish.
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
//!   the deadline it was given (Unix seconds, so it survives a restart).
//! * **A session moves to a new reply handle only on fresh data.** A
//!   repeated CONFIRM from a new handle is answered there but only marks the
//!   handle as a candidate; the session moves when a data frame from it
//!   opens in the ratchet. A replayed data frame does not open (its key was
//!   erased) and changes nothing.
//!   The first two use the injected monotonic clock, the third the injected
//!   wall clock; all are checked on every operation.
//!
//! # Persist before reply
//!
//! A responder's [`Gate`] can be saved, encrypted, with
//! [`Responder::export_snapshot`] and restored with
//! [`Responder::restore_identity`] or [`Responder::restore_callback`]
//! (format in [`crate::snapshot`]). A caller that keeps grant state across
//! restarts must follow one rule: **after anything changes the gate, write
//! a fresh snapshot durably (temporary file, flush, rename:
//! [`crate::snapshot::write_atomically`]) before sending the frame that
//! change produced.** In practice:
//!
//! * [`ResponderEvent::Established`]: the grant was committed (an
//!   invitation consumed, a caller made a contact, a callback used). Persist,
//!   then send its ACK. If the process dies before the snapshot is written,
//!   no ACK went out and the restored gate still shows the grant unused, so
//!   the caller's retry is answered as the first try was; once the ACK has
//!   gone out, the consumption is on disk and a replay after a restart is
//!   refused.
//! * [`Responder::record_invitation`], [`Responder::block`],
//!   [`Responder::unblock`], [`Responder::remove_contact`]: persist before
//!   telling anyone the change was made.
//! * A WELCOME ([`ResponderEvent::Reply`] to a HELLO) changes no persistent
//!   state, so it needs no new snapshot.
//!
//! Live sessions and unconfirmed handshakes are not persisted; after a
//! restart callers handshake again (a contact is let in by its grant). One
//! device per identity: the snapshot is crash safety for a single device,
//! not a way to share a gate between devices.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use zeroize::Zeroizing;

use crate::contact::{
    is_contributory_key, random_bytes, ContactCard, ContactError, ContactIdentity, Invitation, Network, StaticKey,
};
use crate::gate::{Gate, Grant, Now};
use crate::ratchet::{self, Ratchet, RatchetError, RatchetKey};
use crate::snapshot::{self, SnapshotError, StorageKey};
use crate::session::{
    Handshake, Incoming, Session, SessionError, MAX_PLAINTEXT, MESSAGE1_LEN, MESSAGE2_LEN, MIN_SEALED, REFERENCE_LEN,
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
const CONFIRM_MARKER: &[u8] = b"anonymum/confirm/v5";
const ACK_MARKER: &[u8] = b"anonymum/acknowledge/v5";
/// Inner record: type byte, then call id and attempt for control records.
const CONTROL_LEN: usize = 1 + 8;
/// A fresh random seed each side contributes to the ratchet's root key.
const SEED_LEN: usize = 32;
/// CONFIRM's plaintext: control record, marker, the caller's seed and its
/// ephemeral first ratchet public key.
const CONFIRM_LEN: usize = CONTROL_LEN + CONFIRM_MARKER.len() + SEED_LEN + 32;
/// ACK's plaintext: control record, marker, the answerer's seed and its
/// first ratchet public key.
const ACK_LEN: usize = CONTROL_LEN + ACK_MARKER.len() + SEED_LEN + 32;

/// The longest valid frame: a data frame carrying [`MAX_DATA`].
pub const MAX_FRAME: usize = 1 + ratchet::MAX_MESSAGE;
/// Most data frames a caller holds while it waits for the ACK (they cannot
/// be opened before it: the ACK carries the answerer's ratchet seed).
pub const MAX_EARLY_DATA: usize = 16;
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
    /// A data frame the Double Ratchet refused; nothing changed.
    Ratchet(RatchetError),
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

/// The plaintext of a CONFIRM: its control record, the caller's seed and
/// its ephemeral first ratchet public key.
fn confirm_record(at: Attempt, seed: &[u8; SEED_LEN], ratchet_key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([control(CONFIRM, at, CONFIRM_MARKER).as_slice(), seed, ratchet_key].concat())
}

/// The plaintext of an ACK: control record, the answerer's seed and its
/// first ratchet public key.
fn ack_record(at: Attempt, seed: &[u8; SEED_LEN], ratchet_key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([control(ACK, at, ACK_MARKER).as_slice(), seed, ratchet_key].concat())
}

/// A data frame: `DATA || ratchet message`, the inner record typed DATA.
fn data_frame(ratchet: &mut Ratchet, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
    if plaintext.len() > MAX_DATA {
        return Err(SessionError::TooLarge.into());
    }
    let inner = Zeroizing::new([&[DATA], plaintext].concat());
    let sealed = ratchet.encrypt(&inner).map_err(WireError::Ratchet)?;
    Ok([&[DATA], sealed.as_slice()].concat())
}

/// Open a data frame's body with the ratchet: the inner type must be DATA.
/// A refusal or failure changes nothing in the ratchet.
fn open_data(ratchet: &mut Ratchet, body: &[u8]) -> Result<Vec<u8>, WireError> {
    let plaintext = ratchet.decrypt_if(body, |p| p.first() == Some(&DATA)).map_err(|e| match e {
        RatchetError::Refused => WireError::Stale,
        other => WireError::Ratchet(other),
    })?;
    Ok(plaintext[1..].to_vec())
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
            return if body.len() < ratchet::MIN_MESSAGE + 1 { Err(WireError::Malformed) } else { Ok(Frame::Data(body)) };
        }
        HELLO => MESSAGE1_LEN,
        WELCOME => MESSAGE2_LEN,
        CONFIRM => MIN_SEALED + CONFIRM_LEN,
        ACK => MIN_SEALED + ACK_LEN,
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
    /// Messages that arrived before the ACK, opened once it came.
    early: Vec<Vec<u8>>,
}

enum State {
    /// HELLO sent; waiting for WELCOME.
    Handshaking { handshake: Handshake, sent: Vec<u8>, resends: u32 },
    /// CONFIRM (carrying `seed` and the public half of `ratchet_key`) sent;
    /// waiting for the answerer's ACK. Data frames that arrive first are
    /// held in `held`, unopened.
    Confirming {
        session: Session,
        seed: Zeroizing<[u8; SEED_LEN]>,
        ratchet_key: RatchetKey,
        sent: Vec<u8>,
        resends: u32,
        held: Vec<Vec<u8>>,
    },
    Established(Ratchet),
    /// The last attempt failed; the next starts after [`Initiator::wait`].
    Waiting,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitiatorEvent {
    /// Send this frame to the peer (the CONFIRM).
    Send(Vec<u8>),
    /// The answerer acknowledged; [`Initiator::seal`] is usable. Messages
    /// that arrived before the ACK are in [`Initiator::take_early`].
    Established,
    /// A message.
    Message(Vec<u8>),
    /// A data frame arrived before the ACK. It is held (at most
    /// [`MAX_EARLY_DATA`]) and opened when the ACK comes.
    Held,
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
            early: Vec::new(),
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

    /// Messages that arrived before the ACK and opened once it came, in
    /// arrival order. Each is returned once.
    pub fn take_early(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.early)
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
                        let seed = Zeroizing::new(random_bytes());
                        let ratchet_key = RatchetKey::generate();
                        let record = session.seal(&confirm_record(current, &seed, &ratchet_key.public()))?;
                        let sent = handshake_frame(CONFIRM, current, &record);
                        self.state = State::Confirming {
                            session,
                            seed,
                            ratchet_key,
                            sent: sent.clone(),
                            resends: 0,
                            held: Vec::new(),
                        };
                        Ok(InitiatorEvent::Send(sent))
                    }
                    Err(error) => {
                        self.state = State::Waiting;
                        Err(WireError::AttemptFailed(error))
                    }
                }
            }
            (Frame::Handshake { kind: ACK, at, body }, State::Confirming { mut session, seed, ratchet_key, sent, resends, held }) => {
                // The answerer's seed and first ratchet key, inside the
                // sealed ACK; a small-order ratchet key is refused before
                // the record counts.
                let expected = control(ACK, current, ACK_MARKER);
                let keys_at = expected.len();
                let opened = (at == current)
                    .then(|| {
                        session.open_if(body, |p| {
                            p.len() == ACK_LEN
                                && p.starts_with(&expected)
                                && is_contributory_key(p[keys_at + SEED_LEN..].try_into().expect("32 bytes"))
                        })
                    })
                    .and_then(Result::ok)
                    .map(Zeroizing::new);
                let Some(record) = opened else {
                    self.state = State::Confirming { session, seed, ratchet_key, sent, resends, held };
                    return Err(WireError::Stale);
                };
                let seed_r: [u8; SEED_LEN] = record[keys_at..keys_at + SEED_LEN].try_into().expect("32 bytes");
                let seed_r = Zeroizing::new(seed_r);
                let dh_r0: [u8; 32] = record[keys_at + SEED_LEN..].try_into().expect("32 bytes");
                let root = ratchet::root_from_handshake(&seed, &seed_r, session.handshake_hash());
                // Our ephemeral key is the one the answerer started from;
                // the first step with its key happens now.
                let mut ratchet =
                    Ratchet::respond_to(&root, self.network, ratchet_key, dh_r0).map_err(WireError::Ratchet)?;
                for frame in held {
                    if let Ok(plaintext) = open_data(&mut ratchet, &frame) {
                        self.early.push(plaintext);
                    }
                }
                self.state = State::Established(ratchet);
                Ok(InitiatorEvent::Established)
            }
            (Frame::Data(body), State::Confirming { session, seed, ratchet_key, sent, resends, mut held }) => {
                let kept = held.len() < MAX_EARLY_DATA;
                if kept {
                    held.push(body.to_vec());
                }
                self.state = State::Confirming { session, seed, ratchet_key, sent, resends, held };
                if kept { Ok(InitiatorEvent::Held) } else { Err(WireError::Busy) }
            }
            (Frame::Data(body), State::Established(mut ratchet)) => {
                let result = open_data(&mut ratchet, body);
                self.state = State::Established(ratchet);
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
        let State::Established(ratchet) = &mut self.state else { return Err(WireError::NoSession) };
        data_frame(ratchet, plaintext)
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
    keys: HandshakeKeys,
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

/// The handshake keys a responder answers on: the active one, and the
/// draining one with the Unix time its grace ends.
struct HandshakeKeys {
    active: StaticKey,
    draining: Option<(StaticKey, u64)>,
}

impl HandshakeKeys {
    fn single(key: &StaticKey) -> Self {
        HandshakeKeys { active: key.clone(), draining: None }
    }

    fn of(me: &ContactIdentity) -> Self {
        HandshakeKeys {
            active: me.handshake_key().clone(),
            draining: me.draining().map(|d| (d.handshake_key().clone(), d.grace_end())),
        }
    }

    /// The draining key, if its grace has not ended at `now_secs`.
    fn draining_at(&self, now_secs: u64) -> Option<&StaticKey> {
        self.draining.as_ref().filter(|(_, end)| now_secs < *end).map(|(key, _)| key)
    }
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
/// Data frames use the Double Ratchet; the Noise session is not kept.
struct Live<T> {
    handle: T,
    at: Attempt,
    last: Vec<u8>,
    ack: Vec<u8>,
    peer: [u8; 32],
    ratchet: Ratchet,
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
    ///
    /// It answers on the identity's active handshake key and, during its
    /// grace, the draining one. After [`ContactIdentity::rotate_epoch`] or
    /// [`ContactIdentity::purge_expired`], pass the identity to
    /// [`Responder::refresh_keys`].
    pub fn for_identity(me: &ContactIdentity, network: Network) -> Self {
        Self::build(HandshakeKeys::of(me), Gate::new(network, Some(me.signing_key())))
    }

    /// A stranger's callback listener (reverse rendezvous): answers only
    /// `caller` naming `reference`, until `deadline` (Unix seconds).
    pub fn for_callback(
        callback: &StaticKey,
        network: Network,
        caller: [u8; 32],
        reference: [u8; REFERENCE_LEN],
        deadline: u64,
    ) -> Result<Self, ContactError> {
        let mut gate = Gate::new(network, None);
        gate.expect_callback(caller, reference, deadline)?;
        Ok(Self::build(HandshakeKeys::single(callback), gate))
    }

    /// A stranger's callback listener on a contact identity's handshake
    /// keys: as [`Responder::for_callback`], but it also answers on the
    /// draining epoch's key during its grace. So a stranger who rotated
    /// right after sealing a note (its card naming the old handshake key)
    /// can still be called back, until that key is purged.
    pub fn for_callback_identity(
        me: &ContactIdentity,
        network: Network,
        caller: [u8; 32],
        reference: [u8; REFERENCE_LEN],
        deadline: u64,
    ) -> Result<Self, ContactError> {
        let mut gate = Gate::new(network, None);
        gate.expect_callback(caller, reference, deadline)?;
        Ok(Self::build(HandshakeKeys::of(me), gate))
    }

    /// Take the handshake keys of `me` again, after it rotated or purged
    /// an epoch: a purged key is dropped (wiped) here. An identity
    /// responder refuses another identity's keys.
    pub fn refresh_keys(&mut self, me: &ContactIdentity) -> Result<(), ContactError> {
        if self.gate.issuer().is_some_and(|issuer| issuer != me.signing_key()) {
            return Err(ContactError::WrongIssuer);
        }
        self.keys = HandshakeKeys::of(me);
        Ok(())
    }

    /// The handshake public keys this responder answers on now: the active
    /// one and, during its grace, the draining one.
    pub fn handshake_keys(&self) -> Vec<[u8; 32]> {
        let mut out = vec![self.keys.active.public()];
        out.extend(self.keys.draining_at(self.gate.last_seen()).map(StaticKey::public));
        out
    }

    fn build(keys: HandshakeKeys, gate: Gate) -> Self {
        Responder {
            keys,
            gate,
            limits: Limits::default(),
            pending: HashMap::new(),
            sessions: HashMap::new(),
            routes: HashMap::new(),
            candidates: HashMap::new(),
        }
    }

    /// The gate's state at `now` (its clock floor moved up to `now` first),
    /// encrypted under `key` for this responder's network with a fresh
    /// nonce. Write it durably before replying (see the module
    /// documentation, "Persist before reply").
    pub fn export_snapshot(&mut self, key: &StorageKey, now: Now) -> Vec<u8> {
        self.gate.effective_now(now.unix);
        let plaintext = zeroize::Zeroizing::new(self.gate.encode());
        snapshot::seal(key, &self.gate.network(), &plaintext)
    }

    /// A responder for `me` restored from a snapshot it exported. Fails
    /// loudly (never an empty gate) on an unknown version, the wrong key or
    /// network, a modified or truncated snapshot, or another identity's.
    pub fn restore_identity(
        me: &ContactIdentity,
        network: Network,
        key: &StorageKey,
        saved: &[u8],
    ) -> Result<Self, SnapshotError> {
        let gate = Self::restore_gate(network, key, saved)?;
        if gate.issuer() != Some(me.signing_key()) {
            return Err(SnapshotError::WrongIdentity);
        }
        Ok(Self::build(HandshakeKeys::of(me), gate))
    }

    /// A callback listener restored from a snapshot it exported; as
    /// [`Responder::restore_identity`], for a gate that issues nothing.
    pub fn restore_callback(
        callback: &StaticKey,
        network: Network,
        key: &StorageKey,
        saved: &[u8],
    ) -> Result<Self, SnapshotError> {
        let gate = Self::restore_gate(network, key, saved)?;
        if gate.issuer().is_some() {
            return Err(SnapshotError::WrongIdentity);
        }
        Ok(Self::build(HandshakeKeys::single(callback), gate))
    }

    /// A callback listener on a contact identity's handshake keys, restored
    /// from a snapshot it exported (see [`Responder::for_callback_identity`]).
    pub fn restore_callback_identity(
        me: &ContactIdentity,
        network: Network,
        key: &StorageKey,
        saved: &[u8],
    ) -> Result<Self, SnapshotError> {
        let gate = Self::restore_gate(network, key, saved)?;
        if gate.issuer().is_some() {
            return Err(SnapshotError::WrongIdentity);
        }
        Ok(Self::build(HandshakeKeys::of(me), gate))
    }

    fn restore_gate(network: Network, key: &StorageKey, saved: &[u8]) -> Result<Gate, SnapshotError> {
        let plaintext = snapshot::open(key, &network, saved)?;
        Gate::decode(&plaintext, &network)
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
    ///
    /// A contact's other handshake keys known through a rollover (its
    /// retiring key, or its current one when an old key is named) are
    /// blocked with it.
    pub fn block(&mut self, caller: [u8; 32]) {
        for key in self.gate.keys_of(&caller) {
            self.gate.block(key);
            self.drop_peer(&key);
        }
    }

    pub fn unblock(&mut self, caller: &[u8; 32]) {
        self.gate.unblock(caller);
    }

    /// End a relationship without blocking: the caller key is no longer a
    /// contact, and in the same step its sessions, pending handshakes and
    /// cached replies are dropped and its unused invitation and outstanding
    /// callback grant are cancelled. Reopening needs a new invitation.
    /// A contact's other handshake keys known through a rollover go too.
    pub fn remove_contact(&mut self, caller: [u8; 32]) {
        for key in self.gate.keys_of(&caller) {
            self.gate.remove_contact(&key);
            self.drop_peer(&key);
        }
    }

    /// Record who a contact or an expected callback is: `card`'s signing
    /// key, for the grant held by its handshake key. The card must verify
    /// for this network at `now`. Needed before
    /// [`Responder::roll_contact_key`] can move that contact to a new key.
    /// Persist the gate afterwards.
    pub fn bind_contact_card(&mut self, card: &ContactCard, now: Now) -> Result<(), ContactError> {
        self.gate.bind_signer(card, now)
    }

    /// Move a contact to the handshake key on `card`, a fresh card from the
    /// same signing key: the card must verify for this network at `now`,
    /// its signing key must be the one recorded for a current contact, and
    /// its `not_after` must be later than the bound card's
    /// ([`ContactError::StaleCard`] otherwise, nothing changed), so an older
    /// card that is still valid cannot move a contact back to an older key.
    /// The contact's grant moves to the new key; the old key stays admitted
    /// for [`crate::contact::DRAIN_GRACE`] (so calls in flight finish) and
    /// is then dropped with its sessions. Returns the old key. Persist the
    /// gate before telling anyone.
    pub fn roll_contact_key(&mut self, card: &ContactCard, now: Now) -> Result<[u8; 32], ContactError> {
        self.gate.roll_key(card, now)
    }

    fn drop_peer(&mut self, caller: &[u8; 32]) {
        self.pending.retain(|_, p| &p.session.peer() != caller);
        self.sessions.remove(caller);
        self.routes.retain(|_, c| c != caller);
        self.candidates.retain(|_, c| c != caller);
    }

    /// Drop answered handshakes past their deadline and sessions idle past
    /// theirs, and prune the gate of grants and revocations that can no
    /// longer matter ([`Gate::prune`]). Runs at the start of every
    /// operation; drivers may also call it on a timer.
    pub fn expire(&mut self, now: Now) -> Expired<T> {
        self.gate.prune(now.unix);
        // The draining handshake key goes once its grace has ended, by the
        // gate's clock floor (a clock set back cannot bring it back).
        if self.keys.draining_at(self.gate.last_seen()).is_none() {
            self.keys.draining = None;
        }
        let gone_keys = self.gate.take_retired();
        for key in &gone_keys {
            self.drop_peer(key);
        }
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
        // Only a fresh frame that the ratchet opens counts; a replayed or
        // forged one changes nothing, so it cannot move the session.
        let plaintext = open_data(&mut live.ratchet, body)?;
        live.idle_deadline = now.mono + SESSION_IDLE_TIMEOUT;
        let peer = live.peer;
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
        let hello = self.read_hello(&at, body)?;
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

    /// Read a HELLO with the active handshake key; only if that fails to
    /// decrypt, with the draining key during its grace. Any other outcome
    /// of the active read (an opened HELLO, a weak caller key, a size
    /// error) is final.
    fn read_hello(&self, at: &Attempt, body: &[u8]) -> Result<Incoming, WireError> {
        let network = self.gate.network();
        match Incoming::read(&self.keys.active, &network, &at.label(), body) {
            Err(SessionError::Noise(error)) => match self.keys.draining_at(self.gate.last_seen()) {
                Some(draining) => Ok(Incoming::read(draining, &network, &at.label(), body)?),
                None => Err(SessionError::Noise(error).into()),
            },
            result => Ok(result?),
        }
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
        // A small-order ephemeral key is refused before the record counts.
        let keys_at = expected.len();
        let record = match pending.session.open_if(body, |p| {
            p.len() == CONFIRM_LEN
                && p.starts_with(&expected)
                && is_contributory_key(p[keys_at + SEED_LEN..].try_into().expect("32 bytes"))
        }) {
            Ok(record) => Zeroizing::new(record),
            Err(_) => return Err(WireError::Stale),
        };
        let seed_i: [u8; SEED_LEN] = record[keys_at..keys_at + SEED_LEN].try_into().expect("32 bytes");
        let seed_i = Zeroizing::new(seed_i);
        let dh_i0: [u8; 32] = record[keys_at + SEED_LEN..].try_into().expect("32 bytes");
        // Our seed and first ratchet key; the ratchet starts from the
        // caller's ephemeral key (inside the sealed CONFIRM), not its static
        // key, so that key's later theft does not open our first messages.
        let seed_r = Zeroizing::new(random_bytes());
        let own = RatchetKey::generate();
        let own_public = own.public();
        let root = ratchet::root_from_handshake(&seed_i, &seed_r, pending.session.handshake_hash());
        let ratchet = Ratchet::initiate_with(&root, self.gate.network(), own, dh_i0).map_err(WireError::Ratchet)?;
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
        let ack = handshake_frame(ACK, at, &pending.session.seal(&ack_record(at, &seed_r, &own_public))?);
        let grant = pending.grant;
        let live = Live {
            handle: from,
            at,
            last: incoming.to_vec(),
            ack: ack.clone(),
            peer,
            ratchet,
            reference: pending.reference,
            idle_deadline: now.mono + SESSION_IDLE_TIMEOUT,
        };
        self.sessions.insert(peer, live);
        Ok(ResponderEvent::Established { peer, grant, reply: ack })
    }

    pub fn seal(&mut self, to: &T, plaintext: &[u8], now: Now) -> Result<Vec<u8>, WireError> {
        self.expire(now);
        let live = self.live(to)?;
        let frame = data_frame(&mut live.ratchet, plaintext)?;
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
        let bob = ContactIdentity::generate_at(0);
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
        inner.resize(CONFIRM_LEN, 0x55);
        let forged = [&confirm[..HEADER_LEN], session.seal(&inner).unwrap().as_slice()].concat();
        assert_eq!(forged.len(), confirm.len());
        assert!(matches!(side.handle(1, &forged, now()), Err(WireError::Stale)));
        assert!(matches!(side.handle(1, &confirm, now()), Ok(ResponderEvent::Established { .. })));
    }

    #[test]
    fn an_ack_with_a_small_order_ratchet_key_is_refused_and_the_real_one_still_counts() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        let at = Attempt { call: call.call, number: 1 };
        // An ACK sealed in Bob's own pending session (so it authenticates),
        // naming a small-order first ratchet key.
        for weak in crate::contact::tests::SMALL_ORDER {
            let pending = side.pending.get_mut(&(1, at.call)).unwrap();
            let forged = handshake_frame(ACK, at, &pending.session.seal(&ack_record(at, &[7; SEED_LEN], &weak)).unwrap());
            assert!(matches!(call.handle(&forged), Err(WireError::Stale)));
            assert!(!call.is_established());
        }
        let ResponderEvent::Established { reply, .. } = side.handle(1, &confirm, now()).unwrap() else { panic!() };
        assert_eq!(call.handle(&reply).unwrap(), InitiatorEvent::Established);
        let frame = call.seal(b"x").unwrap();
        assert!(matches!(side.handle(1, &frame, now()), Ok(ResponderEvent::Message { .. })));
    }

    #[test]
    fn a_hello_the_active_key_opened_from_a_weak_caller_is_not_retried_with_the_draining_key() {
        let mut bob = ContactIdentity::generate_at(0);
        bob.rotate_epoch(crate::contact::EPOCH_LEN);
        let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
        let at = Attempt { call: 7, number: 1 };
        let when = Now { unix: crate::contact::EPOCH_LEN + 60, mono: Instant::now() };
        for weak in crate::contact::tests::SMALL_ORDER {
            for (tag, key) in [(1, bob.handshake_key().public()), (2, bob.draining().unwrap().handshake_key().public())] {
                let m1 = crate::session::tests::weak_message1(&key, &NET, &at.label(), &[1; 32], weak);
                let hello = handshake_frame(HELLO, at, &m1);
                // Read by the key it was sent to and refused there: a retry
                // with the other key would report a decryption failure.
                assert!(matches!(side.handle(tag, &hello, when), Err(WireError::Session(SessionError::WeakKey))));
            }
        }
    }

    #[test]
    fn a_confirm_with_a_small_order_ephemeral_key_is_refused_and_the_real_one_still_counts() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        let at = Attempt { call: call.call, number: 1 };
        let State::Confirming { session, .. } = &mut call.state else { panic!() };
        // Sealed in the caller's own session, so it authenticates.
        for weak in crate::contact::tests::SMALL_ORDER {
            let forged = handshake_frame(CONFIRM, at, &session.seal(&confirm_record(at, &[7; SEED_LEN], &weak)).unwrap());
            assert!(matches!(side.handle(1, &forged, now()), Err(WireError::Stale)));
            assert_eq!(side.sessions(), 0, "nothing committed");
            assert_eq!(side.pending(), 1, "the attempt stays");
        }
        let ResponderEvent::Established { reply, .. } = side.handle(1, &confirm, now()).unwrap() else { panic!() };
        assert_eq!(call.handle(&reply).unwrap(), InitiatorEvent::Established);
    }

    #[test]
    fn the_answerers_first_turn_uses_the_ephemeral_key_and_the_static_key_cannot_open_it() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        let ResponderEvent::Established { reply, .. } = side.handle(1, &confirm, now()).unwrap() else { panic!() };
        // The answerer speaks first.
        let first = side.seal(&1, b"first turn", now()).unwrap();
        let Frame::Data(first_body) = parse(&first).unwrap() else { panic!() };
        // The strongest thief: it has the caller's static secret and even
        // the root key (both seeds and the transcript hash).
        let static_secret = *call.me.secret();
        let static_public = call.me.public();
        let State::Confirming { session, seed, ratchet_key, .. } = &mut call.state else { panic!() };
        assert_ne!(ratchet_key.public(), static_public, "a separate key");
        let hash = *session.handshake_hash();
        let Frame::Handshake { body, .. } = parse(&reply).unwrap() else { panic!() };
        let record = session.open_if(body, |_| true).unwrap();
        let keys_at = control(ACK, Attempt { call: 0, number: 0 }, ACK_MARKER).len();
        let seed_r: [u8; SEED_LEN] = record[keys_at..keys_at + SEED_LEN].try_into().unwrap();
        let dh_r0: [u8; 32] = record[keys_at + SEED_LEN..].try_into().unwrap();
        let root = ratchet::root_from_handshake(seed, &seed_r, &hash);
        let mut thief = Ratchet::respond_to(&root, NET, RatchetKey::from_bytes(&static_secret), dh_r0).unwrap();
        assert!(matches!(open_data(&mut thief, first_body), Err(WireError::Ratchet(RatchetError::Decrypt))));
        // The same derivation with the ephemeral key opens it.
        let mut honest = Ratchet::respond_to(&root, NET, ratchet_key.copy_for_tests(), dh_r0).unwrap();
        assert_eq!(open_data(&mut honest, first_body).unwrap(), b"first turn");
    }

    #[test]
    fn a_fresh_attempt_uses_a_fresh_ephemeral_key() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        call.handle(&w).unwrap();
        let State::Confirming { ratchet_key, .. } = &call.state else { panic!() };
        let first = ratchet_key.public();
        call.policy.resends = 0;
        let again = call.on_timeout().unwrap().unwrap();
        let w = welcome(&mut side, &again);
        call.handle(&w).unwrap();
        let State::Confirming { ratchet_key, .. } = &call.state else { panic!() };
        assert_ne!(ratchet_key.public(), first);
    }

    #[test]
    fn both_sides_derive_the_same_first_root_key_from_both_seeds_and_the_transcript() {
        let (mut side, mut call, hello) = setup();
        let w = welcome(&mut side, &hello);
        let InitiatorEvent::Send(confirm) = call.handle(&w).unwrap() else { panic!() };
        let State::Confirming { session, seed, .. } = &call.state else { panic!() };
        let hash = *session.handshake_hash();
        let pending = side.pending.get(&(1, call.call)).unwrap();
        assert_eq!(&hash, pending.session.handshake_hash(), "one transcript hash on both sides");
        let seed = **seed;
        let ResponderEvent::Established { reply, .. } = side.handle(1, &confirm, now()).unwrap() else { panic!() };
        // A different seed or transcript gives a different root.
        let base = ratchet::root_from_handshake(&seed, &[1; 32], &hash);
        assert_ne!(*base, *ratchet::root_from_handshake(&[0; 32], &[1; 32], &hash));
        assert_ne!(*base, *ratchet::root_from_handshake(&seed, &[2; 32], &hash));
        assert_ne!(*base, *ratchet::root_from_handshake(&seed, &[1; 32], &[0; 32]));
        assert_eq!(call.handle(&reply).unwrap(), InitiatorEvent::Established);
    }
}
