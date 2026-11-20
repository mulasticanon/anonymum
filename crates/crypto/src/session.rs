//! End-to-end encrypted sessions between contact keys (spec v0.7 section 2a).
//!
//! Handshake: Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s), two messages,
//! through `snow`'s public API. The caller already holds the answerer's
//! handshake key (from a contact card, an invitation or a note). Message 1
//! carries the caller's static key, encrypted and authenticated, plus a
//! 32-byte *reference* (an invitation id, a contact relationship or the
//! accepted request): the answerer reads both and decides **before writing
//! anything** whether to reply ([`Incoming`]). Dropping an [`Incoming`]
//! sends nothing. The reference is part of the handshake transcript, so the
//! session is bound to it. No wallet key is involved.
//!
//! Known costs of IK (spec question 11): message 1 can be replayed, and if
//! the answerer's handshake key is later compromised, a recorded message 1
//! reveals the caller's key and reference. Hence caller keys scoped to one
//! relationship or request, a minimal payload, and grants committed only
//! after a fresh session confirmation ([`crate::wire`], [`crate::gate`]).
//!
//! Transport: every message carries its own counter, so messages may arrive
//! in any order (a mixnet reorders them on purpose). Replays are rejected.
//!
//! Limits, stated plainly:
//! * Unreviewed prototype of section 2a (questions 11 and 12).
//! * Forward secrecy is per session, not per message. No double ratchet.
//! * No post-quantum key exchange yet.
//! * Message length is visible to the transport. The mixnet's fixed-size
//!   packets hide it on the wire.

use std::collections::BTreeSet;
use std::fmt;

use snow::{Builder, HandshakeState, StatelessTransportState};

use crate::contact::{Network, StaticKey};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/session/v2";
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 8;
/// What message 1 names: invitation id, relationship or accepted request.
pub const REFERENCE_LEN: usize = 32;
/// Exact lengths of the two IK messages: `e, es, s, ss` + reference;
/// `e, ee, se` + empty payload.
pub(crate) const MESSAGE1_LEN: usize = KEY_LEN + (KEY_LEN + TAG_LEN) + (REFERENCE_LEN + TAG_LEN);
pub(crate) const MESSAGE2_LEN: usize = KEY_LEN + TAG_LEN;
/// Smallest sealed transport message: nonce and tag around nothing.
pub(crate) const MIN_SEALED: usize = NONCE_LEN + TAG_LEN;
/// Largest Noise message (Noise's own limit). Larger input is refused before
/// any buffer is allocated for it.
pub(crate) const MAX_NOISE_MESSAGE: usize = 65_535;
/// How far behind the newest message an old one may arrive and still be read.
const REPLAY_WINDOW: u64 = 2_048;

/// Largest plaintext one sealed message can carry.
pub const MAX_PLAINTEXT: usize = MAX_NOISE_MESSAGE - TAG_LEN;

#[derive(Debug)]
pub enum SessionError {
    /// Decryption or handshake failure (wrong key, tampering, wrong step).
    Noise(snow::Error),
    TooLarge,
    Malformed,
    /// This message was already received, or is too old to check.
    Replay,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SessionError {}

impl From<snow::Error> for SessionError {
    fn from(e: snow::Error) -> Self {
        SessionError::Noise(e)
    }
}

fn builder<'a>(me: &'a StaticKey, prologue: &'a [u8]) -> Result<Builder<'a>, SessionError> {
    let params = PATTERN.parse().expect("pattern is a valid constant");
    Ok(Builder::new(params).prologue(prologue)?.local_private_key(me.secret())?)
}

fn prologue(network: &Network) -> Vec<u8> {
    [PROLOGUE, network.as_slice()].concat()
}

/// The caller's handshake in progress, waiting for message 2. Following the
/// Noise rule, a message 2 that fails ends it ([`Handshake::finish`]
/// consumes it).
pub struct Handshake {
    state: HandshakeState,
    peer: [u8; 32],
}

impl Handshake {
    /// Call the holder of `peer` (its handshake key) as `me`, naming
    /// `reference`. Returns message 1.
    pub fn initiate(
        me: &StaticKey,
        peer: &[u8; 32],
        network: &Network,
        reference: &[u8; REFERENCE_LEN],
    ) -> Result<(Handshake, Vec<u8>), SessionError> {
        let prologue = prologue(network);
        let mut state = builder(me, &prologue)?.remote_public_key(peer)?.build_initiator()?;
        let mut message1 = vec![0u8; MESSAGE1_LEN];
        let n = state.write_message(reference, &mut message1)?;
        message1.truncate(n);
        Ok((Handshake { state, peer: *peer }, message1))
    }

    /// Read message 2. Success proves the answerer holds the key we called.
    pub fn finish(mut self, message2: &[u8]) -> Result<Session, SessionError> {
        if message2.len() > MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge);
        }
        let mut payload = vec![0u8; message2.len()];
        let n = self.state.read_message(message2, &mut payload)?;
        if n != 0 {
            return Err(SessionError::Malformed);
        }
        Ok(Session::new(self.state.into_stateless_transport_mode()?, self.peer))
    }
}

/// A message 1 the answerer has read but not answered. Decide with
/// [`Incoming::caller`] and [`Incoming::reference`]; then
/// [`Incoming::accept`], or drop it to send nothing at all.
pub struct Incoming {
    state: HandshakeState,
    caller: [u8; 32],
    reference: [u8; REFERENCE_LEN],
}

impl Incoming {
    /// Read message 1 with our handshake key. Writes nothing.
    pub fn read(me: &StaticKey, network: &Network, message1: &[u8]) -> Result<Incoming, SessionError> {
        if message1.len() > MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge);
        }
        let prologue = prologue(network);
        let mut state = builder(me, &prologue)?.build_responder()?;
        let mut payload = vec![0u8; message1.len()];
        let n = state.read_message(message1, &mut payload)?;
        let reference: [u8; REFERENCE_LEN] = payload[..n].try_into().map_err(|_| SessionError::Malformed)?;
        let caller: [u8; 32] =
            state.get_remote_static().and_then(|k| k.try_into().ok()).ok_or(SessionError::Malformed)?;
        Ok(Incoming { state, caller, reference })
    }

    /// The caller's authenticated static key.
    pub fn caller(&self) -> [u8; 32] {
        self.caller
    }

    pub fn reference(&self) -> [u8; REFERENCE_LEN] {
        self.reference
    }

    /// Answer: returns the session and message 2.
    pub fn accept(mut self) -> Result<(Session, Vec<u8>), SessionError> {
        let mut message2 = vec![0u8; MESSAGE2_LEN];
        let n = self.state.write_message(&[], &mut message2)?;
        message2.truncate(n);
        Ok((Session::new(self.state.into_stateless_transport_mode()?, self.caller), message2))
    }
}

/// An established end-to-end encrypted session.
pub struct Session {
    transport: StatelessTransportState,
    peer: [u8; 32],
    next_send: u64,
    newest_received: Option<u64>,
    received: BTreeSet<u64>,
}

impl Session {
    fn new(transport: StatelessTransportState, peer: [u8; 32]) -> Self {
        Session { transport, peer, next_send: 0, newest_received: None, received: BTreeSet::new() }
    }

    /// The other end's authenticated static key.
    pub fn peer(&self) -> [u8; 32] {
        self.peer
    }

    /// Encrypt one message.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(SessionError::TooLarge);
        }
        let nonce = self.next_send;
        let mut out = vec![0u8; NONCE_LEN + plaintext.len() + TAG_LEN];
        out[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
        let n = self.transport.write_message(nonce, plaintext, &mut out[NONCE_LEN..])?;
        out.truncate(NONCE_LEN + n);
        self.next_send += 1;
        Ok(out)
    }

    /// Decrypt one message. Order does not matter; duplicates are refused.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, SessionError> {
        if sealed.len() > NONCE_LEN + MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge); // before allocating anything
        }
        if sealed.len() < MIN_SEALED {
            return Err(SessionError::Malformed);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = u64::from_le_bytes(nonce_bytes.try_into().expect("split at 8"));
        if let Some(newest) = self.newest_received {
            let too_old = nonce.saturating_add(REPLAY_WINDOW) <= newest;
            if too_old || self.received.contains(&nonce) {
                return Err(SessionError::Replay);
            }
        }
        let mut plaintext = vec![0u8; ciphertext.len()];
        let n = self.transport.read_message(nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(n);
        // Only a message that decrypted correctly may advance the window.
        let newest = self.newest_received.map_or(nonce, |old| old.max(nonce));
        self.newest_received = Some(newest);
        self.received.insert(nonce);
        let oldest_kept = newest.saturating_sub(REPLAY_WINDOW - 1);
        self.received = self.received.split_off(&oldest_kept);
        Ok(plaintext)
    }
}
