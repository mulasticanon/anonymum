//! End-to-end encrypted sessions between two addresses.
//!
//! Handshake: Noise XX (X25519, ChaCha20-Poly1305, BLAKE2s), three messages.
//! Each side proves which address it is by sending, *inside the encrypted
//! part of the handshake*, its address plus a signature binding its Noise
//! key to that address. An observer of the handshake learns neither address.
//!
//! Transport: every message carries its own counter, so messages may arrive
//! in any order (a mixnet reorders them on purpose). Replays are rejected.
//!
//! Limits, stated plainly:
//! * Forward secrecy is per session, not per message. Start a fresh session
//!   regularly. A double ratchet would tighten this.
//! * No post-quantum key exchange yet.
//! * Message length is visible to the transport. The mixnet's fixed-size
//!   packets hide it on the wire.

use std::collections::BTreeSet;
use std::fmt;

use anonymum_core::Address;
use snow::{Builder, HandshakeState, StatelessTransportState};
use zeroize::Zeroizing;

use crate::identity::{verify_binding, Identity};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/session/v1";
const CREDENTIALS_LEN: usize = 32 + 64;
const TAG_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 8;
const KEY_LEN: usize = 32;
/// Exact lengths of the three XX messages with our payloads: `e`;
/// `e, ee, s, es` + credentials; `s, se` + credentials.
pub(crate) const MESSAGE1_LEN: usize = KEY_LEN;
pub(crate) const MESSAGE2_LEN: usize = KEY_LEN + (KEY_LEN + TAG_LEN) + (CREDENTIALS_LEN + TAG_LEN);
pub(crate) const MESSAGE3_LEN: usize = (KEY_LEN + TAG_LEN) + (CREDENTIALS_LEN + TAG_LEN);
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
    /// The peer's address does not vouch for the key it used.
    BadCredentials,
    /// We reached someone, but not the address we meant to talk to.
    UnexpectedPeer { got: Address },
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

/// A handshake in progress.
///
/// Uses `snow`'s public API only. Following the Noise rule, a handshake
/// message that fails to decrypt or authenticate ends the handshake: the
/// finishing steps consume `self`, and the caller starts again with a fresh
/// handshake (a fresh ephemeral key). [`crate::wire`] adds the retry rules.
pub struct Handshake {
    state: HandshakeState,
    credentials: [u8; CREDENTIALS_LEN],
    expected_peer: Option<Address>,
}

impl Handshake {
    /// Step 1 (initiator). Returns the first message to send to `peer`.
    pub fn initiate(me: &Identity, peer: Address) -> Result<(Handshake, Vec<u8>), SessionError> {
        let secret = Zeroizing::new(me.messaging_secret());
        let mut state = builder(&secret)?.build_initiator()?;
        let mut message1 = vec![0u8; MAX_NOISE_MESSAGE];
        let n = state.write_message(&[], &mut message1)?;
        message1.truncate(n);
        let handshake = Handshake { state, credentials: credentials(me), expected_peer: Some(peer) };
        Ok((handshake, message1))
    }

    /// Step 2 (responder). Takes message 1, returns message 2.
    pub fn respond(me: &Identity, message1: &[u8]) -> Result<(Handshake, Vec<u8>), SessionError> {
        if message1.len() > MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge); // before allocating anything
        }
        let secret = Zeroizing::new(me.messaging_secret());
        let mut state = builder(&secret)?.build_responder()?;
        let mut scratch = vec![0u8; message1.len()];
        state.read_message(message1, &mut scratch)?;
        let creds = credentials(me);
        let mut message2 = vec![0u8; MAX_NOISE_MESSAGE];
        let n = state.write_message(&creds, &mut message2)?;
        message2.truncate(n);
        Ok((Handshake { state, credentials: creds, expected_peer: None }, message2))
    }

    /// Read the peer's next handshake message and return its payload.
    fn read(&mut self, message: &[u8]) -> Result<Vec<u8>, SessionError> {
        if message.len() > MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge); // before allocating anything
        }
        // A payload is never longer than the message carrying it.
        let mut payload = vec![0u8; message.len()];
        let n = self.state.read_message(message, &mut payload)?;
        payload.truncate(n);
        Ok(payload)
    }

    /// Step 3 (initiator). Takes message 2, returns the session and message 3.
    /// Fails unless the responder proved it is the address we asked for. Any
    /// failure ends this handshake.
    pub fn initiator_finish(mut self, message2: &[u8]) -> Result<(Session, Vec<u8>), SessionError> {
        let payload = self.read(message2)?;
        let peer = authenticate(&payload, self.state.get_remote_static())?;
        if self.expected_peer != Some(peer) {
            return Err(SessionError::UnexpectedPeer { got: peer });
        }
        let mut message3 = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.state.write_message(&self.credentials, &mut message3)?;
        message3.truncate(n);
        Ok((Session::new(self.state.into_stateless_transport_mode()?, peer), message3))
    }

    /// Step 4 (responder). Takes message 3, returns the session. The caller
    /// learns who the initiator is from [`Session::peer`] and decides
    /// whether to talk to them (e.g. by checking for an open channel). Any
    /// failure ends this handshake.
    pub fn responder_finish(mut self, message3: &[u8]) -> Result<Session, SessionError> {
        let payload = self.read(message3)?;
        let peer = authenticate(&payload, self.state.get_remote_static())?;
        Ok(Session::new(self.state.into_stateless_transport_mode()?, peer))
    }
}

fn builder(secret: &[u8; 32]) -> Result<Builder<'_>, SessionError> {
    let params = PATTERN.parse().expect("pattern is a valid constant");
    Ok(Builder::new(params).prologue(PROLOGUE)?.local_private_key(secret)?)
}

fn credentials(me: &Identity) -> [u8; CREDENTIALS_LEN] {
    let mut out = [0u8; CREDENTIALS_LEN];
    out[..32].copy_from_slice(&me.address().0);
    out[32..].copy_from_slice(&me.binding());
    out
}

/// Check that the claimed address signed the Noise key the peer really used.
fn authenticate(payload: &[u8], remote_static: Option<&[u8]>) -> Result<Address, SessionError> {
    if payload.len() != CREDENTIALS_LEN {
        return Err(SessionError::BadCredentials);
    }
    let mut address = [0u8; 32];
    address.copy_from_slice(&payload[..32]);
    let mut binding = [0u8; 64];
    binding.copy_from_slice(&payload[32..]);
    let remote: [u8; 32] = remote_static
        .and_then(|key| key.try_into().ok())
        .ok_or(SessionError::BadCredentials)?;
    let address = Address(address);
    if !verify_binding(&address, &remote, &binding) {
        return Err(SessionError::BadCredentials);
    }
    Ok(address)
}

/// An established end-to-end encrypted session.
pub struct Session {
    transport: StatelessTransportState,
    peer: Address,
    next_send: u64,
    newest_received: Option<u64>,
    received: BTreeSet<u64>,
}

impl Session {
    fn new(transport: StatelessTransportState, peer: Address) -> Self {
        Session { transport, peer, next_send: 0, newest_received: None, received: BTreeSet::new() }
    }

    /// The authenticated address on the other end.
    pub fn peer(&self) -> Address {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forged_credentials_are_rejected() {
        let bob = Identity::generate();
        let mallory = Identity::generate();
        // Mallory presents Bob's address with her own binding signature.
        let mut forged = credentials(&mallory);
        forged[..32].copy_from_slice(&bob.address().0);
        let result = authenticate(&forged, Some(&mallory.messaging_public()));
        assert!(matches!(result, Err(SessionError::BadCredentials)));
        // And Bob's genuine credentials do not transfer to Mallory's key.
        let result = authenticate(&credentials(&bob), Some(&mallory.messaging_public()));
        assert!(matches!(result, Err(SessionError::BadCredentials)));
        // The honest case passes.
        let ok = authenticate(&credentials(&bob), Some(&bob.messaging_public())).unwrap();
        assert_eq!(ok, bob.address());
    }
}
