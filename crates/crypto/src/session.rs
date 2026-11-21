//! End-to-end encrypted sessions between contact keys (spec v0.7 section 2a).
//!
//! Handshake: Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s), two messages,
//! through `snow`'s public API. The caller already holds the answerer's
//! handshake key (from a contact card, an invitation or a note). Message 1
//! carries the caller's static key, encrypted and authenticated, plus a
//! 32-byte *reference* (an invitation id, a contact relationship or the
//! accepted request): the answerer reads both and decides **before writing
//! anything** whether to reply. The reference is part of the handshake
//! transcript, so the session is bound to it. The prologue carries the
//! network id and the wire layer's call id and attempt number, so those are
//! authenticated too. No wallet key is involved.
//!
//! The answering side's types are crate-private: the only way to produce a
//! message 2 is [`crate::wire::Responder`], which asks its gate first.
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

use crate::contact::{is_contributory_key, Network, StaticKey};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/session/v3";
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
    /// A peer key whose key agreement would not depend on our secret.
    WeakKey,
    /// Decrypted, but the content was refused (wrong record type).
    Refused,
    /// The send counter is used up; start a new session.
    Exhausted,
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

/// Domain, network, and the wire layer's call id and attempt number.
fn prologue(network: &Network, context: &[u8; 8]) -> Vec<u8> {
    [PROLOGUE, network.as_slice(), context.as_slice()].concat()
}

/// The caller's handshake in progress, waiting for message 2. Following the
/// Noise rule, a message 2 that fails ends it ([`Handshake::finish`]
/// consumes it).
pub(crate) struct Handshake {
    state: HandshakeState,
    peer: [u8; 32],
}

impl Handshake {
    /// Call the holder of `peer` (its handshake key) as `me`, naming
    /// `reference`; `context` is bound into the prologue. Returns message 1.
    pub(crate) fn initiate(
        me: &StaticKey,
        peer: &[u8; 32],
        network: &Network,
        context: &[u8; 8],
        reference: &[u8; REFERENCE_LEN],
    ) -> Result<(Handshake, Vec<u8>), SessionError> {
        if !is_contributory_key(peer) {
            return Err(SessionError::WeakKey);
        }
        let prologue = prologue(network, context);
        let mut state = builder(me, &prologue)?.remote_public_key(peer)?.build_initiator()?;
        let mut message1 = vec![0u8; MESSAGE1_LEN];
        let n = state.write_message(reference, &mut message1)?;
        message1.truncate(n);
        Ok((Handshake { state, peer: *peer }, message1))
    }

    /// Read message 2. Success proves the answerer holds the key we called.
    pub(crate) fn finish(mut self, message2: &[u8]) -> Result<Session, SessionError> {
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

/// A message 1 the answerer has read but not answered. The wire layer asks
/// its gate about [`Incoming::caller`] and [`Incoming::reference`], then
/// calls [`Incoming::accept`] or drops it, which sends nothing at all.
pub(crate) struct Incoming {
    state: HandshakeState,
    caller: [u8; 32],
    reference: [u8; REFERENCE_LEN],
}

impl Incoming {
    /// Read message 1 with our handshake key. Writes nothing.
    pub(crate) fn read(
        me: &StaticKey,
        network: &Network,
        context: &[u8; 8],
        message1: &[u8],
    ) -> Result<Incoming, SessionError> {
        if message1.len() > MAX_NOISE_MESSAGE {
            return Err(SessionError::TooLarge);
        }
        let prologue = prologue(network, context);
        let mut state = builder(me, &prologue)?.build_responder()?;
        let mut payload = vec![0u8; message1.len()];
        let n = state.read_message(message1, &mut payload)?;
        let reference: [u8; REFERENCE_LEN] = payload[..n].try_into().map_err(|_| SessionError::Malformed)?;
        let caller: [u8; 32] =
            state.get_remote_static().and_then(|k| k.try_into().ok()).ok_or(SessionError::Malformed)?;
        if !is_contributory_key(&caller) {
            return Err(SessionError::WeakKey);
        }
        Ok(Incoming { state, caller, reference })
    }

    /// The caller's authenticated static key.
    pub(crate) fn caller(&self) -> [u8; 32] {
        self.caller
    }

    pub(crate) fn reference(&self) -> [u8; REFERENCE_LEN] {
        self.reference
    }

    /// Answer: returns the session and message 2.
    pub(crate) fn accept(mut self) -> Result<(Session, Vec<u8>), SessionError> {
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
        // Noise reserves the nonce u64::MAX; u64::MAX - 1 is the last one
        // used. Refuse rather than wrap.
        let nonce = self.next_send;
        if nonce == u64::MAX {
            return Err(SessionError::Exhausted);
        }
        let next = nonce + 1;
        let mut out = vec![0u8; NONCE_LEN + plaintext.len() + TAG_LEN];
        out[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
        let n = self.transport.write_message(nonce, plaintext, &mut out[NONCE_LEN..])?;
        out.truncate(NONCE_LEN + n);
        self.next_send = next;
        Ok(out)
    }

    /// Decrypt one message. Order does not matter; duplicates are refused.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.open_if(sealed, |_| true)
    }

    /// Decrypt one message and keep it only if `accept` approves the
    /// plaintext. A refused message does not use up its counter, so the
    /// genuine use of the same bytes still works.
    pub(crate) fn open_if(&mut self, sealed: &[u8], accept: impl FnOnce(&[u8]) -> bool) -> Result<Vec<u8>, SessionError> {
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
        if !accept(&plaintext) {
            return Err(SessionError::Refused);
        }
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
    use crate::contact::ContactIdentity;
    use crate::identity::Identity;

    const NET: Network = [9; 32];
    const CTX: [u8; 8] = [0, 0, 0, 7, 0, 0, 0, 1];
    const REF: [u8; 32] = [3; 32];

    /// An IK handshake from caller key `caller` to `answerer`'s handshake key.
    fn connect(caller: &StaticKey, answerer: &ContactIdentity) -> (Session, Session) {
        let (hs, m1) = Handshake::initiate(caller, &answerer.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        let incoming = Incoming::read(answerer.handshake_key(), &NET, &CTX, &m1).unwrap();
        let (session_r, m2) = incoming.accept().unwrap();
        (hs.finish(&m2).unwrap(), session_r)
    }

    #[test]
    fn session_round_trip_and_mutual_authentication() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, mut b) = connect(&alice, &bob);
        assert_eq!(a.peer(), bob.handshake_key().public());
        assert_eq!(b.peer(), alice.public(), "the answerer learns the caller's key from message 1");
        let sealed = a.seal(b"meet at noon").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"meet at noon");
        assert_eq!(a.open(&b.seal(b"ok").unwrap()).unwrap(), b"ok");
    }

    #[test]
    fn the_answerer_reads_caller_and_reference_before_writing_anything() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (_hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        let incoming = Incoming::read(bob.handshake_key(), &NET, &CTX, &m1).unwrap();
        assert_eq!((incoming.caller(), incoming.reference()), (alice.public(), REF));
        // Another key, another network, or other call/attempt labels: no read.
        assert!(Incoming::read(ContactIdentity::generate_at(0).handshake_key(), &NET, &CTX, &m1).is_err());
        assert!(Incoming::read(bob.handshake_key(), &[0; 32], &CTX, &m1).is_err());
        assert!(Incoming::read(bob.handshake_key(), &NET, &[0, 0, 0, 8, 0, 0, 0, 1], &m1).is_err());
        assert!(Incoming::read(bob.handshake_key(), &NET, &[0, 0, 0, 7, 0, 0, 0, 2], &m1).is_err());
    }

    #[test]
    fn ciphertext_reveals_nothing_recognisable_and_outsiders_cannot_open_it() {
        let (alice, bob, eve) = (StaticKey::generate(), ContactIdentity::generate_at(0), ContactIdentity::generate_at(0));
        let (mut a, _b) = connect(&alice, &bob);
        let secret = b"the launch code is 0000";
        let sealed = a.seal(secret).unwrap();
        assert!(!sealed.windows(secret.len()).any(|w| w == secret));
        let (_a2, mut e) = connect(&alice, &eve);
        assert!(matches!(e.open(&sealed), Err(SessionError::Noise(_))));
    }

    #[test]
    fn handshake_exposes_no_static_key_reference_or_wallet() {
        let (alice, bob, wallet) = (StaticKey::generate(), ContactIdentity::generate_at(0), Identity::generate());
        let (hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        let (_s, m2) = Incoming::read(bob.handshake_key(), &NET, &CTX, &m1).unwrap().accept().unwrap();
        hs.finish(&m2).unwrap();
        for wire in [&m1, &m2] {
            for key in [alice.public(), bob.handshake_key().public(), bob.signing_key(), REF, wallet.address().0] {
                assert!(!wire.windows(32).any(|w| w == key), "a key or the reference is visible on the wire");
            }
        }
    }

    #[test]
    fn messages_survive_reordering_but_not_replay() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, mut b) = connect(&alice, &bob);
        let sealed: Vec<Vec<u8>> = (0..5u8).map(|i| a.seal(&[i]).unwrap()).collect();
        for i in [3usize, 0, 4, 1, 2] {
            assert_eq!(b.open(&sealed[i]).unwrap(), vec![i as u8]);
        }
        for message in &sealed {
            assert!(matches!(b.open(message), Err(SessionError::Replay)));
        }
    }

    #[test]
    fn a_refused_record_does_not_use_up_its_counter() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, mut b) = connect(&alice, &bob);
        let sealed = a.seal(b"x").unwrap();
        assert!(matches!(b.open_if(&sealed, |_| false), Err(SessionError::Refused)));
        assert_eq!(b.open(&sealed).unwrap(), b"x");
        assert!(matches!(b.open(&sealed), Err(SessionError::Replay)));
    }

    #[test]
    fn tampered_message_is_rejected_and_does_not_block_the_real_one() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, mut b) = connect(&alice, &bob);
        let sealed = a.seal(b"pay 10").unwrap();
        let mut forged = sealed.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(b.open(&forged), Err(SessionError::Noise(_))));
        assert!(matches!(b.open(&[0u8; 5]), Err(SessionError::Malformed)));
        assert_eq!(b.open(&sealed).unwrap(), b"pay 10");
    }

    #[test]
    fn a_caller_reaching_the_wrong_answerer_cannot_finish() {
        let (alice, bob, mallory) = (StaticKey::generate(), ContactIdentity::generate_at(0), ContactIdentity::generate_at(0));
        let (hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        assert!(Incoming::read(mallory.handshake_key(), &NET, &CTX, &m1).is_err());
        let (_other, m1m) = Handshake::initiate(&alice, &mallory.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        let (_s, forged) = Incoming::read(mallory.handshake_key(), &NET, &CTX, &m1m).unwrap().accept().unwrap();
        assert!(matches!(hs.finish(&forged), Err(SessionError::Noise(_))));
    }

    /// A test-only snow resolver: everything is snow's default, except that
    /// a static key set to `MARK` reports the small-order point `point` as
    /// its public key and an all-zero agreement result. That is exactly what
    /// a caller with a small-order static key would produce, built through
    /// snow's public `CryptoResolver` / `Dh` traits; no Noise processing is
    /// written by hand.
    mod weak_static {
        use snow::params::{CipherChoice, DHChoice, HashChoice};
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        use snow::types::{Cipher, Dh, Hash, Random};

        pub(super) const MARK: [u8; 32] = [0xEE; 32];

        pub(super) struct Resolver(pub(super) [u8; 32]);

        struct WeakDh {
            inner: Box<dyn Dh>,
            point: [u8; 32],
            weak: bool,
        }

        impl Dh for WeakDh {
            fn name(&self) -> &'static str {
                self.inner.name()
            }
            fn pub_len(&self) -> usize {
                self.inner.pub_len()
            }
            fn priv_len(&self) -> usize {
                self.inner.priv_len()
            }
            fn set(&mut self, privkey: &[u8]) {
                self.weak = privkey == MARK;
                self.inner.set(privkey);
            }
            fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
                self.weak = false;
                self.inner.generate(rng)
            }
            fn pubkey(&self) -> &[u8] {
                if self.weak { &self.point } else { self.inner.pubkey() }
            }
            fn privkey(&self) -> &[u8] {
                self.inner.privkey()
            }
            fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
                if self.weak {
                    out[..32].fill(0); // what any secret gives with a small-order point
                    Ok(())
                } else {
                    self.inner.dh(pubkey, out)
                }
            }
        }

        impl CryptoResolver for Resolver {
            fn resolve_rng(&self) -> Option<Box<dyn Random>> {
                DefaultResolver.resolve_rng()
            }
            fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
                let inner = DefaultResolver.resolve_dh(choice)?;
                Some(Box::new(WeakDh { inner, point: self.0, weak: false }))
            }
            fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
                DefaultResolver.resolve_hash(choice)
            }
            fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
                DefaultResolver.resolve_cipher(choice)
            }
        }
    }

    #[test]
    fn a_hello_from_a_small_order_caller_key_is_refused_after_reading() {
        let bob = ContactIdentity::generate_at(0);
        let prologue = prologue(&NET, &CTX);
        for weak in crate::contact::tests::SMALL_ORDER {
            let mut caller = snow::Builder::with_resolver(
                PATTERN.parse().unwrap(),
                Box::new(weak_static::Resolver(weak)),
            )
            .prologue(&prologue)
            .unwrap()
            .local_private_key(&weak_static::MARK)
            .unwrap()
            .remote_public_key(&bob.handshake_key().public())
            .unwrap()
            .build_initiator()
            .unwrap();
            let mut message1 = vec![0u8; MESSAGE1_LEN];
            let n = caller.write_message(&REF, &mut message1).unwrap();
            message1.truncate(n);
            // The message decrypts (snow accepts the all-zero agreement) and
            // is refused by our check on the caller's key.
            assert!(matches!(Incoming::read(bob.handshake_key(), &NET, &CTX, &message1), Err(SessionError::WeakKey)));
        }
        // Control: the same resolver with an ordinary key reads fine.
        let alice = StaticKey::generate();
        let (_hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &CTX, &REF).unwrap();
        assert!(Incoming::read(bob.handshake_key(), &NET, &CTX, &m1).is_ok());
    }

    #[test]
    fn calling_a_small_order_key_is_refused() {
        let alice = StaticKey::generate();
        for weak in crate::contact::tests::SMALL_ORDER {
            assert!(matches!(Handshake::initiate(&alice, &weak, &NET, &CTX, &REF), Err(SessionError::WeakKey)));
        }
    }

    #[test]
    fn the_send_counter_refuses_to_wrap() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, mut b) = connect(&alice, &bob);
        // u64::MAX is reserved by Noise; the last usable nonce is MAX - 1.
        a.next_send = u64::MAX - 2;
        let before = a.seal(b"before").unwrap();
        assert_eq!(b.open(&before).unwrap(), b"before");
        assert_eq!(a.next_send, u64::MAX - 1);
        let last = a.seal(b"last").unwrap();
        assert_eq!(&last[..8], &(u64::MAX - 1).to_le_bytes(), "sealed with nonce MAX - 1");
        assert_eq!(b.open(&last).unwrap(), b"last");
        assert!(matches!(a.seal(b"one too many"), Err(SessionError::Exhausted)));
        assert!(matches!(a.seal(b"still"), Err(SessionError::Exhausted)), "and stays refused");
    }

    #[test]
    fn oversized_message_is_refused() {
        let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate_at(0));
        let (mut a, _b) = connect(&alice, &bob);
        assert!(matches!(a.seal(&vec![0u8; MAX_PLAINTEXT + 1]), Err(SessionError::TooLarge)));
        assert!(a.seal(&vec![0u8; MAX_PLAINTEXT]).is_ok());
    }
}
