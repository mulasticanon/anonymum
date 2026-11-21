//! A Double Ratchet for session messages, after the Signal specification
//! ("The Double Ratchet Algorithm", revision 1, sections 3.2-3.5), built
//! from primitives already in the workspace: X25519 (`x25519-dalek`),
//! keyed BLAKE2s (`blake2`) and ChaCha20-Poly1305 (`chacha20poly1305`).
//! Nothing here is a new primitive; this module composes them.
//!
//! **Unreviewed prototype** (roadmap step 6). It gives, as far as the tests
//! in `tests/ratchet.rs` show:
//! * per-message forward secrecy: every message key is used once and
//!   erased, and a chain key is replaced as soon as the next one is derived;
//! * post-compromise security: one DH ratchet round trip after a state
//!   compromise produces keys the holder of the stolen state cannot derive;
//! * out-of-order delivery (the mixnet reorders on purpose) through a
//!   bounded cache of skipped message keys.
//!
//! Choices, stated plainly:
//! * `KDF_RK(rk, dh) = (MAC_rk("anonymum/dr-rk/v1" || 1 || dh),
//!   MAC_rk("anonymum/dr-rk/v1" || 2 || dh))` and `KDF_CK(ck) =
//!   (MAC_ck("anonymum/dr-ck/v1" || 1), MAC_ck("anonymum/dr-ck/v1" || 2))`,
//!   with `MAC` keyed BLAKE2s-256 (a PRF), in place of the HKDF and HMAC the
//!   Signal document suggests.
//! * The AEAD is ChaCha20-Poly1305 under the one-time message key with an
//!   all-zero nonce, which is safe only because no message key is ever used
//!   twice. The associated data is `"anonymum/dr-msg/v1" || network ||
//!   header`.
//! * The header (40 bytes: ratchet public key, previous chain length, message
//!   number, both big-endian) is authenticated but **not encrypted**; the
//!   Signal header-encryption variant is not implemented. Whoever sees the
//!   frame (only the other end, inside the mixnet's own encryption) sees the
//!   ratchet key and the counters.
//! * Every received ratchet key is checked with
//!   [`crate::is_contributory_key`] before any key agreement.
//! * A failed decryption changes nothing: all new state is computed on the
//!   side and committed only after the message decrypts and is accepted.
//! * At most [`MAX_SKIP_PER_STEP`] keys are skipped per chain step and at
//!   most [`MAX_TOTAL_SKIPPED`] are kept (oldest evicted), so a header with a
//!   huge message number costs a refusal, not memory or CPU.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use blake2::digest::Mac;
use blake2::Blake2sMac256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::contact::{is_contributory_key, Network};

const RK_LABEL: &[u8] = b"anonymum/dr-rk/v1";
const CK_LABEL: &[u8] = b"anonymum/dr-ck/v1";
const MSG_LABEL: &[u8] = b"anonymum/dr-msg/v1";
const ROOT_LABEL: &[u8] = b"anonymum/dr-root/v1";

/// Ratchet public key (32), previous chain length (4), message number (4).
pub const HEADER_LEN: usize = 32 + 4 + 4;
const TAG_LEN: usize = 16;
/// Smallest ratchet message: header and tag around nothing.
pub const MIN_MESSAGE: usize = HEADER_LEN + TAG_LEN;
/// Largest plaintext one ratchet message carries (the Noise transport's
/// limit, kept so the wire layer's [`crate::wire::MAX_DATA`] is unchanged).
pub const MAX_PLAINTEXT: usize = crate::session::MAX_PLAINTEXT;
/// Largest ratchet message.
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_PLAINTEXT + TAG_LEN;
/// Most message keys one received header may make us skip in one chain.
pub const MAX_SKIP_PER_STEP: u32 = 256;
/// Most skipped message keys kept; beyond it the oldest are erased.
pub const MAX_TOTAL_SKIPPED: usize = 1_024;

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// Shorter than a header and tag, or longer than [`MAX_MESSAGE`].
    Malformed,
    /// Plaintext longer than [`MAX_PLAINTEXT`].
    TooLarge,
    /// The header's ratchet key is small-order (its agreement would not
    /// depend on our secret). Refused before any key agreement.
    WeakKey,
    /// Opening would skip more than [`MAX_SKIP_PER_STEP`] keys in a chain.
    TooManySkipped,
    /// A message number already used in the current chain and not in the
    /// skipped cache: a replay, or a message whose key was already erased.
    Replay,
    /// Authentication failed (wrong key, tampering, or a replay of a message
    /// from an earlier chain).
    Decrypt,
    /// Decrypted, but the content was refused by the caller (wrong record
    /// type). Nothing is used up.
    Refused,
    /// No sending chain yet: the side that did not start must hear from the
    /// other first.
    NoSendingChain,
    /// The message counter of this chain is used up.
    Exhausted,
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RatchetError {}

/// A ratchet key pair (X25519). The secret is erased when dropped.
pub struct RatchetKey {
    secret: StaticSecret,
    public: [u8; 32],
}

impl RatchetKey {
    /// A fresh key pair from the operating system's randomness.
    pub fn generate() -> Self {
        Self::from_secret(StaticSecret::random_from_rng(OsRng))
    }

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_secret(StaticSecret::from(*bytes))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret).to_bytes();
        RatchetKey { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    fn agree(&self, their: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.diffie_hellman(&PublicKey::from(*their)).to_bytes())
    }

    fn duplicate(&self) -> Self {
        RatchetKey { secret: self.secret.clone(), public: self.public }
    }

    /// A copy of this key pair, secret included, for tests only.
    #[doc(hidden)]
    pub fn copy_for_tests(&self) -> Self {
        self.duplicate()
    }
}

impl fmt::Debug for RatchetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RatchetKey({:02x?}..)", &self.public[..4])
    }
}

type Secret = Zeroizing<[u8; 32]>;

fn mac(key: &[u8], parts: &[&[u8]]) -> Secret {
    let mut m = <Blake2sMac256 as Mac>::new_from_slice(key).expect("keys of at most 32 bytes are accepted");
    for part in parts {
        m.update(part);
    }
    Zeroizing::new(m.finalize().into_bytes().into())
}

/// `KDF_RK`: a new root key and chain key from the root key and a DH output.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> (Secret, Secret) {
    (mac(rk, &[RK_LABEL, &[1], dh_out]), mac(rk, &[RK_LABEL, &[2], dh_out]))
}

/// `KDF_CK`: the next chain key and this step's message key.
fn kdf_ck(ck: &[u8; 32]) -> (Secret, Secret) {
    (mac(ck, &[CK_LABEL, &[1]]), mac(ck, &[CK_LABEL, &[2]]))
}

/// The first root key after a handshake: both sides' fresh seeds and the
/// handshake transcript hash (`snow`'s `get_handshake_hash`).
pub fn root_from_handshake(seed_i: &[u8; 32], seed_r: &[u8; 32], handshake_hash: &[u8]) -> Zeroizing<[u8; 32]> {
    mac(ROOT_LABEL, &[seed_i, seed_r, handshake_hash])
}

fn associated_data(network: &Network, header: &[u8]) -> Vec<u8> {
    [MSG_LABEL, network.as_slice(), header].concat()
}

fn seal_with(mk: &[u8; 32], network: &Network, header: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let aad = associated_data(network, header);
    ChaCha20Poly1305::new(Key::from_slice(mk))
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: plaintext, aad: &aad })
        .expect("ChaCha20-Poly1305 encryption of a bounded message does not fail")
}

fn open_with(mk: &[u8; 32], network: &Network, header: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
    let aad = associated_data(network, header);
    ChaCha20Poly1305::new(Key::from_slice(mk))
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: ciphertext, aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| RatchetError::Decrypt)
}

struct Header {
    dh: [u8; 32],
    pn: u32,
    n: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Header {
        let word = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        Header { dh: bytes[..32].try_into().expect("32 bytes"), pn: word(32), n: word(36) }
    }
}

/// One side of a Double Ratchet conversation.
pub struct Ratchet {
    network: Network,
    root: Secret,
    dh_self: RatchetKey,
    dh_remote: Option<[u8; 32]>,
    send_ck: Option<Secret>,
    recv_ck: Option<Secret>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), Secret>,
    /// Insertion order of `skipped`, for evicting the oldest.
    skipped_order: VecDeque<([u8; 32], u32)>,
}

/// Everything one received message would change, computed before it is
/// known to decrypt; committed only if it does.
struct Staged {
    message_key: Secret,
    /// Keys skipped by this message, in order, to add to the cache.
    skipped: Vec<(([u8; 32], u32), Secret)>,
    /// A cached key this message uses (removed on commit).
    from_cache: Option<([u8; 32], u32)>,
    /// A DH ratchet step: new root, receiving and sending chains and key.
    step: Option<Step>,
    /// The receiving chain key and counter after this message.
    recv_ck: Option<Secret>,
    nr: u32,
}

struct Step {
    remote: [u8; 32],
    root: Secret,
    send_ck: Secret,
    dh_self: RatchetKey,
}

impl Ratchet {
    /// The side that starts (Signal's "Alice"): knows the other side's
    /// current ratchet public key and sends first, with a fresh key pair.
    pub fn initiate(root: &[u8; 32], network: Network, their: [u8; 32]) -> Result<Self, RatchetError> {
        Self::initiate_with(root, network, RatchetKey::generate(), their)
    }

    /// As [`Ratchet::initiate`] with a given key pair, whose public key the
    /// other side must already have (the wire layer sends it in the ACK).
    pub fn initiate_with(root: &[u8; 32], network: Network, own: RatchetKey, their: [u8; 32]) -> Result<Self, RatchetError> {
        if !is_contributory_key(&their) {
            return Err(RatchetError::WeakKey);
        }
        let (root, send_ck) = kdf_rk(root, &own.agree(&their));
        Ok(Ratchet {
            network,
            root,
            dh_self: own,
            dh_remote: Some(their),
            send_ck: Some(send_ck),
            recv_ck: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            skipped_order: VecDeque::new(),
        })
    }

    /// The side that answers (Signal's "Bob"): holds the key pair whose
    /// public key the starter used. It cannot send until it has heard.
    pub fn respond(root: &[u8; 32], network: Network, own: RatchetKey) -> Self {
        Ratchet {
            network,
            root: Zeroizing::new(*root),
            dh_self: own,
            dh_remote: None,
            send_ck: None,
            recv_ck: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            skipped_order: VecDeque::new(),
        }
    }

    /// As [`Ratchet::respond`], already knowing the starter's first ratchet
    /// key `their` (sent in the handshake): performs that DH ratchet step at
    /// once, so this side can send before it has received anything.
    pub fn respond_to(root: &[u8; 32], network: Network, own: RatchetKey, their: [u8; 32]) -> Result<Self, RatchetError> {
        if !is_contributory_key(&their) {
            return Err(RatchetError::WeakKey);
        }
        let mut ratchet = Self::respond(root, network, own);
        let (recv_ck, step) = ratchet.dh_step(&their);
        ratchet.commit_step(step);
        ratchet.recv_ck = Some(recv_ck);
        Ok(ratchet)
    }

    /// Our current ratchet public key.
    pub fn public(&self) -> [u8; 32] {
        self.dh_self.public
    }

    /// How many skipped message keys are cached.
    pub fn skipped_keys(&self) -> usize {
        self.skipped.len()
    }

    /// A full copy of this state, secrets included. It exists only so tests
    /// can model a stolen device; never call it in a client.
    #[doc(hidden)]
    pub fn copy_state_for_tests(&self) -> Ratchet {
        Ratchet {
            network: self.network,
            root: self.root.clone(),
            dh_self: self.dh_self.duplicate(),
            dh_remote: self.dh_remote,
            send_ck: self.send_ck.clone(),
            recv_ck: self.recv_ck.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
            skipped_order: self.skipped_order.clone(),
        }
    }

    /// Encrypt one message: `header || ciphertext`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(RatchetError::TooLarge);
        }
        let ck = self.send_ck.as_ref().ok_or(RatchetError::NoSendingChain)?;
        let next_ns = self.ns.checked_add(1).ok_or(RatchetError::Exhausted)?;
        let (next_ck, mk) = kdf_ck(ck);
        let header = Header { dh: self.dh_self.public, pn: self.pn, n: self.ns }.encode();
        let ciphertext = seal_with(&mk, &self.network, &header, plaintext);
        self.send_ck = Some(next_ck);
        self.ns = next_ns;
        Ok([header.as_slice(), &ciphertext].concat())
    }

    /// Decrypt one message. Order does not matter within the skip limits;
    /// a message already opened is refused. A failure changes nothing.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
        self.decrypt_if(message, |_| true)
    }

    /// Decrypt one message and keep the result only if `accept` approves the
    /// plaintext. A refused or failed message changes nothing, so the
    /// genuine use of the same bytes still works.
    pub fn decrypt_if(
        &mut self,
        message: &[u8],
        accept: impl FnOnce(&[u8]) -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
        if message.len() < MIN_MESSAGE || message.len() > MAX_MESSAGE {
            return Err(RatchetError::Malformed);
        }
        let (header_bytes, ciphertext) = message.split_at(HEADER_LEN);
        let header = Header::decode(header_bytes);
        let staged = self.stage(&header)?;
        let plaintext = open_with(&staged.message_key, &self.network, header_bytes, ciphertext)?;
        if !accept(&plaintext) {
            return Err(RatchetError::Refused);
        }
        self.commit(staged);
        Ok(plaintext)
    }

    /// Work out the message key for `header` and every state change it
    /// implies, without changing anything.
    fn stage(&self, header: &Header) -> Result<Staged, RatchetError> {
        let id = (header.dh, header.n);
        if let Some(mk) = self.skipped.get(&id) {
            return Ok(Staged {
                message_key: mk.clone(),
                skipped: Vec::new(),
                from_cache: Some(id),
                step: None,
                recv_ck: self.recv_ck.clone(),
                nr: self.nr,
            });
        }
        let mut skipped = Vec::new();
        if self.dh_remote == Some(header.dh) && self.recv_ck.is_some() {
            // The current receiving chain.
            if header.n < self.nr {
                return Err(RatchetError::Replay);
            }
            if header.n - self.nr > MAX_SKIP_PER_STEP {
                return Err(RatchetError::TooManySkipped);
            }
            let ck = self.recv_ck.clone().expect("checked above");
            let (ck, nr) = skip(ck, self.nr, header.n, &header.dh, &mut skipped);
            let (next_ck, message_key) = kdf_ck(&ck);
            return Ok(Staged { message_key, skipped, from_cache: None, step: None, recv_ck: Some(next_ck), nr: nr + 1 });
        }
        // A new ratchet key: check everything that is cheap before any key
        // agreement or derivation.
        if !is_contributory_key(&header.dh) {
            return Err(RatchetError::WeakKey);
        }
        if header.n > MAX_SKIP_PER_STEP {
            return Err(RatchetError::TooManySkipped);
        }
        if let (Some(_), Some(remote)) = (&self.recv_ck, self.dh_remote) {
            if header.pn > self.nr && header.pn - self.nr > MAX_SKIP_PER_STEP {
                return Err(RatchetError::TooManySkipped);
            }
            // Keys left in the old receiving chain, up to its announced end.
            let ck = self.recv_ck.clone().expect("matched above");
            skip(ck, self.nr, header.pn, &remote, &mut skipped);
        }
        let (recv_ck, step) = self.dh_step(&header.dh);
        let (ck, nr) = skip(recv_ck, 0, header.n, &header.dh, &mut skipped);
        let (next_ck, message_key) = kdf_ck(&ck);
        Ok(Staged { message_key, skipped, from_cache: None, step: Some(step), recv_ck: Some(next_ck), nr: nr + 1 })
    }

    /// The DH ratchet step for a new remote key: the receiving chain it
    /// opens, and the new root, sending chain and our fresh key pair.
    fn dh_step(&self, remote: &[u8; 32]) -> (Secret, Step) {
        let (root, recv_ck) = kdf_rk(&self.root, &self.dh_self.agree(remote));
        let dh_self = RatchetKey::generate();
        let (root, send_ck) = kdf_rk(&root, &dh_self.agree(remote));
        (recv_ck, Step { remote: *remote, root, send_ck, dh_self })
    }

    fn commit_step(&mut self, step: Step) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_remote = Some(step.remote);
        self.root = step.root;
        self.send_ck = Some(step.send_ck);
        self.dh_self = step.dh_self;
    }

    fn commit(&mut self, staged: Staged) {
        if let Some(id) = staged.from_cache {
            // Used once: erase it now (the Zeroizing value wipes on drop).
            self.skipped.remove(&id);
            self.skipped_order.retain(|k| *k != id);
            return;
        }
        if let Some(step) = staged.step {
            self.commit_step(step);
        }
        for (id, key) in staged.skipped {
            self.skipped.insert(id, key);
            self.skipped_order.push_back(id);
        }
        while self.skipped.len() > MAX_TOTAL_SKIPPED {
            let Some(oldest) = self.skipped_order.pop_front() else { break };
            self.skipped.remove(&oldest);
        }
        self.recv_ck = staged.recv_ck;
        self.nr = staged.nr;
    }
}

/// Advance chain `ck` from message `from` up to (not including) `until`,
/// collecting the skipped message keys for `dh`. Returns the chain key and
/// counter reached. The caller has checked `until - from` against the cap.
fn skip(
    mut ck: Secret,
    from: u32,
    until: u32,
    dh: &[u8; 32],
    out: &mut Vec<(([u8; 32], u32), Secret)>,
) -> (Secret, u32) {
    let mut n = from;
    while n < until {
        let (next, mk) = kdf_ck(&ck);
        out.push(((*dh, n), mk));
        ck = next;
        n += 1;
    }
    (ck, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Network = [7; 32];

    fn pair() -> (Ratchet, Ratchet) {
        let root = [1u8; 32];
        let bob_key = RatchetKey::generate();
        let bob_pub = bob_key.public();
        (Ratchet::initiate(&root, NET, bob_pub).unwrap(), Ratchet::respond(&root, NET, bob_key))
    }

    #[test]
    fn the_kdfs_are_domain_separated() {
        let k = [5u8; 32];
        let (a, b) = kdf_ck(&k);
        let (c, d) = kdf_rk(&k, &[0u8; 32]);
        let all = [*a, *b, *c, *d];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn a_failed_message_leaves_every_field_as_it_was() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x").unwrap();
        let mut bad = m.clone();
        *bad.last_mut().unwrap() ^= 1;
        let before = (b.dh_self.public, b.dh_remote, b.nr, b.ns, b.pn, *b.root, b.skipped.len());
        assert_eq!(b.decrypt(&bad).unwrap_err(), RatchetError::Decrypt);
        assert_eq!(before, (b.dh_self.public, b.dh_remote, b.nr, b.ns, b.pn, *b.root, b.skipped.len()));
        assert_eq!(&*b.decrypt(&m).unwrap(), b"x");
    }

    #[test]
    fn the_skipped_cache_evicts_the_oldest_beyond_its_cap() {
        let (mut a, mut b) = pair();
        b.decrypt(&a.encrypt(b"start").unwrap()).unwrap();
        // Five chains of 256 skipped keys each (more than the cap of 1,024).
        let mut first_skipped = None;
        for round in 0..5 {
            let held: Vec<Vec<u8>> = (0..=MAX_SKIP_PER_STEP).map(|i| a.encrypt(&[i as u8]).unwrap()).collect();
            if round == 0 {
                first_skipped = Some(held[0].clone());
            }
            b.decrypt(held.last().unwrap()).unwrap();
            // Turn the ratchet so the next round is a fresh chain.
            a.decrypt(&b.encrypt(b"turn").unwrap()).unwrap();
            assert!(b.skipped.len() <= MAX_TOTAL_SKIPPED);
            assert_eq!(b.skipped.len(), b.skipped_order.len());
        }
        assert_eq!(b.skipped.len(), MAX_TOTAL_SKIPPED);
        assert_eq!(b.decrypt(&first_skipped.unwrap()).unwrap_err(), RatchetError::Decrypt, "evicted");
    }
}
