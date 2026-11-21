//! Contact identities, contact cards and invitations (spec v0.7 section 2a).
//!
//! A contact identity is separate from the wallet: three keys generated
//! independently of any money key. None of them can spend, view balances or
//! compute a nullifier, and no wallet key appears in a card, a handshake or
//! a note.
//!
//! * a **contact signing key** (Ed25519) signs the card and invitations;
//! * a **handshake key** (X25519) is the Noise static key callers reach,
//!   and the static key a stranger's note and callback are tied to;
//! * an **inbox key** (X25519) opens sealed notes from strangers;
//! * a **post-quantum inbox key** (ML-KEM-768, FIPS 203, via the RustCrypto
//!   `ml-kem` crate) is combined with the inbox key in the hybrid note (v5).
//!   The handshake key has no post-quantum counterpart yet.
//!
//! Only the signing key is long-lived: it is who the contact is. The
//! handshake key and the two inbox keys belong to a [`KeyEpoch`] on a
//! shared weekly grid and are rotated together
//! ([`ContactIdentity::rotate_epoch`]). The identity keeps at most two
//! epochs, the active one (published on the card) and one draining epoch
//! that can still open notes and answer handshakes and callbacks until its
//! end plus [`DRAIN_GRACE`]; after that [`ContactIdentity::purge_expired`]
//! drops it, and notes, handshakes and callbacks addressed to it can no
//! longer be read by anyone who later takes the device (forward secrecy
//! for notes, audit CRIT-02, and for the first IK message; unreviewed).
//! Contacts learn a rotated handshake key from a new card signed by the
//! same signing key ([`crate::wire::Responder::roll_contact_key`]).
//!
//! Callers use *caller keys* ([`StaticKey`]) scoped to one relationship or
//! one request; an invitation is issued to such a holder key.
//!
//! Stated plainly: these formats are a prototype of section 2a. They have
//! not been reviewed (spec questions 11 and 12).

use std::fmt;

use blake2::{Blake2s256, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ml_kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Which network a card or invitation is for (e.g. a genesis hash).
pub type Network = [u8; 32];

/// Smallest units, as on the chain.
pub type Amount = u128;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContactError {
    BadSignature,
    NotYetValid,
    Expired,
    WrongNetwork,
    WrongIssuer,
    UnknownPurpose,
    Malformed,
    /// An X25519 public key whose key agreement would not depend on our
    /// secret (a small-order point; RFC 7748 section 6.1).
    WeakKey,
    /// A price that does not fit the shielded design's 64-bit amounts.
    PriceOutOfRange,
    /// An invitation that was cancelled by a block or a removal.
    Revoked,
    /// A key rollover for a signing key that is not a current contact.
    UnknownContact,
    /// A card or binding whose signing key is not the one recorded for
    /// that contact.
    SignerMismatch,
    /// A new handshake key that is blocked or already belongs to another
    /// contact or grant.
    KeyInUse,
    /// A rollover card whose `not_after` is not later than the bound
    /// card's: an old card replayed, or a second card for the same epoch.
    StaleCard,
    /// An ML-KEM-768 encapsulation key that does not decode (FIPS 203 check).
    BadPqKey,
}

/// Length of an ML-KEM-768 encapsulation key.
pub const PQ_KEY_LEN: usize = 1_184;
/// Length of an ML-KEM-768 ciphertext.
pub const PQ_CIPHERTEXT_LEN: usize = 1_088;
/// Length of the seed an ML-KEM-768 decapsulation key is derived from.
pub const PQ_SEED_LEN: usize = 64;

/// The 32-byte commitment to a post-quantum inbox key that the card
/// signature covers: `BLAKE2s-256("anonymum/pq-inbox-key/v1" || key)`. A note
/// carries this hash instead of the 1,184-byte key.
pub fn pq_key_hash(key: &[u8; PQ_KEY_LEN]) -> [u8; 32] {
    Blake2s256::new().chain_update(b"anonymum/pq-inbox-key/v1").chain_update(key).finalize().into()
}

/// The ML-KEM-768 encapsulation key in `bytes`, if it passes FIPS 203's
/// input check.
pub(crate) fn pq_encapsulation_key(bytes: &[u8; PQ_KEY_LEN]) -> Result<EncapsulationKey768, ContactError> {
    EncapsulationKey768::new(&(*bytes).into()).map_err(|_| ContactError::BadPqKey)
}

/// Encapsulate to `key`: the ciphertext and the 32-byte shared secret.
pub(crate) fn pq_encapsulate(key: &[u8; PQ_KEY_LEN]) -> Result<([u8; PQ_CIPHERTEXT_LEN], [u8; 32]), ContactError> {
    let (ciphertext, shared) = pq_encapsulation_key(key)?.encapsulate();
    Ok((ciphertext.into(), shared.into()))
}

impl fmt::Display for ContactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ContactError {}

/// 32 fresh random bytes from the operating system, e.g. a stand-in
/// admission commitment where the transparent prototype chain has none.
pub fn random_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

/// Is `public` an X25519 key whose key agreement depends on our secret?
///
/// RFC 7748 section 6.1 lets a party check that the shared secret is not
/// all zeros. We use x25519-dalek's own facility for that check,
/// `SharedSecret::was_contributory`, on an agreement between `public` and a
/// fresh random secret. Clamped X25519 scalars are multiples of the
/// cofactor, so the result is all zeros for every secret exactly when
/// `public` has small order; one fresh secret therefore decides it. No list
/// of bad points is kept here. Applied to every X25519 key we receive from
/// someone else: card keys, invitation holder keys, a note's callback key,
/// the key a caller presents, and the keys we are asked to call or seal to.
pub fn is_contributory_key(public: &[u8; 32]) -> bool {
    StaticSecret::random_from_rng(OsRng).diffie_hellman(&PublicKey::from(*public)).was_contributory()
}

pub(crate) fn check_key(public: &[u8; 32]) -> Result<(), ContactError> {
    if is_contributory_key(public) {
        Ok(())
    } else {
        Err(ContactError::WeakKey)
    }
}

// ---- inbox epochs -----------------------------------------------------------------

/// Length of an inbox epoch: one week. Epochs start at multiples of this
/// (Unix seconds), the same grid for everyone, so a card's validity does
/// not reveal when its owner created or rotated it.
pub const EPOCH_LEN: u64 = 7 * 86_400;

/// How far a card's `not_before` lies before its epoch's start. The chain
/// stamps a request's `created_at` as the start of the clock-grid window
/// that holds its block (spec P11), which can be earlier than the moment
/// the card was made; the widest window P11 allows is 24 hours (it must
/// divide 24 hours). Backdating by a full day means a freshly made card is
/// always valid at the floored `created_at` of a note sealed with it, and
/// also absorbs a sender clock that runs up to a day ahead.
pub const CLOCK_GRID_BACKDATE: u64 = 86_400;

/// How long after an epoch's `not_after` its inbox secrets are kept: the
/// 24-hour request lifetime (decision D2) plus 2 hours for gateway delivery
/// and clock skew. A note sealed to the card at its last valid moment can
/// be answered until its request expires, and opened for 2 hours more.
pub const DRAIN_GRACE: u64 = 24 * 3600 + 2 * 3600;

/// The start of the epoch that holds `now_secs`.
pub fn epoch_start(now_secs: u64) -> u64 {
    now_secs - now_secs % EPOCH_LEN
}

/// Storage format of a contact identity. Version 2 (2026-11-21) keeps a
/// handshake key in each epoch; version 1 kept one long-lived handshake key
/// and is still read (see [`ContactIdentity::from_secret_bytes`]).
const IDENTITY_VERSION: u8 = 2;
const IDENTITY_V1: u8 = 1;
const EPOCH_BYTES: usize = 32 + 32 + PQ_SEED_LEN + 8 + 8;
const EPOCH_BYTES_V1: usize = 32 + PQ_SEED_LEN + 8 + 8;
/// The longest stored identity: both epochs.
const IDENTITY_MAX_LEN: usize = 1 + 32 + EPOCH_BYTES + 1 + EPOCH_BYTES;
const IDENTITY_MAX_LEN_V1: usize = 1 + 64 + EPOCH_BYTES_V1 + 1 + EPOCH_BYTES_V1;

/// One epoch's keys: the X25519 handshake key, the X25519 inbox key and the
/// ML-KEM-768 seed, and the validity a card for them carries. Every secret
/// is held in a zeroizing buffer, so dropping an epoch wipes them from
/// memory.
pub struct KeyEpoch {
    handshake: StaticKey,
    inbox: StaticKey,
    pq_seed: Zeroizing<[u8; PQ_SEED_LEN]>,
    not_before: u64,
    not_after: u64,
}

impl KeyEpoch {
    /// Fresh keys for the epoch that holds `now_secs`, valid from
    /// [`CLOCK_GRID_BACKDATE`] before its start until its end.
    pub fn generate_at(now_secs: u64) -> Self {
        let start = epoch_start(now_secs);
        let mut pq_seed = Zeroizing::new([0u8; PQ_SEED_LEN]);
        OsRng.fill_bytes(pq_seed.as_mut());
        KeyEpoch {
            handshake: StaticKey::generate(),
            inbox: StaticKey::generate(),
            pq_seed,
            not_before: start.saturating_sub(CLOCK_GRID_BACKDATE),
            not_after: start.saturating_add(EPOCH_LEN),
        }
    }

    /// Restore from storage. The validity must be a non-empty interval.
    pub fn from_secret_bytes(
        handshake: [u8; 32],
        inbox: [u8; 32],
        pq_seed: [u8; PQ_SEED_LEN],
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, ContactError> {
        if not_before >= not_after {
            return Err(ContactError::Malformed);
        }
        Ok(KeyEpoch {
            handshake: StaticKey::from_bytes(handshake),
            inbox: StaticKey::from_bytes(inbox),
            pq_seed: Zeroizing::new(pq_seed),
            not_before,
            not_after,
        })
    }

    /// The three secrets and the validity, for encrypted storage. Handle
    /// with care.
    pub fn to_secret_bytes(&self) -> ([u8; 32], [u8; 32], [u8; PQ_SEED_LEN], u64, u64) {
        (self.handshake.to_bytes(), self.inbox.to_bytes(), *self.pq_seed, self.not_before, self.not_after)
    }

    /// When this epoch's secrets are dropped: its `not_after` plus
    /// [`DRAIN_GRACE`].
    pub fn grace_end(&self) -> u64 {
        self.not_after.saturating_add(DRAIN_GRACE)
    }

    /// This epoch's handshake key (the Noise static key callers reach).
    pub fn handshake_key(&self) -> &StaticKey {
        &self.handshake
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    pub fn inbox_key(&self) -> &StaticKey {
        &self.inbox
    }

    fn pq_decapsulation_key(&self) -> DecapsulationKey768 {
        DecapsulationKey768::from_seed((*self.pq_seed).into())
    }

    /// The post-quantum inbox key (ML-KEM-768 encapsulation key) for the card.
    pub fn pq_inbox_key(&self) -> [u8; PQ_KEY_LEN] {
        self.pq_decapsulation_key().encapsulation_key().to_bytes().into()
    }

    /// The shared secret in `ciphertext`, as ML-KEM decapsulates it (an
    /// unrelated value for a ciphertext not made for this key: FIPS 203's
    /// implicit rejection).
    pub(crate) fn pq_decapsulate(&self, ciphertext: &[u8; PQ_CIPHERTEXT_LEN]) -> [u8; 32] {
        self.pq_decapsulation_key().decapsulate(&(*ciphertext).into()).into()
    }
}

impl fmt::Debug for KeyEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyEpoch({:?}, {:?}, [{}, {}))", self.handshake, self.inbox, self.not_before, self.not_after)
    }
}

/// Largest price a card may quote: the shielded design's amounts are
/// unsigned 64-bit (spec section 3).
pub const MAX_PRICE: Amount = u64::MAX as Amount;

/// An X25519 private key: a handshake key, an inbox key, or a caller key.
#[derive(Clone)]
pub struct StaticKey(Zeroizing<[u8; 32]>);

impl StaticKey {
    pub fn generate() -> Self {
        StaticKey(Zeroizing::new(StaticSecret::random_from_rng(OsRng).to_bytes()))
    }

    pub fn from_bytes(secret: [u8; 32]) -> Self {
        StaticKey(Zeroizing::new(secret))
    }

    /// The secret, for encrypted storage. Handle with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*self.0)).to_bytes()
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StaticKey(public {:02x?}…)", &self.public()[..4])
    }
}

/// A contact identity: the long-lived signing key and a ring of at most
/// two key epochs (the active one and one draining), each holding a
/// handshake key and the inbox keys.
pub struct ContactIdentity {
    signing: SigningKey,
    active: KeyEpoch,
    draining: Option<KeyEpoch>,
}

impl ContactIdentity {
    /// A new identity whose first key epoch holds `now_secs`.
    pub fn generate_at(now_secs: u64) -> Self {
        ContactIdentity { signing: SigningKey::generate(&mut OsRng), active: KeyEpoch::generate_at(now_secs), draining: None }
    }

    /// Restore from the signing secret and the epoch ring.
    pub fn from_parts(signing: [u8; 32], active: KeyEpoch, draining: Option<KeyEpoch>) -> Self {
        ContactIdentity { signing: SigningKey::from_bytes(&signing), active, draining }
    }

    /// The signing secret, for encrypted storage (the epochs are stored
    /// through [`Self::active`] and [`Self::draining`]). Handle with care.
    pub fn signing_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Everything, for encrypted storage, in one versioned encoding
    /// (version 2): `version (1) || signing (32) || active epoch || draining
    /// flag (1) [|| draining epoch]`, an epoch being `handshake (32) || inbox
    /// (32) || post-quantum seed (64) || not_before (8) || not_after (8)`,
    /// integers big-endian. Handle with care: the buffer is wiped when
    /// dropped.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(IDENTITY_MAX_LEN));
        out.push(IDENTITY_VERSION);
        out.extend_from_slice(self.signing_secret_bytes().as_ref());
        let mut epoch = |e: &KeyEpoch| {
            out.extend_from_slice(e.handshake.secret());
            out.extend_from_slice(e.inbox.secret());
            out.extend_from_slice(e.pq_seed.as_ref());
            out.extend_from_slice(&e.not_before.to_be_bytes());
            out.extend_from_slice(&e.not_after.to_be_bytes());
        };
        epoch(&self.active);
        if let Some(d) = &self.draining {
            epoch(d);
        }
        out.insert(1 + 32 + EPOCH_BYTES, self.draining.is_some() as u8);
        out
    }

    /// Restore what [`Self::to_secret_bytes`] wrote. Strict: an unknown
    /// version, flag or length, or an empty validity, is refused.
    ///
    /// Version 1 (one long-lived handshake key) is still read: that key
    /// becomes the handshake key of both stored epochs, which is what their
    /// cards published, so existing contacts keep reaching it. The next
    /// [`Self::rotate_epoch`] gives the new epoch a fresh handshake key, and
    /// the old one is gone once both epochs that held it are purged.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, ContactError> {
        let version = *bytes.first().ok_or(ContactError::Malformed)?;
        let (v1, epoch_len, max_len) = match version {
            IDENTITY_VERSION => (false, EPOCH_BYTES, IDENTITY_MAX_LEN),
            IDENTITY_V1 => (true, EPOCH_BYTES_V1, IDENTITY_MAX_LEN_V1),
            _ => return Err(ContactError::Malformed),
        };
        let first_epoch_at = if v1 { 1 + 64 } else { 1 + 32 };
        let flag_at = first_epoch_at + epoch_len;
        if bytes.len() <= flag_at {
            return Err(ContactError::Malformed);
        }
        let expected = match bytes[flag_at] {
            0 => flag_at + 1,
            1 => max_len,
            _ => return Err(ContactError::Malformed),
        };
        if bytes.len() != expected {
            return Err(ContactError::Malformed);
        }
        let shared = v1.then(|| Zeroizing::new(take::<32>(bytes, &mut 33)));
        let epoch = |at: usize| {
            let mut at = at;
            let handshake = match &shared {
                Some(key) => Zeroizing::new(**key),
                None => Zeroizing::new(take::<32>(bytes, &mut at)),
            };
            let inbox = Zeroizing::new(take::<32>(bytes, &mut at));
            let seed = Zeroizing::new(take::<PQ_SEED_LEN>(bytes, &mut at));
            let not_before = u64::from_be_bytes(take(bytes, &mut at));
            let not_after = u64::from_be_bytes(take(bytes, &mut at));
            KeyEpoch::from_secret_bytes(*handshake, *inbox, *seed, not_before, not_after)
        };
        let signing = Zeroizing::new(take::<32>(bytes, &mut 1));
        let active = epoch(first_epoch_at)?;
        let draining = if bytes[flag_at] == 1 { Some(epoch(flag_at + 1)?) } else { None };
        Ok(Self::from_parts(*signing, active, draining))
    }

    /// The epoch whose keys the card publishes.
    pub fn active(&self) -> &KeyEpoch {
        &self.active
    }

    /// The previous epoch, while it is kept.
    pub fn draining(&self) -> Option<&KeyEpoch> {
        self.draining.as_ref()
    }

    /// Start a new key epoch for `now_secs`: fresh handshake, inbox and
    /// post-quantum inbox keys. The active epoch becomes the draining one,
    /// and an older draining epoch is dropped at once (its secrets wiped),
    /// whatever its grace left. Publish a new card after, and send it to
    /// contacts so they roll their record of the handshake key forward.
    pub fn rotate_epoch(&mut self, now_secs: u64) {
        let previous = std::mem::replace(&mut self.active, KeyEpoch::generate_at(now_secs));
        let oldest = self.draining.replace(previous);
        drop(oldest);
    }

    /// Drop the draining epoch (wiping its handshake, inbox and post-quantum
    /// secrets) once `now_secs` has reached its `not_after` plus
    /// [`DRAIN_GRACE`]. Returns whether it did.
    pub fn purge_expired(&mut self, now_secs: u64) -> bool {
        if self.draining.as_ref().is_some_and(|d| now_secs >= d.grace_end()) {
            let expired = self.draining.take();
            drop(expired);
            return true;
        }
        false
    }

    /// The draining epoch, if it may still be used at `now_secs`.
    pub fn draining_at(&self, now_secs: u64) -> Option<&KeyEpoch> {
        self.draining.as_ref().filter(|d| now_secs < d.grace_end())
    }

    /// The handshake secret whose public key is `public`: the active
    /// epoch's, or the draining epoch's while its grace lasts. A caller uses
    /// it to call back with the exact key a card it handed out named.
    pub fn handshake_key_for(&self, public: &[u8; 32], now_secs: u64) -> Option<&StaticKey> {
        std::iter::once(&self.active)
            .chain(self.draining_at(now_secs))
            .map(|e| &e.handshake)
            .find(|k| &k.public() == public)
    }

    /// The active epoch's post-quantum inbox key.
    pub fn pq_inbox_key(&self) -> [u8; PQ_KEY_LEN] {
        self.active.pq_inbox_key()
    }

    /// The public contact signing key: who this contact is.
    pub fn signing_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The active epoch's handshake key: the one the card publishes.
    pub fn handshake_key(&self) -> &StaticKey {
        &self.active.handshake
    }

    /// The active epoch's inbox key.
    pub fn inbox_key(&self) -> &StaticKey {
        self.active.inbox_key()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// A signed card to hand out or list, for one network: keys, price, and
    /// the active epoch's validity (backdated start, epoch end).
    pub fn card(&self, network: Network, price: Amount) -> ContactCard {
        self.card_within(network, price, self.active.not_before, self.active.not_after)
    }

    /// A card whose validity is `[not_before, not_after)` narrowed to the
    /// active epoch's: a card never outlives the inbox keys it publishes.
    pub fn card_within(&self, network: Network, price: Amount, not_before: u64, not_after: u64) -> ContactCard {
        let not_before = not_before.max(self.active.not_before);
        let not_after = not_after.min(self.active.not_after);
        let mut card = ContactCard {
            network,
            signing_key: self.signing_key(),
            handshake_key: self.active.handshake.public(),
            inbox_key: self.active.inbox.public(),
            pq_inbox_key: self.active.pq_inbox_key(),
            price,
            not_before,
            not_after,
            signature: [0; 64],
        };
        card.signature = self.sign(&card.summary().signed_bytes());
        card
    }

    /// An invitation to the holder of `holder` (a caller key the invitee
    /// generated for this relationship). Its id is random.
    pub fn invite(&self, network: Network, holder: [u8; 32], purpose: Purpose, expires_at: u64) -> Invitation {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        let mut invitation =
            Invitation { network, issuer: self.signing_key(), holder, purpose, expires_at, id, signature: [0; 64] };
        invitation.signature = self.sign(&invitation.signed_bytes());
        invitation
    }
}

fn verify(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), ContactError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| ContactError::BadSignature)?;
    key.verify_strict(message, &Signature::from_bytes(signature)).map_err(|_| ContactError::BadSignature)
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> [u8; N] {
    let out = bytes[*at..*at + N].try_into().expect("length checked by caller");
    *at += N;
    out
}

// ---- contact card ------------------------------------------------------------

/// What a user hands out or lists publicly, signed by the contact signing key.
/// Valid on one network only (issue I20). Format v3: the signature covers a
/// 32-byte hash of the post-quantum inbox key ([`pq_key_hash`]), not the
/// 1,184 bytes themselves, so a note can carry the hash and the recipient
/// can still check the card.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactCard {
    pub network: Network,
    pub signing_key: [u8; 32],
    pub handshake_key: [u8; 32],
    pub inbox_key: [u8; 32],
    pub pq_inbox_key: [u8; PQ_KEY_LEN],
    pub price: Amount,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

/// A card's signed content with the post-quantum key replaced by its hash:
/// what a note carries about its sender, and what the signature covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CardSummary {
    pub network: Network,
    pub signing_key: [u8; 32],
    pub handshake_key: [u8; 32],
    pub inbox_key: [u8; 32],
    pub pq_inbox_hash: [u8; 32],
    pub price: Amount,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl CardSummary {
    /// The bytes the card's signature covers (card format v3).
    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
        let mut out = b"anonymum/contact-card/v3".to_vec();
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.signing_key);
        out.extend_from_slice(&self.handshake_key);
        out.extend_from_slice(&self.inbox_key);
        out.extend_from_slice(&self.pq_inbox_hash);
        out.extend_from_slice(&self.price.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out
    }

    /// Signature, network, X25519 keys, price and validity at time `now`.
    pub fn verify(&self, network: &Network, now: u64) -> Result<(), ContactError> {
        verify(&self.signing_key, &self.signed_bytes(), &self.signature)?;
        if &self.network != network {
            return Err(ContactError::WrongNetwork);
        }
        check_key(&self.handshake_key)?;
        check_key(&self.inbox_key)?;
        if self.price > MAX_PRICE {
            return Err(ContactError::PriceOutOfRange);
        }
        if now < self.not_before {
            return Err(ContactError::NotYetValid);
        }
        if now >= self.not_after {
            return Err(ContactError::Expired);
        }
        Ok(())
    }
}

impl ContactCard {
    /// Serialised length: network, three X25519 keys, the ML-KEM-768 key,
    /// price, validity and signature.
    pub const LEN: usize = 32 + 32 * 3 + PQ_KEY_LEN + 16 + 8 + 8 + 64;

    /// The signed content with the post-quantum key hashed.
    pub fn summary(&self) -> CardSummary {
        CardSummary {
            network: self.network,
            signing_key: self.signing_key,
            handshake_key: self.handshake_key,
            inbox_key: self.inbox_key,
            pq_inbox_hash: pq_key_hash(&self.pq_inbox_key),
            price: self.price,
            not_before: self.not_before,
            not_after: self.not_after,
            signature: self.signature,
        }
    }

    /// Signature, network, keys (including the post-quantum key's FIPS 203
    /// check), price and validity at time `now`.
    pub fn verify(&self, network: &Network, now: u64) -> Result<(), ContactError> {
        self.summary().verify(network, now)?;
        pq_encapsulation_key(&self.pq_inbox_key)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.signing_key);
        out.extend_from_slice(&self.handshake_key);
        out.extend_from_slice(&self.inbox_key);
        out.extend_from_slice(&self.pq_inbox_key);
        out.extend_from_slice(&self.price.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContactError> {
        if bytes.len() != Self::LEN {
            return Err(ContactError::Malformed);
        }
        let at = &mut 0;
        Ok(ContactCard {
            network: take(bytes, at),
            signing_key: take(bytes, at),
            handshake_key: take(bytes, at),
            inbox_key: take(bytes, at),
            pq_inbox_key: take(bytes, at),
            price: u128::from_be_bytes(take(bytes, at)),
            not_before: u64::from_be_bytes(take(bytes, at)),
            not_after: u64::from_be_bytes(take(bytes, at)),
            signature: take(bytes, at),
        })
    }
}

// ---- invitation ----------------------------------------------------------------

/// What an invitation is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// Open a contact relationship (messaging).
    Contact,
}

impl Purpose {
    fn to_byte(self) -> u8 {
        match self {
            Purpose::Contact => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, ContactError> {
        match b {
            1 => Ok(Purpose::Contact),
            _ => Err(ContactError::UnknownPurpose),
        }
    }
}

/// Issued by a contact identity to one holder key, for one network, one
/// purpose, until `expires_at` (seconds). The issuer's app records which
/// invitations it has honoured ([`crate::gate::Gate`]); one is used up only
/// after a confirmed session.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invitation {
    pub network: Network,
    /// The issuer's contact signing key.
    pub issuer: [u8; 32],
    /// The caller key the invitation is for.
    pub holder: [u8; 32],
    pub purpose: Purpose,
    pub expires_at: u64,
    /// Random; the caller names it inside the encrypted first message.
    pub id: [u8; 32],
    pub signature: [u8; 64],
}

impl Invitation {
    pub const LEN: usize = 32 * 3 + 1 + 8 + 32 + 64;

    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = b"anonymum/invitation/v1".to_vec();
        out.extend_from_slice(&self.to_bytes()[..Self::LEN - 64]);
        out
    }

    /// The holder's check: issued by `issuer` for `network`, signed, and not
    /// expired at `now`.
    pub fn verify(&self, issuer: &[u8; 32], network: &Network, now: u64) -> Result<(), ContactError> {
        if &self.issuer != issuer {
            return Err(ContactError::WrongIssuer);
        }
        if &self.network != network {
            return Err(ContactError::WrongNetwork);
        }
        verify(&self.issuer, &self.signed_bytes(), &self.signature)?;
        check_key(&self.holder)?;
        if now >= self.expires_at {
            return Err(ContactError::Expired);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.issuer);
        out.extend_from_slice(&self.holder);
        out.push(self.purpose.to_byte());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContactError> {
        if bytes.len() != Self::LEN {
            return Err(ContactError::Malformed);
        }
        let at = &mut 0;
        let network = take(bytes, at);
        let issuer = take(bytes, at);
        let holder = take(bytes, at);
        let purpose = Purpose::from_byte(take::<1>(bytes, at)[0])?;
        Ok(Invitation {
            network,
            issuer,
            holder,
            purpose,
            expires_at: u64::from_be_bytes(take(bytes, at)),
            id: take(bytes, at),
            signature: take(bytes, at),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Small-order points on Curve25519 and their non-canonical encodings
    /// (the u-coordinates 0, 1, the two order-8 points, p-1, p, p+1), as
    /// listed for X25519 implementations; used only as test vectors here.
    pub(crate) const SMALL_ORDER: [[u8; 32]; 7] = [
        hex32("0000000000000000000000000000000000000000000000000000000000000000"),
        hex32("0100000000000000000000000000000000000000000000000000000000000000"),
        hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];

    const fn hex32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        }
    }

    const NET: Network = [9; 32];

    /// A card signed over arbitrary keys, as a malicious holder could make.
    fn signed_card(id: &ContactIdentity, handshake: [u8; 32], inbox: [u8; 32], price: Amount) -> ContactCard {
        let mut card = id.card_within(NET, price, 0, 100);
        card.handshake_key = handshake;
        card.inbox_key = inbox;
        card.signature = id.sign(&card.summary().signed_bytes());
        card
    }

    #[test]
    fn small_order_points_are_not_contributory_and_real_keys_are() {
        for weak in SMALL_ORDER {
            assert!(!is_contributory_key(&weak), "{weak:02x?}");
        }
        for _ in 0..16 {
            assert!(is_contributory_key(&StaticKey::generate().public()));
        }
    }

    #[test]
    fn a_signed_card_with_a_small_order_key_is_refused() {
        let id = ContactIdentity::generate_at(0);
        let good = StaticKey::generate().public();
        for weak in SMALL_ORDER {
            assert_eq!(signed_card(&id, weak, good, 1).verify(&NET, 50), Err(ContactError::WeakKey));
            assert_eq!(signed_card(&id, good, weak, 1).verify(&NET, 50), Err(ContactError::WeakKey));
        }
        assert_eq!(signed_card(&id, good, StaticKey::generate().public(), 1).verify(&NET, 50), Ok(()));
    }

    #[test]
    fn a_signed_card_with_an_invalid_post_quantum_key_is_refused() {
        // Signed by its holder, so only the FIPS 203 input check catches it:
        // coefficients of 0xFFF are not below the ML-KEM modulus.
        let id = ContactIdentity::generate_at(0);
        let mut card = id.card_within(NET, 1, 0, 100);
        card.pq_inbox_key = [0xFF; PQ_KEY_LEN];
        card.signature = id.sign(&card.summary().signed_bytes());
        assert_eq!(card.summary().verify(&NET, 50), Ok(()), "the signature itself is fine");
        assert_eq!(card.verify(&NET, 50), Err(ContactError::BadPqKey));
        assert_eq!(id.card_within(NET, 1, 0, 100).verify(&NET, 50), Ok(()));
    }

    #[test]
    fn a_card_price_must_fit_64_bits() {
        let id = ContactIdentity::generate_at(0);
        let (h, i) = (StaticKey::generate().public(), StaticKey::generate().public());
        assert_eq!(signed_card(&id, h, i, MAX_PRICE).verify(&NET, 50), Ok(()));
        assert_eq!(signed_card(&id, h, i, MAX_PRICE + 1).verify(&NET, 50), Err(ContactError::PriceOutOfRange));
        assert_eq!(signed_card(&id, h, i, u128::MAX).verify(&NET, 50), Err(ContactError::PriceOutOfRange));
    }

    #[test]
    fn an_invitation_to_a_small_order_holder_key_is_refused() {
        let id = ContactIdentity::generate_at(0);
        for weak in SMALL_ORDER {
            let invitation = id.invite(NET, weak, Purpose::Contact, 100);
            assert_eq!(invitation.verify(&id.signing_key(), &NET, 50), Err(ContactError::WeakKey));
        }
    }
}
