//! Contact identities, contact cards and invitations (spec v0.7 section 2a).
//!
//! A contact identity is separate from the wallet: three keys generated
//! independently of any money key. None of them can spend, view balances or
//! compute a nullifier, and no wallet key appears in a card, a handshake or
//! a note.
//!
//! * a **contact signing key** (Ed25519) signs the card and invitations;
//! * a **handshake key** (X25519) is the Noise static key callers reach;
//! * an **inbox key** (X25519) opens sealed notes from strangers.
//!
//! Callers use *caller keys* ([`StaticKey`]) scoped to one relationship or
//! one request; an invitation is issued to such a holder key.
//!
//! Stated plainly: these formats are a prototype of section 2a. They have
//! not been reviewed (spec questions 11 and 12).

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

/// A contact identity: signing, handshake and inbox keys.
pub struct ContactIdentity {
    signing: SigningKey,
    handshake: StaticKey,
    inbox: StaticKey,
}

impl ContactIdentity {
    pub fn generate() -> Self {
        ContactIdentity {
            signing: SigningKey::generate(&mut OsRng),
            handshake: StaticKey::generate(),
            inbox: StaticKey::generate(),
        }
    }

    /// Restore from the three secrets (signing, handshake, inbox).
    pub fn from_secret_bytes(signing: [u8; 32], handshake: [u8; 32], inbox: [u8; 32]) -> Self {
        ContactIdentity {
            signing: SigningKey::from_bytes(&signing),
            handshake: StaticKey::from_bytes(handshake),
            inbox: StaticKey::from_bytes(inbox),
        }
    }

    /// The three secrets, for encrypted storage. Handle with care.
    pub fn to_secret_bytes(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.signing.to_bytes(), self.handshake.to_bytes(), self.inbox.to_bytes())
    }

    /// The public contact signing key: who this contact is.
    pub fn signing_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn handshake_key(&self) -> &StaticKey {
        &self.handshake
    }

    pub fn inbox_key(&self) -> &StaticKey {
        &self.inbox
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// A signed card to hand out or list, for one network: keys, price,
    /// validity `[not_before, not_after)` in seconds.
    pub fn card(&self, network: Network, price: Amount, not_before: u64, not_after: u64) -> ContactCard {
        let mut card = ContactCard {
            network,
            signing_key: self.signing_key(),
            handshake_key: self.handshake.public(),
            inbox_key: self.inbox.public(),
            price,
            not_before,
            not_after,
            signature: [0; 64],
        };
        card.signature = self.sign(&card.signed_bytes());
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

pub(crate) fn verify_signature(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verify(key, message, signature).is_ok()
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> [u8; N] {
    let out = bytes[*at..*at + N].try_into().expect("length checked by caller");
    *at += N;
    out
}

// ---- contact card ------------------------------------------------------------

/// What a user hands out or lists publicly, signed by the contact signing key.
/// Valid on one network only (issue I20).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactCard {
    pub network: Network,
    pub signing_key: [u8; 32],
    pub handshake_key: [u8; 32],
    pub inbox_key: [u8; 32],
    pub price: Amount,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl ContactCard {
    /// Serialised length.
    pub const LEN: usize = 32 + 32 * 3 + 16 + 8 + 8 + 64;

    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = b"anonymum/contact-card/v2".to_vec();
        out.extend_from_slice(&self.to_bytes()[..Self::LEN - 64]);
        out
    }

    /// Signature, network, keys, price and validity at time `now`.
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.signing_key);
        out.extend_from_slice(&self.handshake_key);
        out.extend_from_slice(&self.inbox_key);
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
        let mut card = id.card(NET, price, 0, 100);
        card.handshake_key = handshake;
        card.inbox_key = inbox;
        card.signature = id.sign(&card.signed_bytes());
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
        let id = ContactIdentity::generate();
        let good = StaticKey::generate().public();
        for weak in SMALL_ORDER {
            assert_eq!(signed_card(&id, weak, good, 1).verify(&NET, 50), Err(ContactError::WeakKey));
            assert_eq!(signed_card(&id, good, weak, 1).verify(&NET, 50), Err(ContactError::WeakKey));
        }
        assert_eq!(signed_card(&id, good, StaticKey::generate().public(), 1).verify(&NET, 50), Ok(()));
    }

    #[test]
    fn a_card_price_must_fit_64_bits() {
        let id = ContactIdentity::generate();
        let (h, i) = (StaticKey::generate().public(), StaticKey::generate().public());
        assert_eq!(signed_card(&id, h, i, MAX_PRICE).verify(&NET, 50), Ok(()));
        assert_eq!(signed_card(&id, h, i, MAX_PRICE + 1).verify(&NET, 50), Err(ContactError::PriceOutOfRange));
        assert_eq!(signed_card(&id, h, i, u128::MAX).verify(&NET, 50), Err(ContactError::PriceOutOfRange));
    }

    #[test]
    fn an_invitation_to_a_small_order_holder_key_is_refused() {
        let id = ContactIdentity::generate();
        for weak in SMALL_ORDER {
            let invitation = id.invite(NET, weak, Purpose::Contact, 100);
            assert_eq!(invitation.verify(&id.signing_key(), &NET, 50), Err(ContactError::WeakKey));
        }
    }
}
