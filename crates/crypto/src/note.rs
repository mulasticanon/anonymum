//! A stranger's sealed note (spec v0.7 section 2a, rule 4; reverse
//! rendezvous), format v5: hybrid post-quantum confidentiality (ML-KEM-768
//! with X25519) and deniable sender authentication (issue I27).
//!
//! A stranger who pays to reach someone cannot know their mixnet route: it
//! is never published. The stranger seals a note to the recipient's contact
//! card. The recipient opens it with their own secrets alone: no sender
//! address or other hint is needed, so a fresh wallet finds its notes by
//! trying each one.
//!
//! **Hybrid confidentiality.** The sender encapsulates to the recipient's
//! post-quantum inbox key (ML-KEM-768, FIPS 203, the RustCrypto `ml-kem`
//! crate), getting a 1,088-byte ciphertext and a 32-byte shared secret. The
//! ciphertext is bound into the Noise prologue and the shared secret is the
//! pre-shared key of one Noise Xpsk0 message
//! (`Noise_Xpsk0_25519_ChaChaPoly_BLAKE2s`, via `snow`'s public API) to the
//! recipient's X25519 inbox key. Reading the note needs both the ML-KEM
//! secret and the X25519 inbox secret, so an attacker who later breaks
//! X25519 (a quantum computer) still cannot read recorded notes unless
//! ML-KEM-768 is also broken. Whether this combination is the right hybrid
//! is for the cryptographer (W6); nothing here is a reviewed design.
//!
//! **Who sent it, deniably.** Noise X's sender static key is the sender's
//! contact *handshake key*, authenticated to the recipient by
//! Diffie-Hellman, not by a signature: the recipient is convinced, but could
//! have computed the same message from their own inbox secret and the
//! sender's public card (encapsulating to their own public post-quantum key
//! needs no secret at all), so the note proves nothing to anyone else. The
//! ciphertext also carries the rest of the sender's signed card, with the
//! sender's post-quantum key replaced by its 32-byte hash (which is what
//! the card signature covers), so the recipient learns which contact
//! identity the handshake key belongs to without 1,184 more bytes.
//!
//! **The costs (recorded for the cryptographer).**
//! - Anyone who holds the recipient's X25519 inbox secret can make a note
//!   that opens as if from any sender whose card they have; the ML-KEM layer
//!   does not change that. The callback limits the damage: the recipient
//!   calls the sender's handshake key itself, so only its holder can answer.
//! - Sender authentication is classical only. An attacker who can break
//!   X25519 can derive the inbox secret from the public card and forge
//!   notes, and the callback's Noise IK handshake is classical too
//!   (post-quantum callbacks are to be negotiated off-chain later).
//! - Forward secrecy for notes comes only from rotating the inbox keys
//!   ([`ContactIdentity::rotate_epoch`], weekly epochs): while an epoch's
//!   two secrets are kept, anyone who takes them can read every recorded
//!   note sealed to that epoch. Once the epoch is purged (its end plus
//!   [`crate::contact::DRAIN_GRACE`]) they are gone from the device.
//!   Unreviewed.
//!
//! # Field layout (fixed, [`SEALED_NOTE_LEN`] = 1,787 bytes)
//!
//! ```text
//! admission commitment                  32
//! ML-KEM-768 ciphertext               1088
//! Noise Xpsk0 message                  667
//!   e (ephemeral public key)            32
//!   s (sender handshake key) + tag      48
//!   payload (571) + tag                587
//! ```
//!
//! The payload, all inside the ciphertext:
//!
//! ```text
//! offset  len  field
//!      0    1  version (5)
//!      1   32  sender's contact signing key          (card)
//!     33   32  sender's inbox key                    (card)
//!     65   32  hash of sender's post-quantum key     (card, signed)
//!     97   16  price, u128 big-endian                (card)
//!    113    8  card not_before, u64 big-endian       (card)
//!    121    8  card not_after, u64 big-endian        (card)
//!    129   64  card signature                        (card)
//!    193   96  throwaway route (a Nym Recipient)
//!    289    2  intro length, u16 big-endian
//!    291  280  intro, UTF-8, zero-padded
//! ```
//!
//! The card's handshake key is the authenticated Noise static and its
//! network is the one in the prologue, so neither is repeated. The Noise
//! prologue is `"anonymum/contact-note/v5" || network || admission ||
//! ML-KEM ciphertext`, so the note opens only on its network, next to the
//! admission commitment it names, and with its own ciphertext. In the
//! shielded design the admission commitment is a separate public field of
//! the transaction (spec section 3); the transparent prototype chain has
//! none, so here the note field carries it.
//!
//! Nothing here is hand-made cryptography. Stated plainly: unreviewed
//! (spec questions 11 and 12).

use std::fmt;

use anonymum_core::crypto::SealedNote;
use rand_core::{OsRng, RngCore};
use snow::Builder;

use crate::contact::{
    is_contributory_key, pq_encapsulate, random_bytes, CardSummary, ContactCard, ContactError, ContactIdentity, KeyEpoch,
    Network, PQ_CIPHERTEXT_LEN,
};

const PATTERN: &str = "Noise_Xpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/contact-note/v5";
const VERSION: u8 = 5;

/// Bytes reserved for the throwaway route (sized for a Nym `Recipient`).
pub const ROUTE_LEN: usize = 96;
/// Longest intro, in bytes of UTF-8. Proposed cap; open question.
pub const INTRO_MAX_BYTES: usize = 280;
pub const ADMISSION_LEN: usize = 32;
/// The card fields the note carries: signing key, inbox key, hash of the
/// post-quantum key, price, validity and signature.
const CARD_LEN: usize = 32 + 32 + 32 + 16 + 8 + 8 + 64;
const ROUTE_AT: usize = 1 + CARD_LEN;
const LEN_AT: usize = ROUTE_AT + ROUTE_LEN;
const PAYLOAD_LEN: usize = LEN_AT + 2 + INTRO_MAX_BYTES;
/// Noise X: e (32), encrypted s (32 + 16), encrypted payload (+ 16). The
/// psk0 modifier adds no bytes.
const ENVELOPE_LEN: usize = 32 + 48 + PAYLOAD_LEN + 16;
const ENVELOPE_AT: usize = ADMISSION_LEN + PQ_CIPHERTEXT_LEN;
/// The whole note field.
pub const SEALED_NOTE_LEN: usize = ENVELOPE_AT + ENVELOPE_LEN;
const _: () = assert!(SEALED_NOTE_LEN == anonymum_core::SEALED_NOTE_LEN, "the chain checks this length");
const _: () = assert!(SEALED_NOTE_LEN == 1_787 && ENVELOPE_LEN == 667);

/// What the recipient reads after opening a note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactNote {
    /// The admission commitment the note is bound to.
    pub admission: [u8; ADMISSION_LEN],
    /// The sender's card, rebuilt and verified, with the post-quantum key as
    /// its hash. Its handshake key is the key Noise X authenticated; the
    /// recipient calls back to it.
    pub card: CardSummary,
    /// Where to call (a Nym `Recipient`, as bytes).
    pub route: [u8; ROUTE_LEN],
    pub intro: String,
}

impl ContactNote {
    /// The sender's contact signing key (who the stranger is).
    pub fn sender(&self) -> [u8; 32] {
        self.card.signing_key
    }

    /// The handshake key to call back: the one Noise X authenticated.
    pub fn callback(&self) -> [u8; 32] {
        self.card.handshake_key
    }
}

#[derive(Debug)]
pub enum NoteError {
    IntroTooLong { len: usize },
    BadSize { len: usize },
    /// Not for these inbox keys, for another network or admission
    /// commitment, another note format, or tampered (including the ML-KEM
    /// ciphertext).
    Noise(snow::Error),
    /// The sender's card does not verify (signature, network, keys, price,
    /// validity), does not belong to the sending identity, or the
    /// recipient's card is unusable (wrong network, bad post-quantum key).
    BadCard(ContactError),
    /// Decrypted, but not a well-formed note.
    Malformed,
    /// A key whose key agreement would not depend on our secret.
    WeakKey,
}

impl fmt::Display for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NoteError {}

impl From<snow::Error> for NoteError {
    fn from(e: snow::Error) -> Self {
        NoteError::Noise(e)
    }
}

fn prologue(network: &Network, admission: &[u8; ADMISSION_LEN], ciphertext: &[u8; PQ_CIPHERTEXT_LEN]) -> Vec<u8> {
    [PROLOGUE, network.as_slice(), admission.as_slice(), ciphertext.as_slice()].concat()
}

fn builder() -> Builder<'static> {
    Builder::new(PATTERN.parse().expect("pattern is a valid constant"))
}

/// The payload for a note from the holder of the card summarised by `card`.
fn payload(card: &CardSummary, route: &[u8; ROUTE_LEN], intro: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_LEN];
    out[0] = VERSION;
    out[1..33].copy_from_slice(&card.signing_key);
    out[33..65].copy_from_slice(&card.inbox_key);
    out[65..97].copy_from_slice(&card.pq_inbox_hash);
    out[97..113].copy_from_slice(&card.price.to_be_bytes());
    out[113..121].copy_from_slice(&card.not_before.to_be_bytes());
    out[121..129].copy_from_slice(&card.not_after.to_be_bytes());
    out[129..193].copy_from_slice(&card.signature);
    out[ROUTE_AT..LEN_AT].copy_from_slice(route);
    out[LEN_AT..LEN_AT + 2].copy_from_slice(&(intro.len() as u16).to_be_bytes());
    out[LEN_AT + 2..LEN_AT + 2 + intro.len()].copy_from_slice(intro);
    out
}

/// The whole note field: admission, ML-KEM ciphertext, and one Noise Xpsk0
/// message from `local_secret` (through `builder`'s resolver) to
/// `recipient_inbox` keyed by `shared` (the encapsulated secret).
#[allow(clippy::too_many_arguments)]
fn envelope(
    builder: Builder<'_>,
    network: &Network,
    admission: &[u8; ADMISSION_LEN],
    ciphertext: &[u8; PQ_CIPHERTEXT_LEN],
    shared: &[u8; 32],
    local_secret: &[u8],
    recipient_inbox: &[u8; 32],
    payload: &[u8],
) -> Result<SealedNote, NoteError> {
    let prologue = prologue(network, admission, ciphertext);
    let mut noise = builder
        .prologue(&prologue)?
        .psk(0, shared)?
        .local_private_key(local_secret)?
        .remote_public_key(recipient_inbox)?
        .build_initiator()?;
    let mut out = vec![0u8; SEALED_NOTE_LEN];
    out[..ADMISSION_LEN].copy_from_slice(admission);
    out[ADMISSION_LEN..ENVELOPE_AT].copy_from_slice(ciphertext);
    let len = noise.write_message(payload, &mut out[ENVELOPE_AT..])?;
    debug_assert_eq!(len, ENVELOPE_LEN);
    Ok(SealedNote(out))
}

/// Seal a note from `sender` (whose card is `sender_card`) to the holder of
/// `recipient_card`, bound to `network` and the transaction's admission
/// commitment.
pub fn seal_note(
    network: &Network,
    recipient_card: &ContactCard,
    sender: &ContactIdentity,
    sender_card: &ContactCard,
    route: &[u8; ROUTE_LEN],
    intro: &str,
    admission: &[u8; ADMISSION_LEN],
) -> Result<SealedNote, NoteError> {
    let intro = intro.as_bytes();
    if intro.len() > INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro.len() });
    }
    if &recipient_card.network != network {
        return Err(NoteError::BadCard(ContactError::WrongNetwork));
    }
    if !is_contributory_key(&recipient_card.inbox_key) {
        return Err(NoteError::WeakKey);
    }
    if sender_card.signing_key != sender.signing_key()
        || sender_card.handshake_key != sender.handshake_key().public()
        || &sender_card.network != network
    {
        return Err(NoteError::BadCard(ContactError::WrongIssuer));
    }
    let (ciphertext, shared) = pq_encapsulate(&recipient_card.pq_inbox_key).map_err(NoteError::BadCard)?;
    envelope(
        builder(),
        network,
        admission,
        &ciphertext,
        &shared,
        sender.handshake_key().secret(),
        &recipient_card.inbox_key,
        &payload(&sender_card.summary(), route, intro),
    )
}

/// A dummy for an unused stranger-note slot (spec W4, audit MED-03): a real
/// v5 note, sealed through [`seal_note`] from one fresh throwaway contact
/// identity to another, with a random admission commitment, a random route
/// and an empty intro. Every secret is dropped on return, so nobody, its
/// maker included, can open it.
///
/// Why not random bytes: the note's first Noise field is an X25519
/// ephemeral public key, whose top bit is always 0 and which always lies on
/// Curve25519 rather than its twist, and whose ML-KEM ciphertext has its own
/// structure. Uniform random bytes fail those tests about half the time per
/// note, so a slot of random bytes would mark itself as a dummy. A note made
/// the real way is, as far as we know, computationally indistinguishable
/// from a real one (unreviewed). `now_secs` dates the throwaway cards.
pub fn dummy_note(network: &[u8; 32], now_secs: u64) -> [u8; SEALED_NOTE_LEN] {
    let recipient = ContactIdentity::generate_at(now_secs);
    let sender = ContactIdentity::generate_at(now_secs);
    let mut route = [0u8; ROUTE_LEN];
    OsRng.fill_bytes(&mut route);
    let note = seal_note(
        network,
        &recipient.card(*network, 0),
        &sender,
        &sender.card(*network, 0),
        &route,
        "",
        &random_bytes(),
    )
    .expect("a fresh card on its own network always seals");
    note.0.try_into().expect("seal_note returns SEALED_NOTE_LEN bytes")
}

/// Try to open a note on `network` with `me`'s inbox keys (X25519 and
/// ML-KEM): the active epoch's first, then the draining epoch's if
/// `now_secs` (the opener's clock) is before its `not_after` plus
/// [`crate::contact::DRAIN_GRACE`]. `created_at` is the wall-clock time
/// (seconds) at which the request carrying the note was created on chain,
/// taken from chain state: the sender's card must have been valid then (it
/// may have expired since). Needs nothing else: no sender address, no hint.
/// A note for someone else (or for an epoch already dropped), another
/// network, another admission commitment, another note format or with a
/// tampered ciphertext fails with [`NoteError::Noise`]. A note that
/// decrypts under the active keys but fails a later check is not retried
/// with the draining keys.
pub fn open_note(
    me: &ContactIdentity,
    network: &Network,
    note: &SealedNote,
    created_at: u64,
    now_secs: u64,
) -> Result<ContactNote, NoteError> {
    if note.0.len() != SEALED_NOTE_LEN {
        return Err(NoteError::BadSize { len: note.0.len() });
    }
    match open_with(me.active(), network, note, created_at) {
        Err(NoteError::Noise(error)) => match me.draining_at(now_secs) {
            Some(previous) => open_with(previous, network, note, created_at),
            None => Err(NoteError::Noise(error)),
        },
        result => result,
    }
}

/// Open a note of the right length with one epoch's inbox keys.
fn open_with(
    me: &KeyEpoch,
    network: &Network,
    note: &SealedNote,
    created_at: u64,
) -> Result<ContactNote, NoteError> {
    let admission: [u8; ADMISSION_LEN] = note.0[..ADMISSION_LEN].try_into().expect("32 bytes");
    let ciphertext: [u8; PQ_CIPHERTEXT_LEN] = note.0[ADMISSION_LEN..ENVELOPE_AT].try_into().expect("1088 bytes");
    // ML-KEM's implicit rejection: a ciphertext not made for our key gives
    // an unrelated secret, so the Noise message below fails to decrypt.
    let shared = me.pq_decapsulate(&ciphertext);
    let prologue = prologue(network, &admission, &ciphertext);
    let mut noise = builder()
        .prologue(&prologue)?
        .psk(0, &shared)?
        .local_private_key(me.inbox_key().secret())?
        .build_responder()?;
    let mut body = vec![0u8; PAYLOAD_LEN];
    let len = noise.read_message(&note.0[ENVELOPE_AT..], &mut body)?;
    // Before trusting anything: the sender's static key must be one whose
    // key agreement depended on our secret.
    let sender_static: [u8; 32] =
        noise.get_remote_static().and_then(|k| k.try_into().ok()).ok_or(NoteError::Malformed)?;
    if !is_contributory_key(&sender_static) {
        return Err(NoteError::WeakKey);
    }
    if len != PAYLOAD_LEN || body[0] != VERSION {
        return Err(NoteError::Malformed);
    }
    let card = CardSummary {
        network: *network,
        signing_key: body[1..33].try_into().expect("32 bytes"),
        handshake_key: sender_static,
        inbox_key: body[33..65].try_into().expect("32 bytes"),
        pq_inbox_hash: body[65..97].try_into().expect("32 bytes"),
        price: u128::from_be_bytes(body[97..113].try_into().expect("16 bytes")),
        not_before: u64::from_be_bytes(body[113..121].try_into().expect("8 bytes")),
        not_after: u64::from_be_bytes(body[121..129].try_into().expect("8 bytes")),
        signature: body[129..193].try_into().expect("64 bytes"),
    };
    card.verify(network, created_at).map_err(NoteError::BadCard)?;
    let intro_len = u16::from_be_bytes([body[LEN_AT], body[LEN_AT + 1]]) as usize;
    if intro_len > INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro_len });
    }
    let (intro, padding) = body[LEN_AT + 2..].split_at(intro_len);
    if padding.iter().any(|b| *b != 0) {
        return Err(NoteError::Malformed);
    }
    Ok(ContactNote {
        admission,
        card,
        route: body[ROUTE_AT..LEN_AT].try_into().expect("96 bytes"),
        intro: String::from_utf8(intro.to_vec()).map_err(|_| NoteError::Malformed)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::{StaticKey, PQ_KEY_LEN};

    const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
    const ADMISSION: [u8; 32] = [0xAD; 32];
    const NET: Network = [9; 32];
    const NOW: u64 = 50;

    fn card_of(id: &ContactIdentity) -> ContactCard {
        id.card_within(NET, 1, 0, 100)
    }

    fn seal(to: &ContactIdentity, from: &ContactIdentity, intro: &str) -> SealedNote {
        seal_note(&NET, &card_of(to), from, &card_of(from), &ROUTE, intro, &ADMISSION).unwrap()
    }

    /// Seal a note whose sender static is `claimed` (a public key) using a
    /// test-only resolver: for the key marked `MARK`, the static
    /// Diffie-Hellman is computed with the *recipient's* inbox secret
    /// against `claimed`, which gives the same result as the sender's
    /// would (X25519 is symmetric). This is exactly the forgery a holder of
    /// the inbox secret can make, through snow's public resolver traits.
    pub(super) mod forge {
        use snow::params::{CipherChoice, DHChoice, HashChoice};
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        use snow::types::{Cipher, Dh, Hash, Random};

        pub(crate) const MARK: [u8; 32] = [0xF0; 32];

        pub(crate) struct Resolver {
            pub(crate) claimed: [u8; 32],
            pub(crate) inbox_secret: [u8; 32],
        }

        struct ForgingDh {
            inner: Box<dyn Dh>,
            claimed: [u8; 32],
            inbox_secret: [u8; 32],
            forging: bool,
        }

        impl Dh for ForgingDh {
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
                self.forging = privkey == MARK;
                if self.forging {
                    self.inner.set(&self.inbox_secret);
                } else {
                    self.inner.set(privkey);
                }
            }
            fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
                self.forging = false;
                self.inner.generate(rng)
            }
            fn pubkey(&self) -> &[u8] {
                if self.forging { &self.claimed } else { self.inner.pubkey() }
            }
            fn privkey(&self) -> &[u8] {
                self.inner.privkey()
            }
            fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
                if self.forging {
                    // DH(inbox secret, claimed sender key) = DH(sender secret, inbox key).
                    self.inner.dh(&self.claimed, out)
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
                Some(Box::new(ForgingDh { inner, claimed: self.claimed, inbox_secret: self.inbox_secret, forging: false }))
            }
            fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
                DefaultResolver.resolve_hash(choice)
            }
            fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
                DefaultResolver.resolve_cipher(choice)
            }
        }
    }

    /// A note that opens at the holder of `inbox` (whose public post-quantum
    /// key is `pq_key`) as if from the holder of `card`, made with only the
    /// X25519 inbox secret and public keys: encapsulating to `pq_key` needs
    /// no secret.
    pub(crate) fn forged_note(
        inbox: &StaticKey,
        pq_key: &[u8; PQ_KEY_LEN],
        card: &ContactCard,
        route: &[u8; ROUTE_LEN],
        intro: &str,
    ) -> SealedNote {
        let resolver = forge::Resolver { claimed: card.handshake_key, inbox_secret: inbox.to_bytes() };
        let (ciphertext, shared) = pq_encapsulate(pq_key).unwrap();
        envelope(
            Builder::with_resolver(PATTERN.parse().unwrap(), Box::new(resolver)),
            &card.network,
            &ADMISSION,
            &ciphertext,
            &shared,
            &forge::MARK,
            &inbox.public(),
            &payload(&card.summary(), route, intro.as_bytes()),
        )
        .unwrap()
    }

    /// A v5 note from Carol to Bob with an arbitrary payload, ciphertext
    /// and pre-shared key.
    fn reseal_with(
        bob: &ContactIdentity,
        carol: &ContactIdentity,
        ciphertext: &[u8; PQ_CIPHERTEXT_LEN],
        shared: &[u8; 32],
        body: &[u8],
    ) -> SealedNote {
        envelope(
            builder(),
            &NET,
            &ADMISSION,
            ciphertext,
            shared,
            carol.handshake_key().secret(),
            &bob.inbox_key().public(),
            body,
        )
        .unwrap()
    }

    fn reseal(bob: &ContactIdentity, carol: &ContactIdentity, body: &[u8]) -> SealedNote {
        let (ciphertext, shared) = pq_encapsulate(&bob.pq_inbox_key()).unwrap();
        reseal_with(bob, carol, &ciphertext, &shared, body)
    }

    #[test]
    fn the_recipient_can_forge_a_v5_note_from_any_sender_so_a_note_proves_nothing_to_others() {
        // Deniability: Bob, with only his own inbox secrets (X25519 and
        // ML-KEM) and Carol's public card, makes a note that opens exactly
        // as one from Carol.
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let forged = forged_note(bob.inbox_key(), &bob.pq_inbox_key(), &card_of(&carol), &ROUTE, "I never sent this");
        assert_eq!(forged.0.len(), SEALED_NOTE_LEN);
        let opened = open_note(&bob, &NET, &forged, NOW, NOW).unwrap();
        assert_eq!(opened.sender(), carol.signing_key());
        assert_eq!(opened.callback(), carol.handshake_key().public());
        assert_eq!(opened.card, card_of(&carol).summary());
        // An honest note from Carol opens the same way: Bob cannot show a
        // third party which of the two he received.
        let honest = seal(&bob, &carol, "hi");
        let opened_honest = open_note(&bob, &NET, &honest, NOW, NOW).unwrap();
        assert_eq!(opened.card, opened_honest.card);
        assert_eq!(forged.0.len(), honest.0.len());
    }

    #[test]
    fn the_cost_anyone_with_the_x25519_inbox_secret_can_forge_notes_to_that_inbox() {
        // Mallory stole only Bob's X25519 inbox secret (not his ML-KEM
        // secret, not Carol's keys). Bob's post-quantum key is public, so
        // she can still make a note that opens at Bob as one from Carol.
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let stolen = StaticKey::from_bytes(bob.inbox_key().to_bytes());
        let malloys_route = [0x66; ROUTE_LEN];
        let forged = forged_note(&stolen, &card_of(&bob).pq_inbox_key, &card_of(&carol), &malloys_route, "call me here");
        let opened = open_note(&bob, &NET, &forged, NOW, NOW).unwrap();
        assert_eq!(opened.sender(), carol.signing_key(), "it opens as Carol's");
        assert_eq!(opened.route, malloys_route);
        // What limits it: the callback goes to Carol's handshake key, which
        // Mallory does not hold (see tests/contact.rs, the callback test).
        assert_eq!(opened.callback(), carol.handshake_key().public());
        // The forgery only works against the stolen inbox: Dave rejects it.
        let dave = ContactIdentity::generate_at(NOW);
        assert!(matches!(open_note(&dave, &NET, &forged, NOW, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn a_forger_with_the_inbox_secret_cannot_complete_the_callback() {
        use crate::gate::Now;
        use crate::wire::{Initiator, Responder, ResponderEvent, RetryPolicy, WireError};
        use std::time::Instant;

        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let bob_card = bob.card_within(NET, 1, 0, 100);
        // Mallory holds Bob's inbox secret and forges a note "from Carol"
        // pointing at her own route.
        let stolen = StaticKey::from_bytes(bob.inbox_key().to_bytes());
        let forged = forged_note(&stolen, &bob_card.pq_inbox_key, &card_of(&carol), &[0x66; ROUTE_LEN], "call me");
        let opened = open_note(&bob, &NET, &forged, NOW, NOW).unwrap();
        // Bob calls back the handshake key the note authenticated.
        let (_, hello) =
            Initiator::start_with(bob.handshake_key(), opened.callback(), NET, opened.admission, RetryPolicy::default())
                .unwrap();
        let now = Now { unix: NOW, mono: Instant::now() };
        let deadline = now.unix + 60;
        // Mallory answers with any key she holds, here her own: nothing can
        // be read, so nothing is sent and no session forms.
        let mallory = StaticKey::generate();
        let mut hers: Responder<u32> =
            Responder::for_callback(&mallory, NET, bob_card.handshake_key, opened.admission, deadline).unwrap();
        assert!(matches!(hers.handle(1, &hello, now), Err(WireError::Session(_))));
        // Even with Bob's inbox secret as her static key she cannot read it.
        let mut with_inbox: Responder<u32> =
            Responder::for_callback(&stolen, NET, bob_card.handshake_key, opened.admission, deadline).unwrap();
        assert!(matches!(with_inbox.handle(1, &hello, now), Err(WireError::Session(_))));
        // Only the holder of Carol's handshake key can answer.
        let mut carols: Responder<u32> =
            Responder::for_callback(carol.handshake_key(), NET, bob_card.handshake_key, opened.admission, deadline)
                .unwrap();
        assert!(matches!(carols.handle(1, &hello, now), Ok(ResponderEvent::Reply(_))));
    }

    #[test]
    fn a_note_from_a_small_order_sender_key_is_refused() {
        // Built with the forging resolver: the claimed sender key is a
        // small-order point, so the static agreement is all zeros on both
        // sides and snow accepts it; our check refuses it.
        let bob = ContactIdentity::generate_at(NOW);
        let carol = ContactIdentity::generate_at(NOW);
        for weak in crate::contact::tests::SMALL_ORDER {
            let mut card = card_of(&carol);
            card.handshake_key = weak;
            let forged = forged_note(bob.inbox_key(), &bob.pq_inbox_key(), &card, &ROUTE, "x");
            assert!(matches!(open_note(&bob, &NET, &forged, NOW, NOW), Err(NoteError::WeakKey)), "{weak:02x?}");
        }
    }

    #[test]
    fn a_tampered_ml_kem_ciphertext_is_refused() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let note = seal(&bob, &carol, "hi");
        assert!(open_note(&bob, &NET, &note, NOW, NOW).is_ok(), "control");
        for at in [ADMISSION_LEN, ADMISSION_LEN + 500, ENVELOPE_AT - 1] {
            let mut bad = note.0.clone();
            bad[at] ^= 1;
            assert!(matches!(open_note(&bob, &NET, &SealedNote(bad), NOW, NOW), Err(NoteError::Noise(_))), "byte {at}");
        }
        // A whole fresh ciphertext to Bob's own key, swapped in: refused too.
        let (other, _) = pq_encapsulate(&bob.pq_inbox_key()).unwrap();
        let mut swapped = note.0.clone();
        swapped[ADMISSION_LEN..ENVELOPE_AT].copy_from_slice(&other);
        assert!(matches!(open_note(&bob, &NET, &SealedNote(swapped), NOW, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn the_ml_kem_secret_is_the_noise_pre_shared_key() {
        // Ciphertext and prologue as normal, but the Noise message keyed by
        // a different encapsulation's secret: it does not open. So the
        // shared secret is used, not only the ciphertext's bytes.
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let body = payload(&card_of(&carol).summary(), &ROUTE, b"hi");
        let (ciphertext, shared) = pq_encapsulate(&bob.pq_inbox_key()).unwrap();
        let (_, other_shared) = pq_encapsulate(&bob.pq_inbox_key()).unwrap();
        assert!(open_note(&bob, &NET, &reseal_with(&bob, &carol, &ciphertext, &shared, &body), NOW, NOW).is_ok(), "control");
        assert!(matches!(
            open_note(&bob, &NET, &reseal_with(&bob, &carol, &ciphertext, &other_shared, &body), NOW, NOW),
            Err(NoteError::Noise(_))
        ));
        // Without Bob's ML-KEM secret the X25519 inbox secret is not enough
        // to read a note: someone holding the same X25519 key but another
        // ML-KEM key cannot open it.
        let signing = bob.signing_secret_bytes();
        let (handshake, inbox, _, not_before, not_after) = bob.active().to_secret_bytes();
        let other_pq = KeyEpoch::from_secret_bytes(handshake, inbox, [0x42; 64], not_before, not_after).unwrap();
        let half_bob = ContactIdentity::from_parts(*signing, other_pq, None);
        assert!(matches!(open_note(&half_bob, &NET, &seal(&bob, &carol, "hi"), NOW, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn a_card_with_the_wrong_pq_inbox_hash_is_refused() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let honest = card_of(&carol).summary();
        assert!(open_note(&bob, &NET, &reseal(&bob, &carol, &payload(&honest, &ROUTE, b"hi")), NOW, NOW).is_ok(), "control");
        // One bit off, or another identity's key hash: the card signature
        // (which covers the hash) does not verify.
        let other = crate::contact::pq_key_hash(&ContactIdentity::generate_at(NOW).pq_inbox_key());
        for hash in [{ let mut h = honest.pq_inbox_hash; h[0] ^= 1; h }, other] {
            let summary = CardSummary { pq_inbox_hash: hash, ..honest };
            assert!(matches!(
                open_note(&bob, &NET, &reseal(&bob, &carol, &payload(&summary, &ROUTE, b"hi")), NOW, NOW),
                Err(NoteError::BadCard(ContactError::BadSignature))
            ));
        }
    }

    /// The previous format (v4: Noise X without the post-quantum layer, 667
    /// bytes), kept here only to show the formats cannot be confused.
    mod v4 {
        use super::*;

        pub(super) const LEN: usize = 667;
        const PAYLOAD: usize = 539;

        pub(super) fn seal(network: &Network, inbox: &[u8; 32], sender: &ContactIdentity) -> SealedNote {
            let prologue = [b"anonymum/contact-note/v4".as_slice(), network, &ADMISSION].concat();
            let mut noise = Builder::new("Noise_X_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .prologue(&prologue)
                .unwrap()
                .local_private_key(sender.handshake_key().secret())
                .unwrap()
                .remote_public_key(inbox)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut plaintext = vec![0u8; PAYLOAD];
            plaintext[0] = 4;
            let mut out = vec![0u8; LEN];
            out[..32].copy_from_slice(&ADMISSION);
            noise.write_message(&plaintext, &mut out[32..]).unwrap();
            SealedNote(out)
        }

        /// Read `envelope` as a v4 opener would (any length).
        pub(super) fn opens(me: &ContactIdentity, network: &Network, admission: &[u8], envelope: &[u8]) -> bool {
            let prologue = [b"anonymum/contact-note/v4".as_slice(), network, admission].concat();
            let mut noise = Builder::new("Noise_X_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .prologue(&prologue)
                .unwrap()
                .local_private_key(me.inbox_key().secret())
                .unwrap()
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; envelope.len()];
            noise.read_message(envelope, &mut buf).is_ok()
        }
    }

    #[test]
    fn v4_and_v5_notes_cannot_be_confused() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let old = v4::seal(&NET, &bob.inbox_key().public(), &carol);
        assert!(v4::opens(&bob, &NET, &old.0[..32], &old.0[32..]), "control: the v4 note is valid as v4");
        assert!(matches!(open_note(&bob, &NET, &old, NOW, NOW), Err(NoteError::BadSize { len: 667 })));
        // Padded to v5's length, either way round, it still does not open.
        let mut padded = old.0.clone();
        padded.resize(SEALED_NOTE_LEN, 0);
        assert!(matches!(open_note(&bob, &NET, &SealedNote(padded), NOW, NOW), Err(NoteError::Noise(_))));
        let mut placed = vec![0u8; SEALED_NOTE_LEN];
        placed[..32].copy_from_slice(&ADMISSION);
        placed[ENVELOPE_AT..ENVELOPE_AT + v4::LEN - 32].copy_from_slice(&old.0[32..]);
        assert!(matches!(open_note(&bob, &NET, &SealedNote(placed), NOW, NOW), Err(NoteError::Noise(_))));
        // And a v5 note's Noise message is not a v4 note.
        let new = seal(&bob, &carol, "hi");
        assert!(!v4::opens(&bob, &NET, &new.0[..32], &new.0[ENVELOPE_AT..]));
    }

    #[test]
    fn padding_version_and_card_are_checked() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let card = card_of(&carol).summary();
        let mut bad_version = payload(&card, &ROUTE, b"hi");
        bad_version[0] = 4;
        assert!(matches!(open_note(&bob, &NET, &reseal(&bob, &carol, &bad_version), NOW, NOW), Err(NoteError::Malformed)));
        let mut bad_padding = payload(&card, &ROUTE, b"hi");
        bad_padding[PAYLOAD_LEN - 1] = 1;
        assert!(matches!(open_note(&bob, &NET, &reseal(&bob, &carol, &bad_padding), NOW, NOW), Err(NoteError::Malformed)));
        // Someone else's card fields under Carol's handshake key: the card
        // signature (which covers the handshake key) does not verify.
        let wrong_card = payload(&card_of(&ContactIdentity::generate_at(NOW)).summary(), &ROUTE, b"hi");
        assert!(matches!(open_note(&bob, &NET, &reseal(&bob, &carol, &wrong_card), NOW, NOW), Err(NoteError::BadCard(_))));
        // A card that had expired when the request was created.
        assert!(matches!(
            open_note(&bob, &NET, &reseal(&bob, &carol, &payload(&card, &ROUTE, b"hi")), 100, 100),
            Err(NoteError::BadCard(ContactError::Expired))
        ));
    }

    #[test]
    fn a_note_for_network_a_does_not_open_on_network_b() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let note = seal(&bob, &carol, "hi");
        assert_eq!(note.0.len(), SEALED_NOTE_LEN);
        assert!(open_note(&bob, &NET, &note, NOW, NOW).is_ok());
        assert!(matches!(open_note(&bob, &[0xB; 32], &note, NOW, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn sealing_refuses_a_weak_inbox_a_bad_pq_key_or_a_card_that_is_not_the_senders() {
        let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
        let try_to = |recipient: &ContactCard, sender_card: &ContactCard| {
            seal_note(&NET, recipient, &carol, sender_card, &ROUTE, "", &ADMISSION)
        };
        for weak in crate::contact::tests::SMALL_ORDER {
            let recipient = ContactCard { inbox_key: weak, ..card_of(&bob) };
            assert!(matches!(try_to(&recipient, &card_of(&carol)), Err(NoteError::WeakKey)));
        }
        // Coefficients of 0xFFF are not below the ML-KEM modulus (FIPS 203
        // input check).
        let recipient = ContactCard { pq_inbox_key: [0xFF; PQ_KEY_LEN], ..card_of(&bob) };
        assert!(matches!(try_to(&recipient, &card_of(&carol)), Err(NoteError::BadCard(ContactError::BadPqKey))));
        let elsewhere = bob.card_within([1; 32], 1, 0, 100);
        assert!(matches!(try_to(&elsewhere, &card_of(&carol)), Err(NoteError::BadCard(ContactError::WrongNetwork))));
        let other_card = card_of(&ContactIdentity::generate_at(NOW));
        assert!(matches!(try_to(&card_of(&bob), &other_card), Err(NoteError::BadCard(ContactError::WrongIssuer))));
    }
}
