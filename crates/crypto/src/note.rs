//! A stranger's sealed note (spec v0.7 section 2a, rule 4; reverse
//! rendezvous), format v4: deniable sender authentication (issue I27).
//!
//! A stranger who pays to reach someone cannot know their mixnet route: it
//! is never published. The stranger seals a note to the recipient's
//! **inbox key** (from the recipient's contact card). The recipient opens it
//! with that key alone: no sender address or other hint is needed, so a
//! fresh wallet finds its notes by trying each one.
//!
//! **Who sent it, deniably.** The note is one Noise X message
//! (`Noise_X_25519_ChaChaPoly_BLAKE2s`, via `snow`'s public API) whose
//! sender static key is the sender's contact *handshake key*. Noise X
//! authenticates that key to the recipient by Diffie-Hellman, not by a
//! signature: the recipient is convinced, but could have computed the same
//! message from their own inbox secret and the sender's public key, so the
//! note proves nothing to anyone else. The ciphertext also carries the rest
//! of the sender's signed contact card, so the recipient learns which
//! contact identity the handshake key belongs to. The card's signature
//! covers only the card (keys, price, validity, network), never the act of
//! contacting anyone, and cards are handed out publicly anyway.
//!
//! **The cost (recorded for the cryptographer).** Anyone who holds the
//! recipient's inbox secret can make a note that opens as if from any
//! sender whose card they have. The callback limits the damage: the
//! recipient calls the sender's handshake key itself (the key Noise X
//! authenticated), so only its holder can answer; a forger with the inbox
//! secret cannot complete the callback. Forward secrecy for notes is still
//! open: if the inbox key leaks, every recorded note to it can be read.
//!
//! # Field layout (fixed, [`SEALED_NOTE_LEN`] = 667 bytes)
//!
//! ```text
//! admission commitment                  32
//! Noise X message                      635
//!   e (ephemeral public key)            32
//!   s (sender handshake key) + tag      48
//!   payload (539) + tag                555
//! ```
//!
//! The payload, all inside the ciphertext:
//!
//! ```text
//! offset  len  field
//!      0    1  version (4)
//!      1   32  sender's contact signing key     (card)
//!     33   32  sender's inbox key               (card)
//!     65   16  price, u128 big-endian           (card)
//!     81    8  card not_before, u64 big-endian  (card)
//!     89    8  card not_after, u64 big-endian   (card)
//!     97   64  card signature                   (card)
//!    161   96  throwaway route (a Nym Recipient)
//!    257    2  intro length, u16 big-endian
//!    259  280  intro, UTF-8, zero-padded
//! ```
//!
//! The card's handshake key is the authenticated Noise static and its
//! network is the one in the prologue, so neither is repeated. The Noise
//! prologue is `"anonymum/contact-note/v4" || network || admission`, so the
//! note opens only on its network and next to the admission commitment it
//! names. In the shielded design that commitment is a separate public field
//! of the transaction (spec section 3); the transparent prototype chain has
//! none, so here the note field carries it.
//!
//! Nothing here is hand-made cryptography. Stated plainly: unreviewed
//! (spec questions 11 and 12).

use std::fmt;

use anonymum_core::crypto::SealedNote;
use snow::Builder;

use crate::contact::{is_contributory_key, ContactCard, ContactIdentity, Network};

const PATTERN: &str = "Noise_X_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/contact-note/v4";
const VERSION: u8 = 4;

/// Bytes reserved for the throwaway route (sized for a Nym `Recipient`).
pub const ROUTE_LEN: usize = 96;
/// Longest intro, in bytes of UTF-8. Proposed cap; open question.
pub const INTRO_MAX_BYTES: usize = 280;
pub const ADMISSION_LEN: usize = 32;
/// The card fields the note carries: signing key, inbox key, price,
/// validity and signature.
const CARD_LEN: usize = 32 + 32 + 16 + 8 + 8 + 64;
const ROUTE_AT: usize = 1 + CARD_LEN;
const LEN_AT: usize = ROUTE_AT + ROUTE_LEN;
const PAYLOAD_LEN: usize = LEN_AT + 2 + INTRO_MAX_BYTES;
/// Noise X: e (32), encrypted s (32 + 16), encrypted payload (+ 16).
const ENVELOPE_LEN: usize = 32 + 48 + PAYLOAD_LEN + 16;
/// The whole note field.
pub const SEALED_NOTE_LEN: usize = ADMISSION_LEN + ENVELOPE_LEN;
const _: () = assert!(SEALED_NOTE_LEN == anonymum_core::SEALED_NOTE_LEN, "the chain checks this length");
const _: () = assert!(SEALED_NOTE_LEN == 667);

/// What the recipient reads after opening a note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactNote {
    /// The admission commitment the note is bound to.
    pub admission: [u8; ADMISSION_LEN],
    /// The sender's contact card, rebuilt and verified. Its handshake key is
    /// the key Noise X authenticated; the recipient calls back to it.
    pub card: ContactCard,
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
    /// Not for this inbox key, for another network or admission commitment,
    /// another note format, or tampered.
    Noise(snow::Error),
    /// The sender's card does not verify (signature, network, keys, price,
    /// validity), or does not belong to the sending identity.
    BadCard(crate::contact::ContactError),
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

fn prologue(network: &Network, admission: &[u8; ADMISSION_LEN]) -> Vec<u8> {
    [PROLOGUE, network.as_slice(), admission.as_slice()].concat()
}

fn builder() -> Builder<'static> {
    Builder::new(PATTERN.parse().expect("pattern is a valid constant"))
}

/// The payload for a note from the holder of `card`.
fn payload(card: &ContactCard, route: &[u8; ROUTE_LEN], intro: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_LEN];
    out[0] = VERSION;
    out[1..33].copy_from_slice(&card.signing_key);
    out[33..65].copy_from_slice(&card.inbox_key);
    out[65..81].copy_from_slice(&card.price.to_be_bytes());
    out[81..89].copy_from_slice(&card.not_before.to_be_bytes());
    out[89..97].copy_from_slice(&card.not_after.to_be_bytes());
    out[97..161].copy_from_slice(&card.signature);
    out[ROUTE_AT..LEN_AT].copy_from_slice(route);
    out[LEN_AT..LEN_AT + 2].copy_from_slice(&(intro.len() as u16).to_be_bytes());
    out[LEN_AT + 2..LEN_AT + 2 + intro.len()].copy_from_slice(intro);
    out
}

/// Seal a note from `sender` (whose card is `sender_card`) to the holder of
/// `recipient_inbox`, bound to `network` and the transaction's admission
/// commitment.
pub fn seal_note(
    network: &Network,
    recipient_inbox: &[u8; 32],
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
    if !is_contributory_key(recipient_inbox) {
        return Err(NoteError::WeakKey);
    }
    if sender_card.signing_key != sender.signing_key()
        || sender_card.handshake_key != sender.handshake_key().public()
        || &sender_card.network != network
    {
        return Err(NoteError::BadCard(crate::contact::ContactError::WrongIssuer));
    }
    let prologue = prologue(network, admission);
    let mut noise = builder()
        .prologue(&prologue)?
        .local_private_key(sender.handshake_key().secret())?
        .remote_public_key(recipient_inbox)?
        .build_initiator()?;
    let mut out = vec![0u8; SEALED_NOTE_LEN];
    out[..ADMISSION_LEN].copy_from_slice(admission);
    let len = noise.write_message(&payload(sender_card, route, intro), &mut out[ADMISSION_LEN..])?;
    debug_assert_eq!(len, ENVELOPE_LEN);
    Ok(SealedNote(out))
}

/// Try to open a note on `network` with `me`'s inbox key. `created_at` is
/// the wall-clock time (seconds) at which the request carrying the note was
/// created on chain, taken from chain state: the sender's card must have
/// been valid then (it may have expired since). Needs nothing else: no
/// sender address, no hint. A note for someone else, another network,
/// another admission commitment or another note format fails with
/// [`NoteError::Noise`].
pub fn open_note(
    me: &ContactIdentity,
    network: &Network,
    note: &SealedNote,
    created_at: u64,
) -> Result<ContactNote, NoteError> {
    if note.0.len() != SEALED_NOTE_LEN {
        return Err(NoteError::BadSize { len: note.0.len() });
    }
    let (admission, envelope) = note.0.split_at(ADMISSION_LEN);
    let admission: [u8; ADMISSION_LEN] = admission.try_into().expect("split at 32");
    let prologue = prologue(network, &admission);
    let mut noise =
        builder().prologue(&prologue)?.local_private_key(me.inbox_key().secret())?.build_responder()?;
    let mut body = vec![0u8; PAYLOAD_LEN];
    let len = noise.read_message(envelope, &mut body)?;
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
    let card = ContactCard {
        network: *network,
        signing_key: body[1..33].try_into().expect("32 bytes"),
        handshake_key: sender_static,
        inbox_key: body[33..65].try_into().expect("32 bytes"),
        price: u128::from_be_bytes(body[65..81].try_into().expect("16 bytes")),
        not_before: u64::from_be_bytes(body[81..89].try_into().expect("8 bytes")),
        not_after: u64::from_be_bytes(body[89..97].try_into().expect("8 bytes")),
        signature: body[97..161].try_into().expect("64 bytes"),
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
    use crate::contact::StaticKey;

    const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
    const ADMISSION: [u8; 32] = [0xAD; 32];
    const NET: Network = [9; 32];
    const NOW: u64 = 50;

    fn card_of(id: &ContactIdentity) -> ContactCard {
        id.card(NET, 1, 0, 100)
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

    /// A note that opens at the holder of `inbox` as if from the holder of
    /// `card`, made with only the inbox secret and the card (public).
    pub(crate) fn forged_note(inbox: &StaticKey, card: &ContactCard, route: &[u8; ROUTE_LEN], intro: &str) -> SealedNote {
        let resolver = forge::Resolver { claimed: card.handshake_key, inbox_secret: inbox.to_bytes() };
        let mut noise = Builder::with_resolver(PATTERN.parse().unwrap(), Box::new(resolver))
            .prologue(&prologue(&card.network, &ADMISSION))
            .unwrap()
            .local_private_key(&forge::MARK)
            .unwrap()
            .remote_public_key(&inbox.public())
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut out = vec![0u8; SEALED_NOTE_LEN];
        out[..ADMISSION_LEN].copy_from_slice(&ADMISSION);
        noise.write_message(&payload(card, route, intro.as_bytes()), &mut out[ADMISSION_LEN..]).unwrap();
        SealedNote(out)
    }

    #[test]
    fn the_recipient_can_forge_a_note_from_any_sender_so_a_note_proves_nothing_to_others() {
        // Deniability: Bob, with only his own inbox secret and Carol's
        // public card, makes a note that opens exactly as one from Carol.
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let forged = forged_note(bob.inbox_key(), &card_of(&carol), &ROUTE, "I never sent this");
        let opened = open_note(&bob, &NET, &forged, NOW).unwrap();
        assert_eq!(opened.sender(), carol.signing_key());
        assert_eq!(opened.callback(), carol.handshake_key().public());
        // An honest note from Carol opens the same way: Bob cannot show a
        // third party which of the two he received.
        let honest =
            seal_note(&NET, &bob.inbox_key().public(), &carol, &card_of(&carol), &ROUTE, "hi", &ADMISSION).unwrap();
        let opened_honest = open_note(&bob, &NET, &honest, NOW).unwrap();
        assert_eq!((opened.sender(), opened.callback()), (opened_honest.sender(), opened_honest.callback()));
    }

    #[test]
    fn the_cost_anyone_with_the_inbox_secret_can_forge_notes_to_that_inbox() {
        // Mallory stole Bob's inbox secret (not Carol's keys). She can make a
        // note that opens at Bob as one from Carol, with her own route.
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let stolen = StaticKey::from_bytes(bob.inbox_key().to_bytes());
        let malloys_route = [0x66; ROUTE_LEN];
        let forged = forged_note(&stolen, &card_of(&carol), &malloys_route, "call me here");
        let opened = open_note(&bob, &NET, &forged, NOW).unwrap();
        assert_eq!(opened.sender(), carol.signing_key(), "it opens as Carol's");
        assert_eq!(opened.route, malloys_route);
        // What limits it: the callback goes to Carol's handshake key, which
        // Mallory does not hold (see tests/contact.rs, the callback test).
        assert_eq!(opened.callback(), carol.handshake_key().public());
        // The forgery only works against the stolen inbox: Dave rejects it.
        let dave = ContactIdentity::generate();
        assert!(matches!(open_note(&dave, &NET, &forged, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn a_forger_with_the_inbox_secret_cannot_complete_the_callback() {
        use crate::gate::Now;
        use crate::wire::{Initiator, Responder, ResponderEvent, RetryPolicy, WireError};
        use std::time::{Duration, Instant};

        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let bob_card = bob.card(NET, 1, 0, 100);
        // Mallory holds Bob's inbox secret and forges a note "from Carol"
        // pointing at her own route.
        let stolen = StaticKey::from_bytes(bob.inbox_key().to_bytes());
        let forged = forged_note(&stolen, &card_of(&carol), &[0x66; ROUTE_LEN], "call me");
        let opened = open_note(&bob, &NET, &forged, NOW).unwrap();
        // Bob calls back the handshake key the note authenticated.
        let (_, hello) =
            Initiator::start_with(bob.handshake_key(), opened.callback(), NET, opened.admission, RetryPolicy::default())
                .unwrap();
        let now = Now { unix: NOW, mono: Instant::now() };
        let deadline = now.mono + Duration::from_secs(60);
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
        let bob = ContactIdentity::generate();
        let carol = ContactIdentity::generate();
        for weak in crate::contact::tests::SMALL_ORDER {
            let mut card = card_of(&carol);
            card.handshake_key = weak;
            let forged = forged_note(bob.inbox_key(), &card, &ROUTE, "x");
            assert!(matches!(open_note(&bob, &NET, &forged, NOW), Err(NoteError::WeakKey)), "{weak:02x?}");
        }
    }

    /// The previous format (v3: Noise N plus an Ed25519 signature, 587
    /// bytes), kept here only to show the formats cannot be confused.
    mod v3 {
        use super::*;

        pub(super) const LEN: usize = 587;

        pub(super) fn seal(network: &Network, inbox: &[u8; 32]) -> SealedNote {
            let prologue = [b"anonymum/contact-note/v3".as_slice(), network, &ADMISSION].concat();
            let mut noise = Builder::new("Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .prologue(&prologue)
                .unwrap()
                .remote_public_key(inbox)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut plaintext = vec![0u8; LEN - 32 - 48];
            plaintext[0] = 3;
            let mut out = vec![0u8; LEN];
            out[..32].copy_from_slice(&ADMISSION);
            noise.write_message(&plaintext, &mut out[32..]).unwrap();
            SealedNote(out)
        }

        /// Read the envelope as a v3 opener would.
        pub(super) fn opens(me: &ContactIdentity, network: &Network, note: &SealedNote) -> bool {
            let prologue = [b"anonymum/contact-note/v3".as_slice(), network, &ADMISSION].concat();
            let mut noise = Builder::new("Noise_N_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .prologue(&prologue)
                .unwrap()
                .local_private_key(me.inbox_key().secret())
                .unwrap()
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; note.0.len()];
            note.0.len() == LEN && noise.read_message(&note.0[32..], &mut buf).is_ok()
        }
    }

    #[test]
    fn v3_and_v4_notes_cannot_be_confused() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let old = v3::seal(&NET, &bob.inbox_key().public());
        assert!(v3::opens(&bob, &NET, &old), "control: the v3 note is valid as v3");
        assert!(matches!(open_note(&bob, &NET, &old, NOW), Err(NoteError::BadSize { len: 587 })));
        // Padded to v4's length it still does not open: wrong pattern and label.
        let mut padded = old.0.clone();
        padded.resize(SEALED_NOTE_LEN, 0);
        assert!(matches!(open_note(&bob, &NET, &SealedNote(padded), NOW), Err(NoteError::Noise(_))));
        // And a v4 note is not a v3 one.
        let new =
            seal_note(&NET, &bob.inbox_key().public(), &carol, &card_of(&carol), &ROUTE, "hi", &ADMISSION).unwrap();
        assert!(!v3::opens(&bob, &NET, &new));
        let mut cut = new.0.clone();
        cut.truncate(v3::LEN);
        assert!(!v3::opens(&bob, &NET, &SealedNote(cut)));
    }

    #[test]
    fn padding_version_and_card_are_checked() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let card = card_of(&carol);
        let reseal = |body: Vec<u8>| {
            let mut noise = builder()
                .prologue(&prologue(&NET, &ADMISSION))
                .unwrap()
                .local_private_key(carol.handshake_key().secret())
                .unwrap()
                .remote_public_key(&bob.inbox_key().public())
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut out = vec![0u8; SEALED_NOTE_LEN];
            out[..ADMISSION_LEN].copy_from_slice(&ADMISSION);
            noise.write_message(&body, &mut out[ADMISSION_LEN..]).unwrap();
            SealedNote(out)
        };
        let mut bad_version = payload(&card, &ROUTE, b"hi");
        bad_version[0] = 3;
        assert!(matches!(open_note(&bob, &NET, &reseal(bad_version), NOW), Err(NoteError::Malformed)));
        let mut bad_padding = payload(&card, &ROUTE, b"hi");
        bad_padding[PAYLOAD_LEN - 1] = 1;
        assert!(matches!(open_note(&bob, &NET, &reseal(bad_padding), NOW), Err(NoteError::Malformed)));
        // Someone else's card fields under Carol's handshake key: the card
        // signature (which covers the handshake key) does not verify.
        let mut wrong_card = payload(&card_of(&ContactIdentity::generate()), &ROUTE, b"hi");
        wrong_card[0] = VERSION;
        assert!(matches!(open_note(&bob, &NET, &reseal(wrong_card), NOW), Err(NoteError::BadCard(_))));
        // A card that had expired when the request was created.
        assert!(matches!(
            open_note(&bob, &NET, &reseal(payload(&card, &ROUTE, b"hi")), 100),
            Err(NoteError::BadCard(crate::contact::ContactError::Expired))
        ));
    }

    #[test]
    fn a_note_for_network_a_does_not_open_on_network_b() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let note =
            seal_note(&NET, &bob.inbox_key().public(), &carol, &card_of(&carol), &ROUTE, "hi", &ADMISSION).unwrap();
        assert_eq!(note.0.len(), SEALED_NOTE_LEN);
        assert!(open_note(&bob, &NET, &note, NOW).is_ok());
        assert!(matches!(open_note(&bob, &[0xB; 32], &note, NOW), Err(NoteError::Noise(_))));
    }

    #[test]
    fn sealing_refuses_a_weak_inbox_or_a_card_that_is_not_the_senders() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let inbox = bob.inbox_key().public();
        for weak in crate::contact::tests::SMALL_ORDER {
            assert!(matches!(
                seal_note(&NET, &weak, &carol, &card_of(&carol), &ROUTE, "", &ADMISSION),
                Err(NoteError::WeakKey)
            ));
        }
        let other_card = card_of(&ContactIdentity::generate());
        assert!(matches!(
            seal_note(&NET, &inbox, &carol, &other_card, &ROUTE, "", &ADMISSION),
            Err(NoteError::BadCard(_))
        ));
    }
}
