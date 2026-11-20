//! A stranger's sealed note (spec v0.7 section 2a, rule 4; reverse
//! rendezvous).
//!
//! A stranger who pays to reach someone cannot know their mixnet route: it
//! is never published. The stranger seals a note to the recipient's
//! **inbox key** (from the recipient's contact card). The recipient opens it
//! with that key alone: no sender address or other hint is needed, so a
//! fresh wallet finds its notes by trying each one.
//!
//! Inside the ciphertext: the sender's contact signing key, a fresh
//! *callback* handshake key made for this one request, the throwaway route,
//! a short intro, and the sender's signature over all of it together with
//! the admission commitment and the recipient's inbox key.
//!
//! Field layout (fixed size, [`SEALED_NOTE_LEN`]):
//! `admission commitment (32) || Noise N message (555)`. The Noise N
//! prologue and the signed bytes include the network id and the admission
//! commitment, so the note opens only on its network and next to the
//! admission record it names. (There is no pool id yet; one would join the
//! network id here.) The callback key inside is checked before use. In the shielded design
//! that commitment is a separate public field of the transaction (spec
//! section 3); the transparent prototype chain has no such field, so here
//! the note field carries it.
//!
//! Construction: one Noise N message (`Noise_N_25519_ChaChaPoly_BLAKE2s`,
//! via `snow`) and an Ed25519 signature (`ed25519-dalek`). Nothing here is
//! hand-made cryptography. Stated plainly: unreviewed (spec question 12).
//! Noise N has no forward secrecy for the recipient: if the inbox key leaks
//! later, old notes to it can be read.

use std::fmt;

use anonymum_core::crypto::SealedNote;
use snow::Builder;

use crate::contact::{is_contributory_key, verify_signature, ContactIdentity, Network};

const PATTERN: &str = "Noise_N_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"anonymum/contact-note/v3";
const SIGNED: &[u8] = b"anonymum/contact-note-signature/v3";
const VERSION: u8 = 3;

/// Bytes reserved for the throwaway route (sized for a Nym `Recipient`).
pub const ROUTE_LEN: usize = 96;
/// Longest intro, in bytes of UTF-8. Proposed cap; open question.
pub const INTRO_MAX_BYTES: usize = 280;
pub const ADMISSION_LEN: usize = 32;
/// Version, sender key, callback key, route, intro length, padded intro.
const BODY_LEN: usize = 1 + 32 + 32 + ROUTE_LEN + 2 + INTRO_MAX_BYTES;
const PLAINTEXT_LEN: usize = BODY_LEN + 64;
/// Noise N: ephemeral key (32) + encrypted plaintext + tag (16).
const ENVELOPE_LEN: usize = 32 + PLAINTEXT_LEN + 16;
/// The whole note field.
pub const SEALED_NOTE_LEN: usize = ADMISSION_LEN + ENVELOPE_LEN;
const _: () = assert!(SEALED_NOTE_LEN == anonymum_core::SEALED_NOTE_LEN, "the chain checks this length");

/// What the recipient reads after opening a note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactNote {
    /// The admission commitment the note is bound to.
    pub admission: [u8; ADMISSION_LEN],
    /// The sender's contact signing key (who the stranger is).
    pub sender: [u8; 32],
    /// The handshake key to call back, made for this request only.
    pub callback: [u8; 32],
    /// Where to call (a Nym `Recipient`, as bytes).
    pub route: [u8; ROUTE_LEN],
    pub intro: String,
}

#[derive(Debug)]
pub enum NoteError {
    IntroTooLong { len: usize },
    BadSize { len: usize },
    /// Not for this inbox key, bound to another admission record, or
    /// tampered.
    Noise(snow::Error),
    /// The sender's signature does not verify.
    BadSignature,
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

fn signed_message(network: &Network, admission: &[u8; ADMISSION_LEN], inbox: &[u8; 32], body: &[u8]) -> Vec<u8> {
    [SIGNED, network.as_slice(), admission.as_slice(), inbox.as_slice(), body].concat()
}

fn prologue(network: &Network, admission: &[u8; ADMISSION_LEN]) -> Vec<u8> {
    [PROLOGUE, network.as_slice(), admission.as_slice()].concat()
}

fn builder() -> Builder<'static> {
    Builder::new(PATTERN.parse().expect("pattern is a valid constant"))
}

/// Seal a note from `sender` to the holder of `recipient_inbox`, bound to
/// `network` and the transaction's admission commitment.
pub fn seal_note(
    network: &Network,
    recipient_inbox: &[u8; 32],
    sender: &ContactIdentity,
    callback: &[u8; 32],
    route: &[u8; ROUTE_LEN],
    intro: &str,
    admission: &[u8; ADMISSION_LEN],
) -> Result<SealedNote, NoteError> {
    let intro = intro.as_bytes();
    if intro.len() > INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro.len() });
    }
    if !is_contributory_key(recipient_inbox) || !is_contributory_key(callback) {
        return Err(NoteError::WeakKey);
    }
    let mut plaintext = vec![0u8; PLAINTEXT_LEN];
    plaintext[0] = VERSION;
    plaintext[1..33].copy_from_slice(&sender.signing_key());
    plaintext[33..65].copy_from_slice(callback);
    plaintext[65..65 + ROUTE_LEN].copy_from_slice(route);
    let len_at = 65 + ROUTE_LEN;
    plaintext[len_at..len_at + 2].copy_from_slice(&(intro.len() as u16).to_be_bytes());
    plaintext[len_at + 2..len_at + 2 + intro.len()].copy_from_slice(intro);
    let signature = sender.sign(&signed_message(network, admission, recipient_inbox, &plaintext[..BODY_LEN]));
    plaintext[BODY_LEN..].copy_from_slice(&signature);

    seal_plaintext(network, recipient_inbox, &plaintext, admission)
}

/// Encrypt a complete plaintext (body and signature) to `recipient_inbox`.
fn seal_plaintext(
    network: &Network,
    recipient_inbox: &[u8; 32],
    plaintext: &[u8],
    admission: &[u8; ADMISSION_LEN],
) -> Result<SealedNote, NoteError> {
    let prologue = prologue(network, admission);
    let mut noise = builder().prologue(&prologue)?.remote_public_key(recipient_inbox)?.build_initiator()?;
    let mut out = vec![0u8; SEALED_NOTE_LEN];
    out[..ADMISSION_LEN].copy_from_slice(admission);
    let len = noise.write_message(plaintext, &mut out[ADMISSION_LEN..])?;
    debug_assert_eq!(len, ENVELOPE_LEN);
    Ok(SealedNote(out))
}

/// Try to open a note on `network` with `me`'s inbox key. Needs nothing
/// else: no sender address, no hint. A note for someone else, or sealed for
/// another network, fails with [`NoteError::Noise`].
pub fn open_note(me: &ContactIdentity, network: &Network, note: &SealedNote) -> Result<ContactNote, NoteError> {
    if note.0.len() != SEALED_NOTE_LEN {
        return Err(NoteError::BadSize { len: note.0.len() });
    }
    let (admission, envelope) = note.0.split_at(ADMISSION_LEN);
    let admission: [u8; ADMISSION_LEN] = admission.try_into().expect("split at 32");
    let prologue = prologue(network, &admission);
    let mut noise =
        builder().prologue(&prologue)?.local_private_key(me.inbox_key().secret())?.build_responder()?;
    let mut plaintext = vec![0u8; PLAINTEXT_LEN];
    let len = noise.read_message(envelope, &mut plaintext)?;
    if len != PLAINTEXT_LEN || plaintext[0] != VERSION {
        return Err(NoteError::Malformed);
    }
    let (body, signature) = plaintext.split_at(BODY_LEN);
    let sender: [u8; 32] = body[1..33].try_into().expect("32 bytes");
    let signature: [u8; 64] = signature.try_into().expect("64 bytes");
    if !verify_signature(&sender, &signed_message(network, &admission, &me.inbox_key().public(), body), &signature) {
        return Err(NoteError::BadSignature);
    }
    let callback: [u8; 32] = body[33..65].try_into().expect("32 bytes");
    if !is_contributory_key(&callback) {
        return Err(NoteError::WeakKey);
    }
    let len_at = 65 + ROUTE_LEN;
    let intro_len = u16::from_be_bytes([body[len_at], body[len_at + 1]]) as usize;
    if intro_len > INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro_len });
    }
    let (intro, padding) = body[len_at + 2..].split_at(intro_len);
    if padding.iter().any(|b| *b != 0) {
        return Err(NoteError::Malformed);
    }
    Ok(ContactNote {
        admission,
        sender,
        callback,
        route: body[65..65 + ROUTE_LEN].try_into().expect("96 bytes"),
        intro: String::from_utf8(intro.to_vec()).map_err(|_| NoteError::Malformed)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
    const ADMISSION: [u8; 32] = [0xAD; 32];
    const NET: Network = [9; 32];

    fn cb() -> [u8; 32] {
        crate::contact::StaticKey::generate().public()
    }

    /// Decrypt a note to its raw plaintext, as its recipient can.
    fn raw(me: &ContactIdentity, note: &SealedNote) -> Vec<u8> {
        let mut noise = builder()
            .prologue(&prologue(&NET, &ADMISSION))
            .unwrap()
            .local_private_key(me.inbox_key().secret())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut plaintext = vec![0u8; PLAINTEXT_LEN];
        noise.read_message(&note.0[ADMISSION_LEN..], &mut plaintext).unwrap();
        plaintext
    }

    #[test]
    fn a_sender_cannot_claim_someone_elses_contact_identity() {
        let (bob, carol, mallory) =
            (ContactIdentity::generate(), ContactIdentity::generate(), ContactIdentity::generate());
        let inbox = bob.inbox_key().public();
        let honest = seal_note(&NET, &inbox, &mallory, &cb(), &ROUTE, "hi", &ADMISSION).unwrap();
        // Mallory names Carol as the sender but can only sign with her own key.
        let mut forged = raw(&bob, &honest);
        forged[1..33].copy_from_slice(&carol.signing_key());
        let note = seal_plaintext(&NET, &inbox, &forged, &ADMISSION).unwrap();
        assert!(matches!(open_note(&bob, &NET, &note), Err(NoteError::BadSignature)));
    }

    #[test]
    fn a_recipient_cannot_forward_a_note_as_if_written_to_someone_else() {
        // Bob opens Carol's note and re-seals the same body and signature to
        // Dave. The signature covers Bob's inbox key, so Dave refuses it.
        let (bob, carol, dave) = (ContactIdentity::generate(), ContactIdentity::generate(), ContactIdentity::generate());
        let note = seal_note(&NET, &bob.inbox_key().public(), &carol, &cb(), &ROUTE, "hi", &ADMISSION).unwrap();
        let forwarded = seal_plaintext(&NET, &dave.inbox_key().public(), &raw(&bob, &note), &ADMISSION).unwrap();
        assert!(matches!(open_note(&dave, &NET, &forwarded), Err(NoteError::BadSignature)));
    }

    #[test]
    fn padding_and_version_are_checked() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let inbox = bob.inbox_key().public();
        let note = seal_note(&NET, &inbox, &carol, &cb(), &ROUTE, "hi", &ADMISSION).unwrap();
        let mut bad_version = raw(&bob, &note);
        bad_version[0] = 9;
        let note2 = seal_plaintext(&NET, &inbox, &bad_version, &ADMISSION).unwrap();
        assert!(matches!(open_note(&bob, &NET, &note2), Err(NoteError::Malformed)));
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use crate::contact::StaticKey;

    const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
    const ADMISSION: [u8; 32] = [0xAD; 32];
    const NET_A: Network = [0xA; 32];
    const NET_B: Network = [0xB; 32];

    /// Decrypt with network A's prologue, as the recipient can.
    fn raw_on(network: &Network, me: &ContactIdentity, note: &SealedNote) -> Vec<u8> {
        let mut noise = builder()
            .prologue(&prologue(network, &ADMISSION))
            .unwrap()
            .local_private_key(me.inbox_key().secret())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut plaintext = vec![0u8; PLAINTEXT_LEN];
        noise.read_message(&note.0[ADMISSION_LEN..], &mut plaintext).unwrap();
        plaintext
    }

    #[test]
    fn a_note_for_network_a_neither_opens_nor_verifies_on_network_b() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let inbox = bob.inbox_key().public();
        let note = seal_note(&NET_A, &inbox, &carol, &StaticKey::generate().public(), &ROUTE, "hi", &ADMISSION).unwrap();
        assert_eq!(note.0.len(), SEALED_NOTE_LEN, "still 587 bytes");
        assert!(open_note(&bob, &NET_A, &note).is_ok());
        // The prologue differs: it does not open on network B.
        assert!(matches!(open_note(&bob, &NET_B, &note), Err(NoteError::Noise(_))));
        // Re-encrypted for network B by the recipient, the sender's signature
        // (made over network A) does not verify there.
        let moved = seal_plaintext(&NET_B, &inbox, &raw_on(&NET_A, &bob, &note), &ADMISSION).unwrap();
        assert!(matches!(open_note(&bob, &NET_B, &moved), Err(NoteError::BadSignature)));
    }

    #[test]
    fn a_signed_note_with_a_small_order_callback_key_is_refused() {
        let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
        let inbox = bob.inbox_key().public();
        let honest = seal_note(&NET_A, &inbox, &carol, &StaticKey::generate().public(), &ROUTE, "hi", &ADMISSION).unwrap();
        for weak in crate::contact::tests::SMALL_ORDER {
            // A sender who signs a weak callback key on purpose.
            let mut plaintext = raw_on(&NET_A, &bob, &honest);
            plaintext[33..65].copy_from_slice(&weak);
            let signature = carol.sign(&signed_message(&NET_A, &ADMISSION, &inbox, &plaintext[..BODY_LEN]));
            plaintext[BODY_LEN..].copy_from_slice(&signature);
            let note = seal_plaintext(&NET_A, &inbox, &plaintext, &ADMISSION).unwrap();
            assert!(matches!(open_note(&bob, &NET_A, &note), Err(NoteError::WeakKey)));
            // And sealing to a weak inbox or with a weak callback is refused.
            assert!(matches!(seal_note(&NET_A, &weak, &carol, &[9; 32], &ROUTE, "", &ADMISSION), Err(NoteError::WeakKey)));
            assert!(matches!(seal_note(&NET_A, &inbox, &carol, &weak, &ROUTE, "", &ADMISSION), Err(NoteError::WeakKey)));
        }
    }
}
