//! Sealed contact notes (decision B: reverse rendezvous).
//!
//! A stranger who pays to reach someone cannot know their mixnet address:
//! it is never published. Instead the stranger seals a note to the
//! recipient's on-chain messaging key. The note holds a throwaway mixnet
//! address made for this one request and a greeting-length intro. If the
//! recipient accepts, their client calls the stranger at that address.
//!
//! Construction: one Noise N message (`Noise_N_25519_ChaChaPoly_BLAKE2s`,
//! via `snow`). Noise N is Noise's one-way pattern: an ephemeral key from
//! the sender, the recipient's static key, one encrypted payload. Nothing
//! here is hand-made cryptography. The Noise prologue binds the note to the
//! requesting and receiving addresses, so a note copied into someone else's
//! request will not open.
//!
//! Every note is the same size ([`SEALED_NOTE_LEN`]): the plaintext is
//! padded to the longest allowed intro, so the length reveals nothing.
//!
//! Stated plainly: the sender is not authenticated by the note itself. The
//! chain already authenticates who sent the request, and the prologue ties
//! the note to that address. Noise N has no forward secrecy for the
//! recipient: if the recipient's messaging key leaks later, old notes to it
//! can be read.

use std::fmt;

use anonymum_core::crypto::{
    contact_note_prologue, MessagingKey, SealedNote, NOTE_INTRO_MAX_BYTES, NOTE_PLAINTEXT_LEN,
    NOTE_REPLY_ADDRESS_LEN, SEALED_NOTE_LEN,
};
use anonymum_core::Address;
use snow::Builder;

use crate::identity::Identity;

const PATTERN: &str = "Noise_N_25519_ChaChaPoly_BLAKE2s";
const VERSION: u8 = 1;

/// What the recipient reads after opening a note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ContactNote {
    /// Where to call the stranger back (a Nym `Recipient`, as bytes).
    pub reply_to: [u8; NOTE_REPLY_ADDRESS_LEN],
    pub intro: String,
}

#[derive(Debug)]
pub enum NoteError {
    IntroTooLong { len: usize },
    BadSize { len: usize },
    /// Wrong key, wrong sender/recipient, or tampered.
    Noise(snow::Error),
    /// Decrypted, but not a well-formed note.
    Malformed,
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

/// Seal a note from `from` to `to`, encrypted to `to`'s published key.
pub fn seal_note(
    recipient_key: &MessagingKey,
    from: &Address,
    to: &Address,
    reply_to: &[u8; NOTE_REPLY_ADDRESS_LEN],
    intro: &str,
) -> Result<SealedNote, NoteError> {
    let intro = intro.as_bytes();
    if intro.len() > NOTE_INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro.len() });
    }
    let mut plaintext = [0u8; NOTE_PLAINTEXT_LEN];
    plaintext[0] = VERSION;
    plaintext[1..1 + NOTE_REPLY_ADDRESS_LEN].copy_from_slice(reply_to);
    let len_at = 1 + NOTE_REPLY_ADDRESS_LEN;
    plaintext[len_at..len_at + 2].copy_from_slice(&(intro.len() as u16).to_be_bytes());
    plaintext[len_at + 2..len_at + 2 + intro.len()].copy_from_slice(intro);

    let prologue = contact_note_prologue(from, to);
    let mut noise = Builder::new(PATTERN.parse().expect("pattern is a valid constant"))
        .prologue(&prologue)?
        .remote_public_key(&recipient_key.0)?
        .build_initiator()?;
    let mut out = vec![0u8; SEALED_NOTE_LEN];
    let len = noise.write_message(&plaintext, &mut out)?;
    debug_assert_eq!(len, SEALED_NOTE_LEN);
    out.truncate(len);
    Ok(SealedNote(out))
}

/// Open a note addressed to `me`, sent by `from`.
pub fn open_note(me: &Identity, from: &Address, note: &SealedNote) -> Result<ContactNote, NoteError> {
    if note.0.len() != SEALED_NOTE_LEN {
        return Err(NoteError::BadSize { len: note.0.len() });
    }
    let prologue = contact_note_prologue(from, &me.address());
    let secret = me.messaging_secret();
    let mut noise = Builder::new(PATTERN.parse().expect("pattern is a valid constant"))
        .prologue(&prologue)?
        .local_private_key(&secret)?
        .build_responder()?;
    let mut plaintext = [0u8; NOTE_PLAINTEXT_LEN];
    let len = noise.read_message(&note.0, &mut plaintext)?;
    if len != NOTE_PLAINTEXT_LEN || plaintext[0] != VERSION {
        return Err(NoteError::Malformed);
    }
    let mut reply_to = [0u8; NOTE_REPLY_ADDRESS_LEN];
    reply_to.copy_from_slice(&plaintext[1..1 + NOTE_REPLY_ADDRESS_LEN]);
    let len_at = 1 + NOTE_REPLY_ADDRESS_LEN;
    let intro_len = u16::from_be_bytes([plaintext[len_at], plaintext[len_at + 1]]) as usize;
    if intro_len > NOTE_INTRO_MAX_BYTES {
        return Err(NoteError::IntroTooLong { len: intro_len });
    }
    let (intro, padding) = plaintext[len_at + 2..].split_at(intro_len);
    if padding.iter().any(|b| *b != 0) {
        return Err(NoteError::Malformed);
    }
    let intro = String::from_utf8(intro.to_vec()).map_err(|_| NoteError::Malformed)?;
    Ok(ContactNote { reply_to, intro })
}
