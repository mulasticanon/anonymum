//! Cryptographic interfaces.
//!
//! The core never implements cryptography itself. It defines what it needs
//! and a real implementation (Ed25519 via a vetted crate) is plugged in.
//!
//! # Why invites are key pairs, not secret codes
//!
//! A plain secret code has to be revealed on-chain to be used, and anyone
//! watching pending transactions could copy it and use it first. Instead the
//! recipient registers an invite *public key* and hands the invite *private
//! key* to their contact. The contact signs "I, <opener>, am opening a
//! channel with <recipient>". The signature is useless to anyone else.

use crate::types::Address;

/// Public half of a one-time invite. Registered on-chain by the recipient.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct InviteKey(pub [u8; 32]);

/// Signature made with the invite's private half.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InviteProof(pub Vec<u8>);

/// A wallet's X25519 messaging public key, published on-chain so strangers
/// can seal a contact note to it. A key is not a location: it reveals
/// nothing about where the wallet connects to the mixnet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessagingKey(pub [u8; 32]);

/// Signature by the wallet's address key over [`key_binding_message`].
/// Proves the messaging key belongs to that address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyBinding(pub [u8; 64]);

/// Signature checks the chain needs. Production: Ed25519.
pub trait InviteScheme {
    /// Is `proof` a valid signature by the invite `key` over `message`?
    fn verify(&self, key: &InviteKey, message: &[u8], proof: &InviteProof) -> bool;
    /// Does `address` vouch for `key` with `binding`?
    fn verify_key_binding(&self, address: &Address, key: &MessagingKey, binding: &KeyBinding) -> bool;
}

/// The exact bytes an address key signs to bind its messaging key.
pub fn key_binding_message(key: &MessagingKey) -> Vec<u8> {
    let mut message = b"anonymum/msgkey-binding/v1".to_vec();
    message.extend_from_slice(&key.0);
    message
}

// ---- contact notes (decision B) -------------------------------------------
//
// A stranger's contact request carries a note sealed to the recipient's
// messaging key: a throwaway mixnet address for this one request, plus a
// short intro. Every note has the same size, so its length says nothing.
// The chain can only check that size; the intro limit is enforced by the
// fixed layout and checked again by the recipient's client when it opens
// the note. Sealing and opening live in `anonymum-crypto`.

/// Bytes reserved for the throwaway reply address (sized for a Nym
/// `Recipient`: identity key, encryption key, gateway key).
pub const NOTE_REPLY_ADDRESS_LEN: usize = 96;
/// Longest intro, in bytes of UTF-8. Proposed cap; open question.
pub const NOTE_INTRO_MAX_BYTES: usize = 280;
/// Version byte, reply address, intro length (u16), intro padded to the max.
pub const NOTE_PLAINTEXT_LEN: usize = 1 + NOTE_REPLY_ADDRESS_LEN + 2 + NOTE_INTRO_MAX_BYTES;
/// Noise N message: ephemeral key (32) + encrypted plaintext + tag (16).
pub const SEALED_NOTE_LEN: usize = 32 + NOTE_PLAINTEXT_LEN + 16;

/// An encrypted contact note. Opaque to the chain apart from its length.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedNote(pub Vec<u8>);

/// Mixed into the note's encryption, so a note copied into another
/// sender's request (or aimed at another recipient) fails to open.
pub fn contact_note_prologue(from: &Address, to: &Address) -> Vec<u8> {
    let mut prologue = b"anonymum/contact-note/v1".to_vec();
    prologue.extend_from_slice(&from.0);
    prologue.extend_from_slice(&to.0);
    prologue
}

/// The exact bytes an opener signs. Binding both addresses stops replay
/// against a different opener or a different recipient.
pub fn invite_message(opener: &Address, recipient: &Address) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + 64);
    message.extend_from_slice(b"anonymum/invite/v1");
    message.extend_from_slice(&opener.0);
    message.extend_from_slice(&recipient.0);
    message
}

/// **INSECURE stand-in for tests and demos only.**
///
/// The "signature" contains the secret itself, so it protects nothing. It
/// exists so the state machine can be exercised without external crates.
/// Replace with Ed25519 before anything leaves a test network.
pub mod mock {
    use super::{InviteKey, InviteProof, InviteScheme, KeyBinding, MessagingKey};
    use crate::types::Address;

    /// INSECURE: the "binding" is just the address and key side by side.
    pub fn mock_binding(address: &Address, key: &MessagingKey) -> KeyBinding {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&address.0);
        bytes[32..].copy_from_slice(&key.0);
        KeyBinding(bytes)
    }

    pub struct MockInviteSecret(pub [u8; 32]);

    impl MockInviteSecret {
        pub fn from_seed(seed: u8) -> Self {
            let mut bytes = [0u8; 32];
            for (i, slot) in bytes.iter_mut().enumerate() {
                *slot = seed.wrapping_mul(31).wrapping_add(i as u8);
            }
            MockInviteSecret(bytes)
        }

        pub fn public(&self) -> InviteKey {
            let mut bytes = self.0;
            for slot in bytes.iter_mut() {
                *slot ^= 0xFF;
            }
            InviteKey(bytes)
        }

        pub fn sign(&self, message: &[u8]) -> InviteProof {
            let mut out = self.0.to_vec();
            out.extend_from_slice(message);
            InviteProof(out)
        }
    }

    pub struct MockScheme;

    impl InviteScheme for MockScheme {
        fn verify(&self, key: &InviteKey, message: &[u8], proof: &InviteProof) -> bool {
            if proof.0.len() < 32 {
                return false;
            }
            let (secret, signed) = proof.0.split_at(32);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(secret);
            MockInviteSecret(bytes).public() == *key && signed == message
        }

        fn verify_key_binding(&self, address: &Address, key: &MessagingKey, binding: &KeyBinding) -> bool {
            mock_binding(address, key) == *binding
        }
    }
}
