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
    /// Is `binding` `address`'s signature over `message` (a
    /// [`key_binding_message`])?
    fn verify_key_binding(&self, address: &Address, message: &[u8], binding: &KeyBinding) -> bool;
}

/// The exact bytes an address key signs to bind its messaging key: the
/// chain's genesis hash, the account and the key (v2, 2026-11-20 audit
/// HIGH-04), so a binding made for another chain or account is refused.
pub fn key_binding_message(genesis: &[u8; 32], account: &Address, key: &MessagingKey) -> Vec<u8> {
    let mut message = b"anonymum/msgkey-binding/v2".to_vec();
    message.extend_from_slice(genesis);
    message.extend_from_slice(&account.0);
    message.extend_from_slice(&key.0);
    message
}

// ---- contact notes (decision B; format v2 from spec v0.7 section 2a) ------
//
// A stranger's contact request carries a note sealed to the recipient's
// contact inbox key: the sender's contact identity, a fresh callback key, a
// throwaway route and a short intro, preceded by the admission commitment
// the note is bound to. Every note has the same size, so its length says
// nothing. The chain checks only that size; the layout, sealing and opening
// live in `anonymum-crypto::note`.

/// Exact length of a note field, format v5 (hybrid post-quantum, 2026-11-20):
/// admission commitment (32) + ML-KEM-768 ciphertext (1,088) + Noise Xpsk0
/// message (667). Was 667 (v4), 587 (v3) and 427 before.
pub const SEALED_NOTE_LEN: usize = 1_787;

/// An encrypted contact note. Opaque to the chain apart from its length.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedNote(pub Vec<u8>);

/// The exact bytes an opener signs. Binding both addresses stops replay
/// against a different opener or a different recipient; the genesis hash
/// (v2) against another chain.
pub fn invite_message(genesis: &[u8; 32], opener: &Address, recipient: &Address) -> Vec<u8> {
    let mut message = Vec::with_capacity(18 + 96);
    message.extend_from_slice(b"anonymum/invite/v2");
    message.extend_from_slice(genesis);
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
    use super::{key_binding_message, InviteKey, InviteProof, InviteScheme, KeyBinding, MessagingKey};
    use crate::types::Address;

    /// INSECURE: the "binding" is the address next to the binding message
    /// folded into 32 bytes. Anyone can compute it.
    pub fn mock_binding(genesis: &[u8; 32], address: &Address, key: &MessagingKey) -> KeyBinding {
        fold(address, &key_binding_message(genesis, address, key))
    }

    fn fold(address: &Address, message: &[u8]) -> KeyBinding {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&address.0);
        for (i, b) in message.iter().enumerate() {
            bytes[32 + i % 32] = bytes[32 + i % 32].rotate_left(3) ^ b;
        }
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

        fn verify_key_binding(&self, address: &Address, message: &[u8], binding: &KeyBinding) -> bool {
            fold(address, message) == *binding
        }
    }
}
