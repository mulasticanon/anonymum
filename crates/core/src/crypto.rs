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

/// Signature verification for invites. Production: Ed25519.
pub trait InviteScheme {
    fn verify(&self, key: &InviteKey, message: &[u8], proof: &InviteProof) -> bool;
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
    use super::{InviteKey, InviteProof, InviteScheme};

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
    }
}
