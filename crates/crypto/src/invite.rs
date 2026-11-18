use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use anonymum_core::crypto::{
    invite_message, InviteKey, InviteProof, InviteScheme, KeyBinding, MessagingKey,
};
use anonymum_core::Address;
use rand_core::OsRng;

/// The private half of a one-time invite.
///
/// The recipient generates it, registers [`InviteSecret::public`] on-chain,
/// and hands these 32 bytes to one contact over any private channel (QR code
/// in person, an existing secure chat). Whoever holds it can open one
/// channel at the cheap rate.
pub struct InviteSecret(SigningKey);

impl InviteSecret {
    pub fn generate() -> Self {
        InviteSecret(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        InviteSecret(SigningKey::from_bytes(&bytes))
    }

    /// The bytes to hand to the invited contact.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// What the recipient registers on-chain.
    pub fn public(&self) -> InviteKey {
        InviteKey(self.0.verifying_key().to_bytes())
    }

    /// Proof that `opener` holds this invite and wants to reach `recipient`.
    /// Useless to any other opener, so copying it from a pending transaction
    /// gains nothing.
    pub fn sign_for(&self, opener: &Address, recipient: &Address) -> InviteProof {
        InviteProof(self.0.sign(&invite_message(opener, recipient)).to_bytes().to_vec())
    }
}

/// Production [`InviteScheme`]: Ed25519 with strict verification.
#[derive(Clone, Copy, Default)]
pub struct Ed25519Invites;

impl InviteScheme for Ed25519Invites {
    fn verify(&self, key: &InviteKey, message: &[u8], proof: &InviteProof) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&key.0) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&proof.0) else {
            return false;
        };
        key.verify_strict(message, &signature).is_ok()
    }

    fn verify_key_binding(&self, address: &Address, key: &MessagingKey, binding: &KeyBinding) -> bool {
        crate::identity::verify_binding(address, &key.0, &binding.0)
    }
}
