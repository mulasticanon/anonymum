use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use murmur_core::Address;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const BINDING_DOMAIN: &[u8] = b"murmur/msgkey-binding/v1";

/// A wallet's private keys. Never leaves the device.
///
/// The address is the Ed25519 public key. The X25519 key encrypts messages.
/// The address key signs the encryption key (the "binding"), so a peer who
/// knows only your address can check they are encrypting to you and not to
/// someone in the middle.
pub struct Identity {
    signing: SigningKey,
    messaging: StaticSecret,
}

impl Identity {
    pub fn generate() -> Self {
        Identity {
            signing: SigningKey::generate(&mut OsRng),
            messaging: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Restore from the two 32-byte secrets (e.g. from encrypted storage).
    pub fn from_secret_bytes(signing: [u8; 32], messaging: [u8; 32]) -> Self {
        Identity {
            signing: SigningKey::from_bytes(&signing),
            messaging: StaticSecret::from(messaging),
        }
    }

    /// The two secrets, for encrypted storage. Handle with care.
    pub fn to_secret_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.signing.to_bytes(), self.messaging.to_bytes())
    }

    pub fn address(&self) -> Address {
        Address(self.signing.verifying_key().to_bytes())
    }

    pub(crate) fn messaging_secret(&self) -> [u8; 32] {
        self.messaging.to_bytes()
    }

    pub(crate) fn messaging_public(&self) -> [u8; 32] {
        PublicKey::from(&self.messaging).to_bytes()
    }

    /// Signature by the address key over the encryption key.
    pub(crate) fn binding(&self) -> [u8; 64] {
        self.signing.sign(&binding_message(&self.messaging_public())).to_bytes()
    }
}

fn binding_message(messaging_public: &[u8; 32]) -> Vec<u8> {
    let mut message = BINDING_DOMAIN.to_vec();
    message.extend_from_slice(messaging_public);
    message
}

/// Does `address` vouch for `messaging_public`?
pub(crate) fn verify_binding(
    address: &Address,
    messaging_public: &[u8; 32],
    binding: &[u8; 64],
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&address.0) else {
        return false;
    };
    key.verify_strict(&binding_message(messaging_public), &Signature::from_bytes(binding))
        .is_ok()
}
