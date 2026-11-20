use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use anonymum_core::crypto::{key_binding_message, KeyBinding, MessagingKey};
use anonymum_core::{Address, Tx};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// A wallet's private keys. Never leaves the device, and never appears in a
/// contact card, a handshake or a note (spec v0.7 section 2a).
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

    pub(crate) fn messaging_public(&self) -> [u8; 32] {
        PublicKey::from(&self.messaging).to_bytes()
    }

    /// Signature by the address key over the encryption key, for the chain
    /// with this genesis hash.
    pub(crate) fn binding(&self, genesis: &[u8; 32]) -> [u8; 64] {
        let message = key_binding_message(genesis, &self.address(), &MessagingKey(self.messaging_public()));
        self.signing.sign(&message).to_bytes()
    }

    /// The transaction that publishes this wallet's messaging key on the
    /// chain with genesis hash `genesis`.
    pub fn publish_key_tx(&self, genesis: &[u8; 32]) -> Tx {
        Tx::PublishMessagingKey {
            key: MessagingKey(self.messaging_public()),
            binding: KeyBinding(self.binding(genesis)),
        }
    }
}

/// Is `binding` `address`'s strict Ed25519 signature over `message`?
pub(crate) fn verify_binding(address: &Address, message: &[u8], binding: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&address.0) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(binding)).is_ok()
}
