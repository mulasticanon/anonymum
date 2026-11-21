//! Encrypted, versioned snapshots of a responder's gate (durable grant
//! state: issues file R8, 2026-11-20 audit MED-04).
//!
//! A snapshot holds everything the [`crate::Gate`] decides with: issued and
//! consumed invitations, revocations, contacts, callback grants and blocks.
//! It holds no session keys: live sessions are not persisted, and after a
//! restart callers handshake again.
//!
//! # Format
//!
//! ```text
//! version (1, in the clear)  nonce (12)  ChaCha20-Poly1305 ciphertext || tag (16)
//! ```
//!
//! The associated data is `"anonymum/gate-snapshot/v1" || network`, so a
//! snapshot opens only under the right [`StorageKey`] and for the network it
//! was written for. The plaintext repeats the version as its first byte (so
//! the clear one is authenticated too) and is laid out as documented on the
//! gate's encoder. The cipher is the RustCrypto `chacha20poly1305` crate;
//! nothing here is hand-made cryptography. Unreviewed.
//!
//! Every failure is an explicit [`SnapshotError`]: a caller must never
//! treat a snapshot it cannot read as an empty gate, which would quietly
//! re-enable revoked and consumed invitations.
//!
//! # Persist before reply
//!
//! See [`crate::wire`]: after any change to the gate, the caller writes a
//! fresh snapshot durably (for example with [`write_atomically`]) before it
//! sends the frame that change produced.

use std::fmt;
use std::io::Write;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::contact::Network;

/// The current snapshot format: 4 since 2026-11-21 (a bound contact carries
/// its card's signed `seq`, for forward-only rollover).
pub const GATE_SNAPSHOT_VERSION: u8 = 4;
/// A bound contact carried its card's `not_after`; still read (the value is
/// dropped).
pub const GATE_SNAPSHOT_V3: u8 = 3;
/// Signing keys and rollover state, no card `not_after`; still read.
pub const GATE_SNAPSHOT_V2: u8 = 2;
/// Contacts without signing keys; still read.
pub const GATE_SNAPSHOT_V1: u8 = 1;
const AAD_LABEL: &[u8] = b"anonymum/gate-snapshot/v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The shortest well-formed snapshot: version, nonce and tag.
pub const MIN_SNAPSHOT_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

/// The 32-byte key snapshots are encrypted under. Keep it apart from the
/// snapshot (for example in the operating system's key store); it is wiped
/// from memory when dropped.
pub struct StorageKey(Zeroizing<[u8; 32]>);

impl StorageKey {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        StorageKey(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        StorageKey(Zeroizing::new(bytes))
    }

    /// The key bytes, for storing the key itself. Handle with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.0.as_ref()))
    }
}

impl fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageKey(..)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapshotError {
    /// A format version this code does not know. Nothing is read from it.
    UnsupportedVersion(u8),
    /// Shorter than any snapshot can be.
    Truncated,
    /// Does not decrypt: the wrong storage key, the wrong network, or a
    /// modified or cut-short ciphertext (the AEAD cannot tell these apart).
    Undecryptable,
    /// Decrypted, but not a well-formed gate.
    Malformed,
    /// Decrypted, but names another network.
    WrongNetwork,
    /// Decrypted, but belongs to another identity (another issuer key) or
    /// another kind of responder.
    WrongIdentity,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SnapshotError {}

fn aad(network: &Network) -> Vec<u8> {
    [AAD_LABEL, network.as_slice()].concat()
}

/// Encrypt `plaintext` (a gate encoding) for `network` under a fresh nonce.
pub(crate) fn seal(key: &StorageKey, network: &Network, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = key
        .cipher()
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad(network) })
        .expect("encrypting a buffer in memory");
    [&[GATE_SNAPSHOT_VERSION], nonce.as_slice(), &sealed].concat()
}

/// Decrypt a snapshot for `network`; the plaintext's own version byte must
/// match the clear one.
pub(crate) fn open(key: &StorageKey, network: &Network, snapshot: &[u8]) -> Result<Zeroizing<Vec<u8>>, SnapshotError> {
    let version = *snapshot.first().ok_or(SnapshotError::Truncated)?;
    if ![GATE_SNAPSHOT_VERSION, GATE_SNAPSHOT_V3, GATE_SNAPSHOT_V2, GATE_SNAPSHOT_V1].contains(&version) {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    if snapshot.len() < MIN_SNAPSHOT_LEN {
        return Err(SnapshotError::Truncated);
    }
    let (nonce, sealed) = snapshot[1..].split_at(NONCE_LEN);
    let plaintext = key
        .cipher()
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: &aad(network) })
        .map_err(|_| SnapshotError::Undecryptable)?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.first() != Some(&version) {
        return Err(SnapshotError::Malformed);
    }
    Ok(plaintext)
}

/// Replace the file at `path` with `bytes` so that a crash leaves either the
/// old contents or the new, never a mix: write a temporary file next to it,
/// flush it to disk, rename it over `path`, then (on Unix) flush the
/// directory so the rename itself is durable.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Checks behind the public API: the inner encoding, sealed with a
    //! valid key, must still be exactly right.

    use super::*;
    use crate::gate::Gate;

    const NET: Network = [9; 32];

    fn sealed_gate(edit: impl FnOnce(&mut Vec<u8>)) -> Result<Gate, SnapshotError> {
        let key = StorageKey::from_bytes([4; 32]);
        let mut plain = Gate::new(NET, Some([1; 32])).encode();
        edit(&mut plain);
        let opened = open(&key, &NET, &seal(&key, &NET, &plain))?;
        Gate::decode(&opened, &NET)
    }

    #[test]
    fn the_inner_encoding_is_checked_strictly() {
        assert!(sealed_gate(|_| {}).is_ok(), "control");
        // The plaintext's version must match the clear one.
        assert_eq!(sealed_gate(|p| p[0] = GATE_SNAPSHOT_V1).err(), Some(SnapshotError::Malformed));
        // The encoded network must be the one the snapshot is opened for.
        assert_eq!(sealed_gate(|p| p[1] ^= 1).err(), Some(SnapshotError::WrongNetwork));
        // No trailing bytes, no missing ones, no unknown issuer flag.
        assert_eq!(sealed_gate(|p| p.push(0)).err(), Some(SnapshotError::Malformed));
        assert_eq!(sealed_gate(|p| { p.pop(); }).err(), Some(SnapshotError::Malformed));
        assert_eq!(sealed_gate(|p| p[33] = 2).err(), Some(SnapshotError::Malformed));
        // A table count larger than what follows.
        assert_eq!(sealed_gate(|p| p[74..78].copy_from_slice(&1u32.to_be_bytes())).err(), Some(SnapshotError::Malformed));
    }

    /// A plaintext with one contact (`contact_tail` after caller and
    /// reference) and one callback (`callback_tail` after its deadline).
    fn one_of_each(version: u8, contact_tail: &[u8], callback_tail: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(&NET);
        p.push(1);
        p.extend_from_slice(&[1; 32]);
        p.extend_from_slice(&5u64.to_be_bytes());
        for _ in 0..3 {
            p.extend_from_slice(&0u32.to_be_bytes());
        }
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&[7; 32]);
        p.extend_from_slice(&[8; 32]);
        p.extend_from_slice(contact_tail);
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&[9; 32]);
        p.extend_from_slice(&[10; 32]);
        p.extend_from_slice(&99u64.to_be_bytes());
        p.extend_from_slice(callback_tail);
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    }

    fn open_plain(version: u8, plain: &[u8]) -> Result<Gate, SnapshotError> {
        let key = StorageKey::from_bytes([4; 32]);
        let mut sealed = seal(&key, &NET, plain);
        sealed[0] = version;
        Gate::decode(&open(&key, &NET, &sealed)?, &NET)
    }

    #[test]
    fn a_version_1_snapshot_is_still_read_and_rewritten_as_the_current_one() {
        let gate = open_plain(GATE_SNAPSHOT_V1, &one_of_each(GATE_SNAPSHOT_V1, &[], &[])).unwrap();
        assert!(gate.admits(&[7; 32], &[8; 32]));
        assert_eq!(gate.signer_of(&[7; 32]), None);
        let again = gate.encode();
        assert_eq!(again[0], GATE_SNAPSHOT_VERSION);
        assert_eq!(again, one_of_each(GATE_SNAPSHOT_VERSION, &[0], &[0]));
        assert_eq!(Gate::decode(&again, &NET).unwrap(), gate);
    }

    #[test]
    fn a_version_2_snapshot_loads_with_no_recorded_card_seq() {
        let signer = [3u8; 32];
        let contact = [&[3u8][..], &signer, &77u64.to_be_bytes()].concat();
        let callback = [&[1u8][..], &signer].concat();
        let gate = open_plain(GATE_SNAPSHOT_V2, &one_of_each(GATE_SNAPSHOT_V2, &contact, &callback)).unwrap();
        assert_eq!(gate.signer_of(&[7; 32]), Some(signer));
        assert_eq!(gate.card_seq(&[7; 32]), Some(0));
        assert_eq!(gate.card_seq(&[9; 32]), Some(0));
        let again = gate.encode();
        assert_eq!(again[0], GATE_SNAPSHOT_VERSION);
        assert_eq!(Gate::decode(&again, &NET).unwrap(), gate);
    }

    #[test]
    fn a_version_3_snapshot_drops_its_not_after_and_is_rewritten_as_the_current_one() {
        let signer = [3u8; 32];
        let contact = [&[3u8][..], &signer, &500u64.to_be_bytes(), &77u64.to_be_bytes()].concat();
        let callback = [&[1u8][..], &signer, &600u64.to_be_bytes()].concat();
        let gate = open_plain(GATE_SNAPSHOT_V3, &one_of_each(GATE_SNAPSHOT_V3, &contact, &callback)).unwrap();
        assert_eq!(gate.signer_of(&[7; 32]), Some(signer));
        assert_eq!(gate.card_seq(&[7; 32]), Some(0), "a not_after is not a sequence number");
        assert_eq!(gate.card_seq(&[9; 32]), Some(0));
        let again = gate.encode();
        assert_eq!(again[0], GATE_SNAPSHOT_VERSION);
        assert_eq!(Gate::decode(&again, &NET).unwrap(), gate);
    }

    #[test]
    fn contact_and_callback_flags_are_checked_strictly() {
        let signer = [3u8; 32];
        let with = |c: &[u8], b: &[u8]| open_plain(GATE_SNAPSHOT_VERSION, &one_of_each(GATE_SNAPSHOT_VERSION, c, b));
        let both = [&[3u8][..], &signer, &500u64.to_be_bytes(), &77u64.to_be_bytes()].concat();
        let callback = [&[1u8][..], &signer, &600u64.to_be_bytes()].concat();
        let gate = with(&both, &callback).unwrap();
        assert_eq!(gate.signer_of(&[7; 32]), Some(signer));
        assert_eq!(gate.signer_of(&[9; 32]), Some(signer));
        assert_eq!(gate.card_seq(&[7; 32]), Some(500));
        assert_eq!(gate.card_seq(&[9; 32]), Some(600));
        assert_eq!(gate.encode(), one_of_each(GATE_SNAPSHOT_VERSION, &both, &callback));
        // A signer without its card's seq is cut short.
        assert_eq!(with(&[&[1u8][..], &signer].concat(), &[0]).err(), Some(SnapshotError::Malformed));
        // Unknown bits, or a flag promising bytes that are not there.
        assert_eq!(with(&[4], &[0]).err(), Some(SnapshotError::Malformed));
        assert_eq!(with(&[0], &[2]).err(), Some(SnapshotError::Malformed));
        assert_eq!(with(&[1], &[0]).err(), Some(SnapshotError::Malformed));
        assert_eq!(with(&[0], &[1]).err(), Some(SnapshotError::Malformed));
        // A version-1 snapshot has no flag bytes at all.
        assert_eq!(open_plain(GATE_SNAPSHOT_V1, &one_of_each(GATE_SNAPSHOT_V1, &[0], &[0])).err(), Some(SnapshotError::Malformed));
    }

    #[test]
    fn the_storage_key_does_not_print() {
        assert_eq!(format!("{:?}", StorageKey::from_bytes([7; 32])), "StorageKey(..)");
    }
}
