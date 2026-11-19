//! A minimal wallet: everything derives from one backed-up master secret,
//! and an opening transaction carries an encrypted recovery copy of the
//! escrow (spec section 4, "the sender can always recover their own
//! escrow"). Enough to run the section 5b acceptance test in the model.
//!
//! The copy is sealed with ChaCha20-Poly1305 (the `chacha20poly1305`
//! crate) and stored together with its fresh random nonce, so a restored
//! wallet makes exactly one decryption attempt per payload slot (spec v0.5,
//! I11). How the key is derived is a model choice, not a reviewed design
//! (spec question 9).

use std::collections::HashSet;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::chain::{Chain, PAYLOAD_LEN};
use crate::hash::{h, Hash};
use crate::objects::*;

const NONCE_BYTES: usize = 12;
const ESCROW_BYTES: usize = 8 + 8 + 32 * 5;
const TAG_BYTES: usize = 16;
const _: () = assert!(
    NONCE_BYTES + ESCROW_BYTES + TAG_BYTES == PAYLOAD_LEN,
    "a recovery copy (nonce + sealed escrow) fills one payload slot"
);

/// How far a restore searches for refund identities.
pub const REFUND_SEARCH: u64 = 1_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Wallet {
    master: Hash,
}

impl Wallet {
    /// A wallet from its backup (the master secret).
    pub fn from_backup(master: Hash) -> Self {
        Wallet { master }
    }

    /// The secret for `purpose`, number `index`.
    pub fn secret(&self, purpose: &str, index: u64) -> Secret {
        Secret(h("wallet/secret", &[&self.master, purpose.as_bytes(), &index.to_le_bytes()]))
    }

    /// The identity a refund for escrow number `index` goes to (a fresh one
    /// per escrow).
    pub fn refund_secret(&self, index: u64) -> Secret {
        self.secret("refund", index)
    }

    fn recovery_cipher(&self) -> ChaCha20Poly1305 {
        let key = h("wallet/recovery-key", &[&self.master]);
        ChaCha20Poly1305::new(Key::from_slice(&key))
    }

    /// The recovery copy to put in one payload slot of the opening:
    /// `nonce || ciphertext`. The nonce must be fresh and random; the model
    /// has no randomness of its own, so the caller supplies it.
    pub fn seal_recovery(&self, escrow: &EscrowNote, nonce: [u8; NONCE_BYTES]) -> Vec<u8> {
        let mut plain = Vec::with_capacity(ESCROW_BYTES);
        plain.extend_from_slice(&escrow.price.to_le_bytes());
        plain.extend_from_slice(&escrow.fee_reserve.to_le_bytes());
        for part in [&escrow.recipient.0, &escrow.refund_to.0, &escrow.canceller.0, &escrow.seed, &escrow.blinding] {
            plain.extend_from_slice(part);
        }
        let sealed = self
            .recovery_cipher()
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .expect("encryption of a fixed-size buffer");
        [nonce.as_slice(), &sealed].concat()
    }

    /// One decryption attempt: is this payload slot one of this wallet's
    /// recovery copies?
    pub fn open_recovery(&self, slot: &[u8]) -> Option<EscrowNote> {
        if slot.len() != PAYLOAD_LEN {
            return None;
        }
        let (nonce, sealed) = slot.split_at(NONCE_BYTES);
        let plain = self.recovery_cipher().decrypt(Nonce::from_slice(nonce), sealed).ok()?;
        decode_escrow(&plain)
    }

    /// Every escrow this wallet opened that the chain holds, recovered from
    /// the chain alone: one decryption attempt per payload slot.
    pub fn recover_escrows(&self, chain: &Chain) -> Vec<EscrowNote> {
        let on_chain: HashSet<Commitment> = chain.leaves().iter().map(|l| l.commitment).collect();
        let mut found = Vec::new();
        for slot in chain.log().iter().flat_map(|tx| tx.payloads.iter()) {
            if let Some(escrow) = self.open_recovery(slot) {
                if on_chain.contains(&Note::Escrow(escrow).commitment()) && !found.contains(&escrow) {
                    found.push(escrow);
                }
            }
        }
        found
    }

    /// The secret that owns `authority`, if this wallet derived it.
    pub fn refund_secret_for(&self, authority: &Authority) -> Option<Secret> {
        (0..REFUND_SEARCH).map(|i| self.refund_secret(i)).find(|s| s.authority() == *authority)
    }
}

/// The refunds that exist on chain for `escrow`, one per position the
/// escrow was inserted at: `(refund note, refund position, created_at)`.
pub fn find_refunds(chain: &Chain, escrow: &EscrowNote) -> Vec<(Note, u64, Time)> {
    find_note(chain, &Note::Escrow(*escrow))
        .into_iter()
        .flat_map(|(escrow_position, _)| {
            let refund = derived_refund(escrow, escrow_position);
            find_note(chain, &refund).into_iter().map(move |(pos, at)| (refund, pos, at))
        })
        .collect()
}

fn decode_escrow(plain: &[u8]) -> Option<EscrowNote> {
    if plain.len() != ESCROW_BYTES {
        return None;
    }
    let u64_at = |at: usize| u64::from_le_bytes(plain[at..at + 8].try_into().expect("8 bytes"));
    let h_at = |at: usize| -> Hash { plain[at..at + 32].try_into().expect("32 bytes") };
    Some(EscrowNote {
        price: u64_at(0),
        fee_reserve: u64_at(8),
        recipient: Authority(h_at(16)),
        refund_to: Authority(h_at(48)),
        canceller: Authority(h_at(80)),
        seed: h_at(112),
        blinding: h_at(144),
    })
}

/// Where a note with this commitment sits in the tree, if anywhere: the
/// sender can look for the derived refund without help from anyone.
pub fn find_note(chain: &Chain, note: &Note) -> Vec<(u64, Time)> {
    let c = note.commitment();
    chain
        .leaves()
        .iter()
        .enumerate()
        .filter(|(_, l)| l.commitment == c)
        .map(|(i, l)| (i as u64, l.created_at))
        .collect()
}
