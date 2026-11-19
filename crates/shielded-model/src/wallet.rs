//! A minimal wallet: everything derives from one backed-up master secret,
//! and an opening transaction carries an encrypted recovery copy of the
//! escrow (spec section 4, "the sender can always recover their own
//! escrow"). Enough to run the section 5b acceptance test in the model.
//!
//! The copy records, besides the escrow, *how to derive* the refund
//! identity and the cancel authority (a purpose and an index each), so a
//! restored wallet derives both keys directly. There is no index search, so
//! any index works (design review H2).
//!
//! A refund is found by first locating the finalised transaction that
//! consumed the escrow's nullifier, then matching the derived refund among
//! that transaction's outputs only, never anywhere else in history (design
//! review M1).
//!
//! The copy is sealed with ChaCha20-Poly1305 (the `chacha20poly1305` crate)
//! and stored with its fresh random nonce, so a restored wallet makes one
//! decryption attempt per payload slot (spec v0.5, I11). How the key is
//! derived is a model choice, not a reviewed design (spec question 9).

use std::collections::HashSet;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::chain::{Chain, PAYLOAD_LEN};
use crate::hash::{h, Hash};
use crate::objects::*;

const NONCE_BYTES: usize = 12;
const ESCROW_BYTES: usize = 8 + 8 + 32 * 5;
const PURPOSE_BYTES: usize = 16;
const PATH_BYTES: usize = PURPOSE_BYTES + 8;
const TAG_BYTES: usize = 16;
const PLAIN_BYTES: usize = ESCROW_BYTES + 2 * PATH_BYTES;
const _: () = assert!(
    NONCE_BYTES + PLAIN_BYTES + TAG_BYTES == PAYLOAD_LEN,
    "a recovery copy (nonce + sealed escrow and key paths) fills one payload slot"
);

/// How a wallet derives one of its secrets: a purpose and an index.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyPath {
    /// At most 16 bytes.
    pub purpose: String,
    pub index: u64,
}

impl KeyPath {
    pub fn new(purpose: &str, index: u64) -> Self {
        KeyPath { purpose: purpose.to_string(), index }
    }
}

/// An escrow recovered from the chain, with the paths to its two keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Recovered {
    pub escrow: EscrowNote,
    pub refund: KeyPath,
    pub cancel: KeyPath,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryError {
    /// A purpose longer than 16 bytes.
    PurposeTooLong,
    /// The path does not derive the authority the escrow names.
    PathDoesNotMatch,
}

/// Where an escrow stands, judged from the transaction that consumed it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EscrowStatus {
    /// No finalised transaction has published its nullifier.
    Unresolved,
    /// Resolved by the transaction at `tx_index` without a refund to the
    /// sender (a claim).
    ResolvedWithoutRefund { tx_index: usize },
    /// Resolved by `tx_index`, whose outputs include the derived refund.
    Refunded { tx_index: usize, refund: Note, position: u64, created_at: Time },
}

/// The status of one inserted copy of an escrow, plus, for a refund the
/// wallet can spend, whether that refund has already been spent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RefundState {
    pub escrow_position: u64,
    pub status: EscrowStatus,
    pub refund_spent: Option<bool>,
}

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

    pub fn secret_at(&self, path: &KeyPath) -> Secret {
        self.secret(&path.purpose, path.index)
    }

    fn recovery_cipher(&self) -> ChaCha20Poly1305 {
        let key = h("wallet/recovery-key", &[&self.master]);
        ChaCha20Poly1305::new(Key::from_slice(&key))
    }

    /// The recovery copy to put in one payload slot of the opening:
    /// `nonce || ciphertext`, recording the escrow and the paths to its
    /// refund and cancel keys. The nonce must be fresh and random; the
    /// model has no randomness of its own, so the caller supplies it.
    pub fn seal_recovery(
        &self,
        escrow: &EscrowNote,
        refund: &KeyPath,
        cancel: &KeyPath,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Vec<u8>, RecoveryError> {
        if self.secret_at(refund).authority() != escrow.refund_to || self.secret_at(cancel).authority() != escrow.canceller {
            return Err(RecoveryError::PathDoesNotMatch);
        }
        let mut plain = Vec::with_capacity(PLAIN_BYTES);
        plain.extend_from_slice(&escrow.price.to_le_bytes());
        plain.extend_from_slice(&escrow.fee_reserve.to_le_bytes());
        for part in [&escrow.recipient.0, &escrow.refund_to.0, &escrow.canceller.0, &escrow.seed, &escrow.blinding] {
            plain.extend_from_slice(part);
        }
        for path in [refund, cancel] {
            let purpose = path.purpose.as_bytes();
            if purpose.len() > PURPOSE_BYTES {
                return Err(RecoveryError::PurposeTooLong);
            }
            let mut field = [0u8; PURPOSE_BYTES];
            field[..purpose.len()].copy_from_slice(purpose);
            plain.extend_from_slice(&field);
            plain.extend_from_slice(&path.index.to_le_bytes());
        }
        let sealed = self
            .recovery_cipher()
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .expect("encryption of a fixed-size buffer");
        Ok([nonce.as_slice(), &sealed].concat())
    }

    /// One decryption attempt: is this payload slot one of this wallet's
    /// recovery copies? Its key paths must derive the authorities the escrow
    /// names, so a restored wallet can act on what it returns.
    pub fn open_recovery(&self, slot: &[u8]) -> Option<Recovered> {
        if slot.len() != PAYLOAD_LEN {
            return None;
        }
        let (nonce, sealed) = slot.split_at(NONCE_BYTES);
        let plain = self.recovery_cipher().decrypt(Nonce::from_slice(nonce), sealed).ok()?;
        let recovered = decode(&plain)?;
        let ok = self.secret_at(&recovered.refund).authority() == recovered.escrow.refund_to
            && self.secret_at(&recovered.cancel).authority() == recovered.escrow.canceller;
        ok.then_some(recovered)
    }

    /// Every escrow this wallet opened that the chain holds, recovered from
    /// the chain alone: one decryption attempt per payload slot.
    pub fn recover_escrows(&self, chain: &Chain) -> Vec<Recovered> {
        let on_chain: HashSet<Commitment> = chain.leaves().iter().map(|l| l.commitment).collect();
        let mut found: Vec<Recovered> = Vec::new();
        for slot in chain.log().iter().flat_map(|tx| tx.payloads.iter()) {
            if let Some(r) = self.open_recovery(slot) {
                if on_chain.contains(&Note::Escrow(r.escrow).commitment()) && !found.contains(&r) {
                    found.push(r);
                }
            }
        }
        found
    }

    /// The state of every inserted copy of a recovered escrow, including
    /// whether a refund this wallet owns is still unspent.
    pub fn refund_states(&self, chain: &Chain, recovered: &Recovered) -> Vec<RefundState> {
        let owner = self.secret_at(&recovered.refund);
        escrow_positions(chain, &recovered.escrow)
            .into_iter()
            .map(|escrow_position| {
                let status = escrow_status(chain, &recovered.escrow, escrow_position);
                let refund_spent = match status {
                    EscrowStatus::Refunded { refund, position, .. } => {
                        Some(chain.is_spent(&ordinary_nullifier(&owner, &refund.commitment(), position)))
                    }
                    _ => None,
                };
                RefundState { escrow_position, status, refund_spent }
            })
            .collect()
    }
}

/// Every tree position at which this escrow's commitment was inserted.
pub fn escrow_positions(chain: &Chain, escrow: &EscrowNote) -> Vec<u64> {
    let c = Note::Escrow(*escrow).commitment();
    chain.leaves().iter().enumerate().filter(|(_, l)| l.commitment == c).map(|(i, _)| i as u64).collect()
}

/// Where the escrow at `escrow_position` stands: find the finalised
/// transaction that consumed its nullifier, then look for the derived
/// refund among *that transaction's outputs only*. An identical commitment
/// anywhere else in history proves nothing about this escrow.
pub fn escrow_status(chain: &Chain, escrow: &EscrowNote, escrow_position: u64) -> EscrowStatus {
    let commitment = Note::Escrow(*escrow).commitment();
    let nullifier = escrow_nullifier(&escrow.seed, &commitment, escrow_position);
    let Some(tx_index) = chain.transaction_spending(&nullifier) else {
        return EscrowStatus::Unresolved;
    };
    let refund = derived_refund(escrow, escrow_position);
    let c = refund.commitment();
    chain
        .output_positions(tx_index)
        .find(|&p| chain.leaves()[p as usize].commitment == c)
        .map(|position| EscrowStatus::Refunded {
            tx_index,
            refund,
            position,
            created_at: chain.leaves()[position as usize].created_at,
        })
        .unwrap_or(EscrowStatus::ResolvedWithoutRefund { tx_index })
}

fn decode(plain: &[u8]) -> Option<Recovered> {
    if plain.len() != PLAIN_BYTES {
        return None;
    }
    let u64_at = |at: usize| u64::from_le_bytes(plain[at..at + 8].try_into().expect("8 bytes"));
    let h_at = |at: usize| -> Hash { plain[at..at + 32].try_into().expect("32 bytes") };
    let escrow = EscrowNote {
        price: u64_at(0),
        fee_reserve: u64_at(8),
        recipient: Authority(h_at(16)),
        refund_to: Authority(h_at(48)),
        canceller: Authority(h_at(80)),
        seed: h_at(112),
        blinding: h_at(144),
    };
    let path_at = |at: usize| -> Option<KeyPath> {
        let field = &plain[at..at + PURPOSE_BYTES];
        let end = field.iter().position(|b| *b == 0).unwrap_or(PURPOSE_BYTES);
        if field[end..].iter().any(|b| *b != 0) {
            return None; // not zero-padded: not something this wallet wrote
        }
        let purpose = String::from_utf8(field[..end].to_vec()).ok()?;
        Some(KeyPath { purpose, index: u64_at(at + PURPOSE_BYTES) })
    };
    Some(Recovered {
        escrow,
        refund: path_at(ESCROW_BYTES)?,
        cancel: path_at(ESCROW_BYTES + PATH_BYTES)?,
    })
}

/// Every position at which a note with this commitment sits. A match alone
/// does not say *why* the note is there; to find an escrow's refund use
/// [`escrow_status`].
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
