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
//! decryption attempt per coin-note payload slot (spec v0.5, I11). How the
//! key is derived is a model choice, not a reviewed design (spec question 9).
//!
//! The copy fits one 200-byte coin slot: it records the escrow's price,
//! reserve, recipient, seed and blinding plus the two key paths, but not the
//! refund and cancel authorities, which the wallet re-derives from the paths
//! (they are checked against the escrow commitment when it is found).
//!
//! The plaintext starts with a version byte naming the copy's layout *and*
//! the key-derivation scheme ([`RECOVERY_VERSION`]). A copy of any other
//! version is refused with [`RecoveryError::UnsupportedVersion`], never read
//! with the wrong layout or derivation.
//!
//! # Recovery copy layout, version 1 (exactly 200 bytes)
//!
//! ```text
//! offset  len  field
//!      0   12  nonce (fresh, random; in the clear)
//!     12  172  ChaCha20-Poly1305 ciphertext of the plaintext below
//!    184   16  authentication tag
//!
//! plaintext (172 bytes)
//!      0    1  version (1)
//!      1    8  price, u64 little-endian
//!      9    8  fee reserve, u64 little-endian
//!     17   32  recipient authority
//!     49   32  escrow seed
//!     81   32  escrow blinding
//!    113   16  refund key purpose, UTF-8, zero-padded
//!    129    8  refund key index, u64 little-endian
//!    137   16  cancel key purpose, UTF-8, zero-padded
//!    153    8  cancel key index, u64 little-endian
//!    161   11  zero (spare: the remaining headroom)
//! ```
//!
//! Version 1 derives a key as `H("wallet/secret", master, purpose, index)`
//! and the copy's key as `H("wallet/recovery-key", master)`.

use std::collections::HashSet;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::chain::{Chain, COIN_PAYLOAD_LEN, N_COIN};
use crate::hash::{h, Hash};
use crate::objects::*;

const NONCE_BYTES: usize = 12;
/// The recovery copy's format and key-derivation version.
pub const RECOVERY_VERSION: u8 = 1;
const VERSION_BYTES: usize = 1;
/// Price, fee reserve, recipient, seed, blinding (the authorities are
/// re-derived from the key paths).
const ESCROW_BYTES: usize = 8 + 8 + 32 * 3;
const PURPOSE_BYTES: usize = 16;
const PATH_BYTES: usize = PURPOSE_BYTES + 8;
const TAG_BYTES: usize = 16;
/// Where the escrow fields start in the plaintext.
const ESCROW_AT: usize = VERSION_BYTES;
const PATHS_AT: usize = ESCROW_AT + ESCROW_BYTES;
const PAD_AT: usize = PATHS_AT + 2 * PATH_BYTES;
/// Spare zero bytes left in the 200-byte slot.
pub const RECOVERY_HEADROOM: usize = COIN_PAYLOAD_LEN - NONCE_BYTES - TAG_BYTES - PAD_AT;
const PAD_BYTES: usize = RECOVERY_HEADROOM;
const PLAIN_BYTES: usize = PAD_AT + PAD_BYTES;
const _: () = assert!(RECOVERY_HEADROOM == 11 && PLAIN_BYTES == 172);
const _: () = assert!(
    NONCE_BYTES + PLAIN_BYTES + TAG_BYTES == COIN_PAYLOAD_LEN,
    "a recovery copy (nonce + sealed escrow fields and key paths) fills one coin slot"
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
    /// The refund path is not a one-time refund key ([`REFUND_PURPOSE`]),
    /// or names the same key as the cancel path: a long-term or shared key
    /// as `refund_to` would link escrows to each other (I13, review H5).
    NotAOneTimeRefundKey,
    /// The refund key is already the `refund_to` of another escrow of this
    /// wallet on the chain.
    RefundKeyReused,
    /// No refund index is left above the highest one in use.
    KeysExhausted,
    /// The path does not derive the authority the escrow names.
    PathDoesNotMatch,
    /// Not this wallet's copy: wrong size, or it does not decrypt under
    /// this wallet's recovery key.
    NotThisWallet,
    /// This wallet's copy, but of a format and key-derivation version this
    /// code does not know. Nothing is derived from it.
    UnsupportedVersion(u8),
    /// This wallet's copy and version, but not well formed (padding or a
    /// key path this code would never have written).
    Malformed,
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
    /// Claimed by `tx_index`, whose outputs include the derived surplus of
    /// the fee reserve, returned to the sender (I8).
    ClaimedWithSurplus { tx_index: usize, surplus: Note, position: u64, created_at: Time },
}

impl EscrowStatus {
    /// The note owed to the sender that this resolution created, if any:
    /// the refund, or a claim's fee surplus. `(note, position, created_at)`.
    pub fn sender_note(&self) -> Option<(Note, u64, Time)> {
        match *self {
            EscrowStatus::Refunded { refund: n, position, created_at, .. }
            | EscrowStatus::ClaimedWithSurplus { surplus: n, position, created_at, .. } => Some((n, position, created_at)),
            _ => None,
        }
    }
}

/// The key purpose of a one-time refund identity. Each escrow gets its own
/// index under it, so no two escrows share a `refund_to` (I13, H5).
pub const REFUND_PURPOSE: &str = "refund";
/// The key purpose of an escrow's cancel authority.
pub const CANCEL_PURPOSE: &str = "cancel";

/// A new escrow as a wallet prepares it: the note, the paths of its fresh
/// refund and cancel keys, and the recovery copy for a coin slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedEscrow {
    pub escrow: EscrowNote,
    pub refund: KeyPath,
    pub cancel: KeyPath,
    pub recovery_copy: Vec<u8>,
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
        if [refund, cancel].iter().any(|path| path.purpose.len() > PURPOSE_BYTES) {
            return Err(RecoveryError::PurposeTooLong);
        }
        // The refund identity is a one-time key of its own (I13, H5).
        if refund.purpose != REFUND_PURPOSE || escrow.refund_to == escrow.canceller {
            return Err(RecoveryError::NotAOneTimeRefundKey);
        }
        let mut plain = Vec::with_capacity(PLAIN_BYTES);
        plain.push(RECOVERY_VERSION);
        plain.extend_from_slice(&escrow.price.to_le_bytes());
        plain.extend_from_slice(&escrow.fee_reserve.to_le_bytes());
        for part in [&escrow.recipient.0, &escrow.seed, &escrow.blinding] {
            plain.extend_from_slice(part);
        }
        for path in [refund, cancel] {
            let purpose = path.purpose.as_bytes(); // length checked above
            let mut field = [0u8; PURPOSE_BYTES];
            field[..purpose.len()].copy_from_slice(purpose);
            plain.extend_from_slice(&field);
            plain.extend_from_slice(&path.index.to_le_bytes());
        }
        plain.extend_from_slice(&[0u8; PAD_BYTES]);
        debug_assert_eq!(plain.len(), PLAIN_BYTES);
        Ok(self.seal_plain(&plain, nonce))
    }

    fn seal_plain(&self, plain: &[u8], nonce: [u8; NONCE_BYTES]) -> Vec<u8> {
        let sealed =
            self.recovery_cipher().encrypt(Nonce::from_slice(&nonce), plain).expect("encryption of a fixed-size buffer");
        [nonce.as_slice(), &sealed].concat()
    }

    /// One decryption attempt: is this payload slot one of this wallet's
    /// recovery copies? Only a known version is read; the refund and cancel
    /// authorities are derived from its key paths with that version's
    /// scheme.
    pub fn open_recovery(&self, slot: &[u8]) -> Result<Recovered, RecoveryError> {
        if slot.len() != COIN_PAYLOAD_LEN {
            return Err(RecoveryError::NotThisWallet);
        }
        let (nonce, sealed) = slot.split_at(NONCE_BYTES);
        let plain = self
            .recovery_cipher()
            .decrypt(Nonce::from_slice(nonce), sealed)
            .map_err(|_| RecoveryError::NotThisWallet)?;
        self.decode(&plain)
    }

    /// Every escrow this wallet opened that the chain holds, recovered from
    /// the chain alone: one decryption attempt per coin-note slot. Fails if
    /// one of this wallet's own copies cannot be read (an unknown version
    /// or a malformed copy), rather than report an incomplete list.
    pub fn recover_escrows(&self, chain: &Chain) -> Result<Vec<Recovered>, RecoveryError> {
        let on_chain: HashSet<Commitment> = chain.leaves().iter().map(|l| l.commitment).collect();
        self.scan(chain.log().iter().flat_map(|tx| tx.payloads[..N_COIN].iter()), &on_chain)
    }

    /// Try every slot; keep this wallet's escrows that are on chain.
    fn scan<'a>(
        &self,
        slots: impl IntoIterator<Item = &'a Vec<u8>>,
        on_chain: &HashSet<Commitment>,
    ) -> Result<Vec<Recovered>, RecoveryError> {
        let mut found: Vec<Recovered> = Vec::new();
        for slot in slots {
            match self.open_recovery(slot) {
                Ok(r) => {
                    if on_chain.contains(&Note::Escrow(r.escrow).commitment()) && !found.contains(&r) {
                        found.push(r);
                    }
                }
                Err(RecoveryError::NotThisWallet) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(found)
    }

    /// The state of every inserted copy of a recovered escrow, including
    /// whether a note this wallet is owed (a refund, or a claim's fee
    /// surplus) is still unspent.
    pub fn refund_states(&self, chain: &Chain, recovered: &Recovered) -> Vec<RefundState> {
        let owner = self.secret_at(&recovered.refund);
        escrow_positions(chain, &recovered.escrow)
            .into_iter()
            .map(|escrow_position| {
                let status = escrow_status(chain, &recovered.escrow, escrow_position);
                let refund_spent = status
                    .sender_note()
                    .map(|(note, position, _)| chain.is_spent(&ordinary_nullifier(&owner, &note.commitment(), position)));
                RefundState { escrow_position, status, refund_spent }
            })
            .collect()
    }

    /// The refund and cancel paths for this wallet's next escrow: index one
    /// above the highest refund index any of its escrows on `chain` uses,
    /// so a restored wallet never hands out a refund key twice.
    pub fn next_escrow_keys(&self, chain: &Chain) -> Result<(KeyPath, KeyPath), RecoveryError> {
        let used = self.recover_escrows(chain)?;
        let index = match used.iter().filter(|r| r.refund.purpose == REFUND_PURPOSE).map(|r| r.refund.index).max() {
            None => 0,
            Some(top) => top.checked_add(1).ok_or(RecoveryError::KeysExhausted)?,
        };
        Ok((KeyPath::new(REFUND_PURPOSE, index), KeyPath::new(CANCEL_PURPOSE, index)))
    }

    /// Prepare an escrow to `recipient` with a fresh one-time refund key
    /// and its own cancel key, and seal its recovery copy. Refuses a refund
    /// key some escrow of this wallet on `chain` already uses (so even a
    /// caller who picks the paths by hand cannot link two escrows).
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_escrow(
        &self,
        chain: &Chain,
        keys: (KeyPath, KeyPath),
        price: Value,
        fee_reserve: Value,
        recipient: Authority,
        seed: Hash,
        blinding: Hash,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<PreparedEscrow, RecoveryError> {
        let (refund, cancel) = keys;
        let refund_to = self.secret_at(&refund).authority();
        if self.recover_escrows(chain)?.iter().any(|r| r.escrow.refund_to == refund_to) {
            return Err(RecoveryError::RefundKeyReused);
        }
        let escrow = EscrowNote {
            price,
            fee_reserve,
            recipient,
            refund_to,
            canceller: self.secret_at(&cancel).authority(),
            seed,
            blinding,
        };
        let recovery_copy = self.seal_recovery(&escrow, &refund, &cancel, nonce)?;
        Ok(PreparedEscrow { escrow, refund, cancel, recovery_copy })
    }
}

/// Every tree position at which this escrow's commitment was inserted.
pub fn escrow_positions(chain: &Chain, escrow: &EscrowNote) -> Vec<u64> {
    let c = Note::Escrow(*escrow).commitment();
    chain.leaves().iter().enumerate().filter(|(_, l)| l.commitment == c).map(|(i, _)| i as u64).collect()
}

/// Where the escrow at `escrow_position` stands: find the finalised
/// transaction that consumed its nullifier, then look for the derived
/// refund, or a claim's derived fee surplus, among *that transaction's
/// outputs only*. Both depend on the base fee that transaction paid, which
/// is public. An identical commitment anywhere else in history proves
/// nothing about this escrow.
pub fn escrow_status(chain: &Chain, escrow: &EscrowNote, escrow_position: u64) -> EscrowStatus {
    let commitment = Note::Escrow(*escrow).commitment();
    let nullifier = escrow_nullifier(&escrow.seed, &commitment, escrow_position);
    let Some(tx_index) = chain.transaction_spending(&nullifier) else {
        return EscrowStatus::Unresolved;
    };
    let fee = chain.log()[tx_index].base_fee;
    let find = |note: &Note| {
        let c = note.commitment();
        chain
            .output_positions(tx_index)
            .find(|&p| chain.leaves()[p as usize].commitment == c)
            .map(|position| (position, chain.leaves()[position as usize].created_at))
    };
    let refund = derived_refund(escrow, escrow_position, fee);
    if let Some((position, created_at)) = find(&refund) {
        return EscrowStatus::Refunded { tx_index, refund, position, created_at };
    }
    if let Some(surplus) = derived_claim_surplus(escrow, escrow_position, fee) {
        if let Some((position, created_at)) = find(&surplus) {
            return EscrowStatus::ClaimedWithSurplus { tx_index, surplus, position, created_at };
        }
    }
    EscrowStatus::ResolvedWithoutRefund { tx_index }
}

impl Wallet {
    /// The escrow and key paths in a recovery copy's plaintext; the refund
    /// and cancel authorities are derived from the paths.
    fn decode(&self, plain: &[u8]) -> Result<Recovered, RecoveryError> {
        // The version first: nothing else is read under an unknown layout
        // or derivation scheme.
        match plain.first() {
            Some(&RECOVERY_VERSION) => {}
            Some(&other) => return Err(RecoveryError::UnsupportedVersion(other)),
            None => return Err(RecoveryError::Malformed),
        }
        if plain.len() != PLAIN_BYTES || plain[PAD_AT..].iter().any(|b| *b != 0) {
            return Err(RecoveryError::Malformed);
        }
        let u64_at = |at: usize| u64::from_le_bytes(plain[at..at + 8].try_into().expect("8 bytes"));
        let h_at = |at: usize| -> Hash { plain[at..at + 32].try_into().expect("32 bytes") };
        let path_at = |at: usize| -> Result<KeyPath, RecoveryError> {
            let field = &plain[at..at + PURPOSE_BYTES];
            let end = field.iter().position(|b| *b == 0).unwrap_or(PURPOSE_BYTES);
            if field[end..].iter().any(|b| *b != 0) {
                return Err(RecoveryError::Malformed); // not zero-padded: not something this wallet wrote
            }
            let purpose = String::from_utf8(field[..end].to_vec()).map_err(|_| RecoveryError::Malformed)?;
            Ok(KeyPath { purpose, index: u64_at(at + PURPOSE_BYTES) })
        };
        let refund = path_at(PATHS_AT)?;
        let cancel = path_at(PATHS_AT + PATH_BYTES)?;
        let e = ESCROW_AT;
        let escrow = EscrowNote {
            price: u64_at(e),
            fee_reserve: u64_at(e + 8),
            recipient: Authority(h_at(e + 16)),
            refund_to: self.secret_at(&refund).authority(),
            canceller: self.secret_at(&cancel).authority(),
            seed: h_at(e + 48),
            blinding: h_at(e + 80),
        };
        Ok(Recovered { escrow, refund, cancel })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn escrow_of(wallet: &Wallet, refund: &KeyPath, cancel: &KeyPath) -> EscrowNote {
        EscrowNote {
            price: 1_000,
            fee_reserve: 10,
            recipient: Authority([0x11; 32]),
            refund_to: wallet.secret_at(refund).authority(),
            canceller: wallet.secret_at(cancel).authority(),
            seed: [0x22; 32],
            blinding: [0x33; 32],
        }
    }

    #[test]
    fn a_v1_copy_re_derives_refund_and_cancel_authorities_matching_the_escrow() {
        let wallet = Wallet::from_backup([0x42; 32]);
        let (refund, cancel) = (KeyPath::new("refund", 7), KeyPath::new("cancel", 9));
        let escrow = escrow_of(&wallet, &refund, &cancel);
        let slot = wallet.seal_recovery(&escrow, &refund, &cancel, [0x5C; NONCE_BYTES]).unwrap();
        assert_eq!(slot.len(), COIN_PAYLOAD_LEN);
        let plain = wallet.recovery_cipher().decrypt(Nonce::from_slice(&slot[..NONCE_BYTES]), &slot[NONCE_BYTES..]).unwrap();
        assert_eq!((plain.len(), plain[0]), (PLAIN_BYTES, RECOVERY_VERSION));
        assert!(plain[PAD_AT..].iter().all(|b| *b == 0) && plain.len() - PAD_AT == RECOVERY_HEADROOM);
        // A restored wallet (same backup) gets the same escrow back, with
        // authorities derived from the paths, so its commitment matches.
        let restored = Wallet::from_backup([0x42; 32]);
        let opened = restored.open_recovery(&slot).unwrap();
        assert_eq!(opened, Recovered { escrow, refund, cancel });
        assert_eq!(Note::Escrow(opened.escrow).commitment(), Note::Escrow(escrow).commitment());
        // Another wallet cannot read it.
        assert_eq!(Wallet::from_backup([0x43; 32]).open_recovery(&slot), Err(RecoveryError::NotThisWallet));
    }

    #[test]
    fn a_copy_with_an_unsupported_version_byte_is_refused() {
        let wallet = Wallet::from_backup([0x42; 32]);
        let (refund, cancel) = (KeyPath::new("refund", 0), KeyPath::new("cancel", 0));
        let slot = wallet.seal_recovery(&escrow_of(&wallet, &refund, &cancel), &refund, &cancel, [1; NONCE_BYTES]).unwrap();
        let plain = wallet.recovery_cipher().decrypt(Nonce::from_slice(&slot[..NONCE_BYTES]), &slot[NONCE_BYTES..]).unwrap();
        for version in [0u8, 2, 0xFF] {
            let mut other = plain.clone();
            other[0] = version;
            let resealed = wallet.seal_plain(&other, [2; NONCE_BYTES]);
            assert_eq!(wallet.open_recovery(&resealed), Err(RecoveryError::UnsupportedVersion(version)));
        }
        // Control: the same bytes resealed with version 1 still open.
        assert!(wallet.open_recovery(&wallet.seal_plain(&plain, [3; NONCE_BYTES])).is_ok());
        // A scan that meets one of this wallet's own copies in an unknown
        // version fails instead of returning an incomplete list.
        let escrow = escrow_of(&wallet, &refund, &cancel);
        let on_chain: HashSet<Commitment> = [Note::Escrow(escrow).commitment()].into();
        let mut v2 = plain.clone();
        v2[0] = 2;
        let noise = vec![0u8; COIN_PAYLOAD_LEN];
        assert_eq!(wallet.scan([&slot, &noise], &on_chain), Ok(vec![Recovered { escrow, refund: refund.clone(), cancel: cancel.clone() }]));
        assert_eq!(
            wallet.scan([&slot, &noise, &wallet.seal_plain(&v2, [6; NONCE_BYTES])], &on_chain),
            Err(RecoveryError::UnsupportedVersion(2))
        );
        // Non-zero spare bytes are refused too.
        let mut padded = plain.clone();
        padded[PLAIN_BYTES - 1] = 1;
        assert_eq!(wallet.open_recovery(&wallet.seal_plain(&padded, [4; NONCE_BYTES])), Err(RecoveryError::Malformed));
    }
}
