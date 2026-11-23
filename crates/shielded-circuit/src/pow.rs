//! The client's side of the shielded pallet's anti-spam proof of work.
//!
//! `BLAKE2s("anonymum/shielded-pow/v1" || sighash || root || nullifiers[0]
//! || nullifiers[1] || proof || nonce_le)` must start with at least
//! `difficulty` zero bits, counted from the first byte's high bit. The rule
//! itself lives in `substrate/pallets/anonymum-shielded`, whose tests compare
//! it with this code. It prices a submission; it proves nothing about the
//! transaction and is outside the circuit.

use blake2::{Blake2s256, Digest};

pub const POW_DOMAIN: &[u8] = b"anonymum/shielded-pow/v1";

fn prefix(sighash: &[u8; 32], root: &[u8; 32], nullifiers: &[[u8; 32]; 2], proof: &[u8; 192]) -> Blake2s256 {
    let mut hasher = Blake2s256::new();
    hasher.update(POW_DOMAIN);
    hasher.update(sighash);
    hasher.update(root);
    hasher.update(nullifiers[0]);
    hasher.update(nullifiers[1]);
    hasher.update(proof);
    hasher
}

pub fn pow_hash(sighash: &[u8; 32], root: &[u8; 32], nullifiers: &[[u8; 32]; 2], proof: &[u8; 192], nonce: u64) -> [u8; 32] {
    let mut hasher = prefix(sighash, root, nullifiers, proof);
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        bits += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    bits
}

/// The first nonce meeting `difficulty`, which must be at most 64.
pub fn solve_pow(sighash: &[u8; 32], root: &[u8; 32], nullifiers: &[[u8; 32]; 2], proof: &[u8; 192], difficulty: u32) -> u64 {
    assert!(difficulty <= 64, "a u64 nonce cannot be expected to reach this difficulty");
    let start = prefix(sighash, root, nullifiers, proof);
    (0..=u64::MAX)
        .find(|nonce| {
            let mut hasher = start.clone();
            hasher.update(nonce.to_le_bytes());
            leading_zero_bits(&hasher.finalize().into()) >= difficulty
        })
        .expect("a nonce exists at this difficulty with overwhelming probability; qed")
}
