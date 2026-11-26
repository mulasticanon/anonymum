//! What the chain computes outside the circuit, byte for byte the same as
//! `crates/shielded-circuit`: Poseidon, the Merkle frontier, the two BLAKE2s
//! digests, and the strict decoders. `no_std`. Unit tests compare each one
//! against that crate.

use alloc::{format, vec::Vec};

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use blake2::{Blake2s256, Digest};

use crate::poseidon_constants::{ARK, MDS};

pub const TREE_DEPTH: usize = 20;
pub const N_PUBLIC: usize = 11;
pub const PROOF_LEN: usize = 192;
pub const COIN_PAYLOAD_LEN: usize = 200;
pub const STRANGER_NOTE_LEN: u32 = 1_795;
/// How long a stranger note is kept, from the start of its window.
pub const NOTE_TTL_SECS: u64 = 24 * 60 * 60;
/// Largest stored verifying key (uncompressed, 11 public inputs).
pub const MAX_VK_LEN: u32 = 2_048;

pub type Bytes32 = [u8; 32];

const DOMAIN_PREFIX: &[u8] = b"anonymum/shielded-circuit/poseidon-domain/v1";

fn fr_constant(limbs: &[u64; 4]) -> Fr {
    Fr::from_bigint(BigInt::new(*limbs)).expect("generated constants are below the modulus; qed")
}

/// Domain-separated Poseidon with this crate's precomputed parameters.
pub struct Poseidon {
    config: PoseidonConfig<Fr>,
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon {
    pub fn new() -> Self {
        let ark = ARK.iter().map(|row| row.iter().map(fr_constant).collect()).collect();
        let mds = MDS.iter().map(|row| row.iter().map(fr_constant).collect()).collect();
        Poseidon { config: PoseidonConfig::new(8, 60, 5, mds, ark, 4, 1) }
    }

    #[cfg(test)]
    pub fn config(&self) -> &PoseidonConfig<Fr> {
        &self.config
    }

    pub fn hash(&self, label: &str, inputs: &[Fr]) -> Fr {
        let mut sponge = PoseidonSponge::new(&self.config);
        let mut all = Vec::with_capacity(inputs.len() + 1);
        all.push(domain_tag(label, inputs.len()));
        all.extend_from_slice(inputs);
        sponge.absorb(&all);
        sponge.squeeze_field_elements::<Fr>(1)[0]
    }

    pub fn leaf(&self, commitment: Fr, created_at: u64) -> Fr {
        self.hash("leaf", &[commitment, Fr::from(created_at)])
    }

    /// The commitment of an ordinary note, `H("commit", 0, value, 0, owner,
    /// 0, 0, 0, blinding)`: the circuit's `Note::ordinary(..).commitment()`.
    pub fn ordinary_commitment(&self, value: u64, owner: Fr, blinding: Fr) -> Fr {
        let z = Fr::from(0u64);
        self.hash("commit", &[z, Fr::from(value), z, owner, z, z, z, blinding])
    }

    pub fn node(&self, level: usize, left: Fr, right: Fr) -> Fr {
        self.hash(&format!("merkle/{level}"), &[left, right])
    }

    /// `zero[l]`: the root of an empty subtree of height `l`.
    pub fn empty_subtrees(&self) -> [Fr; TREE_DEPTH + 1] {
        let mut zero = [domain_tag("merkle/empty-leaf", 0); TREE_DEPTH + 1];
        for level in 0..TREE_DEPTH {
            zero[level + 1] = self.node(level, zero[level], zero[level]);
        }
        zero
    }

    /// Add the leaf at `index` to the frontier; returns the new root.
    pub fn append(
        &self,
        frontier: &mut [Fr; TREE_DEPTH],
        zero: &[Fr; TREE_DEPTH + 1],
        index: u64,
        leaf: Fr,
    ) -> Fr {
        let mut current = leaf;
        for level in 0..TREE_DEPTH {
            current = if (index >> level) & 1 == 0 {
                frontier[level] = current;
                self.node(level, current, zero[level])
            } else {
                self.node(level, frontier[level], current)
            };
        }
        current
    }
}

pub fn domain_tag(label: &str, arity: usize) -> Fr {
    let mut hasher = Blake2s256::new();
    hasher.update((DOMAIN_PREFIX.len() as u64).to_le_bytes());
    hasher.update(DOMAIN_PREFIX);
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((arity as u64).to_le_bytes());
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

/// `H("stranger-note-slot", slot)`, the model's permanent slot hash.
pub fn stranger_note_hash(slot: &[u8]) -> Bytes32 {
    let tag: &[u8] = b"anonymum/shielded-model/v0/stranger-note-slot";
    let mut hasher = Blake2s256::new();
    hasher.update((tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update((slot.len() as u64).to_le_bytes());
    hasher.update(slot);
    hasher.finalize().into()
}

/// The ten public inputs before the sighash, in circuit order.
pub struct SighashInputs<'a> {
    pub chain_id: u32,
    pub version: u32,
    pub fields: &'a [Fr; N_PUBLIC - 1],
    pub coin_slots: &'a [[u8; COIN_PAYLOAD_LEN]; 2],
    pub stranger_note_hash: &'a Bytes32,
}

/// The whole-transaction digest, reduced into `Fr`.
pub fn compute_sighash(tx: &SighashInputs) -> Fr {
    fn part(hasher: &mut Blake2s256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Blake2s256::new();
    part(&mut hasher, b"anonymum/shielded-circuit/sighash/v1");
    part(&mut hasher, &tx.chain_id.to_le_bytes());
    part(&mut hasher, &tx.version.to_le_bytes());
    for field in tx.fields {
        part(&mut hasher, &field.into_bigint().to_bytes_le());
    }
    for slot in tx.coin_slots {
        part(&mut hasher, slot);
    }
    part(&mut hasher, tx.stranger_note_hash);
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

/// Domain label of the anti-spam proof of work.
pub const POW_DOMAIN: &[u8] = b"anonymum/shielded-pow/v1";
/// Highest allowed difficulty: the nonce is a `u64`.
pub const MAX_POW_DIFFICULTY: u32 = 64;

/// The proof-of-work hash. It covers the proof bytes, so one solution cannot
/// be reused across many different invalid proofs, and the root, so work
/// cannot be done long in advance.
pub fn pow_hash(sighash: &Bytes32, root: &Bytes32, nullifiers: &[Bytes32; 2], proof: &[u8; PROOF_LEN], nonce: u64) -> Bytes32 {
    let mut hasher = Blake2s256::new();
    hasher.update(POW_DOMAIN);
    hasher.update(sighash);
    hasher.update(root);
    hasher.update(nullifiers[0]);
    hasher.update(nullifiers[1]);
    hasher.update(proof);
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Zero bits at the start of `hash`, from the first byte's high bit.
pub fn leading_zero_bits(hash: &Bytes32) -> u32 {
    let mut bits = 0;
    for byte in hash {
        bits += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    bits
}

/// A canonical scalar: a value at or above the modulus is refused, never
/// reduced, so one nullifier cannot have two encodings.
pub fn decode_fr(bytes: &Bytes32) -> Option<Fr> {
    Fr::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes).ok()
}

pub fn encode_fr(x: &Fr) -> Bytes32 {
    let mut out = [0u8; 32];
    x.serialize_compressed(&mut out[..]).expect("a scalar is 32 bytes; qed");
    out
}

/// Canonical compressed decoding: on the curve, in the prime-order
/// subgroup, not the identity, and re-encoding to the same bytes.
pub fn decode_proof(bytes: &[u8; PROOF_LEN]) -> Option<Proof<Bls12_381>> {
    let proof = Proof::<Bls12_381>::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes).ok()?;
    if proof.a.is_zero() || proof.b.is_zero() || proof.c.is_zero() {
        return None;
    }
    let mut again = [0u8; PROOF_LEN];
    proof.serialize_compressed(&mut again[..]).ok()?;
    (again == *bytes).then_some(proof)
}

/// Validate a compressed key once, at genesis, and return the uncompressed
/// form that is stored, so each transaction skips point decompression.
pub fn prepare_stored_key(compressed: &[u8]) -> Option<Vec<u8>> {
    let mut reader = compressed;
    let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes).ok()?;
    if !reader.is_empty() || vk.gamma_abc_g1.len() != N_PUBLIC + 1 {
        return None;
    }
    let mut out = Vec::new();
    vk.serialize_uncompressed(&mut out).ok()?;
    (out.len() <= MAX_VK_LEN as usize).then_some(out)
}

/// Verify against the stored key, which was validated at genesis.
pub fn verify(stored_key: &[u8], proof: &Proof<Bls12_381>, inputs: &[Fr; N_PUBLIC]) -> bool {
    let Ok(vk) = VerifyingKey::<Bls12_381>::deserialize_with_mode(stored_key, Compress::No, Validate::No) else {
        return false;
    };
    if vk.gamma_abc_g1.len() != N_PUBLIC + 1 {
        return false;
    }
    Groth16::<Bls12_381>::verify_proof(&prepare_verifying_key(&vk), proof, inputs).unwrap_or(false)
}
