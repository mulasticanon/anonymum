//! Domain-separated Poseidon over the BLS12-381 scalar field, natively and
//! as a constraint gadget. The permutation and sponge are arkworks'.
//!
//! Parameters (for the cryptographer to confirm): state width 5 (rate 4,
//! capacity 1), S-box `x^5`, 8 full and 60 partial rounds, round constants
//! and MDS matrix from the Grain LFSR in `ark-crypto-primitives`. These are
//! the width-5 figures published for a 255-bit field at a 128-bit target.
//!
//! Every hash absorbs a domain tag first. The tag is a BLAKE2s digest of the
//! label and the number of inputs, so two domains, or two arities of one
//! domain, never share an input encoding.

use std::sync::OnceLock;

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use blake2::{Blake2s256, Digest};

pub const RATE: usize = 4;
pub const CAPACITY: usize = 1;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 60;
pub const ALPHA: u64 = 5;

const DOMAIN_PREFIX: &[u8] = b"anonymum/shielded-circuit/poseidon-domain/v1";

/// The one Poseidon configuration this crate uses.
pub fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            u64::from(Fr::MODULUS_BIT_SIZE),
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

/// The field element that separates `label` with `arity` inputs.
pub fn domain_tag(label: &str, arity: usize) -> Fr {
    let mut hasher = Blake2s256::new();
    hasher.update((DOMAIN_PREFIX.len() as u64).to_le_bytes());
    hasher.update(DOMAIN_PREFIX);
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((arity as u64).to_le_bytes());
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

/// `H(label, inputs...)`.
pub fn hash(label: &str, inputs: &[Fr]) -> Fr {
    hash_with_tag(domain_tag(label, inputs.len()), inputs)
}

/// The sponge behind [`hash`], for a tag computed by the caller.
pub fn hash_with_tag(tag: Fr, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    let mut all = Vec::with_capacity(inputs.len() + 1);
    all.push(tag);
    all.extend_from_slice(inputs);
    sponge.absorb(&all);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// [`hash`] as constraints.
pub fn hash_var(cs: &ConstraintSystemRef<Fr>, label: &str, inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var_with_tag(cs, &FpVar::Constant(domain_tag(label, inputs.len())), inputs)
}

/// [`hash_with_tag`] as constraints. The tag may be a variable, which lets
/// one permutation serve several domains chosen by a selector.
pub fn hash_var_with_tag(
    cs: &ConstraintSystemRef<Fr>,
    tag: &FpVar<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), config());
    let mut all = Vec::with_capacity(inputs.len() + 1);
    all.push(tag.clone());
    all.extend_from_slice(inputs);
    sponge.absorb(&all)?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}
