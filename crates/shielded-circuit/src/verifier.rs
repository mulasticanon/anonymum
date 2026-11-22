//! Key generation (development only), proving, and the strict decoders a
//! verifier must use on untrusted bytes.
//!
//! RFC-0163's host functions do not check subgroup membership on decode, so
//! a chain must decode strictly first. [`decode_proof`] uses canonical
//! compressed deserialization with validation, which checks that each point
//! is on the curve and in the prime-order subgroup.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::AffineRepr;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Validate};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore};

use crate::circuit::{CircuitParams, ShieldedCircuit};
use crate::objects::{PublicInputs, TxEnvelope, N_PUBLIC};

/// Compressed proof: `A` (G1, 48), `B` (G2, 96), `C` (G1, 48).
pub const PROOF_LEN: usize = 192;
/// One canonical scalar.
pub const FR_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyError {
    /// Wrong length.
    BadLength,
    /// Not a canonical encoding of valid points or scalars in the right
    /// subgroup.
    BadEncoding,
    /// A proof element is the identity.
    IdentityPoint,
    /// The verifying key is not for this statement's 11 public inputs.
    WrongKeyShape,
    /// The public `sighash` is not the digest of this transaction.
    SighashMismatch,
    /// A well-formed proof that does not verify.
    Rejected,
}

impl From<SerializationError> for VerifyError {
    fn from(_: SerializationError) -> Self {
        VerifyError::BadEncoding
    }
}

/// **Development only.** One process generates the keys and briefly holds
/// the toxic waste, so whoever controls it could forge proofs. A real
/// network needs a multi-party ceremony.
pub fn insecure_dev_setup<R: RngCore + CryptoRng>(
    params: CircuitParams,
    rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), ark_relations::r1cs::SynthesisError> {
    Groth16::<Bls12_381>::setup(ShieldedCircuit::blank(params), rng)
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bls12_381>,
    circuit: ShieldedCircuit,
    rng: &mut R,
) -> Result<Proof<Bls12_381>, ark_relations::r1cs::SynthesisError> {
    Groth16::<Bls12_381>::prove(pk, circuit, rng)
}

pub fn encode_proof(proof: &Proof<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROOF_LEN);
    proof.serialize_compressed(&mut out).expect("writing to a Vec cannot fail");
    out
}

/// Decode untrusted proof bytes: exact length, canonical compressed points,
/// on the curve, in the prime-order subgroup, none the identity.
pub fn decode_proof(bytes: &[u8]) -> Result<Proof<Bls12_381>, VerifyError> {
    if bytes.len() != PROOF_LEN {
        return Err(VerifyError::BadLength);
    }
    let proof = Proof::<Bls12_381>::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)?;
    if proof.a.is_zero() || proof.b.is_zero() || proof.c.is_zero() {
        return Err(VerifyError::IdentityPoint);
    }
    if encode_proof(&proof) != bytes {
        return Err(VerifyError::BadEncoding);
    }
    Ok(proof)
}

/// Decode a verifying key with the same validation, and check its shape.
pub fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bls12_381>, VerifyError> {
    let mut reader = bytes;
    let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)?;
    if !reader.is_empty() {
        return Err(VerifyError::BadLength);
    }
    if vk.gamma_abc_g1.len() != N_PUBLIC + 1 {
        return Err(VerifyError::WrongKeyShape);
    }
    Ok(vk)
}

/// Decode `N_PUBLIC` canonical scalars; a value at or above the modulus is
/// refused rather than reduced.
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, VerifyError> {
    if bytes.len() != N_PUBLIC * FR_LEN {
        return Err(VerifyError::BadLength);
    }
    bytes
        .chunks_exact(FR_LEN)
        .map(|chunk| Fr::deserialize_with_mode(chunk, Compress::Yes, Validate::Yes).map_err(VerifyError::from))
        .collect()
}

pub fn prepare(vk: &VerifyingKey<Bls12_381>) -> Result<PreparedVerifyingKey<Bls12_381>, VerifyError> {
    if vk.gamma_abc_g1.len() != N_PUBLIC + 1 {
        return Err(VerifyError::WrongKeyShape);
    }
    Ok(prepare_verifying_key(vk))
}

/// What a chain should call: recompute `sighash` from the transaction's own
/// bytes, then [`verify_strict`]. The other chain-side checks (accepted
/// root, unused and distinct nullifiers, window) are still the caller's.
pub fn verify_transaction(
    pvk: &PreparedVerifyingKey<Bls12_381>,
    proof_bytes: &[u8],
    public: &PublicInputs,
    envelope: &TxEnvelope,
) -> Result<(), VerifyError> {
    if public.compute_sighash(envelope) != public.sighash {
        return Err(VerifyError::SighashMismatch);
    }
    verify_strict(pvk, proof_bytes, public)
}

/// Strictly decode `proof_bytes` and verify them against `public`.
pub fn verify_strict(
    pvk: &PreparedVerifyingKey<Bls12_381>,
    proof_bytes: &[u8],
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    let proof = decode_proof(proof_bytes)?;
    if pvk.vk.gamma_abc_g1.len() != N_PUBLIC + 1 {
        return Err(VerifyError::WrongKeyShape);
    }
    match Groth16::<Bls12_381>::verify_with_processed_vk(pvk, &public.to_vec(), &proof) {
        Ok(true) => Ok(()),
        _ => Err(VerifyError::Rejected),
    }
}
