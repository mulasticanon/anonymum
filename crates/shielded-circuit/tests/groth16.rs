//! Real Groth16 proofs for every branch, and the strict decoders.

use std::sync::OnceLock;

use anonymum_shielded_circuit::fixtures::*;
use anonymum_shielded_circuit::verifier::*;
use anonymum_shielded_circuit::*;
use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand_core::OsRng;

struct Keys {
    pk: ProvingKey<Bls12_381>,
    vk: VerifyingKey<Bls12_381>,
    pvk: PreparedVerifyingKey<Bls12_381>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let (pk, vk) = insecure_dev_setup(PARAMS, &mut OsRng).expect("setup");
        let pvk = prepare(&vk).expect("shape");
        Keys { pk, vk, pvk }
    })
}

fn proved(case: Case) -> (Built, Vec<u8>) {
    let built = build(case);
    let proof = prove(&keys().pk, built.circuit.clone(), &mut OsRng).expect("prove");
    let bytes = encode_proof(&proof);
    (built, bytes)
}

fn one_proof() -> &'static (Built, Vec<u8>) {
    static PROOF: OnceLock<(Built, Vec<u8>)> = OnceLock::new();
    PROOF.get_or_init(|| proved(Case::DeclineSurplus))
}

macro_rules! branch_proofs {
    ($($name:ident: $case:expr,)*) => {$(
        #[test]
        fn $name() {
            let (built, bytes) = proved($case);
            assert_eq!(bytes.len(), PROOF_LEN);
            assert_eq!(
                verify_transaction(&keys().pvk, &bytes, &built.circuit.public, &built.envelope),
                Ok(())
            );
        }
    )*};
}

branch_proofs! {
    proves_transfer: Case::Transfer,
    proves_invited_request: Case::Invited,
    proves_open: Case::Open,
    proves_claim_with_surplus: Case::ClaimSurplus,
    proves_claim_at_exact_fee: Case::ClaimExactFee,
    proves_claim_with_top_up: Case::ClaimTopUp,
    proves_decline_with_surplus: Case::DeclineSurplus,
    proves_decline_with_top_up: Case::DeclineTopUp,
    proves_sender_refund_with_surplus: Case::RefundSurplus,
    proves_sender_refund_with_top_up: Case::RefundTopUp,
}

// ---- (h) sighash and public inputs -----------------------------------------

#[test]
fn a_tampered_sighash_fails_the_proof_itself() {
    let (built, bytes) = one_proof();
    let mut public = built.circuit.public;
    public.sighash += Fr::one();
    assert_eq!(verify_strict(&keys().pvk, bytes, &public), Err(VerifyError::Rejected));
    assert_eq!(
        verify_transaction(&keys().pvk, bytes, &public, &built.envelope),
        Err(VerifyError::SighashMismatch)
    );
}

#[test]
fn every_part_of_the_envelope_changes_the_sighash() {
    let (built, bytes) = one_proof();
    let public = built.circuit.public;
    let alterations: [fn(&mut TxEnvelope); 5] = [
        |e| e.chain_id += 1,
        |e| e.version += 1,
        |e| e.coin_slots[0][17] ^= 1,
        |e| e.coin_slots[1][199] ^= 1,
        |e| e.stranger_note_hash[3] ^= 1,
    ];
    for alter in alterations {
        let mut envelope = built.envelope.clone();
        alter(&mut envelope);
        assert_eq!(
            verify_transaction(&keys().pvk, bytes, &public, &envelope),
            Err(VerifyError::SighashMismatch)
        );
    }
}

#[test]
fn the_sighash_covers_every_other_public_input() {
    let (built, _) = one_proof();
    let base = built.circuit.public;
    for index in 0..N_PUBLIC - 1 {
        let mut values = base.to_vec();
        values[index] += Fr::one();
        let changed = PublicInputs {
            root: values[0],
            nullifiers: [values[1], values[2]],
            commitments: [values[3], values[4], values[5]],
            admission: values[6],
            base_fee: values[7],
            not_before: values[8],
            not_after: values[9],
            sighash: values[10],
        };
        assert_ne!(changed.compute_sighash(&built.envelope), base.sighash, "input {index}");
    }
}

#[test]
fn every_public_input_is_bound_by_the_proof() {
    let (built, bytes) = one_proof();
    let proof = decode_proof(bytes).unwrap();
    let base = built.circuit.public.to_vec();
    assert_eq!(base.len(), N_PUBLIC);
    assert!(Groth16::<Bls12_381>::verify_proof(&keys().pvk, &proof, &base).unwrap());
    for index in 0..N_PUBLIC {
        let mut changed = base.clone();
        changed[index] += Fr::one();
        assert!(!Groth16::<Bls12_381>::verify_proof(&keys().pvk, &proof, &changed).unwrap(), "input {index}");
    }
}

#[test]
fn a_rerandomised_proof_is_valid_for_the_same_statement_only() {
    // Groth16 proofs are malleable as bytes, so they must never identify a
    // transaction. The statement, sighash included, cannot change.
    let (built, bytes) = one_proof();
    let proof = decode_proof(bytes).unwrap();
    let other = Groth16::<Bls12_381>::rerandomize_proof(&keys().vk, &proof, &mut OsRng);
    let other_bytes = encode_proof(&other);
    assert_ne!(&other_bytes, bytes);
    assert_eq!(verify_strict(&keys().pvk, &other_bytes, &built.circuit.public), Ok(()));
    let mut public = built.circuit.public;
    public.sighash += Fr::one();
    assert_eq!(verify_strict(&keys().pvk, &other_bytes, &public), Err(VerifyError::Rejected));
}

#[test]
fn a_proof_for_one_transaction_does_not_verify_for_another() {
    let (_, bytes) = one_proof();
    let other = build(Case::ClaimSurplus);
    assert_eq!(
        verify_transaction(&keys().pvk, bytes, &other.circuit.public, &other.envelope),
        Err(VerifyError::Rejected)
    );
}

#[test]
fn a_decline_and_a_sender_refund_share_one_public_statement() {
    // The branch is hidden: with the same outputs the two outcomes publish
    // identical inputs, so one proof verifies for both.
    let (decline, bytes) = one_proof();
    let refund = build(Case::RefundSurplus);
    assert_eq!(decline.circuit.public, refund.circuit.public);
    assert_eq!(verify_transaction(&keys().pvk, bytes, &refund.circuit.public, &refund.envelope), Ok(()));
}

#[test]
fn a_proof_under_another_key_is_rejected() {
    let (built, bytes) = one_proof();
    let (_, other_vk) = insecure_dev_setup(PARAMS, &mut OsRng).unwrap();
    let other = prepare(&other_vk).unwrap();
    assert_eq!(
        verify_transaction(&other, bytes, &built.circuit.public, &built.envelope),
        Err(VerifyError::Rejected)
    );
}

// ---- (i) strict decoding -----------------------------------------------------

/// A point on the G1 curve but outside the prime-order subgroup.
fn g1_outside_subgroup() -> G1Affine {
    (1u64..)
        .find_map(|x| {
            G1Affine::get_point_from_x_unchecked(Fq::from(x), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap()
}

/// A point on the G2 curve but outside the prime-order subgroup.
fn g2_outside_subgroup() -> G2Affine {
    (1u64..)
        .find_map(|x| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::one()), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap()
}

fn compressed(point: &impl CanonicalSerialize) -> Vec<u8> {
    let mut out = Vec::new();
    point.serialize_compressed(&mut out).unwrap();
    out
}

fn sample() -> [u8; PROOF_LEN] {
    one_proof().1.clone().try_into().unwrap()
}

#[test]
fn a_g1_point_outside_the_subgroup_is_refused_in_a_and_c() {
    let bad = compressed(&g1_outside_subgroup());
    assert_eq!(bad.len(), 48);
    for offset in [0, 144] {
        let mut bytes = sample();
        bytes[offset..offset + 48].copy_from_slice(&bad);
        // The hazard is real: without validation these bytes decode.
        assert!(Proof::<Bls12_381>::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::No).is_ok());
        assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::BadEncoding), "offset {offset}");
    }
}

#[test]
fn a_g2_point_outside_the_subgroup_is_refused_in_b() {
    let bad = compressed(&g2_outside_subgroup());
    assert_eq!(bad.len(), 96);
    let mut bytes = sample();
    bytes[48..144].copy_from_slice(&bad);
    assert!(Proof::<Bls12_381>::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::No).is_ok());
    assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::BadEncoding));
}

#[test]
fn an_x_with_no_curve_point_is_refused() {
    let x = (1u64..).find(|x| G1Affine::get_point_from_x_unchecked(Fq::from(*x), false).is_none()).unwrap();
    let mut encoded = Fq::from(x).into_bigint().to_bytes_be();
    encoded[0] |= 0x80; // the "compressed" flag
    let mut bytes = sample();
    bytes[..48].copy_from_slice(&encoded);
    assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::BadEncoding));
}

#[test]
fn an_x_at_or_above_the_modulus_is_refused() {
    let mut encoded = Fq::MODULUS.to_bytes_be();
    encoded[0] |= 0x80;
    let mut bytes = sample();
    bytes[..48].copy_from_slice(&encoded);
    assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::BadEncoding));
}

#[test]
fn an_uncompressed_flag_is_refused() {
    let mut bytes = sample();
    bytes[0] &= 0x7F;
    assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::BadEncoding));
}

#[test]
fn identity_points_are_refused() {
    let g1 = compressed(&G1Affine::zero());
    let g2 = compressed(&G2Affine::zero());
    for (offset, point) in [(0usize, &g1), (48, &g2), (144, &g1)] {
        let mut bytes = sample();
        bytes[offset..offset + point.len()].copy_from_slice(point);
        assert_eq!(decode_proof(&bytes).err(), Some(VerifyError::IdentityPoint), "offset {offset}");
    }
}

#[test]
fn wrong_lengths_are_refused() {
    let bytes = sample();
    assert_eq!(decode_proof(&bytes[..PROOF_LEN - 1]).err(), Some(VerifyError::BadLength));
    let mut long = bytes.to_vec();
    long.push(0);
    assert_eq!(decode_proof(&long).err(), Some(VerifyError::BadLength));
    assert_eq!(decode_proof(&[]).err(), Some(VerifyError::BadLength));
}

#[test]
fn a_bad_proof_never_reaches_the_pairing() {
    let (built, _) = one_proof();
    let mut bytes = sample();
    bytes[..48].copy_from_slice(&compressed(&g1_outside_subgroup()));
    assert_eq!(
        verify_transaction(&keys().pvk, &bytes, &built.circuit.public, &built.envelope),
        Err(VerifyError::BadEncoding)
    );
}

#[test]
fn a_flipped_proof_bit_is_refused() {
    let (built, _) = one_proof();
    for index in [5usize, 60, 150] {
        let mut bytes = sample();
        bytes[index] ^= 1;
        assert!(verify_strict(&keys().pvk, &bytes, &built.circuit.public).is_err(), "byte {index}");
    }
}

#[test]
fn public_inputs_decode_only_when_canonical() {
    let (built, _) = one_proof();
    let mut bytes = Vec::new();
    for x in built.circuit.public.to_vec() {
        x.serialize_compressed(&mut bytes).unwrap();
    }
    assert_eq!(decode_public_inputs(&bytes).unwrap(), built.circuit.public.to_vec());
    assert_eq!(decode_public_inputs(&bytes[1..]).err(), Some(VerifyError::BadLength));
    let modulus = Fr::MODULUS.to_bytes_le();
    bytes[..32].copy_from_slice(&modulus);
    assert_eq!(decode_public_inputs(&bytes).err(), Some(VerifyError::BadEncoding));
}

#[test]
fn the_verifying_key_round_trips_and_its_shape_is_checked() {
    let vk = &keys().vk;
    let bytes = compressed(vk);
    assert_eq!(decode_verifying_key(&bytes).unwrap(), *vk);
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(decode_verifying_key(&long).err(), Some(VerifyError::BadLength));

    let mut short = vk.clone();
    short.gamma_abc_g1.pop();
    assert_eq!(decode_verifying_key(&compressed(&short)).err(), Some(VerifyError::WrongKeyShape));
    assert_eq!(prepare(&short).err(), Some(VerifyError::WrongKeyShape));
}
