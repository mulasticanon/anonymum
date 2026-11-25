//! Real Groth16 proofs from `crates/shielded-circuit`, submitted to the
//! pallet. Every refusal is `assert_noop!`, which compares the storage root.

use crate::mock::*;
use crate::pallet::*;
use crate::primitives::*;
use anonymum_shielded_circuit as circuit;
use anonymum_shielded_circuit::fixtures::{self, Built, Case};
use anonymum_shielded_circuit::verifier::{encode_proof, prove};
use anonymum_shielded_circuit::{Bls12_381, Fr, MerkleTree};
use anonymum_shielded_model as model;
use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use frame::deps::frame_support::{assert_noop, assert_ok, traits::Hooks};
use frame::deps::sp_runtime::transaction_validity::{InvalidTransaction, TransactionSource};
use frame::deps::frame_support::dispatch::GetDispatchInfo;
use frame::deps::frame_support::traits::Authorize;
use frame::deps::sp_runtime::traits::DispatchTransaction;
use frame::deps::sp_runtime::transaction_validity::{TransactionValidityError, ValidTransaction};
use frame::deps::sp_runtime::DispatchError;
use polkadot_sdk::frame_system::AuthorizeCall;
use polkadot_sdk::polkadot_sdk_frame as frame;
use rand_core::OsRng;
use std::sync::OnceLock;

type E = Error<Test>;

/// One transaction's call arguments.
#[derive(Clone)]
struct Tx {
    root: Bytes32,
    nullifiers: [Bytes32; 2],
    commitments: [Bytes32; 3],
    admission: Bytes32,
    not_before: u64,
    not_after: u64,
    coin: [[u8; 200]; 2],
    note: Vec<u8>,
    proof: [u8; 192],
    /// `None` solves the proof of work for the current fields.
    pow_nonce: Option<u64>,
}

impl Tx {
    /// The sighash the chain would compute, if every field is canonical.
    fn sighash(&self) -> Option<Bytes32> {
        let fields: [Fr; N_PUBLIC - 1] = [
            decode_fr(&self.root)?,
            decode_fr(&self.nullifiers[0])?,
            decode_fr(&self.nullifiers[1])?,
            decode_fr(&self.commitments[0])?,
            decode_fr(&self.commitments[1])?,
            decode_fr(&self.commitments[2])?,
            decode_fr(&self.admission)?,
            Fr::from(BaseFee::<Test>::get()),
            Fr::from(self.not_before),
            Fr::from(self.not_after),
        ];
        Some(encode_fr(&compute_sighash(&SighashInputs {
            chain_id: CHAIN_ID,
            version: TX_VERSION,
            fields: &fields,
            coin_slots: &self.coin,
            stranger_note_hash: &stranger_note_hash(&self.note),
        })))
    }

    fn nonce(&self) -> u64 {
        self.pow_nonce.unwrap_or_else(|| {
            self.sighash().map_or(0, |s| {
                circuit::pow::solve_pow(&s, &self.root, &self.nullifiers, &self.proof, PowBits::get())
            })
        })
    }

    fn with_nonce(&self, nonce: u64) -> Tx {
        Tx { pow_nonce: Some(nonce), ..self.clone() }
    }

    /// The first nonce whose hash has exactly `bits` leading zero bits.
    fn nonce_with_exactly(&self, bits: u32) -> u64 {
        let s = self.sighash().unwrap();
        (0u64..1 << 16)
            .find(|n| leading_zero_bits(&pow_hash(&s, &self.root, &self.nullifiers, &self.proof, *n)) == bits)
            .expect("a nonce with this many zero bits within the search bound")
    }

    fn bounded_note(&self) -> StrangerNote {
        self.note.clone().try_into().expect("test notes fit the bound")
    }

    /// Through the real pipeline: `AuthorizeCall` at inclusion, then the
    /// dispatch. An authorization refusal is reported as the pallet's error.
    fn submit(&self) -> frame::prelude::DispatchResult {
        let call = RuntimeCall::Shielded(self.call());
        let info = call.get_dispatch_info();
        let len = codec::Encode::encoded_size(&call);
        match AuthorizeCall::<Test>::new().dispatch_transaction(RuntimeOrigin::none(), call, &info, len, 0) {
            Ok(result) => result.map(|_| ()).map_err(|e| e.error),
            Err(refused) => Err(pallet_error(refused).into()),
        }
    }

    /// What the pool sees.
    fn authorize(&self, source: TransactionSource) -> Result<ValidTransaction, TransactionValidityError> {
        self.call().authorize(source).expect("this call authorizes itself").map(|(valid, _)| valid)
    }

    fn call(&self) -> Call<Test> {
        Call::submit_shielded {
            root: self.root,
            nullifiers: self.nullifiers,
            commitments: self.commitments,
            admission_commitment: self.admission,
            not_before: self.not_before,
            not_after: self.not_after,
            coin_payloads: self.coin,
            stranger_note: self.bounded_note(),
            proof: self.proof,
            pow_nonce: self.nonce(),
        }
    }
}

/// The pallet error behind an authorization refusal. `Future` is the
/// too-early case of `OutsideWindow`.
fn pallet_error(refused: TransactionValidityError) -> E {
    match refused {
        TransactionValidityError::Invalid(InvalidTransaction::Future) => E::OutsideWindow,
        TransactionValidityError::Invalid(InvalidTransaction::Custom(code)) => match code {
            1 => E::WrongNoteLength,
            2 => E::NonCanonicalField,
            3 => E::WindowNotOnGrid,
            4 => E::OutsideWindow,
            5 => E::UnknownRoot,
            6 => E::DuplicateNullifier,
            7 => E::NullifierUsed,
            8 => E::TreeFull,
            9 => E::FeeOverflow,
            10 => E::NoVerifyingKey,
            11 => E::MalformedProof,
            12 => E::InvalidProof,
            13 => E::InsufficientPow,
            other => panic!("unknown refusal code {other}"),
        },
        other => panic!("unexpected refusal {other:?}"),
    }
}

fn from_built(built: &Built, note: Vec<u8>) -> Tx {
    let p = built.circuit.public;
    let proof = prove(&keys().pk, built.circuit.clone(), &mut OsRng).unwrap();
    let int = |x: Fr| x.into_bigint().0[0];
    Tx {
        root: fr_bytes(&p.root),
        nullifiers: p.nullifiers.map(|x| fr_bytes(&x)),
        commitments: p.commitments.map(|x| fr_bytes(&x)),
        admission: fr_bytes(&p.admission),
        not_before: int(p.not_before),
        not_after: int(p.not_after),
        coin: [
            built.envelope.coin_slots[0].clone().try_into().unwrap(),
            built.envelope.coin_slots[1].clone().try_into().unwrap(),
        ],
        note,
        proof: encode_proof(&proof).try_into().unwrap(),
        pow_nonce: None,
    }
}

fn real_tx(case: Case) -> Tx {
    let note = note(0x5A);
    let built = fixtures::build_for_chain(case, CHAIN_ID, TX_VERSION, fixtures::NOT_BEFORE, WINDOW, &note);
    from_built(&built, note)
}

/// One proved Transfer, reused by the refusal tests.
fn transfer() -> Tx {
    static TX: OnceLock<Tx> = OnceLock::new();
    TX.get_or_init(|| real_tx(Case::Transfer)).clone()
}

fn circuit_tree(case: Case) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for l in fixtures::world_leaves(case) {
        tree.append(l).unwrap();
    }
    tree
}

fn rerandomised(tx: &Tx) -> [u8; 192] {
    let proof = circuit::verifier::decode_proof(&tx.proof).unwrap();
    let other = Groth16::<Bls12_381>::rerandomize_proof(&keys().vk, &proof, &mut OsRng);
    encode_proof(&other).try_into().unwrap()
}

fn compressed(x: &impl CanonicalSerialize) -> Vec<u8> {
    let mut out = Vec::new();
    x.serialize_compressed(&mut out).unwrap();
    out
}

// ---- agreement with crates/shielded-circuit ----------------------------------

#[test]
fn poseidon_constants_match_the_circuit() {
    let ours = Poseidon::new();
    let theirs = circuit::poseidon::config();
    assert_eq!(ours.config().ark, theirs.ark);
    assert_eq!(ours.config().mds, theirs.mds);
    assert_eq!(
        (ours.config().full_rounds, ours.config().partial_rounds, ours.config().alpha),
        (theirs.full_rounds, theirs.partial_rounds, theirs.alpha)
    );
    assert_eq!((ours.config().rate, ours.config().capacity), (theirs.rate, theirs.capacity));
}

#[test]
fn hashes_match_the_circuit() {
    let p = Poseidon::new();
    let x = [Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
    assert_eq!(p.hash("nullifier/escrow", &x), circuit::poseidon::hash("nullifier/escrow", &x));
    assert_eq!(domain_tag("commit", 8), circuit::poseidon::domain_tag("commit", 8));
    assert_eq!(p.leaf(x[0], 3_600), circuit::leaf(x[0], 3_600u64.into()));
    assert_eq!(p.node(4, x[0], x[1]), circuit::merkle::node(4, x[0], x[1]));
}

#[test]
fn the_frontier_tracks_the_circuits_tree() {
    let p = Poseidon::new();
    let zero = p.empty_subtrees();
    let mut frontier = [zero[0]; TREE_DEPTH];
    let mut tree = MerkleTree::new();
    assert_eq!(zero[TREE_DEPTH], tree.root(), "empty root");
    for i in 0..70u64 {
        let leaf = Fr::from(i + 1_000);
        tree.append(leaf).unwrap();
        assert_eq!(p.append(&mut frontier, &zero, i, leaf), tree.root(), "after leaf {i}");
    }
}

#[test]
fn the_stranger_note_hash_matches_model_and_circuit() {
    for slot in [vec![], vec![1u8; 7], note(0xEE)] {
        assert_eq!(stranger_note_hash(&slot), model::chain::stranger_note_hash(&slot));
        assert_eq!(stranger_note_hash(&slot), circuit::stranger_note_hash(&slot));
    }
}

#[test]
fn the_sighash_matches_the_circuit() {
    let n = note(0x11);
    let built = fixtures::build_for_chain(Case::Open, 9, 3, 4_200, 60, &n);
    let p = built.circuit.public;
    let all = p.to_vec();
    let fields: [Fr; N_PUBLIC - 1] = all[..N_PUBLIC - 1].try_into().unwrap();
    let coin: [[u8; 200]; 2] =
        [built.envelope.coin_slots[0].clone().try_into().unwrap(), built.envelope.coin_slots[1].clone().try_into().unwrap()];
    let ours = compute_sighash(&SighashInputs {
        chain_id: 9,
        version: 3,
        fields: &fields,
        coin_slots: &coin,
        stranger_note_hash: &stranger_note_hash(&n),
    });
    assert_eq!(ours, p.sighash);
}

#[test]
fn constants_match_the_circuit_and_model() {
    assert_eq!(TREE_DEPTH, circuit::TREE_DEPTH);
    assert_eq!(N_PUBLIC, circuit::N_PUBLIC);
    assert_eq!(PROOF_LEN, circuit::verifier::PROOF_LEN);
    assert_eq!(STRANGER_NOTE_LEN as usize, model::chain::STRANGER_NOTE_LEN);
    assert_eq!(COIN_PAYLOAD_LEN, model::chain::COIN_PAYLOAD_LEN);
    assert_eq!(NOTE_TTL_SECS, model::chain::TTL);
}

// ---- real proofs, all six branches ---------------------------------------------

fn accepts(case: Case) {
    let tx = real_tx(case);
    new_test_ext(case).execute_with(|| {
        assert_eq!(CurrentRoot::<Test>::get(), fr_bytes(&circuit_tree(case).root()));
        assert_ok!(tx.authorize(TransactionSource::External));
        assert_ok!(tx.submit());

        for n in &tx.nullifiers {
            assert!(Nullifiers::<Test>::contains_key(n));
        }
        // The on-chain root is the circuit's tree with the three new leaves.
        let mut tree = circuit_tree(case);
        for c in &tx.commitments {
            let c = decode_fr(c).unwrap();
            tree.append(circuit::leaf(c, fixtures::NOT_BEFORE.into())).unwrap();
        }
        let root = fr_bytes(&tree.root());
        assert_eq!(CurrentRoot::<Test>::get(), root);
        assert!(AcceptedRoots::<Test>::contains_key(root));
        assert!(AcceptedRoots::<Test>::contains_key(tx.root), "the old root stays usable");
        assert_eq!(NextIndex::<Test>::get(), 7);
        assert_eq!(BurnedFees::<Test>::get() + NodeRewardPool::<Test>::get(), u128::from(BASE_FEE));
    });
}

#[test]
fn accepts_transfer() {
    accepts(Case::Transfer);
}
#[test]
fn accepts_invited_request() {
    accepts(Case::Invited);
}
#[test]
fn accepts_open() {
    accepts(Case::Open);
}
#[test]
fn accepts_claim_with_surplus() {
    accepts(Case::ClaimSurplus);
}
#[test]
fn accepts_claim_at_exact_fee() {
    accepts(Case::ClaimExactFee);
}
#[test]
fn accepts_claim_with_top_up() {
    accepts(Case::ClaimTopUp);
}
#[test]
fn accepts_decline_with_surplus() {
    accepts(Case::DeclineSurplus);
}
#[test]
fn accepts_decline_with_top_up() {
    accepts(Case::DeclineTopUp);
}
#[test]
fn accepts_sender_refund_with_surplus() {
    accepts(Case::RefundSurplus);
}
#[test]
fn accepts_sender_refund_with_top_up() {
    accepts(Case::RefundTopUp);
}

#[test]
fn a_new_output_can_be_spent_against_the_new_root() {
    // Spend a note the pallet itself inserted, with the circuit's own path.
    let first = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        assert_ok!(first.submit());
        let mut tree = circuit_tree(Case::Transfer);
        for c in &first.commitments {
            tree.append(circuit::leaf(decode_fr(c).unwrap(), fixtures::NOT_BEFORE.into())).unwrap();
        }
        let spent = circuit::Note::ordinary(1_000, circuit::authority(fixtures::f("funder")), fixtures::f("out1"));
        assert_eq!(fr_bytes(&spent.commitment()), first.commitments[1]);

        let n = note(0x77);
        let mut built = fixtures::build_for_chain(Case::Transfer, CHAIN_ID, TX_VERSION, fixtures::NOT_BEFORE, WINDOW, &n);
        let w = &mut built.circuit.witness;
        w.inputs[0] = circuit::InputWitness::real(&tree, spent, fixtures::NOT_BEFORE, 5, fixtures::f("funder"));
        // A dummy secret must be fresh: reusing one repeats its nullifier.
        w.inputs[1] = circuit::InputWitness::dummy(fixtures::f("second-dummy"));
        w.outputs = [
            circuit::Note::retired(0, fixtures::f("a")),
            circuit::Note::retired(0, fixtures::f("b")),
            circuit::Note::retired(0, fixtures::f("c")),
        ];
        built.circuit.public.root = tree.root();
        built.reseal();
        assert_ok!(from_built(&built, n).submit());

        // The second transaction's root needs the frontier the first saved.
        for c in built.circuit.public.commitments {
            tree.append(circuit::leaf(c, fixtures::NOT_BEFORE.into())).unwrap();
        }
        assert_eq!(CurrentRoot::<Test>::get(), fr_bytes(&tree.root()));
        assert_eq!(NextIndex::<Test>::get(), 10);
    });
}

// ---- refusals, each with no state change ----------------------------------------

#[test]
fn a_double_spend_is_refused() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        assert_ok!(tx.submit());
        assert_noop!(tx.submit(), E::NullifierUsed);
    });
}

#[test]
fn either_spent_nullifier_blocks_a_transaction() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for slot in 0..2 {
            let mut other = tx.clone();
            Nullifiers::<Test>::insert(tx.nullifiers[slot], ());
            other.nullifiers[1 - slot] = [9; 32];
            assert_noop!(other.submit(), E::NullifierUsed);
            Nullifiers::<Test>::remove(tx.nullifiers[slot]);
        }
    });
}

#[test]
fn duplicate_nullifiers_are_refused() {
    let mut tx = transfer();
    tx.nullifiers[1] = tx.nullifiers[0];
    new_test_ext(Case::Transfer).execute_with(|| { assert_noop!(tx.submit(), E::DuplicateNullifier); });
}

#[test]
fn an_unknown_root_is_refused() {
    let mut tx = transfer();
    tx.root[0] ^= 1;
    new_test_ext(Case::Transfer).execute_with(|| { assert_noop!(tx.submit(), E::UnknownRoot); });
}

#[test]
fn a_root_evicted_from_the_history_is_refused() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        assert!(AcceptedRoots::<Test>::contains_key(tx.root));
        for i in 0..ROOT_HISTORY {
            let mut root = [0u8; 32];
            root[0] = i as u8 + 1;
            Pallet::<Test>::accept_root(root);
        }
        assert!(!AcceptedRoots::<Test>::contains_key(tx.root));
        assert_eq!(AcceptedRoots::<Test>::iter().count(), ROOT_HISTORY as usize);
        assert_noop!(tx.submit(), E::UnknownRoot);
    });
}

#[test]
fn a_block_time_outside_the_window_is_refused() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        set_time(tx.not_before - 1);
        assert_noop!(tx.submit(), E::OutsideWindow);
        set_time(tx.not_after);
        assert_noop!(tx.submit(), E::OutsideWindow);
        set_time(tx.not_after - 1);
        assert_ok!(tx.submit());
    });
}

#[test]
fn a_window_off_the_grid_is_refused() {
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let mut tx = base.clone();
        tx.not_before += 1;
        tx.not_after += 1;
        assert_noop!(tx.submit(), E::WindowNotOnGrid);
        let mut tx = base.clone();
        tx.not_after += WINDOW;
        assert_noop!(tx.submit(), E::WindowNotOnGrid);
        let mut tx = base.clone();
        tx.not_before = u64::MAX - u64::MAX % WINDOW;
        tx.not_after = 0;
        assert_noop!(tx.submit(), E::WindowNotOnGrid);
    });
}

#[test]
fn a_wrong_note_length_is_refused() {
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for len in [0, 1, 1_787, 1_794] {
            let mut tx = base.clone();
            tx.note.truncate(len);
            assert_noop!(tx.submit(), E::WrongNoteLength);
        }
    });
}

#[test]
fn an_oversized_note_cannot_even_be_built() {
    let oversized = vec![0u8; STRANGER_NOTE_LEN as usize + 1];
    assert!(StrangerNote::try_from(oversized).is_err());
}

#[test]
fn a_tampered_stranger_note_is_refused() {
    let mut tx = transfer();
    tx.note[900] ^= 1;
    new_test_ext(Case::Transfer).execute_with(|| { assert_noop!(tx.submit(), E::InvalidProof); });
}

#[test]
fn tampered_coin_payloads_are_refused() {
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for slot in 0..2 {
            let mut tx = base.clone();
            tx.coin[slot][33] ^= 1;
            assert_noop!(tx.submit(), E::InvalidProof);
        }
    });
}

#[test]
fn every_tampered_public_field_is_refused() {
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for slot in 0..3 {
            let mut tx = base.clone();
            tx.commitments[slot] = fr_bytes(&(decode_fr(&tx.commitments[slot]).unwrap() + Fr::one()));
            assert_noop!(tx.submit(), E::InvalidProof);
        }
        for slot in 0..2 {
            let mut tx = base.clone();
            tx.nullifiers[slot] = fr_bytes(&(decode_fr(&tx.nullifiers[slot]).unwrap() + Fr::one()));
            assert_noop!(tx.submit(), E::InvalidProof);
        }
        let mut tx = base.clone();
        tx.admission = fr_bytes(&(decode_fr(&tx.admission).unwrap() + Fr::one()));
        assert_noop!(tx.submit(), E::InvalidProof);
    });
}

#[test]
fn a_different_base_fee_breaks_the_proof() {
    let tx = transfer();
    new_test_ext_with(Case::Transfer, BASE_FEE + 1, true).execute_with(|| {
        assert_noop!(tx.submit(), E::InvalidProof);
    });
}

#[test]
fn a_proof_for_another_chain_is_refused() {
    let n = note(0x5A);
    let built = fixtures::build_for_chain(Case::Transfer, CHAIN_ID + 1, TX_VERSION, fixtures::NOT_BEFORE, WINDOW, &n);
    let other_chain = from_built(&built, n.clone());
    let built = fixtures::build_for_chain(Case::Transfer, CHAIN_ID, TX_VERSION + 1, fixtures::NOT_BEFORE, WINDOW, &n);
    let other_version = from_built(&built, n);
    new_test_ext(Case::Transfer).execute_with(|| {
        assert_noop!(other_chain.submit(), E::InvalidProof);
        assert_noop!(other_version.submit(), E::InvalidProof);
    });
}

#[test]
fn non_canonical_field_encodings_are_refused() {
    // r + x encodes the same residue as x: it must not be a second nullifier.
    let base = transfer();
    let modulus: Bytes32 = Fr::MODULUS.to_bytes_le().try_into().unwrap();
    new_test_ext(Case::Transfer).execute_with(|| {
        let mut tx = base.clone();
        tx.nullifiers[0] = modulus;
        assert_noop!(tx.submit(), E::NonCanonicalField);
        let mut tx = base.clone();
        tx.commitments[2] = [0xFF; 32];
        assert_noop!(tx.submit(), E::NonCanonicalField);
        let mut tx = base.clone();
        tx.admission = modulus;
        assert_noop!(tx.submit(), E::NonCanonicalField);
    });
}

#[test]
fn a_non_subgroup_g1_point_is_refused() {
    let point = (1u64..)
        .find_map(|x| {
            G1Affine::get_point_from_x_unchecked(Fq::from(x), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    let bad = compressed(&point);
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for offset in [0, 144] {
            let mut tx = base.clone();
            tx.proof[offset..offset + 48].copy_from_slice(&bad);
            assert_noop!(tx.submit(), E::MalformedProof);
        }
    });
}

#[test]
fn a_non_subgroup_g2_point_is_refused() {
    let point = (1u64..)
        .find_map(|x| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::one()), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    let bad = compressed(&point);
    let mut tx = transfer();
    tx.proof[48..144].copy_from_slice(&bad);
    new_test_ext(Case::Transfer).execute_with(|| { assert_noop!(tx.submit(), E::MalformedProof); });
}

#[test]
fn malformed_proof_bytes_are_refused() {
    let base = transfer();
    let g1 = compressed(&G1Affine::zero());
    let g2 = compressed(&G2Affine::zero());
    new_test_ext(Case::Transfer).execute_with(|| {
        for (offset, point) in [(0usize, &g1), (48, &g2), (144, &g1)] {
            let mut tx = base.clone();
            tx.proof[offset..offset + point.len()].copy_from_slice(point);
            assert_noop!(tx.submit(), E::MalformedProof);
        }
        let mut tx = base.clone();
        tx.proof = [0xFF; 192];
        assert_noop!(tx.submit(), E::MalformedProof);
        let mut tx = base.clone();
        tx.proof[0] &= 0x7F; // clears the "compressed" flag
        assert_noop!(tx.submit(), E::MalformedProof);
    });
}

#[test]
fn a_well_formed_wrong_proof_is_refused() {
    let tx = transfer();
    let mut wrong = tx.clone();
    wrong.proof = real_tx(Case::Invited).proof;
    new_test_ext(Case::Transfer).execute_with(|| { assert_noop!(wrong.submit(), E::InvalidProof); });
}

#[test]
fn a_rerandomised_proof_verifies_but_cannot_replay() {
    let tx = transfer();
    let mut replay = tx.clone();
    replay.proof = rerandomised(&tx);
    assert_ne!(replay.proof, tx.proof);
    new_test_ext(Case::Transfer).execute_with(|| {
        assert_ok!(replay.authorize(TransactionSource::External));
        assert_ok!(tx.submit());
        assert_noop!(replay.submit(), E::NullifierUsed);
    });
}

#[test]
fn storage_does_not_depend_on_the_proof_bytes() {
    let tx = transfer();
    let mut other = tx.clone();
    other.proof = rerandomised(&tx);
    let root_with = |t: &Tx| {
        new_test_ext(Case::Transfer).execute_with(|| {
            assert_ok!(t.submit());
            frame::deps::sp_io::storage::root(frame::deps::sp_runtime::StateVersion::V1)
        })
    };
    let strip_events = root_with(&tx);
    assert_ne!(tx.proof, other.proof);
    assert_eq!(strip_events, root_with(&other), "two proofs of one statement leave identical state");
}

#[test]
fn no_verifying_key_refuses_everything() {
    let tx = transfer();
    new_test_ext_with(Case::Transfer, BASE_FEE, false).execute_with(|| {
        assert_noop!(tx.submit(), E::NoVerifyingKey);
    });
}

#[test]
fn only_the_authorized_origin_can_dispatch() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for origin in [RuntimeOrigin::signed(1), RuntimeOrigin::root(), RuntimeOrigin::none()] {
            assert_noop!(
                Shielded::submit_shielded(
                    origin,
                    tx.root,
                    tx.nullifiers,
                    tx.commitments,
                    tx.admission,
                    tx.not_before,
                    tx.not_after,
                    tx.coin,
                    tx.bounded_note(),
                    tx.proof,
                    0,
                ),
                DispatchError::BadOrigin
            );
        }
    });
}

#[test]
fn a_full_tree_is_refused() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        NextIndex::<Test>::put((1u64 << TREE_DEPTH) - 2);
        assert_noop!(tx.submit(), E::TreeFull);
        NextIndex::<Test>::put((1u64 << TREE_DEPTH) - 3);
        assert_ok!(tx.submit());
        assert_eq!(NextIndex::<Test>::get(), 1 << TREE_DEPTH);
    });
}

#[test]
fn a_fee_counter_overflow_is_refused() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        BurnedFees::<Test>::put(u128::MAX);
        assert_noop!(tx.submit(), E::FeeOverflow);
        BurnedFees::<Test>::put(0);
        NodeRewardPool::<Test>::put(u128::MAX);
        assert_noop!(tx.submit(), E::FeeOverflow);
    });
}

// ---- the fee split ----------------------------------------------------------------

#[test]
fn the_base_fee_splits_between_burn_and_pool() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        assert_ok!(tx.submit());
        assert_eq!(BurnedFees::<Test>::get(), 300);
        assert_eq!(NodeRewardPool::<Test>::get(), 700);
    });
}

#[test]
fn the_burn_rounds_down_and_nothing_is_lost() {
    use frame::deps::sp_runtime::Percent;
    for fee in [0u64, 1, 3, 99, 101, 1_001, u64::MAX] {
        let burned = Percent::from_percent(30).mul_floor(fee);
        assert!(u128::from(burned) * 100 <= u128::from(fee) * 30, "fee {fee}");
        assert_eq!(burned + (fee - burned), fee);
    }
}

// ---- authorization: the transaction pool and inclusion ---------------------------

fn refused_by_pool(tx: &Tx, code: u8) {
    for source in [TransactionSource::External, TransactionSource::Local, TransactionSource::InBlock] {
        assert_eq!(tx.authorize(source), Err(InvalidTransaction::Custom(code).into()), "{source:?}");
    }
}

fn authorizes(case: Case) {
    let tx = real_tx(case);
    new_test_ext(case).execute_with(|| {
        for source in [TransactionSource::External, TransactionSource::Local, TransactionSource::InBlock] {
            let valid = tx.authorize(source).unwrap_or_else(|e| panic!("{case:?} {source:?}: {e:?}"));
            assert_eq!(valid.provides.len(), 2);
        }
        assert_eq!(NextIndex::<Test>::get(), 4, "authorization writes nothing");
    });
}

#[test]
fn authorizes_transfer() {
    authorizes(Case::Transfer);
}
#[test]
fn authorizes_invited_request() {
    authorizes(Case::Invited);
}
#[test]
fn authorizes_open() {
    authorizes(Case::Open);
}
#[test]
fn authorizes_claim_with_surplus() {
    authorizes(Case::ClaimSurplus);
}
#[test]
fn authorizes_claim_at_exact_fee() {
    authorizes(Case::ClaimExactFee);
}
#[test]
fn authorizes_claim_with_top_up() {
    authorizes(Case::ClaimTopUp);
}
#[test]
fn authorizes_decline_with_surplus() {
    authorizes(Case::DeclineSurplus);
}
#[test]
fn authorizes_decline_with_top_up() {
    authorizes(Case::DeclineTopUp);
}
#[test]
fn authorizes_sender_refund_with_surplus() {
    authorizes(Case::RefundSurplus);
}
#[test]
fn authorizes_sender_refund_with_top_up() {
    authorizes(Case::RefundTopUp);
}

#[test]
fn authorization_refuses_a_bad_note_length() {
    let mut tx = transfer();
    tx.note.truncate(1_794);
    new_test_ext(Case::Transfer).execute_with(|| refused_by_pool(&tx, 1));
}

#[test]
fn authorization_refuses_a_bad_window() {
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let mut off_grid = base.clone();
        off_grid.not_before += 1;
        off_grid.not_after += 1;
        refused_by_pool(&off_grid, 3);
        let mut wide = base.clone();
        wide.not_after += WINDOW;
        refused_by_pool(&wide, 3);
        set_time(base.not_after);
        refused_by_pool(&base, 4);
    });
}

#[test]
fn authorization_refuses_an_unknown_root() {
    let mut tx = transfer();
    tx.root[0] ^= 1;
    new_test_ext(Case::Transfer).execute_with(|| refused_by_pool(&tx, 5));
}

#[test]
fn authorization_refuses_duplicate_and_spent_nullifiers() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let mut duplicate = tx.clone();
        duplicate.nullifiers[1] = duplicate.nullifiers[0];
        refused_by_pool(&duplicate, 6);
        for slot in 0..2 {
            Nullifiers::<Test>::insert(tx.nullifiers[slot], ());
            refused_by_pool(&tx, 7);
            Nullifiers::<Test>::remove(tx.nullifiers[slot]);
        }
    });
}

#[test]
fn authorization_refuses_malformed_proof_bytes() {
    let g1 = (1u64..)
        .find_map(|x| {
            G1Affine::get_point_from_x_unchecked(Fq::from(x), false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    let base = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let mut garbage = base.clone();
        garbage.proof = [0xFF; 192];
        refused_by_pool(&garbage, 11);
        let mut outside_subgroup = base.clone();
        outside_subgroup.proof[..48].copy_from_slice(&compressed(&g1));
        refused_by_pool(&outside_subgroup, 11);
        let mut identity = base.clone();
        identity.proof[144..].copy_from_slice(&compressed(&G1Affine::zero()));
        refused_by_pool(&identity, 11);
    });
}

#[test]
fn authorization_refuses_a_bad_proof() {
    let mut tx = transfer();
    tx.note[1] ^= 1;
    new_test_ext(Case::Transfer).execute_with(|| refused_by_pool(&tx, 12));
}

#[test]
fn the_checks_run_cheapest_first() {
    // Every check fails at once; fixing one at a time reveals the next.
    let good = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        Nullifiers::<Test>::insert(good.nullifiers[1], ());
        let mut tx = good.clone();
        tx.note.truncate(10);
        tx.not_before += 1;
        tx.root[0] ^= 1;
        tx.proof = [0xFF; 192];
        refused_by_pool(&tx, 1); // length
        tx.note = good.note.clone();
        refused_by_pool(&tx, 3); // grid
        tx.not_before = good.not_before;
        refused_by_pool(&tx, 5); // root
        tx.root = good.root;
        refused_by_pool(&tx, 7); // nullifiers
        Nullifiers::<Test>::remove(good.nullifiers[1]);
        refused_by_pool(&tx, 11); // proof encoding
        tx.proof = good.proof;
        tx.coin[0][0] ^= 1;
        let unsolved = tx.nonce_with_exactly(0);
        refused_by_pool(&tx.with_nonce(unsolved), 13); // proof of work
        refused_by_pool(&tx, 12); // pairing
    });
}

#[test]
fn tags_are_the_nullifiers_and_never_the_proof() {
    use codec::Encode;
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let valid = tx.authorize(TransactionSource::External).unwrap();
        let tag = |n: &Bytes32| ("AnonymumShielded", n).encode();
        assert_eq!(valid.provides, vec![tag(&tx.nullifiers[0]), tag(&tx.nullifiers[1])]);
        assert!(valid.requires.is_empty(), "a spend depends on no other pooled transaction");
        assert!(valid.propagate);
        assert_eq!(valid.longevity, 10);

        let mut copy = tx.clone();
        copy.proof = rerandomised(&tx);
        let other = copy.authorize(TransactionSource::Local).unwrap();
        assert_eq!(valid.provides, other.provides, "a re-randomised copy conflicts in the pool");
    });
}

#[test]
fn the_pool_allows_the_next_window_and_no_later() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let check = || tx.authorize(TransactionSource::External);
        set_time(tx.not_before - WINDOW);
        assert!(check().is_ok());
        set_time(tx.not_before - WINDOW - 1);
        assert_eq!(check(), Err(InvalidTransaction::Custom(4).into()));
        set_time(tx.not_after);
        assert_eq!(check(), Err(InvalidTransaction::Custom(4).into()));
    });
}

#[test]
fn inclusion_uses_the_strict_clock_and_sees_spent_nullifiers() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        let check = || tx.authorize(TransactionSource::InBlock);
        set_time(tx.not_before - 1);
        assert_eq!(check(), Err(InvalidTransaction::Future.into()), "too early: stays in the pool");
        set_time(tx.not_after);
        assert_eq!(check(), Err(InvalidTransaction::Custom(4).into()), "too late: dropped");
        set_time(tx.not_before);
        assert!(check().is_ok());
        assert_ok!(tx.submit());
        assert_eq!(check(), Err(InvalidTransaction::Custom(7).into()));
    });
}

#[test]
fn the_dispatch_repeats_the_state_checks() {
    // If state changed after authorization, the dispatch itself refuses.
    let tx = transfer();
    let authorized = || RuntimeOrigin::from(polkadot_sdk::frame_system::Origin::<Test>::Authorized);
    let dispatch = || {
        Shielded::submit_shielded(
            authorized(),
            tx.root,
            tx.nullifiers,
            tx.commitments,
            tx.admission,
            tx.not_before,
            tx.not_after,
            tx.coin,
            tx.bounded_note(),
            tx.proof,
            0,
        )
    };
    new_test_ext(Case::Transfer).execute_with(|| {
        Nullifiers::<Test>::insert(tx.nullifiers[0], ());
        assert_noop!(dispatch(), E::NullifierUsed);
        Nullifiers::<Test>::remove(tx.nullifiers[0]);
        set_time(tx.not_after);
        assert_noop!(dispatch(), E::OutsideWindow);
        // The pool may hold a transaction for the next window; a block may not.
        set_time(tx.not_before - 1);
        assert_noop!(dispatch(), E::OutsideWindow);
    });
}

#[test]
fn authorization_and_dispatch_carry_their_benchmarked_weights() {
    let tx = Tx { pow_nonce: Some(0), ..transfer() };
    let call = tx.call();
    assert_eq!(call.weight_of_authorize(), <() as crate::WeightInfo>::authorize_submit_shielded());
    let info = call.get_dispatch_info();
    assert_eq!(info.call_weight, <() as crate::WeightInfo>::submit_shielded());
    // The measured WebAssembly costs with their margin (weights.rs), so a
    // weight lowered below them fails here.
    const MS: u64 = 1_000_000_000;
    assert!(call.weight_of_authorize().ref_time() >= 175 * MS);
    assert!(info.call_weight.ref_time() >= 115 * MS);
    assert!(<() as crate::WeightInfo>::prune_stranger_notes(64, 64).ref_time() >= 2_860 * MS / 1_000);
}

#[test]
fn on_initialize_reserves_the_pruning_bound_only_when_notes_may_expire() {
    new_test_ext(Case::Transfer).execute_with(|| {
        use frame::deps::frame_support::traits::Get;
        use frame::deps::frame_support::weights::RuntimeDbWeight;
        let reads = <<Test as polkadot_sdk::frame_system::Config>::DbWeight as Get<RuntimeDbWeight>>::get().reads(1);
        assert_eq!(Shielded::on_initialize(1), reads);
        PruneCursor::<Test>::put(0);
        assert_eq!(Shielded::on_initialize(1), <() as crate::WeightInfo>::prune_stranger_notes(2, 8));
    });
}

// ---- proof of work ----------------------------------------------------------------

#[test]
fn the_pow_hash_is_the_specified_concatenation_and_matches_the_client() {
    use blake2::{Blake2s256, Digest};
    let (sighash, root, nullifiers, proof) = ([1u8; 32], [2u8; 32], [[3u8; 32], [4u8; 32]], [5u8; 192]);
    let nonce = 0x0102_0304_0506_0708u64;
    let mut message = b"anonymum/shielded-pow/v1".to_vec();
    for part in [&sighash[..], &root, &nullifiers[0], &nullifiers[1], &proof, &nonce.to_le_bytes()] {
        message.extend_from_slice(part);
    }
    let expected: Bytes32 = Blake2s256::digest(&message).into();
    assert_eq!(pow_hash(&sighash, &root, &nullifiers, &proof, nonce), expected);
    assert_eq!(circuit::pow::pow_hash(&sighash, &root, &nullifiers, &proof, nonce), expected);

    let solved = circuit::pow::solve_pow(&sighash, &root, &nullifiers, &proof, 10);
    assert!(leading_zero_bits(&pow_hash(&sighash, &root, &nullifiers, &proof, solved)) >= 10);
}

#[test]
fn leading_zero_bits_are_counted_exactly() {
    assert_eq!(leading_zero_bits(&[0; 32]), 256);
    for bits in 0..256usize {
        let mut hash = [0u8; 32];
        hash[bits / 8] = 0x80 >> (bits % 8);
        hash[31] |= (bits < 248) as u8; // bits after the first one do not count
        assert_eq!(leading_zero_bits(&hash), bits as u32);
        assert_eq!(circuit::pow::leading_zero_bits(&hash), bits as u32);
    }
}

#[test]
fn the_pow_hash_covers_every_bound_field() {
    let (sighash, root, nullifiers, proof) = ([1u8; 32], [2u8; 32], [[3u8; 32], [4u8; 32]], [5u8; 192]);
    let base = pow_hash(&sighash, &root, &nullifiers, &proof, 7);
    let flip = |mut x: Bytes32| {
        x[31] ^= 1;
        x
    };
    let mut other_proof = proof;
    other_proof[191] ^= 1;
    assert_ne!(base, pow_hash(&flip(sighash), &root, &nullifiers, &proof, 7), "sighash");
    assert_ne!(base, pow_hash(&sighash, &flip(root), &nullifiers, &proof, 7), "root");
    assert_ne!(base, pow_hash(&sighash, &root, &[flip(nullifiers[0]), nullifiers[1]], &proof, 7), "first nullifier");
    assert_ne!(base, pow_hash(&sighash, &root, &[nullifiers[0], flip(nullifiers[1])], &proof, 7), "second nullifier");
    assert_ne!(base, pow_hash(&sighash, &root, &nullifiers, &other_proof, 7), "proof");
    assert_ne!(base, pow_hash(&sighash, &root, &nullifiers, &proof, 8), "nonce");
    assert_ne!(base, pow_hash(&sighash, &root, &[nullifiers[1], nullifiers[0]], &proof, 7), "nullifier order");
}

#[test]
fn a_bad_nonce_is_refused_before_the_pairing_with_no_state_change() {
    let good = transfer();
    let wrong_proof = real_tx(Case::Invited).proof;
    new_test_ext(Case::Transfer).execute_with(|| {
        PowBits::set(8);
        let bad = good.with_nonce(good.nonce_with_exactly(7));
        refused_by_pool(&bad, 13);
        assert_noop!(bad.submit(), E::InsufficientPow);

        // A proof the pairing would refuse reports the proof of work first,
        // and reaches the pairing only once the work is done.
        let mut wrong = good.clone();
        wrong.proof = wrong_proof;
        refused_by_pool(&wrong.with_nonce(wrong.nonce_with_exactly(7)), 13);
        refused_by_pool(&wrong, 12);

        // The check runs before the verifying key is even read.
        DevVerifyingKey::<Test>::kill();
        refused_by_pool(&bad, 13);
        refused_by_pool(&good, 10);
    });
}

#[test]
fn a_solved_nonce_does_not_carry_over_to_a_changed_transaction() {
    let base = transfer();
    let other_proof = rerandomised(&base);
    new_test_ext(Case::Transfer).execute_with(|| {
        PowBits::set(8);
        let other_root = fr_bytes(&(decode_fr(&base.root).unwrap() + Fr::one()));
        AcceptedRoots::<Test>::insert(other_root, ());

        let change = |f: &dyn Fn(&mut Tx)| {
            let mut tx = base.clone();
            f(&mut tx);
            tx
        };
        let bump = |x: &Bytes32| fr_bytes(&(decode_fr(x).unwrap() + Fr::one()));
        let changed = [
            change(&|t| t.proof = other_proof),      // the proof bytes
            change(&|t| t.coin[0][0] ^= 1),          // the sighash alone
            change(&|t| t.root = other_root),        // the root
            change(&|t| t.nullifiers[0] = bump(&t.nullifiers[0])),
            change(&|t| t.nullifiers[1] = bump(&t.nullifiers[1])),
        ];

        // At 8 bits a changed transaction passes by luck 1 time in 256, so
        // use a nonce that solves the original and none of the others.
        let digest = |t: &Tx| (t.sighash().unwrap(), t.root, t.nullifiers, t.proof);
        let solves = |d: &(Bytes32, Bytes32, [Bytes32; 2], [u8; 192]), n: u64| {
            leading_zero_bits(&pow_hash(&d.0, &d.1, &d.2, &d.3, n)) >= 8
        };
        let original = digest(&base);
        let others: Vec<_> = changed.iter().map(digest).collect();
        // Bounded: if the hash ignored a field, no such nonce would exist.
        let nonce = (0u64..1 << 16)
            .find(|n| solves(&original, *n) && others.iter().all(|d| !solves(d, *n)))
            .expect("every changed field changes the hash");

        assert_ok!(base.with_nonce(nonce).authorize(TransactionSource::External));
        for tx in &changed {
            refused_by_pool(&tx.with_nonce(nonce), 13);
        }
    });
}

#[test]
fn the_difficulty_boundary_is_exact() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        for difficulty in [1, 4, 8] {
            PowBits::set(difficulty);
            refused_by_pool(&tx.with_nonce(tx.nonce_with_exactly(difficulty - 1)), 13);
            let exact = tx.with_nonce(tx.nonce_with_exactly(difficulty));
            assert!(exact.authorize(TransactionSource::External).is_ok(), "difficulty {difficulty}");
        }
        PowBits::set(8);
        assert_ok!(tx.with_nonce(tx.nonce_with_exactly(8)).submit());
    });
}

#[test]
fn the_highest_difficulty_a_u64_nonce_allows_passes_the_startup_check() {
    PowBits::set(MAX_POW_DIFFICULTY);
    <Shielded as Hooks<u64>>::integrity_test();
}

#[test]
#[should_panic(expected = "the nonce is a u64")]
fn a_difficulty_above_that_fails_the_startup_check() {
    PowBits::set(MAX_POW_DIFFICULTY + 1);
    <Shielded as Hooks<u64>>::integrity_test();
}

#[test]
fn difficulty_zero_disables_the_check() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        PowBits::set(0);
        let any = tx.with_nonce(tx.nonce_with_exactly(0));
        assert_ok!(any.authorize(TransactionSource::External));
        assert_ok!(any.submit());
    });
}

// ---- 24-hour pruning ---------------------------------------------------------------

fn finalize_at(seconds: u64) {
    set_time(seconds);
    Shielded::on_finalize(System::block_number());
}

#[test]
fn a_note_is_pruned_at_24_hours_and_everything_else_stays() {
    let tx = transfer();
    new_test_ext(Case::Transfer).execute_with(|| {
        System::reset_events();
        assert_ok!(tx.submit());
        let window = tx.not_before;
        let (sighash, note_hash) = System::events()
            .iter()
            .find_map(|r| match &r.event {
                RuntimeEvent::Shielded(Event::Shielded { sighash, stranger_note_hash, .. }) => {
                    Some((*sighash, *stranger_note_hash))
                }
                _ => None,
            })
            .expect("the event");
        assert_eq!(note_hash, stranger_note_hash(&tx.note));
        let stored = StrangerNotes::<Test>::get(window, sighash).expect("kept");
        assert_eq!(stored.len(), 1_795);
        let (root, index, fees) = (CurrentRoot::<Test>::get(), NextIndex::<Test>::get(), BurnedFees::<Test>::get());

        finalize_at(window + NOTE_TTL_SECS - 1);
        assert!(StrangerNotes::<Test>::contains_key(window, sighash), "kept until the last second");

        finalize_at(window + NOTE_TTL_SECS);
        assert!(!StrangerNotes::<Test>::contains_key(window, sighash), "removed at 24 h");
        assert!(System::events().iter().any(|r| matches!(
            r.event,
            RuntimeEvent::Shielded(Event::StrangerNotesPruned { window_start, removed: 1 }) if window_start == window
        )));

        assert_eq!(CurrentRoot::<Test>::get(), root);
        assert!(AcceptedRoots::<Test>::contains_key(root));
        assert_eq!(NextIndex::<Test>::get(), index);
        assert_eq!(BurnedFees::<Test>::get(), fees);
        for n in &tx.nullifiers {
            assert!(Nullifiers::<Test>::contains_key(n), "a pruned note's nullifier stays spent");
        }
        assert!(
            System::events().iter().any(|r| matches!(
                &r.event,
                RuntimeEvent::Shielded(Event::Shielded { stranger_note_hash: h, sighash: s, .. })
                    if *h == note_hash && *s == sighash
            )),
            "the note's hash and the sighash stay in the event log"
        );
    });
}

#[test]
fn pruning_respects_the_per_block_limit() {
    new_test_ext(Case::Transfer).execute_with(|| {
        let bytes: StrangerNote = note(1).try_into().unwrap();
        for i in 0..5u8 {
            StrangerNotes::<Test>::insert(WINDOW, [i; 32], bytes.clone());
        }
        PruneCursor::<Test>::put(WINDOW);
        let later = WINDOW + NOTE_TTL_SECS;
        Pallet::<Test>::prune_stranger_notes(later);
        assert_eq!(StrangerNotes::<Test>::iter_prefix(WINDOW).count(), 3);
        assert_eq!(PruneCursor::<Test>::get(), Some(WINDOW), "the window is not done");
        Pallet::<Test>::prune_stranger_notes(later);
        assert_eq!(StrangerNotes::<Test>::iter_prefix(WINDOW).count(), 1);
        Pallet::<Test>::prune_stranger_notes(later);
        assert_eq!(StrangerNotes::<Test>::iter_prefix(WINDOW).count(), 0);
        assert_eq!(PruneCursor::<Test>::get(), Some(2 * WINDOW));
    });
}

#[test]
fn the_cursor_crosses_empty_windows_within_its_limit() {
    new_test_ext(Case::Transfer).execute_with(|| {
        let bytes: StrangerNote = note(1).try_into().unwrap();
        let far = WINDOW * 20;
        StrangerNotes::<Test>::insert(far, [1u8; 32], bytes);
        PruneCursor::<Test>::put(WINDOW);
        Pallet::<Test>::prune_stranger_notes(far + NOTE_TTL_SECS);
        assert_eq!(PruneCursor::<Test>::get(), Some(WINDOW + 8 * WINDOW), "at most 8 windows per block");
        assert!(StrangerNotes::<Test>::contains_key(far, [1u8; 32]));
        Pallet::<Test>::prune_stranger_notes(far + NOTE_TTL_SECS);
        Pallet::<Test>::prune_stranger_notes(far + NOTE_TTL_SECS);
        assert!(!StrangerNotes::<Test>::contains_key(far, [1u8; 32]));
    });
}

#[test]
fn pruning_never_touches_a_live_window() {
    new_test_ext(Case::Transfer).execute_with(|| {
        let bytes: StrangerNote = note(1).try_into().unwrap();
        StrangerNotes::<Test>::insert(WINDOW, [1u8; 32], bytes.clone());
        StrangerNotes::<Test>::insert(2 * WINDOW, [2u8; 32], bytes);
        PruneCursor::<Test>::put(WINDOW);
        Pallet::<Test>::prune_stranger_notes(WINDOW + NOTE_TTL_SECS);
        assert!(!StrangerNotes::<Test>::contains_key(WINDOW, [1u8; 32]));
        assert!(StrangerNotes::<Test>::contains_key(2 * WINDOW, [2u8; 32]));
    });
}

// ---- genesis ------------------------------------------------------------------------

#[test]
fn genesis_stores_a_validated_uncompressed_key() {
    new_test_ext(Case::Transfer).execute_with(|| {
        let stored = DevVerifyingKey::<Test>::get().expect("stored");
        assert!(stored.len() > keys().vk_bytes.len(), "uncompressed");
        assert!(stored.len() <= MAX_VK_LEN as usize);
    });
}

#[test]
fn a_bad_verifying_key_is_refused() {
    assert!(prepare_stored_key(&keys().vk_bytes).is_some());
    let mut long = keys().vk_bytes.clone();
    long.push(0);
    assert!(prepare_stored_key(&long).is_none(), "trailing bytes");
    assert!(prepare_stored_key(&keys().vk_bytes[1..]).is_none(), "truncated");
    let mut short = keys().vk.clone();
    short.gamma_abc_g1.pop();
    assert!(prepare_stored_key(&compressed(&short)).is_none(), "wrong input count");
}
