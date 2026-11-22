//! Constraint-satisfaction tests: each valid branch satisfies the circuit,
//! and each altered witness does not. Public inputs are re-derived after
//! most alterations, so a failure comes from the rule under test.

use anonymum_shielded_circuit::fixtures::*;
use anonymum_shielded_circuit::merkle::{root_from_path, MerkleTree};
use anonymum_shielded_circuit::poseidon::{self, domain_tag};
use anonymum_shielded_circuit::*;
use anonymum_shielded_model as model;
use ark_ff::{One, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

const RESOLUTIONS: [Case; 7] = [
    Case::ClaimSurplus,
    Case::ClaimExactFee,
    Case::ClaimTopUp,
    Case::DeclineSurplus,
    Case::DeclineTopUp,
    Case::RefundSurplus,
    Case::RefundTopUp,
];
const EMPTY_RECORD: [Case; 4] = [Case::Transfer, Case::ClaimSurplus, Case::DeclineSurplus, Case::RefundSurplus];

fn satisfied(circuit: ShieldedCircuit) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("synthesis");
    cs.is_satisfied().expect("assigned")
}

/// Alter the witness, re-derive the public inputs, expect refusal.
fn refused(case: Case, alter: impl FnOnce(&mut TxWitness)) {
    let mut built = build(case);
    assert!(satisfied(built.circuit.clone()), "{case:?} must be valid before the alteration");
    alter(&mut built.circuit.witness);
    built.reseal();
    assert!(!satisfied(built.circuit), "{case:?}: the altered witness was accepted");
}

/// Alter the public inputs only.
fn public_refused(case: Case, alter: impl FnOnce(&mut PublicInputs)) {
    let mut built = build(case);
    alter(&mut built.circuit.public);
    assert!(!satisfied(built.circuit), "{case:?}: the altered public input was accepted");
}

fn neg(x: u64) -> Fr {
    -Fr::from(x)
}

// ---- valid transactions ----------------------------------------------------

#[test]
fn every_branch_and_fee_path_is_satisfied() {
    for case in Case::ALL {
        assert!(satisfied(build(case).circuit), "{case:?}");
    }
}

#[test]
fn every_branch_has_the_same_constraint_shape_as_the_blank_circuit() {
    let count = |circuit: ShieldedCircuit| {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        (cs.num_constraints(), cs.num_instance_variables(), cs.num_witness_variables())
    };
    let blank = count(ShieldedCircuit::blank(PARAMS));
    assert_eq!(blank.1, N_PUBLIC + 1, "11 public inputs plus the constant one");
    for case in Case::ALL {
        assert_eq!(count(build(case).circuit), blank, "{case:?}");
    }
}

#[test]
fn a_claim_in_the_last_window_before_the_deadline_is_valid() {
    let mut built = build(Case::ClaimSurplus);
    built.circuit.public.not_after = (CREATED_AT + TTL).into();
    built.reseal();
    assert!(satisfied(built.circuit));
}

#[test]
fn decline_and_refund_have_no_deadline() {
    for case in [Case::DeclineSurplus, Case::RefundSurplus] {
        let mut built = build(case);
        built.circuit.public.not_after = (CREATED_AT + 10 * TTL).into();
        built.reseal();
        assert!(satisfied(built.circuit), "{case:?}");
    }
}

#[test]
fn a_top_up_with_no_change_uses_an_unused_output() {
    for case in [Case::ClaimTopUp, Case::DeclineTopUp, Case::RefundTopUp] {
        let mut built = build(case);
        let w = &mut built.circuit.witness;
        // Move the change into the fee by making the shortfall the whole
        // top-up: rebuild the tree around a top-up of exactly the shortfall.
        let top_up = Note::ordinary(SHORTFALL, authority(f("resolver")), f("exact-top-up"));
        let escrow = w.inputs[0].note;
        let mut tree = MerkleTree::new();
        tree.append(f("filler-leaf")).unwrap();
        tree.append(f("filler-leaf-2")).unwrap();
        tree.append(leaf(escrow.commitment(), CREATED_AT.into())).unwrap();
        tree.append(leaf(top_up.commitment(), CREATED_AT.into())).unwrap();
        let secret = w.inputs[0].secret;
        w.inputs = [
            InputWitness::real(&tree, escrow, CREATED_AT, 2, secret),
            InputWitness::real(&tree, top_up, CREATED_AT, 3, f("resolver")),
        ];
        w.outputs[2] = Note::retired(0, f("unused"));
        built.circuit.public.root = tree.root();
        built.reseal();
        assert!(satisfied(built.circuit), "{case:?}");
    }
}

// ---- primitives and agreement with the model -------------------------------

#[test]
fn native_and_constraint_poseidon_agree() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    for arity in [1usize, 2, 3, 6, 8] {
        let inputs: Vec<Fr> = (0..arity).map(|i| Fr::from(i as u64 + 11)).collect();
        let vars: Vec<FpVar<Fr>> =
            inputs.iter().map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap()).collect();
        let out = poseidon::hash_var(&cs, "test", &vars).unwrap();
        assert_eq!(out.value().unwrap(), poseidon::hash("test", &inputs), "arity {arity}");
    }
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn domains_and_arities_are_separated() {
    let x = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    assert_ne!(poseidon::hash("nullifier/ordinary", &x), poseidon::hash("nullifier/escrow", &x));
    assert_ne!(poseidon::hash("nullifier/ordinary", &x), poseidon::hash("nullifier/dummy", &x));
    assert_ne!(domain_tag("a", 1), domain_tag("a", 2));
    assert_ne!(ordinary_nullifier(x[0], x[1], 3), escrow_nullifier(x[0], x[1], 3));
}

#[test]
fn the_tree_gives_paths_that_reach_its_root() {
    let mut tree = MerkleTree::new();
    let leaves: Vec<Fr> = (0..9u64).map(|i| Fr::from(i + 100)).collect();
    for l in &leaves {
        tree.append(*l).unwrap();
    }
    for (i, l) in leaves.iter().enumerate() {
        let path = tree.path(i as u64);
        assert_eq!(path.len(), TREE_DEPTH);
        assert_eq!(root_from_path(*l, i as u64, &path), tree.root(), "leaf {i}");
        assert_ne!(root_from_path(*l, i as u64 ^ 1, &path), tree.root(), "wrong position, leaf {i}");
    }
}

#[test]
fn constants_and_rule_arithmetic_match_the_model() {
    assert_eq!(N_IN, model::chain::N_IN);
    assert_eq!(N_OUT, model::chain::N_OUT);
    assert_eq!(TTL, model::chain::TTL);
    for price in [0u64, 1, 2, 99, 100, 101, 199, 200, 10_101, u64::MAX - 1, u64::MAX] {
        assert_eq!(penalty(price), model::objects::penalty(price), "price {price}");
        for (reserve, fee) in [(0u64, 0u64), (5, 5), (10, 3), (3, 10), (u64::MAX, 1), (1, u64::MAX)] {
            let escrow = model::objects::EscrowNote {
                price,
                fee_reserve: reserve,
                recipient: model::objects::Authority([1; 32]),
                refund_to: model::objects::Authority([2; 32]),
                canceller: model::objects::Authority([3; 32]),
                seed: [4; 32],
                blinding: [5; 32],
            };
            let hints = Hints::for_resolution(price, reserve, fee);
            assert_eq!(hints.penalty, Fr::from(model::objects::penalty(price)));
            assert_eq!(hints.surplus, Fr::from(model::objects::fee_surplus(&escrow, fee)));
            assert_eq!(hints.shortfall, Fr::from(model::objects::fee_shortfall(&escrow, fee)));
            assert_eq!(
                Fr::from(price) + hints.penalty_rem,
                hints.penalty * Fr::from(100u64),
                "price + rem = 100 * penalty for {price}"
            );
        }
    }
}

// ---- (a) Merkle path and root ----------------------------------------------

#[test]
fn a_wrong_sibling_is_refused() {
    for level in [0, 7, TREE_DEPTH - 1] {
        refused(Case::Transfer, |w| w.inputs[0].path[level] += Fr::one());
        refused(Case::ClaimSurplus, |w| w.inputs[0].path[level] += Fr::one());
    }
}

#[test]
fn a_wrong_root_is_refused() {
    public_refused(Case::Transfer, |p| p.root += Fr::one());
    public_refused(Case::DeclineSurplus, |p| p.root += Fr::one());
}

#[test]
fn a_wrong_position_is_refused() {
    refused(Case::Transfer, |w| w.inputs[0].position ^= 1);
    refused(Case::ClaimSurplus, |w| w.inputs[0].position += 1 << (TREE_DEPTH - 1));
}

#[test]
fn a_note_that_is_not_in_the_tree_is_refused() {
    refused(Case::Transfer, |w| w.inputs[0].note.blinding += Fr::one());
    refused(Case::Transfer, |w| w.inputs[0].created_at += Fr::one());
}

#[test]
fn a_top_up_outside_the_tree_is_refused() {
    refused(Case::ClaimTopUp, |w| w.inputs[1].path[3] += Fr::one());
}

// ---- (b) spending secret and nullifier -------------------------------------

#[test]
fn a_wrong_owner_secret_is_refused() {
    refused(Case::Transfer, |w| w.inputs[0].secret = f("thief"));
    refused(Case::ClaimTopUp, |w| w.inputs[1].secret = f("thief"));
}

#[test]
fn only_the_right_party_can_resolve_an_escrow() {
    refused(Case::ClaimSurplus, |w| w.inputs[0].secret = f("canceller"));
    refused(Case::DeclineSurplus, |w| w.inputs[0].secret = f("canceller"));
    refused(Case::RefundSurplus, |w| w.inputs[0].secret = f("recipient"));
    for case in [Case::ClaimSurplus, Case::DeclineSurplus, Case::RefundSurplus] {
        refused(case, |w| w.inputs[0].secret = f("refund-key"));
    }
}

#[test]
fn a_forged_nullifier_is_refused() {
    for slot in 0..N_IN {
        public_refused(Case::Transfer, |p| p.nullifiers[slot] += Fr::one());
        public_refused(Case::ClaimTopUp, |p| p.nullifiers[slot] += Fr::one());
    }
}

#[test]
fn a_nullifier_from_the_wrong_domain_is_refused() {
    let mut built = build(Case::Transfer);
    let input = &built.circuit.witness.inputs[0];
    built.circuit.public.nullifiers[0] =
        escrow_nullifier(input.secret, input.note.commitment(), input.position);
    assert!(!satisfied(built.circuit));

    let mut built = build(Case::ClaimSurplus);
    let input = &built.circuit.witness.inputs[0];
    built.circuit.public.nullifiers[0] =
        ordinary_nullifier(input.note.seed, input.note.commitment(), input.position);
    assert!(!satisfied(built.circuit));
}

#[test]
fn a_dummy_slot_cannot_publish_a_real_notes_nullifier() {
    let real = build(Case::Transfer).circuit.public.nullifiers[0];
    let mut built = build(Case::Transfer);
    built.circuit.public.nullifiers[1] = real;
    assert!(!satisfied(built.circuit));
}

#[test]
fn a_dummy_input_carries_no_value() {
    refused(Case::Transfer, |w| {
        w.inputs[1].note.value = 5u64.into();
        w.outputs[2] = Note::ordinary(5, authority(f("payee")), f("minted"));
    });
}

// ---- (c) value and range ---------------------------------------------------

#[test]
fn value_inflation_is_refused() {
    for case in Case::ALL {
        refused(case, |w| {
            let slot = if case.branch() == Branch::Open { 2 } else { 0 };
            w.outputs[slot].value += Fr::one();
        });
    }
}

#[test]
fn value_deflation_is_refused() {
    refused(Case::Transfer, |w| w.outputs[0].value -= Fr::one());
}

#[test]
fn a_negative_output_cannot_fund_a_larger_one() {
    // Balanced in the field; only the range check stops it.
    refused(Case::Transfer, |w| {
        w.outputs[0].value += Fr::from(1_000_000u64);
        w.outputs[2] = Note { value: neg(1_000_000), ..Note::ordinary(0, authority(f("x")), f("y")) };
    });
}

#[test]
fn an_output_at_2_pow_64_is_refused() {
    let big = Fr::from(u64::MAX) + Fr::one();
    refused(Case::Transfer, |w| {
        w.outputs[0].value = big;
        w.outputs[2] = Note { value: Fr::from(FUNDING - BASE_FEE - 1_000) - big, ..w.outputs[1] };
    });
}

#[test]
fn an_escrow_whose_total_overflows_u64_is_refused() {
    refused(Case::Open, |w| {
        w.outputs[0].value = Fr::from(u64::MAX);
        w.outputs[0].fee_reserve = Fr::from(BASE_FEE);
        // Conservation over the integers would need more than the inputs.
        w.outputs[2].value = Fr::from(FUNDING - BASE_FEE - SURCHARGE) - w.outputs[0].value - w.outputs[0].fee_reserve;
        w.admission.escrow = w.outputs[0].commitment();
    });
}

#[test]
fn an_out_of_range_public_amount_is_refused() {
    let big = Fr::from(u64::MAX) + Fr::one();
    public_refused(Case::Transfer, |p| p.base_fee = big);
    public_refused(Case::Transfer, |p| p.not_before = big);
    public_refused(Case::Transfer, |p| p.not_after = big);
}

#[test]
fn a_negative_base_fee_cannot_mint() {
    let mut built = build(Case::Transfer);
    built.circuit.witness.outputs[0].value += Fr::from(BASE_FEE + 7);
    built.circuit.public.base_fee = neg(7);
    built.reseal();
    assert!(!satisfied(built.circuit));
}

#[test]
fn unused_outputs_carry_no_value() {
    refused(Case::Transfer, |w| {
        w.outputs[0].value -= Fr::from(5u64);
        w.outputs[2].value = 5u64.into(); // hidden in a retired slot
    });
    refused(Case::ClaimExactFee, |w| {
        w.outputs[0].value -= Fr::from(5u64);
        w.outputs[1].value = 5u64.into();
    });
}

#[test]
fn surplus_and_shortfall_hints_are_range_checked() {
    refused(Case::DeclineSurplus, |w| {
        w.hints.surplus = neg(1);
        w.hints.shortfall = Fr::zero();
    });
    refused(Case::ClaimTopUp, |w| w.hints.shortfall = neg(1));
}

// ---- (d) penalty -----------------------------------------------------------

#[test]
fn a_wrong_penalty_is_refused_even_when_balanced() {
    for case in [Case::DeclineSurplus, Case::DeclineTopUp, Case::RefundSurplus, Case::RefundTopUp] {
        for delta in [Fr::one(), -Fr::one()] {
            refused(case, |w| {
                w.hints.penalty += delta;
                w.outputs[1].value += delta;
                w.outputs[0].value -= delta;
            });
        }
    }
}

#[test]
fn rounding_the_penalty_down_is_refused() {
    refused(Case::DeclineSurplus, |w| {
        let down = Fr::from(PRICE / 100);
        let up = Fr::from(PENALTY);
        w.hints.penalty = down;
        w.hints.penalty_rem = neg(PRICE % 100);
        w.outputs[1].value = down;
        w.outputs[0].value += up - down;
    });
}

#[test]
fn a_remainder_of_100_is_refused() {
    refused(Case::DeclineSurplus, |w| {
        w.hints.penalty += Fr::one();
        w.hints.penalty_rem += Fr::from(100u64);
        w.outputs[1].value += Fr::one();
        w.outputs[0].value -= Fr::one();
    });
}

#[test]
fn the_retired_output_must_equal_the_penalty() {
    refused(Case::RefundSurplus, |w| {
        w.outputs[1].value -= Fr::one();
        w.outputs[0].value += Fr::one();
    });
    refused(Case::RefundSurplus, |w| w.outputs[1].kind = NoteKind::Ordinary);
}

// ---- (e) claim deadline ----------------------------------------------------

#[test]
fn an_expired_claim_is_refused() {
    for case in [Case::ClaimSurplus, Case::ClaimExactFee, Case::ClaimTopUp] {
        let mut built = build(case);
        built.circuit.public.not_after = (CREATED_AT + TTL + 1).into();
        built.reseal();
        assert!(!satisfied(built.circuit), "{case:?}");
    }
}

#[test]
fn a_claim_cannot_move_its_created_at() {
    refused(Case::ClaimSurplus, |w| w.inputs[0].created_at += Fr::from(TTL));
}

#[test]
fn a_created_at_whose_deadline_overflows_is_refused() {
    let mut built = build(Case::DeclineSurplus);
    let late = u64::MAX - TTL + 1;
    let escrow = built.circuit.witness.inputs[0].note;
    let mut tree = MerkleTree::new();
    tree.append(f("filler-leaf")).unwrap();
    tree.append(f("filler-leaf-2")).unwrap();
    tree.append(leaf(escrow.commitment(), late.into())).unwrap();
    let secret = built.circuit.witness.inputs[0].secret;
    built.circuit.witness.inputs[0] = InputWitness::real(&tree, escrow, late, 2, secret);
    built.circuit.public.root = tree.root();
    built.reseal();
    assert!(!satisfied(built.circuit));
}

#[test]
fn a_created_at_above_u64_is_refused() {
    let big = Fr::from(u64::MAX) + Fr::one();
    let mut built = build(Case::Transfer);
    let note = built.circuit.witness.inputs[0].note;
    let mut tree = MerkleTree::new();
    tree.append(f("filler-leaf")).unwrap();
    tree.append(leaf(note.commitment(), big)).unwrap();
    let input = &mut built.circuit.witness.inputs[0];
    input.created_at = big;
    input.path = tree.path(1);
    built.circuit.public.root = tree.root();
    built.reseal();
    assert!(!satisfied(built.circuit));
}

#[test]
fn fee_hints_are_zero_outside_a_resolution() {
    for case in [Case::Transfer, Case::Invited, Case::Open] {
        refused(case, |w| w.hints.surplus = Fr::one());
        refused(case, |w| w.hints.shortfall = Fr::one());
    }
}

// ---- (f) refund blinding and destination -----------------------------------

#[test]
fn a_wrong_refund_blinding_is_refused() {
    for case in [Case::DeclineSurplus, Case::DeclineTopUp, Case::RefundSurplus, Case::RefundTopUp] {
        refused(case, |w| w.outputs[0].blinding = f("unknown-to-the-sender"));
    }
}

#[test]
fn a_wrong_claim_surplus_blinding_is_refused() {
    refused(Case::ClaimSurplus, |w| w.outputs[1].blinding = f("unknown-to-the-sender"));
}

#[test]
fn the_refund_blinding_depends_on_the_escrows_position() {
    refused(Case::DeclineSurplus, |w| w.outputs[0].blinding = refund_blinding(w.inputs[0].note.seed, 3));
}

#[test]
fn refunds_and_surplus_go_only_to_refund_to() {
    for case in [Case::DeclineSurplus, Case::RefundSurplus] {
        refused(case, |w| w.outputs[0].owner = authority(f("thief")));
    }
    refused(Case::ClaimSurplus, |w| w.outputs[1].owner = authority(f("thief")));
}

#[test]
fn a_claim_pays_exactly_the_price_to_the_recipient() {
    refused(Case::ClaimSurplus, |w| w.outputs[0].owner = authority(f("thief")));
    refused(Case::ClaimSurplus, |w| {
        w.outputs[0].value -= Fr::one();
        w.outputs[1].value += Fr::one();
    });
}

#[test]
fn a_claim_cannot_keep_the_surplus() {
    refused(Case::ClaimSurplus, |w| {
        w.outputs[0].value += Fr::from(SURPLUS);
        w.outputs[1] = Note::retired(0, f("unused"));
    });
    refused(Case::ClaimSurplus, |w| w.outputs[1] = Note::retired(SURPLUS, f("burned")));
}

// ---- (g) W3: the empty admission record -------------------------------------

#[test]
fn a_non_zero_field_in_an_empty_record_is_refused() {
    for case in EMPTY_RECORD {
        refused(case, |w| w.admission.contact_key = Fr::one());
        refused(case, |w| w.admission.request_digest = Fr::one());
        refused(case, |w| w.admission.tier = Fr::one());
        refused(case, |w| w.admission.tier = Fr::from(2u64));
        refused(case, |w| w.admission.has_escrow = Fr::one());
        refused(case, |w| w.admission.escrow = Fr::one());
    }
}

#[test]
fn an_empty_records_blinding_is_free() {
    for case in EMPTY_RECORD {
        let mut built = build(case);
        built.circuit.witness.admission.blinding = f("another-blinding");
        built.reseal();
        assert!(satisfied(built.circuit), "{case:?}");
    }
}

#[test]
fn the_admission_commitment_is_bound() {
    public_refused(Case::Invited, |p| p.admission += Fr::one());
}

#[test]
fn an_invited_request_has_its_tier_and_no_escrow() {
    refused(Case::Invited, |w| w.admission.tier = Fr::from(2u64));
    refused(Case::Invited, |w| w.admission.tier = Fr::zero());
    refused(Case::Invited, |w| w.admission.has_escrow = Fr::one());
    refused(Case::Invited, |w| w.admission.escrow = Fr::one());
}

#[test]
fn a_stranger_record_names_this_transactions_escrow() {
    refused(Case::Open, |w| w.admission.escrow = f("another-escrow"));
    refused(Case::Open, |w| w.admission.has_escrow = Fr::zero());
    refused(Case::Open, |w| w.admission.tier = Fr::one());
}

// ---- Open --------------------------------------------------------------------

#[test]
fn open_must_retire_exactly_the_surcharge() {
    refused(Case::Open, |w| {
        w.outputs[1].value -= Fr::one();
        w.outputs[2].value += Fr::one();
    });
    refused(Case::Open, |w| w.outputs[1].kind = NoteKind::Ordinary);
}

#[test]
fn open_needs_a_reserve_of_at_least_the_base_fee() {
    refused(Case::Open, |w| {
        let lower = Fr::from(RESERVE_SURPLUS - BASE_FEE + 1);
        w.outputs[0].fee_reserve -= lower;
        w.outputs[2].value += lower;
        w.admission.escrow = w.outputs[0].commitment();
    });
}

#[test]
fn open_creates_an_escrow_in_output_zero() {
    refused(Case::Open, |w| {
        w.outputs[0].kind = NoteKind::Ordinary;
        w.admission.escrow = w.outputs[0].commitment();
    });
}

#[test]
fn only_open_can_create_an_escrow() {
    refused(Case::Transfer, |w| {
        let value = w.outputs[0].value;
        w.outputs[0] = Note { value, ..escrow_note(0) };
    });
}

// ---- types, selectors and the top-up rule -----------------------------------

#[test]
fn exactly_one_branch_is_selected() {
    // Claim the same transaction under each other branch.
    for case in [Case::Transfer, Case::ClaimSurplus, Case::DeclineSurplus] {
        for branch in Branch::ALL {
            if branch != case.branch() {
                refused(case, |w| w.branch = branch);
            }
        }
    }
}

#[test]
fn ordinary_branches_cannot_spend_an_escrow() {
    let escrow = escrow_note(RESERVE_SURPLUS);
    for branch in [Branch::Transfer, Branch::Invited, Branch::Open] {
        let mut built = build(Case::ClaimSurplus);
        built.circuit.witness.branch = branch;
        built.reseal();
        assert_eq!(built.circuit.witness.inputs[0].note, escrow);
        assert!(!satisfied(built.circuit), "{branch:?}");
    }
}

#[test]
fn a_resolution_must_spend_an_escrow() {
    refused(Case::ClaimSurplus, |w| w.inputs[0].kind = InputKind::Ordinary);
    refused(Case::ClaimSurplus, |w| w.inputs[0].kind = InputKind::Dummy);
}

#[test]
fn a_retired_note_cannot_be_spent() {
    let note = Note::retired(777, f("retired"));
    let mut tree = MerkleTree::new();
    tree.append(leaf(note.commitment(), CREATED_AT.into())).unwrap();
    let mut built = build(Case::Transfer);
    let input = InputWitness::real(&tree, note, CREATED_AT, 0, f("funder"));
    assert_eq!(input.kind, InputKind::Ordinary);
    built.circuit.witness.inputs[0] = input;
    built.circuit.witness.outputs =
        [Note::ordinary(0, authority(f("x")), f("a")), Note::retired(0, f("b")), Note::retired(0, f("c"))];
    built.circuit.public.root = tree.root();
    built.circuit.public.base_fee = 777u64.into();
    built.reseal();
    assert!(!satisfied(built.circuit));
}

#[test]
fn a_top_up_is_refused_when_the_reserve_covers_the_fee() {
    // Spend a real ordinary note alongside a sufficient reserve.
    let mut built = build(Case::ClaimSurplus);
    let top_up = build(Case::ClaimTopUp).circuit.witness.inputs[1].clone();
    let tree_top_up = Note::ordinary(TOP_UP_VALUE, authority(f("resolver")), f("top-up/blinding"));
    assert_eq!(top_up.note, tree_top_up);
    let mut tree = MerkleTree::new();
    tree.append(f("filler-leaf")).unwrap();
    tree.append(f("filler-leaf-2")).unwrap();
    let escrow = built.circuit.witness.inputs[0].note;
    tree.append(leaf(escrow.commitment(), CREATED_AT.into())).unwrap();
    tree.append(leaf(tree_top_up.commitment(), CREATED_AT.into())).unwrap();
    let secret = built.circuit.witness.inputs[0].secret;
    built.circuit.witness.inputs =
        [InputWitness::real(&tree, escrow, CREATED_AT, 2, secret), InputWitness::real(&tree, tree_top_up, CREATED_AT, 3, f("resolver"))];
    built.circuit.witness.outputs[2] = Note::ordinary(TOP_UP_VALUE, authority(f("resolver")), f("change"));
    built.circuit.public.root = tree.root();
    built.reseal();
    assert!(!satisfied(built.circuit));
}

#[test]
fn a_shortfall_needs_a_real_top_up() {
    for case in [Case::ClaimTopUp, Case::DeclineTopUp, Case::RefundTopUp] {
        refused(case, |w| {
            w.inputs[1] = InputWitness::dummy(f("dummy-input"));
            w.outputs[2] = Note::retired(0, f("unused"));
        });
    }
}

#[test]
fn the_surplus_and_shortfall_cannot_both_be_set() {
    refused(Case::DeclineSurplus, |w| {
        w.hints.surplus += Fr::one();
        w.hints.shortfall += Fr::one();
        w.outputs[0].value += Fr::one();
    });
}

#[test]
fn a_forged_surplus_is_refused() {
    refused(Case::DeclineSurplus, |w| {
        w.hints.surplus += Fr::one();
        w.outputs[0].value += Fr::one();
    });
}

#[test]
fn top_up_change_must_be_exact() {
    for case in [Case::ClaimTopUp, Case::DeclineTopUp, Case::RefundTopUp] {
        refused(case, |w| w.outputs[2].value += Fr::one());
        refused(case, |w| w.outputs[2].value -= Fr::one());
    }
}

#[test]
fn without_a_top_up_output_two_stays_unused() {
    refused(Case::DeclineSurplus, |w| {
        w.outputs[0].value -= Fr::from(3u64);
        w.outputs[2] = Note::ordinary(3, authority(f("thief")), f("skim"));
    });
}

#[test]
fn a_non_escrow_note_cannot_hide_escrow_fields() {
    refused(Case::Transfer, |w| w.outputs[0].seed = Fr::one());
    refused(Case::Transfer, |w| w.outputs[0].fee_reserve = Fr::one());
    refused(Case::Transfer, |w| w.outputs[0].refund_to = Fr::one());
    refused(Case::Transfer, |w| w.outputs[0].canceller = Fr::one());
    refused(Case::Transfer, |w| w.outputs[2].owner = Fr::one());
}

#[test]
fn every_public_commitment_is_bound() {
    for slot in 0..N_OUT {
        public_refused(Case::Transfer, |p| p.commitments[slot] += Fr::one());
    }
}

// ---- attacks that reach one specific constraint -------------------------------
//
// Each is balanced and otherwise well formed, so exactly the named rule
// stops it. Mutation checks showed the simpler alterations above can be
// caught by an earlier rule and leave these constraints untested.

/// Alter the whole transaction, re-derive the public inputs, expect refusal.
fn attack(case: Case, alter: impl FnOnce(&mut Built)) {
    let mut built = build(case);
    assert!(satisfied(built.circuit.clone()), "{case:?} must be valid first");
    alter(&mut built);
    built.reseal();
    assert!(!satisfied(built.circuit), "{case:?}: the attack was accepted");
}

/// Put `escrow` and `second` at positions 2 and 3 of a fresh tree and spend
/// them, as if a note of this exact shape already existed.
fn spend_from_tree(built: &mut Built, escrow: Note, second: Option<(Note, Fr)>) {
    let mut tree = MerkleTree::new();
    tree.append(f("filler-leaf")).unwrap();
    tree.append(f("filler-leaf-2")).unwrap();
    tree.append(leaf(escrow.commitment(), CREATED_AT.into())).unwrap();
    let w = &mut built.circuit.witness;
    let secret = w.inputs[0].secret;
    if let Some((note, _)) = &second {
        tree.append(leaf(note.commitment(), CREATED_AT.into())).unwrap();
    }
    w.inputs[0] = InputWitness::real(&tree, escrow, CREATED_AT, 2, secret);
    if let Some((note, owner_secret)) = second {
        w.inputs[1] = InputWitness::real(&tree, note, CREATED_AT, 3, owner_secret);
    }
    built.circuit.public.root = tree.root();
}

fn top_up() -> Option<(Note, Fr)> {
    Some((top_up_note(), f("resolver")))
}

fn as_transfer(w: &mut TxWitness, value: u64) {
    w.branch = Branch::Transfer;
    w.hints = Hints::ZERO;
    w.outputs = [
        Note::ordinary(value, authority(f("thief")), f("stolen")),
        Note::retired(0, f("u1")),
        Note::retired(0, f("u2")),
    ];
}

#[test]
fn no_branch_selected_is_refused() {
    attack(Case::Transfer, |b| {
        let mut bits = Flags::honest(&b.circuit.witness);
        bits.branch = [false; 6];
        b.circuit.forced_flags = Some(bits);
    });
}

#[test]
fn an_input_with_no_type_cannot_mint_a_second_nullifier() {
    // Tag zero would give the same note a fresh nullifier: a double spend.
    let mut built = build(Case::Transfer);
    let mut bits = Flags::honest(&built.circuit.witness);
    bits.inputs[0] = [false; 3];
    built.circuit.forced_flags = Some(bits);
    let input = &built.circuit.witness.inputs[0];
    built.circuit.public.nullifiers[0] =
        poseidon::hash_with_tag(Fr::zero(), &[input.secret, input.note.commitment(), input.position.into()]);
    assert!(!satisfied(built.circuit));
}

#[test]
fn an_output_with_no_type_is_refused() {
    attack(Case::Transfer, |b| {
        let mut bits = Flags::honest(&b.circuit.witness);
        bits.outputs[0] = [false; 3];
        b.circuit.forced_flags = Some(bits);
    });
}

#[test]
fn a_negative_price_is_refused() {
    attack(Case::Open, |b| {
        let w = &mut b.circuit.witness;
        w.outputs[0].value = neg(5);
        w.outputs[0].fee_reserve += Fr::from(PRICE + 5);
        w.admission.escrow = w.outputs[0].commitment();
    });
}

#[test]
fn an_escrow_with_a_negative_reserve_is_refused() {
    attack(Case::DeclineTopUp, |b| {
        let mut escrow = escrow_note(0);
        escrow.fee_reserve = neg(5);
        spend_from_tree(b, escrow, Some((funding_note(), f("funder"))));
        let w = &mut b.circuit.witness;
        w.hints.surplus = Fr::zero();
        w.hints.shortfall = Fr::from(BASE_FEE + 5);
        w.outputs[0] = Note::ordinary(PRICE - PENALTY, escrow.refund_to, refund_blinding(escrow.seed, 2));
        w.outputs[2].value = Fr::from(FUNDING - BASE_FEE - 5);
    });
}

#[test]
fn a_spent_escrow_whose_total_overflows_is_refused() {
    attack(Case::DeclineSurplus, |b| {
        let mut escrow = escrow_note(BASE_FEE);
        escrow.value = u64::MAX.into();
        spend_from_tree(b, escrow, None);
        let w = &mut b.circuit.witness;
        let p = penalty(u64::MAX);
        w.hints = Hints::for_resolution(u64::MAX, BASE_FEE, BASE_FEE);
        w.outputs[0] = Note::ordinary(u64::MAX - p, escrow.refund_to, refund_blinding(escrow.seed, 2));
        w.outputs[1] = Note::retired(p, f("penalty"));
    });
}

#[test]
fn an_ordinary_note_cannot_carry_a_reserve() {
    attack(Case::Transfer, |b| {
        let out = &mut b.circuit.witness.outputs[0];
        out.value -= Fr::one();
        out.fee_reserve = Fr::one();
    });
}

#[test]
fn a_transfer_cannot_steal_an_escrow_from_either_input_slot() {
    let total = PRICE + RESERVE_SURPLUS - BASE_FEE;
    attack(Case::ClaimSurplus, |b| as_transfer(&mut b.circuit.witness, total));
    attack(Case::ClaimSurplus, |b| {
        let w = &mut b.circuit.witness;
        w.inputs.swap(0, 1);
        as_transfer(w, total);
    });
}

#[test]
fn only_output_zero_of_an_open_can_be_an_escrow() {
    let escrow = Note::escrow(500, 500, f("a"), f("b"), f("c"), f("d"), f("e"));
    attack(Case::Transfer, |b| b.circuit.witness.outputs[1] = escrow);
    attack(Case::Transfer, |b| {
        let w = &mut b.circuit.witness;
        w.outputs[1] = Note::retired(0, f("u1"));
        w.outputs[2] = escrow;
    });
}

#[test]
fn a_transfer_cannot_retire_value() {
    attack(Case::Transfer, |b| {
        let w = &mut b.circuit.witness;
        w.outputs[0] = Note::retired(FUNDING - BASE_FEE - 1_000, f("r0"));
    });
    attack(Case::Transfer, |b| b.circuit.witness.outputs[1] = Note::retired(1_000, f("r1")));
}

#[test]
fn a_negative_surplus_cannot_replace_the_top_up() {
    attack(Case::DeclineTopUp, |b| {
        let w = &mut b.circuit.witness;
        let surplus = Fr::from(RESERVE_SHORT) - Fr::from(BASE_FEE);
        w.inputs[1] = InputWitness::dummy(f("dummy-input"));
        w.hints.surplus = surplus;
        w.hints.shortfall = Fr::zero();
        w.outputs[0].value = Fr::from(PRICE - PENALTY) + surplus;
        w.outputs[2] = Note::retired(0, f("u2"));
    });
}

#[test]
fn a_negative_shortfall_cannot_take_the_senders_surplus() {
    attack(Case::DeclineSurplus, |b| {
        let escrow = b.circuit.witness.inputs[0].note;
        spend_from_tree(b, escrow, top_up());
        let w = &mut b.circuit.witness;
        w.hints.surplus = Fr::zero();
        w.hints.shortfall = Fr::from(BASE_FEE) - Fr::from(RESERVE_SURPLUS);
        w.outputs[0].value = Fr::from(PRICE - PENALTY);
        w.outputs[2] = Note::ordinary(TOP_UP_VALUE + SURPLUS, authority(f("thief")), f("loot"));
    });
}

#[test]
fn surplus_and_shortfall_cannot_both_be_non_zero_when_balanced() {
    attack(Case::DeclineTopUp, |b| {
        let w = &mut b.circuit.witness;
        w.hints.surplus = Fr::one();
        w.hints.shortfall = Fr::from(SHORTFALL + 1);
        w.outputs[0].value += Fr::one();
        w.outputs[2].value -= Fr::one();
    });
}

#[test]
fn a_false_shortfall_cannot_divert_the_surplus_to_the_resolver() {
    attack(Case::DeclineSurplus, |b| {
        let escrow = b.circuit.witness.inputs[0].note;
        spend_from_tree(b, escrow, top_up());
        let w = &mut b.circuit.witness;
        w.hints.surplus = Fr::zero();
        w.hints.shortfall = Fr::one();
        w.outputs[0].value = Fr::from(PRICE - PENALTY);
        w.outputs[2] = Note::ordinary(TOP_UP_VALUE + SURPLUS, authority(f("thief")), f("loot"));
    });
}

#[test]
fn a_zero_value_top_up_is_refused_when_none_is_needed() {
    attack(Case::DeclineSurplus, |b| {
        let escrow = b.circuit.witness.inputs[0].note;
        let zero = Note::ordinary(0, authority(f("resolver")), f("zero-note"));
        spend_from_tree(b, escrow, Some((zero, f("resolver"))));
    });
}

#[test]
fn a_zero_value_ordinary_output_two_is_refused_without_a_top_up() {
    attack(Case::DeclineSurplus, |b| {
        b.circuit.witness.outputs[2] = Note::ordinary(0, authority(f("x")), f("extra"));
    });
}

#[test]
fn a_zero_value_ordinary_surplus_slot_is_refused() {
    attack(Case::ClaimExactFee, |b| {
        b.circuit.witness.outputs[1] = Note::ordinary(0, authority(f("x")), f("extra"));
    });
}

#[test]
fn a_top_up_cannot_shift_value_out_of_the_payout() {
    attack(Case::ClaimTopUp, |b| {
        let w = &mut b.circuit.witness;
        w.outputs[0].value -= Fr::one();
        w.outputs[2].value += Fr::one();
    });
}

#[test]
fn a_top_up_cannot_shift_value_out_of_the_refund() {
    for case in [Case::DeclineTopUp, Case::RefundTopUp] {
        attack(case, |b| {
            let w = &mut b.circuit.witness;
            w.outputs[0].value -= Fr::one();
            w.outputs[2].value += Fr::one();
        });
    }
}

#[test]
fn a_top_up_cannot_shift_value_out_of_the_penalty() {
    for case in [Case::DeclineTopUp, Case::RefundTopUp] {
        attack(case, |b| {
            let w = &mut b.circuit.witness;
            w.outputs[1].value -= Fr::one();
            w.outputs[2].value += Fr::one();
        });
    }
}

#[test]
fn a_remainder_that_fits_seven_bits_but_exceeds_99_is_refused() {
    attack(Case::DeclineSurplus, |b| {
        const P: u64 = 10_190; // honest penalty 102, remainder 10
        let mut escrow = escrow_note(RESERVE_SURPLUS);
        escrow.value = P.into();
        spend_from_tree(b, escrow, None);
        let w = &mut b.circuit.witness;
        w.hints = Hints::for_resolution(P, RESERVE_SURPLUS, BASE_FEE);
        w.hints.penalty = 103u64.into();
        w.hints.penalty_rem = 110u64.into();
        w.outputs[0] = Note::ordinary(P - 103 + SURPLUS, escrow.refund_to, refund_blinding(escrow.seed, 2));
        w.outputs[1] = Note::retired(103, f("penalty"));
    });
}
