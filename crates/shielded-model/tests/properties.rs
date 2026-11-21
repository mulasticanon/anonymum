//! Spec section 5: every property, with the adversarial cases.
//! The harness (`common::World`) also checks, on every submission, that an
//! accepted transaction keeps the conservation equation and a rejected one
//! changes nothing.

mod common;

use anonymum_shielded_model::build::{rebind, reseal, TxBuilder};
use anonymum_shielded_model::wallet::{escrow_status, EscrowStatus};
use anonymum_shielded_model::*;
use common::*;

// ---- conservation and the happy paths ---------------------------------------

#[test]
fn every_branch_conserves_value() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    assert!(w.conserved());
    // Transfer
    let coins = w.position_of(&ordinary(500, &p.recipient, "recipient-coins"));
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[coins as usize], w.created_at(coins), coins, p.recipient)
        .output(ordinary(200, &p.sender, "t/a"))
        .output(ordinary(500 - 200 - F, &p.recipient, "t/b"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    // Claim
    let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "claim");
    w.submit(&public, &witness).unwrap();
    assert!(w.conserved());
    assert_eq!(w.chain.fees_collected(), 3 * u128::from(F));
    assert_eq!(w.chain.fees_burned(), 3 * u128::from(F) / 2, "the public base fee is split");
}

#[test]
fn decline_and_sender_refund_each_conserve_value() {
    let p = parties();
    for (branch, wait) in [(Branch::Decline, 0), (Branch::SenderRefund, 0), (Branch::SenderRefund, DAY)] {
        let (mut w, escrow, pos) = world_with_escrow(101);
        w.advance(wait);
        let who = if branch == Branch::Decline { p.recipient } else { p.canceller };
        let (public, witness) = refund_tx(&w, branch, &escrow, pos, who, "r");
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("{branch:?} after {wait}s: {e:?}"));
        assert!(w.conserved());
    }
}

#[test]
fn an_invited_request_pays_only_the_base_fee_and_opens_as_invited() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "coins")]);
    let record = AdmissionRecord {
        contact_key: CONTACT_KEY,
        request_digest: REQUEST,
        tier: Tier::Invited,
        escrow: None,
        blinding: blinding("invited"),
    };
    let (public, witness) = TxBuilder::new(Branch::InvitedRequest, b"inv")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "inv/change"))
        .admission(record)
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    assert_eq!(open_receipt(&public.admission, &record, &CONTACT_KEY, &REQUEST, None), Ok(Tier::Invited));
}

// ---- one outcome per escrow -------------------------------------------------

#[test]
fn an_escrow_resolves_once_whichever_branches_are_tried() {
    let p = parties();
    let attempts: [(Branch, Branch); 7] = [
        (Branch::Claim, Branch::Decline),
        (Branch::Decline, Branch::Claim),
        (Branch::SenderRefund, Branch::Claim),
        (Branch::Claim, Branch::SenderRefund),
        (Branch::Decline, Branch::SenderRefund),
        (Branch::SenderRefund, Branch::Decline),
        (Branch::Claim, Branch::Claim),
    ];
    for (first, second) in attempts {
        let (mut w, escrow, pos) = world_with_escrow(101);
        let make = |w: &World, b: Branch, tag: &str| match b {
            Branch::Claim => claim_tx(w, &escrow, pos, p.recipient, tag),
            Branch::Decline => refund_tx(w, b, &escrow, pos, p.recipient, tag),
            _ => refund_tx(w, b, &escrow, pos, p.canceller, tag),
        };
        let (public, witness) = make(&w, first, "first");
        w.submit(&public, &witness).unwrap();
        let (public, witness) = make(&w, second, "second");
        assert_eq!(w.submit(&public, &witness), Err(Reject::NullifierUsed), "{first:?} then {second:?}");
    }
}

#[test]
fn an_early_sender_refund_cannot_be_repeated_after_the_deadline() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (public, witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "early");
    w.submit(&public, &witness).unwrap();
    w.advance(DAY);
    let (public, witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "late");
    assert_eq!(w.submit(&public, &witness), Err(Reject::NullifierUsed));
}

#[test]
fn the_escrow_nullifier_is_the_same_on_every_branch() {
    let p = parties();
    let (w, escrow, pos) = world_with_escrow(101);
    let claim = claim_tx(&w, &escrow, pos, p.recipient, "a").0.nullifiers[0];
    let decline = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "b").0.nullifiers[0];
    let refund = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "c").0.nullifiers[0];
    assert_eq!(claim, decline);
    assert_eq!(claim, refund);
}

#[test]
fn two_identical_commitments_at_different_positions_resolve_separately() {
    let p = parties();
    let mut w = World::new(&[ordinary(10_000, &p.sender, "f1"), ordinary(10_000, &p.sender, "f2")]);
    let escrow = escrow_note(101, &p, "twin"); // same seed and blinding twice
    let (public, witness) = open_tx(&w, 0, &escrow, "open-1");
    w.submit(&public, &witness).unwrap();
    let first = w.position_of(&Note::Escrow(escrow));
    let (public, witness) = open_tx(&w, 1, &escrow, "open-2");
    w.submit(&public, &witness).unwrap();
    let second = w.position_of(&Note::Escrow(escrow));
    assert_ne!(first, second);
    assert_eq!(w.chain.leaves()[first as usize].commitment, w.chain.leaves()[second as usize].commitment);

    let (public, witness) = claim_tx(&w, &escrow, first, p.recipient, "c1");
    let nf_first = public.nullifiers[0];
    w.submit(&public, &witness).unwrap();
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, second, p.recipient, "d2");
    assert_ne!(public.nullifiers[0], nf_first, "position-bound: each insertion has its own identity");
    w.submit(&public, &witness).unwrap();
    let (public, witness) = claim_tx(&w, &escrow, second, p.recipient, "c2");
    assert_eq!(w.submit(&public, &witness), Err(Reject::NullifierUsed));
    assert!(w.conserved());
}

#[test]
fn two_escrows_with_the_same_seed_give_different_refunds() {
    // v0.5, I9: the refund blinding comes from the seed and the escrow's
    // position, so sharing a seed no longer makes two refunds identical.
    let p = parties();
    for twins in [false, true] {
        let mut w = World::new(&[ordinary(10_000, &p.sender, "f1"), ordinary(10_000, &p.sender, "f2")]);
        let first = escrow_note(101, &p, "shared");
        // Same seed; either an exact twin, or a different escrow (blinding).
        let second = if twins { first } else { EscrowNote { blinding: blinding("other"), ..first } };
        assert_eq!(first.seed, second.seed);
        let (public, witness) = open_tx(&w, 0, &first, "o1");
        w.submit(&public, &witness).unwrap();
        let pos1 = w.chain.leaves().iter().position(|l| l.commitment == Note::Escrow(first).commitment()).unwrap() as u64;
        let (public, witness) = open_tx(&w, 1, &second, "o2");
        w.submit(&public, &witness).unwrap();
        let pos2 = w.position_of(&Note::Escrow(second));
        assert_ne!(pos1, pos2);

        let (public, witness) = refund_tx(&w, Branch::Decline, &first, pos1, p.recipient, "d1");
        w.submit(&public, &witness).unwrap();
        let (public, witness) = refund_tx(&w, Branch::Decline, &second, pos2, p.recipient, "d2");
        w.submit(&public, &witness).unwrap();
        let (r1, r2) = (derived_refund(&first, pos1, F), derived_refund(&second, pos2, F));
        assert_ne!(r1.commitment(), r2.commitment(), "twins={twins}: refunds must differ");

        // The sender finds each refund through the transaction that consumed
        // its escrow, and can spend both.
        for (escrow, escrow_pos, tag) in [(first, pos1, "s1"), (second, pos2, "s2")] {
            let EscrowStatus::Refunded { refund, position, created_at, .. } = escrow_status(&w.chain, &escrow, escrow_pos) else {
                panic!("twins={twins}: escrow at {escrow_pos} should be refunded")
            };
            let (public, witness) = TxBuilder::new(Branch::Transfer, tag.as_bytes())
                .spend(refund, created_at, position, p.refund)
                .output(ordinary(99 - F, &p.sender, &format!("{tag}/home")))
                .build(&w.chain, w.time);
            w.submit(&public, &witness).unwrap();
        }
        assert!(w.conserved());
    }
}

// ---- right party, right destination -----------------------------------------

#[test]
fn every_branch_rejects_the_wrong_authority() {
    let p = parties();
    let stranger = secret("someone-else");
    let cases = [
        (Branch::Claim, p.canceller),
        (Branch::Claim, stranger),
        (Branch::Decline, p.canceller),
        (Branch::Decline, stranger),
        (Branch::SenderRefund, p.recipient),
        (Branch::SenderRefund, stranger),
    ];
    for (branch, who) in cases {
        let (mut w, escrow, pos) = world_with_escrow(101);
        let (public, witness) = match branch {
            Branch::Claim => claim_tx(&w, &escrow, pos, who, "x"),
            _ => refund_tx(&w, branch, &escrow, pos, who, "x"),
        };
        assert_eq!(w.submit(&public, &witness), Err(Reject::WrongAuthority), "{branch:?}");
    }
}

#[test]
fn spending_someone_elses_ordinary_note_is_rejected() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "coins")]);
    for branch in [Branch::Transfer, Branch::InvitedRequest, Branch::Open] {
        let mut b = TxBuilder::new(branch, b"steal")
            .spend(w.notes[0], 0, 0, p.recipient)
            .output(ordinary(100 - F, &p.recipient, "stolen"));
        if branch == Branch::InvitedRequest {
            b = b.admission(AdmissionRecord { tier: Tier::Invited, ..AdmissionRecord::empty(blinding("a")) });
        }
        let (public, witness) = b.build(&w.chain, w.time);
        assert_eq!(w.submit(&public, &witness), Err(Reject::WrongAuthority), "{branch:?}");
    }
}

#[test]
fn a_claim_can_only_pay_the_recipient_the_price() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let thief = secret("thief");
    let (mut public, mut witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
    witness.outputs[0] = OutputWitness::Real(Note::Ordinary { value: 101, owner: thief.authority(), blinding: blinding("x") });
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::ClaimPayoutWrong));
    // Splitting the payout keeps the sum but not the destination.
    witness.outputs[0] = OutputWitness::Real(Note::Ordinary { value: 100, owner: escrow.recipient, blinding: blinding("y") });
    witness.outputs[1] = OutputWitness::Real(Note::Ordinary { value: 1, owner: thief.authority(), blinding: blinding("z") });
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::ClaimPayoutWrong));
}

#[test]
fn a_refund_that_differs_from_the_derived_one_is_rejected() {
    let p = parties();
    let thief = secret("thief");
    let (_, escrow, escrow_pos) = world_with_escrow(101);
    let derived = derived_refund(&escrow, escrow_pos, F);
    let Note::Ordinary { value, owner, blinding: b } = derived else { unreachable!() };
    let altered = [
        ("owner", Note::Ordinary { value, owner: thief.authority(), blinding: b }),
        ("blinding", Note::Ordinary { value, owner, blinding: blinding("unfindable") }),
        // v0.4's derivation (seed only) and another position's: both wrong now.
        ("blinding from another position", Note::Ordinary { value, owner, blinding: refund_blinding(&escrow.seed, escrow_pos + 1) }),
    ];
    for (what, bad) in altered {
        let (mut w, escrow, pos) = world_with_escrow(101);
        let (mut public, mut witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
        witness.outputs[0] = OutputWitness::Real(bad);
        reseal(&mut public, &mut witness);
        assert_eq!(w.submit(&public, &witness), Err(Reject::RefundNotDerived), "{what}");
    }
    // A different amount, with the penalty adjusted so value is conserved.
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (mut public, mut witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    witness.outputs[0] = OutputWitness::Real(Note::Ordinary { value: value - 1, owner, blinding: b });
    witness.outputs[1] = OutputWitness::Real(Note::Retired { value: penalty(101) + 1, blinding: blinding("pen") });
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::RefundNotDerived), "amount");
}

// ---- penalty ------------------------------------------------------------------

#[test]
fn penalty_is_one_percent_rounded_up_without_overflow() {
    assert_eq!(penalty(0), 0);
    assert_eq!(penalty(1), 1);
    assert_eq!(penalty(99), 1);
    assert_eq!(penalty(100), 1);
    assert_eq!(penalty(101), 2);
    assert_eq!(penalty(10_000), 100);
    assert_eq!(penalty(u64::MAX), u64::MAX / 100 + 1);
}

#[test]
fn a_penalty_that_is_too_small_is_rejected() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (mut public, mut witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "c");
    // Retire 1 instead of 2 and keep the extra unit as a third output.
    witness.outputs[1] = OutputWitness::Real(Note::Retired { value: 1, blinding: blinding("p") });
    witness.outputs[2] = OutputWitness::Real(Note::Retired { value: 1, blinding: blinding("q") });
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongOutputs));
    // Just too small, value not conserved.
    witness.outputs[2] = OutputWitness::Dummy { blinding: blinding("d") };
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::ValueNotConserved));
}

#[test]
fn a_penalty_redirected_to_a_spendable_note_is_rejected() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (mut public, mut witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    witness.outputs[1] = OutputWitness::Real(ordinary(penalty(101), &p.recipient, "pocketed"));
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongOutputs));
}

#[test]
fn the_right_penalty_with_the_wrong_value_is_rejected() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (mut public, mut witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    // Refund 98 instead of 99 is caught as not derived, before the penalty.
    witness.outputs[1] = OutputWitness::Real(Note::Retired { value: 3, blinding: blinding("p") });
    witness.outputs[0] = OutputWitness::Real(Note::Ordinary { value: 98, owner: escrow.refund_to, blinding: refund_blinding(&escrow.seed, pos) });
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::RefundNotDerived));
}

// ---- receipts and tier honesty --------------------------------------------------

#[test]
fn a_stranger_receipt_opens_only_for_its_own_request_recipient_and_escrow() {
    let (w, escrow, _) = world_with_escrow(101);
    let opening = &w.chain.log()[0];
    let record = stranger_record(&escrow, "open");
    let mine = Note::Escrow(escrow).commitment();
    assert_eq!(open_receipt(&opening.admission, &record, &CONTACT_KEY, &REQUEST, Some(&mine)), Ok(Tier::Stranger));
    assert_eq!(
        open_receipt(&opening.admission, &record, &CONTACT_KEY, &[1; 32], Some(&mine)),
        Err(ReceiptError::NotThisRequest)
    );
    assert_eq!(
        open_receipt(&opening.admission, &record, &[2; 32], &REQUEST, Some(&mine)),
        Err(ReceiptError::NotMyContactKey)
    );
    let other = Note::Escrow(escrow_note(101, &parties(), "other")).commitment();
    assert_eq!(
        open_receipt(&opening.admission, &record, &CONTACT_KEY, &REQUEST, Some(&other)),
        Err(ReceiptError::NotThisEscrow)
    );
    // Presenting a record altered to name another recipient, request or
    // escrow does not match the public commitment.
    for altered in [
        AdmissionRecord { contact_key: [2; 32], ..record },
        AdmissionRecord { request_digest: [1; 32], ..record },
        AdmissionRecord { escrow: Some(other), ..record },
    ] {
        assert_eq!(
            open_receipt(&opening.admission, &altered, &altered.contact_key, &altered.request_digest, altered.escrow.as_ref()),
            Err(ReceiptError::NotThisRecord)
        );
    }
}

#[test]
fn an_opening_whose_receipt_names_another_escrow_is_rejected() {
    let p = parties();
    let w = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let mut w = w;
    let escrow = escrow_note(101, &p, "e");
    let (mut public, mut witness) = open_tx(&w, 0, &escrow, "o");
    witness.admission.escrow = Some(Note::Escrow(escrow_note(101, &p, "elsewhere")).commitment());
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::ReceiptEscrowMismatch));
}

#[test]
fn a_stranger_receipt_needs_the_surcharge_retired() {
    let p = parties();
    let escrow = escrow_note(101, &p, "e");
    let mut w = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let (mut public, mut witness) = open_tx(&w, 0, &escrow, "o");
    // No surcharge: the change absorbs S.
    witness.outputs[1] = OutputWitness::Dummy { blinding: blinding("d") };
    witness.outputs[2] = OutputWitness::Real(ordinary(10_000 - 101 - 2 * F, &p.sender, "c"));
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::MissingSurcharge));
    // A surcharge one unit short.
    witness.outputs[1] = OutputWitness::Real(Note::Retired { value: S - 1, blinding: blinding("s") });
    witness.outputs[2] = OutputWitness::Real(ordinary(10_000 - 101 - 2 * F - (S - 1), &p.sender, "c"));
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::MissingSurcharge));
}

#[test]
fn only_an_opening_can_carry_a_stranger_receipt() {
    let p = parties();
    let mut w = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let escrow = escrow_note(101, &p, "e");
    let stranger = stranger_record(&escrow, "x");
    for branch in [Branch::Transfer, Branch::InvitedRequest] {
        // Even with S retired, a transfer or invited request cannot say "stranger".
        let (public, witness) = TxBuilder::new(branch, b"t")
            .spend(w.notes[0], 0, 0, p.sender)
            .output(Note::Retired { value: S, blinding: blinding("s") })
            .output(ordinary(10_000 - S - F, &p.sender, "c"))
            .admission(stranger)
            .build(&w.chain, w.time);
        assert_eq!(w.submit(&public, &witness), Err(Reject::TierMismatch), "{branch:?}");
    }
    let (mut public, mut witness) = open_tx(&w, 0, &escrow, "o");
    witness.admission.tier = Tier::Invited;
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::TierMismatch), "an opening must say stranger");
}

#[test]
fn an_escrow_with_the_wrong_fee_reserve_is_rejected() {
    let p = parties();
    let mut w = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let mut escrow = escrow_note(101, &p, "e");
    escrow.fee_reserve = F - 1;
    let (mut public, mut witness) = open_tx(&w, 0, &escrow, "o");
    witness.outputs[2] = OutputWitness::Real(ordinary(10_000 - 101 - (F - 1) - S - F, &p.sender, "c"));
    reseal(&mut public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::FeeReserveWrong));
}

// ---- unlinkable and recoverable refunds -----------------------------------------

#[test]
fn knowing_the_seed_gives_the_recipient_no_authority_over_the_refund() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    w.submit(&public, &witness).unwrap();
    let refund = derived_refund(&escrow, pos, F);
    let rpos = w.position_of(&refund);
    // The recipient can compute the refund commitment (they know the seed)...
    assert_eq!(w.chain.leaves()[rpos as usize].commitment, refund.commitment());
    // ...but cannot spend it,
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"grab")
        .spend(refund, w.created_at(rpos), rpos, p.recipient)
        .output(ordinary(99 - F, &p.recipient, "grabbed"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongAuthority));
    // ...and cannot compute the nullifier the sender's spend will publish.
    let real = ordinary_nullifier(&p.refund, &refund.commitment(), rpos);
    let guesses = [
        ordinary_nullifier(&p.recipient, &refund.commitment(), rpos),
        escrow_nullifier(&escrow.seed, &refund.commitment(), rpos),
        ordinary_nullifier(&Secret(escrow.seed), &refund.commitment(), rpos),
    ];
    assert!(!guesses.contains(&real));
    // The sender spends it; what is published is `real`.
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend")
        .spend(refund, w.created_at(rpos), rpos, p.refund)
        .output(ordinary(99 - F, &p.refund, "spent"))
        .build(&w.chain, w.time);
    assert_eq!(public.nullifiers[0], real);
    w.submit(&public, &witness).unwrap();
}

#[test]
fn after_a_decline_the_sender_finds_and_spends_the_refund_from_what_they_held_at_opening() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(250);
    let held_at_opening = escrow; // the sender's own copy
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    w.submit(&public, &witness).unwrap();
    // The sender finds the transaction that consumed their escrow, and the
    // derived refund among its outputs.
    let EscrowStatus::Refunded { refund, position: rpos, created_at, .. } = escrow_status(&w.chain, &held_at_opening, pos) else {
        panic!("expected a refund")
    };
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend")
        .spend(refund, created_at, rpos, p.refund)
        .output(ordinary(250 - penalty(250) - F, &p.sender, "home"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
}

// ---- hidden notes ------------------------------------------------------------------

#[test]
fn commitments_depend_on_a_secret_blinding_even_for_retired_and_zero_value_notes() {
    let a = Note::Retired { value: S, blinding: blinding("1") };
    let b = Note::Retired { value: S, blinding: blinding("2") };
    assert_ne!(a.commitment(), b.commitment(), "two surcharges look different");
    let z1 = Note::Retired { value: 0, blinding: blinding("3") };
    let z2 = Note::Ordinary { value: 0, owner: secret("x").authority(), blinding: blinding("3") };
    assert_ne!(z1.commitment(), z2.commitment(), "type is bound inside the commitment");
    // Guessing with every public value but no blinding does not work.
    let zeros = Note::Retired { value: S, blinding: [0; 32] };
    assert_ne!(zeros.commitment(), a.commitment());
    // The derived refund's blinding comes from the secret seed (with the
    // escrow's public position), not from public values alone.
    let escrow = escrow_note(101, &parties(), "e");
    assert_ne!(refund_blinding(&escrow.seed, 2), refund_blinding(&[0; 32], 2));
}

#[test]
fn dummy_outputs_are_indistinguishable_commitments() {
    let p = parties();
    let w = World::new(&[ordinary(100, &p.sender, "f")]);
    let (public, _) = TxBuilder::new(Branch::Transfer, b"a").spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(90, &p.sender, "c")).build(&w.chain, w.time);
    let (other, _) = TxBuilder::new(Branch::Transfer, b"b").spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(90, &p.sender, "c")).build(&w.chain, w.time);
    assert_ne!(public.commitments[1], other.commitments[1], "dummy outputs carry fresh blindings");
    assert_ne!(public.admission, other.admission, "empty admission records do too");
}

// ---- retired value and padding -------------------------------------------------

#[test]
fn a_retired_note_can_never_be_spent() {
    let p = parties();
    let (mut w, _, _) = world_with_escrow(101);
    let retired = w.notes.iter().position(|n| matches!(n, Note::Retired { value, .. } if *value == S)).unwrap() as u64;
    for branch in [Branch::Transfer, Branch::Claim, Branch::Decline] {
        let (public, witness) = TxBuilder::new(branch, b"r")
            .spend(w.notes[retired as usize], w.created_at(retired), retired, p.sender)
            .output(ordinary(S - F, &p.sender, "revived"))
            .build(&w.chain, w.time);
        assert_eq!(w.submit(&public, &witness), Err(Reject::RetiredInput), "{branch:?}");
    }
}

#[test]
fn padding_cannot_mint_value() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    // Outputs worth more than the inputs: a dummy input slot adds nothing.
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"m")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(1_000, &p.sender, "minted"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::ValueNotConserved));
    // A note that was never inserted, presented as an input.
    let fake = ordinary(1_000, &p.sender, "fake");
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"f")
        .spend(fake, 0, 0, p.sender)
        .output(ordinary(990, &p.sender, "minted"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::NotInTree));
    // A real retired note with value in a transfer's output is not a dummy.
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"h")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(Note::Retired { value: 5, blinding: blinding("hidden") })
        .output(ordinary(100 - 5 - F, &p.sender, "c"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongOutputs));
}

#[test]
fn a_dummy_slot_cannot_carry_a_real_notes_nullifier() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    // The recipient's pending claim publishes this nullifier.
    let pending = claim_tx(&w, &escrow, pos, p.recipient, "c").0.nullifiers[0];
    // An attacker puts it in a dummy slot of their own transfer, to get the
    // genuine claim rejected later.
    let coins = w.position_of(&ordinary(500, &p.recipient, "recipient-coins"));
    let (mut public, mut witness) = TxBuilder::new(Branch::Transfer, b"block")
        .spend(w.notes[coins as usize], w.created_at(coins), coins, p.recipient)
        .output(ordinary(500 - F, &p.recipient, "c"))
        .build(&w.chain, w.time);
    public.nullifiers[1] = pending;
    rebind(&public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::BadDummyNullifier));
    let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
    w.submit(&public, &witness).unwrap();
}

// ---- integer limits ----------------------------------------------------------------

#[test]
fn values_at_the_integer_limits_neither_wrap_nor_break_conservation() {
    let p = parties();
    let max = u64::MAX;
    let mut w = World::new(&[ordinary(max, &p.sender, "a"), ordinary(max, &p.sender, "b")]);
    // Two maximal inputs: the sum exceeds u64 but is checked exactly.
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"big")
        .spend(w.notes[0], 0, 0, p.sender)
        .spend(w.notes[1], 0, 1, p.sender)
        .output(ordinary(max, &p.sender, "x"))
        .output(ordinary(max - F, &p.sender, "y"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    // An escrow whose price + fee reserve does not fit the value range.
    let escrow = escrow_note(max - F + 1, &p, "huge");
    let funding = w.position_of(&ordinary(max, &p.sender, "x"));
    let (public, witness) = TxBuilder::new(Branch::Open, b"o")
        .spend(w.notes[funding as usize], w.created_at(funding), funding, p.sender)
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding("s") })
        .admission(stranger_record(&escrow, "o"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::Overflow));
}

#[test]
fn the_largest_escrow_that_fits_resolves_correctly() {
    let p = parties();
    let price = u64::MAX - F;
    let mut w = World::new(&[ordinary(u64::MAX, &p.sender, "a"), ordinary(u64::MAX, &p.sender, "b")]);
    let escrow = escrow_note(price, &p, "max");
    let (public, witness) = TxBuilder::new(Branch::Open, b"o")
        .spend(w.notes[0], 0, 0, p.sender)
        .spend(w.notes[1], 0, 1, p.sender)
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding("s") })
        .output(ordinary(u64::MAX - S - F, &p.sender, "c"))
        .admission(stranger_record(&escrow, "o"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    let pos = w.position_of(&Note::Escrow(escrow));
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    w.submit(&public, &witness).unwrap();
    assert!(w.conserved());
}

// ---- time --------------------------------------------------------------------------

#[test]
fn a_claim_in_the_last_window_before_the_deadline_is_accepted() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let deadline = w.created_at(pos) + DAY;
    w.time = deadline - 1; // inside the window [deadline - 1h, deadline)
    let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
    w.submit(&public, &witness).unwrap();
}

#[test]
fn no_claim_at_or_after_the_deadline() {
    let p = parties();
    for t in [0, 1, HOUR, DAY] {
        let (mut w, escrow, pos) = world_with_escrow(101);
        w.time = w.created_at(pos) + DAY + t;
        let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
        assert_eq!(w.submit(&public, &witness), Err(Reject::ClaimTooLate), "deadline + {t}s");
    }
}

#[test]
fn the_sender_refund_is_valid_at_any_time() {
    // v0.5 merged Cancel and Timeout (I2): one sender refund with no time
    // condition, before the deadline, at it, and long after.
    let p = parties();
    for offset in [0, DAY - 1, DAY, 7 * DAY] {
        let (mut w, escrow, pos) = world_with_escrow(101);
        w.time = w.created_at(pos) + offset;
        let (public, witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "r");
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("created_at + {offset}s: {e:?}"));
    }
}

#[test]
fn after_the_deadline_only_a_refund_is_possible() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    w.time = w.created_at(pos) + DAY;
    let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
    assert_eq!(w.submit(&public, &witness), Err(Reject::ClaimTooLate));
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    w.submit(&public, &witness).unwrap();
}

#[test]
fn a_creation_time_off_the_grid_or_other_than_stamped_is_rejected() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_escrow(101);
    let stamped = w.created_at(pos);
    assert_eq!(stamped % HOUR, 0, "the chain stamps created_at on the grid");
    for claimed in [stamped + HOUR, stamped + 6, stamped - 1] {
        // Claiming a later or off-grid creation time to push the claim
        // deadline back, after the real one has passed.
        w.time = stamped + DAY + 10;
        let (public, witness) = TxBuilder::new(Branch::Claim, b"c")
            .spend(Note::Escrow(escrow), claimed, pos, p.recipient)
            .output(Note::Ordinary { value: 101, owner: escrow.recipient, blinding: blinding("pay") })
            .build(&w.chain, w.time);
        assert_eq!(w.submit(&public, &witness), Err(Reject::NotInTree), "claimed created_at {claimed}");
    }
}

#[test]
fn a_sender_cannot_create_an_already_expired_escrow() {
    // created_at is the start of the including window, chosen by the chain,
    // so every new escrow has a full 24 hours from its window.
    let (w, _, pos) = world_with_escrow(101);
    let created = w.created_at(pos);
    assert!(created <= w.time && w.time < created + HOUR);
    assert_eq!(created, w.chain.log()[0].not_before);
}

// ---- chain-side checks, binding and replay ---------------------------------------

#[test]
fn replay_under_another_chain_or_version_is_rejected() {
    let p = parties();
    let genesis = [ordinary(100, &p.sender, "f")];
    let w = World::new(&genesis);
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .build(&w.chain, w.time);
    for other in [Params { chain_id: 8, ..params() }, Params { version: 2, ..params() }] {
        let mut chain = Chain::genesis(other, &genesis);
        let expect = if other.chain_id != 7 { Reject::WrongChain } else { Reject::WrongVersion };
        assert_eq!(chain.submit(&public, &witness, w.time), Err(expect));
        // Rewriting the identifiers: on another chain the root is unknown
        // (roots are chain-specific); rewriting the root too breaks the binding.
        let mut moved = public.clone();
        moved.chain_id = other.chain_id;
        moved.version = other.version;
        let root_check = if other.chain_id != 7 { Reject::UnknownRoot } else { Reject::BindingMismatch };
        assert_eq!(chain.submit(&moved, &witness, w.time), Err(root_check));
        moved.root = chain.root();
        assert_eq!(chain.submit(&moved, &witness, w.time), Err(Reject::BindingMismatch));
    }
}

#[test]
fn a_relay_that_alters_payload_bytes_invalidates_the_transaction() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    let (mut public, witness) = TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .payload(0, vec![7; anonymum_shielded_model::chain::COIN_PAYLOAD_LEN])
        .build(&w.chain, w.time);
    public.payloads[0][5] ^= 1;
    assert_eq!(w.submit(&public, &witness), Err(Reject::BindingMismatch));
}

#[test]
fn chain_side_checks_reject_malformed_transactions() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f"), ordinary(100, &p.sender, "g")]);
    let build = |w: &World| {
        TxBuilder::new(Branch::Transfer, b"t")
            .spend(w.notes[0], 0, 0, p.sender)
            .output(ordinary(100 - F, &p.sender, "c"))
            .build(&w.chain, w.time)
    };
    let (public, witness) = build(&w);

    let mut bad = public.clone();
    bad.root = [9; 32];
    let mut wit = witness;
    rebind(&bad, &mut wit);
    assert_eq!(w.submit(&bad, &wit), Err(Reject::UnknownRoot));

    let mut bad = public.clone();
    bad.base_fee = F + 1;
    assert_eq!(w.submit(&bad, &witness), Err(Reject::WrongBaseFee));

    let mut bad = public.clone();
    bad.payloads[2] = vec![0; 10];
    assert_eq!(w.submit(&bad, &witness), Err(Reject::MalformedPayload));

    let mut bad = public.clone();
    bad.not_after = bad.not_before + 2 * HOUR;
    assert_eq!(w.submit(&bad, &witness), Err(Reject::WindowNotShared));
    let mut bad = public.clone();
    bad.not_before += 6;
    bad.not_after += 6;
    assert_eq!(w.submit(&bad, &witness), Err(Reject::WindowNotShared));

    // Included outside its own window.
    let at = w.time;
    w.time = at + HOUR;
    assert_eq!(w.submit(&public, &witness), Err(Reject::OutsideWindow));
    w.time = at;

    // The same note twice in one transaction.
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"twice")
        .spend(w.notes[0], 0, 0, p.sender)
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(200 - F, &p.sender, "c"))
        .build(&w.chain, w.time);
    assert_eq!(w.submit(&public, &witness), Err(Reject::DuplicateNullifier));

    // Accepted once, then replayed.
    let (public, witness) = build(&w);
    w.submit(&public, &witness).unwrap();
    assert_eq!(w.submit(&public, &witness), Err(Reject::NullifierUsed));
}

#[test]
fn a_public_commitment_that_does_not_match_the_witness_is_rejected() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    let (mut public, mut witness) = TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .build(&w.chain, w.time);
    public.commitments[0] = ordinary(1_000, &p.sender, "more").commitment();
    rebind(&public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::CommitmentMismatch));
    let (mut public, mut witness) = TxBuilder::new(Branch::Transfer, b"u")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .build(&w.chain, w.time);
    public.admission = AdmissionRecord::empty(blinding("other")).commitment();
    rebind(&public, &mut witness);
    assert_eq!(w.submit(&public, &witness), Err(Reject::AdmissionMismatch));
}

// ---- review fixtures: boundary prices and a penalty equal to S --------------

/// An escrow at `price`, funded with enough (two maximal notes for the
/// largest price), ready to resolve.
fn escrow_at_price(price: Value) -> (World, EscrowNote, u64) {
    let p = parties();
    let big = price > 1_000_000;
    let mut genesis = if big {
        vec![ordinary(u64::MAX, &p.sender, "a"), ordinary(u64::MAX, &p.sender, "b")]
    } else {
        vec![ordinary(1_000_000, &p.sender, "a")]
    };
    genesis.push(ordinary(500, &p.recipient, "r"));
    let mut w = World::new(&genesis);
    let escrow = escrow_note(price, &p, &format!("p{price}"));
    let mut b = TxBuilder::new(Branch::Open, format!("open{price}").as_bytes()).spend(w.notes[0], 0, 0, p.sender);
    let inputs: u128 = if big { 2 * u128::from(u64::MAX) } else { 1_000_000 };
    if big {
        b = b.spend(w.notes[1], 0, 1, p.sender);
    }
    let change = inputs - u128::from(price) - 2 * u128::from(F) - u128::from(S);
    let (public, witness) = b
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding("s") })
        .output(ordinary(u64::try_from(change).expect("change fits"), &p.sender, "c"))
        .admission(stranger_record(&escrow, "o"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap_or_else(|e| panic!("open at {price}: {e:?}"));
    let pos = w.position_of(&Note::Escrow(escrow));
    (w, escrow, pos)
}

#[test]
fn boundary_prices_resolve_exactly_by_claim_and_by_decline() {
    let p = parties();
    let largest = u64::MAX - F; // price + fee_reserve must fit 64 bits
    let cases = [
        (0, 0, 0),
        (1, 0, 1),
        (99, 98, 1),
        (100, 99, 1),
        (largest, largest - (largest / 100 + 1), largest / 100 + 1),
    ];
    for (price, refund_value, penalty_value) in cases {
        assert_eq!(penalty(price), penalty_value, "penalty at {price}");
        // Decline: exact refund and penalty.
        let (mut w, escrow, pos) = escrow_at_price(price);
        let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("decline at {price}: {e:?}"));
        assert_eq!(derived_refund(&escrow, pos, F).value(), Some(refund_value), "refund at {price}");
        assert!(w.conserved());
        // Claim: the recipient gets the full price.
        let (mut w, escrow, pos) = escrow_at_price(price);
        let (public, witness) = claim_tx(&w, &escrow, pos, p.recipient, "c");
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("claim at {price}: {e:?}"));
        assert!(w.conserved());
    }
}

#[test]
fn a_decline_retiring_exactly_s_never_yields_a_stranger_receipt() {
    // At price 5,000 the penalty is 50 = S: the decline retires the same
    // amount an opening retires as the stranger surcharge.
    let p = parties();
    let price = 5_000;
    assert_eq!(penalty(price), S);
    let (mut w, escrow, pos) = escrow_at_price(price);
    let (public, witness) = refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d");
    // Forcing a stranger receipt onto the decline is rejected,
    for record in [stranger_record(&escrow, "forced"), AdmissionRecord { escrow: None, ..stranger_record(&escrow, "forced2") }] {
        let (mut bad_public, mut bad_witness) = (public.clone(), witness);
        bad_witness.admission = record;
        reseal(&mut bad_public, &mut bad_witness);
        assert_eq!(w.submit(&bad_public, &bad_witness), Err(Reject::TierMismatch));
    }
    // and the honest decline's receipt opens as no request at all.
    w.submit(&public, &witness).unwrap();
    let mine = Note::Escrow(escrow).commitment();
    assert_eq!(
        open_receipt(&public.admission, &witness.admission, &CONTACT_KEY, &REQUEST, Some(&mine)),
        Err(ReceiptError::NotARequest)
    );
}
