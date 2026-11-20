//! W3 (empty admission records), the uniform asymmetric payload slots, and
//! the prunable 24-hour stranger-note store. The harness checks, on every
//! submission, that a rejected transaction changes nothing (no charge).

mod common;

use anonymum_shielded_model::build::{reseal, TxBuilder};
use anonymum_shielded_model::chain::{COIN_PAYLOAD_LEN, N_IN, N_OUT, PAYLOAD_LENS, STRANGER_NOTE_LEN, STRANGER_SLOT, TTL};
use anonymum_shielded_model::*;
use common::*;

// ---- W3: an empty admission record is all zero apart from its blinding --------

fn transfer_with(w: &World, record: AdmissionRecord) -> (PublicTx, Witness) {
    let p = parties();
    TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .admission(record)
        .build(&w.chain, w.time)
}

/// Records that claim to be empty (tier none, no escrow) but are not.
fn not_quite_empty() -> [(&'static str, AdmissionRecord); 2] {
    let empty = AdmissionRecord::empty(blinding("e"));
    [
        ("contact key", AdmissionRecord { contact_key: CONTACT_KEY, ..empty }),
        ("request digest", AdmissionRecord { request_digest: REQUEST, ..empty }),
    ]
}

#[test]
fn a_transfer_with_a_non_empty_admission_record_is_rejected_at_no_charge() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    for (field, record) in not_quite_empty() {
        let (public, witness) = transfer_with(&w, record);
        assert_eq!(w.submit(&public, &witness), Err(Reject::NonEmptyAdmission), "{field}");
    }
    let (public, witness) = transfer_with(&w, AdmissionRecord::empty(blinding("ok")));
    w.submit(&public, &witness).unwrap();
}

#[test]
fn claim_decline_and_refund_with_a_non_empty_admission_record_are_rejected_at_no_charge() {
    let p = parties();
    for branch in [Branch::Claim, Branch::Decline, Branch::SenderRefund] {
        let (mut w, escrow, pos) = world_with_escrow(101);
        for (field, record) in not_quite_empty() {
            let (mut public, mut witness) = match branch {
                Branch::Claim => claim_tx(&w, &escrow, pos, p.recipient, "x"),
                Branch::Decline => refund_tx(&w, branch, &escrow, pos, p.recipient, "x"),
                _ => refund_tx(&w, branch, &escrow, pos, p.canceller, "x"),
            };
            witness.admission = record;
            reseal(&mut public, &mut witness);
            assert_eq!(w.submit(&public, &witness), Err(Reject::NonEmptyAdmission), "{branch:?}: {field}");
        }
        // The same transaction with a truly empty record goes through.
        let (public, witness) = match branch {
            Branch::Claim => claim_tx(&w, &escrow, pos, p.recipient, "ok"),
            Branch::Decline => refund_tx(&w, branch, &escrow, pos, p.recipient, "ok"),
            _ => refund_tx(&w, branch, &escrow, pos, p.canceller, "ok"),
        };
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("{branch:?}: {e:?}"));
    }
}

// ---- uniform asymmetric payload slots ---------------------------------------------

#[test]
fn every_branch_has_the_same_payload_shape() {
    let p = parties();
    let (w, escrow, pos) = world_with_escrow(101);
    let funds = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let invited = AdmissionRecord {
        contact_key: CONTACT_KEY,
        request_digest: REQUEST,
        tier: Tier::Invited,
        escrow: None,
        blinding: blinding("i"),
    };
    let shapes: Vec<(&str, PublicTx)> = vec![
        ("transfer", transfer_with(&World::new(&[ordinary(100, &p.sender, "f")]), AdmissionRecord::empty(blinding("t"))).0),
        (
            "invited request",
            TxBuilder::new(Branch::InvitedRequest, b"i")
                .spend(funds.notes[0], 0, 0, p.sender)
                .output(ordinary(10_000 - F, &p.sender, "c"))
                .admission(invited)
                .build(&funds.chain, funds.time)
                .0,
        ),
        ("open", open_tx(&funds, 0, &escrow_note(101, &p, "o"), "o").0),
        ("claim", claim_tx(&w, &escrow, pos, p.recipient, "c").0),
        ("decline", refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d").0),
        ("sender refund", refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "r").0),
    ];
    assert_eq!(PAYLOAD_LENS, [COIN_PAYLOAD_LEN, COIN_PAYLOAD_LEN, STRANGER_NOTE_LEN]);
    assert_eq!((COIN_PAYLOAD_LEN, STRANGER_NOTE_LEN), (200, 1_787));
    for (name, public) in &shapes {
        let lens: Vec<usize> = public.payloads.iter().map(Vec::len).collect();
        assert_eq!(lens, PAYLOAD_LENS.to_vec(), "{name}");
        assert_eq!((public.nullifiers.len(), public.commitments.len()), (N_IN, N_OUT), "{name}");
    }
}

#[test]
fn a_slot_of_the_wrong_size_is_rejected_at_no_charge() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    for (slot, len) in [(0, COIN_PAYLOAD_LEN + 1), (1, COIN_PAYLOAD_LEN - 1), (2, STRANGER_NOTE_LEN - 1), (2, COIN_PAYLOAD_LEN)] {
        let (mut public, mut witness) = transfer_with(&w, AdmissionRecord::empty(blinding("t")));
        public.payloads[slot] = vec![0; len];
        reseal(&mut public, &mut witness);
        assert_eq!(w.submit(&public, &witness), Err(Reject::MalformedPayload), "slot {slot}, {len} bytes");
    }
}

// ---- prunable stranger-note store ---------------------------------------------------

#[test]
fn a_stranger_note_is_kept_for_24_hours_and_then_pruned_leaving_the_chain_intact() {
    let p = parties();
    let mut w = World::new(&[ordinary(10_000, &p.sender, "f")]);
    let escrow = escrow_note(101, &p, "o");
    let note: Vec<u8> = (0..STRANGER_NOTE_LEN).map(|i| (i % 251) as u8).collect();
    let (mut public, mut witness) = open_tx(&w, 0, &escrow, "o");
    public.payloads[STRANGER_SLOT] = note.clone();
    reseal(&mut public, &mut witness);
    w.submit(&public, &witness).unwrap();
    let index = w.chain.log().len() - 1;
    let window_start = public.not_before;

    // Retrievable while the request lives; not in the permanent log.
    assert_eq!(w.chain.stranger_note(index), Some(note.as_slice()));
    assert!(w.chain.log()[index].payloads[STRANGER_SLOT].is_empty(), "the log keeps no copy");
    assert_eq!(w.chain.log()[index].payloads[0].len(), COIN_PAYLOAD_LEN, "coin slots are permanent");

    let (root, leaves, admission) = (w.chain.root(), w.chain.leaves().len(), w.chain.log()[index].admission);
    let nullifier = public.nullifiers[0];
    assert_eq!(w.chain.prune_stranger_notes(window_start + TTL - 1), 0, "still within 24 hours");
    assert_eq!(w.chain.stranger_note(index), Some(note.as_slice()));

    // Pruned once 24 hours have passed since the window started.
    assert_eq!(w.chain.prune_stranger_notes(window_start + TTL), 1);
    assert_eq!(w.chain.stranger_note(index), None);
    // The tree, the nullifiers and the admission commitment are untouched.
    assert_eq!(w.chain.root(), root);
    assert_eq!(w.chain.leaves().len(), leaves);
    assert!(w.chain.is_spent(&nullifier));
    assert_eq!(w.chain.log()[index].admission, admission);

    // And the escrow still resolves: the sender's refund after the deadline.
    w.time = window_start + TTL;
    let pos = w.position_of(&Note::Escrow(escrow));
    let (public, witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "r");
    w.submit(&public, &witness).unwrap();
}

#[test]
fn accepting_a_later_transaction_prunes_expired_notes_on_the_way() {
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f"), ordinary(100, &p.sender, "g")]);
    let (public, witness) = transfer_with(&w, AdmissionRecord::empty(blinding("a")));
    w.submit(&public, &witness).unwrap();
    assert_eq!(w.chain.stranger_notes_kept(), 1, "every transaction carries a stranger slot");
    w.time += TTL + 3_600;
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"later")
        .spend(w.notes[1], 0, 1, p.sender)
        .output(ordinary(100 - F, &p.sender, "c2"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    assert_eq!(w.chain.stranger_note(0), None, "the old one went when a later block was accepted");
    assert!(w.chain.stranger_note(1).is_some());
}
