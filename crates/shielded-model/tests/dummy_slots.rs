//! Unused payload slots are never blank (audit M2, MED-03): coin slots get
//! fresh random bytes, the stranger slot gets a caller-supplied dummy note
//! (production: `anonymum_crypto::dummy_note`) or random bytes. The
//! stranger-note hash still binds and verifies across pruning.

mod common;

use anonymum_shielded_model::build::TxBuilder;
use anonymum_shielded_model::chain::{stranger_note_hash, PAYLOAD_LENS, STRANGER_NOTE_LEN, STRANGER_SLOT, TTL};
use anonymum_shielded_model::*;
use common::*;

fn transfer(w: &World) -> (PublicTx, Witness) {
    let p = parties();
    TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .build(&w.chain, w.time)
}

/// Transfer, Claim, Decline and Sender refund, each in its own world, as
/// the builder makes them with no payload supplied.
fn built() -> Vec<(&'static str, World, PublicTx, Witness)> {
    let p = parties();
    let w = World::new(&[ordinary(100, &p.sender, "f")]);
    let (public, witness) = transfer(&w);
    let mut out = vec![("transfer", w, public, witness)];
    for name in ["claim", "decline", "sender refund"] {
        let (w, escrow, pos) = world_with_escrow(101);
        let (public, witness) = match name {
            "claim" => claim_tx(&w, &escrow, pos, p.recipient, "c"),
            "decline" => refund_tx(&w, Branch::Decline, &escrow, pos, p.recipient, "d"),
            _ => refund_tx(&w, Branch::SenderRefund, &escrow, pos, p.canceller, "r"),
        };
        out.push((name, w, public, witness));
    }
    out
}

#[test]
fn built_transactions_have_no_blank_payload_slot() {
    for (name, _, public, _) in built() {
        for (slot, bytes) in public.payloads.iter().enumerate() {
            assert_eq!(bytes.len(), PAYLOAD_LENS[slot], "{name}, slot {slot}");
            assert!(bytes.iter().any(|b| *b != 0), "{name}: slot {slot} is all zero");
            // Not a constant fill either: random bytes have many values.
            let distinct: std::collections::HashSet<u8> = bytes.iter().copied().collect();
            assert!(distinct.len() > 64, "{name}: slot {slot} does not look random");
        }
        assert_eq!(public.stranger_note_hash, stranger_note_hash(&public.payloads[STRANGER_SLOT]), "{name}");
    }
}

#[test]
fn dummy_slots_are_fresh_for_every_transaction() {
    let p = parties();
    let w = World::new(&[ordinary(100, &p.sender, "f")]);
    let (a, b) = (transfer(&w).0, transfer(&w).0);
    for slot in 0..PAYLOAD_LENS.len() {
        assert_ne!(a.payloads[slot], b.payloads[slot], "slot {slot}");
    }
    assert_ne!(a.stranger_note_hash, b.stranger_note_hash);
}

#[test]
fn dummy_slots_bind_and_survive_pruning_in_every_branch() {
    for (name, mut w, public, witness) in built() {
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let index = w.chain.log().len() - 1;
        assert_eq!(w.chain.stranger_note(index), Some(public.payloads[STRANGER_SLOT].as_slice()), "{name}");
        w.chain.prune_stranger_notes(public.not_before + TTL);
        assert_eq!(w.chain.stranger_note(index), None, "{name}: pruned");
        let logged = &w.chain.log()[index];
        assert_eq!(logged.stranger_note_hash, stranger_note_hash(&public.payloads[STRANGER_SLOT]), "{name}");
        assert_eq!(logged.digest(), witness.bound_digest, "{name}: the binding still verifies");
        assert!(logged.payloads[..STRANGER_SLOT].iter().all(|s| s.iter().any(|b| *b != 0)), "{name}: coin slots kept");
    }
}

/// End to end with the real crate (a dev-dependency only): the slot holds
/// exactly the dummy note the wallet passed, the chain accepts it, it binds
/// across pruning, and nobody can open it.
#[test]
fn a_real_dummy_note_from_anonymum_crypto_fills_the_stranger_slot() {
    const NET: [u8; 32] = [9; 32];
    let p = parties();
    let mut w = World::new(&[ordinary(100, &p.sender, "f")]);
    let dummy = anonymum_crypto::dummy_note(&NET, 1_800_000_000);
    assert_eq!(dummy.len(), STRANGER_NOTE_LEN);
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"t")
        .spend(w.notes[0], 0, 0, p.sender)
        .output(ordinary(100 - F, &p.sender, "c"))
        .dummy_stranger_note(dummy)
        .build(&w.chain, w.time);
    assert_eq!(public.payloads[STRANGER_SLOT], dummy.to_vec());
    assert_eq!(public.stranger_note_hash, stranger_note_hash(&dummy));
    w.submit(&public, &witness).unwrap();
    let index = w.chain.log().len() - 1;
    w.chain.prune_stranger_notes(public.not_before + TTL);
    assert_eq!(w.chain.log()[index].digest(), witness.bound_digest);
    let someone = anonymum_crypto::ContactIdentity::generate_at(1_800_000_000);
    let note = anonymum_core::SealedNote(dummy.to_vec());
    assert!(anonymum_crypto::open_note(&someone, &NET, &note, 1_800_000_000, 1_800_000_000).is_err());
}
