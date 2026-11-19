//! Spec section 5b, the first end-to-end acceptance test, as far as a model
//! can take it: price 101, the recipient declines with unusable settlement
//! data, the sender's wallet is rebuilt from its backup and the chain alone,
//! and must find and spend a refund of exactly 99, with the settlement fee
//! paid from the prepaid reserve.
//!
//! What a model cannot cover: proof time, peak memory, bytes downloaded and
//! inclusion delay (there are no proofs, phones or network here).

mod common;

use anonymum_shielded_model::build::TxBuilder;
use anonymum_shielded_model::wallet::{find_note, Wallet};
use anonymum_shielded_model::*;
use common::*;

#[test]
fn a_restored_sender_finds_and_spends_exactly_99_after_a_garbage_decline() {
    let backup = blinding("the sender's backed-up master secret");
    let sender = Wallet::from_backup(backup);
    let recipient = secret("recipient");
    let funds = sender.secret("spend", 0);
    let mut w = World::new(&[ordinary(1_000, &funds, "sender-funds")]);

    // 1. The sender funds the request (with its recovery copy) and goes offline.
    let escrow = EscrowNote {
        price: 101,
        fee_reserve: F,
        recipient: recipient.authority(),
        refund_to: sender.refund_secret(7).authority(),
        canceller: sender.secret("cancel", 7).authority(),
        seed: blinding("escrow seed shared with the recipient"),
        blinding: blinding("escrow blinding"),
    };
    let (public, witness) = TxBuilder::new(Branch::Open, b"open")
        .spend(w.notes[0], 0, 0, funds)
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding("surcharge") })
        .output(ordinary(1_000 - 101 - 2 * F - S, &funds, "change"))
        .admission(stranger_record(&escrow, "open"))
        .payload(0, sender.seal_recovery(&escrow))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("opening accepted");
    let escrow_pos = w.position_of(&Note::Escrow(escrow));
    // The sender goes offline and loses all local history: `sender` is not
    // used again; only `backup` survives.

    // 2. The recipient declines, deliberately attaching unusable settlement data.
    w.advance(2 * HOUR);
    let (public, witness) = TxBuilder::new(Branch::Decline, b"decline")
        .spend(Note::Escrow(escrow), w.created_at(escrow_pos), escrow_pos, recipient)
        .output(derived_refund(&escrow))
        .output(Note::Retired { value: penalty(101), blinding: blinding("penalty") })
        .payload(0, vec![0xEE; 192])
        .payload(1, vec![0x00; 192])
        .payload(2, (0..192).map(|i| i as u8).collect())
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("decline accepted");
    let fees_before = w.chain.fees_collected();

    // 3. Wiped wallet, restored from the backup only.
    let restored = Wallet::from_backup(backup);
    let recovered = restored.recover_escrows(&w.chain);
    assert_eq!(recovered, vec![escrow], "the escrow is recovered from the chain alone");

    // 4. Find the refund from the recovered escrow, and spend it.
    let refund = derived_refund(&recovered[0]);
    let Note::Ordinary { value, owner, .. } = refund else { unreachable!() };
    assert_eq!(value, 99, "101 - ceil(101/100)");
    let places = find_note(&w.chain, &refund);
    assert_eq!(places.len(), 1, "exactly one refund note on chain");
    let (pos, created_at) = places[0];
    let refund_key = restored.refund_secret_for(&owner).expect("the restored wallet controls the refund identity");
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend refund")
        .spend(refund, created_at, pos, refund_key)
        .output(ordinary(99 - F, &restored.secret("spend", 1), "back home"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("the restored wallet spends the refund");

    // The settlement fee came from the prepaid reserve: the decline itself
    // paid one base fee and the escrow still returned 99 + 2 (penalty).
    assert_eq!(fees_before, 2 * u128::from(F));
    assert!(w.conserved());
}

#[test]
fn a_wallet_without_the_backup_recovers_nothing() {
    let sender = Wallet::from_backup(blinding("real"));
    let thief = Wallet::from_backup(blinding("other"));
    let funds = sender.secret("spend", 0);
    let mut w = World::new(&[ordinary(1_000, &funds, "f")]);
    let escrow = EscrowNote {
        price: 101,
        fee_reserve: F,
        recipient: secret("recipient").authority(),
        refund_to: sender.refund_secret(0).authority(),
        canceller: sender.secret("cancel", 0).authority(),
        seed: blinding("seed"),
        blinding: blinding("b"),
    };
    let (public, witness) = TxBuilder::new(Branch::Open, b"o")
        .spend(w.notes[0], 0, 0, funds)
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding("s") })
        .output(ordinary(1_000 - 101 - 2 * F - S, &funds, "c"))
        .admission(stranger_record(&escrow, "o"))
        .payload(0, sender.seal_recovery(&escrow))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    assert!(thief.recover_escrows(&w.chain).is_empty());
    assert!(thief.refund_secret_for(&escrow.refund_to).is_none());
}
