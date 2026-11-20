//! Spec section 5b, the first end-to-end acceptance test, as far as a model
//! can take it, plus the recovery guarantees the design review asked for
//! (H2: keys derived from paths recorded in the copy, any index; M1: refunds
//! found through the transaction that consumed the escrow).
//!
//! What a model cannot cover: proof time, peak memory, bytes downloaded and
//! inclusion delay (there are no proofs, phones or network here).

mod common;

use anonymum_shielded_model::build::TxBuilder;
use anonymum_shielded_model::chain::{COIN_PAYLOAD_LEN, STRANGER_NOTE_LEN};
use anonymum_shielded_model::wallet::{escrow_status, EscrowStatus, KeyPath, RecoveryError, Wallet};
use anonymum_shielded_model::*;
use common::*;

/// A sender wallet's escrow whose refund and cancel keys sit at the given
/// paths, funded by `funds` at `funding_pos`, with its recovery copy.
fn open_from_wallet(
    w: &mut World,
    sender: &Wallet,
    funding_pos: u64,
    price: Value,
    refund: &KeyPath,
    cancel: &KeyPath,
    tag: &str,
) -> (EscrowNote, u64) {
    let funding = w.notes[funding_pos as usize];
    let value = funding.value().unwrap();
    let funds = sender.secret("spend", funding_pos);
    let escrow = EscrowNote {
        price,
        fee_reserve: F,
        recipient: secret("recipient").authority(),
        refund_to: sender.secret_at(refund).authority(),
        canceller: sender.secret_at(cancel).authority(),
        seed: blinding(&format!("{tag}/seed")),
        blinding: blinding(&format!("{tag}/blinding")),
    };
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blinding(&format!("{tag}/nonce"))[..12]); // a wallet would use fresh randomness
    let (public, witness) = TxBuilder::new(Branch::Open, tag.as_bytes())
        .spend(funding, w.created_at(funding_pos), funding_pos, funds)
        .output(Note::Escrow(escrow))
        .output(Note::Retired { value: S, blinding: blinding(&format!("{tag}/s")) })
        .output(Note::Ordinary { value: value - price - 2 * F - S, owner: funds.authority(), blinding: blinding(&format!("{tag}/c")) })
        .admission(stranger_record(&escrow, tag))
        .payload(0, sender.seal_recovery(&escrow, refund, cancel, nonce).expect("paths match the escrow"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("opening accepted");
    let pos = w.position_of(&Note::Escrow(escrow));
    (escrow, pos)
}

/// A world whose genesis gives `sender` one funding note per entry of
/// `values`, at positions 0, 1, ... (owned by `sender.secret("spend", i)`).
fn funded_world(sender: &Wallet, values: &[Value]) -> World {
    let notes: Vec<Note> = values
        .iter()
        .enumerate()
        .map(|(i, v)| Note::Ordinary { value: *v, owner: sender.secret("spend", i as u64).authority(), blinding: blinding(&format!("fund{i}")) })
        .collect();
    World::new(&notes)
}

fn decline(w: &mut World, escrow: &EscrowNote, pos: u64, tag: &str) {
    let (public, witness) = TxBuilder::new(Branch::Decline, tag.as_bytes())
        .spend(Note::Escrow(*escrow), w.created_at(pos), pos, secret("recipient"))
        .output(derived_refund(escrow, pos))
        .output(Note::Retired { value: penalty(escrow.price), blinding: blinding(&format!("{tag}/p")) })
        // Deliberately unusable settlement data.
        .payload(0, vec![0xEE; COIN_PAYLOAD_LEN])
        .payload(1, vec![0x00; COIN_PAYLOAD_LEN])
        .payload(2, (0..STRANGER_NOTE_LEN).map(|i| i as u8).collect())
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("decline accepted");
}

/// What a freshly restored wallet sees: its one refund, found through the
/// consuming transaction, and whether it is spent.
fn restore_and_find(w: &World, backup: [u8; 32]) -> (Wallet, KeyPath, Note, u64, Time, bool) {
    let restored = Wallet::from_backup(backup);
    let recovered = restored.recover_escrows(&w.chain).unwrap();
    assert_eq!(recovered.len(), 1, "one escrow recovered from the chain alone");
    let states = restored.refund_states(&w.chain, &recovered[0]);
    assert_eq!(states.len(), 1);
    let EscrowStatus::Refunded { refund, position, created_at, .. } = states[0].status else {
        panic!("expected a refund, got {:?}", states[0].status)
    };
    (restored, recovered[0].refund.clone(), refund, position, created_at, states[0].refund_spent.unwrap())
}

#[test]
fn a_restored_sender_finds_and_spends_exactly_99_after_a_garbage_decline() {
    let backup = blinding("the sender's backed-up master secret");
    let sender = Wallet::from_backup(backup);
    let mut w = funded_world(&sender, &[1_000]);
    // 1. The sender funds the request and goes offline (`sender` is not used again).
    let (escrow, pos) = open_from_wallet(&mut w, &sender, 0, 101, &KeyPath::new("refund", 7), &KeyPath::new("cancel", 7), "open");
    // 2. The recipient declines, attaching unusable settlement data.
    w.advance(2 * HOUR);
    decline(&mut w, &escrow, pos, "decline");
    assert_eq!(w.chain.fees_collected(), 2 * u128::from(F), "the decline's fee came from the reserve");
    // 3-4. Restored from the backup only: find and spend exactly 99.
    let (restored, refund_path, refund, rpos, created_at, spent) = restore_and_find(&w, backup);
    assert_eq!(refund.value(), Some(99), "101 - ceil(101/100)");
    assert!(!spent);
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend refund")
        .spend(refund, created_at, rpos, restored.secret_at(&refund_path))
        .output(ordinary(99 - F, &restored.secret("spend", 1), "back home"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("the restored wallet spends the refund");
    assert!(w.conserved());
}

#[test]
fn a_second_wipe_and_restore_still_finds_and_spends_the_refund() {
    let backup = blinding("backup");
    let sender = Wallet::from_backup(backup);
    let mut w = funded_world(&sender, &[1_000]);
    let (escrow, pos) = open_from_wallet(&mut w, &sender, 0, 101, &KeyPath::new("refund", 3), &KeyPath::new("cancel", 3), "o");
    decline(&mut w, &escrow, pos, "d");
    // First restore: finds the refund, then the device is wiped again.
    let first = restore_and_find(&w, backup);
    assert!(!first.5, "unspent after the first restore");
    // Second restore: still finds it, and spends it.
    let (restored, path, refund, rpos, at, spent) = restore_and_find(&w, backup);
    assert_eq!((refund, rpos), (first.2, first.3));
    assert!(!spent);
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend")
        .spend(refund, at, rpos, restored.secret_at(&path))
        .output(ordinary(99 - F, &restored.secret("spend", 9), "home"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    // A third restore reports it spent.
    assert!(restore_and_find(&w, backup).5, "reported spent");
}

#[test]
fn restore_works_at_the_largest_index_and_at_sparse_indices() {
    for (refund_index, cancel_index) in [(u64::MAX, u64::MAX - 1), (1_000, 5), (1u64 << 40, 70_000), (0, u64::MAX)] {
        let backup = blinding(&format!("sparse {refund_index}"));
        let sender = Wallet::from_backup(backup);
        let mut w = funded_world(&sender, &[1_000]);
        let refund = KeyPath::new("refund", refund_index);
        let cancel = KeyPath::new("cancel", cancel_index);
        let (escrow, pos) = open_from_wallet(&mut w, &sender, 0, 250, &refund, &cancel, "o");

        let restored = Wallet::from_backup(backup);
        let recovered = restored.recover_escrows(&w.chain).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!((recovered[0].refund.index, recovered[0].cancel.index), (refund_index, cancel_index));
        // The restored wallet holds the cancel authority directly and uses it.
        let (public, witness) = refund_tx(&w, Branch::SenderRefund, &escrow, pos, restored.secret_at(&recovered[0].cancel), "r");
        w.submit(&public, &witness).unwrap_or_else(|e| panic!("index {cancel_index}: {e:?}"));
        let states = restored.refund_states(&w.chain, &recovered[0]);
        assert!(matches!(states[0].status, EscrowStatus::Refunded { .. }));
        assert_eq!(states[0].refund_spent, Some(false));
    }
}

#[test]
fn a_wallet_that_opened_many_escrows_recovers_every_one() {
    let backup = blinding("busy wallet");
    let sender = Wallet::from_backup(backup);
    let n = 40u64;
    let mut w = funded_world(&sender, &vec![10_000; n as usize]);
    let mut opened = Vec::new();
    for i in 0..n {
        // Spread-out indices: the copy records them, so restore needs no search.
        let refund = KeyPath::new("refund", i * 1_000_003);
        let cancel = KeyPath::new("cancel", u64::MAX - i);
        let (escrow, pos) = open_from_wallet(&mut w, &sender, i, 100 + i, &refund, &cancel, &format!("o{i}"));
        opened.push((escrow, pos, refund, cancel));
        if i % 2 == 0 {
            decline(&mut w, &escrow, pos, &format!("d{i}"));
        }
    }
    let restored = Wallet::from_backup(backup);
    let recovered = restored.recover_escrows(&w.chain).unwrap();
    assert_eq!(recovered.len(), n as usize);
    for (escrow, pos, refund, cancel) in &opened {
        let r = recovered.iter().find(|r| r.escrow == *escrow).expect("recovered");
        assert_eq!((&r.refund, &r.cancel), (refund, cancel));
        let declined = (escrow.price - 100) % 2 == 0;
        let status = escrow_status(&w.chain, escrow, *pos);
        assert_eq!(matches!(status, EscrowStatus::Refunded { .. }), declined);
        assert_eq!(matches!(status, EscrowStatus::Unresolved), !declined);
    }
}

#[test]
fn an_identical_commitment_elsewhere_is_not_mistaken_for_the_refund() {
    // The recipient knows the seed and can see the escrow's position, so it
    // can create a note with exactly the refund's commitment before ever
    // resolving the escrow. A match "anywhere in history" would then report
    // a refund that has not happened (review M1).
    let backup = blinding("victim");
    let sender = Wallet::from_backup(backup);
    let recipient = secret("recipient");
    let mut w = funded_world(&sender, &[1_000]);
    let recipient_coins = w.chain.leaves().len() as u64;
    let mut genesis_like = w.notes.clone();
    genesis_like.push(ordinary(1_000, &recipient, "recipient-coins"));
    w = World::new(&genesis_like);
    let (escrow, pos) = open_from_wallet(&mut w, &sender, 0, 101, &KeyPath::new("refund", 1), &KeyPath::new("cancel", 1), "o");

    // The decoy: same owner, value and derived blinding as the real refund.
    let decoy = derived_refund(&escrow, pos);
    let (public, witness) = TxBuilder::new(Branch::Transfer, b"decoy")
        .spend(w.notes[recipient_coins as usize], 0, recipient_coins, recipient)
        .output(decoy)
        .output(ordinary(1_000 - 99 - F, &recipient, "change"))
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    let decoy_pos = w.position_of(&decoy);

    // Not resolved yet, whatever identical notes exist.
    assert_eq!(escrow_status(&w.chain, &escrow, pos), EscrowStatus::Unresolved);
    // Now the real decline; the refund is the one in the consuming transaction.
    decline(&mut w, &escrow, pos, "d");
    let EscrowStatus::Refunded { position, tx_index, .. } = escrow_status(&w.chain, &escrow, pos) else { panic!() };
    assert_ne!(position, decoy_pos, "the decoy is not the refund");
    assert!(w.chain.output_positions(tx_index).contains(&position));
    assert_eq!(w.chain.leaves()[position as usize].commitment, w.chain.leaves()[decoy_pos as usize].commitment);
}

#[test]
fn a_wallet_without_the_backup_recovers_nothing_and_paths_must_match() {
    let sender = Wallet::from_backup(blinding("real"));
    let thief = Wallet::from_backup(blinding("other"));
    let mut w = funded_world(&sender, &[1_000]);
    open_from_wallet(&mut w, &sender, 0, 101, &KeyPath::new("refund", 0), &KeyPath::new("cancel", 0), "o");
    assert!(thief.recover_escrows(&w.chain).unwrap().is_empty());
    // A copy whose paths do not derive the escrow's keys is refused at sealing.
    let escrow = escrow_note(101, &parties(), "e");
    let nonce = [1; 12];
    assert_eq!(
        sender.seal_recovery(&escrow, &KeyPath::new("refund", 0), &KeyPath::new("cancel", 0), nonce),
        Err(RecoveryError::PathDoesNotMatch)
    );
    let long = KeyPath::new("a purpose longer than sixteen bytes", 0);
    let mine = EscrowNote { refund_to: sender.secret_at(&long).authority(), canceller: sender.secret_at(&long).authority(), ..escrow };
    assert_eq!(sender.seal_recovery(&mine, &long, &long, nonce), Err(RecoveryError::PurposeTooLong));
}

#[test]
fn a_recovery_copy_opens_with_one_decryption_and_no_chain_context() {
    let wallet = Wallet::from_backup(blinding("w"));
    let (refund, cancel) = (KeyPath::new("refund", 42), KeyPath::new("cancel", 43));
    let escrow = EscrowNote {
        refund_to: wallet.secret_at(&refund).authority(),
        canceller: wallet.secret_at(&cancel).authority(),
        ..escrow_note(101, &parties(), "e")
    };
    let slot = wallet.seal_recovery(&escrow, &refund, &cancel, [0x5C; 12]).unwrap();
    assert_eq!(slot.len(), COIN_PAYLOAD_LEN);
    let opened = wallet.open_recovery(&slot).expect("opens");
    assert_eq!((opened.escrow, opened.refund, opened.cancel), (escrow, refund.clone(), cancel.clone()));
    assert_ne!(slot, wallet.seal_recovery(&escrow, &refund, &cancel, [0x5D; 12]).unwrap());
    let mut tampered = slot.clone();
    tampered[40] ^= 1;
    assert_eq!(wallet.open_recovery(&vec![0; COIN_PAYLOAD_LEN]), Err(RecoveryError::NotThisWallet));
    assert_eq!(wallet.open_recovery(&tampered), Err(RecoveryError::NotThisWallet));
    assert_eq!(Wallet::from_backup(blinding("other")).open_recovery(&slot), Err(RecoveryError::NotThisWallet));
}
