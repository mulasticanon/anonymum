//! Audit HIGH-03: a base fee that changes while escrows are open (issue I8,
//! review H1), and refunds the resolver cannot grief or link (issue I13,
//! review H5). The harness checks conservation after every accepted
//! transaction and that a rejected one changes nothing.

mod common;

use anonymum_shielded_model::build::{default_fee_reserve, reseal, TopUp, TxBuilder, FEE_CEILING_MULTIPLE};
use anonymum_shielded_model::hash::Hash;
use anonymum_shielded_model::wallet::{escrow_status, EscrowStatus, KeyPath, RecoveryError, Wallet, CANCEL_PURPOSE, REFUND_PURPOSE};
use anonymum_shielded_model::*;
use common::*;

const PRICE: Value = 101;
/// The default reserve at opening: `FEE_CEILING_MULTIPLE * F` = 20.
const RESERVE: Value = FEE_CEILING_MULTIPLE * F;
const BRANCHES: [Branch; 3] = [Branch::Claim, Branch::Decline, Branch::SenderRefund];
/// Genesis positions of the resolvers' own coins, for top-ups.
const RECIPIENT_COINS: u64 = 1;
const CANCELLER_COINS: u64 = 2;
const RECIPIENT_SMALL: u64 = 3;

/// A world with an escrow of `PRICE` locking `reserve`, opened at fee `F`.
fn world_with_reserve(reserve: Value) -> (World, EscrowNote, u64) {
    let p = parties();
    let mut w = World::new(&[
        ordinary(1_000_000, &p.sender, "funding"),
        ordinary(500, &p.recipient, "recipient-coins"),
        ordinary(500, &p.canceller, "canceller-coins"),
        ordinary(7, &p.recipient, "recipient-small"),
    ]);
    let escrow = EscrowNote { fee_reserve: reserve, ..escrow_note(PRICE, &p, "escrow") };
    let (public, witness) = open_tx(&w, 0, &escrow, "open");
    w.submit(&public, &witness).expect("opening accepted");
    let pos = w.position_of(&Note::Escrow(escrow));
    (w, escrow, pos)
}

fn resolver(branch: Branch) -> Secret {
    let p = parties();
    if branch == Branch::SenderRefund {
        p.canceller
    } else {
        p.recipient
    }
}

/// The resolver's own 500-unit note as a top-up, change back to them.
fn top_up(w: &World, branch: Branch) -> TopUp {
    let position = if branch == Branch::SenderRefund { CANCELLER_COINS } else { RECIPIENT_COINS };
    let owner = resolver(branch);
    TopUp { note: w.notes[position as usize], created_at: w.created_at(position), position, owner, change_to: owner.authority() }
}

fn resolve(w: &World, branch: Branch, escrow: &EscrowNote, pos: u64, top: Option<TopUp>, tag: &str) -> (PublicTx, Witness) {
    TxBuilder::resolution(&w.chain, branch, escrow, w.created_at(pos), pos, resolver(branch), top, tag.as_bytes())
        .build(&w.chain, w.time)
}

/// What the sender is owed after `branch` at base fee `fee`: the note's
/// value, or `None` for a claim with no surplus.
fn owed(branch: Branch, escrow: &EscrowNote, fee: Value) -> Option<Value> {
    let surplus = escrow.fee_reserve.saturating_sub(fee);
    match branch {
        Branch::Claim => (surplus > 0).then_some(surplus),
        _ => Some(PRICE - penalty(PRICE) + surplus),
    }
}

/// After a resolution, what the sender's wallet finds through the
/// consuming transaction, checked against what it is owed.
fn assert_sender_finds(w: &World, branch: Branch, escrow: &EscrowNote, pos: u64, fee: Value) {
    let status = escrow_status(&w.chain, escrow, pos);
    match (branch, owed(branch, escrow, fee)) {
        (Branch::Claim, None) => assert!(matches!(status, EscrowStatus::ResolvedWithoutRefund { .. }), "{status:?}"),
        (Branch::Claim, Some(v)) => {
            let EscrowStatus::ClaimedWithSurplus { surplus, .. } = status else { panic!("{status:?}") };
            assert_eq!(surplus.value(), Some(v));
            assert_eq!(surplus, derived_claim_surplus(escrow, pos, fee).unwrap());
        }
        (_, Some(v)) => {
            let EscrowStatus::Refunded { refund, .. } = status else { panic!("{status:?}") };
            assert_eq!(refund.value(), Some(v));
            assert_eq!(refund, derived_refund(escrow, pos, fee));
        }
        (_, None) => unreachable!(),
    }
    // Whatever it is, the sender's refund key spends it.
    if let Some((note, position, _)) = status.sender_note() {
        let Note::Ordinary { owner, .. } = note else { panic!() };
        assert_eq!(owner, parties().refund.authority());
        assert!(!w.chain.is_spent(&ordinary_nullifier(&parties().refund, &note.commitment(), position)));
    }
}

// ---- the default reserve ------------------------------------------------------

#[test]
fn an_opening_locks_the_fee_ceiling_by_default_and_never_less_than_f() {
    assert_eq!(default_fee_reserve(&params()), RESERVE);
    assert!(RESERVE > F);
    let (w, escrow, _) = world_with_reserve(default_fee_reserve(&params()));
    assert_eq!(escrow.fee_reserve, 2 * F);
    assert!(w.conserved());
    // Exactly F is still allowed; below F is not (existing test covers F - 1).
    let (w, _, _) = world_with_reserve(F);
    assert!(w.conserved());
    // The ceiling saturates rather than overflow.
    let huge = Params { base_fee: u64::MAX, ..params() };
    assert_eq!(default_fee_reserve(&huge), u64::MAX);
}

// ---- (a) F rises, still at or below the reserve -------------------------------

#[test]
fn a_fee_rise_within_the_reserve_settles_every_branch_and_returns_the_exact_surplus() {
    for new_fee in [F + 1, 15, RESERVE] {
        for branch in BRANCHES {
            let (mut w, escrow, pos) = world_with_reserve(RESERVE);
            w.chain.set_base_fee(new_fee);
            let fees_before = w.chain.fees_collected();
            let (public, witness) = resolve(&w, branch, &escrow, pos, None, "r");
            assert_eq!(public.base_fee, new_fee);
            w.submit(&public, &witness).unwrap_or_else(|e| panic!("{branch:?} at F={new_fee}: {e:?}"));
            assert_eq!(w.chain.fees_collected() - fees_before, u128::from(new_fee), "the new fee, from the reserve");
            assert_sender_finds(&w, branch, &escrow, pos, new_fee);
        }
    }
}

#[test]
fn a_claim_with_a_surplus_pays_the_full_price_and_returns_reserve_minus_f() {
    let (mut w, escrow, pos) = world_with_reserve(RESERVE);
    w.chain.set_base_fee(15);
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, None, "c");
    w.submit(&public, &witness).unwrap();
    let outputs: Vec<Note> = witness.outputs.iter().map(|o| o.note()).collect();
    assert!(matches!(outputs[0], Note::Ordinary { value: PRICE, owner, .. } if owner == escrow.recipient));
    assert_eq!(outputs[1], derived_claim_surplus(&escrow, pos, 15).unwrap());
    assert_eq!(outputs[1].value(), Some(RESERVE - 15));
    // The wallet reads the fee from the consuming transaction, so a later
    // fee change does not hide the surplus from it.
    w.chain.set_base_fee(3);
    assert_sender_finds(&w, Branch::Claim, &escrow, pos, 15);
}

#[test]
fn a_top_up_is_refused_when_the_reserve_covers_the_fee() {
    for branch in BRANCHES {
        let (mut w, escrow, pos) = world_with_reserve(RESERVE);
        w.chain.set_base_fee(15);
        let (public, witness) = resolve(&w, branch, &escrow, pos, Some(top_up(&w, branch)), "t");
        assert_eq!(w.submit(&public, &witness), Err(Reject::TopUpWrong), "{branch:?}");
    }
}

// ---- (b) F rises above the reserve: a top-up, never a stranded escrow --------

#[test]
fn a_fee_rise_above_the_reserve_settles_every_branch_with_a_top_up_and_exact_change() {
    for (reserve, new_fee) in [(RESERVE, RESERVE + 1), (RESERVE, 35), (F, 2 * F)] {
        for branch in BRANCHES {
            let (mut w, escrow, pos) = world_with_reserve(reserve);
            w.chain.set_base_fee(new_fee);
            // Without a top-up the value cannot balance: refused at no charge.
            let (public, witness) = resolve(&w, branch, &escrow, pos, None, "bare");
            assert_eq!(w.submit(&public, &witness), Err(Reject::ValueNotConserved), "{branch:?}");
            // With one it settles; the change is exactly what the fee did not take.
            let top = top_up(&w, branch);
            let (public, witness) = resolve(&w, branch, &escrow, pos, Some(top), "topped");
            w.submit(&public, &witness).unwrap_or_else(|e| panic!("{branch:?} at F={new_fee}: {e:?}"));
            let change = 500 - (new_fee - reserve);
            let expected = Note::Ordinary { value: change, owner: top.change_to, blinding: [0; 32] };
            let found = witness.outputs.iter().map(|o| o.note()).find(|n| {
                matches!((n, &expected), (Note::Ordinary { value: a, owner: o, .. }, Note::Ordinary { value: b, owner: q, .. }) if a == b && o == q)
            });
            assert!(found.is_some(), "{branch:?}: change of {change} to the resolver");
            assert!(w.spent.contains(&top.position), "the top-up was spent");
            assert!(w.spent.contains(&pos), "the escrow is settled");
            assert_sender_finds(&w, branch, &escrow, pos, new_fee);
        }
    }
}

#[test]
fn a_top_up_of_exactly_the_shortfall_leaves_no_change_and_a_smaller_one_is_refused() {
    let p = parties();
    // Reserve 10, fee 17: shortfall 7, the recipient's 7-unit note covers it exactly.
    let (mut w, escrow, pos) = world_with_reserve(F);
    w.chain.set_base_fee(17);
    let exact = TopUp {
        note: w.notes[RECIPIENT_SMALL as usize],
        created_at: w.created_at(RECIPIENT_SMALL),
        position: RECIPIENT_SMALL,
        owner: p.recipient,
        change_to: p.recipient.authority(),
    };
    let (public, witness) = resolve(&w, Branch::Decline, &escrow, pos, Some(exact), "exact");
    assert!(matches!(witness.outputs[2], OutputWitness::Dummy { .. }), "no change");
    w.submit(&public, &witness).unwrap();
    // Fee 18: the same note is one short; conservation refuses it.
    let (mut w, escrow, pos) = world_with_reserve(F);
    w.chain.set_base_fee(18);
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, Some(exact), "short");
    assert!(w.submit(&public, &witness).is_err());
}

#[test]
fn a_top_up_cannot_be_someone_elses_note_or_move_the_change_into_the_payout() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_reserve(F);
    w.chain.set_base_fee(30);
    // The recipient tries to use the canceller's coins.
    let theft = TopUp { owner: p.recipient, ..top_up(&w, Branch::SenderRefund) };
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, Some(theft), "theft");
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongAuthority));
    // Two change notes: only one ordinary output besides the required ones.
    let (mut public, mut witness) = resolve(&w, Branch::Decline, &escrow, pos, Some(top_up(&w, Branch::Decline)), "split");
    let OutputWitness::Real(Note::Ordinary { value, owner, .. }) = witness.outputs[2] else { panic!() };
    witness.outputs[1] = OutputWitness::Real(Note::Ordinary { value: penalty(PRICE), owner, blinding: blinding("x") });
    witness.outputs[2] = OutputWitness::Real(Note::Ordinary { value, owner, blinding: blinding("y") });
    reseal(&mut public, &mut witness);
    assert!(w.submit(&public, &witness).is_err());
}

// ---- (c) F falls ---------------------------------------------------------------

#[test]
fn a_fee_cut_returns_the_whole_surplus_and_conserves_value() {
    for new_fee in [F - 1, 4, 1, 0] {
        for branch in BRANCHES {
            for reserve in [F, RESERVE] {
                let (mut w, escrow, pos) = world_with_reserve(reserve);
                w.chain.set_base_fee(new_fee);
                let (public, witness) = resolve(&w, branch, &escrow, pos, None, "cut");
                w.submit(&public, &witness).unwrap_or_else(|e| panic!("{branch:?} R={reserve} F={new_fee}: {e:?}"));
                assert!(w.conserved());
                assert_sender_finds(&w, branch, &escrow, pos, new_fee);
                // The surplus is exactly reserve - F.
                let total_to_sender = owed(branch, &escrow, new_fee).unwrap_or(0);
                let base = if branch == Branch::Claim { 0 } else { PRICE - penalty(PRICE) };
                assert_eq!(total_to_sender - base, reserve - new_fee);
            }
        }
    }
}

#[test]
fn an_old_rule_resolution_paying_the_reserve_as_fee_is_refused_after_a_change() {
    // Claiming as if the fee were still the reserve: the public fee must be
    // today's, so the transaction is refused at no charge.
    let (mut w, escrow, pos) = world_with_reserve(F);
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, None, "old");
    w.chain.set_base_fee(4);
    assert_eq!(w.submit(&public, &witness), Err(Reject::WrongBaseFee));
}

// ---- (d) the resolver cannot choose the sender's note -------------------------

fn swap_output(public: &mut PublicTx, witness: &mut Witness, slot: usize, note: Note) {
    witness.outputs[slot] = OutputWitness::Real(note);
    reseal(public, witness);
}

#[test]
fn a_decline_with_a_refund_blinding_the_sender_cannot_derive_is_rejected_at_no_charge() {
    let p = parties();
    for fee in [F, 15, 4] {
        let (mut w, escrow, pos) = world_with_reserve(RESERVE);
        w.chain.set_base_fee(fee);
        let derived = derived_refund(&escrow, pos, fee);
        let Note::Ordinary { value, owner, .. } = derived else { panic!() };
        let (public, witness) = resolve(&w, Branch::Decline, &escrow, pos, None, "d");
        for blinding_used in [blinding("random"), [0; 32], refund_blinding(&escrow.seed, pos + 1)] {
            let (mut public, mut witness) = (public.clone(), witness);
            swap_output(&mut public, &mut witness, 0, Note::Ordinary { value, owner, blinding: blinding_used });
            assert_eq!(w.submit(&public, &witness), Err(Reject::RefundNotDerived), "fee {fee}");
        }
        // The surplus split off into a note the resolver chose: refused too.
        let (mut public2, mut witness2) = (public.clone(), witness);
        let old_value = PRICE - penalty(PRICE);
        let Note::Ordinary { blinding: derived_blinding, .. } = derived else { panic!() };
        swap_output(&mut public2, &mut witness2, 0, Note::Ordinary { value: old_value, owner, blinding: derived_blinding });
        if fee < RESERVE {
            witness2.outputs[2] = OutputWitness::Real(ordinary(RESERVE - fee, &p.recipient, "kept"));
            reseal(&mut public2, &mut witness2);
            assert_eq!(w.submit(&public2, &witness2), Err(Reject::RefundNotDerived));
        }
        // Control: the honest decline is accepted.
        w.submit(&public, &witness).unwrap();
    }
}

#[test]
fn a_claim_whose_surplus_note_the_sender_cannot_derive_is_rejected_at_no_charge() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_reserve(RESERVE);
    w.chain.set_base_fee(15);
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, None, "c");
    let surplus = RESERVE - 15;
    let bad = [
        ("random blinding", Note::Ordinary { value: surplus, owner: escrow.refund_to, blinding: blinding("random") }),
        ("wrong owner", Note::Ordinary { value: surplus, owner: p.recipient.authority(), blinding: refund_blinding(&escrow.seed, pos) }),
        ("retired instead", Note::Retired { value: surplus, blinding: refund_blinding(&escrow.seed, pos) }),
    ];
    for (what, note) in bad {
        let (mut public, mut witness) = (public.clone(), witness);
        swap_output(&mut public, &mut witness, 1, note);
        assert_eq!(w.submit(&public, &witness), Err(Reject::SurplusNotDerived), "{what}");
    }
    // Keeping the surplus by raising the payout instead: refused.
    let (mut public2, mut witness2) = (public.clone(), witness);
    witness2.outputs[1] = OutputWitness::Dummy { blinding: blinding("d") };
    swap_output(&mut public2, &mut witness2, 0, Note::Ordinary { value: PRICE + surplus, owner: escrow.recipient, blinding: blinding("p") });
    assert_eq!(w.submit(&public2, &witness2), Err(Reject::SurplusNotDerived));
    // Control.
    w.submit(&public, &witness).unwrap();
}

#[test]
fn a_claim_with_no_surplus_carries_no_extra_note() {
    let p = parties();
    let (mut w, escrow, pos) = world_with_reserve(F);
    let (mut public, mut witness) = resolve(&w, Branch::Claim, &escrow, pos, None, "c");
    assert!(matches!(witness.outputs[1], OutputWitness::Dummy { .. }));
    // An extra ordinary note (paid out of a smaller payout) is refused.
    swap_output(&mut public, &mut witness, 0, Note::Ordinary { value: PRICE - 1, owner: escrow.recipient, blinding: blinding("p") });
    swap_output(&mut public, &mut witness, 1, ordinary(1, &p.refund, "extra"));
    assert_eq!(w.submit(&public, &witness), Err(Reject::ClaimPayoutWrong));
}

// ---- (e) one-time refund keys; the resolver cannot spend or trace the refund --

fn nonce(tag: &str) -> [u8; 12] {
    blinding(tag)[..12].try_into().unwrap()
}

/// Open an escrow from `wallet` with fresh keys and its recovery copy.
fn open_from_wallet(w: &mut World, wallet: &Wallet, funding_pos: u64, tag: &str) -> (EscrowNote, u64, KeyPath) {
    let keys = wallet.next_escrow_keys(&w.chain).unwrap();
    let seed: Hash = blinding(&format!("{tag}/seed"));
    let prepared = wallet
        .prepare_escrow(&w.chain, keys, PRICE, default_fee_reserve(w.chain.params()), parties().recipient.authority(), seed, blinding(&format!("{tag}/b")), nonce(tag))
        .unwrap();
    let funding = w.notes[funding_pos as usize];
    let funds = wallet.secret("spend", funding_pos);
    let change = funding.value().unwrap() - PRICE - prepared.escrow.fee_reserve - S - F;
    let (public, witness) = TxBuilder::new(Branch::Open, tag.as_bytes())
        .spend(funding, w.created_at(funding_pos), funding_pos, funds)
        .output(Note::Escrow(prepared.escrow))
        .output(Note::Retired { value: S, blinding: blinding(&format!("{tag}/s")) })
        .output(Note::Ordinary { value: change, owner: funds.authority(), blinding: blinding(&format!("{tag}/c")) })
        .admission(stranger_record(&prepared.escrow, tag))
        .payload(0, prepared.recovery_copy)
        .build(&w.chain, w.time);
    w.submit(&public, &witness).expect("opening accepted");
    let pos = w.position_of(&Note::Escrow(prepared.escrow));
    (prepared.escrow, pos, prepared.refund)
}

fn wallet_world(wallet: &Wallet) -> World {
    let p = parties();
    World::new(&[
        Note::Ordinary { value: 10_000, owner: wallet.secret("spend", 0).authority(), blinding: blinding("f0") },
        Note::Ordinary { value: 10_000, owner: wallet.secret("spend", 1).authority(), blinding: blinding("f1") },
        ordinary(500, &p.recipient, "recipient-coins"),
    ])
}

#[test]
fn every_escrow_of_a_wallet_gets_its_own_one_time_refund_key() {
    let wallet = Wallet::from_backup(blinding("one wallet"));
    let mut w = wallet_world(&wallet);
    let (first, _, first_path) = open_from_wallet(&mut w, &wallet, 0, "o1");
    let (second, _, second_path) = open_from_wallet(&mut w, &wallet, 1, "o2");
    assert_ne!(first.refund_to, second.refund_to, "distinct refund authorities");
    assert_ne!(first.refund_to, first.canceller);
    assert_eq!((first_path.purpose.as_str(), first_path.index, second_path.index), (REFUND_PURPOSE, 0, 1));
    // A restored wallet continues above the highest index in use.
    let restored = Wallet::from_backup(blinding("one wallet"));
    assert_eq!(restored.next_escrow_keys(&w.chain).unwrap(), (KeyPath::new(REFUND_PURPOSE, 2), KeyPath::new(CANCEL_PURPOSE, 2)));
    // Reusing a refund key already on chain is refused, even if chosen by hand.
    let reuse = (first_path.clone(), KeyPath::new(CANCEL_PURPOSE, 9));
    let recipient = parties().recipient.authority();
    assert_eq!(
        restored.prepare_escrow(&w.chain, reuse, 5, RESERVE, recipient, [1; 32], [2; 32], nonce("x")),
        Err(RecoveryError::RefundKeyReused)
    );
    // A long-term key, or the cancel key, as the refund identity: refused.
    for (refund, cancel) in [
        (KeyPath::new("spend", 0), KeyPath::new(CANCEL_PURPOSE, 7)),
        (KeyPath::new(REFUND_PURPOSE, 7), KeyPath::new(REFUND_PURPOSE, 7)),
    ] {
        assert_eq!(
            restored.prepare_escrow(&w.chain, (refund, cancel), 5, RESERVE, recipient, [1; 32], [2; 32], nonce("y")),
            Err(RecoveryError::NotAOneTimeRefundKey)
        );
    }
    // The next fresh key works.
    let next = restored.next_escrow_keys(&w.chain).unwrap();
    assert!(restored.prepare_escrow(&w.chain, next, 5, RESERVE, recipient, [1; 32], [2; 32], nonce("z")).is_ok());
}

#[test]
fn the_index_space_running_out_is_reported_not_wrapped() {
    let wallet = Wallet::from_backup(blinding("full"));
    let mut w = wallet_world(&wallet);
    let keys = (KeyPath::new(REFUND_PURPOSE, u64::MAX), KeyPath::new(CANCEL_PURPOSE, u64::MAX));
    let prepared = wallet
        .prepare_escrow(&w.chain, keys, PRICE, RESERVE, parties().recipient.authority(), [3; 32], [4; 32], nonce("m"))
        .unwrap();
    let (public, witness) = TxBuilder::new(Branch::Open, b"m")
        .spend(w.notes[0], 0, 0, wallet.secret("spend", 0))
        .output(Note::Escrow(prepared.escrow))
        .output(Note::Retired { value: S, blinding: blinding("ms") })
        .output(Note::Ordinary { value: 10_000 - PRICE - RESERVE - S - F, owner: wallet.secret("spend", 0).authority(), blinding: blinding("mc") })
        .admission(stranger_record(&prepared.escrow, "m"))
        .payload(0, prepared.recovery_copy)
        .build(&w.chain, w.time);
    w.submit(&public, &witness).unwrap();
    assert_eq!(wallet.next_escrow_keys(&w.chain), Err(RecoveryError::KeysExhausted));
}

/// Everything the recipient knows about the sender's note, used as a
/// would-be spending secret: none of it is the sender's key.
fn recipient_guesses(escrow: &EscrowNote, pos: u64) -> Vec<Secret> {
    vec![
        parties().recipient,
        Secret(escrow.seed),
        Secret(escrow.refund_to.0),
        Secret(escrow.blinding),
        Secret(refund_blinding(&escrow.seed, pos)),
        Secret(Note::Escrow(*escrow).commitment().0),
    ]
}

#[test]
fn the_recipient_cannot_spend_or_trace_the_refund_or_the_claim_surplus() {
    for (branch, fee) in [(Branch::Decline, F), (Branch::Claim, F), (Branch::Decline, 25)] {
        let backup = blinding("sender backup");
        let wallet = Wallet::from_backup(backup);
        let mut w = wallet_world(&wallet);
        let (escrow, pos, refund_path) = open_from_wallet(&mut w, &wallet, 0, "o");
        w.chain.set_base_fee(fee);
        let top = (fee > escrow.fee_reserve).then(|| TopUp {
            note: w.notes[2],
            created_at: w.created_at(2),
            position: 2,
            owner: parties().recipient,
            change_to: parties().recipient.authority(),
        });
        let (public, witness) = resolve(&w, branch, &escrow, pos, top, "r");
        w.submit(&public, &witness).unwrap();

        // The sender, restored from backup, finds the note it is owed.
        let restored = Wallet::from_backup(backup);
        let recovered = restored.recover_escrows(&w.chain).unwrap();
        let state = restored.refund_states(&w.chain, &recovered[0])[0];
        let (note, rpos, created_at) = state.status.sender_note().expect("the sender is owed a note");
        assert_eq!(state.refund_spent, Some(false));
        let commitment = note.commitment();
        assert_eq!(w.chain.leaves()[rpos as usize].commitment, commitment, "the recipient can recompute it");

        // The recipient holds the seed, the escrow, refund_to, the derived
        // blinding and the commitment, and still cannot spend it...
        let value = note.value().unwrap();
        for guess in recipient_guesses(&escrow, pos) {
            let (public, witness) = TxBuilder::new(Branch::Transfer, b"grab")
                .spend(note, created_at, rpos, guess)
                .output(ordinary(value - fee, &parties().recipient, "grabbed"))
                .build(&w.chain, w.time);
            assert_eq!(w.submit(&public, &witness), Err(Reject::WrongAuthority));
        }
        // ...or compute the nullifier the sender's spend will publish.
        let owner = restored.secret_at(&refund_path);
        let real = ordinary_nullifier(&owner, &commitment, rpos);
        for guess in recipient_guesses(&escrow, pos) {
            assert_ne!(ordinary_nullifier(&guess, &commitment, rpos), real);
        }
        assert_ne!(escrow_nullifier(&escrow.seed, &commitment, rpos), real);
        // The nullifier depends on the spending secret alone (with the
        // commitment and position): the published one is exactly `real`.
        let (public, witness) = TxBuilder::new(Branch::Transfer, b"spend")
            .spend(note, created_at, rpos, owner)
            .output(Note::Ordinary { value: value - fee, owner: restored.secret("spend", 5).authority(), blinding: blinding("home") })
            .build(&w.chain, w.time);
        assert_eq!(public.nullifiers[0], real);
        w.submit(&public, &witness).unwrap();
        assert_eq!(restored.refund_states(&w.chain, &recovered[0])[0].refund_spent, Some(true));
    }
}

#[test]
fn two_escrows_of_one_wallet_leave_unrelated_refund_notes() {
    let wallet = Wallet::from_backup(blinding("w2"));
    let mut w = wallet_world(&wallet);
    let (a, apos, _) = open_from_wallet(&mut w, &wallet, 0, "a");
    let (b, bpos, _) = open_from_wallet(&mut w, &wallet, 1, "b");
    for (escrow, pos, tag) in [(a, apos, "da"), (b, bpos, "db")] {
        let (public, witness) = resolve(&w, Branch::Decline, &escrow, pos, None, tag);
        w.submit(&public, &witness).unwrap();
    }
    let (ra, rb) = (derived_refund(&a, apos, F), derived_refund(&b, bpos, F));
    let (Note::Ordinary { owner: oa, blinding: ba, .. }, Note::Ordinary { owner: ob, blinding: bb, .. }) = (ra, rb) else { panic!() };
    assert_ne!(oa, ob, "different owners: nothing in the notes ties the two escrows to one wallet");
    assert_ne!(ba, bb);
    assert_ne!(ra.commitment(), rb.commitment());
}

#[test]
fn a_resolution_without_a_top_up_carries_no_extra_note_not_even_a_zero_value_one() {
    let p = parties();
    let cases = [(Branch::Claim, F, F, 1), (Branch::Claim, RESERVE, 15, 2), (Branch::Decline, RESERVE, F, 2), (Branch::SenderRefund, RESERVE, 4, 2)];
    for (branch, reserve, fee, free_slot) in cases {
        let (mut w, escrow, pos) = world_with_reserve(reserve);
        w.chain.set_base_fee(fee);
        let (public, witness) = resolve(&w, branch, &escrow, pos, None, "x");
        let (mut public2, mut witness2) = (public.clone(), witness);
        assert!(matches!(witness2.outputs[free_slot], OutputWitness::Dummy { .. }));
        swap_output(&mut public2, &mut witness2, free_slot, ordinary(0, &p.recipient, "zero"));
        let want = if branch == Branch::Claim { Reject::ClaimPayoutWrong } else { Reject::WrongOutputs };
        assert_eq!(w.submit(&public2, &witness2), Err(want), "{branch:?} at F={fee}");
        w.submit(&public, &witness).unwrap();
    }
}

#[test]
fn the_claim_surplus_blinding_is_derived_from_the_seed_and_the_escrow_position() {
    let (mut w, escrow, pos) = world_with_reserve(RESERVE);
    w.chain.set_base_fee(15);
    let surplus = derived_claim_surplus(&escrow, pos, 15).unwrap();
    assert_eq!(surplus, Note::Ordinary { value: RESERVE - 15, owner: escrow.refund_to, blinding: refund_blinding(&escrow.seed, pos) });
    // Twin escrows (same seed and blinding) at two positions get different surplus notes.
    assert_ne!(surplus, derived_claim_surplus(&escrow, pos + 1, 15).unwrap());
    // A surplus note with another position's blinding, or the escrow's own blinding, is refused.
    let (public, witness) = resolve(&w, Branch::Claim, &escrow, pos, None, "c");
    for wrong in [refund_blinding(&escrow.seed, pos + 1), escrow.blinding] {
        let (mut public, mut witness) = (public.clone(), witness);
        swap_output(&mut public, &mut witness, 1, Note::Ordinary { value: RESERVE - 15, owner: escrow.refund_to, blinding: wrong });
        assert_eq!(w.submit(&public, &witness), Err(Reject::SurplusNotDerived));
    }
    w.submit(&public, &witness).unwrap();
}
