use anonymum_core::crypto::mock::{mock_binding, MockInviteSecret, MockScheme};
use anonymum_core::crypto::invite_message;

/// The simulation's default genesis id, which signed messages carry.
const G: [u8; 32] = *b"anonymum-core-simulation-genesis";
use anonymum_core::ratelimit::TokenBucket;
use anonymum_core::*;

/// Alice, Bob and Carol with published messaging keys and 10 coins free
/// each (they are minted the key deposit on top, which stays held).
fn setup() -> (Chain<MockScheme>, Address, Address, Address) {
    let mut chain = Chain::new(Params::default(), MockScheme);
    let (alice, bob, carol) = (
        Address::from_label("alice"),
        Address::from_label("bob"),
        Address::from_label("carol"),
    );
    let key_deposit = chain.params().key_deposit;
    for who in [alice, bob, carol] {
        chain.mint(who, 10 * COIN + key_deposit);
        chain.apply(who, publish_key(who)).unwrap();
    }
    (chain, alice, bob, carol)
}

fn publish_key(who: Address) -> Tx {
    let key = MessagingKey(who.0); // any 32 bytes do for the mock
    Tx::PublishMessagingKey { key, binding: mock_binding(&G, &who, &key) }
}

/// A correctly sized note. The chain cannot read notes, only measure them;
/// sealing and opening are tested in `anonymum-crypto`.
fn note() -> SealedNote {
    SealedNote(vec![0xAB; SEALED_NOTE_LEN])
}

fn req(recipient: Address, max_price: Amount) -> Tx {
    Tx::RequestContact { recipient, max_price, note: note() }
}

/// Opens a paid channel from `from` to `to` (request + accept).
fn paid_channel(chain: &mut Chain<MockScheme>, from: Address, to: Address) -> ChannelId {
    let events = chain.apply(from, req(to, chain.contact_price(&to))).unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!("wrong event") };
    chain.apply(to, Tx::AcceptContact { request }).unwrap();
    chain.channel_between(&from, &to).unwrap().id
}

/// Asserts a transaction fails with `expected` and changes no balance,
/// escrow, burn or pool.
fn fails_charging_nothing(chain: &mut Chain<MockScheme>, sender: Address, tx: Tx, expected: Error) {
    let ledger_before = chain.ledger().clone();
    let events_before = chain.events().len();
    assert_eq!(chain.apply(sender, tx).unwrap_err(), expected);
    let after = chain.ledger();
    for who in ["alice", "bob", "carol", "dave"].map(Address::from_label) {
        assert_eq!(after.balance(&who), ledger_before.balance(&who), "{who} charged");
        assert_eq!(after.reserved(&who), ledger_before.reserved(&who), "{who}'s deposits moved");
    }
    assert_eq!(after.escrowed(), ledger_before.escrowed());
    assert_eq!(after.burned(), ledger_before.burned());
    assert_eq!(after.reward_pool(), ledger_before.reward_pool());
    assert_eq!(chain.events().len(), events_before, "a failed tx emits nothing");
    assert!(after.is_balanced());
}

/// Bob registers an invite; returns the secret he would hand to a contact.
fn bob_invite(chain: &mut Chain<MockScheme>, bob: Address, seed: u8) -> MockInviteSecret {
    let secret = MockInviteSecret::from_seed(seed);
    chain
        .apply(bob, Tx::RegisterInvite { key: secret.public(), expires_at: None })
        .unwrap();
    secret
}

fn open_tx(secret: &MockInviteSecret, opener: Address, recipient: Address) -> Tx {
    Tx::OpenWithInvite {
        recipient,
        key: secret.public(),
        proof: secret.sign(&invite_message(&G, &opener, &recipient)),
    }
}

#[test]
fn invite_opens_channel_for_small_fee() {
    let (mut chain, alice, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);

    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();

    let fee = chain.params().invite_open_fee;
    assert_eq!(chain.ledger().balance(&alice), 10 * COIN - fee);
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN, "invites cost the recipient nothing");
    assert_eq!(chain.channel_between(&alice, &bob).unwrap().via, OpenedVia::Invite);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn invite_is_one_time() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();

    let err = chain.apply(carol, open_tx(&secret, carol, bob)).unwrap_err();
    assert_eq!(err, Error::UnknownInvite);
}

#[test]
fn stolen_proof_cannot_be_reused_by_someone_else() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);

    // Carol copies Alice's pending transaction and submits it as herself.
    let alices_tx = open_tx(&secret, alice, bob);
    let err = chain.apply(carol, alices_tx).unwrap_err();

    assert_eq!(err, Error::BadInviteProof);
    assert!(chain.channel_between(&carol, &bob).is_none());
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN, "failed tx must not charge");
}

#[test]
fn invite_only_works_for_its_owner() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    // Alice tries to use Bob's invite to reach Carol.
    let tx = Tx::OpenWithInvite {
        recipient: carol,
        key: secret.public(),
        proof: secret.sign(&invite_message(&G, &alice, &carol)),
    };
    assert_eq!(chain.apply(alice, tx).unwrap_err(), Error::UnknownInvite);
}

#[test]
fn expired_invite_is_rejected() {
    let (mut chain, alice, bob, _) = setup();
    let secret = MockInviteSecret::from_seed(7);
    chain
        .apply(bob, Tx::RegisterInvite { key: secret.public(), expires_at: Some(5) })
        .unwrap();
    chain.advance_blocks(6);
    let err = chain.apply(alice, open_tx(&secret, alice, bob)).unwrap_err();
    assert_eq!(err, Error::InviteExpired);
}

#[test]
fn stranger_pays_network_and_recipient() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::SetContactPrice { price: 3 * COIN }).unwrap();

    let events = chain
        .apply(carol, req(bob, 3 * COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!("wrong event") };

    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN - fee - 3 * COIN);
    assert_eq!(chain.ledger().escrowed(), 3 * COIN);
    assert!(chain.channel_between(&carol, &bob).is_none(), "no channel until Bob accepts");

    chain.apply(bob, Tx::AcceptContact { request }).unwrap();

    assert_eq!(chain.ledger().balance(&bob), 13 * COIN);
    assert_eq!(chain.ledger().escrowed(), 0);
    assert_eq!(chain.channel_between(&carol, &bob).unwrap().via, OpenedVia::PaidRequest);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn cold_contact_costs_more_than_invite() {
    let p = Params::default();
    assert!(p.cold_network_fee > p.invite_open_fee);
}

/// Default decline fee: 1% of the default 1-coin price.
const DECLINE_FEE: Amount = COIN / 100;

#[test]
fn declined_request_burns_decline_fee_and_keeps_network_fee() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain
        .apply(carol, req(bob, COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    let burned_before = chain.ledger().burned();

    let events = chain.apply(bob, Tx::CancelRequest { request }).unwrap();

    assert_eq!(
        events[0],
        Event::RequestRefunded {
            request,
            to: carol,
            amount: COIN - DECLINE_FEE,
            burned: DECLINE_FEE,
            reason: RefundReason::CancelledBy(bob),
        }
    );
    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN - fee - DECLINE_FEE);
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN, "recipient gains nothing from declining");
    assert_eq!(chain.ledger().burned(), burned_before + DECLINE_FEE);
    assert_eq!(chain.ledger().escrowed(), 0);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn sender_cancelling_pays_the_same_decline_fee() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain
        .apply(carol, req(bob, COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    let pool_before = chain.ledger().reward_pool();

    chain.apply(carol, Tx::CancelRequest { request }).unwrap();

    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN - fee - DECLINE_FEE);
    assert_eq!(chain.ledger().reward_pool(), pool_before, "decline fee is burned, not pooled");
    assert!(chain.ledger().is_balanced());
}

#[test]
fn unanswered_request_expires_and_refunds_minus_decline_fee() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, req(bob, COIN)).unwrap();

    let ttl = chain.params().request_ttl_blocks();
    assert!(chain.advance_blocks(ttl - 1).is_empty());
    let events = chain.advance_blocks(1);

    assert!(matches!(
        events[0],
        Event::RequestRefunded { reason: RefundReason::Expired, burned: DECLINE_FEE, .. }
    ));
    assert_eq!(chain.ledger().escrowed(), 0);
    assert_eq!(
        chain.ledger().balance(&carol),
        10 * COIN - chain.params().cold_network_fee - DECLINE_FEE
    );
    assert!(chain.ledger().is_balanced());
}

#[test]
fn failed_cancel_charges_nothing() {
    let (mut chain, alice, bob, carol) = setup();
    let events = chain
        .apply(carol, req(bob, COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    let (carol_before, burned_before) = (chain.ledger().balance(&carol), chain.ledger().burned());

    let err = chain.apply(alice, Tx::CancelRequest { request }).unwrap_err();

    assert_eq!(err, Error::NotRequestParty);
    assert_eq!(chain.ledger().balance(&carol), carol_before);
    assert_eq!(chain.ledger().burned(), burned_before);
    assert_eq!(chain.ledger().escrowed(), COIN, "request still pending");
    assert!(chain.ledger().is_balanced());
}

#[test]
fn decline_fee_scales_with_price_and_rounds_up() {
    use anonymum_core::chain::bps_of_rounded_up;
    assert_eq!(bps_of_rounded_up(COIN, 100), COIN / 100);
    assert_eq!(bps_of_rounded_up(1, 100), 1, "a non-zero price never costs zero");
    assert_eq!(bps_of_rounded_up(0, 100), 0);
    assert_eq!(bps_of_rounded_up(250, 100), 3, "2.5 rounds up to 3");
    assert_eq!(bps_of_rounded_up(COIN, 0), 0);
    assert_eq!(bps_of_rounded_up(COIN, 20_000), COIN, "capped at 100%");
    assert_eq!(bps_of_rounded_up(Amount::MAX, 10_000), Amount::MAX, "no overflow");

    // A recipient with a high price is protected by a higher decline fee.
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::SetContactPrice { price: 5 * COIN }).unwrap();
    let events = chain
        .apply(carol, req(bob, 5 * COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    let events = chain.apply(bob, Tx::CancelRequest { request }).unwrap();
    assert!(matches!(events[0], Event::RequestRefunded { burned, .. } if burned == 5 * COIN / 100));
    assert!(chain.ledger().is_balanced());
}

#[test]
fn price_rise_before_inclusion_is_rejected() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::SetContactPrice { price: 5 * COIN }).unwrap();
    let err = chain
        .apply(carol, req(bob, COIN))
        .unwrap_err();
    assert_eq!(err, Error::PriceAboveMax { price: 5 * COIN });
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN);
}

#[test]
fn cannot_request_without_funds_and_nothing_is_charged() {
    let (mut chain, _, bob, _) = setup();
    let dave = Address::from_label("dave");
    chain.mint(dave, COIN); // enough for the fee OR the price, not both
    let err = chain
        .apply(dave, req(bob, COIN))
        .unwrap_err();
    assert!(matches!(err, Error::InsufficientFunds { .. }));
    assert_eq!(chain.ledger().balance(&dave), COIN);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn only_recipient_can_accept() {
    let (mut chain, alice, bob, carol) = setup();
    let events = chain
        .apply(carol, req(bob, COIN))
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    assert_eq!(chain.apply(carol, Tx::AcceptContact { request }).unwrap_err(), Error::NotRecipient);
    assert_eq!(chain.apply(alice, Tx::CancelRequest { request }).unwrap_err(), Error::NotRequestParty);
}

#[test]
fn no_duplicate_channels_or_requests() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    assert_eq!(
        chain.apply(bob, req(alice, COIN)).unwrap_err(),
        Error::ChannelExists
    );

    chain.apply(carol, req(bob, COIN)).unwrap();
    assert_eq!(
        chain.apply(bob, req(carol, COIN)).unwrap_err(),
        Error::RequestPending
    );
}

#[test]
fn invite_supersedes_pending_request_and_refunds_it() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, req(bob, COIN)).unwrap();
    let secret = bob_invite(&mut chain, bob, 2);

    let events = chain.apply(carol, open_tx(&secret, carol, bob)).unwrap();

    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::RequestRefunded { amount: COIN, burned: 0, reason: RefundReason::Superseded, .. }
        )),
        "an invite turns a stranger into a contact: full refund, no decline fee"
    );
    let fees = chain.params().cold_network_fee + chain.params().invite_open_fee;
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN - fees);
    assert_eq!(chain.ledger().escrowed(), 0);
    assert!(chain.channel_between(&carol, &bob).is_some());
    assert!(chain.ledger().is_balanced());
}

// ---- A: closing blocks, Block / Unblock -----------------------------------

#[test]
fn closing_a_channel_blocks_the_closed_out_address() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;

    fails_charging_nothing(&mut chain, carol, Tx::CloseChannel { channel: id }, Error::NotParticipant);
    let events = chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();

    assert_eq!(
        events,
        vec![
            Event::ChannelClosed { channel: id, by: bob },
            Event::Blocked { by: bob, target: alice },
        ]
    );
    assert!(chain.channel_between(&alice, &bob).is_none());
    assert!(chain.is_blocked(&bob, &alice));
    assert!(!chain.is_blocked(&alice, &bob), "the closer is not blocked");
    fails_charging_nothing(&mut chain, alice, req(bob, COIN), Error::Blocked);
}

#[test]
fn the_closer_may_still_pay_to_reach_the_other_side() {
    let (mut chain, alice, bob, _) = setup();
    let id = paid_channel(&mut chain, alice, bob);
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();

    chain.apply(bob, req(alice, COIN)).unwrap();
    assert!(chain.ledger().is_balanced());
}

#[test]
fn a_fresh_invite_from_the_closer_reopens_and_clears_the_block() {
    let (mut chain, alice, bob, _) = setup();
    let first = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&first, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();

    let fresh = bob_invite(&mut chain, bob, 2);
    let events = chain.apply(alice, open_tx(&fresh, alice, bob)).unwrap();

    assert!(events.contains(&Event::Unblocked {
        by: bob,
        target: alice,
        reason: UnblockReason::ChannelOpened
    }));
    assert!(!chain.is_blocked(&bob, &alice));
    assert!(chain.channel_between(&alice, &bob).is_some());
    assert!(chain.ledger().is_balanced());
}

#[test]
fn an_invite_issued_before_the_block_cannot_lift_it() {
    let (mut chain, alice, bob, _) = setup();
    let first = bob_invite(&mut chain, bob, 1);
    let spare = bob_invite(&mut chain, bob, 2); // Alice kept a second one
    chain.apply(alice, open_tx(&first, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();

    fails_charging_nothing(&mut chain, alice, open_tx(&spare, alice, bob), Error::Blocked);
    assert!(chain.is_blocked(&bob, &alice));
}

#[test]
fn an_older_invite_still_works_for_someone_not_blocked() {
    let (mut chain, alice, bob, carol) = setup();
    let first = bob_invite(&mut chain, bob, 1);
    let for_carol = bob_invite(&mut chain, bob, 2);
    chain.apply(alice, open_tx(&first, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();

    chain.apply(carol, open_tx(&for_carol, carol, bob)).unwrap();
    assert!(chain.channel_between(&carol, &bob).is_some());
}

#[test]
fn block_without_a_channel_stops_paid_requests() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain.apply(bob, Tx::Block { target: carol }).unwrap();
    assert_eq!(events, vec![Event::Blocked { by: bob, target: carol }]);

    fails_charging_nothing(&mut chain, carol, req(bob, COIN), Error::Blocked);
}

#[test]
fn a_block_is_per_address_so_a_new_wallet_pays_stranger_costs() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    let dave = Address::from_label("dave");
    chain.mint(dave, 10 * COIN);

    chain.apply(dave, req(bob, COIN)).unwrap();
    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().balance(&dave), 10 * COIN - fee - COIN);
}

#[test]
fn blocking_refunds_a_pending_request_in_full() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain.apply(carol, req(bob, COIN)).unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };

    let events = chain.apply(bob, Tx::Block { target: carol }).unwrap();

    assert_eq!(
        events[0],
        Event::RequestRefunded {
            request,
            to: carol,
            amount: COIN,
            burned: 0,
            reason: RefundReason::Blocked,
        }
    );
    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN - fee, "only the network fee is lost");
    assert_eq!(chain.ledger().escrowed(), 0);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn blocking_cancels_the_blockers_own_request_with_decline_fee() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain.apply(bob, req(carol, COIN)).unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };

    let events = chain.apply(bob, Tx::Block { target: carol }).unwrap();

    assert_eq!(
        events,
        vec![
            Event::RequestRefunded {
                request,
                to: bob,
                amount: COIN - DECLINE_FEE,
                burned: DECLINE_FEE,
                reason: RefundReason::CancelledBy(bob),
            },
            Event::Blocked { by: bob, target: carol },
        ]
    );
    assert_eq!(chain.ledger().escrowed(), 0);
    assert!(chain.request(request).is_none(), "Carol can no longer accept it");
    assert!(chain.ledger().is_balanced());
}

#[test]
fn blocking_closes_an_open_channel() {
    let (mut chain, alice, bob, _) = setup();
    let id = paid_channel(&mut chain, alice, bob);

    let events = chain.apply(bob, Tx::Block { target: alice }).unwrap();

    assert_eq!(
        events,
        vec![
            Event::ChannelClosed { channel: id, by: bob },
            Event::Blocked { by: bob, target: alice },
        ]
    );
    assert!(chain.channel_between(&alice, &bob).is_none());
    fails_charging_nothing(&mut chain, alice, req(bob, COIN), Error::Blocked);
}

#[test]
fn unblock_lets_paid_requests_through_again() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    let events = chain.apply(bob, Tx::Unblock { target: carol }).unwrap();
    assert_eq!(
        events,
        vec![Event::Unblocked { by: bob, target: carol, reason: UnblockReason::Lifted }]
    );
    chain.apply(carol, req(bob, COIN)).unwrap();
}

#[test]
fn only_the_blocker_can_lift_a_block() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    fails_charging_nothing(&mut chain, carol, Tx::Unblock { target: bob }, Error::NotBlocked);
    assert!(chain.is_blocked(&bob, &carol));
}

#[test]
fn block_and_unblock_failure_paths() {
    let (mut chain, _, bob, carol) = setup();
    fails_charging_nothing(&mut chain, bob, Tx::Block { target: bob }, Error::SelfContact);
    fails_charging_nothing(&mut chain, bob, Tx::Unblock { target: carol }, Error::NotBlocked);
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    fails_charging_nothing(&mut chain, bob, Tx::Block { target: carol }, Error::AlreadyBlocked);
}

#[test]
fn an_accepted_request_from_the_blocker_clears_blocks_both_ways() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    chain.apply(carol, Tx::Block { target: bob }).unwrap();
    chain.apply(carol, Tx::Unblock { target: bob }).unwrap();

    // Bob blocked Carol, but Bob may still pay to reach her.
    let events = chain.apply(bob, req(carol, COIN)).unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    let events = chain.apply(carol, Tx::AcceptContact { request }).unwrap();

    assert!(events.contains(&Event::Unblocked {
        by: bob,
        target: carol,
        reason: UnblockReason::ChannelOpened
    }));
    assert!(!chain.is_blocked(&bob, &carol));
    assert!(chain.channel_between(&bob, &carol).is_some());
}

#[test]
fn a_mutual_block_is_cleared_when_an_invite_opens_a_channel() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    chain.apply(carol, Tx::Block { target: bob }).unwrap();

    let fresh = bob_invite(&mut chain, bob, 7);
    chain.apply(carol, open_tx(&fresh, carol, bob)).unwrap();

    assert!(!chain.is_blocked(&bob, &carol));
    assert!(!chain.is_blocked(&carol, &bob));
}

// ---- B: messaging keys, sealed notes, invite-only -------------------------

#[test]
fn messaging_key_needs_a_valid_binding() {
    let (mut chain, alice, bob, _) = setup();
    let key = MessagingKey([9; 32]);
    let forged = Tx::PublishMessagingKey { key, binding: mock_binding(&G, &bob, &key) };
    fails_charging_nothing(&mut chain, alice, forged, Error::BadKeyBinding);
    assert_ne!(chain.messaging_key(&alice).unwrap().key, key, "old key kept");

    chain.apply(alice, Tx::PublishMessagingKey { key, binding: mock_binding(&G, &alice, &key) }).unwrap();
    assert_eq!(chain.messaging_key(&alice).unwrap().key, key, "a key can be replaced");
}

#[test]
fn request_to_a_wallet_without_a_messaging_key_fails() {
    let (mut chain, _, _, carol) = setup();
    let dave = Address::from_label("dave");
    fails_charging_nothing(&mut chain, carol, req(dave, COIN), Error::NoMessagingKey);
}

#[test]
fn request_carries_the_sealed_note_to_the_recipient() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain.apply(carol, req(bob, COIN)).unwrap();
    let Event::ContactRequested { request, note: ref sent, .. } = events[0] else { panic!() };
    assert_eq!(*sent, note());
    assert_eq!(chain.request(request).unwrap().note, note());
}

#[test]
fn notes_of_the_wrong_size_are_refused() {
    let (mut chain, _, bob, carol) = setup();
    for len in [0, SEALED_NOTE_LEN - 1, SEALED_NOTE_LEN + 1, 10_000] {
        let tx = Tx::RequestContact { recipient: bob, max_price: COIN, note: SealedNote(vec![0; len]) };
        fails_charging_nothing(&mut chain, carol, tx, Error::BadNoteSize { len });
    }
}

#[test]
fn invite_only_wallets_refuse_strangers_but_not_invites() {
    let (mut chain, alice, bob, carol) = setup();
    chain.apply(bob, Tx::SetAcceptStrangers { accept: false }).unwrap();
    assert!(!chain.accepts_strangers(&bob));

    fails_charging_nothing(&mut chain, carol, req(bob, COIN), Error::StrangersNotAccepted);

    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    assert!(chain.channel_between(&alice, &bob).is_some());

    chain.apply(bob, Tx::SetAcceptStrangers { accept: true }).unwrap();
    chain.apply(carol, req(bob, COIN)).unwrap();
}

#[test]
fn going_invite_only_leaves_pending_requests_answerable() {
    let (mut chain, _, bob, carol) = setup();
    let events = chain.apply(carol, req(bob, COIN)).unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { panic!() };
    chain.apply(bob, Tx::SetAcceptStrangers { accept: false }).unwrap();
    chain.apply(bob, Tx::AcceptContact { request }).unwrap();
    assert!(chain.channel_between(&bob, &carol).is_some());
}

// ---- C: 24-hour expiry (D2) -----------------------------------------------

#[test]
fn request_ttl_is_24_hours_of_blocks() {
    let p = Params::default();
    assert_eq!(p.request_ttl_secs, 24 * 3600);
    assert_eq!(p.request_ttl_blocks(), 14_400, "24 h at 6 s blocks");
    let slow = Params { block_time_ms: 7_000, ..Params::default() };
    assert_eq!(slow.request_ttl_blocks(), 12_343, "rounded up: never shorter than 24 h");
    assert!(slow.request_ttl_blocks() * 7 >= 24 * 3600);
}

#[test]
fn request_expires_exactly_at_24_hours() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, req(bob, COIN)).unwrap();
    assert!(chain.advance_blocks(14_399).is_empty(), "still pending one block before");
    let events = chain.advance_blocks(1);
    assert!(matches!(events[0], Event::RequestRefunded { reason: RefundReason::Expired, .. }));
}

#[test]
fn network_fees_split_between_burn_and_node_rewards() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, req(bob, COIN)).unwrap();
    let fee = chain.params().cold_network_fee;
    assert_eq!(chain.ledger().burned(), fee / 2);
    assert_eq!(chain.ledger().reward_pool(), fee - fee / 2);
}

#[test]
fn inbox_drops_strangers_and_delivers_contacts() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();

    let mut inbox = Inbox::new(bob, 5, 1);
    let from_alice = Envelope { from: alice, to: bob, payload: b"hi".to_vec() };
    let from_carol = Envelope { from: carol, to: bob, payload: b"spam".to_vec() };

    assert_eq!(inbox.admit(&chain, &from_alice, 0), Verdict::Deliver);
    assert_eq!(inbox.admit(&chain, &from_carol, 0), Verdict::DropNoChannel);
    assert_eq!(
        inbox.admit(&chain, &Envelope { from: alice, to: carol, payload: vec![] }, 0),
        Verdict::DropMisaddressed
    );
}

#[test]
fn inbox_rate_limits_free_messages() {
    let (mut chain, alice, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();

    let mut inbox = Inbox::new(bob, 3, 1);
    let msg = Envelope { from: alice, to: bob, payload: vec![] };
    for _ in 0..3 {
        assert_eq!(inbox.admit(&chain, &msg, 0), Verdict::Deliver);
    }
    assert_eq!(inbox.admit(&chain, &msg, 0), Verdict::DropRateLimited);
    assert_eq!(inbox.admit(&chain, &msg, 1_000), Verdict::Deliver, "one token per second returns");
}

#[test]
fn token_bucket_never_exceeds_capacity() {
    let mut bucket = TokenBucket::new(2, 10, 0);
    // A long idle period must not bank more than the burst size.
    let delivered = (0..10).filter(|_| bucket.try_take(60_000)).count();
    assert_eq!(delivered, 2);
}

#[test]
fn coins_are_conserved_across_a_mixed_history() {
    let (mut chain, alice, bob, carol) = setup();
    let issued = chain.ledger().issued();
    let s1 = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&s1, alice, bob)).unwrap();
    chain.apply(carol, req(bob, COIN)).unwrap();
    chain.apply(carol, req(alice, COIN)).unwrap();
    chain.advance_blocks(chain.params().request_ttl_blocks());
    chain.apply(alice, req(carol, COIN)).unwrap();

    assert!(chain.ledger().is_balanced());
    assert_eq!(chain.ledger().issued(), issued);
}

// ---- F1: no arithmetic overflow ---------------------------------------------

#[test]
fn a_price_near_u128_max_cannot_wrap_past_the_funds_check() {
    let (mut chain, _, bob, carol) = setup();
    let fee = chain.params().cold_network_fee;
    chain.apply(bob, Tx::SetContactPrice { price: u128::MAX - fee + 1 }).unwrap();
    let tx = Tx::RequestContact { recipient: bob, max_price: u128::MAX, note: note() };
    let err = chain.apply(carol, tx.clone()).unwrap_err();
    assert!(matches!(err, Error::InsufficientFunds { .. }), "got {err:?}");
    fails_charging_nothing(&mut chain, carol, tx, err);
}

#[test]
fn time_saturates_instead_of_wrapping() {
    let (mut chain, _, bob, carol) = setup();
    chain.advance_blocks(u64::MAX - 5);
    chain.apply(carol, req(bob, COIN)).unwrap(); // expiry would overflow u64
    chain.advance_blocks(u64::MAX); // must not panic
    assert_eq!(chain.height(), u64::MAX);
    assert!(chain.ledger().is_balanced());
}

// ---- F2: invite keys cannot be squatted -------------------------------------

#[test]
fn a_squatted_invite_key_does_not_stop_the_owner_or_the_invitee() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = MockInviteSecret::from_seed(42);
    // Carol sees Bob's pending registration and registers the key first.
    chain.apply(carol, Tx::RegisterInvite { key: secret.public(), expires_at: None }).unwrap();
    // Bob's own registration still succeeds, and Alice can use it.
    chain.apply(bob, Tx::RegisterInvite { key: secret.public(), expires_at: None }).unwrap();
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    assert!(chain.channel_between(&alice, &bob).is_some());
    // Carol's entry is separate: still registered, so she cannot add it twice.
    fails_charging_nothing(
        &mut chain,
        carol,
        Tx::RegisterInvite { key: secret.public(), expires_at: None },
        Error::InviteAlreadyRegistered,
    );
}

#[test]
fn only_the_owner_can_revoke_an_invite() {
    let (mut chain, alice, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    fails_charging_nothing(&mut chain, alice, Tx::RevokeInvite { key: secret.public() }, Error::UnknownInvite);
    chain.apply(bob, Tx::RevokeInvite { key: secret.public() }).unwrap();
    fails_charging_nothing(&mut chain, alice, open_tx(&secret, alice, bob), Error::UnknownInvite);
}

// ---- F3: refundable storage deposits ----------------------------------------

const DEPOSIT: Amount = COIN / 100;

#[test]
fn an_invite_holds_a_deposit_returned_when_used() {
    let (mut chain, alice, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN - DEPOSIT);
    assert_eq!(chain.ledger().reserved(&bob), 2 * DEPOSIT, "key + invite");
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN, "invite deposit back");
    assert!(chain.ledger().is_balanced());
}

#[test]
fn revoking_an_invite_returns_its_deposit() {
    let (mut chain, _, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(bob, Tx::RevokeInvite { key: secret.public() }).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN);
}

#[test]
fn anyone_may_remove_an_expired_invite_and_the_owner_gets_the_deposit() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = MockInviteSecret::from_seed(9);
    chain.apply(bob, Tx::RegisterInvite { key: secret.public(), expires_at: Some(5) }).unwrap();
    let remove = Tx::RemoveExpiredInvite { owner: bob, key: secret.public() };
    fails_charging_nothing(&mut chain, carol, remove.clone(), Error::InviteNotExpired);
    chain.advance_blocks(6);
    let events = chain.apply(carol, remove.clone()).unwrap();
    assert_eq!(events, vec![Event::ExpiredInviteRemoved { owner: bob, key: secret.public(), by: carol }]);
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN, "deposit to the owner");
    assert_eq!(chain.ledger().balance(&carol), 10 * COIN, "not to the caller");
    fails_charging_nothing(&mut chain, carol, remove, Error::UnknownInvite);
    fails_charging_nothing(&mut chain, alice, open_tx(&secret, alice, bob), Error::UnknownInvite);
}

#[test]
fn an_invite_without_expiry_cannot_be_removed_by_others() {
    let (mut chain, _, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.advance_blocks(1_000_000);
    fails_charging_nothing(
        &mut chain,
        carol,
        Tx::RemoveExpiredInvite { owner: bob, key: secret.public() },
        Error::InviteNotExpired,
    );
}

#[test]
fn storing_anything_without_the_deposit_fails_and_charges_nothing() {
    let (mut chain, _, bob, _) = setup();
    let dave = Address::from_label("dave");
    chain.mint(dave, DEPOSIT - 1);
    let key = MessagingKey([7; 32]);
    let txs = [
        Tx::RegisterInvite { key: MockInviteSecret::from_seed(3).public(), expires_at: None },
        Tx::Block { target: bob },
        Tx::PublishMessagingKey { key, binding: mock_binding(&G, &dave, &key) },
    ];
    for tx in txs {
        let err = chain.apply(dave, tx.clone()).unwrap_err();
        assert!(matches!(err, Error::InsufficientFunds { .. }), "got {err:?}");
        fails_charging_nothing(&mut chain, dave, tx, err);
    }
}

#[test]
fn a_block_holds_a_deposit_returned_on_unblock() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN - DEPOSIT);
    chain.apply(bob, Tx::Unblock { target: carol }).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN);
}

#[test]
fn closing_takes_the_block_deposit_from_the_closer() {
    let (mut chain, alice, bob, _) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN - DEPOSIT);
    assert_eq!(chain.ledger().reserved(&bob), 2 * DEPOSIT, "key + block");
}

#[test]
fn a_closer_who_cannot_pay_the_block_deposit_cannot_close() {
    let (mut chain, alice, bob, _) = setup();
    // Erin has exactly enough for a key deposit and an invite deposit.
    let erin = Address::from_label("erin");
    chain.mint(erin, 2 * DEPOSIT);
    let key = MessagingKey([5; 32]);
    chain.apply(erin, Tx::PublishMessagingKey { key, binding: mock_binding(&G, &erin, &key) }).unwrap();
    let invite = MockInviteSecret::from_seed(6);
    chain.apply(erin, Tx::RegisterInvite { key: invite.public(), expires_at: None }).unwrap();
    chain.apply(bob, open_tx(&invite, bob, erin)).unwrap(); // invite deposit back to Erin
    chain.apply(erin, Tx::Block { target: alice }).unwrap(); // and spent on a block
    assert_eq!(chain.ledger().balance(&erin), 0);
    let channel = chain.channel_between(&bob, &erin).unwrap().id;

    fails_charging_nothing(
        &mut chain,
        erin,
        Tx::CloseChannel { channel },
        Error::InsufficientFunds { needed: DEPOSIT, available: 0 },
    );
    assert!(chain.channel_between(&bob, &erin).is_some(), "channel stays open");
}

#[test]
fn opening_a_channel_returns_cleared_block_deposits_to_the_blockers() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(bob, Tx::Block { target: carol }).unwrap();
    chain.apply(carol, Tx::Block { target: bob }).unwrap();
    let fresh = bob_invite(&mut chain, bob, 7);
    chain.apply(carol, open_tx(&fresh, carol, bob)).unwrap();
    assert_eq!(chain.ledger().balance(&bob), 10 * COIN, "block + invite deposits back");
    assert_eq!(
        chain.ledger().balance(&carol),
        10 * COIN - chain.params().invite_open_fee,
        "block deposit back"
    );
    assert!(chain.ledger().is_balanced());
}

#[test]
fn replacing_a_messaging_key_keeps_a_single_deposit() {
    let (mut chain, alice, _, _) = setup();
    let key = MessagingKey([9; 32]);
    chain.apply(alice, Tx::PublishMessagingKey { key, binding: mock_binding(&G, &alice, &key) }).unwrap();
    assert_eq!(chain.ledger().reserved(&alice), DEPOSIT);
    assert_eq!(chain.ledger().balance(&alice), 10 * COIN);
}

// ---- signed messages carry the chain (2026-11-20 audit HIGH-04) ------------

#[test]
fn signatures_made_for_another_chain_are_refused() {
    let (mut chain, alice, bob, _) = setup();
    let other = [7u8; 32];
    let key = MessagingKey([8; 32]);
    let foreign = Tx::PublishMessagingKey { key, binding: mock_binding(&other, &alice, &key) };
    fails_charging_nothing(&mut chain, alice, foreign, Error::BadKeyBinding);

    let secret = bob_invite(&mut chain, bob, 21);
    let foreign = Tx::OpenWithInvite {
        recipient: bob,
        key: secret.public(),
        proof: secret.sign(&invite_message(&other, &alice, &bob)),
    };
    fails_charging_nothing(&mut chain, alice, foreign, Error::BadInviteProof);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
}

#[test]
fn the_genesis_id_is_a_chain_parameter() {
    let params = Params { genesis: [7u8; 32], ..Params::default() };
    let mut chain = Chain::new(params, MockScheme);
    let alice = Address([1; 32]);
    chain.mint(alice, 10 * COIN);
    let key = MessagingKey([8; 32]);
    let made_for_default = Tx::PublishMessagingKey { key, binding: mock_binding(&G, &alice, &key) };
    assert_eq!(chain.apply(alice, made_for_default).unwrap_err(), Error::BadKeyBinding);
    let made_for_this = Tx::PublishMessagingKey { key, binding: mock_binding(&[7u8; 32], &alice, &key) };
    chain.apply(alice, made_for_this).unwrap();
}
