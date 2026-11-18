use anonymum_core::crypto::mock::{MockInviteSecret, MockScheme};
use anonymum_core::crypto::invite_message;
use anonymum_core::ratelimit::TokenBucket;
use anonymum_core::*;

fn setup() -> (Chain<MockScheme>, Address, Address, Address) {
    let mut chain = Chain::new(Params::default(), MockScheme);
    let (alice, bob, carol) = (
        Address::from_label("alice"),
        Address::from_label("bob"),
        Address::from_label("carol"),
    );
    for who in [alice, bob, carol] {
        chain.mint(who, 10 * COIN);
    }
    (chain, alice, bob, carol)
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
        proof: secret.sign(&invite_message(&opener, &recipient)),
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
        proof: secret.sign(&invite_message(&alice, &carol)),
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: 3 * COIN })
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN })
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN })
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
    chain.apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN }).unwrap();

    let ttl = chain.params().request_ttl_blocks;
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN })
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: 5 * COIN })
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
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN })
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
        .apply(dave, Tx::RequestContact { recipient: bob, max_price: COIN })
        .unwrap_err();
    assert!(matches!(err, Error::InsufficientFunds { .. }));
    assert_eq!(chain.ledger().balance(&dave), COIN);
    assert!(chain.ledger().is_balanced());
}

#[test]
fn only_recipient_can_accept() {
    let (mut chain, alice, bob, carol) = setup();
    let events = chain
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN })
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
        chain.apply(bob, Tx::RequestContact { recipient: alice, max_price: COIN }).unwrap_err(),
        Error::ChannelExists
    );

    chain.apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN }).unwrap();
    assert_eq!(
        chain.apply(bob, Tx::RequestContact { recipient: carol, max_price: COIN }).unwrap_err(),
        Error::RequestPending
    );
}

#[test]
fn invite_supersedes_pending_request_and_refunds_it() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN }).unwrap();
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

#[test]
fn closing_a_channel_forces_reopening() {
    let (mut chain, alice, bob, carol) = setup();
    let secret = bob_invite(&mut chain, bob, 1);
    chain.apply(alice, open_tx(&secret, alice, bob)).unwrap();
    let id = chain.channel_between(&alice, &bob).unwrap().id;

    assert_eq!(chain.apply(carol, Tx::CloseChannel { channel: id }).unwrap_err(), Error::NotParticipant);
    chain.apply(bob, Tx::CloseChannel { channel: id }).unwrap();
    assert!(chain.channel_between(&alice, &bob).is_none());
}

#[test]
fn network_fees_split_between_burn_and_node_rewards() {
    let (mut chain, _, bob, carol) = setup();
    chain.apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN }).unwrap();
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
    chain.apply(carol, Tx::RequestContact { recipient: bob, max_price: COIN }).unwrap();
    chain.apply(carol, Tx::RequestContact { recipient: alice, max_price: COIN }).unwrap();
    chain.advance_blocks(chain.params().request_ttl_blocks);
    chain.apply(alice, Tx::RequestContact { recipient: carol, max_price: COIN }).unwrap();

    assert!(chain.ledger().is_balanced());
    assert_eq!(chain.ledger().issued(), issued);
}
