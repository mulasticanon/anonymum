//! Ported from `crates/core/tests/protocol.rs`. Client-side tests (inbox,
//! rate limiter) stay in the core crate: they are not chain rules.
//!
//! `assert_noop!` checks that a failed call leaves the whole storage root
//! unchanged: no balance, hold, burn, pool, event or table moved.

use crate::mock::*;
use crate::pallet::{
    HoldReason, Blocks, Channels, Error, Event, ExpiryQueue, MessagingKeys, OpenedVia, RefundReason, Requests,
    UnblockReason,
};
use crate::{invite_message, SealedNote, SEALED_NOTE_LEN};
use codec::Encode;
use frame::deps::sp_core::{ed25519, Pair};
use frame::deps::sp_io::hashing::blake2_256;
use frame::deps::sp_runtime::{AccountId32, ArithmeticError, MultiSignature};
use frame::testing_prelude::*;
use frame::traits::fungible::InspectHold;
use polkadot_sdk::polkadot_sdk_frame as frame;

const DECLINE_FEE: Balance = COIN / 100;
const COLD_FEE: Balance = COIN / 2;
const INVITE_FEE: Balance = COIN / 100;

fn signed(name: &str) -> RuntimeOrigin {
    RuntimeOrigin::signed(account(name))
}

fn free(name: &str) -> Balance {
    Balances::free_balance(account(name))
}

/// Held in contact-request escrow (not counting storage deposits).
fn held(name: &str) -> Balance {
    Balances::balance_on_hold(&HoldReason::ContactEscrow.into(), &account(name))
}

/// Held as storage deposits (invites, blocks, messaging key).
fn deposits(name: &str) -> Balance {
    Balances::total_balance_on_hold(&account(name)) - held(name)
}

fn issuance() -> Balance {
    Balances::total_issuance()
}

fn pool_balance() -> Balance {
    Balances::free_balance(pool())
}

fn our_events() -> Vec<Event<Test>> {
    System::events()
        .into_iter()
        .filter_map(|r| if let RuntimeEvent::Anonymum(e) = r.event { Some(e) } else { None })
        .collect()
}

/// Events since the last call.
fn new_events() -> Vec<Event<Test>> {
    let events = our_events();
    System::reset_events();
    events
}

fn req(from: &str, to: &str, max_price: Balance) -> DispatchResult {
    Anonymum::request_contact(signed(from), account(to), max_price, note())
}

/// The id of the request just made.
fn last_request() -> u64 {
    our_events()
        .into_iter()
        .rev()
        .find_map(|e| if let Event::ContactRequested { request, .. } = e { Some(request) } else { None })
        .expect("a request was made")
}

/// `owner` registers an invite; returns the secret they would hand out.
fn invite(owner: &str, seed: u8) -> ed25519::Pair {
    let secret = ed25519::Pair::from_seed(&blake2_256(&[b'i', seed]));
    Anonymum::register_invite(signed(owner), secret.public().0, None).unwrap();
    secret
}

fn open(opener: &str, recipient: &str, secret: &ed25519::Pair) -> DispatchResult {
    let message = invite_message(&genesis(), &account(opener).encode(), &account(recipient).encode());
    Anonymum::open_with_invite(signed(opener), account(recipient), secret.public().0, secret.sign(&message).0)
}

fn channel(a: &str, b: &str) -> Option<u64> {
    let (a, b) = (account(a), account(b));
    let key = if a <= b { (a, b) } else { (b, a) };
    crate::pallet::ChannelByPair::<Test>::get(key)
}

/// Opens a paid channel from `from` to `to` (request + accept).
fn paid_channel(from: &str, to: &str) -> u64 {
    req(from, to, Anonymum::contact_price(&account(to))).unwrap();
    Anonymum::accept_contact(signed(to), last_request()).unwrap();
    channel(from, to).unwrap()
}

fn blocked(blocker: &str, target: &str) -> bool {
    Blocks::<Test>::contains_key(account(blocker), account(target))
}

/// Every coin is in a wallet (free or held) or the pool, or was burned.
fn assert_conserved(start_issuance: Balance) {
    let wallets: Balance =
        ["alice", "bob", "carol", "dave"].iter().map(|n| free(n) + held(n) + deposits(n)).sum();
    assert_eq!(wallets + pool_balance(), issuance(), "all coins accounted for");
    assert!(issuance() <= start_issuance);
}

// ---- invites ----------------------------------------------------------------

#[test]
fn invite_opens_channel_for_small_fee() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_ok!(open("alice", "bob", &secret));
        assert_eq!(free("alice"), 10 * COIN - INVITE_FEE);
        assert_eq!(free("bob"), 10 * COIN, "nothing to the recipient");
        let id = channel("alice", "bob").unwrap();
        assert_eq!(Channels::<Test>::get(id).unwrap().via, OpenedVia::Invite);
    });
}

#[test]
fn invite_is_one_time() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_ok!(open("alice", "bob", &secret));
        assert_noop!(open("carol", "bob", &secret), Error::<Test>::UnknownInvite);
    });
}

#[test]
fn invite_only_works_for_its_owner() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_noop!(open("alice", "carol", &secret), Error::<Test>::UnknownInvite);
    });
}

#[test]
fn stolen_proof_cannot_be_reused_by_someone_else() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        let alices_proof = secret.sign(&invite_message(&genesis(), &account("alice").encode(), &account("bob").encode()));
        assert_noop!(
            Anonymum::open_with_invite(signed("carol"), account("bob"), secret.public().0, alices_proof.0),
            Error::<Test>::BadInviteProof
        );
    });
}

#[test]
fn expired_invite_is_rejected() {
    new_test_ext().execute_with(|| {
        let secret = ed25519::Pair::from_seed(&[9; 32]);
        assert_ok!(Anonymum::register_invite(signed("bob"), secret.public().0, Some(5)));
        System::set_block_number(6);
        assert_noop!(open("alice", "bob", &secret), Error::<Test>::InviteExpired);
    });
}

#[test]
fn invites_can_be_revoked_only_by_their_owner() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        // Alice can only find (and revoke) invites registered under her own name.
        assert_noop!(Anonymum::revoke_invite(signed("alice"), secret.public().0), Error::<Test>::UnknownInvite);
        assert_noop!(
            Anonymum::register_invite(signed("bob"), secret.public().0, None),
            Error::<Test>::InviteAlreadyRegistered
        );
        assert_ok!(Anonymum::revoke_invite(signed("bob"), secret.public().0));
        assert_noop!(open("alice", "bob", &secret), Error::<Test>::UnknownInvite);
    });
}

#[test]
fn a_squatted_invite_key_does_not_stop_the_owner_or_the_invitee() {
    new_test_ext().execute_with(|| {
        // Carol sees Bob's pending registration and registers the key first.
        let secret = ed25519::Pair::from_seed(&blake2_256(b"bob's invite"));
        assert_ok!(Anonymum::register_invite(signed("carol"), secret.public().0, None));
        // Bob's own registration still succeeds, and Alice can use it.
        assert_ok!(Anonymum::register_invite(signed("bob"), secret.public().0, None));
        assert_ok!(open("alice", "bob", &secret));
        assert!(channel("alice", "bob").is_some());
        // Carol's entry is separate and untouched; Bob's is used up.
        assert!(crate::pallet::Invites::<Test>::contains_key(account("carol"), secret.public().0));
        assert!(!crate::pallet::Invites::<Test>::contains_key(account("bob"), secret.public().0));
        assert_noop!(
            Anonymum::register_invite(signed("carol"), secret.public().0, None),
            Error::<Test>::InviteAlreadyRegistered
        );
    });
}

// ---- paid requests, escrow, decline fee ------------------------------------

#[test]
fn stranger_pays_network_and_recipient() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::set_contact_price(signed("bob"), 3 * COIN));
        assert_ok!(req("carol", "bob", 3 * COIN));
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE - 3 * COIN);
        assert_eq!(held("carol"), 3 * COIN, "price is escrowed");
        assert!(channel("carol", "bob").is_none(), "no channel until Bob accepts");

        assert_ok!(Anonymum::accept_contact(signed("bob"), last_request()));
        assert_eq!(free("bob"), 13 * COIN);
        assert_eq!(held("carol"), 0);
        let id = channel("carol", "bob").unwrap();
        assert_eq!(Channels::<Test>::get(id).unwrap().via, OpenedVia::PaidRequest);
    });
}

#[test]
fn network_fees_split_between_burn_and_node_rewards() {
    new_test_ext().execute_with(|| {
        let (start, pool_start) = (issuance(), pool_balance());
        assert_ok!(req("carol", "bob", COIN));
        assert_eq!(start - issuance(), COLD_FEE / 2, "half burned");
        assert_eq!(pool_balance() - pool_start, COLD_FEE - COLD_FEE / 2, "half to nodes");
        assert_conserved(start);
    });
}

#[test]
fn declined_request_burns_decline_fee_and_keeps_network_fee() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let request = last_request();
        let burned_before = issuance();
        System::reset_events();

        assert_ok!(Anonymum::cancel_request(signed("bob"), request));

        assert_eq!(
            new_events(),
            vec![Event::RequestRefunded {
                request,
                to: account("carol"),
                amount: COIN - DECLINE_FEE,
                burned: DECLINE_FEE,
                reason: RefundReason::CancelledBy(account("bob")),
            }]
        );
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE - DECLINE_FEE);
        assert_eq!(free("bob"), 10 * COIN, "recipient gains nothing from declining");
        assert_eq!(burned_before - issuance(), DECLINE_FEE);
        assert_eq!(held("carol"), 0);
    });
}

#[test]
fn sender_cancelling_pays_the_same_decline_fee() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let pool_before = pool_balance();
        assert_ok!(Anonymum::cancel_request(signed("carol"), last_request()));
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE - DECLINE_FEE);
        assert_eq!(pool_balance(), pool_before, "decline fee is burned, not pooled");
    });
}

#[test]
fn failed_cancel_charges_nothing() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        assert_noop!(Anonymum::cancel_request(signed("alice"), last_request()), Error::<Test>::NotRequestParty);
        assert_noop!(Anonymum::cancel_request(signed("alice"), 999), Error::<Test>::UnknownRequest);
    });
}

#[test]
fn price_rise_before_inclusion_is_rejected() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::set_contact_price(signed("bob"), 5 * COIN));
        assert_noop!(req("carol", "bob", COIN), Error::<Test>::PriceAboveMax);
    });
}

#[test]
fn cannot_request_without_funds_and_nothing_is_charged() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::set_contact_price(signed("bob"), 10 * COIN));
        assert_noop!(req("carol", "bob", 10 * COIN), Error::<Test>::InsufficientFunds);
    });
}

#[test]
fn only_recipient_can_accept() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        assert_noop!(Anonymum::accept_contact(signed("carol"), last_request()), Error::<Test>::NotRecipient);
        assert_noop!(Anonymum::accept_contact(signed("bob"), 999), Error::<Test>::UnknownRequest);
    });
}

#[test]
fn no_duplicate_channels_or_requests() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_ok!(open("alice", "bob", &secret));
        assert_noop!(req("bob", "alice", COIN), Error::<Test>::ChannelExists);
        let second = invite("bob", 2);
        assert_noop!(open("alice", "bob", &second), Error::<Test>::ChannelExists);

        assert_ok!(req("carol", "bob", COIN));
        assert_noop!(req("bob", "carol", COIN), Error::<Test>::RequestPending);
        assert_noop!(req("carol", "carol", COIN), Error::<Test>::SelfContact);
    });
}

#[test]
fn invite_supersedes_pending_request_and_refunds_it() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let secret = invite("bob", 2);
        System::reset_events();
        assert_ok!(open("carol", "bob", &secret));
        assert!(new_events().iter().any(|e| matches!(
            e,
            Event::RequestRefunded { amount: COIN, burned: 0, reason: RefundReason::Superseded, .. }
        )));
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE - INVITE_FEE);
        assert_eq!(held("carol"), 0);
        assert!(channel("carol", "bob").is_some());
    });
}

#[test]
fn decline_fee_scales_with_price_and_rounds_up() {
    new_test_ext().execute_with(|| {
        assert_eq!(Anonymum::bps_of_rounded_up(COIN, 100), COIN / 100);
        assert_eq!(Anonymum::bps_of_rounded_up(1, 100), 1, "a non-zero price never costs zero");
        assert_eq!(Anonymum::bps_of_rounded_up(0, 100), 0);
        assert_eq!(Anonymum::bps_of_rounded_up(250, 100), 3, "2.5 rounds up to 3");
        assert_eq!(Anonymum::bps_of_rounded_up(COIN, 20_000), COIN, "capped at 100%");

        assert_ok!(Anonymum::set_contact_price(signed("bob"), 5 * COIN));
        assert_ok!(req("carol", "bob", 5 * COIN));
        let request = last_request();
        System::reset_events();
        assert_ok!(Anonymum::cancel_request(signed("bob"), request));
        assert!(matches!(new_events()[0], Event::RequestRefunded { burned, .. } if burned == 5 * COIN / 100));
    });
}

// ---- A: closing blocks, Block / Unblock -------------------------------------

#[test]
fn closing_a_channel_blocks_the_closed_out_address() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_ok!(open("alice", "bob", &secret));
        let id = channel("alice", "bob").unwrap();
        assert_noop!(Anonymum::close_channel(signed("carol"), id), Error::<Test>::NotParticipant);
        assert_noop!(Anonymum::close_channel(signed("bob"), 999), Error::<Test>::UnknownChannel);
        System::reset_events();

        assert_ok!(Anonymum::close_channel(signed("bob"), id));
        assert_eq!(
            new_events(),
            vec![
                Event::ChannelClosed { channel: id, by: account("bob") },
                Event::Blocked { by: account("bob"), target: account("alice") },
            ]
        );
        assert!(channel("alice", "bob").is_none());
        assert!(blocked("bob", "alice"));
        assert!(!blocked("alice", "bob"), "the closer is not blocked");
        assert_noop!(req("alice", "bob", COIN), Error::<Test>::Blocked);
    });
}

#[test]
fn the_closer_may_still_pay_to_reach_the_other_side() {
    new_test_ext().execute_with(|| {
        let id = paid_channel("alice", "bob");
        assert_ok!(Anonymum::close_channel(signed("bob"), id));
        assert_ok!(req("bob", "alice", COIN));
    });
}

#[test]
fn a_fresh_invite_from_the_closer_reopens_and_clears_the_block() {
    new_test_ext().execute_with(|| {
        assert_ok!(open("alice", "bob", &invite("bob", 1)));
        assert_ok!(Anonymum::close_channel(signed("bob"), channel("alice", "bob").unwrap()));
        let fresh = invite("bob", 2);
        System::reset_events();
        assert_ok!(open("alice", "bob", &fresh));
        assert!(new_events().contains(&Event::Unblocked {
            by: account("bob"),
            target: account("alice"),
            reason: UnblockReason::ChannelOpened,
        }));
        assert!(!blocked("bob", "alice"));
        assert!(channel("alice", "bob").is_some());
    });
}

#[test]
fn an_invite_issued_before_the_block_cannot_lift_it() {
    new_test_ext().execute_with(|| {
        let first = invite("bob", 1);
        let spare = invite("bob", 2); // Alice kept a second one
        assert_ok!(open("alice", "bob", &first));
        assert_ok!(Anonymum::close_channel(signed("bob"), channel("alice", "bob").unwrap()));
        assert_noop!(open("alice", "bob", &spare), Error::<Test>::Blocked);
    });
}

#[test]
fn an_older_invite_still_works_for_someone_not_blocked() {
    new_test_ext().execute_with(|| {
        let first = invite("bob", 1);
        let for_carol = invite("bob", 2);
        assert_ok!(open("alice", "bob", &first));
        assert_ok!(Anonymum::close_channel(signed("bob"), channel("alice", "bob").unwrap()));
        assert_ok!(open("carol", "bob", &for_carol));
    });
}

#[test]
fn block_without_a_channel_stops_paid_requests() {
    new_test_ext().execute_with(|| {
        System::reset_events();
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_eq!(new_events(), vec![Event::Blocked { by: account("bob"), target: account("carol") }]);
        assert_noop!(req("carol", "bob", COIN), Error::<Test>::Blocked);
    });
}

#[test]
fn a_block_is_per_address_so_a_new_wallet_pays_stranger_costs() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_ok!(req("dave", "bob", COIN));
        assert_eq!(free("dave"), 10 * COIN - COLD_FEE - COIN);
    });
}

#[test]
fn blocking_refunds_a_pending_request_in_full() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let request = last_request();
        System::reset_events();
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_eq!(
            new_events()[0],
            Event::RequestRefunded {
                request,
                to: account("carol"),
                amount: COIN,
                burned: 0,
                reason: RefundReason::Blocked,
            }
        );
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE, "only the network fee is lost");
        assert_eq!(held("carol"), 0);
    });
}

#[test]
fn blocking_cancels_the_blockers_own_request_with_decline_fee() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("bob", "carol", COIN));
        let request = last_request();
        let issuance_before = issuance();
        System::reset_events();

        assert_ok!(Anonymum::block(signed("bob"), account("carol")));

        assert_eq!(
            new_events(),
            vec![
                Event::RequestRefunded {
                    request,
                    to: account("bob"),
                    amount: COIN - DECLINE_FEE,
                    burned: DECLINE_FEE,
                    reason: RefundReason::CancelledBy(account("bob")),
                },
                Event::Blocked { by: account("bob"), target: account("carol") },
            ]
        );
        assert_eq!(held("bob"), 0);
        assert_eq!(issuance_before - issuance(), DECLINE_FEE);
        assert!(Requests::<Test>::get(request).is_none(), "Carol can no longer accept it");
    });
}

#[test]
fn blocking_closes_an_open_channel() {
    new_test_ext().execute_with(|| {
        let id = paid_channel("alice", "bob");
        System::reset_events();
        assert_ok!(Anonymum::block(signed("bob"), account("alice")));
        assert_eq!(
            new_events(),
            vec![
                Event::ChannelClosed { channel: id, by: account("bob") },
                Event::Blocked { by: account("bob"), target: account("alice") },
            ]
        );
        assert!(channel("alice", "bob").is_none());
        assert_noop!(req("alice", "bob", COIN), Error::<Test>::Blocked);
    });
}

#[test]
fn unblock_lets_paid_requests_through_again() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        System::reset_events();
        assert_ok!(Anonymum::unblock(signed("bob"), account("carol")));
        assert_eq!(
            new_events(),
            vec![Event::Unblocked { by: account("bob"), target: account("carol"), reason: UnblockReason::Lifted }]
        );
        assert_ok!(req("carol", "bob", COIN));
    });
}

#[test]
fn only_the_blocker_can_lift_a_block() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_noop!(Anonymum::unblock(signed("carol"), account("bob")), Error::<Test>::NotBlocked);
        assert!(blocked("bob", "carol"));
    });
}

#[test]
fn block_and_unblock_failure_paths() {
    new_test_ext().execute_with(|| {
        assert_noop!(Anonymum::block(signed("bob"), account("bob")), Error::<Test>::SelfContact);
        assert_noop!(Anonymum::unblock(signed("bob"), account("carol")), Error::<Test>::NotBlocked);
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_noop!(Anonymum::block(signed("bob"), account("carol")), Error::<Test>::AlreadyBlocked);
    });
}

#[test]
fn an_accepted_request_from_the_blocker_clears_blocks_both_ways() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_ok!(req("bob", "carol", COIN));
        let request = last_request();
        System::reset_events();
        assert_ok!(Anonymum::accept_contact(signed("carol"), request));
        assert!(new_events().contains(&Event::Unblocked {
            by: account("bob"),
            target: account("carol"),
            reason: UnblockReason::ChannelOpened,
        }));
        assert!(!blocked("bob", "carol"));
        assert!(channel("bob", "carol").is_some());
    });
}

#[test]
fn a_mutual_block_is_cleared_when_an_invite_opens_a_channel() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_ok!(Anonymum::block(signed("carol"), account("bob")));
        let fresh = invite("bob", 7);
        assert_ok!(open("carol", "bob", &fresh));
        assert!(!blocked("bob", "carol"));
        assert!(!blocked("carol", "bob"));
    });
}

// ---- B: messaging keys, sealed notes, invite-only ---------------------------

#[test]
fn messaging_key_needs_a_valid_binding() {
    new_test_ext().execute_with(|| {
        // Bob's key and Bob's valid binding, submitted by Alice.
        let (bobs_key, bobs_binding) = messaging_key("bob");
        assert_noop!(
            Anonymum::publish_messaging_key(signed("alice"), bobs_key, bobs_binding),
            Error::<Test>::BadKeyBinding
        );
        // A new key for Alice, properly signed: replaces the old one.
        let new_key = [9u8; 32];
        let binding = binding_by("alice", "alice", &new_key);
        assert_ok!(Anonymum::publish_messaging_key(signed("alice"), new_key, binding));
        assert_eq!(MessagingKeys::<Test>::get(account("alice")).unwrap().key, new_key);
    });
}

#[test]
fn request_to_a_wallet_without_a_messaging_key_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(req("carol", "dave", COIN), Error::<Test>::NoMessagingKey);
    });
}

#[test]
fn request_carries_the_sealed_note_to_the_recipient() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let request = last_request();
        assert!(our_events().iter().any(|e| matches!(e, Event::ContactRequested { note: n, .. } if *n == note())));
        assert_eq!(Requests::<Test>::get(request).unwrap().note, note());
    });
}

#[test]
fn notes_of_the_wrong_size_are_refused() {
    new_test_ext().execute_with(|| {
        for len in [0usize, 1, SEALED_NOTE_LEN as usize - 1] {
            let short: SealedNote = vec![0u8; len].try_into().unwrap();
            assert_noop!(
                Anonymum::request_contact(signed("carol"), account("bob"), COIN, short),
                Error::<Test>::BadNoteSize
            );
        }
        // Longer than SEALED_NOTE_LEN cannot even be decoded into a call: the bound
        // on `SealedNote` rejects it.
        assert!(SealedNote::try_from(vec![0u8; SEALED_NOTE_LEN as usize + 1]).is_err());
    });
}

#[test]
fn invite_only_wallets_refuse_strangers_but_not_invites() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::set_accept_strangers(signed("bob"), false));
        assert_noop!(req("carol", "bob", COIN), Error::<Test>::StrangersNotAccepted);
        assert_ok!(open("alice", "bob", &invite("bob", 1)));
        assert_ok!(Anonymum::set_accept_strangers(signed("bob"), true));
        assert_ok!(req("carol", "bob", COIN));
    });
}

#[test]
fn going_invite_only_leaves_pending_requests_answerable() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let request = last_request();
        assert_ok!(Anonymum::set_accept_strangers(signed("bob"), false));
        assert_ok!(Anonymum::accept_contact(signed("bob"), request));
        assert!(channel("bob", "carol").is_some());
    });
}

// ---- C: 24-hour expiry (D2) ------------------------------------------------------

#[test]
fn request_ttl_is_48_hours_of_blocks() {
    new_test_ext().execute_with(|| {
        assert_eq!(Anonymum::request_ttl_blocks(), 14_400);
    });
}

#[test]
fn request_expires_exactly_at_48_hours_minus_decline_fee() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN)); // at block 1
        let request = last_request();
        System::reset_events();

        System::set_block_number(14_400);
        Anonymum::on_initialize(14_400);
        assert!(new_events().is_empty(), "still pending one block before");

        System::set_block_number(14_401);
        Anonymum::on_initialize(14_401);
        assert_eq!(
            new_events(),
            vec![Event::RequestRefunded {
                request,
                to: account("carol"),
                amount: COIN - DECLINE_FEE,
                burned: DECLINE_FEE,
                reason: RefundReason::Expired,
            }]
        );
        assert_eq!(free("carol"), 10 * COIN - COLD_FEE - DECLINE_FEE);
        assert!(!ExpiryQueue::<Test>::contains_key(14_401));
    });
}

#[test]
fn an_answered_request_is_skipped_at_expiry() {
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        assert_ok!(Anonymum::accept_contact(signed("bob"), last_request()));
        System::reset_events();
        Anonymum::on_initialize(14_401);
        assert!(new_events().is_empty());
        assert_eq!(free("bob"), 11 * COIN);
    });
}

#[test]
fn a_full_expiry_queue_refuses_more_requests_and_charges_nothing() {
    new_test_ext().execute_with(|| {
        // MaxRequestsPerBlock is 4 in the mock. Fill the queue for one block.
        let senders: Vec<AccountId32> = (0..5).map(|i| account(&format!("sender{i}"))).collect();
        for s in &senders {
            assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), s.clone(), 10 * COIN));
        }
        for s in &senders[..4] {
            assert_ok!(Anonymum::request_contact(RuntimeOrigin::signed(s.clone()), account("bob"), COIN, note()));
        }
        assert_noop!(
            Anonymum::request_contact(RuntimeOrigin::signed(senders[4].clone()), account("bob"), COIN, note()),
            Error::<Test>::ExpiryQueueFull
        );
        // Next block, a new slot opens.
        System::set_block_number(2);
        assert_ok!(Anonymum::request_contact(RuntimeOrigin::signed(senders[4].clone()), account("bob"), COIN, note()));
    });
}

// ---- conservation -----------------------------------------------------------

#[test]
fn coins_are_conserved_across_a_mixed_history() {
    new_test_ext().execute_with(|| {
        let start = issuance();
        assert_ok!(open("alice", "bob", &invite("bob", 1)));
        assert_ok!(req("carol", "bob", COIN));
        assert_ok!(req("carol", "alice", COIN));
        assert_ok!(Anonymum::block(signed("alice"), account("carol")));
        System::set_block_number(14_401);
        Anonymum::on_initialize(14_401);
        assert_ok!(req("alice", "carol", COIN));
        assert_ok!(Anonymum::cancel_request(signed("carol"), last_request()));
        assert_conserved(start);
        // Burned: half of three cold fees and one invite fee, two decline fees.
        let burned = 3 * (COLD_FEE / 2) + INVITE_FEE / 2 + 2 * DECLINE_FEE;
        assert_eq!(start - issuance(), burned);
    });
}

// ---- F3: refundable storage deposits ----------------------------------------

#[test]
fn an_invite_holds_a_deposit_returned_when_used() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_eq!(free("bob"), 10 * COIN - DEPOSIT);
        assert_eq!(deposits("bob"), 2 * DEPOSIT, "key + invite");
        assert_ok!(open("alice", "bob", &secret));
        assert_eq!(free("bob"), 10 * COIN, "invite deposit back");
        assert_eq!(deposits("bob"), DEPOSIT);
    });
}

#[test]
fn revoking_an_invite_returns_its_deposit() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        assert_ok!(Anonymum::revoke_invite(signed("bob"), secret.public().0));
        assert_eq!(free("bob"), 10 * COIN);
    });
}

#[test]
fn anyone_may_remove_an_expired_invite_and_the_owner_gets_the_deposit() {
    new_test_ext().execute_with(|| {
        let secret = ed25519::Pair::from_seed(&[9; 32]);
        let key = secret.public().0;
        assert_ok!(Anonymum::register_invite(signed("bob"), key, Some(5)));
        assert_noop!(
            Anonymum::remove_expired_invite(signed("carol"), account("bob"), key),
            Error::<Test>::InviteNotExpired
        );
        System::set_block_number(6);
        System::reset_events();
        assert_ok!(Anonymum::remove_expired_invite(signed("carol"), account("bob"), key));
        assert_eq!(
            new_events(),
            vec![Event::ExpiredInviteRemoved { owner: account("bob"), key, by: account("carol") }]
        );
        assert_eq!(free("bob"), 10 * COIN, "deposit to the owner");
        assert_eq!(free("carol"), 10 * COIN, "not to the caller");
        assert_noop!(
            Anonymum::remove_expired_invite(signed("carol"), account("bob"), key),
            Error::<Test>::UnknownInvite
        );
    });
}

#[test]
fn an_invite_without_expiry_cannot_be_removed_by_others() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 1);
        System::set_block_number(1_000_000);
        assert_noop!(
            Anonymum::remove_expired_invite(signed("carol"), account("bob"), secret.public().0),
            Error::<Test>::InviteNotExpired
        );
    });
}

#[test]
fn storing_anything_without_the_deposit_fails_and_charges_nothing() {
    new_test_ext().execute_with(|| {
        // Erin's whole balance is one deposit, but an account must also keep
        // the existential deposit, so she cannot hold one.
        let erin = account("erin");
        assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), erin.clone(), DEPOSIT));
        let origin = || RuntimeOrigin::signed(erin.clone());
        assert_noop!(Anonymum::register_invite(origin(), [3; 32], None), Error::<Test>::InsufficientFunds);
        assert_noop!(Anonymum::block(origin(), account("bob")), Error::<Test>::InsufficientFunds);
        let key = [7u8; 32];
        let binding = binding_by("erin", "erin", &key);
        assert_noop!(Anonymum::publish_messaging_key(origin(), key, binding), Error::<Test>::InsufficientFunds);
    });
}

#[test]
fn a_block_holds_a_deposit_returned_on_unblock() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_eq!(free("bob"), 10 * COIN - DEPOSIT);
        assert_ok!(Anonymum::unblock(signed("bob"), account("carol")));
        assert_eq!(free("bob"), 10 * COIN);
    });
}

#[test]
fn closing_takes_the_block_deposit_from_the_closer() {
    new_test_ext().execute_with(|| {
        assert_ok!(open("alice", "bob", &invite("bob", 1)));
        assert_ok!(Anonymum::close_channel(signed("bob"), channel("alice", "bob").unwrap()));
        assert_eq!(free("bob"), 10 * COIN - DEPOSIT);
        assert_eq!(deposits("bob"), 2 * DEPOSIT, "key + block");
    });
}

#[test]
fn a_closer_who_cannot_pay_the_block_deposit_cannot_close() {
    new_test_ext().execute_with(|| {
        assert_ok!(open("alice", "bob", &invite("bob", 1)));
        let id = channel("alice", "bob").unwrap();
        // Leave Bob with only the existential deposit free.
        assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), account("bob"), 1));
        assert_noop!(Anonymum::close_channel(signed("bob"), id), Error::<Test>::InsufficientFunds);
        assert!(channel("alice", "bob").is_some(), "channel stays open");
    });
}

#[test]
fn opening_a_channel_returns_cleared_block_deposits_to_the_blockers() {
    new_test_ext().execute_with(|| {
        assert_ok!(Anonymum::block(signed("bob"), account("carol")));
        assert_ok!(Anonymum::block(signed("carol"), account("bob")));
        let fresh = invite("bob", 7);
        assert_ok!(open("carol", "bob", &fresh));
        assert_eq!(free("bob"), 10 * COIN, "block + invite deposits back");
        assert_eq!(free("carol"), 10 * COIN - INVITE_FEE, "block deposit back");
    });
}

#[test]
fn replacing_a_messaging_key_keeps_a_single_deposit() {
    new_test_ext().execute_with(|| {
        let key = [9u8; 32];
        let binding = binding_by("alice", "alice", &key);
        assert_ok!(Anonymum::publish_messaging_key(signed("alice"), key, binding));
        assert_eq!(deposits("alice"), DEPOSIT);
        assert_eq!(free("alice"), 10 * COIN);
    });
}

// ---- F5: a refund that cannot complete is visible ---------------------------

#[test]
fn a_refund_whose_hold_is_gone_still_completes_and_reports_it() {
    use frame::traits::fungible::MutateHold;
    use frame::traits::tokens::Precision;
    new_test_ext().execute_with(|| {
        assert_ok!(req("carol", "bob", COIN));
        let request = last_request();
        // Simulate a broken invariant: the escrow hold vanishes.
        assert_ok!(<Balances as MutateHold<_>>::release(
            &HoldReason::ContactEscrow.into(),
            &account("carol"),
            COIN,
            Precision::Exact,
        ));
        System::reset_events();
        assert_ok!(Anonymum::cancel_request(signed("bob"), request));
        let events = new_events();
        assert!(events.iter().any(|e| matches!(e, Event::HoldNotReleased { .. })), "{events:?}");
        assert!(events.iter().any(|e| matches!(e, Event::RequestRefunded { .. })));
        assert!(Requests::<Test>::get(request).is_none(), "the request is still cleaned up");
    });
}


// ---- 2026-11-20 audit: expiry slots, signed messages, arithmetic -------------

fn funded(name: &str) -> AccountId32 {
    let who = account(name);
    assert_ok!(Balances::force_set_balance(RuntimeOrigin::root(), who.clone(), 10 * COIN));
    who
}

fn queued(at: u64) -> usize {
    ExpiryQueue::<Test>::get(at).len()
}

#[test]
fn early_resolutions_free_their_expiry_slots() {
    new_test_ext().execute_with(|| {
        // MaxRequestsPerBlock is 4. Fill block 1's slot (expiring at 28,801).
        let expiry = 1 + 14_400;
        let s: Vec<AccountId32> = (0..10).map(|i| funded(&format!("early{i}"))).collect();
        for who in &s[..4] {
            assert_ok!(Anonymum::request_contact(RuntimeOrigin::signed(who.clone()), account("bob"), COIN, note()));
        }
        assert_eq!(queued(expiry), 4);
        assert_noop!(
            Anonymum::request_contact(RuntimeOrigin::signed(s[4].clone()), account("bob"), COIN, note()),
            Error::<Test>::ExpiryQueueFull
        );
        let id = |who: &AccountId32| {
            let key = if *who <= account("bob") { (who.clone(), account("bob")) } else { (account("bob"), who.clone()) };
            crate::pallet::RequestByPair::<Test>::get(key).unwrap()
        };
        // Accepted, declined, cancelled by the sender, ended by a block.
        assert_ok!(Anonymum::accept_contact(signed("bob"), id(&s[0])));
        assert_eq!(queued(expiry), 3);
        assert_ok!(Anonymum::cancel_request(signed("bob"), id(&s[1])));
        assert_eq!(queued(expiry), 2);
        assert_ok!(Anonymum::cancel_request(RuntimeOrigin::signed(s[2].clone()), id(&s[2])));
        assert_eq!(queued(expiry), 1);
        assert_ok!(Anonymum::block(signed("bob"), s[3].clone()));
        assert_eq!(queued(expiry), 0);
        assert!(!ExpiryQueue::<Test>::contains_key(expiry), "an empty slot is removed");
        // Superseded by an invite.
        assert_ok!(Anonymum::request_contact(RuntimeOrigin::signed(s[4].clone()), account("bob"), COIN, note()));
        assert_eq!(queued(expiry), 1);
        let secret = invite("bob", 77);
        let message = invite_message(&genesis(), &s[4].encode(), &account("bob").encode());
        assert_ok!(Anonymum::open_with_invite(
            RuntimeOrigin::signed(s[4].clone()),
            account("bob"),
            secret.public().0,
            secret.sign(&message).0
        ));
        assert_eq!(queued(expiry), 0);
        // The same block's slot takes four new requests again, then is full.
        for who in &s[5..9] {
            assert_ok!(Anonymum::request_contact(RuntimeOrigin::signed(who.clone()), account("bob"), COIN, note()));
        }
        assert_noop!(
            Anonymum::request_contact(RuntimeOrigin::signed(s[9].clone()), account("bob"), COIN, note()),
            Error::<Test>::ExpiryQueueFull
        );
        // Expiry still refunds what is left, and only that.
        System::reset_events();
        Anonymum::on_initialize(expiry);
        let refunds = new_events().iter().filter(|e| matches!(e, Event::RequestRefunded { .. })).count();
        assert_eq!(refunds, 4);
    });
}

#[test]
fn a_key_binding_names_the_account_and_the_chain() {
    new_test_ext().execute_with(|| {
        let key = [0x42; 32];
        // Alice's own signature, but over a message naming Bob's account.
        let for_bob = binding_by("alice", "bob", &key);
        assert_noop!(Anonymum::publish_messaging_key(signed("alice"), key, for_bob), Error::<Test>::BadKeyBinding);
        // A binding made for another chain's genesis hash.
        let other = crate::key_binding_message(&[7u8; 32], &account("alice").encode(), &key);
        let foreign = MultiSignature::Ed25519(keypair("alice").sign(&other));
        assert_noop!(Anonymum::publish_messaging_key(signed("alice"), key, foreign), Error::<Test>::BadKeyBinding);
        assert_ok!(Anonymum::publish_messaging_key(signed("alice"), key, binding_by("alice", "alice", &key)));
    });
}

#[test]
fn an_invite_proof_for_another_chain_is_refused() {
    new_test_ext().execute_with(|| {
        let secret = invite("bob", 3);
        let other = invite_message(&[7u8; 32], &account("alice").encode(), &account("bob").encode());
        assert_noop!(
            Anonymum::open_with_invite(signed("alice"), account("bob"), secret.public().0, secret.sign(&other).0),
            Error::<Test>::BadInviteProof
        );
        assert_ok!(open("alice", "bob", &secret));
    });
}

#[test]
fn a_weak_invite_key_is_refused_and_charges_nothing() {
    // The host ed25519 check (ZIP 215) would accept (R = identity, S = 0)
    // for a small-order key, so such keys are refused at registration.
    new_test_ext().execute_with(|| {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        // An Ed25519 point of order 8.
        let order_8: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a,
            0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
        ];
        for weak in [identity, order_8] {
            assert!(!Anonymum::is_usable_invite_key(&weak));
            assert_noop!(Anonymum::register_invite(signed("bob"), weak, None), Error::<Test>::WeakInviteKey);
        }
        // So the trivial proof never gets a key to verify against.
        let mut proof = [0u8; 64];
        proof[0] = 1;
        assert_noop!(
            Anonymum::open_with_invite(signed("alice"), account("bob"), identity, proof),
            Error::<Test>::UnknownInvite
        );
        // An ordinary key is still accepted.
        assert_ok!(Anonymum::register_invite(signed("bob"), ed25519::Pair::from_seed(&[4; 32]).public().0, None));
    });
}

#[test]
fn the_fee_split_cannot_overflow() {
    new_test_ext().execute_with(|| {
        // FeeBurnPercent is 50 in the mock.
        assert_eq!(Anonymum::burn_share(u128::MAX), u128::MAX / 2);
        assert_eq!(Anonymum::burn_share(0), 0);
        assert_eq!(Anonymum::burn_share(1), 0);
        assert_eq!(Anonymum::burn_share(3), 1);
    });
}

#[test]
fn an_expiry_height_that_would_overflow_is_refused_charging_nothing() {
    new_test_ext().execute_with(|| {
        // The mock's lifetime is 14,400 blocks: the last height that fits is
        // u64::MAX - 14,400.
        System::set_block_number(u64::MAX - 14_399);
        assert_noop!(req("carol", "bob", COIN), DispatchError::Arithmetic(ArithmeticError::Overflow));
        System::set_block_number(u64::MAX - 14_400);
        assert_ok!(req("carol", "bob", COIN));
    });
}

#[test]
fn id_and_sequence_counters_refuse_to_wrap_charging_nothing() {
    new_test_ext().execute_with(|| {
        crate::pallet::NextId::<Test>::put(u64::MAX);
        assert_noop!(req("carol", "bob", COIN), DispatchError::Arithmetic(ArithmeticError::Overflow));
        crate::pallet::NextId::<Test>::put(u64::MAX - 1);
        assert_ok!(req("carol", "bob", COIN));
        let key = ed25519::Pair::from_seed(&[5; 32]).public().0;
        crate::pallet::NextSeq::<Test>::put(u64::MAX);
        assert_noop!(
            Anonymum::register_invite(signed("bob"), key, None),
            DispatchError::Arithmetic(ArithmeticError::Overflow)
        );
        crate::pallet::NextSeq::<Test>::put(u64::MAX - 1);
        assert_ok!(Anonymum::register_invite(signed("bob"), key, None));
    });
}
