//! Spec v0.7 section 2a: contact identities, authorise-before-reply,
//! invitations, the stranger's note and reverse rendezvous.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anonymum_crypto::note::ROUTE_LEN;
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{
    open_note, seal_note, ContactCard, ContactError, ContactIdentity, Grant, Identity, Invitation, Network, Now,
    Purpose, StaticKey,
};

const NET: Network = [9; 32];
const NOW: u64 = 1_000;
const POLICY: RetryPolicy = RetryPolicy { attempts: 2, resends: 1, base_wait: Duration::from_secs(10) };

fn now() -> Now {
    Now { unix: NOW, mono: Instant::now() }
}

fn bob_with_card() -> (ContactIdentity, ContactCard, Responder<u32>) {
    let bob = ContactIdentity::generate();
    let card = bob.card(NET, 1_000_000, 0, NOW + 86_400);
    let side = Responder::for_identity(&bob, NET);
    (bob, card, side)
}

fn reply(event: ResponderEvent) -> Vec<u8> {
    match event {
        ResponderEvent::Reply(frame) => frame,
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// Run a call against `side` frame by frame until it is established.
/// Returns the call, the recorded HELLO and CONFIRM, and the grant.
fn connect(
    key: &StaticKey,
    peer: [u8; 32],
    reference: [u8; 32],
    side: &mut Responder<u32>,
    tag: u32,
) -> (Initiator, Vec<u8>, Vec<u8>, Grant) {
    let (mut call, hello) = Initiator::start_with(key, peer, NET, reference, POLICY).unwrap();
    let welcome = reply(side.handle(tag, &hello, now()).unwrap());
    let InitiatorEvent::Send(confirm) = call.handle(&welcome).unwrap() else { panic!() };
    let ResponderEvent::Established { peer: who, grant, reply: ack } = side.handle(tag, &confirm, now()).unwrap() else {
        panic!("not established")
    };
    assert_eq!(who, key.public());
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    (call, hello, confirm, grant)
}

// ---- cards and invitations -------------------------------------------------------

#[test]
fn a_card_holds_three_contact_keys_and_no_wallet_key() {
    let wallet = Identity::generate();
    let bob = ContactIdentity::generate();
    let card = bob.card(NET, 5, 10, 20);
    assert_eq!(card.verify(&NET, 10), Ok(()));
    assert_eq!(ContactCard::from_bytes(&card.to_bytes()).unwrap(), card);
    let keys = [card.signing_key, card.handshake_key, card.inbox_key];
    assert!(keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2], "three separate keys");
    assert!(!card.to_bytes().windows(32).any(|w| w == wallet.address().0));
    assert_eq!(card.verify(&NET, 9), Err(ContactError::NotYetValid));
    assert_eq!(card.verify(&NET, 20), Err(ContactError::Expired));
    let mut forged = card.clone();
    forged.price = 1;
    assert_eq!(forged.verify(&NET, 15), Err(ContactError::BadSignature));
    let mut swapped = card.clone();
    swapped.inbox_key = ContactIdentity::generate().inbox_key().public();
    assert_eq!(swapped.verify(&NET, 15), Err(ContactError::BadSignature));
    assert_eq!(ContactCard::from_bytes(&card.to_bytes()[1..]), Err(ContactError::Malformed));
}

#[test]
fn a_card_carries_one_post_quantum_inbox_key_covered_by_its_signature() {
    let bob = ContactIdentity::generate();
    let card = bob.card(NET, 5, 10, 20);
    assert_eq!((ContactCard::LEN, card.to_bytes().len()), (1_408, 1_408));
    assert_eq!(card.pq_inbox_key, bob.pq_inbox_key());
    assert_eq!(card.summary().pq_inbox_hash, anonymum_crypto::contact::pq_key_hash(&bob.pq_inbox_key()));
    // Another valid ML-KEM key swapped in: the signature (over its hash) fails.
    let mut swapped = card.clone();
    swapped.pq_inbox_key = ContactIdentity::generate().pq_inbox_key();
    assert_eq!(swapped.verify(&NET, 15), Err(ContactError::BadSignature));
    let mut flipped = card.clone();
    flipped.pq_inbox_key[1_000] ^= 1;
    assert_eq!(flipped.verify(&NET, 15), Err(ContactError::BadSignature));
    // A summary (what a note carries) verifies exactly when the card does.
    assert_eq!(card.summary().verify(&NET, 15), Ok(()));
    assert_eq!(swapped.summary().verify(&NET, 15), Err(ContactError::BadSignature));
    // Restoring an identity restores its post-quantum key.
    let (s, h, i, pq) = bob.to_secret_bytes();
    assert_eq!(ContactIdentity::from_secret_bytes(s, h, i, pq).card(NET, 5, 10, 20), card);
}

#[test]
fn a_card_for_another_network_is_refused() {
    let bob = ContactIdentity::generate();
    let card = bob.card(NET, 5, 10, 20);
    assert_eq!(card.network, NET);
    // Shown on another network, the genuine card is refused.
    assert_eq!(card.verify(&[1; 32], 15), Err(ContactError::WrongNetwork));
    // Relabelling it breaks the signature, which covers the network.
    let mut relabelled = card.clone();
    relabelled.network = [1; 32];
    assert_eq!(relabelled.verify(&[1; 32], 15), Err(ContactError::BadSignature));
    // A card Bob signs for the other network is valid there and only there.
    let other = bob.card([1; 32], 5, 10, 20);
    assert_eq!(other.verify(&[1; 32], 15), Ok(()));
    assert_eq!(other.verify(&NET, 15), Err(ContactError::WrongNetwork));
    assert_eq!(ContactCard::from_bytes(&other.to_bytes()).unwrap(), other);
}

#[test]
fn an_invitation_names_issuer_holder_network_purpose_and_expiry() {
    let bob = ContactIdentity::generate();
    let holder = StaticKey::generate().public();
    let invitation = bob.invite(NET, holder, Purpose::Contact, NOW + 60);
    assert_eq!(invitation.verify(&bob.signing_key(), &NET, NOW), Ok(()));
    assert_eq!(Invitation::from_bytes(&invitation.to_bytes()).unwrap(), invitation);
    assert_eq!(invitation.verify(&bob.signing_key(), &[0; 32], NOW), Err(ContactError::WrongNetwork));
    assert_eq!(invitation.verify(&[1; 32], &NET, NOW), Err(ContactError::WrongIssuer));
    assert_eq!(invitation.verify(&bob.signing_key(), &NET, NOW + 60), Err(ContactError::Expired));
    let mut moved = invitation.clone();
    moved.holder = StaticKey::generate().public();
    assert_eq!(moved.verify(&bob.signing_key(), &NET, NOW), Err(ContactError::BadSignature));
    let mut bytes = invitation.to_bytes();
    bytes[96] = 7;
    assert_eq!(Invitation::from_bytes(&bytes), Err(ContactError::UnknownPurpose));
}

// ---- Dave: a real card and route, no authorisation --------------------------------

#[test]
fn dave_with_bobs_real_card_and_route_gets_no_reply_of_any_kind() {
    let (bob, card, mut bob_side) = bob_with_card();
    // Alice is invited, so Bob is answering someone.
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();

    assert_eq!(card.verify(&NET, NOW), Ok(()));
    let dave = StaticKey::generate();
    // Dave tries a made-up reference, and even Alice's invitation id (say he
    // saw her invitation): his key is not the holder.
    for reference in [[0u8; 32], [0x42; 32], invitation.id] {
        let (mut call, hello) = Initiator::start_with(&dave, card.handshake_key, NET, reference, POLICY).unwrap();
        let mut sent = vec![hello];
        while let Ok(Some(frame)) = call.on_timeout() {
            sent.push(frame); // resends and fresh attempts
        }
        assert_eq!(sent.len(), 4, "every resend and fresh attempt was tried");
        for frame in &sent {
            let result = bob_side.handle(66, frame, now());
            assert!(matches!(result, Err(WireError::Unauthorised)), "Dave got {result:?}");
        }
        // Forged later frames, with the header of his call: nothing either.
        for kind in [3u8, 4, 5] {
            let mut forged = sent[0][..9].to_vec();
            forged[0] = kind;
            forged.extend_from_slice(&[0u8; 40]);
            assert!(bob_side.handle(66, &forged, now()).is_err());
        }
    }
    assert_eq!(bob_side.pending(), 0, "nothing stored for Dave");
    assert!(!bob_side.gate().is_contact(&dave.public()));
    // Alice still connects.
    let (_, _, _, grant) = connect(&alice, card.handshake_key, invitation.id, &mut bob_side, 1);
    assert_eq!(grant, Grant::Invitation { id: invitation.id });
}

// ---- invited Alice ------------------------------------------------------------------

#[test]
fn invited_alice_connects_and_is_a_contact_afterwards() {
    let (bob, card, mut bob_side) = bob_with_card();
    // Alice makes a caller key for this one relationship and hands its public
    // half to Bob; Bob returns his card and an invitation to that key.
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();
    assert_eq!(card.verify(&NET, NOW), Ok(()));
    assert_eq!(invitation.verify(&card.signing_key, &NET, NOW), Ok(()));
    assert_eq!(invitation.holder, alice.public());
    // The holder must name the invitation it holds.
    let (_, wrong) = Initiator::start_with(&alice, card.handshake_key, NET, [5; 32], POLICY).unwrap();
    assert!(matches!(bob_side.handle(9, &wrong, now()), Err(WireError::Unauthorised)));

    let (mut call, _, _, grant) = connect(&alice, card.handshake_key, invitation.id, &mut bob_side, 1);
    assert_eq!(grant, Grant::Invitation { id: invitation.id });
    assert!(bob_side.gate().is_honoured(&invitation.id));
    let frame = call.seal(b"hi Bob").unwrap();
    assert!(matches!(bob_side.handle(1, &frame, now()), Ok(ResponderEvent::Message { .. })));

    // Later calls about the same relationship are let in as a contact...
    let (_, _, _, grant) = connect(&alice, card.handshake_key, invitation.id, &mut bob_side, 2);
    assert_eq!(grant, Grant::Contact);
    // ...but not about anything else: the key is scoped to this relationship.
    let (_, hello) = Initiator::start_with(&alice, card.handshake_key, NET, [5; 32], POLICY).unwrap();
    assert!(matches!(bob_side.handle(3, &hello, now()), Err(WireError::Unauthorised)));
}

#[test]
fn an_expired_or_foreign_invitation_gets_no_reply() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let late = bob.invite(NET, alice.public(), Purpose::Contact, NOW);
    assert_eq!(bob_side.record_invitation(late.clone(), now()), Err(ContactError::Expired));
    let (_, hello) = Initiator::start_with(&alice, card.handshake_key, NET, late.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(1, &hello, now()), Err(WireError::Unauthorised)), "expired");

    let carol = StaticKey::generate();
    let foreign = bob.invite([1; 32], carol.public(), Purpose::Contact, NOW + 60);
    assert_eq!(bob_side.record_invitation(foreign.clone(), now()), Err(ContactError::WrongNetwork));
    let (_, hello) = Initiator::start_with(&carol, card.handshake_key, NET, foreign.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(2, &hello, now()), Err(WireError::Unauthorised)), "other network");
}

// ---- replay ---------------------------------------------------------------------------

#[test]
fn a_replayed_first_message_cannot_use_an_invitation_twice() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();

    // An attacker records Alice's HELLO and replays it *before* she
    // confirms: Bob answers (the replay is valid IK), but only Alice can
    // confirm, and the invitation is not used by answering.
    let (mut call, hello) = Initiator::start_with(&alice, card.handshake_key, NET, invitation.id, POLICY).unwrap();
    let _to_attacker = reply(bob_side.handle(99, &hello, now()).unwrap());
    assert!(!bob_side.gate().is_honoured(&invitation.id));
    let welcome = reply(bob_side.handle(1, &hello, now()).unwrap());
    let InitiatorEvent::Send(confirm) = call.handle(&welcome).unwrap() else { panic!() };
    // The recorded CONFIRM replayed on the attacker's handle does not open.
    assert!(matches!(bob_side.handle(99, &confirm, now()), Err(WireError::Stale)));
    assert!(matches!(bob_side.handle(1, &confirm, now()), Ok(ResponderEvent::Established { .. })));
    assert!(bob_side.gate().is_honoured(&invitation.id));

    // Bob ends the relationship (no block). The recorded HELLO, replayed on
    // any handle, gets nothing: the invitation was used once.
    bob_side.remove_contact(alice.public());
    for tag in [1, 2, 99] {
        // Including the attacker's handle that was answered before.
        assert!(matches!(bob_side.handle(tag, &hello, now()), Err(WireError::Unauthorised)), "tag {tag}");
        assert!(bob_side.handle(tag, &confirm, now()).is_err());
    }
    // A fresh call with the same invitation: nothing either, even if Bob's
    // app reloads the invitation into its list of issued ones.
    let (_, fresh) = Initiator::start_with(&alice, card.handshake_key, NET, invitation.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(3, &fresh, now()), Err(WireError::Unauthorised)));
    bob_side.record_invitation(invitation.clone(), now()).unwrap();
    assert!(matches!(bob_side.handle(4, &fresh, now()), Err(WireError::Unauthorised)));
}

#[test]
fn a_replayed_first_message_cannot_reopen_a_blocked_contact() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();
    let (_, hello, confirm, _) = connect(&alice, card.handshake_key, invitation.id, &mut bob_side, 1);

    bob_side.block(alice.public());
    for tag in [1, 2, 99] {
        assert!(matches!(bob_side.handle(tag, &hello, now()), Err(WireError::Unauthorised)), "tag {tag}");
        assert!(bob_side.handle(tag, &confirm, now()).is_err());
    }
    let (_, fresh) = Initiator::start_with(&alice, card.handshake_key, NET, invitation.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(3, &fresh, now()), Err(WireError::Unauthorised)));
    assert_eq!(bob_side.pending(), 0);

    // A block that lands between the answer and the confirmation wins too.
    let carol = StaticKey::generate();
    let inv = bob.invite(NET, carol.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(inv.clone(), now()).unwrap();
    let (mut call, hello) = Initiator::start_with(&carol, card.handshake_key, NET, inv.id, POLICY).unwrap();
    let welcome = reply(bob_side.handle(4, &hello, now()).unwrap());
    let InitiatorEvent::Send(confirm) = call.handle(&welcome).unwrap() else { panic!() };
    bob_side.block(carol.public());
    assert!(bob_side.handle(4, &confirm, now()).is_err(), "no ACK");
    assert!(!bob_side.gate().is_honoured(&inv.id));

    // And a repeat of an answered HELLO is not answered again once blocked:
    // the cached reply is checked against the gate too.
    let dan = StaticKey::generate();
    let inv = bob.invite(NET, dan.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(inv.clone(), now()).unwrap();
    let (_, hello) = Initiator::start_with(&dan, card.handshake_key, NET, inv.id, POLICY).unwrap();
    reply(bob_side.handle(5, &hello, now()).unwrap());
    bob_side.block(dan.public());
    assert!(matches!(bob_side.handle(5, &hello, now()), Err(WireError::Unauthorised)));
}

// ---- Carol: the stranger, by note and reverse rendezvous ------------------------------

#[test]
fn offline_carol_accepts_only_bobs_callback() {
    let (bob, card, _) = bob_with_card();
    let carol = ContactIdentity::generate();
    let carol_card = carol.card(NET, 1_000, 0, NOW + 86_400);
    let route = [0x77; ROUTE_LEN];
    let admission = [0xAD; 32];
    let note = seal_note(&NET, &card, &carol, &carol_card, &route, "Carol here", &admission).unwrap();
    // The key Bob will call back: Carol's handshake key, the one the note's
    // Noise X message authenticates (no separate callback key any more).
    let callback = carol.handshake_key();

    // Carol's throwaway side answers only Bob's handshake key, about this
    // request. It is offline: frames queue at her gateway.
    let deadline = Instant::now() + Duration::from_secs(3_600);
    let mut carol_side: Responder<u32> =
        Responder::for_callback(callback, NET, card.handshake_key, admission, deadline).unwrap();
    let mut gateway: VecDeque<(u32, Vec<u8>)> = VecDeque::new();

    // Eve learned the route (Carol's handshake key is on her public card):
    // her own key gets nothing, whatever reference she names.
    let eve = StaticKey::generate();
    for reference in [admission, [0; 32]] {
        let (_, hello) = Initiator::start_with(&eve, callback.public(), NET, reference, POLICY).unwrap();
        gateway.push_back((50, hello));
    }
    // Bob's other identity, or Bob about another request: nothing either.
    let (_, hello) =
        Initiator::start_with(ContactIdentity::generate().handshake_key(), callback.public(), NET, admission, POLICY)
            .unwrap();
    gateway.push_back((51, hello));
    let (_, hello) = Initiator::start_with(bob.handshake_key(), callback.public(), NET, [1; 32], POLICY).unwrap();
    gateway.push_back((52, hello));

    // Bob opens the note with his inbox key alone; once his claim is final
    // he calls the callback key, naming the request inside the encrypted
    // first message.
    let opened = open_note(&bob, &NET, &note, NOW).unwrap();
    assert_eq!((opened.sender(), opened.callback(), opened.route), (carol.signing_key(), callback.public(), route));
    let (mut call, hello) =
        Initiator::start_with(bob.handshake_key(), opened.callback(), NET, opened.admission, POLICY).unwrap();
    assert!(!hello.windows(32).any(|w| w == admission), "the request reference is not in clear");
    gateway.push_back((7, hello));

    // Carol comes back online and works through the queue.
    let mut replies = Vec::new();
    while let Some((tag, frame)) = gateway.pop_front() {
        match carol_side.handle(tag, &frame, now()) {
            Ok(ResponderEvent::Reply(welcome)) => replies.push((tag, welcome)),
            Err(WireError::Unauthorised) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(replies.len(), 1, "exactly one reply, and it is to Bob");
    let (tag, welcome) = replies.pop().unwrap();
    assert_eq!(tag, 7);
    let InitiatorEvent::Send(confirm) = call.handle(&welcome).unwrap() else { panic!() };
    let ResponderEvent::Established { peer, grant, reply: ack } = carol_side.handle(7, &confirm, now()).unwrap() else {
        panic!()
    };
    assert_eq!((peer, grant), (card.handshake_key, Grant::Callback));
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    let frame = carol_side.seal(&7, b"my long-lived route", now()).unwrap();
    assert_eq!(call.handle(&frame).unwrap(), InitiatorEvent::Message(b"my long-lived route".to_vec()));
}

#[test]
fn record_invitation_checks_what_it_is_given() {
    let (bob, _, mut bob_side) = bob_with_card();
    let holder = StaticKey::generate().public();
    // Issued by someone else.
    let other = ContactIdentity::generate().invite(NET, holder, Purpose::Contact, NOW + 60);
    assert_eq!(bob_side.record_invitation(other, now()), Err(ContactError::WrongIssuer));
    // Tampered after signing.
    let mut tampered = bob.invite(NET, holder, Purpose::Contact, NOW + 60);
    tampered.expires_at += 1;
    assert_eq!(bob_side.record_invitation(tampered, now()), Err(ContactError::BadSignature));
    // A small-order holder key, signed by Bob himself.
    let weak = bob.invite(NET, [0; 32], Purpose::Contact, NOW + 60);
    assert_eq!(bob_side.record_invitation(weak, now()), Err(ContactError::WeakKey));
    // A callback listener issues no invitations at all.
    let mut listener: Responder<u32> = Responder::for_callback(
        &StaticKey::generate(),
        NET,
        bob.handshake_key().public(),
        [1; 32],
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    let good = bob.invite(NET, holder, Purpose::Contact, NOW + 60);
    assert_eq!(listener.record_invitation(good.clone(), now()), Err(ContactError::WrongIssuer));
    assert_eq!(bob_side.record_invitation(good, now()), Ok(()));
}

#[test]
fn responder_and_gate_share_one_network() {
    let (_, _, bob_side) = bob_with_card();
    assert_eq!(bob_side.network(), NET);
    assert_eq!(bob_side.gate().network(), NET);
    // There is no public way to give a responder a gate of its own (see the
    // compile_fail examples in `gate.rs`), so the two cannot differ.
}

#[test]
fn a_callback_grant_expires_at_its_deadline_and_nothing_is_sent() {
    let bob = ContactIdentity::generate();
    let callback = StaticKey::generate();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(600);
    let mut carol_side: Responder<u32> =
        Responder::for_callback(&callback, NET, bob.handshake_key().public(), [1; 32], deadline).unwrap();
    let (_, hello) = Initiator::start_with(bob.handshake_key(), callback.public(), NET, [1; 32], POLICY).unwrap();
    let late = Now { unix: NOW, mono: deadline };
    assert!(matches!(carol_side.handle(7, &hello, late), Err(WireError::Unauthorised)));
    assert_eq!(carol_side.pending(), 0);
    let early = Now { unix: NOW, mono: deadline - Duration::from_secs(1) };
    assert!(matches!(carol_side.handle(7, &hello, early), Ok(ResponderEvent::Reply(_))));
    // A small-order caller key cannot be expected at all.
    assert!(Responder::<u32>::for_callback(&callback, NET, [0; 32], [1; 32], deadline).is_err());
}

#[test]
fn calling_or_sealing_to_a_small_order_key_is_refused() {
    let alice = StaticKey::generate();
    for weak in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        assert!(matches!(
            Initiator::start_with(&alice, weak, NET, [1; 32], POLICY),
            Err(WireError::Session(anonymum_crypto::SessionError::WeakKey))
        ));
        assert!(!anonymum_crypto::is_contributory_key(&weak));
    }
}

// ---- revocation cancels outstanding grants (owner decision 2026-11-20) -----

#[test]
fn removing_a_contact_cancels_its_unused_invitation_and_a_fresh_one_works() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let first = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(first.clone(), now()).unwrap();
    connect(&alice, card.handshake_key, first.id, &mut bob_side, 1);
    // A second, still unused invitation to the same key.
    let spare = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(spare.clone(), now()).unwrap();

    bob_side.remove_contact(alice.public());
    let (_, hello) = Initiator::start_with(&alice, card.handshake_key, NET, spare.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(2, &hello, now()), Err(WireError::Unauthorised)), "no reply");
    assert_eq!(bob_side.pending(), 0);
    // Re-recording the cancelled invitation does not bring it back.
    assert_eq!(bob_side.record_invitation(spare, now()), Err(ContactError::Revoked));
    assert!(matches!(bob_side.handle(3, &hello, now()), Err(WireError::Unauthorised)));

    // A fresh invitation issued afterwards reopens the channel.
    let fresh = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(fresh.clone(), now()).unwrap();
    let (_, _, _, grant) = connect(&alice, card.handshake_key, fresh.id, &mut bob_side, 4);
    assert_eq!(grant, Grant::Invitation { id: fresh.id });
}

#[test]
fn removing_a_key_that_never_connected_cancels_its_invitation() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();
    bob_side.remove_contact(alice.public());
    let (_, hello) = Initiator::start_with(&alice, card.handshake_key, NET, invitation.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(1, &hello, now()), Err(WireError::Unauthorised)), "no reply");
    assert!(!bob_side.gate().is_honoured(&invitation.id));
}

#[test]
fn blocking_cancels_grants_and_unblocking_restores_none() {
    let (bob, card, mut bob_side) = bob_with_card();
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(invitation.clone(), now()).unwrap();
    bob_side.block(alice.public());
    bob_side.unblock(&alice.public());
    let (_, hello) = Initiator::start_with(&alice, card.handshake_key, NET, invitation.id, POLICY).unwrap();
    assert!(matches!(bob_side.handle(1, &hello, now()), Err(WireError::Unauthorised)), "no reply");
    assert_eq!(bob_side.record_invitation(invitation, now()), Err(ContactError::Revoked));
    let fresh = bob.invite(NET, alice.public(), Purpose::Contact, NOW + 3_600);
    bob_side.record_invitation(fresh.clone(), now()).unwrap();
    let (_, _, _, grant) = connect(&alice, card.handshake_key, fresh.id, &mut bob_side, 2);
    assert_eq!(grant, Grant::Invitation { id: fresh.id });
}

#[test]
fn removing_the_recipient_cancels_an_outstanding_callback_grant() {
    let bob = ContactIdentity::generate();
    let callback = StaticKey::generate();
    let deadline = Instant::now() + Duration::from_secs(3_600);
    let mut carol_side: Responder<u32> =
        Responder::for_callback(&callback, NET, bob.handshake_key().public(), [1; 32], deadline).unwrap();
    carol_side.remove_contact(bob.handshake_key().public());
    let (_, hello) = Initiator::start_with(bob.handshake_key(), callback.public(), NET, [1; 32], POLICY).unwrap();
    assert!(matches!(carol_side.handle(7, &hello, now()), Err(WireError::Unauthorised)), "no reply");
    assert_eq!(carol_side.pending(), 0);
    // Blocking cancels it the same way.
    let mut carol_side: Responder<u32> =
        Responder::for_callback(&callback, NET, bob.handshake_key().public(), [1; 32], deadline).unwrap();
    carol_side.block(bob.handshake_key().public());
    carol_side.unblock(&bob.handshake_key().public());
    assert!(matches!(carol_side.handle(7, &hello, now()), Err(WireError::Unauthorised)), "no reply");
}
