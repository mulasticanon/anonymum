use std::time::Duration;

use anonymum_crypto::wire::{
    Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError, MAX_FRAME, PENDING_TICKS,
};
use anonymum_crypto::{Identity, SessionError, MAX_PLAINTEXT};

const POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(10) };

fn reply(event: ResponderEvent) -> Vec<u8> {
    match event {
        ResponderEvent::Reply(frame) => frame,
        other => panic!("expected a reply, got {other:?}"),
    }
}

fn send(event: InitiatorEvent) -> Vec<u8> {
    match event {
        InitiatorEvent::Send(frame) => frame,
        other => panic!("expected a frame to send, got {other:?}"),
    }
}

/// The confirmation to send back, after checking who the caller proved to be.
fn confirmed(event: ResponderEvent, expected: &Identity) -> Vec<u8> {
    match event {
        ResponderEvent::Established { peer, reply } => {
            assert_eq!(peer, expected.address());
            reply
        }
        other => panic!("expected an established session, got {other:?}"),
    }
}

/// Finish an attempt whose first frame is `f1`.
fn finish(caller: &mut Initiator, f1: &[u8], alice: &Identity, bob: &Identity, bob_side: &mut Responder<u32>, tag: u32) {
    let f2 = reply(bob_side.handle(bob, tag, f1).unwrap());
    let f3 = send(caller.handle(&f2).unwrap());
    assert!(!caller.is_established(), "not before the responder confirms");
    assert!(matches!(caller.seal(b"too early"), Err(WireError::NoSession)));
    let confirm = confirmed(bob_side.handle(bob, tag, &f3).unwrap(), alice);
    assert_eq!(caller.handle(&confirm).unwrap(), InitiatorEvent::Established);
    assert!(caller.is_established());
    assert_eq!(caller.wait(), None);
}

/// Drive a full handshake; `tag` plays the role of the transport's reply handle.
fn establish(alice: &Identity, bob: &Identity, bob_side: &mut Responder<u32>, tag: u32) -> Initiator {
    let (mut caller, f1) = Initiator::start_with(alice, bob.address(), POLICY).unwrap();
    finish(&mut caller, &f1, alice, bob, bob_side, tag);
    caller
}

/// Both directions still carry messages.
fn talks(caller: &mut Initiator, alice: &Identity, bob: &Identity, bob_side: &mut Responder<u32>, tag: u32) {
    let frame = caller.seal(b"ping").unwrap();
    assert_eq!(
        bob_side.handle(bob, tag, &frame).unwrap(),
        ResponderEvent::Message { peer: alice.address(), plaintext: b"ping".to_vec() }
    );
    let frame = bob_side.seal(&tag, b"pong").unwrap();
    assert_eq!(caller.handle(&frame).unwrap(), InitiatorEvent::Message(b"pong".to_vec()));
}

fn flip(frame: &[u8], at: usize) -> Vec<u8> {
    let mut out = frame.to_vec();
    out[at] ^= 0x01;
    out
}

fn people() -> (Identity, Identity, Responder<u32>) {
    (Identity::generate(), Identity::generate(), Responder::new())
}

#[test]
fn full_conversation_over_frames() {
    let (alice, bob, mut bob_side) = people();
    let mut caller = establish(&alice, &bob, &mut bob_side, 7);
    talks(&mut caller, &alice, &bob, &mut bob_side, 7);
}

#[test]
fn responder_keeps_callers_apart() {
    let (alice, bob, mut bob_side) = people();
    let carol = Identity::generate();
    let mut from_alice = establish(&alice, &bob, &mut bob_side, 1);
    let mut from_carol = establish(&carol, &bob, &mut bob_side, 2);

    let a = from_alice.seal(b"from alice").unwrap();
    let c = from_carol.seal(b"from carol").unwrap();
    // Carol's frame presented under Alice's handle must not decrypt.
    assert!(matches!(bob_side.handle(&bob, 1, &c), Err(WireError::Session(_))));
    assert!(matches!(bob_side.handle(&bob, 1, &a), Ok(ResponderEvent::Message { .. })));
    assert!(matches!(bob_side.handle(&bob, 2, &c), Ok(ResponderEvent::Message { .. })));
}

#[test]
fn forgotten_or_unknown_callers_cannot_send_data() {
    let (alice, bob, mut bob_side) = people();
    let mut caller = establish(&alice, &bob, &mut bob_side, 1);
    bob_side.forget(&1);
    let frame = caller.seal(b"still there?").unwrap();
    assert!(matches!(bob_side.handle(&bob, 1, &frame), Err(WireError::NoSession)));
    assert!(matches!(bob_side.handle(&bob, 99, &frame), Err(WireError::NoSession)));
}

#[test]
fn nonsense_frames_are_errors_not_panics() {
    let (alice, bob, mut bob_side) = people();
    assert!(matches!(bob_side.handle(&bob, 1, &[]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob_side.handle(&bob, 1, &[200, 1, 2]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob_side.handle(&bob, 1, &[3, 1, 2]), Err(WireError::Malformed)));
    assert!(matches!(bob_side.handle(&bob, 1, &[1, 1, 2]), Err(WireError::Malformed)));
    assert!(matches!(bob_side.handle(&bob, 1, &[4, 1, 2]), Err(WireError::Malformed)));
    let (mut caller, _) = Initiator::start(&alice, bob.address()).unwrap();
    assert!(matches!(caller.seal(b"too early"), Err(WireError::NoSession)));
    assert!(matches!(caller.handle(&[2, 0, 0]), Err(WireError::Malformed)));
    assert_eq!(bob_side.pending(), 0);
}

#[test]
fn a_repeated_call_delivered_twice_still_makes_one_handshake() {
    // Carol was offline; Bob sent the same first frame twice and her
    // gateway delivers both copies when she comes back.
    let (bob, carol, mut carol_side) = people();
    let (mut call, f1) = Initiator::start_with(&bob, carol.address(), POLICY).unwrap();
    let reply_a = reply(carol_side.handle(&carol, 5, &f1).unwrap());
    let reply_b = reply(carol_side.handle(&carol, 5, &f1).unwrap());
    assert_eq!(reply_a, reply_b, "the repeat gets the same answer");

    let f3 = send(call.handle(&reply_a).unwrap());
    // The duplicate answer is stale: ignored, the attempt goes on.
    assert!(matches!(call.handle(&reply_b), Err(WireError::Stale)));
    let confirm = confirmed(carol_side.handle(&carol, 5, &f3).unwrap(), &bob);
    assert_eq!(call.handle(&confirm).unwrap(), InitiatorEvent::Established);
    talks(&mut call, &bob, &carol, &mut carol_side, 5);
}

#[test]
fn of_two_calls_from_the_same_caller_the_first_to_finish_wins() {
    let (bob, carol, mut carol_side) = people();
    let (mut old_call, old_f1) = Initiator::start_with(&bob, carol.address(), POLICY).unwrap();
    let (mut new_call, new_f1) = Initiator::start_with(&bob, carol.address(), POLICY).unwrap();
    let old_f2 = reply(carol_side.handle(&carol, 5, &old_f1).unwrap());
    let new_f2 = reply(carol_side.handle(&carol, 5, &new_f1).unwrap());
    assert_eq!(carol_side.pending(), 2, "a second call does not displace the first");
    let old_f3 = send(old_call.handle(&old_f2).unwrap());
    let new_f3 = send(new_call.handle(&new_f2).unwrap());

    let confirm = confirmed(carol_side.handle(&carol, 5, &new_f3).unwrap(), &bob);
    assert_eq!(new_call.handle(&confirm).unwrap(), InitiatorEvent::Established);
    assert!(matches!(carol_side.handle(&carol, 5, &old_f3), Err(WireError::Stale)), "the other call is over");
    assert_eq!(carol_side.pending(), 0);
    talks(&mut new_call, &bob, &carol, &mut carol_side, 5);
}

// ---- review finding M3 --------------------------------------------------------

/// Frames the outer framing rejects: empty, unknown type, one byte short,
/// one byte long, and relabelled as another frame type.
fn bad_framings(good: &[u8]) -> Vec<Vec<u8>> {
    let relabelled = if good[0] == 2 { 3 } else { 2 };
    vec![
        vec![],
        [&[99u8], &good[1..]].concat(),
        good[..good.len() - 1].to_vec(),
        [good, &[0u8]].concat(),
        [&[relabelled], &good[1..]].concat(),
    ]
}

#[test]
fn bad_framing_is_ignored_and_the_handshake_completes() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    for bad in bad_framings(&f1) {
        assert!(bob_side.handle(&bob, 1, &bad).is_err());
    }
    assert_eq!(bob_side.pending(), 0, "a rejected frame starts nothing");
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    for bad in bad_framings(&f2) {
        assert!(caller.handle(&bad).is_err());
        assert!(bob_side.handle(&bob, 1, &bad).is_err(), "nor disturbs the responder's pending handshake");
    }
    let f3 = send(caller.handle(&f2).unwrap());
    for bad in bad_framings(&f3) {
        assert!(bob_side.handle(&bob, 1, &bad).is_err());
        assert!(caller.handle(&bad).is_err());
    }
    let confirm = confirmed(bob_side.handle(&bob, 1, &f3).unwrap(), &alice);
    for bad in bad_framings(&confirm) {
        assert!(caller.handle(&bad).is_err());
    }
    assert_eq!(caller.handle(&confirm).unwrap(), InitiatorEvent::Established);
    assert_eq!(caller.attempt(), 1, "no fresh handshake was needed");
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn a_tampered_message_2_ends_the_attempt_and_a_fresh_handshake_connects() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    let last = f2.len() - 1;
    assert!(matches!(caller.handle(&flip(&f2, last)), Err(WireError::AttemptFailed(SessionError::Noise(_)))));
    // The attempt is over: even the genuine message 2 is now stale.
    assert!(matches!(caller.handle(&f2), Err(WireError::Stale)));
    assert_eq!(caller.wait(), Some(POLICY.base_wait));
    let fresh = caller.on_timeout(&alice).unwrap().expect("a fresh first frame");
    assert_ne!(fresh[9..], f1[9..], "a fresh ephemeral key");
    assert_eq!(caller.attempt(), 2);
    finish(&mut caller, &fresh, &alice, &bob, &mut bob_side, 1);
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn a_tampered_message_3_ends_the_responders_attempt_and_the_caller_reconnects() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    let f3 = send(caller.handle(&f2).unwrap());
    let last = f3.len() - 1;
    assert!(matches!(bob_side.handle(&bob, 1, &flip(&f3, last)), Err(WireError::AttemptFailed(_))));
    assert_eq!(bob_side.pending(), 0, "the responder's attempt ended");
    assert!(matches!(bob_side.handle(&bob, 1, &f3), Err(WireError::Stale)));
    // The caller hears nothing: it resends message 3, then starts afresh.
    for _ in 0..POLICY.resends {
        let again = caller.on_timeout(&alice).unwrap().unwrap();
        assert_eq!(again, f3, "a timeout resends the exact bytes");
        assert!(matches!(bob_side.handle(&bob, 1, &again), Err(WireError::Stale)));
    }
    let fresh = caller.on_timeout(&alice).unwrap().unwrap();
    assert_eq!(caller.attempt(), 2);
    finish(&mut caller, &fresh, &alice, &bob, &mut bob_side, 1);
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn an_impostor_ends_the_attempt_and_a_fresh_handshake_reaches_the_real_peer() {
    // Mallory answers Alice's first frame with a message 2 that decrypts
    // but proves Mallory, not Bob.
    let (alice, bob, mut bob_side) = people();
    let mallory = Identity::generate();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let forged = reply(Responder::new().handle(&mallory, 1u32, &f1).unwrap());
    assert!(matches!(
        caller.handle(&forged),
        Err(WireError::AttemptFailed(SessionError::UnexpectedPeer { got })) if got == mallory.address()
    ));
    let genuine = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    assert!(matches!(caller.handle(&genuine), Err(WireError::Stale)), "attempt 1 is over");
    let fresh = caller.on_timeout(&alice).unwrap().unwrap();
    finish(&mut caller, &fresh, &alice, &bob, &mut bob_side, 1);
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn late_frames_from_an_old_attempt_do_not_disturb_a_new_one() {
    let no_resends = RetryPolicy { resends: 0, ..POLICY };
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1_old) = Initiator::start_with(&alice, bob.address(), no_resends).unwrap();
    let f2_old = reply(bob_side.handle(&bob, 1, &f1_old).unwrap());
    let f3_old = send(caller.handle(&f2_old).unwrap());
    // Message 3 is slow; the caller gives up on attempt 1 and starts attempt 2.
    let f1_new = caller.on_timeout(&alice).unwrap().unwrap();
    assert_eq!(caller.attempt(), 2);
    let f2_new = reply(bob_side.handle(&bob, 1, &f1_new).unwrap());

    // Old frames now arrive at both ends.
    assert!(matches!(bob_side.handle(&bob, 1, &f1_old), Err(WireError::Stale)));
    assert!(matches!(bob_side.handle(&bob, 1, &f3_old), Err(WireError::Stale)));
    assert!(matches!(caller.handle(&f2_old), Err(WireError::Stale)));
    assert_eq!(bob_side.pending(), 1);

    let f3_new = send(caller.handle(&f2_new).unwrap());
    // And again after the new attempt has finished on the responder.
    let confirm = confirmed(bob_side.handle(&bob, 1, &f3_new).unwrap(), &alice);
    for old in [&f1_old, &f3_old, &f1_new] {
        assert!(matches!(bob_side.handle(&bob, 1, old), Err(WireError::Stale)));
    }
    assert!(matches!(caller.handle(&f2_old), Err(WireError::Stale)));
    assert_eq!(caller.handle(&confirm).unwrap(), InitiatorEvent::Established);
    assert_eq!(bob_side.pending(), 0);
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn retry_limits_are_enforced() {
    let policy = RetryPolicy { attempts: 2, resends: 1, base_wait: Duration::from_secs(10) };
    let (alice, bob, _) = people();
    let (mut caller, first) = Initiator::start_with(&alice, bob.address(), policy).unwrap();
    // Nobody answers: resend, fresh attempt, resend, give up.
    assert_eq!(caller.on_timeout(&alice).unwrap().unwrap(), first);
    let second = caller.on_timeout(&alice).unwrap().unwrap();
    assert_ne!(second, first);
    assert_eq!(caller.on_timeout(&alice).unwrap().unwrap(), second);
    assert!(matches!(caller.on_timeout(&alice), Err(WireError::GaveUp)));
    assert_eq!(caller.wait(), None);
    assert!(matches!(caller.on_timeout(&alice), Err(WireError::GaveUp)));
    assert_eq!(caller.attempt(), 2);
}

#[test]
fn failed_attempts_back_off_and_stop_at_the_limit() {
    let policy = RetryPolicy { attempts: 4, resends: 2, base_wait: Duration::from_secs(10) };
    let (alice, bob, mut bob_side) = people();
    let (mut caller, mut f1) = Initiator::start_with(&alice, bob.address(), policy).unwrap();
    for (attempt, backoff) in [(1, 10), (2, 20), (3, 40), (4, 80)] {
        assert_eq!(caller.attempt(), attempt);
        let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
        let last = f2.len() - 1;
        assert!(matches!(caller.handle(&flip(&f2, last)), Err(WireError::AttemptFailed(_))));
        assert_eq!(caller.wait(), Some(Duration::from_secs(backoff)));
        match caller.on_timeout(&alice) {
            Ok(Some(next)) => f1 = next,
            Err(WireError::GaveUp) => assert_eq!(attempt, 4),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(caller.wait(), None);
}

#[test]
fn a_lost_message_3_is_resent_and_the_session_is_confirmed() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    let f3 = send(caller.handle(&f2).unwrap()); // lost on the way
    assert!(!caller.is_established());
    let again = caller.on_timeout(&alice).unwrap().unwrap();
    assert_eq!(again, f3);
    let confirm = confirmed(bob_side.handle(&bob, 1, &again).unwrap(), &alice);
    assert_eq!(caller.handle(&confirm).unwrap(), InitiatorEvent::Established);
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn a_lost_confirmation_is_sent_again_and_forgeries_are_ignored() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    let f3 = send(caller.handle(&f2).unwrap());
    let confirm = confirmed(bob_side.handle(&bob, 1, &f3).unwrap(), &alice); // lost
    let again = caller.on_timeout(&alice).unwrap().unwrap();
    let resent = reply(bob_side.handle(&bob, 1, &again).unwrap());
    assert_eq!(resent, confirm, "the same confirmation, not a second session");
    // A tampered confirmation is dropped; the attempt stays valid.
    let last = resent.len() - 1;
    assert!(matches!(caller.handle(&flip(&resent, last)), Err(WireError::Stale)));
    // So is the genuine one relabelled with another attempt number.
    assert!(matches!(caller.handle(&flip(&resent, 8)), Err(WireError::Stale)));
    assert!(!caller.is_established());
    assert_eq!(caller.handle(&resent).unwrap(), InitiatorEvent::Established);
    assert!(matches!(caller.handle(&resent), Err(WireError::Stale)), "a duplicate later is ignored");
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}

#[test]
fn a_message_from_the_responder_also_confirms_the_session() {
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    let f3 = send(caller.handle(&f2).unwrap());
    let _lost = confirmed(bob_side.handle(&bob, 1, &f3).unwrap(), &alice);
    let hello = bob_side.seal(&1, b"hello").unwrap();
    assert_eq!(caller.handle(&hello).unwrap(), InitiatorEvent::Message(b"hello".to_vec()));
    assert!(caller.is_established());
}

#[test]
fn both_ends_recover_or_fail_within_a_bounded_time() {
    // Bob's side drops a handshake whose message 3 never comes.
    let (alice, bob, mut bob_side) = people();
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let f2 = reply(bob_side.handle(&bob, 1, &f1).unwrap());
    for _ in 1..PENDING_TICKS {
        assert!(bob_side.tick().is_empty());
    }
    assert_eq!(bob_side.tick(), vec![1]);
    assert_eq!(bob_side.pending(), 0);
    // Alice's message 3 arrives too late; she recovers with a fresh attempt.
    let f3 = send(caller.handle(&f2).unwrap());
    assert!(matches!(bob_side.handle(&bob, 1, &f3), Err(WireError::Stale)));
    let mut timeouts = 0;
    let fresh = loop {
        timeouts += 1;
        let frame = caller.on_timeout(&alice).unwrap().unwrap();
        if frame != f3 {
            break frame;
        }
    };
    assert_eq!(timeouts, POLICY.resends + 1);
    finish(&mut caller, &fresh, &alice, &bob, &mut bob_side, 1);

    // A caller whose peer never answers gives up after a bounded number of
    // timeouts: attempts * (resends + 1).
    let (mut lonely, _) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    let mut timeouts = 0;
    while lonely.on_timeout(&alice).is_ok() {
        timeouts += 1;
        assert!(timeouts < 100);
    }
    assert_eq!(timeouts + 1, POLICY.attempts * (POLICY.resends + 1));
}

// ---- frame limits ---------------------------------------------------------------

#[test]
fn the_largest_plaintext_round_trips_both_ways() {
    let (alice, bob, mut bob_side) = people();
    let mut caller = establish(&alice, &bob, &mut bob_side, 1);
    let largest: Vec<u8> = (0..MAX_PLAINTEXT).map(|i| i as u8).collect();

    let frame = caller.seal(&largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME, "the largest data frame is exactly the limit");
    assert_eq!(
        bob_side.handle(&bob, 1, &frame).unwrap(),
        ResponderEvent::Message { peer: alice.address(), plaintext: largest.clone() }
    );
    let frame = bob_side.seal(&1, &largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME);
    assert_eq!(caller.handle(&frame).unwrap(), InitiatorEvent::Message(largest.clone()));

    let too_long = [&largest[..], b"!"].concat();
    assert!(matches!(caller.seal(&too_long), Err(WireError::Session(SessionError::TooLarge))));
    assert!(matches!(bob_side.seal(&1, &too_long), Err(WireError::Session(SessionError::TooLarge))));
}

#[test]
fn oversized_frames_are_refused_on_both_sides_and_in_a_session() {
    let (alice, bob, mut bob_side) = people();
    let huge = vec![4u8; MAX_FRAME + 1];
    assert!(matches!(bob_side.handle(&bob, 1, &huge), Err(WireError::Oversized)));
    let (mut caller, f1) = Initiator::start_with(&alice, bob.address(), POLICY).unwrap();
    assert!(matches!(caller.handle(&[&[2u8], &huge[1..]].concat()), Err(WireError::Oversized)));
    // The pending handshakes survive and complete.
    finish(&mut caller, &f1, &alice, &bob, &mut bob_side, 1);
    assert!(matches!(bob_side.handle(&bob, 1, &huge), Err(WireError::Oversized)));
    assert!(matches!(caller.handle(&huge), Err(WireError::Oversized)));
    talks(&mut caller, &alice, &bob, &mut bob_side, 1);
}
