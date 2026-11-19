use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, WireError};
use anonymum_crypto::Identity;

/// Drive a full handshake; `tag` plays the role of the transport's reply handle.
fn establish(alice: &Identity, bob: &Identity, bob_side: &mut Responder<u32>, tag: u32) -> Initiator {
    let (mut caller, f1) = Initiator::start(alice, bob.address()).unwrap();
    let ResponderEvent::Reply(f2) = bob_side.handle(bob, tag, &f1).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    let event = bob_side.handle(bob, tag, &f3).unwrap();
    assert_eq!(event, ResponderEvent::Established { peer: alice.address() });
    caller
}

#[test]
fn full_conversation_over_frames() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side = Responder::new();
    let mut caller = establish(&alice, &bob, &mut bob_side, 7);

    let frame = caller.seal(b"hello").unwrap();
    assert_eq!(
        bob_side.handle(&bob, 7, &frame).unwrap(),
        ResponderEvent::Message { peer: alice.address(), plaintext: b"hello".to_vec() }
    );
    let reply = bob_side.seal(&7, b"hi back").unwrap();
    assert_eq!(caller.handle(&reply).unwrap(), InitiatorEvent::Message(b"hi back".to_vec()));
}

#[test]
fn responder_keeps_callers_apart() {
    let (alice, carol, bob) = (Identity::generate(), Identity::generate(), Identity::generate());
    let mut bob_side = Responder::new();
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
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side = Responder::new();
    let mut caller = establish(&alice, &bob, &mut bob_side, 1);
    bob_side.forget(&1);
    let frame = caller.seal(b"still there?").unwrap();
    assert!(matches!(bob_side.handle(&bob, 1, &frame), Err(WireError::NoSession)));
    assert!(matches!(bob_side.handle(&bob, 99, &frame), Err(WireError::NoSession)));
}

#[test]
fn nonsense_frames_are_errors_not_panics() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side: Responder<u32> = Responder::new();
    assert!(matches!(bob_side.handle(&bob, 1, &[]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob_side.handle(&bob, 1, &[200, 1, 2]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob_side.handle(&bob, 1, &[3, 1, 2]), Err(WireError::UnexpectedFrame)));
    assert!(matches!(bob_side.handle(&bob, 1, &[1, 1, 2]), Err(WireError::Session(_))));
    let (mut caller, _) = Initiator::start(&alice, bob.address()).unwrap();
    assert!(matches!(caller.seal(b"too early"), Err(WireError::NoSession)));
    assert!(matches!(caller.handle(&[2, 0, 0]), Err(WireError::Session(_))));
}

#[test]
fn a_repeated_call_delivered_twice_still_makes_one_handshake() {
    // Carol was offline; Bob sent the same first frame twice and her
    // gateway delivers both copies when she comes back.
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let mut carol_side = Responder::new();
    let (mut call, f1) = Initiator::start(&bob, carol.address()).unwrap();

    let ResponderEvent::Reply(reply_a) = carol_side.handle(&carol, 5, &f1).unwrap() else { panic!() };
    let ResponderEvent::Reply(reply_b) = carol_side.handle(&carol, 5, &f1).unwrap() else { panic!() };
    assert_eq!(reply_a, reply_b, "the repeat gets the same answer");

    let InitiatorEvent::Established { reply: f3 } = call.handle(&reply_a).unwrap() else { panic!() };
    // The duplicate answer arrives after the session is up: an error to
    // ignore, not a failure of the session.
    assert!(matches!(call.handle(&reply_b), Err(WireError::UnexpectedFrame)));
    assert_eq!(
        carol_side.handle(&carol, 5, &f3).unwrap(),
        ResponderEvent::Established { peer: bob.address() }
    );
    let frame = call.seal(b"made it").unwrap();
    assert!(matches!(carol_side.handle(&carol, 5, &frame), Ok(ResponderEvent::Message { .. })));
}

#[test]
fn a_fresh_call_from_the_same_caller_replaces_the_old_one() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let mut carol_side = Responder::new();
    let (mut old_call, old_f1) = Initiator::start(&bob, carol.address()).unwrap();
    let (mut new_call, new_f1) = Initiator::start(&bob, carol.address()).unwrap();

    let ResponderEvent::Reply(old_f2) = carol_side.handle(&carol, 5, &old_f1).unwrap() else { panic!() };
    let ResponderEvent::Reply(new_f2) = carol_side.handle(&carol, 5, &new_f1).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: old_f3 } = old_call.handle(&old_f2).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: new_f3 } = new_call.handle(&new_f2).unwrap() else { panic!() };

    assert_eq!(
        carol_side.handle(&carol, 5, &new_f3).unwrap(),
        ResponderEvent::Established { peer: bob.address() },
        "the newest call wins"
    );
    assert!(carol_side.handle(&carol, 5, &old_f3).is_err(), "the replaced handshake cannot finish");
    let frame = new_call.seal(b"still fine").unwrap();
    assert!(matches!(carol_side.handle(&carol, 5, &frame), Ok(ResponderEvent::Message { .. })));
}

// ---- review finding M3: bad frames must not destroy a pending handshake -----

/// Frames that fail validation: garbage, a flipped byte, truncated, empty
/// body, wrong type byte.
fn bad_versions(good: &[u8]) -> Vec<Vec<u8>> {
    let mut flipped = good.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let mut mid = good.to_vec();
    mid[good.len() / 2] ^= 0x80;
    vec![
        vec![good[0]; good.len()],
        flipped,
        mid,
        good[..good.len() - 1].to_vec(),
        good[..1].to_vec(),
        [&[good[0]], &[0u8; 40][..]].concat(),
    ]
}

#[test]
fn a_malformed_message_2_does_not_destroy_the_initiators_handshake() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side: Responder<u32> = Responder::new();
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    for bad in bad_versions(&f2) {
        assert!(caller.handle(&bad).is_err(), "a bad message 2 must be rejected");
    }
    // The genuine message 2 still completes the handshake.
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    assert_eq!(bob_side.handle(&bob, 1, &f3).unwrap(), ResponderEvent::Established { peer: alice.address() });
    let msg = caller.seal(b"still here").unwrap();
    assert!(matches!(bob_side.handle(&bob, 1, &msg), Ok(ResponderEvent::Message { .. })));
}

#[test]
fn a_malformed_message_3_does_not_destroy_the_responders_handshake() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side: Responder<u32> = Responder::new();
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    for bad in bad_versions(&f3) {
        assert!(bob_side.handle(&bob, 1, &bad).is_err(), "a bad message 3 must be rejected");
    }
    assert_eq!(bob_side.handle(&bob, 1, &f3).unwrap(), ResponderEvent::Established { peer: alice.address() });
}

#[test]
fn a_malformed_first_frame_does_not_replace_a_pending_handshake() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side: Responder<u32> = Responder::new();
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    // Garbage claiming to be a new first frame from the same caller.
    assert!(bob_side.handle(&bob, 1, &[f1[0], 1, 2, 3]).is_err());
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    assert_eq!(bob_side.handle(&bob, 1, &f3).unwrap(), ResponderEvent::Established { peer: alice.address() });
}

#[test]
fn a_validly_encrypted_message_2_from_an_impostor_does_not_end_the_handshake() {
    // Mallory answers Alice's first frame with a message 2 that Noise
    // accepts but that proves Mallory, not Bob. It is rejected, and Bob's
    // genuine message 2 still completes the handshake.
    let (alice, bob, mallory) = (Identity::generate(), Identity::generate(), Identity::generate());
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    let mut mallory_side: Responder<u32> = Responder::new();
    let ResponderEvent::Reply(forged) = mallory_side.handle(&mallory, 1, &f1).unwrap() else { panic!() };
    assert!(caller.handle(&forged).is_err(), "Mallory is not Bob");
    let mut bob_side: Responder<u32> = Responder::new();
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    assert_eq!(bob_side.handle(&bob, 1, &f3).unwrap(), ResponderEvent::Established { peer: alice.address() });
}

#[test]
fn a_finished_handshake_takes_no_more_handshake_frames() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut bob_side: Responder<u32> = Responder::new();
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    caller.handle(&f2).unwrap();
    assert!(matches!(caller.handle(&f2), Err(WireError::UnexpectedFrame)), "message 2 replayed after finishing");
}

// ---- oversized frames are refused before anything is allocated --------------

#[test]
fn oversized_frames_are_refused_on_both_sides_and_in_a_session() {
    use anonymum_crypto::wire::MAX_FRAME;
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let huge = vec![1u8; MAX_FRAME + 1];
    let mut bob_side: Responder<u32> = Responder::new();
    assert!(matches!(bob_side.handle(&bob, 1, &huge), Err(WireError::Oversized)));
    let (mut caller, f1) = Initiator::start(&alice, bob.address()).unwrap();
    assert!(matches!(caller.handle(&[&[2u8], &huge[1..]].concat()), Err(WireError::Oversized)));
    // The pending handshakes survive and complete.
    let ResponderEvent::Reply(f2) = bob_side.handle(&bob, 1, &f1).unwrap() else { panic!() };
    let InitiatorEvent::Established { reply: f3 } = caller.handle(&f2).unwrap() else { panic!() };
    bob_side.handle(&bob, 1, &f3).unwrap();
    // Established sessions refuse oversized data frames too.
    assert!(matches!(bob_side.handle(&bob, 1, &[&[4u8], &huge[1..]].concat()), Err(WireError::Oversized)));
    // The largest valid frame size is not refused as oversized.
    let at_limit = [&[4u8], &vec![0u8; MAX_FRAME - 1][..]].concat();
    assert!(!matches!(bob_side.handle(&bob, 1, &at_limit), Err(WireError::Oversized)));
}
