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
