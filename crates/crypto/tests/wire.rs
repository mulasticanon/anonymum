//! The wire layer: retries, confirmation, stale frames and frame limits
//! (design review M3, af61c8f), adapted to Noise IK and the gate.

use std::time::Duration;

use anonymum_crypto::wire::{
    Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError, MAX_FRAME, PENDING_TICKS,
};
use anonymum_crypto::{ContactIdentity, Gate, Grant, Network, Purpose, SessionError, StaticKey, MAX_PLAINTEXT};

const NET: Network = [9; 32];
const NOW: u64 = 1_000;
const POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(10) };

/// Bob, who answers, and one invited caller key per invitation he issues.
struct Bob {
    me: ContactIdentity,
    side: Responder<u32>,
}

struct Caller {
    key: StaticKey,
    reference: [u8; 32],
}

impl Bob {
    fn new() -> Bob {
        let me = ContactIdentity::generate();
        let side = Responder::new(me.handshake_key(), NET, Gate::new(NET));
        Bob { me, side }
    }

    fn invite(&mut self) -> Caller {
        let key = StaticKey::generate();
        let invitation = self.me.invite(NET, key.public(), Purpose::Contact, NOW + 3_600);
        let reference = invitation.id;
        self.side.gate_mut().record_invitation(invitation);
        Caller { key, reference }
    }

    fn call(&self, caller: &Caller, policy: RetryPolicy) -> (Initiator, Vec<u8>) {
        Initiator::start_with(&caller.key, self.me.handshake_key().public(), NET, caller.reference, policy).unwrap()
    }

    fn handle(&mut self, tag: u32, frame: &[u8]) -> Result<ResponderEvent, WireError> {
        self.side.handle(tag, frame, NOW)
    }
}

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

/// The ACK to send back, after checking who confirmed.
fn established(event: ResponderEvent, caller: &Caller) -> Vec<u8> {
    match event {
        ResponderEvent::Established { peer, reply, .. } => {
            assert_eq!(peer, caller.key.public());
            reply
        }
        other => panic!("expected an established session, got {other:?}"),
    }
}

/// Finish an attempt whose first frame is `hello`.
fn finish(call: &mut Initiator, hello: &[u8], caller: &Caller, bob: &mut Bob, tag: u32) {
    let welcome = reply(bob.handle(tag, hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    assert!(!call.is_established(), "not before the answerer acknowledges");
    assert!(matches!(call.seal(b"too early"), Err(WireError::NoSession)));
    let ack = established(bob.handle(tag, &confirm).unwrap(), caller);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert!(call.is_established());
    assert_eq!(call.wait(), None);
}

fn establish(caller: &Caller, bob: &mut Bob, tag: u32) -> Initiator {
    let (mut call, hello) = bob.call(caller, POLICY);
    finish(&mut call, &hello, caller, bob, tag);
    call
}

/// Both directions still carry messages.
fn talks(call: &mut Initiator, caller: &Caller, bob: &mut Bob, tag: u32) {
    let frame = call.seal(b"ping").unwrap();
    assert_eq!(
        bob.handle(tag, &frame).unwrap(),
        ResponderEvent::Message { peer: caller.key.public(), plaintext: b"ping".to_vec() }
    );
    let frame = bob.side.seal(&tag, b"pong").unwrap();
    assert_eq!(call.handle(&frame).unwrap(), InitiatorEvent::Message(b"pong".to_vec()));
}

fn flip(frame: &[u8], at: usize) -> Vec<u8> {
    let mut out = frame.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn full_conversation_over_frames() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let mut call = establish(&alice, &mut bob, 7);
    talks(&mut call, &alice, &mut bob, 7);
}

#[test]
fn responder_keeps_callers_apart() {
    let mut bob = Bob::new();
    let (alice, carol) = (bob.invite(), bob.invite());
    let mut from_alice = establish(&alice, &mut bob, 1);
    let mut from_carol = establish(&carol, &mut bob, 2);
    let a = from_alice.seal(b"from alice").unwrap();
    let c = from_carol.seal(b"from carol").unwrap();
    assert!(matches!(bob.handle(1, &c), Err(WireError::Session(_))));
    assert!(matches!(bob.handle(1, &a), Ok(ResponderEvent::Message { .. })));
    assert!(matches!(bob.handle(2, &c), Ok(ResponderEvent::Message { .. })));
}

#[test]
fn forgotten_or_unknown_callers_cannot_send_data() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let mut call = establish(&alice, &mut bob, 1);
    bob.side.forget(&1);
    let frame = call.seal(b"still there?").unwrap();
    assert!(matches!(bob.handle(1, &frame), Err(WireError::NoSession)));
    assert!(matches!(bob.handle(99, &frame), Err(WireError::NoSession)));
}

#[test]
fn nonsense_frames_are_errors_not_panics() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    assert!(matches!(bob.handle(1, &[]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob.handle(1, &[200, 1, 2]), Err(WireError::UnknownFrame)));
    assert!(matches!(bob.handle(1, &[3, 1, 2]), Err(WireError::Malformed)));
    assert!(matches!(bob.handle(1, &[1, 1, 2]), Err(WireError::Malformed)));
    assert!(matches!(bob.handle(1, &[4, 1, 2]), Err(WireError::Malformed)));
    let (mut call, _) = bob.call(&alice, POLICY);
    assert!(matches!(call.seal(b"too early"), Err(WireError::NoSession)));
    assert!(matches!(call.handle(&[2, 0, 0]), Err(WireError::Malformed)));
    assert_eq!(bob.side.pending(), 0);
}

#[test]
fn a_repeated_call_delivered_twice_still_makes_one_handshake() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome_a = reply(bob.handle(5, &hello).unwrap());
    let welcome_b = reply(bob.handle(5, &hello).unwrap());
    assert_eq!(welcome_a, welcome_b, "the repeat gets the same answer");
    let confirm = send(call.handle(&welcome_a).unwrap());
    assert!(matches!(call.handle(&welcome_b), Err(WireError::Stale)));
    let ack = established(bob.handle(5, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    talks(&mut call, &alice, &mut bob, 5);
}

#[test]
fn of_two_calls_from_the_same_caller_the_first_to_confirm_wins() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut old_call, old_hello) = bob.call(&alice, POLICY);
    let (mut new_call, new_hello) = bob.call(&alice, POLICY);
    let old_welcome = reply(bob.handle(5, &old_hello).unwrap());
    let new_welcome = reply(bob.handle(5, &new_hello).unwrap());
    assert_eq!(bob.side.pending(), 2, "a second call does not displace the first");
    let old_confirm = send(old_call.handle(&old_welcome).unwrap());
    let new_confirm = send(new_call.handle(&new_welcome).unwrap());
    let ack = established(bob.handle(5, &new_confirm).unwrap(), &alice);
    assert_eq!(new_call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert!(matches!(bob.handle(5, &old_confirm), Err(WireError::Stale)), "the other call is over");
    assert_eq!(bob.side.pending(), 0);
    talks(&mut new_call, &alice, &mut bob, 5);
}

// ---- review finding M3 ----------------------------------------------------------

/// Frames the outer framing rejects: empty, unknown type, one byte short,
/// one byte long, and relabelled as another frame type.
fn bad_framings(good: &[u8]) -> Vec<Vec<u8>> {
    let relabelled = if good[0] == 2 { 1 } else { 2 };
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
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    for bad in bad_framings(&hello) {
        assert!(bob.handle(1, &bad).is_err());
    }
    assert_eq!(bob.side.pending(), 0, "a rejected frame starts nothing");
    let welcome = reply(bob.handle(1, &hello).unwrap());
    for bad in bad_framings(&welcome) {
        assert!(call.handle(&bad).is_err());
        assert!(bob.handle(1, &bad).is_err());
    }
    let confirm = send(call.handle(&welcome).unwrap());
    for bad in bad_framings(&confirm) {
        assert!(bob.handle(1, &bad).is_err());
        assert!(call.handle(&bad).is_err());
    }
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    for bad in bad_framings(&ack) {
        assert!(call.handle(&bad).is_err());
    }
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert_eq!(call.attempt(), 1, "no fresh handshake was needed");
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_tampered_welcome_ends_the_attempt_and_a_fresh_handshake_connects() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let last = welcome.len() - 1;
    assert!(matches!(call.handle(&flip(&welcome, last)), Err(WireError::AttemptFailed(SessionError::Noise(_)))));
    assert!(matches!(call.handle(&welcome), Err(WireError::Stale)), "the attempt is over");
    assert_eq!(call.wait(), Some(POLICY.base_wait));
    let fresh = call.on_timeout().unwrap().expect("a fresh first frame");
    assert_ne!(fresh[9..], hello[9..], "a fresh ephemeral key");
    assert_eq!(call.attempt(), 2);
    finish(&mut call, &fresh, &alice, &mut bob, 1);
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_welcome_from_a_different_handshake_ends_the_attempt() {
    // A genuine WELCOME from another of Bob's handshakes, relabelled with
    // Alice's call id and attempt: it does not decrypt for her.
    let mut bob = Bob::new();
    let (alice, carol) = (bob.invite(), bob.invite());
    let (mut call, hello) = bob.call(&alice, POLICY);
    let (_other, carol_hello) = bob.call(&carol, POLICY);
    let theirs = reply(bob.handle(2, &carol_hello).unwrap());
    let relabelled = [&hello[..9], &theirs[9..]].concat();
    assert!(matches!(call.handle(&[&[2u8], &relabelled[1..]].concat()), Err(WireError::AttemptFailed(_))));
    let fresh = call.on_timeout().unwrap().unwrap();
    finish(&mut call, &fresh, &alice, &mut bob, 1);
}

#[test]
fn a_forged_confirm_is_dropped_and_the_real_one_still_works() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let last = confirm.len() - 1;
    assert!(matches!(bob.handle(1, &flip(&confirm, last)), Err(WireError::Stale)));
    assert_eq!(bob.side.pending(), 1, "the answered handshake is still waiting");
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
}

#[test]
fn late_frames_from_an_old_attempt_do_not_disturb_a_new_one() {
    let no_resends = RetryPolicy { resends: 0, ..POLICY };
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello_old) = bob.call(&alice, no_resends);
    let welcome_old = reply(bob.handle(1, &hello_old).unwrap());
    let confirm_old = send(call.handle(&welcome_old).unwrap());
    // The CONFIRM is slow; the caller gives up on attempt 1 and starts 2.
    let hello_new = call.on_timeout().unwrap().unwrap();
    assert_eq!(call.attempt(), 2);
    let welcome_new = reply(bob.handle(1, &hello_new).unwrap());

    assert!(matches!(bob.handle(1, &hello_old), Err(WireError::Stale)));
    assert!(matches!(bob.handle(1, &confirm_old), Err(WireError::Stale)));
    assert!(matches!(call.handle(&welcome_old), Err(WireError::Stale)));
    assert_eq!(bob.side.pending(), 1);

    let confirm_new = send(call.handle(&welcome_new).unwrap());
    let ack = established(bob.handle(1, &confirm_new).unwrap(), &alice);
    for old in [&hello_old, &confirm_old, &hello_new] {
        assert!(matches!(bob.handle(1, old), Err(WireError::Stale)));
    }
    assert!(matches!(call.handle(&welcome_old), Err(WireError::Stale)));
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn retry_limits_are_enforced() {
    let policy = RetryPolicy { attempts: 2, resends: 1, base_wait: Duration::from_secs(10) };
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, first) = bob.call(&alice, policy);
    assert_eq!(call.on_timeout().unwrap().unwrap(), first);
    let second = call.on_timeout().unwrap().unwrap();
    assert_ne!(second, first);
    assert_eq!(call.on_timeout().unwrap().unwrap(), second);
    assert!(matches!(call.on_timeout(), Err(WireError::GaveUp)));
    assert_eq!(call.wait(), None);
    assert!(matches!(call.on_timeout(), Err(WireError::GaveUp)));
    assert_eq!(call.attempt(), 2);
}

#[test]
fn failed_attempts_back_off_and_stop_at_the_limit() {
    let policy = RetryPolicy { attempts: 4, resends: 2, base_wait: Duration::from_secs(10) };
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, mut hello) = bob.call(&alice, policy);
    for (attempt, backoff) in [(1, 10), (2, 20), (3, 40), (4, 80)] {
        assert_eq!(call.attempt(), attempt);
        let welcome = reply(bob.handle(1, &hello).unwrap());
        let last = welcome.len() - 1;
        assert!(matches!(call.handle(&flip(&welcome, last)), Err(WireError::AttemptFailed(_))));
        assert_eq!(call.wait(), Some(Duration::from_secs(backoff)));
        match call.on_timeout() {
            Ok(Some(next)) => hello = next,
            Err(WireError::GaveUp) => assert_eq!(attempt, 4),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(call.wait(), None);
}

#[test]
fn a_lost_confirm_is_resent_and_the_session_is_acknowledged() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap()); // lost
    let again = call.on_timeout().unwrap().unwrap();
    assert_eq!(again, confirm);
    let ack = established(bob.handle(1, &again).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_lost_ack_is_sent_again_and_forgeries_are_ignored() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice); // lost
    let again = call.on_timeout().unwrap().unwrap();
    let resent = reply(bob.handle(1, &again).unwrap());
    assert_eq!(resent, ack, "the same ACK, not a second session");
    let last = resent.len() - 1;
    assert!(matches!(call.handle(&flip(&resent, last)), Err(WireError::Stale)));
    assert!(matches!(call.handle(&flip(&resent, 8)), Err(WireError::Stale)), "relabelled attempt");
    assert!(!call.is_established());
    assert_eq!(call.handle(&resent).unwrap(), InitiatorEvent::Established);
    assert!(matches!(call.handle(&resent), Err(WireError::Stale)), "a duplicate later is ignored");
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_message_from_the_answerer_also_establishes_the_session() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let _lost = established(bob.handle(1, &confirm).unwrap(), &alice);
    let hello_msg = bob.side.seal(&1, b"hello").unwrap();
    assert_eq!(call.handle(&hello_msg).unwrap(), InitiatorEvent::Message(b"hello".to_vec()));
    assert!(call.is_established());
}

#[test]
fn both_ends_recover_or_fail_within_a_bounded_time() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    for _ in 1..PENDING_TICKS {
        assert!(bob.side.tick().is_empty());
    }
    assert_eq!(bob.side.tick(), vec![1]);
    assert_eq!(bob.side.pending(), 0);
    let confirm = send(call.handle(&welcome).unwrap());
    assert!(matches!(bob.handle(1, &confirm), Err(WireError::Stale)));
    let mut timeouts = 0;
    let fresh = loop {
        timeouts += 1;
        let frame = call.on_timeout().unwrap().unwrap();
        if frame != confirm {
            break frame;
        }
    };
    assert_eq!(timeouts, POLICY.resends + 1);
    finish(&mut call, &fresh, &alice, &mut bob, 1);

    let lonely_bob = Bob::new();
    let (mut lonely, _) = lonely_bob.call(&alice, POLICY);
    let mut timeouts = 0;
    while lonely.on_timeout().is_ok() {
        timeouts += 1;
        assert!(timeouts < 100);
    }
    assert_eq!(timeouts + 1, POLICY.attempts * (POLICY.resends + 1));
}

#[test]
fn the_grant_is_reported_and_committed_only_on_confirm() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    assert!(!bob.side.gate().is_honoured(&alice.reference), "answering is not using");
    assert!(!bob.side.gate().is_contact(&alice.key.public()));
    let confirm = send(call.handle(&welcome).unwrap());
    match bob.handle(1, &confirm).unwrap() {
        ResponderEvent::Established { grant, .. } => assert_eq!(grant, Grant::Invitation { id: alice.reference }),
        other => panic!("{other:?}"),
    }
    assert!(bob.side.gate().is_honoured(&alice.reference));
    assert!(bob.side.gate().is_contact(&alice.key.public()));
}

// ---- frame limits ---------------------------------------------------------------

#[test]
fn the_largest_plaintext_round_trips_both_ways() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let mut call = establish(&alice, &mut bob, 1);
    let largest: Vec<u8> = (0..MAX_PLAINTEXT).map(|i| i as u8).collect();
    let frame = call.seal(&largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME, "the largest data frame is exactly the limit");
    assert_eq!(
        bob.handle(1, &frame).unwrap(),
        ResponderEvent::Message { peer: alice.key.public(), plaintext: largest.clone() }
    );
    let frame = bob.side.seal(&1, &largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME);
    assert_eq!(call.handle(&frame).unwrap(), InitiatorEvent::Message(largest.clone()));
    let too_long = [&largest[..], b"!"].concat();
    assert!(matches!(call.seal(&too_long), Err(WireError::Session(SessionError::TooLarge))));
    assert!(matches!(bob.side.seal(&1, &too_long), Err(WireError::Session(SessionError::TooLarge))));
}

#[test]
fn oversized_frames_are_refused_on_both_sides_and_in_a_session() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let huge = vec![4u8; MAX_FRAME + 1];
    assert!(matches!(bob.handle(1, &huge), Err(WireError::Oversized)));
    let (mut call, hello) = bob.call(&alice, POLICY);
    assert!(matches!(call.handle(&[&[2u8], &huge[1..]].concat()), Err(WireError::Oversized)));
    finish(&mut call, &hello, &alice, &mut bob, 1);
    assert!(matches!(bob.handle(1, &huge), Err(WireError::Oversized)));
    assert!(matches!(call.handle(&huge), Err(WireError::Oversized)));
    talks(&mut call, &alice, &mut bob, 1);
}
