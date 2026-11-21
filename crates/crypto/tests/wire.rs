//! The wire layer: retries, confirmation, stale frames, frame limits,
//! authenticated labels and record types, deadlines and revocation.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anonymum_crypto::wire::{
    Initiator, InitiatorEvent, Limits, Responder, ResponderEvent, RetryPolicy, WireError, MAX_DATA, MAX_FRAME,
    MAX_PENDING, MAX_PENDING_PER_CALLER, MAX_SESSIONS, PENDING_TIMEOUT, SESSION_IDLE_TIMEOUT,
};
use anonymum_crypto::{ContactIdentity, Grant, Network, Now, Purpose, SessionError, StaticKey};

const NET: Network = [9; 32];
const UNIX: u64 = 1_000;
const POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(10) };

/// Bob, who answers, with an injected clock.
struct Bob {
    me: ContactIdentity,
    side: Responder<u32>,
    now: Now,
}

struct Caller {
    key: StaticKey,
    reference: [u8; 32],
}

impl Bob {
    fn new() -> Bob {
        let me = ContactIdentity::generate_at(0);
        let side = Responder::for_identity(&me, NET);
        Bob { me, side, now: Now { unix: UNIX, mono: Instant::now() } }
    }

    fn with_limits(limits: Limits) -> Bob {
        let mut bob = Bob::new();
        bob.side = Responder::for_identity(&bob.me, NET).with_limits(limits);
        bob
    }

    fn invite(&mut self) -> Caller {
        let key = StaticKey::generate();
        let invitation = self.me.invite(NET, key.public(), Purpose::Contact, UNIX + 3_600);
        let reference = invitation.id;
        self.side.record_invitation(invitation, self.now).unwrap();
        Caller { key, reference }
    }

    fn call(&self, caller: &Caller, policy: RetryPolicy) -> (Initiator, Vec<u8>) {
        Initiator::start_with(&caller.key, self.me.handshake_key().public(), NET, caller.reference, policy).unwrap()
    }

    fn handle(&mut self, tag: u32, frame: &[u8]) -> Result<ResponderEvent, WireError> {
        self.side.handle(tag, frame, self.now)
    }

    fn seal(&mut self, tag: u32, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        self.side.seal(&tag, plaintext, self.now)
    }

    fn advance(&mut self, by: Duration) {
        self.now.mono += by;
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
    let frame = bob.seal(tag, b"pong").unwrap();
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
    let mut bob = Bob::new();
    let (alice, carol) = (bob.invite(), bob.invite());
    let (mut call, hello) = bob.call(&alice, POLICY);
    let (_other, carol_hello) = bob.call(&carol, POLICY);
    let theirs = reply(bob.handle(2, &carol_hello).unwrap());
    let relabelled = [&[2u8], &hello[1..9], &theirs[9..]].concat();
    assert!(matches!(call.handle(&relabelled), Err(WireError::AttemptFailed(_))));
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
fn a_caller_that_moved_to_a_higher_attempt_after_a_lost_ack_is_confirmed() {
    // Bob committed attempt 1 and sent an ACK that was lost. Alice, with no
    // resends left, starts attempt 2 on the same handle and call id. Bob
    // must welcome it and accept its CONFIRM, not test it against the
    // older live session; the invitation is not used twice.
    let no_resends = RetryPolicy { resends: 0, ..POLICY };
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello1) = bob.call(&alice, no_resends);
    let welcome1 = reply(bob.handle(1, &hello1).unwrap());
    let confirm1 = send(call.handle(&welcome1).unwrap());
    let _lost = established(bob.handle(1, &confirm1).unwrap(), &alice);
    assert!(bob.side.gate().is_honoured(&alice.reference));

    let hello2 = call.on_timeout().unwrap().unwrap();
    assert_eq!(call.attempt(), 2);
    let welcome2 = reply(bob.handle(1, &hello2).unwrap());
    let confirm2 = send(call.handle(&welcome2).unwrap());
    match bob.handle(1, &confirm2).unwrap() {
        ResponderEvent::Established { grant, reply: ack, .. } => {
            assert_eq!(grant, Grant::Contact, "now a contact; the invitation is not used again");
            assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
        }
        other => panic!("{other:?}"),
    }
    talks(&mut call, &alice, &mut bob, 1);
}

// ---- a driver loop with deterministic loss ------------------------------------------

/// Drive a caller and Bob's responder the way an application would: Bob
/// keeps handling every frame that arrives (also after he has committed),
/// and the caller handles what arrives and calls `on_timeout` when nothing
/// does. `drop` lists frames to lose, by send order (0 = first HELLO).
/// Returns the established call, or `None` if the caller gave up.
fn drive(bob: &mut Bob, caller: &Caller, policy: RetryPolicy, drop: &[usize]) -> Option<Initiator> {
    let (mut call, hello) = bob.call(caller, policy);
    let mut sent = 0usize;
    let mut to_bob: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_caller: VecDeque<Vec<u8>> = VecDeque::new();
    let mut post = |queue: &mut VecDeque<Vec<u8>>, frame: Vec<u8>| {
        if !drop.contains(&sent) {
            queue.push_back(frame);
        }
        sent += 1;
    };
    post(&mut to_bob, hello);
    for _ in 0..200 {
        while let Some(frame) = to_bob.pop_front() {
            match bob.handle(1, &frame) {
                Ok(ResponderEvent::Reply(f)) | Ok(ResponderEvent::Established { reply: f, .. }) => {
                    post(&mut to_caller, f)
                }
                _ => {}
            }
        }
        if let Some(frame) = to_caller.pop_front() {
            if let Ok(InitiatorEvent::Send(f)) = call.handle(&frame) {
                post(&mut to_bob, f);
            }
        } else if call.is_established() {
            return Some(call);
        } else {
            match call.on_timeout() {
                Ok(Some(f)) => post(&mut to_bob, f),
                Ok(None) => return Some(call),
                Err(_) => return None,
            }
        }
    }
    panic!("the drivers did not settle");
}

#[test]
fn drivers_converge_under_deterministic_loss() {
    // Frame numbers in send order with no loss: 0 HELLO, 1 WELCOME,
    // 2 CONFIRM, 3 ACK. Each loss shifts the numbers after it.
    let cases: &[(&str, RetryPolicy, &[usize])] = &[
        ("nothing lost", POLICY, &[]),
        ("HELLO lost", POLICY, &[0]),
        ("WELCOME lost", POLICY, &[1]),
        ("CONFIRM lost", POLICY, &[2]),
        ("ACK lost", POLICY, &[3]),
        ("ACK lost twice", POLICY, &[3, 5]),
        ("ACK lost, no resends: attempt rollover", RetryPolicy { resends: 0, ..POLICY }, &[3]),
        ("ACK and the next WELCOME lost", RetryPolicy { resends: 0, ..POLICY }, &[3, 5]),
    ];
    for (name, policy, drop) in cases {
        let mut bob = Bob::new();
        let alice = bob.invite();
        let mut call = drive(&mut bob, &alice, *policy, drop).unwrap_or_else(|| panic!("{name}: gave up"));
        assert!(call.is_established(), "{name}");
        assert!(bob.side.gate().is_honoured(&alice.reference), "{name}");
        talks(&mut call, &alice, &mut bob, 1);
    }
    // Every frame lost from the third on: the caller gives up in bounded
    // time and Bob is left with at most one committed grant.
    let mut bob = Bob::new();
    let alice = bob.invite();
    let all: Vec<usize> = (2..100).collect();
    assert!(drive(&mut bob, &alice, POLICY, &all).is_none());
    assert!(!bob.side.gate().is_honoured(&alice.reference), "no CONFIRM ever arrived");
}

// ---- authenticated labels and record types -----------------------------------------

#[test]
fn altering_call_id_or_attempt_in_a_hello_is_rejected_without_reply() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    for at in [1, 4, 5, 8] {
        let altered = flip(&hello, at);
        assert!(matches!(bob.handle(1, &altered), Err(WireError::Session(SessionError::Noise(_)))), "byte {at}");
    }
    assert_eq!(bob.side.pending(), 0);
    finish(&mut call, &hello, &alice, &mut bob, 1);
}

#[test]
fn a_record_cannot_change_type_and_a_refused_one_keeps_its_counter() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let _lost_ack = established(bob.handle(1, &confirm).unwrap(), &alice);

    // Bob's next DATA, sized like an ACK, relabelled as an ACK for Alice's
    // current attempt: refused (its inner type is DATA), and the genuine
    // DATA frame still delivers afterwards.
    let data = bob.seal(1, &[0x55; 31]).unwrap();
    let as_ack = [&[5u8], &confirm[1..9], &data[1..]].concat();
    assert_eq!(as_ack.len(), _lost_ack.len(), "same length as a real ACK");
    assert!(matches!(call.handle(&as_ack), Err(WireError::Stale)));
    assert!(!call.is_established());
    assert_eq!(call.handle(&data).unwrap(), InitiatorEvent::Message(vec![0x55; 31]));

    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn an_ack_relabelled_as_data_is_refused_and_still_counts_afterwards() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    // The ACK's body (a fresh, authentic record) as a DATA frame.
    let as_data = [&[4u8], &ack[9..]].concat();
    assert!(matches!(call.handle(&as_data), Err(WireError::Stale)));
    assert!(!call.is_established());
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established, "its counter was not used up");
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_confirm_body_cannot_pose_as_data() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    // Alice's CONFIRM, its body presented as a DATA frame: refused (its
    // counter was already used when Bob committed it; its inner type is
    // CONFIRM in any case), and Bob's session is unaffected.
    let as_data = [&[4u8], &confirm[9..]].concat();
    assert!(matches!(
        bob.handle(1, &as_data),
        Err(WireError::Session(SessionError::Replay)) | Err(WireError::Stale)
    ));
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn a_confirm_relabelled_with_another_attempt_is_refused() {
    let no_resends = RetryPolicy { resends: 0, ..POLICY };
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello1) = bob.call(&alice, no_resends);
    let welcome1 = reply(bob.handle(1, &hello1).unwrap());
    let confirm1 = send(call.handle(&welcome1).unwrap()); // lost
    let hello2 = call.on_timeout().unwrap().unwrap();
    let welcome2 = reply(bob.handle(1, &hello2).unwrap());
    let confirm2 = send(call.handle(&welcome2).unwrap());
    // Attempt 1's CONFIRM relabelled as attempt 2: the inner labels say 1.
    let relabelled = [&confirm2[..9], &confirm1[9..]].concat();
    assert!(matches!(bob.handle(1, &relabelled), Err(WireError::Stale)));
    let ack = established(bob.handle(1, &confirm2).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
}

// ---- deadlines (injected clock) ---------------------------------------------------------

#[test]
fn an_answered_handshake_expires_without_its_confirm() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    bob.advance(PENDING_TIMEOUT - Duration::from_secs(1));
    assert_eq!(bob.side.pending(), 1);
    bob.advance(Duration::from_secs(1));
    assert!(matches!(bob.handle(1, &confirm), Err(WireError::Stale)), "nothing sent");
    assert_eq!(bob.side.pending(), 0);
    assert!(!bob.side.gate().is_honoured(&alice.reference));
}

#[test]
fn an_idle_session_expires_and_is_refused_both_ways() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let mut call = establish(&alice, &mut bob, 1);
    bob.advance(SESSION_IDLE_TIMEOUT - Duration::from_secs(1));
    talks(&mut call, &alice, &mut bob, 1); // traffic resets the deadline
    bob.advance(SESSION_IDLE_TIMEOUT);
    let frame = call.seal(b"still there?").unwrap();
    assert!(matches!(bob.handle(1, &frame), Err(WireError::NoSession)), "nothing delivered, nothing sent");
    assert!(matches!(bob.seal(1, b"hi"), Err(WireError::NoSession)));
    assert!(!bob.side.is_live(&1));
}

#[test]
fn the_expiry_is_checked_on_every_operation_not_only_on_timeouts() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let _call = establish(&alice, &mut bob, 1);
    bob.advance(SESSION_IDLE_TIMEOUT);
    // A frame for some other caller arrives first; the idle session goes.
    let _ = bob.handle(99, &[200]);
    assert!(!bob.side.is_live(&1));
    let mut bob = Bob::new();
    let alice = bob.invite();
    let _call = establish(&alice, &mut bob, 1);
    bob.advance(SESSION_IDLE_TIMEOUT);
    let expired = bob.side.expire(bob.now);
    assert_eq!(expired.sessions, vec![1]);
}

// ---- atomic revocation ---------------------------------------------------------------------

/// Alice established, plus a recorded HELLO answered on another handle (a
/// cached WELCOME) and her CONFIRM (a cached ACK).
fn revocable() -> (Bob, Caller, Initiator, Vec<u8>, Vec<u8>) {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    // A replay of a later HELLO from Alice as a contact, on handle 2.
    let (_c2, hello2) = bob.call(&Caller { key: alice.key.clone(), reference: alice.reference }, POLICY);
    reply(bob.handle(2, &hello2).unwrap());
    (bob, alice, call, hello2, confirm)
}

fn assert_cut_off(bob: &mut Bob, call: &mut Initiator, hello2: &[u8], confirm: &[u8]) {
    assert_eq!(bob.side.pending(), 0, "cached WELCOMEs dropped with the grant");
    assert!(!bob.side.is_live(&1), "sessions ended with the grant");
    let frame = call.seal(b"hello?").unwrap();
    assert!(bob.handle(1, &frame).is_err(), "no data in");
    assert!(bob.seal(1, b"hi").is_err(), "no data out");
    assert!(bob.handle(1, confirm).is_err(), "no cached ACK");
    assert!(bob.handle(2, hello2).is_err(), "no cached WELCOME");
    assert_eq!(bob.side.pending(), 0);
    assert!(!bob.side.is_live(&1));
}

#[test]
fn blocking_cuts_off_data_and_cached_replies_at_once() {
    let (mut bob, alice, mut call, hello2, confirm) = revocable();
    bob.side.block(alice.key.public());
    assert_cut_off(&mut bob, &mut call, &hello2, &confirm);
}

#[test]
fn removing_a_contact_cuts_off_data_and_cached_replies_at_once() {
    let (mut bob, alice, mut call, hello2, confirm) = revocable();
    bob.side.remove_contact(alice.key.public());
    assert_cut_off(&mut bob, &mut call, &hello2, &confirm);
}

// ---- frame limits ---------------------------------------------------------------

#[test]
fn the_largest_message_round_trips_both_ways() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let mut call = establish(&alice, &mut bob, 1);
    let largest: Vec<u8> = (0..MAX_DATA).map(|i| i as u8).collect();
    let frame = call.seal(&largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME, "the largest data frame is exactly the limit");
    assert_eq!(
        bob.handle(1, &frame).unwrap(),
        ResponderEvent::Message { peer: alice.key.public(), plaintext: largest.clone() }
    );
    let frame = bob.seal(1, &largest).unwrap();
    assert_eq!(frame.len(), MAX_FRAME);
    assert_eq!(call.handle(&frame).unwrap(), InitiatorEvent::Message(largest.clone()));
    let too_long = [&largest[..], b"!"].concat();
    assert!(matches!(call.seal(&too_long), Err(WireError::Session(SessionError::TooLarge))));
    assert!(matches!(bob.seal(1, &too_long), Err(WireError::Session(SessionError::TooLarge))));
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

// ---- sessions per caller, caps (2026-11-20 audit HIGH-02) ----------------------

#[test]
fn the_default_limits_are_the_named_constants() {
    let limits = Limits::default();
    assert_eq!((limits.pending, limits.pending_per_caller, limits.sessions), (MAX_PENDING, MAX_PENDING_PER_CALLER, MAX_SESSIONS));
}

#[test]
fn one_authorised_caller_cannot_fill_the_pending_table_for_others() {
    let mut bob = Bob::with_limits(Limits { pending: 6, pending_per_caller: 4, sessions: 16 });
    let (alice, carol) = (bob.invite(), bob.invite());
    // Alice opens ten calls from ten handles and never confirms any.
    let mut answered = 0;
    for tag in 100..110 {
        let (_, hello) = bob.call(&alice, POLICY);
        match bob.handle(tag, &hello) {
            Ok(ResponderEvent::Reply(_)) => answered += 1,
            Err(WireError::Busy) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(answered, 4, "her share of answered handshakes");
    assert_eq!(bob.side.pending(), 4);
    // Carol still gets through.
    let mut call = establish(&carol, &mut bob, 1);
    talks(&mut call, &carol, &mut bob, 1);
    // A repeat of one of Alice's answered HELLOs is still answered (it
    // replaces nothing and adds nothing).
    assert_eq!(bob.side.pending(), 4);
}

#[test]
fn a_reconnecting_caller_keeps_one_session_on_its_new_handle() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let _old = establish(&alice, &mut bob, 1);
    let mut new = establish(&alice, &mut bob, 2);
    assert_eq!(bob.side.sessions(), 1, "one session per caller key");
    assert!(bob.side.is_live(&2) && !bob.side.is_live(&1));
    talks(&mut new, &alice, &mut bob, 2);
}

#[test]
fn a_caller_whose_handle_changes_after_a_lost_ack_keeps_its_session() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let _lost = established(bob.handle(1, &confirm).unwrap(), &alice);
    // Her resend arrives on a new handle: the cached ACK is sent there.
    let again = call.on_timeout().unwrap().unwrap();
    let ack = reply(bob.handle(2, &again).unwrap());
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert!(bob.side.is_live(&1), "a repeated CONFIRM alone moves nothing");
    // Her first fresh message on the new handle moves the session there.
    let frame = call.seal(b"from my new handle").unwrap();
    assert!(matches!(bob.handle(2, &frame), Ok(ResponderEvent::Message { .. })));
    assert!(bob.side.is_live(&2) && !bob.side.is_live(&1));
    assert_eq!(bob.side.sessions(), 1);
    let frame = bob.seal(2, b"answer on the new handle").unwrap();
    assert_eq!(call.handle(&frame).unwrap(), InitiatorEvent::Message(b"answer on the new handle".to_vec()));
}

#[test]
fn a_replayed_confirm_or_data_frame_cannot_redirect_a_session() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    let data = call.seal(b"hello").unwrap();
    assert!(matches!(bob.handle(1, &data), Ok(ResponderEvent::Message { .. })));
    // Someone replays both from handle 99.
    let _ = bob.handle(99, &confirm);
    assert!(matches!(bob.handle(99, &data), Err(WireError::Session(SessionError::Replay))));
    assert!(bob.side.is_live(&1) && !bob.side.is_live(&99), "the session stays on Alice's handle");
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn the_session_cap_refuses_a_new_caller_and_commits_nothing() {
    let mut bob = Bob::with_limits(Limits { pending: 16, pending_per_caller: 4, sessions: 2 });
    let (alice, carol, dave) = (bob.invite(), bob.invite(), bob.invite());
    establish(&alice, &mut bob, 1);
    establish(&carol, &mut bob, 2);
    let (mut call, hello) = bob.call(&dave, POLICY);
    let welcome = reply(bob.handle(3, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    assert!(matches!(bob.handle(3, &confirm), Err(WireError::Busy)), "nothing sent");
    assert!(!bob.side.gate().is_honoured(&dave.reference), "the invitation is not used");
    // A known caller may still replace its own session at the cap.
    establish(&alice, &mut bob, 4);
    assert_eq!(bob.side.sessions(), 2);
    // Once a place is free, Dave gets in on the same invitation.
    bob.side.remove_contact(carol.key.public());
    let ack = established(bob.handle(3, &confirm).unwrap(), &dave);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
}

#[test]
fn replaying_a_confirm_from_many_handles_keeps_one_candidate() {
    let mut bob = Bob::new();
    let alice = bob.invite();
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    let ack = established(bob.handle(1, &confirm).unwrap(), &alice);
    assert_eq!(call.handle(&ack).unwrap(), InitiatorEvent::Established);
    for tag in 1_000..1_200 {
        let _ = bob.handle(tag, &confirm);
    }
    assert_eq!(bob.side.candidate_handles(), 1, "at most one candidate per caller");
    assert!(bob.side.is_live(&1));
    talks(&mut call, &alice, &mut bob, 1);
}

#[test]
fn evicting_a_peer_from_a_handle_drops_its_candidates_too() {
    let mut bob = Bob::new();
    let (alice, carol) = (bob.invite(), bob.invite());
    // Alice's session on handle 1, with a candidate handle 7.
    let (mut call, hello) = bob.call(&alice, POLICY);
    let welcome = reply(bob.handle(1, &hello).unwrap());
    let confirm = send(call.handle(&welcome).unwrap());
    established(bob.handle(1, &confirm).unwrap(), &alice);
    reply(bob.handle(7, &confirm).unwrap());
    assert_eq!(bob.side.candidate_handles(), 1);
    // Carol completes a handshake on handle 1: Alice is evicted from it.
    let mut carol_call = establish(&carol, &mut bob, 1);
    assert_eq!(bob.side.candidate_handles(), 0, "Alice's candidate went with her");
    assert_eq!(bob.side.sessions(), 1);
    talks(&mut carol_call, &carol, &mut bob, 1);
}
