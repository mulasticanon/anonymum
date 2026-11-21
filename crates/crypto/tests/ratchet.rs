//! The Double Ratchet (unreviewed prototype): turn-arounds, out-of-order
//! and dropped messages, replay, forward secrecy, post-compromise security,
//! denial-of-service limits, and its use for data frames in the wire layer.

use std::time::Instant;

use anonymum_crypto::ratchet::{HEADER_LEN, MAX_SKIP_PER_STEP, MAX_TOTAL_SKIPPED};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, WireError};
use anonymum_crypto::{random_bytes, ContactIdentity, Network, Now, Purpose, Ratchet, RatchetError, RatchetKey, StaticKey};

const NET: Network = [9; 32];

/// Small-order Curve25519 points (RFC 7748 section 6.1 lists why they are
/// refused): zero, one, and a point of order 8.
const SMALL_ORDER: [[u8; 32]; 3] = [
    [0; 32],
    {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09,
        0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
];

/// Alice starts (knows Bob's ratchet key); Bob answers.
fn pair() -> (Ratchet, Ratchet) {
    let root = random_bytes();
    let bob_key = RatchetKey::generate();
    let bob_public = bob_key.public();
    (Ratchet::initiate(&root, NET, bob_public).unwrap(), Ratchet::respond(&root, NET, bob_key))
}

fn open(r: &mut Ratchet, m: &[u8]) -> Vec<u8> {
    r.decrypt(m).unwrap().to_vec()
}

/// The header fields of a message: ratchet key, previous chain length, number.
fn header(m: &[u8]) -> ([u8; 32], u32, u32) {
    let w = |at: usize| u32::from_be_bytes(m[at..at + 4].try_into().unwrap());
    (m[..32].try_into().unwrap(), w(32), w(36))
}

fn with_header(m: &[u8], dh: [u8; 32], pn: u32, n: u32) -> Vec<u8> {
    let mut out = m.to_vec();
    out[..32].copy_from_slice(&dh);
    out[32..36].copy_from_slice(&pn.to_be_bytes());
    out[36..40].copy_from_slice(&n.to_be_bytes());
    out
}

// ---- (a) bidirectional chat with DH ratchet turn-arounds -----------------------------

#[test]
fn a_bidirectional_chat_turns_the_ratchet_every_time_the_speaker_changes() {
    let (mut alice, mut bob) = pair();
    assert_eq!(bob.encrypt(b"too early").unwrap_err(), RatchetError::NoSendingChain);
    let mut alice_keys = vec![alice.public()];
    let mut bob_keys = vec![bob.public()];
    for round in 0..6u8 {
        for i in 0..3u8 {
            let m = alice.encrypt(&[round, i, 0xA]).unwrap();
            assert_eq!(header(&m).0, alice.public(), "the header names the sender's ratchet key");
            assert_eq!(open(&mut bob, &m), [round, i, 0xA]);
        }
        bob_keys.push(bob.public());
        for i in 0..2u8 {
            assert_eq!(open(&mut alice, &bob.encrypt(&[round, i, 0xB]).unwrap()), [round, i, 0xB]);
        }
        alice_keys.push(alice.public());
    }
    // Every turn-around gave the receiving side a fresh ratchet key.
    for keys in [&alice_keys, &bob_keys] {
        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), keys.len(), "a ratchet key was reused");
    }
    assert_eq!(alice.skipped_keys() + bob.skipped_keys(), 0);
}

#[test]
fn messages_are_bound_to_the_network_and_hide_their_content() {
    let root = random_bytes();
    let bob_key = RatchetKey::generate();
    let bob_public = bob_key.public();
    let mut alice = Ratchet::initiate(&root, NET, bob_public).unwrap();
    let secret = b"the launch code is 0000";
    let m = alice.encrypt(secret).unwrap();
    assert!(!m.windows(secret.len()).any(|w| w == secret));
    let mut elsewhere = Ratchet::respond(&root, [1; 32], bob_key.copy_for_tests());
    assert_eq!(elsewhere.decrypt(&m).unwrap_err(), RatchetError::Decrypt, "another network");
    let mut other_root = Ratchet::respond(&random_bytes(), NET, bob_key.copy_for_tests());
    assert_eq!(other_root.decrypt(&m).unwrap_err(), RatchetError::Decrypt, "another root key");
    let mut bob = Ratchet::respond(&root, NET, bob_key);
    assert_eq!(open(&mut bob, &m), secret);
}

// ---- (b) out-of-order and dropped messages --------------------------------------------

#[test]
fn out_of_order_and_dropped_messages_across_the_current_and_the_previous_chain() {
    let (mut alice, mut bob) = pair();
    let a: Vec<Vec<u8>> = (0..5u8).map(|i| alice.encrypt(&[b'a', i]).unwrap()).collect();
    // Same chain, out of order.
    assert_eq!(open(&mut bob, &a[3]), b"a\x03");
    assert_eq!(bob.skipped_keys(), 3, "a0, a1, a2 skipped");
    assert_eq!(open(&mut bob, &a[0]), b"a\x00");
    assert_eq!(bob.skipped_keys(), 2);
    // Bob answers; Alice turns the ratchet and writes on a new chain.
    assert_eq!(open(&mut alice, &bob.encrypt(b"b0").unwrap()), b"b0");
    let c: Vec<Vec<u8>> = (0..3u8).map(|i| alice.encrypt(&[b'c', i]).unwrap()).collect();
    assert_eq!(header(&c[0]).1, 5, "the new chain announces the old one's length");
    // The new chain's second message first: a4 (the old chain's tail) and c0
    // are skipped, a1 and a2 are still cached.
    assert_eq!(open(&mut bob, &c[1]), b"c\x01");
    assert_eq!(bob.skipped_keys(), 4, "a1, a2, a4, c0");
    // Previous-chain messages after the ratchet turned.
    assert_eq!(open(&mut bob, &a[4]), b"a\x04");
    assert_eq!(open(&mut bob, &c[0]), b"c\x00");
    assert_eq!(open(&mut bob, &a[1]), b"a\x01");
    assert_eq!(open(&mut bob, &c[2]), b"c\x02");
    // a2 is dropped for good: its key waits in the cache, nothing else does.
    assert_eq!(bob.skipped_keys(), 1);
    assert_eq!(open(&mut bob, &a[2]), b"a\x02", "a late message still opens");
    assert_eq!(bob.skipped_keys(), 0);
}

#[test]
fn many_messages_in_reverse_order_all_open() {
    let (mut alice, mut bob) = pair();
    let m: Vec<Vec<u8>> = (0..=MAX_SKIP_PER_STEP).map(|i| alice.encrypt(&i.to_be_bytes()).unwrap()).collect();
    for (i, message) in m.iter().enumerate().rev() {
        assert_eq!(open(&mut bob, message), (i as u32).to_be_bytes());
    }
    assert_eq!(bob.skipped_keys(), 0);
}

// ---- (c) replay ---------------------------------------------------------------------------

#[test]
fn a_replay_of_any_opened_message_fails_and_changes_nothing() {
    let (mut alice, mut bob) = pair();
    let a: Vec<Vec<u8>> = (0..4u8).map(|i| alice.encrypt(&[i]).unwrap()).collect();
    open(&mut bob, &a[0]); // in order
    open(&mut bob, &a[2]); // skips a1
    open(&mut bob, &a[1]); // from the cache
    open(&mut alice, &bob.encrypt(b"turn").unwrap());
    let c0 = alice.encrypt(b"c0").unwrap();
    open(&mut bob, &c0); // the ratchet turns; a3 stays cached
    assert_eq!(bob.skipped_keys(), 1);
    for (name, message) in [("in order", &a[0]), ("skipped", &a[1]), ("after a skip", &a[2]), ("new chain", &c0)] {
        assert!(bob.decrypt(message).is_err(), "replay of a {name} message opened");
    }
    assert_eq!(bob.decrypt(&c0).unwrap_err(), RatchetError::Replay, "the current chain says so plainly");
    assert_eq!(bob.skipped_keys(), 1, "replays added and removed nothing");
    // Everything still works afterwards.
    assert_eq!(open(&mut bob, &a[3]), [3]);
    assert!(bob.decrypt(&a[3]).is_err(), "a cached key is erased once used");
    assert_eq!(open(&mut bob, &alice.encrypt(b"c1").unwrap()), b"c1");
}

// ---- (d) per-message forward secrecy ----------------------------------------------------

#[test]
fn a_state_taken_after_message_n_cannot_open_message_n_minus_1() {
    let (mut alice, mut bob) = pair();
    let m: Vec<Vec<u8>> = (0..6u8).map(|i| alice.encrypt(&[i]).unwrap()).collect();
    for n in 0..m.len() {
        open(&mut bob, &m[n]);
        let stolen = bob.copy_state_for_tests();
        for earlier in &m[..=n] {
            assert!(stolen.copy_state_for_tests().decrypt(earlier).is_err(), "message {n} or earlier opened");
        }
    }
    // Across a turn of the ratchet as well: the old chain's keys are gone.
    open(&mut alice, &bob.encrypt(b"turn").unwrap());
    let next = alice.encrypt(b"new chain").unwrap();
    open(&mut bob, &next);
    let mut stolen = bob.copy_state_for_tests();
    for message in m.iter().chain([&next]) {
        assert!(stolen.decrypt(message).is_err());
    }
}

#[test]
fn every_message_in_a_chain_gets_its_own_key() {
    // The same plaintext sent twice in one chain: with the zero nonce, a
    // repeated message key would repeat the keystream and so the ciphertext
    // body. A message's key also cannot open its neighbour.
    let (mut alice, mut bob) = pair();
    let first = alice.encrypt(b"same words").unwrap();
    let second = alice.encrypt(b"same words").unwrap();
    assert_eq!(header(&first).0, header(&second).0, "one chain");
    let body = |m: &[u8]| m[HEADER_LEN..m.len() - 16].to_vec();
    assert_ne!(body(&first), body(&second), "each message has a fresh key");
    let relabelled = with_header(&second, header(&first).0, 0, 0);
    assert_eq!(bob.decrypt(&relabelled).unwrap_err(), RatchetError::Decrypt);
    assert_eq!(open(&mut bob, &first), b"same words");
    assert_eq!(open(&mut bob, &second), b"same words");
}

#[test]
fn the_sender_keeps_no_key_for_what_it_already_sent() {
    let (mut alice, mut bob) = pair();
    let m0 = alice.encrypt(b"m0").unwrap();
    // A thief with Alice's state now cannot open m0 (she cannot either: her
    // sending chain has moved on and she keeps no receiving key for it).
    let mut stolen = alice.copy_state_for_tests();
    assert!(stolen.decrypt(&m0).is_err());
    assert_eq!(open(&mut bob, &m0), b"m0");
}

// ---- (e) post-compromise security -------------------------------------------------------

#[test]
fn one_dh_round_trip_after_a_compromise_locks_the_thief_out() {
    let (mut alice, mut bob) = pair();
    open(&mut bob, &alice.encrypt(b"hello").unwrap());
    open(&mut alice, &bob.encrypt(b"hi").unwrap());
    // Eve copies Bob's whole state.
    let eve = bob.copy_state_for_tests();
    // The compromise is real: she reads Alice's next message.
    let x = alice.encrypt(b"x").unwrap();
    assert_eq!(open(&mut eve.copy_state_for_tests(), &x), b"x");
    // One round trip: Bob answers with a fresh ratchet key, Alice answers
    // that with a fresh key of her own.
    open(&mut bob, &x);
    let y = bob.encrypt(b"y").unwrap();
    open(&mut alice, &y);
    let z = alice.encrypt(b"z").unwrap();
    // Eve, from the stolen state, and from the state she would have after
    // reading x, opens neither the reply to Bob nor anything after it.
    let mut eve_now = eve.copy_state_for_tests();
    assert!(eve_now.decrypt(&z).is_err(), "from the stolen state");
    let mut eve_after_x = eve.copy_state_for_tests();
    open(&mut eve_after_x, &x);
    assert!(eve_after_x.decrypt(&z).is_err(), "after following x");
    let later: Vec<Vec<u8>> = (0..3u8).map(|i| alice.encrypt(&[i]).unwrap()).collect();
    for m in &later {
        assert!(eve.copy_state_for_tests().decrypt(m).is_err());
        assert!(eve_after_x.copy_state_for_tests().decrypt(m).is_err());
    }
    // Bob is unaffected.
    assert_eq!(open(&mut bob, &z), b"z");
    for (i, m) in later.iter().enumerate() {
        assert_eq!(open(&mut bob, m), [i as u8]);
    }
}

// ---- (f) denial-of-service limits -------------------------------------------------------

/// What can be observed from outside: Bob's ratchet key, skipped keys, and
/// whether he can still read the genuine next message.
fn assert_unchanged_and_working(bob: &mut Ratchet, before: ([u8; 32], usize), genuine: &[u8], expect: &[u8]) {
    assert_eq!((bob.public(), bob.skipped_keys()), before, "state changed");
    assert_eq!(open(bob, genuine), expect);
}

#[test]
fn a_huge_message_number_is_refused_at_once_without_allocating_keys() {
    let (mut alice, mut bob) = pair();
    open(&mut bob, &alice.encrypt(b"start").unwrap());
    let genuine = alice.encrypt(b"next").unwrap();
    let (dh, pn, _) = header(&genuine);
    let before = (bob.public(), bob.skipped_keys());
    let started = Instant::now();
    for n in [MAX_SKIP_PER_STEP + 2, 1_000_000, u32::MAX] {
        // Same chain: n far ahead.
        assert_eq!(bob.decrypt(&with_header(&genuine, dh, pn, n)).unwrap_err(), RatchetError::TooManySkipped);
        // A new chain: n far ahead, or a previous chain claimed far longer.
        let fresh = RatchetKey::generate().public();
        assert_eq!(bob.decrypt(&with_header(&genuine, fresh, 0, n)).unwrap_err(), RatchetError::TooManySkipped);
        assert_eq!(bob.decrypt(&with_header(&genuine, fresh, n, 0)).unwrap_err(), RatchetError::TooManySkipped);
    }
    assert!(started.elapsed().as_secs() < 5, "refusals must be cheap");
    assert_unchanged_and_working(&mut bob, before, &genuine, b"next");
}

#[test]
fn the_skip_limit_is_exact_for_genuine_messages() {
    let (mut alice, mut bob) = pair();
    // Exactly MAX_SKIP_PER_STEP skipped: allowed.
    let m: Vec<Vec<u8>> = (0..=MAX_SKIP_PER_STEP).map(|i| alice.encrypt(&i.to_be_bytes()).unwrap()).collect();
    open(&mut bob, m.last().unwrap());
    assert_eq!(bob.skipped_keys(), MAX_SKIP_PER_STEP as usize);
    // One more than that in the same chain: refused, nothing cached.
    let ahead: Vec<Vec<u8>> = (0..=MAX_SKIP_PER_STEP + 1).map(|_| alice.encrypt(b"x").unwrap()).collect();
    let before = (bob.public(), bob.skipped_keys());
    assert_eq!(bob.decrypt(ahead.last().unwrap()).unwrap_err(), RatchetError::TooManySkipped);
    assert_unchanged_and_working(&mut bob, before, &ahead[0], b"x");
}

#[test]
fn the_skipped_cache_never_exceeds_its_cap() {
    let (mut alice, mut bob) = pair();
    for _ in 0..6 {
        let held: Vec<Vec<u8>> = (0..=MAX_SKIP_PER_STEP).map(|_| alice.encrypt(b"x").unwrap()).collect();
        open(&mut bob, held.last().unwrap());
        assert!(bob.skipped_keys() <= MAX_TOTAL_SKIPPED);
        open(&mut alice, &bob.encrypt(b"turn").unwrap());
    }
    assert_eq!(bob.skipped_keys(), MAX_TOTAL_SKIPPED);
}

#[test]
fn a_small_order_ratchet_key_is_refused_before_any_key_agreement() {
    let (mut alice, mut bob) = pair();
    open(&mut bob, &alice.encrypt(b"start").unwrap());
    let genuine = alice.encrypt(b"next").unwrap();
    let before = (bob.public(), bob.skipped_keys());
    for weak in SMALL_ORDER {
        assert_eq!(bob.decrypt(&with_header(&genuine, weak, 0, 0)).unwrap_err(), RatchetError::WeakKey);
        assert_eq!(bob.decrypt(&with_header(&genuine, weak, 0, u32::MAX)).unwrap_err(), RatchetError::WeakKey);
        assert_eq!(Ratchet::initiate(&[1; 32], NET, weak).err(), Some(RatchetError::WeakKey));
        assert_eq!(Ratchet::respond_to(&[1; 32], NET, RatchetKey::generate(), weak).err(), Some(RatchetError::WeakKey));
    }
    assert_unchanged_and_working(&mut bob, before, &genuine, b"next");
}

#[test]
fn malformed_tampered_and_refused_messages_change_nothing() {
    let (mut alice, mut bob) = pair();
    let m = alice.encrypt(b"hello").unwrap();
    let before = (bob.public(), bob.skipped_keys());
    assert_eq!(bob.decrypt(&m[..HEADER_LEN + 15]).unwrap_err(), RatchetError::Malformed);
    for at in [0, 33, 39, HEADER_LEN, m.len() - 1] {
        let mut bad = m.clone();
        bad[at] ^= 1;
        assert!(bob.decrypt(&bad).is_err(), "byte {at} tampered");
    }
    assert_eq!(bob.decrypt_if(&m, |_| false).unwrap_err(), RatchetError::Refused);
    assert_unchanged_and_working(&mut bob, before, &m, b"hello");
}

#[test]
fn oversized_plaintext_is_refused() {
    let (mut alice, _bob) = pair();
    let max = anonymum_crypto::ratchet::MAX_PLAINTEXT;
    assert_eq!(alice.encrypt(&vec![0; max + 1]).unwrap_err(), RatchetError::TooLarge);
    assert!(alice.encrypt(&vec![0; max]).is_ok());
}

// ---- (g) the wire layer: bootstrap and handle migration ---------------------------------

fn now() -> Now {
    Now { unix: 1_000, mono: Instant::now() }
}

struct World {
    bob: Responder<u32>,
    caller: StaticKey,
    call: Initiator,
    confirm: Vec<u8>,
}

/// Alice calls Bob on handle 1 with an invitation; CONFIRM sent, ACK not
/// yet delivered.
fn confirming() -> (World, Vec<u8>) {
    let me = ContactIdentity::generate_at(0);
    let mut bob = Responder::for_identity(&me, NET);
    let caller = StaticKey::generate();
    let invitation = me.invite(NET, caller.public(), Purpose::Contact, 5_000);
    let reference = invitation.id;
    bob.record_invitation(invitation, now()).unwrap();
    let (mut call, hello) = Initiator::start(&caller, me.handshake_key().public(), NET, reference).unwrap();
    let ResponderEvent::Reply(welcome) = bob.handle(1, &hello, now()).unwrap() else { panic!() };
    let InitiatorEvent::Send(confirm) = call.handle(&welcome).unwrap() else { panic!() };
    let ResponderEvent::Established { reply: ack, .. } = bob.handle(1, &confirm, now()).unwrap() else { panic!() };
    (World { bob, caller, call, confirm }, ack)
}

fn established() -> World {
    let (mut w, ack) = confirming();
    assert_eq!(w.call.handle(&ack).unwrap(), InitiatorEvent::Established);
    w
}

fn message(event: ResponderEvent) -> Vec<u8> {
    match event {
        ResponderEvent::Message { plaintext, .. } => plaintext,
        other => panic!("{other:?}"),
    }
}

#[test]
fn over_the_wire_either_side_may_speak_first_and_turns_keep_working() {
    let mut w = established();
    // The answerer first (it started the ratchet), then several turns.
    let f = w.bob.seal(&1, b"bob first", now()).unwrap();
    assert_eq!(w.call.handle(&f).unwrap(), InitiatorEvent::Message(b"bob first".to_vec()));
    for round in 0..4u8 {
        let f = w.call.seal(&[round, 1]).unwrap();
        assert_eq!(message(w.bob.handle(1, &f, now()).unwrap()), [round, 1]);
        let f = w.bob.seal(&1, &[round, 2], now()).unwrap();
        assert_eq!(w.call.handle(&f).unwrap(), InitiatorEvent::Message(vec![round, 2]));
    }
    // And the caller first on a fresh session.
    let mut w = established();
    let f = w.call.seal(b"alice first").unwrap();
    assert_eq!(message(w.bob.handle(1, &f, now()).unwrap()), b"alice first");
}

#[test]
fn data_frames_survive_reordering_and_refuse_replay_over_the_wire() {
    let mut w = established();
    let frames: Vec<Vec<u8>> = (0..5u8).map(|i| w.call.seal(&[i]).unwrap()).collect();
    for i in [3usize, 0, 4, 1, 2] {
        assert_eq!(message(w.bob.handle(1, &frames[i], now()).unwrap()), [i as u8]);
    }
    for f in &frames {
        assert!(matches!(w.bob.handle(1, f, now()), Err(WireError::Ratchet(_))));
    }
}

#[test]
fn data_that_reaches_the_caller_before_the_ack_is_held_then_opened() {
    let (mut w, ack) = confirming();
    let early: Vec<Vec<u8>> = (0..3u8).map(|i| w.bob.seal(&1, &[b'e', i], now()).unwrap()).collect();
    for f in early.iter().rev() {
        assert_eq!(w.call.handle(f).unwrap(), InitiatorEvent::Held);
    }
    assert!(!w.call.is_established());
    assert_eq!(w.call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert_eq!(w.call.take_early(), vec![b"e\x02".to_vec(), b"e\x01".to_vec(), b"e\x00".to_vec()]);
    assert!(w.call.take_early().is_empty(), "each early message is returned once");
}

#[test]
fn the_early_data_buffer_is_bounded() {
    let (mut w, ack) = confirming();
    let cap = anonymum_crypto::wire::MAX_EARLY_DATA;
    let frames: Vec<Vec<u8>> = (0..=cap).map(|i| w.bob.seal(&1, &[i as u8], now()).unwrap()).collect();
    for f in &frames[..cap] {
        assert_eq!(w.call.handle(f).unwrap(), InitiatorEvent::Held);
    }
    assert!(matches!(w.call.handle(&frames[cap]), Err(WireError::Busy)));
    assert_eq!(w.call.handle(&ack).unwrap(), InitiatorEvent::Established);
    assert_eq!(w.call.take_early().len(), cap);
    // The refused one was never consumed: it still opens now.
    assert_eq!(w.call.handle(&frames[cap]).unwrap(), InitiatorEvent::Message(vec![cap as u8]));
}

#[test]
fn a_replayed_confirm_never_moves_a_session_only_fresh_ratcheted_data_does() {
    let mut w = established();
    let old = w.call.seal(b"first").unwrap();
    assert_eq!(message(w.bob.handle(1, &old, now()).unwrap()), b"first");
    // A replayed CONFIRM from handle 2 is answered with the cached ACK and
    // makes handle 2 a candidate, nothing more.
    assert!(matches!(w.bob.handle(2, &w.confirm, now()), Ok(ResponderEvent::Reply(_))));
    assert_eq!(w.bob.candidate_handles(), 1);
    assert!(w.bob.is_live(&1) && !w.bob.is_live(&2));
    // A replayed data frame from the candidate handle: refused, no move.
    assert!(matches!(w.bob.handle(2, &old, now()), Err(WireError::Ratchet(RatchetError::Replay))));
    // A tampered fresh frame: refused, no move.
    let fresh = w.call.seal(b"from handle 2").unwrap();
    let mut forged = fresh.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(w.bob.handle(2, &forged, now()), Err(WireError::Ratchet(RatchetError::Decrypt))));
    // A frame relabelled as coming from another chain: refused, no move.
    let mut relabelled = fresh.clone();
    relabelled[1..33].copy_from_slice(&RatchetKey::generate().public());
    assert!(w.bob.handle(2, &relabelled, now()).is_err());
    assert!(w.bob.is_live(&1) && !w.bob.is_live(&2), "still on handle 1");
    // The genuine fresh frame moves it.
    assert_eq!(message(w.bob.handle(2, &fresh, now()).unwrap()), b"from handle 2");
    assert!(w.bob.is_live(&2) && !w.bob.is_live(&1));
    assert_eq!(w.bob.candidate_handles(), 0);
    let reply = w.bob.seal(&2, b"answer", now()).unwrap();
    assert_eq!(w.call.handle(&reply).unwrap(), InitiatorEvent::Message(b"answer".to_vec()));
    let _ = w.caller;
}

#[test]
fn a_data_frame_from_a_handle_that_is_not_even_a_candidate_is_refused() {
    let mut w = established();
    let fresh = w.call.seal(b"x").unwrap();
    assert!(matches!(w.bob.handle(3, &fresh, now()), Err(WireError::NoSession)));
    // Nothing was used up: it still opens on the right handle.
    assert_eq!(message(w.bob.handle(1, &fresh, now()).unwrap()), b"x");
}

#[test]
fn every_handshake_gives_new_ratchet_keys() {
    // Two sessions between the same keys must not share message keys: the
    // first data frame of one does not open in the other.
    let mut a = established();
    let mut b = established();
    let fa = a.call.seal(b"same text").unwrap();
    let fb = b.call.seal(b"same text").unwrap();
    assert_ne!(fa, fb);
    assert!(b.bob.handle(1, &fa, now()).is_err());
    assert!(a.bob.handle(1, &fb, now()).is_err());
    assert_eq!(message(a.bob.handle(1, &fa, now()).unwrap()), b"same text");
}
