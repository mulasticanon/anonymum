//! Durable grant state: encrypted gate snapshots, restore across a
//! simulated restart, replay refusal, pruning, and loud failures (issues
//! file R8, audit MED-04).

use std::time::{Duration, Instant};

use anonymum_crypto::snapshot::MIN_SNAPSHOT_LEN;
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{
    write_atomically, ContactError, ContactIdentity, Grant, Invitation, Network, Now, Purpose, SnapshotError,
    StaticKey, StorageKey, CLOCK_SKEW_SECS,
};

const NET: Network = [9; 32];
const NOW: u64 = 1_000;
const POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 1, base_wait: Duration::from_secs(10) };

fn at(unix: u64) -> Now {
    Now { unix, mono: Instant::now() }
}

fn now() -> Now {
    at(NOW)
}

/// Run a call to the end. Returns the grant, or the error that stopped it.
fn call(side: &mut Responder<u32>, key: &StaticKey, peer: [u8; 32], reference: [u8; 32], tag: u32, when: Now) -> Result<Grant, WireError> {
    let (mut caller, hello) = Initiator::start_with(key, peer, NET, reference, POLICY).unwrap();
    let ResponderEvent::Reply(welcome) = side.handle(tag, &hello, when)? else { panic!("expected WELCOME") };
    let InitiatorEvent::Send(confirm) = caller.handle(&welcome).unwrap() else { panic!("expected CONFIRM") };
    let ResponderEvent::Established { grant, reply, .. } = side.handle(tag, &confirm, when)? else { panic!() };
    assert_eq!(caller.handle(&reply).unwrap(), InitiatorEvent::Established);
    Ok(grant)
}

fn invite(bob: &ContactIdentity, key: &StaticKey, expires_at: u64) -> Invitation {
    bob.invite(NET, key.public(), Purpose::Contact, expires_at)
}

#[test]
fn a_restored_responder_keeps_contacts_blocks_callbacks_and_revocations() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let peer = bob.handshake_key().public();
    // Alice becomes a contact through an invitation.
    let alice = StaticKey::generate();
    let alice_inv = invite(&bob, &alice, NOW + 3_600);
    side.record_invitation(alice_inv.clone(), now()).unwrap();
    assert_eq!(call(&mut side, &alice, peer, alice_inv.id, 1, now()).unwrap(), Grant::Invitation { id: alice_inv.id });
    // Dave's unused invitation is revoked by removing him; Eve is blocked;
    // Frank holds an invitation he has not used yet.
    let (dave, eve, frank) = (StaticKey::generate(), StaticKey::generate(), StaticKey::generate());
    let dave_inv = invite(&bob, &dave, NOW + 3_600);
    side.record_invitation(dave_inv.clone(), now()).unwrap();
    side.remove_contact(dave.public());
    side.block(eve.public());
    let frank_inv = invite(&bob, &frank, NOW + 3_600);
    side.record_invitation(frank_inv.clone(), now()).unwrap();

    // Restart: only the snapshot survives.
    let saved = side.export_snapshot(&storage, now());
    drop(side);
    let mut restored: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &saved).unwrap();
    assert!(restored.gate().is_contact(&alice.public()));
    assert!(restored.gate().is_honoured(&alice_inv.id));
    assert!(restored.gate().is_revoked(&dave_inv.id));
    assert!(restored.gate().is_blocked(&eve.public()));
    // Equal state, and an equal snapshot plaintext (sealed under a new nonce).
    let again = Responder::<u32>::restore_identity(&bob, NET, &storage, &restored.export_snapshot(&storage, now())).unwrap();
    assert!(again.gate() == restored.gate());
    assert_ne!(saved, restored.export_snapshot(&storage, now()), "a fresh nonce every time");

    // And it behaves the same: Alice calls as a contact, Frank uses his
    // invitation, Eve and Dave get nothing.
    assert_eq!(call(&mut restored, &alice, peer, alice_inv.id, 2, now()).unwrap(), Grant::Contact);
    assert_eq!(call(&mut restored, &frank, peer, frank_inv.id, 3, now()).unwrap(), Grant::Invitation { id: frank_inv.id });
    assert!(matches!(call(&mut restored, &eve, peer, [0; 32], 4, now()), Err(WireError::Unauthorised)));
    assert!(matches!(call(&mut restored, &dave, peer, dave_inv.id, 5, now()), Err(WireError::Unauthorised)));

    // A callback listener keeps its grant and deadline (Unix seconds).
    let carol = StaticKey::generate();
    let mut listener: Responder<u32> = Responder::for_callback(&carol, NET, peer, [7; 32], NOW + 600).unwrap();
    let saved = listener.export_snapshot(&storage, now());
    let mut back: Responder<u32> = Responder::restore_callback(&carol, NET, &storage, &saved).unwrap();
    assert!(matches!(call(&mut back, bob.handshake_key(), carol.public(), [7; 32], 6, at(NOW + 599)), Ok(Grant::Callback)));
    // The gate's own deadline check (not only the pruning in front of it).
    let gate = listener.gate();
    assert_eq!(gate.authorise(&peer, &[7; 32], at(NOW + 599)), Some(Grant::Callback));
    assert_eq!(gate.authorise(&peer, &[7; 32], at(NOW + 600)), None);
    let mut late: Responder<u32> = Responder::restore_callback(&carol, NET, &storage, &saved).unwrap();
    assert!(matches!(call(&mut late, bob.handshake_key(), carol.public(), [7; 32], 7, at(NOW + 600)), Err(WireError::Unauthorised)));
}

#[test]
fn a_consumed_or_revoked_invitation_cannot_be_replayed_after_a_restore() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let peer = bob.handshake_key().public();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    // Alice consumes her invitation, then the relationship ends.
    let alice = StaticKey::generate();
    let alice_inv = invite(&bob, &alice, NOW + 3_600);
    side.record_invitation(alice_inv.clone(), now()).unwrap();
    call(&mut side, &alice, peer, alice_inv.id, 1, now()).unwrap();
    side.remove_contact(alice.public());
    // Dave's invitation is revoked before he uses it.
    let dave = StaticKey::generate();
    let dave_inv = invite(&bob, &dave, NOW + 3_600);
    side.record_invitation(dave_inv.clone(), now()).unwrap();
    side.remove_contact(dave.public());
    let saved = side.export_snapshot(&storage, now());

    let mut restored: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &saved).unwrap();
    // Recording either invitation again does not make it usable.
    restored.record_invitation(alice_inv.clone(), now()).unwrap();
    assert_eq!(restored.record_invitation(dave_inv.clone(), now()), Err(ContactError::Revoked));
    assert!(matches!(call(&mut restored, &alice, peer, alice_inv.id, 2, now()), Err(WireError::Unauthorised)));
    assert!(matches!(call(&mut restored, &dave, peer, dave_inv.id, 3, now()), Err(WireError::Unauthorised)));

    // Control: without the snapshot (a responder started empty), the same
    // invitations would work again. This is what the snapshot prevents.
    let mut amnesiac: Responder<u32> = Responder::for_identity(&bob, NET);
    amnesiac.record_invitation(alice_inv.clone(), now()).unwrap();
    amnesiac.record_invitation(dave_inv.clone(), now()).unwrap();
    assert!(call(&mut amnesiac, &alice, peer, alice_inv.id, 2, now()).is_ok());
    assert!(call(&mut amnesiac, &dave, peer, dave_inv.id, 3, now()).is_ok());
}

#[test]
fn persist_before_reply_a_crash_before_the_ack_leaves_the_invitation_unused() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let peer = bob.handshake_key().public();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let alice = StaticKey::generate();
    let inv = invite(&bob, &alice, NOW + 3_600);
    side.record_invitation(inv.clone(), now()).unwrap();
    let before = side.export_snapshot(&storage, now());
    // The invitation is committed in memory, then the process dies before
    // the new snapshot is written: no ACK was sent.
    assert!(call(&mut side, &alice, peer, inv.id, 1, now()).is_ok());
    drop(side);
    // The old snapshot shows the invitation unused, so Alice's retry is
    // answered as her first try was (it was never acknowledged).
    let mut restored: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &before).unwrap();
    assert!(!restored.gate().is_honoured(&inv.id));
    assert_eq!(call(&mut restored, &alice, peer, inv.id, 2, now()).unwrap(), Grant::Invitation { id: inv.id });
    // Persisted this time (before the ACK): after another restart it is spent.
    let after = restored.export_snapshot(&storage, now());
    let back: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &after).unwrap();
    assert!(back.gate().is_honoured(&inv.id));
}

#[test]
fn expired_revocations_are_pruned_after_expiry_plus_skew_and_unexpired_ones_stay() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let (short, long) = (StaticKey::generate(), StaticKey::generate());
    let short_inv = invite(&bob, &short, NOW + 60);
    let long_inv = invite(&bob, &long, NOW + 100_000);
    for (key, inv) in [(&short, &short_inv), (&long, &long_inv)] {
        side.record_invitation(inv.clone(), now()).unwrap();
        side.remove_contact(key.public());
    }
    let edge = NOW + 60 + CLOCK_SKEW_SECS;
    side.expire(at(edge - 1));
    assert!(side.gate().is_revoked(&short_inv.id), "kept until expiry plus skew");
    side.expire(at(edge));
    assert!(!side.gate().is_revoked(&short_inv.id), "pruned");
    assert!(side.gate().is_revoked(&long_inv.id), "an unexpired revocation stays");
    // The pruned one cannot come back: the invitation itself has expired.
    assert_eq!(side.record_invitation(short_inv.clone(), at(edge)), Err(ContactError::Expired));
    assert_eq!(side.record_invitation(long_inv.clone(), at(edge)), Err(ContactError::Revoked));
    // An unused invitation is dropped once it has expired.
    let frank = StaticKey::generate();
    let frank_inv = invite(&bob, &frank, edge + 10);
    side.record_invitation(frank_inv.clone(), at(edge)).unwrap();
    assert_eq!(side.gate().authorise(&frank.public(), &frank_inv.id, at(edge)), Some(Grant::Invitation { id: frank_inv.id }));
    assert_eq!(side.gate().authorise(&frank.public(), &frank_inv.id, at(edge + 10)), None, "expired");
    let before = side.export_snapshot(&storage, at(edge + 10)).len();
    side.expire(at(edge + 10));
    assert_eq!(side.gate().authorise(&frank.public(), &frank_inv.id, at(edge)), None, "pruned, not just expired");
    // Pruning frees the space: the snapshot no longer carries it.
    assert_eq!(before - side.export_snapshot(&storage, at(edge + 10)).len(), Invitation::LEN);
    // Pruning is reflected in the snapshot, and the rest survives it.
    let restored: Responder<u32> =
        Responder::restore_identity(&bob, NET, &storage, &side.export_snapshot(&storage, now())).unwrap();
    assert!(!restored.gate().is_revoked(&short_inv.id));
    assert!(restored.gate().is_revoked(&long_inv.id));
}

#[test]
fn a_consumed_invitation_is_kept_until_expiry_plus_skew() {
    let bob = ContactIdentity::generate_at(NOW);
    let peer = bob.handshake_key().public();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let alice = StaticKey::generate();
    let inv = invite(&bob, &alice, NOW + 60);
    side.record_invitation(inv.clone(), now()).unwrap();
    call(&mut side, &alice, peer, inv.id, 1, now()).unwrap();
    side.expire(at(NOW + 60 + CLOCK_SKEW_SECS - 1));
    assert!(side.gate().is_honoured(&inv.id));
    side.expire(at(NOW + 60 + CLOCK_SKEW_SECS));
    assert!(!side.gate().is_honoured(&inv.id));
    assert!(side.gate().is_contact(&alice.public()), "the contact itself stays");
}

#[test]
fn bad_snapshots_fail_loudly() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    side.block([3; 32]);
    let saved = side.export_snapshot(&storage, now());
    let restore = |key: &StorageKey, network: Network, bytes: &[u8]| {
        Responder::<u32>::restore_identity(&bob, network, key, bytes).map(|_| ())
    };
    assert_eq!(restore(&storage, NET, &saved), Ok(()), "control");
    assert_eq!(restore(&StorageKey::generate(), NET, &saved), Err(SnapshotError::Undecryptable), "wrong key");
    assert_eq!(restore(&storage, [8; 32], &saved), Err(SnapshotError::Undecryptable), "wrong network");
    for i in [1, 12, 13, saved.len() / 2, saved.len() - 1] {
        let mut tampered = saved.clone();
        tampered[i] ^= 1;
        assert_eq!(restore(&storage, NET, &tampered), Err(SnapshotError::Undecryptable), "byte {i}");
    }
    let mut versioned = saved.clone();
    versioned[0] = 9;
    assert_eq!(restore(&storage, NET, &versioned), Err(SnapshotError::UnsupportedVersion(9)));
    // The previous format's number on a current snapshot: the inner version
    // byte no longer matches.
    versioned[0] = 1;
    assert_eq!(restore(&storage, NET, &versioned), Err(SnapshotError::Malformed));
    versioned[0] = 0;
    assert_eq!(restore(&storage, NET, &versioned), Err(SnapshotError::UnsupportedVersion(0)));
    assert_eq!(restore(&storage, NET, &saved[..saved.len() - 1]), Err(SnapshotError::Undecryptable), "cut short");
    assert_eq!(restore(&storage, NET, &saved[..MIN_SNAPSHOT_LEN - 1]), Err(SnapshotError::Truncated));
    assert_eq!(restore(&storage, NET, &[]), Err(SnapshotError::Truncated));
    // Another identity's snapshot, or a callback listener's, is refused.
    let other = ContactIdentity::generate_at(NOW);
    let theirs = Responder::<u32>::for_identity(&other, NET).export_snapshot(&storage, now());
    assert_eq!(restore(&storage, NET, &theirs), Err(SnapshotError::WrongIdentity));
    let mut listener = Responder::<u32>::for_callback(&StaticKey::generate(), NET, [5; 32], [1; 32], NOW + 60).unwrap();
    assert_eq!(restore(&storage, NET, &listener.export_snapshot(&storage, now())), Err(SnapshotError::WrongIdentity));
    assert_eq!(
        Responder::<u32>::restore_callback(bob.handshake_key(), NET, &storage, &saved).map(|_| ()),
        Err(SnapshotError::WrongIdentity)
    );
}

#[test]
fn snapshots_are_written_atomically() {
    let dir = std::env::temp_dir().join(format!("anonymum-snapshot-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gate.snapshot");
    write_atomically(&path, b"first").unwrap();
    write_atomically(&path, b"second").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
    assert!(!dir.join("gate.snapshot.tmp").exists(), "no temporary file left behind");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- the clock floor: time never runs backwards for the gate ----------------------

#[test]
fn a_pruned_invitation_stays_refused_when_the_clock_jumps_back_after_a_restore() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let peer = bob.handshake_key().public();
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    // Dave's invitation is revoked; Alice's is consumed and then she is
    // removed. Both expire at NOW + 60.
    let (dave, alice) = (StaticKey::generate(), StaticKey::generate());
    let dave_inv = invite(&bob, &dave, NOW + 60);
    side.record_invitation(dave_inv.clone(), now()).unwrap();
    side.remove_contact(dave.public());
    let alice_inv = invite(&bob, &alice, NOW + 60);
    side.record_invitation(alice_inv.clone(), now()).unwrap();
    call(&mut side, &alice, peer, alice_inv.id, 1, now()).unwrap();
    side.remove_contact(alice.public());
    // Time passes expiry plus skew: both ids are pruned. Saved and restored.
    let later = NOW + 60 + CLOCK_SKEW_SECS;
    side.expire(at(later));
    assert!(!side.gate().is_revoked(&dave_inv.id) && !side.gate().is_honoured(&alice_inv.id), "pruned");
    assert_eq!(side.gate().last_seen(), later, "pruning moved the floor up");
    side.expire(at(NOW));
    assert_eq!(side.gate().last_seen(), later, "and an earlier reading does not move it back");
    let saved = side.export_snapshot(&storage, at(later));
    let mut restored: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &saved).unwrap();
    assert_eq!(restored.gate().last_seen(), later, "the floor survives the restart");
    // The system clock now reads a time before the invitations expired.
    let back = at(NOW + 30);
    for (key, inv, tag) in [(&dave, &dave_inv, 2), (&alice, &alice_inv, 3)] {
        assert_eq!(restored.record_invitation(inv.clone(), back), Err(ContactError::Expired), "judged at the floor");
        assert!(matches!(call(&mut restored, key, peer, inv.id, tag, back), Err(WireError::Unauthorised)));
    }
    assert_eq!(restored.gate().last_seen(), later, "a backward clock does not lower the floor");
}

#[test]
fn a_callback_grant_cannot_be_resurrected_by_a_backward_clock_across_a_restart() {
    let bob = ContactIdentity::generate_at(NOW);
    let storage = StorageKey::generate();
    let carol = StaticKey::generate();
    let peer = bob.handshake_key().public();
    let mut listener: Responder<u32> = Responder::for_callback(&carol, NET, peer, [7; 32], NOW + 600).unwrap();
    // Saved after the deadline has been seen, before anything pruned the
    // grant, so the snapshot still contains it.
    let saved = listener.export_snapshot(&storage, at(NOW + 605));
    // Pruning at the floor frees the grant's space (caller, reference,
    // deadline, flags: 73 bytes) even with an earlier clock reading.
    let mut pruned: Responder<u32> = Responder::restore_callback(&carol, NET, &storage, &saved).unwrap();
    pruned.expire(at(NOW + 590));
    assert_eq!(saved.len() - pruned.export_snapshot(&storage, at(NOW + 590)).len(), 32 + 32 + 8 + 1);
    // Within the run the floor already refuses an earlier clock reading.
    assert_eq!(listener.gate().authorise(&peer, &[7; 32], at(NOW + 590)), None);
    // Across a restart, with the clock set back before the deadline.
    let mut restored: Responder<u32> = Responder::restore_callback(&carol, NET, &storage, &saved).unwrap();
    assert_eq!(restored.gate().last_seen(), NOW + 605);
    assert_eq!(restored.gate().authorise(&peer, &[7; 32], at(NOW + 590)), None);
    assert!(matches!(
        call(&mut restored, bob.handshake_key(), carol.public(), [7; 32], 1, at(NOW + 590)),
        Err(WireError::Unauthorised)
    ));
    // Control: a snapshot saved before the deadline was seen still answers.
    let mut fresh: Responder<u32> = Responder::for_callback(&carol, NET, peer, [7; 32], NOW + 600).unwrap();
    let early = fresh.export_snapshot(&storage, at(NOW + 500));
    let mut back: Responder<u32> = Responder::restore_callback(&carol, NET, &storage, &early).unwrap();
    assert!(matches!(call(&mut back, bob.handshake_key(), carol.public(), [7; 32], 2, at(NOW + 590)), Ok(Grant::Callback)));
}
