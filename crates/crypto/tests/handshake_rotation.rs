//! Handshake key rotation (unreviewed): the handshake key lives in the same
//! two-slot epoch ring as the inbox keys, a responder answers on the
//! draining key during its grace and never after the purge, and contacts
//! roll their record of a rotated key forward from a card signed by the
//! same signing key.

use std::time::{Duration, Instant};

use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{
    epoch_start, open_note, seal_note, ContactError, ContactIdentity, Grant, KeyEpoch, Network, Now, Purpose,
    SessionError, StaticKey, StorageKey, DRAIN_GRACE, EPOCH_LEN,
};

const NET: Network = [9; 32];
const ROUTE: [u8; 96] = [7; 96];
const ADMISSION: [u8; 32] = [0xAD; 32];
/// Three days into an epoch.
const T0: u64 = 2_900 * EPOCH_LEN + 3 * 86_400 + 1_234;
const POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 1, base_wait: Duration::from_secs(10) };

/// The next epoch boundary after `T0`: the old epoch's `not_after`.
fn boundary() -> u64 {
    epoch_start(T0) + EPOCH_LEN
}

fn at(unix: u64) -> Now {
    Now { unix, mono: Instant::now() }
}

/// A HELLO from `key` to `peer`, and the caller that sent it.
fn hello(key: &StaticKey, peer: [u8; 32], reference: [u8; 32]) -> (Initiator, Vec<u8>) {
    Initiator::start_with(key, peer, NET, reference, POLICY).unwrap()
}

/// Finish a call whose HELLO was already made. Returns the grant, or the
/// error that stopped it.
fn finish(side: &mut Responder<u32>, mut caller: Initiator, hello: &[u8], tag: u32, when: Now) -> Result<Grant, WireError> {
    let ResponderEvent::Reply(welcome) = side.handle(tag, hello, when)? else { panic!("expected WELCOME") };
    let InitiatorEvent::Send(confirm) = caller.handle(&welcome).unwrap() else { panic!("expected CONFIRM") };
    let ResponderEvent::Established { grant, reply, .. } = side.handle(tag, &confirm, when)? else { panic!() };
    assert_eq!(caller.handle(&reply).unwrap(), InitiatorEvent::Established);
    Ok(grant)
}

fn call(side: &mut Responder<u32>, key: &StaticKey, peer: [u8; 32], reference: [u8; 32], tag: u32, when: Now) -> Result<Grant, WireError> {
    let (caller, first) = hello(key, peer, reference);
    finish(side, caller, &first, tag, when)
}

fn is_noise(r: &Result<Grant, WireError>) -> bool {
    matches!(r, Err(WireError::Session(SessionError::Noise(_))))
}

// ---- the ring --------------------------------------------------------------------

#[test]
fn rotating_an_epoch_rotates_the_handshake_key_with_the_inbox_keys() {
    let mut bob = ContactIdentity::generate_at(T0);
    let (old_handshake, old_inbox) = (bob.handshake_key().public(), bob.inbox_key().public());
    let old_card = bob.card(NET, 1);
    assert_eq!(old_card.handshake_key, old_handshake);
    bob.rotate_epoch(boundary() + 10);
    assert_ne!(bob.handshake_key().public(), old_handshake);
    assert_ne!(bob.inbox_key().public(), old_inbox);
    assert_eq!(bob.card(NET, 1).handshake_key, bob.handshake_key().public());
    let draining = bob.draining().unwrap();
    assert_eq!((draining.handshake_key().public(), draining.inbox_key().public()), (old_handshake, old_inbox));
    // The old secret is found during the grace, and not after it.
    let grace_end = boundary() + DRAIN_GRACE;
    assert_eq!(draining.grace_end(), grace_end);
    assert!(bob.handshake_key_for(&old_handshake, grace_end - 1).is_some());
    assert!(bob.handshake_key_for(&old_handshake, grace_end).is_none());
    assert!(bob.handshake_key_for(&bob.handshake_key().public(), grace_end).is_some());
    // Purging drops all three draining secrets together.
    assert!(!bob.purge_expired(grace_end - 1));
    assert!(bob.purge_expired(grace_end));
    assert!(bob.draining().is_none());
    let back = ContactIdentity::from_secret_bytes(&bob.to_secret_bytes()).unwrap();
    assert!(back.draining().is_none());
    assert_eq!(back.handshake_key().public(), bob.handshake_key().public());
}

#[test]
fn a_version_1_identity_still_loads_and_keeps_its_handshake_key() {
    // Lay out a version-1 identity by hand: one handshake key outside the
    // epochs, epochs without handshake keys.
    let mut bob = ContactIdentity::generate_at(T0);
    bob.rotate_epoch(boundary() + 10);
    let handshake = StaticKey::generate();
    let epoch = |e: &KeyEpoch| {
        let (_, inbox, pq, not_before, not_after) = e.to_secret_bytes();
        [&inbox[..], &pq, &not_before.to_be_bytes(), &not_after.to_be_bytes()].concat()
    };
    let v1 = [
        &[1u8][..],
        bob.signing_secret_bytes().as_ref(),
        &handshake.to_bytes(),
        &epoch(bob.active()),
        &[1],
        &epoch(bob.draining().unwrap()),
    ]
    .concat();
    let mut old = ContactIdentity::from_secret_bytes(&v1).unwrap();
    assert_eq!(old.signing_key(), bob.signing_key());
    assert_eq!(old.handshake_key().public(), handshake.public(), "existing contacts keep reaching it");
    assert_eq!(old.draining().unwrap().handshake_key().public(), handshake.public());
    assert_eq!(old.inbox_key().public(), bob.inbox_key().public());
    // Strict: a cut or padded version-1 buffer is refused.
    assert_eq!(ContactIdentity::from_secret_bytes(&v1[..v1.len() - 1]).err(), Some(ContactError::Malformed));
    assert_eq!(ContactIdentity::from_secret_bytes(&[&v1[..], &[0]].concat()).err(), Some(ContactError::Malformed));
    // It is written back as version 2, and the next rotation gives a fresh
    // handshake key.
    let v2 = old.to_secret_bytes();
    assert_eq!(v2[0], 2);
    assert_eq!(ContactIdentity::from_secret_bytes(&v2).unwrap().card(NET, 1), old.card(NET, 1));
    old.rotate_epoch(boundary() + EPOCH_LEN);
    assert_ne!(old.handshake_key().public(), handshake.public());
    assert_eq!(old.draining().unwrap().handshake_key().public(), handshake.public());
}

// ---- (a) and (b): handshakes to the draining key -------------------------------

#[test]
fn a_handshake_to_the_previous_epochs_key_works_during_the_grace_and_not_after_the_purge() {
    let mut bob = ContactIdentity::generate_at(T0);
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let old_key = bob.handshake_key().public();
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, boundary() + 2 * EPOCH_LEN);
    side.record_invitation(invitation.clone(), at(T0)).unwrap();

    bob.rotate_epoch(boundary() + 10);
    side.refresh_keys(&bob).unwrap();
    let new_key = bob.handshake_key().public();
    assert_eq!(side.handshake_keys(), vec![new_key, old_key]);
    let grace_end = boundary() + DRAIN_GRACE;

    // (a) Alice still has the old card: her call to the old key goes through
    // in the grace window, and becomes a contact.
    let (caller, recorded) = hello(&alice, old_key, invitation.id);
    assert_eq!(finish(&mut side, caller, &recorded, 1, at(grace_end - 60)).unwrap(), Grant::Invitation { id: invitation.id });
    // Her next call reaches the new key.
    assert_eq!(call(&mut side, &alice, new_key, invitation.id, 2, at(grace_end - 30)).unwrap(), Grant::Contact);

    // (b) Bob purges the old epoch: the old key is gone, and the recorded
    // HELLO (or any late one) to it no longer decrypts.
    assert!(bob.purge_expired(grace_end));
    side.refresh_keys(&bob).unwrap();
    assert_eq!(side.handshake_keys(), vec![new_key]);
    assert!(matches!(side.handle(3, &recorded, at(grace_end)), Err(WireError::Session(SessionError::Noise(_)))));
    assert!(is_noise(&call(&mut side, &alice, old_key, invitation.id, 4, at(grace_end))));
    assert_eq!(call(&mut side, &alice, new_key, invitation.id, 5, at(grace_end)).unwrap(), Grant::Contact);
}

#[test]
fn the_responder_drops_the_draining_key_at_the_end_of_its_grace_by_itself_and_for_good() {
    let mut bob = ContactIdentity::generate_at(T0);
    let alice = StaticKey::generate();
    let invitation = bob.invite(NET, alice.public(), Purpose::Contact, boundary() + 2 * EPOCH_LEN);
    let old_key = bob.handshake_key().public();
    bob.rotate_epoch(boundary() + 10);
    // Built after the rotation, never refreshed, the identity never purged.
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    side.record_invitation(invitation.clone(), at(boundary() + 20)).unwrap();
    let grace_end = boundary() + DRAIN_GRACE;
    let (caller, recorded) = hello(&alice, old_key, invitation.id);
    assert!(matches!(side.handle(1, &recorded, at(grace_end - 1)), Ok(ResponderEvent::Reply(_))), "in the grace");
    drop(caller);
    assert!(matches!(side.handle(2, &recorded, at(grace_end)), Err(WireError::Session(SessionError::Noise(_)))));
    assert_eq!(side.handshake_keys(), vec![bob.handshake_key().public()]);
    // A clock set back afterwards does not bring the key back, nor does a
    // refresh from an identity that still holds it (its grace is over by
    // the gate's clock floor).
    assert!(matches!(side.handle(3, &recorded, at(grace_end - 100)), Err(WireError::Session(_))));
    side.refresh_keys(&bob).unwrap();
    assert!(matches!(side.handle(4, &recorded, at(grace_end - 100)), Err(WireError::Session(_))));
    // A responder restored from a snapshot taken at the end of the grace
    // has the same floor.
    let storage = StorageKey::generate();
    let saved = side.export_snapshot(&storage, at(grace_end));
    let mut restored: Responder<u32> = Responder::restore_identity(&bob, NET, &storage, &saved).unwrap();
    assert!(matches!(restored.handle(5, &recorded, at(grace_end - 100)), Err(WireError::Session(_))));
}

#[test]
fn a_responder_refuses_another_identitys_keys() {
    let bob = ContactIdentity::generate_at(T0);
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    assert_eq!(side.refresh_keys(&ContactIdentity::generate_at(T0)), Err(ContactError::WrongIssuer));
    assert_eq!(side.handshake_keys(), vec![bob.handshake_key().public()]);
}

#[test]
fn a_callback_to_a_stranger_who_rotated_right_after_sealing_works_during_the_grace_only() {
    let bob = ContactIdentity::generate_at(T0);
    let mut carol = ContactIdentity::generate_at(T0);
    // Carol seals a note at the end of her epoch, then rotates.
    let sealed_at = boundary() - 60;
    let note = seal_note(&NET, &bob.card(NET, 1), &carol, &carol.card(NET, 1), &ROUTE, "hi", &ADMISSION).unwrap();
    let mut listener: Responder<u32> =
        Responder::for_callback_identity(&carol, NET, bob.handshake_key().public(), ADMISSION, sealed_at + 86_400).unwrap();
    carol.rotate_epoch(boundary() + 1);
    listener.refresh_keys(&carol).unwrap();
    // Bob opens the note hours later and calls the key it names: her old one.
    let opened = open_note(&bob, &NET, &note, sealed_at, boundary() + 3_600).unwrap();
    assert_eq!(opened.callback(), carol.draining().unwrap().handshake_key().public());
    let (caller, recorded) = hello(bob.handshake_key(), opened.callback(), opened.admission);
    assert_eq!(finish(&mut listener, caller, &recorded, 1, at(boundary() + 3_600)).unwrap(), Grant::Callback);

    // After the purge, the recorded callback message 1 no longer opens on
    // Carol's device: no one who takes it later can read it.
    let grace_end = boundary() + DRAIN_GRACE;
    let mut late: Responder<u32> =
        Responder::for_callback_identity(&carol, NET, bob.handshake_key().public(), ADMISSION, grace_end + 600).unwrap();
    assert!(matches!(late.handle(2, &recorded, at(grace_end - 1)), Ok(ResponderEvent::Reply(_))), "control");
    assert!(carol.purge_expired(grace_end));
    late.refresh_keys(&carol).unwrap();
    assert!(matches!(late.handle(3, &recorded, at(grace_end)), Err(WireError::Session(SessionError::Noise(_)))));
    assert!(carol.handshake_key_for(&opened.callback(), grace_end).is_none());
    // The plain single-key listener has no draining key at all.
    let mut single: Responder<u32> = Responder::for_callback(
        carol.handshake_key(),
        NET,
        bob.handshake_key().public(),
        ADMISSION,
        grace_end + 600,
    )
    .unwrap();
    assert!(matches!(single.handle(4, &recorded, at(boundary() + 3_600)), Err(WireError::Session(_))));
}

// ---- (d) no fallback after the active key decrypted ------------------------------

#[test]
fn a_hello_the_active_key_opened_but_the_gate_refuses_is_not_retried_with_the_draining_key() {
    let mut bob = ContactIdentity::generate_at(T0);
    let old_key = bob.handshake_key().public();
    bob.rotate_epoch(boundary() + 10);
    let mut side: Responder<u32> = Responder::for_identity(&bob, NET);
    let when = at(boundary() + 3_600);
    let stranger = StaticKey::generate();
    // To the active key: decrypted, refused by the gate, reported as such
    // (a retry with the draining key would have failed to decrypt instead).
    assert!(matches!(call(&mut side, &stranger, bob.handshake_key().public(), [1; 32], 1, when), Err(WireError::Unauthorised)));
    // To the draining key: decrypted by it, refused by the gate.
    assert!(matches!(call(&mut side, &stranger, old_key, [1; 32], 2, when), Err(WireError::Unauthorised)));
    // To neither: a decryption failure with both.
    assert!(is_noise(&call(&mut side, &stranger, StaticKey::generate().public(), [1; 32], 3, when)));
    assert_eq!(side.pending(), 0, "nothing answered");
}

// ---- (c) contact key rollover ------------------------------------------------------

/// Carol's listener with Bob as a bound contact (through his callback).
fn carol_with_bob_as_contact(bob: &ContactIdentity, carol: &ContactIdentity) -> Responder<u32> {
    let mut listener: Responder<u32> =
        Responder::for_callback_identity(carol, NET, bob.handshake_key().public(), ADMISSION, T0 + 86_400).unwrap();
    listener.bind_contact_card(&bob.card(NET, 1), at(T0)).unwrap();
    let grant = call(&mut listener, bob.handshake_key(), carol.handshake_key().public(), ADMISSION, 1, at(T0)).unwrap();
    assert_eq!(grant, Grant::Callback);
    assert!(listener.gate().is_contact(&bob.handshake_key().public()));
    assert_eq!(listener.gate().signer_of(&bob.handshake_key().public()), Some(bob.signing_key()));
    listener
}

#[test]
fn a_new_card_from_the_same_signing_key_rolls_a_contact_forward_and_survives_a_snapshot() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    let carol_key = carol.handshake_key().public();
    let old_key = bob.handshake_key().public();

    bob.rotate_epoch(boundary() + 10);
    let new_card = bob.card(NET, 1);
    let rolled_at = boundary() + 60;
    assert_eq!(listener.roll_contact_key(&new_card, at(rolled_at)), Ok(old_key));
    // Rolling again to the same key changes nothing.
    assert_eq!(listener.roll_contact_key(&new_card, at(rolled_at)), Ok(new_card.handshake_key));
    let new_key = bob.handshake_key().public();
    assert!(listener.gate().admits(&new_key, &ADMISSION));
    assert_eq!(listener.gate().signer_of(&new_key), Some(bob.signing_key()));
    assert_eq!(call(&mut listener, bob.handshake_key(), carol_key, ADMISSION, 2, at(rolled_at + 1)).unwrap(), Grant::Contact);

    // Saved and restored, the rollover holds: the new key with its signer,
    // the old one still retiring.
    let storage = StorageKey::generate();
    let saved = listener.export_snapshot(&storage, at(rolled_at + 2));
    let mut restored: Responder<u32> = Responder::restore_callback_identity(&carol, NET, &storage, &saved).unwrap();
    assert_eq!(restored.gate().signer_of(&new_key), Some(bob.signing_key()));
    assert_eq!(call(&mut restored, bob.handshake_key(), carol_key, ADMISSION, 3, at(rolled_at + 3)).unwrap(), Grant::Contact);
    let old_secret = bob.handshake_key_for(&old_key, rolled_at + 3).unwrap();
    assert_eq!(call(&mut restored, old_secret, carol_key, ADMISSION, 4, at(rolled_at + 4)).unwrap(), Grant::Contact);
    // Once the retiring time is up, the old key is refused and pruned; a
    // later rollover (another rotation) still finds the contact by its
    // signing key.
    let retired = rolled_at + DRAIN_GRACE;
    assert!(matches!(call(&mut restored, old_secret, carol_key, ADMISSION, 5, at(retired)), Err(WireError::Unauthorised)));
    assert!(!restored.gate().is_contact(&old_key));
    assert_eq!(call(&mut restored, bob.handshake_key(), carol_key, ADMISSION, 6, at(retired)).unwrap(), Grant::Contact);
    bob.rotate_epoch(boundary() + EPOCH_LEN + 10);
    assert_eq!(restored.roll_contact_key(&bob.card(NET, 1), at(boundary() + EPOCH_LEN + 60)), Ok(new_key));
}

#[test]
fn a_live_session_on_the_old_key_ends_when_the_old_key_retires() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    bob.rotate_epoch(boundary() + 10);
    let rolled_at = boundary() + 60;
    listener.roll_contact_key(&bob.card(NET, 1), at(rolled_at)).unwrap();
    let old_key = bob.draining().unwrap().handshake_key().public();
    // The session from the first call (tag 1, the old key) still works...
    assert!(listener.seal(&1, b"still here", at(rolled_at + 1)).is_ok());
    // ...and the gate still admits the old key, judged at any time before
    // its retire time, even without a responder operation in between.
    let retired = rolled_at + DRAIN_GRACE;
    assert_eq!(listener.gate().authorise(&old_key, &ADMISSION, at(retired - 1)), Some(Grant::Contact));
    assert_eq!(listener.gate().authorise(&old_key, &ADMISSION, at(retired)), None);
    // A snapshot export moves the clock floor without pruning: the old key
    // is no longer admitted from then on.
    let storage = StorageKey::generate();
    let _ = listener.export_snapshot(&storage, at(retired));
    assert!(!listener.gate().admits(&old_key, &ADMISSION));
    // The session ends when the key retires, at the next expiry pass, even
    // before anything tries to use it.
    listener.expire(at(retired));
    assert_eq!(listener.sessions(), 0);
    assert!(listener.seal(&1, b"gone", at(retired)).is_err());
}

#[test]
fn cards_from_another_signing_key_are_refused() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mallory = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    let old_key = bob.handshake_key().public();
    let now = at(T0 + 60);
    // Mallory's own card: not a contact.
    assert_eq!(listener.roll_contact_key(&mallory.card(NET, 1), now), Err(ContactError::UnknownContact));
    assert_eq!(listener.bind_contact_card(&mallory.card(NET, 1), now), Err(ContactError::UnknownContact));
    // Bob's rotated card with Mallory's signing key put in: its signature fails.
    bob.rotate_epoch(boundary() + 10);
    let mut forged = bob.card(NET, 1);
    forged.signing_key = mallory.signing_key();
    assert_eq!(listener.roll_contact_key(&forged, at(boundary() + 60)), Err(ContactError::BadSignature));
    // Bob's card with Mallory's handshake key put in: signature fails too.
    let mut swapped = bob.card(NET, 1);
    swapped.handshake_key = mallory.handshake_key().public();
    assert_eq!(listener.roll_contact_key(&swapped, at(boundary() + 60)), Err(ContactError::BadSignature));
    // A card for another network, or one that is not valid now.
    assert_eq!(listener.roll_contact_key(&bob.card([8; 32], 1), at(boundary() + 60)), Err(ContactError::WrongNetwork));
    assert_eq!(listener.roll_contact_key(&bob.card(NET, 1), at(boundary() + EPOCH_LEN)), Err(ContactError::Expired));
    // Nothing moved: Bob's old key is still the contact's only key.
    assert!(listener.gate().admits(&old_key, &ADMISSION));
    assert!(!listener.gate().is_contact(&bob.handshake_key().public()));
    // Mallory cannot claim Bob's key under her signing key either: a valid
    // card of hers naming his handshake key does not rebind it.
    let mut claim = ContactIdentity::generate_at(T0).card(NET, 1);
    claim.handshake_key = old_key;
    assert!(claim.verify(&NET, T0).is_err(), "her signature over his key is a different card");
}

#[test]
fn a_rollover_cannot_take_a_key_that_is_blocked_or_already_used() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    bob.rotate_epoch(boundary() + 10);
    let new_key = bob.handshake_key().public();
    listener.block(new_key);
    assert_eq!(listener.roll_contact_key(&bob.card(NET, 1), at(boundary() + 60)), Err(ContactError::KeyInUse));
    listener.unblock(&new_key);
    assert!(listener.roll_contact_key(&bob.card(NET, 1), at(boundary() + 60)).is_ok());
}

#[test]
fn blocking_a_rolled_contact_blocks_its_retiring_key_too() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    let old_key = bob.handshake_key().public();
    bob.rotate_epoch(boundary() + 10);
    let rolled_at = boundary() + 60;
    listener.roll_contact_key(&bob.card(NET, 1), at(rolled_at)).unwrap();
    listener.block(bob.handshake_key().public());
    assert!(listener.gate().is_blocked(&old_key));
    let old_secret = bob.handshake_key_for(&old_key, rolled_at).unwrap();
    let carol_key = carol.handshake_key().public();
    assert!(matches!(call(&mut listener, old_secret, carol_key, ADMISSION, 2, at(rolled_at + 1)), Err(WireError::Unauthorised)));
    assert_eq!(listener.sessions(), 0);
}

#[test]
fn binding_checks_the_card_and_refuses_a_second_signer() {
    let bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    let now = at(T0 + 60);
    // Binding Bob again is fine; binding his key to a card that is not his
    // (here: an expired one, a foreign network) is refused.
    assert_eq!(listener.bind_contact_card(&bob.card(NET, 1), now), Ok(()));
    assert_eq!(listener.bind_contact_card(&bob.card([8; 32], 1), now), Err(ContactError::WrongNetwork));
    // An unknown key cannot be bound.
    let dave = ContactIdentity::generate_at(T0);
    assert_eq!(listener.bind_contact_card(&dave.card(NET, 1), now), Err(ContactError::UnknownContact));
    // An identity that kept Bob's handshake key but has another signing key
    // (a stolen handshake secret) cannot rebind it.
    let thief = thief_with_handshake_of(&bob);
    assert_eq!(thief.card(NET, 1).handshake_key, bob.handshake_key().public());
    assert_eq!(listener.bind_contact_card(&thief.card(NET, 1), now), Err(ContactError::SignerMismatch));
    assert_eq!(listener.gate().signer_of(&bob.handshake_key().public()), Some(bob.signing_key()));
    // Last, since it moves the gate's clock floor past the card's end.
    assert_eq!(listener.bind_contact_card(&bob.card(NET, 1), at(boundary())), Err(ContactError::Expired));
}

/// A new signing key with `victim`'s current epoch (handshake key included).
fn thief_with_handshake_of(victim: &ContactIdentity) -> ContactIdentity {
    let (handshake, inbox, pq, not_before, not_after) = victim.active().to_secret_bytes();
    let epoch = KeyEpoch::from_secret_bytes(handshake, inbox, pq, not_before, not_after).unwrap();
    ContactIdentity::from_parts(StaticKey::generate().to_bytes(), epoch, None)
}


#[test]
fn removing_a_rolled_contact_removes_its_retiring_key_too() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    let old_key = bob.handshake_key().public();
    bob.rotate_epoch(boundary() + 10);
    let rolled_at = boundary() + 60;
    listener.roll_contact_key(&bob.card(NET, 1), at(rolled_at)).unwrap();
    listener.remove_contact(bob.handshake_key().public());
    assert!(!listener.gate().is_contact(&old_key));
    assert!(!listener.gate().is_blocked(&old_key));
    let old_secret = bob.handshake_key_for(&old_key, rolled_at).unwrap();
    let carol_key = carol.handshake_key().public();
    assert!(matches!(call(&mut listener, old_secret, carol_key, ADMISSION, 2, at(rolled_at + 1)), Err(WireError::Unauthorised)));
    assert_eq!(listener.sessions(), 0);
}

#[test]
fn a_blocked_contact_cannot_roll_itself_back_in() {
    let mut bob = ContactIdentity::generate_at(T0);
    let carol = ContactIdentity::generate_at(T0);
    let mut listener = carol_with_bob_as_contact(&bob, &carol);
    listener.block(bob.handshake_key().public());
    bob.rotate_epoch(boundary() + 10);
    assert_eq!(listener.roll_contact_key(&bob.card(NET, 1), at(boundary() + 60)), Err(ContactError::UnknownContact));
    assert!(!listener.gate().admits(&bob.handshake_key().public(), &ADMISSION));
    let carol_key = carol.handshake_key().public();
    assert!(matches!(
        call(&mut listener, bob.handshake_key(), carol_key, ADMISSION, 2, at(boundary() + 61)),
        Err(WireError::Unauthorised)
    ));
}

/// An identity with signing secret `signing` and handshake secret `handshake`.
fn identity_with(signing: [u8; 32], handshake: &StaticKey) -> ContactIdentity {
    let start = epoch_start(T0);
    let epoch = KeyEpoch::from_secret_bytes(handshake.to_bytes(), StaticKey::generate().to_bytes(), [5; 64], start, start + EPOCH_LEN)
        .unwrap();
    ContactIdentity::from_parts(signing, epoch, None)
}

#[test]
fn a_signing_key_binds_to_one_current_key_and_a_blocked_key_binds_to_none() {
    // Carol has two contacts by invitation, on holder keys k1 and k2.
    let carol = ContactIdentity::generate_at(T0);
    let mut side: Responder<u32> = Responder::for_identity(&carol, NET);
    let carol_key = carol.handshake_key().public();
    let (k1, k2) = (StaticKey::generate(), StaticKey::generate());
    for (tag, k) in [(1, &k1), (2, &k2)] {
        let invitation = carol.invite(NET, k.public(), Purpose::Contact, T0 + 3_600);
        side.record_invitation(invitation.clone(), at(T0)).unwrap();
        call(&mut side, k, carol_key, invitation.id, tag, at(T0)).unwrap();
    }
    let bob = ContactIdentity::generate_at(T0);
    let now = at(T0 + 60);
    // Bob's signing key can be bound to k1, but then not also to k2.
    assert_eq!(side.bind_contact_card(&identity_with(*bob.signing_secret_bytes(), &k1).card(NET, 1), now), Ok(()));
    assert_eq!(
        side.bind_contact_card(&identity_with(*bob.signing_secret_bytes(), &k2).card(NET, 1), now),
        Err(ContactError::KeyInUse)
    );
    assert_eq!(side.gate().signer_of(&k2.public()), None);
    // A blocked contact key cannot be bound at all.
    side.block(k2.public());
    let dave = ContactIdentity::generate_at(T0);
    assert_eq!(
        side.bind_contact_card(&identity_with(*dave.signing_secret_bytes(), &k2).card(NET, 1), now),
        Err(ContactError::KeyInUse)
    );
    assert_eq!(side.gate().signer_of(&k2.public()), None);
}
