//! Inbox key rotation: a two-slot ring (active and draining) on a shared
//! weekly grid, with a 26-hour drain grace and purging (audit CRIT-02,
//! forward secrecy for stranger notes). Unreviewed.

use anonymum_core::SealedNote;
use anonymum_crypto::{
    epoch_start, open_note, seal_note, ContactCard, ContactError, ContactIdentity, NoteError, CLOCK_GRID_BACKDATE,
    DRAIN_GRACE, EPOCH_LEN,
};

const NET: [u8; 32] = [9; 32];
const ROUTE: [u8; 96] = [7; 96];
const ADMISSION: [u8; 32] = [0xAD; 32];
/// Three days into an epoch.
const T0: u64 = 2_900 * EPOCH_LEN + 3 * 86_400 + 1_234;
const DAY: u64 = 86_400;

fn seal_to(card: &ContactCard, from: &ContactIdentity) -> SealedNote {
    seal_note(&NET, card, from, &from.card(NET, 1), &ROUTE, "hello", &ADMISSION).unwrap()
}

fn opens(me: &ContactIdentity, note: &SealedNote, created_at: u64, now: u64) -> bool {
    match open_note(me, &NET, note, created_at, now) {
        Ok(opened) => {
            assert_eq!(opened.intro, "hello");
            true
        }
        Err(NoteError::Noise(_)) => false,
        Err(other) => panic!("unexpected {other:?}"),
    }
}

#[test]
fn epochs_lie_on_one_shared_grid() {
    let start = epoch_start(T0);
    assert_eq!(start % EPOCH_LEN, 0);
    assert!(start <= T0 && T0 < start + EPOCH_LEN);
    // Two identities made at different moments of the same epoch publish
    // the same validity: it says nothing about when either was made.
    let (a, b) = (ContactIdentity::generate_at(start), ContactIdentity::generate_at(start + EPOCH_LEN - 1));
    let (ca, cb) = (a.card(NET, 1), b.card(NET, 1));
    assert_eq!((ca.not_before, ca.not_after), (start - CLOCK_GRID_BACKDATE, start + EPOCH_LEN));
    assert_eq!((ca.not_before, ca.not_after), (cb.not_before, cb.not_after));
    assert_eq!(DRAIN_GRACE, 26 * 3_600, "24 h request lifetime (D2) + 2 h");
}

#[test]
fn a_card_never_outlives_its_inbox_epoch() {
    let bob = ContactIdentity::generate_at(T0);
    let wide = bob.card_within(NET, 1, 0, u64::MAX);
    assert_eq!((wide.not_before, wide.not_after), (bob.active().not_before(), bob.active().not_after()));
    let narrow = bob.card_within(NET, 1, T0, T0 + 10);
    assert_eq!((narrow.not_before, narrow.not_after), (T0, T0 + 10));
}

/// (a) A note sealed to epoch E-1 still opens after rotating to E, within
/// the grace window; and the open-time check alone refuses it after.
#[test]
fn a_note_to_the_previous_epoch_opens_during_the_grace_window() {
    let (mut bob, carol) = (ContactIdentity::generate_at(T0), ContactIdentity::generate_at(T0));
    let old_card = bob.card(NET, 1);
    let note = seal_to(&old_card, &carol);
    let created = epoch_start(T0) + 3 * DAY; // floored to a one-day window
    assert!(opens(&bob, &note, created, T0));

    let next = epoch_start(T0) + EPOCH_LEN;
    bob.rotate_epoch(next + 60);
    let new_card = bob.card(NET, 1);
    assert_ne!(new_card.inbox_key, old_card.inbox_key, "the card publishes the new epoch");
    assert_ne!(new_card.pq_inbox_key, old_card.pq_inbox_key);
    assert_eq!((new_card.not_before, new_card.not_after), (next - CLOCK_GRID_BACKDATE, next + EPOCH_LEN));
    assert_eq!(bob.draining().unwrap().not_after(), old_card.not_after);

    // A request created at the old card's last valid second is still open.
    let last_created = old_card.not_after - 1;
    let late = seal_to(&old_card, &carol);
    let deadline = old_card.not_after + DRAIN_GRACE;
    assert!(opens(&bob, &note, created, next + 60));
    assert!(opens(&bob, &late, last_created, last_created + DAY));
    assert!(opens(&bob, &late, last_created, deadline - 1), "last second of the grace");
    // It is the draining slot that opens it: the active keys alone do not.
    let saved = bob.to_secret_bytes();
    let mut active_only = ContactIdentity::from_secret_bytes(&saved).unwrap();
    active_only.purge_expired(u64::MAX);
    assert!(!opens(&active_only, &note, created, next + 60));
    // At the end of the grace the draining keys are no longer tried, even
    // before anyone purges them.
    assert!(bob.draining().is_some());
    assert!(!opens(&bob, &late, last_created, deadline));
}

/// (b) After purging past `not_after + DRAIN_GRACE`, the same note no longer
/// opens: the secrets that could read it are gone.
#[test]
fn purging_the_previous_epoch_makes_its_notes_unreadable() {
    let (mut bob, carol) = (ContactIdentity::generate_at(T0), ContactIdentity::generate_at(T0));
    let old_card = bob.card(NET, 1);
    let note = seal_to(&old_card, &carol);
    bob.rotate_epoch(epoch_start(T0) + EPOCH_LEN);
    let deadline = old_card.not_after + DRAIN_GRACE;

    assert!(!bob.purge_expired(deadline - 1), "kept until the grace is over");
    assert!(bob.draining().is_some());
    assert!(opens(&bob, &note, T0, deadline - 1));

    assert!(bob.purge_expired(deadline));
    assert!(bob.draining().is_none());
    assert!(!bob.purge_expired(deadline + 1), "nothing left to purge");
    // Gone whatever the clock says afterwards, and gone from storage too.
    assert!(!opens(&bob, &note, T0, T0));
    let restored = ContactIdentity::from_secret_bytes(&bob.to_secret_bytes()).unwrap();
    assert!(restored.draining().is_none());
    assert!(!opens(&restored, &note, T0, T0));
    // The new epoch is untouched.
    assert!(opens(&bob, &seal_to(&bob.card(NET, 1), &carol), T0, deadline));
}

/// (c) Rotating twice in a row drops the oldest epoch at once.
#[test]
fn rotating_twice_drops_the_oldest_epoch() {
    let (mut bob, carol) = (ContactIdentity::generate_at(T0), ContactIdentity::generate_at(T0));
    let first = seal_to(&bob.card(NET, 1), &carol);
    bob.rotate_epoch(T0);
    let second = seal_to(&bob.card(NET, 1), &carol);
    bob.rotate_epoch(T0);
    let third = seal_to(&bob.card(NET, 1), &carol);

    assert!(!opens(&bob, &first, T0, T0), "the first epoch is gone, its grace notwithstanding");
    assert!(opens(&bob, &second, T0, T0), "the second is draining");
    assert!(opens(&bob, &third, T0, T0), "the third is active");
    let restored = ContactIdentity::from_secret_bytes(&bob.to_secret_bytes()).unwrap();
    assert!(!opens(&restored, &first, T0, T0));
    assert!(opens(&restored, &second, T0, T0) && opens(&restored, &third, T0, T0));
}

/// (d) A card made just now is valid at the floored start of the clock-grid
/// window its request lands in, even right after an epoch boundary and
/// with a sender clock running ahead of the chain.
#[test]
fn a_fresh_card_opens_at_the_floored_start_of_its_creation_window() {
    let bob = ContactIdentity::generate_at(T0);
    let boundary = epoch_start(T0) + EPOCH_LEN;
    // Carol makes (or rotates to) her identity seconds after an epoch starts.
    let mut carol = ContactIdentity::generate_at(T0);
    carol.rotate_epoch(boundary + 5);
    let card = carol.card(NET, 1);
    assert_eq!(card.not_before, boundary - CLOCK_GRID_BACKDATE);
    let note = seal_to(&bob.card(NET, 1), &carol);
    // Windows of 6 s, one hour and one day, the widest P11 allows: the chain
    // stamps the window's start, before the moment the card was made.
    for window in [6, 3_600, DAY] {
        let floored = (boundary + 5) / window * window;
        assert!(floored <= boundary);
        assert!(opens(&bob, &note, floored, boundary + 5), "window {window}");
    }
    // Carol's clock ran an hour ahead: the chain was still in the old epoch.
    assert!(opens(&bob, &note, boundary - 3_600, boundary + 5));
    // The control: before the backdated start the card is refused.
    assert!(matches!(
        open_note(&bob, &NET, &note, card.not_before - 1, boundary),
        Err(NoteError::BadCard(ContactError::NotYetValid))
    ));
}

#[test]
fn the_stored_identity_is_strict() {
    let mut bob = ContactIdentity::generate_at(T0);
    let one = bob.to_secret_bytes().to_vec();
    bob.rotate_epoch(T0 + EPOCH_LEN);
    let two = bob.to_secret_bytes().to_vec();
    assert_eq!((one.len(), two.len()), (178, 322));
    let back = ContactIdentity::from_secret_bytes(&two).unwrap();
    assert_eq!(back.card(NET, 1), bob.card(NET, 1));
    assert_eq!(back.draining().unwrap().to_secret_bytes(), bob.draining().unwrap().to_secret_bytes());

    let bad = |edit: &dyn Fn(&mut Vec<u8>), from: &Vec<u8>| {
        let mut b = from.clone();
        edit(&mut b);
        ContactIdentity::from_secret_bytes(&b).err()
    };
    let flag = 1 + 32 + 144;
    assert_eq!(bad(&|b| b[0] = 3, &one), Some(ContactError::Malformed), "version");
    // Version 1 has another layout (a one-epoch buffer happens to have the
    // same length in both versions; the version byte tells them apart).
    assert_eq!(bad(&|b| b[0] = 1, &two), Some(ContactError::Malformed), "version 1 has another layout");
    assert_eq!(bad(&|b| b[flag] = 2, &one), Some(ContactError::Malformed), "flag");
    assert_eq!(bad(&|b| b[flag] = 1, &one), Some(ContactError::Malformed), "flag says two, one present");
    assert_eq!(bad(&|b| b[flag] = 0, &two), Some(ContactError::Malformed), "flag says one, two present");
    assert_eq!(bad(&|b| b.push(0), &one), Some(ContactError::Malformed), "trailing byte");
    assert_eq!(bad(&|b| { b.pop(); }, &two), Some(ContactError::Malformed), "missing byte");
    // An empty validity: not_after (last 8 bytes of the epoch) set to 0.
    assert_eq!(bad(&|b| b[flag - 8..flag].fill(0), &one), Some(ContactError::Malformed), "empty validity");
}
