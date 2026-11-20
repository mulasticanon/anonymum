/// The core simulation's default genesis id.
const G: [u8; 32] = *b"anonymum-core-simulation-genesis";

use anonymum_core::{Chain, Error, Event, MessagingKey, Params, SealedNote, Tx, COIN, SEALED_NOTE_LEN};
use anonymum_crypto::note::{INTRO_MAX_BYTES, ROUTE_LEN};
use anonymum_crypto::{open_note, seal_note, ContactCard, ContactIdentity, Ed25519Invites, Identity, NoteError};

const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
const ADMISSION: [u8; 32] = [0xAD; 32];
const NET: [u8; 32] = [9; 32];
const NOW: u64 = 50;

fn card(who: &ContactIdentity) -> ContactCard {
    who.card(NET, 1_000, 0, 100)
}

fn seal(to: &ContactIdentity, from: &ContactIdentity, intro: &str) -> SealedNote {
    seal_note(&NET, &to.inbox_key().public(), from, &card(from), &ROUTE, intro, &ADMISSION).unwrap()
}

#[test]
fn a_note_opens_and_names_the_right_sender() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let intro = "Hello, it's Carol, I really need to talk to you about the flat.";
    let note = seal(&bob, &carol, intro);
    assert_eq!(note.0.len(), SEALED_NOTE_LEN);
    let opened = open_note(&bob, &NET, &note, NOW).unwrap();
    assert_eq!(opened.admission, ADMISSION);
    assert_eq!(opened.sender(), carol.signing_key());
    assert_eq!(opened.callback(), carol.handshake_key().public());
    assert_eq!(opened.card, card(&carol), "the sender's full card, verified");
    assert_eq!((opened.route, opened.intro.as_str()), (ROUTE, intro));
    for key in [carol.signing_key(), carol.handshake_key().public(), carol.inbox_key().public(), bob.inbox_key().public()] {
        assert!(!note.0.windows(32).any(|w| w == key), "a key is visible in the note");
    }
    assert!(!note.0.windows(ROUTE_LEN).any(|w| w == ROUTE), "the route is not visible");
}

#[test]
fn a_fresh_wallet_finds_and_opens_its_note_with_no_sender_hint() {
    let bob = ContactIdentity::generate();
    let (s, h, i) = bob.to_secret_bytes();
    let others: Vec<ContactIdentity> = (0..4).map(|_| ContactIdentity::generate()).collect();
    let carol = ContactIdentity::generate();
    let mut chain_notes: Vec<SealedNote> = others.iter().map(|o| seal(o, &carol, "not for Bob")).collect();
    chain_notes.insert(2, seal(&bob, &carol, "for Bob"));
    chain_notes.push(seal(&others[0], &ContactIdentity::generate(), "also not"));

    let fresh = ContactIdentity::from_secret_bytes(s, h, i);
    let mine: Vec<_> = chain_notes.iter().filter_map(|n| open_note(&fresh, &NET, n, NOW).ok()).collect();
    assert_eq!(mine.len(), 1);
    assert_eq!((mine[0].intro.as_str(), mine[0].sender()), ("for Bob", carol.signing_key()));
}

#[test]
fn every_note_has_the_same_size() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let max = "é".repeat(INTRO_MAX_BYTES / 2); // 280 bytes, 140 characters
    for intro in ["", "hi", max.as_str()] {
        let note = seal(&bob, &carol, intro);
        assert_eq!(note.0.len(), SEALED_NOTE_LEN);
        assert_eq!(open_note(&bob, &NET, &note, NOW).unwrap().intro, intro);
    }
}

#[test]
fn intro_over_280_bytes_is_refused_at_the_client() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let inbox = bob.inbox_key().public();
    let long = "x".repeat(INTRO_MAX_BYTES + 1);
    let result = seal_note(&NET, &inbox, &carol, &card(&carol), &ROUTE, &long, &ADMISSION);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 281 })));
    let long = "é".repeat(141); // bytes, not characters: 282
    let result = seal_note(&NET, &inbox, &carol, &card(&carol), &ROUTE, &long, &ADMISSION);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 282 })));
}

#[test]
fn a_note_for_another_recipient_does_not_open() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let note = seal(&bob, &carol, "hi");
    // Not the sender, not someone else, and not Bob's handshake key.
    assert!(matches!(open_note(&carol, &NET, &note, NOW), Err(NoteError::Noise(_))));
    assert!(matches!(open_note(&ContactIdentity::generate(), &NET, &note, NOW), Err(NoteError::Noise(_))));
    let (s, _, i) = bob.to_secret_bytes();
    let swapped = ContactIdentity::from_secret_bytes(s, i, bob.handshake_key().to_bytes());
    assert!(matches!(open_note(&swapped, &NET, &note, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn a_note_moved_to_another_admission_record_does_not_open() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let mut note = seal(&bob, &carol, "hi");
    note.0[..32].copy_from_slice(&[0xEE; 32]);
    assert!(matches!(open_note(&bob, &NET, &note, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn a_note_sealed_for_one_network_does_not_open_on_another() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let note = seal(&bob, &carol, "hi");
    assert!(open_note(&bob, &NET, &note, NOW).is_ok());
    assert!(matches!(open_note(&bob, &[8; 32], &note, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn tampered_or_truncated_notes_are_rejected() {
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let note = seal(&bob, &carol, "hi");
    for index in [0, 31, 32, 40, 100, 200, SEALED_NOTE_LEN - 1] {
        let mut bad = note.clone();
        bad.0[index] ^= 1;
        assert!(open_note(&bob, &NET, &bad, NOW).is_err(), "flip at {index}");
    }
    let short = SealedNote(note.0[..SEALED_NOTE_LEN - 1].to_vec());
    assert!(matches!(open_note(&bob, &NET, &short, NOW), Err(NoteError::BadSize { .. })));
}

#[test]
fn chain_accepts_a_real_binding_and_rejects_someone_elses() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(bob.address(), COIN); // messaging-key deposit
    let err = chain.apply(carol.address(), bob.publish_key_tx(&G)).unwrap_err();
    assert_eq!(err, Error::BadKeyBinding);
    chain.apply(bob.address(), bob.publish_key_tx(&G)).unwrap();
    let Tx::PublishMessagingKey { key, .. } = bob.publish_key_tx(&G) else { unreachable!() };
    assert_eq!(chain.messaging_key(&bob.address()).unwrap().key, key);
    let _: MessagingKey = key;
}

#[test]
fn stranger_flow_through_the_transparent_chain() {
    // The transparent prototype chain still records wallet-to-wallet
    // requests (a known gap until stage 5). The note itself carries no
    // wallet key and opens with Bob's contact inbox key alone.
    let (bob_wallet, carol_wallet) = (Identity::generate(), Identity::generate());
    let (bob, carol) = (ContactIdentity::generate(), ContactIdentity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(bob_wallet.address(), COIN);
    chain.mint(carol_wallet.address(), 10 * COIN);
    chain.apply(bob_wallet.address(), bob_wallet.publish_key_tx(&G)).unwrap();

    let note = seal(&bob, &carol, "hi Bob");
    for wallet_key in [bob_wallet.address().0, carol_wallet.address().0] {
        assert!(!note.0.windows(32).any(|w| w == wallet_key));
    }
    let events = chain
        .apply(carol_wallet.address(), Tx::RequestContact { recipient: bob_wallet.address(), max_price: COIN, note })
        .unwrap();
    let Event::ContactRequested { note, .. } = &events[0] else { panic!() };
    let opened = open_note(&bob, &NET, note, NOW).unwrap();
    assert_eq!((opened.route, opened.intro.as_str()), (ROUTE, "hi Bob"));
}
