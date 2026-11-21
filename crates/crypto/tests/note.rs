/// The core simulation's default genesis id.
const G: [u8; 32] = *b"anonymum-core-simulation-genesis";

use anonymum_core::{Chain, Error, Event, MessagingKey, Params, SealedNote, Tx, COIN, SEALED_NOTE_LEN};
use anonymum_crypto::note::{INTRO_MAX_BYTES, ROUTE_LEN};
use anonymum_crypto::{open_note, seal_note, ContactCard, ContactIdentity, KeyEpoch, Ed25519Invites, Identity, NoteError};

const ROUTE: [u8; ROUTE_LEN] = [7; ROUTE_LEN];
const ADMISSION: [u8; 32] = [0xAD; 32];
const NET: [u8; 32] = [9; 32];
const NOW: u64 = 50;

fn card(who: &ContactIdentity) -> ContactCard {
    who.card_within(NET, 1_000, 0, 100)
}

fn seal(to: &ContactIdentity, from: &ContactIdentity, intro: &str) -> SealedNote {
    seal_note(&NET, &card(to), from, &card(from), &ROUTE, intro, &ADMISSION).unwrap()
}

#[test]
fn a_note_opens_and_names_the_right_sender() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let intro = "Hello, it's Carol, I really need to talk to you about the flat.";
    let note = seal(&bob, &carol, intro);
    assert_eq!(note.0.len(), SEALED_NOTE_LEN);
    let opened = open_note(&bob, &NET, &note, NOW, NOW).unwrap();
    assert_eq!(opened.admission, ADMISSION);
    assert_eq!(opened.sender(), carol.signing_key());
    assert_eq!(opened.callback(), carol.handshake_key().public());
    assert_eq!(opened.card, card(&carol).summary(), "the sender's card (post-quantum key as its hash), verified");
    assert_eq!((opened.route, opened.intro.as_str()), (ROUTE, intro));
    let carol_pq_hash = card(&carol).summary().pq_inbox_hash;
    for key in [carol.signing_key(), carol.handshake_key().public(), carol.inbox_key().public(), bob.inbox_key().public(), carol_pq_hash] {
        assert!(!note.0.windows(32).any(|w| w == key), "a key is visible in the note");
    }
    assert!(!note.0.windows(ROUTE_LEN).any(|w| w == ROUTE), "the route is not visible");
}

#[test]
fn a_fresh_wallet_finds_and_opens_its_note_with_no_sender_hint() {
    let bob = ContactIdentity::generate_at(NOW);
    let saved = bob.to_secret_bytes();
    let others: Vec<ContactIdentity> = (0..4).map(|_| ContactIdentity::generate_at(NOW)).collect();
    let carol = ContactIdentity::generate_at(NOW);
    let mut chain_notes: Vec<SealedNote> = others.iter().map(|o| seal(o, &carol, "not for Bob")).collect();
    chain_notes.insert(2, seal(&bob, &carol, "for Bob"));
    chain_notes.push(seal(&others[0], &ContactIdentity::generate_at(NOW), "also not"));

    let fresh = ContactIdentity::from_secret_bytes(&saved).unwrap();
    let mine: Vec<_> = chain_notes.iter().filter_map(|n| open_note(&fresh, &NET, n, NOW, NOW).ok()).collect();
    assert_eq!(mine.len(), 1);
    assert_eq!((mine[0].intro.as_str(), mine[0].sender()), ("for Bob", carol.signing_key()));
}

#[test]
fn every_note_has_the_same_size() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let max = "é".repeat(INTRO_MAX_BYTES / 2); // 280 bytes, 140 characters
    for intro in ["", "hi", max.as_str()] {
        let note = seal(&bob, &carol, intro);
        assert_eq!(note.0.len(), SEALED_NOTE_LEN);
        assert_eq!(open_note(&bob, &NET, &note, NOW, NOW).unwrap().intro, intro);
    }
}

#[test]
fn intro_over_280_bytes_is_refused_at_the_client() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let inbox = card(&bob);
    let long = "x".repeat(INTRO_MAX_BYTES + 1);
    let result = seal_note(&NET, &inbox, &carol, &card(&carol), &ROUTE, &long, &ADMISSION);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 281 })));
    let long = "é".repeat(141); // bytes, not characters: 282
    let result = seal_note(&NET, &inbox, &carol, &card(&carol), &ROUTE, &long, &ADMISSION);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 282 })));
}

#[test]
fn a_note_for_another_recipient_does_not_open() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let note = seal(&bob, &carol, "hi");
    // Not the sender, not someone else, and not Bob's handshake key.
    assert!(matches!(open_note(&carol, &NET, &note, NOW, NOW), Err(NoteError::Noise(_))));
    assert!(matches!(open_note(&ContactIdentity::generate_at(NOW), &NET, &note, NOW, NOW), Err(NoteError::Noise(_))));
    let signing = bob.signing_secret_bytes();
    let (handshake, inbox, pq, not_before, not_after) = bob.active().to_secret_bytes();
    let as_inbox = KeyEpoch::from_secret_bytes(inbox, handshake, pq, not_before, not_after).unwrap();
    let swapped = ContactIdentity::from_parts(*signing, as_inbox, None, 1);
    assert!(matches!(open_note(&swapped, &NET, &note, NOW, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn a_note_moved_to_another_admission_record_does_not_open() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let mut note = seal(&bob, &carol, "hi");
    note.0[..32].copy_from_slice(&[0xEE; 32]);
    assert!(matches!(open_note(&bob, &NET, &note, NOW, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn a_note_sealed_for_one_network_does_not_open_on_another() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let note = seal(&bob, &carol, "hi");
    assert!(open_note(&bob, &NET, &note, NOW, NOW).is_ok());
    assert!(matches!(open_note(&bob, &[8; 32], &note, NOW, NOW), Err(NoteError::Noise(_))));
}

#[test]
fn tampered_or_truncated_notes_are_rejected() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let note = seal(&bob, &carol, "hi");
    // Admission, ML-KEM ciphertext, Noise ephemeral, static and payload.
    for index in [0, 31, 32, 600, 1_119, 1_120, 1_160, 1_300, SEALED_NOTE_LEN - 1] {
        let mut bad = note.clone();
        bad.0[index] ^= 1;
        assert!(open_note(&bob, &NET, &bad, NOW, NOW).is_err(), "flip at {index}");
    }
    let short = SealedNote(note.0[..SEALED_NOTE_LEN - 1].to_vec());
    assert!(matches!(open_note(&bob, &NET, &short, NOW, NOW), Err(NoteError::BadSize { .. })));
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
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
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
    let opened = open_note(&bob, &NET, note, NOW, NOW).unwrap();
    assert_eq!((opened.route, opened.intro.as_str()), (ROUTE, "hi Bob"));
}

// ---- the sender's card is checked at the request's creation time ------------

#[test]
fn a_card_valid_at_creation_but_expired_by_opening_time_still_opens() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let note = seal(&bob, &carol, "hi"); // Carol's card is valid in [0, 100)
    // By the time Bob opens it (today's clock), the card has expired...
    let today = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(card(&carol).verify(&NET, today), Err(anonymum_crypto::ContactError::Expired));
    // ...but it was valid when the request was created on chain, at 99.
    let opened = open_note(&bob, &NET, &note, 99, 99).unwrap();
    assert_eq!(opened.sender(), carol.signing_key());
}

#[test]
fn a_card_expired_or_not_yet_valid_at_creation_is_refused() {
    let (bob, carol) = (ContactIdentity::generate_at(NOW), ContactIdentity::generate_at(NOW));
    let note = seal(&bob, &carol, "hi"); // valid in [0, 100)
    assert!(matches!(
        open_note(&bob, &NET, &note, 100, 100),
        Err(NoteError::BadCard(anonymum_crypto::ContactError::Expired))
    ));
    let later = seal_note(&NET, &card(&bob), &carol, &carol.card_within(NET, 1_000, 60, 100), &ROUTE, "hi", &ADMISSION)
        .unwrap();
    assert!(matches!(
        open_note(&bob, &NET, &later, 59, 59),
        Err(NoteError::BadCard(anonymum_crypto::ContactError::NotYetValid))
    ));
    assert!(open_note(&bob, &NET, &later, 60, 60).is_ok());
}
