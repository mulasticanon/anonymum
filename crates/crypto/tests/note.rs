use anonymum_core::crypto::{NOTE_INTRO_MAX_BYTES, NOTE_REPLY_ADDRESS_LEN};
use anonymum_core::{Chain, Error, Event, MessagingKey, Params, SealedNote, Tx, COIN, SEALED_NOTE_LEN};
use anonymum_crypto::{open_note, seal_note, Ed25519Invites, Identity, NoteError};

const REPLY: [u8; NOTE_REPLY_ADDRESS_LEN] = [7; NOTE_REPLY_ADDRESS_LEN];

fn key_of(who: &Identity) -> MessagingKey {
    let Tx::PublishMessagingKey { key, .. } = who.publish_key_tx() else { unreachable!() };
    key
}

#[test]
fn note_round_trip() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let intro = "Hello, it's Carol, I really need to talk to you about the flat.";
    let note = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, intro).unwrap();

    let opened = open_note(&bob, &carol.address(), &note).unwrap();
    assert_eq!(opened.reply_to, REPLY);
    assert_eq!(opened.intro, intro);
}

#[test]
fn every_note_has_the_same_size() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let max = "é".repeat(NOTE_INTRO_MAX_BYTES / 2); // 280 bytes, 140 characters
    for intro in ["", "hi", max.as_str()] {
        let note = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, intro).unwrap();
        assert_eq!(note.0.len(), SEALED_NOTE_LEN);
        assert_eq!(open_note(&bob, &carol.address(), &note).unwrap().intro, intro);
    }
}

#[test]
fn intro_over_280_bytes_is_refused_at_the_client() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let long = "x".repeat(NOTE_INTRO_MAX_BYTES + 1);
    let result = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, &long);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 281 })));
    // Bytes, not characters: 141 two-byte characters are 282 bytes.
    let long = "é".repeat(141);
    let result = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, &long);
    assert!(matches!(result, Err(NoteError::IntroTooLong { len: 282 })));
}

#[test]
fn only_the_recipient_can_open_a_note() {
    let (bob, carol, mallory) = (Identity::generate(), Identity::generate(), Identity::generate());
    let note = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, "hi").unwrap();
    assert!(matches!(open_note(&mallory, &carol.address(), &note), Err(NoteError::Noise(_))));
    assert!(!note.0.windows(REPLY.len()).any(|w| w == REPLY), "reply address not visible");
}

#[test]
fn a_note_copied_into_another_senders_request_does_not_open() {
    let (bob, carol, mallory) = (Identity::generate(), Identity::generate(), Identity::generate());
    let note = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, "hi").unwrap();
    // Mallory submits Carol's note in her own request; Bob opens it as hers.
    assert!(matches!(open_note(&bob, &mallory.address(), &note), Err(NoteError::Noise(_))));
}

#[test]
fn tampered_or_truncated_notes_are_rejected() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let note = seal_note(&key_of(&bob), &carol.address(), &bob.address(), &REPLY, "hi").unwrap();
    for index in [0, 40, SEALED_NOTE_LEN - 1] {
        let mut bad = note.clone();
        bad.0[index] ^= 1;
        assert!(open_note(&bob, &carol.address(), &bad).is_err(), "flip at {index}");
    }
    let short = SealedNote(note.0[..SEALED_NOTE_LEN - 1].to_vec());
    assert!(matches!(open_note(&bob, &carol.address(), &short), Err(NoteError::BadSize { .. })));
}

#[test]
fn chain_accepts_a_real_binding_and_rejects_someone_elses() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);

    // Carol tries to publish Bob's key (with Bob's valid binding) as her own.
    let err = chain.apply(carol.address(), bob.publish_key_tx()).unwrap_err();
    assert_eq!(err, Error::BadKeyBinding);
    assert!(chain.messaging_key(&carol.address()).is_none());

    chain.apply(bob.address(), bob.publish_key_tx()).unwrap();
    assert_eq!(chain.messaging_key(&bob.address()).unwrap().key, key_of(&bob));
}

#[test]
fn stranger_flow_through_the_chain_with_real_keys() {
    let (bob, carol) = (Identity::generate(), Identity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(carol.address(), 10 * COIN);
    chain.apply(bob.address(), bob.publish_key_tx()).unwrap();

    // Carol reads Bob's key from the chain and seals her note to it.
    let bobs_key = chain.messaging_key(&bob.address()).unwrap().key;
    let note = seal_note(&bobs_key, &carol.address(), &bob.address(), &REPLY, "hi Bob").unwrap();
    let events = chain
        .apply(carol.address(), Tx::RequestContact { recipient: bob.address(), max_price: COIN, note })
        .unwrap();

    // Bob's client opens the note from the chain event.
    let Event::ContactRequested { from, note, .. } = &events[0] else { panic!() };
    let opened = open_note(&bob, from, note).unwrap();
    assert_eq!((opened.reply_to, opened.intro.as_str()), (REPLY, "hi Bob"));
}
