use anonymum_core::crypto::InviteProof;
use anonymum_core::{Chain, Error, Params, Tx, COIN};
use anonymum_crypto::{Ed25519Invites, Handshake, Identity, InviteSecret, Session, SessionError};

fn connect(initiator: &Identity, responder: &Identity) -> (Session, Session) {
    let (hs_i, m1) = Handshake::initiate(initiator, responder.address()).unwrap();
    let (hs_r, m2) = Handshake::respond(responder, &m1).unwrap();
    let (session_i, m3) = hs_i.initiator_finish(&m2).unwrap();
    let session_r = hs_r.responder_finish(&m3).unwrap();
    (session_i, session_r)
}

#[test]
fn real_invite_opens_channel_on_chain() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(alice.address(), 10 * COIN);
    chain.mint(bob.address(), COIN); // invite deposit

    let invite = InviteSecret::generate();
    chain.apply(bob.address(), Tx::RegisterInvite { key: invite.public(), expires_at: None }).unwrap();

    // Bob hands the 32 secret bytes to Alice; she rebuilds the invite.
    let received = InviteSecret::from_bytes(invite.to_bytes());
    chain
        .apply(
            alice.address(),
            Tx::OpenWithInvite {
                recipient: bob.address(),
                key: received.public(),
                proof: received.sign_for(&alice.address(), &bob.address()),
            },
        )
        .unwrap();
    assert!(chain.channel_between(&alice.address(), &bob.address()).is_some());
}

#[test]
fn copied_or_tampered_invite_proof_fails() {
    let (alice, bob, mallory) = (Identity::generate(), Identity::generate(), Identity::generate());
    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(mallory.address(), 10 * COIN);
    chain.mint(alice.address(), 10 * COIN);
    chain.mint(bob.address(), COIN); // invite deposit
    let invite = InviteSecret::generate();
    chain.apply(bob.address(), Tx::RegisterInvite { key: invite.public(), expires_at: None }).unwrap();
    let proof = invite.sign_for(&alice.address(), &bob.address());

    // Mallory front-runs with Alice's proof.
    let stolen = Tx::OpenWithInvite { recipient: bob.address(), key: invite.public(), proof: proof.clone() };
    assert_eq!(chain.apply(mallory.address(), stolen).unwrap_err(), Error::BadInviteProof);

    // A flipped bit invalidates the proof even for Alice.
    let mut bytes = proof.0.clone();
    bytes[10] ^= 1;
    let tampered = Tx::OpenWithInvite { recipient: bob.address(), key: invite.public(), proof: InviteProof(bytes) };
    assert_eq!(chain.apply(alice.address(), tampered).unwrap_err(), Error::BadInviteProof);

    // Garbage of the wrong length is rejected, not a crash.
    let junk = Tx::OpenWithInvite { recipient: bob.address(), key: invite.public(), proof: InviteProof(vec![1, 2, 3]) };
    assert_eq!(chain.apply(alice.address(), junk).unwrap_err(), Error::BadInviteProof);
}

#[test]
fn session_round_trip_and_mutual_authentication() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let (mut a, mut b) = connect(&alice, &bob);

    assert_eq!(a.peer(), bob.address());
    assert_eq!(b.peer(), alice.address(), "responder learns who called, from inside the handshake");

    let sealed = a.seal(b"meet at noon").unwrap();
    assert_eq!(b.open(&sealed).unwrap(), b"meet at noon");
    let reply = b.seal(b"ok").unwrap();
    assert_eq!(a.open(&reply).unwrap(), b"ok");
}

#[test]
fn ciphertext_reveals_nothing_recognisable_and_outsiders_cannot_open_it() {
    let (alice, bob, eve) = (Identity::generate(), Identity::generate(), Identity::generate());
    let (mut a, _b) = connect(&alice, &bob);
    let secret = b"the launch code is 0000";
    let sealed = a.seal(secret).unwrap();
    assert!(!sealed.windows(secret.len()).any(|w| w == secret));

    // Eve has her own session with Alice; its keys do not open Bob's traffic.
    let (_a2, mut e) = connect(&alice, &eve);
    assert!(matches!(e.open(&sealed), Err(SessionError::Noise(_))));
}

#[test]
fn handshake_does_not_expose_addresses() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let (hs_i, m1) = Handshake::initiate(&alice, bob.address()).unwrap();
    let (hs_r, m2) = Handshake::respond(&bob, &m1).unwrap();
    let (_s, m3) = hs_i.initiator_finish(&m2).unwrap();
    let _ = hs_r.responder_finish(&m3).unwrap();
    for wire in [&m1, &m2, &m3] {
        for address in [alice.address(), bob.address()] {
            assert!(!wire.windows(32).any(|w| w == address.0), "address visible on the wire");
        }
    }
}

#[test]
fn messages_survive_reordering_but_not_replay() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let (mut a, mut b) = connect(&alice, &bob);
    let sealed: Vec<Vec<u8>> = (0..5u8).map(|i| a.seal(&[i]).unwrap()).collect();

    for i in [3usize, 0, 4, 1, 2] {
        assert_eq!(b.open(&sealed[i]).unwrap(), vec![i as u8]);
    }
    for message in &sealed {
        assert!(matches!(b.open(message), Err(SessionError::Replay)));
    }
}

#[test]
fn tampered_message_is_rejected_and_does_not_block_the_real_one() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let (mut a, mut b) = connect(&alice, &bob);
    let sealed = a.seal(b"pay 10").unwrap();

    let mut forged = sealed.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(b.open(&forged), Err(SessionError::Noise(_))));
    assert!(matches!(b.open(&[0u8; 5]), Err(SessionError::Malformed)));

    assert_eq!(b.open(&sealed).unwrap(), b"pay 10");
}

#[test]
fn initiator_refuses_an_impostor_responder() {
    let (alice, bob, mallory) = (Identity::generate(), Identity::generate(), Identity::generate());
    // Alice wants Bob, but Mallory intercepts and answers.
    let (hs_i, m1) = Handshake::initiate(&alice, bob.address()).unwrap();
    let (_hs_m, m2) = Handshake::respond(&mallory, &m1).unwrap();
    match hs_i.initiator_finish(&m2) {
        Err(SessionError::UnexpectedPeer { got }) => assert_eq!(got, mallory.address()),
        _ => panic!("impostor was accepted"),
    }
}

#[test]
fn identity_survives_save_and_restore() {
    let original = Identity::generate();
    let (signing, messaging) = original.to_secret_bytes();
    let restored = Identity::from_secret_bytes(signing, messaging);
    assert_eq!(original.address(), restored.address());
    let bob = Identity::generate();
    let (mut a, mut b) = connect(&restored, &bob);
    assert_eq!(b.open(&a.seal(b"still me").unwrap()).unwrap(), b"still me");
    assert_eq!(b.peer(), original.address());
}

#[test]
fn oversized_message_is_refused() {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let (mut a, _b) = connect(&alice, &bob);
    assert!(matches!(a.seal(&vec![0u8; anonymum_crypto::MAX_PLAINTEXT + 1]), Err(SessionError::TooLarge)));
    assert!(a.seal(&vec![0u8; anonymum_crypto::MAX_PLAINTEXT]).is_ok());
}
