use anonymum_core::crypto::InviteProof;
use anonymum_core::{Chain, Error, Params, Tx, COIN};
use anonymum_crypto::{
    ContactIdentity, Ed25519Invites, Handshake, Identity, Incoming, InviteSecret, Session, SessionError, StaticKey,
};

const NET: [u8; 32] = [9; 32];
const REF: [u8; 32] = [3; 32];

/// An IK handshake from caller key `caller` to `answerer`'s handshake key.
fn connect(caller: &StaticKey, answerer: &ContactIdentity) -> (Session, Session) {
    let (hs, m1) = Handshake::initiate(caller, &answerer.handshake_key().public(), &NET, &REF).unwrap();
    let incoming = Incoming::read(answerer.handshake_key(), &NET, &m1).unwrap();
    let (session_r, m2) = incoming.accept().unwrap();
    (hs.finish(&m2).unwrap(), session_r)
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
    let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate());
    let (mut a, mut b) = connect(&alice, &bob);
    assert_eq!(a.peer(), bob.handshake_key().public());
    assert_eq!(b.peer(), alice.public(), "the answerer learns the caller's key from message 1");

    let sealed = a.seal(b"meet at noon").unwrap();
    assert_eq!(b.open(&sealed).unwrap(), b"meet at noon");
    let reply = b.seal(b"ok").unwrap();
    assert_eq!(a.open(&reply).unwrap(), b"ok");
}

#[test]
fn the_answerer_reads_caller_and_reference_before_writing_anything() {
    let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate());
    let (_hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &REF).unwrap();
    let incoming = Incoming::read(bob.handshake_key(), &NET, &m1).unwrap();
    assert_eq!(incoming.caller(), alice.public());
    assert_eq!(incoming.reference(), REF);
    // Someone else's handshake key cannot read it; another network neither.
    let eve = ContactIdentity::generate();
    assert!(Incoming::read(eve.handshake_key(), &NET, &m1).is_err());
    assert!(Incoming::read(bob.handshake_key(), &[0; 32], &m1).is_err());
}

#[test]
fn ciphertext_reveals_nothing_recognisable_and_outsiders_cannot_open_it() {
    let (alice, bob, eve) = (StaticKey::generate(), ContactIdentity::generate(), ContactIdentity::generate());
    let (mut a, _b) = connect(&alice, &bob);
    let secret = b"the launch code is 0000";
    let sealed = a.seal(secret).unwrap();
    assert!(!sealed.windows(secret.len()).any(|w| w == secret));
    let (_a2, mut e) = connect(&alice, &eve);
    assert!(matches!(e.open(&sealed), Err(SessionError::Noise(_))));
}

#[test]
fn handshake_exposes_no_static_key_reference_or_wallet() {
    let (alice, bob, wallet) = (StaticKey::generate(), ContactIdentity::generate(), Identity::generate());
    let (hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &REF).unwrap();
    let (_s, m2) = Incoming::read(bob.handshake_key(), &NET, &m1).unwrap().accept().unwrap();
    hs.finish(&m2).unwrap();
    for wire in [&m1, &m2] {
        for key in [alice.public(), bob.handshake_key().public(), bob.signing_key(), REF, wallet.address().0] {
            assert!(!wire.windows(32).any(|w| w == key), "a key or the reference is visible on the wire");
        }
    }
}

#[test]
fn messages_survive_reordering_but_not_replay() {
    let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate());
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
    let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate());
    let (mut a, mut b) = connect(&alice, &bob);
    let sealed = a.seal(b"pay 10").unwrap();
    let mut forged = sealed.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(b.open(&forged), Err(SessionError::Noise(_))));
    assert!(matches!(b.open(&[0u8; 5]), Err(SessionError::Malformed)));
    assert_eq!(b.open(&sealed).unwrap(), b"pay 10");
}

#[test]
fn a_caller_reaching_the_wrong_answerer_cannot_finish() {
    // Alice calls Bob's key; Mallory cannot read message 1, and a message 2
    // she makes for her own handshake does not finish Alice's.
    let (alice, bob, mallory) = (StaticKey::generate(), ContactIdentity::generate(), ContactIdentity::generate());
    let (hs, m1) = Handshake::initiate(&alice, &bob.handshake_key().public(), &NET, &REF).unwrap();
    assert!(Incoming::read(mallory.handshake_key(), &NET, &m1).is_err());
    let (_other, m1_to_mallory) =
        Handshake::initiate(&alice, &mallory.handshake_key().public(), &NET, &REF).unwrap();
    let (_s, forged) = Incoming::read(mallory.handshake_key(), &NET, &m1_to_mallory).unwrap().accept().unwrap();
    assert!(matches!(hs.finish(&forged), Err(SessionError::Noise(_))));
}

#[test]
fn identities_survive_save_and_restore() {
    let wallet = Identity::generate();
    let (signing, messaging) = wallet.to_secret_bytes();
    assert_eq!(Identity::from_secret_bytes(signing, messaging).address(), wallet.address());

    let bob = ContactIdentity::generate();
    let (s, h, i) = bob.to_secret_bytes();
    let restored = ContactIdentity::from_secret_bytes(s, h, i);
    assert_eq!(restored.signing_key(), bob.signing_key());
    let alice = StaticKey::from_bytes(StaticKey::generate().to_bytes());
    let (mut a, mut b) = connect(&alice, &restored);
    assert_eq!(b.open(&a.seal(b"still me").unwrap()).unwrap(), b"still me");
    assert_eq!(a.peer(), bob.handshake_key().public());
}

#[test]
fn oversized_message_is_refused() {
    let (alice, bob) = (StaticKey::generate(), ContactIdentity::generate());
    let (mut a, _b) = connect(&alice, &bob);
    assert!(matches!(a.seal(&vec![0u8; anonymum_crypto::MAX_PLAINTEXT + 1]), Err(SessionError::TooLarge)));
    assert!(a.seal(&vec![0u8; anonymum_crypto::MAX_PLAINTEXT]).is_ok());
}
