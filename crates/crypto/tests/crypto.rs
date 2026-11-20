use anonymum_core::crypto::InviteProof;
use anonymum_core::{Chain, Error, Params, Tx, COIN};
use anonymum_crypto::{ContactIdentity, Ed25519Invites, Identity, InviteSecret, StaticKey};

// The IK session tests live next to the (crate-private) handshake types in
// `src/session.rs`; the wire-level ones in `tests/wire.rs`.

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
fn identities_survive_save_and_restore() {
    let wallet = Identity::generate();
    let (signing, messaging) = wallet.to_secret_bytes();
    assert_eq!(Identity::from_secret_bytes(signing, messaging).address(), wallet.address());
    let bob = ContactIdentity::generate();
    let (s, h, i) = bob.to_secret_bytes();
    let restored = ContactIdentity::from_secret_bytes(s, h, i);
    assert_eq!(restored.signing_key(), bob.signing_key());
    assert_eq!(restored.handshake_key().public(), bob.handshake_key().public());
    assert_eq!(restored.inbox_key().public(), bob.inbox_key().public());
    let key = StaticKey::generate();
    assert_eq!(StaticKey::from_bytes(key.to_bytes()).public(), key.public());
}
