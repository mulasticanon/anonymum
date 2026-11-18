//! Anonymum over the live Nym mixnet.
//!
//! Three wallets in one process, each with its own Nym client:
//!
//! * Alice holds an invite from Bob, opens a channel, and exchanges
//!   end-to-end encrypted messages with him through the mixnet.
//! * Carol has no channel. Bob's client authenticates her, sees no channel
//!   on the chain, and drops her.
//!
//! The chain here is the in-process simulation from `anonymum-core`. The
//! mixnet and the cryptography are real.
//!
//!     cargo run -p anonymum-nym

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anonymum_core::{Chain, Envelope, Inbox, Params, Tx, Verdict, COIN};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent};
use anonymum_crypto::{Ed25519Invites, Identity, InviteSecret};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient,
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);

/// A Nym client plus a queue, because the mixnet hands over messages in batches.
struct Endpoint {
    name: &'static str,
    client: MixnetClient,
    queue: VecDeque<(Vec<u8>, Option<AnonymousSenderTag>)>,
}

impl Endpoint {
    async fn connect(name: &'static str) -> Result<Self, AnyError> {
        let started = Instant::now();
        // Gateways reached over TLS on port 443 work from behind most
        // firewalls. Set ANONYMUM_PLAIN_WS=1 to allow any gateway instead.
        let tls_only = std::env::var_os("ANONYMUM_PLAIN_WS").is_none();
        let client = MixnetClientBuilder::new_ephemeral()
            .force_tls(tls_only)
            .build()?
            .connect_to_mixnet()
            .await?;
        println!("  {name} connected to the mixnet in {:.1}s", started.elapsed().as_secs_f32());
        Ok(Endpoint { name, client, queue: VecDeque::new() })
    }

    fn address(&self) -> Recipient {
        *self.client.nym_address()
    }

    /// Send to a known mixnet address. Reply blocks are attached by default,
    /// so the receiver can answer without learning our address.
    async fn send(&self, to: Recipient, frame: Vec<u8>) -> Result<(), AnyError> {
        self.client.send_plain_message(to, frame).await?;
        Ok(())
    }

    /// Answer a caller through their single-use reply blocks.
    async fn reply(&self, to: AnonymousSenderTag, frame: Vec<u8>) -> Result<(), AnyError> {
        self.client.send_reply(to, frame).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<(Vec<u8>, Option<AnonymousSenderTag>), AnyError> {
        let deadline = tokio::time::Instant::now() + RECEIVE_TIMEOUT;
        loop {
            if let Some(next) = self.queue.pop_front() {
                return Ok(next);
            }
            let batch = tokio::time::timeout_at(deadline, self.client.wait_for_messages())
                .await
                .map_err(|_| format!("{} waited {RECEIVE_TIMEOUT:?} and received nothing", self.name))?
                .ok_or_else(|| format!("{}'s mixnet connection closed", self.name))?;
            self.queue
                .extend(batch.into_iter().filter(|m| !m.message.is_empty()).map(|m| (m.message, m.sender_tag)));
        }
    }
}

/// Stack size for the main and runtime threads. The Nym client's futures are
/// large in debug builds, and Windows gives the main thread only 1 MiB
/// (Linux: 8 MiB), which overflowed while connecting to the mixnet.
const STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> Result<(), AnyError> {
    std::thread::Builder::new()
        .name("anonymum-main".into())
        .stack_size(STACK_SIZE)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(STACK_SIZE)
                .build()?
                .block_on(run())
        })?
        .join()
        .map_err(|_| "main thread panicked")?
}

async fn run() -> Result<(), AnyError> {
    let clock = Instant::now();

    // ---- wallets and chain ------------------------------------------------
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    println!("Wallets\n  alice {}\n  bob   {}\n  carol {}", alice.address(), bob.address(), carol.address());

    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(alice.address(), 10 * COIN);

    println!("\nOn-chain: Bob creates an invite, Alice uses it to open a channel.");
    let invite = InviteSecret::generate();
    chain.apply(bob.address(), Tx::RegisterInvite { key: invite.public(), expires_at: None })?;
    let handed_over = InviteSecret::from_bytes(invite.to_bytes()); // out of band
    chain.apply(
        alice.address(),
        Tx::OpenWithInvite {
            recipient: bob.address(),
            key: handed_over.public(),
            proof: handed_over.sign_for(&alice.address(), &bob.address()),
        },
    )?;
    println!("  channel alice<->bob open: {}", chain.channel_between(&alice.address(), &bob.address()).is_some());
    println!("  channel carol<->bob open: {}", chain.channel_between(&carol.address(), &bob.address()).is_some());

    // ---- mixnet -----------------------------------------------------------
    println!("\nConnecting to the Nym mixnet...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let mut alice_net = Endpoint::connect("alice").await?;
    let mut carol_net = Endpoint::connect("carol").await?;
    // In the real system Bob's mixnet address travels with the invite (or,
    // for strangers, with his public contact listing).
    let bob_mix_address = bob_net.address();
    let mut bob_side: Responder<AnonymousSenderTag> = Responder::new();
    let mut bob_inbox = Inbox::new(bob.address(), 20, 1);

    // ---- Alice calls Bob --------------------------------------------------
    println!("\nAlice -> Bob: encrypted handshake through the mixnet.");
    let started = Instant::now();
    let (mut alice_call, frame1) = Initiator::start(&alice, bob.address())?;
    alice_net.send(bob_mix_address, frame1).await?;

    let (frame, tag) = bob_net.receive().await?;
    let alice_tag = tag.ok_or("handshake arrived without reply blocks")?;
    let ResponderEvent::Reply(frame2) = bob_side.handle(&bob, alice_tag, &frame)? else {
        return Err("expected a handshake reply".into());
    };
    bob_net.reply(alice_tag, frame2).await?;

    let (frame, _) = alice_net.receive().await?;
    let InitiatorEvent::Established { reply: frame3 } = alice_call.handle(&frame)? else {
        return Err("expected handshake completion".into());
    };
    alice_net.send(bob_mix_address, frame3).await?;

    let (frame, tag) = bob_net.receive().await?;
    let ResponderEvent::Established { peer } = bob_side.handle(&bob, tag.unwrap_or(alice_tag), &frame)? else {
        return Err("expected session".into());
    };
    let has_channel = chain.channel_between(&peer, &bob.address()).is_some();
    println!(
        "  Bob authenticated caller as {peer} (alice: {}), channel on chain: {has_channel}, took {:.1}s",
        peer == alice.address(),
        started.elapsed().as_secs_f32()
    );
    if !has_channel {
        return Err("Alice should have a channel".into());
    }

    println!("\nAlice -> Bob: a message.");
    let started = Instant::now();
    let sealed = alice_call.seal(b"Hi Bob. Nobody else can read this.")?;
    println!("  on the wire: {} bytes of ciphertext, starts {:02x?}", sealed.len(), &sealed[..12]);
    alice_net.send(bob_mix_address, sealed).await?;

    let (frame, tag) = bob_net.receive().await?;
    let reply_tag = tag.unwrap_or(alice_tag);
    let ResponderEvent::Message { peer, plaintext } = bob_side.handle(&bob, alice_tag, &frame)? else {
        return Err("expected a message".into());
    };
    let envelope = Envelope { from: peer, to: bob.address(), payload: plaintext };
    let verdict = bob_inbox.admit(&chain, &envelope, clock.elapsed().as_millis() as u64);
    println!(
        "  Bob's inbox: {verdict:?} -> {:?} ({:.1}s)",
        String::from_utf8_lossy(&envelope.payload),
        started.elapsed().as_secs_f32()
    );
    if verdict != Verdict::Deliver {
        return Err("Alice's message should have been delivered".into());
    }

    println!("\nBob -> Alice: reply through anonymous reply blocks (Bob never learns where Alice is).");
    let started = Instant::now();
    bob_net.reply(reply_tag, bob_side.seal(&alice_tag, b"Hi Alice. Got it.")?).await?;
    let (frame, _) = alice_net.receive().await?;
    let InitiatorEvent::Message(text) = alice_call.handle(&frame)? else {
        return Err("expected a message".into());
    };
    println!("  Alice reads: {:?} ({:.1}s)", String::from_utf8_lossy(&text), started.elapsed().as_secs_f32());

    // ---- Carol, a stranger, calls Bob --------------------------------------
    println!("\nCarol -> Bob: handshake from a wallet with no channel.");
    let (mut carol_call, frame1) = Initiator::start(&carol, bob.address())?;
    carol_net.send(bob_mix_address, frame1).await?;
    let (frame, tag) = bob_net.receive().await?;
    let carol_tag = tag.ok_or("handshake arrived without reply blocks")?;
    let ResponderEvent::Reply(frame2) = bob_side.handle(&bob, carol_tag, &frame)? else {
        return Err("expected a handshake reply".into());
    };
    bob_net.reply(carol_tag, frame2).await?;
    let (frame, _) = carol_net.receive().await?;
    let InitiatorEvent::Established { reply: frame3 } = carol_call.handle(&frame)? else {
        return Err("expected handshake completion".into());
    };
    carol_net.send(bob_mix_address, frame3).await?;
    let (frame, _) = bob_net.receive().await?;
    let ResponderEvent::Established { peer } = bob_side.handle(&bob, carol_tag, &frame)? else {
        return Err("expected session".into());
    };
    let has_channel = chain.channel_between(&peer, &bob.address()).is_some();
    println!("  Bob authenticated caller as {peer} (carol: {}), channel on chain: {has_channel}", peer == carol.address());
    if has_channel {
        return Err("Carol should not have a channel".into());
    }
    bob_side.forget(&carol_tag);
    println!("  Bob's client forgets her session.");

    carol_net.send(bob_mix_address, carol_call.seal(b"Limited offer, click here")?).await?;
    let (frame, _) = bob_net.receive().await?;
    match bob_side.handle(&bob, carol_tag, &frame) {
        Err(error) => println!("  Carol's message: dropped ({error}). She must pay Bob's price to get through."),
        Ok(_) => return Err("stranger's message was accepted".into()),
    }

    println!("\nDisconnecting.");
    alice_net.client.disconnect().await;
    carol_net.client.disconnect().await;
    bob_net.client.disconnect().await;
    println!("Done in {:.0}s.", clock.elapsed().as_secs_f32());
    Ok(())
}
