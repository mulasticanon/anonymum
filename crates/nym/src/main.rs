//! Anonymum over the live Nym mixnet.
//!
//! Four wallets in one process, each with its own Nym client:
//!
//! * Alice holds an invite from Bob, opens a channel, and exchanges
//!   end-to-end encrypted messages with him through the mixnet.
//! * Carol is a stranger. Bob's mixnet address is never published, so she
//!   reaches him by reverse rendezvous: she creates a throwaway mixnet
//!   client (kept on disk), seals its address and a short intro to Bob's
//!   on-chain messaging key, and pays for a contact request. Her throwaway
//!   client then goes offline. Bob reads the note, accepts, and calls her
//!   at the throwaway address; the gateway holds his call until she comes
//!   back. Inside the session they swap their long-lived addresses.
//! * Dave has no channel and calls Bob directly. Bob's client
//!   authenticates him, sees no channel on the chain, and drops him.
//!
//! The chain here is the in-process simulation from `anonymum-core`. The
//! mixnet and the cryptography are real.
//!
//!     cargo run -p anonymum-nym
//!
//! Set ANONYMUM_OFFLINE_SECS to change how long Carol's throwaway client
//! stays offline (default 60).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anonymum_core::{Chain, Envelope, Event, Inbox, Params, Tx, Verdict, COIN};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent};
use anonymum_crypto::{open_note, seal_note, Ed25519Invites, Identity, InviteSecret};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient,
    StoragePaths,
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long Bob waits for Carol to answer before calling again. Gateways
/// drop stored messages after 24 h by default, shorter than the 48 h a
/// request lives, so a real client must keep retrying until expiry.
const CALL_RETRY_EVERY: Duration = Duration::from_secs(150);
const CALL_ATTEMPTS: u32 = 3;

/// A Nym client plus a queue, because the mixnet hands over messages in batches.
struct Endpoint {
    name: &'static str,
    client: MixnetClient,
    queue: VecDeque<(Vec<u8>, Option<AnonymousSenderTag>)>,
}

fn tls_only() -> bool {
    // Gateways reached over TLS on port 443 work from behind most
    // firewalls. Set ANONYMUM_PLAIN_WS=1 to allow any gateway instead.
    std::env::var_os("ANONYMUM_PLAIN_WS").is_none()
}

impl Endpoint {
    /// A client whose keys live only in memory.
    async fn connect(name: &'static str) -> Result<Self, AnyError> {
        let started = Instant::now();
        let client = MixnetClientBuilder::new_ephemeral()
            .force_tls(tls_only())
            .build()?
            .connect_to_mixnet()
            .await?;
        println!("  {name} connected to the mixnet in {:.1}s", started.elapsed().as_secs_f32());
        Ok(Endpoint { name, client, queue: VecDeque::new() })
    }

    /// A client whose keys and gateway registration are kept in `dir`, so it
    /// can go offline and come back with the same mixnet address.
    async fn connect_persistent(name: &'static str, dir: &PathBuf) -> Result<Self, AnyError> {
        let started = Instant::now();
        let client = MixnetClientBuilder::new_with_default_storage(StoragePaths::new_from_dir(dir)?)
            .await?
            .force_tls(tls_only())
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
        self.receive_until(deadline)
            .await?
            .ok_or_else(|| format!("{} waited {RECEIVE_TIMEOUT:?} and received nothing", self.name).into())
    }

    /// `Ok(None)` if nothing arrived before `deadline`.
    async fn receive_until(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<(Vec<u8>, Option<AnonymousSenderTag>)>, AnyError> {
        loop {
            if let Some(next) = self.queue.pop_front() {
                return Ok(Some(next));
            }
            let Ok(batch) = tokio::time::timeout_at(deadline, self.client.wait_for_messages()).await else {
                return Ok(None);
            };
            let batch = batch.ok_or_else(|| format!("{}'s mixnet connection closed", self.name))?;
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
    let offline = Duration::from_secs(
        std::env::var("ANONYMUM_OFFLINE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60),
    );

    // ---- wallets and chain ------------------------------------------------
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let dave = Identity::generate();
    println!(
        "Wallets\n  alice {}\n  bob   {}\n  carol {}\n  dave  {}",
        alice.address(),
        bob.address(),
        carol.address(),
        dave.address()
    );

    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(alice.address(), 10 * COIN);
    chain.mint(carol.address(), 10 * COIN);
    chain.mint(bob.address(), COIN); // storage deposits for his key and invite
    chain.apply(bob.address(), bob.publish_key_tx())?;
    println!("\nOn-chain: Bob publishes his messaging key (a key, not a location).");

    println!("On-chain: Bob creates an invite, Alice uses it to open a channel.");
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

    // ---- mixnet -----------------------------------------------------------
    println!("\nConnecting to the Nym mixnet...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let mut alice_net = Endpoint::connect("alice").await?;
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    // Invited contacts get Bob's mixnet address with the invite, out of band.
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

    // ---- Carol, a stranger, reaches Bob by reverse rendezvous ---------------
    println!("\nCarol -> Bob: a stranger. Bob's mixnet address is not published.");
    let throwaway_dir = std::env::temp_dir().join(format!("anonymum-throwaway-{}", std::process::id()));
    let throwaway = Endpoint::connect_persistent("carol (throwaway)", &throwaway_dir).await?;
    let throwaway_address = throwaway.address();
    println!("  throwaway client stored at {}", throwaway_dir.display());

    let bobs_key = chain.messaging_key(&bob.address()).ok_or("Bob has no messaging key")?.key;
    let intro = "Hello Bob, it's Carol from the climbing club. Can we talk about Saturday?";
    let note = seal_note(&bobs_key, &carol.address(), &bob.address(), &throwaway_address.to_bytes(), intro)?;
    println!("  sealed note: {} bytes, same size for every request", note.0.len());
    let events = chain.apply(
        carol.address(),
        Tx::RequestContact { recipient: bob.address(), max_price: COIN, note },
    )?;
    let Event::ContactRequested { request, .. } = events[0] else {
        return Err("expected a contact request".into());
    };
    println!(
        "  On-chain: Carol pays the network fee and escrows Bob's price. Expires in {} blocks (48 h).",
        chain.params().request_ttl_blocks()
    );

    throwaway.client.disconnect().await;
    println!("  Carol's throwaway client goes offline (kept on disk).");

    // Bob's client sees the request on the chain and opens the note.
    let req = chain.request(request).ok_or("request vanished")?.clone();
    let opened = open_note(&bob, &req.from, &req.note)?;
    println!("  Bob's client opens the note. Intro: {:?}", opened.intro);
    let reply_to = Recipient::try_from_bytes(opened.reply_to)?;
    if reply_to != throwaway_address {
        return Err("note carried the wrong reply address".into());
    }
    chain.apply(bob.address(), Tx::AcceptContact { request })?;
    println!("  On-chain: Bob accepts. Channel carol<->bob open: {}", chain.channel_between(&carol.address(), &bob.address()).is_some());

    println!("\nBob calls Carol at the throwaway address; she is offline for {}s.", offline.as_secs());
    let started = Instant::now();
    let bob_calls = call_with_retry(&mut bob_net, &bob, carol.address(), reply_to);
    let carol_answers = async {
        tokio::time::sleep(offline).await;
        let mut throwaway = Endpoint::connect_persistent("carol (throwaway, back online)", &throwaway_dir).await?;
        if throwaway.address() != throwaway_address {
            return Err::<_, AnyError>("throwaway client came back with a different address".into());
        }
        let mut carol_side: Responder<AnonymousSenderTag> = Responder::new();
        loop {
            let (frame, tag) = throwaway.receive().await?;
            let tag = tag.ok_or("call arrived without reply blocks")?;
            match carol_side.handle(&carol, tag, &frame) {
                Ok(ResponderEvent::Reply(frame2)) => {
                    println!(
                        "  Carol's throwaway receives Bob's call {:.0}s after it was sent (held by her gateway).",
                        started.elapsed().as_secs_f32()
                    );
                    throwaway.reply(tag, frame2).await?;
                }
                Ok(ResponderEvent::Established { peer }) => {
                    if peer != bob.address() {
                        return Err("Carol was called by someone other than Bob".into());
                    }
                    return Ok((throwaway, carol_side, tag));
                }
                Ok(other) => println!("  Carol ignores unexpected {other:?}"),
                Err(error) => println!("  Carol ignores a frame: {error}"),
            }
        }
    };
    let (bob_call, carol_end) = tokio::join!(bob_calls, carol_answers);
    let (mut bob_to_carol, attempts) = bob_call?;
    let (mut throwaway, mut carol_side, bob_tag) = carol_end?;
    println!(
        "  Session established after {:.0}s ({attempts} call attempt(s)). Bob is the initiator.",
        started.elapsed().as_secs_f32()
    );

    println!("\nInside the session they swap long-lived mixnet addresses.");
    let carol_long_lived = carol_net.address();
    throwaway.reply(bob_tag, carol_side.seal(&bob_tag, carol_long_lived.to_string().as_bytes())?).await?;
    let text = next_message(&mut bob_net, &mut bob_to_carol).await?;
    let learned: Recipient = String::from_utf8(text)?.parse()?;
    println!("  Bob learns Carol's long-lived address: matches {}", learned == carol_long_lived);

    bob_net.send(reply_to, bob_to_carol.seal(bob_mix_address.to_string().as_bytes())?).await?;
    let (frame, tag) = throwaway.receive().await?;
    let ResponderEvent::Message { plaintext, .. } = carol_side.handle(&carol, tag.unwrap_or(bob_tag), &frame)? else {
        return Err("expected Bob's address".into());
    };
    let learned: Recipient = String::from_utf8(plaintext)?.parse()?;
    println!("  Carol learns Bob's long-lived address: matches {}", learned == bob_mix_address);
    if learned != bob_mix_address {
        return Err("address exchange failed".into());
    }

    throwaway.client.disconnect().await;
    std::fs::remove_dir_all(&throwaway_dir)?;
    println!("  Carol discards the throwaway client and deletes it from disk.");

    // ---- Dave, with no channel, calls Bob directly ---------------------------
    println!("\nDave -> Bob: handshake from a wallet with no channel.");
    let dave_net = Endpoint::connect("dave").await?;
    let (mut dave_call, frame1) = Initiator::start(&dave, bob.address())?;
    dave_net.send(bob_mix_address, frame1).await?;
    let (frame, tag) = bob_net.receive().await?;
    let dave_tag = tag.ok_or("handshake arrived without reply blocks")?;
    let ResponderEvent::Reply(frame2) = bob_side.handle(&bob, dave_tag, &frame)? else {
        return Err("expected a handshake reply".into());
    };
    bob_net.reply(dave_tag, frame2).await?;
    let mut dave_net = dave_net;
    let (frame, _) = dave_net.receive().await?;
    let InitiatorEvent::Established { reply: frame3 } = dave_call.handle(&frame)? else {
        return Err("expected handshake completion".into());
    };
    dave_net.send(bob_mix_address, frame3).await?;
    let (frame, _) = bob_net.receive().await?;
    let ResponderEvent::Established { peer } = bob_side.handle(&bob, dave_tag, &frame)? else {
        return Err("expected session".into());
    };
    let has_channel = chain.channel_between(&peer, &bob.address()).is_some();
    println!("  Bob authenticated caller as {peer} (dave: {}), channel on chain: {has_channel}", peer == dave.address());
    if has_channel {
        return Err("Dave should not have a channel".into());
    }
    bob_side.forget(&dave_tag);
    println!("  Bob's client forgets his session.");

    dave_net.send(bob_mix_address, dave_call.seal(b"Limited offer, click here")?).await?;
    let (frame, _) = bob_net.receive().await?;
    match bob_side.handle(&bob, dave_tag, &frame) {
        Err(error) => println!("  Dave's message: dropped ({error}). He must pay Bob's price to get through."),
        Ok(_) => return Err("stranger's message was accepted".into()),
    }

    println!("\nDisconnecting.");
    alice_net.client.disconnect().await;
    carol_net.client.disconnect().await;
    dave_net.client.disconnect().await;
    bob_net.client.disconnect().await;
    assert!(chain.ledger().is_balanced());
    println!("Every coin accounted for. Done in {:.0}s.", clock.elapsed().as_secs_f32());
    Ok(())
}

/// Bob calls Carol at her throwaway address, calling again if she does not
/// answer in time. Every attempt resends the *same* first frame: if the
/// gateway later delivers several copies, Carol's responder answers them
/// all identically, so exactly one handshake exists. (A first live run with
/// a fresh handshake per attempt failed this way.) Fresh reply blocks are
/// attached to every send. Returns the session and the attempts used.
async fn call_with_retry(
    bob_net: &mut Endpoint,
    bob: &Identity,
    carol: anonymum_core::Address,
    to: Recipient,
) -> Result<(Initiator, u32), AnyError> {
    let (mut call, frame1) = Initiator::start(bob, carol)?;
    for attempt in 1..=CALL_ATTEMPTS {
        bob_net.send(to, frame1.clone()).await?;
        if attempt > 1 {
            println!("  Bob calls again (attempt {attempt}, same first frame).");
        }
        let deadline = tokio::time::Instant::now() + CALL_RETRY_EVERY;
        while let Some((frame, _)) = bob_net.receive_until(deadline).await? {
            match call.handle(&frame) {
                Ok(InitiatorEvent::Established { reply }) => {
                    bob_net.send(to, reply).await?;
                    return Ok((call, attempt));
                }
                Ok(_) | Err(_) => continue,
            }
        }
    }
    Err(format!("Carol did not answer after {CALL_ATTEMPTS} attempts").into())
}

/// The next message on an established call, skipping duplicate handshake
/// replies that arrive late when a call was sent more than once.
async fn next_message(net: &mut Endpoint, call: &mut Initiator) -> Result<Vec<u8>, AnyError> {
    loop {
        let (frame, _) = net.receive().await?;
        match call.handle(&frame) {
            Ok(InitiatorEvent::Message(text)) => return Ok(text),
            Err(anonymum_crypto::wire::WireError::UnexpectedFrame) => continue,
            Ok(other) => return Err(format!("unexpected {other:?}").into()),
            Err(error) => return Err(error.into()),
        }
    }
}
