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
//!   authenticates him, sees no channel on the chain, drops him and sends
//!   no confirmation, so Dave's call never becomes a session.
//!
//! Every call follows the retry rules in `anonymum_crypto::wire`: a timeout
//! resends the same bytes, a failed attempt is replaced by a fresh
//! handshake after a backoff, and the caller treats the session as open only
//! once the callee has confirmed it.
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

use anonymum_core::{Address, Chain, Envelope, Event, Inbox, MessagingKey, Params, SealedNote, Tx, Verdict, COIN};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{open_note, seal_note, Ed25519Invites, Identity, InviteSecret};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient,
    StoragePaths,
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// Alice calling Bob. Worst case before giving up: 3 attempts of 3 sends
/// each, 60 s apart, plus backoff after any failed attempt.
const CALL_POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(60) };
/// Bob calling Carol's throwaway client, which may be offline: her gateway
/// holds the call. Gateways drop stored messages after 24 h by default, so a
/// real client must keep retrying for as long as the request lives.
const RENDEZVOUS_POLICY: RetryPolicy = RetryPolicy { attempts: 2, resends: 2, base_wait: Duration::from_secs(150) };
/// Dave: one attempt, no resends, so the demo shows an unconfirmed call
/// giving up quickly.
const DAVE_POLICY: RetryPolicy = RetryPolicy { attempts: 1, resends: 0, base_wait: Duration::from_secs(30) };
/// How often a responder ages its half-finished handshakes.
const TICK: Duration = Duration::from_secs(60);
/// How long a responder waits for a caller to finish a handshake.
const SERVE_PATIENCE: Duration = Duration::from_secs(600);

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
                .block_on(dispatch())
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
    let has_channel = |peer: &Address| chain.channel_between(peer, &bob.address()).is_some();
    let (alice_end, bob_end) = tokio::join!(
        call(&mut alice_net, &alice, bob.address(), bob_mix_address, CALL_POLICY),
        answer(&mut bob_net, &mut bob_side, &bob, has_channel),
    );
    let (peer, alice_tag, channel) = bob_end?;
    let (mut alice_call, alice_early) = alice_end?;
    println!(
        "  Bob authenticated caller as {peer} (alice: {}), channel on chain: {channel}; \
         Alice has Bob's confirmation after {:.1}s ({} attempt(s))",
        peer == alice.address(),
        started.elapsed().as_secs_f32(),
        alice_call.attempt()
    );
    if !channel {
        return Err("Alice should have a channel".into());
    }

    println!("\nAlice -> Bob: a message.");
    let started = Instant::now();
    let sealed = alice_call.seal(b"Hi Bob. Nobody else can read this.")?;
    println!("  on the wire: {} bytes of ciphertext, starts {:02x?}", sealed.len(), &sealed[..12]);
    alice_net.send(bob_mix_address, sealed).await?;

    let (peer, plaintext, reply_tag) = next_delivery(&mut bob_net, &mut bob_side, &bob, alice_tag).await?;
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
    bob_net.reply(reply_tag, bob_side.seal(&reply_tag, b"Hi Alice. Got it.")?).await?;
    let text = next_message(&mut alice_net, &mut alice_call, alice_early).await?;
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
    rendezvous(&mut bob_net, &bob, &carol, carol_net.address(), reply_to, &throwaway_dir, offline).await?;

    // ---- Dave, with no channel, calls Bob directly ---------------------------
    println!("\nDave -> Bob: handshake from a wallet with no channel.");
    let mut dave_net = Endpoint::connect("dave").await?;
    let has_channel = |peer: &Address| chain.channel_between(peer, &bob.address()).is_some();
    let (dave_end, bob_end) = tokio::join!(
        call(&mut dave_net, &dave, bob.address(), bob_mix_address, DAVE_POLICY),
        answer(&mut bob_net, &mut bob_side, &bob, has_channel),
    );
    let (peer, _, channel) = bob_end?;
    println!("  Bob authenticated caller as {peer} (dave: {}), channel on chain: {channel}", peer == dave.address());
    if channel {
        return Err("Dave should not have a channel".into());
    }
    println!("  Bob's client forgets the handshake and sends no confirmation.");
    match dave_end {
        Err(error) => println!(
            "  Dave's call: {error}. Without a confirmed session he cannot send anything; \
             he must pay Bob's price to get through."
        ),
        Ok(_) => return Err("Dave's call should not have been confirmed".into()),
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

/// Bob calls Carol at her throwaway address (retrying), Carol's throwaway
/// client comes back online after `offline` and answers, and inside the
/// session the two swap long-lived mixnet addresses. Then Carol discards the
/// throwaway client and deletes it from disk. Shared by the demo and `talk`.
async fn rendezvous(
    bob_net: &mut Endpoint,
    bob: &Identity,
    carol: &Identity,
    carol_long_lived: Recipient,
    reply_to: Recipient,
    throwaway_dir: &PathBuf,
    offline: Duration,
) -> Result<(), AnyError> {
    let started = Instant::now();
    let bob_mix_address = bob_net.address();
    let bob_calls = call(bob_net, bob, carol.address(), reply_to, RENDEZVOUS_POLICY);
    let carol_answers = async {
        tokio::time::sleep(offline).await;
        let mut throwaway = Endpoint::connect_persistent("carol (throwaway, back online)", throwaway_dir).await?;
        if throwaway.address() != reply_to {
            return Err::<_, AnyError>("throwaway client came back with a different address".into());
        }
        let mut carol_side: Responder<AnonymousSenderTag> = Responder::new();
        let (peer, tag, confirm) = serve(&mut throwaway, &mut carol_side, carol).await?;
        if peer != bob.address() {
            return Err("Carol was called by someone other than Bob".into());
        }
        println!(
            "  Carol's throwaway authenticates Bob {:.0}s after his first call (held by her gateway) and confirms.",
            started.elapsed().as_secs_f32()
        );
        throwaway.reply(tag, confirm).await?;
        Ok((throwaway, carol_side, tag))
    };
    let (bob_call, carol_end) = tokio::join!(bob_calls, carol_answers);
    let (mut bob_to_carol, bob_early) = bob_call?;
    let (mut throwaway, mut carol_side, bob_tag) = carol_end?;
    println!(
        "  Session confirmed after {:.0}s ({} attempt(s)). Bob is the initiator.",
        started.elapsed().as_secs_f32(),
        bob_to_carol.attempt()
    );

    println!("\nInside the session they swap long-lived mixnet addresses.");
    throwaway.reply(bob_tag, carol_side.seal(&bob_tag, carol_long_lived.to_string().as_bytes())?).await?;
    let text = next_message(bob_net, &mut bob_to_carol, bob_early).await?;
    let learned: Recipient = String::from_utf8(text)?.parse()?;
    println!("  Bob learns Carol's long-lived address: matches {}", learned == carol_long_lived);
    if learned != carol_long_lived {
        return Err("address exchange failed".into());
    }

    bob_net.send(reply_to, bob_to_carol.seal(bob_mix_address.to_string().as_bytes())?).await?;
    let (_, plaintext, _) = next_delivery(&mut throwaway, &mut carol_side, carol, bob_tag).await?;
    let learned: Recipient = String::from_utf8(plaintext)?.parse()?;
    println!("  Carol learns Bob's long-lived address: matches {}", learned == bob_mix_address);
    if learned != bob_mix_address {
        return Err("address exchange failed".into());
    }

    throwaway.client.disconnect().await;
    std::fs::remove_dir_all(throwaway_dir)?;
    println!("  Carol discards the throwaway client and deletes it from disk.");
    Ok(())
}

// ---- subcommands for the end-to-end run against a dev node (audit F8) ------
//
// `substrate/scripts/e2e.mjs` drives these: it does the chain transactions
// (Polkadot.js, signing with each wallet's Ed25519 account key) and calls
// this binary for everything cryptographic and for the mixnet.
//
//   anonymum-nym wallet <file>       create (or load) a wallet; print its
//                                    address, messaging key and binding
//   anonymum-nym throwaway <dir>     create a persisted throwaway Nym client;
//                                    print its address, then go offline
//   anonymum-nym seal --key K --from A --to B --reply R --intro TEXT
//   anonymum-nym open --wallet F --from A --note HEX
//   anonymum-nym talk --bob F --carol F --dir D --reply R
//
// Wallet files hold the two private keys in hex. DEV ONLY: they are plain
// files for this test, not encrypted storage.

async fn dispatch() -> Result<(), AnyError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        None | Some("demo") => run().await,
        Some("wallet") => cmd_wallet(rest),
        Some("throwaway") => cmd_throwaway(rest).await,
        Some("seal") => cmd_seal(rest),
        Some("open") => cmd_open(rest),
        Some("talk") => cmd_talk(rest).await,
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, AnyError> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}").into())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, AnyError> {
    let text = text.trim().trim_start_matches("0x");
    if text.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], AnyError> {
    from_hex(text)?.try_into().map_err(|_| format!("expected {N} bytes").into())
}

fn load_wallet(path: &str) -> Result<Identity, AnyError> {
    let text = std::fs::read_to_string(path)?;
    let field = |name: &str| -> Result<[u8; 32], AnyError> {
        let line = text.lines().find_map(|l| l.strip_prefix(name)).ok_or(format!("{path}: no {name}"))?;
        fixed::<32>(line)
    };
    Ok(Identity::from_secret_bytes(field("signing=")?, field("messaging=")?))
}

fn cmd_wallet(args: &[String]) -> Result<(), AnyError> {
    let path = args.first().ok_or("usage: wallet <file>")?;
    if !std::path::Path::new(path).exists() {
        let (signing, messaging) = Identity::generate().to_secret_bytes();
        std::fs::write(path, format!("signing={}\nmessaging={}\n", to_hex(&signing), to_hex(&messaging)))?;
    }
    let wallet = load_wallet(path)?;
    let Tx::PublishMessagingKey { key, binding } = wallet.publish_key_tx() else { unreachable!() };
    println!("address={}", to_hex(&wallet.address().0));
    println!("msgkey={}", to_hex(&key.0));
    println!("binding={}", to_hex(&binding.0));
    Ok(())
}

async fn cmd_throwaway(args: &[String]) -> Result<(), AnyError> {
    let dir = PathBuf::from(args.first().ok_or("usage: throwaway <dir>")?);
    let throwaway = Endpoint::connect_persistent("carol (throwaway)", &dir).await?;
    println!("address={}", to_hex(&throwaway.address().to_bytes()));
    throwaway.client.disconnect().await;
    Ok(())
}

fn cmd_seal(args: &[String]) -> Result<(), AnyError> {
    let note = seal_note(
        &MessagingKey(fixed::<32>(flag(args, "--key")?)?),
        &Address(fixed::<32>(flag(args, "--from")?)?),
        &Address(fixed::<32>(flag(args, "--to")?)?),
        &fixed::<96>(flag(args, "--reply")?)?,
        flag(args, "--intro")?,
    )?;
    println!("note={}", to_hex(&note.0));
    Ok(())
}

fn cmd_open(args: &[String]) -> Result<(), AnyError> {
    let wallet = load_wallet(flag(args, "--wallet")?)?;
    let from = Address(fixed::<32>(flag(args, "--from")?)?);
    let note = SealedNote(from_hex(flag(args, "--note")?)?);
    let opened = open_note(&wallet, &from, &note)?;
    println!("reply={}", to_hex(&opened.reply_to));
    println!("intro={}", opened.intro.replace('\n', " "));
    Ok(())
}

async fn cmd_talk(args: &[String]) -> Result<(), AnyError> {
    let bob = load_wallet(flag(args, "--bob")?)?;
    let carol = load_wallet(flag(args, "--carol")?)?;
    let dir = PathBuf::from(flag(args, "--dir")?);
    let reply_to = Recipient::try_from_bytes(fixed::<96>(flag(args, "--reply")?)?)?;
    println!("Connecting Bob's and Carol's long-lived clients...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    println!("\nBob calls Carol at the throwaway address from her note.");
    rendezvous(&mut bob_net, &bob, &carol, carol_net.address(), reply_to, &dir, Duration::ZERO).await?;
    carol_net.client.disconnect().await;
    bob_net.client.disconnect().await;
    println!("talk=ok");
    Ok(())
}

// ---- driving the wire layer over the mixnet ----------------------------------

fn deadline_for(call: &Initiator) -> tokio::time::Instant {
    tokio::time::Instant::now() + call.wait().unwrap_or(Duration::ZERO)
}

/// Call `peer` at mixnet address `to` and drive the handshake until the
/// callee confirms it. A timeout resends the same bytes (so a gateway that
/// delivers several copies yields one handshake: the callee answers repeats
/// identically); a failed attempt is followed, after a backoff, by a fresh
/// handshake; the policy bounds both. Returns the confirmed call, plus the
/// callee's first message if that is what confirmed it.
async fn call(
    net: &mut Endpoint,
    me: &Identity,
    peer: Address,
    to: Recipient,
    policy: RetryPolicy,
) -> Result<(Initiator, Option<Vec<u8>>), AnyError> {
    let (mut call, first) = Initiator::start_with(me, peer, policy)?;
    net.send(to, first).await?;
    let mut deadline = deadline_for(&call);
    loop {
        match net.receive_until(deadline).await? {
            Some((frame, _)) => match call.handle(&frame) {
                Ok(InitiatorEvent::Send(frame3)) => {
                    net.send(to, frame3).await?;
                    deadline = deadline_for(&call);
                }
                Ok(InitiatorEvent::Established) => return Ok((call, None)),
                Ok(InitiatorEvent::Message(text)) => return Ok((call, Some(text))),
                Err(WireError::AttemptFailed(error)) => {
                    println!("  {}: attempt {} failed ({error}); a fresh one follows", net.name, call.attempt());
                    deadline = deadline_for(&call);
                }
                Err(error) => println!("  {} ignores a frame: {error}", net.name),
            },
            None => match call.on_timeout(me) {
                Ok(Some(frame)) => {
                    println!("  {}: no answer yet, sending again (attempt {})", net.name, call.attempt());
                    net.send(to, frame).await?;
                    deadline = deadline_for(&call);
                }
                Ok(None) => return Ok((call, None)),
                Err(error) => {
                    return Err(format!("{} gave up after {} attempt(s): {error}", net.name, call.attempt()).into())
                }
            },
        }
    }
}

/// Answer callers until one finishes a handshake. Returns who it is, their
/// reply handle and the confirmation to send if we keep them. Half-finished
/// handshakes are dropped after a few ticks; gives up after SERVE_PATIENCE.
async fn serve(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    me: &Identity,
) -> Result<(Address, AnonymousSenderTag, Vec<u8>), AnyError> {
    let give_up = tokio::time::Instant::now() + SERVE_PATIENCE;
    loop {
        let deadline = give_up.min(tokio::time::Instant::now() + TICK);
        match net.receive_until(deadline).await? {
            None => {
                for _ in side.tick() {
                    println!("  {} drops a handshake that was never finished", net.name);
                }
                if tokio::time::Instant::now() >= give_up {
                    return Err(format!("{}: no caller finished a handshake in {SERVE_PATIENCE:?}", net.name).into());
                }
            }
            Some((_, None)) => println!("  {} ignores a frame without reply blocks", net.name),
            Some((frame, Some(tag))) => match side.handle(me, tag, &frame) {
                Ok(ResponderEvent::Reply(reply)) => net.reply(tag, reply).await?,
                Ok(ResponderEvent::Established { peer, reply }) => return Ok((peer, tag, reply)),
                Ok(ResponderEvent::Message { .. }) => println!("  {} ignores a message during a handshake", net.name),
                Err(error) => println!("  {} ignores a frame: {error}", net.name),
            },
        }
    }
}

/// Bob's side of an incoming call: confirm callers with a channel, forget
/// (without confirming) callers without one.
async fn answer(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    me: &Identity,
    has_channel: impl Fn(&Address) -> bool,
) -> Result<(Address, AnonymousSenderTag, bool), AnyError> {
    let (peer, tag, confirm) = serve(net, side, me).await?;
    let channel = has_channel(&peer);
    if channel {
        net.reply(tag, confirm).await?;
    } else {
        side.forget(&tag);
    }
    Ok((peer, tag, channel))
}

/// The next message from an established caller. Late handshake frames are
/// answered (a resent message 3 gets the confirmation again) or ignored.
async fn next_delivery(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    me: &Identity,
    fallback: AnonymousSenderTag,
) -> Result<(Address, Vec<u8>, AnonymousSenderTag), AnyError> {
    loop {
        let (frame, tag) = net.receive().await?;
        let tag = tag.unwrap_or(fallback);
        match side.handle(me, tag, &frame) {
            Ok(ResponderEvent::Message { peer, plaintext }) => return Ok((peer, plaintext, tag)),
            Ok(ResponderEvent::Reply(reply)) => net.reply(tag, reply).await?,
            Ok(other) => println!("  {} ignores {other:?}", net.name),
            Err(error) => println!("  {} ignores a frame: {error}", net.name),
        }
    }
}

/// The next message on a confirmed call (or the one that confirmed it),
/// ignoring late handshake frames.
async fn next_message(net: &mut Endpoint, call: &mut Initiator, early: Option<Vec<u8>>) -> Result<Vec<u8>, AnyError> {
    if let Some(text) = early {
        return Ok(text);
    }
    loop {
        let (frame, _) = net.receive().await?;
        match call.handle(&frame) {
            Ok(InitiatorEvent::Message(text)) => return Ok(text),
            Ok(other) => println!("  {} ignores {other:?}", net.name),
            Err(error) => println!("  {} ignores a frame: {error}", net.name),
        }
    }
}
