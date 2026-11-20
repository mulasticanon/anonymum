//! Anonymum over the live Nym mixnet, with contact identities (spec v0.7
//! section 2a).
//!
//! Each person has a wallet (for the transparent prototype chain) and,
//! separately, a contact identity or caller keys for messaging. No wallet
//! key appears in a contact card, a handshake or a note.
//!
//! * Alice makes a caller key for her relationship with Bob; Bob gives her
//!   his contact card and an invitation to that key. She calls him (Noise
//!   IK); Bob's client lets her in because she holds his invitation, and only
//!   after her fresh confirmation counts the invitation as used.
//! * Carol is a stranger. Bob's route is never published, so she reaches
//!   him by reverse rendezvous: she seals a note to the inbox key on his card
//!   (her contact identity, a fresh callback key and a throwaway route
//!   inside) and pays for a contact request. Her throwaway client goes
//!   offline. Bob finds the note with his inbox key alone, accepts on chain,
//!   and calls her callback key at the throwaway route. Eve, who learned the
//!   route, calls too and gets nothing. Inside the session Bob and Carol swap
//!   long-lived routes.
//! * Dave has Bob's real card and route but no invitation. Bob's client
//!   sends him nothing at all.
//!
//! Every call follows `anonymum_crypto::wire`: authorise before replying,
//! resend the same bytes on timeout, a fresh handshake after a failed
//! attempt, and a session counts only once both sides have confirmed it.
//!
//! The chain here is the in-process simulation from `anonymum-core`. The
//! mixnet and the cryptography are real; the handshake and note format have
//! not been reviewed (spec questions 11 and 12).
//!
//!     cargo run -p anonymum-nym
//!
//! Set ANONYMUM_OFFLINE_SECS to change how long Carol's throwaway client
//! stays offline (default 60).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anonymum_core::{Chain, Event, MessagingKey, Params, SealedNote, Tx, COIN};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{
    open_note, random_bytes, seal_note, ContactCard, ContactIdentity, Ed25519Invites, Gate, Grant, Identity,
    InviteSecret, Network, Purpose, StaticKey,
};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths,
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// The demo's network id (a real network would use its genesis hash).
const NETWORK: Network = *b"anonymum-dev-network-v1\0\0\0\0\0\0\0\0\0";
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// Alice calling Bob. Worst case before giving up: 3 attempts of 3 sends
/// each, 60 s apart, plus backoff after any failed attempt.
const CALL_POLICY: RetryPolicy = RetryPolicy { attempts: 3, resends: 2, base_wait: Duration::from_secs(60) };
/// Bob calling Carol's throwaway client, which may be offline: her gateway
/// holds the call. Gateways drop stored messages after 24 h by default, so a
/// real client must keep retrying for as long as the request lives.
const RENDEZVOUS_POLICY: RetryPolicy = RetryPolicy { attempts: 2, resends: 2, base_wait: Duration::from_secs(150) };
/// Dave and Eve: one attempt, no resends, so the demo shows an unanswered
/// call giving up quickly.
const SHORT_POLICY: RetryPolicy = RetryPolicy { attempts: 1, resends: 0, base_wait: Duration::from_secs(30) };
/// How often a responder ages its answered, unconfirmed handshakes.
const TICK: Duration = Duration::from_secs(60);
/// How long a responder waits for a caller to finish a handshake.
const SERVE_PATIENCE: Duration = Duration::from_secs(600);

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn short(key: &[u8; 32]) -> String {
    key[..4].iter().map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

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
        let client = MixnetClientBuilder::new_ephemeral().force_tls(tls_only()).build()?.connect_to_mixnet().await?;
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

    // ---- wallets, contact identities and chain ------------------------------
    let (alice_wallet, bob_wallet, carol_wallet) = (Identity::generate(), Identity::generate(), Identity::generate());
    println!(
        "Wallets (chain accounts)\n  alice {}\n  bob   {}\n  carol {}",
        alice_wallet.address(),
        bob_wallet.address(),
        carol_wallet.address()
    );
    let bob = ContactIdentity::generate();
    let card = bob.card(NETWORK, COIN, now_secs(), now_secs() + 86_400);
    println!(
        "Bob's contact card (separate from his wallet): signing {}, handshake {}, inbox {}, price {} units",
        short(&card.signing_key),
        short(&card.handshake_key),
        short(&card.inbox_key),
        card.price
    );

    let mut chain = Chain::new(Params::default(), Ed25519Invites);
    chain.mint(alice_wallet.address(), 10 * COIN);
    chain.mint(carol_wallet.address(), 10 * COIN);
    chain.mint(bob_wallet.address(), COIN); // storage deposits
    // The transparent prototype chain still requires a published wallet key
    // before it accepts requests to Bob (a known gap until stage 5). Notes
    // are sealed to the inbox key on his card, not to this key.
    chain.apply(bob_wallet.address(), bob_wallet.publish_key_tx())?;

    println!("\nOn-chain: Bob creates a chain invite, Alice uses it to open a channel.");
    let chain_invite = InviteSecret::generate();
    chain.apply(bob_wallet.address(), Tx::RegisterInvite { key: chain_invite.public(), expires_at: None })?;
    let handed_over = InviteSecret::from_bytes(chain_invite.to_bytes()); // out of band
    chain.apply(
        alice_wallet.address(),
        Tx::OpenWithInvite {
            recipient: bob_wallet.address(),
            key: handed_over.public(),
            proof: handed_over.sign_for(&alice_wallet.address(), &bob_wallet.address()),
        },
    )?;

    // ---- mixnet -----------------------------------------------------------
    println!("\nConnecting to the Nym mixnet...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let mut alice_net = Endpoint::connect("alice").await?;
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    // Invited contacts get Bob's route with his card, out of band.
    let bob_route = bob_net.address();
    let mut bob_side: Responder<AnonymousSenderTag> = Responder::new(bob.handshake_key(), NETWORK, Gate::new(NETWORK));

    // ---- Alice, invited -------------------------------------------------------
    println!("\nAlice makes a caller key for Bob; Bob gives her his card, his route and an invitation to that key.");
    let alice_key = StaticKey::generate();
    let invitation = bob.invite(NETWORK, alice_key.public(), Purpose::Contact, now_secs() + 3_600);
    bob_side.gate_mut().record_invitation(invitation.clone());
    card.verify(&NETWORK, now_secs())?;
    invitation.verify(&card.signing_key, &NETWORK, now_secs())?;
    println!("  Alice checked the card and the invitation (issuer, network, expiry, signature).");

    println!("\nAlice -> Bob: Noise IK handshake through the mixnet.");
    let started = Instant::now();
    let (alice_end, bob_end) = tokio::join!(
        call(&mut alice_net, &alice_key, card.handshake_key, invitation.id, bob_route, CALL_POLICY),
        serve(&mut bob_net, &mut bob_side, SERVE_PATIENCE),
    );
    let (peer, alice_tag, grant) = bob_end?.ok_or("Alice never finished the handshake")?;
    let (mut alice_call, alice_early) = alice_end?;
    println!(
        "  Bob let in caller key {} ({grant:?}; Alice's: {}) and acknowledged; Alice confirmed after {:.1}s ({} attempt(s)). Invitation now used: {}",
        short(&peer),
        peer == alice_key.public(),
        started.elapsed().as_secs_f32(),
        alice_call.attempt(),
        bob_side.gate().is_honoured(&invitation.id)
    );
    if grant != (Grant::Invitation { id: invitation.id }) {
        return Err("Alice should have come in on her invitation".into());
    }

    println!("\nAlice -> Bob: a message.");
    let started = Instant::now();
    let sealed = alice_call.seal(b"Hi Bob. Nobody else can read this.")?;
    println!("  on the wire: {} bytes of ciphertext, starts {:02x?}", sealed.len(), &sealed[..12]);
    alice_net.send(bob_route, sealed).await?;
    let (_, plaintext, reply_tag) = next_delivery(&mut bob_net, &mut bob_side, alice_tag).await?;
    println!("  Bob reads: {:?} ({:.1}s)", String::from_utf8_lossy(&plaintext), started.elapsed().as_secs_f32());

    println!("\nBob -> Alice: reply through anonymous reply blocks (Bob never learns where Alice is).");
    let started = Instant::now();
    bob_net.reply(reply_tag, bob_side.seal(&reply_tag, b"Hi Alice. Got it.")?).await?;
    let text = next_message(&mut alice_net, &mut alice_call, alice_early).await?;
    println!("  Alice reads: {:?} ({:.1}s)", String::from_utf8_lossy(&text), started.elapsed().as_secs_f32());

    // ---- Carol, a stranger, by note and reverse rendezvous ---------------------
    println!("\nCarol -> Bob: a stranger. Bob's route is not published; she has only his card.");
    let carol = ContactIdentity::generate();
    let callback = StaticKey::generate();
    let throwaway_dir = std::env::temp_dir().join(format!("anonymum-throwaway-{}", std::process::id()));
    let throwaway = Endpoint::connect_persistent("carol (throwaway)", &throwaway_dir).await?;
    let throwaway_route = throwaway.address();
    // Stand-in for the admission commitment (the transparent chain has none).
    let admission = random_bytes();
    let intro = "Hello Bob, it's Carol from the climbing club. Can we talk about Saturday?";
    let note = seal_note(&card.inbox_key, &carol, &callback.public(), &throwaway_route.to_bytes(), intro, &admission)?;
    println!("  sealed note: {} bytes, same size for every request, opens with Bob's inbox key alone", note.0.len());
    let events = chain.apply(
        carol_wallet.address(),
        Tx::RequestContact { recipient: bob_wallet.address(), max_price: COIN, note },
    )?;
    let Event::ContactRequested { request, .. } = events[0] else {
        return Err("expected a contact request".into());
    };
    println!("  On-chain: Carol pays the network fee and escrows Bob's price.");
    throwaway.client.disconnect().await;
    println!("  Carol's throwaway client goes offline (kept on disk).");

    // Bob's client tries his inbox key on the request's note: no sender
    // address or hint is used.
    let req = chain.request(request).ok_or("request vanished")?.clone();
    let opened = open_note(&bob, &req.note)?;
    println!(
        "  Bob's client opens the note with his inbox key alone. Sender's contact key {}, intro: {:?}",
        short(&opened.sender),
        opened.intro
    );
    if opened.sender != carol.signing_key() || opened.callback != callback.public() {
        return Err("note carried the wrong sender or callback key".into());
    }
    let reply_to = Recipient::try_from_bytes(opened.route)?;
    chain.apply(bob_wallet.address(), Tx::AcceptContact { request })?;
    println!("  On-chain: Bob accepts (the claim is final in this simulation).");

    println!("\nBob calls Carol's callback key at the throwaway route; she is offline for {}s.", offline.as_secs());
    println!("Eve learned the route and calls too.");
    let eve_net = Endpoint::connect("eve").await?;
    rendezvous(
        &mut bob_net,
        &bob,
        &card,
        &carol,
        &callback,
        opened.admission,
        carol_net.address(),
        reply_to,
        &throwaway_dir,
        offline,
        Some(eve_net),
    )
    .await?;

    // ---- Dave: Bob's real card and route, no invitation ---------------------------
    println!("\nDave -> Bob: he has Bob's real card and route, but no invitation.");
    let mut dave_net = Endpoint::connect("dave").await?;
    let dave_key = StaticKey::generate();
    let (dave_end, bob_end) = tokio::join!(
        call(&mut dave_net, &dave_key, card.handshake_key, random_bytes(), bob_route, SHORT_POLICY),
        serve(&mut bob_net, &mut bob_side, SHORT_POLICY.base_wait + Duration::from_secs(15)),
    );
    if bob_end?.is_some() {
        return Err("Bob let Dave in".into());
    }
    match dave_end {
        Err(error) => println!("  Dave received nothing at all: {error}. He must pay Bob's price to get through."),
        Ok(_) => return Err("Dave's call should not have been answered".into()),
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

/// Bob calls Carol's callback key at her throwaway route (retrying). Carol's
/// throwaway client comes back after `offline` and answers only Bob's
/// handshake key, about this request; inside the session the two swap
/// long-lived routes. Then Carol discards the throwaway client and deletes
/// it from disk. If `eve` is given, Eve calls the throwaway route too and
/// must get nothing. Shared by the demo and `talk`.
#[allow(clippy::too_many_arguments)]
async fn rendezvous(
    bob_net: &mut Endpoint,
    bob: &ContactIdentity,
    bob_card: &ContactCard,
    carol: &ContactIdentity,
    callback: &StaticKey,
    reference: [u8; 32],
    carol_long_lived: Recipient,
    reply_to: Recipient,
    throwaway_dir: &PathBuf,
    offline: Duration,
    eve: Option<Endpoint>,
) -> Result<(), AnyError> {
    let started = Instant::now();
    let bob_route = bob_net.address();
    let bob_calls = call(bob_net, bob.handshake_key(), callback.public(), reference, reply_to, RENDEZVOUS_POLICY);
    let eve_calls = async {
        let Some(mut eve_net) = eve else { return Ok::<_, AnyError>(None) };
        let eve_key = StaticKey::generate();
        let result = call(&mut eve_net, &eve_key, callback.public(), reference, reply_to, SHORT_POLICY).await;
        eve_net.client.disconnect().await;
        Ok(Some(result.is_ok()))
    };
    let carol_answers = async {
        tokio::time::sleep(offline).await;
        let mut throwaway = Endpoint::connect_persistent("carol (throwaway, back online)", throwaway_dir).await?;
        if throwaway.address() != reply_to {
            return Err::<_, AnyError>("throwaway client came back with a different address".into());
        }
        let mut gate = Gate::new(NETWORK);
        gate.expect_callback(bob_card.handshake_key, reference);
        let mut carol_side: Responder<AnonymousSenderTag> = Responder::new(callback, NETWORK, gate);
        let (peer, tag, grant) = serve(&mut throwaway, &mut carol_side, SERVE_PATIENCE)
            .await?
            .ok_or("Bob's callback never finished")?;
        if peer != bob_card.handshake_key || grant != Grant::Callback {
            return Err("Carol let in someone other than Bob".into());
        }
        println!(
            "  Carol's throwaway let in Bob's key only, {:.0}s after his first call (held by her gateway).",
            started.elapsed().as_secs_f32()
        );
        Ok((throwaway, carol_side, tag))
    };
    let (bob_call, eve_end, carol_end) = tokio::join!(bob_calls, eve_calls, carol_answers);
    let (mut bob_to_carol, bob_early) = bob_call?;
    let (mut throwaway, mut carol_side, bob_tag) = carol_end?;
    match eve_end? {
        Some(true) => return Err("Eve's call was answered".into()),
        Some(false) => println!("  Eve's call: nothing came back; she gave up."),
        None => {}
    }
    println!(
        "  Session confirmed after {:.0}s ({} attempt(s)). Bob is the caller.",
        started.elapsed().as_secs_f32(),
        bob_to_carol.attempt()
    );

    println!("\nInside the session they swap long-lived routes and Carol presents her contact key.");
    let hello = format!("{carol_long_lived} {}", to_hex(&carol.signing_key()));
    throwaway.reply(bob_tag, carol_side.seal(&bob_tag, hello.as_bytes())?).await?;
    let text = String::from_utf8(next_message(bob_net, &mut bob_to_carol, bob_early).await?)?;
    let (route, key) = text.split_once(' ').ok_or("malformed hello")?;
    let learned: Recipient = route.parse()?;
    println!(
        "  Bob learns Carol's long-lived route (matches {}) and her contact key (matches the note: {})",
        learned == carol_long_lived,
        key == to_hex(&carol.signing_key())
    );
    if learned != carol_long_lived {
        return Err("route exchange failed".into());
    }

    bob_net.send(reply_to, bob_to_carol.seal(bob_route.to_string().as_bytes())?).await?;
    let (_, plaintext, _) = next_delivery(&mut throwaway, &mut carol_side, bob_tag).await?;
    let learned: Recipient = String::from_utf8(plaintext)?.parse()?;
    println!("  Carol learns Bob's long-lived route: matches {}", learned == bob_route);
    if learned != bob_route {
        return Err("route exchange failed".into());
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
//   anonymum-nym wallet <file>       create (or load) a wallet and a separate
//                                    contact identity; print the address,
//                                    messaging key, binding and contact card
//   anonymum-nym throwaway <dir>     create a persisted throwaway Nym client;
//                                    print its address, then go offline
//   anonymum-nym seal --card HEX --sender F --reply R --intro TEXT --keep F
//                                    seal a note; keep the callback key and
//                                    admission stand-in in file F
//   anonymum-nym open --wallet F --note HEX    (no sender hint)
//   anonymum-nym talk --bob F --carol F --keep F --dir D --reply R
//
// Wallet files hold the private keys in hex. DEV ONLY: they are plain files
// for this test, not encrypted storage.

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
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.into())).collect()
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], AnyError> {
    from_hex(text)?.try_into().map_err(|_| format!("expected {N} bytes").into())
}

/// `name=hex` lines from a key file.
fn field(path: &str, name: &str) -> Result<[u8; 32], AnyError> {
    let text = std::fs::read_to_string(path)?;
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
        .ok_or(format!("{path}: no {name}"))?;
    fixed::<32>(line)
}

fn load_wallet(path: &str) -> Result<Identity, AnyError> {
    Ok(Identity::from_secret_bytes(field(path, "signing")?, field(path, "messaging")?))
}

fn load_contact(path: &str) -> Result<ContactIdentity, AnyError> {
    Ok(ContactIdentity::from_secret_bytes(
        field(path, "contact_signing")?,
        field(path, "contact_handshake")?,
        field(path, "contact_inbox")?,
    ))
}

fn cmd_wallet(args: &[String]) -> Result<(), AnyError> {
    let path = args.first().ok_or("usage: wallet <file>")?;
    if !std::path::Path::new(path).exists() {
        let (signing, messaging) = Identity::generate().to_secret_bytes();
        let (cs, ch, ci) = ContactIdentity::generate().to_secret_bytes();
        std::fs::write(
            path,
            format!(
                "signing={}\nmessaging={}\ncontact_signing={}\ncontact_handshake={}\ncontact_inbox={}\n",
                to_hex(&signing),
                to_hex(&messaging),
                to_hex(&cs),
                to_hex(&ch),
                to_hex(&ci)
            ),
        )?;
    }
    let wallet = load_wallet(path)?;
    let contact = load_contact(path)?;
    let Tx::PublishMessagingKey { key, binding } = wallet.publish_key_tx() else { unreachable!() };
    let MessagingKey(key) = key;
    println!("address={}", to_hex(&wallet.address().0));
    println!("msgkey={}", to_hex(&key));
    println!("binding={}", to_hex(&binding.0));
    println!("card={}", to_hex(&contact.card(NETWORK, COIN, 0, now_secs() + 86_400).to_bytes()));
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
    let card = ContactCard::from_bytes(&from_hex(flag(args, "--card")?)?)?;
    card.verify(&NETWORK, now_secs())?;
    let sender = load_contact(flag(args, "--sender")?)?;
    let callback = StaticKey::generate();
    let admission = random_bytes();
    let note = seal_note(
        &card.inbox_key,
        &sender,
        &callback.public(),
        &fixed::<96>(flag(args, "--reply")?)?,
        flag(args, "--intro")?,
        &admission,
    )?;
    std::fs::write(
        flag(args, "--keep")?,
        format!("callback={}\nadmission={}\n", to_hex(&callback.to_bytes()), to_hex(&admission)),
    )?;
    println!("note={}", to_hex(&note.0));
    Ok(())
}

fn cmd_open(args: &[String]) -> Result<(), AnyError> {
    let contact = load_contact(flag(args, "--wallet")?)?;
    let note = SealedNote(from_hex(flag(args, "--note")?)?);
    let opened = open_note(&contact, &note)?;
    println!("reply={}", to_hex(&opened.route));
    println!("sender={}", to_hex(&opened.sender));
    println!("callback={}", to_hex(&opened.callback));
    println!("admission={}", to_hex(&opened.admission));
    println!("intro={}", opened.intro.replace('\n', " "));
    Ok(())
}

async fn cmd_talk(args: &[String]) -> Result<(), AnyError> {
    let bob = load_contact(flag(args, "--bob")?)?;
    let carol = load_contact(flag(args, "--carol")?)?;
    let keep = flag(args, "--keep")?;
    let callback = StaticKey::from_bytes(field(keep, "callback")?);
    let admission = field(keep, "admission")?;
    let dir = PathBuf::from(flag(args, "--dir")?);
    let reply_to = Recipient::try_from_bytes(fixed::<96>(flag(args, "--reply")?)?)?;
    let card = bob.card(NETWORK, COIN, 0, now_secs() + 86_400);
    println!("Connecting Bob's and Carol's long-lived clients...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    println!("\nBob calls Carol's callback key at the throwaway route from her note.");
    rendezvous(&mut bob_net, &bob, &card, &carol, &callback, admission, carol_net.address(), reply_to, &dir, Duration::ZERO, None)
        .await?;
    carol_net.client.disconnect().await;
    bob_net.client.disconnect().await;
    println!("talk=ok");
    Ok(())
}

// ---- driving the wire layer over the mixnet ----------------------------------

fn deadline_for(call: &Initiator) -> tokio::time::Instant {
    tokio::time::Instant::now() + call.wait().unwrap_or(Duration::ZERO)
}

/// Call the holder of handshake key `peer` at mixnet address `to`, as `me`,
/// naming `reference` inside the encrypted first message, and drive the
/// handshake until the answerer acknowledges. A timeout resends the same
/// bytes; a failed attempt is followed, after a backoff, by a fresh
/// handshake; the policy bounds both. An unauthorised caller hears nothing
/// and gives up. Returns the established call, plus the answerer's first
/// message if that is what established it.
async fn call(
    net: &mut Endpoint,
    me: &StaticKey,
    peer: [u8; 32],
    reference: [u8; 32],
    to: Recipient,
    policy: RetryPolicy,
) -> Result<(Initiator, Option<Vec<u8>>), AnyError> {
    let (mut call, first) = Initiator::start_with(me, peer, NETWORK, reference, policy)?;
    net.send(to, first).await?;
    let mut deadline = deadline_for(&call);
    loop {
        match net.receive_until(deadline).await? {
            Some((frame, _)) => match call.handle(&frame) {
                Ok(InitiatorEvent::Send(confirm)) => {
                    net.send(to, confirm).await?;
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
            None => match call.on_timeout() {
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

/// Answer authorised callers until one confirms a session; send it the ACK.
/// Unauthorised callers are sent nothing. Returns `Ok(None)` if nobody
/// confirmed within `patience`. Answered but unconfirmed handshakes are
/// dropped after a few ticks.
async fn serve(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    patience: Duration,
) -> Result<Option<([u8; 32], AnonymousSenderTag, Grant)>, AnyError> {
    let give_up = tokio::time::Instant::now() + patience;
    loop {
        let deadline = give_up.min(tokio::time::Instant::now() + TICK);
        match net.receive_until(deadline).await? {
            None => {
                for _ in side.tick() {
                    println!("  {} drops a handshake that was never confirmed", net.name);
                }
                if tokio::time::Instant::now() >= give_up {
                    return Ok(None);
                }
            }
            Some((_, None)) => println!("  {} ignores a frame without reply blocks", net.name),
            Some((frame, Some(tag))) => match side.handle(tag, &frame, now_secs()) {
                Ok(ResponderEvent::Reply(reply)) => net.reply(tag, reply).await?,
                Ok(ResponderEvent::Established { peer, grant, reply }) => {
                    net.reply(tag, reply).await?;
                    return Ok(Some((peer, tag, grant)));
                }
                Ok(ResponderEvent::Message { .. }) => println!("  {} ignores a message during a handshake", net.name),
                Err(WireError::Unauthorised) => {
                    println!("  {}: a caller it has not authorised; sends nothing", net.name)
                }
                Err(error) => println!("  {} ignores a frame: {error}", net.name),
            },
        }
    }
}

/// The next message from an established caller. Late handshake frames are
/// answered (a resent CONFIRM gets the ACK again) or ignored.
async fn next_delivery(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    fallback: AnonymousSenderTag,
) -> Result<([u8; 32], Vec<u8>, AnonymousSenderTag), AnyError> {
    loop {
        let (frame, tag) = net.receive().await?;
        let tag = tag.unwrap_or(fallback);
        match side.handle(tag, &frame, now_secs()) {
            Ok(ResponderEvent::Message { peer, plaintext }) => return Ok((peer, plaintext, tag)),
            Ok(ResponderEvent::Reply(reply)) => net.reply(tag, reply).await?,
            Ok(other) => println!("  {} ignores {other:?}", net.name),
            Err(error) => println!("  {} ignores a frame: {error}", net.name),
        }
    }
}

/// The next message on an established call (or the one that established it),
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

