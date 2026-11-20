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
//! stays offline (default 60). Set ANONYMUM_DROP_FIRST_ACK=1 to make Bob drop
//! the first acknowledgement he sends, to watch Alice recover.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anonymum_core::{Chain, Event, MessagingKey, Params, SealedNote, Tx, COIN};
use anonymum_crypto::wire::{Initiator, InitiatorEvent, Responder, ResponderEvent, RetryPolicy, WireError};
use anonymum_crypto::{
    open_note, random_bytes, seal_note, ContactCard, ContactIdentity, ContactNote, Ed25519Invites, Grant, Identity,
    InviteSecret, Network, Now, Purpose, StaticKey,
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
/// How often an idle responder checks its deadlines (they are also checked
/// on every frame it handles).
const EXPIRY_CHECK: Duration = Duration::from_secs(30);
/// How long a stranger's throwaway listener accepts the recipient's callback
/// (the request lives 48 h on this chain; gateways hold messages 24 h).
const CALLBACK_WINDOW: Duration = Duration::from_secs(24 * 3_600);
/// Carol's receipt for Bob's long-lived route at the end of rendezvous.
const RECEIPT: &[u8] = b"route received";
/// Test switch (env ANONYMUM_DROP_FIRST_ACK): Bob drops the first ACK he
/// would send, to show the caller recover through the real driver.
static DROP_FIRST_ACK: AtomicBool = AtomicBool::new(false);
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
    if std::env::var_os("ANONYMUM_DROP_FIRST_ACK").is_some() {
        DROP_FIRST_ACK.store(true, Ordering::SeqCst);
        println!("(ANONYMUM_DROP_FIRST_ACK: Bob will drop the first acknowledgement he sends.)");
    }

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
    let genesis = chain.params().genesis;
    chain.apply(bob_wallet.address(), bob_wallet.publish_key_tx(&genesis))?;

    println!("\nOn-chain: Bob creates a chain invite, Alice uses it to open a channel.");
    let chain_invite = InviteSecret::generate();
    chain.apply(bob_wallet.address(), Tx::RegisterInvite { key: chain_invite.public(), expires_at: None })?;
    let handed_over = InviteSecret::from_bytes(chain_invite.to_bytes()); // out of band
    chain.apply(
        alice_wallet.address(),
        Tx::OpenWithInvite {
            recipient: bob_wallet.address(),
            key: handed_over.public(),
            proof: handed_over.sign_for(&genesis, &alice_wallet.address(), &bob_wallet.address()),
        },
    )?;

    // ---- mixnet -----------------------------------------------------------
    println!("\nConnecting to the Nym mixnet...");
    let mut bob_net = Endpoint::connect("bob").await?;
    let mut alice_net = Endpoint::connect("alice").await?;
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    // Invited contacts get Bob's route with his card, out of band.
    let bob_route = bob_net.address();
    let mut bob_side: Responder<AnonymousSenderTag> = Responder::for_identity(&bob, NETWORK);

    // ---- Alice, invited -------------------------------------------------------
    println!("\nAlice makes a caller key for Bob; Bob gives her his card, his route and an invitation to that key.");
    let alice_key = StaticKey::generate();
    let invitation = bob.invite(NETWORK, alice_key.public(), Purpose::Contact, now_secs() + 3_600);
    bob_side.record_invitation(invitation.clone(), Now::system())?;
    card.verify(&NETWORK, now_secs())?;
    invitation.verify(&card.signing_key, &NETWORK, now_secs())?;
    println!("  Alice checked the card and the invitation (issuer, network, keys, expiry, signature).");

    println!("\nAlice -> Bob: Noise IK handshake, then a message and a reply, through the mixnet.");
    let started = Instant::now();
    let alice_talks = async {
        let (mut call, early) =
            call(&mut alice_net, &alice_key, card.handshake_key, invitation.id, bob_route, CALL_POLICY).await?;
        let confirmed = started.elapsed().as_secs_f32();
        let sealed = call.seal(b"Hi Bob. Nobody else can read this.")?;
        println!("  on the wire: {} bytes of ciphertext, starts {:02x?}", sealed.len(), &sealed[..12]);
        alice_net.send(bob_route, sealed).await?;
        let text = next_message(&mut alice_net, &mut call, early).await?;
        Ok::<_, AnyError>((call.attempt(), confirmed, text))
    };
    let bob_answers = async {
        let (peer, tag, grant) =
            serve(&mut bob_net, &mut bob_side, SERVE_PATIENCE).await?.ok_or("Alice never finished the handshake")?;
        // Bob keeps reading: a resent CONFIRM gets its ACK again, then
        // Alice's message arrives.
        let (_, plaintext, reply_tag) = next_delivery(&mut bob_net, &mut bob_side, tag).await?;
        bob_net.reply(reply_tag, bob_side.seal(&reply_tag, b"Hi Alice. Got it.", Now::system())?).await?;
        Ok::<_, AnyError>((peer, grant, plaintext))
    };
    let (alice_end, bob_end) = tokio::join!(alice_talks, bob_answers);
    let (peer, grant, plaintext) = bob_end?;
    let (attempts, confirmed, text) = alice_end?;
    let why = match grant {
        Grant::Invitation { .. } => "her invitation",
        Grant::Contact => "a contact",
        Grant::Callback => "a callback",
    };
    println!(
        "  Bob let in caller key {} ({why}; Alice's: {}); Alice confirmed after {confirmed:.1}s ({attempts} attempt(s)). Invitation now used: {}",
        short(&peer),
        peer == alice_key.public(),
        bob_side.gate().is_honoured(&invitation.id)
    );
    println!("  Bob reads: {:?}", String::from_utf8_lossy(&plaintext));
    println!("  Alice reads Bob's reply (via reply blocks; Bob never learns where she is): {:?}", String::from_utf8_lossy(&text));
    if grant != (Grant::Invitation { id: invitation.id }) {
        return Err("Alice should have come in on her invitation".into());
    }

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
    let note = seal_note(
        &NETWORK,
        &card.inbox_key,
        &carol,
        &callback.public(),
        &throwaway_route.to_bytes(),
        intro,
        &admission,
    )?;
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
    // address or hint. Everything he needs to call back comes from the note.
    let req = chain.request(request).ok_or("request vanished")?.clone();
    let opened = open_note(&bob, &NETWORK, &req.note)?;
    println!(
        "  Bob's client opens the note with his inbox key alone. Sender's contact key {}, intro: {:?}",
        short(&opened.sender),
        opened.intro
    );
    chain.apply(bob_wallet.address(), Tx::AcceptContact { request })?;
    println!("  On-chain: Bob accepts (the claim is final in this simulation).");

    println!(
        "\nBob calls the callback key from the note at its throwaway route; Carol is offline for {}s.",
        offline.as_secs()
    );
    println!("Eve learned the route and calls too.");
    let mut eve_net = Endpoint::connect("eve").await?;
    let started = Instant::now();
    let reply_to = Recipient::try_from_bytes(opened.route)?;
    let bob_calls = recipient_side(&mut bob_net, &bob, &opened);
    let eve_calls = async {
        let eve_key = StaticKey::generate();
        let result = call(&mut eve_net, &eve_key, opened.callback, opened.admission, reply_to, SHORT_POLICY).await;
        Ok::<_, AnyError>(result.is_ok())
    };
    let carol_answers = stranger_side(&throwaway_dir, &callback, &card, admission, &carol, carol_net.address(), offline);
    let (bob_end, eve_end, carol_end) = tokio::join!(bob_calls, eve_calls, carol_answers);
    let carol_route = bob_end?;
    let bob_route_learned = carol_end?;
    if eve_end? {
        return Err("Eve's call was answered".into());
    }
    println!("  Eve's call: nothing came back; she gave up.");
    println!(
        "  Routes swapped after {:.0}s: Bob has Carol's ({}), Carol has Bob's ({}).",
        started.elapsed().as_secs_f32(),
        carol_route == carol_net.address(),
        bob_route_learned == bob_route
    );
    if carol_route != carol_net.address() || bob_route_learned != bob_route {
        return Err("route exchange failed".into());
    }
    eve_net.client.disconnect().await;

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

/// The recipient's half of reverse rendezvous. Everything comes from the
/// note the recipient opened: the callback key to call, the route to call it
/// at, the request reference to name, and the sender's contact key the
/// stranger must present. Calls (retrying), checks the presented contact
/// key, and swaps long-lived routes. Returns the stranger's route.
async fn recipient_side(net: &mut Endpoint, me: &ContactIdentity, note: &ContactNote) -> Result<Recipient, AnyError> {
    let route = Recipient::try_from_bytes(note.route)?;
    let my_route = net.address();
    let (mut call, early) =
        call(net, me.handshake_key(), note.callback, note.admission, route, RENDEZVOUS_POLICY).await?;
    println!("  Bob: the stranger's side acknowledged (attempt {}).", call.attempt());
    let text = String::from_utf8(next_message(net, &mut call, early).await?)?;
    let (their_route, their_key) = text.split_once(' ').ok_or("malformed hello")?;
    if their_key != to_hex(&note.sender) {
        return Err("the stranger presented a contact key other than the note's sender".into());
    }
    let their_route: Recipient = their_route.parse()?;
    println!("  Bob: Carol presented the contact key from the note and her long-lived route.");
    net.send(route, call.seal(my_route.to_string().as_bytes())?).await?;
    // Wait for Carol's receipt before going on (or exiting): a client that
    // disconnects at once can lose what it just sent.
    let receipt = next_message(net, &mut call, None).await?;
    if receipt != RECEIPT {
        return Err("unexpected reply instead of the receipt".into());
    }
    println!("  Bob: Carol confirmed she has his route.");
    Ok(their_route)
}

/// The stranger's half of reverse rendezvous. The throwaway client comes
/// back after `offline` and answers only the recipient's handshake key (from
/// the card the note was sealed to), naming this request, within
/// CALLBACK_WINDOW. It sends the stranger's long-lived route and contact key
/// at once, learns the recipient's route, and is deleted from disk.
async fn stranger_side(
    throwaway_dir: &PathBuf,
    callback: &StaticKey,
    recipient_card: &ContactCard,
    reference: [u8; 32],
    me: &ContactIdentity,
    my_long_lived: Recipient,
    offline: Duration,
) -> Result<Recipient, AnyError> {
    tokio::time::sleep(offline).await;
    let started = Instant::now();
    let mut throwaway = Endpoint::connect_persistent("carol (throwaway, back online)", throwaway_dir).await?;
    let mut side: Responder<AnonymousSenderTag> = Responder::for_callback(
        callback,
        NETWORK,
        recipient_card.handshake_key,
        reference,
        Instant::now() + CALLBACK_WINDOW,
    )?;
    let (peer, tag, grant) =
        serve(&mut throwaway, &mut side, SERVE_PATIENCE).await?.ok_or("Bob's callback never finished")?;
    if peer != recipient_card.handshake_key || grant != Grant::Callback {
        return Err("the throwaway let in someone other than the recipient".into());
    }
    println!(
        "  Carol's throwaway let in Bob's key only ({:.0}s after coming back online; his call was held by her gateway).",
        started.elapsed().as_secs_f32()
    );
    // Sent at once: a valid message also establishes the session for Bob if
    // our ACK was lost.
    let hello = format!("{my_long_lived} {}", to_hex(&me.signing_key()));
    throwaway.reply(tag, side.seal(&tag, hello.as_bytes(), Now::system())?).await?;
    let (_, plaintext, _) = next_delivery(&mut throwaway, &mut side, tag).await?;
    let learned: Recipient = String::from_utf8(plaintext)?.parse()?;
    throwaway.reply(tag, side.seal(&tag, RECEIPT, Now::system())?).await?;
    // Give the receipt time to leave before the throwaway disconnects.
    tokio::time::sleep(Duration::from_secs(5)).await;
    throwaway.client.disconnect().await;
    std::fs::remove_dir_all(throwaway_dir)?;
    println!("  Carol learned Bob's long-lived route and deleted the throwaway client.");
    Ok(learned)
}

// ---- subcommands for the end-to-end run against a dev node (audit F8) ------
//
// `substrate/scripts/e2e.mjs` drives these: it does the chain transactions
// (Polkadot.js, signing with each wallet's Ed25519 account key) and calls
// this binary for everything cryptographic and for the mixnet. The two
// people run as separate processes that share only the chain and the
// mixnet.
//
//   anonymum-nym wallet <file> --genesis HEX
//                                    create (or load) a wallet and a separate
//                                    contact identity; print the address,
//                                    messaging key, binding and contact card
//   anonymum-nym throwaway <dir>     create a persisted throwaway Nym client;
//                                    print its address, then go offline
//   anonymum-nym seal --card HEX --sender F --reply R --intro TEXT --keep F
//                                    seal a note; keep the callback key and
//                                    admission stand-in in Carol's file F
//   anonymum-nym open --wallet F --note HEX    (no sender hint)
//   anonymum-nym answer --carol F --keep F --dir D --card HEX
//                                    Carol's process: answer Bob's callback
//   anonymum-nym callback --bob F --note HEX
//                                    Bob's process: open the note himself
//                                    and call back
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
        Some("answer") => cmd_answer(rest).await,
        Some("callback") => cmd_callback(rest).await,
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
    // The binding (v2) names the chain's genesis hash, given by the caller.
    let genesis = fixed::<32>(flag(args, "--genesis")?)?;
    let Tx::PublishMessagingKey { key, binding } = wallet.publish_key_tx(&genesis) else { unreachable!() };
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
        &NETWORK,
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
    let opened = open_note(&contact, &NETWORK, &note)?;
    println!("reply={}", to_hex(&opened.route));
    println!("sender={}", to_hex(&opened.sender));
    println!("callback={}", to_hex(&opened.callback));
    println!("admission={}", to_hex(&opened.admission));
    println!("intro={}", opened.intro.replace('\n', " "));
    Ok(())
}

/// Carol's process: her own contact identity and keep file, Bob's public
/// card, her throwaway directory. Nothing of Bob's private state.
async fn cmd_answer(args: &[String]) -> Result<(), AnyError> {
    let carol = load_contact(flag(args, "--carol")?)?;
    let keep = flag(args, "--keep")?;
    let callback = StaticKey::from_bytes(field(keep, "callback")?);
    let admission = field(keep, "admission")?;
    let card = ContactCard::from_bytes(&from_hex(flag(args, "--card")?)?)?;
    card.verify(&NETWORK, now_secs())?;
    let dir = PathBuf::from(flag(args, "--dir")?);
    let carol_net = Endpoint::connect("carol (long-lived)").await?;
    let learned = stranger_side(&dir, &callback, &card, admission, &carol, carol_net.address(), Duration::ZERO).await?;
    println!("mine={}", carol_net.address());
    carol_net.client.disconnect().await;
    println!("learned={learned}");
    println!("answer=ok");
    Ok(())
}

/// Bob's process: his own wallet file and the note bytes as read from the
/// chain. The callback key, route and request reference come only from the
/// note he decrypts.
async fn cmd_callback(args: &[String]) -> Result<(), AnyError> {
    let bob = load_contact(flag(args, "--bob")?)?;
    let note = SealedNote(from_hex(flag(args, "--note")?)?);
    let opened = open_note(&bob, &NETWORK, &note)?;
    let mut bob_net = Endpoint::connect("bob").await?;
    let learned = recipient_side(&mut bob_net, &bob, &opened).await?;
    println!("mine={}", bob_net.address());
    bob_net.client.disconnect().await;
    println!("learned={learned}");
    println!("callback=ok");
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

/// Answer authorised callers until one confirms a session; send it the ACK
/// (unless the ACK-loss test switch drops the first one). Unauthorised
/// callers are sent nothing. Returns `Ok(None)` if nobody confirmed within
/// `patience`. Callers keep reading afterwards (`next_delivery`), so a
/// resent CONFIRM gets its ACK again.
async fn serve(
    net: &mut Endpoint,
    side: &mut Responder<AnonymousSenderTag>,
    patience: Duration,
) -> Result<Option<([u8; 32], AnonymousSenderTag, Grant)>, AnyError> {
    let give_up = tokio::time::Instant::now() + patience;
    loop {
        let deadline = give_up.min(tokio::time::Instant::now() + EXPIRY_CHECK);
        match net.receive_until(deadline).await? {
            None => {
                for _ in side.expire(Now::system()).pending {
                    println!("  {} drops a handshake that was never confirmed", net.name);
                }
                if tokio::time::Instant::now() >= give_up {
                    return Ok(None);
                }
            }
            Some((_, None)) => println!("  {} ignores a frame without reply blocks", net.name),
            Some((frame, Some(tag))) => match side.handle(tag, &frame, Now::system()) {
                Ok(ResponderEvent::Reply(reply)) => net.reply(tag, reply).await?,
                Ok(ResponderEvent::Established { peer, grant, reply }) => {
                    if DROP_FIRST_ACK.swap(false, Ordering::SeqCst) {
                        println!("  {}: (test) drops its first acknowledgement", net.name);
                    } else {
                        net.reply(tag, reply).await?;
                    }
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
        match side.handle(tag, &frame, Now::system()) {
            Ok(ResponderEvent::Message { peer, plaintext }) => return Ok((peer, plaintext, tag)),
            Ok(ResponderEvent::Reply(reply)) => {
                println!("  {}: a repeated frame; sends its cached answer again", net.name);
                net.reply(tag, reply).await?
            }
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
