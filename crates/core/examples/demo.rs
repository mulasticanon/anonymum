//! Walk through both ways of reaching someone. Run with:
//!
//!     cargo run --example demo

use anonymum_core::crypto::invite_message;
use anonymum_core::crypto::mock::{MockInviteSecret, MockScheme};
use anonymum_core::*;

fn coins(amount: Amount) -> String {
    format!("{}.{:06}", amount / COIN, amount % COIN)
}

fn balances(chain: &Chain<MockScheme>, who: &[Address]) {
    for address in who {
        println!("    {:<6} {}", address.to_string(), coins(chain.ledger().balance(address)));
    }
    println!(
        "    node reward pool {}   burned {}   escrow {}",
        coins(chain.ledger().reward_pool()),
        coins(chain.ledger().burned()),
        coins(chain.ledger().escrowed()),
    );
}

fn deliver(
    chain: &Chain<MockScheme>,
    net: &mut InMemoryTransport,
    inbox: &mut Inbox,
    owner: &Address,
    now_ms: u64,
) {
    while let Some(envelope) = net.receive(owner) {
        let verdict = inbox.admit(chain, &envelope, now_ms);
        println!(
            "    from {:<6} {:?}: {:?}",
            envelope.from.to_string(),
            String::from_utf8_lossy(&envelope.payload),
            verdict
        );
    }
}

fn main() {
    let mut chain = Chain::new(Params::default(), MockScheme);
    let mut net = InMemoryTransport::default();
    let alice = Address::from_label("alice");
    let bob = Address::from_label("bob");
    let carol = Address::from_label("carol");
    let everyone = [alice, bob, carol];
    for who in everyone {
        chain.mint(who, 10 * COIN);
    }
    let mut bob_inbox = Inbox::new(bob, 5, 1);

    println!("Start");
    balances(&chain, &everyone);

    println!("\n1. Bob sets his price for strangers to 2 coins and creates an invite for Alice.");
    chain.apply(bob, Tx::SetContactPrice { price: 2 * COIN }).unwrap();
    let invite = MockInviteSecret::from_seed(42);
    chain.apply(bob, Tx::RegisterInvite { key: invite.public(), expires_at: None }).unwrap();

    println!("\n2. Alice uses the invite: small network fee, nothing to Bob.");
    chain
        .apply(
            alice,
            Tx::OpenWithInvite {
                recipient: bob,
                key: invite.public(),
                proof: invite.sign(&invite_message(&alice, &bob)),
            },
        )
        .unwrap();
    balances(&chain, &everyone);

    println!("\n3. Alice and Carol both message Bob. Carol has no channel.");
    net.send(Envelope { from: alice, to: bob, payload: b"hello Bob".to_vec() });
    net.send(Envelope { from: carol, to: bob, payload: b"buy my stuff".to_vec() });
    deliver(&chain, &mut net, &mut bob_inbox, &bob, 0);

    println!("\n4. Carol pays to request contact: network fee now, Bob's 2 coins held in escrow.");
    let events = chain
        .apply(carol, Tx::RequestContact { recipient: bob, max_price: 2 * COIN })
        .unwrap();
    let Event::ContactRequested { request, .. } = events[0] else { unreachable!() };
    balances(&chain, &everyone);

    println!("\n5. Bob accepts: he receives the 2 coins and the channel opens.");
    chain.apply(bob, Tx::AcceptContact { request }).unwrap();
    balances(&chain, &everyone);

    println!("\n6. Carol messages again, then floods. Free messages are rate limited.");
    for i in 0..7 {
        net.send(Envelope { from: carol, to: bob, payload: format!("msg {i}").into_bytes() });
    }
    deliver(&chain, &mut net, &mut bob_inbox, &bob, 1_000);

    assert!(chain.ledger().is_balanced());
    println!("\nEvery coin accounted for: {}", chain.ledger().is_balanced());
}
