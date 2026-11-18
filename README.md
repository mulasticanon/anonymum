# Anonymum

A messaging coin where reaching someone costs money unless they invited you.

- **Invited contact**: opens a channel for a small network fee.
- **Stranger**: pays a larger network fee plus a price the recipient sets.
- **After that**: messages are free, rate limited, and travel over the Nym mixnet.

Three crates:

| Crate | What it is | Verified how |
|---|---|---|
| `anonymum-core` | The rules: invites, paid contact requests, channels, fees, escrow, client-side admission, rate limits. No dependencies. | 23 tests |
| `anonymum-crypto` | Real cryptography: Ed25519 wallets and invites, Noise XX end-to-end sessions, message framing. | 15 tests |
| `anonymum-nym` | Demo: three wallets exchanging encrypted messages over the live Nym mixnet. | Ran end to end over the live mixnet on Windows, 2026-11-18 (17 s). A single manual run, not an automated test. |

Nothing here has been audited. Do not use it to protect anything real.

## Run it

    cargo test                 # core + crypto, fast
    cargo run -p anonymum-core --example demo
    cargo run -p anonymum-nym    # live mixnet; first build takes several minutes

Needs Rust 1.87 or newer. Keep `Cargo.lock`: it pins the Nym crates to the
set the SDK was released with. A fresh resolve picks mismatched Nym versions
that do not compile.

The Nym demo needs ordinary internet access (DNS, and outbound connections
to mixnet gateways). It prefers gateways on TLS port 443; set
`ANONYMUM_PLAIN_WS=1` to allow any gateway.

First live run (Windows 11, Rust 1.100, 2026-11-18): all three clients
connected in 1–5 s over TLS gateways. Alice's handshake took 4 s, a message
under 1 s, and Bob's anonymous reply 0.5 s. Bob authenticated Carol, found no
channel, and dropped her message. The demo runs its async runtime on 16 MiB
stacks because Windows' 1 MiB main-thread stack overflowed while the Nym
client was connecting.

Nym gives each sender one stable reply tag per recipient, so the responder
can key sessions by that tag.

## What is real and what is not

| Piece | Status |
|---|---|
| Fee and channel rules | Built, tested |
| Invites | Real Ed25519 signatures, bound to opener and recipient |
| End-to-end encryption | Noise XX (X25519, ChaCha20-Poly1305, BLAKE2s). Addresses are proven inside the encrypted handshake, so observers learn neither party |
| Out-of-order delivery, replay protection | Built, tested (a mixnet reorders on purpose) |
| Mixnet transport | Nym SDK; replies go through single-use reply blocks, so the recipient never learns the caller's network location. Ran once live; no automated test |
| The chain itself | Simulated in-process. No real blockchain yet |
| Shielded payments | Not started. The channel table is public |
| Node staking and rewards | Pool accumulates; payout not started |
| Post-quantum key exchange, per-message forward secrecy | Not started |

## Design decisions taken

1. **Messages never go on-chain.** The chain holds money and channel state only.
2. **Invites are one-time key pairs, not secret codes.** The recipient registers
   the public half and hands out the private half. The opener signs
   "opener + recipient", so a copied transaction is useless to anyone else.
3. **Admission is enforced by the recipient's client, not by relay nodes.** Mix
   nodes cannot know who is talking to whom, so they cannot check channels.
   The recipient's client reads the chain and drops everything else.
4. **Stranger's payment is held in escrow.** Accept: recipient gets it. Decline,
   sender cancel, or no answer before the deadline: sender gets it back minus a
   1% decline fee, which is burned. Nobody receives the decline fee, so no one
   profits from turning people away. Exception: if the stranger opens a channel
   with an invite instead, the price is refunded in full. The network fee is
   never refunded, so spam always costs something.
5. **Network fees are split**: part burned, part into a pool for relay nodes.
6. **`max_price` on contact requests** protects the sender from a price change
   between signing and inclusion.

## Open questions for you

- **Fee levels**: current numbers (0.01 / 0.5 / default price 1.0 / decline fee 1%) are
  placeholders. They should come out of a spam-cost simulation.
- **Intro message cap**: 280 bytes is proposed. Right size?

## Decided, not yet built

- **Closing blocks.** If you close a channel, the other address cannot pay to
  reach you again. Only you can reopen, by giving them a new invite. The
  block is per address; a new wallet starts fresh and pays stranger costs.
- **Direct blocking.** You can also block any address you never had a channel
  with, for known spammers or harassers. Only you can lift the block.
- **No mixnet address is ever published.** A stranger's contact request
  carries a sealed note for the recipient: a throwaway mixnet address and a
  greeting-length intro (up to 280 bytes). If the recipient accepts, their app calls the stranger there,
  and the two exchange real addresses inside the encrypted session. Wallets
  can also turn stranger requests off and be invite-only.
- **Requests expire after 48 hours.**

## Known gaps that matter for the security claim

- The channel table is public: the chain shows that A and B are connected.
  This contradicts the mixnet's purpose until shielded payments exist.
- Forward secrecy is per session, not per message. Sessions should be
  renewed often; a double ratchet would do this automatically.
- A handshake costs the responder CPU before it knows who is calling.
  Pending handshakes are capped, but this needs a proper cost for strangers.
- A flood of dropped messages still costs the recipient bandwidth. Nym's paid
  bandwidth credentials are the network-level answer and need integrating.

## Roadmap

1. **Done** — rules as a state machine with tests.
2. **Done** — real invites, identities, end-to-end sessions.
3. **Done** — Nym transport demo, run live over the mixnet.
4. Port `chain.rs` to a Substrate pallet; run a local test chain.
5. Shielded channel opening, so the chain no longer reveals the contact graph.
6. Double ratchet and post-quantum key exchange.
7. Node staking, reward payout, fee simulation, external audit.
