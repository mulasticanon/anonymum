# Anonymum

A messaging coin where reaching someone costs money unless they invited you.

- **Invited contact**: opens a channel for a small network fee.
- **Stranger**: pays a larger network fee plus a price the recipient sets.
- **After that**: messages are free, rate limited, and travel over the Nym mixnet.

Three crates, plus a Substrate port in `substrate/`:

| Crate | What it is | Verified how |
|---|---|---|
| `anonymum-core` | The rules: invites, paid contact requests, channels, blocks, fees, escrow, client-side admission, rate limits. No dependencies. | 45 tests |
| `anonymum-crypto` | Real cryptography: Ed25519 wallets and invites, Noise XX end-to-end sessions, sealed contact notes (Noise N), message framing. | 25 tests |
| `anonymum-nym` | Demo: an invited contact, a stranger arriving by reverse rendezvous, and a dropped non-contact, over the live Nym mixnet. | Manual live runs on Windows, 2026-11-18 (see below). Not an automated test. |

| `pallet-anonymum` (`substrate/`) | The same chain rules as a FRAME pallet (Polkadot SDK `stable2609-2`), plus a minimal runtime that includes it. | 45 tests (43 rule tests ported from the core crate); runtime ran on a local dev node with real transactions, 2026-11-18 |

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

Stranger flow, live (2026-11-18): Carol sealed a 427-byte note to Bob's
on-chain key, paid for the request, and took her throwaway client offline.
Bob opened the note, accepted, and called her. Her gateway held the call
while she was away; she reconnected from disk with the same address,
answered, and the two swapped long-lived addresses inside the session.
Offline 60 s: one call attempt, session after 64 s, whole demo passed in
92 s. Offline 200 s (longer than Bob's 150 s retry): two attempts, both
copies delivered, one session, addresses swapped; that run then failed at
the unrelated last step when Dave's new client could not resolve its
gateway (`ResolutionFailed`), so the 200 s case has not passed end to end.
An earlier 200 s run, before the retry fix, failed on crossed replies (see
CLAUDE.md). `ANONYMUM_OFFLINE_SECS` sets the offline time.

**How long gateways hold messages:** Nym nodes delete stored messages for an
offline client after 24 hours by default (`stale_messages.max_age` in
`nym-node`'s gateway config; operators can change it). That is shorter than
the 48 h a request lives, so the accepting side must keep calling again until
the request would have expired. The demo retries every 150 s; a real client
would retry on a slower schedule.

## Substrate pallet and local node (roadmap step 4)

`substrate/` is its own Cargo workspace (own `Cargo.lock`) so the Polkadot SDK
cannot disturb the pinned Nym crates.

    cd substrate
    cargo test -p pallet-anonymum                 # 45 tests, mock runtime
    cargo build --release -p anonymum-runtime     # native + WebAssembly runtime

On Windows (Rust 1.100, 8 cores, 7.7 GB RAM, `-j 4`): the first release
runtime build took 27 min; later runtime rebuilds took about 2–3 min.
(The first pallet build was interrupted by a restart, so its full time was
not measured.)

The local node runs in WSL2 (Polkadot SDK nodes are not supported on native
Windows), using Parity's prebuilt `polkadot-omni-node` 1.25.2:

    # inside WSL/Ubuntu
    bash substrate/scripts/get-omni-node.sh       # download + SHA-256 check
    bash substrate/scripts/run-node.sh            # dev chain on 127.0.0.1:9944

    # on Windows, with the node running
    cd substrate/scripts && npm install && node smoke.mjs

`smoke.mjs` sends real signed transactions and checks balances and events
after each: a messaging key (and a forged one refused), an invite channel, a
stranger's paid request with its sealed note accepted, a declined request
with the 1% burn, a blocked address refused, a closed channel blocking the
other side, and total issuance falling by exactly the burns plus transaction
fees. All checks passed on 2026-11-18 (three runs on fresh chains).

Differences from the in-process simulation:
- Escrow is a balance hold; the reward pool is the pallet's account.
- Accounts must keep the existential deposit, so payments cannot empty them.
- A failed transaction changes no pallet state and takes no pallet fee, but
  the chain's own transaction fee is still charged (1 unit in this demo
  runtime), as on any Substrate chain.
- Expiry uses one queue per block; at most `MaxRequestsPerBlock` (256)
  requests can expire in one block, and a request that would overflow it
  fails without charge.
- Weights are placeholders, not benchmarks.
- The runtime exposes a stub Aura API (6 s slots, no authorities) only
  because omni-node's dev mode reads it. There is no Aura consensus.
- Dev accounts are sr25519 (Substrate's default); the binding check accepts
  any Substrate signature type, while `anonymum-crypto` wallets are Ed25519.

## What is real and what is not

| Piece | Status |
|---|---|
| Fee and channel rules, blocks, invite-only | Built, tested |
| Reverse rendezvous for strangers | Sealed fixed-size notes built and tested; the full flow ran live in the demo. Retry logic lives in the demo, not yet in a reusable client |
| Invites | Real Ed25519 signatures, bound to opener and recipient |
| End-to-end encryption | Noise XX (X25519, ChaCha20-Poly1305, BLAKE2s). Addresses are proven inside the encrypted handshake, so observers learn neither party |
| Out-of-order delivery, replay protection | Built, tested (a mixnet reorders on purpose) |
| Mixnet transport | Nym SDK; replies go through single-use reply blocks, so the recipient never learns the caller's network location. Ran once live; no automated test |
| The chain itself | Rules run as a Substrate pallet on a local single-node dev chain (manual seal, 6 s blocks). No real network, consensus or validators yet |
| Shielded payments | Not started. The channel table is public |
| Node staking and rewards | Pool accumulates; payout not started |
| Post-quantum key exchange, per-message forward secrecy | Not started |

## Design decisions taken

1. **Messages never go on-chain.** The chain holds money, channel state,
   blocks, messaging keys, and the sealed note of each pending contact
   request (readable only by its recipient).
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
7. **Closing blocks.** If you close a channel, the other address cannot pay to
   reach you again. Only you can reopen: by `Unblock`, or by giving them an
   invite issued *after* the block (an older invite they kept does not work).
   The block is per address; a new wallet starts fresh and pays stranger costs.
8. **Direct blocking.** You can block any address, with or without a channel.
   Its paid requests then fail before any fee is charged, its pending request
   is refunded in full, and an open channel with it is closed. Any new channel
   between two addresses clears blocks both ways, since it only opens with
   both sides' consent.
9. **No mixnet address is ever published.** Wallets publish a messaging key
   (a key, not a location) with a signature tying it to the address. A
   stranger's request carries a note sealed to that key (Noise N): a throwaway
   mixnet address and an intro of at most 280 bytes, padded so every note is
   427 bytes. The note is bound to sender and recipient, so it cannot be
   reused in someone else's request. On accept, the recipient's app calls the
   stranger there, and the two swap real addresses inside the encrypted
   session. Wallets can be invite-only; requests to them fail before any fee.
10. **Requests expire after 48 hours**, defined as a duration and converted to
    blocks from the block time (6 s blocks: 28,800).

## Open questions for you

- **Fee levels**: current numbers (0.01 / 0.5 / default price 1.0 / decline fee 1%) are
  placeholders. They should come out of a spam-cost simulation.
- **Intro message cap**: 280 bytes is proposed. Right size?

## Known gaps that matter for the security claim

- The channel table is public: the chain shows that A and B are connected.
  This contradicts the mixnet's purpose until shielded payments exist. The
  same goes for contact requests (Y requested X) and blocks (who blocked whom).
- Contact notes have no forward secrecy: if a recipient's messaging key leaks
  later, old notes sealed to it can be read. Rotating the key limits this.
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
   **Done** — closing blocks, direct blocking, reverse rendezvous for
   strangers, invite-only wallets, 48 h expiry.
4. **Done** — `chain.rs` ported to a Substrate pallet; local dev chain runs it
   with real transactions. Not done: benchmarked weights, a real network
   with consensus, our own node binary.
5. Shielded channel opening, so the chain no longer reveals the contact graph.
6. Double ratchet and post-quantum key exchange.
7. Node staking, reward payout, fee simulation, external audit.
