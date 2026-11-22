# Anonymum

A messaging coin where reaching someone costs money unless they invited you.

- **Invited contact**: opens a channel for a small network fee.
- **Stranger**: pays a larger network fee plus a price the recipient sets.
- **After that**: messages are free, rate limited, and travel over the Nym mixnet.

> **Not reviewed.** The messaging handshake (Noise IK with an authorisation
> check before any reply) and the stranger's note format are a prototype of
> spec v0.7 section 2a. No cryptographer has reviewed them (spec questions
> 11 and 12), and nothing here is audited.

Four crates, plus a Substrate port in `substrate/`:

| Crate | What it is | Verified how |
|---|---|---|
| `anonymum-core` | The rules: invites, paid contact requests, channels, blocks, fees, escrow, storage deposits, client-side admission, rate limits. No dependencies. | 63 tests |
| `anonymum-crypto` | Real cryptography: Ed25519 wallets and chain invites; contact identities separate from the wallet (cards, invitations); Noise IK sessions where the answering side decides before replying; strangers' notes (format v5: hybrid ML-KEM-768 + Noise Xpsk0, deniable sender authentication) opened with the inbox keys alone; framing with retries and confirmation; a Double Ratchet (Signal specification) for data frames, seeded from the IK handshake; encrypted, versioned snapshots of grant state (one device); weekly rotation of the handshake and inbox keys together, with contact key rollover from a card signed by the same key; dummy stranger notes that are real v5 notes between throwaway keys. **The handshake, ratchet, note format and snapshot have not been reviewed.** | 190 tests |
| `anonymum-nym` | Demo: an invited contact, a stranger arriving by reverse rendezvous, and a dropped non-contact, over the live Nym mixnet. | Manual live runs on Windows, 2026-11-18 to 2026-11-20 (see below). Not an automated test. |
| `anonymum-shielded-model` | A plain-Rust **model of the shielded-money rules** in `docs/shielded-spec-v0.md`, for review. Not private, not secure: no proofs, no encryption of notes; it checks the hidden witness directly. Fixed asymmetric payload slots (2 x 200 + 1,795 bytes), a prunable 24-hour stranger-note store with a permanent hash the proof binds to, random (never all-zero) dummy slots, a versioned recovery copy, escrows that lock a fee ceiling (surplus returned privately, a top-up if the fee rises above it), and one-time refund keys per escrow. | 83 tests, including adversarial cases and a randomised conservation test |
| `pallet-anonymum` (`substrate/`) | The same chain rules as a FRAME pallet (Polkadot SDK `stable2609-2`), plus a minimal runtime that includes it. | 64 tests (rule tests matching the core crate's, plus FRAME checks); runtime ran on a local dev node with real transactions, 2026-11-18 |

Nothing here has been audited. Do not use it to protect anything real.

## Run it

    cargo test                 # core + crypto, fast
    cargo run -p anonymum-core --example demo
    cargo run -p anonymum-nym    # live mixnet; first build takes several minutes
    cargo run -p anonymum-nym -- --no-jitter   # skip the 30-300 s callback delay

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

With the confirmed handshake (2026-11-19, design review M3): every call now
waits for the callee's confirmation and retries by the rules in
`anonymum_crypto::wire`. Live run, offline 60 s: Alice confirmed in 5.8 s,
Carol's session confirmed after 71 s on the first attempt, Dave (no channel,
no confirmation) gave up after his single 30 s attempt; whole demo passed in
175 s. Loss cases (lost message 3, lost confirmation, late frames) are
covered by unit tests, not by live runs.

With contact identities and Noise IK (2026-11-20, spec v0.7 section 2a):
live run, offline 60 s. Alice called with a caller key Bob's invitation
named; Bob let her in and counted the invitation used only after her
confirmation (5.4 s). Carol's note (587 bytes) was opened with Bob's inbox
key alone; Bob called her callback key, her throwaway let in only his key
(70 s, first attempt), and Eve, calling the same route, got nothing. Dave,
with Bob's real card and route but no invitation, got nothing and gave up.
Whole demo passed in 191 s.

Dev chain rerun for the 587-byte note (2026-11-20): runtime rebuilt,
`smoke.mjs` passed every check, and `e2e.mjs` passed end to end. Carol's
real note went through the chain byte for byte, Bob opened it from chain
state with his inbox key alone, and his callback over Nym was confirmed on
the first attempt.

After the source review of cdad354 (2026-11-20): live demo with
`ANONYMUM_DROP_FIRST_ACK=1` passed in 288 s. Bob dropped his first
acknowledgement; Alice resent her confirmation after 60 s and Bob, still
reading, sent the cached acknowledgement again. Eve and Dave again got
nothing. On the dev chain (runtime `spec_version` 1), `smoke.mjs` passed
and `e2e.mjs` passed with Bob and Carol as two separate processes that
share only the chain and the mixnet; every transaction waited for
finality, and Bob's process got the callback key, route and request
reference only from the note it decrypted.

After the AI audit of 3f7092d (2026-11-20; runtime `spec_version` 2, v2
signed messages with the genesis hash): `smoke.mjs` and `e2e.mjs` passed
against the dev node, which verified the real v2 key binding and invite
proof; the live demo passed in 205 s.

With the deniable note (format v4, Noise X, 667 bytes; runtime
`spec_version` 4; 2026-11-20): `smoke.mjs` and `e2e.mjs` passed against the
dev node, Bob calling Carol's handshake key from the note he decrypted; the
live demo passed in 267 s, Eve and Dave again getting nothing.

With 24-hour requests and the sender's card checked at the request's
creation time read from chain state (runtime `spec_version` 5,
2026-11-20): `smoke.mjs` and `e2e.mjs` passed against the dev node.

With the hybrid post-quantum note (format v5, 1,787 bytes; cards 1,408
bytes with one ML-KEM-768 key; runtime `spec_version` 6; 2026-11-20):
`smoke.mjs` passed against the dev node with a 1,787-byte note, and
`e2e.mjs` passed: Carol sealed a v5 note to Bob's real card, Bob read it
back from chain state, opened it with his two inbox secrets, and called
Carol's handshake key over the live Nym mixnet. The live demo was not
rerun.

The signed card sequence number (2026-11-21) makes cards 1,416 bytes and
notes 1,795 bytes (runtime `spec_version` 7). The unit tests cover it;
on 2026-11-22, at `ddbbf73`, the release WebAssembly runtime ran on a local
dev node and `smoke.mjs` and `e2e.mjs` both passed. In `e2e.mjs` a real
1,795-byte note went through chain state unchanged, was opened, and the
callback completed over the live Nym mixnet. These runs are manual: CI does
not build the runtime or start a node. The standalone live demo was not
rerun.

**How long gateways hold messages:** Nym nodes delete stored messages for an
offline client after 24 hours by default (`stale_messages.max_age` in
`nym-node`'s gateway config; operators can change it). A request lives the
same 24 h (decision D2; 48 h before 2026-11-20), but an operator may hold
messages for less, so the accepting side must keep calling again until the
request would have expired. The demo resends every 150 s when calling a
throwaway client; a real client would retry on a slower schedule.

## Substrate pallet and local node (roadmap step 4)

`substrate/` is its own Cargo workspace (own `Cargo.lock`) so the Polkadot SDK
cannot disturb the pinned Nym crates.

    cd substrate
    cargo test -p pallet-anonymum                 # 64 tests, mock runtime
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
    cargo build -p anonymum-nym && node substrate/scripts/e2e.mjs   # needs internet (Nym)

`smoke.mjs` sends real signed transactions and checks balances and events
after each: a messaging key (and a forged one refused), an invite channel, a
stranger's paid request with its sealed note accepted, a declined request
with the 1% burn, a blocked address refused, a closed channel blocking the
other side, and total issuance falling by exactly the burns plus transaction
fees. All checks passed on 2026-11-18 (three runs on fresh chains, and
again after the audit fixes with real fees and deposits).

`e2e.mjs` joins the two halves with nothing simulated: two wallets from
`anonymum-crypto` whose Ed25519 keys are their chain accounts; Bob publishes
his real X25519 messaging key with its real binding; Carol creates a
persisted throwaway Nym client, reads Bob's key from chain state, seals a
real note to it and pays to reach him; Bob reads the note back from chain
state, opens it and accepts; then Bob calls Carol over the live Nym mixnet
at the address from the note and they swap long-lived addresses. Passed on
2026-11-18 (Carol's gateway held the call for the few seconds her throwaway
client was offline).

Differences from the in-process simulation:
- Escrow and storage deposits are balance holds; the reward pool is the
  pallet's account.
- Accounts must keep the existential deposit, so payments cannot empty them.
- A failed transaction changes no pallet state and takes no pallet fee, but
  the chain's own transaction fee is still charged, as on any Substrate
  chain. It scales with weight and size: measured on the dev node, about
  0.007 coin for a contact request and 0.003 coin for opening with an
  invite. Both rates are placeholders, and the weights behind them are not
  benchmarked yet.
- Invite proofs: the crates check with `ed25519-dalek`'s `verify_strict`,
  the pallet with the runtime's `ed25519_verify` host function, which here
  follows ZIP 215 (`ed25519-zebra`) and is more permissive: it would accept
  a trivial proof for a small-order key. The pallet therefore refuses weak
  invite keys at registration (`ed25519-dalek`'s `is_weak`), but the two
  proof checks still differ in other edge cases.
- Balances are `u128` everywhere: simulation, pallet mock and dev runtime
  (the runtime used `u64` until 2026-11-18).
- Expiry uses one queue per block; at most `MaxRequestsPerBlock` (256)
  requests can expire in one block, and a request that would overflow it
  fails without charge.
- Weights are placeholders, not benchmarks.
- The runtime exposes a stub Aura API (6 s slots, no authorities) only
  because omni-node's dev mode reads it. There is no Aura consensus.
- Client accounts are Ed25519 (decided 2026-11-18, audit F8): a wallet's
  `anonymum-crypto` address and its on-chain account are the same key, as
  `e2e.mjs` shows. The well-known dev accounts (`//Alice`, …) are still
  sr25519 and only fund wallets on the dev chain; the binding check accepts
  any Substrate signature type.

**DEV ONLY — must not leave the laptop:**
- Sudo, with the public `//Alice` dev key as the sudo key.
- The well-known dev accounts (`//Alice`, `//Bob`, …) endowed at genesis;
  their private keys are public knowledge.
- `TestDefaultConfig` settings for System, Balances, Sudo, Timestamp and
  TransactionPayment (existential deposit of 1 unit, test limits).
- The stub Aura API in the runtime (6 s slots, no authorities, no Aura).
- Manual seal (`--dev-block-time`), a single node, `--tmp` storage.
- Placeholder weights, fee rates, deposits and network fees.
- The RPC endpoint: `run-node.sh` keeps the default CORS policy, so web
  pages cannot reach the node; `--rpc-cors all` was removed. Add a specific
  `--rpc-cors <origin>` only when a browser UI needs it.
## Shielded money: specification and reference model

The next privacy stage (roadmap step 5) is specified in
`docs/shielded-spec-v0.md` (v0.5, the current source; the owner's
decisions O1–O8 are recorded there and in CLAUDE.md).
`docs/Shielded_Payments_Technical_Research_2026-11-19.md` is the background
research and `docs/Shielded_Payments_Protocol_v0.1.md` an alternative design
kept for reference.

`crates/shielded-model` is **a model of the rules for review, not a private
or secure implementation.** It has no zero-knowledge proofs, no circuits
and no note encryption, and its chain function sees every hidden value. It
lets a reviewer read the spec as code and shows, by test, which transactions
the rules accept and reject: every property in spec section 5 with
adversarial cases (wrong authority on each branch, double resolution,
altered refunds, redirected penalties, forged stranger receipts, dummy-slot
tricks, integer limits, deadlines, replay), a randomised test that checks
conservation after every transaction of long mixed histories, and the
section 5b acceptance test (a restored wallet recovers and spends exactly
99 of a 101 escrow after a garbage decline). Each rule was also disabled in
turn to confirm a test catches it.

    cargo test -p anonymum-shielded-model

Problems found in the spec while building it are listed in
`docs/shielded-spec-v0-issues.md`: v0.5 resolved I1–I12 except I8 (changing
the base fee while escrows are open), and raised two wording issues (I13,
I14). I8 is addressed in the model since 2026-11-21 (audit HIGH-03): an
escrow locks a fee ceiling, the unused part returns to the sender on every
outcome, and a fee above the reserve is paid with a top-up note. Not
reviewed.

## What is real and what is not

| Piece | Status |
|---|---|
| Fee and channel rules, blocks, invite-only | Built, tested |
| Reverse rendezvous for strangers | Sealed fixed-size notes built and tested; the full flow ran live, including once end to end through the dev chain (`e2e.mjs`). Retry rules live in `anonymum_crypto::wire`; the demo binary drives them |
| Invites | Real Ed25519 signatures, bound to opener, recipient and the chain's genesis hash (v2 messages; the messaging-key binding also names the account) |
| End-to-end encryption | Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s) between contact keys, never wallet keys. The answering side reads the caller's key inside message 1 and replies only to a caller it authorised (invitation, contact, expected callback); anyone else gets nothing. **Unreviewed prototype** (spec questions 11 and 12) |
| Per-message forward secrecy, self-healing after compromise | Double Ratchet (Signal specification; X25519, keyed BLAKE2s, ChaCha20-Poly1305) for every data frame, seeded from both sides' fresh seeds and the IK handshake hash. Tested for turn-arounds, reordering, replay, forward secrecy, post-compromise recovery and skip limits. Header not encrypted. **Unreviewed prototype** |
| Out-of-order delivery, replay protection | Built, tested (a mixnet reorders on purpose; the ratchet caches up to 1,024 skipped keys, at most 256 per step) |
| Mixnet transport | Nym SDK; replies go through single-use reply blocks, so the recipient never learns the caller's network location. Ran once live; no automated test |
| The chain itself | Rules run as a Substrate pallet on a local single-node dev chain (manual seal, 6 s blocks). No real network, consensus or validators yet |
| Shielded payments | Specified (`docs/shielded-spec-v0.md`, draft for review) and modelled in plain Rust (`crates/shielded-model`, rules only, not private). No circuit or pallet yet; the channel table is still public |
| Node staking and rewards | Pool accumulates; payout not started |
| Post-quantum key exchange in sessions | Not started |

## Design decisions taken

1. **Messages never go on-chain.** The chain holds money, channel state,
   blocks, messaging keys, and the sealed note of each pending contact
   request (readable only by its recipient).
2. **Invites are one-time key pairs, not secret codes.** The recipient registers
   the public half and hands out the private half. The opener signs
   "opener + recipient", so a copied transaction is useless to anyone else.
   Invites are stored per owner, so registering someone else's invite key
   first does not block them.
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
   **Storage is not free**: each invite, block entry and messaging key holds a
   refundable deposit (placeholder 0.01 coin), returned when the entry is
   used, revoked, lifted, cleared or replaced. Anyone may remove an expired
   invite; its deposit goes back to the owner.
6. **`max_price` on contact requests** protects the sender from a price change
   between signing and inclusion.
7. **Closing blocks.** If you close a channel, the other address cannot pay to
   reach you again. Only you can reopen: by `Unblock`, or by giving them an
   invite issued *after* the block (an older invite they kept does not work).
   The block is per address; a new wallet starts fresh and pays stranger costs.
8. **Direct blocking.** You can block any address, with or without a channel.
   Its paid requests then fail before any fee is charged, its pending request
   is refunded in full, your own pending request to it is cancelled (decline
   fee burned), and an open channel with it is closed. Any new channel
   between two addresses clears blocks both ways, since it only opens with
   both sides' consent.
9. **No mixnet address is ever published.** Each user has a contact identity
   separate from the wallet: a signing key, a handshake key, an inbox key
   and a post-quantum inbox key (ML-KEM-768), listed on a signed contact
   card (with network, price, validity and a signed sequence number; 1,416 bytes). A stranger's
   request carries a note sealed to both inbox keys (an ML-KEM-768
   ciphertext whose shared secret keys one Noise Xpsk0 message from the
   stranger's contact handshake key): the stranger's card (its
   post-quantum key as a hash), a throwaway route and an intro of at most
   280 bytes, padded so every note is 1,795 bytes. It opens with the inbox
   secrets alone (no sender hint) and is bound to the network, the
   request's admission commitment and its ML-KEM ciphertext. Sender
   authentication is classical (X25519) only. The recipient is
   convinced who sent it but cannot prove it to anyone else (deniable; no
   signature over the contact). On accept, the recipient calls the
   stranger's handshake key at the throwaway route; only its holder can
   answer, and the two swap real routes inside the session. Invited contacts call with a
   caller key the invitation names. Wallets can be invite-only; requests to
   them fail before any fee. (The transparent chain still records requests
   wallet to wallet, and still needs a wallet-bound key published.)
10. **Requests expire after 24 hours** (decision D2, matching how long Nym
    gateways hold messages; 48 hours before 2026-11-20), defined as a
    duration and converted to blocks from the block time (6 s blocks:
    14,400). Invites keep their own expiry, set by their owner.

## Open questions for you

- **Fee levels**: current numbers (0.01 / 0.5 / default price 1.0 / decline
  fee 1% / storage deposits 0.01) are placeholders. They should come out of
  a spam-cost simulation.
- **Intro message cap**: 280 bytes is proposed. Right size?

## Known gaps that matter for the security claim

- The channel table is public: the chain shows that A and B are connected.
  This contradicts the mixnet's purpose until shielded payments exist. The
  same goes for contact requests (Y requested X) and blocks (who blocked whom).
- Contact notes and the first handshake message (including a stranger's
  callback) get forward secrecy only from key rotation: the handshake and
  inbox keys rotate together in weekly epochs, and an old epoch's keys are
  dropped 26 hours after it ends, but only when the client rotates and
  purges: nothing does so automatically yet, and nothing sends the new card
  to contacts. Until then, whoever takes a device can read notes and first
  messages sent to the epochs it still holds. Unreviewed.
- Noise IK's first message can be replayed. A replay cannot use an
  invitation twice or reopen a blocked contact (tested), but a still-
  authorised caller's recorded first message gets a reply: an availability
  signal (spec question 11). If an answerer's handshake key leaks, recorded
  first messages to that key's epochs reveal the callers' keys.
- Received X25519 keys are checked for small order (cards, invitations,
  notes, callers), but the ephemeral keys inside `snow`'s handshakes are
  not: its public API offers no hook. Open for the cryptographer.
- Whether a caller can tell an authorised refusal from an unauthorised one
  by timing has not been measured.
- Grant state (invitations used, contacts, blocks, callbacks) can be saved
  as an encrypted snapshot and must be written before each reply that
  follows a change (one device only; the demo does not persist it). There
  is no multi-device guarantee.
- Per-message forward secrecy and post-compromise security rest on an
  unreviewed Double Ratchet prototype. Its header (ratchet key and
  counters) is authenticated but not encrypted.
- Contact key rollover is forward-only by a signed card sequence number,
  so an emergency rotation inside one weekly epoch reaches contacts at
  once. Restoring an identity from an older backup reissues numbers
  contacts refuse until rotations pass them. Unreviewed.
- Reading an IK first message costs the answerer two key agreements before
  it can refuse. Answered handshakes are capped, but strangers' calls need a
  proper cost.
- A flood of dropped messages still costs the recipient bandwidth. Nym's paid
  bandwidth credentials are the network-level answer and need integrating.

## Roadmap

1. **Done** — rules as a state machine with tests.
2. **Done** — real invites, identities, end-to-end sessions.
3. **Done** — Nym transport demo, run live over the mixnet.
   **Done** — closing blocks, direct blocking, reverse rendezvous for
   strangers, invite-only wallets, request expiry (24 h since 2026-11-20).
4. **Done** — `chain.rs` ported to a Substrate pallet; local dev chain runs it
   with real transactions. Not done: benchmarked weights, a real network
   with consensus, our own node binary.
5. Shielded channel opening, so the chain no longer reveals the contact graph.
6. Double ratchet (prototyped 2026-11-21, unreviewed) and post-quantum key
   exchange.
7. Node staking, reward payout, fee simulation, external audit.
