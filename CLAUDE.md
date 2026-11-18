# Handoff notes for Claude (local session)

This file is the context for continuing the project from a local session.
`README.md` is the project's own documentation; keep its status tables honest
as things change.

## What this project is

The owner's idea: a new cryptocurrency with its own chain (not a token on an
existing chain) whose purpose is extremely secure, anonymous messaging.

- You reach someone cheaply if they gave you a one-time invite.
- A stranger pays a larger network fee plus a price the recipient sets.
- After a channel is open, messages are free but rate limited.
- Messages never go on-chain. They travel over the Nym mixnet, end-to-end
  encrypted, so no node and no developer can read them.

The currency and project are called Anonymum, and the crates are named
`anonymum-*`. They were called `murmur-*` (a placeholder) until 2026-11-18;
the protocol domain labels changed with them (e.g. `"anonymum/invite/v1"`).

## State as of 2026-11-18

Written in a cloud workspace (Linux, Rust 1.97). Not yet built or run on
this Windows machine.

| Crate | Contents | Verified |
|---|---|---|
| `crates/core` (`anonymum-core`) | Chain rules as a deterministic state machine: invites, paid contact requests, escrow, channels, fee split, client-side inbox admission, token-bucket rate limit. Zero dependencies. | 23 tests, run by CI on Linux and Windows |
| `crates/crypto` (`anonymum-crypto`) | `Identity` (Ed25519 address + X25519 messaging key, bound by signature), `InviteSecret` / `Ed25519Invites`, Noise XX `Handshake` / `Session`, `wire` framing (`Initiator`, `Responder<T>`). | 15 tests, run by CI on Linux and Windows |
| `crates/nym` (`anonymum-nym`) | Binary: three wallets, three Nym clients, full scenario over the live mixnet. | Ran end to end on Windows, 17 s (one manual run) |

**Update 2026-11-18, local Windows session:** Rust 1.100 (MSVC) installed;
VS Build Tools 2026 provide the C++ toolchain. `cargo test` passes 35/35.
The first `anonymum-nym` build took ~23 min. The first run hit
`STATUS_STACK_OVERFLOW` while connecting (Windows main-thread stack is
1 MiB), so `main` now runs the tokio runtime on 16 MiB stacks. After that the
whole scenario completed over the live mixnet. Nym's
`get_or_create_sender_tag(&recipient)` gives one stable tag per
sender/recipient pair, so keying Bob's sessions by tag is fine. The first
tasks below are done; they are kept for history. Next up: roadmap step 4.

## First tasks (done 2026-11-18)

1. Run `cargo test` and confirm 35 tests pass on Windows.
2. Run `cargo run -p anonymum-nym` and get the live demo to complete. Expect
   to debug this. Likely trouble spots:
   - Windows build of the Nym dependency tree (needs MSVC C++ build tools;
     some crates compile C code).
   - Gateway selection: the demo uses `.force_tls(true)`; setting the
     environment variable `ANONYMUM_PLAIN_WS=1` allows any gateway.
   - Whether replies via `send_reply` carry a `sender_tag` back, and whether
     the tag is stable across a caller's messages. The demo keys Bob's
     sessions by the tag from the first handshake frame and falls back to it
     with `tag.unwrap_or(alice_tag)`. If tags change per message, sessions
     need a different key (e.g. a session id inside the frame).
   - The 120 s receive timeout may be too short on a slow first connection.
3. Update the status table in `README.md` with what actually happened.

The `.bat` helper scripts that once did steps 1 and 2 were deleted on
2026-11-18 with the owner's agreement. Run cargo directly. CI
(`.github/workflows/ci.yml`) runs the tests on Linux and Windows.

## Things that will bite you

- **Keep `Cargo.lock`.** It was seeded from the lockfile shipped inside the
  `nym-sdk` 1.21.6 crate. A fresh resolve pulls `nym-client-core` 1.22.x
  against 1.21.x siblings and fails to compile. If you bump `nym-sdk`, take
  the lockfile from the new crate version the same way.
- Nym's docs describe `nym-sdk` 2.0.1; crates.io had 1.21.6 as the newest at
  the time. Check before assuming the docs match.
- `default-members` in the workspace `Cargo.toml` excludes `crates/nym`, so
  plain `cargo test` / `cargo build` stay fast. Use `-p anonymum-nym`.
- `anonymum_core::crypto::mock` is an insecure stand-in used only by the core
  crate's own tests and example. Never use it outside tests.

## Rules for this codebase

- No hand-written cryptographic primitives. Compose vetted crates only
  (`ed25519-dalek`, `x25519-dalek`, `snow`). Say so plainly wherever
  something is a stand-in.
- Every rule change in `chain.rs` gets a test, including the failure path
  and a check that a failed transaction charges nothing
  (`ledger().is_balanced()`).
- `chain.rs` is meant to port one-to-one into a Substrate pallet: keep it
  deterministic, no I/O, no clocks, no randomness.
- Money is integer smallest-units (`Amount = u128`). No floats.
- Do not claim security properties that have not been tested. Nothing here
  is audited.

## Design decisions already made

1. Messages are off-chain; the chain holds money and channel state only.
2. Invites are one-time key pairs. The opener signs
   `"anonymum/invite/v1" || opener || recipient`, so a proof copied from a
   pending transaction is useless to anyone else.
3. Relay nodes cannot enforce the fee model (a mixnet hides who talks to
   whom). The recipient's client checks the chain and drops non-contacts.
4. A stranger's payment sits in escrow: accept pays the recipient. Decline,
   sender cancel or expiry refunds it minus `decline_fee_bps` (default 1%,
   rounded up), which is burned, never paid to anyone (decided 2026-11-18:
   paying it to the recipient or the node pool would reward declining).
   Superseded by an invite: full refund. The network fee is never refunded.
5. Network fees split between burn and a node reward pool.
6. Sessions use Noise XX. Each side sends address + binding signature inside
   the encrypted handshake payload; observers learn neither address.
7. Transport messages carry an explicit counter so they survive mixnet
   reordering; a sliding window rejects replays.
8. The responder replies through Nym reply blocks (SURBs) and never learns
   the caller's mixnet address.
9. Transport: Nym mixnet (chosen over onion routing for resistance to
   traffic correlation). An optional faster onion mode for calls and large
   files was discussed but is not planned yet.

## Open questions for the owner

- Fee levels are placeholders (0.01 / 0.5 / default price 1.0 coin / 1%
  decline fee); they
  should come from a spam-cost simulation.
- After a channel is closed, does the other party need a new invite, or may
  they pay the stranger price?
- How does a stranger learn a recipient's mixnet address without the chain
  linking wallet to gateway?

## Known gaps that undercut the security claim

- The channel table is public: the chain shows who opened a channel with
  whom. Needs shielded payments (Zcash-style proofs or stealth addresses).
- Forward secrecy is per session, not per message. No double ratchet yet.
- No post-quantum key exchange.
- The chain is simulated in-process; there is no real blockchain.
- No node staking or reward payout.
- A privacy coin faces EU exchange restrictions from July 2027 (AMLR).
  The owner should take legal advice before any public sale.

## Roadmap

1. Done: rules as a state machine.
2. Done: real invites, identities, sessions, framing.
3. Done: live Nym run (2026-11-18, Windows).
4. Port `chain.rs` to a Substrate pallet (Polkadot SDK); local test chain.
5. Shielded channel opening.
6. Double ratchet and post-quantum key exchange.
7. Node staking, reward payout, fee simulation, external audit.
