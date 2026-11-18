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

## Repository identity (done 2026-11-18)

The project is pseudonymous. Every commit is by `mulasticanon
<maximilianmula@tutamail.com>` with dates in `+0000`; the history was
rewritten once (git filter-repo) to make it so, and the remote is the
private repository `https://github.com/mulasticanon/anonymum`.

- Commit only with the repo-local identity (`git config --local user.*`).
  This machine's **global** git identity and the logged-in GitHub CLI are a
  different, personal account: never use them here, and never write the
  owner's real name, email or account into files or commit messages.
- Pushes authenticate through Git Credential Manager, pinned to the
  `mulasticanon` account by the remote URL and
  `credential.https://github.com.username` (device-code sign-in). Use the
  GitHub API with that credential, not `gh`, for this repository.
- Git stamps new commits with the local timezone by default. Keep the
  history in `+0000` by committing like this (Git Bash):
  `d="$(date -u +%s) +0000"; GIT_AUTHOR_DATE="$d" GIT_COMMITTER_DATE="$d" git commit ...`

## State as of 2026-11-18

Written in a cloud workspace (Linux, Rust 1.97), now developed on the owner's
Windows machine (see the update below).

| Crate | Contents | Verified |
|---|---|---|
| `crates/core` (`anonymum-core`) | Chain rules as a deterministic state machine: invites, paid contact requests with sealed notes, escrow, channels, blocks, invite-only, messaging keys, fee split, 48 h expiry, client-side inbox admission, token-bucket rate limit. Zero dependencies. | 45 tests, run by CI on Linux and Windows |
| `crates/crypto` (`anonymum-crypto`) | `Identity` (Ed25519 address + X25519 messaging key, bound by signature), `InviteSecret` / `Ed25519Invites`, Noise XX `Handshake` / `Session`, `note` (`seal_note` / `open_note`, Noise N), `wire` framing (`Initiator`, `Responder<T>`; a repeated first frame gets the same reply). | 25 tests, run by CI on Linux and Windows |
| `substrate/pallets/anonymum` (`pallet-anonymum`) | FRAME port of `chain.rs` (Polkadot SDK `polkadot-stable2609-2`, umbrella crate `=2609.3.0`). Own workspace and `Cargo.lock` in `substrate/`. | 45 tests (43 ported rule tests + 2 FRAME checks); CI workflow `substrate.yml` |
| `substrate/runtime` (`anonymum-runtime`) | Minimal template runtime + the pallet; compiled to WebAssembly. | Ran on a local `polkadot-omni-node` dev chain in WSL2; `substrate/scripts/smoke.mjs` passed (manual) |
| `crates/nym` (`anonymum-nym`) | Binary: Alice (invite), Carol (stranger, reverse rendezvous with a persisted throwaway client and retrying caller), Dave (dropped). | Manual live runs on Windows, see README |

**Update 2026-11-18, local Windows session:** Rust 1.100 (MSVC) installed;
VS Build Tools 2026 provide the C++ toolchain. `cargo test` passed 35/35 at the time (38 since the decline-fee tests).
The first `anonymum-nym` build took ~23 min. The first run hit
`STATUS_STACK_OVERFLOW` while connecting (Windows main-thread stack is
1 MiB), so `main` now runs the tokio runtime on 16 MiB stacks. After that the
whole scenario completed over the live mixnet. Nym's
`get_or_create_sender_tag(&recipient)` gives one stable tag per
sender/recipient pair, so keying Bob's sessions by tag is fine. The first
tasks below are done; they are kept for history. Roadmap step 4 is done
too (see "Substrate port" below). Next up: roadmap step 5.

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

## Decisions A-C (decided and implemented 2026-11-18)

Built in `anonymum-core` / `anonymum-crypto` before the Substrate port, with
tests for every rule and failure path (failed transactions change nothing;
`fails_charging_nothing` in `crates/core/tests/protocol.rs` checks it).

**A. Closing blocks; Block / Unblock.**
- `CloseChannel` closes and blocks the other side (`Event::Blocked`).
- `Tx::Block { target }`: target's paid requests fail with `Error::Blocked`
  before any fee; target's pending request is refunded in full
  (`RefundReason::Blocked`, no decline fee); an open channel is closed.
  The blocker's own pending request to the target is left alone.
- `Tx::Unblock { target }`: only the blocker can send it (`NotBlocked`
  otherwise). Errors: `SelfContact`, `AlreadyBlocked`.
- The owner's answers (2026-11-18): only an invite registered *after* the
  block lifts it; an older unused invite fails for the blocked address
  (ordered by a sequence counter, `Invite::seq`). Any channel opening clears
  blocks in both directions (`UnblockReason::ChannelOpened`), since a
  channel needs both sides' consent.
- The blocker may still pay to request the blocked address.

**B. Reverse rendezvous.**
- `Tx::PublishMessagingKey { key, binding }`: the chain checks the binding
  signature (`InviteScheme::verify_key_binding`; Ed25519 in production,
  `mock_binding` in core tests). A key may be replaced; notes sealed to the
  old key can no longer be opened.
- `Tx::RequestContact` carries `note: SealedNote`. The chain checks only its
  length (`SEALED_NOTE_LEN` = 427). Noise N (`snow`), prologue
  `"anonymum/contact-note/v1" || from || to`, plaintext = version, 96-byte
  reply address (a Nym `Recipient`), u16 intro length, intro padded to 280.
  The intro cap is enforced by the fixed layout plus the client on seal and
  open; the chain cannot see it.
- `Tx::SetAcceptStrangers { accept }`: invite-only wallets refuse requests
  with `StrangersNotAccepted` before any fee. My choice, easy to change:
  switching to invite-only leaves already-pending requests answerable.
- Requests to a wallet with no published key fail with `NoMessagingKey`.
- On accept the recipient calls the requester's throwaway address. The demo
  persists the throwaway client with `StoragePaths::new_from_dir` and
  deletes it afterwards.

**C. 48-hour expiry.** `Params::request_ttl_secs` (172,800) and
`block_time_ms` (6,000); `request_ttl_blocks()` rounds up (28,800).

**Gateway retention, checked:** `nym-node` deletes stored messages after
`stale_messages.max_age`, default 24 h (operator-configurable). So the
accepting side must retry until the request's 48 h would be up. A first live
retry with a fresh handshake per attempt failed: both stored copies arrived
and the replies crossed. Fix: retries resend the *same* first frame, and
`Responder` answers an identical repeat with the cached reply (tests in
`crates/crypto/tests/wire.rs`). The retry loop lives in the demo
(`call_with_retry`), not yet in a reusable client.

Still visible on-chain until roadmap step 5: that wallet Y requested wallet
X, the sealed note, messaging keys, and who blocked whom. Keep the pallet
storage for these thin; step 5 replaces it.

## Substrate port (roadmap step 4, done 2026-11-18)

- Layout: `substrate/` workspace with `pallets/anonymum` (lib, `mock.rs`,
  `tests.rs`), `runtime/` (from the SDK minimal template), `scripts/`
  (`get-omni-node.sh`, `run-node.sh` for WSL; `smoke.mjs` for Windows).
- Mapping: escrow = `fungible::MutateHold` with `HoldReason::ContactEscrow`;
  network fee = `burn_from` + transfer to the pallet account (PalletId
  `anonymum`, must be endowed at genesis); decline fee = `burn_held`;
  expiry = `ExpiryQueue` per block, processed in `on_initialize`;
  pending-request lookup = `RequestByPair` (no scans). Invite proofs:
  `sp_io::crypto::ed25519_verify`. Key binding: `T::Signature: Verify`
  (`MultiSignature` in the runtime).
- Choices to revisit: `MaxRequestsPerBlock` caps expiries per block (256 in
  the runtime; overflow fails with `ExpiryQueueFull`, no charge); payments
  keep the existential deposit; weights are placeholders; the chain's own
  transaction fee is charged even on failed calls.

Things that bit, so they do not bite again:
- Build: cargo is not on the tool PATH (prefix `%USERPROFILE%\.cargo\bin`);
  use `-j 4` (7.7 GB RAM). Needs `rustup target add wasm32v1-none` and
  `rustup component add rust-src` for the runtime.
- FRAME in this release: the supertrait must be written
  `polkadot_sdk::frame_system::Config<RuntimeEvent: From<Event<Self>>>`
  (full path; a separate `type RuntimeEvent` is deprecated), and
  `RuntimeDebug` is not exported here (use `Debug`).
- `assert_noop!` compares the whole storage root, so do any setup (e.g.
  registering an invite) before it, not inside it.
- omni-node 1.25.2 only drives Aura runtimes: the runtime has a stub
  `AuraApi` (6 s, no authorities) for dev mode, and the chain spec needs
  placeholder `-c dev -p 1000` (relay chain / para id) or it refuses to load.
  No relay chain is contacted.
- With manual seal, transactions go Ready -> Finalized with no InBlock
  status; Polkadot.js reads a raw `Uint8Array` for `Bytes` as already
  length-prefixed (pass hex). Both are handled in `smoke.mjs`.
- WSL2 has 3.8 GB RAM: fine to run the node, not to compile one.
- The omni-node checksum is checked, its GPG signature is not.

## Audit fixes (2026-11-18 audit, decided, not yet implemented)

An independent read of the repository made before the history rewrite (the commit now `36c0df0`) (all 70 crate tests and
45 pallet tests passed on a separate Linux machine) found the items below.
Fix them in both `crates/core` and `substrate/pallets/anonymum` unless a
line says otherwise, each with tests including the failure path.

**F1. Overflow in the simulation's `request_contact` (bug).**
`crates/core/src/chain.rs`: `self.ledger.can_pay(&from, fee + price)` adds
two `u128`s unchecked. With the recipient's price near `u128::MAX` and
`max_price: u128::MAX`, a debug build panics and a release build wraps,
passes the check, charges the network fee, then fails at `lock`: a failed
transaction that charged 0.5 coin. Use checked or saturating addition and
return `InsufficientFunds`. Add a test with `SetContactPrice { price:
u128::MAX - fee + 1 }`. Review every other `+`, `-`, `*` on amounts and
heights in `chain.rs` and `ledger.rs` the same way. The pallet already uses
`saturating_add` here and passed this probe.

**F2. Invite keys can be squatted.**
Invites are stored by invite key alone, so anyone who sees a pending
`RegisterInvite` can register the same key first; the owner's registration
then fails with `InviteAlreadyRegistered` and the invite they handed out is
dead. Fix: store invites under `(owner, key)`. `OpenWithInvite` already
names the recipient, so it looks up `(recipient, key)`; `RevokeInvite`
looks up `(sender, key)`. Two different owners may then register the same
key without affecting each other. Test: a third party registering the same
key first does not stop the owner registering or the invitee opening.

**F3. On-chain storage is free.**
500 invites cost no pallet fee; blocks, prices, invite-only flags and
messaging keys are also stored for nothing, and expired invites are never
removed. Pallet:
- Take a refundable deposit (a hold, new `HoldReason`s) for each stored
  invite, block entry and messaging key; return it when the entry is used,
  revoked, lifted, replaced or expires. Deposit sizes are config constants;
  start with a placeholder of 0.01 coin per entry and say so in README.
- A block created automatically by `close_channel` takes the deposit from
  the closer like any other block.
- Let anyone remove an invite that is past `expires_at` (the deposit goes
  back to the owner, not the caller).
- Give the simulation the same deposits so the two stay rule for rule.
Dev runtime: replace `WeightToFee = NoFee` and `LengthToFee = FixedFee<1>`
with real fee settings, so a transaction's cost scales with its size and
weight. Benchmarked weights are still a later task; say so.

**F4. Blocking cancels the blocker's own pending request (decision
changed).** Today `Block` leaves the blocker's own request to the target
alive, and if the target accepts it the block is cleared. The owner wants
the opposite: `Block` also cancels the blocker's pending request to the
target. Treat it as a sender cancel (`CancelledBy(blocker)`, decline fee
burned). Replace the tests `blocking_leaves_the_blockers_own_request_alone`
and any that rely on it; `an_accepted_request_from_the_blocker_clears_
blocks_both_ways` still applies to a request made *after* the block.

**F5. Refund errors are swallowed in the pallet.** `refund` discards the
results of `burn_held` and `release` with `let _ =`. Keep going (it runs in
`on_initialize`, which cannot fail) but report: use `defensive!` or log an
error and emit an event, so a stuck hold is visible.

**F6. Simulation and pallet differ in two quiet ways.** Document both in
the pallet's module docs and README; fix where cheap.
- Invite proofs: the crates use `ed25519-dalek` `verify_strict`; the pallet
  uses `sp_io::crypto::ed25519_verify`, which is more permissive. Only the
  invite's owner chooses the key, so this is not exploitable today.
- Balances: `u128` in the simulation and the pallet's mock, `u64` in the
  dev runtime.

**F7. Dev-only settings that must not leave the laptop.** Sudo with the
public `//Alice` key, `TestDefaultConfig` pallet settings, the stub Aura
API, and `--rpc-cors all` in `run-node.sh` (any web page open in a browser
can reach the local node while it runs). Drop `--rpc-cors all` unless a
browser UI is in use, and add a "DEV ONLY" list to README.

**F8. Join the halves (was already the suggested next step).** The smoke
test sends placeholder bytes as the sealed note and a hash as the messaging
key; the Nym demo still uses the in-process `Chain`. Make one run where a
wallet publishes a real X25519 key with a real binding, a real
`seal_note` output goes through the dev node, the recipient reads it back
from chain state, opens it, and the two then talk over Nym. This also
forces the sr25519 / Ed25519 question: standardise clients on Ed25519
account keys.

## Open questions for the owner

- Fee levels are placeholders (0.01 / 0.5 / default price 1.0 coin / 1%
  decline fee); they
  should come from a spam-cost simulation.
- Is 280 bytes the right cap for the intro message? (Implemented as 280.)

## Known gaps that undercut the security claim

- The channel table is public: the chain shows who opened a channel with
  whom. Needs shielded payments (Zcash-style proofs or stealth addresses).
- Forward secrecy is per session, not per message. No double ratchet yet.
- No post-quantum key exchange.
- The chain runs only as a single-node dev chain (manual seal). No real
  network, consensus, validators or benchmarked weights yet.
- No node staking or reward payout.
- A privacy coin faces EU exchange restrictions from July 2027 (AMLR).
  The owner should take legal advice before any public sale.

## Roadmap

1. Done: rules as a state machine.
2. Done: real invites, identities, sessions, framing.
3. Done: live Nym run (2026-11-18, Windows).
   Done: decisions A-C in the existing crates, demo run live (2026-11-18).
4. Done: `chain.rs` ported to `pallet-anonymum`; local dev chain with real
   transactions (2026-11-18).
5. Shielded channel opening.
6. Double ratchet and post-quantum key exchange.
7. Node staking, reward payout, fee simulation, external audit.
