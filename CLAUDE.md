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
| `crates/core` (`anonymum-core`) | Chain rules as a deterministic state machine: invites, paid contact requests with sealed notes, escrow, channels, blocks, invite-only, messaging keys, fee split, 48 h expiry, client-side inbox admission, token-bucket rate limit, storage deposits. Zero dependencies. | 61 tests, run by CI on Linux and Windows |
| `crates/crypto` (`anonymum-crypto`) | `Identity` (wallet: Ed25519 address + X25519 key bound to it, for the transparent chain only), `InviteSecret` / `Ed25519Invites` (chain invites); spec v0.7 section 2a prototype: `contact` (`ContactIdentity` with signing, handshake and inbox keys; `ContactCard`; `Invitation` to a holder key; `StaticKey` caller keys), `gate` (`Gate`: authorise before replying, commit on confirmation; changed only through the responder), crate-private Noise IK handshake types, `note` (stranger's note opened with the inbox key alone, bound to network and admission commitment), `wire` (HELLO / WELCOME / CONFIRM / ACK; unauthorised callers get nothing; call id and attempt in the IK prologue; inner record types; atomic revocation; deadlines with an injected `Now`). Received X25519 keys checked with `was_contributory`; block and remove cancel the key's unused invitation and callback grant too. Unreviewed. | 84 tests, run by CI on Linux and Windows |
| `substrate/pallets/anonymum` (`pallet-anonymum`) | FRAME port of `chain.rs` (Polkadot SDK `polkadot-stable2609-2`, umbrella crate `=2609.3.0`). Own workspace and `Cargo.lock` in `substrate/`. | 57 tests (rule tests matching the core crate's + FRAME checks); CI workflow `substrate.yml` |
| `substrate/runtime` (`anonymum-runtime`) | Minimal template runtime + the pallet; compiled to WebAssembly. | Ran on a local `polkadot-omni-node` dev chain in WSL2; `substrate/scripts/smoke.mjs` passed (manual) |
| `crates/shielded-model` (`anonymum-shielded-model`) | Reference model of `docs/shielded-spec-v0.md`: notes with blinding, admission records, grid-stamped leaves, position-bound and dummy nullifiers, every section 4 branch (v0.5: one sender refund at any time; refunds derived from seed and escrow position), `Chain::submit`, a recovering wallet (recovery copy carries its nonce and the key paths of the refund and cancel keys; refunds found via the consuming transaction). Rules only: no proofs, not private. Deps: `blake2`, `chacha20poly1305` (pinned, already in the lockfile). | 51 tests (section 5 properties, randomised conservation, 5b acceptance); every rule mutation-checked |
| `crates/nym` (`anonymum-nym`) | Binary: Alice (invite), Carol (stranger, reverse rendezvous with a persisted throwaway client and retrying caller), Dave (dropped); subcommands `wallet`/`throwaway`/`seal`/`open`/`talk` for `substrate/scripts/e2e.mjs`. | Manual live runs on Windows, see README |

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
6. Sessions use Noise IK between contact keys (since 2026-11-20, spec v0.7
   section 2a; was Noise XX with wallet addresses). The answering side reads
   the caller's key and reference from message 1 and replies only if its
   gate authorises them. No wallet key in a card, handshake or note.
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
  The blocker's own pending request to the target was left alone; audit
  F4 changed this (it is now cancelled, decline fee burned).
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
  length (`SEALED_NOTE_LEN` = 587 since 2026-11-20, was 427; core and pallet).
  Format v2 (`anonymum-crypto::note`): admission commitment (32) || Noise N
  to the recipient's contact inbox key, prologue
  `"anonymum/contact-note/v2" || admission`; plaintext = version, sender
  contact key, callback handshake key, 96-byte route, u16 intro length,
  intro padded to 280, Ed25519 signature by the sender's contact key. Opens
  with the inbox key alone.
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
`crates/crypto/tests/wire.rs`). Since 2026-11-19 the retry rules live in
`anonymum_crypto::wire` (`Initiator::on_timeout` / `wait`, `RetryPolicy`); the demo's `call` /
`serve` helpers drive them over the mixnet.

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

## Audit fixes F1-F8 (2026-11-18 audit, done 2026-11-18)

An independent read of the repository (before the history rewrite) found
eight items. All are fixed in `crates/core` and `substrate/pallets/anonymum`
(unless noted), each with tests including the failure path.

- **F1** Overflow in the simulation's `request_contact`: `fee + price` is now
  checked (`InsufficientFunds`); heights saturate; the ledger splits fees
  without multiplying the whole amount and uses bounded adds for totals.
  The regression test fails on the old code (verified).
- **F2** Invite keys could be squatted: invites are stored under
  `(owner, key)`; opening looks up `(recipient, key)`, revoking
  `(sender, key)`. `NotInviteOwner` is gone (a non-owner gets
  `UnknownInvite`).
- **F3** Storage was free: refundable deposits (placeholder 0.01 coin, config
  constants) for each invite, block entry and messaging key, returned when
  used / revoked / lifted / cleared / replaced. `close_channel`'s block takes
  the closer's deposit; a closer who cannot pay cannot close (my reading of
  "like any other block"). Anyone may remove an expired invite
  (`RemoveExpiredInvite` / `remove_expired_invite`); the deposit goes to the
  owner. Replacing a messaging key carries one deposit over. Dev runtime fees
  now scale with weight (ref-time / 100,000) and size (10 units/byte):
  measured 6,921 units for a contact request. Weights are not benchmarked.
- **F4** (decision changed) `Block` also cancels the blocker's own pending
  request to the target as `CancelledBy(blocker)`, decline fee burned.
- **F5** The pallet no longer discards refund/release errors: it carries on,
  logs, and emits `HoldNotReleased`.
- **F6** Documented in the pallet docs and README: invite proofs use
  `verify_strict` in the crates but the more permissive `ed25519_verify`
  host function in the pallet (not exploitable today). Fixed: the dev
  runtime's balances are now `u128` like the simulation and mock.
- **F7** `--rpc-cors all` removed from `run-node.sh` (a foreign origin now
  gets no allow-origin header); README has a "DEV ONLY" list.
- **F8** `substrate/scripts/e2e.mjs` + `anonymum-nym` subcommands (`wallet`,
  `throwaway`, `seal`, `open`, `talk`): real key and binding, a real
  `seal_note` output through the dev node, read back from chain state and
  opened, then a real Nym conversation. Passed live. Clients standardise on
  Ed25519 account keys (wallet address = chain AccountId).

Tests after the fixes: core 61, crypto 25, pallet 57.

## Section 2a prototype (spec v0.7, done 2026-11-20)

`crates/crypto` and the Nym demo implement section 2a with standard Noise
patterns through `snow`'s public API. Unreviewed (spec questions 11, 12);
the README says so. Choices made where the spec was silent are I15-I27 in
`docs/shielded-spec-v0-issues.md` (four-frame confirm, callback with the
card's handshake key, admission commitment carried in the note field on the
transparent chain, invitee-generated holder keys, ...). `substrate/scripts/
e2e.mjs` and the demo's subcommands were moved to contact identities; after
rebuilding the runtime, `smoke.mjs` and `e2e.mjs` both passed (2026-11-20).
The contact card signs its network id (I20 fixed); I27 asks the
cryptographer whether the note's signature should become deniable.

The source review of cdad354 (`docs/source-review-cdad354-2026-11-20.md`)
found R1-R12; fixed or recorded on 2026-11-20 (status table in the issues
file). e2e now runs Bob and Carol as separate processes and waits for
finality. The dev runtime's `spec_version` is 1: **contact notes stored
before the 587-byte format (427-byte notes) cannot be opened by the new
format, by design**; the dev chain starts from a fresh genesis, so nothing
needs migrating. A persistent chain would need an explicit upgrade policy.

## Decided 2026-11-18 (late), not yet implemented

**D1. A block created by closing a channel takes no deposit.** Today
`close_channel` fails if the closer cannot pay the block deposit, so someone
with an empty wallet cannot leave a channel. Change: the automatic block on
close is deposit-free and `close_channel` never fails for lack of funds.
This does not reopen free storage: each such block needs a channel that was
already paid for. A block made directly with `Block` keeps its deposit.
Record which kind a block is, so `Unblock` and a reopening channel return a
deposit only where one was taken. Core and pallet, with tests.

**D2. Contact requests expire after 24 hours, not 48.** This matches how
long Nym gateways hold messages for an offline client. Change
`request_ttl_secs` / `RequestTtlMillis` and every test and document that
says 48 h (24 h at 6 s blocks = 14,400 blocks). Client side: after
replacing a messaging key, keep the old private key for 24 hours, because a
pending request's note was sealed to it.

## Roadmap step 5: read `docs/step-5-anonymity.md` first

That file compares the ways to stop the chain publishing who talks to whom
and recommends two stages (5a: move channels, invites and blocks off the
chain with committed fee tickets, no new cryptography; 5b: shielded money).
**Do not implement any of it yet.** The owner has five decisions to make,
listed at the end of that file. D1 and D2 above can be done now; note that
stage 5a would later remove the block and invite tables they touch.

## Stage 5b research received 2026-11-19 (no implementation yet)

`docs/Shielded_Payments_Technical_Research_2026-11-19.md` is a 25,000-word
study commissioned by the owner from another research tool. Two of its
load-bearing claims were checked against primary sources and hold: the
2026 Orchard soundness flaw (ZIP 257) and the Polkadot SDK elliptic-curve
host functions (RFC-0163: BLS12-381, Bandersnatch, Pallas/Vesta; no
subgroup checks on decode; arkworks unaudited). The rest is unchecked.

Its recommendation: one shielded note pool, Sapling-lineage Groth16 on
BLS12-381, a new conditional-spend (escrow) circuit, verification through
the SDK host functions, no account-signed payment transactions, contacts
and channels entirely client-side. It sets seven feasibility gates
(section 15.1) and says plainly that this is new, security-critical
protocol work needing a specialist and audits.

**Nothing from it is to be built yet.** Gate 1 is a set of product
decisions for the owner, because several existing rules conflict with
hiding amounts and activity:
- a per-refund public 1% burn reveals the escrowed amount to within 100
  units;
- publicly different fees for invited and stranger contacts reveal which
  kind each transaction is;
- a public node reward pool balance reveals variable contributions;
- "refund after 24 hours" cannot be automatic: a wallet or a delegate must
  submit it;
- either side cancelling at any time becomes "first finalised wins";
- blocking cannot be enforced by the chain once contact state is private;
- the stranger's note (427 bytes then, 587 now) does not fit a post-quantum key exchange;
- invites checked inside a proof probably need a circuit-friendly
  signature; Ed25519, used today, is costly inside a circuit.

## Shielded design: current source and owner decisions (2026-11-19)

The current source for the shielded design is
**`docs/shielded-spec-v0.md` (version 0.7)**. Where
`docs/Shielded_Payments_Protocol_v0.1.md` (the alternative protocol, kept
for reference) differs from it, the spec wins. The research report gives
background; section 15.1 gate 1 is what the spec's decisions answer.
`crates/shielded-model` is a plain-Rust reference model of the spec's rules
(no proofs, not private or secure; 51 tests). Spec problems found while
building it are in `docs/shielded-spec-v0-issues.md`: I1-I12 from v0.4,
all resolved in v0.5 except I8 (open); I13-I14 new in v0.5, for the
owner and the cryptographer.

Owner decisions recorded in the spec (section 1):

| # | Decision | Date |
|---|---|---|
| O1 | Go for shielded money (stage 5b), with contact state moved off-chain. | 2026-11-19 |
| O2 | A cryptographer and external audits will be funded before any real value is at stake. | 2026-11-19 |
| O3 | One identical public base fee on every transaction, visibly credited (burn share and node-pool share). Everything tied to a user's price is confidential: the price, the invited/stranger difference, and the decline penalty. Period totals may be published later, once volume is high enough. | 2026-11-19 |
| O4 | Contact requests expire after 24 hours. | 2026-11-18 |
| O5 | The stranger surcharge is burned, not paid to node operators (P1). | 2026-11-19 |
| O6 | Blocked or ignored strangers get no answer and are refunded after 24 hours minus the penalty (P3). | 2026-11-19 |
| O7 | Opening a request locks the price plus one base fee, so settlement is prepaid (P4). | 2026-11-19 |
| O8 | Claims stop at 24 hours; after that only a refund is possible (P5). | 2026-11-19 |

Still: no circuits, ceremony or pallet changes for the shielded design
until the cryptographer has reviewed the spec.

## Open questions for the owner

- Fee levels are placeholders (0.01 / 0.5 / default price 1.0 coin / 1%
  decline fee); they
  should come from a spam-cost simulation.
- Is 280 bytes the right cap for the intro message? (Implemented as 280.)

## Known gaps that undercut the security claim

- The channel table is public: the chain shows who opened a channel with
  whom. Needs shielded payments (Zcash-style proofs or stealth addresses).
- Forward secrecy is per session, not per message. No double ratchet yet.
- Noise IK's first message is replayable: a still-authorised caller's
  recorded first message gets a reply (availability signal, question 11).
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
