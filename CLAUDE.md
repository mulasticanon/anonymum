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
| `crates/core` (`anonymum-core`) | Chain rules as a deterministic state machine: invites, paid contact requests with sealed notes, escrow, channels, blocks, invite-only, messaging keys, fee split, 24 h request expiry, client-side inbox admission, token-bucket rate limit, storage deposits. Zero dependencies. | 63 tests, run by CI on Linux and Windows |
| `crates/crypto` (`anonymum-crypto`) | `Identity` (wallet: Ed25519 address + X25519 key bound to it, for the transparent chain only), `InviteSecret` / `Ed25519Invites` (chain invites); spec v0.7 section 2a prototype: `contact` (`ContactIdentity` with signing, handshake and inbox keys; `ContactCard`; `Invitation` to a holder key; `StaticKey` caller keys), `gate` (`Gate`: authorise before replying, commit on confirmation; changed only through the responder), crate-private Noise IK handshake types, `note` (stranger's note opened with the inbox key alone, bound to network and admission commitment), `wire` (HELLO / WELCOME / CONFIRM / ACK; unauthorised callers get nothing; call id and attempt in the IK prologue; inner record types; atomic revocation; deadlines with an injected `Now`). Received X25519 keys checked with `was_contributory`; block and remove cancel the key's unused invitation and callback grant too; sessions keyed by caller key with caps (`Limits`, one candidate handle per caller); send counter cannot wrap; `snapshot` (encrypted, versioned gate snapshots with `StorageKey`, persist-before-reply; deadlines and revocations in Unix seconds, pruned at expiry + `CLOCK_SKEW_SECS`; a persisted clock floor `last_seen` stops a clock set back from reviving them); key rotation (`KeyEpoch`: handshake + inbox + ML-KEM seed in a two-slot ring of active + draining on a weekly grid, `rotate_epoch`, `purge_expired`, `DRAIN_GRACE` 26 h; `open_note` takes the opener's clock; identity storage v2, still reads v1); `dummy_note` (a real v5 note between throwaway identities, for unused stranger slots). Unreviewed. | 190 tests, run by CI on Linux and Windows |
| `substrate/pallets/anonymum` (`pallet-anonymum`) | FRAME port of `chain.rs` (Polkadot SDK `polkadot-stable2609-2`, umbrella crate `=2609.3.0`). Own workspace and `Cargo.lock` in `substrate/`. | 64 tests (rule tests matching the core crate's + FRAME checks); CI workflow `substrate.yml` |
| `substrate/runtime` (`anonymum-runtime`) | Minimal template runtime + the pallet; compiled to WebAssembly. | Ran on a local `polkadot-omni-node` dev chain in WSL2; `substrate/scripts/smoke.mjs` passed (manual) |
| `crates/shielded-model` (`anonymum-shielded-model`) | Reference model of `docs/shielded-spec-v0.md`: notes with blinding, admission records, grid-stamped leaves, position-bound and dummy nullifiers, every section 4 branch (v0.5: one sender refund at any time; refunds derived from seed and escrow position), `Chain::submit`, a recovering wallet (recovery copy carries its nonce and the key paths of the refund and cancel keys; refunds found via the consuming transaction). Unused payload slots get random bytes, or a caller-supplied dummy stranger note (`dummy_stranger_note`; production passes `anonymum_crypto::dummy_note`). HIGH-03 (2026-11-21): escrows lock `fee_reserve >= F` (default `2 F`), the surplus returns to `refund_to` in a derived note on every outcome (a claim's own surplus note), a fee above the reserve is paid by a top-up note (`TxBuilder::resolution`, `Chain::set_base_fee`); the wallet gives each escrow a one-time refund key (`next_escrow_keys`, `prepare_escrow`). Rules only: no proofs, not private. Deps: `blake2`, `chacha20poly1305`, `rand_core` (pinned, already in the lockfile). | 83 tests (section 5 properties, randomised conservation, 5b acceptance, slots and pruning, fee changes); every rule mutation-checked |
| `crates/crypto` ratchet (2026-11-21) | `ratchet` (`Ratchet`, `RatchetKey`): Double Ratchet after the Signal spec for every DATA frame. `KDF_RK`/`KDF_CK` keyed BLAKE2s (`anonymum/dr-rk/v1`, `anonymum/dr-ck/v1`), ChaCha20-Poly1305 with the one-time key and zero nonce, AAD `anonymum/dr-msg/v1 \|\| network \|\| header`; 40-byte header not encrypted; received ratchet keys checked with `is_contributory_key`; failures change nothing (staged state); `MAX_SKIP_PER_STEP` 256, `MAX_TOTAL_SKIPPED` 1,024 (oldest evicted). Bootstrap in `wire`: CONFIRM carries seed_i + an ephemeral ratchet key `dh_i0`, ACK seed_r + the answerer's first ratchet key (both checked); root = keyed BLAKE2s (`anonymum/dr-root/v1`) of seed_i, seed_r and the IK handshake hash; the answerer starts against `dh_i0` so it may send first (the static IK key is not in the ratchet); data before the ACK is held (`MAX_EARLY_DATA` 16, `Initiator::take_early`, `InitiatorEvent::Held`). Markers v5. Unreviewed. | 22 tests in `tests/ratchet.rs` + 5 unit tests (counted in the crypto total); every new rule mutation-checked |
| `crates/crypto` handshake rotation (2026-11-21) | The handshake key lives in each `KeyEpoch`, so it rotates with the inbox keys. `Responder` holds active + draining handshake keys (`for_identity`, `for_callback_identity`, `restore_*`, `refresh_keys`): a HELLO is read with the active key, and with the draining key only on a Noise decryption failure and only before `not_after + DRAIN_GRACE` (gate clock floor; dropped then). Gate contacts carry an optional signing key and retire time (`bind_contact_card`, `roll_contact_key`: a fresh card from the same signing key moves the grant to the new key; the old key stays admitted 26 h, then pruned with its sessions; block/remove follow both keys; forward-only: the new card's signed `seq` must exceed the bound card's, else `StaleCard`). Gate snapshot v4, still reads v1 to v3. Unreviewed. | 21 tests in `tests/handshake_rotation.rs` + unit tests (counted in the crypto total); every new rule mutation-checked |
| `crates/shielded-circuit` (`anonymum-shielded-circuit`, 2026-11-22) | **Unreviewed prototype, not audited, not for real value.** Groth16 / BLS12-381 circuit (arkworks 0.4, the line already in the lockfile) for all six branches: domain-separated Poseidon (width 5, 8 full + 60 partial rounds, for the cryptographer to confirm), `TREE_DEPTH` 20, 11 public inputs, `sighash` (BLAKE2s reduced into `Fr`, recomputed by `verify_transaction`), strict proof decoding. Keys come from `insecure_dev_setup` (one process holds the toxic waste). `S` is a circuit constant. Slots are fixed as in the model's builder. `substrate/` uses it only as a test dependency. `fixtures::dev_keys` derives keys from a **public seed**. 20,700 constraints, 192-byte proof, 1.95 s setup, 1.88 s proving, 5.89 ms verifying (release, 8 threads). | 115 tests (29 Groth16, 86 rules); 76 of 80 mutations caught, the other 4 are constraints other rules imply |
| `substrate/pallets/anonymum-shielded` (`pallet-anonymum-shielded`, Milestone 4B, 2026-11-22) | **Unreviewed prototype, dev key only, not for real value.** `submit_shielded` is a general transaction (format 5, no signer) using `#[pallet::authorize]`, run in the pool and again at inclusion, cheapest first: note length, clock grid and time, accepted root, nullifiers, strict 192-byte proof decoding, sighash, a BLAKE2s proof of work (`PowDifficulty`, 20 bits in the runtime, calibrated 2026-11-25 to about 3.5x the WASM authorization cost, 0 disables; client helper `anonymum_shielded_circuit::pow::solve_pow`), then Groth16 verification in the runtime (arkworks 0.4, `no_std`). Pool tags are the nullifiers. Dispatch needs the authorized origin and repeats the cheap checks, no second pairing; then nullifiers, Poseidon frontier (depth 20), 24 h note buffer keyed `(window_start, sighash)`, burn/reward counters. Real balances (spec 12, 2026-11-25): pool account `anm/shld` backs every note one to one (genesis mints `initial_supply` = 1,013,001 dev units plus ED); each transaction burns the burn share from it (total issuance falls) and moves the reward share to `anm/rewd`, and is refused (`PoolUnderfunded`, code 14) if the pool cannot pay without its ED; signed `shield(authority, amount, blinding)` moves balance in and inserts an ordinary note whose commitment the chain computes (circuit unchanged; deposit fully public). No unshielding; retired value stays in the pool account and in issuance; the existing `Shielded` event of a transaction is now `Transacted`, and `Shielded` is the deposit. Proof bytes are never a key. Poseidon constants are precomputed (`dev_tool poseidon`) and tested against the circuit. Weights from FRAME benchmarks in the release WASM runtime (2026-11-25, `weights.rs`, one laptop): authorize median 67.0 / p95 87.4 / max 142.7 ms, weight 175 ms; dispatch median 54.6 / p95 78.8 / max 95.0 ms, weight 115 ms; pruning bound 2.86 ms; `shield` weight 160 ms from a second run on a loaded machine (a VirtualBox VM used half the CPU; the other weights keep the clean run's times, counts updated; rerun needed). `frame-benchmarking` =50.0.0 (already locked) behind the `runtime-benchmarks` feature; the fixture is one real Transfer (`dev_tool bench-fixture`). Runtime `spec_version` 12. Polkadot.js cannot build the general transaction; `shielded-smoke.mjs` encodes it. | 97 tests with real proofs (101 with `--features runtime-benchmarks`); 50 of 50 mutations caught before the proof of work, 20 of 20 proof-of-work mutations caught, 28 of 28 balance and shield mutations caught; CI builds the release WASM runtime (job `wasm-runtime`); `shielded-smoke.mjs`, `smoke.mjs`, `e2e.mjs` passed on the dev node (manual) |
| `crates/nym` (`anonymum-nym`) | Binary: Alice (invite), Carol (stranger, reverse rendezvous with a persisted throwaway client and retrying caller), Dave (dropped); the callback after a stranger's note waits a random 30-300 s (`jitter.rs`; `--no-jitter` / `--jitter MIN-MAX`, 5 unit tests run with `cargo test -p anonymum-nym`); subcommands `wallet`/`throwaway`/`seal`/`open`/`talk` for `substrate/scripts/e2e.mjs`. | Manual live runs on Windows, see README |

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
- Never resolve the lockfile with `--offline`: on 2026-11-22 that moved
  unrelated pins. A normal resolve only added the new packages.
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
   `"anonymum/invite/v2" || genesis || opener || recipient` (v2 since
   2026-11-20), so a proof copied from a pending transaction, or made for
   another chain, is useless to anyone else. The messaging-key binding is
   `"anonymum/msgkey-binding/v2" || genesis || account || key`; core's
   `Params::genesis` stands in for the genesis hash in the simulation.
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
  length (`SEALED_NOTE_LEN` = 1,795 since 2026-11-21; 1,787, 667, 587 and 427
  before; core and pallet). Format v5 (`anonymum-crypto::note`, hybrid
  post-quantum, deniable, I27/I29): admission commitment (32) ||
  ML-KEM-768 ciphertext to the recipient card's `pq_inbox_key` (1,088) ||
  one Noise Xpsk0 message (667) from the sender's contact handshake key to
  the recipient's inbox key, psk0 = the ML-KEM shared secret, prologue
  `"anonymum/contact-note/v5" || network || admission || ciphertext`;
  payload = version 5, the sender's card fields with the post-quantum key
  as its 32-byte hash, 96-byte route, u16 intro length, intro padded to
  280; no signature over the contact. Opens with the two inbox secrets
  alone; `ContactNote::card` is a `CardSummary`. The callback goes to the
  sender's handshake key (no separate callback key). Cards (v4 with a signed `seq`, 1,416
  bytes) carry one ML-KEM-768 key and sign its BLAKE2s hash; contact
  identities have four secrets (the fourth is a 64-byte ML-KEM seed; the
  demo's wallet file line was `contact_pq`; since 2026-11-21 the whole
  contact identity is one `contact=` line in the crate's own encoding). `ml-kem` is pinned `=0.3.3`
  (0.3.4 would move `ctutils` and `module-lattice` in the lockfile).
- `Tx::SetAcceptStrangers { accept }`: invite-only wallets refuse requests
  with `StrangersNotAccepted` before any fee. My choice, easy to change:
  switching to invite-only leaves already-pending requests answerable.
- Requests to a wallet with no published key fail with `NoMessagingKey`.
- On accept the recipient calls the requester's throwaway address. The demo
  persists the throwaway client with `StoragePaths::new_from_dir` and
  deletes it afterwards.

**C. Request expiry, 24 hours since 2026-11-20 (D2; 48 hours before).**
`Params::request_ttl_secs` (86,400) and `block_time_ms` (6,000);
`request_ttl_blocks()` rounds up (14,400). The runtime's `RequestTtlMillis`
matches (spec_version 5 then; 7 since the 1,795-byte note).

**Gateway retention, checked:** `nym-node` deletes stored messages after
`stale_messages.max_age`, default 24 h (operator-configurable). So the
accepting side must retry until the request's 24 h would be up. A first live
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

AI audit of 3f7092d (`docs/ai-audit-3f7092d-2026-11-20.md`): expiry slots
freed on early answers, v2 signed messages with genesis hash (and account),
checked pallet arithmetic, sessions per caller key with caps, send counter
limit; done 2026-11-20 (table A1-A7 in the issues file). The host function
`sp_io::crypto::ed25519_verify` follows ZIP 215 here and accepts small-order
invite keys that `verify_strict` refuses, so `register_invite` now refuses
weak keys (`ed25519-dalek`'s `is_weak`, built into the wasm runtime).
spec_version is now 4 (2: v1 proofs and bindings no longer verify; 3: weak
invite keys refused; 4: 667-byte deniable notes, I27 prototyped, unreviewed).
Cost recorded for the cryptographer: whoever holds an inbox secret can forge
notes to it; the callback, answered by the sender's handshake key, stops
such a forger completing contact. Note forward secrecy: inbox key
rotation (weekly epochs, 26 h drain) since 2026-11-21, unreviewed; the
handshake key rotates with the epoch since 2026-11-21 too (callbacks and
IK message 1 forward-secret after the purge), unreviewed.
`open_note` checks the sender's card against the request's creation time
from chain state (not the opener's clock); callers pass it (the demo from
creation height x block time, e2e from the creation block's timestamp).

## Decided 2026-11-18 (late), not yet implemented

**D1. A block created by closing a channel takes no deposit.** Today
`close_channel` fails if the closer cannot pay the block deposit, so someone
with an empty wallet cannot leave a channel. Change: the automatic block on
close is deposit-free and `close_channel` never fails for lack of funds.
This does not reopen free storage: each such block needs a channel that was
already paid for. A block made directly with `Block` keeps its deposit.
Record which kind a block is, so `Unblock` and a reopening channel return a
deposit only where one was taken. Core and pallet, with tests.

**D2. Contact requests expire after 24 hours, not 48. Done 2026-11-20**
(core, pallet mock, runtime, tests, docs; spec_version 5). The client-side
half (keep an old messaging key for 24 hours after replacing it) no longer
applies as written: notes are now sealed to the contact card's inbox key,
so the same rule would apply to an inbox key that is rotated.

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
- the stranger's note (427 bytes then) did not fit a post-quantum key exchange (it is 1,795 bytes with ML-KEM-768 and the card `seq`);
- invites checked inside a proof probably need a circuit-friendly
  signature; Ed25519, used today, is costly inside a circuit.

## Shielded design: current source and owner decisions (2026-11-19)

The current source for the shielded design is
**`docs/shielded-spec-v0.md` (version 0.7)**. Where
`docs/Shielded_Payments_Protocol_v0.1.md` (the alternative protocol, kept
for reference) differs from it, the spec wins. The research report gives
background; section 15.1 gate 1 is what the spec's decisions answer.
`crates/shielded-model` is a plain-Rust reference model of the spec's rules
(no proofs, not private or secure; 83 tests). Since 2026-11-20 it has
two 200-byte coin-note slots plus one 1,795-byte stranger-note slot per
transaction, prunes stranger notes 24 h after their window starts
(`Chain::prune_stranger_notes`; the proof binds to a permanent `stranger_note_hash`, I28), enforces the empty
admission record's zero fields (W3, `Reject::NonEmptyAdmission`), and its
recovery copy (versioned, `RECOVERY_VERSION` = 1, 11 bytes spare) re-derives
the refund and cancel authorities from the key paths to fit 200 bytes. Spec problems found while
building it are in `docs/shielded-spec-v0-issues.md`: I1-I12 from v0.4,
all resolved in v0.5 except I8 (addressed in the model on 2026-11-21 by a
fee ceiling with private surplus and top-up, O9, unreviewed); I13-I14 new in v0.5, for the
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
| O9 | Amends O7: escrows lock a fee ceiling (default 2 F); the unused part returns privately to the sender on every outcome; a fee above the reserve is paid by the resolver's top-up note (P4; I8/H1, audit HIGH-03). | 2026-11-21 |

The owner asked for an isolated prototype circuit on 2026-11-22
(`crates/shielded-circuit`), ahead of the cryptographer's review, and a
pallet that verifies it (Milestone 4B, `substrate/pallets/anonymum-shielded`).
Still: no ceremony, no public network and no real value until the
cryptographer has reviewed the spec, the circuit and the pallet.

## Open questions for the owner

- Fee levels are placeholders (0.01 / 0.5 / default price 1.0 coin / 1%
  decline fee); they
  should come from a spam-cost simulation.
- Is 280 bytes the right cap for the intro message? (Implemented as 280.)

## Known gaps that undercut the security claim

- The channel table is public: the chain shows who opened a channel with
  whom. Needs shielded payments (Zcash-style proofs or stealth addresses).
- Per-message forward secrecy and post-compromise security come from an
  unreviewed Double Ratchet prototype (2026-11-21). Its header is not
  encrypted.
- Stranger notes, IK message 1 and callbacks are forward-secret only
  through epoch rotation (handshake and inbox keys together, weekly epochs,
  an old epoch dropped 26 h after it ends; 2026-11-21). Nothing rotates
  automatically yet, nothing sends a rotated card to contacts, and
  invitation holder keys do not rotate. Rollover is forward-only by a
  signed card `seq` (2026-11-21), so an emergency rotation reaches contacts
  at once; restoring an identity from an older backup reissues numbers
  contacts refuse until rotations pass them.
- Gate state is durable on one device only (encrypted snapshot,
  persist-before-reply; 2026-11-21). One device per contact identity; the
  demo does not persist its gate.
- Noise IK's first message is replayable: a still-authorised caller's
  recorded first message gets a reply (availability signal, question 11).
- No post-quantum key exchange in sessions or callbacks. Stranger notes
  are hybrid (ML-KEM-768 + X25519) since 2026-11-20, unreviewed; their
  sender authentication is classical.
- The shielded pallet charges no fee for a bad proof (a call with no signer
  pays nothing). Each attempt now needs a configurable proof of work before
  the pairing, which prices spam without stopping it: 20 bits cost a CPU
  thread about 3.5x the node's authorization, and GPUs are far faster. Peer
  rate limiting remains a node/P2P concern and is not built. Shielded value
  is backed by `pallet-balances` (2026-11-25) but cannot be unshielded, the
  reward account pays nothing out, and its weights (175 ms authorize + 115 ms dispatch) were benchmarked on
  one laptop, not reference hardware. Its verifying key is from a public seed.
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
6. Double ratchet (prototyped 2026-11-21, unreviewed) and post-quantum key
   exchange.
7. Node staking, reward payout, fee simulation, external audit.
