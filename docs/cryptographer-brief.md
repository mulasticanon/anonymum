# Brief for an external cryptographer

Anonymum project, 2026-11-19, updated 2026-11-20 for spec v0.7. This is the starting point for a specialist
engaged to review the design before any real value is at stake.

## 1. What you should know first

- **Nothing here has been reviewed by a human cryptographer.** All code and
  all design documents were written by AI assistants under the owner's
  direction, and cross-checked by a second AI system. Those two reviews
  share sources and assumptions and are not independent of each other.
  Treat every claim as unverified.
- **No real value exists.** There is no public network, no coin sale and no
  users. The chain runs only as a local development node.
- **The owner works under a pseudonym** and intends the repository to stay
  free of personal identifiers.
- **The owner has committed to fund specialist review and external audits**
  before any release with real value.

## 2. The system in one page

A messaging network with its own coin.

- Messages are end-to-end encrypted and travel over the Nym mixnet. They
  never touch the chain.
- The chain is a standalone Substrate chain (Polkadot SDK, stable2609
  line), in Rust. It handles money only.
- Reaching someone costs money unless they invited you:
  - **Invited contact**: pays the base fee.
  - **Stranger**: pays the base fee, a fixed surcharge that is burned, and
    locks the recipient's price in escrow. The recipient may claim it
    within 24 hours. Otherwise, or if the recipient declines, or if the
    sender withdraws, the sender gets it back minus 1%, which is burned.
- Invitations, block lists, channels and prices are held and enforced by
  the users' own apps, not by the chain.

## 3. The claim the owner wants to be able to make

> Someone who records the whole chain, watches the network, and runs some
> of the nodes cannot tell which two parties are in contact, nor the
> sender, recipient or amount of any payment.

The owner understands this must be stated with a bounded adversary and
explicit assumptions, and that a small user population limits it. Helping
to write that bounded statement is part of the request.

## 4. What exists

| Item | Where | Status |
|---|---|---|
| Shielded design specification, v0.7 | `docs/shielded-spec-v0.md` | **The main thing to review.** Rules only; no cryptographic suite chosen |
| Issues found while modelling it | `docs/shielded-spec-v0-issues.md` | I1-I14 from modelling (open: I8 fee changes, I13 the derived refund, question 8); review findings H1-H7, M1-M4; I15-I27, questions raised while prototyping section 2a; R1-R12, the source review of cdad354 and their status |
| Reference model of the rules | `crates/shielded-model` (about 1,100 lines plus tests) | Plain Rust, no proofs, no privacy. 61 tests including adversarial cases and a randomised conservation test. Entry point: `chain::Chain::submit` |
| Research report | `docs/Shielded_Payments_Technical_Research_2026-11-19.md` | 25,000 words, AI-written. Two claims spot-checked against primary sources (ZIP 257; Polkadot RFC-0163). The rest unchecked |
| Alternative, heavier protocol | `docs/Shielded_Payments_Protocol_v0.1.md` | AI-written. Kept for comparison; section 8 of the spec lists the differences |
| Messaging cryptography | `crates/crypto` (about 1,700 lines) | Working code, tested. Section 2a prototype: contact identities, cards and invitations; Noise IK with the authorisation check before any reply; the stranger's note opened with the inbox key alone. **Unreviewed (questions 11 and 12)** |
| Mixnet demo | `crates/nym` | Ran end to end on the live Nym mixnet, including with the section 2a handshake |
| Transparent prototype chain | `crates/core`, `substrate/` | Working. **Publishes the whole contact graph.** To be replaced by the shielded design; not a review priority |

To run the tests: `cargo test` at the repository root (core, crypto and the
shielded model), and `cargo test -p pallet-anonymum` inside `substrate/`.

## 5. What we are asking you to review, in priority order

### A. The shielded design (highest priority)

Read `docs/shielded-spec-v0.md` and tell us whether the construction is
sound, and where it is not. The spec ends with twelve questions. The ones the
design most depends on:

1. **One nullifier across all escrow outcomes.** An escrow note has two
   authorities (recipient, sender) and must be spendable exactly once
   through claim, decline or sender refund. The spec derives its nullifier
   from a seed shared by both parties, the commitment and the tree
   position. Is that sound, and how should both parties obtain the seed?
2. **Refunds derived, not delivered.** When the recipient declines, the
   refund note is fully determined: owner, amount, and a blinding derived
   from the seed and the escrow's position. The aim is that an offline
   sender can find and spend it even if the recipient sends garbage. The
   recipient can therefore recompute the refund commitment. Can they learn
   anything more, such as when it is spent? (Spec question 8; issue I13.)
3. **No encryption proven inside the proof.** The spec argues a sender who
   sends unreadable data harms only themselves, and that the one
   cross-party case is covered by item 2. Is any case missed?
4. **Binding a fee tier to a request.** A hidden admission record ties the
   burned surcharge to one request, one recipient and one escrow, so the
   recipient's app can verify a stranger paid for this request. Invitations
   are checked by the recipient's app, never in the proof. Is the binding
   sufficient, and does anything about it leak the tier?
5. **Confidential burning.** The surcharge and the 1% penalty are retired
   as unspendable hidden notes; no public counter moves. Is a retired note
   type the right mechanism, compared with a committed supply accumulator?
6. **Time.** Every leaf is stamped with the start of its validity window;
   deadlines fall on window boundaries; claims are valid up to the
   deadline. Do the public windows leak which escrow a claim belongs to?
7. **One transaction shape.** Every action uses the same public layout and
   one circuit, so the worst-case branch sets the cost of all. Is the
   layout achievable, and what does it cost?
8. **Sender self-recovery.** Each opening carries a copy of the escrow
   data encrypted to a key derived from the sender's backed-up keys. How
   should that key and the seed be derived? (Spec question 9.)
9. **Changing the base fee.** Escrows used to hold a reserve equal to the
   fee of their day, so a fee change stranded or marked them (issue I8;
   spec question 10). Since 2026-11-21 the reserve is a ceiling: the
   surplus returns privately in a derived note, a shortfall is topped up
   by the resolver. Modelled, not reviewed.

### B. Choices we need you to make or approve

The spec deliberately leaves the cryptographic suite open.

- Proof system. The research report recommends Groth16 over BLS12-381 in
  the Sapling lineage, with Zcash's Halo 2 as the setup-free alternative.
  Note the Orchard circuit soundness flaw of May 2026 (ZIP 257).
- Hash and commitment scheme suitable for the proof system.
- Key and signature scheme for the note authorities, verifiable in-circuit.
- Note encryption: must not let a public contact key be used to recognise
  ciphertexts addressed to it. Whether post-quantum confidentiality is
  achievable at launch, given that ciphertexts sit on a public chain.
- Tree depth, nullifier derivations, public-input layout.
- Whether proofs can be verified in this chain's runtime through the
  Polkadot SDK curve host functions (RFC-0163). Those functions do not
  check subgroup membership on decode, and the RFC notes the underlying
  arkworks libraries are unaudited.

### C. The messaging cryptography (section 2a prototype; questions 11 and 12)

`crates/crypto`, about 1,700 lines. It prototypes spec section 2a with
standard Noise patterns through `snow`'s public API. Please check both the
composition and whether it answers questions 11 and 12:

- `contact.rs`: a contact identity separate from the wallet (Ed25519
  signing key, X25519 handshake key, X25519 inbox key); a signed contact
  card (network, keys, price, validity); invitations signed by the contact key, to
  one holder key, naming network, purpose and expiry. No wallet key appears
  in a card, a handshake or a note.
- `session.rs`: Noise IK (X25519, ChaCha20-Poly1305, BLAKE2s). Message 1
  carries the caller's static key and a 32-byte reference (invitation id,
  relationship or accepted request) inside the encrypted payload; the
  answerer reads both before writing anything.
- `gate.rs` and `wire.rs`: the answerer replies only to an authorised key
  (an unused invitation it issued, an existing contact, or the expected
  callback), never blocked; anyone else gets no frame at all. Grants are
  committed only when the caller sends a confirmation sealed in the fresh
  session, so a replayed message 1 cannot use an invitation twice or
  reopen a blocked contact. Retries, call ids and exact frame lengths
  around that.
- `note.rs` (format v4, 667 bytes; deniable, prototyped 2026-11-20 on
  the owner's decision): the stranger's note as one Noise X message from
  the sender's contact handshake key to the recipient's inbox key, prologue
  bound to network and admission commitment; inside, the sender's card
  fields, the throwaway route and the intro. Noise X authenticates the
  sender by Diffie-Hellman, so the recipient is convinced but could have
  made the same note. **For you (issue I27):** (1) anyone holding the
  recipient's inbox secret can forge notes to it from any sender whose card
  they have; the callback, answered by the sender's handshake key itself,
  stops such a forger from completing contact. Is that enough? (2) There
  is no per-request callback key any more, so a later compromise of the
  sender's handshake key reveals the recipient's card key and the request
  reference from a recorded callback message. (3) Forward secrecy for notes
  now comes from rotating the inbox keys (below).
- `invite.rs`: the transparent chain's one-time invites (Ed25519), kept.
- Since the source review of cdad354 (`docs/source-review-cdad354-2026-11-20.md`,
  AI-written): revocation is atomic, received X25519 keys are checked for
  small order with `x25519-dalek`'s `was_contributory` (ephemeral keys
  inside `snow` are not; see the issues file), the call id and attempt are
  in the IK prologue, every sealed record carries its type, and pending
  handshakes, idle sessions and callback grants expire by deadline.
- **Also for you** (issues file, "AI-written audit of 3f7092d"): no
  forward secrecy for notes sealed to a long-lived inbox key (inbox key
  rotation, now prototyped as weekly epochs, above); no delay between claim finality and
  the callback (now a uniform 30-300 s in the demo, below); dummy payload
  slots that must be indistinguishable from real ones (slot sizes now
  proposed: two 200-byte coin slots and one 1,787-byte stranger slot, I24;
  dummies now prototyped, below);
  post-quantum key exchange and ratcheting as long-term questions; and
  the host Ed25519 check (ZIP 215 via `ed25519-zebra`) accepting small-order
  invite keys that `verify_strict` refuses.
- **Wallet and network behaviour rules W1-W6** (spec section 2b, issues
  file; proposed, unreviewed): no targeted chain queries; random delays
  before callbacks, refunds and spending an Open's change (the
  distributions are for you); every transaction carries an admission
  commitment, the empty one freshly blinded (the model derives that
  blinding from a test salt today); dummy note slots as real Noise X notes
  between fresh random keys; one pool and one fee structure. Open: hybrid
  post-quantum key exchange for handshakes (for notes it is now
  prototyped, see below) before the note format is frozen; key
  rotation and contact recognition; persistent wallet versus throwaway
  listener; cover traffic (on by default in `nym-sdk` 1.21.6, by reading
  the code); message retrieval at scale.
- **Payload slots, pruning and the hybrid note** (issues file I28, I29;
  2026-11-20, unreviewed): every transaction has two 200-byte coin slots
  and one 1,787-byte stranger slot; the stranger slot is pruned 24 hours
  after its window starts. Each transaction keeps a permanent 32-byte hash
  of its stranger slot, which the proof binds to instead of the bytes, so
  proofs stay checkable after pruning (I28, resolved in the model; which
  hash the circuit uses is yours). The recovery copy now carries a
  version byte for its layout and key derivation. The note is
  now hybrid: ML-KEM-768 ciphertext in the Noise prologue and its shared
  secret as the psk of `Noise_Xpsk0` (`ml-kem` 0.3.3); one ML-KEM key per
  card, signed through its BLAKE2s hash (card 1,408 bytes). Sender
  authentication stays classical. Is this the right hybrid?
- **Durable grant state** (issues file, R8 and MED-04; 2026-11-21,
  unreviewed): a responder's gate can be saved as a ChaCha20-Poly1305
  snapshot (associated data `"anonymum/gate-snapshot/v1" || network`,
  fresh nonce, versioned, every failure explicit), with a
  persist-before-reply rule: the snapshot is written durably before the
  ACK that follows a committed grant. This is crash safety for **one
  device**. Several devices must not share one gate: each device gets its
  own contact identity (own keys and invitations). Revoked and consumed
  invitation ids are pruned at expiry plus 300 s of clock skew, and the
  gate keeps a persisted clock floor so a clock set back cannot revive
  them (a clock that once ran ahead keeps the gate in that future).
- **Inbox key rotation** (issues file, "Inbox key rotation"; 2026-11-21,
  unreviewed): the forward-secrecy half of CRIT-02. The signing and
  handshake keys stay long-lived; the X25519 inbox key and the ML-KEM-768
  seed belong to an epoch on a shared weekly grid (`EPOCH_LEN`, epochs start
  at multiples of 7 days in Unix seconds). A contact identity keeps two
  slots: the active epoch (on the card, valid from one day before the
  epoch starts, `CLOCK_GRID_BACKDATE`, until it ends) and one draining
  epoch. `rotate_inbox` moves active to draining and drops any older
  draining epoch at once; `purge_expired_inbox` drops the draining epoch at
  its end plus 26 hours (`DRAIN_GRACE`: the 24-hour request lifetime plus
  2 hours of delivery and clock grace); `open_note` tries the active keys,
  then the draining keys while that grace lasts. Secrets sit in zeroizing
  buffers (the `ml-kem` decapsulation key is built per use with its
  `zeroize` feature); copies inside `snow`'s handshake state during an
  open are outside our control. **For you:** is a week the right epoch, is
  wiping on drop enough on the devices we target (swap, backups, the
  operating system's own copies), and should the handshake key rotate too
  (it is long-lived, so the callback still has no forward secrecy)?
- **Dummy payloads and callback timing** (issues file, "Dummy payloads
  and callback timing", audit MED-03; 2026-11-21, unreviewed): an unused
  stranger slot holds `dummy_note()`, a real v5 note between two throwaway
  identities whose secrets are dropped, because random bytes fail the
  X25519 ephemeral key's top-bit and on-curve tests. Unused 200-byte coin
  slots hold fresh random bytes, taken to match a ChaCha20-Poly1305
  ciphertext. The recipient's callback waits a uniform 30-300 s. **For
  you:** is the whole dummy note (ML-KEM ciphertext and Noise ciphertexts
  too) indistinguishable from a real one, are random bytes right for coin
  slots once their real format is fixed, and what delay distribution
  (and for refunds and change) would you want?
- **Fee changes and one-time refund keys** (issues file, "Fee changes
  and one-time refund keys", audit HIGH-03, I8/H1, I13/H5; 2026-11-21,
  modelled, unreviewed): an escrow now locks a fee *ceiling*
  (`fee_reserve >= F`, wallet default `2 F`). At resolution the surplus
  `fee_reserve - F` returns to `refund_to` in a note with the derived
  refund blinding: folded into the refund on a decline or sender refund,
  a separate note on a claim. If `F` has risen above the reserve, the
  resolver spends one ordinary top-up note and takes the change. Each
  escrow's `refund_to` is a one-time key; the model's wallet refuses reuse.
  **For you:** is a derived surplus note on a claim as sound as the derived
  refund (question 8), does a two-input resolution (escrow plus top-up)
  show through the proof or its timing (question 4), and is a ceiling of
  `2 F` a reasonable default, or should the surplus be retired instead of
  returned?
- **Two open items on the proof binding** (recorded 2026-11-21, yours to
  decide): (1) `stranger_note_hash` should be computed *outside* the
  circuit with an ordinary hash (BLAKE2s, as the model uses, or SHA-256)
  and enter the proof only as a public input, so the 1,787 slot bytes are
  never hashed in-circuit; which hash, and who computes it (the chain on
  inclusion, the verifier, or both). (2) Everything the proof must commit
  to (nullifiers, commitments, the two coin slots, `stranger_note_hash`,
  the admission commitment, fee and validity window) could be bound
  through one whole-transaction sighash digest that enters Groth16 as a
  single public input (or two field elements for 256 bits), instead of
  many separate inputs, each of which costs the verifier a scalar
  multiplication. The model's `PublicTx::digest` stands in for this. Is a
  single digest sound here (domain separation, how a 256-bit digest maps
  to the scalar field), and what must stay a separate public input
  (nullifiers, so the chain can check double spends)?
- **Open questions for you** (issues file, "Open questions recorded
  2026-11-20"): multi-device grant state; Bob's callback using
  the handshake key on his card (I16); timing equivalence between authorised and unauthorised
  callers, which nobody has measured; and whether the unchecked ephemeral
  keys inside `snow` are acceptable.
- Known limits: IK's replayable message 1 (a still-authorised caller's
  recorded message 1 gets a reply: an availability signal, question 11);
  IK's weaker caller privacy if the answerer's handshake key leaks; notes
  (Noise X) get forward secrecy only from inbox rotation (a seized device
  reads notes to the epochs it still holds: up to a week plus 26 hours); the ephemeral key in a note is
  a raw X25519 point (question 12); forward secrecy per session only; no
  post-quantum key exchange; nothing audited. Questions raised while
  building it are I15-I27 in the issues file.

### D. How the pieces compose at the network layer

- Replies use Nym's single-use reply blocks so the responder never learns
  the caller's mixnet address.
- A stranger is reached by reverse rendezvous: the request carries a
  throwaway mixnet address; the recipient calls back.
- In the shielded design, transactions and chain queries are meant to go
  through the mixnet, and wallets find their notes by scanning everything.

We would like your view on what an observer learns from timing, from
wallet synchronisation, and from the small population at launch.

## 6. What we would like back

1. A written review of the shielded specification: findings by severity,
   and whether the overall construction is viable.
2. A recommended concrete suite for section B, with reasons.
3. A precise statement of what the circuit must prove, or corrections to
   the spec so that one can be written.
4. Your estimate of circuit size and whether proving on a phone is
   plausible, and what to measure first.
5. A bounded, honest version of the claim in section 3.
6. What must be audited separately, in what order, and by what kind of
   firm.
7. A view on effort and cost for implementing the circuit and for audit.

## 7. What we are not asking

- A review of the transparent prototype chain. It is known to publish the
  contact graph and will be replaced.
- Legal advice. The owner is taking that separately.
- An audit of code that does not exist yet: there is no circuit, no
  verifier integration and no wallet.

## 8. Known weaknesses, so you need not rediscover them

- The current chain publishes who contacts whom, who pays whom, and who
  blocks whom.
- The shielded design is a specification and a rules model only.
- Parameter values (base fee, surcharge, window width) are placeholders.
- A resolver with no coins cannot settle an escrow whose reserve is below a
  raised base fee until they have some (I8, top-up rule).
- Wallets must scan every transaction; no detection scheme is designed.
- Refunds are not automatic: the sender's app must submit them.
- A sender can withdraw a request while the recipient's claim is still
  unconfirmed; the first finalised action wins.
- No trusted-setup plan exists, should the proof system need one.
- The section 2a handshake and note format are an unreviewed prototype;
  the transparent chain still links each request to both wallets.
