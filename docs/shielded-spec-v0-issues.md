# Issues found while modelling the shielded spec

Raised while building `crates/shielded-model` against
`docs/shielded-spec-v0.md`. I1–I12 were found in v0.4 (2026-11-19); v0.5
resolves all but I8. I13–I14 were raised by v0.5; v0.6 fixes their wording.
The design review of 2026-11-19 (`design-review-2026-11-19.md`) adds
findings H1–H7 and M1–M4, tracked below. I15–I26 were raised while
prototyping v0.7 section 2a in `crates/crypto` (2026-11-20); I27 is a
question for the cryptographer about one of those choices. W1-W6 (spec
section 2b) are proposed wallet and network rules. I28-I29 come from the
payload slots, pruning and hybrid note of 2026-11-20. Each entry says
how it stands and what the model or prototype does.

| # | Issue | Status |
|---|---|---|
| I1 | Validity window closed vs half-open; claim rule | Resolved in v0.5 |
| I2 | Timeout added nothing over Cancel | Resolved in v0.5 |
| I3 | Ordinary-note nullifier unspecified | Resolved in v0.5 |
| I4 | Value range unspecified | Resolved in v0.5 |
| I5 | Where the admission record lives | Resolved in v0.5 |
| I6 | `created_at`: block time or window start | Resolved in v0.5 |
| I7 | Form of a dummy output | Resolved in v0.5 |
| I8 | Changing `F` strands open escrows | **Addressed in the model, 2026-11-21** (fee ceiling, private surplus, top-up; O9, P4); review open (questions 4, 10) |
| I9 | Refunds of twin escrows were identical | Resolved in v0.5 |
| I10 | Minimum price and parameter values | Resolved in v0.5 (parameter values still placeholders) |
| I11 | Recovery copy needed a nonce search | Resolved in v0.5 |
| I12 | Penalty constraint implied by two others | Resolved in v0.5 (check kept) |
| I13 | "Every note has a fresh secret blinding" vs the derived refund | Wording fixed in v0.6; one-time `refund_to` per escrow enforced by the model's wallet (2026-11-21); **cryptographic question open** (question 8, review H5) |
| I14 | "Refunded after 24 hours" vs a refund valid at any time | Closed: wording fixed in v0.6 |

## Resolved in v0.5

**I1. Validity windows.** v0.4 wrote the window closed in section 4 and
half-open in P11, and its claim rule `not_after < created_at + 24h` would
have forbidden a claim in the last window before the deadline.
*v0.5:* one half-open grid cell `[not_before, not_after)`; claims need
`not_after <= created_at + 24h`. *Model:* as v0.5 (unchanged).

**I2. Timeout added nothing over Cancel.** Same authority, same outputs,
and Cancel had no time limit. *v0.5:* merged into one **Sender refund**,
valid at any time. *Model:* `Branch::SenderRefund` replaces `Cancel` and
`Timeout`; `Reject::TimeoutTooEarly` is gone.

**I3. Ordinary-note nullifier.** *v0.5:* from a secret only the owner
holds, the commitment and the position. *Model:* `H(owner secret,
commitment, position)` (unchanged).

**I4. Value range.** *v0.5:* unsigned 64-bit values, checked sums, and an
escrow's `price + fee_reserve` must fit 64 bits. *Model:* as v0.5
(unchanged).

**I5. Admission record.** *v0.5:* its commitment is a separate public field,
not a tree leaf. *Model:* as v0.5 (unchanged).

**I6. `created_at`.** *v0.5:* the chain stamps the start of the current
window. *Model:* as v0.5 (unchanged).

**I7. Dummy outputs.** *v0.5:* a zero-value retired note with fresh
blinding, inserted like any other. *Model:* as v0.5 (unchanged).

**I9. Twin escrows.** v0.4 derived the refund blinding from `seed` alone,
so two escrows sharing a seed got identical refunds. *v0.5:* from `seed`
and the escrow's position. *Model:* `refund_blinding(seed,
escrow_position)`; the test `two_escrows_with_the_same_seed_give_different_refunds`
covers escrows that share only a seed and exact twins.

**I10. Minimum price.** *v0.5:* none; a price of 1–99 carries a penalty of
1 (price 0 carries none). *Model:* as v0.5 (unchanged). `F`, `S` and the
window width are still placeholder values (`F = 10`, `S = 50`, 1 hour).

**I11. Recovery copy.** v0.4 left the nonce implicit, so the model's
restored wallet tried every payload against every commitment. *v0.5:* the
copy carries a fresh random nonce, one decryption per payload. *Model:* a
payload slot holds `nonce || ciphertext` (12 + 176 + 16 = 204 bytes, so
`PAYLOAD_LEN` grew from 192 to 204); `open_recovery` makes one attempt and
needs no chain context. The model takes the nonce from its caller, because
it has no randomness source of its own.

**I12. Implied penalty constraint.** *v0.5:* the explicit check is kept
anyway. *Model:* kept; disabling it still fails no test, as expected.

## Still open

**I8. Changing `F` strands open escrows.** An escrow's reserve equals the
`F` of its opening and its resolution must pay exactly `F`, so a change of
`F` leaves old escrows unable to resolve, or marks them by a different fee.
v0.6 fixes `F` for the prototype (P4) and names the review's candidate (a
maximum fee `C` locked in each escrow, `C - F` returned privately on every
outcome), which would amend O7 and needs the owner's decision. Same finding
as review H1. *Addressed in the model on 2026-11-21* (O9, the owner's
HIGH-03 request; see "Fee changes and one-time refund keys" at the end of
this file): an opening locks `fee_reserve >= F` (wallet default `2 F`);
the surplus returns to `refund_to` in a derived note on every outcome; a
fee above the reserve is covered by a top-up note. Still for review:
questions 4 and 10.

## Raised by v0.5

**I13. The refund's blinding is not fresh.** Section 3 said every note
carries "a fresh secret `blinding`", but the refund's is derived from `seed`
and the escrow's position, so both escrow parties can recompute its
commitment. *Wording fixed in v0.6:* section 3 names the refund as the one
exception. *Still open:* the cryptographic question of what the recipient
can learn from it (question 8; review H5 asks for owner-only serials and an
in-circuit constraint on destination, amount and blinding). *2026-11-21:*
the model already constrains destination, amount and blinding (including
the new claim surplus); its wallet now gives every escrow its own one-time
`refund_to` key and refuses a reused or long-term one; tests show that
everything the recipient knows (seed, escrow, `refund_to`, blinding,
commitment) neither spends the note nor yields its nullifier. That is a
property of the model's hash stand-ins, not a proof about a circuit.

**I14. "Refunded after 24 hours".** O6 and P3 said an ignored stranger's
escrow "comes back after 24 hours", although the sender refund is valid at
any time and nothing comes back on its own. *Closed:* v0.6 rewords O6 and
P3 ("the sender can take the refund, minus the penalty, at any time; after
24 hours the recipient can no longer claim, so an ignored request is then
always refundable").

## Design review findings (2026-11-19)

| # | Finding (short) | Status |
|---|---|---|
| H1 | A changed base fee strands old escrows (= I8) | **Addressed in the model, 2026-11-21** (audit HIGH-03): the max-fee alternative, with a top-up when the fee exceeds the reserve (O9, P4). Unreviewed |
| H2 | Restore did not cover the key indices the wallet can use | **Fixed in the model** (and v0.6): the recovery copy records purpose and index for the refund identity and the cancel authority; no search. Tested at `u64::MAX`, sparse indices and 40 escrows |
| H3 | Noise XX gives a reusable wallet credential to any initiating peer | Addressed in the prototype, unreviewed; spec questions 11 and 12 |
| H4 | The sealed note's prologue needs the stranger's address before decrypting | Addressed in the prototype, unreviewed; spec questions 11 and 12 |
| H5 | A resolver knows the deterministic refund; spend privacy and recovery need in-circuit guarantees | **Open cryptographic gate.** The model enforces the exact refund and claim-surplus fields and one-time refund keys (2026-11-21); it cannot show proof properties |
| H6 | Wallet-specific fetches, immediate callbacks and a small population can reveal correspondents | **Open deployment gate.** Immediate callbacks: the demo now waits a random 30-300 s before calling back (2026-11-21, MED-03 below); wallet-specific fetches and the small population remain |
| H7 | Circuit completeness, verifier validation, key privacy, setup and mobile proving are unproven | **Open release gate** |
| M1 | Wallet matched the expected refund commitment anywhere in history | **Fixed in the model** (and v0.6): the wallet finds the finalised transaction that consumed the escrow's nullifier, matches the refund among its outputs only, and reports separately whether it is unspent. Tested with an identical decoy commitment made earlier |
| M2 | All-zero padding payloads; receipts and invites replayable across devices | **Padding fixed in the model (2026-11-21, MED-03 below):** unused coin slots get fresh random bytes, the stranger slot a caller-supplied real dummy note (random bytes if none). Receipt and invitation idempotency across devices is still not modelled |
| M3 | Invalid handshake traffic could consume pending state | Malformed-frame regression covered in the prototype; production retry design open, pending the handshake pattern chosen under spec question 11 |
| M4 | A cumulative fee sink double-counts once operator funds are live; deadlines narrow candidates | **Open.** Applies before operator payouts or migrations |

## Found while fixing the review findings

**`snow` restores only part of its state after a failed read.** `snow`
0.10 checkpoints its hash and chaining key before reading a handshake
message and restores them on failure, but not its cipher state. A message 3
that passes its first decryption, re-keys the cipher and then fails on its
payload leaves the responder unable to read the genuine message 3. (Message
2 escapes this by accident: its first key step overwrites the cipher key.)
*In `anonymum-crypto` (owner decision, 2026-11-19):* no workaround. The
crate uses `snow`'s public API only, does not patch `snow`, and follows the
Noise rule that a failed handshake ends: a cryptographic failure, or a peer
proving the wrong identity, ends that attempt, and the caller starts a fresh
handshake with a fresh ephemeral key (bounded retries, backoff). Only frames
rejected by the outer framing (empty, unknown type, wrong length for the
type) are ignored without ending anything. A timeout resends the exact
bytes already sent; every handshake frame carries a call id and an attempt
number so a late frame from an older attempt is ignored; and the initiator
counts the session as open only after the responder confirms it.
*For the cryptographer:* the partial rollback is still worth reporting
upstream, and matters for whichever handshake replaces this one
(question 11).

## Raised while prototyping section 2a (spec v0.7, 2026-11-20)

H3 and H4 are addressed in `crates/crypto` by a prototype of section 2a:
contact identities separate from the wallet, Noise IK with the
authorisation check before any reply, and a note that opens with the
recipient's inbox key alone. Unreviewed; spec questions 11 and 12. Where
the spec left something open, the prototype made the choice below and
carried on. Each needs the owner's or the cryptographer's answer.

| # | Spec gap | What the prototype does |
|---|---|---|
| I15 | Rule 3 says a caller is "treated as present only after a fresh session confirmation" but not who confirms or how. | Four frames: IK message 1, IK message 2, a CONFIRM from the caller sealed in the new session, an ACK from the answerer. Grants (invitation used, contact recorded) are committed on CONFIRM, after checking the gate again; the caller counts the session as open on the ACK. |
| I16 | In reverse rendezvous the stranger answers "only if the caller is the recipient they addressed", but caller keys should be scoped to one request. The stranger knows only the recipient's card. | The recipient calls with the handshake key from its card; the stranger's side accepts exactly that key, naming that request. The recipient's key is therefore not scoped per request (it is public on the card anyway). A fresh per-request key would need a signature from the contact signing key inside message 1. |
| I17 | The note must be bound to "the admission record of the same transaction", but the transparent prototype chain has no admission record. | The note's Noise prologue includes a 32-byte admission commitment. The note field carries `commitment (32) || envelope (555)`, 587 bytes (was 427; core and pallet constants changed). In the shielded design the commitment must be a separate public field, or moving the whole field to another transaction moves the binding with it. The demo uses a random stand-in. |
| I18 | Rule 6: "both sides mix the accepted request's identifier into the session"; the identifier is not defined. | The reference named inside message 1 is part of the IK transcript, so the session is bound to it. For a callback it is the admission commitment; for an invitation, the invitation id; for a contact, the reference recorded when the relationship began. |
| I19 | Who generates the invitation's holder key is not said. | The invitee generates a caller key for this relationship and hands its public half to the issuer, who signs an invitation to it (no secret is handed over). |
| I20 | A contact card names keys, price and validity but no network; invitations name the network. | Fixed after 299f429: the card now carries and signs the network id, and `ContactCard::verify` refuses a card for another network (tested). |
| I21 | Rule 3 asks that a replayed first message not reopen a blocked contact or use an invitation twice, but says nothing of a still-authorised caller. | A recorded message 1 from a caller who is still a contact gets a message 2 (it cannot be confirmed, so no session and no grant). An availability signal: question 11. Repeats of an answered message 1 are re-checked against the gate before the cached reply is resent. |
| I22 | Rule 4 puts the sender's contact identity inside the note but does not say it is authenticated. | The sender signs (contact signing key) the admission commitment, the recipient's inbox key and the note body, so a note cannot claim another identity or be forwarded to a third person as if written to them. |
| I23 | Rule 4: a note must not be recognisable from the public card. | The note's ciphertext does not name the recipient, but its ephemeral key is a raw X25519 point, distinguishable from random bytes (not linkable to the recipient). Elligator-style encoding would need a vetted library. Question 12. **Preferred option for dummy slots (W4, proposed, unreviewed):** fill them with real Noise X notes between fresh random keys, so a dummy has the same structure as a real note instead of being random bytes. |
| I24 | The shielded design's payload slot size (P10) is open; the note is now 587 bytes. | **Proposed 2026-11-20:** two 200-byte coin-note slots and one 1,787-byte stranger-note slot in every transaction (spec P10), implemented in the model (`PAYLOAD_LENS`); the stranger slot holds the v5 note exactly. Sizes unreviewed. |
| I25 | Whether an existing contact may call about anything, or only its relationship. | A contact's calls must name the reference recorded when it was admitted; any other reference gets nothing. |
| I26 | The transparent chain still requires a wallet-bound messaging key before it accepts a request, and records requests wallet to wallet. | Kept for the prototype chain (a known gap until stage 5). Notes are sealed to the card's inbox key and never use that key. |

**I27. Deniable sender authentication for the note: prototyped,
unreviewed.** v3 had the stranger sign the note (I22), which gave the
recipient transferable proof of who contacted them. Owner decision
(2026-11-20): the recipient should be convinced who sent a note but must
not be able to prove it to anyone else.
*Prototype (note format v4, 667 bytes):* one Noise X message
(`Noise_X_25519_ChaChaPoly_BLAKE2s`, snow's public API) from the sender's
contact handshake key to the recipient's inbox key; prologue
`"anonymum/contact-note/v4" || network || admission`; inside, version 4,
the sender's card fields (signing key, inbox key, price, validity,
signature; the handshake key is the authenticated static and the network
is the prologue's), the route and the intro (still 280 bytes). The
recipient rebuilds and verifies the card, and checks the sender's static
key with `was_contributory` before trusting anything. Tests: a note opens
and names the sender; another recipient, network or admission fails; a
small-order sender key is refused; v3 and v4 notes cannot be confused; the
recipient can forge a note that opens as from any sender (the deniability
itself); and the cost, below.
*Size:* with the intro kept at 280 bytes the payload no longer fit 587
bytes (the card fields and the encrypted static cost more than the
signature and callback key they replace), so the field is now 667 bytes in
core, the pallet (runtime `spec_version` 4), the spec, the scripts and the
tests. A 200-byte intro would have kept 587; the intro cap is the owner's
open question, so it was not cut.
*The cost, for the cryptographer:* anyone holding the recipient's inbox
secret can forge notes to that inbox from any sender whose card they have
(a test shows it). Against that, the callback is now answered by the
sender's handshake key itself, the key Noise X authenticated: a forger
with only the inbox secret cannot complete the callback (tested). Its
privacy cost: there is no per-request callback key any more, so the
recipient's first callback message is encrypted to the sender's long-lived
handshake key, and a later compromise of that key reveals the recipient's
card key and the request reference from a recorded first message (before,
only the fresh callback key's compromise did). A per-request key would need
binding to the identity again, which is what the signature did.
*Still open:* forward secrecy for notes (an inbox key leak opens every
recorded note; inbox rotation prototyped 2026-11-21, see the end of this
file); whether Noise X's identity hiding and the visible
ephemeral key meet question 12.

## Source review of cdad354 (2026-11-20)

`docs/source-review-cdad354-2026-11-20.md` (AI-written; not a human
cryptographic audit) found eight items and four smaller ones in the
section 2a prototype. Status after the fixes of 2026-11-20 in
`crates/crypto`, the Nym demo and `e2e.mjs`:

| # | Finding (short) | Status |
|---|---|---|
| R1 | Revocation through the public mutable gate left live sessions and cached ACKs working | **Fixed.** The gate has no public constructor or mutators; `Responder::block` and `Responder::remove_contact` change the policy, end the peer's sessions, drop its cached WELCOME and ACK, and (owner decision, 2026-11-20) cancel its unused invitation (revoked for good, also against re-recording) and any outstanding callback grant, all in one step; unblocking restores none of them, so reopening needs a fresh invitation. Every use of a live session checks the gate again. Tested through both routes, including that the cancelled invitation and callback grant get no reply and a fresh invitation works |
| R2 | The note authenticates only the admission bytes it carries; nothing ties it to a particular finalised escrow (I17) | **Open.** Needs the shielded design's admission record as an independent, finalised public field. The note is now also bound to the network (prologue and signed bytes; still 587 bytes); there is no pool id yet |
| R3 | External X25519 keys were used unvalidated | **Fixed for every key we receive or are asked to use**: card handshake and inbox keys, invitation holder keys, a note's callback key, the inbox and callback keys we seal with, the key an initiator calls, the caller key read from a HELLO, and the caller a callback listener expects. See the check below. Tested with seven small-order encodings, including the caller-key check after reading a HELLO: a crate-internal test builds a HELLO from each small-order key through a test-only `snow` resolver (snow's public `CryptoResolver`/`Dh` traits; default primitives except that the marked static key reports the small-order point and an all-zero agreement); snow accepts it and our check refuses it |
| R4 | e2e started the callback before finality and rebuilt Bob's inputs from Carol's private keep file | **Fixed.** Every transaction waits for finalisation; Bob and Carol run as two processes with separate folders; Bob's process gets his own wallet file and the note bytes read from chain state, nothing else; a contact key that does not match the note's sender is now an error. Not yet run: the review's copied-field and losing-claim cases (they need the shielded admission record) |
| R5 | Lost ACK: the demo stopped reading after its first ACK; a caller that moved to a higher attempt was welcomed but its CONFIRM was tested against the older live session | **Fixed.** A CONFIRM is matched first to the exact live attempt (resend the ACK, after a gate check), then to the matching pending attempt, which replaces the old session as a contact without using the invitation again. The demo's responders keep reading after establishing; `ANONYMUM_DROP_FIRST_ACK=1` drops the first ACK in a live run. Tests: the higher-attempt case and a driver loop under eight deterministic loss patterns |
| R6 | Frame type, call id and attempt were outside the authenticated content | **Fixed.** Call id and attempt are in the IK prologue; every sealed record carries its type, and CONFIRM and ACK also carry call id and attempt, inside the ciphertext; a record whose inner type or labels do not match is refused without using up its counter. Data frames carry at most 65,518 bytes (one byte for the type) |
| R7 | Bob's callback uses his card key (I16); the note signature is transferable (I27) | I16 **open, with the cryptographer**. I27 **prototyped, unreviewed** (deniable Noise X note, 2026-11-20; see I27) |
| R8 | In-memory grant state; no idle or callback expiry; pending expiry only on receive timeouts | **Fixed for one device (2026-11-21, unreviewed).** Answered handshakes expire after `PENDING_TIMEOUT` (180 s) and sessions after `SESSION_IDLE_TIMEOUT` (30 min), on the monotonic clock, in memory only. Everything the gate keeps is now in Unix seconds (invitation expiries, callback deadlines, and the expiry of every revoked or consumed invitation id) and can be saved as an encrypted, versioned snapshot (`Responder::export_snapshot`, `restore_identity`, `restore_callback`; see below). Crash between commit and ACK: handled by the persist-before-reply rule in `wire.rs`. **Open:** multi-device grant state |
| R9 | `Incoming::accept` could build a WELCOME without a gate | **Fixed.** The answering handshake types are crate-private; `Responder` is the only way to answer (compile-fail doc tests) |
| R10 | `record_invitation` trusted its caller | **Fixed.** It checks issuer (our signing key), signature, network, holder key and expiry; a callback listener records none |
| R11 | Responder and gate took the network separately | **Fixed.** `Responder::for_identity` / `for_callback` build the gate from the same network id |
| R12 | Card price is 128-bit; the shielded model's amounts are 64-bit; runtime spec version 0 | **Fixed.** `ContactCard::verify` refuses a price above `u64::MAX`. The dev runtime's `spec_version` is 1; notes stored before the 587-byte format cannot be opened, by design (the dev chain starts from a fresh genesis) |

**The key check chosen (for the cryptographer).** `is_contributory_key`
computes an X25519 agreement between the received public key and a fresh
random secret with `x25519-dalek` 2.0.1 and asks the library's own
`SharedSecret::was_contributory`, which reports whether the output is all
zeros (RFC 7748 section 6.1). Clamped X25519 scalars are multiples of the
cofactor 8, so the output is all zeros for every secret exactly when the
point has small order; one fresh secret decides it. No list of bad points is
kept in the code (the tests use the seven well-known small-order encodings
as vectors). Mixed-order points pass, as they do for X25519 itself. **Not
covered:** the *ephemeral* keys inside IK messages and Noise N notes are
handled by `snow`'s default resolver, which does not reject an all-zero
result, and `snow`'s public API gives no hook to check them before use.
Is that acceptable for IK and N here, or must the resolver fail closed?

## Open questions recorded 2026-11-20 (not to be solved yet)

- **Durable and multi-device grant state** (review finding 8). *Durable
  state on one device: done 2026-11-21 (R8, MED-04 below).* Still open:
  how two devices of one person agree that an invitation was used once.
  The rule until then: one device per contact identity; a second device
  gets its own identity (its own keys and invitations), never a copy of
  another device's gate.
- **Bob's callback uses his card's handshake key** (I16, review finding 7).
  A recorder of the callback's first message who later learns the callback
  secret learns Bob's key and the request reference. How should the
  stranger privately authorise a request-scoped callback key instead?
- **The note's signature was transferable proof of who made contact**
  (I27). Prototyped as deniable Noise X on 2026-11-20 (unreviewed); the
  forgery-on-inbox-compromise cost is recorded under I27.
- **Timing equivalence between authorised and unauthorised callers is
  unmeasured.** Both get no frame from an unauthorised refusal, but the
  work before refusing differs (a blocked key, an unknown key and a wrong
  answerer key each stop at a different point). Nobody has measured what a
  caller, a gateway or a network observer can tell.

## AI-written audit of 3f7092d (2026-11-20)

`docs/ai-audit-3f7092d-2026-11-20.md` (AI-written; not a human audit).
Status after the fixes of 2026-11-20:

| # | Finding (short) | Status |
|---|---|---|
| A1 (HIGH-01) | Early answers never left `ExpiryQueue`, so a block's slot could be filled and the cap reached | **Fixed in the pallet.** Accepting, declining, cancelling, superseding or blocking removes the request's id from its slot (and an empty slot is deleted). Tested with every kind of early resolution; the "queue full charges nothing" test is kept. The in-process simulation (`anonymum-core`) scans for expiry and has no queue. Lazy, permissionless expiry and benchmarked weights (the audit's remedy) are not done |
| A2 (HIGH-04) | Key binding and invite proofs named no chain; the binding named no account | **Fixed.** Both messages are v2: `"anonymum/msgkey-binding/v2" ‖ genesis ‖ account ‖ key` and `"anonymum/invite/v2" ‖ genesis ‖ opener ‖ recipient`, in the pallet (`block_hash(0)`), core (`Params::genesis`), crypto and both scripts. Tested: a binding for one account is refused for another; a signature for another genesis hash is refused (pallet, core, and with real keys in crypto). No nonce was added: invites are one-time and a binding is replaced by publishing a new one |
| A2b | `sp_io::crypto::ed25519_verify` and `verify_strict` | **Checked; weak keys now refused.** In this workspace's SDK (sp-io 49, sp-core 43) the native host function verifies with `ed25519-zebra` (ZIP 215: small-order keys and points allowed, cofactored equation), or with `ed25519-dalek`'s non-strict `verify` when the node registers `UseDalekExt`; on a live chain the node binary's own copy decides. Such a check accepts a trivially made proof (R = identity, S = 0) for a small-order key. Since 2026-11-20 `register_invite` refuses any key `ed25519-dalek` cannot decode or reports weak (`VerifyingKey::from_bytes`, `is_weak`; no list of points), so no such key can be stored (`WeakInviteKey`, charging nothing; tested with the identity and an order-8 point). Builds for the wasm runtime (`spec_version` 3); smoke test passed on the dev node. The proof check itself still differs from `verify_strict` for non-weak keys (non-canonical encodings, cofactored equation) |
| A3 (MED-02) | Unchecked pallet arithmetic | **Fixed.** `Percent::mul_floor` for the fee split; checked adds for the expiry height and the id and sequence counters, returning `ArithmeticError::Overflow` and charging nothing. Tested at each boundary |
| A4 (HIGH-02) | Sessions keyed by reply handle and unbounded; one caller could fill the pending table | **Fixed.** Candidate handles are capped at one per caller (a newer one replaces it) and are dropped with a caller evicted from a handle (tested: a CONFIRM replayed from 200 handles leaves one). Live sessions are keyed by the caller's authenticated key (one each) with a route table from reply handle to caller. Caps with named defaults: `MAX_PENDING` 1,024, `MAX_PENDING_PER_CALLER` 4, `MAX_SESSIONS` 1,024 (`Limits`). A repeated CONFIRM from a new handle gets the cached ACK there, but the session moves only when a fresh data frame from that handle decrypts, so a replayed CONFIRM cannot redirect replies. At the session cap a new caller is refused before its CONFIRM is opened and nothing is committed. Tests for each |
| A5 (MED-01) | Unchecked send counter | **Fixed.** `Session::seal` uses nonces up to `u64::MAX - 1` and then refuses (`Exhausted`); Noise reserves only `u64::MAX`, so it cannot wrap. No rekeying |
| A6 (CRIT-02, HIGH-03, MED-03, MED-04, CRIT-01) | Note signature and forward secrecy, refund blinding and fee, dummy payloads, durable state, the transparent chain and unproved model | **Recorded, not solved; MED-04 (durable state) fixed for one device on 2026-11-21; CRIT-02's forward-secrecy half prototyped on 2026-11-21 (inbox key rotation); MED-03 (dummy payloads, callback timing) addressed on 2026-11-21; HIGH-03 (fee changes, refund keys) addressed in the model on 2026-11-21; see the end of this file** (see below and earlier sections: I8, I13, I27, R8) |
| A7 (LOW-01) | Replace the random-secret key check with a list of small-order points | **Not done, by decision**: no hand-written list of bad points; the check stays on `x25519-dalek`'s `was_contributory` |

**Where the audit is wrong or overstated (my reading, for the owner).**
- HIGH-02 says Nym sender tags "rotate across batches". In `nym-sdk` 1.21.6,
  as recorded in CLAUDE.md, `get_or_create_sender_tag` gives one stable tag
  per sender and recipient; a tag changes when the caller's client is
  replaced. The fix is still right, but the trigger is a reconnection, not
  every batch.
- MED-01 calls a wrapping send counter "catastrophic": reaching 2^64
  messages in one session is not practical, so this was hygiene, not a live
  risk.
- HIGH-01's severity assumes an attacker who pays the network fee for every
  slot-filling request; it is still worth fixing, and is fixed.
- CRIT-01 restates known, documented gaps (the transparent chain publishes
  the contact graph; the shielded layer is a model) rather than a new
  defect.

**Recorded 2026-11-20 for the cryptographer (not to be solved yet).**
- **No forward secrecy for stranger notes.** A note is sealed to a
  long-lived inbox key; if that key leaks, every recorded note to it opens.
  Candidate mitigation: rotate the inbox key (short card validity) and
  erase old inbox secrets once no pending request can still use them.
  *Prototyped 2026-11-21 (weekly epochs, 26-hour drain), see "Inbox key
  rotation" at the end of this file.*
- **No delay between claim finality and the callback.** The recipient
  calls the throwaway route as soon as the acceptance is final, so the
  timing links the chain event to the mixnet traffic. Random delay or batched
  callbacks are candidates. *Random delay prototyped 2026-11-21 (MED-03 at
  the end of this file).*
- **Dummy payload slots must be indistinguishable from real ones.** The
  model pads with zeros (review M2). Slot sizes are now proposed (I24: the
  1,787-byte stranger slot holds a v5 note exactly); dummy content is W4.
  *Done in the model and the crypto crate 2026-11-21 (MED-03 at the end of
  this file).*
- **Post-quantum key exchange and ratcheting** remain long-term questions:
  no per-message forward secrecy (no double ratchet) and no post-quantum
  key agreement in sessions. Notes have a hybrid ML-KEM-768 layer since
  2026-11-20 (I29).

## Wallet and network behaviour rules W1-W6 (proposed, unreviewed, 2026-11-20)

Spec section 2b. Rules for what a wallet does; the chain cannot check
them. All proposed and unreviewed.

| # | Rule | Status |
|---|---|---|
| W1 | Never query a node about a specific nullifier, commitment, admission record, request or block of interest: sync what every wallet syncs, or fetch over the mixnet | **Proposed, unreviewed.** The prototype breaks it by design: `e2e.mjs`, `smoke.mjs` and the demo read specific requests, keys and block timestamps from a local node to check results |
| W2 | Random delay before a callback after a claim is final; before a sender refund after expiry (never the first eligible block); no spending of an Open's change in the next block | **Proposed, unreviewed.** Distributions are a question for the cryptographer. The demo's callback waits a uniform 30-300 s since 2026-11-21 (`--no-jitter` for local runs); refund and change delays are not implemented |
| W3 | Every transaction carries one admission commitment; the empty record in Transfer, Claim, Decline and Sender refund has a fresh, secret, uniformly random blinding, so its commitment is indistinguishable from a real one | **Proposed, unreviewed; zero fields enforced 2026-11-20.** The model rejects a non-empty record in those branches at no charge (`Reject::NonEmptyAdmission`, tests in `slots_and_pruning.rs`). The blinding is still salt-derived in the model: see below |
| W4 | A dummy payload slot holds a real Noise X note from a fresh random key to a fresh random key, not random bytes | **Prototyped 2026-11-21, unreviewed:** `anonymum_crypto::dummy_note`; the model's builder takes it through `dummy_stranger_note` (MED-03 at the end of this file) |
| W5 | Transfers, invited requests and stranger escrows share one pool and one fee structure | **Proposed, unreviewed.** Consistent with O3 and the spec's single circuit |
| W6 | Open questions (below) | **Recorded** |

**W3, what the spec and the model actually do.**
- *Spec:* section 3 says every transaction carries one admission record and
  that non-requests carry "an empty one that looks the same"; section 4
  lists the admission commitment among every transaction's public fields.
  But the branch table named the empty record only for Transfer, and
  nowhere said how the empty record is blinded. The table now names it for
  Claim and Decline (Sender refund is "same as Decline"), and W3 states the
  blinding rule.
- *Model:* every transaction does carry an admission commitment.
  `TxBuilder::build` uses `AdmissionRecord::empty(blinding)` when no record
  is given, with zero contact key and digest, tier none, no escrow. The
  chain checks only that Transfer, Claim, Decline and Sender refund carry
  tier none and no escrow, and since 2026-11-20 also that the contact key
  and request digest are zero (`AdmissionRecord::is_empty`); it does not
  (and cannot) check that the blinding is fresh. **The model's blinding is
  not random:** it is derived from the builder's salt
  (`H("builder/derived", salt, "admission", 0)`), which the caller supplies.
  The code says "a real wallet would use fresh randomness"; two
  transactions built with the same salt would carry identical empty
  commitments. This is a test convenience that W3 forbids in a wallet. The
  model's commitment is a domain-separated BLAKE2s hash with a 32-byte
  blinding: hiding only if the blinding is secret and random. The real
  scheme is for the cryptographer.

**W6, open questions.**
- *Hybrid post-quantum key exchange* for notes and handshakes, decided
  before the note format is frozen. **Notes: prototyped 2026-11-20 (I29).**
  The estimate below (two KEM keys per card) was not what was built: the
  card carries one ML-KEM-768 key, for the inbox, so it is 1,408 bytes;
  the note is 1,787 bytes. Handshakes and callbacks stay classical. Size cost with ML-KEM-768 (public key
  1,184 bytes, ciphertext 1,088 bytes): a note would grow by at least one
  KEM ciphertext, from 667 to about 1,755 bytes; a card carrying KEM public
  keys for the inbox and handshake keys would grow from 224 to about 2,592
  bytes. `snow` 0.10 offers hybrid forward secrecy (Kyber1024) only behind
  its non-default `hfs` feature; whether that or another construction is
  right is open.
- *Inbox and handshake key rotation*, and how a rotated key is recognised
  as the same contact (a new card signed by the same signing key is the
  obvious path; what it costs in linkability is open). Rotating the inbox
  key is also the candidate mitigation for the missing forward secrecy of
  notes.
- *A persistently connected wallet versus a throwaway listener.* A wallet
  that stays connected is reachable and sends cover traffic all the time;
  a throwaway listener that comes online only to answer a callback shows
  when it is online. Which the product wants, and when, is open.
- *Cover traffic, checked 2026-11-20 by reading the code of the locked
  versions (`nym-sdk` 1.21.6, `nym-client-core-config-types` 1.21.6), not
  by measurement:* the SDK's client configuration uses the default debug
  configuration, in which the loop cover traffic stream is on
  (`disable_loop_cover_traffic_stream: false`, average delay 200 ms) and
  the main Poisson packet stream is on
  (`disable_main_poisson_packet_distribution: false`, average 20 ms), so
  real packets are mixed into a constant-rate stream. The demo does not
  change these settings. Cover traffic stops whenever a client
  disconnects, so a throwaway client's online periods remain visible to
  its gateway.
- *Message retrieval at scale* (oblivious message retrieval, fuzzy message
  detection): roadmap only. Today every wallet tries every note.

## Payload slots, pruning and the hybrid note (2026-11-20, unreviewed)

**I28. A pruned stranger note leaves its proof uncheckable.** Spec
section 4 now lets nodes discard a transaction's 1,787-byte stranger-note
slot 24 hours after its window starts (the request can no longer be
claimed, O8). The tree, nullifiers, admission commitments and coin-note
slots stay. But statement 6 binds the proof to every payload slot, so a
node syncing from genesis after pruning cannot recheck the proofs of
pruned transactions. Candidate fix: the chain keeps a 32-byte hash of
each stranger slot permanently and the proof binds to that hash. The
reference model (`Chain::prune_stranger_notes`) drops the bytes and keeps
no hash; it has no proofs to recheck. For the cryptographer.

*Resolved in the model, 2026-11-20 (unreviewed).* `PublicTx` has a
permanent `stranger_note_hash` (`H("stranger-note-slot", slot)`);
`PublicTx::digest`, which models the proof binding, covers that hash and
the two coin-note slots, not the stranger slot's bytes. `Chain::submit`
rejects a slot that does not match its hash
(`Reject::StrangerNoteMismatch`, no charge), keeps the hash in the log and
the bytes in the 24-hour store. Tests in `slots_and_pruning.rs`: a
mismatched hash or slot is rejected at no charge; after pruning, the
logged transaction's digest still equals the digest its witness was bound
to; a different note under its own correct hash fails the binding check.
What stays for the cryptographer: which hash the circuit uses for this
commitment, and whether the proof should bind to it directly or through
a transaction-wide hash.

**Recovery copy versioned (2026-11-20, unreviewed).** The 200-byte
recovery copy's plaintext now starts with a version byte (`RECOVERY_VERSION
= 1`) that names both the byte layout and the key-derivation scheme. A
copy of any other version is refused (`RecoveryError::UnsupportedVersion`),
and a scan that meets one of the wallet's own copies in an unknown version
fails instead of returning a shorter list. The layout is documented in
`wallet.rs`; 11 bytes of the slot remain spare.

**I29. Hybrid post-quantum stranger note (format v5), prototyped.**
`anonymum-crypto::note`, unreviewed.
- *Card:* one ML-KEM-768 encapsulation key (`pq_inbox_key`, 1,184 bytes),
  from a 64-byte seed in the contact identity. The card format is v3: its
  signature covers `BLAKE2s-256("anonymum/pq-inbox-key/v1" || key)`, not
  the key. Card size 1,408 bytes. `ContactCard::verify` also runs FIPS
  203's input check on the key (`ContactError::BadPqKey`).
- *Note:* admission (32) || ML-KEM ciphertext (1,088) || one
  `Noise_Xpsk0_25519_ChaChaPoly_BLAKE2s` message (667). Prologue
  `"anonymum/contact-note/v5" || network || admission || ciphertext`; the
  ML-KEM shared secret is psk0. The payload adds the sender's 32-byte
  post-quantum key hash to the v4 card fields, so the recipient rebuilds a
  `CardSummary` and checks its signature without the 1,184-byte key.
  Total 1,787 bytes (`SEALED_NOTE_LEN` in core and the pallet; runtime
  `spec_version` 6). v4 (667-byte) notes are refused.
- *Crate:* RustCrypto `ml-kem` pinned to `=0.3.3`. 0.3.4, the newest,
  would have moved two packages already in the lockfile (`ctutils`
  0.4.2 to 0.4.8, `module-lattice` 0.2.3 to 0.2.4); 0.3.3 only adds
  packages (`kem`, `ml-kem`, `sha3` 0.12, `shake`, `sponge-cursor`). Only
  `anonymum-crypto` uses it: the pallet and the wasm runtime do not, so
  no `no_std` build is affected. `ml-kem` has not been audited, as far as
  I know.
- *What it gives:* reading a note needs both the X25519 and the ML-KEM
  inbox secrets (tested: an identity with the right X25519 key and another
  ML-KEM key cannot open it). A tampered ciphertext fails (tested).
- *What it does not give:* sender authentication is classical. Anyone
  with the X25519 inbox secret can still forge notes (the post-quantum key
  is public), and so can anyone who breaks X25519; the callback is
  classical Noise IK. Deniability is unchanged: the recipient can forge a
  v5 note from any card (tested).
- *Untestable by design:* binding the ciphertext into the prologue is
  defence in depth. Removing it from both sides is not caught by any test,
  because a changed ciphertext already changes the shared secret (ML-KEM's
  implicit rejection). Removing it from one side is caught.
- *Question for the cryptographer:* is "KEM secret as Noise psk0, KEM
  ciphertext in the prologue" a sound hybrid here, compared with a
  standard hybrid KEM combiner (for example X-Wing) or `snow`'s
  non-default `hfs` feature?

## Durable gate state: R8 and audit MED-04 (2026-11-21, unreviewed)

`anonymum-crypto` can now save and restore a responder's grant state,
encrypted, without any database dependency.
- *Time:* the gate keeps only Unix seconds: invitation expiries, callback
  deadlines (`Responder::for_callback` now takes Unix seconds), and for
  every revoked or consumed invitation id the invitation's expiry. The
  monotonic clock is used only for the wire layer's in-memory timeouts.
- *Pruning:* `Gate::prune(now_secs)`, run by `Responder::expire` before
  every operation, drops a revoked or consumed id once `now_secs >=
  expires_at + CLOCK_SKEW_SECS` (300 s). By then the invitation itself no
  longer verifies, so it cannot be recorded or used again (tested). Expired
  unused invitations and callback grants past their deadline are dropped
  too. A grant pruned at its deadline stays gone if the clock later reads
  earlier.
- *Clock floor (2026-11-21):* the gate remembers the latest Unix time it
  has seen (`last_seen`, in the snapshot) and judges every expiry and
  deadline at `effective_now = max(last_seen, now)`: pruning, `authorise`,
  `commit`, `record_invitation` and `export_snapshot` (which now takes
  `now`). Setting the clock back, within a run or across a restart, cannot
  make a pruned revocation or consumed invitation usable again, nor
  resurrect a callback grant (tested). With the floor, pruning expired
  invitations and callback grants changes no decision (they are refused at
  the floor anyway); it only frees space, which the tests check through the
  snapshot's size. The cost: a clock that once ran far ahead keeps the gate
  in that future until real time catches up, so invitations and callbacks
  issued with expiries before it are refused. The floor's use in `commit`
  cannot be observed through the API (every `handle` prunes first, which
  raises the floor, and `commit` re-runs `authorise`, which reads it), so
  no test catches its removal.
- *Snapshot:* `version (1, clear) || nonce (12) || ChaCha20-Poly1305
  ciphertext || tag`, associated data `"anonymum/gate-snapshot/v1" ||
  network`, a fresh random nonce each time, under a `StorageKey` (32 bytes,
  wiped on drop, never printed). The plaintext repeats the version and the
  network, the clock floor, and lists issued and consumed invitations, revocations,
  contacts, callback grants and blocks, sorted, with exact lengths. Crate
  `chacha20poly1305` `=0.10.1`, already pinned in the lockfile for the
  shielded model (no version moved).
- *Fails loudly:* unknown version (`UnsupportedVersion`), too short
  (`Truncated`), wrong key, wrong network or a modified or cut-short
  ciphertext (`Undecryptable`: the AEAD cannot tell these apart), a bad
  inner encoding (`Malformed`, `WrongNetwork`), another identity's or
  another kind of responder's snapshot (`WrongIdentity`). A caller must
  never start with an empty gate because a snapshot did not open.
- *Persist before reply* (documented in `wire.rs`): after
  `ResponderEvent::Established` (a grant committed) the caller writes the
  snapshot durably (`snapshot::write_atomically`: temporary file, flush,
  rename, and on Unix a directory flush) before sending the ACK; likewise
  after recording an invitation, blocking, unblocking or removing a
  contact. A WELCOME changes nothing persistent. A crash after the commit
  but before the snapshot leaves the invitation unused on disk, and since
  no ACK went out, the caller's retry is simply answered again (tested).
- *Not persisted:* live sessions and unconfirmed handshakes; callers
  handshake again after a restart.
- *Tests* (`tests/snapshot.rs`, unit tests in `snapshot.rs`): round trip
  across a restart; a consumed or revoked invitation refused after a
  restore (and, as a control, accepted by a responder that lost its state);
  the crash case; pruning at expiry plus skew; every loud failure; the
  atomic write. Every new rule was broken once and a test caught it.
- *Not done:* the demo does not persist its gate (its responders live for
  one run); multi-device state (above); the storage key's own protection
  (an operating-system key store) is the caller's job.

## Inbox key rotation: the forward-secrecy half of CRIT-02 (2026-11-21, unreviewed)

A stranger's note is sealed to the recipient card's two inbox keys
(X25519 and ML-KEM-768). Before this change they lived as long as the
contact identity, so whoever later took them could read every recorded
note. Now (`anonymum-crypto::contact`):
- *Stable root:* the signing key (who the contact is) and the handshake key
  are unchanged. Rotating the handshake key would break existing contacts'
  calls; it is left for a separate change. (Done since: see "Handshake key
  rotation and contact key rollover" below; the names here are the
  originals, now `KeyEpoch`, `rotate_epoch`, `purge_expired`.)
- *Epochs on one grid:* `EPOCH_LEN` = 7 days; an epoch starts at a multiple
  of it (Unix seconds), so everyone's cards share the same boundaries and a
  card's validity does not say when its owner made or rotated it. A card
  is valid from `CLOCK_GRID_BACKDATE` (1 day) before its epoch starts until
  the epoch ends. The chain stamps a request's `created_at` as the start of
  its clock-grid window (P11, at most 24 hours wide), which can lie before
  the moment a fresh card was made; backdating by a day keeps a fresh card
  valid there, and absorbs a sender clock up to a day ahead (tested with
  6-second, 1-hour and 1-day windows across an epoch boundary).
  `card_within` narrows a validity but never beyond the epoch's.
- *Two slots:* `ContactIdentity` holds the active `InboxEpoch` (on the
  card) and at most one draining epoch. `rotate_inbox(now)` makes a fresh
  active epoch for `now`'s place on the grid, moves the old active one to
  draining, and drops an older draining epoch at once, whatever grace it
  had left (rotating twice in a row loses the oldest epoch's notes; tested).
- *Grace and purge:* `DRAIN_GRACE` = 26 hours: the 24-hour request
  lifetime (D2) plus 2 hours for gateway delivery and clock skew, counted
  from the draining epoch's `not_after` (a request created at the card's
  last valid second can still be read). `purge_expired_inbox(now)` drops
  the draining epoch once `now >= not_after + DRAIN_GRACE`; `open_note(...,
  now_secs)` tries the active keys, then the draining keys only while
  `now_secs < not_after + DRAIN_GRACE`, so an expired epoch is not used
  even before it is purged. A note that decrypts under the active keys but
  fails a later check is not retried.
- *Wiping:* both secrets of an epoch sit in `Zeroizing` buffers, wiped when
  the epoch is dropped; the ML-KEM decapsulation key is rebuilt per use
  from the seed and wiped on drop (`ml-kem`'s `zeroize` feature). Not
  covered: copies inside `snow`'s handshake state while a note is opened,
  copies the operating system makes (swap, hibernation), and the caller's
  stored copy. `ContactIdentity::to_secret_bytes` (version 1: signing,
  handshake, active epoch, draining flag, draining epoch; 178 or 290 bytes,
  decoded strictly) returns a zeroizing buffer, and after a purge it no
  longer contains the dropped epoch, but an older stored copy still does:
  the caller must overwrite it (for example with `write_atomically`).
- *Tests* (`tests/rotation.rs`, 7): (a) a note to epoch E-1 opens after
  rotating to E, to the last second of the grace, and only through the
  draining slot; (b) after a purge at `not_after + 26 h` it no longer
  opens, at any clock, and not after a store and restore; (c) rotating
  twice drops the oldest epoch; (d) a fresh card opens at the floored
  start of its window; the shared grid, the clamped card validity and the
  strict storage format. 15 mutations of the new rules were each caught.
- *Not done:* nothing rotates automatically (the caller decides when, and
  must publish the new card); `seal_note` does not refuse a recipient card
  that has expired, so a sender with a stale card can pay for a note that
  will not be read after the grace (the demo's `seal` checks the card
  first); the handshake key does not rotate, so callbacks still have no
  forward secrecy; the stored identity format is not yet encrypted by this
  crate (the demo writes it in the clear to a dev wallet file).

## Dummy payloads and callback timing: audit MED-03, review M2 and H6 (2026-11-21, unreviewed)

MED-03 said that all-zero dummy slots let anyone sort transactions by
type, and that an immediate callback ties the mixnet burst to the
acceptance block.
- *Dummy stranger notes* (`anonymum_crypto::dummy_note(network,
  now_secs)`, spec W4): a real v5 note made through `seal_note` from one
  fresh throwaway contact identity to another, with a random admission
  commitment, a random 96-byte route and an empty intro; every secret is
  dropped, so nobody can open it. Random bytes would not do: the note's
  X25519 ephemeral key always has a clear top bit and lies on Curve25519
  rather than its twist (and the ML-KEM ciphertext has structure of its
  own), which uniform bytes fail about three times in four. Tests
  (`tests/dummy.rs`): exact length, no blank field, fresh per call; no
  identity opens one; its ephemeral key passes the curve test
  (`curve25519-dalek`'s `to_edwards`, a dev-dependency already in the
  lockfile) like a real note's, while random strings fail it. Whether the
  rest of the note (ML-KEM ciphertext, Noise ciphertexts) is equally
  indistinguishable is believed, not shown: question for the cryptographer.
- *Model slots* (`crates/shielded-model/src/build.rs`): no slot defaults to
  zeros any more. An unused coin slot (200 bytes) gets fresh random bytes
  (`rand_core` 0.6.4 with `getrandom`, already in the lockfile), the same
  distribution as a ChaCha20-Poly1305 ciphertext of that length. An
  unused stranger slot takes the caller's dummy
  (`TxBuilder::dummy_stranger_note`); without one it gets random bytes,
  which the model accepts but production wallets must not rely on: they
  MUST pass `dummy_note()`. The model has no runtime dependency on
  `anonymum-crypto` (a dev-dependency for one end-to-end test). Tests
  (`tests/dummy_slots.rs`): Transfer, Claim, Decline and Sender refund as
  built have no all-zero or low-variety slot; dummies are fresh per
  transaction; each branch is accepted, its stranger note is pruned after
  24 hours, and the logged digest still equals the bound one; a real
  `dummy_note` passes through unchanged. A caller can still pass an
  all-zero slot explicitly; the chain cannot refuse it without refusing
  some real ciphertext.
- *Callback jitter* (`crates/nym/src/jitter.rs`, W2): before Bob calls back
  after reading a stranger's note he waits a delay drawn uniformly
  (rejection sampling over the operating system's randomness, millisecond
  steps) from 30-300 s by default; `--jitter MIN-MAX` sets the range in
  seconds (at most 300, so the demo stranger's 600-second wait still
  covers the call and its retries) and `--no-jitter` waits nothing, for
  local runs (`e2e.mjs` passes it). Unit tests check the default, both
  ends of the range, the rejection of biased values, zero-delay mode and
  bad arguments; they run with `cargo test -p anonymum-nym`, which CI
  does not run (CI type-checks them with `--all-targets`). A delay of
  minutes blurs the link in a busy network, not in a small one, and the
  distribution is a placeholder for the cryptographer (W2).
- *Mutation checks:* 14 deliberate breaks (random-byte, all-zero or fixed
  dummy notes; zero or partly zero slots; the caller's dummy ignored; the
  hash over another slot; no rejection sampling; an off-by-one range;
  wrong defaults; missing argument checks), each caught.
- *Not done:* refund and change-spending delays (W2); the demo itself
  builds no shielded transactions, so nothing yet passes `dummy_note`
  outside tests.

## Fee changes and one-time refund keys: audit HIGH-03, I8/H1 and I13/H5 (2026-11-21, unreviewed)

The audit's HIGH-03 joined two findings: a change of the base fee `F`
strands open escrows (I8, H1), and the derived refund needs a refund key
the resolver cannot exploit (I13, H5). The owner asked for the max-fee
design; the spec records it as O9 and the new P4.

- *Fee ceiling* (`chain.rs`, `objects.rs`): an Open needs
  `fee_reserve >= F` (was `= F`; `FeeReserveWrong` below `F`). The wallet
  default is `FEE_CEILING_MULTIPLE * F` = `2 F` (`build::default_fee_reserve`,
  a placeholder). `Chain::set_base_fee` models a fee change by runtime
  upgrade; every transaction still pays today's `F` publicly.
- *Surplus* (`fee_reserve >= F`): no top-up note may be spent (`TopUpWrong`).
  Decline and Sender refund must create `derived_refund(escrow, position,
  F)`, worth `price - penalty + (fee_reserve - F)`. A claim with a surplus
  must create `derived_claim_surplus`, an ordinary note of
  `fee_reserve - F` to `refund_to` with the derived refund blinding
  (`SurplusNotDerived` otherwise); with no surplus the slot stays unused
  as before.
- *Top-up* (`fee_reserve < F`): the resolution must spend one ordinary
  top-up note (authorised by its owner, like any input) and may create
  one ordinary change note; conservation pins its value. The sender's
  outcome is as at `F = fee_reserve`. No escrow is stranded, but a
  resolver without coins cannot settle until they have some.
- *Conservation* is unchanged in form for all six branches:
  `sum(inputs) = sum(ordinary outputs) + sum(escrow outputs: price +
  fee_reserve) + sum(retired outputs) + F`; the harness checks the supply
  after every accepted transaction.
- *Builder:* `TxBuilder::resolution(chain, branch, escrow, created_at,
  position, authority, top_up, salt)` fills the fixed slot layout (input 0
  escrow, input 1 top-up or dummy; output 0 payout or refund, output 1
  claim surplus or penalty, output 2 change) and `dummy_output()` keeps a
  slot unused.
- *Wallet* (`wallet.rs`): `escrow_status` reads the fee from the consuming
  transaction (public), so it finds a refund or a claim's surplus
  (`EscrowStatus::ClaimedWithSurplus`) even after a later fee change;
  `refund_states` tracks either. `next_escrow_keys` hands out the index one
  above the highest refund index any of the wallet's escrows on the chain
  uses (`KeysExhausted` at the top, never wraps); `prepare_escrow` refuses a
  `refund_to` already used by one of its escrows on the chain
  (`RefundKeyReused`); `seal_recovery` refuses a refund path whose purpose
  is not `REFUND_PURPOSE` or whose key equals the cancel key
  (`NotAOneTimeRefundKey`). The H2 tests (any index, sparse indices) still
  pass: they use distinct `"refund"` indices.
- *Tests* (`tests/fee_changes.rs`, 18): (a) `F` rises to 11, 15 and 20
  with a reserve of 20: Claim, Decline and Sender refund settle and return
  exactly `reserve - F`; a needless top-up is refused. (b) `F` rises above
  the reserve (21, 35; and 20 over a reserve of 10): each branch settles
  with a top-up and returns exact change; without one it cannot balance;
  an exact top-up leaves no change; a short one, someone else's note, or a
  second change note is refused. (c) `F` falls (9, 4, 1, 0) over reserves of
  10 and 20: the whole surplus comes back and value is conserved; a
  transaction built at the old fee is refused (`WrongBaseFee`). (d) a
  decline whose refund has a random, zero or wrong-position blinding, or
  whose surplus is split off to the recipient, and a claim whose surplus
  has a random blinding, the wrong owner, is retired, or is folded into the
  payout, are all refused at no charge. (e) two escrows of one wallet get
  distinct one-time `refund_to` keys (a restored wallet continues above
  them); reused, long-term or cancel-equal refund keys are refused; for a
  refund and a claim surplus, nothing the recipient knows spends the note
  or reproduces the nullifier the sender's spend publishes. Also: a
  resolution without a top-up may not add even a zero-value note, and the
  claim surplus's blinding is the seed-and-position one.
- *Mutation checks:* 18 deliberate breaks (reserve back to `= F`; the
  top-up rule removed or loosened; change allowed without a top-up; claim
  surplus not required, leftovers or extra decline notes unchecked; the
  surplus missing from the refund, with the escrow's blinding or the
  recipient as owner; the wallet reading today's fee or ignoring claim
  surplus; refund purpose, refund-equals-cancel or reuse unchecked; the
  next index reused or wrapping; default reserve of `F`). The first run
  missed four (extra zero-value notes, surplus blinding source); two tests
  were added and all 18 are now caught.
- *Not checked:* that a circuit can express these rules cheaply, or that a
  two-input resolution (with a top-up) cannot be told apart from others by
  its proof (question 4); fee levels and the ceiling are placeholders.

## Handshake key rotation and contact key rollover (2026-11-21, unreviewed)

The inbox rotation above left the handshake key long-lived, so a recorded
IK message 1 (an ordinary HELLO, or the callback after a stranger's note)
stayed readable by whoever later took the answerer's device. Now
(`anonymum-crypto::contact`, `wire`, `gate`):
- *One ring for both:* the handshake key moved into the epoch, now
  `KeyEpoch` (handshake, inbox, ML-KEM seed, validity; was `InboxEpoch`).
  `rotate_epoch(now)` (was `rotate_inbox`) makes all three fresh;
  `purge_expired(now)` (was `purge_expired_inbox`) drops and wipes all
  three draining secrets once `now >= not_after + DRAIN_GRACE`. Only the
  signing key is long-lived. The card publishes the active epoch's
  handshake key; `handshake_key_for(public, now)` finds the active or
  still-draining secret for a key a card named (a caller calling back with
  the exact key it handed out).
- *Storage format 2:* `version || signing (32) || active epoch || flag ||
  [draining epoch]`, an epoch `handshake (32) || inbox (32) || seed (64) ||
  not_before || not_after` (178 or 322 bytes), decoded strictly. **Version
  1 is still read**: its single handshake key becomes the handshake key of
  both stored epochs (which is what their cards published), so existing
  contacts keep reaching it; it is written back as version 2, and the next
  rotation gives the new epoch a fresh key. A one-epoch buffer has the
  same length in both versions; the version byte tells them apart.
- *Responder (H1):* holds the active key and, with its grace end, the
  draining key (`Responder::for_identity`, `restore_identity`, the new
  `for_callback_identity` / `restore_callback_identity`; `refresh_keys(&me)`
  after a rotation or purge, refusing another identity's keys). A HELLO is
  read with the active key; only a Noise decryption failure falls back to
  the draining key, and only before its grace ends. A HELLO the active key
  opened (refused by the gate, or a weak caller key) is final. The
  draining key is dropped at the end of its grace by the responder itself,
  judged by the gate's clock floor, so neither a clock set back nor a
  refresh from an identity that has not purged yet brings it back. The
  plain `for_callback(key, ...)` is unchanged (one key).
- *Callback (H2):* a stranger who rotates right after sealing a note (the
  note's card naming the old handshake key) is still called back through
  `for_callback_identity` until the old epoch's grace ends; after the
  purge a recorded callback message 1 no longer opens on her device.
- *Rollover (H3):* the gate's contacts carry an optional contact signing
  key and an optional retire time. `Responder::bind_contact_card(card)`
  records the signing key for the contact or expected callback held by the
  card's handshake key (card verified at `now`; a key bound to another
  signer, or a signer already bound to another current key, or a blocked
  key, is refused); a callback's binding is carried into the contact on
  commit. `roll_contact_key(card)` verifies the card at `now`, finds the
  current contact bound to its signing key, moves its grant to the card's
  handshake key, and keeps the old key admitted for `DRAIN_GRACE` from the
  rollover (calls already in flight finish); then it is pruned and its
  sessions dropped. The new key must not be blocked or held by another
  contact, callback or invitation. Blocking or removing one key of a
  rolled contact covers its other key. A card from another signing key, a
  forged or expired card, or one for another network is refused and
  changes nothing.
- *Snapshot format 2:* contacts gain a flags byte (bit 0 signer, bit 1
  retire time) and callbacks one (bit 0 signer); unknown bits are refused.
  Version 1 snapshots are still read (no flags), written back as 2.
- *Choices made where the request left room:* the old key is kept for a
  grace rather than replaced at once, timed from the rollover rather than
  from the old card's end (the gate does not keep cards); invitation
  holder keys (invitee-generated, per relationship) are not bound to a
  signing key and do not roll, so contacts made by invitation keep their
  caller key; `remove_contact` and `block` follow a rolled contact's keys.
- *Tests* (`tests/handshake_rotation.rs`, 16; 2 snapshot unit tests and 1 wire unit test):
  (a) an invited caller's HELLO to epoch E-1's key succeeds in the grace
  after rotating to E, and a stranger's callback to her old key likewise;
  (b) after the purge (or the responder's own grace end, at any later
  clock, after a restore) a recorded HELLO or callback to E-1 fails to
  decrypt; (c) a new card from the same signing key rolls the contact
  forward, survives a snapshot, keeps the old key for the grace and then
  drops it with its session, and works again at the next rotation; cards
  from another signing key, forged, expired or foreign ones are refused, a
  stolen handshake key cannot be rebound to another signer, a blocked new
  key cannot be taken; (d) a HELLO the active key opened but the gate
  refused reports `Unauthorised`, not a draining-key decryption error, and
  one from a small-order caller key reports `WeakKey` on either slot.
  Plus: version-1 identities and snapshots load; strict flags; removing
  or blocking a rolled contact covers its retiring key; a blocked contact
  cannot roll itself back in; one signing key binds to one current key;
  the retire time holds in `authorise` and `admits` even without a pruning
  pass.
- *Mutation checks:* 37 deliberate breaks across the ring, the storage
  format, the responder's fallback, the callback listener, binding,
  rollover, retirement, pruning and both snapshot formats. The first run
  missed eight: six were real gaps (fallback on a non-decryption read
  error; `remove_contact` over both keys; retired sessions dropped at the
  expiry pass; one signer on two keys; binding a blocked key; **a blocked
  contact rolling to an unblocked new key**, which the code already
  refused but no test showed), plus the retire time in `admits` and
  `authorise`. Tests were added and all are caught now, except one pair
  that is redundant by design: the grace check when reading a HELLO and
  the drop of the draining key in `expire` each cover the other (`expire`
  runs before every HELLO), and removing both is caught.
- *Not done:* nothing rotates automatically, and nothing sends the new
  card to contacts (the application must, over a live session; until a
  contact has rolled, a caller should keep calling with its draining key,
  `handshake_key_for`); the callback remains classical; `snow`'s internal
  copies of the static key during a handshake are outside our control; the
  stored identity is not yet encrypted by this crate.

## Ephemeral first ratchet key and forward-only rollover (2026-11-21, unreviewed)

- *Ephemeral `dh_i0`:* CONFIRM now carries a fresh X25519 ratchet public key
  next to `seed_i`, inside the Noise-sealed record (markers v5). The
  responder refuses a small-order `dh_i0` before the record counts (the
  attempt stays, so the real CONFIRM still works) and starts its ratchet
  against `dh_i0`. The caller uses the matching secret for its first DH
  step on the ACK. Each attempt has its own key. The caller's static IK key
  no longer enters the ratchet at all.
- *Forward-only rollover:* a bound contact or callback records its card's
  `not_after`. `roll_contact_key` refuses a card that does not end later
  (`ContactError::StaleCard`), before anything changes. A later card for
  the same handshake key only raises the mark; binding again never lowers
  it. Gate snapshot format 3 stores the mark; versions 1 and 2 are still
  read, with no mark (0).
- *Consequences, for the owner and the cryptographer:* (1) `rotate_epoch`
  twice in one weekly epoch gives a new key with the **same** `not_after`,
  so contacts refuse that card (`StaleCard`) until the next epoch's card:
  an emergency rotation after a suspected key theft cannot reach contacts
  early. A signed card sequence number would fix this but changes the card
  format. (2) A binding loaded from a version 2 snapshot has no mark, so
  its first rollover is unchecked. (3) The check is only as good as the
  signing key: whoever holds it can sign a later card.
- *Tests:* 3 wire unit tests (small-order `dh_i0`, a thief with the static
  secret and root key cannot open the first turn while the ephemeral key
  can, a fresh key per attempt), 1 snapshot unit test (version 2 load), and
  5 in `tests/handshake_rotation.rs` (newer epochs roll and survive a
  snapshot; older and same-`not_after` cards are refused with the gate
  unchanged; a retired key cannot come back; binding cannot lower the mark;
  a later card for the same key moves only the mark).
- *Mutation checks:* 19 deliberate breaks of the new rules (the `dh_i0`
  check, its use and freshness; the staleness check and its boundary; the
  mark on roll, bind, commit, save and load; older snapshot versions), all
  caught on the first run. The old design (both sides ratcheting from the
  static key, which still interoperates) was run against the thief test
  separately.

## Signed card sequence number (2026-11-21, unreviewed)

Resolves consequence (1) of the section above: an emergency rotation inside
one weekly epoch now reaches contacts at once.

- *Card:* format v4 (`anonymum/contact-card/v4`, 1,416 bytes) signs
  `seq: u64`. A fresh identity starts at a random non-zero `u32`, which
  does not reveal its age; `rotate_epoch` adds one with `checked_add` and
  fails with `SeqExhausted`, changing nothing, at the limit.
- *Note:* the embedded card carries `seq`, so the note grows from 1,787 to
  1,795 bytes (core, pallet, shielded model, scripts; runtime
  `spec_version` 7). The note's own version stays 5: the length and the
  card signature's domain both differ from the 1,787-byte layout, so the
  two cannot be confused. 1,787-byte notes are refused.
- *Gate:* `roll_contact_key` requires `new_card.seq > bound seq`, replacing
  the `not_after` comparison; the card must still verify at `now`.
- *Storage:* identity format 3 stores `seq`. Versions 1 and 2 load with a
  stable value hashed from the public signing key, so loading the same old
  file twice cannot look like a rollback. Gate snapshot format 4 stores
  `seq`; versions 1 to 3 load with no mark (0), and a version 3 `not_after`
  is dropped because it is not a sequence number.
- *Consequences, for the owner and the cryptographer:* (1) restoring an
  identity from an older backup reissues sequence numbers contacts refuse
  (`StaleCard`) until rotations pass the highest one they saw, so the
  identity must be persisted before a rotated card is published. (2) The
  gap between two cards shows a contact how many rotations happened,
  including emergency ones. (3) A binding from a snapshot older than
  version 4 accepts any validly signed v4 card on its first rollover.
  (4) The check is only as good as the signing key: its holder can sign any
  `seq`, including `u64::MAX`, which would stop that contact's later
  rollovers.
- *Tests:* 8 new (crypto 190): random non-zero start, +1 per rotation,
  overflow, signed and serialised `seq`, version 2 and 3 loads, two
  emergency rotations in one week, older and same-`seq` cards refused with
  the gate unchanged, and the note carrying `seq` under the card signature.
- *Mutation checks:* 32 deliberate breaks of the new rules, all caught.
  `smoke.mjs`, `e2e.mjs` and the live demo were not rerun.
