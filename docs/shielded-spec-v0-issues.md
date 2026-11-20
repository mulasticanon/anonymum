# Issues found while modelling the shielded spec

Raised while building `crates/shielded-model` against
`docs/shielded-spec-v0.md`. I1–I12 were found in v0.4 (2026-11-19); v0.5
resolves all but I8. I13–I14 were raised by v0.5; v0.6 fixes their wording.
The design review of 2026-11-19 (`design-review-2026-11-19.md`) adds
findings H1–H7 and M1–M4, tracked below. I15–I26 were raised while
prototyping v0.7 section 2a in `crates/crypto` (2026-11-20); I27 is a
question for the cryptographer about one of those choices. Each entry says
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
| I8 | Changing `F` strands open escrows | **Open** (v0.5 question 10) |
| I9 | Refunds of twin escrows were identical | Resolved in v0.5 |
| I10 | Minimum price and parameter values | Resolved in v0.5 (parameter values still placeholders) |
| I11 | Recovery copy needed a nonce search | Resolved in v0.5 |
| I12 | Penalty constraint implied by two others | Resolved in v0.5 (check kept) |
| I13 | "Every note has a fresh secret blinding" vs the derived refund | Wording fixed in v0.6; **cryptographic question open** (question 8, review H5) |
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
as review H1. *Model:* `F` is constant; a resolution needs `fee_reserve = F`.

## Raised by v0.5

**I13. The refund's blinding is not fresh.** Section 3 said every note
carries "a fresh secret `blinding`", but the refund's is derived from `seed`
and the escrow's position, so both escrow parties can recompute its
commitment. *Wording fixed in v0.6:* section 3 names the refund as the one
exception. *Still open:* the cryptographic question of what the recipient
can learn from it (question 8; review H5 asks for owner-only serials and an
in-circuit constraint on destination, amount and blinding).

**I14. "Refunded after 24 hours".** O6 and P3 said an ignored stranger's
escrow "comes back after 24 hours", although the sender refund is valid at
any time and nothing comes back on its own. *Closed:* v0.6 rewords O6 and
P3 ("the sender can take the refund, minus the penalty, at any time; after
24 hours the recipient can no longer claim, so an ignored request is then
always refundable").

## Design review findings (2026-11-19)

| # | Finding (short) | Status |
|---|---|---|
| H1 | A changed base fee strands old escrows (= I8) | **Open.** `F` fixed for the prototype (v0.6 P4); the max-fee alternative needs the owner's decision |
| H2 | Restore did not cover the key indices the wallet can use | **Fixed in the model** (and v0.6): the recovery copy records purpose and index for the refund identity and the cancel authority; no search. Tested at `u64::MAX`, sparse indices and 40 escrows |
| H3 | Noise XX gives a reusable wallet credential to any initiating peer | Addressed in the prototype, unreviewed; spec questions 11 and 12 |
| H4 | The sealed note's prologue needs the stranger's address before decrypting | Addressed in the prototype, unreviewed; spec questions 11 and 12 |
| H5 | A resolver knows the deterministic refund; spend privacy and recovery need in-circuit guarantees | **Open cryptographic gate.** The model enforces the exact refund fields; it cannot show proof properties |
| H6 | Wallet-specific fetches, immediate callbacks and a small population can reveal correspondents | **Open deployment gate** |
| H7 | Circuit completeness, verifier validation, key privacy, setup and mobile proving are unproven | **Open release gate** |
| M1 | Wallet matched the expected refund commitment anywhere in history | **Fixed in the model** (and v0.6): the wallet finds the finalised transaction that consumed the escrow's nullifier, matches the refund among its outputs only, and reports separately whether it is unspent. Tested with an identical decoy commitment made earlier |
| M2 | All-zero padding payloads; receipts and invites replayable across devices | **Open.** The model still pads with zeros; receipt and invitation idempotency is not modelled |
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
| I23 | Rule 4: a note must not be recognisable from the public card. | Noise N gives that for the ciphertext, but its ephemeral key is a raw X25519 point, distinguishable from random bytes (not linkable to the recipient). Elligator-style encoding would need a vetted library. Question 12. |
| I24 | The shielded design's payload slot size (P10) is open; the note is now 587 bytes. | Recorded; the model's 204-byte slot is a placeholder and cannot hold it. |
| I25 | Whether an existing contact may call about anything, or only its relationship. | A contact's calls must name the reference recorded when it was admitted; any other reference gets nothing. |
| I26 | The transparent chain still requires a wallet-bound messaging key before it accepts a request, and records requests wallet to wallet. | Kept for the prototype chain (a known gap until stage 5). Notes are sealed to the card's inbox key and never use that key. |

**I27. The note's signature is transferable proof of who made contact (for
the cryptographer).** The prototype has the stranger sign the note with
their contact signing key (I22), so the recipient can tell a note does not
claim someone else's identity and has not been forwarded from another
recipient. But an Ed25519 signature convinces anyone: the recipient can
show the opened note, with the signature over the admission commitment and
the recipient's own inbox key, to a third party as proof that this contact
identity reached out to them, and when. For a messaging system whose
purpose is anonymity that is a real cost.
*Question:* should authentication that only the two parties can verify
replace the signature, so that the recipient is convinced but cannot
convince anyone else? For example, a Noise pattern that authenticates the
sender's static key by Diffie-Hellman (Noise X, or the K-family) instead
of a signature, or a designated-verifier signature. What does each cost
against the two attacks the signature guards: forwarding a note to a third
person as if written to them, and claiming another identity? Note that a
recipient who can verify alone can also forge such a note to themselves,
which is the point of deniability but means the note proves nothing to an
arbiter either. Does that interact with the admission record and the
escrow, where the payment itself is on-chain? *Prototype:* unchanged
(signature); this needs a decision.

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
| R7 | Bob's callback uses his card key (I16); the note signature is transferable (I27) | **Open, with the cryptographer**, unchanged by the owner's decision (see the open questions below) |
| R8 | In-memory grant state; no idle or callback expiry; pending expiry only on receive timeouts | **Partly fixed.** Answered handshakes expire after `PENDING_TIMEOUT` (180 s), sessions after `SESSION_IDLE_TIMEOUT` (30 min) without traffic, callback grants at their deadline, all checked against an injected monotonic clock on every operation. **Open:** durable and multi-device grant state, crash recovery of an invitation consumed while its ACK is outstanding |
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

- **Durable and multi-device grant state** (review finding 8). Invitations
  honoured, contacts, callbacks and blocks live in one process's memory.
  What must survive a restart, how two devices of one person agree that an
  invitation was used once, and how a crash between committing a grant and
  delivering its ACK is recovered.
- **Bob's callback uses his card's handshake key** (I16, review finding 7).
  A recorder of the callback's first message who later learns the callback
  secret learns Bob's key and the request reference. How should the
  stranger privately authorise a request-scoped callback key instead?
- **The note's signature is transferable proof of who made contact** (I27).
  Should authentication that only the two parties can verify replace it?
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
| A6 (CRIT-02, HIGH-03, MED-03, MED-04, CRIT-01) | Note signature and forward secrecy, refund blinding and fee, dummy payloads, durable state, the transparent chain and unproved model | **Recorded, not solved** (see below and earlier sections: I8, I13, I27, R8) |
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
- **No delay between claim finality and the callback.** The recipient
  calls the throwaway route as soon as the acceptance is final, so the
  timing links the chain event to the mixnet traffic. Random delay or batched
  callbacks are candidates.
- **Dummy payload slots must be indistinguishable from real ones.** The
  model pads with zeros (review M2), and its 252-byte slot cannot hold the
  587-byte note (I24): slot size and dummy content must be fixed together.
- **Post-quantum key exchange and ratcheting** remain long-term questions:
  no per-message forward secrecy (no double ratchet) and no post-quantum
  key agreement in sessions or notes.
