# Issues found while modelling the shielded spec

Raised while building `crates/shielded-model` against
`docs/shielded-spec-v0.md`. I1–I12 were found in v0.4 (2026-11-19); v0.5
resolves all but I8. I13–I14 were raised by v0.5; v0.6 fixes their wording.
The design review of 2026-11-19 (`design-review-2026-11-19.md`) adds
findings H1–H7 and M1–M4, tracked at the end. Each entry says how it stands
and what the model does.

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
| H3 | Noise XX gives a reusable wallet credential to any initiating peer | **Open, needs a design decision** (spec section 2a, question 11). Handshake identity handling deliberately unchanged |
| H4 | The sealed note's prologue needs the stranger's address before decrypting | **Open, needs a design decision** (spec section 2a, question 12). Sealed-note format deliberately unchanged |
| H5 | A resolver knows the deterministic refund; spend privacy and recovery need in-circuit guarantees | **Open cryptographic gate.** The model enforces the exact refund fields; it cannot show proof properties |
| H6 | Wallet-specific fetches, immediate callbacks and a small population can reveal correspondents | **Open deployment gate** |
| H7 | Circuit completeness, verifier validation, key privacy, setup and mobile proving are unproven | **Open release gate** |
| M1 | Wallet matched the expected refund commitment anywhere in history | **Fixed in the model** (and v0.6): the wallet finds the finalised transaction that consumed the escrow's nullifier, matches the refund among its outputs only, and reports separately whether it is unspent. Tested with an identical decoy commitment made earlier |
| M2 | All-zero padding payloads; receipts and invites replayable across devices | **Open.** The model still pads with zeros; receipt and invitation idempotency is not modelled |
| M3 | Invalid handshake traffic could consume pending state | **Fixed in `anonymum-crypto`** for malformed, tampered, truncated and oversized frames and for a validly encrypted message 2 from an impostor, on both sides (see the note below). Reordered and delayed frames are covered only by the existing repeated-frame tests; the Nym demo's retry loop is unchanged |
| M4 | A cumulative fee sink double-counts once operator funds are live; deadlines narrow candidates | **Open.** Applies before operator payouts or migrations |

## Found while fixing the review findings

**`snow` restores only part of its state after a failed read.** `snow`
0.10 checkpoints its hash and chaining key before reading a handshake
message and restores them on failure, but not its cipher state. A message 3
that passes its first decryption, re-keys the cipher and then fails on its
payload leaves the responder unable to read the genuine message 3. (Message
2 escapes this by accident: its first key step overwrites the cipher key.)
*Workaround in `anonymum-crypto`:* a handshake keeps a recipe (static key,
a per-handshake ephemeral key from `snow`'s own generator, the transcript)
and rebuilds a fresh `snow` state for every read attempt, so a failed
attempt changes nothing. This uses `snow`'s `#[doc(hidden)]`
`fixed_ephemeral_key_for_testing_only`, whose warning is against reusing an
ephemeral key across sessions; here each key serves one handshake only.
*For the cryptographer:* accept this, or prefer a `snow` change that also
checkpoints the cipher state (worth reporting upstream either way).
