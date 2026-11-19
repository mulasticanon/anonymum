# Issues found while modelling the shielded spec

Raised while building `crates/shielded-model` against
`docs/shielded-spec-v0.md`. I1–I12 were found in v0.4 (2026-11-19); v0.5
resolves all but I8. I13–I14 are new in v0.5. Each entry says how it stands
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
| I13 | "Every note has a fresh secret blinding" vs the derived refund | **New in v0.5, open** |
| I14 | "Refunded after 24 hours" vs a refund valid at any time | **New in v0.5, open** |

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
v0.5 lists options as question 10 for the cryptographer. *Model:* `F` is
constant; a resolution needs `fee_reserve = F`.

## New in v0.5

**I13. The refund's blinding is not fresh.** Section 3 says every note of
every type carries "a fresh secret `blinding`". The refund note's blinding
is derived from `seed` and the escrow's position, so it is neither fresh nor
secret from the recipient, who knows the seed and can see the position.
It is still hidden from everyone else, and the recipient's knowledge of the
refund commitment is already question 8. Suggest section 3 names the refund
as the one exception and says who can recompute it.

**I14. "Refunded after 24 hours" no longer describes the rule.** O6 and P3
say a blocked or ignored stranger's escrow "comes back after 24 hours minus
the penalty". Since v0.5 the sender refund is valid at any time, so the
sender can take it back earlier, and nothing comes back on its own (P6).
Suggest wording such as: "the sender can take the refund, minus the
penalty, at any time; once 24 hours pass the recipient can no longer
claim, so an ignored request is then always refundable." This is wording
only; the model already implements the rule as v0.5 states it.
