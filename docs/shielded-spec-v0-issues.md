# Issues found while modelling shielded spec v0.4

Found while building `crates/shielded-model` (2026-11-19). Each item is a
place where `docs/shielded-spec-v0.md` (v0.4) is ambiguous, contradicts
itself, or cannot be implemented as written. The model did not guess
silently: where it had to choose so the rest could be built, the choice is
stated here and in the code, and is easy to change.

Numbers I1–I12 are referenced from the code.

## Contradictions and ambiguities that change behaviour

**I1. Validity windows: closed in section 4, half-open in P11.**
Section 4 writes the window as `[not_before, not_after]` and the claim
condition as `not_after < created_at + 24h`; P11 says the half-open
convention `[start, end)` is used everywhere. Read half-open, the claim
condition as written forbids a claim in the last window before the
deadline, even though every inclusion time in that window is before the
deadline. Read closed, `not_after` is the last allowed second and the
condition is right but contradicts P11.
*Model:* windows are half-open grid cells `[not_before, not_after)`; a claim
needs `not_after <= deadline`, a timeout `not_before >= deadline`. A claim
in the window `[deadline - W, deadline)` is accepted; one in
`[deadline, deadline + W)` is not.
Also open: section 4 says windows are "drawn from a small shared set", P11
defines one grid. *Model:* exactly one width, the grid width.

**I2. Timeout adds nothing over Cancel.**
Cancel and Timeout have the same authority (`canceller`), the same outputs,
and Cancel has no time condition, so anything a Timeout can do a Cancel can
do earlier. Either Cancel should be limited (for example to before the
deadline, or to the sender and recipient together), or Timeout should have a
different authority, such as a delegate who may only submit the fixed refund
(P6 mentions such a delegate later). *Model:* implements both as written.

**I3. How an ordinary note's nullifier is derived is not specified.**
Section 3 specifies only the escrow nullifier (`seed`, commitment,
position). *Model:* `H(owner secret, commitment, position)`, so only the
owner can compute it and two insertions of one commitment differ.

**I4. The value range is not specified.**
"All values fit their range" (common part, item 4) without a range or a
maximum supply. *Model:* each note value is a `u64`; sums are computed
exactly in 128 bits; an escrow's `price + fee_reserve` must fit a `u64`
(else `Overflow`).

**I5. Where the admission record lives is not specified.**
Section 3 says every transaction carries one; section 4's list of public
fields does not include it, and it is not a note, so it is unclear whether
it is a tree commitment, a public field or a payload, and how the
recipient's app is meant to find it. *Model:* a separate public commitment
field, not inserted in the tree.

**I6. `created_at`: block time or window start?**
Section 3 and P11 stamp `created_at` as the start of the window containing
the including block; section 4 says the chain "inserts new commitments with
the block time". *Model:* the window start (the including transaction's
`not_before`).

**I7. The form of a dummy output is not specified.**
"Dummy slots carry no value", but not what a dummy output commits to.
*Model:* a zero-value retired note with a fresh blinding, inserted like any
other output, so it cannot be spent and its commitment looks like any note.

**I8. Changing `F` strands open escrows.**
At opening `fee_reserve = F`; at resolution conservation reads
`price + fee_reserve = outputs + F`. If governance changes `F` while an
escrow is open, the escrow can no longer resolve as specified. *Model:*
`F` is constant, and a resolution requires `fee_reserve = F`.

## Gaps and cases the spec does not address

**I9. Refunds of twin escrows are identical.**
The refund's blinding is derived from `seed` alone. Two escrows with the
same `seed` (or one commitment inserted twice, which the position-bound
nullifier explicitly allows) produce identical refund commitments. Both stay
spendable, because ordinary nullifiers include the position, but the
recipient can tell them apart only by position. Deriving the refund blinding
from `seed` and the escrow's position would keep them distinct. Related to
the cryptographer's question 8.

**I10. Minimum price and parameter values are not specified.**
Nothing forbids `price = 0` (penalty 0; the surcharge is still retired),
and `F`, `S` and the window width have no values. *Model:* allows price 0;
uses `F = 10`, `S = 50`, a 1-hour window in tests (placeholders).

**I11. The recovery copy needs a way to find its nonce.**
"Encrypted to a key derived from the sender's backed-up wallet keys" leaves
key and nonce derivation open (question 9). *Model:* ChaCha20-Poly1305 keyed
from the master secret, nonce derived from the escrow commitment. A restored
wallet then has to try every payload against every commitment, which does
not scale; a real design needs a per-copy nonce or key that the wallet can
compute or find without that search.

## Observation (no change required)

**I12. The penalty constraint is implied by two others.**
Given the derived refund (`price - penalty` to `refund_to`) and the
conservation equation with `fee_reserve = F`, the single retired output must
equal the penalty. In the model, disabling the explicit penalty check made
no test fail, because nothing can reach it. A circuit could rely on the two
other constraints, or keep the explicit one as defence in depth; the
cryptographer should choose deliberately.
