# Shielded money: specification v0.5 (draft for review)

Status: draft, 2026-11-19. Written to be reviewed by a cryptographer and to
drive a plain-Rust reference model. It is not a security design until it
has been reviewed. No circuit, ceremony or pallet change follows from this
document alone.

Background and evidence: `Shielded_Payments_Technical_Research_2026-11-19.md`
(the "research report"), especially sections 4, 5, 14 and 15.

v0.5 resolves the twelve issues the reference model raised
(`shielded-spec-v0-issues.md`, I1 to I12). Each change is marked with its
issue number.

A second, more detailed proposal exists in
`Shielded_Payments_Protocol_v0.1.md` (the "alternative protocol"). It shares
this document's core (one escrow note, two authorities, one nullifier,
prepaid resolution fee, hidden retirement) and differs mainly on P1 below.
Three things it got right that v0 of this document missed are now included
and marked *(from the alternative protocol)*. Section 8 lists the remaining
differences.

## 1. Decisions taken by the owner

| # | Decision | Date |
|---|---|---|
| O1 | Go for shielded money (stage 5b), with contact state moved off-chain. | 2026-11-19 |
| O2 | A cryptographer and external audits will be funded before any real value is at stake. | 2026-11-19 |
| O3 | Accounting: one identical public base fee on every transaction, visibly credited (burn share and node-pool share). Everything tied to a user's price is confidential: the price, the difference between invited and stranger contact, and the decline penalty. Period totals may be published later, once volume is high enough. | 2026-11-19 |
| O4 | Contact requests expire after 24 hours. | 2026-11-18 |
| O5 | The stranger surcharge is burned, not paid to node operators (P1). | 2026-11-19 |
| O6 | Blocked or ignored strangers get no answer and are refunded after 24 hours minus the penalty (P3). | 2026-11-19 |
| O7 | Opening a request locks the price plus one base fee, so settlement is prepaid (P4). | 2026-11-19 |
| O8 | Claims stop at 24 hours; after that only a refund is possible (P5). | 2026-11-19 |

## 2. Design rules

P1, P3, P4 and P5 are confirmed by the owner (O5 to O8). P2, P6, P7, P8,
P9 and P11 carry over existing rules or are technical consequences; the
owner has seen them and not objected, and they stay open to change. P10 is
open for the cryptographer.

These fill the remaining gaps in the report's gate 1. Each is the simplest
rule that keeps the privacy goal. The reference model is built on them;
changing one later means changing the model, which is cheap at this stage.

**P1. Strangers pay a surcharge, enforced by the recipient's app; the
surcharge is burned.** (Revised in v0.2. v0 proposed dropping the
surcharge; the owner's ChatGPT consultation of 2026-11-19 showed it can be
kept cheaply.)
- Every transaction pays the same public base fee `F`.
- A transaction may also carry a hidden tier flag. In the stranger tier the
  proof shows that an extra fixed amount `S` was retired, and that the
  request's receipt truthfully records "stranger tier".
- The recipient's app admits a request to the inbox only if it either
  comes with a valid invitation (checked by the app, outside the proof) or
  is in the stranger tier with the price escrowed.
- A stranger can put a cheap, uninvited attempt on-chain, but no honest
  recipient's app will show it.
- `S` is retired, not paid to the node pool. This keeps the tier hidden
  without a shielded treasury: the retired slot already exists for the
  penalty. Paying `S` to node operators instead would need shielded
  treasury notes, a merge action and a treasury viewing key whose holder
  could tell stranger requests apart. Decided by the owner: burned (O5).
- Invitations and price quotes are never verified inside the proof.

**P2. The recipient's price is enforced by the recipient's app.** The chain
does not know anyone's price. A wallet publishes a signed contact card
(contact key, price, validity period) off-chain. An offer below the price
is ignored by the recipient's app and times out.

**P3. Blocking is local.** A blocked or ignored stranger gets no answer;
their escrow comes back after 24 hours minus the penalty. The chain cannot
refuse them in advance.

**P4. Resolution fees are prepaid.** Opening an escrow locks the price plus
one base fee. Whoever resolves the escrow pays the base fee from that
reserve, so a claim pays the recipient the full price and a refund never
strands a sender who has no other coins.

**P5. Claims stop at the deadline.** The recipient can claim only before
24 hours have passed. After that only a refund is possible.

**P6. Refunds are submitted, not automatic.** After the deadline the refund
is claimable at any time, by the sender's app when it is next online. A
delegate service that can submit it for an offline sender is a later
feature.

**P7. Either side may end a request early; the first finalised action
wins.** Same as today's rule. A sender can cancel while the recipient's
claim is still unconfirmed.

**P8. Penalty: 1% of the price, rounded up, on every outcome except a
claim.** Same as today. The penalty is retired inside the pool as an
unspendable note, never published as an amount.

**P9. No public user balances.** Coins are shielded from the first
distribution. Validator and governance flows may stay public.

**P11. One clock grid.** Time is divided into fixed windows `[start, end)`
whose width is a whole number of block times and divides 24 hours exactly.
A note's `created_at` is the start of the window in which it was included,
not the raw block time, so every deadline `created_at + 24h` is itself a
window boundary. (A width that divides 24 hours is not enough on its own:
a note stamped at 12:00:06 would expire inside a window.) The same
half-open convention is used everywhere. A one-second window, as in the
alternative protocol's reference profile, would be includable in roughly
one block in six on a 6-second chain.

**P10. Encrypted payload size is open.** The current 427-byte note cannot
carry a quantum-resistant key exchange (ML-KEM-768 alone needs 1,088
bytes). The model treats payloads as opaque fixed-size slots; the size and
the encryption suite are for the cryptographer to fix.

## 3. Objects

All amounts are unsigned 64-bit integers in base units; sums are checked
and an escrow's `price + fee_reserve` must itself fit in 64 bits (I4).
There is no minimum price. With the penalty rounded up, a price of 1 to 99
units carries a penalty of 1 unit (I10). `H` is a domain-separated
hash. Authorities are public identifiers whose matching secret authorises
an action.

Every note of every type, including retired and zero-value notes, carries
a fresh secret `blinding`, so its public commitment reveals nothing and
cannot be guessed from a known amount. (v0.2 omitted this: a retired note
of the known surcharge `S` could have been recognised on-chain. Found in
the owner's ChatGPT review of 2026-11-19.)

- **Ordinary note**: `(value, owner, blinding)`.
- **Escrow note**: `(price, fee_reserve, recipient, refund_to,
  canceller, seed, blinding)`.
  - `recipient`: authority that may claim or decline.
  - `refund_to`: owner of the refund note (the sender, or a fresh identity
    of theirs).
  - `canceller`: authority that may take the refund at any time (the
    sender).
  - `seed`: secret shared by both parties, from which the escrow's single
    nullifier is derived.
- **Retired note**: `(value, blinding)`. Can never be spent.
- **Admission record**: `(recipient contact key, request digest, tier,
  escrow commitment or none, blinding)`. Its commitment is a separate
  public field of the transaction, not a leaf of the note tree (I5). Ties a fee tier to one request,
  one recipient and, for strangers, one escrow. Every transaction carries
  one; transactions that are not contact requests carry an empty one that
  looks the same.
- **Commitment**: `H(note)`, hiding because of the blinding. Public.
- **Leaf**: `H(commitment, created_at)`. `created_at` is stamped by the
  chain as the start of the validity window that contains the including
  block, so it always lies on the window grid (see P11). Every note of
  every type gets the same leaf shape.
- **Nullifier**: public, one per spent note. For an ordinary note it is
  derived from a secret only the owner holds, the commitment and the
  note's position, so nobody else can compute it or tell when the note is
  spent (I3). For an escrow note it is
  derived from `seed`, the commitment and the note's position in the tree,
  and is identical whichever outcome is used. Including the position stops
  two insertions of the same commitment sharing one identity. *(from the
  alternative protocol)*
- **Dummy nullifier**: an unused input slot still publishes a
  nullifier-shaped value. It must be derived in its own domain from a
  secret the prover knows, so nobody can publish a real pending nullifier
  in a dummy slot and get the genuine transaction rejected. *(from the
  alternative protocol)*

## 4. Transactions

Every transaction has the same public shape, with dummy entries padding
unused slots:

- accepted tree root, chain and version identifiers;
- a fixed number of nullifiers and of new commitments;
- a fixed number of encrypted payload slots;
- a validity window `[not_before, not_after)`: one cell of the single
  window grid in P11, half-open (I1);
- the admission record's commitment;
- the public base fee `F`;
- a proof that the hidden statement below holds.

Nothing public says which kind of transaction it is.

Hidden statement, common part:

1. Every spent note is in the tree under the accepted root, and its
   nullifier is correctly derived.
2. The spender holds the authority the note type and branch require.
3. Types are respected: retired notes are never inputs; outputs are well
   formed; dummy slots carry no value.
4. All values fit their range; no arithmetic wraps.
5. Value is conserved:
   `sum(inputs) = sum(ordinary outputs) + sum(escrow outputs: price + fee_reserve) + sum(retired outputs) + F`.
6. The proof is bound to every public field and to the payload slots.

Branches:

| Branch | Spends | Creates | Authority | Time condition |
|---|---|---|---|---|
| Transfer | ordinary notes | ordinary notes; empty admission record | owners | none |
| Invited request | ordinary notes | change; admission record with tier "invited" and no escrow | owners | none |
| Open (stranger request) | ordinary notes | one escrow note with `fee_reserve = F`; a retired note of `S`; change; admission record with tier "stranger" naming that escrow | owners | none |
| Claim | one escrow note | ordinary note of `price` owned by `recipient` | `recipient` | `not_after <= created_at + 24h` |
| Decline | one escrow note | ordinary note of `price - penalty` owned by `refund_to`; retired note of `penalty` | `recipient` | none |
| Sender refund | one escrow note | same as Decline | `canceller` | none |

`penalty = ceil(price / 100)`, constrained as integers. The explicit
penalty check is kept even though the derived refund and the conservation
equation already imply it (I12).

A claim in the last window before the deadline is valid; one in the window
starting at the deadline is not (I1).

**One sender-refund action, valid at any time.** v0.4 had separate Cancel
and Timeout actions with the same authority and the same effect, so
Timeout added nothing (I2). They are merged. Before the deadline it is an
early cancellation, after it a timeout refund; the effect is identical. A
delegate who may submit only the fixed refund for an offline sender (P6)
would be a new, separately authorised action in a later version.

**Unused output slots** hold a zero-value retired note with fresh blinding,
inserted like any other output (I7).

**Refunds must be recoverable by the sender.** *(problem identified by the
alternative protocol)* In Decline the recipient builds the refund note. A
malicious recipient could build one the sender can never find or spend,
destroying the sender's money at no cost. Proposed rule: the refund note is
fully determined by the escrow. Its owner is `refund_to`, its value is
`price - penalty`, and its blinding is derived from `seed` and the
escrow's position in the tree, so two escrows that happen to share a seed
still produce different refunds (I9). The sender
already holds all three, so their app can compute the exact commitment to
look for and spend it without receiving anything from the recipient. The
alternative protocol instead proves inside the transaction that the
encrypted copy sent to the sender is correct, which is far more expensive.
Which is sound is question 8 for the cryptographer.

In Claim, Decline and Sender refund the transaction's base fee `F` is
paid from the escrow's `fee_reserve`, so the conservation equation reads
`price + fee_reserve = outputs + F` with `fee_reserve = F`.

**The receipt is bound to the request.** The proof shows that the admission
record's tier matches what was actually retired, and that the escrow it
names is the one created in this same transaction. The recipient's app
opens the record and checks it names their own contact key and the request
they decrypted. A valid stranger-tier receipt therefore cannot be attached
to a different request, recipient or escrow.

**Public counters.** The only supply change visible per transaction is the
fixed burn share of `F`. Retired surcharges and penalties never move a
public counter.

**The sender can always recover their own escrow.** Each opening
transaction carries a copy of the escrow data, including `seed`, encrypted
to a key derived from the sender's own backed-up wallet keys. A wallet
restored from backup with no local history scans the chain, decrypts that
copy, and so recovers everything needed to take the sender refund or find a
refund. Writing this copy correctly is in the sender's own interest, so it
is not proven. The copy sits in a payload slot together with a fresh random
nonce, so a restored wallet makes one decryption attempt per payload, the
same work as finding any other note (I11).

**An admitted request is always claimable.** Before showing a request as
actionable, the recipient's app must recover the full escrow data and
check it against the finalised commitment: price, claim authority, payout
destination. Decrypting the message alone is not enough. A sender can fund
an escrow the recipient's app rejects as unreadable; that costs only the
sender.

**Transmitted bytes are bound.** The sender's authorisation covers the
exact encrypted bytes, so a relay that alters them invalidates the
transaction. This binds the bytes without proving how they were encrypted.

The chain, outside the proof:

- rejects a transaction if any nullifier was already used, or appears
  twice in it;
- checks the root is one it accepted, and that the including block's time
  lies inside the validity window;
- inserts new commitments stamped with the start of the current window
  (I6);
- credits `F` to the public burn and node-pool split.

## 5. Properties the model and tests must demonstrate

- **Conservation.** Over any sequence of valid transactions:
  `issued = spendable + in escrow + retired + public fees paid`.
- **One outcome per escrow.** No sequence resolves the same escrow twice,
  through the same or different branches.
- **Right party, right destination.** Only `recipient` can claim or
  decline; only `canceller` can take the sender refund; a refund can only go to
  `refund_to`; a claim can only go to `recipient`.
- **Receipt binding.** A stranger-tier receipt cannot be opened as valid
  for any other request, recipient or escrow.
- **Unlinkable refund.** Knowing the escrow `seed` gives the recipient no
  authority over the refund and no way to recognise when the sender later
  spends it.
- **Hidden notes.** No commitment, including retired and zero-value ones,
  can be recomputed from public values.
- **Tier honesty.** A receipt that says "stranger tier" exists only in a
  transaction that retired `S`; a transaction that did not retire `S`
  cannot produce one.
- **Recoverable refund.** After any Decline, the sender can find and spend
  the refund using only what they held when they opened the escrow.
- **Dummy slots cannot block others.** No value placed in a dummy input
  slot can equal a real note's nullifier.
- **Penalty cannot be avoided or redirected.** Every non-claim outcome
  retires exactly `ceil(price/100)`.
- **Retired value stays retired.**
- **Time.** No claim is included at or after the deadline; a sender cannot create an already-expired escrow.
- **No value from padding.** Dummy inputs and outputs cannot mint or hide
  value.
- **Replay.** A transaction valid on one chain or version is invalid on
  another.

## 5a. Encryption is not proven inside the proof

A sender who garbles the encrypted data they send only harms themselves:
an unreadable payment is money they lost, and an unreadable escrow opening
means the recipient cannot claim and the sender is refunded minus the
penalty. Zcash takes the same position: the recipient's wallet checks what
it decrypts against the public commitment and ignores anything that does
not match. The one case where a party could harm another, a refund built
by the recipient, is handled by deriving the refund from the escrow
(section 4). Whether any remaining case needs encryption proven inside the
proof is for the cryptographer.

One circuit serves every transaction type, so every transaction carries
the cost of the most expensive branch. Measure the whole common circuit,
with Open as the worst case, not a single cheap branch.

## 5b. First end-to-end acceptance test

Two phones, one escrow, price 101 base units.

1. The sender funds the request and goes offline.
2. The recipient declines, deliberately attaching unusable settlement
   data.
3. The sender's wallet is wiped of all local history and restored from the
   promised backup only.
4. The restored wallet must find and successfully spend a refund of
   exactly 99 units (`101 - ceil(101/100)`), with the settlement fee paid
   from the prepaid reserve.

Record proof time, peak memory, bytes downloaded and inclusion delay for
opening and for settlement. This one test exercises the rounding rule, the
offline refund, backup recovery of the escrow seed, and the decision not
to prove encryption.

## 6. Not covered in v0

Note encryption and discovery; the proof system and circuit; verifier
integration; the invitation and contact-card formats; delegated refunds;
period totals; migration of today's transparent prototype; node staking
and reward payout; network-layer privacy of submission and queries.

## 7. Questions for the cryptographer

1. Is a single shared `seed` the right way to get one nullifier across all
   escrow branches, and how do both parties obtain it safely?
2. Can a sender who knows the nullifier learn more than "my escrow was
   resolved"?
3. Is stamping `created_at` into every leaf sound, and do shared validity
   windows leak deadlines near expiry?
4. Does prepaying the resolution fee (P4) create any linkage?
5. Is the retired-note type the best way to burn confidentially, compared
   with a committed supply accumulator?
6. With P1, is any privacy lost by all transactions paying the same public
   fee into a public pool?
7. Which proof system should the circuit target, given the 2026 Orchard
   flaw and the Groth16 setup requirement?
8. Is deriving the refund note from the escrow `seed` sound? The recipient
   also knows the seed, so can recognise the refund commitment. Can they
   learn anything further, such as when the sender spends it?
9. How exactly should a restored wallet derive the key for its own
   recovery copy, and should `seed` be random or derived from the sender's
   keys?
10. Changing the base fee `F` (I8). An open escrow holds a reserve equal
    to the `F` of its day and its resolution must pay exactly `F`. If `F`
    changes, old escrows either cannot resolve or resolve at a visibly
    different fee, which marks them. Options: `F` is fixed for the life of
    a rules version; a change takes effect only for new escrows while old
    ones resolve under a rule that hides the difference; or the reserve is
    over-funded and the excess retired. Until this is settled, `F` cannot
    be changed on a network with open escrows.

## 8. How this differs from the alternative protocol

| Topic | This document | Alternative protocol |
|---|---|---|
| Network fee | One public base fee for every transaction; a hidden, burned surcharge for strangers (O3, P1) | Two confidential fees paid to a shielded treasury |
| Invites and price quotes | Checked by the recipient's app, never on-chain | Signatures verified inside the proof |
| Node pool income | Publicly credited | Shielded treasury notes, a merge action, a treasury viewing key that can tell stranger requests apart |
| Delivery to the other party | Derived from shared escrow data where possible | Encryption proven correct inside the proof, for nine containers |
| Hashing inside the proof | Left to the cryptographer | SHA-256 over notes, tree and the whole transaction |
| Penalty rounding | Up (owner's existing rule) | Down, so prices under 100 units carry no penalty |
| Validity window | Block-aligned (P11) | One second in the reference profile |

The alternative enforces more inside the proof and so gives the network a
second fee tier and consensus-checked prices. The cost is a much larger
proof statement (in-circuit signatures, verifiable encryption and SHA-256
are each expensive), which its own text identifies as possibly unusable on
a phone. Its test lists (sections 9 and 10) and its treatment of chain
integration, denial of service and wallet recovery are worth adopting
whichever design is chosen.
