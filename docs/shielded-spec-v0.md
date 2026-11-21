# Shielded money: specification v0.7 (draft for review)

Status: draft, 2026-11-19. Written to be reviewed by a cryptographer and to
drive a plain-Rust reference model. It is not a security design until it
has been reviewed. No circuit, ceremony or pallet change follows from this
document alone.

Background and evidence: `Shielded_Payments_Technical_Research_2026-11-19.md`
(the "research report"), especially sections 4, 5, 14 and 15.

v0.5 resolves the twelve issues the reference model raised
(`shielded-spec-v0-issues.md`, I1 to I12). Each change is marked with its
issue number.

Updated 2026-11-20 (still v0.7, all unreviewed): fixed asymmetric payload
slots and a prunable stranger-note slot (P10, section 4), the empty
admission record's zero fields enforced (W3), and a hybrid post-quantum
stranger note with one ML-KEM-768 key on the contact card (rules 2 and 4
of section 2a, W6).

Updated 2026-11-21 (still v0.7, unreviewed; audit HIGH-03): escrows lock a
fee ceiling instead of exactly `F`, so a change of `F` no longer strands
them (O9, P4, section 4; issue I8, review H1). The unused part of the
reserve returns to the sender in a derived note on every outcome, and a
fee above the reserve is covered by a top-up note from whoever resolves.
Each escrow's `refund_to` is a one-time key of its own (I13, review H5).

v0.6 takes in the findings of `design-review-2026-11-19.md` (an AI-written
review, not the human specialist review still required): a separate
contact identity (section 2a), key locators in the sender's recovery copy,
a stricter rule for finding refunds, and a fixed base fee for the
prototype (replaced by a fee ceiling on 2026-11-21, O9).

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
| O6 | Blocked or ignored strangers get no answer. The sender can take the refund, minus the penalty, at any time; after 24 hours the recipient can no longer claim, so an ignored request is then always refundable (P3; wording corrected for I14). | 2026-11-19 |
| O7 | Opening a request locks the price plus one base fee, so settlement is prepaid (P4). | 2026-11-19 |
| O8 | Claims stop at 24 hours; after that only a refund is possible (P5). | 2026-11-19 |
| O9 | Amends O7: an opening locks the price plus a fee *ceiling* of at least one base fee (wallet default `2 F`, a placeholder). What the resolution does not need returns privately to the sender on every outcome, including a claim; if the fee has risen above the reserve, whoever resolves adds a top-up note (P4; I8, H1). Requested by the owner with the HIGH-03 work. | 2026-11-21 |

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

**P3. Blocking is local.** A blocked or ignored stranger gets no answer.
They can take their refund, minus the penalty, at any time; once 24 hours
pass the recipient can no longer claim. Nothing comes back on its own
(P6). The chain cannot
refuse them in advance.

**P4. Resolution fees are prepaid, up to a ceiling (O9).** Opening an
escrow locks the price plus a reserve `fee_reserve >= F`, where `F` is the
base fee at opening; wallets lock `2 F` by default (a placeholder until a
fee policy exists). Whoever resolves the escrow pays the base fee `F` in
force *at resolution* from that reserve, so a claim pays the recipient the
full price and a refund never strands a sender who has no other coins.
`F` may change while escrows are open (I8, review H1):

- `fee_reserve >= F`: the surplus `fee_reserve - F` goes back to
  `refund_to` privately. A decline or sender refund folds it into the
  refund note; a claim returns it in a separate note. Both notes have the
  derived refund blinding, so the sender finds them without help and the
  resolver cannot pick a blinding the sender does not know. No top-up note
  may be spent.
- `fee_reserve < F`: the resolution must spend exactly one ordinary top-up
  note of the resolver's, worth at least `F - fee_reserve`; its change goes
  wherever the resolver likes. The sender's outcome is the same as at
  `F = fee_reserve` (no surplus). No escrow is ever stranded, but a
  resolver with no coins of their own cannot settle until they have some.

The public fee of every transaction is still today's `F`, the same for all,
so a resolution does not mark itself by paying an old fee. Whether the
hidden surplus or top-up creates a linkage is question 4.

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
unspendable note, never published as an amount. It is computed on the
price alone: the reserve's surplus (P4) comes back in full.

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

**P10. Encrypted payload slots (sizes proposed 2026-11-20, unreviewed).**
Every transaction carries exactly three slots, the same in every branch:
two *coin-note* slots of 200 bytes (a note's delivery data, or the
sender's recovery copy) and one *stranger-note* slot of 1,795 bytes, sized
for the hybrid post-quantum note (format v5: admission commitment 32,
ML-KEM-768 ciphertext 1,088, Noise Xpsk0 message 667). A slot with nothing
to carry holds a dummy of the same shape (W4). The stranger-note slot is
prunable (section 4). The sizes and the encryption suite remain for the
cryptographer to confirm.

## 2a. Contact identity (new in v0.6; review findings H3, H4)

Today's prototype uses the wallet's own address as the identity in the
messaging handshake and in the stranger's note. In the shielded design
that would give callers and infrastructure a reusable wallet identifier,
whatever the payment proofs hide. Rules:

1. **Two separate identities.** A wallet's money keys (spending, viewing,
   nullifier secrets) and its contact identity (a signing key and an
   encryption key) are generated independently. Nothing in a contact
   identity can spend, view balances or compute a nullifier. A user may
   hold several contact identities.
2. **Contact card.** What a user hands out or lists publicly, signed by
   the contact signing key: that signing key, a handshake key, an inbox
   key for sealed notes, a post-quantum inbox key (ML-KEM-768, 1,184
   bytes; added 2026-11-20), the network, a price and a validity period.
   The keys have separate roles and none is a wallet key. The signature
   covers a 32-byte hash of the post-quantum key
   (`BLAKE2s("anonymum/pq-inbox-key/v1" || key)`), not the key itself, so
   a note can carry the hash in place of the key. Prototype card: 1,416
   bytes. The handshake key has no post-quantum counterpart: post-quantum
   callbacks are to be negotiated off-chain later.
3. **Handshake: answer only authorised callers.** (Rewritten in v0.7.
   v0.6 said the caller should prove it knows the answerer's contact key.
   That is not enough: anyone can know a public card. Correction from the
   owner's ChatGPT consultation of 2026-11-20.) Before sending any reply,
   the answering side checks that the caller controls a key it has
   authorised: an invitation it issued, a request it accepted, or an
   existing contact, still valid and not blocked. Otherwise it sends
   nothing at all: no handshake reply, no credential, no error.
   - Proposed pattern: Noise IK. The caller already holds the answerer's
     handshake key (from the card, invitation or note). IK lets the
     answerer read the caller's authenticated key in the first message and
     decide before replying. Noise XX (the prototype's pattern until
     2026-11-20, now replaced by IK there) makes the answerer reveal
     itself first; Noise XK would make it reply before learning who is
     calling.
   - Invited caller: the answerer checks the caller's key against the
     invitation or contact list, and block status, before message 2.
   - Paying stranger: reverse rendezvous is kept. The stranger's sealed
     note carries a fresh callback handshake key and a throwaway route.
     Once the recipient's claim is final, the recipient calls. The
     stranger is now the answering side and replies only if the caller is
     the recipient they addressed.
   - Uninvited caller: gets no reply.
   - The reference to the accepted request travels inside the encrypted
     first message, never in a clear header.
   - Known cost of IK, for the cryptographer (question 11): the first
     message can be replayed, and if the answerer's handshake key is later
     compromised, a recorded first message reveals the caller's key and
     that message's contents. So: caller keys scoped to one relationship
     or request; a minimal first-message payload; an invitation is
     consumed and a caller treated as present only after a fresh session
     confirmation; a replayed first message must not reopen a blocked
     contact or use an invitation twice.
4. **Stranger's note.** The recipient opens it with their contact
   encryption key alone. The sender's contact identity and the throwaway
   reply address are inside the ciphertext, not needed to open it. The note
   is bound to the admission record of the same transaction. Nobody
   holding only the recipient's public contact card can tell that a note is
   addressed to them (question 12).
   - **Deniable sender authentication** (owner decision, 2026-11-20; I27,
     prototyped, unreviewed). The recipient is convinced who sent a note
     but cannot prove it to anyone else. Prototype: one Noise X message
     whose sender static key is the sender's contact handshake key, which
     Noise X authenticates by Diffie-Hellman rather than by a signature;
     the rest of the sender's signed card travels inside, so the recipient
     learns the contact identity (the card's signature covers the card, not
     the act of contacting).
   - **Hybrid post-quantum confidentiality** (format v5, 2026-11-20,
     prototyped, unreviewed). The sender encapsulates to the recipient's
     post-quantum inbox key (ML-KEM-768); the ciphertext is bound into the
     Noise prologue and the shared secret is the Noise pre-shared key
     (`Noise_Xpsk0`). Reading a note needs both inbox secrets. Sender
     authentication stays classical (X25519). The note field is 1,795
     bytes.
   - **The cost.** Anyone holding the recipient's X25519 inbox secret can
     make a note that opens as if from any sender whose card they have
     (encapsulating to the public post-quantum key needs no secret).
   - **The callback is answered by the key the note authenticated.** The
     recipient calls the sender's handshake key itself, so a forger holding
     only the inbox secret cannot complete the callback. There is no
     separate per-request callback key any more (see I16).
   - **The sender's card must be valid at the request's creation time**
     (the time the request was created on chain, read from chain state).
     It may expire before the recipient opens the note; a card expired or
     not yet valid at creation is refused.
   - Forward secrecy for notes is still open.
5. **Invitations** are issued by a contact identity to a holder key, and
   name the network, an expiry and the purpose. The recipient's app checks
   them and records which ones it has honoured.
   - **Revocation cancels every grant** (owner decision, 2026-11-20).
     Removing a contact or blocking a key ends its sessions, drops any
     cached replies, and cancels any unused invitation and any outstanding
     callback grant for that key, all in one step. A cancelled invitation
     can never be used again, and unblocking restores nothing: a closed
     channel needs a new invitation to reopen.
6. **The session is tied to the request.** Both sides mix the accepted
   request's identifier into the session, so a session cannot be passed
   off as belonging to a different paid request.

The handshake and note format in `crates/crypto` may be prototyped on
these rules, using only standard Noise patterns through the library's
public interface. They stay marked unreviewed until the cryptographer has
answered questions 11 and 12.

## 2b. Wallet and network behaviour rules (proposed, unreviewed)

Added 2026-11-20. These rules govern what a wallet does, not what the
chain checks. A protocol that hides contacts and amounts on-chain still
leaks them if wallets query, time or pad carelessly. All of this is
proposed and unreviewed; the cryptographer is asked to confirm or replace
each rule (issues file, W1-W6).

**W1. Chain access.** A wallet never asks a node about a specific
nullifier, commitment, admission record, request or block of interest.
It downloads the same data every other wallet downloads (every block, or
every leaf, nullifier and payload of a range) and searches it locally, or
it fetches over the mixnet. A query that names a value the wallet cares
about tells the node which value that is. *The prototype breaks this rule
by design:* `e2e.mjs`, `smoke.mjs` and the demo read specific requests,
keys and block timestamps directly from a local node to check results.

**W2. Timing.** A wallet adds a random delay before each action that
follows a public event, so the action's timing does not link it to the
event:
- before calling back after a claim (or acceptance) is final;
- before a sender refund after expiry, and never in the first block in
  which the refund becomes possible;
- before spending change from an Open: never in the next block.
The delay distributions are left to the cryptographer.

**W3. Every transaction carries one admission commitment, and the empty
one is indistinguishable from a real one.** Transfer, Claim, Decline and
Sender refund each carry the commitment to an *empty* admission record
(tier "none", zero contact key and request digest, no escrow) whose
blinding is fresh, secret and uniformly random, drawn by the wallet for
that transaction alone: never derived from anything public, never reused.
With a hiding commitment, an empty record's commitment then looks exactly
like a stranger's or an invited request's. (Section 3 already says every
transaction carries one that "looks the same"; this rule states how.) The
chain can and does check the part that is not secret: a Transfer, Claim,
Decline or Sender refund whose admission record has a non-zero contact
key or request digest is rejected at no charge (in the reference model,
`Reject::NonEmptyAdmission`, 2026-11-20). The blinding cannot be checked.

**W4. Dummy note slots.** A payload slot that carries no note holds a
real note-shaped object built exactly like a real one: in the
stranger-note slot, a format v5 note (ML-KEM-768 encapsulation to a fresh
random post-quantum key, then the Noise Xpsk0 message from a fresh random
static key to a fresh random inbox key), at the full length. Not random
bytes: neither an X25519 public key nor an ML-KEM ciphertext is a
uniformly random string, so random bytes can be told apart from a real
note.

**W5. One pool.** Transfers, invited requests and stranger escrows share
one note pool and one public fee structure (one identical base fee, O3).
No transaction type gets a separate pool, tree or fee.

**W6. Open questions** (recorded, not decided): hybrid post-quantum key
exchange for handshakes and callbacks (for notes it is now prototyped:
format v5, one ML-KEM-768 key per card, 1,416-byte cards and 1,795-byte
notes), and whether the note's construction is right, before the note
format is frozen; inbox and handshake key rotation and how a rotated key
is still recognised as the same contact; a persistently connected wallet
versus a throwaway listener; the mixnet client's cover traffic; message
retrieval at scale (oblivious message retrieval, fuzzy message
detection), as roadmap only. Details in the issues file.

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

The one exception is the note owed to the sender when an escrow resolves
(section 4): the refund of a decline or sender refund, or the fee surplus
of a claim. Its blinding is derived from the escrow's seed and position, so
both escrow parties can recompute its commitment. It stays hidden from
everyone else (I13; question 8). Its owner `refund_to` is a one-time key
used by no other escrow, and spending it needs that key's secret, from
which alone (with the commitment and position) its nullifier is derived:
knowing the seed, the blinding and the commitment does not let the
recipient spend it or recognise its nullifier (review H5; the model tests
this, a circuit must enforce it).

- **Ordinary note**: `(value, owner, blinding)`.
- **Escrow note**: `(price, fee_reserve, recipient, refund_to,
  canceller, seed, blinding)`.
  - `recipient`: authority that may claim or decline.
  - `fee_reserve`: at least `F` at opening (P4); its surplus over the fee
    at resolution returns to `refund_to`.
  - `refund_to`: owner of the refund note and of a claim's fee surplus: a
    fresh one-time identity of the sender's, never reused across escrows
    (I13).
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
- three encrypted payload slots of fixed sizes: two coin-note slots and
  one stranger-note slot (P10);
- a validity window `[not_before, not_after)`: one cell of the single
  window grid in P11, half-open (I1);
- the admission record's commitment;
- the public base fee `F`;
- a proof that the hidden statement below holds.

Nothing public says which kind of transaction it is.

**The stranger-note slot is prunable** (proposed 2026-11-20, unreviewed).
Nodes keep each transaction's stranger-note slot for 24 hours from the
start of its validity window, then may discard it: a request lives 24
hours (O4), so no recipient needs the note afterwards. The tree, the
nullifiers, the admission commitment and the coin-note slots stay
permanent; pruning changes none of them.

**Every transaction carries a permanent stranger-note hash** (I28,
2026-11-20, unreviewed): `stranger_note_hash = H("stranger-note-slot",
slot)`, a 32-byte public field. The proof binds to this hash and to the
coin-note slots' bytes, never to the stranger slot's bytes (statement 6).
The chain checks that a submitted slot hashes to it and rejects the
transaction at no charge otherwise. So a node that syncs history after a
note was pruned can still recompute every transaction's binding from
permanent data. The model's hash is a BLAKE2s stand-in; the real one is
whatever the circuit uses (section 8).

Hidden statement, common part:

1. Every spent note is in the tree under the accepted root, and its
   nullifier is correctly derived.
2. The spender holds the authority the note type and branch require.
3. Types are respected: retired notes are never inputs; outputs are well
   formed; dummy slots carry no value.
4. All values fit their range; no arithmetic wraps.
5. Value is conserved:
   `sum(inputs) = sum(ordinary outputs) + sum(escrow outputs: price + fee_reserve) + sum(retired outputs) + F`.
6. The proof is bound to every public field: the coin-note slots' bytes
   and the stranger note's permanent hash (not its prunable bytes).

Branches:

| Branch | Spends | Creates | Authority | Time condition |
|---|---|---|---|---|
| Transfer | ordinary notes | ordinary notes; empty admission record (W3) | owners | none |
| Invited request | ordinary notes | change; admission record with tier "invited" and no escrow | owners | none |
| Open (stranger request) | ordinary notes | one escrow note with `fee_reserve >= F`; a retired note of `S`; change; admission record with tier "stranger" naming that escrow | owners | none |
| Claim | one escrow note; a top-up note only if `F > fee_reserve` | ordinary note of `price` owned by `recipient`; if `fee_reserve > F`, the derived surplus note of `fee_reserve - F` owned by `refund_to`; top-up change, if any; empty admission record (W3) | `recipient` (and the top-up's owner) | `not_after <= created_at + 24h` |
| Decline | one escrow note; a top-up note only if `F > fee_reserve` | derived refund of `price - penalty + max(0, fee_reserve - F)` owned by `refund_to`; retired note of `penalty`; top-up change, if any; empty admission record (W3) | `recipient` (and the top-up's owner) | none |
| Sender refund | same as Decline | same as Decline | `canceller` (and the top-up's owner) | none |

Slot layout (the model's builder; the proof does not depend on it): input
0 the escrow, input 1 the top-up or a dummy; output 0 the payout or
refund, output 1 the claim's surplus (else unused) or the penalty, output 2
the top-up change (else unused).

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
look for and spend it without receiving anything from the recipient. Its
value also includes the reserve's surplus over the fee the resolving
transaction paid, which is public. A claim's surplus note follows the same
rule (owner `refund_to`, value `fee_reserve - F`, the same derived
blinding), so a recipient who claims cannot keep or hide the sender's
surplus either. The
alternative protocol instead proves inside the transaction that the
encrypted copy sent to the sender is correct, which is far more expensive.
Which is sound is question 8 for the cryptographer.

In Claim, Decline and Sender refund the transaction's base fee `F` is
paid from the escrow's `fee_reserve`, so the conservation equation reads
`price + fee_reserve = outputs + F` when the reserve covers the fee (the
outputs include the surplus), and `price + fee_reserve + top_up = outputs
+ F` when it does not (the outputs include the change).

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
is not proven. The copy also records how to derive the refund identity and
the cancel authority (which key purpose and index), so a restored wallet
derives both directly and never has to search for them (review H2). The
copy sits in a coin-note slot together with a fresh random
nonce, so a restored wallet makes one decryption attempt per coin-note
slot, the same work as finding any other note (I11). To fit the 200-byte
slot, the copy records the escrow's price, reserve, recipient, seed and
blinding and the two key paths, but not the refund identity and cancel
authority themselves: the wallet derives both from the key paths, and the
escrow commitment confirms them when the escrow is found. The copy's first
plaintext byte is a version (1 today) naming both its layout and the
key-derivation scheme; a wallet refuses a copy of a version it does not
know rather than derive keys from it (2026-11-20, unreviewed). Version 1
leaves 11 bytes of the slot spare.

**Finding a refund.** A wallet does not look for the expected refund
commitment anywhere in history. It first finds the finalised transaction
that consumed the escrow's nullifier, then matches the derived refund
among that transaction's outputs, and tracks separately whether that note
is still unspent (review M1). A stranger-tier receipt can only come from
an Open: a refund whose penalty happens to equal `S` must never count as
one.

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
4. Does prepaying the resolution fee (P4) create any linkage? Since
   2026-11-21 the reserve is a ceiling: the surplus or top-up is hidden,
   but a resolution with a top-up spends two notes instead of one escrow;
   does that show through the proof's public shape or timing?
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
10. Changing the base fee `F` (I8). *Answered in the model on 2026-11-21
    (O9, P4):* each escrow locks a ceiling; the surplus returns privately
    in a derived note, and a fee above the reserve is covered by a top-up.
    Open for review: is the derived surplus note on a claim as sound as the
    derived refund (question 8), and does a two-input resolution leak
    anything (question 4)?
11. Is Noise IK, with the authorisation check before the first reply, the
    right replacement for Noise XX (which the prototype used until
    2026-11-20)? Are the mitigations for its
    replayable first message and weaker caller privacy (section 2a,
    rule 3) sufficient, and does a reply to a replayed authorised message
    leak availability in a way that matters?
12. What envelope should carry a stranger's note so that it opens with the
    recipient's contact key alone, carries the sender's identity inside,
    and cannot be recognised by anyone holding only the recipient's public
    contact card?

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
