# Step 5: hiding who talks to whom

Design options and a recommendation. Research note, 2026-11-18. Nothing here
is implemented. No code should be written from this until the owner has
chosen a direction.

**Update 2026-11-19:** the owner is leaning towards stage 5b. A much deeper
study is in `Shielded_Payments_Technical_Research_2026-11-19.md` (same
folder). Where the two disagree, that study is the better source. One
correction to this note is marked below.

## The claim to aim for

"Anonymous" has to be a precise statement or it cannot be tested. Proposed:

> Someone who records the whole chain, watches the whole network, and runs
> some of the nodes cannot tell which two parties opened a channel, and
> cannot tell who a given wallet's payments went to.

No system can promise more than a statement like this. What stays outside
any design is listed under "What cannot be guaranteed".

## What the chain reveals today

| On-chain fact | Who can see it | What it gives away |
|---|---|---|
| Channel table (A, B) | Everyone | The contact graph, directly |
| `OpenWithInvite` signed by A, naming B | Everyone | A contacted B, and when |
| `RequestContact` from A to B, escrow A to B | Everyone | A paid to reach B, the price, and whether B accepted |
| Block table (blocker, blocked) | Everyone | Who cut off whom |
| Invites per owner, messaging key per wallet, price per wallet | Everyone | Which wallets use messaging and how actively |
| Every balance and transfer | Everyone | Funding links between wallets |

The mixnet hides the messages. The chain currently publishes almost
everything the mixnet hides.

## The main idea: the chain does not need to know about channels

The chain was given three jobs that the recipient's own client can do, and
already half does:

- **Is this invite valid, and unused?** The recipient created the invite.
  Their client can check the signature and remember which invites it has
  honoured. No chain needed.
- **Is this caller blocked?** A private list in the recipient's client.
- **Is there a channel?** The two clients each remember it.

What the chain is needed for is money: collecting the network fee, paying
the recipient's price, funding node rewards. So the question becomes: how
does a caller prove to a recipient "I paid" without the chain learning who
the recipient is?

## Options

### A. Committed fee tickets (no new cryptography)

1. The caller pays the network fee in a public transaction that names no
   recipient. This creates a ticket.
2. To use it, the caller publishes `commitment = hash(recipient, random)`
   against the ticket, and sends the random value to the recipient through
   the mixnet.
3. The recipient's client reads the chain, recomputes the hash, and sees the
   ticket was spent for them. The chain marks the ticket used.

The chain sees: wallet X bought a ticket and used it. It never sees for
whom. Only hashes and signatures, which the project already uses.

- Hides: the contact graph, for invited contacts.
- Still shows: which wallets pay fees, how often, and when.
- Cost: small. Removes most of the pallet's tables.

### B. Zero-knowledge fee tickets (Semaphore / mixer pattern)

Same as A, but the ticket is a secret commitment placed in a Merkle tree,
and the caller later proves in zero knowledge "I own some unspent ticket in
this tree", revealing only a one-time nullifier. This breaks the link
between buying a ticket and using it. It is the pattern used by Semaphore
(anonymous group membership with a nullifier against double use) and by
Nym's own zk-nym credentials (deposit publicly, receive a credential that
cannot be linked to the deposit).

- Hides more than A: when and whether a given purchase was used.
- Still shows: which wallets bought tickets.
- Cost: a zero-knowledge circuit, a proof verifier in the runtime, and an
  audit. Groth16 verification inside a Substrate runtime is proven practice
  (zkVerify's `ark-groth16`-based verifier pallet; Orbinum's
  `pallet-zk-verifier`). Groth16 needs a trusted setup ceremony.

### C. Full shielded pool (Zcash pattern)

All coins live as encrypted notes. Sender, recipient and amount of every
payment are hidden; only proofs and nullifiers are public. Fees, the
stranger's price and the escrow all happen inside the pool.

- Hides: everything in the table above, including who funds whom.
- Still shows: coins entering and leaving the pool, and timing.
- Cost: the largest by far. Candidates to reuse, none of them drop-in:
  - **Orchard** (Zcash, Rust, Halo 2): no trusted setup. *Corrected
    2026-11-19:* a soundness flaw in the Orchard circuit was reported on
    2026-05-29 (ZIP 257); Orchard was disabled and re-enabled with a fixed
    circuit and a new verifying key. Earlier audits do not cover the fixed
    circuit, and the zkSecurity review began after the flaw was found.
    Unknown: whether a Halo 2 verifier runs acceptably inside a Substrate
    runtime.
  - **MASP** (Namada, Rust): Sapling-derived circuits, trusted setup,
    built for another chain framework.
  - **Orbinum's Substrate shielded pool** (Groth16, BN254, Poseidon;
    shield / transfer / unshield circuits): the closest fit structurally;
    licence, audit status and maturity not established.
  - The escrow (accept, decline, expire) is conditional payment, which
    standard shielded pools do not provide. It needs a custom circuit.

### D. Stealth (one-time) addresses only

The recipient is paid at a fresh address nobody can link to them in
advance. Hides the recipient of a payment, not the sender, the amount or
the timing, and the link returns when the recipient later moves the money.
Useful as a component, not sufficient alone.

### E. Trusted hardware (enclaves)

Chain state is hidden inside secure processors. The privacy then depends on
the hardware vendor and on the hardware not being broken. Not compatible
with a claim of anonymity that rests on mathematics. Not recommended.

## Recommendation: two stages

**Stage 5a: take the contact graph off the chain. No new cryptography.**

- Channels, invites and blocks move into the clients. The pallet loses its
  channel, invite and block tables.
- Network fees use committed tickets (option A).
- A stranger's sealed note is posted with no recipient named. Every client
  tries to open every note; only the intended recipient succeeds. (The note
  format already fails cleanly for anyone else.)
- The stranger's price is locked against a secret. The recipient claims it
  to a fresh address; if unclaimed, the sender reclaims it after expiry
  minus the decline fee.
- A wallet that wants to be reachable by strangers publishes a contact key
  and price. This should be a separate identity from the wallets that hold
  its money.
- All chain traffic from clients goes through the mixnet, so the node a
  client talks to does not learn its network address.

After 5a the chain no longer says who is connected to whom. It still shows
that a wallet uses the system, how much, and when; and a stranger's payment
can be followed to a fresh address by amount and timing.

**Stage 5b: shielded money (option C, or B as a stepping stone).**

Needed before making the strong claim, because 5a leaves payments
traceable. This is specialist work: it should start with a feasibility
spike (can an audited proof system be verified inside this runtime at
acceptable cost), be designed with a cryptographer, and be audited before
any real use.

## What 5a changes in decisions already made

- **Blocking**: the chain can no longer refuse a blocked caller before the
  fee is charged, because the chain no longer knows who is blocked. A
  blocked stranger pays the fee and is ignored; their price comes back at
  expiry minus the decline fee. Cheap failure is traded for privacy.
- **"Only the closer can reopen"** becomes a rule in the closer's client.
- **Deposits** for invites and blocks disappear with those tables.
- **Scanning**: every client downloads every note (427 bytes each). Fine at
  small scale; needs a detection scheme later.

## What cannot be guaranteed by any design

- **Small crowd at launch.** Hiding among few users is weak. A 2026 study of
  a shielded pool on Kusama called a crowd of 10 "trivially
  deanonymizable", and cited research finding 44% of Tornado Cash deposits
  were linkable through behaviour, not broken mathematics.
- **Timing.** Paying a fee and opening a channel seconds later, or a
  payment claimed right after it was made, can be matched by time.
- **How coins are bought.** An exchange that checks identity knows which
  wallet it sent coins to.
- **The device.** A compromised phone or computer reveals everything.
- **Long-term patterns on the mixnet.** Two parties always online together
  for months can eventually be linked statistically.
- **Bugs.** Unaudited cryptographic code cannot carry a guarantee.

## Legal exposure (not legal advice)

- EU rules (AMLR) bar regulated exchanges from handling privacy coins from
  July 2027.
- A US jury convicted a Tornado Cash developer in August 2025 of conspiracy
  to operate an unlicensed money-transmitting business; the jury did not
  reach a verdict on the laundering and sanctions counts, and the case was
  still running in 2026. US sanctions on the protocol itself were lifted in
  March 2025. Options B and C resemble a mixer more closely than A does.
- Take legal advice before any public network or coin sale.

## Decisions needed from the owner

1. Accept the 5a trade: blocked strangers pay the fee and are ignored?
2. Stranger prices: free amounts (leak more) or a few fixed amounts?
3. After 5a, go to full shielded money (C) directly, or zero-knowledge
   tickets (B) first?
4. Trusted setup acceptable (wider tool choice) or not (Halo 2 only)?
5. Budget for a cryptographer and an audit before any real use.

## Sources

- Semaphore documentation: https://docs.semaphore.pse.dev/
- Nym, "Introducing Pay as You Go" (zk-nyms): https://nym.com/blog/nym-pay-as-you-go
- zkVerify Groth16 verifier pallet: https://docs.zkverify.io/overview/verification_pallets/groth16
- Orbinum ZK verifier reference: https://docs-e40.pages.dev/architecture/zk-verifier-reference
- Namada MASP crates: https://github.com/anoma/masp
- zkSecurity, audit of Zcash Orchard (July 2026): https://reports.zksecurity.xyz/reports/zcash-orchard/
- ZIP 224, Orchard shielded protocol: https://github.com/zcash/zips (zip-0224)
- "ZK Feasibility Study: Can Kusama Asset Hub Run a Shielded Pool?": https://forum.polkadot.network/t/zk-feasibility-study-can-kusama-asset-hub-run-a-shielded-pool/17056
- Decrypt, Storm verdict (Aug 2025): https://decrypt.co/333790/jury-tornado-cash-developer-storm-guilty-money-transmitting
- Crypto Valley Journal, Storm trial delayed to April 2027: https://cryptovalleyjournal.com/focus/legal-and-compliance/tornado-cash-roman-storm-trial-delayed-to-april-2027/
