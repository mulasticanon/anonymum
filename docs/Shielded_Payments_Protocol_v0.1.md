# Shielded payments and paid contact requests
**Protocol specification v0.1 · 19 November 2026**

**Status — review draft, classical cryptographic target, no real-value release.** This document defines a proposed protocol for the messaging network’s native coin. It specifies the payment rules, a candidate public representation, the private statements a prover must establish, and the evidence required to activate a suite. Its escrow arithmetic has an executable reference model. Its proof circuit, FRAME verifier integration, wallet encryption profile and network privacy properties have yet to be demonstrated. No audit of this composition is claimed.

**The main design decision** is to put the money for a stranger’s request in one shielded note with two independent authorities and a single spending marker, called a *nullifier*. The recipient can claim the quoted price. Either party can cause a refund to the original sender. Whichever valid resolution finalizes first determines where the money goes. The contact wallet grants access only after recognizing a receipt under its own contact policy. No on-chain channel registry is needed.

Two decisions matter before anyone implements the full protocol. First, a recipient declining an escrow can create a refund while the sender is offline. The proof must make that refund **recoverable by the sender** even if the recipient constructs the transaction maliciously. Second, counting 24 hours from actual chain inclusion while hiding which opening is being claimed makes the public validity window a real engineering constraint. Both are testable design gates.

### Reading this draft

| If you are reviewing | Start with |
|---|---|
| The product promise and its exceptions | [1. Scope](#1-scope-and-assumptions), [7. Worked settlement](#7-worked-settlement), [8. Privacy limits](#8-privacy-limits-and-operating-decisions) |
| The objects, fees and proof statement | [2. Objects and cryptography](#2-objects-and-cryptographic-profile), [3. State machine](#3-private-money-and-escrow-state-machine), [5. Wire format](#5-public-transaction-and-state-transition) |
| The phone or messaging implementation | [4. Contact admission](#4-contact-admission-and-authenticated-delivery), [6. Wallet recovery](#6-wallet-discovery-recovery-and-delivery) |
| What can be tested now | [9. Assurance](#9-security-properties-and-acceptance-evidence), [10. Implementation order](#10-implementation-order-and-release-decisions), [Appendix A. Executable Rust](#appendix-a-executable-rust-escrow-model) |

## 1. Scope and assumptions

The deployment target supplied by the project is a standalone Rust/FRAME chain on the Polkadot SDK stable2609 line, with Noise XX messaging over Nym and no ordinary conversation data on the ledger. This design charges for a **paid contact request**, once per request. Messages after a channel opens remain off-chain. The 427-byte encrypted stranger-request field is the explicit on-chain exception. Invitations, blocks, channel membership, chat transcripts and successful session handshakes live in clients. A block is a local refusal of contact. It does not prohibit anyone from sending network packets or making an ordinary payment.

The proposed reference protocol has one asset, one pool and one user transaction format. A purely shielded payment needs no public account, fee payer or account nonce. In this document **MUST** identifies a proposed consensus or interoperability requirement. A **gate** identifies a property with insufficient implementation or assurance evidence. A compliant money transition can coexist with an unprivate network deployment. The two have separate acceptance criteria.

| Boundary | Reference decision |
|---|---|
| Sender and receiver | A wallet may have several independent receiving descriptors. Public contact keys have no authority over the ordinary wallet. The protocol hides honest users’ financial endpoints from third-party observers under the stated assumptions. Each counterparty learns its own interaction. |
| Public treasury | The network publishes the treasury descriptor/policy and the position of its output. Contribution amounts and operator payments are shielded. The treasury’s viewing authority can recover its contributions and may classify requests. A publicly queryable exact treasury balance after each transaction would change the privacy claim. |
| Fees and expiry | The sender funds the opening tariff and separately prepays one settlement tariff. A refund retires the integer part of 1% of the principal. The sender may cancel unilaterally from opening onward. After 24 hours of consensus time the recipient loses claim authority. Final settlement still requires an included transaction. |
| Data size | `B427` is the existing application's **exact 427-byte encrypted request object**. The money protocol treats those 427 octets as an opaque field inside a larger, padded, recipient-encrypted delivery container. The application owns any inner framing and decryption. No 427-byte human-plaintext allowance or 427-byte whole transaction is assumed. Other note witnesses and recovery encapsulations have their own space. |
| Observer | Assume an observer sees all blocks, mempool and network packet metadata and operates a specified subset of nodes. The computational ledger claim requires sound primitives, fresh entropy, honest uncompromised challenge wallets, equivalent public information in the compared histories and a trusted consensus/finality boundary. Any whole-network claim also needs a stated corruption placement, cover schedule, realistic population and an independently evaluated transport model. “Some nodes” alone gives no quantitative anonymity bound. |
| Authority to change rules | Governance capable of replacing the runtime or verifier can change the monetary and privacy rules. Every release needs pinned code, public activation criteria and a recoverable path for outstanding notes. Validator censorship, chain halt, lost secrets and unavailable archival data affect liveness. |

### Public-to-shielded cutover

Existing public payments and contact records remain observable in historical blocks. For a first valueless network, initialize a fixed test distribution in the new note tree and disable any generic mint path. For a conversion of a live legacy coin, define a **separate public boundary**. Freeze a finalized balances snapshot and all competing issuance paths, reconcile free/reserved/locked balances and pending escrows, and specify the owner authentication, unique redemption identifier and backing debit for each converted right. Activate a private note only in the same atomic change that extinguishes that right. A public importer leaks at least the redeemed legacy claim and its value. Publish the reconciled supply, unresolved liabilities and the conditions for closing the importer. Duplicate redemptions, reversible public backing with irreversible private credit, and an unrestricted root mint are disallowed. A concrete migration and genesis ceremony are outside the user-transaction verifier and require their own specification before migration of real value.

## 2. Objects and cryptographic profile

**Target.** Use the Sapling model of a commitment tree, private spend authority and public nullifiers, with one new Groth16 relation over BLS12-381. This changes both the note format and the spend statement. Sapling binaries, proving keys, audit results and existing coins cannot be imported as evidence for this relation. The signed policy and note-encryption systems are separate choices. The original Groth16 paper and Zcash’s parameterized protocol provide the design references. [Groth, 2016](https://eprint.iacr.org/2016/260) · [Zcash protocol specification, 19 Nov 2026, §§3–5](https://zips.z.cash/protocol/protocol.pdf) · [Sapling Rust source, inspected 19 Nov 2026](https://github.com/zcash/sapling-crypto)

### Private objects

| Object | Mandatory committed or authenticated contents |
|---|---|
| Ordinary money note | Immutable note-format and pool domain, ordinary type tag, native asset, unsigned 64-bit value, owner payment descriptor, receiver/recovery descriptor linkage, fresh commitment blinding. Its nullifier depends on owner-bound nullifier material hidden from an ordinary sender. |
| Escrow note | Format/domain and escrow type; principal, reserve, frozen tariff terms, recipient resolution key and payout descriptor, sender resolution key and refund descriptor, recovery endpoints, signed-term digest, unique request binding, common serial seed and fresh blinding. Its total value must fit one `u64`. |
| Permanent retirement and output padding | Distinct, authenticated private type tags. A retirement holds the specified economic value and has no spend predicate. Padding has zero value and no spend predicate. A zero-valued *real* settlement receipt can still carry a required recoverable effect. |
| Admission record | Freshly blinded commitment to the intended recipient’s policy, signed quote or invitation, holder/session binding, digest of `B427`, request nonce and actual funded effect. An unrelated money action commits a fresh cover record instead. |
| Authorization | The owner or escrow role authenticates the completed effect under a spending or resolution key, as a private witness. For an ordinary note, prove that the spend key relationship, private nullifier material and original payment descriptor match. Possession of a payment address, a ciphertext opening or the common escrow seed never substitutes for this check. |

The sender must prove control of the designated cancellation authority when funding an escrow and authorize its chosen refund and recovery descriptors. The recipient policy binds all recipient-side descriptors. For the prototype, require a **delegation signed by the scoped recipient resolution key** authorizing the genuine policy key and the listed claim, payout and recovery endpoints. The quote then comes from that policy key. The recipient wallet checks the same chain against its locally authenticated card. A new contact can publish its own valid card; this gives it no authority to sign in the name of an existing contact. A quote and delegation are reusable over their bounded lifetime. Their digests and keys stay private within payment transactions.

### Concrete prototype hash profile

The following **H1** choices give independent implementers the same serial and tree design to model. All hashes use the standard SHA-256 primitive through an existing library and a reviewed matching circuit gadget. Byte-hashing the note and its Merkle path is a deliberately conservative performance experiment. The hiding/security of the resulting structured commitments and serials, and the suitability of the concrete libraries, still need review. The reason for specifying a reference profile now is to make the constraints measurable. [SHA-256 specification, Aug 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

- For the following objects only, define `H(label, fields) = SHA-256(prefix || u8(length(label)) || ASCII(label) || context || fields)`, with `prefix = ASCII("shielded-payments/H1/")`. The immutable `context` is the 32-byte network ID, 32-byte pool ID and little-endian `u16` note-format version in that order. Variable component fields require explicit length/type binding in the suite record; domain labels shown below are distinct. All scalar integer encodings are unsigned little-endian. Raw 32-byte hash outputs remain byte strings.
- For the note or admission object use `H("note", blind32 || canonical_note)` or `H("admission", blind32 || canonical_record)` with newly sampled 32-byte blinding. The type/role and descriptor fields belong **inside** the canonical record. Fix every field’s width, order, validity and optionality in the cryptographic suite before interoperability testing. Reusing blinds or deriving them entirely from a public profile is invalid wallet behavior.
- Ordinary serial: `H("nf-money", nk32 || commitment32 || position_u64)`. The selected owner/key derivation must enforce the connection to `nk32`, keep it from the sender, and make it deterministic for every authorized spend of that note. Escrow serial: `H("nf-escrow", shared_seed32 || commitment32 || position_u64)`. Dummy serial: `H("nf-padding", dummy_secret32)`. An escrow’s role does not enter its serial. The tree position prevents two separate insertions of the same commitment from sharing one note identity. The suite review must address biased or chosen secrets, tag separation and inability to mark a known live serial using the padding domain.
- Prototype tree depth is 32. The all-empty leaf is `H("empty", empty_bytes)`. Every inserted leaf is `H("leaf", commitment32 || t0_u64)`. Internal nodes use `H("node", level_u8 || left32 || right32)`, level zero immediately above leaves. Build empty subtree roots recursively using two equal empty children. The low bit of the leaf position chooses left/right at the first level. Append four consecutive positions per accepted envelope. Reject transactions if all four do not fit. Never reset a full tree in the same namespace or discard its spent serials.
- Commitments and output encryption are constructed before the final transaction digest. An authorizing signature over the completed effect is a *private proof witness*, separate from all digested bytes. An invitation-holder signature inside encrypted application data instead signs a pre-encryption request context. This ordering avoids a signature that would have to authenticate bytes containing itself.

| Building block | Implementation baseline and remaining gate |
|---|---|
| Proof | Groth16/BLS12-381 with one fixed relation and one verifier for the user envelope. Candidate compressed proof layout is G1/G2/G1 at 48/96/48 bytes. Freeze exact subgroup checks, serialization, CRS, circuit and permitted identities with test vectors. A 192-byte proof budget says little about nine ciphertext containers or phone proving time. [Zcash transaction encodings, accessed 19 Nov 2026](https://zips.z.cash/zip-0225) |
| Key and signature relations | Evaluate reviewed Rust Sapling/Jubjub-lineage key, signature and diversified-receiver implementations for the required roles. Pin exact derivation, group validation, randomized signature and in-circuit verification rules. A library implementing an operation does not establish that its corresponding circuit gadget was reviewed. [Sapling implementation, accessed 19 Nov 2026](https://github.com/zcash/sapling-crypto) |
| Confidential delivery | Select an established recipient-anonymous encryption scheme and reviewed implementation with a feasible correctness relation. Require both key privacy for known candidate public keys and correct recoverability for each actual beneficiary. The precise suite, container widths and any hybrid archival mode are open. No custom KEM, cipher, curve arithmetic or unchecked AEAD gadget is authorized by this spec. |
| Tree/serialization and setup | Check native, circuit and runtime byte equivalence on independently generated vectors. Use disposable parameters for prototypes. The reviewed final constraint system needs a circuit-specific setup and publicly verifiable transcript bound to the deployed verifier. [Zcash Foundation, 13 Apr 2018, setup precedent](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/) |

## 3. Private money and escrow state machine

**Proposed consensus rules, draft 0.1 (19 November 2026).** Each accepted action consumes up to two spendable notes and produces four hiding commitments in fixed slots. The first two outputs hold participant notes or padding. The third is a treasury note and the fourth is permanently retired value. Zero contributions occupy their usual slots with fresh randomness. Each real input must prove membership against the common public anchor, ownership or escrow-branch authority, a legal input type, and its unique nullifier. Each input slot publishes a nullifier-shaped value. Padding contributes zero and its nullifier must have a secret preimage in a separate domain. An unconstrained padding nullifier would let an adversary copy a pending user's nullifier and consume it first.

### What gets locked

An escrow opening binds the pool domain, note-format version, native asset, principal `V`, settlement reserve `F`, recipient claim/decline authority, recipient payout destination, sender cancel/refund authority, sender refund destination, quote terms, per-request binding, a fresh shared serial secret and commitment blinding. A payout destination includes the material needed to create a discoverable ordinary note that its intended owner alone can spend. The commitment covers canonical encodings and field roles. Resolution must recompute it. The spend keys themselves never enter the other party's recovery packet. The sender MUST persist its own recovery material before broadcast. Both parties MUST be able to obtain the escrow opening, blinding and serial material and reconstruct the tree witness from finalized data without further cooperation. In particular, a recipient declining a request needs the sender's recorded refund destination.

The OPEN relation MUST enforce correct delivery of the escrow recovery material to the private delivery destinations corresponding to both committed authorities. It must verify the fixed-envelope delivery relation specified for that suite. The same obligation applies to an output made on someone else's behalf, including a refund created by a declining recipient. Merely hashing arbitrary ciphertext into an authorized transaction does not establish that the rightful owner can decrypt it or spend the resulting note. Cross-wallet opening, claim and decline without an auxiliary service are release gates. If the delivery relation has no reviewed feasible instantiation, offline unilateral resolution has not been implemented.

Every output leaf records the same runtime-authenticated inclusion time. Conceptually the leaf commits to the pool context, output commitment and block timestamp `t0`. The spend witness authenticates the leaf and its append position `p` under the accepted root. The wallet learns the position and timestamp after inclusion. The common escrow nullifier is derived privately from the domain, committed serial secret, escrow commitment and its authenticated logical position. All resolution paths use *identical* inputs to this derivation. The claimant role, signature, payout, anchor, current time and accepting protocol version do not vary the nullifier. Persistent note domains and positions survive upgrades. Resolving parties can recognize resolution of this specific escrow. Ordinary notes require a separate owner-bound nullifier derivation, so learning a refund or payout note plaintext does not hand its creator the beneficiary's general spend-tracking capability. Concrete primitives and encodings must satisfy the suite's binding, hiding, pseudorandomness and domain-separation requirements.

### Transition table

`F` is the fixed base fee, charged for ordinary envelopes, invited requests and settlement. `G` is the fixed higher network fee for opening a stranger request and `G > F`. The profile fixes these amounts and their fee split. `D = t0 + 86,400` in consensus seconds. Every envelope is assigned a standard half-open interval `[L,U)`. At execution the pallet requires `L ≤ block_time < U`. Rows below are private cases of the same public relation. A row without change uses its spare participant slots as padding.

| Operation | Required authority and value | Enforced effect |
|---|---|---|
| Ordinary transfer | Ordinary spend authority for every live input | Pay the requested amount and change into ordinary notes. Charge `F`. An ordinary payment gives its recipient no channel-opening entitlement. |
| Invited request | Ordinary spend authority, recipient-issued capability bound to the intended recipient and authorized request holder, and a valid invitation window | Deliver the invitation-bound request to the same recipient and charge `F`. No escrow principal or settlement reserve is created. Return change to its designated receiver. |
| Stranger request | Ordinary spend authority and a valid price quote tied to the exact recipient, claim authority and payout destination | Create exactly one escrow with principal `V` equal to the quoted price and reserve exactly `F`. Deduct `V + F + G` from the input value before change. Deliver the request under the quote-bound policy. The reserve stays inside the escrow. |
| Recipient claim | Possession of the escrow opening and recipient claim authority. Require `U ≤ D`. | Consume the escrow, create an ordinary note of exactly `V` for the committed recipient, and charge exactly `F` from the reserve. |
| Recipient decline | Possession of the opening and recipient decline authority. Require `U ≤ D`. | Create an ordinary note for the committed sender refund destination worth `V − b`. Retire `b` along with the burn portion of the settlement fee. Charge `F` from the reserve. |
| Sender cancellation or timeout refund | Possession of the opening and sender cancel/refund authority | Create the identical refund, retire `b`, charge `F` from the reserve. This authority is valid at every inclusion time. An inclusion before `D` is early cancellation and an inclusion at or after `D` is a timeout refund. Both have exactly the same financial effect. |
| Treasury merge | Treasury authorization for exactly two distinct positive liquid notes bound to the configured fee treasury | Place the checked sum of the two inputs into the treasury slot under the same authority. Both participant slots and the retired slot have zero value. No fee, other receiver or contact entitlement is permitted. |

For **every** resolution require exactly one live input of escrow type, one specified payout, no unconstrained change, and `escrow.value = V + F`. Use padding for the second input and unused participant output. An authorization must cover the transaction's complete effect digest. The circuit verifies it using the authority committed in the consumed escrow. Recipient-issued price quotes and invites authorize policy terms separately from spend or resolution authorization. A sender cannot make a third party's wallet accept a fee discount by signing a quote or invite to itself. All destinations, including the beneficiary encryption addresses, must agree across the certificate, proved output and wallet-delivered effect.

The exact reference profile measures time in whole consensus seconds and uses one-second windows. Both `t0` and `D` lie on window boundaries. The previous half-open window is valid through its last instant. A wallet may prepare a proof for a predicted future window, but a missed window requires a new proof. Block timing, mixnet delay, phone proving time and censorship can prevent timely inclusion. Test this profile before promising that a claim will execute before expiry. With a wider window that does not divide the authenticated creation clock, `D` can fall strictly inside a window. A recipient then loses less than one full pre-deadline window. Such a profile changes the product guarantee and needs a separate version. Sender refunds work across the boundary because the sender already had unilateral cancellation authority. A timestamp in an old anchor never authorizes a late recipient claim.

**Race and liveness.** All outcomes consume the same nullifier. In a canonical block the first successful resolution in execution order consumes it. Wallets treat the outcome as provisional until finality and revert provisional state on a reorganisation. A recipient's off-chain acceptance cannot reserve the escrow against a competing sender cancellation. Passing the deadline never creates a credit by itself. A wallet holding the witness must submit a valid settlement and a validator must include it. A device that stays offline cannot complete that step. A chain halt also halts settlement.

### Amounts, treasury and permanent retirement

Use integer base units. For each refund, constrain `V = 100b + r`, `0 ≤ r < 100`. Thus 99 units refund 99, 100 refund 99, and 101 refund 100, before counting the separately prepaid network fee. At `V=10,099`, the penalty is 100 and the refund is 9,999. Sub-unit penalties round down. The rate applies independently to each escrow. Publishing `b` would narrow `V` to at most 100 consecutive base-unit values. Accordingly, the protocol never emits a public per-refund burn amount or decrements a public supply counter by that amount.

For fee-bearing transitions, let `N` be the required network fee and let `a/d` be the fixed fee-burn fraction in the policy, with `0 < a < d`. The schedule MUST also ensure `1 ≤ floor(aN/d) < N` for each tariff `N` in `{F,G}`, so both the pool and the burn receive at least one unit. Compute the unique integers satisfying `aN = dB + s`, `0 ≤ s < d`. The treasury slot has value exactly `N − B` and the retired slot exactly `B + b`, with `b = 0` except on refund. There is no separate debit of `N` once these outputs have been counted. The reserve equals the settlement fee, leaving no unallocated surplus. For every private transition the sum of live input values equals the sum of the two participant output values plus treasury value plus retired value. An escrow occupies `V + F` on either side of that equality. Enforce the branch-specific equalities even if the global sums already match.

All values, accumulation widths, quotient/remainder equations, timestamps and positions must be constrained as bounded integers. Reject overflow, including `V+F`, `t0+86,400`, fee products and final per-output values, before modular field equality can alias a different integer. Constrain selectors to exactly one allowed branch. Reject retired or padding notes as financial inputs in *every* verifier, migration and emergency path. Restrict minting to explicit, publicly accounted supply boundaries. Burn means universally unspendable committed value. The gross minted supply, spendable circulation and treasury's confidential spendable balance are distinct accounting quantities. The treasury has a public spending policy but individual fee inflows and the unspent integer balance remain confidential. If these quantities must be independently summed and publicly reported, that requires an additional disclosure protocol.

Fee treasury outputs use the ordinary note representation with the exact configured treasury receiver. The fee-free, hidden treasury merge decreases the number of positive treasury notes by one each time it executes. Its only possible beneficiary is that same treasury. This lets the treasury accumulate many small contributions before using an ordinary fee-paying transfer for a shielded operator payout. Operator eligibility and payout accounting are the treasury governors' responsibility in this version. The circuit enforces the deposit recipient and amount, without adjudicating the governors' payout decisions. Measure the block space, fee-queue behavior, scan load and signatures required by these merges before setting an operator payout frequency.

Wallet and node upgrades must service outstanding `V+F` escrows under the committed fee terms, preserve their unique logical positions, nullifier domains and historical spent set, and preserve the prohibition against resurrecting retired notes. No upgrade may charge an extra fee against an existing principal. Before any fee change, demonstrate liveness for the oldest supported escrow without exposing which public transactions settle under an old policy.

**Source boundary.** Penumbra specifies a positioned swap nullifier, constrained claim address, fixed outputs and a prepaid fee. Its construction supports different transaction semantics. The escrow branch relation, unilateral cancellation and hidden penalty above are new obligations for this design. The Zcash specification supplies the ordinary note, commitment-tree and nullifier vocabulary. [Penumbra SwapClaim, accessed 19 November 2026](https://protocol.penumbra.zone/main/dex/action/swap_claim.html) · [Zcash Protocol Specification, 19 November 2026, §§3.2, 3.8–3.9](https://zips.z.cash/protocol/protocol.pdf).

## 4. Contact admission and authenticated delivery

**Rule.** A recipient wallet treats a request as paid only after it verifies a finalized shielded transaction for that particular request. A stranger may transmit packets to a public address or send ordinary shielded coins to a known receiver. Neither event buys access to the request inbox. This distinction is essential when the chain has no contact registry. Validators can check a private relationship between a credential, a price and a funded effect. Only the receiving wallet can recognize *its own* policy or decide whether to start a conversation.

### Authorities and credentials

| Object | Normative scope |
|---|---|
| Public contact card | The user authenticates a contact-policy verification key through an independent channel, such as a previously pinned fingerprint. A signed card binds the network, protocol version, contact delivery key, contact rendezvous/Noise authentication information, and bounded validity. The public directory may distribute signed cards. Substituting a different first-use identity remains possible without a trust anchor. |
| Price quote | The recipient resolution authority first signs the scoped delegation in §2. The contact-policy signer signs canonical, domain-separated terms containing the network, policy generation, fee-schedule identifier, validity interval, price in native base units, delivery key, and the recipient's actual scoped resolution authority and payout descriptor. A recipient can publish a reusable short-lived quote with its card and remain offline during funding. Visible cards or quotes associate their listed endpoints and advertised prices with that contact. Wallets should use scoped receiving authorities and keep wallet-wide viewing material private. |
| Invitation | The same authenticated policy authority signs the invited purpose, network, schedule, delivery target, hash of the applicable signed endpoint terms, validity interval, and an independent grantee verification key. Each contact pair uses a fresh grantee key. A private witness proves control of the corresponding secret or a valid holder authorization for this exact request. The grant in this draft is reusable until expiry. Every admitted request still pays the invited fee. One-use invitation nullifiers are outside this version. |
| Spending and viewing | Ordinary wallet spending authority, incoming/full viewing authority, scoped escrow authorization, contact-policy signing, public contact decryption, invite-holder authentication and Noise static secrets have separate key roles and encodings. A public contact card must never require a spending, incoming-view, full-view or nullifier **secret**. Use reviewed derivation/key-generation interfaces for the chosen suite. A secret used to decrypt a claim package may reveal its escrow amount and settlement nullifier, without conferring authority over unrelated funds. Rotating a public contact key cannot invalidate recovery of outstanding escrows. |

The signature statement must have a single canonical encoding, a distinct purpose tag for each credential, and strict validation of all keys. The proof accepts a quote or invitation only if its validity covers the entire public transaction validity window and the proven schedule is active. A signed generation counter helps a wallet prefer new terms. Consensus honors unexpired commitments under its active schedule even if a recipient has since raised the price, deleted a contact or issued a successor card; instant private global revocation is outside this design. Retain former decryption and resolution keys through outstanding obligations and recovery. Prefer broad cache downloads for public cards. Fetching one named profile from a directory exposes that choice to the directory.

### What the receipt binds

Every envelope contains one randomized hiding commitment to a delivery record, including ordinary transfers and resolutions. A canonical real record commits to this network and version, contact-policy verification key, exact credential digest and branch, recipient delivery key, a fresh request identifier, initiator's scoped Noise identity/rendezvous binding, a digest of the exact 427 bytes of the opaque application ciphertext `B427`, and the funded escrow output commitment for a stranger. Use an explicit tagged empty escrow field for an invitation. Apply fresh hiding randomness even to the empty/padding record on all other branches. Price, stable profile hash, keys, branch and request identifier stay inside the commitment. An unsalted public hash of these fields would permit guesses from a contact directory.

The funding wallet first forms the escrow commitment, then the delivery commitment, then the ciphertexts, and finally the statement binding those ciphertexts. The escrow can include the request identifier but cannot depend on its enclosing delivery commitment. Encryption associated data binds the protocol domain, pre-encryption transaction context, slot and relevant commitments. The outer proof binds the resulting canonical envelope effects. No plaintext, credential, commitment or signature depends on the hash of an as-yet-unbuilt transaction containing itself.

| Private branch | Required equality checks within the relation |
|---|---|
| Stranger | Verify the quote signature under the record's policy key. The funded escrow has the exact quoted price, resolution authority and payout destination. The actual recovery encryption uses the quoted delivery key. The delivery record opens to that very escrow commitment, initiator binding and body digest. Charge the stranger fee and reserve settlement funds as specified. |
| Invited | Verify the invitation, its signed endpoint terms, its time bounds, and holder authorization. Match the policy, delivery target and actual request effect to those signed terms. Bind this holder's authorization to this request context, including the initiator/rendezvous binding. Charge the invited fee. A zero-priced or self-issued stranger quote cannot select this branch. |
| Ordinary or settlement | The record is padding. These branches cannot produce a record that opens as a contact admission under the genuine recipient's policy key. The padded wire layout is shared with both contact branches. |

For a real request, the appropriate encrypted slot must recover the delivery record, its opening randomness and the exact bytes of `B427`. The recipient's escrow recovery material must additionally contain every *shared* witness field needed to claim or decline, as specified by the settlement relation. The prover must establish equality between the canonical plaintext fields, their commitments, the true target key and the posted ciphertext bytes, using a reviewed encryption relation/gadget or independently verified equivalent. The sender must retain a recoverable refund witness. Hashing arbitrary ciphertext into the transaction only prevents later replacement. It cannot compel a malicious funder to encode a usable claim witness. Correct encryption gives a holder of the right keys the ability to recover from available chain data. It cannot prove receipt by a phone, timely inclusion of a claim or physical data availability.

The 427 bytes are the entire existing encrypted application object `B427`. The enclosing money-protocol plaintext contains that object plus private receipt data. Consensus can enforce exact bytes, funding and outer delivery, while an authorized sender can still put meaningless content inside its funded request. Headers, capsule openings, wallet-witness material and encryption overhead require a separately budgeted fixed-length carrier. A non-contact branch must use the same slot/length conventions and the same public verifier. The recipient-anonymous encryption format, canonical record bytes, padding validity, signature gadgets and side-channel behavior require a cryptographic profile and device measurements before interoperability or security can be claimed. A deployment with large archives requires authenticated data availability for the wallet's entire recovery horizon.

### Wallet and conversation rules

1. Scan the common authenticated chain data, open the fixed delivery slot, and check commitment opening, credential, current canonical finality, local contact-policy identity, body digest and sender/session binding. Verify that the escrow output is in the same transaction. Locally synchronize spends through the latest verified height before presenting an actionable escrow. An early cancel can still win before a subsequently submitted claim.
2. Persist the local request identifier with finalized transaction locator and slot. Process repeated deliveries idempotently across devices and restores. Bind a newly authenticated Noise XX session to the accepted receipt and the expected peer identities, for example through locally reconstructed prologue data and verification of the peer's authenticated static key. Keep locators and stable wallet identifiers out of cleartext rendezvous traffic. A receipt-derived value suitable for a Noise prologue is local input to both parties. Sending it in clear would make it a correlation identifier. Check peer identity using the expected static key or its independently authenticated binding. Require the successful finalized claim before the recipient UI promises paid acceptance; an invite has its own finalized fee receipt.
3. Apply local block and invitation-revocation rules before showing content, notifying the user, or admitting the conversation. Do not render unsolicited ordinary payment memos as contact messages. Failed decryptions, ignored credentials and blocks must produce no recipient-specific network response; local filtering leaves bandwidth and scanning costs. A stranger can adopt a new off-chain identity, so blocking a particular authenticated identity cannot promise a permanent block of the same human.
4. Test a valid cheap self-invite addressed to an attacker's card carrying a victim's text, a copy of a genuine receipt delivered to another wallet, a detached ciphertext transplanted between transactions, a sender substituting its own claim key, an expired invite whose old anchor is still valid, and two concurrent deliveries of one receipt. In every case the victim wallet must either ignore the item or admit only the one originally paid request. A consenting invite holder can share its credential and secret or sponsor another sender. Anonymous fee rules cannot prohibit voluntary delegation, raw unsolicited packets, or intentional out-of-band communication between consenting people.

**Design references.** ZIP 32 describes wallet derivation and delegation scopes; ZIP 212 specifies recipient-side checks for diversified note encryption. Neither defines this paid-contact relation. The Noise framework defines the prologue, authenticated handshake state and application responsibilities. Review the selected suite in its exact usage before treating these as implementation evidence. [ZIP 32, 2018-05-22](https://zips.z.cash/zip-0032) · [ZIP 212, 2019-03-31](https://zips.z.cash/zip-0212) · [Noise Framework revision 34, 2018-07-11, §§6, 7.5 and 13](https://noiseprotocol.org/noise.html).

## 5. Public transaction and state transition

**One profile for user transactions.** Opening an escrow, making an invited request, paying, claiming and refunding MUST use the same pallet call, verifying key, total length, field order and number of ciphertexts. Chain observers know the treasury and retirement *positions* and that those positions exist in every envelope. They do not receive their values. This is a draft of the encoding and relation. Interoperable cryptographic encodings require the release manifest described below.

| Canonical order in the effect body `E` | Encoding and rule |
|---|---|
| Format, suite, network, pool, rules | `format:u16, suite:u16, network:[u8;32], pool:[u8;32], rules_id:[u8;32]`. Accept only the configured tuple for this wire profile. Choose the network and pool identifiers before creating notes, make them unique across deployments, and bind them in all financial domains. |
| Anchor and validity | `anchor:[u8;32], window:u64`. The window denotes one globally scheduled half-open interval `[L,U)` of consensus seconds. Its width and origin are public protocol constants. No sender-selected deadline or fee tier appears in the header. |
| Input serials | Two canonical 32-byte nullifiers, in circuit slot order. A transaction with one live input still publishes two serials. |
| New commitments | Four canonical 32-byte note commitments appear in order, two user/effect slots followed by one treasury note and one retirement note. Each position is present even at zero. The circuit also binds a separate 32-byte hiding admission commitment, freshly blinded on every action. |
| Encrypted data | For each of the four notes, in the same order, two fixed-width ciphertext containers for note openings and recovery. Then one fixed-width contact container for the request or cover. Every public byte, including encapsulations, ephemeral keys and authenticated padding, is within the fixed container and covered by the proof statement. Actual widths depend on the selected suite. Each class of container has the same width across all actions. |
| Submitted proof | Append one fixed-width, canonically encoded proof to `E`. It is outside `E`. The outer FRAME call carries the exact bounded bytes. The payer supplies no account ID, user transaction signature, tip, nonce or free-format extension at that outer layer. |

Integers in this table use fixed-width unsigned little-endian encoding. Byte arrays concatenate in their listed order. No optional fields, length prefixes inside the effect body, implicit normalization, surplus bytes or alternative decoding are allowed. If the note and recovery container widths are `N` and `R`, the contact container width is `C` and proof width is `P`, the inner submission occupies exactly `364 + 4*(N+R) + C + P` bytes. This excludes the FRAME extrinsic wrapper. A 32-byte field/point representation must satisfy the field/curve encoding in the release manifest. The decoder MUST reject unsupported sizes *before* allocation and hashing. Extra FRAME wrappers, batching calls or signed paths into this private entry point must neither bypass validation nor be advertised to privacy-preserving wallets.

**Public statement.** Define `d = SHA-256(ASCII("shielded-payments/effect/v01") || E)`. The public inputs to the proposed BLS12-381 Groth16 instance, in order, are the integers represented by `d[0..16]` and `d[16..32]`, each interpreted little-endian as a distinct scalar. Exactly two scalars are accepted. There is no reduction of a 256-bit digest modulo a field. An independent verifier MUST reconstruct both values from the received effect bytes. The circuit MUST constrain every byte of its private copy of `E`, reproduce the hash using a reviewed gadget, enforce equality to both input limbs, and prove the monetary, authorization and ciphertext predicates about those *same* bytes. A host-side check alongside an unconstrained witness digest fails this requirement. The hash standard is dated [August 2015, NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

Construct commitments and the admission opening first, using fresh entropy and any application request nonce. Construct encrypted outputs next, with network, pool, suite, slot and the relevant public commitment bound as associated data according to the reviewed encryption profile. Prove their well-formedness for each required recovery recipient and the required contact recipient. Every cover slot must have a specified generative distribution and a constrained tag/length/format indistinguishable to third parties from the corresponding real slot. Bind a hash of the completed `E` last. Commitments, encryption associated data and embedded payloads MUST NOT contain the digest of their own completed effect. A private signature over the completed effect is possible only when that signature remains outside `E` and the authorization profile defines its exact signing domain. Store a finalized locator alongside a wallet's record *after* inclusion. Byte binding alone proves neither recoverability of an opening nor delivery to a phone.

**Input and output padding.** A live input proves the note opening, its Merkle position, branch authority and the correct deterministic serial. A dummy input has value zero and proves a preimage under the profile's separate dummy-serial domain. Its serial MUST be infeasible to choose equal to a known live serial, including when the prover knows the preimage in the *live* domain. An unchecked random-looking 32-byte input would let either escrow party mark the common serial spent in an unrelated transaction. The circuit permits no live credit from a dummy and no live spend of retirement or output padding. Enforce the same nullifier namespace on every branch consuming the same note and retain it across future circuit upgrades. Run a repeated-public-input rejection check including dummy slots. Wallets use independent randomness for each dummy and each zero commitment. Adversarial participants can fingerprint their own transactions despite these rules.

### Inclusion, clock and finality

Nodes retain the canonical note-tree frontier and leaf count, a bounded rolling set of eligible block-end roots, the persistent global used-nullifier set, and active profile/configuration commitments. Outputs are always appended in transaction then slot order. Wrap *every* output at insertion in the profile's domain-separated leaf commitment to `(network, pool, note_commitment, creation_time)`. Creation time is the chain's validated timestamp in whole consensus seconds. Merkle membership with its position authenticates that time when the note is used. The chain clock rule must define timestamp validity, monotonicity, rounding and permitted proposer skew. The deadline is 86,400 consensus seconds after creation. Real-world inclusion and finality have separate latency.

For the reference profile, `W=1` consensus second, `L=window`, and `U=L+1`. Derive both bounds using checked integer arithmetic. The block applies the transaction only when `L <= block_time < U`. A recipient claim or early decline whose deadline is `D` must prove `U <= D`. Because deadlines and block times are whole seconds, the last eligible second begins at `D-1`. The sender can cancel before expiry and obtain the same fixed refund after expiry, hence the sender refund remains eligible through this boundary. Proving clients must target a future second in which a block can include the action. A missed second requires a fresh proof. Short validity makes block prediction, anonymous submission, censorship and retransmission serious liveness concerns. A relayer may stage a bounded number of future-window envelopes. Consensus can never accept them early. Field-test this end to end before adopting the reference profile. A separately versioned slot clock or wider-window design would need a new timing analysis. With wider windows and unaligned deadlines the recipient loses the final fraction of a window.

| In-block order | Required check or effect |
|---|---|
| 1. Parse | Check the call/origin path, exact bounded lengths and profile, canonical encodings, active rules, eligible anchor, current window, fixed cardinalities, distinct nullifiers, absence of both nullifiers from state, remaining capacity for all four leaves, and block byte/weight quotas. Only completed ancestor-block roots are eligible anchors. |
| 2. Authenticate | Derive the effect digest, retrieve the pinned verifying key from trusted configuration, validate proof points and their prime-order subgroups, apply the chosen profile's identity-point rules, and verify the proof at exactly the required arity. Point/integer decoding must fail closed. A local mempool decision carries no consensus authority. |
| 3. Commit atomically | Under the inclusion state, consume both serials and append exactly four time-wrapped leaves. Make the entire effect and ciphertexts available in the authenticated block body. Any failure leaves every balance, serial, leaf and auxiliary index untouched. End each block with a deterministic root/frontier update. Duplicate roots in quiet blocks must remain eligible until their *last* retained occurrence expires. |
| 4. Follow finality | A conflicting authorized action consuming the same escrow serial loses once its competitor is included on the finalized chain. Wallets track unfinalized effects separately and support rollback. An older root authenticates membership only. The current used-nullifier set and inclusion time are checked even for an old eligible anchor. |

**Fees and accounting at the pallet boundary.** Use confidential values in both special outputs on every user transaction, including zero. The treasury authority and split formula are public policy. Its contribution sizes and the balance under its viewing authority are confidential. Retirement has no live spending predicate. The integer balance invariant is `sum(live inputs) = sum(live user and treasury outputs) + retired amount`, with zero padding and escrow principal plus reserve accounted at full value. Do not deduct the same fee again in a FRAME charge extension. Do not emit a per-refund supply delta, a fee-class event or a recipient balance change. The legacy public treasury and issuance interfaces require a separate migration/accounting boundary. The escrow's prepaid fee and split are fixed by v0.1 rules so an old valid escrow remains resolvable when a node or wallet is updated.

The hidden `TREASURY_MERGE` branch lets the treasury consolidate two positive notes below the cost of a normal payment. Both inputs must belong to the fixed treasury authority and their spends require treasury authorization. Exactly their sum goes to the single treasury output under that same authority. Both user outputs and the retirement output are zero. The charged fee is zero. The public envelope is identical to a payment. Operator payouts use the standard fee-paying path.

### FRAME integration and denial-of-service budget

The candidate runtime entry is a self-authorizing general extrinsic using the SDK's `AuthorizeCall` path. Its `validate` delegates authorization and its `prepare` passes through the returned weight. Mere receipt of an authorized origin does not authenticate this particular witness across arbitrary nested dispatch paths. Specify and test a single inclusion path that establishes proof validity, binds the exact call effect and performs the stateful checks synchronously with atomic writes. A simple reference implementation can verify again in dispatch and charge for the actual worst case. Remove duplicate verification only after proving equivalent behavior on block import, revalidation, pooled and directly authored calls, nested dispatches and upgrades. [Polkadot SDK stable2609, 12 Oct 2026, source inspected 19 Nov 2026](https://github.com/paritytech/polkadot-sdk/blob/polkadot-stable2609/substrate/frame/system/src/extensions/authorize_call.rs)

Separate block safety from RPC safety. Invalid requests cannot pay an on-chain fee. Bound per-peer and global in-flight verification work and queue lengths before pairing, enforce a local CPU budget, discard stale envelopes early and identify successful pool candidates by both conflict serials. For off-chain admission, a positive proof-verification cache MUST bind the exact proof bytes as well as the effect digest and the active profile/VK fingerprint. Never let an invalid proof poison a digest permanently or let a cache bypass state checks. Block import must yield identical results with an empty cache or none at all. Expose capacity and overload uniformly across transaction classes. Rate policy can affect anonymous users sharing a gateway and belongs in the operational privacy tests.

Freeze a reference Wasm runtime, node executor and host registration. Register compatible EC host calls in every supported execution path and cross-check outcomes with an independent reviewed reference. RFC-0163 specifies curve operations and its host decoding omits prime-subgroup checks. The tag's EC crate provides the BLS12-381 host tuple. These are pieces of a verifier, and the exact Rust proving-library-to-runtime adapter still requires a compatibility test and review. [RFC-0163, 21 Jan 2026](https://polkadot-fellows.github.io/RFCs/approved/0163-ec-host-functions.html) · [SDK EC source, stable2609, 12 Oct 2026](https://github.com/paritytech/polkadot-sdk/blob/polkadot-stable2609/substrate/primitives/crypto/ec-utils/src/lib.rs)

Benchmark the complete path on reference validator hardware with valid and rejected proofs, subgroup failures, full queues, Merkle frontier carries, checked-size decoding, maximum encrypted-body sizes, nullifier database writes/reads and repeated validation. Charge both execution time and storage-witness weight. Enforce block bytes and irreversible state growth separately. Bootstrap distribution, issuance authority, operator disbursements, runtime migration, and emergency governance each require their own conservation and authorization checks wherever they meet this pool. A verifying-key replacement can change the monetary rules. Treat it as a consensus upgrade, including a plan that preserves existing notes, serials and permanent retirement.

**Manifest gate.** Fix slot widths, tree depth and hash with position ordering, empty roots, anchor retention, commitments/serial derivations and cross-domain security, encryption/key-validation and covering distributions, exact effect-domain test vectors, note field encodings, claim clock/window policy, fixed tariff, archive/recovery profile, circuit constraints, setup transcript, VK hash, verifier behavior, runtime/host revisions and weight ceilings before interchange or release. Define `rules_id` from a canonical, immutable parameter record whose bytes are independent of the circuit key hash. The runtime binds the tuple to the VK and manifest. No circuit should be required to contain the hash of its own resulting setup/key. Two independently generated encoders and a validator/prover round-trip must reproduce the same public effect and statement on all positive and negative vectors.

## 6. Wallet discovery, recovery and delivery

**Wallet contract.** An honest party with its backed-up keys, a complete finalized chain history and an available submitter MUST be able to discover its funds and construct its side of an unresolved escrow without contacting the other party. Submission before expiry additionally requires timely inclusion. An encrypted off-chain notification MAY improve the display latency. Receiving one MUST NOT unlock a balance, start a channel or serve as the sole source of a settlement witness. Ordinary chat remains on Noise over Nym. The on-chain request field is a permanent encrypted contact record.

### What a valid envelope must deliver

| Reader | Data it must recover locally | What that enables |
| --- | --- | --- |
| Ordinary output owner, including a refund beneficiary absent at resolution | Amount, asset/type, receiver data and all randomness or seeds needed to reconstruct and spend the output | Recompute its commitment and obtain its Merkle witness from the public stream. Exercise spending authority using a separate secret. |
| Each principal of an opened escrow | The same complete escrow opening, including principal, reserve, authorities, bound payout and refund receivers, terms and the common nullifier material. Inclusion metadata comes from the finalized leaf. | Verify the opening and compute the same escrow nullifier. Each can exercise only the branches authorized for its own key. |
| Intended contact | The complete 427-byte encrypted application object `B427` from its authorized outer contact container, the relevant private receipt and a binding to this payment or escrow and rendezvous | Check the signed policy and amount, reject replay and decide locally whether to show a request. |
| Fee treasury when entitled | Witnesses for its assigned shielded receipts | Recover and spend its allotted funds under treasury policy. A treasury decryptor learns its own contribution amounts. |

For each mandatory delivery the proof relation MUST bind the designated recovery public key to the authorized receiver and the recoverable plaintext to the corresponding note opening or contact effect. Proving knowledge of *some* ciphertext, or hashing its bytes into the signed transaction, gives no assurance that a third-party refund beneficiary can decrypt the right opening. The concrete suite MUST specify a verifiable encryption relation and provide test vectors for maliciously inconsistent or misaddressed capsules. No relation may require an absent beneficiary’s spending secret. Padding slots must follow the same public encoding and ciphertext distribution as filled slots under the stated key-privacy assumptions. A published contact key must not permit the public to test which encapsulations targeted it. **These are open cryptographic and phone-cost gates.** A client library that only encrypts and decrypts does not supply a circuit gadget or a proof of key privacy for this combined construction. A relevant design precedent for sender/recipient checks on diversified addresses is [Zcash ZIP 212, 2019-03-31](https://zips.z.cash/zip-0212).

The suite MUST bind authenticated encryption to unambiguous pre-encryption context such as network, suite, ordered output commitments and logical slot index. It MUST define fresh scheme-appropriate ephemeral randomness, nonce management, key validation and ciphertext parsing. A ciphertext cannot depend on a final envelope hash that includes itself. The outer proof MUST in turn bind the final transmitted bytes. A failed match is discarded locally. No success- or failure-dependent network receipt, push notification to a remote provider, detailed error or data fetch is permitted in the privacy profile.

For an escrow, anyone with enough decryption access to recover its entire opening can track its shared nullifier. Mark that explicitly in view-key export screens. A third party that obtains only the contact card's public keys learns neither the opening nor spending authority by design. A wallet that exports a recovery key, an escrow receipt or a payment-specific disclosure must explain the actual fields it reveals. Domain separation does not protect against compromise of a root secret from which every child key is derived.

### Finalized scanning and mobile restore

1. Anchor to the configured genesis and validate the chain's chosen finality proof, including changes of validator authority. Advance only over contiguous authenticated finalized block ranges. For each range obtain an ordered inventory of commitments, inclusion times, nullifiers and delivery bytes for **all** envelopes in that range. Verify completeness against finalized full extrinsic bodies or a consensus-authenticated ordered scan commitment with exact count. An inclusion proof for the entries a server chose to return does not prove completeness.
2. Trial-decrypt each candidate locally using each active recovery role. On a match verify the tag, suite, context, commitment, recognized receiver, note type and local policy. Add the leaf position to the witness set. Advance the local tree and compare its root/count to consensus. Mark a note spent only upon observing its authorized nullifier on the finalized stream. An incoming-only wallet without the required nullifier derivation MUST label spent status unknown. Separate tentative submissions, included-but-unfinalized activity and finalized balances.
3. Fetch the same public range and full payload buckets on a common schedule, whether or not decryption succeeded. Never request an individual leaf path, nullifier or matching transaction in the private profile. If authenticated data are stale, missing or inconsistent, keep the last verified checkpoint, report the oldest unscanned range and retry through independent sources on the ordinary schedule. A cryptographically valid but stale prefix is insufficient to assert a current balance.
4. Persist the finalized cursor, root/frontier, owned-note records, pending envelopes and relevant nullifier evidence atomically in an encrypted local journal. Distinguish data regenerable from backed-up spending, viewing and recovery keys plus a full rescan from device-only contact state, invitation secrets, policy counters and blocks. Back up those separately with integrity and rollback detection, including historical key versions. After backup rollback reconcile against finality before reissuing a payment or relaxing contact restrictions. If current block policy cannot be recovered, quarantine incoming requests until the owner reconciles it. Never silently treat an empty restore as an empty block list.

Measure initial restore and steady-state sync separately, including all capsule bytes, proof data needed for authentication, battery, RAM, trial decryption and background suspension on target phones. A new installation must not silently switch to a per-note RPC or disable transport protection when a full historical scan takes too long. A coarse public birthday bucket may bound a restore if its start is at or before the earliest possible receipt for every recovered key. For Zcash's compact-block precedent and its distinct honest-but-curious proxy assumption, see [ZIP 307, draft created 2018-09-17](https://zips.z.cash/zip-0307).

### Submission, traffic observation and archival privacy

Pass the finished, self-authorizing envelope to a relay through the mixnet. Keep relay traffic and sync requests free of common account IDs, application cookies or client-specific delivery tags. Do not send a contact acknowledgement at the instant the wallet recognizes a payment. Choose a public, common transport profile and test it with the messaging, scan and submission flows running together. Wallets that cannot maintain the profile, for example while a phone sleeps, must accurately describe the resulting coverage gap. Mix nodes and data services may censor, delay or correlate observable traffic. Fixed envelope shape cannot hide an isolated user's activity or the fact that a phone came online. Sustained downloads and destination-visible query patterns are explicit limitations in [Nym's developer documentation, 2026-11-17](https://nym.com/docs/developers/limitations).

Keep **427 bytes** as the size of `B427`. Its own application plaintext allowance depends on its inner framing. Include the outer contact container, encapsulation and escrow-recovery overhead in wire and archival budgets. If the product requires 427 bytes for the *entire* on-chain record, the proposed hybrid delivery profile cannot meet that budget. ML-KEM-768 alone has a 1,088-byte encapsulation and a 1,184-byte public key. A standardized KEM is only one component. Before claiming archival confidentiality, select and independently review a recipient-hiding hybrid, the encryption-correctness circuit, all alternate recovery copies and both sides' backup policy. A classical duplicate carrying the same sensitive fields defeats a hybrid protection claim for those fields. A classical prototype MUST identify its archival exposure. Protecting notes alone leaves classical proof soundness and authorization as separate migration problems. [NIST FIPS 203, Table 3, 2024-08-13](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

## 7. Worked settlement

These are **test parameters chosen for this draft**. They are denominated in base units and do not set the launch price. Set the base/settlement fee `F = 7`, stranger opening fee `G = 25`, and burn one third of each network fee, rounding down. The independent refund penalty is 1%, also rounded down. Give the sender one 50,000-unit ordinary note. The recipient quotes a principal of 12,345. The initial and resulting private amounts below are known to the participants or appropriate treasury viewer. They do not appear on the wire.

| Step or alternative | Sender’s ordinary notes | Recipient’s payout | Escrow | Treasury credit in this step | Retired in this step |
|---|---:|---:|---:|---:|---:|
| Initial state | 50,000 | 0 | 0 | 0 | 0 |
| Stranger opens | 37,623 change | 0 | 12,352 | 17 | 8 |
| Recipient claims | 37,623 | 12,345 | Consumed | 5 | 2 |
| Recipient declines, **or** sender cancels/reclaims | 37,623 + 12,222 | 0 | Consumed | 5 | 125 |

The last two rows are alternative spends of the same 12,352-unit leaf. On refund the sender gets `12,345 − 123 = 12,222`. The 125 retired at settlement is 123 from the penalty plus 2 from the already-funded fee. Prior fee credits remain in the treasury. The two final supply checks are `37,623 + 12,345 + (17+5) + (8+2) = 50,000` and `37,623 + 12,222 + (17+5) + (8+125) = 50,000`.

Suppose the opening entered the chain at consensus second 100. Its deadline is 86,500. A recipient claim included at 86,499 is eligible under the exact-seconds profile. A claim first included at 86,500 fails even if it was constructed and broadcast earlier. A sender refund qualifies at either time if the escrow is still unspent. If both submit at 86,499, the first valid canonical spend consumes the serial. A recipient who only saw an accepted handshake or the common serial on chain still needs evidence of its **actual claim effect**. A matching finalized payment/claim, or the recipient’s own finalized claim digest with the required effect, is appropriate. Seeing the serial alone also happens on a cancellation.

If prices of 0 to 99 units are permitted, rounding the penalty down retires zero principal at those prices. This draft permits zero-priced stranger quotes while charging the full stranger opening fee and reserve. A zero-valued claim still creates the mandatory, recipient-recoverable receipt bound to the originating escrow and outcome. Encode that private receipt link in the settlement delivery plaintext and enforce it in the relation. An application that wants a positive principal penalty for every refund needs a minimum quoted price of at least 100 units or a new rounding rule.

### Header and digest test fixture

This **serialization-only fixture** lets two implementers test field order and byte-to-field packing before the cryptographic suite is chosen. It uses artificial one-byte ciphertext containers. It is not a valid private transaction. Encode `format=1, suite=1`; use bytes `01, 02, 03, 04` repeated 32 times apiece for network, pool, rules and anchor respectively, then `window=100`. For the two nullifiers, four commitments and admission commitment respectively use bytes `05` through `0b`, each repeated 32 times. Finally append the nine single bytes `0c 0d 0e 0f 10 11 12 13 14`, with no proof. All hex values denote octets. This makes the header 364 bytes and the fixture effect 373 bytes. Apply the exact effect domain in §5, which is distinct from the H1 object-hash domain.

| Result | Expected |
|---|---|
| SHA-256 digest, bytes in hash output order | `9f2b86fedaae2c0463dfc7a0ed5ffdc30c560da499236943d18c90be65877631` |
| First 16 digest bytes, interpreted as a little-endian integer | `260515055939014002119371549945331329951` |
| Last 16 digest bytes, interpreted as a little-endian integer | `65747609009085796524273109977824843276` |

## 8. Privacy limits and operating decisions

- A chain recorder sees inclusion times, counts, occupancy, envelope sizes, roots, commitments, serials, eligible windows, the published tariffs and which output positions are reserved for the treasury and retirement. Four output slots do not supply four equally plausible user beneficiaries.
- Competing resolutions or replacement submissions reuse at least one public serial. A mempool recorder can link those attempts, see which won, and sometimes infer a contested request from the timing or submitters. Equal lengths do not hide such a conflict. The public serial of a *single* accepted spend does not by itself identify its originating leaf to an unrelated observer under the proposed assumptions.
- Senders and recipients know their own transaction, quoted amount and off-chain peer. Both escrow principals can recognize when their shared serial appears. Treasury viewing authority sees individual fee amounts. A transferred viewing capability, exported wallet data or a cooperating counterparty can reveal more.
- Reporting the exact retirement increment or a public total-issuance change on each refund would reveal a narrow interval for the principal. A wallet’s confidential-balance accounting cannot simultaneously provide an exact public running total of all these variable burns. Any epoch disclosure requires its own small-batch leakage analysis.
- The existence of public contact cards, advertised prices, historic balances, previous public channel openings/blocks, legacy conversion events and data a user intentionally shares is public. First-use directory substitution, reused contact credentials, exchange records, device compromise and recipients giving out their own keys are outside the ledger’s protection.
- Packet endpoints at the observer’s vantage points, when a phone comes online, retry patterns, mix congestion, and the timing between payment and a conversation may identify participants. When only one pair is plausible, a perfectly hiding commitment cannot create another pair. No numerical whole-network anonymity guarantee has been established for this design.
- Funds do not automatically return while every authorized submitter is offline. Under censorship or a halted chain, a valid claim may miss expiry and a valid refund may be delayed. A lost device with incomplete backup or missing history can also prevent recovery.
- The reference proof and key-exchange targets are classical. Archived request bytes, alternate recovery copies, future breaks of authorization or proof assumptions and a compromised historical key have different consequences. A hybrid note-encryption upgrade alone would leave other classical components. Existing clear records and already copied vulnerable ciphertext cannot be taken back.

**Timing decision for a real deployment.** The exact reference profile is an intentionally demanding test of the stated 24-hour rule. A wallet can build a proof well before its one-second target and a relay may queue it for that target. Only inclusion in the target second is valid. A phone need not prove in one second; block-production predictability, the proof lead time, repeated submissions and the mixnet’s tail latency determine whether this works. The chain may have no block in a chosen second. Local relay policy must permit bounded future buffering without treating those envelopes as currently includable.

Two alternatives have materially different behavior. An aligned, wider **ledger slot clock** whose slot duration divides 86,400 permits a longer common window, with expiry exactly 24 hours between slot timestamps and rounding relative to physical inclusion time. A wider window with **actual insertion seconds** retains the hard no-late-claim rule but can end recipient claim availability less than one window early. Sender refunds remain available throughout. Benchmark all three on the intended block schedule. Do not switch time semantics in a live escrow. Revealing the originating block or individual deadline to simplify verification risks linking a claim with a particular opening.

**Why choose this candidate?** It keeps authorizations, fees and settlement in one bounded proof and gives all branches a common public representation. Its principal weakness is the price of that representation. Nine fixed delivery containers, recipient-key checks, byte hashing, money signatures and both sides’ recovery guarantees must fit a phone prover and a viable full-sync policy. The system could be financially sound and still be unusable on an offline-first phone. If the full escrow relation or its encrypted delivery has no feasible reviewed instantiation, keep the protocol at test value. Relaxing unilateral recovery, moving transaction witnesses to a hosted prover or exposing a branch to save work would each change what users are being promised.

For a bandwidth illustration, suppose both financial container widths were 512 bytes, the contact container 1,024 bytes and the proof 192 bytes. One envelope would be 5,676 bytes. A raw full-envelope scan across 10,000, 1 million and 100 million output commitments would then transfer **14.19 MB, 1.419 GB and 141.9 GB**, respectively, before headers or transport overhead, using decimal units. These widths are hypothetical. The illustration assumes neither that the encrypted data fit nor that a phone can scan at a particular rate.

A relay may submit a fully constructed, fixed-destination refund without holding a spending key. An optional sender-operated or delegated scheduler could hold a preproved envelope for a chosen future window. That works only if the anchor is still accepted, the opening stays canonical, the stored terms still verify and a block includes that window. Retrying a missed window normally requires a new proof. A scheduler learns the timing and can withhold submission. v0.1 confers no general refund authority on a relay.

## 9. Security properties and acceptance evidence

These are **review targets** for this proposal. Passing a reference-model test establishes an example of the rules. A deployed claim also requires a proof or security argument for the specified construction, evidence about the implementation, and an operating environment that meets the assumptions.

### What the security review must establish

| Property | Experiment or invariant | Pass condition |
| --- | --- | --- |
| Chain privacy for honest parties | Let an observer choose two valid histories with the same public context, transaction schedule, envelope sizes, window identifiers, allowed external value flows and information legitimately available to corrupted parties. In separate challenges, swap senders, recipients or channel partners, change a hidden amount, or swap two eligible private action types. Maintain enough funded honest parties for **both** histories to remain possible. Choose a secret random bit and generate a fresh real chain for that history. Show the observer the complete chain and mempool transcript, including proofs, ciphertexts, roots and nullifiers. | For the computational model, require negligible advantage `abs(Pr[correct bit] − 1/2)` under explicit assumptions. Commitment and ciphertext *values* must be generated and exposed in the experiment. Requiring them to match across histories in advance would make the test meaningless. Repeated/replaced submissions and later spends belong in the transcript. Match the structural conflict pattern when testing cryptographic hiding, without fixing the serial values themselves. Analyze additional conflicts generated by real behavior in the whole-system experiment. An observer can directly distinguish a history with a visible contested serial from a history with no repeated serial. |
| Contact-key privacy and discovery | Give an observer two honest public contact cards, including their public encryption keys. Use each as a candidate for a real padded envelope with a hidden choice of card. Allow the documented results of interactions with unrelated addresses and valid decryption by authorized recipients. | Recipients recover their own records. Knowing both public cards gives the observer negligible distinguishing advantage under the claimed key-privacy model. State separately how invalid envelopes, delivery acknowledgements, later receipt disclosure, or compromise of a historical viewing key affect that model. |
| Whole-system privacy | Run the same two choices with the same external workload, observer side information and number of online honest clients. Give the observer packet endpoints, timing, sizes, the chain, mempool and records visible at the chosen mix, relay and RPC nodes. **Generate the network traffic** for each history, including synchronization, retries, proof generation and phone wakeups. | Specify the corruption budget and placement, traffic policy, tolerated advantage and statistical power before testing. Report a held-out confidence bound against the predeclared threshold and an observer with side information alone. Analyze clustered sessions by user/run. A successful test supports only the sampled conditions. Show sparse traffic, offline users, censorship and isolated requests as separate scenarios. |
| Authorization and value conservation | Quantify over every reachable valid state, every valid transition and every permitted upgrade. Each real input opens an included, unspent, eligible note. Each output has the required type, amount, beneficiary and recovery data. Count the escrow reserve exactly once. Account for all externally backed mint/withdraw effects, operator assets, spendable value and cumulative retired value. | A party without the branch authority cannot release value or redirect another party's payout. An accepted transition preserves the supply equation over integers and cannot spend or migrate retired value into circulation. Possessing the escrow opening or its common nullifier material alone gives no spending authority. |
| Single settlement and conditional progress | Resolve one opening under every authority, branch, recognized anchor and time window. Assume an eligible party has keys, opening data, a fresh path, and a valid submission opportunity in an advancing chain. Distinguish inclusion from finality and check the result after replay/reorganization. | All paths use the same nullifier for that ledger note. At most one resolution finalizes on the canonical history. A duly funded eligible party can construct the promised outcome without obtaining the other party's signature, paying from an unrelated balance or receiving a private RPC answer. The protocol supplies eligibility after the deadline. An agent and eventual transaction inclusion supply progress. |

Two limiting cases belong in the threat model. An observer who knows there is only one possible online recipient can identify that recipient from availability alone. An escrow counterparty who shares the opening may recognize the escrow's resolution from its common nullifier. Exclude neither fact from the product's disclosure to users. Where an adversary can learn a challenge secret from an authorized counterparty, viewing key, exposed endpoint or deliberate disclosure, record that information as a distinct threat scenario.

### Minimum conformance and implementation checks

| Test family | Required result |
| --- | --- |
| Integer boundaries | Test permitted prices around 100 base units. For `P = 99, 100, 101`, the penalty and refund pairs are `(0,99)`, `(1,99)`, `(1,100)` where those prices are admitted. Reject prices outside policy, field-wrap representations and an overflowing sum. Acceptance pays exactly `P`; the reserve funds settlement separately. Test the greatest admissible value with every fee component present. |
| Deadlines and contention | Test windows on each side of the authenticated creation time plus 86,400 seconds, windows that straddle it and the exact boundary under the specified inequalities. A stale pre-deadline anchor never extends claim eligibility. Order a timely claim and cancellation both ways on local fixtures, then replay the losing submission. Only the first valid canonical consumption applies. Reorganization restores both nullifier and wallet pending state consistently. |
| Authority and destination | Reject a wrong-authority claim, mismatched quote/recipient binding, unauthorized discount, changed policy output, or a refund payable to the resolver. A recipient with only its restored, specified local secrets and the authenticated chain can discover the opening and compute its authorized transition under the stated recovery contract. Apply the same check to the sender's refund. Exercise intentionally lost optional backups and identify which records become unrecoverable. |
| Ciphertext and delivery | Replacing effect bytes after proving fails verification. Separately check the **semantic** property for a freshly generated proof and arbitrary candidate ciphertexts: an accepted adversarial resolution must still leave its fixed beneficiary a recoverable monetary output. For each escrow write down the opening data both parties need. Demonstrate that every supported family of accepted outputs is recoverable as specified, including under mismatched key/plaintext inputs. No transcript proves a recipient read the request. |
| Shape and correspondence | For ordinary transfers, invited contacts, stranger openings and all resolutions, compare total byte count, proof-key selector, counts and positions, fee metadata, event layout, validity-window policy and RPC patterns. No purportedly hidden field may select a publicly distinguishable format. A party who knows a public contact card alone cannot use the canonical receiver API to recognize its notes. Report timing distributions even when sizes match. |
| Runtime and upgrades | Verify the same vectors under the standalone validator execution path and a pinned independent reference. Reject noncanonical encodings, disallowed subgroup/identity elements, wrong arity, extra bytes, repeated nullifiers and invalid proofs. Failed state application leaves **every** consensus write and fee-accounting effect unchanged. Require cross-chain/domain and pre/post-activation tests. Check old valid notes still exit under the published policy, closed escrow stays closed, and retired value stays retired. |
| Wallet and RPC | Test 10k, 1m and 100m synthetic outputs with known nonempty wallets, corrupt blocks, omitted records, stale prefixes, restarts and duplicate/reorganized blocks. A wallet cannot mark a range complete unless its completeness checks succeed against an authenticated finalized header for that range. A stale but valid prefix must expose its sync height and freshness. Compare queries from hit and miss cases, including payload and Merkle-path fetches. An offline/missing-data wallet must show incomplete state. |
| Resource and side-channel budgets | Publish release-build measurements on named validator, Android and iOS hardware. Include cold/warm complete proofs for each private action, peak resident memory, repeated-use thermals, scanning/restoration bytes and time, battery cost, as well as runtime verification, worst invalid requests, transaction-pool revalidation and block saturation. Predeclare limits and measure proof-to-broadcast and receipt-to-reply timing under matched sessions. Any exceeded bound blocks the corresponding performance or privacy claim. |

### Release gates

1. **Semantic review.** Freeze a table of public fields and leakage, authority/beneficiary table, spendability equations, clock boundaries and a precise wallet recovery contract. Publish valid and invalid examples. Identify which requirements rely on recipient software or an online agent.
2. **Cryptographic review.** Pin domains, randomized canonical encodings, primitive security properties, exact proof statement and public-input mapping. Obtain an independent protocol-and-circuit review covering every constraint and composition, including ciphertext delivery, common nullifiers and shielded supply. Record precise theorem statements if using formal proofs.
3. **Implementation and operations.** Publish reproducible circuit, prover, verifier and runtime hashes. Obtain independent wallet, runtime/host, network and ceremony-tool reviews. Complete the device, full-stack observer, worst-case block and recovery tests against predeclared budgets. Test hold, rollback and migration procedures, and disclose who can delay settlement or change a verifier.
4. **Real-value release.** Bind any production phase-two ceremony to the exact reviewed circuit and publish a verifiable transcript plus verifier-key hash. Reassess changes after review. Publish dated scope, exclusions, findings and retest links for each assurance claim. Assign an owner and public status to each unclosed gate. Use disposable parameters and valueless assets until a production decision.

Two primary references explain the review scope. A published study found receiver-side timing leakage and amount-dependent proving times in earlier wallet implementations, which motivates the network and device tests. Zcash's ZIP 257 documents a 2026 circuit fix, verification-key change and canonical-proof-length rule, which motivate version-specific circuit and decoder review. [Tramèr, Boneh and Paterson, August 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/tramer) · [ZIP 257, 9 June 2026](https://zips.z.cash/zip-0257)

## 10. Implementation order and release decisions

Use the following order because each step can rule out the next large expense. None requires a public mainnet or a production ceremony.

| Order | Deliverable | Decision and evidence |
|---:|---|---|
| 1 | Independent state-machine and money review | Reconcile genesis/backing, the two separate fees, all resolutions, identical nullifiers, hidden burn, treasury authorization and permanently retired notes. Run the Rust fixtures below. Extend to arbitrary sequences and treasury merges with an independent model. Prove that accepted transitions cannot create spendable units. |
| 2 | Two-wallet, malicious-creator escrow feasibility test | Produce and recover an opening, a recipient-created refund and a sender-created cancellation. Disconnect the beneficiary at settlement and wipe its cache. Restore it with only the documented keys/backups and finalized history. Require recovery of the correct amount, destination and spend witness. Account for all nine encrypted containers, key/privacy assumptions, byte encodings and reviewed gadgets. An ordinary happy-path transfer does not answer this question. |
| 3 | Full statement on the intended Rust/FRAME execution path | Compile the complete worst-case relation into a disposable Groth16 circuit. Verify its exact vectors in native and standalone Wasm nodes with the chosen SDK host configuration. Measure parsing, full proof checks, cold and warm state, invalid submissions, weight, block bytes and storage growth. Derive a defensible block limit with reserved capacity for the rest of the chain. |
| 4 | Full proving and timed submission on Android and iOS | On named devices report median/p95/p99 time, peak RSS, thermal throttling and battery cost for every branch. Run two honest wallets on the intended Nym path with realistic sleep/reconnect, congested pools, early queueing and a real block schedule. Record eligibility interval, inclusion time, misses and missed-claim monetary consequence. Predeclare an acceptable success rate and deadline margin. Failure of the one-second target requires an explicit clock/product decision. |
| 5 | Full-chain wallet privacy and restore | Exercise 10k, 1m and 100m outputs. With four commitments per transaction these correspond to 2,500, 250,000 and 25,000,000 complete envelopes under this profile. Multiply by the **full** per-envelope size in §5 for raw envelope traffic before headers, indices, transport and compression. Report privacy leakage and performance for new users and returning phones separately. Prove ordered completeness or verify complete finalized bodies. |
| 6 | Joint observer and operations review | Test the same public workloads with different honest users, action types and amounts. Include the directory, relay, RPC provider, phone behavior and individual treasury viewers. Write the corruption assumptions, observed leakage, migration boundaries, treasury key recovery and emergency rules into the public operating profile. |
| 7 | Independent audits, frozen parameters and release | Publish exact code/constraint hashes, fixed wire and encryption suites, vectors, audit findings and remediation. Run the reviewed circuit-specific ceremony after the circuit freezes. Reproduce keys and verifier artifacts from the transcript. Test upgrade and recovery on historical fixtures. Begin with capped exposure only after the cryptographic, implementation, wallet and operational gates pass. |

### Decisions that remain open

1. **Recoverable, recipient-anonymous encryption.** Name the exact reviewed primitives, implementations and matching circuit gadgets. Show why publicly known contact keys cannot be used to recognize targeted ciphertexts, why refunds decrypt correctly to an absent sender, and how covers are generated. Specify the widths, current classical exposure and whether hybrid protection is possible for every sensitive copy. If a reviewed component cannot do this, the strict delivery profile remains uninstantiated.
2. **Delegation, signatures and key recovery.** Freeze the ordinary/note receiver relation, secrets needed to derive serials, exact signature transcripts, holder permissions, seed backup rules and rotation behavior. Shared escrow-view capability exposes that escrow’s serial. A treasury recovery key with broad scope is a privacy-sensitive governance role.
3. **Time and transport.** Measure validator timestamps and allowed skew. Specify finalized header/time verification, eligible-root retention versus proof lead time, minimal relay behavior and what a wallet tells a user during the final minutes. Decide whether a wider slot clock satisfies the product if target-second inclusion fails. No guarantee of automatic payment at expiry is made.
4. **Operating scale and metadata.** Select and justify the degree of node compromise to tolerate, traffic generation policy, supported mobile resource limits, scan bandwidth and pilot population. An anonymous operation model requires empirical data beyond circuit tests. Choose real fee rates and reward policy after measuring costs and their privacy effects.
5. **Migration, upgrades and assurance.** Pin legacy supply reconciliation, lost-contact backup handling, immutable note identities across upgrades, sunset/escape rules, complete authorized mint boundaries, ceremony governance, audit scope and legal operating model. The preceding technical research report covers regulatory and prior-art evidence as of 19 November 2026. This specification chooses no jurisdictional compliance mechanism. [Prior research report, 19 Nov 2026]

## Appendix A. Executable Rust escrow model

The following single-file Rust model checks **one escrow’s settlement semantics**. Its inputs assume authenticated roles, creation time, fee terms and inclusion time. Its consumed bit models one escrow’s common nullifier on one canonical history. The model accepts general validity intervals to exercise the wider-window boundary as well as the exact-seconds profile. Window scheduling is an external precondition. It does not implement a proof, encryption, a FRAME pallet, the opening network fee or the full note tree.

Save the code block as `escrow_v01.rs`. On Windows run `rustc --edition=2021 --test escrow_v01.rs -o escrow_v01_tests.exe` followed by `.\escrow_v01_tests.exe`. On Linux or macOS choose an output name without the suffix and run that executable. **Verified on 19 November 2026** with Rust 1.100.0 on Windows x86-64. All six test functions passed, including a matrix of competing settlements, rounding at base-unit boundaries and rejection after expiry. The fixture proves no claim about production cryptography or anonymous traffic.

```rust
// Executable escrow arithmetic and authorization model, v0.1.
// Role, creation time, window and prior consumption are authenticated inputs.
// One Escrow models one ledger note with one common nullifier on one history.
// Network fees at opening and the binding of keys/proofs are outside this model.
const DAY: u64 = 86_400;
type Checked<T> = Result<T, &'static str>;

#[derive(Clone, Copy)]
struct Fee {
    total: u64,
    burn: u64,
}

#[derive(Clone, Copy)]
enum Role { Sender, Recipient, Other }
#[derive(Clone, Copy)]
enum Action { Claim, Decline, SenderRefund }

#[derive(Debug, PartialEq)]
struct Payout {
    recipient: u64,
    sender: u64,
    treasury: u64,
    retired: u64,
}

struct Escrow {
    principal: u64,
    funded: u64,
    fee: Fee,
    created: u64,
    deadline: u64,
    consumed: bool,
}

impl Escrow {
    fn open(principal: u64, fee: Fee, funded: u64, created: u64) -> Checked<Self> {
        let required = principal.checked_add(fee.total).ok_or("funding overflow")?;
        if funded != required || fee.burn == 0 || fee.burn >= fee.total {
            return Err("wrong escrow funding or fee split");
        }
        let deadline = created.checked_add(DAY).ok_or("clock overflow")?;
        Ok(Self { principal, funded, fee, created, deadline, consumed: false })
    }

    fn resolve(&mut self, role: Role, action: Action, window: (u64, u64), now: u64)
        -> Checked<Payout>
    {
        let (lower, upper) = window;
        if self.consumed || now < self.created || !(lower <= now && now < upper) {
            return Err("consumed or ineligible at inclusion");
        }
        let before_deadline = upper <= self.deadline;
        let refund = match (role, action) {
            (Role::Recipient, Action::Claim) if before_deadline => false,
            (Role::Recipient, Action::Decline) if before_deadline => true,
            (Role::Sender, Action::SenderRefund) => true,
            _ => return Err("wrong authority or window"),
        };
        let penalty = if refund { self.principal / 100 } else { 0 };
        let payout = Payout {
            recipient: if refund { 0 } else { self.principal },
            sender: if refund { self.principal - penalty } else { 0 },
            treasury: self.fee.total - self.fee.burn,
            retired: self.fee.burn.checked_add(penalty).ok_or("retirement overflow")?,
        };
        let accounted = [payout.recipient, payout.sender, payout.treasury, payout.retired]
            .into_iter().try_fold(0u64, u64::checked_add);
        if accounted != Some(self.funded) {
            return Err("conservation failure");
        }
        self.consumed = true;
        Ok(payout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::Action::{Claim, Decline, SenderRefund};
    use super::Role::{Other, Recipient, Sender};
    const FEE: Fee = Fee { total: 7, burn: 2 };
    const BIRTH: u64 = 100;
    const D: u64 = BIRTH + DAY;
    const EARLY: (u64, u64) = (D - 10, D);
    const LATE: (u64, u64) = (D, D + 10);

    fn escrow(p: u64) -> Escrow {
        Escrow::open(p, FEE, p.checked_add(FEE.total).unwrap(), BIRTH).unwrap()
    }

    #[test]
    fn refund_rounds_down_in_base_units() {
        for (p, penalty) in [(0, 0), (1, 0), (99, 0), (100, 1), (101, 1), (12_345, 123)] {
            let result = escrow(p).resolve(Recipient, Decline, EARLY, D - 1).unwrap();
            assert_eq!(result, Payout { recipient: 0, sender: p - penalty,
                treasury: 5, retired: 2 + penalty });
        }
    }

    #[test]
    fn exact_reserve_and_frozen_terms_preserve_full_claim() {
        let mut schedule = FEE;
        let mut e = Escrow::open(101, schedule, 108, BIRTH).unwrap();
        schedule.total = 42;
        schedule.burn = 31;
        assert!(Escrow::open(101, schedule, 108, BIRTH).is_err());
        assert_eq!(e.resolve(Recipient, Claim, EARLY, D - 1).unwrap(),
            Payout { recipient: 101, sender: 0, treasury: 5, retired: 2 });
        assert!(Escrow::open(101, FEE, 107, BIRTH).is_err());
        assert!(Escrow::open(101, FEE, 109, BIRTH).is_err());
    }

    #[test]
    fn bounded_arithmetic() {
        assert!(Escrow::open(u64::MAX, FEE, 6, BIRTH).is_err());
        assert!(Escrow::open(101, FEE, 108, u64::MAX - DAY + 1).is_err());
        assert!(Escrow::open(101, Fee { total: 7, burn: 8 }, 108, BIRTH).is_err());
        assert!(Escrow::open(101, Fee { total: 7, burn: 7 }, 108, BIRTH).is_err());
        assert!(Escrow::open(101, Fee { total: 7, burn: 0 }, 108, BIRTH).is_err());
        let p = u64::MAX - FEE.total;
        assert_eq!(escrow(p).resolve(Sender, SenderRefund, LATE, D).unwrap().sender,
            p - p / 100);
    }

    #[test]
    fn deadlines_use_inclusion_and_the_whole_window() {
        for action in [Claim, Decline] {
            assert!(escrow(100).resolve(Recipient, action, EARLY, D - 1).is_ok());
            assert!(escrow(100).resolve(Recipient, action, EARLY, D).is_err());
            assert!(escrow(100).resolve(Recipient, action, LATE, D).is_err());
            assert!(escrow(100).resolve(Recipient, action, (D - 5, D + 5), D - 1).is_err());
        }
        for (w, t) in [(EARLY, D - 1), ((D - 5, D + 5), D - 1), (LATE, D), (LATE, D + 1)] {
            assert_eq!(escrow(100).resolve(Sender, SenderRefund, w, t).unwrap().sender, 99);
        }
        for (w, t) in [((0, BIRTH), BIRTH - 1), ((D, D), D), (LATE, D - 1), (EARLY, D)] {
            assert!(escrow(100).resolve(Sender, SenderRefund, w, t).is_err());
        }
    }

    #[test]
    fn wrong_authority_never_consumes() {
        for (role, action) in [(Sender, Claim), (Sender, Decline), (Recipient, SenderRefund),
                               (Other, Claim), (Other, Decline), (Other, SenderRefund)] {
            let mut e = escrow(100);
            assert!(e.resolve(role, action, EARLY, D - 1).is_err());
            assert!(e.resolve(Recipient, Claim, EARLY, D - 1).is_ok());
        }
    }

    #[test]
    fn first_canonical_consumption_wins_for_every_pair() {
        let outcomes = [(Recipient, Claim), (Recipient, Decline), (Sender, SenderRefund)];
        for (role, action) in outcomes {
            for (next_role, next_action) in outcomes {
                let mut e = escrow(100);
                assert!(e.resolve(role, action, EARLY, D - 1).is_ok());
                assert!(e.resolve(next_role, next_action, EARLY, D - 1).is_err());
                assert!(e.resolve(Sender, SenderRefund, LATE, D).is_err());
            }
        }
    }
}
```

## Appendix B. Sources and prior work

These are dated primary specifications, source repositories and design precedents cited above, followed where applicable by the project-specific prior research. All normative rules of the proposed protocol are dated 19 November 2026. A component link does not attest to the proposed system.

- [Groth, 2016](https://eprint.iacr.org/2016/260)
- [Zcash protocol specification, 19 Nov 2026, §§3–5](https://zips.z.cash/protocol/protocol.pdf)
- [Sapling Rust source, inspected 19 Nov 2026](https://github.com/zcash/sapling-crypto)
- [SHA-256 specification, Aug 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [Zcash transaction encodings, accessed 19 Nov 2026](https://zips.z.cash/zip-0225)
- [Zcash Foundation, 13 Apr 2018, setup precedent](https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/)
- [Penumbra SwapClaim, accessed 19 November 2026](https://protocol.penumbra.zone/main/dex/action/swap_claim.html)
- [ZIP 32, 2018-05-22](https://zips.z.cash/zip-0032)
- [ZIP 212, 2019-03-31](https://zips.z.cash/zip-0212)
- [Noise Framework revision 34, 2018-07-11, §§6, 7.5 and 13](https://noiseprotocol.org/noise.html)
- [Polkadot SDK stable2609, 12 Oct 2026, source inspected 19 Nov 2026](https://github.com/paritytech/polkadot-sdk/blob/polkadot-stable2609/substrate/frame/system/src/extensions/authorize_call.rs)
- [RFC-0163, 21 Jan 2026](https://polkadot-fellows.github.io/RFCs/approved/0163-ec-host-functions.html)
- [SDK EC source, stable2609, 12 Oct 2026](https://github.com/paritytech/polkadot-sdk/blob/polkadot-stable2609/substrate/primitives/crypto/ec-utils/src/lib.rs)
- [ZIP 307, draft created 2018-09-17](https://zips.z.cash/zip-0307)
- [Nym's developer documentation, 2026-11-17](https://nym.com/docs/developers/limitations)
- [NIST FIPS 203, Table 3, 2024-08-13](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [Tramèr, Boneh and Paterson, August 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/tramer)
- [ZIP 257, 9 June 2026](https://zips.z.cash/zip-0257)
