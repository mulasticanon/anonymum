//! The objects of spec section 3: notes, commitments, leaves, nullifiers,
//! the admission record, and the derived refund note.

use crate::hash::{h, Hash};

/// Amounts are unsigned 64-bit integers in base units; sums are checked
/// (spec v0.5, I4).
pub type Value = u64;

/// Seconds since the chain's epoch.
pub type Time = u64;

/// A secret. Knowing it is how the model represents "holds the authority".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secret(pub Hash);

/// A public identifier: the hash of a secret. Only someone who knows the
/// secret can act with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Authority(pub Hash);

impl Secret {
    pub fn authority(&self) -> Authority {
        Authority(h("authority", &[&self.0]))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Commitment(pub Hash);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct Nullifier(pub Hash);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf(pub Hash);

/// `(price, fee_reserve, recipient, refund_to, canceller, seed, blinding)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EscrowNote {
    pub price: Value,
    /// Prepaid resolution fee; must equal the base fee `F` at opening (P4).
    pub fee_reserve: Value,
    /// May claim or decline.
    pub recipient: Authority,
    /// Owner of the refund note.
    pub refund_to: Authority,
    /// May take the sender refund, at any time.
    pub canceller: Authority,
    /// Shared by both parties; the escrow's one nullifier and (with its
    /// position) the refund note's blinding are derived from it.
    pub seed: Hash,
    pub blinding: Hash,
}

/// Every note of every type carries a fresh secret `blinding`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Note {
    Ordinary { value: Value, owner: Authority, blinding: Hash },
    Escrow(EscrowNote),
    /// Can never be spent.
    Retired { value: Value, blinding: Hash },
}

impl Note {
    /// `H(note)`. The type tag is inside the commitment, so the type is
    /// bound but not public.
    pub fn commitment(&self) -> Commitment {
        Commitment(match self {
            Note::Ordinary { value, owner, blinding } => {
                h("commit", &[&[0], &value.to_le_bytes(), &owner.0, blinding])
            }
            Note::Escrow(e) => h(
                "commit",
                &[
                    &[1],
                    &e.price.to_le_bytes(),
                    &e.fee_reserve.to_le_bytes(),
                    &e.recipient.0,
                    &e.refund_to.0,
                    &e.canceller.0,
                    &e.seed,
                    &e.blinding,
                ],
            ),
            Note::Retired { value, blinding } => h("commit", &[&[2], &value.to_le_bytes(), blinding]),
        })
    }

    /// The value a note contributes as an input or output. An escrow holds
    /// `price + fee_reserve`; `None` if that does not fit the value range.
    pub fn value(&self) -> Option<Value> {
        match self {
            Note::Ordinary { value, .. } | Note::Retired { value, .. } => Some(*value),
            Note::Escrow(e) => e.price.checked_add(e.fee_reserve),
        }
    }
}

/// `H(commitment, created_at)`. `created_at` is stamped by the chain on the
/// window grid. Every note type gets the same leaf shape.
pub fn leaf(commitment: &Commitment, created_at: Time) -> Leaf {
    Leaf(h("leaf", &[&commitment.0, &created_at.to_le_bytes()]))
}

/// An escrow's single nullifier: from `seed`, the commitment and the tree
/// position, so it is the same for every outcome but differs between two
/// insertions of the same commitment.
pub fn escrow_nullifier(seed: &Hash, commitment: &Commitment, position: u64) -> Nullifier {
    Nullifier(h("nullifier/escrow", &[seed, &commitment.0, &position.to_le_bytes()]))
}

/// An ordinary note's nullifier: from a secret only the owner holds (here,
/// the owner's secret), the commitment and the position (spec v0.5, I3).
pub fn ordinary_nullifier(owner: &Secret, commitment: &Commitment, position: u64) -> Nullifier {
    Nullifier(h("nullifier/ordinary", &[&owner.0, &commitment.0, &position.to_le_bytes()]))
}

/// What an unused input slot publishes: derived in its own domain from a
/// secret the prover knows, so it cannot be made equal to a real note's
/// nullifier.
pub fn dummy_nullifier(secret: &Secret) -> Nullifier {
    Nullifier(h("nullifier/dummy", &[&secret.0]))
}

/// `ceil(price / 100)`, computed without overflow.
pub fn penalty(price: Value) -> Value {
    price / 100 + u64::from(price % 100 != 0)
}

/// The refund blinding, derived from the escrow seed and the escrow's tree
/// position, so two escrows that share a seed still get different refunds
/// (spec v0.5, I9).
pub fn refund_blinding(seed: &Hash, escrow_position: u64) -> Hash {
    h("refund-blinding", &[seed, &escrow_position.to_le_bytes()])
}

/// The one refund note a Decline or Sender refund may create for the escrow
/// at `escrow_position`. Fully determined by the escrow and its position,
/// so the sender can find it without receiving anything from whoever
/// resolved the escrow.
pub fn derived_refund(escrow: &EscrowNote, escrow_position: u64) -> Note {
    Note::Ordinary {
        value: escrow.price - penalty(escrow.price),
        owner: escrow.refund_to,
        blinding: refund_blinding(&escrow.seed, escrow_position),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Not a contact request (transfers, resolutions).
    None,
    Invited,
    Stranger,
}

/// `(recipient contact key, request digest, tier, escrow commitment or
/// none, blinding)`. Every transaction carries the commitment to one; the
/// recipient's app opens it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdmissionRecord {
    pub contact_key: Hash,
    pub request_digest: Hash,
    pub tier: Tier,
    pub escrow: Option<Commitment>,
    pub blinding: Hash,
}

impl AdmissionRecord {
    /// The record a transaction that is not a contact request carries. Its
    /// commitment looks like any other, thanks to the blinding.
    pub fn empty(blinding: Hash) -> Self {
        AdmissionRecord { contact_key: [0; 32], request_digest: [0; 32], tier: Tier::None, escrow: None, blinding }
    }

    /// Is this the empty record a non-request carries: tier none, no
    /// escrow, zero contact key and request digest? (The blinding is not
    /// checked: it must be fresh and random, which no rule can see.)
    pub fn is_empty(&self) -> bool {
        self.tier == Tier::None && self.escrow.is_none() && self.contact_key == [0; 32] && self.request_digest == [0; 32]
    }

    pub fn commitment(&self) -> Commitment {
        let tier = [match self.tier {
            Tier::None => 0,
            Tier::Invited => 1,
            Tier::Stranger => 2,
        }];
        let (has_escrow, escrow) = match self.escrow {
            Some(c) => ([1u8], c.0),
            None => ([0u8], [0; 32]),
        };
        Commitment(h(
            "admission",
            &[&self.contact_key, &self.request_digest, &tier, &has_escrow, &escrow, &self.blinding],
        ))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReceiptError {
    /// The opening does not match the public commitment.
    NotThisRecord,
    NotMyContactKey,
    NotThisRequest,
    NotThisEscrow,
    NotARequest,
}

/// The recipient app's check of a request's admission record: the opening
/// must match the public commitment and name this recipient, this request
/// and (for strangers) this escrow. Returns the tier.
pub fn open_receipt(
    public: &Commitment,
    record: &AdmissionRecord,
    my_contact_key: &Hash,
    request_digest: &Hash,
    escrow: Option<&Commitment>,
) -> Result<Tier, ReceiptError> {
    if record.commitment() != *public {
        return Err(ReceiptError::NotThisRecord);
    }
    if record.tier == Tier::None {
        return Err(ReceiptError::NotARequest);
    }
    if record.contact_key != *my_contact_key {
        return Err(ReceiptError::NotMyContactKey);
    }
    if record.request_digest != *request_digest {
        return Err(ReceiptError::NotThisRequest);
    }
    if record.tier == Tier::Stranger && record.escrow.as_ref() != escrow {
        return Err(ReceiptError::NotThisEscrow);
    }
    Ok(record.tier)
}
