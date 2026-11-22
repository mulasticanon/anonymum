//! The spec's objects over `Fr`, mirroring
//! `crates/shielded-model/src/objects.rs` with Poseidon in place of BLAKE2s.
//!
//! Amounts and times are held as field elements in the witness, so a test
//! can hand the circuit a value outside `u64` and see it refused. The
//! constructors take `u64`.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use blake2::{Blake2s256, Digest};

use crate::merkle::MerkleTree;
use crate::poseidon::hash;

/// Merkle tree depth. The circuit and the tree both read this constant.
pub const TREE_DEPTH: usize = 20;
/// Input slots per transaction (the model's `N_IN`).
pub const N_IN: usize = 2;
/// Output slots per transaction (the model's `N_OUT`).
pub const N_OUT: usize = 3;
/// Request lifetime in seconds (the model's `TTL`).
pub const TTL: u64 = 24 * 60 * 60;
/// Number of public inputs.
pub const N_PUBLIC: usize = 11;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Branch {
    Transfer,
    Invited,
    Open,
    Claim,
    Decline,
    SenderRefund,
}

impl Branch {
    pub const ALL: [Branch; 6] =
        [Branch::Transfer, Branch::Invited, Branch::Open, Branch::Claim, Branch::Decline, Branch::SenderRefund];

    pub fn is_resolution(self) -> bool {
        matches!(self, Branch::Claim | Branch::Decline | Branch::SenderRefund)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoteKind {
    Ordinary,
    Escrow,
    Retired,
}

impl NoteKind {
    /// The type tag inside the commitment.
    pub fn tag(self) -> u64 {
        match self {
            NoteKind::Ordinary => 0,
            NoteKind::Escrow => 1,
            NoteKind::Retired => 2,
        }
    }
}

/// One layout for all note types, so the circuit hashes every note once.
/// Fields a type does not have are zero, and the circuit enforces that.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    pub kind: NoteKind,
    /// Ordinary or retired: the value. Escrow: the price.
    pub value: Fr,
    pub fee_reserve: Fr,
    /// Ordinary: the owner. Escrow: the recipient.
    pub owner: Fr,
    pub refund_to: Fr,
    pub canceller: Fr,
    pub seed: Fr,
    pub blinding: Fr,
}

impl Note {
    pub fn ordinary(value: u64, owner: Fr, blinding: Fr) -> Self {
        Note {
            kind: NoteKind::Ordinary,
            value: value.into(),
            fee_reserve: Fr::zero(),
            owner,
            refund_to: Fr::zero(),
            canceller: Fr::zero(),
            seed: Fr::zero(),
            blinding,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn escrow(price: u64, fee_reserve: u64, recipient: Fr, refund_to: Fr, canceller: Fr, seed: Fr, blinding: Fr) -> Self {
        Note {
            kind: NoteKind::Escrow,
            value: price.into(),
            fee_reserve: fee_reserve.into(),
            owner: recipient,
            refund_to,
            canceller,
            seed,
            blinding,
        }
    }

    pub fn retired(value: u64, blinding: Fr) -> Self {
        Note { kind: NoteKind::Retired, ..Note::ordinary(value, Fr::zero(), blinding) }
    }

    /// `H(note)`, with the type tag inside.
    pub fn commitment(&self) -> Fr {
        hash(
            "commit",
            &[
                Fr::from(self.kind.tag()),
                self.value,
                self.fee_reserve,
                self.owner,
                self.refund_to,
                self.canceller,
                self.seed,
                self.blinding,
            ],
        )
    }
}

pub fn authority(secret: Fr) -> Fr {
    hash("authority", &[secret])
}

/// `H(commitment, created_at)`.
pub fn leaf(commitment: Fr, created_at: Fr) -> Fr {
    hash("leaf", &[commitment, created_at])
}

pub fn ordinary_nullifier(secret: Fr, commitment: Fr, position: u64) -> Fr {
    hash("nullifier/ordinary", &[secret, commitment, position.into()])
}

pub fn escrow_nullifier(seed: Fr, commitment: Fr, position: u64) -> Fr {
    hash("nullifier/escrow", &[seed, commitment, position.into()])
}

/// Same arity as the real nullifiers, so one permutation serves all three
/// domains in the circuit; the commitment and position slots are zero.
pub fn dummy_nullifier(secret: Fr) -> Fr {
    hash("nullifier/dummy", &[secret, Fr::zero(), Fr::zero()])
}

/// The derived blinding of a refund or a claim's surplus note.
pub fn refund_blinding(seed: Fr, escrow_position: u64) -> Fr {
    hash("refund-blinding", &[seed, escrow_position.into()])
}

/// `ceil(price / 100)`.
pub fn penalty(price: u64) -> u64 {
    price / 100 + u64::from(price % 100 != 0)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputKind {
    Dummy,
    Ordinary,
    Escrow,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputWitness {
    pub kind: InputKind,
    pub note: Note,
    pub created_at: Fr,
    pub position: u64,
    /// `TREE_DEPTH` siblings.
    pub path: Vec<Fr>,
    /// Owner's secret; for an escrow, the branch's authority; for a dummy,
    /// the dummy nullifier's secret.
    pub secret: Fr,
}

impl InputWitness {
    pub fn dummy(secret: Fr) -> Self {
        InputWitness {
            kind: InputKind::Dummy,
            note: Note::ordinary(0, Fr::zero(), Fr::zero()),
            created_at: Fr::zero(),
            position: 0,
            path: vec![Fr::zero(); TREE_DEPTH],
            secret,
        }
    }

    /// A real note found in `tree` at `position`.
    pub fn real(tree: &MerkleTree, note: Note, created_at: u64, position: u64, secret: Fr) -> Self {
        let kind = match note.kind {
            NoteKind::Escrow => InputKind::Escrow,
            _ => InputKind::Ordinary,
        };
        InputWitness { kind, note, created_at: created_at.into(), position, path: tree.path(position), secret }
    }

    pub fn nullifier(&self) -> Fr {
        let commitment = self.note.commitment();
        match self.kind {
            InputKind::Dummy => dummy_nullifier(self.secret),
            InputKind::Ordinary => ordinary_nullifier(self.secret, commitment, self.position),
            InputKind::Escrow => escrow_nullifier(self.note.seed, commitment, self.position),
        }
    }
}

/// `(contact key, request digest, tier, has escrow, escrow commitment,
/// blinding)`. Tier: 0 none, 1 invited, 2 stranger.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Admission {
    pub contact_key: Fr,
    pub request_digest: Fr,
    pub tier: Fr,
    pub has_escrow: Fr,
    pub escrow: Fr,
    pub blinding: Fr,
}

impl Admission {
    pub fn empty(blinding: Fr) -> Self {
        Admission {
            contact_key: Fr::zero(),
            request_digest: Fr::zero(),
            tier: Fr::zero(),
            has_escrow: Fr::zero(),
            escrow: Fr::zero(),
            blinding,
        }
    }

    pub fn invited(contact_key: Fr, request_digest: Fr, blinding: Fr) -> Self {
        Admission { contact_key, request_digest, tier: 1u64.into(), ..Admission::empty(blinding) }
    }

    pub fn stranger(contact_key: Fr, request_digest: Fr, escrow: Fr, blinding: Fr) -> Self {
        Admission { contact_key, request_digest, tier: 2u64.into(), has_escrow: 1u64.into(), escrow, blinding }
    }

    pub fn commitment(&self) -> Fr {
        hash(
            "admission",
            &[self.contact_key, self.request_digest, self.tier, self.has_escrow, self.escrow, self.blinding],
        )
    }
}

/// Values the prover supplies and the circuit checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hints {
    /// `ceil(price / 100)`.
    pub penalty: Fr,
    /// `100 * penalty - price`, in `0..=99`.
    pub penalty_rem: Fr,
    /// `max(0, fee_reserve - F)`.
    pub surplus: Fr,
    /// `max(0, F - fee_reserve)`.
    pub shortfall: Fr,
}

impl Hints {
    pub const ZERO: Hints = Hints {
        penalty: Fr::new_unchecked(ark_ff::BigInt::new([0; 4])),
        penalty_rem: Fr::new_unchecked(ark_ff::BigInt::new([0; 4])),
        surplus: Fr::new_unchecked(ark_ff::BigInt::new([0; 4])),
        shortfall: Fr::new_unchecked(ark_ff::BigInt::new([0; 4])),
    };

    /// The honest hints for resolving an escrow of `price` and `fee_reserve`
    /// at base fee `base_fee`.
    pub fn for_resolution(price: u64, fee_reserve: u64, base_fee: u64) -> Self {
        let p = penalty(price);
        Hints {
            penalty: p.into(),
            // 100 * p - price is in 0..=99, computed without overflow.
            penalty_rem: ((100 - price % 100) % 100).into(),
            surplus: fee_reserve.saturating_sub(base_fee).into(),
            shortfall: base_fee.saturating_sub(fee_reserve).into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxWitness {
    pub branch: Branch,
    pub inputs: [InputWitness; N_IN],
    pub outputs: [Note; N_OUT],
    pub admission: Admission,
    pub hints: Hints,
}

/// The transaction fields bound only through `sighash`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxEnvelope {
    pub chain_id: u32,
    pub version: u32,
    /// The two permanent coin-note slots.
    pub coin_slots: [Vec<u8>; 2],
    /// The stranger note's permanent hash (its bytes are prunable).
    pub stranger_note_hash: [u8; 32],
}

/// The 11 public inputs, in the order the circuit allocates them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicInputs {
    pub root: Fr,
    pub nullifiers: [Fr; N_IN],
    pub commitments: [Fr; N_OUT],
    pub admission: Fr,
    pub base_fee: Fr,
    pub not_before: Fr,
    pub not_after: Fr,
    pub sighash: Fr,
}

impl PublicInputs {
    pub fn to_vec(&self) -> Vec<Fr> {
        let mut out = Vec::with_capacity(N_PUBLIC);
        out.push(self.root);
        out.extend_from_slice(&self.nullifiers);
        out.extend_from_slice(&self.commitments);
        out.extend_from_slice(&[self.admission, self.base_fee, self.not_before, self.not_after, self.sighash]);
        out
    }

    /// The digest of the whole transaction: the envelope and every other
    /// public input. A verifier recomputes it; it is never taken from the
    /// sender.
    pub fn compute_sighash(&self, envelope: &TxEnvelope) -> Fr {
        let mut hasher = Blake2s256::new();
        let part = |hasher: &mut Blake2s256, bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        part(&mut hasher, b"anonymum/shielded-circuit/sighash/v1");
        part(&mut hasher, &envelope.chain_id.to_le_bytes());
        part(&mut hasher, &envelope.version.to_le_bytes());
        for field in &self.to_vec()[..N_PUBLIC - 1] {
            part(&mut hasher, &field.into_bigint().to_bytes_le());
        }
        for slot in &envelope.coin_slots {
            part(&mut hasher, slot);
        }
        part(&mut hasher, &envelope.stranger_note_hash);
        Fr::from_le_bytes_mod_order(&hasher.finalize())
    }
}

impl TxWitness {
    /// The public inputs this witness implies.
    pub fn derive_public(
        &self,
        root: Fr,
        base_fee: Fr,
        not_before: Fr,
        not_after: Fr,
        envelope: &TxEnvelope,
    ) -> PublicInputs {
        let mut public = PublicInputs {
            root,
            nullifiers: [self.inputs[0].nullifier(), self.inputs[1].nullifier()],
            commitments: [self.outputs[0].commitment(), self.outputs[1].commitment(), self.outputs[2].commitment()],
            admission: self.admission.commitment(),
            base_fee,
            not_before,
            not_after,
            sighash: Fr::zero(),
        };
        public.sighash = public.compute_sighash(envelope);
        public
    }
}
