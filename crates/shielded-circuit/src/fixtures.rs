//! Valid example transactions for tests and the benchmark. Fixed values, no
//! randomness: **never use these keys or blindings for anything real.**

use ark_bls12_381::Fr;
use ark_bls12_381::Bls12_381;
use ark_ff::Zero;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use crate::circuit::{CircuitParams, ShieldedCircuit};
use crate::merkle::MerkleTree;
use crate::objects::*;
use crate::poseidon::hash;
use crate::verifier::insecure_dev_setup;

pub const BASE_FEE: u64 = 1_000;
pub const SURCHARGE: u64 = 50_000;
pub const PRICE: u64 = 10_101;
/// The penalty on [`PRICE`]: `ceil(10_101 / 100)`.
pub const PENALTY: u64 = 102;
/// A reserve above [`BASE_FEE`], leaving this surplus.
pub const RESERVE_SURPLUS: u64 = 2_000;
pub const SURPLUS: u64 = RESERVE_SURPLUS - BASE_FEE;
/// A reserve below [`BASE_FEE`], leaving this shortfall.
pub const RESERVE_SHORT: u64 = 400;
pub const SHORTFALL: u64 = BASE_FEE - RESERVE_SHORT;
pub const TOP_UP_VALUE: u64 = 900;
pub const TOP_UP_CHANGE: u64 = TOP_UP_VALUE - SHORTFALL;

pub const FUNDING: u64 = 1_000_000;
pub const CREATED_AT: u64 = 3_600;
pub const WINDOW: u64 = 60;
pub const NOT_BEFORE: u64 = CREATED_AT + 600;

pub const PARAMS: CircuitParams = CircuitParams { surcharge: SURCHARGE };

/// A named field element.
pub fn f(label: &str) -> Fr {
    hash("fixture", &[crate::poseidon::domain_tag(label, 0)])
}

pub fn envelope() -> TxEnvelope {
    TxEnvelope {
        chain_id: 7,
        version: 1,
        coin_slots: [vec![0xA0; 200], vec![0xB0; 200]],
        stranger_note_hash: [0xC0; 32],
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Case {
    Transfer,
    Invited,
    Open,
    ClaimSurplus,
    ClaimExactFee,
    ClaimTopUp,
    DeclineSurplus,
    DeclineTopUp,
    RefundSurplus,
    RefundTopUp,
}

impl Case {
    pub const ALL: [Case; 10] = [
        Case::Transfer,
        Case::Invited,
        Case::Open,
        Case::ClaimSurplus,
        Case::ClaimExactFee,
        Case::ClaimTopUp,
        Case::DeclineSurplus,
        Case::DeclineTopUp,
        Case::RefundSurplus,
        Case::RefundTopUp,
    ];

    pub fn branch(self) -> Branch {
        match self {
            Case::Transfer => Branch::Transfer,
            Case::Invited => Branch::Invited,
            Case::Open => Branch::Open,
            Case::ClaimSurplus | Case::ClaimExactFee | Case::ClaimTopUp => Branch::Claim,
            Case::DeclineSurplus | Case::DeclineTopUp => Branch::Decline,
            Case::RefundSurplus | Case::RefundTopUp => Branch::SenderRefund,
        }
    }

    fn reserve(self) -> u64 {
        match self {
            Case::ClaimExactFee => BASE_FEE,
            Case::ClaimTopUp | Case::DeclineTopUp | Case::RefundTopUp => RESERVE_SHORT,
            _ => RESERVE_SURPLUS,
        }
    }

    fn has_top_up(self) -> bool {
        self.reserve() < BASE_FEE
    }
}

/// A valid transaction and everything needed to alter and re-derive it.
#[derive(Clone, Debug)]
pub struct Built {
    pub circuit: ShieldedCircuit,
    pub envelope: TxEnvelope,
}

impl Built {
    /// Recompute every public input from the (possibly altered) witness, so
    /// that a failure comes from the rule under test and not from a stale
    /// public input. The root, fee and window are kept.
    pub fn reseal(&mut self) {
        let p = self.circuit.public;
        self.circuit.public =
            self.circuit.witness.derive_public(p.root, p.base_fee, p.not_before, p.not_after, &self.envelope);
    }
}

fn unused(label: &str) -> Note {
    Note::retired(0, f(label))
}

pub fn funding_note() -> Note {
    Note::ordinary(FUNDING, authority(f("funder")), f("funding/blinding"))
}

pub fn top_up_note() -> Note {
    Note::ordinary(TOP_UP_VALUE, authority(f("resolver")), f("top-up/blinding"))
}

pub fn escrow_note(reserve: u64) -> Note {
    Note::escrow(
        PRICE,
        reserve,
        authority(f("recipient")),
        authority(f("refund-key")),
        authority(f("canceller")),
        f("seed"),
        f("escrow/blinding"),
    )
}

/// A tree holding a filler leaf, the funding note, the escrow and the
/// top-up note, at positions 1, 2 and 3.
fn world(reserve: u64) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for l in leaves_for_reserve(reserve) {
        tree.append(l).expect("room");
    }
    tree
}

fn leaves_for_reserve(reserve: u64) -> Vec<Fr> {
    let mut leaves = vec![f("filler-leaf")];
    for note in [funding_note(), escrow_note(reserve), top_up_note()] {
        leaves.push(leaf(note.commitment(), CREATED_AT.into()));
    }
    leaves
}

/// The leaves a chain must start from for `case` to be spendable.
pub fn world_leaves(case: Case) -> Vec<Fr> {
    leaves_for_reserve(case.reserve())
}

/// **Dev only, and public on purpose.** Keys from a fixed seed, so anyone
/// can reproduce the toxic waste and forge proofs. They exist so a dev chain
/// and its tests share one verifying key.
pub fn dev_keys() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let mut rng = StdRng::from_seed(*b"anonymum-INSECURE-dev-setup-seed");
    insecure_dev_setup(PARAMS, &mut rng).expect("setup")
}

/// `case` as a transaction for a real chain: its id and version, a window
/// starting at `not_before`, and `stranger_note` in the envelope.
pub fn build_for_chain(
    case: Case,
    chain_id: u32,
    version: u32,
    not_before: u64,
    window: u64,
    stranger_note: &[u8],
) -> Built {
    let mut built = build(case);
    built.envelope.chain_id = chain_id;
    built.envelope.version = version;
    built.envelope.stranger_note_hash = stranger_note_hash(stranger_note);
    built.circuit.public.not_before = not_before.into();
    built.circuit.public.not_after = (not_before + window).into();
    built.reseal();
    built
}

/// The valid transaction for `case`.
pub fn build(case: Case) -> Built {
    let reserve = case.reserve();
    let tree = world(reserve);
    let branch = case.branch();
    let funding = InputWitness::real(&tree, funding_note(), CREATED_AT, 1, f("funder"));
    let dummy = InputWitness::dummy(f("dummy-input"));

    let (inputs, outputs, admission, hints) = match branch {
        Branch::Transfer => (
            [funding, dummy],
            [
                Note::ordinary(FUNDING - BASE_FEE - 1_000, authority(f("payee")), f("out0")),
                Note::ordinary(1_000, authority(f("funder")), f("out1")),
                unused("out2"),
            ],
            Admission::empty(f("admission/blinding")),
            Hints::ZERO,
        ),
        Branch::Invited => (
            [funding, dummy],
            [
                Note::ordinary(FUNDING - BASE_FEE, authority(f("funder")), f("out0")),
                unused("out1"),
                unused("out2"),
            ],
            Admission::invited(f("contact-key"), f("request-digest"), f("admission/blinding")),
            Hints::ZERO,
        ),
        Branch::Open => {
            let escrow = Note { blinding: f("new-escrow/blinding"), ..escrow_note(reserve) };
            let change = FUNDING - PRICE - reserve - SURCHARGE - BASE_FEE;
            (
                [funding, dummy],
                [
                    escrow,
                    Note::retired(SURCHARGE, f("surcharge/blinding")),
                    Note::ordinary(change, authority(f("funder")), f("change")),
                ],
                Admission::stranger(f("contact-key"), f("request-digest"), escrow.commitment(), f("admission/blinding")),
                Hints::ZERO,
            )
        }
        Branch::Claim | Branch::Decline | Branch::SenderRefund => {
            let escrow = escrow_note(reserve);
            let secret = f(if branch == Branch::SenderRefund { "canceller" } else { "recipient" });
            let escrow_input = InputWitness::real(&tree, escrow, CREATED_AT, 2, secret);
            let second = if case.has_top_up() {
                InputWitness::real(&tree, top_up_note(), CREATED_AT, 3, f("resolver"))
            } else {
                dummy
            };
            let hints = Hints::for_resolution(PRICE, reserve, BASE_FEE);
            let surplus = reserve.saturating_sub(BASE_FEE);
            let blinding = refund_blinding(escrow.seed, 2);
            let (out0, out1) = if branch == Branch::Claim {
                let payout = Note::ordinary(PRICE, escrow.owner, f("payout"));
                let back = if surplus > 0 {
                    Note::ordinary(surplus, escrow.refund_to, blinding)
                } else {
                    unused("out1")
                };
                (payout, back)
            } else {
                let refund = Note::ordinary(PRICE - PENALTY + surplus, escrow.refund_to, blinding);
                (refund, Note::retired(PENALTY, f("penalty")))
            };
            let out2 = if case.has_top_up() {
                Note::ordinary(TOP_UP_CHANGE, authority(f("resolver")), f("change"))
            } else {
                unused("out2")
            };
            ([escrow_input, second], [out0, out1, out2], Admission::empty(f("admission/blinding")), hints)
        }
    };

    let witness = TxWitness { branch, inputs, outputs, admission, hints };
    let env = envelope();
    let public = witness.derive_public(
        tree.root(),
        BASE_FEE.into(),
        NOT_BEFORE.into(),
        (NOT_BEFORE + WINDOW).into(),
        &env,
    );
    Built { circuit: ShieldedCircuit { params: PARAMS, public, witness, forced_flags: None }, envelope: env }
}

/// A zero element, re-exported for tests that alter fields.
pub fn zero() -> Fr {
    Fr::zero()
}
