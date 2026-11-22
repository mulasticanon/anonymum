//! The constraints: one circuit for all six branches.
//!
//! Slots are fixed, as in the model's builder (`TxBuilder::resolution` and
//! the Open transactions in its tests):
//!
//! | slot | Transfer, Invited | Open | Claim | Decline, Sender refund |
//! |---|---|---|---|---|
//! | input 0 | ordinary or dummy | ordinary or dummy | escrow | escrow |
//! | input 1 | ordinary or dummy | ordinary or dummy | top-up iff `F > reserve`, else dummy | same |
//! | output 0 | ordinary or unused | escrow | `price` to recipient | derived refund |
//! | output 1 | ordinary or unused | retired `S` | derived surplus iff `reserve > F`, else unused | retired penalty |
//! | output 2 | ordinary or unused | change or unused | top-up change or unused | same |
//!
//! "Unused" is a zero-value retired note. The surcharge `S` is a circuit
//! constant ([`CircuitParams`]), so changing it needs a new setup.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::merkle::node_label;
use crate::objects::*;
use crate::poseidon::{domain_tag, hash_var, hash_var_with_tag};

type Cs = ConstraintSystemRef<Fr>;
type Res<T> = Result<T, SynthesisError>;

/// Constants compiled into the circuit (and so into its keys).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CircuitParams {
    /// The stranger surcharge `S`, retired on Open.
    pub surcharge: u64,
}

/// The selector bits a prover assigns. A malicious prover can assign any
/// bits, so the constraints must not rely on these being derived honestly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Flags {
    /// Transfer, Invited, Open, Claim, Decline, SenderRefund.
    pub branch: [bool; 6],
    /// Dummy, ordinary, escrow, per input.
    pub inputs: [[bool; 3]; N_IN],
    /// Ordinary, escrow, retired, per output.
    pub outputs: [[bool; 3]; N_OUT],
}

impl Flags {
    /// The bits an honest prover assigns for `w`.
    pub fn honest(w: &TxWitness) -> Self {
        let input = |i: &InputWitness| {
            [i.kind == InputKind::Dummy, i.kind == InputKind::Ordinary, i.kind == InputKind::Escrow]
        };
        let output = |n: &Note| {
            [n.kind == NoteKind::Ordinary, n.kind == NoteKind::Escrow, n.kind == NoteKind::Retired]
        };
        Flags {
            branch: Branch::ALL.map(|b| b == w.branch),
            inputs: [input(&w.inputs[0]), input(&w.inputs[1])],
            outputs: [output(&w.outputs[0]), output(&w.outputs[1]), output(&w.outputs[2])],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShieldedCircuit {
    pub params: CircuitParams,
    pub public: PublicInputs,
    pub witness: TxWitness,
    /// Selector bits to assign instead of the honest ones. `None` in normal
    /// use; tests set it to act as a malicious prover. It changes only the
    /// witness assignment, never the constraints.
    pub forced_flags: Option<Flags>,
}

impl ShieldedCircuit {
    /// An all-zero assignment, for key generation only.
    pub fn blank(params: CircuitParams) -> Self {
        let zero = Fr::zero();
        let unused = Note::retired(0, zero);
        ShieldedCircuit {
            params,
            public: PublicInputs {
                root: zero,
                nullifiers: [zero; N_IN],
                commitments: [zero; N_OUT],
                admission: zero,
                base_fee: zero,
                not_before: zero,
                not_after: zero,
                sighash: zero,
            },
            witness: TxWitness {
                branch: Branch::Transfer,
                inputs: [InputWitness::dummy(zero), InputWitness::dummy(zero)],
                outputs: [unused; N_OUT],
                admission: Admission::empty(zero),
                hints: Hints::ZERO,
            },
            forced_flags: None,
        }
    }
}

fn witness(cs: &Cs, value: Fr) -> Res<FpVar<Fr>> {
    FpVar::new_witness(cs.clone(), || Ok(value))
}

fn flag(cs: &Cs, value: bool) -> Res<Boolean<Fr>> {
    Boolean::new_witness(cs.clone(), || Ok(value))
}

fn fp(bit: &Boolean<Fr>) -> FpVar<Fr> {
    FpVar::from(bit.clone())
}

fn constant(value: u64) -> FpVar<Fr> {
    FpVar::Constant(Fr::from(value))
}

/// `x` is the sum of `n` boolean bits. Over this field that means `x` is an
/// integer in `0..2^n`.
fn enforce_bits(cs: &Cs, x: &FpVar<Fr>, n: usize) -> Res<()> {
    let value = x.value().unwrap_or_default().into_bigint();
    let bits = (0..n).map(|i| flag(cs, value.get_bit(i))).collect::<Res<Vec<_>>>()?;
    Boolean::le_bits_to_fp_var(&bits)?.enforce_equal(x)
}

fn enforce_u64(cs: &Cs, x: &FpVar<Fr>) -> Res<()> {
    enforce_bits(cs, x, 64)
}

fn enforce_one_hot(flags: &[&Boolean<Fr>]) -> Res<()> {
    let mut sum = FpVar::<Fr>::zero();
    for f in flags {
        sum += fp(f);
    }
    sum.enforce_equal(&FpVar::one())
}

fn zero_if(x: &FpVar<Fr>, condition: &Boolean<Fr>) -> Res<()> {
    x.conditional_enforce_equal(&FpVar::zero(), condition)
}

fn is_zero(x: &FpVar<Fr>) -> Res<Boolean<Fr>> {
    x.is_eq(&FpVar::zero())
}

struct NoteVar {
    value: FpVar<Fr>,
    reserve: FpVar<Fr>,
    owner: FpVar<Fr>,
    refund_to: FpVar<Fr>,
    canceller: FpVar<Fr>,
    seed: FpVar<Fr>,
    blinding: FpVar<Fr>,
    /// `value + reserve`: what the note contributes to conservation.
    total: FpVar<Fr>,
    commitment: FpVar<Fr>,
}

/// Allocate a note, range-check its amounts, zero the fields its type does
/// not have, and hash it.
fn alloc_note(cs: &Cs, note: &Note, type_tag: &FpVar<Fr>, is_escrow: &Boolean<Fr>) -> Res<NoteVar> {
    let value = witness(cs, note.value)?;
    let reserve = witness(cs, note.fee_reserve)?;
    let owner = witness(cs, note.owner)?;
    let refund_to = witness(cs, note.refund_to)?;
    let canceller = witness(cs, note.canceller)?;
    let seed = witness(cs, note.seed)?;
    let blinding = witness(cs, note.blinding)?;

    enforce_u64(cs, &value)?;
    enforce_u64(cs, &reserve)?;
    // An escrow's price + fee_reserve must itself fit in 64 bits (I4).
    let total = &value + &reserve;
    enforce_u64(cs, &total)?;

    let not_escrow = is_escrow.not();
    zero_if(&reserve, &not_escrow)?;
    zero_if(&refund_to, &not_escrow)?;
    zero_if(&canceller, &not_escrow)?;
    zero_if(&seed, &not_escrow)?;

    let commitment = hash_var(
        cs,
        "commit",
        &[
            type_tag.clone(),
            value.clone(),
            reserve.clone(),
            owner.clone(),
            refund_to.clone(),
            canceller.clone(),
            seed.clone(),
            blinding.clone(),
        ],
    )?;
    Ok(NoteVar { value, reserve, owner, refund_to, canceller, seed, blinding, total, commitment })
}

struct InputVar {
    is_ordinary: Boolean<Fr>,
    is_escrow: Boolean<Fr>,
    note: NoteVar,
    created_at: FpVar<Fr>,
    position: FpVar<Fr>,
}

struct Selectors {
    invited: Boolean<Fr>,
    open: Boolean<Fr>,
    claim: Boolean<Fr>,
    refund: Boolean<Fr>,
    /// Decline or Sender refund.
    decline_or_refund: Boolean<Fr>,
    /// Claim, Decline or Sender refund.
    resolution: Boolean<Fr>,
}

fn alloc_selectors(cs: &Cs, bits: &[bool; 6]) -> Res<Selectors> {
    let transfer = flag(cs, bits[0])?;
    let invited = flag(cs, bits[1])?;
    let open = flag(cs, bits[2])?;
    let claim = flag(cs, bits[3])?;
    let decline = flag(cs, bits[4])?;
    let refund = flag(cs, bits[5])?;
    enforce_one_hot(&[&transfer, &invited, &open, &claim, &decline, &refund])?;
    let decline_or_refund = decline.or(&refund)?;
    let resolution = decline_or_refund.or(&claim)?;
    Ok(Selectors { invited, open, claim, refund, decline_or_refund, resolution })
}

/// Membership, authority and nullifier of one input slot.
fn alloc_input(
    cs: &Cs,
    input: &InputWitness,
    bits: &[bool; 3],
    root: &FpVar<Fr>,
    nullifier: &FpVar<Fr>,
    sel: &Selectors,
) -> Res<InputVar> {
    let is_dummy = flag(cs, bits[0])?;
    let is_ordinary = flag(cs, bits[1])?;
    let is_escrow = flag(cs, bits[2])?;
    enforce_one_hot(&[&is_dummy, &is_ordinary, &is_escrow])?;
    let is_real = is_dummy.not();

    // The type tag can only be 0 or 1 here: a retired note (2) has no way in.
    let note = alloc_note(cs, &input.note, &fp(&is_escrow), &is_escrow)?;
    zero_if(&note.value, &is_dummy)?;

    let created_at = witness(cs, input.created_at)?;
    enforce_u64(cs, &created_at)?;

    // Merkle path. The position is exactly these TREE_DEPTH bits.
    let bits = (0..TREE_DEPTH)
        .map(|level| flag(cs, (input.position >> level) & 1 == 1))
        .collect::<Res<Vec<_>>>()?;
    let position = Boolean::le_bits_to_fp_var(&bits)?;
    let mut current = hash_var(cs, "leaf", &[note.commitment.clone(), created_at.clone()])?;
    for (level, bit) in bits.iter().enumerate() {
        let sibling = witness(cs, input.path[level])?;
        let left = FpVar::conditionally_select(bit, &sibling, &current)?;
        let right = FpVar::conditionally_select(bit, &current, &sibling)?;
        current = hash_var(cs, &node_label(level), &[left, right])?;
    }
    current.conditional_enforce_equal(root, &is_real)?;

    // Authority: the owner of an ordinary note; for an escrow, the recipient
    // (Claim, Decline) or the canceller (Sender refund).
    let secret = witness(cs, input.secret)?;
    let held = hash_var(cs, "authority", &[secret.clone()])?;
    let escrow_authority = FpVar::conditionally_select(&sel.refund, &note.canceller, &note.owner)?;
    let required = FpVar::conditionally_select(&is_escrow, &escrow_authority, &note.owner)?;
    held.conditional_enforce_equal(&required, &is_real)?;

    // One permutation, three domains chosen by the slot's type.
    let tag = fp(&is_ordinary) * domain_tag("nullifier/ordinary", 3)
        + fp(&is_escrow) * domain_tag("nullifier/escrow", 3)
        + fp(&is_dummy) * domain_tag("nullifier/dummy", 3);
    let key = FpVar::conditionally_select(&is_escrow, &note.seed, &secret)?;
    let bound_commitment = FpVar::conditionally_select(&is_dummy, &FpVar::zero(), &note.commitment)?;
    let bound_position = FpVar::conditionally_select(&is_dummy, &FpVar::zero(), &position)?;
    hash_var_with_tag(cs, &tag, &[key, bound_commitment, bound_position])?.enforce_equal(nullifier)?;

    Ok(InputVar { is_ordinary, is_escrow, note, created_at, position })
}

struct OutputVar {
    is_ordinary: Boolean<Fr>,
    is_escrow: Boolean<Fr>,
    is_retired: Boolean<Fr>,
    note: NoteVar,
}

fn alloc_output(cs: &Cs, note: &Note, bits: &[bool; 3], commitment: &FpVar<Fr>) -> Res<OutputVar> {
    let is_ordinary = flag(cs, bits[0])?;
    let is_escrow = flag(cs, bits[1])?;
    let is_retired = flag(cs, bits[2])?;
    enforce_one_hot(&[&is_ordinary, &is_escrow, &is_retired])?;
    let type_tag = fp(&is_escrow) + fp(&is_retired).double()?;
    let var = alloc_note(cs, note, &type_tag, &is_escrow)?;
    zero_if(&var.owner, &is_retired)?;
    var.commitment.enforce_equal(commitment)?;
    Ok(OutputVar { is_ordinary, is_escrow, is_retired, note: var })
}

impl ConstraintSynthesizer<Fr> for ShieldedCircuit {
    fn generate_constraints(self, cs: Cs) -> Res<()> {
        let ShieldedCircuit { params, public, witness: w, forced_flags } = self;
        let bits = forced_flags.unwrap_or_else(|| Flags::honest(&w));

        // ---- public inputs, in `PublicInputs::to_vec` order ----------------
        let input = |value: Fr| FpVar::new_input(cs.clone(), || Ok(value));
        let root = input(public.root)?;
        let nullifiers = [input(public.nullifiers[0])?, input(public.nullifiers[1])?];
        let commitments =
            [input(public.commitments[0])?, input(public.commitments[1])?, input(public.commitments[2])?];
        let admission_commitment = input(public.admission)?;
        let base_fee = input(public.base_fee)?;
        let not_before = input(public.not_before)?;
        let not_after = input(public.not_after)?;
        let sighash = input(public.sighash)?;

        // The sighash enters no rule, so give it a constraint of its own:
        // the proof then depends on it through the QAP directly.
        let _ = sighash.square()?;

        enforce_u64(&cs, &base_fee)?;
        enforce_u64(&cs, &not_before)?;
        enforce_u64(&cs, &not_after)?;

        let sel = alloc_selectors(&cs, &bits.branch)?;

        // ---- notes ---------------------------------------------------------
        let in0 = alloc_input(&cs, &w.inputs[0], &bits.inputs[0], &root, &nullifiers[0], &sel)?;
        let in1 = alloc_input(&cs, &w.inputs[1], &bits.inputs[1], &root, &nullifiers[1], &sel)?;
        let out0 = alloc_output(&cs, &w.outputs[0], &bits.outputs[0], &commitments[0])?;
        let out1 = alloc_output(&cs, &w.outputs[1], &bits.outputs[1], &commitments[1])?;
        let out2 = alloc_output(&cs, &w.outputs[2], &bits.outputs[2], &commitments[2])?;

        // ---- conservation ----------------------------------------------------
        // Every term is below 2^64, so neither side can wrap the field.
        (&in0.note.total + &in1.note.total)
            .enforce_equal(&(&out0.note.total + &out1.note.total + &out2.note.total + &base_fee))?;

        // ---- types -----------------------------------------------------------
        in0.is_escrow.enforce_equal(&sel.resolution)?;
        in1.is_escrow.enforce_equal(&Boolean::FALSE)?;
        out0.is_escrow.enforce_equal(&sel.open)?;
        out1.is_escrow.enforce_equal(&Boolean::FALSE)?;
        out2.is_escrow.enforce_equal(&Boolean::FALSE)?;

        // A retired note carries value only in output 1 of Open, Decline or
        // Sender refund. Everywhere else it is an unused, zero-value slot.
        let may_retire = sel.open.or(&sel.decline_or_refund)?;
        zero_if(&out0.note.value, &out0.is_retired)?;
        zero_if(&out1.note.value, &out1.is_retired.and(&may_retire.not())?)?;
        zero_if(&out2.note.value, &out2.is_retired)?;

        // ---- admission record (W3) -------------------------------------------
        let contact_key = witness(&cs, w.admission.contact_key)?;
        let request_digest = witness(&cs, w.admission.request_digest)?;
        let tier = witness(&cs, w.admission.tier)?;
        let has_escrow = witness(&cs, w.admission.has_escrow)?;
        let admission_escrow = witness(&cs, w.admission.escrow)?;
        let admission_blinding = witness(&cs, w.admission.blinding)?;
        hash_var(
            &cs,
            "admission",
            &[
                contact_key.clone(),
                request_digest.clone(),
                tier.clone(),
                has_escrow.clone(),
                admission_escrow.clone(),
                admission_blinding,
            ],
        )?
        .enforce_equal(&admission_commitment)?;
        tier.enforce_equal(&(fp(&sel.invited) + fp(&sel.open).double()?))?;
        has_escrow.enforce_equal(&fp(&sel.open))?;
        // Stranger tier names the escrow created in this transaction;
        // every other tier names none.
        let named = FpVar::conditionally_select(&sel.open, &out0.note.commitment, &FpVar::zero())?;
        admission_escrow.enforce_equal(&named)?;
        let empty_record = sel.invited.or(&sel.open)?.not();
        zero_if(&contact_key, &empty_record)?;
        zero_if(&request_digest, &empty_record)?;

        // ---- Open ------------------------------------------------------------
        out1.is_retired.conditional_enforce_equal(&Boolean::TRUE, &sel.open)?;
        out1.note.value.conditional_enforce_equal(&constant(params.surcharge), &sel.open)?;
        // fee_reserve >= F at opening.
        let reserve_margin = fp(&sel.open) * (&out0.note.reserve - &base_fee);
        enforce_u64(&cs, &reserve_margin)?;

        // ---- fee reserve of a resolution (I8, H1) ----------------------------
        let surplus = witness(&cs, w.hints.surplus)?;
        let shortfall = witness(&cs, w.hints.shortfall)?;
        enforce_u64(&cs, &surplus)?;
        enforce_u64(&cs, &shortfall)?;
        (&surplus * &shortfall).enforce_equal(&FpVar::zero())?;
        (&in0.note.reserve + &shortfall)
            .conditional_enforce_equal(&(&base_fee + &surplus), &sel.resolution)?;
        let not_resolution = sel.resolution.not();
        zero_if(&surplus, &not_resolution)?;
        zero_if(&shortfall, &not_resolution)?;
        let has_surplus = is_zero(&surplus)?.not();
        let has_top_up = is_zero(&shortfall)?.not();

        // Exactly one ordinary top-up when the fee exceeds the reserve, and
        // none otherwise. Its change has no destination rule: conservation
        // fixes the amount.
        in1.is_ordinary.conditional_enforce_equal(&has_top_up, &sel.resolution)?;
        out2.is_retired
            .conditional_enforce_equal(&Boolean::TRUE, &sel.resolution.and(&has_top_up.not())?)?;

        // The blinding of the note owed to the sender (I9, I13).
        let derived_blinding = hash_var(&cs, "refund-blinding", &[in0.note.seed.clone(), in0.position.clone()])?;

        // created_at + TTL must fit in 64 bits for any resolution, as in the
        // model's checked_add.
        let deadline = &in0.created_at + constant(TTL);
        enforce_u64(&cs, &(fp(&sel.resolution) * &deadline))?;

        // ---- Claim -----------------------------------------------------------
        // Every inclusion time t < not_after <= created_at + TTL.
        enforce_u64(&cs, &(fp(&sel.claim) * (&deadline - &not_after)))?;
        out0.is_ordinary.conditional_enforce_equal(&Boolean::TRUE, &sel.claim)?;
        out0.note.owner.conditional_enforce_equal(&in0.note.owner, &sel.claim)?;
        out0.note.value.conditional_enforce_equal(&in0.note.value, &sel.claim)?;
        // Output 1 is the derived surplus when there is one, else unused.
        out1.is_ordinary.conditional_enforce_equal(&has_surplus, &sel.claim)?;
        let claim_surplus = sel.claim.and(&has_surplus)?;
        out1.note.owner.conditional_enforce_equal(&in0.note.refund_to, &claim_surplus)?;
        out1.note.value.conditional_enforce_equal(&surplus, &claim_surplus)?;
        out1.note.blinding.conditional_enforce_equal(&derived_blinding, &claim_surplus)?;

        // ---- Decline, Sender refund ------------------------------------------
        // penalty = ceil(price / 100): price + rem = 100 * penalty, 0 <= rem <= 99.
        let penalty = witness(&cs, w.hints.penalty)?;
        let penalty_rem = witness(&cs, w.hints.penalty_rem)?;
        enforce_u64(&cs, &penalty)?;
        enforce_bits(&cs, &penalty_rem, 7)?;
        enforce_bits(&cs, &(constant(99) - &penalty_rem), 7)?;
        (&in0.note.value + &penalty_rem)
            .conditional_enforce_equal(&(&penalty * Fr::from(100u64)), &sel.decline_or_refund)?;

        out0.is_ordinary.conditional_enforce_equal(&Boolean::TRUE, &sel.decline_or_refund)?;
        out0.note.owner.conditional_enforce_equal(&in0.note.refund_to, &sel.decline_or_refund)?;
        out0.note
            .value
            .conditional_enforce_equal(&(&in0.note.value - &penalty + &surplus), &sel.decline_or_refund)?;
        out0.note.blinding.conditional_enforce_equal(&derived_blinding, &sel.decline_or_refund)?;
        out1.is_retired.conditional_enforce_equal(&Boolean::TRUE, &sel.decline_or_refund)?;
        out1.note.value.conditional_enforce_equal(&penalty, &sel.decline_or_refund)?;

        Ok(())
    }
}
