//! Building well-formed transactions: fills dummy slots, derives nullifiers
//! and commitments, picks the grid window that contains the block time, and
//! binds the witness to the public part. Tests use it so they can state
//! what a transaction does; adversarial tests then alter the result.

use crate::chain::*;
use crate::hash::{h, Hash};
use crate::objects::*;
use rand_core::{OsRng, RngCore};

/// The fee ceiling a wallet locks by default in each escrow, as a multiple
/// of today's base fee `F`: a placeholder until a fee policy exists. The
/// part of the reserve the resolution does not need returns to the sender
/// (issue I8, review H1).
pub const FEE_CEILING_MULTIPLE: Value = 2;

/// The reserve an opening locks unless the caller chooses another one
/// (at least `F`): `FEE_CEILING_MULTIPLE * F`, saturating.
pub fn default_fee_reserve(params: &Params) -> Value {
    params.base_fee.saturating_mul(FEE_CEILING_MULTIPLE)
}

/// An ordinary note spent to cover the shortfall when the base fee rose
/// above an escrow's reserve, and where its change goes.
#[derive(Clone, Copy, Debug)]
pub struct TopUp {
    pub note: Note,
    pub created_at: Time,
    pub position: u64,
    pub owner: Secret,
    /// Owner of the change note (normally the resolver).
    pub change_to: Authority,
}

#[derive(Clone)]
pub struct TxBuilder {
    branch: Branch,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
    admission: Option<AdmissionRecord>,
    /// Slots the caller filled; the rest get dummies at [`TxBuilder::build`].
    payloads: [Option<Vec<u8>>; N_PAY],
    /// Makes dummy secrets and blindings distinct per transaction. A real
    /// wallet would use fresh randomness.
    salt: Hash,
}

impl TxBuilder {
    pub fn new(branch: Branch, salt: &[u8]) -> Self {
        TxBuilder {
            branch,
            inputs: Vec::new(),
            outputs: Vec::new(),
            admission: None,
            payloads: Default::default(),
            salt: h("builder/salt", &[salt]),
        }
    }

    /// Spend a note found at `position` (created at `created_at`), with the
    /// secret of the owner (ordinary) or of the branch's authority (escrow).
    pub fn spend(mut self, note: Note, created_at: Time, position: u64, authority: Secret) -> Self {
        assert!(self.inputs.len() < N_IN, "too many inputs");
        self.inputs.push(InputWitness::Real { note, created_at, position, authority });
        self
    }

    pub fn output(mut self, note: Note) -> Self {
        assert!(self.outputs.len() < N_OUT, "too many outputs");
        self.outputs.push(OutputWitness::Real(note));
        self
    }

    /// Leave the next output slot unused (a zero-value retired note), so a
    /// later output lands in a fixed slot.
    pub fn dummy_output(mut self) -> Self {
        assert!(self.outputs.len() < N_OUT, "too many outputs");
        let blinding = self.derived("dummy-output", self.outputs.len());
        self.outputs.push(OutputWitness::Dummy { blinding });
        self
    }

    /// A Claim, Decline or Sender refund of the escrow at `position`, paying
    /// the base fee `chain` charges now, with the outputs in fixed slots:
    ///
    /// | slot | Claim | Decline, Sender refund |
    /// |---|---|---|
    /// | input 0 | the escrow | the escrow |
    /// | input 1 | top-up note, only if `F > fee_reserve` | the same |
    /// | output 0 | `price` to `recipient` | derived refund: `price - penalty + surplus` to `refund_to` |
    /// | output 1 | derived surplus to `refund_to` if `fee_reserve > F`, else unused | retired penalty |
    /// | output 2 | top-up change, if any | the same |
    ///
    /// `authority` is the recipient's secret (Claim, Decline) or the
    /// canceller's (Sender refund). A top-up passed when none is needed is
    /// spent anyway, and the chain refuses the result (`TopUpWrong`).
    #[allow(clippy::too_many_arguments)]
    pub fn resolution(
        chain: &Chain,
        branch: Branch,
        escrow: &EscrowNote,
        created_at: Time,
        position: u64,
        authority: Secret,
        top_up: Option<TopUp>,
        salt: &[u8],
    ) -> Self {
        assert!(matches!(branch, Branch::Claim | Branch::Decline | Branch::SenderRefund), "not a resolution");
        let fee = chain.params().base_fee;
        let mut b = TxBuilder::new(branch, salt).spend(Note::Escrow(*escrow), created_at, position, authority);
        if let Some(t) = &top_up {
            b = b.spend(t.note, t.created_at, t.position, t.owner);
        }
        b = if branch == Branch::Claim {
            let payout = Note::Ordinary { value: escrow.price, owner: escrow.recipient, blinding: b.derived("payout", 0) };
            let b = b.output(payout);
            match derived_claim_surplus(escrow, position, fee) {
                Some(surplus) => b.output(surplus),
                None => b.dummy_output(),
            }
        } else {
            let retired = Note::Retired { value: penalty(escrow.price), blinding: b.derived("penalty", 0) };
            b.output(derived_refund(escrow, position, fee)).output(retired)
        };
        if let Some(t) = top_up {
            let change = t.note.value().unwrap_or(0).saturating_sub(fee_shortfall(escrow, fee));
            if change > 0 {
                let blinding = b.derived("change", 0);
                b = b.output(Note::Ordinary { value: change, owner: t.change_to, blinding });
            }
        }
        b
    }

    pub fn admission(mut self, record: AdmissionRecord) -> Self {
        self.admission = Some(record);
        self
    }

    pub fn payload(mut self, slot: usize, bytes: Vec<u8>) -> Self {
        self.payloads[slot] = Some(bytes);
        self
    }

    /// A dummy for the stranger-note slot when this transaction carries no
    /// note. Production wallets MUST pass `anonymum_crypto::dummy_note()`
    /// here: a real v5 note between throwaway keys. Without it the slot is
    /// filled with random bytes, which this model accepts but which an
    /// observer can tell apart from a real note (the note's X25519
    /// ephemeral key always has its top bit clear and lies on the curve,
    /// not the twist; random bytes fail that about half the time, spec W4,
    /// audit MED-03). The model does not depend on `anonymum-crypto`.
    pub fn dummy_stranger_note(self, note: [u8; STRANGER_NOTE_LEN]) -> Self {
        self.payload(STRANGER_SLOT, note.to_vec())
    }

    fn derived(&self, what: &str, index: usize) -> Hash {
        h("builder/derived", &[&self.salt, what.as_bytes(), &(index as u64).to_le_bytes()])
    }

    /// The transaction to include at `block_time` on `chain`.
    pub fn build(self, chain: &Chain, block_time: Time) -> (PublicTx, Witness) {
        let p = chain.params();
        let mut inputs = self.inputs.clone();
        while inputs.len() < N_IN {
            let secret = Secret(self.derived("dummy-input", inputs.len()));
            inputs.push(InputWitness::Dummy { secret });
        }
        let mut outputs = self.outputs.clone();
        while outputs.len() < N_OUT {
            let blinding = self.derived("dummy-output", outputs.len());
            outputs.push(OutputWitness::Dummy { blinding });
        }
        let admission = self.admission.unwrap_or_else(|| AdmissionRecord::empty(self.derived("admission", 0)));
        let nullifiers = std::array::from_fn(|i| nullifier_of(&inputs[i]));
        let commitments = std::array::from_fn(|i| outputs[i].note().commitment());
        // Unused slots never stay blank (audit M2, MED-03): a coin slot gets
        // fresh random bytes, which look like a ChaCha20-Poly1305 ciphertext
        // of the same length; the stranger slot gets random bytes unless
        // the caller passed a real dummy note (see `dummy_stranger_note`).
        let payloads: [Vec<u8>; N_PAY] = std::array::from_fn(|i| {
            self.payloads[i].clone().unwrap_or_else(|| {
                let mut bytes = vec![0u8; PAYLOAD_LENS[i]];
                OsRng.fill_bytes(&mut bytes);
                bytes
            })
        });
        let not_before = p.window_start(block_time);
        let public = PublicTx {
            chain_id: p.chain_id,
            version: p.version,
            root: chain.root(),
            nullifiers,
            commitments,
            admission: admission.commitment(),
            stranger_note_hash: stranger_note_hash(&payloads[STRANGER_SLOT]),
            payloads,
            not_before,
            not_after: not_before + p.window,
            base_fee: p.base_fee,
        };
        let witness = Witness {
            branch: self.branch,
            inputs: inputs.try_into().expect("N_IN inputs"),
            outputs: outputs.try_into().expect("N_OUT outputs"),
            admission,
            bound_digest: public.digest(),
        };
        (public, witness)
    }
}

/// The nullifier a slot publishes.
pub fn nullifier_of(input: &InputWitness) -> Nullifier {
    match input {
        InputWitness::Dummy { secret } => dummy_nullifier(secret),
        InputWitness::Real { note, position, authority, .. } => {
            let c = note.commitment();
            match note {
                Note::Escrow(e) => escrow_nullifier(&e.seed, &c, *position),
                _ => ordinary_nullifier(authority, &c, *position),
            }
        }
    }
}

/// Re-bind a witness to an altered public part, as a dishonest prover who
/// holds the witness could. Adversarial tests use it to reach the hidden
/// statement's checks instead of stopping at `BindingMismatch`.
pub fn rebind(public: &PublicTx, witness: &mut Witness) {
    witness.bound_digest = public.digest();
}

/// Replace the stranger-note slot, update its hash and re-bind: what an
/// honest sender does when the slot carries a real note.
pub fn set_stranger_note(public: &mut PublicTx, witness: &mut Witness, note: Vec<u8>) {
    public.stranger_note_hash = stranger_note_hash(&note);
    public.payloads[STRANGER_SLOT] = note;
    rebind(public, witness);
}

/// Recompute every public field derived from the witness (nullifiers,
/// commitments, admission) and re-bind. For adversarial tests that alter
/// the witness itself.
pub fn reseal(public: &mut PublicTx, witness: &mut Witness) {
    public.nullifiers = std::array::from_fn(|i| nullifier_of(&witness.inputs[i]));
    public.commitments = std::array::from_fn(|i| witness.outputs[i].note().commitment());
    public.admission = witness.admission.commitment();
    rebind(public, witness);
}
