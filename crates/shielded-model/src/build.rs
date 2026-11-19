//! Building well-formed transactions: fills dummy slots, derives nullifiers
//! and commitments, picks the grid window that contains the block time, and
//! binds the witness to the public part. Tests use it so they can state
//! what a transaction does; adversarial tests then alter the result.

use crate::chain::*;
use crate::hash::{h, Hash};
use crate::objects::*;

#[derive(Clone)]
pub struct TxBuilder {
    branch: Branch,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
    admission: Option<AdmissionRecord>,
    payloads: [Vec<u8>; N_PAY],
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
            payloads: std::array::from_fn(|_| vec![0; PAYLOAD_LEN]),
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

    pub fn admission(mut self, record: AdmissionRecord) -> Self {
        self.admission = Some(record);
        self
    }

    pub fn payload(mut self, slot: usize, bytes: Vec<u8>) -> Self {
        self.payloads[slot] = bytes;
        self
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
        let not_before = p.window_start(block_time);
        let public = PublicTx {
            chain_id: p.chain_id,
            version: p.version,
            root: chain.root(),
            nullifiers,
            commitments,
            admission: admission.commitment(),
            payloads: self.payloads,
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

/// Recompute every public field derived from the witness (nullifiers,
/// commitments, admission) and re-bind. For adversarial tests that alter
/// the witness itself.
pub fn reseal(public: &mut PublicTx, witness: &mut Witness) {
    public.nullifiers = std::array::from_fn(|i| nullifier_of(&witness.inputs[i]));
    public.commitments = std::array::from_fn(|i| witness.outputs[i].note().commitment());
    public.admission = witness.admission.commitment();
    rebind(public, witness);
}
