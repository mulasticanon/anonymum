//! Transactions (spec section 4) and the chain that checks them.
//!
//! `Chain::submit(public, witness, block_time)` is the one entry point. It
//! runs the chain-side checks (section 4, "the chain, outside the proof")
//! and the hidden statement (common part and branch) against the witness.
//! In the real system the witness never leaves the prover and a proof
//! stands in for it; here the model checks the witness directly, so this is
//! a statement of the rules, not a private implementation.

use std::collections::{HashMap, HashSet};

use crate::hash::{h, Hash};
use crate::objects::*;

/// Input slots per transaction (spent notes or dummies).
pub const N_IN: usize = 2;
/// Output slots per transaction (new notes or dummies).
pub const N_OUT: usize = 3;
/// Encrypted payload slots per transaction.
pub const N_PAY: usize = 3;
/// Bytes per payload slot. A placeholder: the size is open (P10). Sized to
/// hold the sender's recovery copy: a 12-byte nonce, the 176-byte escrow
/// and a 16-byte authentication tag.
pub const PAYLOAD_LEN: usize = 204;
/// Request lifetime: claims stop and timeouts start here (O4, O8).
pub const TTL: Time = 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    pub chain_id: u32,
    pub version: u32,
    /// The public base fee `F`, the same on every transaction.
    pub base_fee: Value,
    /// The stranger surcharge `S`, retired on opening (P1, O5).
    pub surcharge: Value,
    /// Width of the window grid, in seconds (P11).
    pub window: Time,
    /// Target block time, in seconds.
    pub block_time: Time,
    /// Share of `F` that is burned; the rest goes to the node pool.
    pub fee_burn_percent: u8,
}

impl Params {
    /// Checks the P11 constraints: the window is a whole number of block
    /// times and divides 24 hours exactly.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.block_time == 0 || self.window == 0 {
            return Err("block time and window must be positive");
        }
        if self.window % self.block_time != 0 {
            return Err("window must be a whole number of block times");
        }
        if TTL % self.window != 0 {
            return Err("window must divide 24 hours exactly");
        }
        if self.fee_burn_percent > 100 {
            return Err("burn share above 100%");
        }
        Ok(())
    }

    /// Start of the window containing time `t`.
    pub fn window_start(&self, t: Time) -> Time {
        t - t % self.window
    }
}

/// The public part of a transaction. Every transaction has this shape;
/// nothing in it says which branch it is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicTx {
    pub chain_id: u32,
    pub version: u32,
    /// An accepted tree root.
    pub root: Hash,
    pub nullifiers: [Nullifier; N_IN],
    pub commitments: [Commitment; N_OUT],
    /// Commitment to the admission record (empty for non-requests).
    pub admission: Commitment,
    pub payloads: [Vec<u8>; N_PAY],
    /// Validity window: one cell of the window grid, half-open
    /// `[not_before, not_after)` (spec v0.5, I1).
    pub not_before: Time,
    pub not_after: Time,
    pub base_fee: Value,
}

impl PublicTx {
    /// Digest of every public field, including the payload bytes. The
    /// witness must carry the same digest: this models the proof (and the
    /// sender's authorisation) being bound to the whole public part.
    pub fn digest(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = vec![
            self.chain_id.to_le_bytes().to_vec(),
            self.version.to_le_bytes().to_vec(),
            self.root.to_vec(),
        ];
        parts.extend(self.nullifiers.iter().map(|n| n.0.to_vec()));
        parts.extend(self.commitments.iter().map(|c| c.0.to_vec()));
        parts.push(self.admission.0.to_vec());
        parts.extend(self.payloads.iter().cloned());
        parts.push(self.not_before.to_le_bytes().to_vec());
        parts.push(self.not_after.to_le_bytes().to_vec());
        parts.push(self.base_fee.to_le_bytes().to_vec());
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        h("public-tx", &refs)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Branch {
    Transfer,
    InvitedRequest,
    /// Stranger request: opens an escrow.
    Open,
    Claim,
    Decline,
    /// The sender takes the refund (price minus penalty), at any time:
    /// before the deadline an early cancellation, after it a timeout refund
    /// (spec v0.5 merged v0.4's Cancel and Timeout, I2).
    SenderRefund,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputWitness {
    /// An unused slot. Its public nullifier must be `dummy_nullifier(secret)`.
    Dummy { secret: Secret },
    Real {
        note: Note,
        created_at: Time,
        position: u64,
        /// For an ordinary note: the owner's secret. For an escrow: the
        /// secret of the authority the branch requires.
        authority: Secret,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputWitness {
    /// An unused slot: a zero-value retired note with a fresh blinding
    /// (spec v0.5, I7).
    Dummy { blinding: Hash },
    Real(Note),
}

impl OutputWitness {
    pub fn note(&self) -> Note {
        match self {
            OutputWitness::Dummy { blinding } => Note::Retired { value: 0, blinding: *blinding },
            OutputWitness::Real(note) => *note,
        }
    }
}

/// The hidden witness. In the real system only the prover sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Witness {
    pub branch: Branch,
    pub inputs: [InputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
    pub admission: AdmissionRecord,
    /// Must equal `PublicTx::digest()` of the transaction it proves.
    pub bound_digest: Hash,
}

/// Why a transaction was rejected. Nothing changes when one is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    // chain-side checks
    WrongChain,
    WrongVersion,
    WrongBaseFee,
    MalformedPayload,
    WindowNotShared,
    OutsideWindow,
    UnknownRoot,
    DuplicateNullifier,
    NullifierUsed,
    // the hidden statement, common part
    BindingMismatch,
    BadDummyNullifier,
    RetiredInput,
    NotInTree,
    BadNullifier,
    WrongAuthority,
    CommitmentMismatch,
    AdmissionMismatch,
    Overflow,
    ValueNotConserved,
    // the hidden statement, branches
    WrongInputType,
    WrongOutputs,
    FeeReserveWrong,
    MissingSurcharge,
    TierMismatch,
    ReceiptEscrowMismatch,
    ClaimPayoutWrong,
    RefundNotDerived,
    PenaltyWrong,
    ClaimTooLate,
}

/// A note's place in the tree, as anyone can see it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeafRecord {
    pub commitment: Commitment,
    pub created_at: Time,
    pub leaf: Leaf,
}

/// What an accepted transaction did, publicly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Receipt {
    /// Tree position of the first output; the others follow in slot order.
    pub first_position: u64,
    pub created_at: Time,
}

pub struct Chain {
    params: Params,
    leaves: Vec<LeafRecord>,
    /// Accepted root -> tree size at that root.
    roots: HashMap<Hash, u64>,
    current_root: Hash,
    nullifiers: HashSet<Nullifier>,
    /// Every accepted public transaction, in order (what a scanner sees).
    log: Vec<PublicTx>,
    issued: u128,
    fees_collected: u128,
    fees_burned: u128,
    node_pool: u128,
}

impl Chain {
    /// A chain whose genesis distribution creates `notes` (all shielded
    /// from the first distribution, P9), stamped at time 0.
    pub fn genesis(params: Params, notes: &[Note]) -> Self {
        params.validate().expect("invalid chain parameters");
        let empty_root = h("root/empty", &[&params.chain_id.to_le_bytes()]);
        let mut chain = Chain {
            params,
            leaves: Vec::new(),
            roots: HashMap::from([(empty_root, 0)]),
            current_root: empty_root,
            nullifiers: HashSet::new(),
            log: Vec::new(),
            issued: 0,
            fees_collected: 0,
            fees_burned: 0,
            node_pool: 0,
        };
        for note in notes {
            chain.issued += u128::from(note.value().expect("genesis note value fits"));
            chain.insert(note.commitment(), 0);
        }
        chain
    }

    pub fn params(&self) -> &Params {
        &self.params
    }
    pub fn root(&self) -> Hash {
        self.current_root
    }
    pub fn leaves(&self) -> &[LeafRecord] {
        &self.leaves
    }
    pub fn log(&self) -> &[PublicTx] {
        &self.log
    }
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }
    /// Total created at genesis.
    pub fn issued(&self) -> u128 {
        self.issued
    }
    /// All base fees paid, publicly visible.
    pub fn fees_collected(&self) -> u128 {
        self.fees_collected
    }
    pub fn fees_burned(&self) -> u128 {
        self.fees_burned
    }
    pub fn node_pool(&self) -> u128 {
        self.node_pool
    }

    /// A fingerprint of the whole public state, for checking that a rejected
    /// transaction changed nothing.
    pub fn state_digest(&self) -> Hash {
        let mut nfs: Vec<&Nullifier> = self.nullifiers.iter().collect();
        nfs.sort();
        let nf_bytes: Vec<u8> = nfs.iter().flat_map(|n| n.0).collect();
        h(
            "state",
            &[
                &self.current_root,
                &(self.leaves.len() as u64).to_le_bytes(),
                &nf_bytes,
                &(self.log.len() as u64).to_le_bytes(),
                &self.fees_collected.to_le_bytes(),
                &self.fees_burned.to_le_bytes(),
                &self.node_pool.to_le_bytes(),
            ],
        )
    }

    fn insert(&mut self, commitment: Commitment, created_at: Time) {
        let leaf = leaf(&commitment, created_at);
        self.leaves.push(LeafRecord { commitment, created_at, leaf });
        self.current_root = h("root", &[&self.current_root, &leaf.0]);
        self.roots.insert(self.current_root, self.leaves.len() as u64);
    }

    /// Accept or reject one transaction included at `block_time`.
    pub fn submit(&mut self, public: &PublicTx, witness: &Witness, block_time: Time) -> Result<Receipt, Reject> {
        self.check(public, witness, block_time)?;
        // Effects, all or nothing.
        for nf in &public.nullifiers {
            self.nullifiers.insert(*nf);
        }
        let created_at = public.not_before; // the start of the including window
        let first_position = self.leaves.len() as u64;
        for c in &public.commitments {
            self.insert(*c, created_at);
        }
        let fee = u128::from(public.base_fee);
        let burned = fee * u128::from(self.params.fee_burn_percent) / 100;
        self.fees_collected += fee;
        self.fees_burned += burned;
        self.node_pool += fee - burned;
        self.log.push(public.clone());
        Ok(Receipt { first_position, created_at })
    }

    fn check(&self, public: &PublicTx, witness: &Witness, block_time: Time) -> Result<(), Reject> {
        let p = &self.params;

        // ---- the chain, outside the proof --------------------------------
        if public.chain_id != p.chain_id {
            return Err(Reject::WrongChain);
        }
        if public.version != p.version {
            return Err(Reject::WrongVersion);
        }
        if public.base_fee != p.base_fee {
            return Err(Reject::WrongBaseFee);
        }
        if public.payloads.iter().any(|slot| slot.len() != PAYLOAD_LEN) {
            return Err(Reject::MalformedPayload);
        }
        // Windows come from the shared grid: one grid cell, half-open.
        if public.not_before % p.window != 0 || public.not_after != public.not_before.checked_add(p.window).ok_or(Reject::Overflow)? {
            return Err(Reject::WindowNotShared);
        }
        if block_time < public.not_before || block_time >= public.not_after {
            return Err(Reject::OutsideWindow);
        }
        let tree_size = *self.roots.get(&public.root).ok_or(Reject::UnknownRoot)?;
        for (i, nf) in public.nullifiers.iter().enumerate() {
            if public.nullifiers[..i].contains(nf) {
                return Err(Reject::DuplicateNullifier);
            }
            if self.nullifiers.contains(nf) {
                return Err(Reject::NullifierUsed);
            }
        }

        // ---- hidden statement, common part ------------------------------
        // 6. The proof is bound to every public field and the payloads.
        if witness.bound_digest != public.digest() {
            return Err(Reject::BindingMismatch);
        }
        // 1-3. Inputs: membership, nullifier, authority, type.
        let mut input_total: u128 = 0;
        let mut real_inputs: Vec<(&Note, Time, u64, &Secret)> = Vec::new();
        for (slot, nf) in witness.inputs.iter().zip(&public.nullifiers) {
            match slot {
                InputWitness::Dummy { secret } => {
                    if dummy_nullifier(secret) != *nf {
                        return Err(Reject::BadDummyNullifier);
                    }
                }
                InputWitness::Real { note, created_at, position, authority } => {
                    if matches!(note, Note::Retired { .. }) {
                        return Err(Reject::RetiredInput);
                    }
                    let c = note.commitment();
                    let in_tree = *position < tree_size
                        && self.leaves[*position as usize].leaf == leaf(&c, *created_at);
                    if !in_tree {
                        return Err(Reject::NotInTree);
                    }
                    let expected = match note {
                        Note::Ordinary { owner, .. } => {
                            if authority.authority() != *owner {
                                return Err(Reject::WrongAuthority);
                            }
                            ordinary_nullifier(authority, &c, *position)
                        }
                        // Escrow authority depends on the branch: checked below.
                        Note::Escrow(e) => escrow_nullifier(&e.seed, &c, *position),
                        Note::Retired { .. } => unreachable!("rejected above"),
                    };
                    if expected != *nf {
                        return Err(Reject::BadNullifier);
                    }
                    input_total += u128::from(note.value().ok_or(Reject::Overflow)?);
                    real_inputs.push((note, *created_at, *position, authority));
                }
            }
        }
        // Outputs: the public commitments are those of the witness notes.
        let mut output_total: u128 = 0;
        for (slot, c) in witness.outputs.iter().zip(&public.commitments) {
            let note = slot.note();
            if note.commitment() != *c {
                return Err(Reject::CommitmentMismatch);
            }
            output_total += u128::from(note.value().ok_or(Reject::Overflow)?);
        }
        if witness.admission.commitment() != public.admission {
            return Err(Reject::AdmissionMismatch);
        }
        // 5. Value is conserved, with F paid publicly.
        if input_total != output_total + u128::from(public.base_fee) {
            return Err(Reject::ValueNotConserved);
        }

        // ---- hidden statement, branch ------------------------------------
        let real_outputs: Vec<Note> = witness
            .outputs
            .iter()
            .filter_map(|o| match o {
                OutputWitness::Real(n) => Some(*n),
                OutputWitness::Dummy { .. } => None,
            })
            .collect();
        let tier = witness.admission.tier;
        match witness.branch {
            Branch::Transfer | Branch::InvitedRequest => {
                let want = if witness.branch == Branch::Transfer { Tier::None } else { Tier::Invited };
                if tier != want || witness.admission.escrow.is_some() {
                    return Err(Reject::TierMismatch);
                }
                if real_inputs.iter().any(|(n, _, _, _)| !matches!(n, Note::Ordinary { .. })) {
                    return Err(Reject::WrongInputType);
                }
                if real_outputs.iter().any(|n| !matches!(n, Note::Ordinary { .. })) {
                    return Err(Reject::WrongOutputs);
                }
            }
            Branch::Open => {
                if real_inputs.iter().any(|(n, _, _, _)| !matches!(n, Note::Ordinary { .. })) {
                    return Err(Reject::WrongInputType);
                }
                let escrows: Vec<&EscrowNote> =
                    real_outputs.iter().filter_map(|n| if let Note::Escrow(e) = n { Some(e) } else { None }).collect();
                let retired: Vec<Value> = real_outputs
                    .iter()
                    .filter_map(|n| if let Note::Retired { value, .. } = n { Some(*value) } else { None })
                    .collect();
                if escrows.len() != 1 || retired.len() > 1 {
                    return Err(Reject::WrongOutputs);
                }
                if retired != [p.surcharge] {
                    return Err(Reject::MissingSurcharge);
                }
                let escrow = escrows[0];
                if escrow.fee_reserve != p.base_fee {
                    return Err(Reject::FeeReserveWrong);
                }
                if tier != Tier::Stranger {
                    return Err(Reject::TierMismatch);
                }
                if witness.admission.escrow != Some(Note::Escrow(*escrow).commitment()) {
                    return Err(Reject::ReceiptEscrowMismatch);
                }
            }
            Branch::Claim | Branch::Decline | Branch::SenderRefund => {
                if tier != Tier::None || witness.admission.escrow.is_some() {
                    return Err(Reject::TierMismatch);
                }
                let [(Note::Escrow(escrow), created_at, escrow_position, authority)] = real_inputs.as_slice() else {
                    return Err(Reject::WrongInputType);
                };
                let required = match witness.branch {
                    Branch::Claim | Branch::Decline => escrow.recipient,
                    _ => escrow.canceller,
                };
                if authority.authority() != required {
                    return Err(Reject::WrongAuthority);
                }
                if escrow.fee_reserve != p.base_fee {
                    return Err(Reject::FeeReserveWrong);
                }
                let deadline = created_at.checked_add(TTL).ok_or(Reject::Overflow)?;
                match witness.branch {
                    Branch::Claim => {
                        // Every inclusion time t < not_after <= deadline.
                        if public.not_after > deadline {
                            return Err(Reject::ClaimTooLate);
                        }
                        let ok = matches!(real_outputs.as_slice(),
                            [Note::Ordinary { value, owner, .. }] if *value == escrow.price && *owner == escrow.recipient);
                        if !ok {
                            return Err(Reject::ClaimPayoutWrong);
                        }
                    }
                    _ => {
                        // Decline or sender refund: no time condition.
                        let refund = derived_refund(escrow, *escrow_position);
                        let refunds = real_outputs.iter().filter(|n| matches!(n, Note::Ordinary { .. })).count();
                        let retired: Vec<Value> = real_outputs
                            .iter()
                            .filter_map(|n| if let Note::Retired { value, .. } = n { Some(*value) } else { None })
                            .collect();
                        if refunds != 1 || real_outputs.len() != 2 || retired.len() != 1 {
                            return Err(Reject::WrongOutputs);
                        }
                        if !real_outputs.contains(&refund) {
                            return Err(Reject::RefundNotDerived);
                        }
                        // Implied by the derived refund and conservation,
                        // but kept explicitly (spec v0.5, I12).
                        if retired[0] != penalty(escrow.price) {
                            return Err(Reject::PenaltyWrong);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
