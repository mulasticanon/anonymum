//! Test harness: a chain plus an omniscient view of every note's plaintext
//! (which the chain itself never has), so tests can check the conservation
//! equation `issued = spendable + in escrow + retired + fees paid` after
//! every transaction, and that a rejected transaction changed nothing.

#![allow(dead_code)]

use std::collections::HashSet;

use anonymum_shielded_model::build::TxBuilder;
use anonymum_shielded_model::hash::{h, Hash};
use anonymum_shielded_model::*;

pub const F: Value = 10;
pub const S: Value = 50;
pub const HOUR: Time = 3_600;
pub const DAY: Time = 86_400;

pub fn params() -> Params {
    Params {
        chain_id: 7,
        version: 1,
        base_fee: F,
        surcharge: S,
        window: HOUR,
        block_time: 6,
        fee_burn_percent: 50,
    }
}

pub fn secret(name: &str) -> Secret {
    Secret(h("test/secret", &[name.as_bytes()]))
}

pub fn blinding(tag: &str) -> Hash {
    h("test/blinding", &[tag.as_bytes()])
}

pub fn ordinary(value: Value, owner: &Secret, tag: &str) -> Note {
    Note::Ordinary { value, owner: owner.authority(), blinding: blinding(tag) }
}

pub struct World {
    pub chain: Chain,
    /// Plaintext of the note at each tree position.
    pub notes: Vec<Note>,
    pub spent: HashSet<u64>,
    pub time: Time,
}

impl World {
    pub fn new(genesis: &[Note]) -> Self {
        World { chain: Chain::genesis(params(), genesis), notes: genesis.to_vec(), spent: HashSet::new(), time: HOUR }
    }

    pub fn created_at(&self, position: u64) -> Time {
        self.chain.leaves()[position as usize].created_at
    }

    /// Submit at the current time. On success the harness records the new
    /// notes and spent positions; on failure it checks nothing changed.
    pub fn submit(&mut self, public: &PublicTx, witness: &Witness) -> Result<Receipt, Reject> {
        let before = self.chain.state_digest();
        let result = self.chain.submit(public, witness, self.time);
        match result {
            Ok(_) => {
                for input in &witness.inputs {
                    if let InputWitness::Real { position, .. } = input {
                        assert!(self.spent.insert(*position), "harness: position spent twice");
                    }
                }
                for out in &witness.outputs {
                    self.notes.push(out.note());
                }
                assert!(self.conserved(), "conservation broken after an accepted transaction");
            }
            Err(_) => assert_eq!(self.chain.state_digest(), before, "a rejected transaction changed state"),
        }
        result
    }

    /// `issued = spendable + in escrow + retired + public fees paid`.
    pub fn conserved(&self) -> bool {
        let (mut spendable, mut escrow, mut retired) = (0u128, 0u128, 0u128);
        for (pos, note) in self.notes.iter().enumerate() {
            let unspent = !self.spent.contains(&(pos as u64));
            match note {
                Note::Ordinary { value, .. } if unspent => spendable += u128::from(*value),
                Note::Escrow(e) if unspent => escrow += u128::from(e.price) + u128::from(e.fee_reserve),
                Note::Retired { value, .. } => retired += u128::from(*value),
                _ => {}
            }
        }
        let fees = self.chain.fees_collected();
        self.chain.fees_burned() + self.chain.node_pool() == fees
            && self.chain.issued() == spendable + escrow + retired + fees
    }

    pub fn position_of(&self, note: &Note) -> u64 {
        self.notes.iter().rposition(|n| n == note).expect("note is in the tree") as u64
    }

    pub fn advance(&mut self, by: Time) {
        self.time += by;
    }
}

/// The parties to one escrow.
pub struct Parties {
    pub sender: Secret,
    pub recipient: Secret,
    pub canceller: Secret,
    pub refund: Secret,
}

pub fn parties() -> Parties {
    Parties {
        sender: secret("sender"),
        recipient: secret("recipient"),
        canceller: secret("sender/canceller"),
        refund: secret("sender/refund-1"),
    }
}

pub fn escrow_note(price: Value, p: &Parties, tag: &str) -> EscrowNote {
    EscrowNote {
        price,
        fee_reserve: F,
        recipient: p.recipient.authority(),
        refund_to: p.refund.authority(),
        canceller: p.canceller.authority(),
        seed: blinding(&format!("{tag}/seed")),
        blinding: blinding(&format!("{tag}/blinding")),
    }
}

pub const CONTACT_KEY: Hash = [0xC0; 32];
pub const REQUEST: Hash = [0x5E; 32];

pub fn stranger_record(escrow: &EscrowNote, tag: &str) -> AdmissionRecord {
    AdmissionRecord {
        contact_key: CONTACT_KEY,
        request_digest: REQUEST,
        tier: Tier::Stranger,
        escrow: Some(Note::Escrow(*escrow).commitment()),
        blinding: blinding(&format!("{tag}/admission")),
    }
}

/// An opening that spends the funding note at `funding_pos` (owned by
/// `p.sender`), creating the escrow, the retired surcharge and change.
pub fn open_tx(w: &World, funding_pos: u64, escrow: &EscrowNote, tag: &str) -> (PublicTx, Witness) {
    let funding = w.notes[funding_pos as usize];
    let Note::Ordinary { value, .. } = funding else { panic!("funding note must be ordinary") };
    let p = parties();
    let change = value - escrow.price - escrow.fee_reserve - S - F;
    TxBuilder::new(Branch::Open, tag.as_bytes())
        .spend(funding, w.created_at(funding_pos), funding_pos, p.sender)
        .output(Note::Escrow(*escrow))
        .output(Note::Retired { value: S, blinding: blinding(&format!("{tag}/surcharge")) })
        .output(ordinary(change, &p.sender, &format!("{tag}/change")))
        .admission(stranger_record(escrow, tag))
        .build(&w.chain, w.time)
}

/// Open an escrow funded by a fresh genesis note; returns the world and the
/// escrow's position.
pub fn world_with_escrow(price: Value) -> (World, EscrowNote, u64) {
    let p = parties();
    let mut w = World::new(&[ordinary(1_000_000, &p.sender, "funding"), ordinary(500, &p.recipient, "recipient-coins")]);
    let escrow = escrow_note(price, &p, "escrow");
    let (public, witness) = open_tx(&w, 0, &escrow, "open");
    w.submit(&public, &witness).expect("opening accepted");
    let pos = w.position_of(&Note::Escrow(escrow));
    (w, escrow, pos)
}

pub fn claim_tx(w: &World, escrow: &EscrowNote, pos: u64, authority: Secret, tag: &str) -> (PublicTx, Witness) {
    TxBuilder::new(Branch::Claim, tag.as_bytes())
        .spend(Note::Escrow(*escrow), w.created_at(pos), pos, authority)
        .output(Note::Ordinary { value: escrow.price, owner: escrow.recipient, blinding: blinding(&format!("{tag}/payout")) })
        .build(&w.chain, w.time)
}

/// A Decline or Sender refund with the derived refund and the penalty.
pub fn refund_tx(w: &World, branch: Branch, escrow: &EscrowNote, pos: u64, authority: Secret, tag: &str) -> (PublicTx, Witness) {
    TxBuilder::new(branch, tag.as_bytes())
        .spend(Note::Escrow(*escrow), w.created_at(pos), pos, authority)
        .output(derived_refund(escrow, pos))
        .output(Note::Retired { value: penalty(escrow.price), blinding: blinding(&format!("{tag}/penalty")) })
        .build(&w.chain, w.time)
}
