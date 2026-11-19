//! Long random mixed histories. After every transaction (accepted or not)
//! the conservation equation must hold, rejected transactions must change
//! nothing (checked by the harness), and the outcome must be what the rules
//! predict.

mod common;

use std::collections::HashMap;

use anonymum_shielded_model::build::{rebind, reseal, TxBuilder};
use anonymum_shielded_model::chain::PAYLOAD_LEN;
use anonymum_shielded_model::*;
use common::*;

/// SplitMix64: a tiny deterministic generator for picking test actions.
/// Not cryptographic and not used for anything secret: it only decides the
/// order of events so failures are reproducible from the seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

struct Pending {
    escrow: EscrowNote,
    pos: u64,
}

struct Sim {
    w: World,
    rng: Rng,
    /// Authority -> secret, for every identity the actors control.
    keys: HashMap<[u8; 32], Secret>,
    actors: Vec<Secret>,
    pending: Vec<Pending>,
    counter: u64,
    accepted: HashMap<&'static str, u64>,
    rejected_as_predicted: u64,
}

impl Sim {
    fn new(seed: u64) -> Self {
        let actors: Vec<Secret> = (0..4).map(|i| secret(&format!("actor-{i}"))).collect();
        let mut genesis = Vec::new();
        for (i, a) in actors.iter().enumerate() {
            for j in 0..3 {
                genesis.push(ordinary(50_000 + 1_000 * j, a, &format!("g-{seed}-{i}-{j}")));
            }
        }
        let keys = actors.iter().map(|s| (s.authority().0, *s)).collect();
        Sim {
            w: World::new(&genesis),
            rng: Rng(seed),
            keys,
            actors,
            pending: Vec::new(),
            counter: 0,
            accepted: HashMap::new(),
            rejected_as_predicted: 0,
        }
    }

    fn tag(&mut self) -> String {
        self.counter += 1;
        format!("t{}", self.counter)
    }

    fn fresh_identity(&mut self, owner: usize) -> Secret {
        let s = secret(&format!("actor-{owner}/fresh-{}", self.counter));
        self.keys.insert(s.authority().0, s);
        s
    }

    /// An unspent ordinary note an actor's keys control, worth at least `min`.
    fn spendable(&mut self, min: Value) -> Option<(u64, Note, Secret)> {
        let candidates: Vec<(u64, Note, Secret)> = self
            .w
            .notes
            .iter()
            .enumerate()
            .filter(|(pos, _)| !self.w.spent.contains(&(*pos as u64)))
            .filter_map(|(pos, n)| match n {
                Note::Ordinary { value, owner, .. } if *value >= min => {
                    self.keys.get(&owner.0).map(|s| (pos as u64, *n, *s))
                }
                _ => None,
            })
            .collect();
        if candidates.is_empty() {
            None
        } else {
            Some(candidates[self.rng.below(candidates.len() as u64) as usize])
        }
    }

    fn record(&mut self, what: &'static str, result: Result<Receipt, Reject>) {
        result.unwrap_or_else(|e| panic!("valid {what} rejected: {e:?}"));
        *self.accepted.entry(what).or_default() += 1;
    }

    /// Build one valid transaction for a random action, if one is possible.
    fn valid_tx(&mut self) -> Option<(&'static str, PublicTx, Witness, Option<usize>)> {
        let tag = self.tag();
        match self.rng.below(7) {
            0 | 1 => {
                let invited = self.rng.below(2) == 1;
                let (pos, note, owner) = self.spendable(F + 1)?;
                let value = note.value().unwrap();
                let to = self.rng.pick(&self.actors.clone());
                let split = self.rng.below(value - F + 1);
                let mut b = TxBuilder::new(if invited { Branch::InvitedRequest } else { Branch::Transfer }, tag.as_bytes())
                    .spend(note, self.w.created_at(pos), pos, owner)
                    .output(ordinary(split, &to, &format!("{tag}/a")))
                    .output(ordinary(value - F - split, &owner, &format!("{tag}/b")));
                if invited {
                    b = b.admission(AdmissionRecord {
                        contact_key: [self.rng.below(255) as u8; 32],
                        request_digest: blinding(&format!("{tag}/req")),
                        tier: Tier::Invited,
                        escrow: None,
                        blinding: blinding(&format!("{tag}/adm")),
                    });
                }
                let (p, w) = b.build(&self.w.chain, self.w.time);
                Some((if invited { "invited" } else { "transfer" }, p, w, None))
            }
            2 => {
                let price = self.rng.pick(&[0, 1, 99, 100, 101, 250, 1_000, 9_999]);
                let (pos, note, owner) = self.spendable(price + 2 * F + S)?;
                let value = note.value().unwrap();
                let sender = self.actors.iter().position(|a| *a == owner).unwrap_or(0);
                let recipient = self.actors[(sender + 1 + self.rng.below(3) as usize) % 4];
                let refund = self.fresh_identity(sender);
                let escrow = EscrowNote {
                    price,
                    fee_reserve: F,
                    recipient: recipient.authority(),
                    refund_to: refund.authority(),
                    canceller: owner.authority(),
                    seed: blinding(&format!("{tag}/seed")),
                    blinding: blinding(&format!("{tag}/eb")),
                };
                let (p, w) = TxBuilder::new(Branch::Open, tag.as_bytes())
                    .spend(note, self.w.created_at(pos), pos, owner)
                    .output(Note::Escrow(escrow))
                    .output(Note::Retired { value: S, blinding: blinding(&format!("{tag}/s")) })
                    .output(ordinary(value - price - 2 * F - S, &owner, &format!("{tag}/c")))
                    .admission(stranger_record(&escrow, &tag))
                    .build(&self.w.chain, self.w.time);
                Some(("open", p, w, None))
            }
            _ => {
                if self.pending.is_empty() {
                    return None;
                }
                let i = self.rng.below(self.pending.len() as u64) as usize;
                let Pending { escrow, pos } = self.pending[i];
                // Pick a branch the rules allow at this time: claims only in a
                // window that ends by the deadline; refunds at any time.
                let deadline = self.w.created_at(pos) + DAY;
                let window_start = self.w.time - self.w.time % HOUR;
                let expired = window_start >= deadline;
                let branch = match self.rng.below(3) {
                    // Expired escrows are rare (most resolve early), so favour
                    // the sender refund once one has expired.
                    0 if expired => Branch::Decline,
                    _ if expired => Branch::SenderRefund,
                    0 if window_start + HOUR <= deadline => Branch::Claim,
                    0 | 1 => Branch::Decline,
                    _ => Branch::SenderRefund,
                };
                let recipient = self.keys[&escrow.recipient.0];
                let canceller = self.keys[&escrow.canceller.0];
                let (p, w) = match branch {
                    Branch::Claim => claim_tx(&self.w, &escrow, pos, recipient, &tag),
                    Branch::Decline => refund_tx(&self.w, branch, &escrow, pos, recipient, &tag),
                    _ => refund_tx(&self.w, branch, &escrow, pos, canceller, &tag),
                };
                let name = match branch {
                    Branch::Claim => "claim",
                    Branch::Decline => "decline",
                    _ if expired => "sender refund after deadline",
                    _ => "sender refund before deadline",
                };
                Some((name, p, w, Some(i)))
            }
        }
    }

    /// Corrupt a valid transaction so the rules must reject it.
    fn corrupt(&mut self, public: &PublicTx, witness: &Witness) -> (PublicTx, Witness) {
        let (mut p, mut w) = (public.clone(), *witness);
        match self.rng.below(6) {
            0 => p.payloads[self.rng.below(3) as usize][self.rng.below(PAYLOAD_LEN as u64) as usize] ^= 0x40, // relay tampering
            1 => {
                p.nullifiers[self.rng.below(2) as usize] = Nullifier(blinding(&format!("junk{}", self.counter)));
                rebind(&p, &mut w);
            }
            2 => {
                p.commitments[self.rng.below(3) as usize] = Commitment(blinding(&format!("junk{}", self.counter)));
                rebind(&p, &mut w);
            }
            3 => {
                p.not_before += HOUR;
                p.not_after += HOUR;
                rebind(&p, &mut w);
            }
            4 => {
                // Inflate a real output by one unit.
                if let Some(slot) = w.outputs.iter_mut().find(|o| matches!(o, OutputWitness::Real(_))) {
                    if let OutputWitness::Real(note) = slot {
                        match note {
                            Note::Ordinary { value, .. } | Note::Retired { value, .. } => *value = value.saturating_add(1),
                            Note::Escrow(e) => e.price = e.price.saturating_add(1),
                        }
                    }
                }
                reseal(&mut p, &mut w);
            }
            _ => p.chain_id ^= 1,
        }
        (p, w)
    }

    fn step(&mut self) {
        if self.rng.below(5) == 0 {
            // Time passes, in whole blocks, up to 10 hours.
            self.w.advance(6 * self.rng.below(6_000));
            return;
        }
        let Some((what, public, witness, pending_index)) = self.valid_tx() else { return };
        if self.rng.below(4) == 0 {
            let (bad_p, bad_w) = self.corrupt(&public, &witness);
            let result = self.w.submit(&bad_p, &bad_w);
            assert!(result.is_err(), "corrupted {what} accepted");
            self.rejected_as_predicted += 1;
        } else {
            let result = self.w.submit(&public, &witness);
            self.record(what, result);
            if what == "open" {
                let Some(OutputWitness::Real(Note::Escrow(escrow))) = witness.outputs.first().copied() else { unreachable!() };
                let pos = self.w.position_of(&Note::Escrow(escrow));
                self.pending.push(Pending { escrow, pos });
            }
            if let Some(i) = pending_index {
                self.pending.swap_remove(i);
            }
        }
        assert!(self.w.conserved(), "conservation broken");
    }
}

#[test]
fn long_random_histories_conserve_value_after_every_transaction() {
    let mut totals: HashMap<&'static str, u64> = HashMap::new();
    let mut rejected = 0;
    for seed in 1..=25 {
        let mut sim = Sim::new(seed);
        for _ in 0..400 {
            sim.step();
        }
        for (k, v) in sim.accepted {
            *totals.entry(k).or_default() += v;
        }
        rejected += sim.rejected_as_predicted;
    }
    // Every branch must actually have been exercised.
    for branch in ["transfer", "invited", "open", "claim", "decline", "sender refund before deadline", "sender refund after deadline"] {
        assert!(totals.get(branch).copied().unwrap_or(0) > 20, "too few {branch}: {totals:?}");
    }
    assert!(rejected > 100, "too few corrupted transactions tried: {rejected}");
    println!("accepted per branch: {totals:?}; corrupted and rejected: {rejected}");
}
