//! Coin balances, escrow, the node reward pool and the burn counter.
//!
//! Invariant: every coin ever issued is in exactly one of four places —
//! a wallet, escrow, the reward pool, or burned. `is_balanced` checks it.

use std::collections::BTreeMap;

use crate::types::{Address, Amount};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsufficientFunds {
    pub needed: Amount,
    pub available: Amount,
}

#[derive(Default, Debug, Clone)]
pub struct Ledger {
    balances: BTreeMap<Address, Amount>,
    escrowed: Amount,
    reward_pool: Amount,
    burned: Amount,
    issued: Amount,
}

impl Ledger {
    /// Create coins. Genesis allocation and tests only.
    pub fn mint(&mut self, to: Address, amount: Amount) {
        self.issued = self.issued.checked_add(amount).expect("supply overflow");
        self.credit(to, amount);
    }

    pub fn balance(&self, who: &Address) -> Amount {
        self.balances.get(who).copied().unwrap_or(0)
    }

    pub fn escrowed(&self) -> Amount {
        self.escrowed
    }

    /// Coins set aside to pay the nodes that relay messages.
    pub fn reward_pool(&self) -> Amount {
        self.reward_pool
    }

    pub fn burned(&self) -> Amount {
        self.burned
    }

    pub fn issued(&self) -> Amount {
        self.issued
    }

    pub fn is_balanced(&self) -> bool {
        let total = self
            .balances
            .values()
            .chain([&self.escrowed, &self.reward_pool, &self.burned])
            .try_fold(0 as Amount, |sum, x| sum.checked_add(*x));
        total == Some(self.issued)
    }

    pub(crate) fn can_pay(&self, who: &Address, amount: Amount) -> Result<(), InsufficientFunds> {
        let available = self.balance(who);
        if available < amount {
            return Err(InsufficientFunds { needed: amount, available });
        }
        Ok(())
    }

    /// Take a network fee: part is burned, the rest funds node rewards.
    pub(crate) fn pay_network_fee(
        &mut self,
        from: Address,
        amount: Amount,
        burn_percent: u8,
    ) -> Result<(), InsufficientFunds> {
        self.debit(from, amount)?;
        // Split without multiplying the whole amount, which could overflow.
        let percent = Amount::from(burn_percent.min(100));
        let burn = amount / 100 * percent + amount % 100 * percent / 100;
        self.burned = bounded_add(self.burned, burn);
        self.reward_pool = bounded_add(self.reward_pool, amount - burn);
        Ok(())
    }

    /// Move coins from a wallet into escrow.
    pub(crate) fn lock(&mut self, from: Address, amount: Amount) -> Result<(), InsufficientFunds> {
        self.debit(from, amount)?;
        self.escrowed = bounded_add(self.escrowed, amount);
        Ok(())
    }

    /// Destroy coins held in escrow (the decline fee). Nobody receives them.
    pub(crate) fn burn_escrowed(&mut self, amount: Amount) {
        self.escrowed = self.escrowed.checked_sub(amount).expect("escrow underflow");
        self.burned = bounded_add(self.burned, amount);
    }

    /// Move coins from escrow into a wallet.
    pub(crate) fn release(&mut self, to: Address, amount: Amount) {
        self.escrowed = self.escrowed.checked_sub(amount).expect("escrow underflow");
        self.credit(to, amount);
    }

    fn debit(&mut self, who: Address, amount: Amount) -> Result<(), InsufficientFunds> {
        self.can_pay(&who, amount)?;
        let balance = self.balances.entry(who).or_insert(0);
        *balance -= amount;
        Ok(())
    }

    fn credit(&mut self, who: Address, amount: Amount) {
        let balance = self.balances.entry(who).or_insert(0);
        *balance = balance.checked_add(amount).expect("balance overflow");
    }
}

/// Adds two amounts that are each part of the issued supply, so the sum
/// cannot exceed `issued` (itself checked when minted). Panics only if that
/// invariant is broken, never silently wraps.
fn bounded_add(a: Amount, b: Amount) -> Amount {
    a.checked_add(b).expect("ledger totals are bounded by the issued supply")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_network_fee_splits_without_overflow() {
        let who = Address::from_label("whale");
        let mut ledger = Ledger::default();
        ledger.mint(who, Amount::MAX);
        ledger.pay_network_fee(who, Amount::MAX, 50).unwrap();
        assert_eq!(ledger.burned(), Amount::MAX / 2, "floor of half");
        assert_eq!(ledger.reward_pool(), Amount::MAX - Amount::MAX / 2);
        assert!(ledger.is_balanced());
    }

    #[test]
    fn burn_split_matches_the_simple_formula_for_small_amounts() {
        for (amount, pct) in [(1_000_001u128, 50u8), (7, 33), (99, 100), (12_345, 0)] {
            let who = Address::from_label("a");
            let mut ledger = Ledger::default();
            ledger.mint(who, amount);
            ledger.pay_network_fee(who, amount, pct).unwrap();
            assert_eq!(ledger.burned(), amount * pct as u128 / 100);
        }
    }
}
