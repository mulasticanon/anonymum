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
        let in_wallets: Amount = self.balances.values().sum();
        in_wallets + self.escrowed + self.reward_pool + self.burned == self.issued
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
        let burn = amount * Amount::from(burn_percent.min(100)) / 100;
        self.burned += burn;
        self.reward_pool += amount - burn;
        Ok(())
    }

    /// Move coins from a wallet into escrow.
    pub(crate) fn lock(&mut self, from: Address, amount: Amount) -> Result<(), InsufficientFunds> {
        self.debit(from, amount)?;
        self.escrowed += amount;
        Ok(())
    }

    /// Destroy coins held in escrow (the decline fee). Nobody receives them.
    pub(crate) fn burn_escrowed(&mut self, amount: Amount) {
        self.escrowed = self.escrowed.checked_sub(amount).expect("escrow underflow");
        self.burned += amount;
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
