//! Basic value types shared by every module.

use std::fmt;

/// Amounts are integers in the smallest unit. Never use floats for money.
pub type Amount = u128;

/// One whole coin, in smallest units.
pub const COIN: Amount = 1_000_000;

pub type BlockHeight = u64;

/// A wallet address. In production this is derived from a public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Readable address for tests and demos, e.g. `Address::from_label("alice")`.
    pub fn from_label(label: &str) -> Self {
        let mut bytes = [0u8; 32];
        for (slot, byte) in bytes.iter_mut().zip(label.bytes()) {
            *slot = byte;
        }
        Address(bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end = self.0.iter().position(|b| *b == 0).unwrap_or(32);
        let head = &self.0[..end];
        let is_label = !head.is_empty()
            && head.iter().all(|b| b.is_ascii_alphanumeric())
            && self.0[end..].iter().all(|b| *b == 0);
        if is_label {
            write!(f, "{}", String::from_utf8_lossy(head))
        } else {
            for byte in &self.0[..4] {
                write!(f, "{byte:02x}")?;
            }
            write!(f, "…")
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ChannelId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RequestId(pub u64);
