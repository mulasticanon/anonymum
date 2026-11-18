//! Token bucket used to cap "free" messages per contact.
//!
//! Time is passed in explicitly (milliseconds) so behaviour is deterministic
//! and testable.

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity_milli: u64,
    refill_per_sec: u64,
    tokens_milli: u64,
    last_ms: u64,
}

impl TokenBucket {
    /// `capacity` is the burst size; `refill_per_sec` the sustained rate.
    pub fn new(capacity: u32, refill_per_sec: u32, now_ms: u64) -> Self {
        let capacity_milli = u64::from(capacity) * 1000;
        TokenBucket {
            capacity_milli,
            refill_per_sec: u64::from(refill_per_sec),
            tokens_milli: capacity_milli,
            last_ms: now_ms,
        }
    }

    /// Spend one token if available.
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = self.last_ms.max(now_ms);
        // refill_per_sec tokens per 1000 ms == refill_per_sec milli-tokens per ms
        let refill = elapsed.saturating_mul(self.refill_per_sec);
        self.tokens_milli = self.tokens_milli.saturating_add(refill).min(self.capacity_milli);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}
