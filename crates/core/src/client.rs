//! Client-side admission: which incoming messages get shown to the user.
//!
//! Mix nodes cannot enforce "only paid-up contacts may message you", because
//! by design they do not know who is talking to whom. So the rule is
//! enforced where the knowledge exists: in the recipient's own client, which
//! checks the chain for an open channel and silently drops everything else.

use std::collections::BTreeMap;

use crate::chain::Chain;
use crate::crypto::InviteScheme;
use crate::ratelimit::TokenBucket;
use crate::transport::Envelope;
use crate::types::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Deliver,
    /// Not addressed to this inbox.
    DropMisaddressed,
    /// Sender has no open channel with us: they must use an invite or pay.
    DropNoChannel,
    /// Sender is over their free allowance.
    DropRateLimited,
}

pub struct Inbox {
    owner: Address,
    burst: u32,
    per_sec: u32,
    buckets: BTreeMap<Address, TokenBucket>,
}

impl Inbox {
    /// `burst` messages at once, then `per_sec` sustained, per contact.
    pub fn new(owner: Address, burst: u32, per_sec: u32) -> Self {
        Inbox { owner, burst, per_sec, buckets: BTreeMap::new() }
    }

    pub fn admit<S: InviteScheme>(
        &mut self,
        chain: &Chain<S>,
        envelope: &Envelope,
        now_ms: u64,
    ) -> Verdict {
        if envelope.to != self.owner {
            return Verdict::DropMisaddressed;
        }
        if chain.channel_between(&envelope.from, &self.owner).is_none() {
            self.buckets.remove(&envelope.from);
            return Verdict::DropNoChannel;
        }
        let (burst, per_sec) = (self.burst, self.per_sec);
        let bucket = self
            .buckets
            .entry(envelope.from)
            .or_insert_with(|| TokenBucket::new(burst, per_sec, now_ms));
        if bucket.try_take(now_ms) {
            Verdict::Deliver
        } else {
            Verdict::DropRateLimited
        }
    }
}
