//! Message transport.
//!
//! Production transport is the Nym mixnet. The core only needs "send these
//! bytes to that address" and "give me what arrived", so the Nym adapter
//! lives in its own crate and implements [`Transport`].

use std::collections::{BTreeMap, VecDeque};

use crate::types::Address;

/// What travels between clients.
///
/// In production `payload` is end-to-end encrypted ciphertext and `from` is
/// *inside* that ciphertext, so mix nodes never learn the sender. It is a
/// plain field here because milestone 1 has no encryption layer yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub from: Address,
    pub to: Address,
    pub payload: Vec<u8>,
}

pub trait Transport {
    fn send(&mut self, envelope: Envelope);
    fn receive(&mut self, who: &Address) -> Option<Envelope>;
}

/// Loopback transport for tests and demos. No anonymity whatsoever.
#[derive(Default)]
pub struct InMemoryTransport {
    queues: BTreeMap<Address, VecDeque<Envelope>>,
}

impl Transport for InMemoryTransport {
    fn send(&mut self, envelope: Envelope) {
        self.queues.entry(envelope.to).or_default().push_back(envelope);
    }

    fn receive(&mut self, who: &Address) -> Option<Envelope> {
        self.queues.get_mut(who)?.pop_front()
    }
}
