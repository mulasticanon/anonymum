//! Anonymum protocol core.
//!
//! This crate models the *on-chain rules* and the *client-side admission
//! rules* of a messaging coin where:
//!
//! * a contact who holds a one-time invite opens a channel for a small fee;
//! * a stranger pays a larger network fee plus a price set by the recipient;
//! * once a channel is open, messages are free but rate limited.
//!
//! Messages themselves never touch the chain. They travel over a mixnet
//! (Nym) and are admitted or dropped by the recipient's own client, which
//! checks the chain for an open channel. See `README.md` for the design.

pub mod chain;
pub mod client;
pub mod crypto;
pub mod ledger;
pub mod ratelimit;
pub mod transport;
pub mod types;

pub use chain::{
    Chain, Channel, ContactRequest, Error, Event, OpenedVia, Params, PublishedKey, RefundReason,
    Tx, UnblockReason,
};
pub use crypto::{KeyBinding, MessagingKey, SealedNote, SEALED_NOTE_LEN};
pub use client::{Inbox, Verdict};
pub use transport::{Envelope, InMemoryTransport, Transport};
pub use types::{Address, Amount, BlockHeight, ChannelId, RequestId, COIN};
