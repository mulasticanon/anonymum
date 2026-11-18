//! Real cryptography for Anonymum, built only from audited-in-the-wild crates.
//!
//! * [`Identity`] — a wallet: Ed25519 key for the address and signatures,
//!   X25519 key for message encryption, with the second bound to the first.
//! * [`InviteSecret`] / [`Ed25519Invites`] — one-time invites, replacing the
//!   insecure mock in `anonymum-core`.
//! * [`Handshake`] / [`Session`] — end-to-end encryption between two
//!   addresses using the Noise XX pattern. Nobody without one of the two
//!   private keys can read the messages: no node, no developer.
//!
//! This crate composes existing primitives; it invents none. It has not been
//! externally audited.

mod identity;
mod invite;
mod session;
pub mod wire;

pub use identity::Identity;
pub use invite::{Ed25519Invites, InviteSecret};
pub use session::{Handshake, Session, SessionError, MAX_PLAINTEXT};
