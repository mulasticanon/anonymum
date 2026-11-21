//! Real cryptography for Anonymum, built only from audited-in-the-wild crates.
//!
//! * [`Identity`] — a wallet: Ed25519 key for the chain address and
//!   signatures, X25519 key bound to it for the transparent prototype chain.
//!   Never used in a handshake or a note.
//! * [`ContactIdentity`], [`ContactCard`], [`Invitation`] — a contact
//!   identity separate from the wallet (spec v0.7 section 2a).
//! * [`Gate`] — who the answering side lets in, decided before any reply.
//! * [`wire`] — Noise IK sessions between contact keys, driven through
//!   [`wire::Initiator`] and [`wire::Responder`] (the only way to answer). Nobody without one of the two private keys can read the
//!   messages: no node, no developer.
//! * [`ratchet`] — a Double Ratchet (Signal specification) for data frames,
//!   seeded from the IK handshake: per-message forward secrecy and
//!   post-compromise security. Unreviewed prototype.
//! * [`seal_note`] / [`open_note`] — a stranger's fixed-size note, opened
//!   with the recipient's inbox key alone.
//! * [`InviteSecret`] / [`Ed25519Invites`] — the transparent chain's
//!   one-time invites (cheap channel opening), unchanged.
//!
//! This crate composes existing primitives; it invents none. It has not been
//! externally audited, and the handshake and note format (section 2a) have
//! not been reviewed (spec questions 11 and 12).

pub mod contact;
pub mod gate;
mod identity;
mod invite;
pub mod note;
pub mod ratchet;
pub mod snapshot;
mod session;
pub mod wire;

pub use contact::{
    epoch_start, is_contributory_key, random_bytes, CardSummary, ContactCard, ContactError, ContactIdentity, KeyEpoch,
    Invitation, Network, Purpose, StaticKey, CLOCK_GRID_BACKDATE, DRAIN_GRACE, EPOCH_LEN,
};
pub use gate::{Gate, Grant, Now, CLOCK_SKEW_SECS};
pub use snapshot::{write_atomically, SnapshotError, StorageKey, GATE_SNAPSHOT_VERSION};
pub use identity::Identity;
pub use invite::{Ed25519Invites, InviteSecret};
pub use note::{dummy_note, open_note, seal_note, ContactNote, NoteError};
pub use ratchet::{Ratchet, RatchetError, RatchetKey};
pub use session::{Session, SessionError, MAX_PLAINTEXT, REFERENCE_LEN};
