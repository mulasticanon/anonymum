//! # A reference model of the shielded-money rules — for review, not use
//!
//! **This is a model of the rules in `docs/shielded-spec-v0.md` (v0.5), not
//! a private or secure implementation.** There are no zero-knowledge
//! proofs, no circuits and no encryption of notes. The chain function sees
//! every hidden value: it checks the witness directly where the real system
//! would verify a proof. Nothing here hides anything from anyone. It exists
//! so a reviewer can read the rules as code, and so tests can show which
//! transactions the rules accept and reject.
//!
//! What it models:
//! * the objects of section 3: ordinary, escrow and retired notes, each with
//!   a secret blinding; commitments; leaves stamped on the window grid;
//!   position-bound escrow nullifiers; dummy nullifiers in their own domain;
//!   the admission record ([`objects`]);
//! * the transaction shape and every branch of section 4, including the
//!   invited request, the stranger surcharge `S` retired at opening, the
//!   refund derived from the escrow seed, and the chain-side checks
//!   ([`chain::Chain::submit`], the one entry point);
//! * a wallet that recovers its escrows from the chain alone ([`wallet`]).
//!
//! "Holds the authority" is modelled as knowing a secret whose hash is the
//! authority. Hashing is BLAKE2s-256 with domain separation ([`hash`]); the
//! recovery copy uses ChaCha20-Poly1305. No primitive is hand-written.
//!
//! Where the spec was ambiguous the model makes a choice and says so; the
//! list is in `docs/shielded-spec-v0-issues.md`.

pub mod build;
pub mod chain;
pub mod hash;
pub mod objects;
pub mod wallet;

pub use chain::{Branch, Chain, InputWitness, OutputWitness, Params, PublicTx, Receipt, Reject, Witness};
pub use objects::*;
