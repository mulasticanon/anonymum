//! **UNREVIEWED PROTOTYPE. NOT AUDITED. NOT FOR REAL VALUE.**
//!
//! A Groth16 circuit over BLS12-381 for the six transaction branches of
//! `docs/shielded-spec-v0.md`, mirroring the rules of
//! `crates/shielded-model`. It composes arkworks only: no hand-written
//! curve, pairing, proof or Poseidon code.
//!
//! What this crate does not give you:
//!
//! - **No trusted setup.** [`verifier::insecure_dev_setup`] is one process
//!   holding the toxic waste. Whoever holds it can forge proofs and mint.
//! - **No privacy claim.** Nothing here has been analysed for leakage.
//! - **Chain-side checks live elsewhere.** The accepted root, unused and
//!   distinct nullifiers, window grid and payload lengths stay outside the
//!   proof, in `substrate/pallets/anonymum-shielded`, which uses this crate
//!   only as a test dependency.
//! - **Poseidon parameters are a proposal**, for the cryptographer to
//!   confirm (see [`poseidon`]).
//!
//! Groth16 proofs are re-randomisable: anyone can turn a valid proof into a
//! different valid proof **of the same public inputs**. The statement,
//! including `sighash`, cannot change, but the proof bytes must never be
//! used as a transaction identifier or a replay guard.

pub mod circuit;
pub mod fixtures;
pub mod merkle;
pub mod objects;
pub mod poseidon;
pub mod verifier;

pub use ark_bls12_381::{Bls12_381, Fr};
pub use circuit::{CircuitParams, Flags, ShieldedCircuit};
pub use merkle::MerkleTree;
pub use objects::*;
