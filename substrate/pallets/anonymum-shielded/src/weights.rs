//! Weights for `pallet-anonymum-shielded`, from its benchmarks
//! (`benchmarking.rs`) run in the release WebAssembly runtime.
//!
//! **One developer laptop, not reference hardware.** Measured 2026-11-25:
//! Intel Core i5-1035G1 (4 cores, 8 threads, 1.0 GHz base), WSL2 Ubuntu with
//! 3.8 GB RAM; `polkadot-omni-node` 1.25.2 `benchmark pallet` with
//! `--wasm-execution compiled --steps 10 --repeat 50 --min-duration 0`, the
//! runtime built with `--features runtime-benchmarks`. Times are the
//! benchmark's extrinsic time per repeat; one thread.
//!
//! | Benchmark | mean | median | p95 | max | weight |
//! |---|---|---|---|---|---|
//! | `authorize_submit_shielded` | 70.09 ms | 67.00 ms | 87.40 ms | 142.71 ms | 175 ms |
//! | `submit_shielded` | 57.57 ms | 54.59 ms | 78.84 ms | 95.03 ms | 115 ms |
//! | `prune_stranger_notes(64, 64)` | 1.23 ms | 1.22 ms | 1.36 ms | 1.49 ms | 2.86 ms |
//!
//! Rule: 1.2 x the largest of the 50 repeats, rounded up to 5 ms. Pruning is
//! a linear bound at least 1.2 x the largest repeat at each of its 19
//! measured points (`n` notes removed, `w` windows advanced). Database
//! reads and writes are counted by the benchmarks and charged through
//! `T::DbWeight`; proof sizes are the benchmark's `MaxEncodedLen` bounds.
//! For comparison, native verification takes 5.89 ms (release, 8 threads).
//!
//! Rerun after any change to the pallet, the circuit or the SDK, and on the
//! hardware validators will actually use, before any public network.

use core::marker::PhantomData;
use polkadot_sdk::polkadot_sdk_frame::deps::frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};

pub trait WeightInfo {
    fn submit_shielded() -> Weight;
    fn authorize_submit_shielded() -> Weight;
    fn prune_stranger_notes(n: u32, w: u32) -> Weight;
}

/// Picoseconds per millisecond and per microsecond.
const MS: u64 = 1_000_000_000;
const US: u64 = 1_000_000;

/// Execution and proof size, without database access.
fn submit_shielded_base() -> Weight {
    Weight::from_parts(115 * MS, 6_036)
}
fn authorize_base() -> Weight {
    Weight::from_parts(175 * MS, 6_036)
}
fn prune_base(n: u32, w: u32) -> Weight {
    Weight::from_parts(800 * US, 1_493)
        .saturating_add(Weight::from_parts(11 * US, 4_336).saturating_mul(n.into()))
        .saturating_add(Weight::from_parts(21 * US, 4_336).saturating_mul(w.into()))
}

pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: polkadot_sdk::frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// Reads 13, writes 13: nullifiers, tree, roots, note, fee counters.
    fn submit_shielded() -> Weight {
        submit_shielded_base().saturating_add(T::DbWeight::get().reads_writes(13, 13))
    }
    /// Reads 9: roots, nullifiers, tree size, fee and counters, the key.
    fn authorize_submit_shielded() -> Weight {
        authorize_base().saturating_add(T::DbWeight::get().reads(9))
    }
    fn prune_stranger_notes(n: u32, w: u32) -> Weight {
        prune_base(n, w).saturating_add(
            T::DbWeight::get().reads_writes(1 + u64::from(n) + u64::from(w), 1 + u64::from(n)),
        )
    }
}

impl WeightInfo for () {
    fn submit_shielded() -> Weight {
        submit_shielded_base().saturating_add(RocksDbWeight::get().reads_writes(13, 13))
    }
    fn authorize_submit_shielded() -> Weight {
        authorize_base().saturating_add(RocksDbWeight::get().reads(9))
    }
    fn prune_stranger_notes(n: u32, w: u32) -> Weight {
        prune_base(n, w).saturating_add(
            RocksDbWeight::get().reads_writes(1 + u64::from(n) + u64::from(w), 1 + u64::from(n)),
        )
    }
}
