//! Benchmarks for `submit_shielded`'s authorization and dispatch, and for
//! stranger-note pruning. Run against the release WebAssembly runtime with
//! `polkadot-omni-node benchmark pallet`; see `weights.rs` for the results.
//!
//! The transaction is one real Transfer proved under the dev key for the
//! dev runtime's chain id (4242) and version (1), written by
//! `dev_tool bench-fixture 4242 1 1795000000 60 24 <dir>`. Its proof of work
//! is solved at 24 bits, so it passes any `PowDifficulty` up to 24.

use super::*;
use frame::prelude::*;
use crate::primitives::*;
use alloc::vec;
use frame::deps::frame_support::traits::Authorize;
use frame::deps::sp_runtime::transaction_validity::TransactionSource;
use frame_benchmarking::v2::*;
use polkadot_sdk::frame_system::RawOrigin;

const TX: &[u8] = include_bytes!("benchmark_fixture/tx.bin");
const VK: &[u8] = include_bytes!("benchmark_fixture/vk.bin");

struct Fixture {
    root: Bytes32,
    nullifiers: [Bytes32; 2],
    commitments: [Bytes32; 3],
    admission: Bytes32,
    not_before: u64,
    not_after: u64,
    coin: [[u8; COIN_PAYLOAD_LEN]; 2],
    note: StrangerNote,
    proof: [u8; PROOF_LEN],
    nonce: u64,
    base_fee: u64,
    chain_id: u32,
    version: u32,
    pow_bits: u32,
}

fn fixture() -> Fixture {
    let mut at = 0;
    let mut take = |len: usize| {
        let part = &TX[at..at + len];
        at += len;
        part
    };
    let mut word = || -> Bytes32 { take(32).try_into().unwrap() };
    let root = word();
    let nullifiers = [word(), word()];
    let commitments = [word(), word(), word()];
    let admission = word();
    let mut take = |len: usize| {
        let part = &TX[at..at + len];
        at += len;
        part
    };
    let u64_at = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    let u32_at = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let not_before = u64_at(take(8));
    let not_after = u64_at(take(8));
    let coin = [take(COIN_PAYLOAD_LEN).try_into().unwrap(), take(COIN_PAYLOAD_LEN).try_into().unwrap()];
    let note = take(STRANGER_NOTE_LEN as usize).to_vec().try_into().unwrap();
    let proof = take(PROOF_LEN).try_into().unwrap();
    let nonce = u64_at(take(8));
    let base_fee = u64_at(take(8));
    let chain_id = u32_at(take(4));
    let version = u32_at(take(4));
    let pow_bits = u32_at(take(4));
    assert_eq!(at, TX.len(), "fixture layout");
    Fixture {
        root, nullifiers, commitments, admission, not_before, not_after, coin, note, proof, nonce, base_fee,
        chain_id, version, pow_bits,
    }
}

/// The state the fixture proves against, with the root ring full so that
/// accepting the new root also removes an old one (the dispatch worst case).
fn setup<T: Config>(fx: &Fixture) {
    assert_eq!(T::ChainId::get(), fx.chain_id, "the fixture is proved for another chain id");
    assert_eq!(T::TxVersion::get(), fx.version, "the fixture is proved for another version");
    assert!(T::PowDifficulty::get() <= fx.pow_bits, "the fixture's proof of work is too weak");
    let stored = prepare_stored_key(VK).expect("fixture key");
    DevVerifyingKey::<T>::put(BoundedVec::try_from(stored).expect("prepare_stored_key checks the length; qed"));
    BaseFee::<T>::put(fx.base_fee);
    T::BenchmarkHelper::set_time_ms(fx.not_before * 1_000);

    let poseidon = Poseidon::new();
    let zero = poseidon.empty_subtrees();
    EmptySubtrees::<T>::put(zero.map(|x| encode_fr(&x)));
    Frontier::<T>::put([encode_fr(&zero[0]); TREE_DEPTH]);
    NextIndex::<T>::put(4);
    for slot in 0..T::RootHistory::get() {
        let mut old = [0u8; 32];
        old[..4].copy_from_slice(&slot.to_le_bytes());
        RootRing::<T>::insert(slot, old);
        AcceptedRoots::<T>::insert(old, ());
    }
    RootCursor::<T>::put(0);
    AcceptedRoots::<T>::insert(fx.root, ());
}

fn call<T: Config>(fx: &Fixture) -> Call<T> {
    Call::<T>::submit_shielded {
        root: fx.root,
        nullifiers: fx.nullifiers,
        commitments: fx.commitments,
        admission_commitment: fx.admission,
        not_before: fx.not_before,
        not_after: fx.not_after,
        coin_payloads: fx.coin,
        stranger_note: fx.note.clone(),
        proof: fx.proof,
        pow_nonce: fx.nonce,
    }
}

#[benchmarks]
mod benchmarks {
    use super::*;

    /// The state updates: two nullifiers, three leaves at depth 20, a root
    /// replacing the oldest, the 1,795-byte note, fee counters, the event.
    #[benchmark]
    fn submit_shielded() {
        let fx = fixture();
        setup::<T>(&fx);
        #[extrinsic_call]
        submit_shielded(
            RawOrigin::Authorized, fx.root, fx.nullifiers, fx.commitments, fx.admission, fx.not_before,
            fx.not_after, fx.coin, fx.note.clone(), fx.proof, fx.nonce,
        );
        assert!(Nullifiers::<T>::contains_key(fx.nullifiers[0]));
        assert_eq!(NextIndex::<T>::get(), 7);
    }

    /// Every authorization check: the cheap ones, strict proof decoding, the
    /// sighash, the proof of work and the Groth16 pairing.
    #[benchmark]
    fn authorize_submit_shielded() {
        let fx = fixture();
        setup::<T>(&fx);
        let call = call::<T>(&fx);
        let result;
        #[block]
        {
            result = call.authorize(TransactionSource::External);
        }
        assert!(matches!(result, Some(Ok(_))), "the fixture must verify");
    }

    /// `n` notes removed from the last of `w` expired windows.
    #[benchmark]
    fn prune_stranger_notes(n: Linear<1, { T::MaxPrunePerBlock::get() }>, w: Linear<1, { T::MaxPruneWindows::get() }>) {
        let step = T::WindowSecs::get();
        let last = u64::from(w - 1) * step;
        PruneCursor::<T>::put(0);
        let note: StrangerNote = vec![7u8; STRANGER_NOTE_LEN as usize].try_into().unwrap();
        for i in 0..n {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            StrangerNotes::<T>::insert(last, key, note.clone());
        }
        #[block]
        {
            Pallet::<T>::prune_stranger_notes(last + NOTE_TTL_SECS);
        }
        assert_eq!(StrangerNotes::<T>::iter_key_prefix(last).count(), 0);
        assert_eq!(PruneCursor::<T>::get(), Some(last + step));
    }

    impl_benchmark_test_suite!(Pallet, crate::mock::bench_ext(), crate::mock::Test);
}
