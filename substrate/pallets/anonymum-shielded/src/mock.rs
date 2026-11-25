//! Test runtime: System, Timestamp and the shielded pallet, started from the
//! leaves of a `crates/shielded-circuit` fixture.

use crate as pallet_anonymum_shielded;
use crate::primitives::{encode_fr, STRANGER_NOTE_LEN};
use anonymum_shielded_circuit::fixtures::{self, Case};
use anonymum_shielded_circuit::{Bls12_381, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use frame::deps::sp_runtime::{BuildStorage, Percent};
use frame::testing_prelude::*;
use polkadot_sdk::pallet_timestamp;
use polkadot_sdk::polkadot_sdk_frame as frame;
use std::sync::OnceLock;

type Block = frame_system::mocking::MockBlock<Test>;

pub const CHAIN_ID: u32 = 7;
pub const TX_VERSION: u32 = 1;
pub const WINDOW: u64 = fixtures::WINDOW;
pub const BASE_FEE: u64 = fixtures::BASE_FEE;
pub const ROOT_HISTORY: u32 = 4;

#[frame_construct_runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;
    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp::Pallet<Test>;
    #[runtime::pallet_index(2)]
    pub type Shielded = pallet_anonymum_shielded::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

parameter_types! {
    pub const BurnShare: Percent = Percent::from_percent(30);
}

/// Low, so tests stay fast. Each test chain starts from this value.
pub const TEST_POW_BITS: u32 = 4;

parameter_types! {
    pub static PowBits: u32 = TEST_POW_BITS;
    pub static MockChainId: u32 = CHAIN_ID;
}

impl pallet_anonymum_shielded::Config for Test {
    type TimeProvider = Timestamp;
    type ChainId = MockChainId;
    type TxVersion = ConstU32<TX_VERSION>;
    type WindowSecs = ConstU64<WINDOW>;
    type FeeBurnPercent = BurnShare;
    type RootHistory = ConstU32<ROOT_HISTORY>;
    type MaxPrunePerBlock = ConstU32<2>;
    type MaxPruneWindows = ConstU32<8>;
    type PoolLongevity = ConstU64<10>;
    type PowDifficulty = PowBits;
    type WeightInfo = ();
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = TestTime;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct TestTime;
#[cfg(feature = "runtime-benchmarks")]
impl crate::BenchmarkHelper for TestTime {
    fn set_time_ms(ms: u64) {
        pallet_timestamp::Now::<Test>::put(ms);
    }
}

/// The benchmarks' fixture is proved for the dev runtime's chain id.
#[cfg(feature = "runtime-benchmarks")]
pub fn bench_ext() -> TestState {
    let ext = new_test_ext(Case::Transfer);
    MockChainId::set(4242);
    ext
}

pub struct Keys {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
    pub vk_bytes: Vec<u8>,
}

/// The dev keys, shared by all tests.
pub fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let (pk, vk) = fixtures::dev_keys();
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        Keys { pk, vk, vk_bytes }
    })
}

/// A chain holding `case`'s leaves, at a block time inside its window.
pub fn new_test_ext(case: Case) -> TestState {
    new_test_ext_with(case, BASE_FEE, true)
}

pub fn new_test_ext_with(case: Case, base_fee: u64, with_key: bool) -> TestState {
    PowBits::set(TEST_POW_BITS);
    MockChainId::set(CHAIN_ID);
    let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let leaves: Vec<[u8; 32]> = fixtures::world_leaves(case).iter().map(encode_fr).collect();
    pallet_anonymum_shielded::GenesisConfig::<Test> {
        dev_verifying_key: if with_key { keys().vk_bytes.clone() } else { Vec::new() },
        base_fee,
        initial_leaves: leaves,
        _marker: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext = TestState::new(storage);
    ext.execute_with(|| {
        System::set_block_number(1);
        set_time(fixtures::NOT_BEFORE);
    });
    ext
}

/// Set the block time, in seconds.
pub fn set_time(seconds: u64) {
    pallet_timestamp::Now::<Test>::put(seconds * 1_000);
}

/// A distinct, correctly sized stranger note.
pub fn note(byte: u8) -> Vec<u8> {
    vec![byte; STRANGER_NOTE_LEN as usize]
}

pub fn fr_bytes(x: &Fr) -> [u8; 32] {
    encode_fr(x)
}
