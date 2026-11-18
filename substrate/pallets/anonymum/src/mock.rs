//! Test runtime: System, Balances and the Anonymum pallet, with accounts
//! derived from real Ed25519 keys.

use crate as pallet_anonymum;
use crate::{key_binding_message, SealedNote, SEALED_NOTE_LEN};
use frame::deps::frame_support::PalletId;
use frame::deps::sp_core::{ed25519, Pair};
use frame::deps::sp_io::hashing::blake2_256;
use frame::deps::sp_runtime::traits::{AccountIdConversion, IdentityLookup};
use frame::deps::sp_runtime::{AccountId32, BuildStorage, MultiSignature};
use frame::testing_prelude::*;
use polkadot_sdk::pallet_balances;
use polkadot_sdk::polkadot_sdk_frame as frame;

pub type Balance = u128;
pub const COIN: Balance = 1_000_000;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        Anonymum: pallet_anonymum,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId32;
    type Lookup = IdentityLookup<AccountId32>;
    type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type AccountStore = System;
}

parameter_types! {
    pub const AnonymumPalletId: PalletId = PalletId(*b"anonymum");
}

impl pallet_anonymum::Config for Test {
    type Currency = Balances;
    type RuntimeHoldReason = RuntimeHoldReason;
    type Signature = MultiSignature;
    type PalletId = AnonymumPalletId;
    type InviteOpenFee = ConstU128<{ COIN / 100 }>;
    type ColdNetworkFee = ConstU128<{ COIN / 2 }>;
    type DefaultContactPrice = ConstU128<COIN>;
    type RequestTtlMillis = ConstU64<{ 48 * 60 * 60 * 1000 }>;
    type ExpectedBlockTimeMillis = ConstU64<6_000>;
    type FeeBurnPercent = ConstU8<50>;
    type DeclineFeeBps = ConstU16<100>;
    type MaxRequestsPerBlock = ConstU32<4>;
    type InviteDeposit = ConstU128<DEPOSIT>;
    type BlockDeposit = ConstU128<DEPOSIT>;
    type KeyDeposit = ConstU128<DEPOSIT>;
}

/// Storage deposit per invite, block entry and messaging key (placeholder).
pub const DEPOSIT: Balance = COIN / 100;

pub fn keypair(name: &str) -> ed25519::Pair {
    ed25519::Pair::from_seed(&blake2_256(name.as_bytes()))
}

pub fn account(name: &str) -> AccountId32 {
    AccountId32::from(keypair(name).public().0)
}

pub fn pool() -> AccountId32 {
    AnonymumPalletId::get().into_account_truncating()
}

/// The messaging key `name` publishes, and its signature binding it.
pub fn messaging_key(name: &str) -> ([u8; 32], MultiSignature) {
    let key = blake2_256(format!("{name}/messaging").as_bytes());
    let binding = MultiSignature::Ed25519(keypair(name).sign(&key_binding_message(&key)));
    (key, binding)
}

/// A correctly sized note. The chain cannot read notes, only measure them.
pub fn note() -> SealedNote {
    vec![0xAB; SEALED_NOTE_LEN as usize].try_into().unwrap()
}

/// Alice, Bob and Carol with published messaging keys and 10 coins free
/// each (they get the key deposit on top, which stays held); Dave with 10
/// coins and no key; the reward pool holding the existential deposit; block 1.
pub fn new_test_ext() -> TestState {
    let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let mut balances: Vec<(AccountId32, Balance)> =
        ["alice", "bob", "carol"].iter().map(|n| (account(n), 10 * COIN + DEPOSIT)).collect();
    balances.push((account("dave"), 10 * COIN));
    balances.push((pool(), 1));
    pallet_balances::GenesisConfig::<Test> { balances, ..Default::default() }
        .assimilate_storage(&mut storage)
        .unwrap();
    let mut ext = TestState::new(storage);
    ext.execute_with(|| {
        System::set_block_number(1);
        for name in ["alice", "bob", "carol"] {
            let (key, binding) = messaging_key(name);
            Anonymum::publish_messaging_key(RuntimeOrigin::signed(account(name)), key, binding).unwrap();
        }
    });
    ext
}
