// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A minimal solochain runtime with the Anonymum pallet.
//!
//! Adapted from the Polkadot SDK minimal template (polkadot-stable2609-2):
//! the template pallet is replaced by `pallet_anonymum`. Fee constants are
//! the same placeholders as `anonymum-core` (1 coin = 1,000,000 units).

#![cfg_attr(not(feature = "std"), no_std)]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use alloc::vec::Vec;
use pallet_transaction_payment::{FeeDetails, RuntimeDispatchInfo};
use polkadot_sdk::{
	polkadot_sdk_frame::{
		self as frame,
		deps::sp_genesis_builder,
		runtime::{apis, prelude::*},
	},
	*,
};

/// Provides getters for genesis configuration presets.
pub mod genesis_config_presets {
	use super::*;
	use crate::{
		interface::{Balance, MinimumBalance},
		sp_keyring::Sr25519Keyring,
		AnonymumShieldedConfig, BalancesConfig, RuntimeGenesisConfig, SudoConfig,
	};

	use alloc::{vec, vec::Vec};
	use serde_json::Value;

	/// Returns a development genesis config preset.
	pub fn development_config_genesis() -> Value {
		// 1,000 coins each for the dev accounts.
		let endowment: Balance = 1_000 * 1_000_000;
		frame_support::build_struct_json_patch!(RuntimeGenesisConfig {
			balances: BalancesConfig {
				balances: Sr25519Keyring::iter()
					.map(|a| (a.to_account_id(), endowment))
					// The node reward pool must exist before it can receive fees.
					.chain(core::iter::once((pallet_anonymum::Pallet::<Runtime>::pool_account(), <MinimumBalance as Get<Balance>>::get().max(1))))
					.collect::<Vec<_>>(),
			},
			sudo: SudoConfig { key: Some(Sr25519Keyring::Alice.to_account_id()) },
			// DEV ONLY, NEVER FOR REAL VALUE. This key comes from a public seed
			// (`fixtures::dev_keys`), so anyone can forge proofs under it, and
			// the leaves are fixture notes whose secrets are in the repository.
			anonymum_shielded: AnonymumShieldedConfig {
				dev_verifying_key: include_bytes!("../dev_shielded_vk.bin").to_vec(),
				base_fee: SHIELDED_BASE_FEE,
				initial_leaves: include_bytes!("../dev_shielded_leaves.bin")
					.chunks_exact(32)
					.map(|leaf| <[u8; 32]>::try_from(leaf).expect("chunks are 32 bytes; qed"))
					.collect::<Vec<_>>(),
			},
		})
	}

	/// Get the set of the available genesis config presets.
	pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
		let patch = match id.as_ref() {
			sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
			_ => return None,
		};
		Some(
			serde_json::to_string(&patch)
				.expect("serialization to json is expected to work. qed.")
				.into_bytes(),
		)
	}

	/// List of supported presets.
	pub fn preset_names() -> Vec<PresetId> {
		vec![PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET)]
	}
}

/// The runtime version.
#[runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: alloc::borrow::Cow::Borrowed("anonymum-runtime"),
	impl_name: alloc::borrow::Cow::Borrowed("anonymum-runtime"),
	authoring_version: 1,
	// 1: contact notes grew from 427 to 587 bytes (spec v0.7 section 2a).
	// Notes stored before the change cannot be opened by the new format,
	// by design; the dev chain starts from a fresh genesis each run.
	// 2: signed messages v2 (genesis hash in invite proofs and key bindings,
	// account in key bindings); v1 signatures no longer verify.
	// 3: register_invite refuses weak (small-order) Ed25519 invite keys.
	// 4: contact notes grow to 667 bytes (format v4, Noise X, deniable sender
	// authentication); 587-byte notes are refused.
	// 5: contact requests live 24 h (D2), not 48 h.
	// 6: contact notes grow to 1,787 bytes (format v5: ML-KEM-768 ciphertext
	// plus Noise Xpsk0, hybrid post-quantum); 667-byte notes are refused.
	// 7: contact notes grow to 1,795 bytes (the embedded card carries a signed
	// sequence number, card format v4); 1,787-byte notes are refused.
	// 8: adds pallet-anonymum-shielded (unreviewed prototype, dev key only).
	// 9: shielded transactions are general transactions authorized through
	// `AuthorizeCall`; the bare (unsigned) form is no longer accepted.
	spec_version: 9,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	system_version: 1,
};

/// The transaction extensions that are added to the runtime.
type TxExtension = (
	// Authorize calls that validate themselves.
	frame_system::AuthorizeCall<Runtime>,
	// Checks that the sender is not the zero address.
	frame_system::CheckNonZeroSender<Runtime>,
	// Checks that the runtime version is correct.
	frame_system::CheckSpecVersion<Runtime>,
	// Checks that the transaction version is correct.
	frame_system::CheckTxVersion<Runtime>,
	// Checks that the genesis hash is correct.
	frame_system::CheckGenesis<Runtime>,
	// Checks that the era is valid.
	frame_system::CheckEra<Runtime>,
	// Checks that the nonce is valid.
	frame_system::CheckNonce<Runtime>,
	// Checks that the weight is valid.
	frame_system::CheckWeight<Runtime>,
	// Ensures that the sender has enough funds to pay for the transaction
	// and deducts the fee from the sender's account.
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	// Reclaim the unused weight from the block using post dispatch information.
	// It must be last in the pipeline in order to catch the refund in previous transaction
	// extensions
	frame_system::WeightReclaim<Runtime>,
);

// Composes the runtime by adding all the used pallets and deriving necessary types.
#[frame_construct_runtime]
mod runtime {
	/// The main runtime type.
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
	pub struct Runtime;

	/// Mandatory system pallet that should always be included in a FRAME runtime.
	#[runtime::pallet_index(0)]
	pub type System = frame_system::Pallet<Runtime>;

	/// Provides a way for consensus systems to set and check the onchain time.
	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp::Pallet<Runtime>;

	/// Provides the ability to keep track of balances.
	#[runtime::pallet_index(2)]
	pub type Balances = pallet_balances::Pallet<Runtime>;

	/// Provides a way to execute privileged functions.
	#[runtime::pallet_index(3)]
	pub type Sudo = pallet_sudo::Pallet<Runtime>;

	/// Provides the ability to charge for extrinsic execution.
	#[runtime::pallet_index(4)]
	pub type TransactionPayment = pallet_transaction_payment::Pallet<Runtime>;

	/// Invites, paid contact requests, channels, blocks and fees.
	#[runtime::pallet_index(5)]
	pub type Anonymum = pallet_anonymum::Pallet<Runtime>;

	/// UNREVIEWED PROTOTYPE: shielded transactions with a dev-only key.
	#[runtime::pallet_index(6)]
	pub type AnonymumShielded = pallet_anonymum_shielded::Pallet<Runtime>;
}

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
}

/// Implements the types required for the system pallet.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = Block;
	type Version = Version;
	// Use the account data from the balances pallet
	type AccountData = pallet_balances::AccountData<<Runtime as pallet_balances::Config>::Balance>;
}

// Implements the types required for the balances pallet.
#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
	// u128, like `anonymum-core` and the pallet's mock (audit F6).
	type Balance = u128;
	type AccountStore = System;
}

// Implements the types required for the sudo pallet.
#[derive_impl(pallet_sudo::config_preludes::TestDefaultConfig)]
impl pallet_sudo::Config for Runtime {}

// Implements the types required for the sudo pallet.
#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Runtime {}

// Implements the types required for the transaction payment pallet.
#[derive_impl(pallet_transaction_payment::config_preludes::TestDefaultConfig)]
impl pallet_transaction_payment::Config for Runtime {
	type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
	// A transaction's fee scales with its weight and its size (audit F3).
	// Both rates are placeholders, and the pallet's weights are not yet
	// benchmarked, so the weight part is only roughly right.
	type WeightToFee = RefTimeToFee;
	type LengthToFee = frame_support::weights::ConstantMultiplier<u128, ConstU128<FEE_PER_BYTE>>;
}

/// Fee per byte of an encoded transaction (placeholder): 10 units.
pub const FEE_PER_BYTE: u128 = 10;

/// Placeholder weight-to-fee rate: 1 unit per 100,000 units of reference
/// time. Measured on the dev node (2026-11-18), weight plus size fees came
/// to 6,921 units (about 0.007 coin) for a contact request and 3,431 units
/// for opening with an invite, against the 0.5 coin network fee.
pub struct RefTimeToFee;

impl frame_support::weights::WeightToFee for RefTimeToFee {
	type Balance = u128;

	fn weight_to_fee(weight: &Weight) -> u128 {
		u128::from(weight.ref_time() / 100_000)
	}
}

parameter_types! {
	pub const AnonymumPalletId: frame_support::PalletId = frame_support::PalletId(*b"anonymum");
}

/// One coin in smallest units (same as `anonymum-core`).
pub const COIN: u128 = 1_000_000;

impl pallet_anonymum::Config for Runtime {
	type Currency = Balances;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Signature = sp_runtime::MultiSignature;
	type PalletId = AnonymumPalletId;
	type InviteOpenFee = ConstU128<{ COIN / 100 }>;
	type ColdNetworkFee = ConstU128<{ COIN / 2 }>;
	type DefaultContactPrice = ConstU128<COIN>;
	type RequestTtlMillis = ConstU64<{ 24 * 60 * 60 * 1000 }>; // D2: 24 h
	// Run the dev node with `--dev-block-time 6000` to match.
	type ExpectedBlockTimeMillis = ConstU64<6_000>;
	type FeeBurnPercent = ConstU8<50>;
	type DeclineFeeBps = ConstU16<100>;
	type MaxRequestsPerBlock = ConstU32<256>;
	// Refundable storage deposits (audit F3). Placeholders: 0.01 coin each.
	type InviteDeposit = ConstU128<{ COIN / 100 }>;
	type BlockDeposit = ConstU128<{ COIN / 100 }>;
	type KeyDeposit = ConstU128<{ COIN / 100 }>;
}

/// The dev chain's shielded base fee `F`, in base units (matches the
/// circuit fixtures). Shielded value is not connected to `Balances`.
pub const SHIELDED_BASE_FEE: u64 = 1_000;

parameter_types! {
	pub const ShieldedBurnShare: sp_runtime::Percent = sp_runtime::Percent::from_percent(50);
	/// Placeholders, not benchmarks (see README). Together they keep the
	/// 300 ms per transaction set from the dev-node measurements.
	pub const ShieldedSubmitWeight: Weight = Weight::from_parts(60_000_000_000, 32 * 1024);
	pub const ShieldedAuthorizeWeight: Weight = Weight::from_parts(240_000_000_000, 32 * 1024);
}

impl pallet_anonymum_shielded::Config for Runtime {
	type TimeProvider = Timestamp;
	type ChainId = ConstU32<4242>;
	type TxVersion = ConstU32<1>;
	type WindowSecs = ConstU64<60>;
	type FeeBurnPercent = ShieldedBurnShare;
	type RootHistory = ConstU32<128>;
	type MaxPrunePerBlock = ConstU32<64>;
	type MaxPruneWindows = ConstU32<64>;
	type PoolLongevity = ConstU64<10>;
	type SubmitWeight = ShieldedSubmitWeight;
	type AuthorizeWeight = ShieldedAuthorizeWeight;
}

type Block = frame::runtime::types_common::BlockOf<Runtime, TxExtension>;
type Header = HeaderFor<Runtime>;

type RuntimeExecutive =
	Executive<Runtime, Block, frame_system::ChainContext<Runtime>, Runtime, AllPalletsWithSystem>;

impl_runtime_apis! {
	impl apis::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: <Block as frame::traits::Block>::LazyBlock) {
			RuntimeExecutive::execute_block(block)
		}

		fn initialize_block(header: &Header) -> ExtrinsicInclusionMode {
			RuntimeExecutive::initialize_block(header)
		}
	}
	impl apis::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl apis::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: ExtrinsicFor<Runtime>) -> ApplyExtrinsicResult {
			RuntimeExecutive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> HeaderFor<Runtime> {
			RuntimeExecutive::finalize_block()
		}

		fn inherent_extrinsics(data: InherentData) -> Vec<ExtrinsicFor<Runtime>> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: <Block as frame::traits::Block>::LazyBlock,
			data: InherentData,
		) -> CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl apis::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: ExtrinsicFor<Runtime>,
			block_hash: <Runtime as frame_system::Config>::Hash,
		) -> TransactionValidity {
			RuntimeExecutive::validate_transaction(source, tx, block_hash)
		}
	}

	impl apis::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &HeaderFor<Runtime>) {
			RuntimeExecutive::offchain_worker(header)
		}
	}

	impl apis::SessionKeys<Block> for Runtime {
		fn generate_session_keys(_owner: Vec<u8>, _seed: Option<Vec<u8>>) -> apis::OpaqueGeneratedSessionKeys {
			apis::OpaqueGeneratedSessionKeys { keys: Default::default(), proof: Default::default() }
		}

		fn decode_session_keys(
			_encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, apis::KeyTypeId)>> {
			Default::default()
		}
	}

	impl apis::AccountNonceApi<Block, interface::AccountId, interface::Nonce> for Runtime {
		fn account_nonce(account: interface::AccountId) -> interface::Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		interface::Balance,
	> for Runtime {
		fn query_info(uxt: ExtrinsicFor<Runtime>, len: u32) -> RuntimeDispatchInfo<interface::Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(uxt: ExtrinsicFor<Runtime>, len: u32) -> FeeDetails<interface::Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> interface::Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> interface::Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	// Only so `polkadot-omni-node --dev-block-time` can drive this runtime:
	// its dev mode reads the Aura slot duration for timestamps. There is no
	// Aura pallet and no Aura consensus here; blocks come from manual seal.
	impl sp_consensus_aura::AuraApi<Block, sp_consensus_aura::sr25519::AuthorityId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(6_000)
		}

		fn authorities() -> Vec<sp_consensus_aura::sr25519::AuthorityId> {
			Vec::new()
		}
	}

	impl apis::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> {
			get_preset::<RuntimeGenesisConfig>(id, self::genesis_config_presets::get_preset)
		}

		fn preset_names() -> Vec<PresetId> {
			self::genesis_config_presets::preset_names()
		}
	}
}

/// Some re-exports that the node side code needs to know. Some are useful in this context as well.
///
/// Other types should preferably be private.
// TODO: this should be standardized in some way, see:
// https://github.com/paritytech/substrate/issues/10579#issuecomment-1600537558
pub mod interface {
	use super::Runtime;
	use polkadot_sdk::{polkadot_sdk_frame as frame, *};

	pub type Block = super::Block;
	pub use frame::runtime::types_common::OpaqueBlock;
	pub type AccountId = <Runtime as frame_system::Config>::AccountId;
	pub type Nonce = <Runtime as frame_system::Config>::Nonce;
	pub type Hash = <Runtime as frame_system::Config>::Hash;
	pub type Balance = <Runtime as pallet_balances::Config>::Balance;
	pub type MinimumBalance = <Runtime as pallet_balances::Config>::ExistentialDeposit;
}
