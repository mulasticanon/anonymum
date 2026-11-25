//! # Shielded transactions (Milestone 4B)
//!
//! **UNREVIEWED PROTOTYPE. NOT AUDITED. NOT FOR REAL VALUE.**
//!
//! Verifies Groth16 proofs from `crates/shielded-circuit` and enforces the
//! chain-side rules of `docs/shielded-spec-v0.md`. Limits to know:
//!
//! - The verifying key in genesis is a **dev key from a public seed**.
//!   Anyone can forge proofs under it and mint shielded value.
//! - Shielded value is not connected to `pallet-balances`. `BurnedFees` and
//!   `NodeRewardPool` are counters; nothing pays out.
//! - `submit_shielded` has no signer, so nobody pays a fee for a *bad* proof.
//!   A BLAKE2s proof of work (`PowDifficulty`) must be solved before a node
//!   runs the pairing. It raises the cost of spam and does not remove it:
//!   per-peer rate limiting is still a node and P2P concern.
//! - Weights come from benchmarks of the release WebAssembly runtime on one
//!   developer laptop (`weights.rs`), not from reference hardware.
//!
//! The call is a *general* transaction (extrinsic format 5) authorized by
//! `#[pallet::authorize]` through `frame_system::AuthorizeCall`. That runs
//! in the pool and again at inclusion, so the pairing lives there alone; the
//! dispatch repeats only the cheap state checks.
//!
//! Proof bytes are never a key, index or identifier: Groth16 proofs can be
//! re-randomised, and replay is stopped by the nullifiers alone.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

pub mod poseidon_constants;
pub mod primitives;
pub mod weights;
pub use weights::WeightInfo;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

/// Lets the benchmarks set the block time.
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper {
    fn set_time_ms(ms: u64);
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use polkadot_sdk::polkadot_sdk_frame as frame;

#[frame::pallet]
pub mod pallet {
    use super::*;
    use crate::primitives::*;
    use alloc::vec::Vec;
    use ark_bls12_381::Fr;
    use frame::deps::frame_support::traits::Time;
    use frame::deps::frame_support::pallet_prelude::TransactionValidityWithRefund;
    use frame::deps::sp_runtime::transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidityError, ValidTransaction,
    };
    use polkadot_sdk::frame_system::ensure_authorized;
    use frame::deps::sp_runtime::Percent;
    use frame::prelude::*;

    /// The pallet's whole transaction, as submitted.
    pub type StrangerNote = BoundedVec<u8, ConstU32<STRANGER_NOTE_LEN>>;

    #[pallet::config]
    pub trait Config: polkadot_sdk::frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Block time in milliseconds.
        type TimeProvider: Time<Moment = u64>;
        /// Bound into every sighash, so a proof cannot move between chains.
        #[pallet::constant]
        type ChainId: Get<u32>;
        #[pallet::constant]
        type TxVersion: Get<u32>;
        /// Width of the clock grid in seconds; must divide 24 hours.
        #[pallet::constant]
        type WindowSecs: Get<u64>;
        /// Share of the base fee that is burned; the rest is node reward.
        #[pallet::constant]
        type FeeBurnPercent: Get<Percent>;
        /// How many recent roots a transaction may prove against.
        #[pallet::constant]
        type RootHistory: Get<u32>;
        /// Most stranger notes removed in one block.
        #[pallet::constant]
        type MaxPrunePerBlock: Get<u32>;
        /// Most grid windows the prune cursor advances in one block.
        #[pallet::constant]
        type MaxPruneWindows: Get<u32>;
        /// How many blocks a valid transaction may wait in the pool.
        #[pallet::constant]
        type PoolLongevity: Get<u64>;
        /// Leading zero bits the proof-of-work hash needs; 0 disables it.
        #[pallet::constant]
        type PowDifficulty: Get<u32>;
        /// Benchmarked weights (`weights.rs`).
        type WeightInfo: WeightInfo;
        #[cfg(feature = "runtime-benchmarks")]
        type BenchmarkHelper: crate::BenchmarkHelper;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// **DEV ONLY.** The Groth16 verifying key, uncompressed, validated at
    /// genesis. Its setup seed is public: never use it for real value.
    #[pallet::storage]
    pub type DevVerifyingKey<T> = StorageValue<_, BoundedVec<u8, ConstU32<MAX_VK_LEN>>, OptionQuery>;

    /// The public base fee `F`, the same on every transaction.
    #[pallet::storage]
    pub type BaseFee<T> = StorageValue<_, u64, ValueQuery>;

    /// Roots a transaction may currently prove against.
    #[pallet::storage]
    pub type AcceptedRoots<T> = StorageMap<_, Blake2_128Concat, Bytes32, (), OptionQuery>;

    /// Ring buffer behind `AcceptedRoots`, so old roots can be dropped.
    #[pallet::storage]
    pub type RootRing<T> = StorageMap<_, Twox64Concat, u32, Bytes32, OptionQuery>;

    #[pallet::storage]
    pub type RootCursor<T> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type CurrentRoot<T> = StorageValue<_, Bytes32, ValueQuery>;

    /// Spent nullifiers, kept forever.
    #[pallet::storage]
    pub type Nullifiers<T> = StorageMap<_, Blake2_128Concat, Bytes32, (), OptionQuery>;

    /// The Merkle tree's left-hand nodes, one per level.
    #[pallet::storage]
    pub type Frontier<T> = StorageValue<_, [Bytes32; TREE_DEPTH], ValueQuery>;

    /// Roots of empty subtrees per height, computed at genesis.
    #[pallet::storage]
    pub type EmptySubtrees<T> = StorageValue<_, [Bytes32; TREE_DEPTH + 1], ValueQuery>;

    /// Number of leaves in the tree.
    #[pallet::storage]
    pub type NextIndex<T> = StorageValue<_, u64, ValueQuery>;

    /// Stranger notes by `(window_start, sighash)`, kept 24 hours from the
    /// window start. Their hash stays in the `Shielded` event.
    #[pallet::storage]
    pub type StrangerNotes<T> =
        StorageDoubleMap<_, Twox64Concat, u64, Blake2_128Concat, Bytes32, StrangerNote, OptionQuery>;

    /// The oldest window that may still hold notes.
    #[pallet::storage]
    pub type PruneCursor<T> = StorageValue<_, u64, OptionQuery>;

    #[pallet::storage]
    pub type BurnedFees<T> = StorageValue<_, u128, ValueQuery>;

    /// A counter: nothing pays this out yet.
    #[pallet::storage]
    pub type NodeRewardPool<T> = StorageValue<_, u128, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// **DEV ONLY.** Compressed Groth16 verifying key.
        pub dev_verifying_key: Vec<u8>,
        pub base_fee: u64,
        /// Leaves the tree starts with.
        pub initial_leaves: Vec<Bytes32>,
        #[serde(skip)]
        pub _marker: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            if !self.dev_verifying_key.is_empty() {
                let stored = prepare_stored_key(&self.dev_verifying_key).expect("invalid verifying key in genesis");
                let bounded: BoundedVec<u8, ConstU32<MAX_VK_LEN>> =
                    stored.try_into().expect("prepare_stored_key checks the length; qed");
                DevVerifyingKey::<T>::put(bounded);
            }
            BaseFee::<T>::put(self.base_fee);

            let poseidon = Poseidon::new();
            let zero = poseidon.empty_subtrees();
            let mut frontier = [zero[0]; TREE_DEPTH];
            let mut root = zero[TREE_DEPTH];
            for (index, bytes) in self.initial_leaves.iter().enumerate() {
                let leaf = decode_fr(bytes).expect("non-canonical leaf in genesis");
                root = poseidon.append(&mut frontier, &zero, index as u64, leaf);
            }
            EmptySubtrees::<T>::put(zero.map(|x| encode_fr(&x)));
            Frontier::<T>::put(frontier.map(|x| encode_fr(&x)));
            NextIndex::<T>::put(self.initial_leaves.len() as u64);
            Pallet::<T>::accept_root(encode_fr(&root));
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A shielded transaction was accepted. The stranger note's hash and
        /// the sighash stay here after the note itself is pruned.
        Shielded {
            sighash: Bytes32,
            stranger_note_hash: Bytes32,
            window_start: u64,
            nullifiers: [Bytes32; 2],
            commitments: [Bytes32; 3],
            /// Tree position of the first output.
            first_position: u64,
            new_root: Bytes32,
        },
        /// Stranger notes of an expired window were removed.
        StrangerNotesPruned { window_start: u64, removed: u32 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The stranger-note slot is not exactly 1,795 bytes.
        WrongNoteLength,
        /// A field is not a canonical scalar.
        NonCanonicalField,
        /// The window is not one cell of the clock grid.
        WindowNotOnGrid,
        /// The block time is outside `[not_before, not_after)`.
        OutsideWindow,
        UnknownRoot,
        DuplicateNullifier,
        NullifierUsed,
        /// The Merkle tree has no room for three more leaves.
        TreeFull,
        /// A fee counter would overflow.
        FeeOverflow,
        /// No verifying key is configured.
        NoVerifyingKey,
        /// The proof bytes are not valid canonical subgroup points.
        MalformedProof,
        /// The proof does not verify.
        InvalidProof,
        /// The proof-of-work hash has too few leading zero bits.
        InsufficientPow,
    }

    impl<T> Error<T> {
        /// The code a refused transaction reports to the pool.
        fn code(&self) -> u8 {
            match self {
                Error::WrongNoteLength => 1,
                Error::NonCanonicalField => 2,
                Error::WindowNotOnGrid => 3,
                Error::OutsideWindow => 4,
                Error::UnknownRoot => 5,
                Error::DuplicateNullifier => 6,
                Error::NullifierUsed => 7,
                Error::TreeFull => 8,
                Error::FeeOverflow => 9,
                Error::NoVerifyingKey => 10,
                Error::MalformedProof => 11,
                Error::InvalidProof => 12,
                Error::InsufficientPow => 13,
                _ => 0,
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // Reserve what `on_finalize` may use.
            if PruneCursor::<T>::exists() {
                T::WeightInfo::prune_stranger_notes(T::MaxPrunePerBlock::get(), T::MaxPruneWindows::get())
            } else {
                T::DbWeight::get().reads(1)
            }
        }

        // Not `on_initialize`: the timestamp inherent has not run by then.
        fn on_finalize(_n: BlockNumberFor<T>) {
            Self::prune_stranger_notes(Self::now_secs());
        }

        fn integrity_test() {
            let window = T::WindowSecs::get();
            assert!(window > 0 && NOTE_TTL_SECS % window == 0, "the window must divide 24 hours");
            assert!(T::RootHistory::get() > 0, "at least one root must be accepted");
            assert!(T::MaxPruneWindows::get() > 0 && T::MaxPrunePerBlock::get() > 0, "pruning must progress");
            assert!(T::PowDifficulty::get() <= MAX_POW_DIFFICULTY, "the nonce is a u64");
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit one shielded transaction. No account appears: the call
        /// authorizes itself with its proof.
        #[pallet::call_index(0)]
        #[pallet::weight((T::WeightInfo::submit_shielded(), DispatchClass::Normal, Pays::No))]
        #[pallet::authorize(Self::authorize_submit)]
        #[pallet::weight_of_authorize(T::WeightInfo::authorize_submit_shielded())]
        #[allow(clippy::too_many_arguments)]
        pub fn submit_shielded(
            origin: OriginFor<T>,
            root: Bytes32,
            nullifiers: [Bytes32; 2],
            commitments: [Bytes32; 3],
            admission_commitment: Bytes32,
            not_before: u64,
            not_after: u64,
            coin_payloads: [[u8; COIN_PAYLOAD_LEN]; 2],
            stranger_note: StrangerNote,
            proof: [u8; PROOF_LEN],
            pow_nonce: u64,
        ) -> DispatchResult {
            ensure_authorized(origin)?;
            // Checked in authorization, which is what grants this origin.
            let _ = pow_nonce;
            let tx = TxRef {
                root: &root,
                nullifiers: &nullifiers,
                commitments: &commitments,
                admission: &admission_commitment,
                not_before,
                not_after,
                coin_payloads: &coin_payloads,
                stranger_note: &stranger_note,
                proof: &proof,
            };
            // The authorized origin means this transaction's proof verified at
            // inclusion. Repeat the cheap checks, never the pairing, and do all
            // of it before the first write.
            let checked = Self::check_cheap(&tx, TimeRule::InBlock(Self::now_secs()))?;
            let digests = Self::digests(&tx, &checked);
            Self::apply(&tx, checked, digests, stranger_note.clone());
            Ok(())
        }
    }

    /// Borrowed view of the call's arguments.
    pub(crate) struct TxRef<'a> {
        root: &'a Bytes32,
        nullifiers: &'a [Bytes32; 2],
        commitments: &'a [Bytes32; 3],
        admission: &'a Bytes32,
        not_before: u64,
        not_after: u64,
        coin_payloads: &'a [[u8; COIN_PAYLOAD_LEN]; 2],
        stranger_note: &'a StrangerNote,
        proof: &'a [u8; PROOF_LEN],
    }

    /// Which clock rule applies.
    #[derive(Clone, Copy)]
    pub(crate) enum TimeRule {
        /// In a block: the block time must lie in the window.
        InBlock(u64),
        /// In the pool, the time is the last block's: also allow the next
        /// window, which the next block may already be in.
        InPool(u64),
    }

    /// What the cheap checks computed.
    pub(crate) struct Checked {
        /// The public inputs before the sighash, in circuit order.
        fields: [Fr; N_PUBLIC - 1],
        burned: u128,
        reward: u128,
        first_position: u64,
    }

    /// The transaction's digests, computed outside the circuit.
    pub(crate) struct Digests {
        inputs: [Fr; N_PUBLIC],
        sighash: Bytes32,
        note_hash: Bytes32,
    }

    impl<T: Config> Pallet<T> {
        fn now_secs() -> u64 {
            T::TimeProvider::now() / 1_000
        }

        /// Authorization, in strict order: (1) note length, (2) clock grid
        /// and block time, (3) root, (4) nullifiers, each in `check_cheap`;
        /// (5) strict proof decoding; (6) the sighash and proof of work;
        /// (7) only then the pairing.
        /// Tags are the nullifiers, never the proof, so a re-randomised copy
        /// conflicts with the original in the pool.
        #[allow(clippy::too_many_arguments)]
        fn authorize_submit(
            source: TransactionSource,
            root: &Bytes32,
            nullifiers: &[Bytes32; 2],
            commitments: &[Bytes32; 3],
            admission_commitment: &Bytes32,
            not_before: &u64,
            not_after: &u64,
            coin_payloads: &[[u8; COIN_PAYLOAD_LEN]; 2],
            stranger_note: &StrangerNote,
            proof: &[u8; PROOF_LEN],
            pow_nonce: &u64,
        ) -> TransactionValidityWithRefund {
            let tx = TxRef {
                root,
                nullifiers,
                commitments,
                admission: admission_commitment,
                not_before: *not_before,
                not_after: *not_after,
                coin_payloads,
                stranger_note,
                proof,
            };
            let now = Self::now_secs();
            let in_block = source == TransactionSource::InBlock;
            let rule = if in_block { TimeRule::InBlock(now) } else { TimeRule::InPool(now) };
            let refuse = |error: Error<T>| -> TransactionValidityError {
                // The pool also holds transactions for the next window. `Future`
                // leaves one there for a later block instead of dropping it.
                if in_block && now < *not_before && matches!(error, Error::OutsideWindow) {
                    InvalidTransaction::Future.into()
                } else {
                    InvalidTransaction::Custom(error.code()).into()
                }
            };

            let checked = Self::check_cheap(&tx, rule).map_err(refuse)?;
            let decoded = decode_proof(tx.proof).ok_or(Error::<T>::MalformedProof).map_err(refuse)?;
            let digests = Self::digests(&tx, &checked);
            let work = pow_hash(&digests.sighash, tx.root, tx.nullifiers, tx.proof, *pow_nonce);
            if leading_zero_bits(&work) < T::PowDifficulty::get() {
                return Err(refuse(Error::<T>::InsufficientPow));
            }
            let key = DevVerifyingKey::<T>::get().ok_or(Error::<T>::NoVerifyingKey).map_err(refuse)?;
            if !verify(&key, &decoded, &digests.inputs) {
                return Err(refuse(Error::<T>::InvalidProof));
            }

            let validity = ValidTransaction::with_tag_prefix("AnonymumShielded")
                .priority(1)
                // Two transactions spending one note can never both be pooled.
                .and_provides(tx.nullifiers[0])
                .and_provides(tx.nullifiers[1])
                .longevity(T::PoolLongevity::get())
                .propagate(true)
                .build()?;
            Ok((validity, Weight::zero()))
        }

        /// Steps 1 to 4 and the other checks that need no curve arithmetic.
        /// Reads only.
        pub(crate) fn check_cheap(tx: &TxRef, time: TimeRule) -> Result<Checked, Error<T>> {
            ensure!(tx.stranger_note.len() == STRANGER_NOTE_LEN as usize, Error::<T>::WrongNoteLength);

            let window = T::WindowSecs::get();
            ensure!(
                window > 0
                    && tx.not_before % window == 0
                    && tx.not_before.checked_add(window) == Some(tx.not_after),
                Error::<T>::WindowNotOnGrid
            );
            let in_window = match time {
                TimeRule::InBlock(now) => tx.not_before <= now && now < tx.not_after,
                TimeRule::InPool(now) => tx.not_before <= now.saturating_add(window) && now < tx.not_after,
            };
            ensure!(in_window, Error::<T>::OutsideWindow);

            ensure!(AcceptedRoots::<T>::contains_key(tx.root), Error::<T>::UnknownRoot);
            ensure!(tx.nullifiers[0] != tx.nullifiers[1], Error::<T>::DuplicateNullifier);
            for nullifier in tx.nullifiers {
                ensure!(!Nullifiers::<T>::contains_key(nullifier), Error::<T>::NullifierUsed);
            }

            let first_position = NextIndex::<T>::get();
            ensure!(first_position.saturating_add(3) <= 1u64 << TREE_DEPTH, Error::<T>::TreeFull);

            let fee = BaseFee::<T>::get();
            let burned = T::FeeBurnPercent::get().mul_floor(fee);
            let to_pool = fee.checked_sub(burned).ok_or(Error::<T>::FeeOverflow)?;
            let burned = BurnedFees::<T>::get().checked_add(u128::from(burned)).ok_or(Error::<T>::FeeOverflow)?;
            let reward =
                NodeRewardPool::<T>::get().checked_add(u128::from(to_pool)).ok_or(Error::<T>::FeeOverflow)?;

            let field = |bytes: &Bytes32| decode_fr(bytes).ok_or(Error::<T>::NonCanonicalField);
            let fields: [Fr; N_PUBLIC - 1] = [
                field(tx.root)?,
                field(&tx.nullifiers[0])?,
                field(&tx.nullifiers[1])?,
                field(&tx.commitments[0])?,
                field(&tx.commitments[1])?,
                field(&tx.commitments[2])?,
                field(tx.admission)?,
                Fr::from(fee),
                Fr::from(tx.not_before),
                Fr::from(tx.not_after),
            ];
            Ok(Checked { fields, burned, reward, first_position })
        }

        /// The stranger-note hash and the sighash, computed outside the circuit.
        pub(crate) fn digests(tx: &TxRef, checked: &Checked) -> Digests {
            let note_hash = stranger_note_hash(tx.stranger_note);
            let sighash = compute_sighash(&SighashInputs {
                chain_id: T::ChainId::get(),
                version: T::TxVersion::get(),
                fields: &checked.fields,
                coin_slots: tx.coin_payloads,
                stranger_note_hash: &note_hash,
            });
            let mut inputs = [sighash; N_PUBLIC];
            inputs[..N_PUBLIC - 1].copy_from_slice(&checked.fields);
            Digests { inputs, sighash: encode_fr(&sighash), note_hash }
        }

        /// All values are computed first, so no write can be left half done.
        fn apply(tx: &TxRef, checked: Checked, digests: Digests, note: StrangerNote) {
            let poseidon = Poseidon::new();
            let window_start = tx.not_before;
            let zero = EmptySubtrees::<T>::get().map(|b| decode_fr(&b).expect("stored canonically; qed"));
            let mut frontier = Frontier::<T>::get().map(|b| decode_fr(&b).expect("stored canonically; qed"));
            let mut root = checked.fields[0];
            for (offset, commitment) in checked.fields[3..6].iter().enumerate() {
                let leaf = poseidon.leaf(*commitment, window_start);
                root = poseidon.append(&mut frontier, &zero, checked.first_position + offset as u64, leaf);
            }
            let new_root = encode_fr(&root);

            for nullifier in tx.nullifiers {
                Nullifiers::<T>::insert(nullifier, ());
            }
            Frontier::<T>::put(frontier.map(|x| encode_fr(&x)));
            NextIndex::<T>::put(checked.first_position + 3);
            Self::accept_root(new_root);
            StrangerNotes::<T>::insert(window_start, digests.sighash, note);
            if !PruneCursor::<T>::exists() {
                PruneCursor::<T>::put(window_start);
            }
            BurnedFees::<T>::put(checked.burned);
            NodeRewardPool::<T>::put(checked.reward);

            Self::deposit_event(Event::Shielded {
                sighash: digests.sighash,
                stranger_note_hash: digests.note_hash,
                window_start,
                nullifiers: *tx.nullifiers,
                commitments: *tx.commitments,
                first_position: checked.first_position,
                new_root,
            });
        }

        /// Make `root` current and drop the oldest accepted root if full.
        pub(crate) fn accept_root(root: Bytes32) {
            let capacity = T::RootHistory::get().max(1);
            let slot = RootCursor::<T>::get() % capacity;
            if let Some(oldest) = RootRing::<T>::get(slot) {
                AcceptedRoots::<T>::remove(oldest);
            }
            RootRing::<T>::insert(slot, root);
            AcceptedRoots::<T>::insert(root, ());
            RootCursor::<T>::put((slot + 1) % capacity);
            CurrentRoot::<T>::put(root);
        }

        /// Remove notes whose window started 24 hours or more before `now`,
        /// within the per-block limits. Touches nothing else.
        pub(crate) fn prune_stranger_notes(now: u64) {
            let Some(mut window) = PruneCursor::<T>::get() else { return };
            let step = T::WindowSecs::get();
            let mut budget = T::MaxPrunePerBlock::get();
            let mut windows = T::MaxPruneWindows::get();
            let start = window;
            while budget > 0 && windows > 0 && window.saturating_add(NOTE_TTL_SECS) <= now {
                // Not `clear_prefix`: its limit ignores keys written earlier in
                // the same block, so it would neither bound nor count them.
                let keys: Vec<Bytes32> =
                    StrangerNotes::<T>::iter_key_prefix(window).take(budget as usize).collect();
                for key in &keys {
                    StrangerNotes::<T>::remove(window, key);
                }
                let removed = keys.len() as u32;
                budget = budget.saturating_sub(removed);
                if removed > 0 {
                    Self::deposit_event(Event::StrangerNotesPruned { window_start: window, removed });
                }
                if StrangerNotes::<T>::iter_key_prefix(window).next().is_some() {
                    break; // this window still has notes: continue next block
                }
                window = window.saturating_add(step);
                windows -= 1;
            }
            if window != start {
                PruneCursor::<T>::put(window);
            }
        }
    }
}
