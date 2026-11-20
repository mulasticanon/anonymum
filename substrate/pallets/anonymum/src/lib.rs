//! # Anonymum pallet
//!
//! A port of `anonymum-core`'s `chain.rs` to FRAME: invites, paid contact
//! requests carrying a sealed note, escrow, channels, blocks, invite-only
//! wallets, messaging keys, fees and 48-hour expiry. The rules and their
//! failure paths match the core crate one for one; the tests in `tests.rs`
//! are ported from `crates/core/tests/protocol.rs`.
//!
//! Differences from the in-process simulation, stated plainly:
//! * Escrow and storage deposits are balance holds (`HoldReason`), the
//!   reward pool is the pallet's account, and burns reduce total issuance.
//! * Invite proofs: the crates verify with `ed25519-dalek`'s
//!   `verify_strict`; this pallet uses the host function
//!   `sp_io::crypto::ed25519_verify`. In the SDK version this workspace
//!   builds against (sp-io 49, sp-core 43) its native implementation uses
//!   `ed25519-zebra` (ZIP 215 rules: small-order keys and points allowed,
//!   cofactored check), or `ed25519-dalek`'s non-strict `verify` when the
//!   node registers `UseDalekExt`; on a live chain the node binary's own
//!   copy decides. Either way it accepts signatures `verify_strict`
//!   rejects; a small-order invite key would let anyone open the invite
//!   with a trivially made proof. `register_invite` therefore refuses keys
//!   `ed25519-dalek` cannot decode or calls weak (audit F6; 2026-11-20 audit
//!   HIGH-04). The proof check itself still differs from `verify_strict`.
//! * Signed messages (v2) carry the chain's genesis hash, and the key
//!   binding also the signing account, so a signature made for another
//!   chain or another account is refused.
//! * Balances are `u128` in the simulation, this pallet's mock and the dev
//!   runtime. (The runtime used `u64` until audit F6.)
//! * Accounts must keep the existential deposit: payments use
//!   `Preservation::Preserve`.
//! * Expiry uses a queue per block instead of scanning every request, so at
//!   most `MaxRequestsPerBlock` requests can expire in one block; a request
//!   that would overflow it fails with `ExpiryQueueFull` (charging nothing).
//! * A failed extrinsic changes no pallet state and takes no pallet fee, but
//!   the chain's own transaction (inclusion) fee is still charged, as on any
//!   Substrate chain.
//! * Weights are placeholders, not benchmarks.
//! * If returning or burning a held amount ever fails (it should not), the
//!   call carries on, logs an error and emits `HoldNotReleased` (audit F5).
//!
//! Storage is deliberately thin: roadmap step 5 (shielded channel opening)
//! replaces the channel, request and block tables.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use polkadot_sdk::polkadot_sdk_frame as frame;

/// The exact bytes an invite proof signs (same as `anonymum-core`): the
/// chain's genesis hash, the opener and the recipient.
pub fn invite_message(genesis: &[u8], opener: &[u8], recipient: &[u8]) -> Vec<u8> {
    let mut message = b"anonymum/invite/v2".to_vec();
    message.extend_from_slice(genesis);
    message.extend_from_slice(opener);
    message.extend_from_slice(recipient);
    message
}

/// The exact bytes an account signs to bind its messaging key (same as
/// `anonymum-core`): the chain's genesis hash, the account and the key.
pub fn key_binding_message(genesis: &[u8], account: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut message = b"anonymum/msgkey-binding/v2".to_vec();
    message.extend_from_slice(genesis);
    message.extend_from_slice(account);
    message.extend_from_slice(key);
    message
}

/// Every sealed contact note is exactly this long (see `anonymum-core`).
pub const SEALED_NOTE_LEN: u32 = 587;

/// Basis points per whole (100%).
pub const BPS_DENOMINATOR: u16 = 10_000;

const LOG_TARGET: &str = "runtime::anonymum";

#[frame::pallet]
pub mod pallet {
    use super::*;
    use frame::deps::frame_support::PalletId;
    use frame::deps::sp_core::ed25519;
    use frame::deps::sp_io;
    use frame::deps::sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
    use frame::deps::sp_runtime::{ArithmeticError, Percent, SaturatedConversion};
    use frame::prelude::*;
    use frame::traits::fungible::{Inspect, Mutate, MutateHold};
    use frame::traits::tokens::{Fortitude, Precision, Preservation, Restriction};

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;
    pub type MessagingKey = [u8; 32];
    pub type InviteKey = [u8; 32];
    pub type SealedNote = BoundedVec<u8, ConstU32<SEALED_NOTE_LEN>>;
    pub type ChannelId = u64;
    pub type RequestId = u64;

    #[pallet::config]
    pub trait Config: polkadot_sdk::frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type Currency: Inspect<Self::AccountId>
            + Mutate<Self::AccountId>
            + MutateHold<Self::AccountId, Reason = Self::RuntimeHoldReason>;
        type RuntimeHoldReason: From<HoldReason>;
        /// Signature that proves a messaging key belongs to an account.
        type Signature: Verify<Signer: IdentifyAccount<AccountId = Self::AccountId>>
            + Parameter
            + MaxEncodedLen;
        /// Owner of the node reward pool account.
        #[pallet::constant]
        type PalletId: Get<PalletId>;
        /// Fee to open a channel with a valid invite. Small.
        #[pallet::constant]
        type InviteOpenFee: Get<BalanceOf<Self>>;
        /// Non-refundable fee to request contact with a stranger. Larger.
        #[pallet::constant]
        type ColdNetworkFee: Get<BalanceOf<Self>>;
        /// Price a stranger pays, unless the recipient set their own.
        #[pallet::constant]
        type DefaultContactPrice: Get<BalanceOf<Self>>;
        /// Lifetime of an unanswered request, in milliseconds (48 h).
        #[pallet::constant]
        type RequestTtlMillis: Get<u64>;
        /// Target block time, in milliseconds, to turn the TTL into blocks.
        #[pallet::constant]
        type ExpectedBlockTimeMillis: Get<u64>;
        /// Share of each network fee that is burned; the rest pays nodes.
        #[pallet::constant]
        type FeeBurnPercent: Get<u8>;
        /// Share of the price burned when a request ends without a channel.
        #[pallet::constant]
        type DeclineFeeBps: Get<u16>;
        /// Most requests that may expire in one block.
        #[pallet::constant]
        type MaxRequestsPerBlock: Get<u32>;
        /// Refundable deposit held for each registered invite (audit F3).
        #[pallet::constant]
        type InviteDeposit: Get<BalanceOf<Self>>;
        /// Refundable deposit held for each block entry, including the one
        /// `close_channel` creates.
        #[pallet::constant]
        type BlockDeposit: Get<BalanceOf<Self>>;
        /// Refundable deposit held for a published messaging key.
        #[pallet::constant]
        type KeyDeposit: Get<BalanceOf<Self>>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::composite_enum]
    pub enum HoldReason {
        /// A stranger's payment, held until the recipient answers.
        ContactEscrow,
        /// Deposit for a registered invite.
        InviteDeposit,
        /// Deposit for a block entry.
        BlockDeposit,
        /// Deposit for a published messaging key.
        KeyDeposit,
    }

    #[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Copy, PartialEq, Eq, Debug)]
    pub enum OpenedVia {
        Invite,
        PaidRequest,
    }

    #[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Copy, PartialEq, Eq, Debug)]
    pub enum RefundReason<AccountId> {
        CancelledBy(AccountId),
        Expired,
        Superseded,
        Blocked,
    }

    #[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Copy, PartialEq, Eq, Debug)]
    pub enum UnblockReason {
        Lifted,
        ChannelOpened,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
    pub struct Invite<BlockNumber, Balance> {
        pub expires_at: Option<BlockNumber>,
        /// Only an invite issued after a block can lift it.
        pub seq: u64,
        /// Held from the owner; returned when used, revoked or removed.
        pub deposit: Balance,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
    pub struct BlockEntry<Balance> {
        /// When the block was made (see `Invite::seq`).
        pub seq: u64,
        /// Held from the blocker; returned when the block is lifted or cleared.
        pub deposit: Balance,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
    pub struct Channel<AccountId, BlockNumber> {
        pub a: AccountId,
        pub b: AccountId,
        pub opened_at: BlockNumber,
        pub via: OpenedVia,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
    pub struct ContactRequest<AccountId, Balance, BlockNumber> {
        pub from: AccountId,
        pub to: AccountId,
        pub price: Balance,
        pub expires_at: BlockNumber,
        pub note: SealedNote,
    }

    #[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
    pub struct PublishedKey<Signature, Balance> {
        pub key: MessagingKey,
        pub binding: Signature,
        /// Held from the owner; carried over when the key is replaced.
        pub deposit: Balance,
    }

    type RequestOf<T> = ContactRequest<
        <T as frame_system::Config>::AccountId,
        BalanceOf<T>,
        BlockNumberFor<T>,
    >;

    #[pallet::storage]
    pub type Prices<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, BalanceOf<T>>;

    #[pallet::storage]
    pub type InviteOnly<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ()>;

    #[pallet::storage]
    pub type MessagingKeys<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, PublishedKey<T::Signature, BalanceOf<T>>>;

    #[pallet::storage]
    /// (owner, invite key) -> invite. Keyed by owner too, so nobody can
    /// squat an owner's key by registering it first (audit F2).
    pub type Invites<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        InviteKey,
        Invite<BlockNumberFor<T>, BalanceOf<T>>,
    >;

    #[pallet::storage]
    pub type Channels<T: Config> =
        StorageMap<_, Twox64Concat, ChannelId, Channel<T::AccountId, BlockNumberFor<T>>>;

    /// Ordered pair -> channel.
    #[pallet::storage]
    pub type ChannelByPair<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, T::AccountId), ChannelId>;

    #[pallet::storage]
    pub type Requests<T: Config> = StorageMap<_, Twox64Concat, RequestId, RequestOf<T>>;

    /// Ordered pair -> pending request (at most one per pair).
    #[pallet::storage]
    pub type RequestByPair<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, T::AccountId), RequestId>;

    /// Block number -> requests that expire then. Entries for requests that
    /// were already answered are skipped.
    #[pallet::storage]
    pub type ExpiryQueue<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BlockNumberFor<T>,
        BoundedVec<RequestId, T::MaxRequestsPerBlock>,
        ValueQuery,
    >;

    /// (blocker, blocked) -> sequence number when the block was made.
    #[pallet::storage]
    pub type Blocks<T: Config> =
        StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, T::AccountId, BlockEntry<BalanceOf<T>>>;

    #[pallet::storage]
    pub type NextId<T> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    pub type NextSeq<T> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ContactPriceSet { who: T::AccountId, price: BalanceOf<T> },
        AcceptStrangersSet { who: T::AccountId, accept: bool },
        MessagingKeyPublished { who: T::AccountId, key: MessagingKey },
        InviteRegistered { owner: T::AccountId, key: InviteKey },
        InviteRevoked { owner: T::AccountId, key: InviteKey },
        ExpiredInviteRemoved { owner: T::AccountId, key: InviteKey, by: T::AccountId },
        /// A held amount could not be returned or burned as expected. The
        /// call went on; the hold is still on `who`'s account (audit F5).
        HoldNotReleased { who: T::AccountId, amount: BalanceOf<T> },
        ContactRequested {
            request: RequestId,
            from: T::AccountId,
            to: T::AccountId,
            price: BalanceOf<T>,
            note: SealedNote,
        },
        /// `amount` went back to the requester; `burned` was the decline fee.
        RequestRefunded {
            request: RequestId,
            to: T::AccountId,
            amount: BalanceOf<T>,
            burned: BalanceOf<T>,
            reason: RefundReason<T::AccountId>,
        },
        ChannelOpened { channel: ChannelId, a: T::AccountId, b: T::AccountId, via: OpenedVia },
        ChannelClosed { channel: ChannelId, by: T::AccountId },
        Blocked { by: T::AccountId, target: T::AccountId },
        Unblocked { by: T::AccountId, target: T::AccountId, reason: UnblockReason },
    }

    #[pallet::error]
    pub enum Error<T> {
        InsufficientFunds,
        SelfContact,
        ChannelExists,
        InviteAlreadyRegistered,
        UnknownInvite,
        InviteExpired,
        BadInviteProof,
        PriceAboveMax,
        RequestPending,
        UnknownRequest,
        NotRequestParty,
        NotRecipient,
        UnknownChannel,
        NotParticipant,
        /// The recipient has blocked the sender.
        Blocked,
        /// The recipient is invite-only.
        StrangersNotAccepted,
        /// The recipient has not published a messaging key.
        NoMessagingKey,
        BadNoteSize,
        BadKeyBinding,
        AlreadyBlocked,
        NotBlocked,
        /// Too many requests already expire in the target block.
        ExpiryQueueFull,
        /// The invite has no expiry, or it has not passed yet.
        InviteNotExpired,
        /// The invite key is not a valid Ed25519 key, or is a weak
        /// (small-order) one that the host signature check would accept
        /// trivially signed proofs for.
        WeakInviteKey,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// Refund requests whose 48 hours are up.
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let due = ExpiryQueue::<T>::take(now);
            let count = due.len() as u64;
            for id in due {
                if Requests::<T>::contains_key(id) {
                    Self::refund(id, RefundReason::Expired);
                }
            }
            T::DbWeight::get().reads_writes(1 + 2 * count, 1 + 4 * count)
        }
    }

    /// Placeholder weight until the pallet is benchmarked.
    fn placeholder<T: Config>(reads: u64, writes: u64) -> Weight {
        Weight::from_parts(20_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(reads, writes))
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Set what strangers must pay to reach the sender.
        #[pallet::call_index(0)]
        #[pallet::weight(placeholder::<T>(0, 1))]
        pub fn set_contact_price(origin: OriginFor<T>, price: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Prices::<T>::insert(&who, price);
            Self::deposit_event(Event::ContactPriceSet { who, price });
            Ok(())
        }

        /// Accept paid requests from strangers (default) or be invite-only.
        #[pallet::call_index(1)]
        #[pallet::weight(placeholder::<T>(0, 1))]
        pub fn set_accept_strangers(origin: OriginFor<T>, accept: bool) -> DispatchResult {
            let who = ensure_signed(origin)?;
            if accept {
                InviteOnly::<T>::remove(&who);
            } else {
                InviteOnly::<T>::insert(&who, ());
            }
            Self::deposit_event(Event::AcceptStrangersSet { who, accept });
            Ok(())
        }

        /// Publish or replace the sender's messaging key, with the sender's
        /// signature over it.
        #[pallet::call_index(2)]
        #[pallet::weight(placeholder::<T>(0, 1))]
        pub fn publish_messaging_key(
            origin: OriginFor<T>,
            key: MessagingKey,
            binding: T::Signature,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let message = key_binding_message(Self::genesis_hash().as_ref(), &who.encode(), &key);
            ensure!(binding.verify(&message[..], &who), Error::<T>::BadKeyBinding);
            // One deposit per key: return the old one, hold the current one.
            if let Some(old) = MessagingKeys::<T>::get(&who) {
                Self::release_hold(HoldReason::KeyDeposit, &who, old.deposit);
            }
            let deposit = T::KeyDeposit::get();
            Self::hold(HoldReason::KeyDeposit, &who, deposit)?;
            MessagingKeys::<T>::insert(&who, PublishedKey { key, binding, deposit });
            Self::deposit_event(Event::MessagingKeyPublished { who, key });
            Ok(())
        }

        /// Publish the public half of a one-time invite (an Ed25519 key).
        #[pallet::call_index(3)]
        #[pallet::weight(placeholder::<T>(2, 2))]
        pub fn register_invite(
            origin: OriginFor<T>,
            key: InviteKey,
            expires_at: Option<BlockNumberFor<T>>,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            ensure!(Self::is_usable_invite_key(&key), Error::<T>::WeakInviteKey);
            ensure!(!Invites::<T>::contains_key(&owner, key), Error::<T>::InviteAlreadyRegistered);
            let deposit = T::InviteDeposit::get();
            Self::hold(HoldReason::InviteDeposit, &owner, deposit)?;
            let seq = Self::take_seq()?;
            Invites::<T>::insert(&owner, key, Invite { expires_at, seq, deposit });
            Self::deposit_event(Event::InviteRegistered { owner, key });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(placeholder::<T>(1, 1))]
        pub fn revoke_invite(origin: OriginFor<T>, key: InviteKey) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // Only the owner's own entry can be found, so only the owner can
            // revoke it.
            let invite = Invites::<T>::take(&who, key).ok_or(Error::<T>::UnknownInvite)?;
            Self::release_hold(HoldReason::InviteDeposit, &who, invite.deposit);
            Self::deposit_event(Event::InviteRevoked { owner: who, key });
            Ok(())
        }

        /// Anyone may remove an invite past its `expires_at`; the deposit
        /// goes back to the owner, not the caller.
        #[pallet::call_index(12)]
        #[pallet::weight(placeholder::<T>(1, 2))]
        pub fn remove_expired_invite(
            origin: OriginFor<T>,
            owner: T::AccountId,
            key: InviteKey,
        ) -> DispatchResult {
            let by = ensure_signed(origin)?;
            let invite = Invites::<T>::get(&owner, key).ok_or(Error::<T>::UnknownInvite)?;
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(invite.expires_at.is_some_and(|deadline| now > deadline), Error::<T>::InviteNotExpired);
            Invites::<T>::remove(&owner, key);
            Self::release_hold(HoldReason::InviteDeposit, &owner, invite.deposit);
            Self::deposit_event(Event::ExpiredInviteRemoved { owner, key, by });
            Ok(())
        }

        /// Cheap path: open a channel with an invite the recipient handed out.
        /// `proof` is the invite key's Ed25519 signature over
        /// [`invite_message`]`(opener, recipient)`.
        #[pallet::call_index(5)]
        #[pallet::weight(placeholder::<T>(6, 8))]
        pub fn open_with_invite(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            key: InviteKey,
            proof: [u8; 64],
        ) -> DispatchResult {
            let opener = ensure_signed(origin)?;
            ensure!(opener != recipient, Error::<T>::SelfContact);
            ensure!(!ChannelByPair::<T>::contains_key(pair::<T>(&opener, &recipient)), Error::<T>::ChannelExists);
            let invite = Invites::<T>::get(&recipient, key).ok_or(Error::<T>::UnknownInvite)?;
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(invite.expires_at.map_or(true, |deadline| now <= deadline), Error::<T>::InviteExpired);
            if let Some(block) = Blocks::<T>::get(&recipient, &opener) {
                ensure!(invite.seq >= block.seq, Error::<T>::Blocked);
            }
            let message = invite_message(Self::genesis_hash().as_ref(), &opener.encode(), &recipient.encode());
            ensure!(
                sp_io::crypto::ed25519_verify(
                    &ed25519::Signature::from_raw(proof),
                    &message,
                    &ed25519::Public::from_raw(key),
                ),
                Error::<T>::BadInviteProof
            );
            Self::pay_network_fee(&opener, T::InviteOpenFee::get())?;
            // One-time use: the invite goes, its deposit returns to the owner.
            Invites::<T>::remove(&recipient, key);
            Self::release_hold(HoldReason::InviteDeposit, &recipient, invite.deposit);
            if let Some(id) = RequestByPair::<T>::get(pair::<T>(&opener, &recipient)) {
                Self::refund(id, RefundReason::Superseded);
            }
            Self::open_channel(opener, recipient, OpenedVia::Invite)
        }

        /// Expensive path: pay the network fee and escrow the recipient's
        /// price. `note` must be exactly [`SEALED_NOTE_LEN`] bytes.
        #[pallet::call_index(6)]
        #[pallet::weight(placeholder::<T>(9, 9))]
        pub fn request_contact(
            origin: OriginFor<T>,
            recipient: T::AccountId,
            max_price: BalanceOf<T>,
            note: SealedNote,
        ) -> DispatchResult {
            let from = ensure_signed(origin)?;
            let to = recipient;
            ensure!(from != to, Error::<T>::SelfContact);
            let key = pair::<T>(&from, &to);
            ensure!(!ChannelByPair::<T>::contains_key(&key), Error::<T>::ChannelExists);
            ensure!(!Blocks::<T>::contains_key(&to, &from), Error::<T>::Blocked);
            ensure!(!InviteOnly::<T>::contains_key(&to), Error::<T>::StrangersNotAccepted);
            ensure!(MessagingKeys::<T>::contains_key(&to), Error::<T>::NoMessagingKey);
            ensure!(note.len() as u32 == SEALED_NOTE_LEN, Error::<T>::BadNoteSize);
            ensure!(!RequestByPair::<T>::contains_key(&key), Error::<T>::RequestPending);
            let price = Self::contact_price(&to);
            ensure!(price <= max_price, Error::<T>::PriceAboveMax);
            let fee = T::ColdNetworkFee::get();
            let available = T::Currency::reducible_balance(&from, Preservation::Preserve, Fortitude::Polite);
            ensure!(available >= fee.saturating_add(price), Error::<T>::InsufficientFunds);

            let expires_at = frame_system::Pallet::<T>::block_number()
                .checked_add(&Self::request_ttl_blocks())
                .ok_or(ArithmeticError::Overflow)?;
            let id = Self::take_id()?;
            ExpiryQueue::<T>::try_mutate(expires_at, |queue| queue.try_push(id))
                .map_err(|_| Error::<T>::ExpiryQueueFull)?;
            Self::pay_network_fee(&from, fee)?;
            T::Currency::hold(&HoldReason::ContactEscrow.into(), &from, price)
                .map_err(|_| Error::<T>::InsufficientFunds)?;
            Requests::<T>::insert(
                id,
                ContactRequest { from: from.clone(), to: to.clone(), price, expires_at, note: note.clone() },
            );
            RequestByPair::<T>::insert(&key, id);
            Self::deposit_event(Event::ContactRequested { request: id, from, to, price, note });
            Ok(())
        }

        /// Recipient accepts: the escrowed price is theirs, the channel opens.
        #[pallet::call_index(7)]
        #[pallet::weight(placeholder::<T>(5, 8))]
        pub fn accept_contact(origin: OriginFor<T>, request: RequestId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let req = Requests::<T>::get(request).ok_or(Error::<T>::UnknownRequest)?;
            ensure!(who == req.to, Error::<T>::NotRecipient);
            T::Currency::transfer_on_hold(
                &HoldReason::ContactEscrow.into(),
                &req.from,
                &req.to,
                req.price,
                Precision::Exact,
                Restriction::Free,
                Fortitude::Polite,
            )?;
            Requests::<T>::remove(request);
            RequestByPair::<T>::remove(pair::<T>(&req.from, &req.to));
            Self::unqueue(request, req.expires_at);
            Self::open_channel(req.from, req.to, OpenedVia::PaidRequest)
        }

        /// Either side cancels: the price returns minus the burned decline fee.
        #[pallet::call_index(8)]
        #[pallet::weight(placeholder::<T>(2, 4))]
        pub fn cancel_request(origin: OriginFor<T>, request: RequestId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let req = Requests::<T>::get(request).ok_or(Error::<T>::UnknownRequest)?;
            ensure!(who == req.from || who == req.to, Error::<T>::NotRequestParty);
            Self::refund(request, RefundReason::CancelledBy(who));
            Ok(())
        }

        /// Close a channel; the other side is blocked from paying to reach
        /// the closer again.
        #[pallet::call_index(9)]
        #[pallet::weight(placeholder::<T>(2, 4))]
        pub fn close_channel(origin: OriginFor<T>, channel: ChannelId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let ch = Channels::<T>::get(channel).ok_or(Error::<T>::UnknownChannel)?;
            ensure!(who == ch.a || who == ch.b, Error::<T>::NotParticipant);
            let other = if who == ch.a { ch.b.clone() } else { ch.a.clone() };
            Self::remove_channel(channel, &ch, who.clone());
            // The automatic block takes a deposit like any other block; if the
            // closer cannot pay it, the whole call fails and nothing changes.
            Self::add_block(who, other)?;
            Ok(())
        }

        /// Block an address: its paid requests fail, its pending request is
        /// refunded in full, the blocker's own pending request to it is
        /// cancelled (decline fee burned), an open channel with it is closed.
        #[pallet::call_index(10)]
        #[pallet::weight(placeholder::<T>(5, 8))]
        pub fn block(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(who != target, Error::<T>::SelfContact);
            ensure!(!Blocks::<T>::contains_key(&who, &target), Error::<T>::AlreadyBlocked);
            let key = pair::<T>(&who, &target);
            if let Some(channel) = ChannelByPair::<T>::get(&key) {
                if let Some(ch) = Channels::<T>::get(channel) {
                    Self::remove_channel(channel, &ch, who.clone());
                }
            }
            // The target's pending request is refunded in full; the
            // blocker's own is cancelled as a sender cancel (decline fee
            // burned; audit F4).
            if let Some(id) = RequestByPair::<T>::get(&key) {
                if let Some(req) = Requests::<T>::get(id) {
                    let reason = if req.from == target {
                        RefundReason::Blocked
                    } else {
                        RefundReason::CancelledBy(who.clone())
                    };
                    Self::refund(id, reason);
                }
            }
            Self::add_block(who, target)?;
            Ok(())
        }

        #[pallet::call_index(11)]
        #[pallet::weight(placeholder::<T>(1, 1))]
        pub fn unblock(origin: OriginFor<T>, target: T::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let entry = Blocks::<T>::take(&who, &target).ok_or(Error::<T>::NotBlocked)?;
            Self::release_hold(HoldReason::BlockDeposit, &who, entry.deposit);
            Self::deposit_event(Event::Unblocked { by: who, target, reason: UnblockReason::Lifted });
            Ok(())
        }
    }

    /// The pair in a fixed order, so (a, b) and (b, a) share one key.
    fn pair<T: Config>(a: &T::AccountId, b: &T::AccountId) -> (T::AccountId, T::AccountId) {
        if a <= b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) }
    }

    impl<T: Config> Pallet<T> {
        /// The node reward pool.
        pub fn pool_account() -> T::AccountId {
            T::PalletId::get().into_account_truncating()
        }

        /// What a stranger must pay `who`.
        pub fn contact_price(who: &T::AccountId) -> BalanceOf<T> {
            Prices::<T>::get(who).unwrap_or_else(T::DefaultContactPrice::get)
        }

        /// The request lifetime in blocks, rounded up (48 h at 6 s = 28,800).
        pub fn request_ttl_blocks() -> BlockNumberFor<T> {
            let block_ms = T::ExpectedBlockTimeMillis::get().max(1);
            T::RequestTtlMillis::get().div_ceil(block_ms).saturated_into()
        }

        /// `bps` basis points of `amount`, rounded up, capped at `amount`.
        pub fn bps_of_rounded_up(amount: BalanceOf<T>, bps: u16) -> BalanceOf<T> {
            let bps: BalanceOf<T> = u32::from(bps.min(BPS_DENOMINATOR)).into();
            let denom: BalanceOf<T> = u32::from(BPS_DENOMINATOR).into();
            let rem = (amount % denom) * bps;
            let up = (rem + denom - 1u32.into()) / denom;
            amount / denom * bps + up
        }

        /// A key `ed25519-dalek` decodes and does not call weak (small
        /// order). The host function `ed25519_verify` follows ZIP 215 and
        /// would accept a trivially made proof for a weak key, so such keys
        /// are refused before they are stored (2026-11-20 audit HIGH-04).
        pub fn is_usable_invite_key(key: &InviteKey) -> bool {
            ed25519_dalek::VerifyingKey::from_bytes(key).is_ok_and(|k| !k.is_weak())
        }

        /// The burned share of a network fee, rounded down; cannot overflow.
        pub fn burn_share(fee: BalanceOf<T>) -> BalanceOf<T> {
            Percent::from_percent(T::FeeBurnPercent::get().min(100)).mul_floor(fee)
        }

        /// The chain's genesis hash, which signed messages carry.
        pub fn genesis_hash() -> T::Hash {
            frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero())
        }

        /// Burn part of a network fee and pay the rest into the pool.
        fn pay_network_fee(from: &T::AccountId, fee: BalanceOf<T>) -> DispatchResult {
            let available = T::Currency::reducible_balance(from, Preservation::Preserve, Fortitude::Polite);
            ensure!(available >= fee, Error::<T>::InsufficientFunds);
            let burn = Self::burn_share(fee);
            T::Currency::burn_from(from, burn, Preservation::Preserve, Precision::Exact, Fortitude::Polite)?;
            T::Currency::transfer(from, &Self::pool_account(), fee.saturating_sub(burn), Preservation::Preserve)?;
            Ok(())
        }

        /// Free a resolved request's slot in the expiry queue (2026-11-20
        /// audit HIGH-01), so early answers do not use up the block's cap.
        fn unqueue(id: RequestId, expires_at: BlockNumberFor<T>) {
            ExpiryQueue::<T>::mutate_exists(expires_at, |queue| {
                if let Some(ids) = queue {
                    ids.retain(|queued| *queued != id);
                    if ids.is_empty() {
                        *queue = None;
                    }
                }
            });
        }

        /// End a request without a paid channel. The decline fee is burned
        /// unless the request was superseded by an invite or ended by a block.
        fn refund(id: RequestId, reason: RefundReason<T::AccountId>) {
            let Some(req) = Requests::<T>::take(id) else { return };
            RequestByPair::<T>::remove(pair::<T>(&req.from, &req.to));
            Self::unqueue(id, req.expires_at);
            let burned = match reason {
                RefundReason::Superseded | RefundReason::Blocked => Zero::zero(),
                RefundReason::CancelledBy(_) | RefundReason::Expired => {
                    Self::bps_of_rounded_up(req.price, T::DeclineFeeBps::get())
                }
            };
            let amount = req.price - burned;
            // Exactly `price` is on hold for this request, so neither step
            // should fail. If one does, carry on (this may run in
            // `on_initialize`, which cannot fail) but make it visible.
            let escrow = HoldReason::ContactEscrow.into();
            if let Err(error) =
                T::Currency::burn_held(&escrow, &req.from, burned, Precision::Exact, Fortitude::Force)
            {
                log::error!(target: LOG_TARGET, "request {id}: burning the decline fee failed: {error:?}");
                Self::deposit_event(Event::HoldNotReleased { who: req.from.clone(), amount: burned });
            }
            Self::release_hold(HoldReason::ContactEscrow, &req.from, amount);
            Self::deposit_event(Event::RequestRefunded { request: id, to: req.from, amount, burned, reason });
        }

        /// A channel needs both sides' consent, so it clears blocks both ways.
        fn open_channel(a: T::AccountId, b: T::AccountId, via: OpenedVia) -> DispatchResult {
            let (a, b) = pair::<T>(&a, &b);
            for (blocker, target) in [(&a, &b), (&b, &a)] {
                if let Some(entry) = Blocks::<T>::take(blocker, target) {
                    Self::release_hold(HoldReason::BlockDeposit, blocker, entry.deposit);
                    Self::deposit_event(Event::Unblocked {
                        by: blocker.clone(),
                        target: target.clone(),
                        reason: UnblockReason::ChannelOpened,
                    });
                }
            }
            let id = Self::take_id()?;
            let opened_at = frame_system::Pallet::<T>::block_number();
            Channels::<T>::insert(id, Channel { a: a.clone(), b: b.clone(), opened_at, via });
            ChannelByPair::<T>::insert((a.clone(), b.clone()), id);
            Self::deposit_event(Event::ChannelOpened { channel: id, a, b, via });
            Ok(())
        }

        fn remove_channel(channel: ChannelId, ch: &Channel<T::AccountId, BlockNumberFor<T>>, by: T::AccountId) {
            Channels::<T>::remove(channel);
            ChannelByPair::<T>::remove((ch.a.clone(), ch.b.clone()));
            Self::deposit_event(Event::ChannelClosed { channel, by });
        }

        fn add_block(blocker: T::AccountId, target: T::AccountId) -> DispatchResult {
            let deposit = T::BlockDeposit::get();
            Self::hold(HoldReason::BlockDeposit, &blocker, deposit)?;
            let seq = Self::take_seq()?;
            Blocks::<T>::insert(&blocker, &target, BlockEntry { seq, deposit });
            Self::deposit_event(Event::Blocked { by: blocker, target });
            Ok(())
        }

        /// Hold a deposit; an account that cannot afford it gets
        /// `InsufficientFunds` (and the whole call is rolled back).
        fn hold(reason: HoldReason, who: &T::AccountId, amount: BalanceOf<T>) -> DispatchResult {
            T::Currency::hold(&reason.into(), who, amount).map_err(|_| Error::<T>::InsufficientFunds.into())
        }

        /// Return a held amount. Should never fail; if it does, log it and
        /// emit `HoldNotReleased` instead of failing (audit F5).
        fn release_hold(reason: HoldReason, who: &T::AccountId, amount: BalanceOf<T>) {
            if let Err(error) = T::Currency::release(&reason.into(), who, amount, Precision::Exact) {
                log::error!(target: LOG_TARGET, "returning a {reason:?} hold of {amount:?} failed: {error:?}");
                Self::deposit_event(Event::HoldNotReleased { who: who.clone(), amount });
            }
        }

        fn take_id() -> Result<u64, DispatchError> {
            NextId::<T>::try_mutate(|n| {
                *n = n.checked_add(1).ok_or(ArithmeticError::Overflow)?;
                Ok(*n)
            })
        }

        fn take_seq() -> Result<u64, DispatchError> {
            NextSeq::<T>::try_mutate(|n| {
                *n = n.checked_add(1).ok_or(ArithmeticError::Overflow)?;
                Ok(*n)
            })
        }
    }
}
