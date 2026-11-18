//! The on-chain rules: invites, paid contact requests, channels, blocks
//! and fees.
//!
//! This is written as a plain deterministic state machine so it can be
//! tested in isolation and later ported one-to-one into a Substrate pallet.
//! `sender` on [`Chain::apply`] is assumed to be authenticated already (the
//! surrounding chain verifies the transaction signature, as Substrate's
//! `origin` does).
//!
//! # Privacy note
//!
//! In this milestone the channel table, contact requests and blocks are
//! transparent: anyone reading the chain can see that two addresses opened
//! a channel, that one requested the other, and who blocked whom. Hiding
//! that needs shielded payments and is a later milestone. Do not ship this
//! as-is.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{
    invite_message, InviteKey, InviteProof, InviteScheme, KeyBinding, MessagingKey, SealedNote,
    SEALED_NOTE_LEN,
};
use crate::ledger::{InsufficientFunds, Ledger};
use crate::types::{Address, Amount, BlockHeight, ChannelId, RequestId, COIN};

/// Tunable economics. Values are placeholders to be set by simulation.
#[derive(Debug, Clone)]
pub struct Params {
    /// Fee to open a channel with a valid invite. Small.
    pub invite_open_fee: Amount,
    /// Non-refundable fee to request contact with a stranger. Larger.
    pub cold_network_fee: Amount,
    /// Price a stranger pays the recipient, unless the recipient set their own.
    pub default_contact_price: Amount,
    /// How long an unanswered contact request lives before it expires and
    /// is refunded, in seconds. Decided: 48 hours.
    pub request_ttl_secs: u64,
    /// Target time between blocks, in milliseconds. Substrate's default is
    /// 6 s. Used only to turn durations into block counts.
    pub block_time_ms: u64,
    /// Share of each network fee that is destroyed; the rest pays nodes.
    pub fee_burn_percent: u8,
    /// Share of the escrowed price that is burned when a contact request
    /// ends without a channel (declined, cancelled or expired), in basis
    /// points (100 = 1%). Rounded up. Burned rather than paid to anyone, so
    /// nobody profits from turning strangers away. Not charged when the
    /// request is superseded by an invite or ended by a block.
    pub decline_fee_bps: u16,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            invite_open_fee: COIN / 100,
            cold_network_fee: COIN / 2,
            default_contact_price: COIN,
            request_ttl_secs: 48 * 60 * 60,
            block_time_ms: 6_000,
            fee_burn_percent: 50,
            decline_fee_bps: 100,
        }
    }
}

impl Params {
    /// The request lifetime in blocks, rounded up so a request never lives
    /// shorter than `request_ttl_secs`. 48 h at 6 s blocks = 28,800.
    pub fn request_ttl_blocks(&self) -> BlockHeight {
        self.request_ttl_secs.saturating_mul(1_000).div_ceil(self.block_time_ms.max(1))
    }
}

/// Basis points per whole (100%).
pub const BPS_DENOMINATOR: u16 = 10_000;

/// `bps` basis points of `amount`, rounded up, capped at `amount`.
/// Split into quotient and remainder so it cannot overflow.
pub fn bps_of_rounded_up(amount: Amount, bps: u16) -> Amount {
    let bps = Amount::from(bps.min(BPS_DENOMINATOR));
    let denom = Amount::from(BPS_DENOMINATOR);
    amount / denom * bps + (amount % denom * bps).div_ceil(denom)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenedVia {
    Invite,
    PaidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub id: ChannelId,
    pub a: Address,
    pub b: Address,
    pub opened_at: BlockHeight,
    pub via: OpenedVia,
}

#[derive(Debug, Clone)]
struct Invite {
    owner: Address,
    expires_at: Option<BlockHeight>,
    /// Position in the chain's history of invites and blocks. Only an
    /// invite issued after a block can lift that block.
    seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    pub id: RequestId,
    pub from: Address,
    pub to: Address,
    /// Held in escrow until the recipient answers or the request expires.
    pub price: Amount,
    pub expires_at: BlockHeight,
    /// Sealed to the recipient's messaging key: a throwaway mixnet address
    /// and a short intro. Only the recipient can open it.
    pub note: SealedNote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub key: MessagingKey,
    pub binding: KeyBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tx {
    /// Set what strangers must pay to reach the sender.
    SetContactPrice { price: Amount },
    /// Accept paid requests from strangers (default) or be invite-only.
    SetAcceptStrangers { accept: bool },
    /// Publish (or replace) the sender's messaging key, with the address
    /// key's signature over it.
    PublishMessagingKey { key: MessagingKey, binding: KeyBinding },
    /// Publish the public half of a one-time invite.
    RegisterInvite { key: InviteKey, expires_at: Option<BlockHeight> },
    RevokeInvite { key: InviteKey },
    /// Cheap path: open a channel using an invite the recipient handed out.
    OpenWithInvite { recipient: Address, key: InviteKey, proof: InviteProof },
    /// Expensive path: pay the network and escrow the recipient's price.
    /// `max_price` protects the sender if the price changes before inclusion.
    /// `note` must be exactly [`SEALED_NOTE_LEN`] bytes.
    RequestContact { recipient: Address, max_price: Amount, note: SealedNote },
    /// Recipient accepts: they receive the escrowed price, channel opens.
    AcceptContact { request: RequestId },
    /// Either side cancels: escrow returns to the requester, minus the
    /// burned decline fee.
    CancelRequest { request: RequestId },
    /// Close a channel. The other side is blocked from paying to reach the
    /// closer again.
    CloseChannel { channel: ChannelId },
    /// Block an address: its paid requests fail, its pending request is
    /// refunded in full, an open channel with it is closed.
    Block { target: Address },
    Unblock { target: Address },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundReason {
    CancelledBy(Address),
    Expired,
    /// The pair opened a channel another way while the request was pending.
    Superseded,
    /// The recipient blocked the requester. Full refund: the requester
    /// broke no rule by asking.
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockReason {
    /// The blocker sent `Unblock`.
    Lifted,
    /// A channel opened between the two, which both sides consented to.
    ChannelOpened,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ContactPriceSet { who: Address, price: Amount },
    AcceptStrangersSet { who: Address, accept: bool },
    MessagingKeyPublished { who: Address, key: MessagingKey },
    InviteRegistered { owner: Address, key: InviteKey },
    InviteRevoked { owner: Address, key: InviteKey },
    ContactRequested { request: RequestId, from: Address, to: Address, price: Amount, note: SealedNote },
    /// `amount` went back to the requester; `burned` was the decline fee.
    RequestRefunded {
        request: RequestId,
        to: Address,
        amount: Amount,
        burned: Amount,
        reason: RefundReason,
    },
    ChannelOpened { channel: ChannelId, a: Address, b: Address, via: OpenedVia },
    ChannelClosed { channel: ChannelId, by: Address },
    Blocked { by: Address, target: Address },
    Unblocked { by: Address, target: Address, reason: UnblockReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InsufficientFunds { needed: Amount, available: Amount },
    SelfContact,
    ChannelExists,
    InviteAlreadyRegistered,
    UnknownInvite,
    NotInviteOwner,
    InviteExpired,
    BadInviteProof,
    PriceAboveMax { price: Amount },
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
    /// The recipient has not published a messaging key, so no note can be
    /// sealed to them.
    NoMessagingKey,
    BadNoteSize { len: usize },
    BadKeyBinding,
    AlreadyBlocked,
    NotBlocked,
}

impl From<InsufficientFunds> for Error {
    fn from(e: InsufficientFunds) -> Self {
        Error::InsufficientFunds { needed: e.needed, available: e.available }
    }
}

fn pair(a: Address, b: Address) -> (Address, Address) {
    if a <= b { (a, b) } else { (b, a) }
}

pub struct Chain<S: InviteScheme> {
    params: Params,
    scheme: S,
    height: BlockHeight,
    ledger: Ledger,
    prices: BTreeMap<Address, Amount>,
    /// Addresses that refuse paid requests from strangers.
    invite_only: BTreeSet<Address>,
    messaging_keys: BTreeMap<Address, PublishedKey>,
    invites: BTreeMap<InviteKey, Invite>,
    channels: BTreeMap<ChannelId, Channel>,
    by_pair: BTreeMap<(Address, Address), ChannelId>,
    requests: BTreeMap<RequestId, ContactRequest>,
    /// (blocker, blocked) -> sequence number when the block was made.
    blocks: BTreeMap<(Address, Address), u64>,
    next_id: u64,
    next_seq: u64,
    events: Vec<Event>,
}

impl<S: InviteScheme> Chain<S> {
    pub fn new(params: Params, scheme: S) -> Self {
        Chain {
            params,
            scheme,
            height: 0,
            ledger: Ledger::default(),
            prices: BTreeMap::new(),
            invite_only: BTreeSet::new(),
            messaging_keys: BTreeMap::new(),
            invites: BTreeMap::new(),
            channels: BTreeMap::new(),
            by_pair: BTreeMap::new(),
            requests: BTreeMap::new(),
            blocks: BTreeMap::new(),
            next_id: 1,
            next_seq: 1,
            events: Vec::new(),
        }
    }

    // ---- read access -----------------------------------------------------

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Full event log since genesis.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// What a stranger must pay `who` to request contact.
    pub fn contact_price(&self, who: &Address) -> Amount {
        self.prices.get(who).copied().unwrap_or(self.params.default_contact_price)
    }

    pub fn accepts_strangers(&self, who: &Address) -> bool {
        !self.invite_only.contains(who)
    }

    pub fn messaging_key(&self, who: &Address) -> Option<&PublishedKey> {
        self.messaging_keys.get(who)
    }

    /// Has `blocker` blocked `target`?
    pub fn is_blocked(&self, blocker: &Address, target: &Address) -> bool {
        self.blocks.contains_key(&(*blocker, *target))
    }

    pub fn channel_between(&self, a: &Address, b: &Address) -> Option<&Channel> {
        self.by_pair.get(&pair(*a, *b)).and_then(|id| self.channels.get(id))
    }

    pub fn request(&self, id: RequestId) -> Option<&ContactRequest> {
        self.requests.get(&id)
    }

    // ---- state changes ---------------------------------------------------

    /// Genesis allocation / test faucet.
    pub fn mint(&mut self, to: Address, amount: Amount) {
        self.ledger.mint(to, amount);
    }

    /// Advance time. Unanswered contact requests past their deadline are
    /// refunded. Returns the events this produced.
    pub fn advance_blocks(&mut self, blocks: BlockHeight) -> Vec<Event> {
        let start = self.events.len();
        self.height += blocks;
        let expired: Vec<RequestId> = self
            .requests
            .values()
            .filter(|r| r.expires_at <= self.height)
            .map(|r| r.id)
            .collect();
        for id in expired {
            self.refund(id, RefundReason::Expired);
        }
        self.events[start..].to_vec()
    }

    /// Apply one transaction. Either it fully succeeds and returns its
    /// events, or it fails and changes nothing.
    pub fn apply(&mut self, sender: Address, tx: Tx) -> Result<Vec<Event>, Error> {
        let start = self.events.len();
        match tx {
            Tx::SetContactPrice { price } => {
                self.prices.insert(sender, price);
                self.events.push(Event::ContactPriceSet { who: sender, price });
            }
            Tx::SetAcceptStrangers { accept } => {
                if accept {
                    self.invite_only.remove(&sender);
                } else {
                    self.invite_only.insert(sender);
                }
                self.events.push(Event::AcceptStrangersSet { who: sender, accept });
            }
            Tx::PublishMessagingKey { key, binding } => {
                if !self.scheme.verify_key_binding(&sender, &key, &binding) {
                    return Err(Error::BadKeyBinding);
                }
                self.messaging_keys.insert(sender, PublishedKey { key, binding });
                self.events.push(Event::MessagingKeyPublished { who: sender, key });
            }
            Tx::RegisterInvite { key, expires_at } => {
                if self.invites.contains_key(&key) {
                    return Err(Error::InviteAlreadyRegistered);
                }
                let seq = self.take_seq();
                self.invites.insert(key, Invite { owner: sender, expires_at, seq });
                self.events.push(Event::InviteRegistered { owner: sender, key });
            }
            Tx::RevokeInvite { key } => {
                let invite = self.invites.get(&key).ok_or(Error::UnknownInvite)?;
                if invite.owner != sender {
                    return Err(Error::NotInviteOwner);
                }
                self.invites.remove(&key);
                self.events.push(Event::InviteRevoked { owner: sender, key });
            }
            Tx::OpenWithInvite { recipient, key, proof } => {
                self.open_with_invite(sender, recipient, key, proof)?
            }
            Tx::RequestContact { recipient, max_price, note } => {
                self.request_contact(sender, recipient, max_price, note)?
            }
            Tx::AcceptContact { request } => self.accept_contact(sender, request)?,
            Tx::CancelRequest { request } => {
                let req = self.requests.get(&request).ok_or(Error::UnknownRequest)?;
                if sender != req.from && sender != req.to {
                    return Err(Error::NotRequestParty);
                }
                self.refund(request, RefundReason::CancelledBy(sender));
            }
            Tx::CloseChannel { channel } => {
                let ch = self.channels.get(&channel).ok_or(Error::UnknownChannel)?;
                if sender != ch.a && sender != ch.b {
                    return Err(Error::NotParticipant);
                }
                let other = if sender == ch.a { ch.b } else { ch.a };
                self.close_channel(channel, sender);
                self.add_block(sender, other);
            }
            Tx::Block { target } => {
                if target == sender {
                    return Err(Error::SelfContact);
                }
                if self.is_blocked(&sender, &target) {
                    return Err(Error::AlreadyBlocked);
                }
                if let Some(&channel) = self.by_pair.get(&pair(sender, target)) {
                    self.close_channel(channel, sender);
                }
                let pending: Vec<RequestId> = self
                    .requests
                    .values()
                    .filter(|r| r.from == target && r.to == sender)
                    .map(|r| r.id)
                    .collect();
                for id in pending {
                    self.refund(id, RefundReason::Blocked);
                }
                self.add_block(sender, target);
            }
            Tx::Unblock { target } => {
                if self.blocks.remove(&(sender, target)).is_none() {
                    return Err(Error::NotBlocked);
                }
                self.events.push(Event::Unblocked { by: sender, target, reason: UnblockReason::Lifted });
            }
        }
        Ok(self.events[start..].to_vec())
    }

    fn open_with_invite(
        &mut self,
        opener: Address,
        recipient: Address,
        key: InviteKey,
        proof: InviteProof,
    ) -> Result<(), Error> {
        if opener == recipient {
            return Err(Error::SelfContact);
        }
        if self.by_pair.contains_key(&pair(opener, recipient)) {
            return Err(Error::ChannelExists);
        }
        let invite = self.invites.get(&key).ok_or(Error::UnknownInvite)?;
        if invite.owner != recipient {
            return Err(Error::UnknownInvite);
        }
        if invite.expires_at.is_some_and(|deadline| self.height > deadline) {
            return Err(Error::InviteExpired);
        }
        // A blocked opener may only use an invite issued after the block:
        // the recipient handing out a fresh invite is how they reopen.
        if let Some(&blocked_at) = self.blocks.get(&(recipient, opener)) {
            if invite.seq < blocked_at {
                return Err(Error::Blocked);
            }
        }
        if !self.scheme.verify(&key, &invite_message(&opener, &recipient), &proof) {
            return Err(Error::BadInviteProof);
        }
        // All checks passed; the fee is the last thing that can fail.
        self.ledger.pay_network_fee(
            opener,
            self.params.invite_open_fee,
            self.params.fee_burn_percent,
        )?;
        self.invites.remove(&key); // one-time use
        let superseded: Vec<RequestId> = self
            .requests
            .values()
            .filter(|r| pair(r.from, r.to) == pair(opener, recipient))
            .map(|r| r.id)
            .collect();
        for id in superseded {
            self.refund(id, RefundReason::Superseded);
        }
        self.open_channel(opener, recipient, OpenedVia::Invite);
        Ok(())
    }

    fn request_contact(
        &mut self,
        from: Address,
        to: Address,
        max_price: Amount,
        note: SealedNote,
    ) -> Result<(), Error> {
        if from == to {
            return Err(Error::SelfContact);
        }
        if self.by_pair.contains_key(&pair(from, to)) {
            return Err(Error::ChannelExists);
        }
        if self.is_blocked(&to, &from) {
            return Err(Error::Blocked);
        }
        if !self.accepts_strangers(&to) {
            return Err(Error::StrangersNotAccepted);
        }
        if !self.messaging_keys.contains_key(&to) {
            return Err(Error::NoMessagingKey);
        }
        if note.0.len() != SEALED_NOTE_LEN {
            return Err(Error::BadNoteSize { len: note.0.len() });
        }
        if self.requests.values().any(|r| pair(r.from, r.to) == pair(from, to)) {
            return Err(Error::RequestPending);
        }
        let price = self.contact_price(&to);
        if price > max_price {
            return Err(Error::PriceAboveMax { price });
        }
        let fee = self.params.cold_network_fee;
        self.ledger.can_pay(&from, fee + price)?;
        self.ledger.pay_network_fee(from, fee, self.params.fee_burn_percent)?;
        self.ledger.lock(from, price)?;
        let id = RequestId(self.take_id());
        let expires_at = self.height + self.params.request_ttl_blocks();
        self.requests.insert(
            id,
            ContactRequest { id, from, to, price, expires_at, note: note.clone() },
        );
        self.events.push(Event::ContactRequested { request: id, from, to, price, note });
        Ok(())
    }

    fn accept_contact(&mut self, sender: Address, id: RequestId) -> Result<(), Error> {
        let req = self.requests.get(&id).ok_or(Error::UnknownRequest)?;
        if sender != req.to {
            return Err(Error::NotRecipient);
        }
        let req = self.requests.remove(&id).expect("checked above");
        self.ledger.release(req.to, req.price);
        self.open_channel(req.from, req.to, OpenedVia::PaidRequest);
        Ok(())
    }

    /// End a request without a paid channel. The decline fee is burned
    /// unless the request was superseded by an invite or ended by a block.
    fn refund(&mut self, id: RequestId, reason: RefundReason) {
        if let Some(req) = self.requests.remove(&id) {
            let burned = match reason {
                RefundReason::Superseded | RefundReason::Blocked => 0,
                RefundReason::CancelledBy(_) | RefundReason::Expired => {
                    bps_of_rounded_up(req.price, self.params.decline_fee_bps)
                }
            };
            let amount = req.price - burned;
            self.ledger.burn_escrowed(burned);
            self.ledger.release(req.from, amount);
            self.events.push(Event::RequestRefunded {
                request: id,
                to: req.from,
                amount,
                burned,
                reason,
            });
        }
    }

    /// A channel only opens with both sides' consent (an invite the
    /// recipient issued, or a request the recipient accepted), so it clears
    /// any block between the two, in both directions.
    fn open_channel(&mut self, a: Address, b: Address, via: OpenedVia) {
        let id = ChannelId(self.take_id());
        let (a, b) = pair(a, b);
        for (blocker, target) in [(a, b), (b, a)] {
            if self.blocks.remove(&(blocker, target)).is_some() {
                self.events.push(Event::Unblocked {
                    by: blocker,
                    target,
                    reason: UnblockReason::ChannelOpened,
                });
            }
        }
        self.channels.insert(id, Channel { id, a, b, opened_at: self.height, via });
        self.by_pair.insert((a, b), id);
        self.events.push(Event::ChannelOpened { channel: id, a, b, via });
    }

    fn close_channel(&mut self, channel: ChannelId, by: Address) {
        if let Some(ch) = self.channels.remove(&channel) {
            self.by_pair.remove(&(ch.a, ch.b));
            self.events.push(Event::ChannelClosed { channel, by });
        }
    }

    fn add_block(&mut self, blocker: Address, target: Address) {
        let seq = self.take_seq();
        self.blocks.insert((blocker, target), seq);
        self.events.push(Event::Blocked { by: blocker, target });
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
