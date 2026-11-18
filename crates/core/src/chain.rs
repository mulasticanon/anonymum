//! The on-chain rules: invites, paid contact requests, channels and fees.
//!
//! This is written as a plain deterministic state machine so it can be
//! tested in isolation and later ported one-to-one into a Substrate pallet.
//! `sender` on [`Chain::apply`] is assumed to be authenticated already (the
//! surrounding chain verifies the transaction signature, as Substrate's
//! `origin` does).
//!
//! # Privacy note
//!
//! In this milestone the channel table is transparent: anyone reading the
//! chain can see that two addresses opened a channel. Hiding that needs
//! shielded payments and is a later milestone. Do not ship this as-is.

use std::collections::BTreeMap;

use crate::crypto::{invite_message, InviteKey, InviteProof, InviteScheme};
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
    /// Blocks before an unanswered contact request expires and is refunded.
    pub request_ttl_blocks: BlockHeight,
    /// Share of each network fee that is destroyed; the rest pays nodes.
    pub fee_burn_percent: u8,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            invite_open_fee: COIN / 100,
            cold_network_fee: COIN / 2,
            default_contact_price: COIN,
            request_ttl_blocks: 1_000,
            fee_burn_percent: 50,
        }
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    pub id: RequestId,
    pub from: Address,
    pub to: Address,
    /// Held in escrow until the recipient answers or the request expires.
    pub price: Amount,
    pub expires_at: BlockHeight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tx {
    /// Set what strangers must pay to reach the sender.
    SetContactPrice { price: Amount },
    /// Publish the public half of a one-time invite.
    RegisterInvite { key: InviteKey, expires_at: Option<BlockHeight> },
    RevokeInvite { key: InviteKey },
    /// Cheap path: open a channel using an invite the recipient handed out.
    OpenWithInvite { recipient: Address, key: InviteKey, proof: InviteProof },
    /// Expensive path: pay the network and escrow the recipient's price.
    /// `max_price` protects the sender if the price changes before inclusion.
    RequestContact { recipient: Address, max_price: Amount },
    /// Recipient accepts: they receive the escrowed price, channel opens.
    AcceptContact { request: RequestId },
    /// Either side cancels: escrow returns to the requester.
    CancelRequest { request: RequestId },
    CloseChannel { channel: ChannelId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundReason {
    CancelledBy(Address),
    Expired,
    /// The pair opened a channel another way while the request was pending.
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ContactPriceSet { who: Address, price: Amount },
    InviteRegistered { owner: Address, key: InviteKey },
    InviteRevoked { owner: Address, key: InviteKey },
    ContactRequested { request: RequestId, from: Address, to: Address, price: Amount },
    RequestRefunded { request: RequestId, to: Address, amount: Amount, reason: RefundReason },
    ChannelOpened { channel: ChannelId, a: Address, b: Address, via: OpenedVia },
    ChannelClosed { channel: ChannelId, by: Address },
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
    invites: BTreeMap<InviteKey, Invite>,
    channels: BTreeMap<ChannelId, Channel>,
    by_pair: BTreeMap<(Address, Address), ChannelId>,
    requests: BTreeMap<RequestId, ContactRequest>,
    next_id: u64,
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
            invites: BTreeMap::new(),
            channels: BTreeMap::new(),
            by_pair: BTreeMap::new(),
            requests: BTreeMap::new(),
            next_id: 1,
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
            Tx::RegisterInvite { key, expires_at } => {
                if self.invites.contains_key(&key) {
                    return Err(Error::InviteAlreadyRegistered);
                }
                self.invites.insert(key, Invite { owner: sender, expires_at });
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
            Tx::RequestContact { recipient, max_price } => {
                self.request_contact(sender, recipient, max_price)?
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
                let key = pair(ch.a, ch.b);
                self.by_pair.remove(&key);
                self.channels.remove(&channel);
                self.events.push(Event::ChannelClosed { channel, by: sender });
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
    ) -> Result<(), Error> {
        if from == to {
            return Err(Error::SelfContact);
        }
        if self.by_pair.contains_key(&pair(from, to)) {
            return Err(Error::ChannelExists);
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
        let expires_at = self.height + self.params.request_ttl_blocks;
        self.requests.insert(id, ContactRequest { id, from, to, price, expires_at });
        self.events.push(Event::ContactRequested { request: id, from, to, price });
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

    fn refund(&mut self, id: RequestId, reason: RefundReason) {
        if let Some(req) = self.requests.remove(&id) {
            self.ledger.release(req.from, req.price);
            self.events.push(Event::RequestRefunded {
                request: id,
                to: req.from,
                amount: req.price,
                reason,
            });
        }
    }

    fn open_channel(&mut self, a: Address, b: Address, via: OpenedVia) {
        let id = ChannelId(self.take_id());
        let (a, b) = pair(a, b);
        self.channels.insert(id, Channel { id, a, b, opened_at: self.height, via });
        self.by_pair.insert((a, b), id);
        self.events.push(Event::ChannelOpened { channel: id, a, b, via });
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
