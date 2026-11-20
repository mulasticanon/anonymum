//! Who the answering side lets in (spec v0.7 section 2a, rule 3).
//!
//! The answering side reads the caller's authenticated key from the first
//! handshake message and asks the gate *before sending anything*. A caller
//! is let in only if its key is
//!
//! * the holder of an invitation this side issued, unexpired, for this
//!   network, and not yet honoured;
//! * an existing contact; or
//! * an expected callback: the recipient of a request this side made,
//!   calling about that request (reverse rendezvous);
//!
//! and in every case not blocked, with the reference named inside the
//! encrypted first message matching. Anyone else gets no reply at all.
//!
//! A grant is only *committed* (an invitation counted as honoured, a caller
//! recorded as a contact) once the caller has confirmed a fresh session, so
//! a replayed first message cannot use an invitation twice; and a blocked
//! key is refused whatever it replays.

use std::collections::{HashMap, HashSet};

use crate::contact::{Invitation, Network, Purpose};

/// Why a caller was let in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grant {
    /// Holder of the invitation with this id.
    Invitation { id: [u8; 32] },
    /// An existing contact.
    Contact,
    /// The recipient of our request, calling about it.
    Callback,
}

#[derive(Default)]
pub struct Gate {
    network: Network,
    /// Invitations we issued and have not honoured, by holder key.
    issued: HashMap<[u8; 32], Invitation>,
    honoured: HashSet<[u8; 32]>,
    /// Caller key -> the reference its calls must name.
    contacts: HashMap<[u8; 32], [u8; 32]>,
    callbacks: HashMap<[u8; 32], [u8; 32]>,
    blocked: HashSet<[u8; 32]>,
}

impl Gate {
    pub fn new(network: Network) -> Self {
        Gate { network, ..Default::default() }
    }

    /// Remember an invitation we issued, so its holder can call.
    pub fn record_invitation(&mut self, invitation: Invitation) {
        self.issued.insert(invitation.holder, invitation);
    }

    /// Accept a call from `caller` about the request `reference` (the
    /// stranger's side of reverse rendezvous).
    pub fn expect_callback(&mut self, caller: [u8; 32], reference: [u8; 32]) {
        self.callbacks.insert(caller, reference);
    }

    pub fn add_contact(&mut self, caller: [u8; 32], reference: [u8; 32]) {
        self.contacts.insert(caller, reference);
    }

    /// End a relationship (without blocking).
    pub fn remove_contact(&mut self, caller: &[u8; 32]) {
        self.contacts.remove(caller);
    }

    pub fn is_contact(&self, caller: &[u8; 32]) -> bool {
        self.contacts.contains_key(caller)
    }

    pub fn block(&mut self, caller: [u8; 32]) {
        self.blocked.insert(caller);
    }

    pub fn unblock(&mut self, caller: &[u8; 32]) {
        self.blocked.remove(caller);
    }

    pub fn is_honoured(&self, invitation_id: &[u8; 32]) -> bool {
        self.honoured.contains(invitation_id)
    }

    /// May `caller`, naming `reference`, be answered at time `now`?
    pub fn authorise(&self, caller: &[u8; 32], reference: &[u8; 32], now: u64) -> Option<Grant> {
        if self.blocked.contains(caller) {
            return None;
        }
        if self.contacts.get(caller) == Some(reference) {
            return Some(Grant::Contact);
        }
        if self.callbacks.get(caller) == Some(reference) {
            return Some(Grant::Callback);
        }
        let invitation = self.issued.get(caller)?;
        let usable = &invitation.id == reference
            && invitation.network == self.network
            && invitation.purpose == Purpose::Contact
            && now < invitation.expires_at
            && !self.honoured.contains(&invitation.id);
        usable.then_some(Grant::Invitation { id: invitation.id })
    }

    /// After a fresh session confirmation: check again and commit the grant.
    /// Returns `false` (and changes nothing) if it no longer holds, e.g. the
    /// caller was blocked meanwhile or the invitation was honoured already.
    pub(crate) fn commit(&mut self, caller: &[u8; 32], reference: &[u8; 32], grant: Grant, now: u64) -> bool {
        if self.authorise(caller, reference, now) != Some(grant) {
            return false;
        }
        match grant {
            Grant::Invitation { id } => {
                self.honoured.insert(id);
                self.issued.remove(caller);
            }
            Grant::Callback => {
                self.callbacks.remove(caller);
            }
            Grant::Contact => {}
        }
        self.contacts.insert(*caller, *reference);
        true
    }
}
