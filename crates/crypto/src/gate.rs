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
//!   calling about that request before its deadline (reverse rendezvous);
//!
//! and in every case not blocked, with the reference named inside the
//! encrypted first message matching. Anyone else gets no reply at all.
//!
//! A grant is only *committed* (an invitation counted as honoured, a caller
//! recorded as a contact) once the caller has confirmed a fresh session, so
//! a replayed first message cannot use an invitation twice; and a blocked
//! key is refused whatever it replays.
//!
//! The gate belongs to one [`crate::wire::Responder`], built from the same
//! network id, and can only be changed through that responder, so a
//! revocation always ends sessions and drops cached replies with it. It has
//! no public constructor:
//!
//! ```compile_fail
//! let gate = anonymum_crypto::Gate::new([0; 32]);
//! ```
//!
//! and no public way to change it from outside a responder:
//!
//! ```compile_fail
//! # use anonymum_crypto::{wire::Responder, ContactIdentity};
//! let me = ContactIdentity::generate();
//! let mut side: Responder<u32> = Responder::for_identity(&me, [0; 32]);
//! side.gate_mut().block([1; 32]);
//! ```
//!
//! State lives in memory only: durable and multi-device grant state is an
//! open question (issues file, review finding 8).

use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::contact::{check_key, ContactError, Invitation, Network, Purpose};

/// The time, as the gate and the wire layer need it: wall-clock seconds for
/// invitation expiry (an absolute date both sides can check) and a monotonic
/// instant for deadlines. Tests inject both.
#[derive(Clone, Copy, Debug)]
pub struct Now {
    pub unix: u64,
    pub mono: Instant,
}

impl Now {
    pub fn system() -> Now {
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Now { unix, mono: Instant::now() }
    }
}

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

pub struct Gate {
    network: Network,
    /// Our contact signing key, if we issue invitations.
    issuer: Option<[u8; 32]>,
    /// Invitations we issued and have not honoured, by holder key.
    issued: HashMap<[u8; 32], Invitation>,
    honoured: HashSet<[u8; 32]>,
    /// Invitations cancelled by a block or a removal; never usable again.
    revoked: HashSet<[u8; 32]>,
    /// Caller key -> the reference its calls must name.
    contacts: HashMap<[u8; 32], [u8; 32]>,
    /// Caller key -> (reference, deadline).
    callbacks: HashMap<[u8; 32], ([u8; 32], Instant)>,
    blocked: HashSet<[u8; 32]>,
}

impl Gate {
    pub(crate) fn new(network: Network, issuer: Option<[u8; 32]>) -> Self {
        Gate {
            network,
            issuer,
            issued: HashMap::new(),
            honoured: HashSet::new(),
            revoked: HashSet::new(),
            contacts: HashMap::new(),
            callbacks: HashMap::new(),
            blocked: HashSet::new(),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Remember an invitation so its holder can call. It must be one we
    /// issued (our signing key, valid signature), for our network, with a
    /// valid holder key, and unexpired at `now`.
    pub(crate) fn record_invitation(&mut self, invitation: Invitation, now: Now) -> Result<(), ContactError> {
        let issuer = self.issuer.ok_or(ContactError::WrongIssuer)?;
        invitation.verify(&issuer, &self.network, now.unix)?;
        if self.revoked.contains(&invitation.id) {
            return Err(ContactError::Revoked);
        }
        self.issued.insert(invitation.holder, invitation);
        Ok(())
    }

    /// Accept a call from `caller` about the request `reference` until
    /// `deadline` (the stranger's side of reverse rendezvous).
    pub(crate) fn expect_callback(
        &mut self,
        caller: [u8; 32],
        reference: [u8; 32],
        deadline: Instant,
    ) -> Result<(), ContactError> {
        check_key(&caller)?;
        self.callbacks.insert(caller, (reference, deadline));
        Ok(())
    }

    /// End the relationship with `caller` and cancel every grant it still
    /// holds: an unused invitation (revoked for good) and an outstanding
    /// callback. A closed channel needs a new invitation to reopen (owner
    /// decision, 2026-11-20).
    pub(crate) fn remove_contact(&mut self, caller: &[u8; 32]) {
        self.contacts.remove(caller);
        self.cancel_grants(caller);
    }

    /// Block `caller` and cancel its grants, as [`Gate::remove_contact`]
    /// does. Unblocking later restores nothing.
    pub(crate) fn block(&mut self, caller: [u8; 32]) {
        self.blocked.insert(caller);
        self.cancel_grants(&caller);
    }

    fn cancel_grants(&mut self, caller: &[u8; 32]) {
        if let Some(invitation) = self.issued.remove(caller) {
            self.revoked.insert(invitation.id);
        }
        self.callbacks.remove(caller);
    }

    pub(crate) fn unblock(&mut self, caller: &[u8; 32]) {
        self.blocked.remove(caller);
    }

    pub fn is_contact(&self, caller: &[u8; 32]) -> bool {
        self.contacts.contains_key(caller)
    }

    pub fn is_blocked(&self, caller: &[u8; 32]) -> bool {
        self.blocked.contains(caller)
    }

    pub fn is_honoured(&self, invitation_id: &[u8; 32]) -> bool {
        self.honoured.contains(invitation_id)
    }

    /// Is `caller` a current, unblocked contact for `reference`? Checked on
    /// every use of an established session.
    pub fn admits(&self, caller: &[u8; 32], reference: &[u8; 32]) -> bool {
        !self.blocked.contains(caller) && self.contacts.get(caller) == Some(reference)
    }

    /// May `caller`, naming `reference`, be answered at `now`?
    pub fn authorise(&self, caller: &[u8; 32], reference: &[u8; 32], now: Now) -> Option<Grant> {
        if self.blocked.contains(caller) {
            return None;
        }
        if self.contacts.get(caller) == Some(reference) {
            return Some(Grant::Contact);
        }
        if let Some((expected, deadline)) = self.callbacks.get(caller) {
            if expected == reference && now.mono < *deadline {
                return Some(Grant::Callback);
            }
        }
        let invitation = self.issued.get(caller)?;
        let usable = &invitation.id == reference
            && invitation.network == self.network
            && invitation.purpose == Purpose::Contact
            && now.unix < invitation.expires_at
            && !self.honoured.contains(&invitation.id)
            && !self.revoked.contains(&invitation.id);
        usable.then_some(Grant::Invitation { id: invitation.id })
    }

    /// After a fresh session confirmation: check again and commit the grant.
    /// Returns `false` (and changes nothing) if it no longer holds, e.g. the
    /// caller was blocked meanwhile, the invitation was honoured already or
    /// the callback deadline passed.
    pub(crate) fn commit(&mut self, caller: &[u8; 32], reference: &[u8; 32], grant: Grant, now: Now) -> bool {
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
