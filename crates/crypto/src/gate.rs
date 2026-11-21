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
//! # Time and durability
//!
//! Everything the gate keeps is measured in Unix seconds, so it means the
//! same after a restart: invitation expiries, callback deadlines, and the
//! expiry of every revoked or consumed invitation id. (The wire layer's
//! short timeouts for unconfirmed handshakes and idle sessions use a
//! monotonic clock and are not persisted: after a restart callers simply
//! handshake again.) A revoked or consumed id is kept until its invitation
//! has expired plus [`CLOCK_SKEW_SECS`], after which the invitation itself
//! no longer verifies, so [`Gate::prune`] may forget it.
//!
//! **The gate's clock never runs backwards.** It remembers the latest Unix
//! time it has seen (`last_seen`, saved in the snapshot) and judges every
//! deadline and expiry by [`Gate::effective_now`], the later of that and
//! the time it is given. So once it has seen a revoked invitation expire
//! (and pruned it) or a callback grant run out, setting the clock back,
//! within a run or across a restart, cannot make either usable again.
//!
//! The gate's state can be saved and restored, encrypted, through
//! [`crate::wire::Responder::export_snapshot`] and the `restore_*`
//! constructors (see [`crate::snapshot`]); the responder documents when a
//! caller must persist it (persist before reply). One device per contact
//! identity: two devices sharing a gate's state are not supported.

use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::contact::{check_key, ContactError, Invitation, Network, Purpose};
use crate::snapshot::{SnapshotError, GATE_SNAPSHOT_VERSION};

/// How long past an invitation's expiry its revoked or consumed id is still
/// kept, in case this machine's clock steps backwards.
pub const CLOCK_SKEW_SECS: u64 = 300;

/// The time, as the gate and the wire layer need it: wall-clock seconds for
/// everything the gate keeps (absolute dates that survive a restart) and a
/// monotonic instant for the wire layer's in-memory timeouts. Tests inject
/// both.
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

#[derive(Debug, PartialEq, Eq)]
pub struct Gate {
    network: Network,
    /// Our contact signing key, if we issue invitations.
    issuer: Option<[u8; 32]>,
    /// Invitations we issued and have not honoured, by holder key.
    issued: HashMap<[u8; 32], Invitation>,
    /// Consumed invitation id -> its expiry (Unix seconds).
    honoured: HashMap<[u8; 32], u64>,
    /// Invitations cancelled by a block or a removal, never usable again:
    /// id -> its expiry (Unix seconds).
    revoked: HashMap<[u8; 32], u64>,
    /// Caller key -> the reference its calls must name.
    contacts: HashMap<[u8; 32], [u8; 32]>,
    /// Caller key -> (reference, deadline in Unix seconds).
    callbacks: HashMap<[u8; 32], ([u8; 32], u64)>,
    blocked: HashSet<[u8; 32]>,
    /// The latest Unix time this gate has seen; its clock floor.
    last_seen: u64,
}

impl Gate {
    pub(crate) fn new(network: Network, issuer: Option<[u8; 32]>) -> Self {
        Gate {
            network,
            issuer,
            issued: HashMap::new(),
            honoured: HashMap::new(),
            revoked: HashMap::new(),
            contacts: HashMap::new(),
            callbacks: HashMap::new(),
            blocked: HashSet::new(),
            last_seen: 0,
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
        let now_secs = self.effective_now(now.unix);
        invitation.verify(&issuer, &self.network, now_secs)?;
        if self.revoked.contains_key(&invitation.id) {
            return Err(ContactError::Revoked);
        }
        self.issued.insert(invitation.holder, invitation);
        Ok(())
    }

    /// Accept a call from `caller` about the request `reference` until
    /// `deadline`, in Unix seconds (the stranger's side of reverse
    /// rendezvous).
    pub(crate) fn expect_callback(
        &mut self,
        caller: [u8; 32],
        reference: [u8; 32],
        deadline: u64,
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
            self.revoked.insert(invitation.id, invitation.expires_at);
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
        self.honoured.contains_key(invitation_id)
    }

    pub fn is_revoked(&self, invitation_id: &[u8; 32]) -> bool {
        self.revoked.contains_key(invitation_id)
    }

    /// Forget what can no longer matter at `now_secs`: revoked and consumed
    /// ids once their invitation expired [`CLOCK_SKEW_SECS`] ago (it no
    /// longer verifies, so it cannot be recorded or used again), unused
    /// invitations once expired, and callback grants past their deadline.
    /// Returns how many entries were dropped.
    pub fn prune(&mut self, now_secs: u64) -> usize {
        let now_secs = self.effective_now(now_secs);
        let before = self.len();
        let keep = |expires_at: &mut u64| now_secs < expires_at.saturating_add(CLOCK_SKEW_SECS);
        self.honoured.retain(|_, e| keep(e));
        self.revoked.retain(|_, e| keep(e));
        self.issued.retain(|_, invitation| now_secs < invitation.expires_at);
        self.callbacks.retain(|_, (_, deadline)| now_secs < *deadline);
        before - self.len()
    }

    /// Move the clock floor up to `now_secs` if it is later, and return the
    /// floor: the time every gate decision uses.
    pub fn effective_now(&mut self, now_secs: u64) -> u64 {
        self.last_seen = self.last_seen.max(now_secs);
        self.last_seen
    }

    /// The latest Unix time this gate has seen.
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// The time a read-only check uses: never earlier than the floor.
    fn floor(&self, now_secs: u64) -> u64 {
        self.last_seen.max(now_secs)
    }

    fn len(&self) -> usize {
        self.honoured.len() + self.revoked.len() + self.issued.len() + self.callbacks.len()
    }

    /// Is `caller` a current, unblocked contact for `reference`? Checked on
    /// every use of an established session.
    pub fn admits(&self, caller: &[u8; 32], reference: &[u8; 32]) -> bool {
        !self.blocked.contains(caller) && self.contacts.get(caller) == Some(reference)
    }

    /// May `caller`, naming `reference`, be answered at `now`?
    /// Judged at the later of `now` and the gate's clock floor.
    pub fn authorise(&self, caller: &[u8; 32], reference: &[u8; 32], now: Now) -> Option<Grant> {
        let now_secs = self.floor(now.unix);
        if self.blocked.contains(caller) {
            return None;
        }
        if self.contacts.get(caller) == Some(reference) {
            return Some(Grant::Contact);
        }
        if let Some((expected, deadline)) = self.callbacks.get(caller) {
            if expected == reference && now_secs < *deadline {
                return Some(Grant::Callback);
            }
        }
        let invitation = self.issued.get(caller)?;
        let usable = &invitation.id == reference
            && invitation.network == self.network
            && invitation.purpose == Purpose::Contact
            && now_secs < invitation.expires_at
            && !self.honoured.contains_key(&invitation.id)
            && !self.revoked.contains_key(&invitation.id);
        usable.then_some(Grant::Invitation { id: invitation.id })
    }

    /// After a fresh session confirmation: check again and commit the grant.
    /// Returns `false` (and changes nothing) if it no longer holds, e.g. the
    /// caller was blocked meanwhile, the invitation was honoured already or
    /// the callback deadline passed.
    pub(crate) fn commit(&mut self, caller: &[u8; 32], reference: &[u8; 32], grant: Grant, now: Now) -> bool {
        let now = Now { unix: self.effective_now(now.unix), ..now };
        if self.authorise(caller, reference, now) != Some(grant) {
            return false;
        }
        match grant {
            Grant::Invitation { id } => {
                let expires_at = self.issued.remove(caller).map_or(u64::MAX, |i| i.expires_at);
                self.honoured.insert(id, expires_at);
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

// ---- snapshot encoding -------------------------------------------------------

/// The plaintext of a gate snapshot, format version 1. All integers are
/// big-endian; every table is sorted by key, so equal gates encode equally.
///
/// ```text
/// version (1)  network (32)  issuer flag (1) [issuer (32)]  last_seen (8)
/// issued:    u32 count, each an Invitation (Invitation::LEN bytes)
/// honoured:  u32 count, each id (32) || expires_at (8)
/// revoked:   u32 count, each id (32) || expires_at (8)
/// contacts:  u32 count, each caller (32) || reference (32)
/// callbacks: u32 count, each caller (32) || reference (32) || deadline (8)
/// blocked:   u32 count, each caller (32)
/// ```
impl Gate {
    pub(crate) fn encode(&self) -> Vec<u8> {
        fn sorted<K: Ord + Copy, V>(map: &HashMap<K, V>) -> Vec<(K, &V)> {
            let mut out: Vec<(K, &V)> = map.iter().map(|(k, v)| (*k, v)).collect();
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        }
        fn count(out: &mut Vec<u8>, n: usize) {
            out.extend_from_slice(&u32::try_from(n).expect("table fits u32").to_be_bytes());
        }
        let mut out = vec![GATE_SNAPSHOT_VERSION];
        out.extend_from_slice(&self.network);
        match self.issuer {
            Some(issuer) => {
                out.push(1);
                out.extend_from_slice(&issuer);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.last_seen.to_be_bytes());
        count(&mut out, self.issued.len());
        for (_, invitation) in sorted(&self.issued) {
            out.extend_from_slice(&invitation.to_bytes());
        }
        for table in [&self.honoured, &self.revoked] {
            count(&mut out, table.len());
            for (id, expires_at) in sorted(table) {
                out.extend_from_slice(&id);
                out.extend_from_slice(&expires_at.to_be_bytes());
            }
        }
        count(&mut out, self.contacts.len());
        for (caller, reference) in sorted(&self.contacts) {
            out.extend_from_slice(&caller);
            out.extend_from_slice(reference);
        }
        count(&mut out, self.callbacks.len());
        for (caller, (reference, deadline)) in sorted(&self.callbacks) {
            out.extend_from_slice(&caller);
            out.extend_from_slice(reference);
            out.extend_from_slice(&deadline.to_be_bytes());
        }
        let mut blocked: Vec<&[u8; 32]> = self.blocked.iter().collect();
        blocked.sort();
        count(&mut out, blocked.len());
        for caller in blocked {
            out.extend_from_slice(caller);
        }
        out
    }

    /// A gate from its encoding, for `network`. Strict: every byte must be
    /// accounted for, and the encoded network must match.
    pub(crate) fn decode(bytes: &[u8], network: &Network) -> Result<Gate, SnapshotError> {
        let mut r = Reader { bytes, at: 0 };
        let version = r.u8()?;
        if version != GATE_SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        if &r.array::<32>()? != network {
            return Err(SnapshotError::WrongNetwork);
        }
        let issuer = match r.u8()? {
            0 => None,
            1 => Some(r.array::<32>()?),
            _ => return Err(SnapshotError::Malformed),
        };
        let mut gate = Gate::new(*network, issuer);
        gate.last_seen = r.u64()?;
        for _ in 0..r.count()? {
            let invitation = Invitation::from_bytes(r.take(Invitation::LEN)?).map_err(|_| SnapshotError::Malformed)?;
            if invitation.network != *network || gate.issued.insert(invitation.holder, invitation).is_some() {
                return Err(SnapshotError::Malformed);
            }
        }
        for table in [&mut gate.honoured, &mut gate.revoked] {
            for _ in 0..r.count()? {
                let (id, expires_at) = (r.array::<32>()?, r.u64()?);
                if table.insert(id, expires_at).is_some() {
                    return Err(SnapshotError::Malformed);
                }
            }
        }
        for _ in 0..r.count()? {
            let (caller, reference) = (r.array::<32>()?, r.array::<32>()?);
            if gate.contacts.insert(caller, reference).is_some() {
                return Err(SnapshotError::Malformed);
            }
        }
        for _ in 0..r.count()? {
            let (caller, reference, deadline) = (r.array::<32>()?, r.array::<32>()?, r.u64()?);
            if gate.callbacks.insert(caller, (reference, deadline)).is_some() {
                return Err(SnapshotError::Malformed);
            }
        }
        for _ in 0..r.count()? {
            if !gate.blocked.insert(r.array::<32>()?) {
                return Err(SnapshotError::Malformed);
            }
        }
        if r.at != bytes.len() {
            return Err(SnapshotError::Malformed);
        }
        Ok(gate)
    }

    pub(crate) fn issuer(&self) -> Option<[u8; 32]> {
        self.issuer
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.bytes.len()).ok_or(SnapshotError::Malformed)?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }
    fn u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn count(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}
