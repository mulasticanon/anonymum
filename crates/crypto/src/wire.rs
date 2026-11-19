//! Framing that carries handshakes and sealed messages over any transport.
//!
//! One leading byte says what a frame is. The initiator knows the
//! recipient's transport address; the responder only ever sees an opaque
//! reply handle `T` (on Nym: an anonymous sender tag backed by single-use
//! reply blocks), so it can answer without learning where the caller is.

use std::collections::HashMap;
use std::hash::Hash;

use anonymum_core::Address;

use crate::identity::Identity;
use crate::session::{Handshake, Session, SessionError, MAX_NOISE_MESSAGE};

const HANDSHAKE_1: u8 = 1;
const HANDSHAKE_2: u8 = 2;
const HANDSHAKE_3: u8 = 3;
const DATA: u8 = 4;

/// Cap on half-finished handshakes a responder keeps, so strangers cannot
/// exhaust memory by starting handshakes and never finishing.
const MAX_PENDING: usize = 1_024;

#[derive(Debug)]
pub enum WireError {
    Session(SessionError),
    /// Empty frame or unknown type byte.
    UnknownFrame,
    /// Frame type makes no sense at this point of the conversation.
    UnexpectedFrame,
    /// Data arrived (or was to be sent) without an established session.
    NoSession,
    Busy,
    /// Longer than any valid frame; refused before anything is allocated.
    Oversized,
}

/// The longest valid frame: one type byte and one Noise message.
pub const MAX_FRAME: usize = 1 + MAX_NOISE_MESSAGE;

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WireError {}

impl From<SessionError> for WireError {
    fn from(e: SessionError) -> Self {
        WireError::Session(e)
    }
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn split(frame: &[u8]) -> Result<(u8, &[u8]), WireError> {
    if frame.len() > MAX_FRAME {
        return Err(WireError::Oversized);
    }
    frame.split_first().map(|(kind, body)| (*kind, body)).ok_or(WireError::UnknownFrame)
}

// ---- initiator -------------------------------------------------------------

/// The calling side of one conversation.
pub struct Initiator {
    pending: Option<Handshake>,
    session: Option<Session>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitiatorEvent {
    /// Handshake complete. Send `reply` to the peer; then `seal` is usable.
    Established { reply: Vec<u8> },
    Message(Vec<u8>),
}

impl Initiator {
    /// Begin talking to `peer`. Returns the first frame to send.
    pub fn start(me: &Identity, peer: Address) -> Result<(Initiator, Vec<u8>), WireError> {
        let (handshake, message1) = Handshake::initiate(me, peer)?;
        Ok((Initiator { pending: Some(handshake), session: None }, frame(HANDSHAKE_1, &message1)))
    }

    pub fn handle(&mut self, incoming: &[u8]) -> Result<InitiatorEvent, WireError> {
        match split(incoming)? {
            (HANDSHAKE_2, body) => {
                let handshake = self.pending.as_mut().ok_or(WireError::UnexpectedFrame)?;
                match handshake.initiator_finish(body) {
                    Ok((session, message3)) => {
                        self.pending = None;
                        self.session = Some(session);
                        Ok(InitiatorEvent::Established { reply: frame(HANDSHAKE_3, &message3) })
                    }
                    Err(error) => {
                        // A frame Noise rejected leaves the handshake waiting
                        // for the real message 2.
                        if !handshake.is_live() {
                            self.pending = None;
                        }
                        Err(error.into())
                    }
                }
            }
            (DATA, body) => {
                let session = self.session.as_mut().ok_or(WireError::NoSession)?;
                Ok(InitiatorEvent::Message(session.open(body)?))
            }
            (HANDSHAKE_1 | HANDSHAKE_3, _) => Err(WireError::UnexpectedFrame),
            _ => Err(WireError::UnknownFrame),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let session = self.session.as_mut().ok_or(WireError::NoSession)?;
        Ok(frame(DATA, &session.seal(plaintext)?))
    }
}

// ---- responder -------------------------------------------------------------

/// The answering side, serving many callers at once.
pub struct Responder<T> {
    pending: HashMap<T, Pending>,
    sessions: HashMap<T, Session>,
}

/// A half-finished handshake, with the frame that started it and our reply.
/// A caller who is not answered (e.g. we were offline) sends the same first
/// frame again; when both copies arrive, we answer the repeat with the same
/// reply, so there is still exactly one handshake to finish.
struct Pending {
    first: Vec<u8>,
    reply: Vec<u8>,
    handshake: Handshake,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponderEvent {
    /// Send this frame back to the caller.
    Reply(Vec<u8>),
    /// A caller proved it is `peer`. Decide now whether to keep talking
    /// (check the chain for an open channel) or call [`Responder::forget`].
    Established { peer: Address },
    Message { peer: Address, plaintext: Vec<u8> },
}

impl<T: Hash + Eq + Clone> Default for Responder<T> {
    fn default() -> Self {
        Responder { pending: HashMap::new(), sessions: HashMap::new() }
    }
}

impl<T: Hash + Eq + Clone> Responder<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle(
        &mut self,
        me: &Identity,
        from: T,
        incoming: &[u8],
    ) -> Result<ResponderEvent, WireError> {
        match split(incoming)? {
            (HANDSHAKE_1, body) => {
                if let Some(pending) = self.pending.get(&from) {
                    if pending.first == body {
                        return Ok(ResponderEvent::Reply(pending.reply.clone()));
                    }
                }
                if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&from) {
                    return Err(WireError::Busy);
                }
                let (handshake, message2) = Handshake::respond(me, body)?;
                let reply = frame(HANDSHAKE_2, &message2);
                self.pending.insert(from, Pending { first: body.to_vec(), reply: reply.clone(), handshake });
                Ok(ResponderEvent::Reply(reply))
            }
            (HANDSHAKE_3, body) => {
                let pending = self.pending.get_mut(&from).ok_or(WireError::UnexpectedFrame)?;
                let session = match pending.handshake.responder_finish(body) {
                    Ok(session) => session,
                    Err(error) => {
                        // A frame Noise rejected leaves the handshake waiting
                        // for the real message 3.
                        if !pending.handshake.is_live() {
                            self.pending.remove(&from);
                        }
                        return Err(error.into());
                    }
                };
                self.pending.remove(&from);
                let peer = session.peer();
                self.sessions.insert(from, session);
                Ok(ResponderEvent::Established { peer })
            }
            (DATA, body) => {
                let session = self.sessions.get_mut(&from).ok_or(WireError::NoSession)?;
                let plaintext = session.open(body)?;
                Ok(ResponderEvent::Message { peer: session.peer(), plaintext })
            }
            (HANDSHAKE_2, _) => Err(WireError::UnexpectedFrame),
            _ => Err(WireError::UnknownFrame),
        }
    }

    pub fn seal(&mut self, to: &T, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let session = self.sessions.get_mut(to).ok_or(WireError::NoSession)?;
        Ok(frame(DATA, &session.seal(plaintext)?))
    }

    /// Drop a caller, e.g. because they have no open channel.
    pub fn forget(&mut self, from: &T) {
        self.pending.remove(from);
        self.sessions.remove(from);
    }
}
