//! An implementation of the CPace Password-Authenticated Key Exchange (PAKE)
//! using Ristretto255. Note that this is an experimental implementation of a
//! draft spec -- don't deploy it until 1.0.

#[derive(Copy, Clone, Debug)]
/// The output of the PAKE: a password-authenticated key.
pub struct Key(pub [u8; 32]);
/// The message sent by the initiator to the responder.
#[derive(Copy, Clone, Debug)]
pub struct InitMessage(pub [u8; 32]);
/// The message sent by the responder to the initiator.
#[derive(Copy, Clone, Debug)]
pub struct ResponseMessage(pub [u8; 32]);

use thiserror::Error;
/// An error that occurred while performing a PAKE.
#[derive(Error, Debug)]
pub enum Error {
    // ...
}

/// Contextual data bound to the resulting [`Key`].
///
/// Both peers need to construct identical contexts to agree on a key.
pub struct Context<'ctx> {
    /// A representation of the identity of the initiator.
    pub initiator_id: &'ctx str,
    /// A representation of the identity of the responder.
    pub responder_id: &'ctx str,
    /// Optional associated data the key will be bound to (can be empty).
    pub associated_data: &'ctx [u8],
}

/// Initiate a PAKE.
pub fn init(_password: &str, _context: Context) -> Result<(InitMessage, AwaitingResponse), Error> {
    unimplemented!();
}

/// Respond to a PAKE [`InitMessage`].
pub fn respond(_password: &str, _context: Context, _msg: InitMessage) -> Result<Key, Error> {
    unimplemented!();
}

/// An intermediate initiator state.
pub struct AwaitingResponse {
    // ...
}

impl AwaitingResponse {
    /// Receive the [`ResponseMessage`] from the responder and (hopefully) obtain
    /// a shared [`Key`].
    ///
    /// Note that this function consumes `self` to ensure that at most one
    /// response is processed.
    pub fn recv(self, _response: ResponseMessage) -> Result<Key, Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        //let ctx = Context::new("", "", None);
        //let (_msg, state) = init("", &ctx).unwrap();
        let (_msg, state) = init(
            "password",
            Context {
                initiator_id: "alice",
                responder_id: "bob",
                associated_data: b"",
            },
        )
        .unwrap();
        let rsp = ResponseMessage([0; 32]);

        let _k1 = state.recv(rsp).unwrap();
        // illegal:
        // let k2 = state.recv(rsp).unwrap();

        assert_eq!(2 + 2, 4);
    }
}
