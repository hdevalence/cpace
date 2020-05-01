//! An implementation of the CPace Password-Authenticated Key Exchange (PAKE)
//! using Ristretto255. Note that this is an experimental implementation of a
//! draft spec -- don't deploy it until 1.0.
//!
//! This implementation is based on [`go-cpace-ristretto255`](https://github.com/FiloSottile/go-cpace-ristretto255) by Filippo Valsorda.
//!
//! # Example
//!
//! ```
//! use rand::rngs::OsRng;
//! use cpace;
//!
//! let (init_msg, state) = cpace::init(
//!     "password",
//!     cpace::Context {
//!         initiator_id: "Alice",
//!         responder_id: "Bob",
//!         associated_data: b"",
//!     },
//!     OsRng,
//! )
//! .unwrap();
//!
//! let (bob_key, rsp_msg) = cpace::respond(
//!     init_msg,
//!     "password",
//!     cpace::Context {
//!         initiator_id: "Alice",
//!         responder_id: "Bob",
//!         associated_data: b"",
//!     },
//!     OsRng,
//! )
//! .unwrap();
//!
//! let alice_key = state.recv(rsp_msg).unwrap();
//!
//! assert_eq!(alice_key.0[..], bob_key.0[..]);
//! ```
#![doc(html_root_url = "https://docs.rs/cpace/0.1.0")]

use std::convert::TryFrom;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

#[derive(Copy, Clone)]
/// The output of the PAKE: a password-authenticated key.
///
/// XXX this should be 32 bytes.
pub struct Key(pub [u8; 64]);
/// The message sent by the initiator to the responder.
#[derive(Copy, Clone)]
pub struct InitMessage(pub [u8; 48]);
/// The message sent by the responder to the initiator.
#[derive(Copy, Clone)]
pub struct ResponseMessage(pub [u8; 32]);

use thiserror::Error;
/// An error that occurred while performing a PAKE.
#[derive(Error, Debug)]
pub enum Error {
    /// The initiator's ID string was longer than `2**16` bytes.
    #[error("{0}-byte initiator id is too long.")]
    InitiatorIdTooLong(usize),
    /// The responder's ID string was longer than `2**16` bytes.
    #[error("{0}-byte responder id is too long.")]
    ResponderIdTooLong(usize),
    /// The associated data was longer than `2**16` bytes.
    #[error("{0}-byte associated data is too long.")]
    AssociatedDataTooLong(usize),
    /// The remote peer sent an invalid curve point.
    #[error("Invalid point encoding.")]
    InvalidPoint,
}

/// Contextual data bound to the resulting [`Key`].
///
/// Both peers need to construct identical contexts to agree on a key.
///
/// The `Context` struct is intended to be constructed inline to the call to
/// [`init`] or [`respond`], simulating named parameters.
#[derive(Copy, Clone)]
pub struct Context<'ctx> {
    /// A representation of the identity of the initiator.
    pub initiator_id: &'ctx str,
    /// A representation of the identity of the responder.
    pub responder_id: &'ctx str,
    /// Optional associated data the key will be bound to (can be empty).
    pub associated_data: &'ctx [u8],
}

const CONTEXT_LABEL: &[u8; 10] = b"cpace-r255";

impl<'ctx> Context<'ctx> {
    // XXX this defeats the whole point of the alloc-free Context API.
    // the problem is that the current HKDF API doesn't allow streaming
    // into the expand call, so we have to build a Vec.
    // But doing an internal alloc secretly means we can change it later.
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();

        let len = u16::try_from(CONTEXT_LABEL.len()).unwrap();
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(CONTEXT_LABEL);

        let len = u16::try_from(self.initiator_id.len())
            .map_err(|_| Error::InitiatorIdTooLong(self.initiator_id.len()))?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(self.initiator_id.as_bytes());

        let len = u16::try_from(self.responder_id.len())
            .map_err(|_| Error::ResponderIdTooLong(self.responder_id.len()))?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(self.responder_id.as_bytes());

        let len = u16::try_from(self.associated_data.len())
            .map_err(|_| Error::AssociatedDataTooLong(self.associated_data.len()))?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(self.associated_data);

        Ok(bytes)
    }
}

fn secret_generator(password: &str, salt: &[u8], context_bytes: &[u8]) -> RistrettoPoint {
    let mut output = [0; 64];
    // XXX Why does this use Sha512 instead of Sha256?
    Hkdf::<Sha512>::new(Some(salt), password.as_bytes())
        .expand(context_bytes, &mut output)
        .expect("64 bytes is less than max output size");
    RistrettoPoint::from_uniform_bytes(&output)
}

fn transcript(init_msg: InitMessage, rsp_msg: ResponseMessage) -> [u8; 16 + 32 + 32] {
    let mut bytes = [0; 16 + 32 + 32];
    bytes[0..48].copy_from_slice(&init_msg.0[..]);
    bytes[48..].copy_from_slice(&rsp_msg.0[..]);
    bytes
}

/// Initiate a PAKE.
#[allow(non_snake_case)]
pub fn init<R: RngCore + CryptoRng>(
    password: &str,
    context: Context,
    mut rng: R,
) -> Result<(InitMessage, AwaitingResponse), Error> {
    let mut msg_bytes = [0u8; 48];
    let (salt, point) = msg_bytes.split_at_mut(16);

    // One way to think about the protocol is as "spicy DH":
    // instead of doing DH with a fixed basepoint, we do DH
    // using a basepoint derived from the secret password.
    rng.fill_bytes(salt);
    let H = secret_generator(password, salt, &context.serialize()?);
    let a = Scalar::random(&mut rng);
    let A = a * H;

    point.copy_from_slice(A.compress().as_bytes());

    let init_msg = InitMessage(msg_bytes);

    Ok((init_msg, AwaitingResponse { a, init_msg }))
}

/// Respond to a PAKE [`InitMessage`].
#[allow(non_snake_case)]
pub fn respond<R: RngCore + CryptoRng>(
    init_msg: InitMessage,
    password: &str,
    context: Context,
    mut rng: R,
) -> Result<(Key, ResponseMessage), Error> {
    let (salt, A_bytes) = init_msg.0[..].split_at(16);

    let H = secret_generator(password, salt, &context.serialize()?);
    let b = Scalar::random(&mut rng);
    let B = b * H;

    let rsp_msg = ResponseMessage(B.compress().to_bytes());

    let A = CompressedRistretto::from_slice(A_bytes)
        .decompress()
        .ok_or(Error::InvalidPoint)?;

    let (key_bytes, _) = Hkdf::<Sha512>::extract(
        Some(&transcript(init_msg, rsp_msg)[..]),
        (b * A).compress().as_bytes(),
    );

    let key = {
        // awkward dance to extract from a GenericArray
        let mut bytes = [0; 64];
        bytes.copy_from_slice(&key_bytes[..]);
        Key(bytes)
    };

    Ok((key, rsp_msg))
}

/// An intermediate initiator state.
pub struct AwaitingResponse {
    a: Scalar,
    init_msg: InitMessage,
}

impl AwaitingResponse {
    /// Receive the [`ResponseMessage`] from the responder and (hopefully) obtain
    /// a shared [`Key`].
    ///
    /// Note that this function consumes `self` to ensure that at most one
    /// response is processed.
    #[allow(non_snake_case)]
    pub fn recv(self, rsp_msg: ResponseMessage) -> Result<Key, Error> {
        let B = CompressedRistretto(rsp_msg.0)
            .decompress()
            .ok_or(Error::InvalidPoint)?;

        let (key_bytes, _) = Hkdf::<Sha512>::extract(
            Some(&transcript(self.init_msg, rsp_msg)[..]),
            (self.a * B).compress().as_bytes(),
        );

        let key = {
            // awkward dance to extract from a GenericArray
            let mut bytes = [0; 64];
            bytes.copy_from_slice(&key_bytes[..]);
            Key(bytes)
        };

        Ok(key)
    }
}
