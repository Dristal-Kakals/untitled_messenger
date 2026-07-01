//! um_protocol — wire messages + length-prefixed framing for the UM relay.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;
pub mod framing;
pub mod message;

pub use error::ProtocolError;
pub use framing::{decode, encode, MAX_FRAME_SIZE};
pub use message::{ClientMessage, EncryptedEnvelope, ServerError, ServerMessage};
