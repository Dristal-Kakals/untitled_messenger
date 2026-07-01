//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub use error::CryptoError;
