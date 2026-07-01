//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod double_ratchet;
pub mod error;
pub mod identity;
pub mod sender_keys;
pub mod x3dh;
pub use ed25519_dalek::VerifyingKey;
pub use error::CryptoError;
