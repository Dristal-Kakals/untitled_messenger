//! um_crypto — pure E2EE protocol primitives: X3DH (with optional post-quantum
//! hybrid ML-KEM-768 layer), Double Ratchet, Sender Keys. No I/O, no async, no
//! panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod double_ratchet;
pub mod error;
pub mod identity;
pub mod kem;
pub mod sender_keys;
pub mod x3dh;
pub use ed25519_dalek::{Signature, VerifyingKey};
pub use error::CryptoError;
pub use identity::fingerprint_of_pub;
pub use kem::{
    CT_768_LEN, DK_768_LEN, EK_768_LEN, PqCiphertext, PqDecapsulationKey, PqEncapsulationKey,
    SS_768_LEN,
};
