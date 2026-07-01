//! um_server — the UM relay. A dumb encrypted mailbox + key directory.
//! Stores prekey bundles and forwards ciphertext; never holds private keys,
//! never decrypts. In-memory only (lost on restart).

#![forbid(unsafe_code)]

pub mod handler;
pub mod store;

pub use store::Store;
