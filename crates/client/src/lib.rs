//! um_client — the UM client. Headless core: session state, TCP networking,
//! encrypted local store, and a thin crypto bridge. No GUI in this crate
//! (a future `um_gui` crate will depend on it).
//!
//! No `unsafe`, no panics in non-test code.

#![forbid(unsafe_code)]

pub mod crypto_bridge;
pub mod error;
pub mod net;
pub mod session;
pub mod store;

pub use error::ClientError;
pub use net::{Client, ClientReader, ClientWriter};
pub use session::ClientSession;
pub use store::{Contact, Store, StoreKey, StoredMessage, StoredMessageRow};
