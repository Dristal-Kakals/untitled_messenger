use thiserror::Error;

/// Errors surfaced by the client crate.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("crypto error: {0}")]
    Crypto(#[from] um_crypto::CryptoError),
    #[error("protocol error: {0}")]
    Protocol(#[from] um_protocol::ProtocolError),
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no session with peer")]
    NoSession,
    #[error("no one-time prekey with id {0}")]
    NoOneTimePreKey(u32),
    #[error("store error: {0}")]
    Store(String),
    #[error("not connected")]
    NotConnected,
}
