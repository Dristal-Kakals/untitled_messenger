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
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("no session with peer")]
    NoSession,
    #[error("no group session with id {0}")]
    NoGroupSession(String),
    /// A group message's `header.sender_id` (the sender's Sender-Key member id,
    /// derived from their identity fingerprint) did not match the identity pub
    /// the envelope claims to be from (`envelope.sender`). The group AEAD
    /// signature is over the header + ciphertext, not over `envelope.sender`, so
    /// without this check a group member could spoof another member's identity
    /// by setting `envelope.sender` to their pub while signing with their own
    /// Sender-Key signing key. The receiver must reject this.
    #[error("group sender_id does not match envelope.sender")]
    GroupSenderMismatch,
    #[error("no one-time prekey with id {0}")]
    NoOneTimePreKey(u32),
    #[error("store error: {0}")]
    Store(String),
    #[error("not connected")]
    NotConnected,
}
