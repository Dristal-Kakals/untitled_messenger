use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("missing prekey")]
    MissingPreKey,
    #[error("skipped message key cache limit reached")]
    SkippedMessageLimit,
    #[error("malformed prekey bundle")]
    MalformedBundle,
    #[error("invalid ratchet state")]
    InvalidState,
}

impl Clone for CryptoError {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for CryptoError {}
impl PartialEq for CryptoError {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}
impl Eq for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_compare_by_variant() {
        assert_eq!(CryptoError::DecryptionFailed, CryptoError::DecryptionFailed);
        assert_ne!(CryptoError::DecryptionFailed, CryptoError::InvalidSignature);
    }

    #[test]
    fn errors_display() {
        assert_eq!(CryptoError::MissingPreKey.to_string(), "missing prekey");
    }
}
