use thiserror::Error;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
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
