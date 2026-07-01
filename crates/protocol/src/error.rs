use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("incomplete frame")]
    Incomplete,
    #[error("encode failed: {0}")]
    Encode(#[from] postcard::Error),
    #[error("decode failed")]
    Decode(postcard::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_compare_by_variant() {
        assert_eq!(ProtocolError::Incomplete, ProtocolError::Incomplete);
        assert!(matches!(
            ProtocolError::FrameTooLarge(42),
            ProtocolError::FrameTooLarge(42)
        ));
    }

    #[test]
    fn errors_display() {
        assert_eq!(
            ProtocolError::FrameTooLarge(100).to_string(),
            "frame too large: 100 bytes"
        );
        assert_eq!(ProtocolError::Incomplete.to_string(), "incomplete frame");
    }
}
