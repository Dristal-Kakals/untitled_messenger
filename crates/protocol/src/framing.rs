//! Length-prefixed framing: 4-byte big-endian length header + postcard payload.

use crate::error::ProtocolError;

/// Maximum allowed frame payload size (16 MiB).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Encode a serializable value into a length-prefixed frame.
///
/// Frame layout: `[u32 BE length][postcard bytes]`
pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(value).map_err(ProtocolError::Encode)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a length-prefixed frame from a byte slice.
///
/// Returns the deserialized value and the number of bytes consumed.
pub fn decode<T: for<'de> serde::Deserialize<'de>>(
    buf: &[u8],
) -> Result<(T, usize), ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::Incomplete);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let end = 4 + len;
    if buf.len() < end {
        return Err(ProtocolError::Incomplete);
    }
    let value = postcard::from_bytes(&buf[4..end]).map_err(ProtocolError::Decode)?;
    Ok((value, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ClientMessage, EncryptedEnvelope, ServerMessage};

    fn sample_envelope(id: u64) -> EncryptedEnvelope {
        EncryptedEnvelope {
            id,
            sender: [0xBB; 32],
            header: vec![1, 2, 3],
            init: None,
            ciphertext: b"test payload".to_vec(),
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let msg = ClientMessage::Send {
            recipients: vec![[0xAA; 32]],
            envelope: sample_envelope(1),
        };
        let frame = encode(&msg).expect("encode");
        assert!(frame.len() >= 4);
        let (decoded, consumed): (ClientMessage, usize) = decode(&frame).expect("decode");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn encode_decode_server_message() {
        let msg = ServerMessage::AckOk;
        let frame = encode(&msg).expect("encode");
        let (decoded, consumed): (ServerMessage, usize) = decode(&frame).expect("decode");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decode_incomplete_header() {
        let buf = [0u8; 3];
        let result: Result<(ClientMessage, usize), _> = decode(&buf);
        assert!(matches!(result, Err(ProtocolError::Incomplete)));
    }

    #[test]
    fn decode_incomplete_payload() {
        let msg = ClientMessage::Subscribe;
        let frame = encode(&msg).expect("encode");
        // Truncate one byte from the payload
        let truncated = &frame[..frame.len() - 1];
        let result: Result<(ClientMessage, usize), _> = decode(truncated);
        assert!(matches!(result, Err(ProtocolError::Incomplete)));
    }

    #[test]
    fn decode_frame_too_large() {
        // Craft a header claiming MAX_FRAME_SIZE + 1 bytes
        let len = (MAX_FRAME_SIZE + 1) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        let result: Result<(ClientMessage, usize), _> = decode(&buf);
        assert!(matches!(result, Err(ProtocolError::FrameTooLarge(_))));
    }

    #[test]
    fn partial_second_frame_not_consumed() {
        let msg = ClientMessage::Subscribe;
        let mut buf = encode(&msg).expect("encode");
        // Append a partial second frame
        buf.extend_from_slice(&[0, 0, 0, 10, 1, 2]); // claims 10 bytes, only 2 present
        let (decoded, consumed): (ClientMessage, usize) = decode(&buf).expect("decode first");
        assert_eq!(decoded, msg);
        // Only the first frame consumed
        let remaining = &buf[consumed..];
        let result: Result<(ClientMessage, usize), _> = decode(remaining);
        assert!(matches!(result, Err(ProtocolError::Incomplete)));
    }
}
