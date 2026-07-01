use serde::{Deserialize, Serialize};

/// Opaque encrypted payload with sender identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Sender's long-term identity key (32 bytes).
    pub sender_key: [u8; 32],
    /// Ciphertext produced by the Double Ratchet AEAD.
    pub ciphertext: Vec<u8>,
}

/// Messages sent from a client to the relay server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Deliver an encrypted envelope to the named recipient.
    Send {
        recipient_key: [u8; 32],
        envelope: EncryptedEnvelope,
    },
    /// Fetch queued messages for the authenticated identity.
    Fetch,
    /// Publish or refresh a one-time prekey bundle.
    RegisterPrekeys { prekeys: Vec<[u8; 32]> },
}

/// Messages sent from the relay server to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// One or more envelopes waiting for this client.
    Deliver(Vec<EncryptedEnvelope>),
    /// Acknowledgement that the last Send was accepted.
    Ack,
    /// A structured error from the server.
    Error(ServerError),
}

/// Structured error variants the server may return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerError {
    /// Recipient unknown or has no registered prekeys.
    RecipientNotFound,
    /// The client sent a malformed message.
    BadRequest,
    /// Server-side fault; client may retry.
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        value: &T,
    ) {
        let bytes = postcard::to_allocvec(value).expect("encode");
        let decoded: T = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(*value, decoded);
    }

    #[test]
    fn encrypted_envelope_round_trip() {
        let env = EncryptedEnvelope {
            sender_key: [0xAB; 32],
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        round_trip(&env);
    }

    #[test]
    fn client_message_send_round_trip() {
        let msg = ClientMessage::Send {
            recipient_key: [0x01; 32],
            envelope: EncryptedEnvelope {
                sender_key: [0x02; 32],
                ciphertext: b"hello".to_vec(),
            },
        };
        round_trip(&msg);
    }

    #[test]
    fn client_message_fetch_round_trip() {
        round_trip(&ClientMessage::Fetch);
    }

    #[test]
    fn client_message_register_prekeys_round_trip() {
        let msg = ClientMessage::RegisterPrekeys {
            prekeys: vec![[0xCC; 32], [0xDD; 32]],
        };
        round_trip(&msg);
    }

    #[test]
    fn server_message_deliver_round_trip() {
        let msg = ServerMessage::Deliver(vec![
            EncryptedEnvelope {
                sender_key: [0x10; 32],
                ciphertext: vec![9, 8, 7],
            },
            EncryptedEnvelope {
                sender_key: [0x20; 32],
                ciphertext: vec![],
            },
        ]);
        round_trip(&msg);
    }

    #[test]
    fn server_message_ack_round_trip() {
        round_trip(&ServerMessage::Ack);
    }

    #[test]
    fn server_error_variants_round_trip() {
        round_trip(&ServerMessage::Error(ServerError::RecipientNotFound));
        round_trip(&ServerMessage::Error(ServerError::BadRequest));
        round_trip(&ServerMessage::Error(ServerError::Internal));
    }
}
