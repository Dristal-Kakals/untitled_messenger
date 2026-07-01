use serde::{Deserialize, Serialize};

/// Opaque encrypted envelope relayed by the server. The server never
/// inspects `ciphertext` or `header`; both are produced/consumed by the
/// crypto crate on the client side. `id` is a server-assigned monotonic id
/// used for acknowledgement. `sender` is the sender's identity public key
/// (32-byte Ed25519 verifying key, opaque bytes to the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Server-assigned monotonic id, used for `Ack`.
    pub id: u64,
    /// Sender's long-term identity public key (32 bytes).
    pub sender: [u8; 32],
    /// Double Ratchet / Sender Keys header, opaque to the server.
    pub header: Vec<u8>,
    /// X3DH init message, present only on the first message of a 1:1
    /// session so the receiver can seed a matching ratchet. Opaque to the
    /// server.
    pub init: Option<Vec<u8>>,
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

/// A prekey bundle a client registers with the server and that other
/// clients fetch to start X3DH. All fields are opaque bytes to the server
/// except `identity_pub` (used as the registry key) and `signed_prekey_sig`
/// (verified against `identity_pub` on `Register`). The bundle is the
/// public half only — the server never holds private keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Owner identity public key (32-byte Ed25519 verifying key).
    pub identity_pub: [u8; 32],
    /// Signed prekey id (client-chosen).
    pub signed_prekey_id: u32,
    /// Signed prekey public key (32-byte X25519).
    pub signed_prekey_pub: [u8; 32],
    /// Ed25519 signature over `signed_prekey_pub` by `identity_pub`.
    pub signed_prekey_sig: Vec<u8>,
    /// One-time prekey ids + public keys (32-byte X25519 each).
    pub one_time_prekeys: Vec<(u32, [u8; 32])>,
}

/// Messages sent from a client to the relay server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Register/refresh this client's prekey bundle. The server verifies
    /// `signed_prekey_sig` against `identity_pub` and stores the bundle
    /// keyed by `identity_pub`.
    Register { bundle: PreKeyBundle },
    /// Fetch the stored prekey bundle for `target` identity. The server
    /// replies with `ServerMessage::Bundle(Some(_))`, or `None` if the
    /// target is not registered.
    FetchBundle { target: [u8; 32] },
    /// Deliver an encrypted envelope to each recipient in `recipients`.
    /// The server is group-oblivious: for a 1:1 message `recipients` has
    /// one entry, for a group message every member's identity pub. The
    /// server iterates the list and appends `envelope` to each outbox.
    Send {
        recipients: Vec<[u8; 32]>,
        envelope: EncryptedEnvelope,
    },
    /// Poll for undelivered envelopes addressed to this client since `since`.
    Poll { since: u64 },
    /// Acknowledge delivered envelopes by id; the server drops them.
    Ack { envelope_ids: Vec<u64> },
    /// Long-lived poll: the server pushes new envelopes on this connection.
    Subscribe,
}

/// Messages sent from the relay server to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Response to `FetchBundle`: the target's bundle, or `None` if the
    /// target identity is not registered.
    Bundle(Option<PreKeyBundle>),
    /// Envelopes delivered to this client (response to `Poll`/`Subscribe`).
    Delivered(Vec<EncryptedEnvelope>),
    /// Acknowledgement that `Ack` was processed.
    AckOk,
    /// A structured error from the server.
    Error(ServerError),
}

/// Structured error variants the server may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerError {
    /// `Send` targeted an identity that is not registered.
    UnknownRecipient,
    /// `Register` carried a bad signed-prekey signature.
    InvalidSignature,
    /// The client sent a malformed frame; the connection is closed.
    MalformedFrame,
    /// A frame exceeded the maximum payload size.
    TooLarge,
    /// The client is not registered (e.g. `Poll` before `Register`).
    NotRegistered,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> PreKeyBundle {
        PreKeyBundle {
            identity_pub: [0x11; 32],
            signed_prekey_id: 1,
            signed_prekey_pub: [0x22; 32],
            signed_prekey_sig: vec![0xAB; 64],
            one_time_prekeys: vec![(10, [0x33; 32]), (11, [0x44; 32])],
        }
    }

    fn sample_envelope(id: u64, with_init: bool) -> EncryptedEnvelope {
        EncryptedEnvelope {
            id,
            sender: [0x55; 32],
            header: vec![1, 2, 3, 4],
            init: if with_init { Some(vec![9, 9, 9]) } else { None },
            ciphertext: vec![0xAA; 16],
        }
    }

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        value: &T,
    ) {
        let bytes = postcard::to_allocvec(value).expect("encode");
        let decoded: T = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(*value, decoded);
    }

    #[test]
    fn encrypted_envelope_with_init_round_trips() {
        round_trip(&sample_envelope(42, true));
    }

    #[test]
    fn encrypted_envelope_without_init_round_trips() {
        round_trip(&sample_envelope(43, false));
    }

    #[test]
    fn client_message_register_round_trips() {
        round_trip(&ClientMessage::Register {
            bundle: sample_bundle(),
        });
    }

    #[test]
    fn client_message_fetch_bundle_round_trips() {
        round_trip(&ClientMessage::FetchBundle { target: [0x77; 32] });
    }

    #[test]
    fn client_message_send_single_recipient_round_trips() {
        round_trip(&ClientMessage::Send {
            recipients: vec![[0x77; 32]],
            envelope: sample_envelope(1, true),
        });
    }

    #[test]
    fn client_message_send_group_recipients_round_trips() {
        round_trip(&ClientMessage::Send {
            recipients: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
            envelope: sample_envelope(2, false),
        });
    }

    #[test]
    fn client_message_poll_ack_subscribe_round_trip() {
        round_trip(&ClientMessage::Poll { since: 99 });
        round_trip(&ClientMessage::Ack {
            envelope_ids: vec![1, 2, 3],
        });
        round_trip(&ClientMessage::Subscribe);
    }

    #[test]
    fn server_message_bundle_some_round_trips() {
        round_trip(&ServerMessage::Bundle(Some(sample_bundle())));
    }

    #[test]
    fn server_message_bundle_none_round_trips() {
        round_trip(&ServerMessage::Bundle(None));
    }

    #[test]
    fn server_message_delivered_round_trips() {
        round_trip(&ServerMessage::Delivered(vec![
            sample_envelope(1, false),
            sample_envelope(2, false),
        ]));
    }

    #[test]
    fn server_message_ackok_and_error_round_trip() {
        round_trip(&ServerMessage::AckOk);
        round_trip(&ServerMessage::Error(ServerError::UnknownRecipient));
    }

    #[test]
    fn server_error_variants_distinct() {
        assert_ne!(ServerError::UnknownRecipient, ServerError::InvalidSignature);
        assert_ne!(ServerError::MalformedFrame, ServerError::TooLarge);
        assert_ne!(ServerError::TooLarge, ServerError::NotRegistered);
    }

    #[test]
    fn prekey_bundle_round_trips() {
        round_trip(&sample_bundle());
    }
}
