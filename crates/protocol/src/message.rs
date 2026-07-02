use serde::{Deserialize, Serialize};

/// What kind of ciphertext an `EncryptedEnvelope` carries. The server treats
/// this as opaque metadata (it already infers 1:1-vs-group from the
/// `recipients` list length); the client uses it to route decryption to the
/// right state machine without a destructive trial-and-error decrypt (a failed
/// 1:1 ratchet decrypt would advance the recv chain and skip message keys).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    /// 1:1 Double Ratchet message (`header` = ratchet `Header`, `ciphertext`
    /// = AEAD ciphertext, `init` present on the first message).
    #[default]
    Direct,
    /// Group Sender Keys message (`header` = `GroupHeader`, `ciphertext` =
    /// group AEAD ciphertext, `signature` = sender's Ed25519 signature over
    /// header ‖ ciphertext, `init` always `None`).
    Group,
}

/// Opaque encrypted envelope relayed by the server. The server never
/// inspects `ciphertext`, `header`, or `signature`; all three are produced/
/// consumed by the crypto crate on the client side. `id` is a server-assigned
/// monotonic id used for acknowledgement. `sender` is the sender's identity
/// public key (32-byte Ed25519 verifying key, opaque bytes to the server).
/// `kind` tells the client which decrypt path to take (see `MessageKind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Server-assigned monotonic id, used for `Ack`.
    pub id: u64,
    /// Sender's long-term identity public key (32 bytes).
    pub sender: [u8; 32],
    /// Which decrypt path the client should take. Opaque to the server.
    #[serde(default)]
    pub kind: MessageKind,
    /// Double Ratchet / Sender Keys header, opaque to the server.
    pub header: Vec<u8>,
    /// X3DH init message, present only on the first message of a 1:1
    /// session so the receiver can seed a matching ratchet. Opaque to the
    /// server. Always `None` for `Group` messages.
    pub init: Option<Vec<u8>>,
    /// AEAD ciphertext (1:1) or group AEAD ciphertext (group). Opaque to the
    /// server.
    pub ciphertext: Vec<u8>,
    /// Sender's Ed25519 signature over `header ‖ ciphertext`. Empty for
    /// `Direct` (1:1 auth is via the ratchet's AEAD + DH); the sender's group
    /// signing key signature for `Group`. Opaque to the server.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// A prekey bundle a client registers with the server and that other
/// clients fetch to start X3DH. All fields are opaque bytes to the server
/// except `identity_pub` (used as the registry key) and `signed_prekey_sig`
/// (verified against `identity_pub` on `Register`). The bundle is the
/// public half only — the server never holds private keys.
///
/// `pq_encapsulation_key` / `pq_encapsulation_key_sig` carry an optional
/// ML-KEM-768 encapsulation key + the identity signature over it, enabling
/// hybrid PQXDH. Both are `None` for classical-only clients (backward compat);
/// the server treats them as opaque bytes. `#[serde(default)]` keeps old
/// bundles (registered before PQ support) deserializable.
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
    /// Optional ML-KEM-768 encapsulation key (1184 bytes), for hybrid PQXDH.
    #[serde(default)]
    pub pq_encapsulation_key: Option<Vec<u8>>,
    /// Optional Ed25519 signature over `pq_encapsulation_key` by
    /// `identity_pub`. Present iff `pq_encapsulation_key` is.
    #[serde(default)]
    pub pq_encapsulation_key_sig: Option<Vec<u8>>,
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
    /// Application-level liveness probe. The server replies with
    /// [`ServerMessage::Pong`]. A subscribed connection may legitimately idle
    /// for hours between pushes, so neither side can otherwise tell a live-but-
    /// quiet peer from a half-open one (a NAT/firewall that silently dropped
    /// the path without a FIN — no EOF, no RST, the socket just looks idle).
    /// The client sends `Ping` on a fixed interval and treats a missing `Pong`
    /// within a grace window as a dead link, tearing down and reconnecting so
    /// offline mail is recovered instead of the connection hanging forever.
    /// The server treats `Ping` as a no-op liveness check (no store mutation).
    Ping,
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
    /// Reply to [`ClientMessage::Ping`]. A liveness probe that carries no
    /// data; the client uses its (non-)arrival within a grace window to decide
    /// the connection is half-open and should be torn down.
    Pong,
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
    /// `Send` carried an `envelope.sender` that does not match the connection's
    /// authenticated identity. A connection may only send envelopes it authored;
    /// this blocks a client from impersonating another identity at the relay.
    BadSender,
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
            pq_encapsulation_key: None,
            pq_encapsulation_key_sig: None,
        }
    }

    fn sample_envelope(id: u64, with_init: bool) -> EncryptedEnvelope {
        EncryptedEnvelope {
            id,
            sender: [0x55; 32],
            kind: MessageKind::Direct,
            header: vec![1, 2, 3, 4],
            init: if with_init { Some(vec![9, 9, 9]) } else { None },
            ciphertext: vec![0xAA; 16],
            signature: vec![],
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
    fn encrypted_envelope_group_kind_round_trips() {
        let env = EncryptedEnvelope {
            id: 7,
            sender: [0x55; 32],
            kind: MessageKind::Group,
            header: vec![1, 2, 3, 4],
            init: None,
            ciphertext: vec![0xBB; 16],
            signature: vec![0xCC; 64],
        };
        round_trip(&env);
    }

    #[test]
    fn message_kind_distinct() {
        assert_ne!(MessageKind::Direct, MessageKind::Group);
    }

    #[test]
    fn client_message_poll_ack_subscribe_round_trip() {
        round_trip(&ClientMessage::Poll { since: 99 });
        round_trip(&ClientMessage::Ack {
            envelope_ids: vec![1, 2, 3],
        });
        round_trip(&ClientMessage::Subscribe);
        round_trip(&ClientMessage::Ping);
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
        round_trip(&ServerMessage::Pong);
        round_trip(&ServerMessage::Error(ServerError::UnknownRecipient));
        round_trip(&ServerMessage::Error(ServerError::BadSender));
    }

    #[test]
    fn server_error_variants_distinct() {
        assert_ne!(ServerError::UnknownRecipient, ServerError::InvalidSignature);
        assert_ne!(ServerError::MalformedFrame, ServerError::TooLarge);
        assert_ne!(ServerError::TooLarge, ServerError::NotRegistered);
        assert_ne!(ServerError::BadSender, ServerError::UnknownRecipient);
        assert_ne!(ServerError::BadSender, ServerError::InvalidSignature);
    }

    #[test]
    fn prekey_bundle_round_trips() {
        round_trip(&sample_bundle());
    }

    #[test]
    fn prekey_bundle_with_pq_key_round_trips() {
        let bundle = PreKeyBundle {
            pq_encapsulation_key: Some(vec![0xAB; 1184]),
            pq_encapsulation_key_sig: Some(vec![0xCD; 64]),
            ..sample_bundle()
        };
        round_trip(&bundle);
    }

    #[test]
    fn prekey_bundle_without_pq_fields_decodes_from_classical_toml() {
        // A bundle serialized before PQ support (no pq_* fields) must still
        // deserialize thanks to `#[serde(default)]` — backward compat for
        // in-flight registrations.
        let classical = PreKeyBundle {
            identity_pub: [0x11; 32],
            signed_prekey_id: 1,
            signed_prekey_pub: [0x22; 32],
            signed_prekey_sig: vec![0xAB; 64],
            one_time_prekeys: vec![(10, [0x33; 32])],
            pq_encapsulation_key: None,
            pq_encapsulation_key_sig: None,
        };
        let bytes = postcard::to_allocvec(&classical).unwrap();
        let back: PreKeyBundle = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, classical);
        assert!(back.pq_encapsulation_key.is_none());
    }
}
