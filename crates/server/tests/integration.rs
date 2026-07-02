//! Integration test: spin up the server on an ephemeral port, two mock
//! clients register + exchange, assert envelope delivery + ack removal +
//! bundle fetch + signature rejection.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
use um_protocol::{
    framing::{decode, encode},
    ClientMessage, EncryptedEnvelope, PreKeyBundle, ServerMessage,
};
use um_server::{listener::serve, Store, Subscribers};

/// A minimal framed TCP client for tests.
struct TestClient {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    buf: Vec<u8>,
}

impl TestClient {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (r, w) = stream.into_split();
        Self {
            reader: BufReader::new(r),
            writer: w,
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, msg: &ClientMessage) {
        let frame = encode(msg).expect("encode");
        self.writer.write_all(&frame).await.expect("write");
    }

    /// Read one ServerMessage. Returns None on EOF.
    async fn recv(&mut self) -> Option<ServerMessage> {
        loop {
            if let Ok((msg, consumed)) = decode::<ServerMessage>(&self.buf) {
                self.buf.drain(0..consumed);
                return Some(msg);
            }
            let mut chunk = [0u8; 4096];
            let n = self.reader.read(&mut chunk).await.expect("read");
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Build a real signed protocol bundle from a fresh identity.
fn real_bundle() -> (IdentityKey, PreKeyBundle) {
    let id = IdentityKey::generate();
    let spk = SignedPreKey::generate(1, &id);
    let otpk = OneTimePreKey::generate(10);
    let crypto_bundle = um_crypto::identity::PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
    let bundle = PreKeyBundle {
        identity_pub: id.verifying.to_bytes(),
        signed_prekey_id: crypto_bundle.signed_prekey_id,
        signed_prekey_pub: crypto_bundle.signed_prekey_pub.to_bytes(),
        signed_prekey_sig: crypto_bundle.signed_prekey_sig.to_bytes().to_vec(),
        one_time_prekeys: crypto_bundle
            .one_time_prekeys
            .iter()
            .map(|(k, v)| (*k, v.to_bytes()))
            .collect(),
    };
    (id, bundle)
}

/// Build an envelope claiming to be from `sender`. The Send arm checks
/// `envelope.sender == self_id`, so a test driving `Send` as `alice` must pass
/// `alice_pub` here.
fn envelope_from(sender: [u8; 32]) -> EncryptedEnvelope {
    EncryptedEnvelope {
        id: 0, // server assigns
        sender,
        kind: um_protocol::MessageKind::Direct,
        header: vec![1, 2, 3],
        init: None,
        ciphertext: vec![0xAA; 8],
        signature: vec![],
    }
}

#[tokio::test]
async fn register_send_poll_ack_round_trip() {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store.clone(), subs)
        .await
        .expect("serve");

    let (alice_id, alice_bundle) = real_bundle();
    let (bob_id, bob_bundle) = real_bundle();
    let alice_pub = alice_id.verifying.to_bytes();
    let bob_pub = bob_id.verifying.to_bytes();

    // Alice registers.
    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, Some(ServerMessage::AckOk)));

    // Bob registers.
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob.recv().await, Some(ServerMessage::AckOk)));

    // Alice fetches Bob's bundle.
    alice
        .send(&ClientMessage::FetchBundle { target: bob_pub })
        .await;
    match alice.recv().await {
        Some(ServerMessage::Bundle(Some(b))) => assert_eq!(b.identity_pub, bob_pub),
        other => panic!("expected Bundle(Some), got {other:?}"),
    }

    // Alice sends an envelope to Bob.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: EncryptedEnvelope {
                id: 0,
                sender: alice_pub,
                kind: um_protocol::MessageKind::Direct,
                header: vec![1, 2, 3],
                init: None,
                ciphertext: vec![0xAA; 8],
                signature: vec![],
            },
        })
        .await;
    assert!(matches!(alice.recv().await, Some(ServerMessage::AckOk)));

    // Bob polls and receives one envelope.
    bob.send(&ClientMessage::Poll { since: 0 }).await;
    let polled = match bob.recv().await {
        Some(ServerMessage::Delivered(v)) => v,
        other => panic!("expected Delivered, got {other:?}"),
    };
    assert_eq!(polled.len(), 1);
    let env_id = polled[0].id;
    assert_eq!(polled[0].sender, alice_pub);

    // Bob acks; the server drops it.
    bob.send(&ClientMessage::Ack {
        envelope_ids: vec![env_id],
    })
    .await;
    assert!(matches!(bob.recv().await, Some(ServerMessage::AckOk)));
    // Re-poll: nothing left.
    bob.send(&ClientMessage::Poll { since: 0 }).await;
    match bob.recv().await {
        Some(ServerMessage::Delivered(v)) => assert!(v.is_empty()),
        other => panic!("expected empty Delivered, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_bundle_for_unregistered_returns_none() {
    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let (_, bundle) = real_bundle();
    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle }).await;
    let _ = alice.recv().await; // AckOk

    alice
        .send(&ClientMessage::FetchBundle { target: [0xFF; 32] })
        .await;
    assert!(matches!(
        alice.recv().await,
        Some(ServerMessage::Bundle(None))
    ));
}

#[tokio::test]
async fn send_to_unregistered_recipient_errors() {
    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let (alice_id, bundle) = real_bundle();
    let alice_pub = alice_id.verifying.to_bytes();
    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle }).await;
    let _ = alice.recv().await; // AckOk

    alice
        .send(&ClientMessage::Send {
            recipients: vec![[0xFF; 32]],
            envelope: envelope_from(alice_pub),
        })
        .await;
    assert!(matches!(
        alice.recv().await,
        Some(ServerMessage::Error(
            um_protocol::ServerError::UnknownRecipient
        ))
    ));
}

#[tokio::test]
async fn bad_signature_register_rejected() {
    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let (_, mut bundle) = real_bundle();
    bundle.signed_prekey_sig[0] ^= 0xFF; // corrupt
    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle }).await;
    assert!(matches!(
        alice.recv().await,
        Some(ServerMessage::Error(
            um_protocol::ServerError::InvalidSignature
        ))
    ));
}

#[tokio::test]
async fn poll_before_register_errors() {
    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let mut alice = TestClient::connect(addr).await;
    // Poll without registering first.
    alice.send(&ClientMessage::Poll { since: 0 }).await;
    // The server rejects a non-Register first frame by closing the
    // connection (best-effort error then close). Expect EOF or an error.
    let msg = alice.recv().await;
    assert!(
        msg.is_none()
            || matches!(
                msg,
                Some(ServerMessage::Error(
                    um_protocol::ServerError::NotRegistered
                ))
            ),
        "expected close or NotRegistered, got {msg:?}"
    );
}

/// A frame whose 4-byte length header claims more than `MAX_FRAME_SIZE` bytes
/// must be rejected with `ServerError::TooLarge` (then the connection closes).
/// Before the fix the server lumped this into the generic malformed-frame arm
/// and silently closed, so the client saw a bare EOF and the `TooLarge` variant
/// was dead code on the wire.
#[tokio::test]
async fn oversized_frame_rejected_with_too_large() {
    use um_protocol::framing::MAX_FRAME_SIZE;

    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let mut alice = TestClient::connect(addr).await;
    // Craft a length header claiming MAX_FRAME_SIZE + 1 bytes, followed by a
    // few junk bytes (the server reads the header, rejects, and never reads the
    // claimed body).
    let len = (MAX_FRAME_SIZE + 1) as u32;
    let mut bad = Vec::new();
    bad.extend_from_slice(&len.to_be_bytes());
    bad.extend_from_slice(&[0u8; 8]);
    alice.writer.write_all(&bad).await.expect("write bad frame");

    // The server must reply with Error(TooLarge) before closing.
    let msg = alice.recv().await;
    assert!(
        matches!(
            msg,
            Some(ServerMessage::Error(um_protocol::ServerError::TooLarge))
        ),
        "expected Error(TooLarge), got {msg:?}"
    );
}

/// A complete-length frame whose body is not a valid postcard `ClientMessage`
/// must be rejected with `ServerError::MalformedFrame` (then the connection
/// closes). The length header is honest (matches the junk body length) so the
/// frame is fully read and the failure is purely a deserialize error — the
/// `MalformedFrame` path, distinct from `TooLarge`.
#[tokio::test]
async fn malformed_frame_rejected_with_malformed_frame() {
    let store = Arc::new(Store::new());
    let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
        .await
        .expect("serve");

    let mut alice = TestClient::connect(addr).await;
    // An honest length header wrapping bytes that are not a valid ClientMessage
    // encoding (postcard will reject this variant tag).
    let junk = [0xFFu8; 16];
    let mut bad = Vec::new();
    bad.extend_from_slice(&(junk.len() as u32).to_be_bytes());
    bad.extend_from_slice(&junk);
    alice.writer.write_all(&bad).await.expect("write bad frame");

    let msg = alice.recv().await;
    assert!(
        matches!(
            msg,
            Some(ServerMessage::Error(
                um_protocol::ServerError::MalformedFrame
            ))
        ),
        "expected Error(MalformedFrame), got {msg:?}"
    );
}
