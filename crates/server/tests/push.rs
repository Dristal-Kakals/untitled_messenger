//! Integration tests for server Subscribe push over real TCP.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, EncryptedEnvelope, PreKeyBundle, ServerMessage};
use um_server::{listener::serve, Store, Subscribers};

/// A framed client over a raw TcpStream (test helper).
struct TestClient {
    stream: TcpStream,
    read_buf: Vec<u8>,
}

impl TestClient {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }

    async fn send(&mut self, msg: &ClientMessage) {
        let frame = encode(msg).expect("encode");
        self.stream.write_all(&frame).await.expect("write");
    }

    async fn recv(&mut self) -> ServerMessage {
        loop {
            if let Ok((msg, consumed)) = decode::<ServerMessage>(&self.read_buf) {
                self.read_buf.drain(0..consumed);
                return msg;
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await.expect("read");
            assert!(n > 0, "unexpected EOF waiting for server message");
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn real_bundle() -> ([u8; 32], PreKeyBundle) {
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
    (id.verifying.to_bytes(), bundle)
}

fn envelope() -> EncryptedEnvelope {
    EncryptedEnvelope {
        id: 0,
        sender: [0x55; 32],
        kind: um_protocol::MessageKind::Direct,
        header: vec![1, 2, 3],
        init: None,
        ciphertext: vec![0xAA; 8],
        signature: vec![],
    }
}

async fn spawn_server() -> std::net::SocketAddr {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    serve("127.0.0.1:0", store, subs).await.expect("serve")
}

#[tokio::test]
async fn subscribe_receives_push_for_new_message() {
    let addr = spawn_server().await;
    let (alice_pub, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    // Alice sends to bob.
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
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob receives the push without polling.
    let pushed = bob.recv().await;
    match pushed {
        ServerMessage::Delivered(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].sender, alice_pub);
        }
        other => panic!("expected Delivered push, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_flushes_unacked_outbox() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob registers (connection stays open) but has NOT subscribed yet.
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    // Alice sends while bob is registered-but-not-subscribed. The envelope
    // lands in bob's outbox.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Now bob subscribes; the unacked outbox is flushed as Delivered.
    bob.send(&ClientMessage::Subscribe).await;
    // The listener flushes the outbox BEFORE writing the AckOk reply, so
    // Delivered arrives first, then AckOk. Accept either order defensively.
    let first = bob.recv().await;
    let second = bob.recv().await;
    let delivered = match (&first, &second) {
        (ServerMessage::Delivered(_), ServerMessage::AckOk) => &first,
        (ServerMessage::AckOk, ServerMessage::Delivered(_)) => &second,
        other => panic!("expected Delivered + AckOk, got {other:?}"),
    };
    match delivered {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered, got {other:?}"),
    }
}

#[tokio::test]
async fn reconnect_repushes_unacked() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob subscribes and receives a push, but does NOT ack.
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register {
        bundle: bob_bundle.clone(),
    })
    .await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    let _first_push = bob.recv().await; // Delivered, not acked

    // Bob disconnects (drop) and reconnects with the SAME identity pub (the
    // same bundle, which carries the same identity_pub).
    drop(bob);
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    // The unacked envelope is re-pushed on the flush, then AckOk.
    let first = bob.recv().await;
    let second = bob.recv().await;
    let delivered = match (&first, &second) {
        (ServerMessage::Delivered(_), _) => &first,
        (_, ServerMessage::Delivered(_)) => &second,
        other => panic!("expected a Delivered re-push, got {other:?}"),
    };
    match delivered {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered, got {other:?}"),
    }
}

#[tokio::test]
async fn last_subscribe_wins_evicts_old() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob conn1 subscribes.
    let mut bob1 = TestClient::connect(addr).await;
    bob1.send(&ClientMessage::Register {
        bundle: bob_bundle.clone(),
    })
    .await;
    assert!(matches!(bob1.recv().await, ServerMessage::AckOk));
    bob1.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob1.recv().await, ServerMessage::AckOk));

    // Bob conn2 subscribes — evicts conn1.
    let mut bob2 = TestClient::connect(addr).await;
    bob2.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob2.recv().await, ServerMessage::AckOk));
    bob2.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob2.recv().await, ServerMessage::AckOk));

    // conn1's push channel is closed by the eviction; its next recv hits EOF.
    // Give the server a moment to close conn1, then assert EOF.
    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        bob1.stream.read(&mut buf),
    )
    .await;
    match res {
        Ok(Ok(0)) => {} // EOF — expected
        Ok(Ok(_)) => panic!("conn1 should have been closed, got data"),
        Ok(Err(_)) => {} // connection error — also acceptable
        Err(_) => panic!("conn1 read did not resolve (no eviction)"),
    }

    // conn2 still works: alice sends, conn2 gets the push.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    match bob2.recv().await {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered on conn2, got {other:?}"),
    }
}

#[tokio::test]
async fn poll_still_works_alongside_subscribe() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice
        .send(&ClientMessage::Register {
            bundle: alice_bundle,
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle })
        .await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    // Bob receives the push.
    assert!(matches!(bob.recv().await, ServerMessage::Delivered(_)));

    // Bob also polls — the envelope is still in the outbox (not acked).
    bob.send(&ClientMessage::Poll { since: 0 }).await;
    match bob.recv().await {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered from Poll, got {other:?}"),
    }
}
