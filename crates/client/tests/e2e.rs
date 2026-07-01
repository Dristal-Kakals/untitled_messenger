//! End-to-end smoke test: spawn the relay, run two headless client sessions
//! over real TCP, exchange real Double-Ratchet-encrypted messages, and assert
//! the decrypted plaintext matches. This exercises the full stack —
//! `um_crypto` (X3DH + Double Ratchet), `um_protocol` (framing), `um_server`
//! (relay dispatch), and `um_client` (session + net) — exactly as the spec's
//! "E2E smoke test" describes. No GUI, no iced; headless only.

use std::sync::Arc;
use um_client::net::Client;
use um_client::session::ClientSession;
use um_protocol::{ClientMessage, ServerMessage};
use um_server::{listener::serve, Store, Subscribers};

/// Register a session's prekey bundle over a fresh TCP connection and wait
/// for the server's `AckOk`. The relay requires `Register` as the first frame
/// on every connection, so this must precede any other exchange.
async fn register(client: &mut Client, session: &ClientSession) {
    client
        .send_msg(&ClientMessage::Register {
            bundle: session.registration_bundle(),
        })
        .await
        .expect("send register");
    match client.recv_msg().await.expect("recv register") {
        Some(ServerMessage::AckOk) => {}
        other => panic!("expected AckOk for register, got {other:?}"),
    }
}

/// Fetch the bundle for `target` over `client`, returning the parsed bundle.
async fn fetch_bundle(client: &mut Client, target: [u8; 32]) -> um_protocol::PreKeyBundle {
    client
        .send_msg(&ClientMessage::FetchBundle { target })
        .await
        .expect("send fetch");
    match client.recv_msg().await.expect("recv fetch") {
        Some(ServerMessage::Bundle(Some(b))) => b,
        Some(ServerMessage::Bundle(None)) => panic!("bundle for target not registered"),
        other => panic!("expected Bundle, got {other:?}"),
    }
}

/// Send an envelope to `recipients` and wait for `AckOk`.
async fn send_envelope(
    client: &mut Client,
    recipients: Vec<[u8; 32]>,
    env: um_protocol::EncryptedEnvelope,
) {
    client
        .send_msg(&ClientMessage::Send {
            recipients,
            envelope: env,
        })
        .await
        .expect("send envelope");
    match client.recv_msg().await.expect("recv send") {
        Some(ServerMessage::AckOk) => {}
        other => panic!("expected AckOk for send, got {other:?}"),
    }
}

/// Poll for envelopes addressed to this client since `since`. Returns the
/// delivered vector.
async fn poll(client: &mut Client, since: u64) -> Vec<um_protocol::EncryptedEnvelope> {
    client
        .send_msg(&ClientMessage::Poll { since })
        .await
        .expect("send poll");
    match client.recv_msg().await.expect("recv poll") {
        Some(ServerMessage::Delivered(v)) => v,
        other => panic!("expected Delivered, got {other:?}"),
    }
}

/// Ack a set of envelope ids and wait for `AckOk`.
async fn ack(client: &mut Client, ids: Vec<u64>) {
    client
        .send_msg(&ClientMessage::Ack { envelope_ids: ids })
        .await
        .expect("send ack");
    match client.recv_msg().await.expect("recv ack") {
        Some(ServerMessage::AckOk) => {}
        other => panic!("expected AckOk for ack, got {other:?}"),
    }
}

/// Full E2E flow: Alice and Bob register, Alice fetches Bob's bundle, runs
/// X3DH, sends "hi" (first message carries the init), Bob polls + decrypts,
/// acks; Alice sends a follow-up "second"; Bob replies "yo" and Alice
/// decrypts it. Asserts plaintext at every hop and that ack removes the
/// envelope from the outbox.
#[tokio::test]
async fn e2e_full_exchange_decrypts_end_to_end() {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs).await.expect("serve");

    let mut alice_session = ClientSession::generate(5);
    let mut bob_session = ClientSession::generate(5);
    let alice_pub = alice_session.identity_pub();
    let bob_pub = bob_session.identity_pub();

    let mut alice = Client::connect(addr).await.expect("alice connect");
    let mut bob = Client::connect(addr).await.expect("bob connect");

    register(&mut alice, &alice_session).await;
    register(&mut bob, &bob_session).await;

    // Alice fetches Bob's bundle from the relay.
    let bob_bundle = fetch_bundle(&mut alice, bob_pub).await;
    assert_eq!(bob_bundle.identity_pub, bob_pub);

    // Alice starts a session (X3DH) and sends the first message. The envelope
    // carries the X3DH init so Bob can seed his matching ratchet.
    let env1 = alice_session
        .start_session(&bob_bundle, b"hi")
        .expect("alice start_session");
    assert!(env1.init.is_some(), "first message must carry the init");
    send_envelope(&mut alice, vec![bob_pub], env1).await;

    // Bob polls and decrypts.
    let delivered1 = poll(&mut bob, 0).await;
    assert_eq!(delivered1.len(), 1, "bob should receive one envelope");
    assert_eq!(delivered1[0].sender, alice_pub);
    let env1_id = delivered1[0].id;
    let (pt1, sender1) = bob_session
        .receive(&delivered1[0])
        .expect("bob receive first");
    assert_eq!(pt1, b"hi", "decrypted plaintext must match");
    assert_eq!(sender1, alice_pub);

    // Bob acks; the server drops the envelope from his outbox.
    ack(&mut bob, vec![env1_id]).await;
    let re_polled = poll(&mut bob, 0).await;
    assert!(
        re_polled.is_empty(),
        "ack must remove the envelope from the outbox"
    );

    // Follow-up: Alice sends a second message (no init).
    let env2 = alice_session
        .send(&bob_pub, b"second")
        .expect("alice send follow-up");
    assert!(env2.init.is_none(), "follow-up must not carry an init");
    send_envelope(&mut alice, vec![bob_pub], env2).await;

    let delivered2 = poll(&mut bob, env1_id).await;
    assert_eq!(delivered2.len(), 1, "bob should receive the follow-up");
    let (pt2, _) = bob_session
        .receive(&delivered2[0])
        .expect("bob receive follow-up");
    assert_eq!(pt2, b"second");

    // Bidirectional: Bob replies to Alice. Bob now has a ratchet with Alice
    // (seeded when he received env1), so he can send directly.
    let env3 = bob_session.send(&alice_pub, b"yo").expect("bob send reply");
    send_envelope(&mut bob, vec![alice_pub], env3).await;

    let delivered3 = poll(&mut alice, 0).await;
    assert_eq!(delivered3.len(), 1, "alice should receive bob's reply");
    let (pt3, sender3) = alice_session
        .receive(&delivered3[0])
        .expect("alice receive reply");
    assert_eq!(pt3, b"yo");
    assert_eq!(sender3, bob_pub);
}

/// A longer back-and-forth: alternating messages in both directions, all
/// decrypting correctly through the ratchet's send/recv chains.
#[tokio::test]
async fn e2e_alternating_messages_stay_in_sync() {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs).await.expect("serve");

    let mut alice_session = ClientSession::generate(5);
    let mut bob_session = ClientSession::generate(5);
    let alice_pub = alice_session.identity_pub();
    let bob_pub = bob_session.identity_pub();

    let mut alice = Client::connect(addr).await.expect("alice connect");
    let mut bob = Client::connect(addr).await.expect("bob connect");
    register(&mut alice, &alice_session).await;
    register(&mut bob, &bob_session).await;

    let bob_bundle = fetch_bundle(&mut alice, bob_pub).await;

    // Seed the session with Alice's first message.
    let env = alice_session
        .start_session(&bob_bundle, b"a1")
        .expect("start");
    send_envelope(&mut alice, vec![bob_pub], env).await;
    let d = poll(&mut bob, 0).await;
    let (pt, _) = bob_session.receive(&d[0]).expect("recv a1");
    assert_eq!(pt, b"a1");
    let mut last_bob = d[0].id;
    // Alice has seen nothing yet.
    let mut last_alice: u64 = 0;

    // Alternating a2/b1/a3/b2 — each side's ratchet advances independently.
    let rounds: [(&[u8], &[u8]); 3] = [(b"a2", b"b1"), (b"a3", b"b2"), (b"a4", b"b3")];
    for (a_msg, b_msg) in rounds {
        // Alice -> Bob.
        let env_a = alice_session.send(&bob_pub, a_msg).expect("alice send");
        send_envelope(&mut alice, vec![bob_pub], env_a).await;
        let da = poll(&mut bob, last_bob).await;
        assert_eq!(da.len(), 1);
        let (pt_a, _) = bob_session.receive(&da[0]).expect("bob recv");
        assert_eq!(pt_a, a_msg);
        last_bob = da[0].id;

        // Bob -> Alice.
        let env_b = bob_session.send(&alice_pub, b_msg).expect("bob send");
        send_envelope(&mut bob, vec![alice_pub], env_b).await;
        let db = poll(&mut alice, last_alice).await;
        assert_eq!(db.len(), 1);
        let (pt_b, _) = alice_session.receive(&db[0]).expect("alice recv");
        assert_eq!(pt_b, b_msg);
        last_alice = db[0].id;
    }
}
