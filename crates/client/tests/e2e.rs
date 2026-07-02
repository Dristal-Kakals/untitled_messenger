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
use um_server::{Store, Subscribers, listener::serve};

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
    // The relay must carry Bob's PQ encapsulation key + signature through the
    // Bundle fetch unchanged — this is the hybrid PQXDH precondition.
    assert!(
        bob_bundle.pq_encapsulation_key.is_some(),
        "fetched bundle must carry the PQ encapsulation key"
    );
    assert!(bob_bundle.pq_encapsulation_key_sig.is_some());

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

/// E2E group exchange over real TCP. Three members register, each fetches the
/// others' bundles, they establish pairwise 1:1 ratchets, then found a group
/// and distribute their Sender Key states to each other *over those 1:1
/// ratchets* (as the spec requires). Finally any member's group message
/// decrypts for both peers through the relay.
///
/// Distribution payloads are carried as the plaintext of 1:1 ratchet messages;
/// the receiver decrypts the 1:1 envelope, then feeds the recovered typed
/// `SenderKeyState` into its group session. This mirrors how a real client
/// transports sender-key distribution without a dedicated wire message.
#[tokio::test]
async fn e2e_group_three_members_decrypt_each_other() {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs).await.expect("serve");

    let mut sa = ClientSession::generate(5);
    let mut sb = ClientSession::generate(5);
    let mut sc = ClientSession::generate(5);
    let pa = sa.identity_pub();
    let pb = sb.identity_pub();
    let pc = sc.identity_pub();

    let mut ca = Client::connect(addr).await.expect("a connect");
    let mut cb = Client::connect(addr).await.expect("b connect");
    let mut cc = Client::connect(addr).await.expect("c connect");
    register(&mut ca, &sa).await;
    register(&mut cb, &sb).await;
    register(&mut cc, &sc).await;

    // Establish pairwise 1:1 sessions. A fetches B and C; B fetches C. Each
    // first 1:1 message carries the X3DH init so the peer seeds a ratchet.
    // Each delivered envelope is acked right after it is consumed, so a later
    // poll never re-delivers an already-processed envelope (which would desync
    // the ratchet recv chain).
    let bundle_b = fetch_bundle(&mut ca, pb).await;
    let bundle_c = fetch_bundle(&mut ca, pc).await;
    let bundle_c_for_b = fetch_bundle(&mut cb, pc).await;

    // A -> B: seed + a throwaway first message.
    let env = sa
        .start_session(&bundle_b, b"a->b seed")
        .expect("a start b");
    send_envelope(&mut ca, vec![pb], env).await;
    let d = poll(&mut cb, 0).await;
    sb.receive(&d[0]).expect("b recv seed");
    ack(&mut cb, vec![d[0].id]).await;

    // A -> C: seed.
    let env = sa
        .start_session(&bundle_c, b"a->c seed")
        .expect("a start c");
    send_envelope(&mut ca, vec![pc], env).await;
    let d = poll(&mut cc, 0).await;
    sc.receive(&d[0]).expect("c recv seed");
    ack(&mut cc, vec![d[0].id]).await;

    // B -> C: seed.
    let env = sb
        .start_session(&bundle_c_for_b, b"b->c seed")
        .expect("b start c");
    send_envelope(&mut cb, vec![pc], env).await;
    let d = poll(&mut cc, 0).await;
    sc.receive(&d[0]).expect("c recv b seed");
    ack(&mut cc, vec![d[0].id]).await;

    // Found the group on every member.
    let gid = [0x42; 32];
    sa.create_group(gid).expect("a create group");
    sb.create_group(gid).expect("b create group");
    sc.create_group(gid).expect("c create group");

    // Helper: ship one member's distribution state to a peer over their 1:1
    // ratchet. The state is postcard-encoded as the 1:1 plaintext; the
    // receiver decrypts, decodes it, and acks so a later poll never
    // re-delivers it.
    async fn ship_distribution(
        sender_net: &mut Client,
        sender_sess: &mut ClientSession,
        to_pub: [u8; 32],
        recv_net: &mut Client,
        recv_sess: &mut ClientSession,
        gid: [u8; 32],
    ) {
        let state = sender_sess.group_distribution(&gid).expect("dist");
        let bytes = postcard::to_allocvec(&state).expect("encode dist");
        let env = sender_sess.send(&to_pub, &bytes).expect("send dist");
        send_envelope(sender_net, vec![to_pub], env).await;
        let d = poll(recv_net, 0).await;
        let (pt, _) = recv_sess.receive(&d[0]).expect("recv dist");
        ack(recv_net, vec![d[0].id]).await;
        let state: um_crypto::sender_keys::SenderKeyState =
            postcard::from_bytes(&pt).expect("decode dist");
        recv_sess.add_group_peer(&gid, state).expect("add peer");
    }

    // Full-mesh distribution: each member sends its state to the other two.
    ship_distribution(&mut ca, &mut sa, pb, &mut cb, &mut sb, gid).await; // a->b
    ship_distribution(&mut ca, &mut sa, pc, &mut cc, &mut sc, gid).await; // a->c
    ship_distribution(&mut cb, &mut sb, pa, &mut ca, &mut sa, gid).await; // b->a
    ship_distribution(&mut cb, &mut sb, pc, &mut cc, &mut sc, gid).await; // b->c
    ship_distribution(&mut cc, &mut sc, pa, &mut ca, &mut sa, gid).await; // c->a
    ship_distribution(&mut cc, &mut sc, pb, &mut cb, &mut sb, gid).await; // c->b

    // A sends a group message fanned out to B and C. Both decrypt it.
    let genv = sa.send_group(&gid, b"hello group").expect("a group send");
    assert_eq!(genv.kind, um_protocol::MessageKind::Group);
    let recipients = vec![pb, pc];
    send_envelope(&mut ca, recipients, genv).await;

    let db = poll(&mut cb, 0).await;
    assert_eq!(db.len(), 1);
    let (ptb, sb_sender) = sb.receive(&db[0]).expect("b group recv");
    assert_eq!(ptb, b"hello group");
    assert_eq!(sb_sender, pa);
    ack(&mut cb, vec![db[0].id]).await;

    let dc = poll(&mut cc, 0).await;
    assert_eq!(dc.len(), 1);
    let (ptc, sc_sender) = sc.receive(&dc[0]).expect("c group recv");
    assert_eq!(ptc, b"hello group");
    assert_eq!(sc_sender, pa);
    ack(&mut cc, vec![dc[0].id]).await;

    // B replies to the group; A and C decrypt.
    let genv2 = sb.send_group(&gid, b"hi from b").expect("b group send");
    send_envelope(&mut cb, vec![pa, pc], genv2).await;
    let da = poll(&mut ca, 0).await;
    assert_eq!(da.len(), 1);
    let (pta, _) = sa.receive(&da[0]).expect("a group recv");
    assert_eq!(pta, b"hi from b");
    ack(&mut ca, vec![da[0].id]).await;
    let dc2 = poll(&mut cc, 0).await;
    assert_eq!(dc2.len(), 1);
    let (ptc2, _) = sc.receive(&dc2[0]).expect("c group recv b");
    assert_eq!(ptc2, b"hi from b");
}

/// Hybrid PQXDH end-to-end over real TCP. Two clients register hybrid bundles
/// (ML-KEM-768 encapsulation key advertised), Alice fetches Bob's bundle from
/// the relay, runs hybrid X3DH (encapsulating to Bob's PQ key), sends the first
/// message, Bob decapsulates + decrypts. Asserts the PQ fields survive the
/// relay round trip and the hybrid root key is established on both sides — the
/// full post-quantum path through the network stack, not just the crypto unit.
#[tokio::test]
async fn e2e_hybrid_pqxdh_over_tcp() {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs).await.expect("serve");

    let mut alice_session = ClientSession::generate(3);
    let mut bob_session = ClientSession::generate(3);
    let alice_pub = alice_session.identity_pub();
    let bob_pub = bob_session.identity_pub();

    let mut alice = Client::connect(addr).await.expect("alice connect");
    let mut bob = Client::connect(addr).await.expect("bob connect");
    register(&mut alice, &alice_session).await;
    register(&mut bob, &bob_session).await;

    // Bob's bundle must arrive at Alice with the PQ fields intact.
    let bob_bundle = fetch_bundle(&mut alice, bob_pub).await;
    let pq_ek = bob_bundle
        .pq_encapsulation_key
        .as_ref()
        .expect("relay must deliver PQ encapsulation key");
    assert_eq!(pq_ek.len(), um_crypto::EK_768_LEN);
    assert!(bob_bundle.pq_encapsulation_key_sig.is_some());

    // Hybrid X3DH: Alice encapsulates to Bob's PQ key during initiate.
    let env = alice_session
        .start_session(&bob_bundle, b"pq hello")
        .expect("alice hybrid start");
    assert!(env.init.is_some(), "first message must carry the X3DH init");
    send_envelope(&mut alice, vec![bob_pub], env).await;

    // Bob decapsulates + decrypts via the hybrid receive path.
    let d = poll(&mut bob, 0).await;
    assert_eq!(d.len(), 1);
    let (pt, sender) = bob_session.receive(&d[0]).expect("bob hybrid recv");
    assert_eq!(pt, b"pq hello");
    assert_eq!(sender, alice_pub);
    ack(&mut bob, vec![d[0].id]).await;

    // Follow-up on the established (hybrid-rooted) ratchet.
    let env2 = alice_session
        .send(&bob_pub, b"pq second")
        .expect("alice follow-up");
    send_envelope(&mut alice, vec![bob_pub], env2).await;
    let d2 = poll(&mut bob, d[0].id).await;
    assert_eq!(d2.len(), 1);
    let (pt2, _) = bob_session.receive(&d2[0]).expect("bob follow-up");
    assert_eq!(pt2, b"pq second");
}
