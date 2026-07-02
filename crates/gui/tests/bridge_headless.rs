//! Headless end-to-end test for the GUI `Bridge` over a real `um_server` on
//! localhost. No iced, no window: the bridge is driven purely through its
//! `Command`/`Event` channels, exactly as the iced app would drive it.
//!
//! This exercises the full GUI→bridge→client→protocol→server stack:
//! - `Connect` registers the bundle + subscribes for push.
//! - `StartSession` fetches the peer bundle (X3DH) and sends the first
//!   Double-Ratchet message.
//! - The recipient bridge receives the push, decrypts, and emits
//!   `Event::Decrypted` with the plaintext.
//! - A reply exercises the established ratchet in both directions.
//!
//! Stores are created in a per-test temp directory (NOT the user's XDG data
//! dir) so the test never pollutes the real home directory. The bridge is
//! constructed with the store already attached (`Bridge::new(session, Some(store), config)`),
//! bypassing `Setup`/`Unlock` which would write to the real XDG paths.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::task::LocalSet;
use um_client::session::ClientSession;
use um_client::Store;
use um_gui::config::Config;
use um_gui::{Bridge, Command, Event};
use um_server::{listener::serve, Store as ServerStore, Subscribers};

/// A unique temp dir per test run: `um-bridge-test-<unix_nanos>-<pid>`.
fn test_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("um-bridge-test-{nanos}-{pid}"))
}

/// Build a bridge with a fresh session + a store created in `dir`, already
/// attached (no Setup/Unlock round trip, no XDG writes). The session is
/// persisted to the store so the bridge's write-through `persist_session`
/// has a key to update. Returns the bridge and its identity pub.
fn make_bridge(dir: &std::path::Path, server_addr: &str) -> (Bridge, [u8; 32]) {
    let session = ClientSession::generate(5);
    let pub_hex = hex::encode(session.identity_pub());
    let path = dir.join(format!("{pub_hex}.db"));
    let store = Store::create(&path, "test-pass").expect("create store");
    store.put("session", &session).expect("persist session");
    let config = Config {
        server_addr: server_addr.to_string(),
        ..Default::default()
    };
    let id_pub = session.identity_pub();
    (Bridge::new(session, Some(store), config), id_pub)
}

/// Spawn a bridge on a `LocalSet` (the bridge owns a `rusqlite::Connection`,
/// which is `!Sync`, so it needs `spawn_local`). Returns the command sender
/// and event receiver.
fn spawn_bridge(bridge: Bridge) -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let handle = bridge.spawn();
    (handle.command_tx, handle.event_rx)
}

/// Drain events from `rx` until a predicate accepts one, or panic after a
/// 10s timeout. An `Event::Error` aborts immediately. Other non-matching
/// events are drained (e.g. a stray `Connected` re-emit).
async fn expect_event<F>(rx: &mut mpsc::Receiver<Event>, mut accept: F) -> Event
where
    F: FnMut(&Event) -> bool,
{
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => panic!("timed out waiting for an accepted event"),
            ev = rx.recv() => match ev {
                Some(ev) if accept(&ev) => return ev,
                Some(Event::Error(e)) => panic!("bridge emitted error: {e}"),
                Some(_) => { /* keep draining until the one we want */ }
                None => panic!("bridge event channel closed before expected event"),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_1to1_round_trip_over_real_server() {
    let dir = test_dir();
    std::fs::create_dir_all(&dir).expect("create test dir");
    // Clean up the test dir when the test ends, regardless of outcome.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    // Spawn the relay on an ephemeral port.
    let store = Arc::new(ServerStore::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs)
        .await
        .expect("serve relay");
    let server_addr = addr.to_string();

    // Both bridges must run on the same LocalSet (spawn_local). Run the whole
    // exchange inside one LocalSet on the multi-thread runtime.
    let local = LocalSet::new();
    local
        .run_until(async move {
            let (alice_bridge, alice_pub) = make_bridge(&dir, &server_addr);
            let (bob_bridge, bob_pub) = make_bridge(&dir, &server_addr);

            let (alice_cmd, mut alice_ev) = spawn_bridge(alice_bridge);
            let (bob_cmd, mut bob_ev) = spawn_bridge(bob_bridge);

            // Connect both bridges: register + subscribe.
            alice_cmd
                .send(Command::Connect { addr })
                .await
                .expect("send alice connect");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;

            bob_cmd
                .send(Command::Connect { addr })
                .await
                .expect("send bob connect");
            expect_event(&mut bob_ev, |e| matches!(e, Event::Connected)).await;

            // Alice starts a session with bob and sends the first message.
            alice_cmd
                .send(Command::StartSession {
                    peer: bob_pub,
                    first_message: "hello from alice".to_string(),
                    local_id: 1,
                })
                .await
                .expect("send alice startsession");
            // Alice sees her own outgoing message confirmed as Sent.
            let sent = expect_event(&mut alice_ev, |e| {
                matches!(e, Event::Sent { local_id: 1, .. })
            })
            .await;
            let alice_sent_text = match sent {
                Event::Sent { msg, .. } => msg.text,
                _ => unreachable!(),
            };
            assert_eq!(alice_sent_text, "hello from alice");

            // Bob receives the push, decrypts, and emits Decrypted.
            let decrypted =
                expect_event(&mut bob_ev, |e| matches!(e, Event::Decrypted { .. })).await;
            match decrypted {
                Event::Decrypted { chat, msg } => {
                    assert_eq!(chat, um_gui::types::ChatId::Peer(alice_pub));
                    assert_eq!(msg.text, "hello from alice");
                    assert_eq!(msg.dir, um_gui::types::Direction::In);
                }
                other => panic!("expected Decrypted, got {other:?}"),
            }

            // Bob replies on the now-established ratchet.
            bob_cmd
                .send(Command::SendMessage {
                    peer: alice_pub,
                    text: "hi back from bob".to_string(),
                    local_id: 2,
                })
                .await
                .expect("send bob reply");
            expect_event(&mut bob_ev, |e| {
                matches!(e, Event::Sent { local_id: 2, .. })
            })
            .await;

            // Alice receives bob's reply.
            let reply = expect_event(&mut alice_ev, |e| matches!(e, Event::Decrypted { .. })).await;
            match reply {
                Event::Decrypted { chat, msg } => {
                    assert_eq!(chat, um_gui::types::ChatId::Peer(bob_pub));
                    assert_eq!(msg.text, "hi back from bob");
                    assert_eq!(msg.dir, um_gui::types::Direction::In);
                }
                other => panic!("expected Decrypted reply, got {other:?}"),
            }

            // Drop command senders so the bridges shut down cleanly.
            drop(alice_cmd);
            drop(bob_cmd);
        })
        .await;
}

/// E2E group exchange through the bridge: Alice founds a group with Bob,
/// Bob is auto-invited (receives the Sender-Key distribution over the 1:1
/// ratchet, imports it, acks his own distribution back), then both can send
/// group messages that the other decrypts. Exercises the full
/// `CreateGroup` → `GroupDist` → `add_group_peer` → `SendGroupMessage` →
/// `receive_group` path through the bridge + real TCP + Subscribe push.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_group_exchange_over_real_server() {
    let dir = test_dir();
    std::fs::create_dir_all(&dir).expect("create test dir");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    let store = Arc::new(ServerStore::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs)
        .await
        .expect("serve relay");
    let server_addr = addr.to_string();

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (alice_bridge, _alice_pub) = make_bridge(&dir, &server_addr);
            let (bob_bridge, bob_pub) = make_bridge(&dir, &server_addr);

            let (alice_cmd, mut alice_ev) = spawn_bridge(alice_bridge);
            let (bob_cmd, mut bob_ev) = spawn_bridge(bob_bridge);

            // Connect both.
            alice_cmd
                .send(Command::Connect { addr })
                .await
                .expect("alice connect");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;
            bob_cmd
                .send(Command::Connect { addr })
                .await
                .expect("bob connect");
            expect_event(&mut bob_ev, |e| matches!(e, Event::Connected)).await;

            // Alice must have a 1:1 session with bob before founding a group
            // (the Sender-Key distribution rides the 1:1 ratchet).
            alice_cmd
                .send(Command::StartSession {
                    peer: bob_pub,
                    first_message: "seed".to_string(),
                    local_id: 1,
                })
                .await
                .expect("alice seed");
            expect_event(&mut alice_ev, |e| {
                matches!(e, Event::Sent { local_id: 1, .. })
            })
            .await;
            // Bob receives the seed (a Chat payload) — drain it.
            expect_event(&mut bob_ev, |e| matches!(e, Event::Decrypted { .. })).await;

            // Alice founds a group with bob as the sole member.
            alice_cmd
                .send(Command::CreateGroup {
                    name: "team".to_string(),
                    members: vec![bob_pub],
                })
                .await
                .expect("alice create group");
            // Alice sees GroupCreated.
            let created =
                expect_event(&mut alice_ev, |e| matches!(e, Event::GroupCreated { .. })).await;
            let group = match created {
                Event::GroupCreated { group, name } => {
                    assert_eq!(name, "team");
                    group
                }
                other => panic!("expected GroupCreated, got {other:?}"),
            };

            // Bob receives the distribution → GroupInvited.
            let invited =
                expect_event(&mut bob_ev, |e| matches!(e, Event::GroupInvited { .. })).await;
            match invited {
                Event::GroupInvited { group: g, name } => {
                    assert_eq!(g, group);
                    assert_eq!(name, "team");
                }
                other => panic!("expected GroupInvited, got {other:?}"),
            }
            // Alice may also receive a GroupInvited when bob's ack-dist lands
            // (the founder path still emits it as a "member joined" signal).
            // Drain any such event on alice's side without asserting.

            // Alice sends a group message; bob decrypts it.
            alice_cmd
                .send(Command::SendGroupMessage {
                    group,
                    text: "group hi from alice".to_string(),
                    local_id: 2,
                })
                .await
                .expect("alice group send");
            expect_event(&mut alice_ev, |e| {
                matches!(e, Event::Sent { local_id: 2, .. })
            })
            .await;
            let alice_group_msg =
                expect_event(&mut bob_ev, |e| matches!(e, Event::Decrypted { .. })).await;
            match alice_group_msg {
                Event::Decrypted { chat, msg } => {
                    assert_eq!(chat, um_gui::types::ChatId::Group(group));
                    assert_eq!(msg.text, "group hi from alice");
                    assert_eq!(msg.dir, um_gui::types::Direction::In);
                }
                other => panic!("expected group Decrypted, got {other:?}"),
            }

            // Bob replies in the group; alice decrypts it.
            bob_cmd
                .send(Command::SendGroupMessage {
                    group,
                    text: "group hi from bob".to_string(),
                    local_id: 3,
                })
                .await
                .expect("bob group send");
            expect_event(&mut bob_ev, |e| {
                matches!(e, Event::Sent { local_id: 3, .. })
            })
            .await;
            let bob_group_msg =
                expect_event(&mut alice_ev, |e| matches!(e, Event::Decrypted { .. })).await;
            match bob_group_msg {
                Event::Decrypted { chat, msg } => {
                    assert_eq!(chat, um_gui::types::ChatId::Group(group));
                    assert_eq!(msg.text, "group hi from bob");
                    assert_eq!(msg.dir, um_gui::types::Direction::In);
                }
                other => panic!("expected group Decrypted reply, got {other:?}"),
            }

            drop(alice_cmd);
            drop(bob_cmd);
        })
        .await;
}

/// Regression test for offline-mail recovery on reconnect.
///
/// The server flushes the unacked outbox as `Delivered` frames *before* the
/// Subscribe `AckOk`. The bridge must decrypt + persist those frames during
/// the Subscribe handshake (not discard them), so mail that arrived while the
/// recipient was offline is recovered when it reconnects. Before the fix,
/// `drain_until_ack` discarded the flush → silent data loss on every
/// reconnect.
///
/// Flow: bob connects + registers + subscribes (so the server knows his
/// bundle), then disconnects. Alice starts a 1:1 session (X3DH against bob's
/// registered bundle) and sends the first message while bob is OFFLINE — the
/// server holds it in bob's outbox (no live subscriber). Bob reconnects with
/// his persisted session: the Subscribe flush delivers the offline envelope,
/// the bridge decrypts it during the handshake, and emits `Event::Decrypted`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_reconnect_recovers_offline_mail() {
    let dir = test_dir();
    std::fs::create_dir_all(&dir).expect("create test dir");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    let store = Arc::new(ServerStore::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", store, subs)
        .await
        .expect("serve relay");
    let server_addr = addr.to_string();

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (alice_bridge, alice_pub) = make_bridge(&dir, &server_addr);
            let (bob_bridge, bob_pub) = make_bridge(&dir, &server_addr);

            let (alice_cmd, mut alice_ev) = spawn_bridge(alice_bridge);
            let (bob_cmd, mut bob_ev) = spawn_bridge(bob_bridge);

            // Both connect + register + subscribe so the server has both
            // bundles and can route.
            alice_cmd
                .send(Command::Connect { addr })
                .await
                .expect("alice connect");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;
            bob_cmd
                .send(Command::Connect { addr })
                .await
                .expect("bob connect");
            expect_event(&mut bob_ev, |e| matches!(e, Event::Connected)).await;

            // Bob goes OFFLINE now: drop his bridge so the server loses his
            // live subscriber (the bundle stays registered). Any pending
            // events are discarded — we have not sent him anything yet.
            drop(bob_cmd);
            drop(bob_ev);
            // Let the old bridge task wind down + the server observe the
            // closed connection (subscriber unregistered on EOF).
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;

            // Alice starts a 1:1 session with bob (X3DH against his registered
            // bundle) and sends the first message — while bob is offline. The
            // server has no live subscriber for bob, so the envelope sits in
            // bob's outbox.
            alice_cmd
                .send(Command::StartSession {
                    peer: bob_pub,
                    first_message: "offline-mail".to_string(),
                    local_id: 1,
                })
                .await
                .expect("alice offline send");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Sent { local_id: 1, .. })).await;

            // Bob reconnects with a fresh bridge built from the SAME persisted
            // session (the session was persisted at Setup time by make_bridge,
            //so the ratchet state is the pre-receive state and the offline
            // envelope — bob's first received message — decrypts via X3DH).
            let bob_pub_hex = hex::encode(bob_pub);
            let path = dir.join(format!("{bob_pub_hex}.db"));
            let store = Store::open(&path, "test-pass").expect("reopen bob store");
            let session: ClientSession = store.get("session").expect("load session").unwrap();
            let config = Config {
                server_addr: server_addr.to_string(),
                ..Default::default()
            };
            let bob_bridge2 = Bridge::new(session, Some(store), config);
            let (bob_cmd2, mut bob_ev2) = spawn_bridge(bob_bridge2);
            bob_cmd2
                .send(Command::Connect { addr })
                .await
                .expect("bob reconnect");

            // Collect every event from the reconnect. The Subscribe flush
            // emits `Event::Decrypted` for the offline envelope BEFORE
            // `Event::Connected`, so we must not drain-and-discard while
            // waiting for Connected — collect them all in one pass.
            let mut recovered = Vec::new();
            let mut saw_connected = false;
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(10));
            tokio::pin!(deadline);
            loop {
                if saw_connected && recovered.iter().any(|t| t == "offline-mail") {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = &mut deadline => break,
                    ev = bob_ev2.recv() => match ev {
                        Some(Event::Decrypted { chat, msg }) => {
                            if chat == um_gui::types::ChatId::Peer(alice_pub) {
                                recovered.push(msg.text);
                            }
                        }
                        Some(Event::Connected) => { saw_connected = true; }
                        Some(Event::Error(e)) => panic!("reconnect bridge error: {e}"),
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            assert!(saw_connected, "reconnect never reported Connected");
            assert!(
                recovered.iter().any(|t| t == "offline-mail"),
                "offline mail not recovered; got {recovered:?} — outbox flush was dropped on reconnect"
            );

            drop(alice_cmd);
            drop(bob_cmd2);
        })
        .await;
}
