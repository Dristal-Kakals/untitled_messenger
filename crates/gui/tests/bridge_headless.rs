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
use um_client::Store;
use um_client::session::ClientSession;
use um_gui::config::Config;
use um_gui::{Bridge, Command, Event};
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};
use um_server::{Store as ServerStore, Subscribers, listener::serve};

/// A unique temp dir per test run: `um-bridge-test-<unix_nanos>-<pid>`.
fn test_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
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
            () = &mut deadline => panic!("timed out waiting for an accepted event"),
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
                Event::GroupCreated {
                    group,
                    name,
                    members,
                } => {
                    assert_eq!(name, "team");
                    // Alice founded a group with bob as the sole invitee;
                    // member count = invitees (1) + founder (1) = 2.
                    assert_eq!(members, 2, "GroupCreated member count = invitees + founder");
                    group
                }
                other => panic!("expected GroupCreated, got {other:?}"),
            };

            // Bob receives the distribution → GroupInvited.
            let invited =
                expect_event(&mut bob_ev, |e| matches!(e, Event::GroupInvited { .. })).await;
            match invited {
                Event::GroupInvited {
                    group: g,
                    name,
                    members,
                } => {
                    assert_eq!(g, group);
                    assert_eq!(name, "team");
                    // Bob's roster at invite time = {alice} (the inviter) →
                    // count = roster (1) + self (1) = 2.
                    assert_eq!(members, 2, "GroupInvited member count = inviter + self");
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
                server_addr: server_addr.clone(),
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
                    () = &mut deadline => break,
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

/// The manual fingerprint-verification flag must PERSIST to the encrypted
/// store, so the UI's ✓ mark survives a store close/reopen. Before the fix,
/// `handle_verify_fingerprint` was UI-local state and `load_contacts` always
/// returned `verified: false`, so the mark was lost on every restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_verify_fingerprint_persists_across_reopen() {
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

            // Alice adds bob as a contact.
            alice_cmd
                .send(Command::AddContact {
                    identity_pub: bob_pub,
                    nickname: "bob".to_string(),
                })
                .await
                .expect("add contact");
            let loaded =
                expect_event(&mut alice_ev, |e| matches!(e, Event::ContactsLoaded(_))).await;
            match loaded {
                Event::ContactsLoaded(contacts) => {
                    let bob = contacts
                        .iter()
                        .find(|c| c.identity_pub == bob_pub)
                        .expect("bob in contacts");
                    assert!(!bob.verified, "contact starts unverified");
                }
                other => panic!("expected ContactsLoaded, got {other:?}"),
            }

            // Alice marks bob's fingerprint verified.
            alice_cmd
                .send(Command::VerifyFingerprint {
                    identity_pub: bob_pub,
                })
                .await
                .expect("verify");
            // The bridge emits FingerprintVerified then ContactsLoaded.
            expect_event(&mut alice_ev, |e| {
                matches!(e, Event::FingerprintVerified { .. })
            })
            .await;
            let reloaded =
                expect_event(&mut alice_ev, |e| matches!(e, Event::ContactsLoaded(_))).await;
            match reloaded {
                Event::ContactsLoaded(contacts) => {
                    let bob = contacts
                        .iter()
                        .find(|c| c.identity_pub == bob_pub)
                        .expect("bob in contacts");
                    assert!(bob.verified, "verified flag set after VerifyFingerprint");
                }
                other => panic!("expected ContactsLoaded, got {other:?}"),
            }

            // Drop alice's bridge (closes the store), reopen the SAME store,
            // and check the verified flag survived to disk.
            drop(alice_cmd);
            drop(alice_ev);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            let alice_pub_hex = hex::encode(alice_pub);
            let path = dir.join(format!("{alice_pub_hex}.db"));
            let store = Store::open(&path, "test-pass").expect("reopen alice store");
            let session: ClientSession = store.get("session").expect("load session").unwrap();
            let contacts = store.contacts().expect("load contacts");
            let bob = contacts
                .iter()
                .find(|c| c.identity_pub == bob_pub)
                .expect("bob persisted");
            assert!(
                bob.verified,
                "verified flag persisted to disk across store reopen"
            );
            // Touch session so it is not unused (proves the round-trip works).
            assert_eq!(session.identity_pub(), alice_pub);

            drop(bob_cmd);
        })
        .await;
}

/// `RotateSignedPrekey` and `ReplenishOneTimePrekeys` must actually change the
/// bundle (new signed-prekey id + more one-time prekeys) and re-register it,
/// not just re-register the same bundle. Before the fix both handlers were
/// stubs that re-registered the current bundle unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_rotate_and_replenish_change_bundle() {
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
            let (alice_cmd, mut alice_ev) = spawn_bridge(alice_bridge);

            alice_cmd
                .send(Command::Connect { addr })
                .await
                .expect("alice connect");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;

            // Snapshot the session from disk to read the pre-key ids before
            // rotation. The bridge persists the session on every state change,
            // so after each command we can reload it.
            let alice_pub_hex = {
                // We need the identity pub to locate the store; read it from
                // the first Ready-ish signal is not emitted post-Connect, so
                // derive it from the store file name instead.
                let mut entries = std::fs::read_dir(&dir).expect("read dir");
                let entry = entries.next().expect("one store file").expect("entry");
                entry
                    .file_name()
                    .to_string_lossy()
                    .trim_end_matches(".db")
                    .to_string()
            };
            let path = dir.join(format!("{alice_pub_hex}.db"));

            let load_session = || {
                let store = Store::open(&path, "test-pass").expect("reopen store");
                store
                    .get::<ClientSession>("session")
                    .expect("load session")
                    .unwrap()
            };

            let before = load_session();
            let spk_before = before.signed_prekey_id();
            let otpk_before = before.one_time_prekey_count();

            // Rotate the signed prekey.
            alice_cmd
                .send(Command::RotateSignedPrekey)
                .await
                .expect("rotate");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;

            let after_rotate = load_session();
            assert_eq!(
                after_rotate.signed_prekey_id(),
                spk_before + 1,
                "signed prekey id bumped after RotateSignedPrekey"
            );

            // Replenish one-time prekeys.
            alice_cmd
                .send(Command::ReplenishOneTimePrekeys { count: 5 })
                .await
                .expect("replenish");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;

            let after_replenish = load_session();
            assert_eq!(
                after_replenish.one_time_prekey_count(),
                otpk_before + 5,
                "one-time prekey count grew by 5 after ReplenishOneTimePrekeys"
            );
            // Rotation id is stable across replenish.
            assert_eq!(
                after_replenish.signed_prekey_id(),
                spk_before + 1,
                "replenish did not disturb the signed prekey"
            );

            drop(alice_cmd);
        })
        .await;
}

/// Regression test for group-roster persistence across a restart.
///
/// Before the fix, the bridge's `group_rosters` / `group_names` were
/// in-memory only. The Sender-Key group sessions themselves were restored
/// from the persisted `ClientSession` on Unlock, but the roster was lost — so
/// after a restart a `SendGroupMessage` had no recipients and failed with
/// "group has no known recipients", and the ContactList "Groups" section was
/// empty until a fresh distribution arrived. The fix persists the roster +
/// names to the store's `groups` / `group_members` tables and reloads them on
/// Unlock (emitting `Event::GroupsLoaded`).
///
/// Flow: alice founds a group with bob, the mesh converges (alice's roster =
/// [bob]). Drop alice's bridge, reopen the SAME store into a fresh bridge,
/// reconnect, and send a group message — bob must still decrypt it, proving
/// the roster survived the restart. We also assert the reopened bridge emits
/// `Event::GroupsLoaded` with the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_group_roster_survives_restart() {
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

            // Seed a 1:1 session alice -> bob (the group dist rides it).
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
            expect_event(&mut bob_ev, |e| matches!(e, Event::Decrypted { .. })).await;

            // Alice founds a group with bob.
            alice_cmd
                .send(Command::CreateGroup {
                    name: "team".to_string(),
                    members: vec![bob_pub],
                })
                .await
                .expect("alice create group");
            let created =
                expect_event(&mut alice_ev, |e| matches!(e, Event::GroupCreated { .. })).await;
            let group = match created {
                Event::GroupCreated { group, .. } => group,
                other => panic!("expected GroupCreated, got {other:?}"),
            };
            // Bob receives the distribution → GroupInvited (mesh converges).
            expect_event(&mut bob_ev, |e| matches!(e, Event::GroupInvited { .. })).await;
            // Drain any ack-dist GroupInvited alice may receive.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                expect_event(&mut alice_ev, |e| matches!(e, Event::GroupInvited { .. })),
            )
            .await;

            // Drop alice's bridge (closes her store), then reopen the SAME
            // store into a fresh bridge. The persisted roster must rebuild.
            drop(alice_cmd);
            drop(alice_ev);
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            let alice_pub_hex = hex::encode(alice_pub);
            let path = dir.join(format!("{alice_pub_hex}.db"));
            let store = Store::open(&path, "test-pass").expect("reopen alice store");
            let session: ClientSession = store.get("session").expect("load session").unwrap();
            // Sanity: the persisted store has the group + bob as a member.
            let groups = store.groups().expect("load groups");
            assert_eq!(groups.len(), 1, "group persisted to store");
            assert_eq!(groups[0].name, "team");
            let members = store.group_members(&group).expect("load members");
            assert!(
                members.contains(&bob_pub),
                "bob persisted in group roster: {members:?}"
            );

            let config = Config {
                server_addr: server_addr.clone(),
                ..Default::default()
            };
            let alice_bridge2 = Bridge::new(session, Some(store), config);
            let (alice_cmd2, mut alice_ev2) = spawn_bridge(alice_bridge2);
            alice_cmd2
                .send(Command::Connect { addr })
                .await
                .expect("alice reconnect");
            // The reopened bridge must emit GroupsLoaded with the persisted
            // group so the UI can list it immediately.
            let loaded =
                expect_event(&mut alice_ev2, |e| matches!(e, Event::GroupsLoaded(_))).await;
            match loaded {
                Event::GroupsLoaded(gs) => {
                    assert_eq!(gs.len(), 1, "one group loaded from store");
                    assert_eq!(gs[0].id, group);
                    assert_eq!(gs[0].name, "team");
                }
                other => panic!("expected GroupsLoaded, got {other:?}"),
            }
            expect_event(&mut alice_ev2, |e| matches!(e, Event::Connected)).await;

            // Alice sends a group message from the RESTARTED bridge. Without
            // the persisted roster this would fail with "group has no known
            // recipients"; with it, bob decrypts.
            alice_cmd2
                .send(Command::SendGroupMessage {
                    group,
                    text: "after restart".to_string(),
                    local_id: 10,
                })
                .await
                .expect("alice group send after restart");
            expect_event(&mut alice_ev2, |e| {
                matches!(e, Event::Sent { local_id: 10, .. })
            })
            .await;
            let after_restart =
                expect_event(&mut bob_ev, |e| matches!(e, Event::Decrypted { .. })).await;
            match after_restart {
                Event::Decrypted { chat, msg } => {
                    assert_eq!(chat, um_gui::types::ChatId::Group(group));
                    assert_eq!(msg.text, "after restart");
                    assert_eq!(msg.dir, um_gui::types::Direction::In);
                }
                other => panic!("expected group Decrypted after restart, got {other:?}"),
            }

            drop(alice_cmd2);
            drop(bob_cmd);
        })
        .await;
}

/// Persisted unread counts survive a bridge restart. The app emits
/// `Command::SetUnread` whenever its in-memory badge count changes; the bridge
/// writes it to the `unread` table. On a fresh `Unlock` the bridge reloads the
/// counts and emits `Event::UnreadLoaded`, so the sidebar badges reappear
/// instead of resetting to 0. This test drives the bridge directly (no iced
/// app): it sets a count, drops the bridge, reopens the same store into a new
/// bridge, and asserts the count comes back via `UnreadLoaded`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_unread_count_survives_restart() {
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
            let (bob_bridge, bob_pub) = make_bridge(&dir, &server_addr);
            let (bob_cmd, mut bob_ev) = spawn_bridge(bob_bridge);

            // Connect so the store is attached + registered.
            bob_cmd
                .send(Command::Connect { addr })
                .await
                .expect("bob connect");
            expect_event(&mut bob_ev, |e| matches!(e, Event::Connected)).await;

            // Simulate the app bumping bob's unread for a peer chat to 2
            // (two incoming messages while the chat was closed). The bridge
            // persists this to the `unread` table.
            let peer = [0xAA; 32];
            bob_cmd
                .send(Command::SetUnread { peer, count: 2 })
                .await
                .expect("set unread");
            // Give the best-effort persist a moment to land (the command is
            // fire-and-forget; the bridge does not reply).
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Drop the bridge (closes the store), then reopen the SAME store
            // into a fresh bridge — exactly what happens on restart.
            drop(bob_cmd);
            drop(bob_ev);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            let bob_pub_hex = hex::encode(bob_pub);
            let path = dir.join(format!("{bob_pub_hex}.db"));
            let store = Store::open(&path, "test-pass").expect("reopen bob store");
            let session: ClientSession = store.get("session").expect("load session").unwrap();
            // Sanity: the count persisted to the `unread` table.
            let counts = store.unread_counts().expect("load unread counts");
            assert_eq!(counts, vec![(peer, 2)], "unread count persisted");

            let config = Config {
                server_addr: server_addr.clone(),
                ..Default::default()
            };
            let bob_bridge2 = Bridge::new(session, Some(store), config);
            let (bob_cmd2, mut bob_ev2) = spawn_bridge(bob_bridge2);
            // The reopened bridge emits UnreadLoaded with the persisted count.
            let loaded = expect_event(&mut bob_ev2, |e| matches!(e, Event::UnreadLoaded(_))).await;
            match loaded {
                Event::UnreadLoaded(counts) => {
                    assert_eq!(
                        counts,
                        vec![(peer, 2)],
                        "UnreadLoaded carries persisted count"
                    );
                }
                other => panic!("expected UnreadLoaded, got {other:?}"),
            }

            // Clearing the count (app opens the chat) must delete the row, so a
            // further restart loads nothing.
            bob_cmd2
                .send(Command::SetUnread { peer, count: 0 })
                .await
                .expect("clear unread");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            drop(bob_cmd2);
            drop(bob_ev2);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            let store = Store::open(&path, "test-pass").expect("reopen bob store 2");
            assert!(
                store.unread_counts().expect("load unread 2").is_empty(),
                "count=0 clears the row"
            );

            let _ = std::fs::remove_dir_all(&dir);
        })
        .await;
}

/// Acks are best-effort: if an ack never reaches the relay (network drop, or
/// the relay restarts before processing it), the envelope stays in the outbox
/// and the next `Subscribe` flush re-delivers the SAME envelope (same
/// relay-assigned `id`). Without dedup this would (a) insert a duplicate row
/// in the store and (b) emit a second `Event::Decrypted`, showing the message
/// twice in the UI. The store's `(peer, server_id)` partial unique index +
/// `INSERT OR IGNORE` in `put_message` collapses the re-delivery: the bridge's
/// `deliver_chat` sees `Ok(None)` and suppresses the duplicate event while
/// still acking so the relay drops the envelope.
///
/// This test simulates a lost ack with `ServerStore::reinsert_envelope`
/// (gated behind the `test-helpers` feature). Flow: bob registers then goes
/// offline; alice sends a 1:1 message so the envelope sits UNACKED in bob's
/// outbox; the test captures that exact envelope; bob comes online (Subscribe
/// flush → delivery #1 → Decrypted → ack → relay drops); the test re-inserts
/// the SAME envelope (lost ack from the relay's view); bob reconnects
/// (Subscribe re-flushes → the store dedups → NO second Decrypted, but the
/// bridge still acks so the relay drops it). Asserts: exactly one
/// `Event::Decrypted`, one store row, and the relay outbox empty afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_redelivery_dedups_decrypted_event() {
    let dir = test_dir();
    std::fs::create_dir_all(&dir).expect("create test dir");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    let server_store = Arc::new(ServerStore::new());
    let subs = Arc::new(Subscribers::new());
    let addr = serve("127.0.0.1:0", server_store.clone(), subs)
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

            // Bob registers (Connect = Register + Subscribe) while his outbox
            // is empty, so the Subscribe drain is a no-op and bob idles. Then
            // take bob OFFLINE: drop the bridge so the relay sees a
            // disconnect. bob stays REGISTERED, so alice's send still lands in
            // bob's outbox (deliver skips only unregistered recipients).
            bob_cmd
                .send(Command::Connect { addr })
                .await
                .expect("bob connect");
            expect_event(&mut bob_ev, |e| matches!(e, Event::Connected)).await;
            drop(bob_cmd);
            drop(bob_ev);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            // Alice connects + sends the first (X3DH) message. The envelope
            // lands in bob's outbox and STAYS there: bob is offline, so there
            // is no push and no ack.
            alice_cmd
                .send(Command::Connect { addr })
                .await
                .expect("alice connect");
            expect_event(&mut alice_ev, |e| matches!(e, Event::Connected)).await;
            alice_cmd
                .send(Command::StartSession {
                    peer: bob_pub,
                    first_message: "offline dedup me".to_string(),
                    local_id: 10,
                })
                .await
                .expect("alice startsession");
            expect_event(&mut alice_ev, |e| {
                matches!(e, Event::Sent { local_id: 10, .. })
            })
            .await;

            // Capture the exact envelope the relay is holding for bob, BEFORE
            // any ack. `poll(identity, 0)` returns every envelope with id > 0
            // WITHOUT removing it from the outbox, so this is a non-destructive
            // snapshot of the re-delivery candidate.
            //
            // `Event::Sent` only confirms the `Send` frame was written to the
            // socket; the relay processes it asynchronously in its accept-loop
            // task, so the envelope may not yet be in bob's outbox when we
            // reach this point. Poll with a bounded retry instead of a one-shot
            // assert so the test is deterministic regardless of scheduling.
            let captured = {
                let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
                tokio::pin!(deadline);
                loop {
                    let pending = server_store.poll(&bob_pub, 0);
                    if pending.len() == 1 {
                        break pending[0].clone();
                    }
                    tokio::select! {
                        biased;
                        () = &mut deadline => panic!(
                            "one envelope pending for offline bob; got {} before timeout",
                            pending.len()
                        ),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
                    }
                }
            };
            let env_id = captured.id;

            // Bring bob back online with the SAME store + session: reopen the
            // store bob's bridge created, load the persisted session, spawn a
            // fresh bridge. The Subscribe drain delivers the offline mail
            // (delivery #1), bob acks, the relay drops the envelope.
            let bob_path = dir.join(format!("{}.db", hex::encode(bob_pub)));
            let bob_store = Store::open(&bob_path, "test-pass").expect("open bob store");
            let bob_session: ClientSession = bob_store
                .get("session")
                .expect("load bob session")
                .expect("bob session present");
            let bob_bridge2 = Bridge::new(
                bob_session,
                Some(bob_store),
                Config {
                    server_addr: server_addr.clone(),
                    ..Default::default()
                },
            );
            let (bob_cmd2, mut bob_ev2) = spawn_bridge(bob_bridge2);
            bob_cmd2
                .send(Command::Connect { addr })
                .await
                .expect("bob reconnect");

            // The Subscribe drain emits `Event::Decrypted` for the offline
            // envelope BEFORE `Event::Connected`, so we must collect every
            // event in one pass (draining until Connected would discard the
            // first Decrypted). Capture delivery #1 here.
            let mut first: Option<Event> = None;
            let mut saw_connected = false;
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(10));
            tokio::pin!(deadline);
            loop {
                if saw_connected && first.is_some() {
                    break;
                }
                tokio::select! {
                    biased;
                    () = &mut deadline => panic!(
                        "delivery#1 timed out; connected={saw_connected}, first={first:?}"
                    ),
                    ev = bob_ev2.recv() => match ev {
                        Some(e) => {
                            if first.is_none() && matches!(e, Event::Decrypted { .. }) {
                                first = Some(e);
                            } else if matches!(e, Event::Connected) {
                                saw_connected = true;
                            } else if let Event::Error(msg) = e {
                                panic!("bob2 bridge error: {msg}");
                            }
                        }
                        None => panic!("bob2 channel closed before delivery #1"),
                    },
                }
            }
            let first = first.expect("delivery #1 Decrypted");
            match &first {
                Event::Decrypted { msg, .. } => assert_eq!(msg.text, "offline dedup me"),
                other => panic!("expected first Decrypted, got {other:?}"),
            }
            // The Decrypted message's local_id IS the relay envelope id (the
            // bridge uses env.id as the MessageView local_id for incoming
            // messages), so it must match the id we captured pre-delivery.
            if let Event::Decrypted { msg, .. } = &first {
                assert_eq!(msg.local_id, env_id, "local_id == relay envelope id");
            }
            // Let bob's best-effort ack reach the relay. The ack is sent
            // during the Subscribe drain (before this Decrypted was emitted),
            // but the relay processes it asynchronously; retry the empty-poll
            // check for a short window instead of a fixed 200ms sleep so the
            // test is robust to scheduling jitter.
            {
                let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
                tokio::pin!(deadline);
                loop {
                    if server_store.poll(&bob_pub, 0).is_empty() {
                        break;
                    }
                    tokio::select! {
                        biased;
                        () = &mut deadline => panic!(
                            "ack dropped the envelope after delivery #1 (still pending)"
                        ),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
                    }
                }
            }

            // Simulate a LOST ACK from the relay's perspective: the client
            // thought it acked, but the relay never recorded it, so the
            // envelope reappears in the outbox with the SAME id. The next
            // Subscribe flush will re-deliver it verbatim.
            server_store.reinsert_envelope(&bob_pub, captured);

            // Bob reconnects again. We drop bob2 and spawn bob3 from the same
            // store (the unambiguous restart path; the store already holds the
            // delivered row, which is the dedup target).
            drop(bob_cmd2);
            drop(bob_ev2);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let bob_store2 = Store::open(&bob_path, "test-pass").expect("reopen bob store");
            let bob_session2: ClientSession = bob_store2
                .get("session")
                .expect("reload bob session")
                .expect("bob session present");
            let bob_bridge3 = Bridge::new(
                bob_session2,
                Some(bob_store2),
                Config {
                    server_addr: server_addr.clone(),
                    ..Default::default()
                },
            );
            let (bob_cmd3, mut bob_ev3) = spawn_bridge(bob_bridge3);
            bob_cmd3
                .send(Command::Connect { addr })
                .await
                .expect("bob reconnect 2");
            expect_event(&mut bob_ev3, |e| matches!(e, Event::Connected)).await;

            // The re-delivered envelope must be deduped: the bridge acks it
            // (dropping it from the outbox) but emits NO second Decrypted.
            // Watch bob's event stream for 2s; a duplicate Decrypted would
            // surface here. Silence is success (the dedup suppressed it).
            let mut got_second = false;
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(2));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    biased;
                    () = &mut deadline => break,
                    ev = bob_ev3.recv() => match ev {
                        Some(Event::Decrypted { .. }) => { got_second = true; break; }
                        Some(Event::Error(e)) => panic!("bridge error: {e}"),
                        Some(_) => {}
                        None => break,
                    },
                }
            }
            assert!(
                !got_second,
                "re-delivered envelope must NOT emit a second Decrypted (dedup)"
            );

            // The relay outbox must be empty now: the bridge acked the
            // re-delivered envelope even though it was a local duplicate, so
            // the relay stops re-flushing it on future Subscribes. Retry the
            // empty-poll check for a short window — the ack is processed
            // asynchronously by the relay.
            {
                let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
                tokio::pin!(deadline);
                loop {
                    if server_store.poll(&bob_pub, 0).is_empty() {
                        break;
                    }
                    tokio::select! {
                        biased;
                        () = &mut deadline => panic!(
                            "re-delivered envelope acked → dropped from outbox (still pending)"
                        ),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
                    }
                }
            }

            // The store holds exactly ONE row for the 1:1 thread (keyed by the
            // peer identity pub): the original delivery, not a duplicate from
            // the re-delivery. Drop the bridge first so its store connection
            // is released, then reopen the file and read the thread via the
            // paginated production path.
            drop(alice_cmd);
            drop(bob_cmd3);
            drop(bob_ev3);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let bob_store_check = Store::open(&bob_path, "test-pass").expect("reopen for check");
            // The 1:1 thread is keyed by the PEER's identity pub (alice's),
            // not bob's own: an incoming message lives under
            // `ChatId::Peer(env.sender)` = `ChatId::Peer(alice_pub)`.
            let page = bob_store_check
                .messages_page(&alice_pub, None, 100)
                .expect("load bob's thread with alice");
            assert_eq!(
                page.rows.len(),
                1,
                "store holds one row, not a duplicate from re-delivery"
            );
            assert_eq!(page.rows[0].msg.text, "offline dedup me");

            let _ = std::fs::remove_dir_all(&dir);
        })
        .await;
}

/// A minimal framing-speaking relay stub for the heartbeat test. It does NOT
/// run `um_server` — it speaks the raw `um_protocol` framing directly so we
/// can control exactly when it stops answering, simulating a half-open path
/// (the socket stays open, but the relay stops replying to `Ping`).
///
/// The first connection completes the Register/Subscribe handshake and then
/// goes silent on `Ping` — never `Pong`, never EOF — which is exactly the
/// half-open condition the heartbeat must detect. Every subsequent connection
/// answers `Ping` with `Pong`, so the bridge's reconnect lands on a live peer
/// and re-emits `Event::Connected`.
async fn spawn_silent_after_subscribe_relay(
    addr: std::net::SocketAddr,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind stub");
    let bound = listener.local_addr().expect("local addr");
    let conn_count = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let n = conn_count.fetch_add(1, Ordering::SeqCst);
            let first = n == 0;
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    // Read until we have at least one full frame.
                    loop {
                        match decode::<ClientMessage>(&buf) {
                            Ok(_) => break,
                            Err(um_protocol::error::ProtocolError::Incomplete) => {
                                let mut chunk = [0u8; 4096];
                                match reader.read(&mut chunk).await {
                                    Ok(0) => return, // EOF
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                    Err(_) => return,
                                }
                            }
                            Err(_) => return, // fatal framing error: drop conn
                        }
                    }
                    let (msg, consumed) = match decode::<ClientMessage>(&buf) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    buf.drain(..consumed);
                    match msg {
                        ClientMessage::Register { .. } | ClientMessage::Subscribe => {
                            let Ok(frame) = encode(&ServerMessage::AckOk) else {
                                break;
                            };
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        ClientMessage::Ping => {
                            // First connection: go silent (half-open). Hold the
                            // socket open without replying so the bridge's recv
                            // branch never sees an EOF — only the heartbeat
                            // grace timer can detect this. Later connections
                            // echo Pong so reconnect succeeds.
                            if first {
                                continue;
                            }
                            let Ok(frame) = encode(&ServerMessage::Pong) else {
                                break;
                            };
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        // Anything else (Send/Ack/StartSession/FetchBundle):
                        // ignore. The heartbeat test sends no mail.
                        _ => {}
                    }
                }
            });
        }
    });
    (bound, handle)
}

/// The bridge's application-level heartbeat must detect a half-open relay —
/// one that holds the TCP socket open but stops replying to `Ping` (a NAT/
/// firewall that silently dropped the path, or a relay that has gone
/// unresponsive) — and tear down + reconnect instead of hanging on the dead
/// socket forever. With shrunk heartbeat params (interval/grace in tens of
/// ms) this exercises the full path in well under the test deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_heartbeat_detects_half_open_and_reconnects() {
    let dir = test_dir();
    std::fs::create_dir_all(&dir).expect("create test dir");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());

    // Stub relay: conn #1 goes silent after Subscribe, conn #2+ answers Pong.
    let (addr, _stub) = spawn_silent_after_subscribe_relay("127.0.0.1:0".parse().unwrap()).await;
    let server_addr = addr.to_string();

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (mut bridge, _id_pub) = make_bridge(&dir, &server_addr);
            // Shrink the heartbeat so the half-open path fires in well under a
            // second, not the 30s/90s production cadence. Grace is kept
            // comfortably larger than the interval and generously sized so a
            // scheduler stall under parallel-test load (the stub task not
            // getting CPU for a few intervals) does not spuriously trip a live
            // link — the test asserts the *detection* path, not tight timing.
            bridge = bridge.with_heartbeat_params(
                std::time::Duration::from_millis(150),
                std::time::Duration::from_millis(800),
            );
            let (cmd, mut ev) = spawn_bridge(bridge);

            // Initial connect: Register + Subscribe handshake completes, the
            // stub answers AckOk, the bridge emits Connected.
            cmd.send(Command::Connect { addr })
                .await
                .expect("send connect");
            expect_event(&mut ev, |e| matches!(e, Event::Connected)).await;

            // The stub now goes silent on Ping. The heartbeat grace (150ms)
            // expires with no Pong/any frame → the bridge presumes half-open,
            // emits Disconnected, and reconnects. The second connection answers
            // Pong, so the bridge re-emits Connected.
            expect_event(&mut ev, |e| matches!(e, Event::Disconnected { .. })).await;
            expect_event(&mut ev, |e| matches!(e, Event::Connected)).await;

            // After reconnect the link is live: the bridge should NOT emit
            // another Disconnected within a window covering several heartbeat
            // intervals (the second conn answers Pong, so the heartbeat stays
            // satisfied). A window too short would not actually verify
            // stability; ~10 intervals gives the heartbeat real chances to
            // re-probe and re-confirm.
            let deadline = tokio::time::sleep(std::time::Duration::from_millis(1500));
            tokio::pin!(deadline);
            let mut spuriously_disconnected = false;
            tokio::select! {
                biased;
                () = &mut deadline => {}
                ev2 = ev.recv() => {
                    if matches!(ev2, Some(Event::Disconnected { .. })) {
                        spuriously_disconnected = true;
                    }
                }
            }
            assert!(
                !spuriously_disconnected,
                "reconnected link answers Pong — heartbeat must not trip again"
            );

            drop(cmd);
        })
        .await;
}
