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
