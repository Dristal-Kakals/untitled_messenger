//! The async bridge: owns the live `ClientSession` + `Store` + the relay
//! connection, runs a single command/recv loop, and emits `Event`s to the
//! GUI. This is where all the logic lives — it is fully testable without iced
//! by driving `command_rx` / `event_rx` against a real `um_server` on
//! localhost (see `tests/bridge_headless.rs`).
//!
//! Ownership model (no shared mutable state, no locks): a **single task**
//! owns `session` + `store` + the `Client`. It `select!`s over `command_rx`
//! (from the GUI) and `client.recv_msg()` (from the relay). When a command
//! needs to fetch a peer bundle (X3DH start), it sends `FetchBundle` and
//! reads frames inline until the `Bundle` reply arrives — decrypting any
//! `Delivered` frames that arrive in the meantime — then resumes the loop.
//! This mirrors the proven headless CLI (`um_client/src/main.rs`) and keeps
//! the crypto state single-owner.
//!
//! Reconnect: on `recv_msg` EOF/error the bridge emits `Event::Disconnected`
//! and retries connect + register + subscribe with exponential backoff
//! (1s → 30s cap) inside the loop.
//!
//! The bridge never panics: every fallible path becomes an `Event::Error`.
//! `#![forbid(unsafe_code)]` is set at the crate root.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use um_client::session::ClientSession;
use um_client::store::{StoredGroup, StoredMessage};
use um_client::{Client, ClientError, Store};
use um_crypto::sender_keys::SenderKeyState;
use um_protocol::{ClientMessage, EncryptedEnvelope, MessageKind, ServerMessage};

use crate::command::Command;
use crate::config::Config;
use crate::event::Event;
use crate::types::{ChatId, ContactView, Direction, GroupView, MessageView, Status};

/// The plaintext carried inside every 1:1 Double-Ratchet message the bridge
/// sends. Wrapping the payload lets the bridge multiplex two logical 1:1
/// contents over the same ratchet without a dedicated wire `MessageKind`:
/// ordinary chat text, and Sender-Key group distribution (the spec's
/// "distribution rides 1:1 ratchet plaintext" rule). On receive, the bridge
/// decodes this enum and routes `Chat` to the thread view and `GroupDist` to
/// the group-session import path. Postcard-encoded before encryption, so the
/// wrapping is invisible to the relay and to `um_client`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
enum P2pPayload {
    /// A normal 1:1 chat message.
    Chat(String),
    /// A Sender-Key distribution: the sender is sharing their group sender-key
    /// state so the receiver can decrypt this sender's group messages. `group`
    /// is the group id; `name` is the group's display name (so the invitee can
    /// label the thread); `state` is the sender's exported `SenderKeyState`.
    /// Boxed: `SenderKeyState` is ~520 bytes, which would balloon the enum
    /// and trip `clippy::large_enum_variant`; the payload is short-lived
    /// (encoded right away), so the indirection is free.
    GroupDist {
        group: [u8; 32],
        name: String,
        state: Box<SenderKeyState>,
    },
}

/// Channel capacity for the GUI↔bridge channels.
const CHAN_CAP: usize = 256;

/// Reconnect backoff ceiling (seconds). The loop retries 1→2→4→…→30 forever.
const BACKOFF_CAP_SECS: u64 = 30;

/// The async bridge state. Constructed with [`Bridge::new`] and run via
/// [`Bridge::spawn`], which spawns the loop on the caller's runtime.
pub struct Bridge {
    session: ClientSession,
    store: Option<Store>,
    /// The relay connection; `None` until connected.
    net: Option<Client>,
    config: Config,
    /// Store file path for the current identity (set on Setup/Unlock).
    store_path: Option<PathBuf>,
    /// Last delivered envelope id seen (informational; the server flushes
    /// unacked outbox on Subscribe).
    last_delivered_id: u64,
    /// Group rosters the bridge knows about: group id → member identity pubs.
    /// Mirrored to the store's `groups` + `group_members` tables so a
    /// close/reopen (Unlock) rebuilds the roster and group sends still fan out
    /// after a restart (the Sender-Key sessions themselves are restored from
    /// the persisted `ClientSession`, but without the roster the bridge would
    /// have no recipients).
    group_rosters: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Group display names, for `Event::GroupInvited` and re-emitting on
    /// later distribution. group id → name. Persisted to the `groups` table.
    group_names: HashMap<[u8; 32], String>,
    /// Records of `(group_id, peer)` pairs we have already shipped our own
    /// Sender-Key distribution to, so the invite-ack handshake does not loop
    /// (Alice invites Bob → Bob acks his dist back → Alice does not re-ack
    /// because she already sent hers to Bob on create).
    dist_sent: HashSet<([u8; 32], [u8; 32])>,
}

/// A handle returned by [`Bridge::spawn`] — the GUI holds the command sender
/// and the event receiver.
pub struct BridgeHandle {
    pub command_tx: mpsc::Sender<Command>,
    pub event_rx: mpsc::Receiver<Event>,
}

impl Bridge {
    /// Build a bridge around an existing (just-generated or just-loaded)
    /// session. `store` is `Some` after Unlock/Setup, `None` before. The
    /// bridge is not yet connected.
    pub fn new(session: ClientSession, store: Option<Store>, config: Config) -> Self {
        Self {
            session,
            store,
            net: None,
            config,
            store_path: None,
            last_delivered_id: 0,
            group_rosters: HashMap::new(),
            group_names: HashMap::new(),
            dist_sent: HashSet::new(),
        }
    }

    /// Spawn the bridge on the current runtime: creates the two GUI channels,
    /// runs the loop as a task, and returns the handle the GUI uses.
    ///
    /// Uses `tokio::task::spawn_local`, so this **must** be called inside a
    /// `tokio::task::LocalSet` (the bridge owns a `rusqlite::Connection`, which
    /// is not `Sync`, so the future is not `Send` and cannot run on a
    /// multi-thread runtime's shared pool). `main.rs` runs the bridge on a
    /// `LocalSet` pinned to one worker of a multi-thread runtime; the iced
    /// event loop runs on the main thread.
    pub fn spawn(self) -> BridgeHandle {
        let (command_tx, command_rx) = mpsc::channel::<Command>(CHAN_CAP);
        let (event_tx, event_rx) = mpsc::channel::<Event>(CHAN_CAP);
        tokio::task::spawn_local(async move {
            Self::run(self, command_rx, event_tx).await;
        });
        BridgeHandle {
            command_tx,
            event_rx,
        }
    }

    /// Run the bridge to completion. `select!`s over GUI commands and relay
    /// frames; exits when the command channel closes (GUI dropped).
    async fn run(mut self, mut command_rx: mpsc::Receiver<Command>, event_tx: mpsc::Sender<Event>) {
        // If the bridge was constructed with a store already attached (the
        // headless test harness embeds the store directly, bypassing
        // `Command::Unlock`), hydrate the in-memory group rosters + names now
        // and emit `GroupsLoaded` so the UI lists known groups immediately —
        // the same thing `handle_unlock` does for the app's Unlock path. In the
        // app the store is `None` at startup, so this is a no-op there and the
        // real load happens on Unlock (no double emit).
        if self.store.is_some() {
            let groups = self.load_groups();
            if !groups.is_empty() {
                let _ = event_tx.send(Event::GroupsLoaded(groups)).await;
            }
        }
        loop {
            tokio::select! {
                cmd = command_rx.recv() => match cmd {
                    Some(cmd) => self.handle_command(cmd, &event_tx).await,
                    None => break, // GUI gone; shut down.
                },
                frame = async {
                    match self.net.as_mut() {
                        Some(net) => net.recv_msg().await,
                        None => {
                            // Not connected: park forever so this branch never
                            // wins until a connection exists.
                            std::future::pending::<
                                Result<Option<ServerMessage>, ClientError>,
                            >().await
                        }
                    }
                } => match frame {
                    Ok(Some(ServerMessage::Delivered(envs))) => {
                        self.handle_delivered(&envs, &event_tx).await;
                    }
                    Ok(Some(ServerMessage::AckOk)) => {}
                    Ok(Some(ServerMessage::Bundle(_))) => {
                        // A stray bundle reply outside a StartSession fetch.
                        // Nothing to do; the inline fetch consumes its own.
                    }
                    Ok(Some(ServerMessage::Error(e))) => {
                        let _ = event_tx
                            .send(Event::Error(format!("server: {e:?}")))
                            .await;
                    }
                    Ok(None) => self.handle_disconnect(&event_tx).await,
                    Err(_e) => self.handle_disconnect(&event_tx).await,
                },
            }
        }
    }

    /// Dispatch one GUI command. All fallible paths become `Event::Error`; the
    /// bridge never panics.
    async fn handle_command(&mut self, cmd: Command, event_tx: &mpsc::Sender<Event>) {
        match cmd {
            Command::Setup {
                passphrase,
                one_time_count,
            } => {
                self.handle_setup(passphrase, one_time_count, event_tx)
                    .await;
            }
            Command::Unlock { passphrase } => self.handle_unlock(passphrase, event_tx).await,
            Command::Connect { addr } => self.handle_connect(addr, event_tx).await,
            Command::AddContact {
                identity_pub,
                nickname,
            } => {
                self.handle_add_contact(identity_pub, nickname, event_tx)
                    .await;
            }
            Command::VerifyFingerprint { identity_pub } => {
                self.handle_verify_fingerprint(identity_pub, event_tx).await;
            }
            Command::StartSession {
                peer,
                first_message,
                local_id,
            } => {
                self.handle_start_session(peer, first_message, local_id, event_tx)
                    .await;
            }
            Command::SendMessage {
                peer,
                text,
                local_id,
            } => {
                self.handle_send_message(peer, text, local_id, event_tx)
                    .await;
            }
            Command::LoadThread { peer } => self.handle_load_thread(peer, event_tx).await,
            Command::CreateGroup { name, members } => {
                self.handle_create_group(name, members, event_tx).await;
            }
            Command::SendGroupMessage {
                group,
                text,
                local_id,
            } => {
                self.handle_send_group(group, text, local_id, event_tx)
                    .await;
            }
            Command::LoadGroupThread { group } => {
                self.handle_load_group_thread(group, event_tx).await;
            }
            Command::RotateSignedPrekey => self.handle_rotate_signed_prekey(event_tx).await,
            Command::ReplenishOneTimePrekeys { count } => {
                self.handle_replenish_one_time(count, event_tx).await;
            }
            Command::ChangeServer { addr } => self.handle_change_server(addr, event_tx).await,
            Command::Logout => self.handle_logout(event_tx).await,
        }
    }

    // ---- Setup / Unlock -------------------------------------------------

    async fn handle_setup(
        &mut self,
        passphrase: String,
        one_time_count: u32,
        event_tx: &mpsc::Sender<Event>,
    ) {
        // A fresh identity was already generated for this bridge; create the
        // store for it now. (one_time_count is honored at session generation
        // time by the caller; here we only persist.)
        let _ = one_time_count;
        let pub_hex = hex::encode(self.session.identity_pub());
        let Some(path) = crate::config::store_path(&pub_hex) else {
            let _ = event_tx
                .send(Event::Error("no data directory (XDG unavailable)".into()))
                .await;
            return;
        };
        let store = match Store::create(&path, &passphrase) {
            Ok(s) => s,
            Err(e) => {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        };
        if let Err(e) = store.put("session", &self.session) {
            let _ = event_tx.send(Event::Error(humanize(&e))).await;
            return;
        }
        self.store = Some(store);
        self.store_path = Some(path);
        self.config.last_identity_pub = pub_hex;
        let _ = crate::config::save(&self.config);
        let identity_pub = self.session.identity_pub();
        let identity_fingerprint = self.session.fingerprint();
        let _ = event_tx
            .send(Event::Ready {
                identity_pub,
                identity_fingerprint,
            })
            .await;
    }

    async fn handle_unlock(&mut self, passphrase: String, event_tx: &mpsc::Sender<Event>) {
        let pub_hex = self.config.last_identity_pub.clone();
        if pub_hex.is_empty() {
            let _ = event_tx
                .send(Event::Error("no stored identity to unlock".into()))
                .await;
            return;
        }
        let Some(path) = crate::config::store_path(&pub_hex) else {
            let _ = event_tx
                .send(Event::Error("no data directory (XDG unavailable)".into()))
                .await;
            return;
        };
        let store = match Store::open(&path, &passphrase) {
            Ok(s) => s,
            Err(e) => {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        };
        let session: ClientSession = match store.get("session") {
            Ok(Some(s)) => s,
            Ok(None) => {
                let _ = event_tx
                    .send(Event::Error("store has no session (corrupt?)".into()))
                    .await;
                return;
            }
            Err(e) => {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        };
        self.session = session;
        self.store = Some(store);
        self.store_path = Some(path);
        let identity_pub = self.session.identity_pub();
        let identity_fingerprint = self.session.fingerprint();
        let contacts = self.load_contacts().unwrap_or_default();
        // Rebuild the in-memory group rosters + names from the persisted
        // `groups`/`group_members` tables so group sends and the ContactList
        // "Groups" section work right after a restart (the Sender-Key sessions
        // are restored from `session`, but the rosters are bridge-local).
        let groups = self.load_groups();
        let _ = event_tx
            .send(Event::Ready {
                identity_pub,
                identity_fingerprint,
            })
            .await;
        let _ = event_tx.send(Event::ContactsLoaded(contacts)).await;
        let _ = event_tx.send(Event::GroupsLoaded(groups)).await;
    }

    // ---- Connect / reconnect -------------------------------------------

    async fn handle_connect(&mut self, addr: SocketAddr, event_tx: &mpsc::Sender<Event>) {
        if let Err(reason) = self.connect_and_subscribe(event_tx).await {
            let _ = event_tx.send(Event::Error(reason)).await;
            return;
        }
        self.config.server_addr = addr.to_string();
        let _ = crate::config::save(&self.config);
        let _ = event_tx.send(Event::Connected).await;
    }

    /// Connect, register the bundle, subscribe for push. On success `self.net`
    /// is set. Returns `Err(reason_string)` on any failure.
    ///
    /// The Subscribe drain does NOT discard `Delivered` frames: the server
    /// flushes the unacked outbox as `Delivered` *before* the Subscribe
    /// `AckOk`, so those frames are exactly the mail that arrived while we
    /// were offline. They are decrypted + persisted + emitted here so a
    /// reconnect recovers them instead of silently dropping them.
    async fn connect_and_subscribe(
        &mut self,
        event_tx: &mpsc::Sender<Event>,
    ) -> Result<(), String> {
        let addr = self.config.server_socket_addr();
        let mut client = Client::connect(addr).await.map_err(|e| humanize(&e))?;
        client
            .send_msg(&ClientMessage::Register {
                bundle: self.session.registration_bundle(),
            })
            .await
            .map_err(|e| humanize(&e))?;
        // Drain until the Register AckOk. The server does not flush the outbox
        // on Register (only on Subscribe), so only AckOk is expected here.
        drain_until_ack(&mut client)
            .await
            .map_err(|e| humanize(&e))?;
        client
            .send_msg(&ClientMessage::Subscribe)
            .await
            .map_err(|e| humanize(&e))?;
        // Process the outbox flush: keep reading until the Subscribe AckOk,
        // decrypting every `Delivered` batch inline so offline mail is
        // recovered, not lost.
        loop {
            let frame = client.recv_msg().await.map_err(|e| humanize(&e))?;
            match frame {
                Some(ServerMessage::AckOk) => break,
                Some(ServerMessage::Delivered(envs)) => {
                    self.handle_delivered(&envs, event_tx).await;
                }
                Some(ServerMessage::Error(e)) => {
                    return Err(format!("server: {e:?}"));
                }
                Some(_) => {}
                None => return Err("connection closed during subscribe".into()),
            }
        }
        self.net = Some(client);
        Ok(())
    }

    async fn handle_disconnect(&mut self, event_tx: &mpsc::Sender<Event>) {
        self.net = None;
        let _ = event_tx
            .send(Event::Disconnected {
                reason: "connection closed".into(),
            })
            .await;
        // Reconnect with exponential backoff, unbounded in v1.
        let mut delay = 1u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            if self.net.is_some() {
                // A concurrent ChangeServer/Connect already reconnected.
                break;
            }
            match self.connect_and_subscribe(event_tx).await {
                Ok(()) => {
                    let _ = event_tx.send(Event::Connected).await;
                    break;
                }
                Err(_) => {
                    delay = (delay * 2).min(BACKOFF_CAP_SECS);
                }
            }
        }
    }

    async fn handle_change_server(&mut self, addr: SocketAddr, event_tx: &mpsc::Sender<Event>) {
        // Drop the old connection.
        self.net = None;
        self.config.server_addr = addr.to_string();
        if let Err(reason) = self.connect_and_subscribe(event_tx).await {
            let _ = event_tx.send(Event::Error(reason)).await;
            return;
        }
        let _ = crate::config::save(&self.config);
        let _ = event_tx.send(Event::Connected).await;
    }

    // ---- Contacts ------------------------------------------------------

    async fn handle_add_contact(
        &mut self,
        identity_pub: [u8; 32],
        nickname: String,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let Some(store) = self.store.as_ref() else {
            let _ = event_tx
                .send(Event::Error("store not unlocked".into()))
                .await;
            return;
        };
        let fingerprint = fingerprint_of_pub(&identity_pub);
        if let Err(e) = store.put_contact(&identity_pub, &nickname, &fingerprint) {
            let _ = event_tx.send(Event::Error(humanize(&e))).await;
            return;
        }
        let contacts = self.load_contacts().unwrap_or_default();
        let _ = event_tx.send(Event::ContactsLoaded(contacts)).await;
    }

    async fn handle_verify_fingerprint(
        &mut self,
        identity_pub: [u8; 32],
        event_tx: &mpsc::Sender<Event>,
    ) {
        // Persist the manual-verification flag so the UI's ✓ mark survives
        // restarts (previously UI-local state, lost on every reopen).
        if let Some(store) = self.store.as_ref() {
            if let Err(e) = store.set_verified(&identity_pub, true) {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        }
        let _ = event_tx
            .send(Event::FingerprintVerified { identity_pub })
            .await;
        let contacts = self.load_contacts().unwrap_or_default();
        let _ = event_tx.send(Event::ContactsLoaded(contacts)).await;
    }

    // ---- 1:1 chat ------------------------------------------------------

    async fn handle_start_session(
        &mut self,
        peer: [u8; 32],
        first_message: String,
        local_id: u64,
        event_tx: &mpsc::Sender<Event>,
    ) {
        // Fetch the peer's bundle, draining any Delivered frames inline.
        let bundle = match self.fetch_bundle(peer, event_tx).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                self.fail_send(
                    ChatId::Peer(peer),
                    local_id,
                    "contact not registered or offline",
                    event_tx,
                )
                .await;
                return;
            }
            Err(reason) => {
                self.fail_send(ChatId::Peer(peer), local_id, &reason, event_tx)
                    .await;
                return;
            }
        };
        let payload = match encode_payload(&P2pPayload::Chat(first_message.clone())) {
            Ok(b) => b,
            Err(e) => {
                self.fail_send(ChatId::Peer(peer), local_id, &humanize(&e), event_tx)
                    .await;
                return;
            }
        };
        let envelope = match self.session.start_session(&bundle, &payload) {
            Ok(env) => env,
            Err(e) => {
                self.fail_send(ChatId::Peer(peer), local_id, &humanize(&e), event_tx)
                    .await;
                return;
            }
        };
        if let Err(reason) = self.send_envelope(vec![peer], envelope, event_tx).await {
            self.fail_send(ChatId::Peer(peer), local_id, &reason, event_tx)
                .await;
            return;
        }
        let msg =
            self.persist_outgoing(&ChatId::Peer(peer), &first_message, local_id, Status::Sent);
        let _ = event_tx
            .send(Event::Sent {
                chat: ChatId::Peer(peer),
                local_id,
                msg,
            })
            .await;
    }

    async fn handle_send_message(
        &mut self,
        peer: [u8; 32],
        text: String,
        local_id: u64,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let payload = match encode_payload(&P2pPayload::Chat(text.clone())) {
            Ok(b) => b,
            Err(e) => {
                self.fail_send(ChatId::Peer(peer), local_id, &humanize(&e), event_tx)
                    .await;
                return;
            }
        };
        let envelope = match self.session.send(&peer, &payload) {
            Ok(env) => env,
            Err(e) => {
                self.fail_send(ChatId::Peer(peer), local_id, &humanize(&e), event_tx)
                    .await;
                return;
            }
        };
        if let Err(reason) = self.send_envelope(vec![peer], envelope, event_tx).await {
            self.fail_send(ChatId::Peer(peer), local_id, &reason, event_tx)
                .await;
            return;
        }
        let msg = self.persist_outgoing(&ChatId::Peer(peer), &text, local_id, Status::Sent);
        let _ = event_tx
            .send(Event::Sent {
                chat: ChatId::Peer(peer),
                local_id,
                msg,
            })
            .await;
    }

    async fn handle_load_thread(&self, peer: [u8; 32], event_tx: &mpsc::Sender<Event>) {
        let msgs = self.load_history(&ChatId::Peer(peer));
        let _ = event_tx
            .send(Event::HistoryLoaded(ChatId::Peer(peer), msgs))
            .await;
    }

    // ---- Group chat ----------------------------------------------------

    async fn handle_create_group(
        &mut self,
        name: String,
        members: Vec<[u8; 32]>,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let group_id = group_id(&name, &members, &self.session.identity_pub());
        if let Err(e) = self.session.create_group(group_id) {
            let _ = event_tx.send(Event::Error(humanize(&e))).await;
            return;
        }
        let distribution = match self.session.group_distribution(&group_id) {
            Ok(d) => d,
            Err(e) => {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        };
        // The distribution payload is a typed `P2pPayload::GroupDist` so the
        // invitee can import the founder's sender-key state and learn the
        // group id + display name.
        let dist_bytes = match encode_payload(&P2pPayload::GroupDist {
            group: group_id,
            name: name.clone(),
            state: Box::new(distribution),
        }) {
            Ok(b) => b,
            Err(e) => {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
        };
        // Record the roster + name for this group so group sends know the
        // recipients and the UI can label the thread.
        self.group_rosters.insert(group_id, members.clone());
        self.group_names.insert(group_id, name.clone());
        // Persist the group + roster so a restart rebuilds them from disk
        // (the Sender-Key session is restored from `session`, but the roster
        // is bridge-local and would otherwise be lost).
        self.persist_group(&group_id, &name, &members);
        let mut failed = 0usize;
        for member in &members {
            match self.session.send(member, &dist_bytes) {
                Ok(env) => {
                    // Record that we have shipped our distribution to this
                    // member so a later ack-dist from them does not re-trigger
                    // an ack back (handshake convergence).
                    self.dist_sent.insert((group_id, *member));
                    if let Err(reason) = self.send_envelope(vec![*member], env, event_tx).await {
                        let _ = event_tx
                            .send(Event::Error(format!(
                                "group invite to {} failed: {reason}",
                                hex::encode(member)
                            )))
                            .await;
                        failed += 1;
                    }
                }
                Err(ClientError::NoSession) => {
                    let _ = event_tx
                        .send(Event::Error(format!(
                            "cannot invite {}: no 1:1 session yet (send them a message first)",
                            hex::encode(member)
                        )))
                        .await;
                    failed += 1;
                }
                Err(e) => {
                    let _ = event_tx.send(Event::Error(humanize(&e))).await;
                    failed += 1;
                }
            }
        }
        self.persist_session();
        // Roster size = invitees + the founder (us). The founder is always a
        // member of their own group; the roster stored above is invitees-only,
        // so add 1 for the GroupChat header member count.
        let member_count = (members.len() as u32).saturating_add(1);
        let _ = event_tx
            .send(Event::GroupCreated {
                group: group_id,
                name: name.clone(),
                members: member_count,
            })
            .await;
        if failed > 0 {
            let _ = event_tx
                .send(Event::Error(format!(
                    "{failed} member(s) could not be invited; group created locally"
                )))
                .await;
        }
    }

    async fn handle_send_group(
        &mut self,
        group: [u8; 32],
        text: String,
        local_id: u64,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let envelope = match self.session.send_group(&group, text.as_bytes()) {
            Ok(env) => env,
            Err(e) => {
                self.fail_send(ChatId::Group(group), local_id, &humanize(&e), event_tx)
                    .await;
                return;
            }
        };
        let mut recipients = self.group_rosters.get(&group).cloned().unwrap_or_default();
        // Dedup recipients: a duplicate makes the relay deliver the same
        // envelope twice (with two ids), and the receiver's sender-key
        // generation check rejects the second copy.
        recipients.sort_unstable();
        recipients.dedup();
        if recipients.is_empty() {
            self.fail_send(
                ChatId::Group(group),
                local_id,
                "group has no known recipients",
                event_tx,
            )
            .await;
            return;
        }
        if let Err(reason) = self.send_envelope(recipients, envelope, event_tx).await {
            self.fail_send(ChatId::Group(group), local_id, &reason, event_tx)
                .await;
            return;
        }
        let msg = self.persist_outgoing(&ChatId::Group(group), &text, local_id, Status::Sent);
        let _ = event_tx
            .send(Event::Sent {
                chat: ChatId::Group(group),
                local_id,
                msg,
            })
            .await;
    }

    async fn handle_load_group_thread(&self, group: [u8; 32], event_tx: &mpsc::Sender<Event>) {
        let msgs = self.load_history(&ChatId::Group(group));
        let _ = event_tx
            .send(Event::HistoryLoaded(ChatId::Group(group), msgs))
            .await;
    }

    // ---- Settings ------------------------------------------------------

    async fn handle_rotate_signed_prekey(&mut self, event_tx: &mpsc::Sender<Event>) {
        // Rotate the signed prekey (new id, retired old one retained for
        // stale-bundle initiations), then re-register the refreshed bundle.
        self.session.rotate_signed_prekey();
        self.persist_session();
        if let Err(reason) = self.re_register().await {
            let _ = event_tx.send(Event::Error(reason)).await;
            return;
        }
        let _ = event_tx.send(Event::Connected).await;
    }

    async fn handle_replenish_one_time(&mut self, count: u32, event_tx: &mpsc::Sender<Event>) {
        // Generate `count` fresh one-time prekeys (new ids past the current
        // max), then re-register so the server advertises them.
        self.session.replenish_one_time_prekeys(count);
        self.persist_session();
        if let Err(reason) = self.re_register().await {
            let _ = event_tx.send(Event::Error(reason)).await;
            return;
        }
        let _ = event_tx.send(Event::Connected).await;
    }

    async fn handle_logout(&mut self, event_tx: &mpsc::Sender<Event>) {
        self.store = None;
        self.net = None;
        self.store_path = None;
        // Clear the in-memory group maps so a subsequent Unlock of a different
        // identity does not carry over a stale roster. The persisted tables are
        // keyed per-identity (separate store file), so they are untouched.
        self.group_rosters.clear();
        self.group_names.clear();
        self.dist_sent.clear();
        let _ = event_tx
            .send(Event::Disconnected {
                reason: "logged out".into(),
            })
            .await;
    }

    // ---- Helpers -------------------------------------------------------

    /// Fetch a peer's bundle. Sends `FetchBundle`, then reads frames inline
    /// until the `Bundle` reply arrives — decrypting any `Delivered` frames
    /// that arrive in the meantime (so push during a fetch is not lost).
    /// Returns `Ok(None)` if the peer is not registered.
    async fn fetch_bundle(
        &mut self,
        peer: [u8; 32],
        event_tx: &mpsc::Sender<Event>,
    ) -> Result<Option<um_protocol::PreKeyBundle>, String> {
        {
            let net = self.net.as_mut().ok_or("not connected")?;
            net.send_msg(&ClientMessage::FetchBundle { target: peer })
                .await
                .map_err(|e| humanize(&e))?;
        }
        loop {
            // Re-borrow net per iteration so we can release it to process any
            // Delivered frames (which touch self.session/self.store).
            let frame = {
                let net = self.net.as_mut().ok_or("not connected")?;
                net.recv_msg().await.map_err(|e| humanize(&e))?
            };
            match frame {
                Some(ServerMessage::Bundle(b)) => return Ok(b),
                Some(ServerMessage::Delivered(envs)) => {
                    // Decrypt inline so push during the fetch is not lost.
                    self.handle_delivered(&envs, event_tx).await;
                }
                Some(ServerMessage::AckOk) => {}
                Some(ServerMessage::Error(e)) => {
                    return Err(format!("server: {e:?}"));
                }
                None => return Err("connection closed during bundle fetch".into()),
            }
        }
    }

    /// Send an envelope to `recipients` over the relay, then persist session.
    async fn send_envelope(
        &mut self,
        recipients: Vec<[u8; 32]>,
        envelope: EncryptedEnvelope,
        _event_tx: &mpsc::Sender<Event>,
    ) -> Result<(), String> {
        {
            let net = self.net.as_mut().ok_or("not connected")?;
            net.send_msg(&ClientMessage::Send {
                recipients,
                envelope,
            })
            .await
            .map_err(|e| humanize(&e))?;
        }
        self.persist_session();
        Ok(())
    }

    /// Re-register the current bundle (after a key change / refresh).
    async fn re_register(&mut self) -> Result<(), String> {
        let net = self.net.as_mut().ok_or("not connected")?;
        net.send_msg(&ClientMessage::Register {
            bundle: self.session.registration_bundle(),
        })
        .await
        .map_err(|e| humanize(&e))?;
        Ok(())
    }

    /// Decrypt + persist a batch of delivered envelopes, emitting
    /// `Event::Decrypted` per message. A decrypt failure on one envelope is
    /// surfaced as `Event::Error` and dropped; the rest still process.
    ///
    /// Successfully decrypted envelopes are acked to the server so the outbox
    /// drops them and they are not re-flushed on the next Subscribe. Without
    /// acks, every reconnect re-delivers the whole unacked outbox as
    /// duplicates, which breaks the Double-Ratchet (a repeated message number
    /// is not in the skipped cache and decrypt fails). Acks are best-effort:
    /// a send failure just leaves the envelope in the outbox for the next
    /// flush, which is harmless because the receiver's ratchet already
    /// advanced past it (a re-delivery decrypts-fails and is dropped, not
    /// fatal).
    async fn handle_delivered(
        &mut self,
        envs: &[EncryptedEnvelope],
        event_tx: &mpsc::Sender<Event>,
    ) {
        let mut acked_ids: Vec<u64> = Vec::new();
        for env in envs {
            self.last_delivered_id = self.last_delivered_id.max(env.id);
            let (plaintext, _sender) = match self.session.receive(env) {
                Ok(p) => p,
                Err(e) => {
                    let _ = event_tx
                        .send(Event::Error(format!(
                            "failed to decrypt message from {}: {}",
                            hex::encode(env.sender),
                            humanize(&e)
                        )))
                        .await;
                    continue;
                }
            };
            match env.kind {
                MessageKind::Direct => {
                    // Try to decode the typed payload. A bridge peer sends a
                    // `P2pPayload`; a non-bridge peer (e.g. the headless CLI)
                    // sends raw text, which fails to decode and falls back to
                    // a plain chat message so 1:1 interop still works.
                    match decode_payload(&plaintext) {
                        Some(P2pPayload::Chat(text)) => {
                            self.deliver_chat(ChatId::Peer(env.sender), env.id, text, event_tx)
                                .await;
                        }
                        Some(P2pPayload::GroupDist { group, name, state }) => {
                            self.handle_group_dist(env.sender, group, name, *state, event_tx)
                                .await;
                        }
                        None => {
                            // Raw bytes from a non-bridge peer: treat as text.
                            let text = String::from_utf8_lossy(&plaintext).into_owned();
                            self.deliver_chat(ChatId::Peer(env.sender), env.id, text, event_tx)
                                .await;
                        }
                    }
                }
                MessageKind::Group => {
                    let chat = match um_client::crypto_bridge::group_header_from_envelope(env) {
                        Ok(h) => ChatId::Group(h.group_id),
                        Err(_) => ChatId::Peer(env.sender),
                    };
                    let text = String::from_utf8_lossy(&plaintext).into_owned();
                    self.deliver_chat(chat, env.id, text, event_tx).await;
                }
            }
            // Decrypted + persisted successfully → ack so the server drops it
            // from the outbox and does not re-flush it on reconnect.
            acked_ids.push(env.id);
        }
        self.persist_session();
        // Best-effort ack of everything we processed this batch. A failure
        // leaves the envelopes in the outbox; the next flush re-delivers them
        // as (decrypt-failing) duplicates, which `handle_delivered` drops.
        if !acked_ids.is_empty() {
            self.ack_envelopes(&acked_ids).await;
        }
    }

    /// Send an `Ack` for our own identity with the given envelope ids.
    /// Best-effort: errors are logged via tracing and swallowed (the outbox
    /// keeps the envelopes, recoverable on the next Subscribe flush).
    async fn ack_envelopes(&mut self, envelope_ids: &[u64]) {
        let Some(net) = self.net.as_mut() else {
            return;
        };
        if net
            .send_msg(&ClientMessage::Ack {
                envelope_ids: envelope_ids.to_vec(),
            })
            .await
            .is_err()
        {
            tracing::warn!("failed to ack {} delivered envelope(s)", envelope_ids.len());
        }
    }

    /// Persist + emit an incoming chat message (1:1 or group text).
    async fn deliver_chat(
        &self,
        chat: ChatId,
        env_id: u64,
        text: String,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let timestamp = now_secs();
        if let Some(store) = self.store.as_ref() {
            let key = chat.key();
            let _ = store.put_message(
                &key,
                1,
                &StoredMessage {
                    text: text.clone(),
                    status: Status::Delivered.as_u8(),
                },
                timestamp as i64,
            );
        }
        let msg = MessageView {
            local_id: env_id,
            text,
            dir: Direction::In,
            timestamp,
            status: Status::Delivered,
        };
        let _ = event_tx.send(Event::Decrypted { chat, msg }).await;
    }

    /// Import a peer's Sender-Key distribution for `group`. If we do not yet
    /// have a local group session, create one (generating our own sender-key
    /// state), then import the peer's state so we can decrypt their group
    /// messages. To complete the mesh, ship our own distribution back to the
    /// peer — unless we already did (e.g. we are the founder and invited them
    /// first), which `dist_sent` guards against to converge the handshake.
    /// Emits `Event::GroupInvited` so the UI shows the new group thread.
    async fn handle_group_dist(
        &mut self,
        from: [u8; 32],
        group: [u8; 32],
        name: String,
        state: SenderKeyState,
        event_tx: &mpsc::Sender<Event>,
    ) {
        // Create the local group session if this is our first contact with it.
        let was_new = !self.session.has_group(&group);
        if was_new {
            if let Err(e) = self.session.create_group(group) {
                let _ = event_tx.send(Event::Error(humanize(&e))).await;
                return;
            }
            self.group_names.insert(group, name.clone());
        }
        if let Err(e) = self.session.add_group_peer(&group, state) {
            let _ = event_tx.send(Event::Error(humanize(&e))).await;
            return;
        }

        // Ack our own distribution back to the inviter so they can decrypt our
        // group messages — but only if we have not already sent it to them
        // (founder path: we invited them, so `dist_sent` already records it).
        if !self.dist_sent.contains(&(group, from)) {
            let our_state = match self.session.group_distribution(&group) {
                Ok(s) => s,
                Err(e) => {
                    let _ = event_tx.send(Event::Error(humanize(&e))).await;
                    return;
                }
            };
            let payload = match encode_payload(&P2pPayload::GroupDist {
                group,
                name: self.group_names.get(&group).cloned().unwrap_or_default(),
                state: Box::new(our_state),
            }) {
                Ok(b) => b,
                Err(e) => {
                    let _ = event_tx.send(Event::Error(humanize(&e))).await;
                    return;
                }
            };
            match self.session.send(&from, &payload) {
                Ok(env) => {
                    self.dist_sent.insert((group, from));
                    if let Err(reason) = self.send_envelope(vec![from], env, event_tx).await {
                        let _ = event_tx
                            .send(Event::Error(format!(
                                "group dist ack to {} failed: {reason}",
                                hex::encode(from)
                            )))
                            .await;
                    }
                }
                Err(e) => {
                    let _ = event_tx
                        .send(Event::Error(format!(
                            "could not ack group dist to {}: {}",
                            hex::encode(from),
                            humanize(&e)
                        )))
                        .await;
                }
            }
        }

        // Record the peer in the roster so our future group sends include
        // them — but never duplicate (the founder already lists invitees, and
        // a duplicate recipient makes the relay deliver twice, which breaks
        // the receiver's sender-key generation check).
        let roster = self.group_rosters.entry(group).or_default();
        if !roster.contains(&from) {
            roster.push(from);
        }
        // Persist the group name + roster so a restart rebuilds them. The name
        // refreshes on every distribution (the inviter may rename); members are
        // `INSERT OR IGNORE`'d so re-distribution never duplicates.
        if let Some(name) = self.group_names.get(&group).cloned() {
            self.persist_group(
                &group,
                &name,
                self.group_rosters.get(&group).unwrap_or(&Vec::new()),
            );
        }
        self.persist_session();
        // Roster size the bridge knows so far: the peers we have exchanged
        // distributions with (the roster map) plus ourselves. At minimum this
        // is the inviter + us = 2.
        let roster_len = self.group_rosters.get(&group).map_or(0, |r| r.len() as u32);
        let member_count = roster_len.saturating_add(1);
        let _ = event_tx
            .send(Event::GroupInvited {
                group,
                name: self.group_names.get(&group).cloned().unwrap_or_default(),
                members: member_count,
            })
            .await;
    }

    /// Persist an outgoing message and return its `MessageView`. direction = 0.
    fn persist_outgoing(
        &self,
        chat: &ChatId,
        text: &str,
        local_id: u64,
        status: Status,
    ) -> MessageView {
        let timestamp = now_secs();
        if let Some(store) = self.store.as_ref() {
            let key = chat.key();
            let _ = store.put_message(
                &key,
                0,
                &StoredMessage {
                    text: text.to_string(),
                    status: status.as_u8(),
                },
                timestamp as i64,
            );
        }
        MessageView {
            local_id,
            text: text.to_string(),
            dir: Direction::Out,
            timestamp,
            status,
        }
    }

    /// Persist the whole session (identity + prekeys + ratchets + groups) to
    /// the store under `"session"`. Write-through on every state change.
    fn persist_session(&self) {
        if let Some(store) = self.store.as_ref() {
            let _ = store.put("session", &self.session);
        }
    }

    /// Load contacts from the store into view models.
    fn load_contacts(&self) -> Result<Vec<ContactView>, ClientError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClientError::Store("store not unlocked".into()))?;
        let contacts = store.contacts()?;
        Ok(contacts
            .into_iter()
            .map(|c| ContactView {
                identity_pub: c.identity_pub,
                nickname: c.nickname,
                fingerprint: c.fingerprint,
                verified: c.verified,
            })
            .collect())
    }

    /// Load a chat's history from the store into view models, oldest first.
    fn load_history(&self, chat: &ChatId) -> Vec<MessageView> {
        let Some(store) = self.store.as_ref() else {
            return Vec::new();
        };
        let key = chat.key();
        let Ok(rows) = store.messages(&key) else {
            return Vec::new();
        };
        rows.into_iter()
            .map(|r| MessageView {
                local_id: r.id as u64,
                text: r.msg.text,
                dir: if r.direction == 0 {
                    Direction::Out
                } else {
                    Direction::In
                },
                timestamp: r.timestamp as u64,
                status: Status::from_u8(r.msg.status),
            })
            .collect()
    }

    /// Persist a group's name + full roster to the store. Write-through on
    /// group create / distribution so a restart rebuilds the roster from disk.
    /// The `members` list is the authoritative roster for `group_id`: every
    /// member is `INSERT OR IGNORE`'d (re-adding is a no-op, never a
    /// duplicate).
    fn persist_group(&self, group_id: &[u8; 32], name: &str, members: &[[u8; 32]]) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if store.put_group(group_id, name).is_err() {
            return;
        }
        for m in members {
            let _ = store.add_group_member(group_id, m);
        }
    }

    /// Load every persisted group + its member roster into the bridge's
    /// in-memory maps. Called on Unlock so group sends and the ContactList
    /// "Groups" section work immediately after a restart, without waiting for
    /// a fresh distribution. Returns the `GroupView` list (id + name) for
    /// `Event::GroupsLoaded`.
    fn load_groups(&mut self) -> Vec<GroupView> {
        let Some(store) = self.store.as_ref() else {
            return Vec::new();
        };
        let groups: Vec<StoredGroup> = match store.groups() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut views = Vec::with_capacity(groups.len());
        for g in groups {
            let members = store.group_members(&g.group_id).unwrap_or_default();
            // Member count = persisted roster + ourselves (we are a member of
            // every group we know). The roster table holds the *other*
            // members; the founder/invitee self-entry is implicit.
            let member_count = (members.len() as u32).saturating_add(1);
            self.group_rosters.insert(g.group_id, members);
            self.group_names.insert(g.group_id, g.name.clone());
            views.push(GroupView {
                id: g.group_id,
                name: g.name,
                members: member_count,
            });
        }
        views
    }

    /// Emit a `SendFailed` event for a chat + local_id.
    async fn fail_send(
        &self,
        chat: ChatId,
        local_id: u64,
        reason: &str,
        event_tx: &mpsc::Sender<Event>,
    ) {
        let _ = event_tx
            .send(Event::SendFailed {
                chat,
                local_id,
                reason: reason.to_string(),
            })
            .await;
    }
}

// ---- free functions -----------------------------------------------------

/// Consume server frames until an `AckOk` arrives (the Register handshake).
/// Used only for `Register`, which does not flush the outbox; the Subscribe
/// handshake is handled inline in `connect_and_subscribe` so its outbox
/// flush is recovered, not discarded.
async fn drain_until_ack(client: &mut Client) -> Result<(), ClientError> {
    loop {
        match client.recv_msg().await? {
            Some(ServerMessage::AckOk) => return Ok(()),
            Some(ServerMessage::Delivered(_envs)) => {
                // Discard early envelopes during the Register handshake.
            }
            Some(ServerMessage::Error(e)) => {
                return Err(ClientError::Store(format!("server: {e:?}")));
            }
            Some(_) => {}
            None => return Err(ClientError::NotConnected),
        }
    }
}

/// Map a `ClientError` to a human-readable string with no crypto/stack detail.
pub fn humanize(e: &ClientError) -> String {
    match e {
        ClientError::NoSession => "no secure session with this contact yet".to_string(),
        ClientError::NoGroupSession(_) => "no group session for this group".to_string(),
        ClientError::GroupSenderMismatch => {
            "group message sender does not match its claimed author".to_string()
        }
        ClientError::NoOneTimePreKey(_) => "missing one-time prekey".to_string(),
        ClientError::NotConnected => "not connected to server".to_string(),
        ClientError::Store(s) if s.contains("wrong passphrase") => "wrong passphrase".to_string(),
        ClientError::Store(s) if s.contains("already exists") => {
            "a store already exists for this identity".to_string()
        }
        ClientError::Store(s) => s.clone(),
        ClientError::Io(_) => "network error".to_string(),
        ClientError::Crypto(_) => "cryptographic error".to_string(),
        ClientError::Protocol(_) => "protocol error".to_string(),
        ClientError::Postcard(_) => "encoding error".to_string(),
        ClientError::Sqlite(_) => "local store error".to_string(),
    }
}

/// Encode a `P2pPayload` to the byte slice handed to the 1:1 ratchet.
fn encode_payload(p: &P2pPayload) -> Result<Vec<u8>, ClientError> {
    postcard::to_allocvec(p).map_err(ClientError::from)
}

/// Decode a `P2pPayload` from a decrypted 1:1 plaintext. Returns
/// `Ok(None)` if the bytes are not a valid `P2pPayload` (e.g. a message from
/// a non-bridge peer such as the headless CLI, which sends raw text); the
/// caller then falls back to treating the bytes as plain chat text so 1:1
/// interop with the headless client still works.
fn decode_payload(bytes: &[u8]) -> Option<P2pPayload> {
    postcard::from_bytes(bytes).ok()
}

/// `SHA-256(pub)` — the identity fingerprint, from the pub key only.
fn fingerprint_of_pub(pub_bytes: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pub_bytes);
    let out = h.finalize();
    let mut f = [0u8; 32];
    f.copy_from_slice(&out);
    f
}

/// Deterministic group id = `SHA-256(name ‖ members ‖ founder_identity_pub)`.
fn group_id(name: &str, members: &[[u8; 32]], founder: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([members.len() as u8]);
    for m in members {
        h.update(m);
    }
    h.update(founder);
    let out = h.finalize();
    let mut g = [0u8; 32];
    g.copy_from_slice(&out);
    g
}

/// Current unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_of_pub_is_deterministic() {
        let fp = fingerprint_of_pub(&[0x01; 32]);
        assert_eq!(fp, fingerprint_of_pub(&[0x01; 32]));
        assert_ne!(fp, fingerprint_of_pub(&[0x02; 32]));
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn group_id_is_deterministic_and_input_sensitive() {
        let founder = [0xAB; 32];
        let m1 = [0x01; 32];
        let m2 = [0x02; 32];
        let g = group_id("team", &[m1, m2], &founder);
        assert_eq!(g, group_id("team", &[m1, m2], &founder));
        assert_ne!(g, group_id("squad", &[m1, m2], &founder));
        assert_ne!(g, group_id("team", &[m1], &founder));
        assert_ne!(g, group_id("team", &[m1, m2], &[0xCD; 32]));
    }

    #[test]
    fn humanize_maps_known_variants() {
        assert_eq!(
            humanize(&ClientError::NoSession),
            "no secure session with this contact yet"
        );
        assert_eq!(
            humanize(&ClientError::NotConnected),
            "not connected to server"
        );
        assert_eq!(
            humanize(&ClientError::Store("wrong passphrase".into())),
            "wrong passphrase"
        );
    }

    #[test]
    fn now_secs_is_monotonic_ish() {
        let a = now_secs();
        let b = now_secs();
        assert!(b >= a);
        assert!(a > 0);
    }
}
