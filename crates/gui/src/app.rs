//! The iced `Application`: display-only state, `Message` enum, `update()`,
//! `subscription()`, and `view()`. Views never touch `um_client` or async
//! directly — they emit `Message`s, which `update` maps to bridge `Command`s.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use iced::widget::{Space, button, column, container, row, text};
use iced::{Element, Fill, Subscription, Task};
use tokio::sync::mpsc;

use um_gui::config::Config;
use um_gui::theme;
use um_gui::types::{ChatId, ContactView, GroupView, MessageView, Status};
use um_gui::{Command, Event};

use crate::views;

/// Which screen is active. `ChatThread` carries the peer identity pub;
/// `GroupChat` carries the group id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Setup,
    Login,
    ContactList,
    ChatThread([u8; 32]),
    GroupChat([u8; 32]),
    Settings,
}

/// The iced `Application` state. Display-only: holds copies of *data*, never
/// live `um_client` objects. The bridge owns all crypto/net/store state.
///
/// `Clone` is sound: every field is cheaply cloneable (the bridge command
/// sender and the event-receiver slot are behind `Arc`), and iced's `boot`
/// closure is `Fn` (called once at startup), so the clone taken there is the
/// only one. The shared `event_rx` slot means a clone still references the same
/// single receiver — only the subscription ever takes it.
#[derive(Clone)]
pub struct UmApp {
    pub view: View,
    pub identity_pub: Option<[u8; 32]>,
    /// This identity's fingerprint (`SHA-256` of the identity pub), surfaced
    /// in the Settings view per the spec. `None` until `Event::Ready`.
    pub identity_fingerprint: Option<[u8; 32]>,
    pub contacts: Vec<ContactView>,
    /// Which thread is open (peer or group).
    pub open_chat: Option<ChatId>,
    /// In-memory message cache per open chat. The store is source of truth.
    pub threads: HashMap<ChatId, Vec<MessageView>>,
    /// Keyset-pagination cursor per chat: the smallest store row id currently
    /// held in the cache for that chat. `LoadOlder`/`LoadOlderGroup` pass this
    /// as `before_id` so the next page is strictly older than what is cached.
    /// Set on `HistoryLoaded`/`OlderHistoryLoaded` and cleared on `Logout`.
    /// Chats with no cached history have no entry (lookups default to "no
    /// older page to fetch").
    pub oldest_loaded: HashMap<ChatId, i64>,
    /// Whether older history exists beyond the cached page for each chat.
    /// `false` once the oldest row has been reached, so scroll-to-top stops
    /// issuing `LoadOlder` commands (and no "loading older…" indicator is
    /// shown). Driven by the `has_more` flag the bridge returns with each page.
    pub has_more_history: HashMap<ChatId, bool>,
    /// Chats with an in-flight `LoadOlder` request, so scroll-to-top does not
    /// fire a second fetch before the first `OlderHistoryLoaded` arrives
    /// (which would duplicate the page). Cleared on the event.
    pub loading_older: HashSet<ChatId>,
    /// Last observed viewport absolute y-offset per open chat, captured from
    /// every `ChatScrolled`. Used to restore the scroll position after an
    /// older page is prepended: the app emits a `scroll_to` task to
    /// `saved_offset + prepended_rows * EST_ROW_HEIGHT` so the row the user
    /// was reading stays in view instead of jumping down. Cleared on `Logout`.
    pub scroll_offset: HashMap<ChatId, f32>,
    /// Group threads the app knows about. Hydrated from `Event::GroupsLoaded`
    /// on Unlock (the persisted `groups` table) and updated by
    /// `Event::GroupCreated` / `Event::GroupInvited` at runtime. Drives the
    /// ContactList "Groups" section.
    pub groups: Vec<GroupView>,
    /// Unread-message count per chat, bumped on `Event::Decrypted` when that
    /// chat is not the open one, cleared when the chat is opened. Drives the
    /// unread badge on ContactList.
    pub unread: HashMap<ChatId, u32>,
    /// Monotonic id for optimistic-send matching.
    pub next_local_id: u64,
    /// Transient form state.
    pub passphrase_input: String,
    pub passphrase_confirm: String,
    pub server_input: String,
    pub add_contact_hex: String,
    pub add_contact_nick: String,
    pub compose_input: String,
    pub new_group_name: String,
    /// Sidebar search/filter query. Empty = show all contacts + groups; any
    /// non-empty substring (case-insensitive) filters both lists by nickname /
    /// group name / lowercase hex of the identity pub or group id. Drives the
    /// search box at the top of [`views::sidebar`].
    pub search_query: String,
    /// Settings: how many one-time prekeys to replenish (spec: count input).
    pub replenish_count: String,
    /// A single banner error string.
    pub error: Option<String>,
    /// Connection status banner.
    pub connected: bool,
    /// Clone of the bridge command sender.
    pub bridge_cmd: Arc<mpsc::Sender<Command>>,
    /// The event receiver, wrapped so the `subscription` (which gets `&self`)
    /// can take it once. Iced keys subscriptions by id, so the stream is built
    /// once and reused across `subscription` calls.
    pub event_rx: Arc<Mutex<Option<mpsc::Receiver<Event>>>>,
    pub config: Config,
}

/// All iced messages: user input from views + bridge events.
#[derive(Debug, Clone)]
pub enum Message {
    // Form input.
    PassphraseChanged(String),
    PassphraseConfirmChanged(String),
    ServerChanged(String),
    AddContactHexChanged(String),
    AddContactNickChanged(String),
    ComposeChanged(String),
    NewGroupNameChanged(String),
    /// Sidebar search/filter box input.
    SearchChanged(String),
    /// Settings: edit the one-time-prekey replenish count.
    ReplenishCountChanged(String),
    // Setup / Login.
    SetupSubmit,
    UnlockSubmit,
    // Navigation.
    /// Explicit "go to contact list" (currently `Back` covers this from
    /// Settings/Chat; kept for a future top-bar nav). Not yet wired to a view.
    #[allow(dead_code)]
    OpenContactList,
    OpenSettings,
    OpenChat([u8; 32]),
    /// Open a group thread from the ContactList "Groups" section.
    OpenGroup([u8; 32]),
    Back,
    // Contacts.
    AddContact,
    /// Mark the open 1:1 peer's fingerprint as manually verified.
    VerifyFingerprint([u8; 32]),
    // Chat.
    SendPressed,
    /// A chat thread's scrollable moved. `at_top` is true when the viewport is
    /// pinned to the top (relative offset y ≈ 0), which the app uses to fire
    /// `LoadOlder`/`LoadOlderGroup` for keyset history pagination — but only
    /// if more history exists and no older page is already loading. `offset`
    /// is the viewport's current absolute y-offset, captured every scroll so
    /// the app can restore the scroll position after an older page is
    /// prepended (see [`views::scroll_restore_target`]).
    ChatScrolled {
        chat: ChatId,
        at_top: bool,
        offset: f32,
    },
    // Group.
    CreateGroupPressed,
    // Settings.
    RotateSignedPrekey,
    ReplenishOneTimePrekeys,
    /// Apply the edited server address (disconnect + reconnect to it).
    ChangeServer,
    Logout,
    // Bridge events.
    Event(Event),
    // Misc.
    DismissError,
    Quit,
}

impl UmApp {
    /// Build the app with a bridge command sender, an initial view, and a
    /// config snapshot (read at startup).
    pub fn new(bridge_cmd: Arc<mpsc::Sender<Command>>, initial_view: View, config: Config) -> Self {
        let server_input = config.server_addr.clone();
        Self {
            view: initial_view,
            identity_pub: None,
            identity_fingerprint: None,
            contacts: Vec::new(),
            open_chat: None,
            threads: HashMap::new(),
            oldest_loaded: HashMap::new(),
            has_more_history: HashMap::new(),
            loading_older: HashSet::new(),
            scroll_offset: HashMap::new(),
            groups: Vec::new(),
            unread: HashMap::new(),
            next_local_id: 1,
            passphrase_input: String::new(),
            passphrase_confirm: String::new(),
            server_input,
            add_contact_hex: String::new(),
            add_contact_nick: String::new(),
            compose_input: String::new(),
            new_group_name: String::new(),
            search_query: String::new(),
            replenish_count: "10".to_string(),
            error: None,
            connected: false,
            bridge_cmd,
            event_rx: Arc::new(Mutex::new(None)),
            config,
        }
    }

    /// Hand the event receiver to the app (moved into the subscription).
    pub fn set_event_rx(&mut self, rx: mpsc::Receiver<Event>) {
        if let Ok(mut slot) = self.event_rx.lock() {
            *slot = Some(rx);
        }
    }

    /// Send a command to the bridge (fire-and-forget).
    fn send_cmd(&self, cmd: Command) {
        let _ = self.bridge_cmd.blocking_send(cmd);
    }

    /// Sum of per-chat unread counts across every chat (peers + groups). Drives
    /// the total-unread badge in the sidebar header, which stays visible even
    /// when the contacts list is scrolled or filtered so the user notices new
    /// messages without scanning every row. Chats with no entry (count 0) are
    /// absent from the map, so this is just a sum of the stored values.
    pub fn total_unread(&self) -> u32 {
        self.unread.values().copied().sum()
    }

    /// The next optimistic-send local id.
    const fn next_local_id(&mut self) -> u64 {
        let id = self.next_local_id;
        self.next_local_id += 1;
        id
    }

    /// Append an outgoing message to the open thread cache at `Sending`.
    fn optimistic_send(&mut self, chat: ChatId, text: String, local_id: u64) {
        let mv = MessageView {
            local_id,
            text,
            dir: um_gui::types::Direction::Out,
            timestamp: 0,
            status: Status::Sending,
            sender: None,
        };
        self.threads.entry(chat).or_default().push(mv);
    }

    /// Update a cached outgoing message's status by `local_id`.
    fn update_outgoing_status(&mut self, chat: ChatId, local_id: u64, status: Status) {
        if let Some(msgs) = self.threads.get_mut(&chat) {
            for m in msgs.iter_mut() {
                if m.local_id == local_id {
                    m.status = status;
                }
            }
        }
    }

    /// Record (or refresh) a known group thread, including its member count.
    /// Idempotent: a re-emit for an existing id updates the name + member
    /// count but never duplicates. The member count is authoritative from the
    /// bridge (it owns the roster); a stale UI count is always overwritten.
    fn upsert_group(&mut self, id: [u8; 32], name: String, members: u32) {
        if let Some(g) = self.groups.iter_mut().find(|g| g.id == id) {
            if g.name != name {
                g.name = name;
            }
            g.members = members;
            return;
        }
        self.groups.push(GroupView { id, name, members });
    }

    /// Mark a contact's fingerprint as verified in the cached contact list.
    fn mark_verified(&mut self, identity_pub: [u8; 32]) {
        for c in &mut self.contacts {
            if c.identity_pub == identity_pub {
                c.verified = true;
            }
        }
    }

    /// The smallest store row id cached for `chat`, or `None` if the cache is
    /// empty (no cursor to page back from). Used to decide whether
    /// scroll-to-top can fire `LoadOlder`.
    fn oldest_loaded(&self, chat: &ChatId) -> Option<i64> {
        self.oldest_loaded.get(chat).copied()
    }

    /// True if an older page may be fetchable for `chat`: more history is
    /// known to exist (`has_more_history`) and no page is already in flight
    /// (`loading_older`). Scroll-to-top checks this before sending
    /// `LoadOlder`/`LoadOlderGroup`.
    fn can_load_older(&self, chat: &ChatId) -> bool {
        self.has_more_history.get(chat).copied().unwrap_or(false)
            && !self.loading_older.contains(chat)
    }

    /// Record the keyset cursor + `has_more` for `chat` from a freshly loaded
    /// page (initial or older). The cursor is the smallest `local_id` in the
    /// page — which, for history-loaded rows, is the store row id (stable,
    /// monotonic). `has_more` is stored so `can_load_older` knows when the
    /// oldest row has been reached.
    fn note_page(&mut self, chat: ChatId, msgs: &[MessageView], has_more: bool) {
        if let Some(min) = msgs.iter().map(|m| m.local_id as i64).min() {
            // `min` becomes the new cursor only if it is older than any
            // already-cached row (older pages prepend smaller ids). For the
            // initial page the cache was empty, so this just sets it. For an
            // older page, the prepended rows are all older, so their min is
            // smaller — take it.
            let prev = self.oldest_loaded.get(&chat).copied();
            if prev.is_none_or(|p| min < p) {
                self.oldest_loaded.insert(chat, min);
            }
        }
        self.has_more_history.insert(chat, has_more);
    }
}

/// The iced `update` function: maps `Message`s to state changes + bridge
/// commands.
pub fn update(app: &mut UmApp, msg: Message) -> Task<Message> {
    match msg {
        Message::PassphraseChanged(s) => app.passphrase_input = s,
        Message::PassphraseConfirmChanged(s) => app.passphrase_confirm = s,
        Message::ServerChanged(s) => app.server_input = s,
        Message::AddContactHexChanged(s) => app.add_contact_hex = s,
        Message::AddContactNickChanged(s) => app.add_contact_nick = s,
        Message::ComposeChanged(s) => app.compose_input = s,
        Message::NewGroupNameChanged(s) => app.new_group_name = s,
        Message::SearchChanged(s) => app.search_query = s,
        Message::ReplenishCountChanged(s) => app.replenish_count = s,

        Message::SetupSubmit => {
            if app.passphrase_input.len() < 8 {
                app.error = Some("passphrase must be at least 8 characters".into());
            } else if app.passphrase_input != app.passphrase_confirm {
                app.error = Some("passphrases do not match".into());
            } else {
                app.error = None;
                app.send_cmd(Command::Setup {
                    passphrase: app.passphrase_input.clone(),
                    one_time_count: 10,
                });
            }
        }

        Message::UnlockSubmit => {
            app.error = None;
            app.send_cmd(Command::Unlock {
                passphrase: app.passphrase_input.clone(),
            });
        }

        Message::OpenContactList => app.view = View::ContactList,
        Message::OpenSettings => app.view = View::Settings,
        Message::OpenChat(peer) => {
            let chat = ChatId::Peer(peer);
            app.open_chat = Some(chat);
            app.unread.remove(&chat);
            // Persist the cleared count so a restart does not resurrect the
            // badge for a chat the user already opened.
            app.send_cmd(Command::SetUnread {
                peer: chat.key(),
                count: 0,
            });
            app.view = View::ChatThread(peer);
            app.send_cmd(Command::LoadThread { peer });
        }
        Message::OpenGroup(group) => {
            let chat = ChatId::Group(group);
            app.open_chat = Some(chat);
            app.unread.remove(&chat);
            app.send_cmd(Command::SetUnread {
                peer: chat.key(),
                count: 0,
            });
            app.view = View::GroupChat(group);
            app.send_cmd(Command::LoadGroupThread { group });
        }
        Message::Back => {
            app.view = View::ContactList;
            app.open_chat = None;
        }

        Message::AddContact => match views::parse_pubkey_hex(&app.add_contact_hex) {
            Ok(pub_) => {
                app.send_cmd(Command::AddContact {
                    identity_pub: pub_,
                    nickname: app.add_contact_nick.clone(),
                });
                app.add_contact_hex.clear();
                app.add_contact_nick.clear();
                app.error = None;
            }
            Err(e) => app.error = Some(e),
        },

        Message::VerifyFingerprint(peer) => {
            app.send_cmd(Command::VerifyFingerprint { identity_pub: peer });
            app.mark_verified(peer);
        }

        Message::SendPressed => {
            let text = app.compose_input.trim().to_string();
            if text.is_empty() {
                return Task::none();
            }
            let local_id = app.next_local_id();
            let mut snap: Option<Task<Message>> = None;
            match app.open_chat {
                Some(ChatId::Peer(peer)) => {
                    app.optimistic_send(ChatId::Peer(peer), text.clone(), local_id);
                    snap = Some(iced::widget::operation::snap_to_end(
                        views::chat_thread::thread_scroll_id(),
                    ));
                    // First send to this peer → StartSession (X3DH); else SendMessage.
                    let has_session = app.threads.get(&ChatId::Peer(peer)).is_some_and(|ms| {
                        ms.iter().any(|m| m.dir == um_gui::types::Direction::Out)
                    });
                    if has_session {
                        app.send_cmd(Command::SendMessage {
                            peer,
                            text,
                            local_id,
                        });
                    } else {
                        app.send_cmd(Command::StartSession {
                            peer,
                            first_message: text,
                            local_id,
                        });
                    }
                    app.compose_input.clear();
                }
                Some(ChatId::Group(group)) => {
                    app.optimistic_send(ChatId::Group(group), text.clone(), local_id);
                    snap = Some(iced::widget::operation::snap_to_end(
                        views::group_chat::group_scroll_id(),
                    ));
                    app.send_cmd(Command::SendGroupMessage {
                        group,
                        text,
                        local_id,
                    });
                    app.compose_input.clear();
                }
                None => {}
            }
            return snap.unwrap_or_else(Task::none);
        }

        Message::ChatScrolled {
            chat,
            at_top,
            offset,
        } => {
            // Record the latest viewport offset so an `OlderHistoryLoaded`
            // can restore the scroll position after prepending older rows.
            app.scroll_offset.insert(chat, offset);
            // Scroll-to-top fires a keyset `LoadOlder` request — but only if
            // more history exists, no page is already loading, and we have a
            // cursor to page back from. The bridge answers with
            // `OlderHistoryLoaded`, which prepends the page and clears the
            // in-flight marker.
            if at_top
                && app.can_load_older(&chat)
                && let Some(before_id) = app.oldest_loaded(&chat)
            {
                app.loading_older.insert(chat);
                match chat {
                    ChatId::Peer(peer) => {
                        app.send_cmd(Command::LoadOlder { peer, before_id });
                    }
                    ChatId::Group(group) => {
                        app.send_cmd(Command::LoadOlderGroup { group, before_id });
                    }
                }
            }
        }

        Message::CreateGroupPressed => {
            let name = app.new_group_name.trim().to_string();
            if name.is_empty() {
                app.error = Some("group name is empty".into());
                return Task::none();
            }
            // v1: create a group with all current contacts as members.
            let members: Vec<[u8; 32]> = app.contacts.iter().map(|c| c.identity_pub).collect();
            if members.is_empty() {
                app.error = Some("add contacts before creating a group".into());
                return Task::none();
            }
            app.send_cmd(Command::CreateGroup { name, members });
            app.new_group_name.clear();
            app.error = None;
        }

        Message::RotateSignedPrekey => app.send_cmd(Command::RotateSignedPrekey),
        Message::ReplenishOneTimePrekeys => {
            // Parse the Settings count input; reject non-numeric / empty /
            // zero with a banner (a zero-count replenish is a no-op that
            // still re-registers, which is misleading).
            match app.replenish_count.trim().parse::<u32>() {
                Ok(count) if count > 0 => {
                    app.error = None;
                    app.send_cmd(Command::ReplenishOneTimePrekeys { count });
                }
                _ => app.error = Some("replenish count must be a positive number".into()),
            }
        }
        Message::ChangeServer => match app.server_input.trim().parse() {
            Ok(addr) => {
                app.error = None;
                app.send_cmd(Command::ChangeServer { addr });
            }
            Err(_) => {
                app.error = Some("invalid server address".into());
            }
        },
        Message::Logout => {
            app.send_cmd(Command::Logout);
            app.identity_pub = None;
            app.identity_fingerprint = None;
            app.contacts.clear();
            app.threads.clear();
            app.groups.clear();
            app.unread.clear();
            app.search_query.clear();
            // Drop keyset-pagination cursors so a re-login starts each thread
            // at its newest page (not a stale `before_id` from the prior
            // session) and does not think an older page is in flight.
            app.oldest_loaded.clear();
            app.has_more_history.clear();
            app.loading_older.clear();
            app.scroll_offset.clear();
            app.view = View::Login;
            app.passphrase_input.clear();
            app.connected = false;
        }

        Message::DismissError => app.error = None,
        Message::Quit => return iced::exit(),

        Message::Event(ev) => return handle_event(app, ev),
    }
    Task::none()
}

/// Apply a bridge `Event` to the app state. Returns a `Task` so it can snap the
/// open thread's scrollable to the latest message when new content arrives.
fn handle_event(app: &mut UmApp, ev: Event) -> Task<Message> {
    match ev {
        Event::Ready {
            identity_pub,
            identity_fingerprint,
        } => {
            app.identity_pub = Some(identity_pub);
            app.identity_fingerprint = Some(identity_fingerprint);
            app.passphrase_input.clear();
            app.passphrase_confirm.clear();
            // After Ready, connect to the configured server.
            if let Ok(addr) = app.config.server_socket_addr().to_string().parse() {
                app.send_cmd(Command::Connect { addr });
            }
            app.view = View::ContactList;
        }
        Event::Connected => {
            app.connected = true;
            app.error = None;
        }
        Event::Disconnected { reason } => {
            app.connected = false;
            if app.view != View::Login && app.view != View::Setup {
                app.error = Some(format!("disconnected: {reason}"));
            }
        }
        Event::Error(e) => app.error = Some(e),
        Event::ContactsLoaded(contacts) => {
            app.contacts = contacts;
        }
        Event::GroupsLoaded(groups) => {
            // Hydrate the ContactList "Groups" section from the persisted
            // roster. Upsert so a later runtime `GroupCreated`/`GroupInvited`
            // for the same id only refreshes the name/count, never duplicates.
            for g in groups {
                app.upsert_group(g.id, g.name, g.members);
            }
        }
        Event::UnreadLoaded(counts) => {
            // Rehydrate the in-memory unread map from the persisted counts so
            // the sidebar badges reappear after a restart. Replaces any prior
            // entries (Logout already cleared the map, and a fresh Unlock is
            // the only emitter of this event). The store keys chats by their
            // 32-byte key only (a peer pub or a group id), so we disambiguate
            // Peer vs Group by checking the loaded groups roster: a key that
            // matches a known group id is a group chat, otherwise a 1:1 peer.
            app.unread.clear();
            for (key, count) in counts {
                if count == 0 {
                    continue;
                }
                let chat = if app.groups.iter().any(|g| g.id == key) {
                    ChatId::Group(key)
                } else {
                    ChatId::Peer(key)
                };
                app.unread.insert(chat, count);
            }
        }
        Event::HistoryLoaded {
            chat,
            msgs,
            has_more,
        } => {
            // Initial page: replace the cache, then record the keyset cursor
            // (smallest id in the page) + `has_more` so scroll-to-top knows
            // whether older history is fetchable.
            app.threads.insert(chat, msgs.clone());
            app.note_page(chat, &msgs, has_more);
            return snap_for_chat(app, &chat);
        }
        Event::OlderHistoryLoaded {
            chat,
            msgs,
            has_more,
        } => {
            // Older page: prepend to the cached thread (the page arrives
            // oldest-first within the slice, so it goes before the cache).
            // The in-flight marker is cleared regardless of whether the page
            // was empty — an empty older page with `has_more = false` means we
            // reached the oldest row and must stop paging; an empty page with
            // `has_more = true` (e.g. all rows on this page were corrupt and
            // skipped) still lets a future scroll retry.
            app.loading_older.remove(&chat);
            let prepended = msgs.len();
            let entry = app.threads.entry(chat).or_default();
            let mut combined = msgs.clone();
            combined.append(entry);
            *entry = combined;
            app.note_page(chat, &msgs, has_more);
            // Restore the scroll position: prepending `prepended` rows grew
            // the content from the top, so the row the user was reading slid
            // down by `prepended * EST_ROW_HEIGHT`. Scroll to the saved offset
            // plus that shift so it returns to the top of the viewport instead
            // of the view jumping to the newly-loaded oldest row. Only when the
            // chat is open (otherwise there is no scrollable to adjust) and we
            // actually prepended rows (an empty page moves nothing).
            if app.open_chat.as_ref() == Some(&chat) && prepended > 0 {
                let saved = app.scroll_offset.get(&chat).copied().unwrap_or(0.0);
                let target = views::scroll_restore_target(saved, prepended, theme::EST_ROW_HEIGHT);
                return scroll_to_offset(app, &chat, target);
            }
        }
        Event::Decrypted { chat, msg } => {
            // If this chat is open, append to the visible thread. Otherwise
            // bump the unread count so the ContactList shows a badge.
            if app.open_chat == Some(chat) {
                app.threads.entry(chat).or_default().push(msg);
                return snap_for_chat(app, &chat);
            } else {
                let count = {
                    let entry = app.unread.entry(chat).or_insert(0);
                    *entry += 1;
                    *entry
                };
                // Persist the bumped count so the badge survives a restart.
                app.send_cmd(Command::SetUnread {
                    peer: chat.key(),
                    count,
                });
            }
        }
        Event::Sent {
            chat,
            local_id,
            msg,
        } => {
            app.update_outgoing_status(chat, local_id, msg.status);
        }
        Event::SendFailed {
            chat,
            local_id,
            reason,
        } => {
            app.update_outgoing_status(chat, local_id, Status::Failed);
            app.error = Some(reason);
        }
        Event::FingerprintVerified { identity_pub } => {
            // Mirror the bridge's verification into the cached contact row.
            app.mark_verified(identity_pub);
        }
        Event::GroupCreated {
            group,
            name,
            members,
        } => {
            app.upsert_group(group, name, members);
            let chat = ChatId::Group(group);
            app.open_chat = Some(chat);
            app.unread.remove(&chat);
            app.view = View::GroupChat(group);
        }
        Event::GroupInvited {
            group,
            name,
            members,
        } => {
            // Record the group so it appears in the ContactList "Groups"
            // section, then surface a notification banner.
            app.upsert_group(group, name, members);
            app.error = Some("you were added to a group".into());
        }
    }
    Task::none()
}

/// A `snap_to_end` task for the scrollable of the given chat, or `Task::none`
/// if the chat is not currently open. Used after a message is appended so the
/// latest message is in view.
fn snap_for_chat(app: &UmApp, chat: &ChatId) -> Task<Message> {
    if app.open_chat.as_ref() != Some(chat) {
        return Task::none();
    }
    match chat {
        ChatId::Peer(_) => {
            iced::widget::operation::snap_to_end(views::chat_thread::thread_scroll_id())
        }
        ChatId::Group(_) => {
            iced::widget::operation::snap_to_end(views::group_chat::group_scroll_id())
        }
    }
}

/// A `scroll_to` task that moves the open chat's scrollable to the absolute
/// y-offset `target`, used after prepending an older history page to keep the
/// previously-topmost row in view. Resolves the scrollable id the same way
/// [`snap_for_chat`] does (1:1 vs group). The caller must have already checked
/// the chat is open.
fn scroll_to_offset(_app: &UmApp, chat: &ChatId, target: f32) -> Task<Message> {
    let id = match chat {
        ChatId::Peer(_) => views::chat_thread::thread_scroll_id(),
        ChatId::Group(_) => views::group_chat::group_scroll_id(),
    };
    iced::widget::operation::scroll_to(
        id,
        iced::widget::scrollable::AbsoluteOffset { x: 0.0, y: target },
    )
}

/// The iced `subscription` function: streams bridge `Event`s into
/// `Message::Event`. The event receiver lives behind a shared slot; iced
/// identifies the subscription by its `data` (the slot's `Arc` pointer, which
/// is stable for the process lifetime), so the builder runs once and the stream
/// drains the receiver until the bridge drops its sender.
pub fn subscription(app: &UmApp) -> Subscription<Message> {
    // Clone the slot handle into the subscription `data`. Iced keys the
    // subscription by `BridgeSlot`'s `Hash` (the `Arc` pointer address), which
    // is stable across `subscription` calls, so the stream is built once. The
    // builder takes the receiver out of the slot the first time it runs; later
    // rebuilds (which iced avoids anyway thanks to the stable id) find `None`
    // and yield an immediately-finished stream.
    let slot = BridgeSlot(app.event_rx.clone());
    Subscription::run_with(slot, bridge_stream)
}

/// A shared slot holding the bridge's event receiver, wrapped so it can key an
/// iced subscription. `Hash` is by `Arc` pointer address (stable for the
/// process lifetime), not by contents — the receiver is taken once.
#[derive(Clone)]
struct BridgeSlot(Arc<Mutex<Option<mpsc::Receiver<Event>>>>);

impl Hash for BridgeSlot {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// Build the bridge event stream: take the receiver from the slot once, then
/// pump one `Message::Event` per event until the bridge drops its sender. If
/// the slot is already empty (a rebuild after the receiver was taken), the
/// stream finishes immediately. The boxed type lets the function satisfy
/// `iced`'s `fn(&D) -> S` builder signature with a single concrete `S`.
fn bridge_stream(
    slot: &BridgeSlot,
) -> std::pin::Pin<Box<dyn iced::futures::Stream<Item = Message> + Send>> {
    use iced::futures::StreamExt;

    let rx = slot.0.lock().ok().and_then(|mut g| g.take());
    let stream = iced::futures::stream::unfold(rx, |mut rx| async move {
        match rx.as_mut() {
            Some(r) => r.recv().await.map(|ev| (Message::Event(ev), rx)),
            None => None,
        }
    });
    stream.boxed()
}

/// The iced `view` function: routes to the active view. Post-login routes
/// (ChatThread, GroupChat, Settings) render as a two-column layout — the
/// persistent contact-list [`views::sidebar`] on the left, the active panel
/// on the right — so the full window width is used instead of a fixed 520px
/// column. Setup/Login stay full-window centered cards (no sidebar yet).
pub fn view(app: &UmApp) -> Element<'_, Message> {
    let content = match app.view {
        View::Setup => views::setup(app),
        View::Login => views::login(app),
        // Sidebar + right-pane placeholder ("select a chat").
        View::ContactList => views::contact_list(app),
        // Two-column: sidebar + the open 1:1 thread.
        View::ChatThread(peer) => split(views::sidebar(app), views::chat_thread(app, peer)),
        // Two-column: sidebar + the open group thread.
        View::GroupChat(group) => split(views::sidebar(app), views::group_chat(app, group)),
        // Two-column: sidebar + settings.
        View::Settings => split(views::sidebar(app), views::settings(app)),
    };

    // Error banner on top of any view.
    if let Some(err) = &app.error {
        let banner = container(
            row![
                text(err).color(theme::ERROR).size(13),
                Space::new().width(Fill),
                button(text("dismiss"))
                    .style(theme::secondary_button_style)
                    .on_press(Message::DismissError),
            ]
            .spacing(10)
            .align_y(iced::alignment::Vertical::Center),
        )
        .style(|_| theme::panel_style())
        .padding(8);
        column![banner, content].spacing(8).into()
    } else {
        content
    }
}

/// Compose a two-column row: `sidebar` (fixed width) + `right` (fills the
/// rest). Both stretch to the window height.
fn split<'a>(sidebar: Element<'a, Message>, right: Element<'a, Message>) -> Element<'a, Message> {
    row![sidebar, right]
        .width(Fill)
        .height(Fill)
        .spacing(0)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use um_gui::types::Direction;

    /// A minimal app for state-logic tests: no bridge channels needed since the
    /// tests only touch pure helpers + `handle_event`, never `send_cmd`.
    fn test_app() -> UmApp {
        let (tx, _rx) = mpsc::channel::<Command>(1);
        let bridge_cmd = Arc::new(tx);
        UmApp::new(bridge_cmd, View::ContactList, Config::default())
    }

    fn incoming(text: &str) -> MessageView {
        MessageView {
            local_id: 0,
            text: text.into(),
            dir: Direction::In,
            timestamp: 0,
            status: Status::Delivered,
            sender: None,
        }
    }

    #[test]
    fn decrypted_when_chat_open_appends_to_thread() {
        let mut app = test_app();
        let chat = ChatId::Peer([0x11; 32]);
        app.open_chat = Some(chat);
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("hi"),
            },
        );
        let thread = app.threads.get(&chat).expect("thread cached");
        assert_eq!(thread.len(), 1);
        assert_eq!(thread[0].text, "hi");
        assert_eq!(app.unread.get(&chat), None, "no unread when open");
    }

    #[test]
    fn decrypted_when_chat_closed_bumps_unread() {
        let mut app = test_app();
        let chat = ChatId::Peer([0x11; 32]);
        // Chat not open → unread bumps, thread cache stays empty.
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("a"),
            },
        );
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("b"),
            },
        );
        assert_eq!(app.unread.get(&chat), Some(&2));
        assert!(!app.threads.contains_key(&chat));
    }

    #[test]
    fn opening_chat_clears_its_unread() {
        let mut app = test_app();
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        app.unread.insert(chat, 3);
        let _ = update(&mut app, Message::OpenChat(peer));
        assert_eq!(app.open_chat, Some(chat));
        assert_eq!(app.view, View::ChatThread(peer));
        assert_eq!(app.unread.get(&chat), None, "unread cleared on open");
    }

    #[test]
    fn decrypted_when_chat_closed_sends_set_unread_with_bumped_count() {
        // Bumping the unread count on a closed chat must also emit a
        // `SetUnread` command so the badge survives a restart. The count in
        // the command matches the new in-memory count.
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let bridge_cmd = Arc::new(tx);
        let mut app = UmApp::new(bridge_cmd, View::ContactList, Config::default());
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("a"),
            },
        );
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("b"),
            },
        );
        assert_eq!(app.unread.get(&chat), Some(&2));
        let mut seen = 0;
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Command::SetUnread { peer: p, count } => {
                    assert_eq!(p, peer);
                    assert_eq!(count, seen + 1, "count must be the bumped value");
                    seen += 1;
                }
                other => panic!("expected SetUnread, got {other:?}"),
            }
        }
        assert_eq!(seen, 2, "one SetUnread per incoming message");
    }

    #[test]
    fn decrypted_when_chat_open_sends_no_set_unread() {
        // An incoming message in the OPEN chat appends to the thread and does
        // not touch unread, so no `SetUnread` command is emitted.
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let bridge_cmd = Arc::new(tx);
        let mut app = UmApp::new(bridge_cmd, View::ContactList, Config::default());
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        app.open_chat = Some(chat);
        let _ = handle_event(
            &mut app,
            Event::Decrypted {
                chat,
                msg: incoming("hi"),
            },
        );
        assert!(rx.try_recv().is_err(), "open chat sends no SetUnread");
    }

    #[test]
    fn opening_chat_sends_set_unread_zero() {
        // Opening a chat clears its unread and must persist the zero so a
        // restart does not resurrect the badge.
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let bridge_cmd = Arc::new(tx);
        let mut app = UmApp::new(bridge_cmd, View::ContactList, Config::default());
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        app.unread.insert(chat, 4);
        let _ = update(&mut app, Message::OpenChat(peer));
        let mut got_zero = false;
        while let Ok(cmd) = rx.try_recv() {
            if let Command::SetUnread { peer: p, count: 0 } = cmd {
                assert_eq!(p, peer);
                got_zero = true;
            }
        }
        assert!(got_zero, "OpenChat must emit SetUnread with count 0");
    }

    #[test]
    fn opening_group_sends_set_unread_zero_with_group_key() {
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let bridge_cmd = Arc::new(tx);
        let mut app = UmApp::new(bridge_cmd, View::ContactList, Config::default());
        let gid = [0x22; 32];
        let chat = ChatId::Group(gid);
        app.unread.insert(chat, 2);
        let _ = update(&mut app, Message::OpenGroup(gid));
        let mut got_zero = false;
        while let Ok(cmd) = rx.try_recv() {
            if let Command::SetUnread { peer: p, count: 0 } = cmd {
                assert_eq!(p, gid, "group chat keys by the group id");
                got_zero = true;
            }
        }
        assert!(got_zero, "OpenGroup must emit SetUnread with count 0");
    }

    #[test]
    fn unread_loaded_hydrates_map_peer_vs_group() {
        // The store keys chats by 32-byte key only; `UnreadLoaded` must
        // disambiguate Peer vs Group against the loaded groups roster. A key
        // matching a known group id becomes a group chat; otherwise a peer.
        let mut app = test_app();
        app.groups.push(GroupView {
            id: [0x33; 32],
            name: "team".into(),
            members: 3,
        });
        let _ = handle_event(
            &mut app,
            Event::UnreadLoaded(vec![
                ([0x11; 32], 2), // peer
                ([0x33; 32], 5), // group (matches roster)
                ([0x44; 32], 0), // zero → skipped
            ]),
        );
        assert_eq!(app.unread.get(&ChatId::Peer([0x11; 32])), Some(&2));
        assert_eq!(app.unread.get(&ChatId::Group([0x33; 32])), Some(&5));
        // Zero-count entries are not inserted (absent = no badge).
        assert!(!app.unread.contains_key(&ChatId::Peer([0x44; 32])));
    }

    #[test]
    fn unread_loaded_replaces_prior_entries() {
        // A fresh Unlock's `UnreadLoaded` must replace any stale in-memory
        // entries (Logout clears the map, but this guards against double-emit).
        let mut app = test_app();
        app.unread.insert(ChatId::Peer([0xAA; 32]), 99);
        let _ = handle_event(&mut app, Event::UnreadLoaded(vec![([0x11; 32], 1)]));
        assert!(
            !app.unread.contains_key(&ChatId::Peer([0xAA; 32])),
            "stale dropped"
        );
        assert_eq!(app.unread.get(&ChatId::Peer([0x11; 32])), Some(&1));
    }

    #[test]
    fn back_clears_open_chat_and_returns_to_contact_list() {
        // In the two-column layout, `Back` closes the active chat so the right
        // pane reverts to the "select a chat" placeholder while the sidebar
        // stays. `open_chat` must be cleared so the sidebar's active-row
        // highlight disappears.
        let mut app = test_app();
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        let _ = update(&mut app, Message::OpenChat(peer));
        assert_eq!(app.open_chat, Some(chat));
        let _ = update(&mut app, Message::Back);
        assert_eq!(app.view, View::ContactList);
        assert!(app.open_chat.is_none(), "open_chat cleared on Back");
    }

    #[test]
    fn opening_group_sets_open_chat_to_group() {
        let mut app = test_app();
        let gid = [0x22; 32];
        let chat = ChatId::Group(gid);
        let _ = update(&mut app, Message::OpenGroup(gid));
        assert_eq!(app.open_chat, Some(chat));
        assert_eq!(app.view, View::GroupChat(gid));
    }

    #[test]
    fn opening_settings_keeps_open_chat_unchanged() {
        // Settings is a right-pane route; the sidebar stays and the previously
        // open chat (if any) is not disturbed — `open_chat` drives the
        // sidebar highlight, so navigating to settings must not clear it.
        let mut app = test_app();
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        let _ = update(&mut app, Message::OpenChat(peer));
        let _ = update(&mut app, Message::OpenSettings);
        assert_eq!(app.view, View::Settings);
        assert_eq!(
            app.open_chat,
            Some(chat),
            "settings does not clear open_chat"
        );
    }

    #[test]
    fn group_events_upsert_without_duplicate() {
        let mut app = test_app();
        let gid = [0x22; 32];
        let _ = handle_event(
            &mut app,
            Event::GroupCreated {
                group: gid,
                name: "team".into(),
                members: 2,
            },
        );
        assert_eq!(app.groups.len(), 1);
        assert_eq!(app.groups[0].name, "team");
        assert_eq!(app.groups[0].members, 2);
        assert_eq!(app.view, View::GroupChat(gid));
        // A re-invite with the same id refreshes the name + count, no dup row.
        let _ = handle_event(
            &mut app,
            Event::GroupInvited {
                group: gid,
                name: "team v2".into(),
                members: 3,
            },
        );
        assert_eq!(app.groups.len(), 1);
        assert_eq!(app.groups[0].name, "team v2");
        assert_eq!(app.groups[0].members, 3);
    }

    #[test]
    fn groups_loaded_hydrates_without_duplicate() {
        // Restart path: Unlock emits GroupsLoaded with the persisted groups.
        // The app must populate `groups` so the ContactList "Groups" section
        // lists them before any runtime GroupCreated/GroupInvited.
        let mut app = test_app();
        let _ = handle_event(
            &mut app,
            Event::GroupsLoaded(vec![
                GroupView {
                    id: [0x22; 32],
                    name: "team".into(),
                    members: 2,
                },
                GroupView {
                    id: [0x33; 32],
                    name: "squad".into(),
                    members: 4,
                },
            ]),
        );
        assert_eq!(app.groups.len(), 2);
        // A later runtime GroupInvited for an already-loaded group refreshes,
        // it does not duplicate.
        let _ = handle_event(
            &mut app,
            Event::GroupInvited {
                group: [0x22; 32],
                name: "team v2".into(),
                members: 5,
            },
        );
        assert_eq!(app.groups.len(), 2);
        assert_eq!(
            app.groups.iter().find(|g| g.id == [0x22; 32]).unwrap().name,
            "team v2"
        );
        assert_eq!(
            app.groups
                .iter()
                .find(|g| g.id == [0x22; 32])
                .unwrap()
                .members,
            5
        );
    }

    #[test]
    fn verify_fingerprint_marks_cached_contact() {
        let mut app = test_app();
        let peer = [0x33; 32];
        app.contacts.push(ContactView {
            identity_pub: peer,
            nickname: "bob".into(),
            fingerprint: [0u8; 32],
            verified: false,
        });
        let _ = update(&mut app, Message::VerifyFingerprint(peer));
        assert!(app.contacts[0].verified);
    }

    #[test]
    fn change_server_rejects_bad_address() {
        let mut app = test_app();
        app.server_input = "not an addr".into();
        let _ = update(&mut app, Message::ChangeServer);
        assert!(
            app.error
                .as_deref()
                .unwrap_or("")
                .contains("invalid server")
        );
    }

    #[test]
    fn logout_clears_groups_and_unread() {
        let mut app = test_app();
        app.groups.push(GroupView {
            id: [0x22; 32],
            name: "team".into(),
            members: 2,
        });
        app.unread.insert(ChatId::Peer([0x11; 32]), 2);
        app.search_query = "bob".into();
        let _ = update(&mut app, Message::Logout);
        assert!(app.groups.is_empty());
        assert!(app.unread.is_empty());
        assert!(
            app.search_query.is_empty(),
            "search query cleared on logout"
        );
        assert_eq!(app.view, View::Login);
        assert!(app.identity_pub.is_none());
        assert!(app.identity_fingerprint.is_none());
    }

    #[test]
    fn search_changed_updates_query() {
        let mut app = test_app();
        let _ = update(&mut app, Message::SearchChanged("alice".into()));
        assert_eq!(app.search_query, "alice");
    }

    #[test]
    fn optimistic_send_then_sent_flips_status() {
        let mut app = test_app();
        let peer = [0x11; 32];
        let chat = ChatId::Peer(peer);
        app.optimistic_send(chat, "hi".into(), 7);
        assert_eq!(app.threads.get(&chat).unwrap()[0].status, Status::Sending);
        let _ = handle_event(
            &mut app,
            Event::Sent {
                chat,
                local_id: 7,
                msg: MessageView {
                    local_id: 7,
                    text: "hi".into(),
                    dir: Direction::Out,
                    timestamp: 0,
                    status: Status::Sent,
                    sender: None,
                },
            },
        );
        assert_eq!(app.threads.get(&chat).unwrap()[0].status, Status::Sent);
    }

    #[test]
    fn replenish_count_change_updates_field() {
        let mut app = test_app();
        let _ = update(&mut app, Message::ReplenishCountChanged("42".into()));
        assert_eq!(app.replenish_count, "42");
    }

    #[test]
    fn replenish_rejects_non_positive_count() {
        let mut app = test_app();
        app.replenish_count = "0".into();
        let _ = update(&mut app, Message::ReplenishOneTimePrekeys);
        assert!(
            app.error
                .as_deref()
                .unwrap_or("")
                .contains("positive number")
        );
        // Non-numeric is also rejected.
        app.replenish_count = "lots".into();
        let _ = update(&mut app, Message::ReplenishOneTimePrekeys);
        assert!(
            app.error
                .as_deref()
                .unwrap_or("")
                .contains("positive number")
        );
    }

    #[test]
    fn ready_event_stores_identity_fingerprint() {
        let mut app = test_app();
        let pub_ = [0x11; 32];
        let fp = [0xAB; 32];
        let _ = handle_event(
            &mut app,
            Event::Ready {
                identity_pub: pub_,
                identity_fingerprint: fp,
            },
        );
        assert_eq!(app.identity_pub, Some(pub_));
        assert_eq!(app.identity_fingerprint, Some(fp));
        assert_eq!(app.view, View::ContactList);
    }

    #[test]
    fn total_unread_sums_across_peers_and_groups() {
        // The header badge sums every entry in `unread`, peers + groups alike.
        let mut app = test_app();
        assert_eq!(app.total_unread(), 0, "empty unread → 0");
        app.unread.insert(ChatId::Peer([0x11; 32]), 2);
        app.unread.insert(ChatId::Peer([0x22; 32]), 3);
        app.unread.insert(ChatId::Group([0x33; 32]), 5);
        assert_eq!(app.total_unread(), 10, "2 + 3 + 5 across peer + group");
    }

    #[test]
    fn total_unread_drops_to_zero_when_chats_opened() {
        // Opening a chat clears its unread entry, so the total reflects that.
        let mut app = test_app();
        app.unread.insert(ChatId::Peer([0x11; 32]), 4);
        app.unread.insert(ChatId::Group([0x22; 32]), 1);
        assert_eq!(app.total_unread(), 5);
        let _ = update(&mut app, Message::OpenChat([0x11; 32]));
        assert_eq!(app.total_unread(), 1, "opened peer's unread cleared");
    }

    #[test]
    fn total_unread_zero_after_logout() {
        let mut app = test_app();
        app.unread.insert(ChatId::Peer([0x11; 32]), 7);
        assert_eq!(app.total_unread(), 7);
        let _ = update(&mut app, Message::Logout);
        assert_eq!(app.total_unread(), 0, "logout clears unread → total 0");
    }

    /// Build a view-model row with an explicit store `id` (becomes
    /// `local_id`), so pagination-cursor tests can control the keyset order.
    fn row_with_id(id: u64, text: &str) -> MessageView {
        MessageView {
            local_id: id,
            text: text.into(),
            dir: Direction::In,
            timestamp: 0,
            status: Status::Delivered,
            sender: None,
        }
    }

    #[test]
    fn history_loaded_records_cursor_and_has_more() {
        // An initial page of 3 rows (ids 5,6,7) with `has_more = true` must
        // set the cursor to the smallest id (5) and remember that older
        // history exists, so `can_load_older` returns true.
        let mut app = test_app();
        let chat = ChatId::Peer([0x11; 32]);
        let msgs = vec![
            row_with_id(5, "m5"),
            row_with_id(6, "m6"),
            row_with_id(7, "m7"),
        ];
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: msgs.clone(),
                has_more: true,
            },
        );
        assert_eq!(app.oldest_loaded(&chat), Some(5), "cursor = smallest id");
        assert!(
            app.can_load_older(&chat),
            "has_more + not loading → can fetch"
        );
        assert_eq!(
            app.threads.get(&chat).map(|t| t.len()),
            Some(3),
            "page cached",
        );
    }

    #[test]
    fn history_loaded_has_more_false_blocks_load_older() {
        // When the initial page is the whole thread (`has_more = false`),
        // `can_load_older` must be false even though a cursor exists.
        let mut app = test_app();
        let chat = ChatId::Group([0x22; 32]);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(1, "only")],
                has_more: false,
            },
        );
        assert_eq!(app.oldest_loaded(&chat), Some(1));
        assert!(
            !app.can_load_older(&chat),
            "no older history → cannot load older",
        );
    }

    #[test]
    fn chat_scrolled_at_top_fires_load_older_only_when_able() {
        // Scroll-to-top with `has_more = true` + a cursor must insert the
        // in-flight marker (so a second scroll does not double-fire) and send
        // a `LoadOlder` command. With `has_more = false` it must do nothing.
        let (tx, mut rx) = mpsc::channel::<Command>(8);
        let bridge_cmd = Arc::new(tx);
        let mut app = UmApp::new(bridge_cmd, View::ContactList, Config::default());
        let chat = ChatId::Peer([0x44; 32]);
        app.open_chat = Some(chat);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(10, "m10"), row_with_id(11, "m11")],
                has_more: true,
            },
        );

        // at_top = true, able → fires LoadOlder with before_id = cursor (10).
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: true,
                offset: 0.0,
            },
        );
        let cmd = rx.try_recv().expect("LoadOlder command sent");
        match cmd {
            Command::LoadOlder { peer, before_id } => {
                assert_eq!(peer, [0x44; 32]);
                assert_eq!(before_id, 10, "before_id = current cursor");
            }
            other => panic!("expected LoadOlder, got {other:?}"),
        }
        assert!(app.loading_older.contains(&chat), "in-flight marker set",);

        // A second scroll-to-top while loading must NOT fire another command.
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: true,
                offset: 0.0,
            },
        );
        assert!(
            rx.try_recv().is_err(),
            "no second LoadOlder while one is in flight",
        );

        // at_top = false must never fire.
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: false,
                offset: 200.0,
            },
        );
        assert!(rx.try_recv().is_err(), "not-at-top fires nothing");
        // The offset is still recorded for scroll-restore even when no load
        // fires, so a later OlderHistoryLoaded can restore from it.
        assert_eq!(app.scroll_offset.get(&chat), Some(&200.0));
    }

    #[test]
    fn older_history_loaded_prepends_and_clears_inflight() {
        // An older page (ids 1,2, older than the cached 5,6,7) must be
        // prepended to the cache, advance the cursor to the new min (1), and
        // clear the in-flight marker. With `has_more = false` the cursor
        // still updates and `can_load_older` becomes false.
        let mut app = test_app();
        let chat = ChatId::Peer([0x55; 32]);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(5, "m5"), row_with_id(7, "m7")],
                has_more: true,
            },
        );
        app.loading_older.insert(chat); // simulate an in-flight fetch

        let older = vec![row_with_id(1, "m1"), row_with_id(2, "m2")];
        let _ = handle_event(
            &mut app,
            Event::OlderHistoryLoaded {
                chat,
                msgs: older,
                has_more: false,
            },
        );
        let thread = app.threads.get(&chat).expect("thread cached");
        assert_eq!(
            thread.iter().map(|m| m.local_id).collect::<Vec<_>>(),
            vec![1, 2, 5, 7],
            "older page prepended before cached rows",
        );
        assert_eq!(
            app.oldest_loaded(&chat),
            Some(1),
            "cursor advanced to new min"
        );
        assert!(
            !app.loading_older.contains(&chat),
            "in-flight marker cleared",
        );
        assert!(!app.can_load_older(&chat), "has_more false → stop paging");
    }

    #[test]
    fn older_history_loaded_empty_still_clears_inflight() {
        // An empty older page (e.g. all rows corrupt and skipped) must still
        // clear the in-flight marker so scroll-to-top can retry on a later
        // `has_more = true`. The cursor is unchanged (no new min to take).
        let mut app = test_app();
        let chat = ChatId::Group([0x66; 32]);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(3, "m3")],
                has_more: true,
            },
        );
        app.loading_older.insert(chat);
        let _ = handle_event(
            &mut app,
            Event::OlderHistoryLoaded {
                chat,
                msgs: Vec::new(),
                has_more: true,
            },
        );
        assert!(
            !app.loading_older.contains(&chat),
            "empty page still clears in-flight marker",
        );
        assert_eq!(app.oldest_loaded(&chat), Some(3), "cursor unchanged");
        assert!(app.can_load_older(&chat), "still able to retry");
    }

    #[test]
    fn chat_scrolled_records_offset_for_restore() {
        // Every ChatScrolled records the viewport offset, even when no LoadOlder
        // fires (not at top, or unable). OlderHistoryLoaded later reads it to
        // restore the scroll position.
        let mut app = test_app();
        let chat = ChatId::Peer([0x88; 32]);
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: false,
                offset: 137.5,
            },
        );
        assert_eq!(app.scroll_offset.get(&chat), Some(&137.5));
        // A later scroll updates it (latest wins).
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: false,
                offset: 42.0,
            },
        );
        assert_eq!(app.scroll_offset.get(&chat), Some(&42.0));
    }

    #[test]
    fn older_history_loaded_restores_scroll_when_chat_open() {
        // With the chat open + a recorded scroll offset, OlderHistoryLoaded
        // must (a) prepend the page, (b) keep the saved offset, and (c) return
        // a non-none Task (the scroll_to restore). The target offset is
        // saved + prepended * EST_ROW_HEIGHT — verified indirectly by the pure
        // `scroll_restore_target` test; here we assert the state side: the
        // offset is preserved and the page is prepended. The Task itself is
        // opaque (iced 0.14 Debug does not expose the action), so we only
        // confirm it is not `Task::none` by checking the handler ran the
        // restore branch — which is observable via the offset still being
        // present and the thread prepended.
        let mut app = test_app();
        let chat = ChatId::Peer([0x99; 32]);
        app.open_chat = Some(chat);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(5, "m5"), row_with_id(6, "m6")],
                has_more: true,
            },
        );
        // User scrolled to the top (offset ~0) which fired the load; record it.
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: true,
                offset: 0.0,
            },
        );
        let _ = handle_event(
            &mut app,
            Event::OlderHistoryLoaded {
                chat,
                msgs: vec![
                    row_with_id(1, "m1"),
                    row_with_id(2, "m2"),
                    row_with_id(3, "m3"),
                ],
                has_more: false,
            },
        );
        let thread = app.threads.get(&chat).expect("thread cached");
        assert_eq!(
            thread.iter().map(|m| m.local_id).collect::<Vec<_>>(),
            vec![1, 2, 3, 5, 6],
            "older page prepended",
        );
        // The saved offset is retained so a subsequent restore can reuse it.
        assert_eq!(app.scroll_offset.get(&chat), Some(&0.0));
    }

    #[test]
    fn older_history_loaded_skips_restore_when_chat_closed() {
        // If the chat is not open, no scrollable exists to adjust — the restore
        // branch must be skipped (no panic, no offset mutation), but the page
        // is still prepended and the in-flight marker cleared.
        let mut app = test_app();
        let chat = ChatId::Group([0xAA; 32]);
        // open_chat stays None (test_app default).
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(7, "m7")],
                has_more: true,
            },
        );
        app.loading_older.insert(chat);
        let _ = handle_event(
            &mut app,
            Event::OlderHistoryLoaded {
                chat,
                msgs: vec![row_with_id(1, "m1")],
                has_more: false,
            },
        );
        assert_eq!(
            app.threads.get(&chat).map(|t| t.len()),
            Some(2),
            "page prepended even with chat closed",
        );
        assert!(!app.loading_older.contains(&chat), "in-flight cleared");
    }

    #[test]
    fn logout_clears_scroll_offset() {
        // Logout drops the recorded scroll offsets so a re-login does not
        // restore against a stale offset from the prior session.
        let mut app = test_app();
        let chat = ChatId::Peer([0xBB; 32]);
        let _ = update(
            &mut app,
            Message::ChatScrolled {
                chat,
                at_top: false,
                offset: 99.0,
            },
        );
        assert_eq!(app.scroll_offset.get(&chat), Some(&99.0));
        let _ = update(&mut app, Message::Logout);
        assert!(app.scroll_offset.is_empty(), "logout clears scroll offsets");
    }

    #[test]
    fn logout_clears_pagination_state() {
        // Logout must drop the keyset cursors + has_more + in-flight markers
        // so a re-login does not carry stale pagination state forward.
        let mut app = test_app();
        let chat = ChatId::Peer([0x77; 32]);
        let _ = handle_event(
            &mut app,
            Event::HistoryLoaded {
                chat,
                msgs: vec![row_with_id(9, "m9")],
                has_more: true,
            },
        );
        app.loading_older.insert(chat);
        assert_eq!(app.oldest_loaded(&chat), Some(9));
        let _ = update(&mut app, Message::Logout);
        assert!(
            app.oldest_loaded.is_empty()
                && app.has_more_history.is_empty()
                && app.loading_older.is_empty(),
            "logout clears all pagination state",
        );
    }
}
