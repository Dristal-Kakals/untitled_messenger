//! The iced `Application`: display-only state, `Message` enum, `update()`,
//! `subscription()`, and `view()`. Views never touch `um_client` or async
//! directly — they emit `Message`s, which `update` maps to bridge `Command`s.

use std::collections::HashMap;
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
            app.view = View::ChatThread(peer);
            app.send_cmd(Command::LoadThread { peer });
        }
        Message::OpenGroup(group) => {
            let chat = ChatId::Group(group);
            app.open_chat = Some(chat);
            app.unread.remove(&chat);
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
        Event::HistoryLoaded(chat, msgs) => {
            app.threads.insert(chat, msgs);
            return snap_for_chat(app, &chat);
        }
        Event::Decrypted { chat, msg } => {
            // If this chat is open, append to the visible thread. Otherwise
            // bump the unread count so the ContactList shows a badge.
            if app.open_chat == Some(chat) {
                app.threads.entry(chat).or_default().push(msg);
                return snap_for_chat(app, &chat);
            } else {
                *app.unread.entry(chat).or_insert(0) += 1;
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
}
