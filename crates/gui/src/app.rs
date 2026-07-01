//! The iced `Application`: display-only state, `Message` enum, `update()`,
//! `subscription()`, and `view()`. Views never touch `um_client` or async
//! directly — they emit `Message`s, which `update` maps to bridge `Command`s.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iced::widget::{button, column, row, text};
use iced::{Element, Subscription, Task};
use tokio::sync::mpsc;

use um_gui::config::Config;
use um_gui::types::{ChatId, ContactView, MessageView, Status};
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
pub struct UmApp {
    pub view: View,
    pub identity_pub: Option<[u8; 32]>,
    pub contacts: Vec<ContactView>,
    /// Which thread is open (peer or group).
    pub open_chat: Option<ChatId>,
    /// In-memory message cache per open chat. The store is source of truth.
    pub threads: HashMap<ChatId, Vec<MessageView>>,
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
    /// Open a group thread from a future persisted group list. Not yet wired
    /// (v1 has no group list view; groups open via `Event::GroupCreated`).
    #[allow(dead_code)]
    OpenGroup([u8; 32]),
    Back,
    // Contacts.
    AddContact,
    // Chat.
    SendPressed,
    // Group.
    CreateGroupPressed,
    // Settings.
    RotateSignedPrekey,
    ReplenishOneTimePrekeys,
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
            contacts: Vec::new(),
            open_chat: None,
            threads: HashMap::new(),
            next_local_id: 1,
            passphrase_input: String::new(),
            passphrase_confirm: String::new(),
            server_input,
            add_contact_hex: String::new(),
            add_contact_nick: String::new(),
            compose_input: String::new(),
            new_group_name: String::new(),
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
    fn next_local_id(&mut self) -> u64 {
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
            app.open_chat = Some(ChatId::Peer(peer));
            app.view = View::ChatThread(peer);
            app.send_cmd(Command::LoadThread { peer });
        }
        Message::OpenGroup(group) => {
            app.open_chat = Some(ChatId::Group(group));
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

        Message::SendPressed => {
            let text = app.compose_input.trim().to_string();
            if text.is_empty() {
                return Task::none();
            }
            let local_id = app.next_local_id();
            match app.open_chat {
                Some(ChatId::Peer(peer)) => {
                    app.optimistic_send(ChatId::Peer(peer), text.clone(), local_id);
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
                    app.send_cmd(Command::SendGroupMessage {
                        group,
                        text,
                        local_id,
                    });
                    app.compose_input.clear();
                }
                None => {}
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
            app.send_cmd(Command::ReplenishOneTimePrekeys { count: 10 });
        }
        Message::Logout => {
            app.send_cmd(Command::Logout);
            app.identity_pub = None;
            app.contacts.clear();
            app.threads.clear();
            app.view = View::Login;
            app.passphrase_input.clear();
            app.connected = false;
        }

        Message::DismissError => app.error = None,
        Message::Quit => return iced::exit(),

        Message::Event(ev) => handle_event(app, ev),
    }
    Task::none()
}

/// Apply a bridge `Event` to the app state.
fn handle_event(app: &mut UmApp, ev: Event) {
    match ev {
        Event::Ready { identity_pub } => {
            app.identity_pub = Some(identity_pub);
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
        Event::HistoryLoaded(chat, msgs) => {
            app.threads.insert(chat, msgs);
        }
        Event::Decrypted { chat, msg } => {
            // Only append if this chat is open; else the unread badge logic
            // (v1: a simple re-render) would bump a count.
            app.threads.entry(chat).or_default().push(msg);
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
        Event::FingerprintVerified { identity_pub: _ } => {
            // v1: verification is UI-local; no state change beyond the contact
            // list re-emit the bridge already sent.
        }
        Event::GroupCreated { group, name: _ } => {
            app.open_chat = Some(ChatId::Group(group));
            app.view = View::GroupChat(group);
        }
        Event::GroupInvited { group: _, name: _ } => {
            // v1: a notification; the group appears once a message arrives.
            app.error = Some("you were added to a group".into());
        }
    }
}

/// The iced `subscription` function: streams bridge `Event`s into
/// `Message::Event`. The event receiver is taken once from the shared slot
/// (iced keys the subscription by id, so the stream is built once and reused).
pub fn subscription(app: &UmApp) -> Subscription<Message> {
    // Take the receiver out of the shared slot once. Iced identifies the
    // subscription by its id (`"um-bridge"`); on subsequent `subscription`
    // calls it keeps the already-running stream and discards the new recipe,
    // so this take happens exactly once. If the slot is already empty (e.g. a
    // rebuild after the receiver was taken), return an empty subscription.
    let rx = {
        let mut guard = match app.event_rx.lock() {
            Ok(g) => g,
            Err(_) => return Subscription::none(),
        };
        match guard.take() {
            Some(rx) => rx,
            None => return Subscription::none(),
        }
    };

    // Drive the receiver as a stream: one `Message::Event` per event, forever.
    // The stream ends only when the bridge drops its event sender (bridge
    // thread exited), which is process-lifetime in practice.
    let stream = iced::futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|ev| (Message::Event(ev), rx))
    });
    Subscription::run_with_id("um-bridge", stream)
}

/// The iced `view` function: routes to the active view.
pub fn view(app: &UmApp) -> Element<'_, Message> {
    let content = match app.view {
        View::Setup => views::setup(app),
        View::Login => views::login(app),
        View::ContactList => views::contact_list(app),
        View::ChatThread(peer) => views::chat_thread(app, peer),
        View::GroupChat(group) => views::group_chat(app, group),
        View::Settings => views::settings(app),
    };

    // Error banner on top of any view.
    if let Some(err) = &app.error {
        let banner = row![
            text(err).color([0.8, 0.2, 0.2]),
            button("dismiss").on_press(Message::DismissError),
        ];
        column![banner, content].into()
    } else {
        content
    }
}
