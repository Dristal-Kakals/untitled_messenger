//! Events the bridge emits to the GUI (bridge → GUI), delivered to iced
//! through `iced::subscription::run` as `Message::Event(Event)`.

use crate::types::{ChatId, ContactView, GroupView, MessageView};

/// An event from the async bridge to the iced UI.
#[derive(Debug, Clone)]
pub enum Event {
    // ---- Lifecycle -----------------------------------------------------
    /// Setup or Unlock succeeded; the identity is ready. Carries the identity
    /// pub (so the UI can display it) and the identity fingerprint
    /// (`SHA-256` of the pub, so the Settings view can show it per the spec
    /// without re-deriving it in the display layer).
    Ready {
        identity_pub: [u8; 32],
        identity_fingerprint: [u8; 32],
    },
    /// Connected to the relay, registered, and subscribed for push.
    Connected,
    /// The recv-loop died; the bridge will retry with backoff.
    Disconnected { reason: String },
    /// A human-readable error surfaced as a banner.
    Error(String),

    // ---- Data ----------------------------------------------------------
    /// Contacts loaded from the store (after Unlock).
    ContactsLoaded(Vec<ContactView>),
    /// Groups loaded from the store (after Unlock). Lets the ContactList
    /// "Groups" section list known groups immediately on restart, before any
    /// fresh distribution arrives. Each entry is id + display name.
    GroupsLoaded(Vec<GroupView>),
    /// Thread history loaded from the store (response to `LoadThread` /
    /// `LoadGroupThread`). Replaces the cache for that chat.
    HistoryLoaded(ChatId, Vec<MessageView>),
    /// An incoming message was decrypted + persisted.
    Decrypted { chat: ChatId, msg: MessageView },
    /// Our outgoing message was encrypted + sent to the relay.
    Sent {
        chat: ChatId,
        local_id: u64,
        msg: MessageView,
    },
    /// Sending failed; the cached row flips to `Failed`.
    SendFailed {
        chat: ChatId,
        local_id: u64,
        reason: String,
    },
    /// A contact's fingerprint was marked verified.
    FingerprintVerified { identity_pub: [u8; 32] },

    // ---- Group ---------------------------------------------------------
    /// A group was created locally. `members` is the roster size (founder +
    /// invitees), so the GroupChat header can show "name (N members)".
    GroupCreated {
        group: [u8; 32],
        name: String,
        members: u32,
    },
    /// We were added to a group (received a sender-key distribution). `members`
    /// is the roster size the bridge knows so far (at least the inviter + us).
    GroupInvited {
        group: [u8; 32],
        name: String,
        members: u32,
    },
}
