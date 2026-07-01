//! Events the bridge emits to the GUI (bridge → GUI), delivered to iced
//! through `iced::subscription::run` as `Message::Event(Event)`.

use crate::types::{ChatId, ContactView, MessageView};

/// An event from the async bridge to the iced UI.
#[derive(Debug, Clone)]
pub enum Event {
    // ---- Lifecycle -----------------------------------------------------
    /// Setup or Unlock succeeded; the identity is ready. Carries the identity
    /// pub so the UI can display it.
    Ready { identity_pub: [u8; 32] },
    /// Connected to the relay, registered, and subscribed for push.
    Connected,
    /// The recv-loop died; the bridge will retry with backoff.
    Disconnected { reason: String },
    /// A human-readable error surfaced as a banner.
    Error(String),

    // ---- Data ----------------------------------------------------------
    /// Contacts loaded from the store (after Unlock).
    ContactsLoaded(Vec<ContactView>),
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
    /// A group was created locally.
    GroupCreated { group: [u8; 32], name: String },
    /// We were added to a group (received a sender-key distribution).
    GroupInvited { group: [u8; 32], name: String },
}
