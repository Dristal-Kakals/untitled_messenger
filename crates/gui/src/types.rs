//! Plain view-data shared between the bridge and the iced views. No `um_client`
//! or crypto types leak here — the GUI only ever holds copies of *data*
//! (pubkeys as `[u8;32]`, message text, status), never live session objects.

/// Identifies a chat: a 1:1 peer (by identity pub) or a group (by group id).
/// Both are 32 bytes; the variant distinguishes 1:1 from group so the views
/// route send/load to the right bridge `Command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatId {
    Peer([u8; 32]),
    Group([u8; 32]),
}

impl ChatId {
    /// The 32-byte key backing this chat id (peer pub or group id).
    pub fn key(&self) -> [u8; 32] {
        match self {
            ChatId::Peer(k) => *k,
            ChatId::Group(k) => *k,
        }
    }

    /// True if this is a 1:1 peer chat.
    pub fn is_peer(&self) -> bool {
        matches!(self, ChatId::Peer(_))
    }
}

/// A contact as the GUI displays it: identity pub, nickname, fingerprint, and
/// whether the fingerprint has been manually verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    pub identity_pub: [u8; 32],
    pub nickname: String,
    pub fingerprint: [u8; 32],
    pub verified: bool,
}

/// A group thread as the GUI lists it: group id, display name, and the member
/// count (number of identity pubs in the roster). Plain data mirroring the
/// bridge's in-memory `group_names` + `group_rosters` (themselves persisted to
/// the store's `groups` / `group_members` tables). The app keeps a `Vec` of
/// these — hydrated from `Event::GroupsLoaded` on Unlock and updated by
/// `Event::GroupCreated` / `Event::GroupInvited` at runtime — so the
/// ContactList "Groups" section can list + open group threads, and the
/// GroupChat header can show "group name (N members)" per the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: [u8; 32],
    pub name: String,
    /// Number of members in the roster (excludes nobody; the founder is a
    /// member of their own group). Drives the GroupChat header member count.
    pub members: u32,
}

/// A single chat message as the GUI displays it. `local_id` is the app's
/// monotonic id used to match optimistic-send rows to later `Event::Sent` /
/// `Event::SendFailed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub local_id: u64,
    pub text: String,
    pub dir: Direction,
    pub timestamp: u64,
    pub status: Status,
}

/// Message direction relative to this client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent by this client.
    Out,
    /// Received from a peer.
    In,
}

/// Delivery status of an outgoing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Not yet handed to the bridge / not yet acked.
    Sending,
    /// Bridge encrypted + sent to the relay.
    Sent,
    /// Server confirmed delivery (future: per-recipient).
    Delivered,
    /// Send or encrypt failed.
    Failed,
}

impl Status {
    /// Encode to the small integer stored in `StoredMessage::status`.
    pub fn as_u8(self) -> u8 {
        match self {
            Status::Sending => 0,
            Status::Sent => 1,
            Status::Delivered => 2,
            Status::Failed => 3,
        }
    }

    /// Decode from the small integer stored in `StoredMessage::status`.
    pub fn from_u8(v: u8) -> Status {
        match v {
            1 => Status::Sent,
            2 => Status::Delivered,
            3 => Status::Failed,
            _ => Status::Sending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_id_key_and_is_peer() {
        let peer = ChatId::Peer([0x11; 32]);
        let group = ChatId::Group([0x22; 32]);
        assert_eq!(peer.key(), [0x11; 32]);
        assert_eq!(group.key(), [0x22; 32]);
        assert!(peer.is_peer());
        assert!(!group.is_peer());
        assert_ne!(peer, group);
    }

    #[test]
    fn group_view_equality() {
        let g = GroupView {
            id: [0x55; 32],
            name: "team".into(),
            members: 3,
        };
        assert_eq!(g, g.clone());
        assert_ne!(
            g,
            GroupView {
                id: [0x56; 32],
                ..g.clone()
            }
        );
        assert_ne!(
            g,
            GroupView {
                name: "squad".into(),
                ..g.clone()
            }
        );
        assert_ne!(
            g,
            GroupView {
                members: 4,
                ..g.clone()
            }
        );
    }

    #[test]
    fn status_round_trips_through_u8() {
        for s in [
            Status::Sending,
            Status::Sent,
            Status::Delivered,
            Status::Failed,
        ] {
            assert_eq!(Status::from_u8(s.as_u8()), s);
        }
    }

    #[test]
    fn status_from_unknown_u8_defaults_to_sending() {
        assert_eq!(Status::from_u8(255), Status::Sending);
    }
}
