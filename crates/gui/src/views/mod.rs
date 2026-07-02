//! The six views. Each is a function returning `iced::Element<Message>`. The
//! router in [`crate::app::view`] matches the active `View`. All user input
//! becomes a `Message`; views never touch `um_client` or async directly.
//!
//! `parse_pubkey_hex` and `route_after_event` are pure functions extracted for
//! unit testing without iced.

pub mod chat_thread;
pub mod contact_list;
pub mod group_chat;
pub mod login;
pub mod settings;
pub mod setup;

use std::fmt::Write as _;

// Re-export the app types so each view submodule can write
// `use super::{Message, UmApp}` without importing from `crate::app` directly.
pub use crate::app::{Message, UmApp, View};

/// Parse a 64-char hex string into a 32-byte identity pub. Pure, testable.
pub fn parse_pubkey_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("expected 64 hex chars (32 bytes)".into());
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("bad hex digit".into()),
    }
}

/// Pure view transition: given a bridge `Event` and the current `View`, what
/// `View` should the app show next? Tested without iced. The app's
/// `handle_event` is the real authority; this mirrors its routing for the
/// cases where the view changes, so the logic is unit-testable.
#[allow(dead_code)]
pub fn route_after_event(ev: &crate::Event, _current: &View) -> Option<View> {
    match ev {
        crate::Event::Ready { .. } => Some(View::ContactList),
        crate::Event::GroupCreated { group, .. } => Some(View::GroupChat(*group)),
        _ => None,
    }
}
/// Render the first 4 bytes of a key as short hex for display.
pub fn short_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(11);
    for b in &bytes[..4] {
        let _ = write!(s, "{b:02x}");
    }
    s.push('…');
    s
}

/// Full lowercase hex of a 32-byte key.
pub fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

pub use chat_thread::chat_thread;
pub use contact_list::contact_list;
pub use group_chat::group_chat;
pub use login::login;
pub use settings::settings;
pub use setup::setup;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatId, Direction, Event, MessageView, Status};

    #[test]
    fn parse_pubkey_hex_round_trips() {
        let v = [0xAB; 32];
        let s = hex::encode(v);
        assert_eq!(parse_pubkey_hex(&s).unwrap(), v);
    }

    #[test]
    fn parse_pubkey_hex_rejects_short() {
        assert!(parse_pubkey_hex("ab").is_err());
    }

    #[test]
    fn parse_pubkey_hex_rejects_bad_digit() {
        let bad = "zz".to_string() + &"00".repeat(31);
        assert!(parse_pubkey_hex(&bad).is_err());
    }

    #[test]
    fn route_after_event_ready_goes_to_contact_list() {
        let ev = Event::Ready {
            identity_pub: [0x11; 32],
            identity_fingerprint: [0xAB; 32],
        };
        assert_eq!(
            route_after_event(&ev, &View::Login),
            Some(View::ContactList)
        );
    }

    #[test]
    fn route_after_event_group_created_opens_group_chat() {
        let gid = [0x22; 32];
        let ev = Event::GroupCreated {
            group: gid,
            name: "team".into(),
            members: 2,
        };
        assert_eq!(
            route_after_event(&ev, &View::ContactList),
            Some(View::GroupChat(gid))
        );
    }

    #[test]
    fn route_after_event_decrypted_no_view_change() {
        let ev = Event::Decrypted {
            chat: ChatId::Peer([0x33; 32]),
            msg: MessageView {
                local_id: 1,
                text: "hi".into(),
                dir: Direction::In,
                timestamp: 0,
                status: Status::Delivered,
            },
        };
        assert_eq!(route_after_event(&ev, &View::ChatThread([0x33; 32])), None);
    }

    #[test]
    fn short_hex_is_short() {
        assert_eq!(short_hex(&[0xAB; 32]), "abababab…");
    }
}
