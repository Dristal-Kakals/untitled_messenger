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
pub const fn route_after_event(ev: &crate::Event, _current: &View) -> Option<View> {
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

/// Case-insensitive substring filter for the sidebar search box. A query
/// matches a contact or group when (a) the query is empty/whitespace (show
/// all), or (b) the trimmed, lowercased query is a substring of any of the
/// provided haystack strings — typically the nickname / group name and the
/// lowercase hex of the identity pub or group id. Pure, testable.
///
/// Whitespace in the query is ignored so a stray space never hides everything.
pub fn matches_query(query: &str, haystacks: &[&str]) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    haystacks.iter().any(|h| h.to_lowercase().contains(&q))
}

/// Format a unix-seconds timestamp as `HH:MM` (UTC). Returns `""` for `0`
/// (the optimistic-send placeholder timestamp, which is not a real time).
/// Pure, testable.
pub fn format_time(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return String::new();
    }
    let secs_per_day = 86_400u64;
    let days = unix_secs / secs_per_day;
    let rem = unix_secs % secs_per_day;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    // Civil-from-days (Howard Hinnant's algorithm): days since 1970-01-01 →
    // (year, month, day). Lets us render a date stamp without pulling in
    // `time`/`chrono`.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{min:02}")
}

pub use chat_thread::chat_thread;
pub use contact_list::{contact_list, sidebar};
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
                sender: None,
            },
        };
        assert_eq!(route_after_event(&ev, &View::ChatThread([0x33; 32])), None);
    }

    #[test]
    fn short_hex_is_short() {
        assert_eq!(short_hex(&[0xAB; 32]), "abababab…");
    }

    #[test]
    fn format_time_epoch_zero_is_empty() {
        assert_eq!(format_time(0), "");
    }

    #[test]
    fn format_time_known_stamp() {
        // 2026-07-02 03:10:00 UTC = 1782961800.
        assert_eq!(format_time(1_782_961_800), "2026-07-02 03:10");
    }

    #[test]
    fn format_time_is_utc_not_local() {
        // Same stamp renders identically regardless of the host TZ.
        let a = format_time(1_782_961_800);
        // Re-render — deterministic.
        assert_eq!(a, format_time(1_782_961_800));
        assert!(a.starts_with("2026-07-02"));
    }

    #[test]
    fn matches_query_empty_shows_all() {
        assert!(matches_query("", &["bob"]));
        assert!(matches_query("   ", &["bob"]));
    }

    #[test]
    fn matches_query_substring_case_insensitive() {
        assert!(matches_query("BO", &["bob", "deadbeef…"]));
        assert!(matches_query("bob", &["Bob", "deadbeef…"]));
        assert!(matches_query("dead", &["Bob", "deadbeef…"]));
    }

    #[test]
    fn matches_query_no_match() {
        assert!(!matches_query("zzz", &["bob", "deadbeef…"]));
    }

    #[test]
    fn matches_query_matches_hex_id() {
        // A contact's lowercase hex pub is a haystack, so pasting part of it
        // filters down to that contact.
        let id_hex = hex32(&[0xAB; 32]);
        assert!(matches_query("ababab", &[&id_hex]));
        assert!(!matches_query("cdcdcd", &[&id_hex]));
    }

    #[test]
    fn matches_query_ignores_surrounding_whitespace() {
        assert!(matches_query("  bob  ", &["bob"]));
    }
}
