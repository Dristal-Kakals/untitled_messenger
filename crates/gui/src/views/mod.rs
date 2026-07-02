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
///
/// Thin wrapper over [`query_rank`]: a row matches iff it has a rank.
/// Kept for direct callers/tests even though the sidebar now sorts via
/// [`query_rank`] directly.
#[allow(dead_code)]
pub fn matches_query(query: &str, haystacks: &[&str]) -> bool {
    query_rank(query, haystacks).is_some()
}

/// Ranked match for the sidebar search box. Returns `Some(score)` when the
/// query matches at least one haystack, `None` when it matches none. Lower
/// score = better match; the sidebar sorts rows ascending by score so the
/// best hits float to the top. Empty/whitespace query matches everything with
/// score `0` (all rows tie → original order preserved by stable sort).
///
/// Scoring (per haystack; the minimum across haystacks wins):
/// - **tier 0** — exact (case-insensitive) equality, e.g. query `"bob"` vs
///   nickname `"Bob"`. Best.
/// - **tier 1** — prefix match, e.g. `"bo"` vs `"Bob"`.
/// - **tier 2** — substring match anywhere, e.g. `"ob"` vs `"Bob"`.
///
/// Within a tier, an earlier match position scores lower (so `"al"` at the
/// start of `"alice"` beats `"al"` later in `"real"`).
///
/// A haystack that looks like a hex id (≥8 chars, all ASCII hex digits or
/// the `…` ellipsis used by [`short_hex`]) is penalized by `+500` so a name
/// hit always sorts above a hex-id hit for the same query — pasting part of
/// a pubkey still finds the contact, but it drops below nickname matches.
///
/// The score is `tier * 1000 + position + id_penalty`. The `1000` gap between
/// tiers dwarfs any realistic position (names are short), so tier dominates;
/// position only breaks ties within a tier.
pub fn query_rank(query: &str, haystacks: &[&str]) -> Option<u32> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Some(0);
    }
    let mut best: Option<u32> = None;
    for h in haystacks {
        let hl = h.to_lowercase();
        let (tier, pos) = if hl == q {
            (0u32, 0u32)
        } else if hl.starts_with(&q) {
            (1, 0u32)
        } else if let Some(p) = hl.find(&q) {
            (2, p as u32)
        } else {
            continue;
        };
        // A hex-id haystack (full 64-char pub or the short "abababab…" form)
        // ranks below a name haystack for the same query so nickname hits
        // surface first. `…` is the trailing ellipsis [`short_hex`] appends.
        let is_id = h.len() >= 8 && h.chars().all(|c| c.is_ascii_hexdigit() || c == '…');
        let score = tier * 1000 + pos + u32::from(is_id) * 500;
        best = Some(best.map_or(score, |b: u32| b.min(score)));
    }
    best
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

/// Byte range `(start, end)` of the first case-insensitive match of `query`
/// inside `haystack`, or `None` when the (trimmed) query is empty or does not
/// occur. The range indexes `haystack`'s bytes; the caller slices the original
/// (mixed-case) string with them so the displayed fragment keeps its original
/// capitalization while the *match* itself is case-insensitive.
///
/// Empty/whitespace query → `None` (no highlight: the whole row is shown
/// unstyled, matching the "empty query shows everything" rule of
/// [`query_rank`]). This keeps the highlighter consistent with the filter: a
/// row only gets a highlighted fragment when it actually matched a real query.
///
/// Pure, testable. The sidebar's `highlighted_name` wraps this to build the
/// `iced` `Span` list.
pub fn match_range(query: &str, haystack: &str) -> Option<(usize, usize)> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    let hl = haystack.to_lowercase();
    let start = hl.find(&q)?;
    Some((start, start + q.len()))
}

/// Build the `iced` `Span` list for a display string, highlighting the
/// substring the sidebar search matched. When `query` matches `label`
/// (case-insensitive, via [`match_range`]) the matched fragment is rendered
/// with the accent highlight wash (`theme::HIGHLIGHT` background +
/// `theme::HIGHLIGHT_FG` text); the text before and after it is plain. When
/// there is no match (empty query, or this label was not the haystack that
/// matched — e.g. the nickname matched but we are also rendering the hex id),
/// a single plain span is returned so the row looks unchanged.
///
/// `label` is borrowed for the span lifetimes; the returned `Vec` is fed
/// straight to `iced::widget::rich_text`.
pub fn highlighted_name<'a>(query: &str, label: &'a str) -> Vec<iced::widget::text::Span<'a>> {
    use iced::widget::span;

    let Some((start, end)) = match_range(query, label) else {
        return vec![span(label)];
    };
    let before = &label[..start];
    let mid = &label[start..end];
    let after = &label[end..];
    let mut spans = Vec::with_capacity(3);
    if !before.is_empty() {
        spans.push(span(before));
    }
    spans.push(
        span(mid)
            .color(crate::theme::HIGHLIGHT_FG)
            .background(crate::theme::HIGHLIGHT),
    );
    if !after.is_empty() {
        spans.push(span(after));
    }
    spans
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

    #[test]
    fn query_rank_empty_is_zero() {
        assert_eq!(query_rank("", &["bob"]), Some(0));
        assert_eq!(query_rank("   ", &["bob"]), Some(0));
    }

    #[test]
    fn query_rank_no_match_is_none() {
        assert_eq!(query_rank("zzz", &["bob", "deadbeef…"]), None);
    }

    #[test]
    fn query_rank_exact_beats_prefix_beats_substring() {
        // "bob" exact, "bobby" prefix, "barboba" substring.
        let exact = query_rank("bob", &["bob"]).unwrap();
        let prefix = query_rank("bob", &["bobby"]).unwrap();
        let substr = query_rank("bob", &["barboba"]).unwrap();
        assert!(exact < prefix, "{exact} should beat {prefix}");
        assert!(prefix < substr, "{prefix} should beat {substr}");
    }

    #[test]
    fn query_rank_earlier_position_beats_later_within_tier() {
        // Both substring (tier 2) matches; "al" at pos 0 in "alice" beats
        // "al" at pos 2 in "real".
        let early = query_rank("al", &["alice"]).unwrap();
        let late = query_rank("al", &["real"]).unwrap();
        assert!(
            early < late,
            "earlier match ({early}) should beat later ({late})"
        );
    }

    #[test]
    fn query_rank_name_beats_hex_id_for_same_query() {
        // Query "ab" matches both a nickname-ish "ab" and a hex id. The name
        // hit must rank strictly below the hex-id hit so nickname matches
        // float above pasted-pubkey matches in the sidebar.
        let name = query_rank("ab", &["ab"]).unwrap();
        let id = query_rank("ab", &["abababababababab"]).unwrap();
        assert!(name < id, "name ({name}) should beat hex id ({id})");
    }

    #[test]
    fn query_rank_takes_min_across_haystacks() {
        // "bob" matches the nickname exactly (tier 0) and the hex id as
        // substring (tier 2 + id penalty). The row's rank is the better
        // (lower) of the two — the nickname wins.
        let id_hex = hex32(&[0xAB; 32]); // contains "ababab…", no "bob" → no match
        let rank = query_rank("bob", &["bob", &id_hex]).unwrap();
        assert_eq!(rank, 0, "exact nickname match → tier 0, score 0");
    }

    #[test]
    fn query_rank_short_hex_is_treated_as_id() {
        // short_hex form "abababab…" is ≥8 chars and all hex/ellipsis → id
        // penalty applies, so a nickname prefix match beats it.
        let name_prefix = query_rank("ab", &["abbot"]).unwrap();
        let short = query_rank("ab", &["abababab…"]).unwrap();
        assert!(
            name_prefix < short,
            "name prefix ({name_prefix}) should beat short-hex ({short})"
        );
    }

    #[test]
    fn match_range_empty_query_is_none() {
        assert_eq!(match_range("", "bob"), None);
        assert_eq!(match_range("   ", "bob"), None);
    }

    #[test]
    fn match_range_no_match_is_none() {
        assert_eq!(match_range("zzz", "bob"), None);
    }

    #[test]
    fn match_range_substring_case_insensitive() {
        // "BO" matches "bob" at byte range (0, 2) — indexes the original
        // (lowercase) haystack so the caller slices the mixed-case label.
        assert_eq!(match_range("BO", "bob"), Some((0, 2)));
        assert_eq!(match_range("ob", "Bob"), Some((1, 3)));
    }

    #[test]
    fn match_range_returns_first_occurrence() {
        // "ab" first occurs at index 0 in "abab", not 2.
        assert_eq!(match_range("ab", "abab"), Some((0, 2)));
    }

    #[test]
    fn match_range_trims_query() {
        // Surrounding whitespace in the query is ignored, matching
        // [`query_rank`]'s trim rule.
        assert_eq!(match_range("  bob  ", "bob"), Some((0, 3)));
    }

    #[test]
    fn match_range_preserves_original_case_range() {
        // The range indexes the haystack bytes directly, so slicing the
        // original (mixed-case) string yields the matched fragment with its
        // original capitalization — the highlighter keeps "Bob" not "bob".
        let (s, e) = match_range("ob", "Bob").unwrap();
        assert_eq!(&"Bob"[s..e], "ob");
    }
}
