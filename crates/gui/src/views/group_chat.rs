//! Group chat thread view: same layout as 1:1, keyed by group id. Header
//! shows the group name + member count.

use iced::alignment;
use iced::widget::scrollable::Viewport;
use iced::widget::{Id, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, TopHint, UmApp, format_time, hex32, history_top_hint, short_hex};
use super::chat_thread::SCROLL_AT_TOP_EPS;
use crate::ChatId;
use crate::ContactView;
use crate::theme;

/// The scrollable id for the group thread.
pub fn group_scroll_id() -> Id {
    Id::new("um-group-thread")
}

/// Resolve a sender identity pub to a display label: the contact's nickname if
/// known, else the first 4 bytes of the pub as short hex. Pure (takes the
/// contact slice so it is unit-testable without a full `UmApp`).
fn sender_label(contacts: &[ContactView], sender: &[u8; 32]) -> String {
    match contacts.iter().find(|c| &c.identity_pub == sender) {
        Some(c) => c.nickname.clone(),
        None => short_hex(sender),
    }
}

fn message_row<'a>(
    app: &UmApp,
    text_str: &'a str,
    dir: crate::Direction,
    ts: u64,
    status: crate::Status,
    sender: Option<[u8; 32]>,
) -> Element<'a, Message> {
    let (bubble_style, align) = if dir == crate::Direction::Out {
        (theme::bubble_out_style(), alignment::Horizontal::Right)
    } else {
        (theme::bubble_in_style(), alignment::Horizontal::Left)
    };
    let suffix = match (dir, status) {
        (crate::Direction::Out, crate::Status::Sending) => " …",
        (crate::Direction::Out, crate::Status::Failed) => " ✗",
        (crate::Direction::Out, _) => " ✓",
        _ => "",
    };
    // For an incoming group message with a known author, prefix "nick: ".
    let prefix = match (dir, sender) {
        (crate::Direction::In, Some(s)) => format!("{}: ", sender_label(&app.contacts, &s)),
        _ => String::new(),
    };
    let body = text(format!("{prefix}{text_str}{suffix}")).size(14);
    let time = format_time(ts);
    let bubble = container(body)
        .style(move |_| bubble_style)
        .padding(theme::BUBBLE_PAD)
        .width(Length::Shrink);
    let col = if time.is_empty() {
        column![bubble]
    } else {
        column![bubble, text(time).color(theme::MUTED).size(9)]
    }
    .spacing(2)
    .align_x(align);
    container(col)
        .align_x(align)
        .width(Fill)
        .padding([0, 4])
        .into()
}

/// A dim centered line shown at the top of the group thread (above the oldest
/// cached message) when an older page is loading or the start of history has
/// been reached. Mirrors [`chat_thread::top_hint_line`]; kept here so the group
/// view stays self-contained (no shared widget module yet).
fn top_hint_line(hint: TopHint) -> Element<'static, Message> {
    let (label, color) = match hint {
        TopHint::Loading => ("loading older…", theme::MUTED),
        TopHint::StartOfHistory => ("start of history", theme::MUTED),
    };
    container(text(label).color(color).size(11))
        .align_x(alignment::Horizontal::Center)
        .width(Fill)
        .into()
}

pub fn group_chat(app: &UmApp, group: [u8; 32]) -> Element<'_, Message> {
    let title = match app.groups.iter().find(|g| g.id == group) {
        Some(g) => {
            let noun = if g.members == 1 { "member" } else { "members" };
            format!("{} · {} {noun}", g.name, g.members)
        }
        None => format!("group {}", hex32(&group)),
    };
    let header = row![
        button(text("← back"))
            .style(theme::secondary_button_style)
            .on_press(Message::Back),
        text(title).size(13).color(theme::MUTED),
    ]
    .spacing(10)
    .align_y(alignment::Vertical::Center);

    let chat = ChatId::Group(group);
    let mut msgs = column![].spacing(6);
    // Top-of-thread hint (see chat_thread::chat_thread): only once the thread
    // has cached messages — an empty group thread shows "no group messages
    // yet" instead.
    let thread_nonempty = app
        .threads
        .get(&chat)
        .is_some_and(|t| !t.is_empty());
    if thread_nonempty {
        let loading = app.loading_older.contains(&chat);
        let has_more = app.has_more_history.get(&chat).copied().unwrap_or(false);
        if let Some(hint) = history_top_hint(loading, has_more) {
            msgs = msgs.push(top_hint_line(hint));
        }
    }
    if let Some(thread) = app.threads.get(&chat) {
        for m in thread {
            msgs = msgs.push(message_row(
                app,
                &m.text,
                m.dir,
                m.timestamp,
                m.status,
                m.sender,
            ));
        }
    }
    if app
        .threads
        .get(&chat)
        .is_none_or(|t| t.is_empty())
    {
        msgs = msgs.push(
            container(text("no group messages yet").color(theme::MUTED).size(13))
                .align_x(alignment::Horizontal::Center)
                .width(Fill),
        );
    }

    let compose = row![
        text_input("type a group message…", &app.compose_input)
            .on_input(Message::ComposeChanged)
            .on_submit(Message::SendPressed)
            .padding(8),
        button(text("send"))
            .style(theme::primary_button_style)
            .on_press(Message::SendPressed),
    ]
    .spacing(8)
    .align_y(alignment::Vertical::Center);

    column![
        header,
        scrollable(msgs)
            .id(group_scroll_id())
            .height(Fill)
            .anchor_bottom()
            .auto_scroll(true)
            .on_scroll(move |vp: Viewport| Message::ChatScrolled {
                chat: ChatId::Group(group),
                at_top: vp.absolute_offset().y <= SCROLL_AT_TOP_EPS,
            })
            .spacing(4),
        compose,
    ]
    .spacing(10)
    .padding(20)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(pub_: [u8; 32], nick: &str) -> ContactView {
        ContactView {
            identity_pub: pub_,
            nickname: nick.into(),
            fingerprint: [0; 32],
            verified: false,
        }
    }

    #[test]
    fn sender_label_uses_known_nickname() {
        let pub_ = [0x11; 32];
        let contacts = vec![contact(pub_, "alice")];
        assert_eq!(sender_label(&contacts, &pub_), "alice");
    }

    #[test]
    fn sender_label_falls_back_to_short_hex() {
        let pub_ = [0xAB; 32];
        // No contact matches → short hex of the first 4 bytes.
        assert_eq!(sender_label(&[], &pub_), "abababab…");
    }

    #[test]
    fn sender_label_ignores_non_matching_contacts() {
        let known = [0x11; 32];
        let unknown = [0x22; 32];
        let contacts = vec![contact(known, "alice")];
        // A different pub is not "alice" — it falls back to short hex.
        assert_eq!(sender_label(&contacts, &unknown), "22222222…");
    }
}
