//! 1:1 chat thread view: header (back + peer + verify), a scrollable message
//! list with right/left-aligned bubbles + timestamps, and a compose row.
//! The scrollable uses `auto_scroll` + `anchor_bottom` so new messages stay in
//! view; `update` also emits a `snap_to_end` task on send/receive.

use iced::alignment;
use iced::widget::scrollable::Viewport;
use iced::widget::{Id, Space, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, TopHint, UmApp, format_time, hex32, history_top_hint};
use crate::ChatId;
use crate::theme;

/// The scrollable id for the 1:1 thread. Used by `update` to snap to the
/// latest message.
pub fn thread_scroll_id() -> Id {
    Id::new("um-chat-thread")
}

/// Viewport-relative threshold (px) under which the thread is considered
/// pinned to the top, triggering a keyset `LoadOlder` fetch. `absolute_offset`
/// is clamped to `[0, content-bounds]`, so `y ≈ 0` means the top of the
/// content is flush with the top of the viewport. A small epsilon absorbs
/// sub-pixel rounding from the layout engine.
pub(crate) const SCROLL_AT_TOP_EPS: f32 = 1.0;

/// A single message row: a bubble (in/out styled) + a small timestamp under
/// it, aligned to the bubble's side.
fn message_row(
    text_str: &str,
    dir: crate::Direction,
    ts: u64,
    status: crate::Status,
) -> Element<'_, Message> {
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
    let body = text(format!("{text_str}{suffix}")).size(14);
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

/// A dim centered line shown at the top of the thread (above the oldest cached
/// message) when an older page is loading or the start of history has been
/// reached. Pure over the `TopHint`; returns `None` when no hint applies so the
/// caller can skip pushing anything.
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

pub fn chat_thread(app: &UmApp, peer: [u8; 32]) -> Element<'_, Message> {
    let contact = app.contacts.iter().find(|c| c.identity_pub == peer);
    let title = match contact {
        Some(c) => format!("{} · {}", c.nickname, hex32(&c.fingerprint)),
        None => format!("peer {}", hex32(&peer)),
    };
    let header = row![
        button(text("← back"))
            .style(theme::secondary_button_style)
            .on_press(Message::Back),
        text(title).size(13).color(theme::MUTED),
        Space::new().width(Fill),
        button(text("verify fingerprint"))
            .style(theme::secondary_button_style)
            .on_press(Message::VerifyFingerprint(peer)),
    ]
    .spacing(10)
    .align_y(alignment::Vertical::Center);

    let chat = ChatId::Peer(peer);
    let mut msgs = column![].spacing(6);
    // Top-of-thread hint: a "loading older…" line while a page is in flight, or
    // a "start of history" marker once the oldest row is reached. Only shown
    // once the thread has at least one cached message — a bare "no messages
    // yet" thread has no pagination state to hint about.
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
            msgs = msgs.push(message_row(&m.text, m.dir, m.timestamp, m.status));
        }
    }
    if app
        .threads
        .get(&chat)
        .is_none_or(|t| t.is_empty())
    {
        msgs = msgs.push(
            container(text("no messages yet").color(theme::MUTED).size(13))
                .align_x(alignment::Horizontal::Center)
                .width(Fill),
        );
    }

    let compose = row![
        text_input("type a message…", &app.compose_input)
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
            .id(thread_scroll_id())
            .height(Fill)
            .anchor_bottom()
            .auto_scroll(true)
            .on_scroll(move |vp: Viewport| Message::ChatScrolled {
                chat: ChatId::Peer(peer),
                at_top: vp.absolute_offset().y <= SCROLL_AT_TOP_EPS,
            })
            .spacing(4),
        compose,
    ]
    .spacing(10)
    .padding(20)
    .into()
}
