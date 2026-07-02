//! 1:1 chat thread view: header (back + peer + verify), a scrollable message
//! list with right/left-aligned bubbles + timestamps, and a compose row.
//! The scrollable uses `auto_scroll` + `anchor_bottom` so new messages stay in
//! view; `update` also emits a `snap_to_end` task on send/receive.

use iced::alignment;
use iced::widget::{Id, Space, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp, format_time, hex32};
use crate::ChatId;
use crate::theme;

/// The scrollable id for the 1:1 thread. Used by `update` to snap to the
/// latest message.
pub fn thread_scroll_id() -> Id {
    Id::new("um-chat-thread")
}

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

    let mut msgs = column![].spacing(6);
    if let Some(thread) = app.threads.get(&ChatId::Peer(peer)) {
        for m in thread {
            msgs = msgs.push(message_row(&m.text, m.dir, m.timestamp, m.status));
        }
    }
    if app
        .threads
        .get(&ChatId::Peer(peer))
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
            .spacing(4),
        compose,
    ]
    .spacing(10)
    .padding(20)
    .into()
}
