//! 1:1 chat thread view: message list + compose + send + back.

use iced::Element;
use iced::alignment;
use iced::widget::{button, column, container, row, scrollable, text, text_input};

use super::{Message, UmApp, hex32};
use crate::ChatId;

pub fn chat_thread(app: &UmApp, peer: [u8; 32]) -> Element<'_, Message> {
    // Header: peer nickname (if the peer is a known contact) + their
    // fingerprint, per the spec ("header with peer nickname + fingerprint").
    // Falls back to the raw identity-pub hex for an unknown peer.
    let contact = app.contacts.iter().find(|c| c.identity_pub == peer);
    let title = match contact {
        Some(c) => format!("{} · {}", c.nickname, hex32(&c.fingerprint)),
        None => format!("peer {}", hex32(&peer)),
    };
    let header = row![
        button("← back").on_press(Message::Back),
        text(title).size(12),
        button("verify fingerprint").on_press(Message::VerifyFingerprint(peer)),
    ]
    .spacing(10);

    let mut msgs = column![].spacing(4);
    if let Some(thread) = app.threads.get(&ChatId::Peer(peer)) {
        for m in thread {
            let label = match (m.dir, m.status) {
                (crate::Direction::Out, crate::Status::Sending) => {
                    format!("{} …", m.text)
                }
                (crate::Direction::Out, crate::Status::Failed) => {
                    format!("{} ✗", m.text)
                }
                (crate::Direction::Out, _) => format!("{} ✓", m.text),
                (crate::Direction::In, _) => format!("< {}", m.text),
            };
            let aligned = if m.dir == crate::Direction::Out {
                container(text(label)).align_x(alignment::Horizontal::Right)
            } else {
                container(text(label)).align_x(alignment::Horizontal::Left)
            };
            msgs = msgs.push(aligned);
        }
    }

    let compose = row![
        text_input("type a message…", &app.compose_input)
            .on_input(Message::ComposeChanged)
            .on_submit(Message::SendPressed),
        button("send").on_press(Message::SendPressed),
    ]
    .spacing(10);

    column![header, scrollable(msgs).height(iced::Fill), compose,]
        .spacing(10)
        .padding(20)
        .into()
}
