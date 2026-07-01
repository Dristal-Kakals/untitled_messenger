//! Group chat thread view: same layout as 1:1, keyed by group id.

use iced::alignment;
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::Element;

use super::{hex32, Message, UmApp};
use crate::ChatId;

pub fn group_chat(app: &UmApp, group: [u8; 32]) -> Element<'_, Message> {
    let header = row![
        button("← back").on_press(Message::Back),
        text(format!("group {}", hex32(&group))).size(12),
    ]
    .spacing(10);

    let mut msgs = column![].spacing(4);
    if let Some(thread) = app.threads.get(&ChatId::Group(group)) {
        for m in thread {
            let label = match (m.dir, m.status) {
                (crate::Direction::Out, crate::Status::Sending) => format!("{} …", m.text),
                (crate::Direction::Out, crate::Status::Failed) => format!("{} ✗", m.text),
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
        text_input("type a group message…", &app.compose_input)
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
