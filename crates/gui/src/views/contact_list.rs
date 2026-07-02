//! Contact list view: contacts + add-contact form + open/new-group/settings.

use iced::Element;
use iced::widget::{button, column, row, scrollable, text, text_input};

use super::{Message, UmApp, hex32, short_hex};
use crate::ChatId;

pub fn contact_list(app: &UmApp) -> Element<'_, Message> {
    let mut list = column![text("Contacts").size(20),].spacing(6);

    if app.contacts.is_empty() {
        list = list.push(text(
            "(no contacts yet — add one by pasting their identity pub)",
        ));
    }
    for c in &app.contacts {
        let unread_badge = app
            .unread
            .get(&ChatId::Peer(c.identity_pub))
            .copied()
            .filter(|n| *n > 0)
            .map(|n| text(format!("({n})")).color([0.2, 0.5, 0.9]))
            .unwrap_or_else(|| text(""));
        let mut line = row![
            text(c.nickname.clone()),
            text(short_hex(&c.identity_pub)),
            text(if c.verified { "✓" } else { "" }),
            unread_badge,
            button("open").on_press(Message::OpenChat(c.identity_pub)),
        ]
        .spacing(10);
        line = line.push(text(hex32(&c.fingerprint)).size(10));
        list = list.push(line);
    }

    let add_form = column![
        text("Add contact"),
        text_input("identity pub (64 hex chars)", &app.add_contact_hex)
            .on_input(Message::AddContactHexChanged),
        text_input("nickname", &app.add_contact_nick).on_input(Message::AddContactNickChanged),
        button("add").on_press(Message::AddContact),
    ]
    .spacing(6);

    // Groups section: lists every group the app knows about (rebuilt from
    // GroupCreated/GroupInvited events each session). Each row opens the group
    // thread; an unread badge shows for groups with unseen messages.
    let mut groups = column![text("Groups"),].spacing(6);
    if app.groups.is_empty() {
        groups = groups.push(text("(no groups yet)"));
    }
    for g in &app.groups {
        let badge = app
            .unread
            .get(&ChatId::Group(g.id))
            .copied()
            .filter(|n| *n > 0)
            .map(|n| text(format!("({n})")).color([0.2, 0.5, 0.9]))
            .unwrap_or_else(|| text(""));
        groups = groups.push(
            row![
                text(g.name.clone()),
                text(short_hex(&g.id)),
                badge,
                button("open").on_press(Message::OpenGroup(g.id)),
            ]
            .spacing(10),
        );
    }

    let new_group_form = column![
        text_input("group name", &app.new_group_name).on_input(Message::NewGroupNameChanged),
        button("new group").on_press(Message::CreateGroupPressed),
    ]
    .spacing(6);

    let nav = row![button("settings").on_press(Message::OpenSettings),].spacing(10);

    let status = if app.connected {
        text("● connected")
    } else {
        text("○ disconnected")
    };

    column![
        status,
        nav,
        scrollable(list).height(iced::Fill),
        add_form,
        new_group_form,
        groups,
    ]
    .spacing(10)
    .padding(20)
    .into()
}
