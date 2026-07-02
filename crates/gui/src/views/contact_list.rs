//! Contact list view: the home screen. A header bar (status + settings), a
//! scrollable contacts list with unread badges, an add-contact form, a groups
//! section, and a new-group form. Layout uses `theme` styling.

use iced::alignment;
use iced::widget::{Space, button, column, container, row, scrollable, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp, hex32, short_hex};
use crate::ChatId;
use crate::theme;

/// Section header: a small uppercase label with the accent color.
fn section(label: &str) -> iced::widget::Text<'_> {
    text(label).size(13).color(theme::ACCENT)
}

/// A pill-style unread badge, or an empty spacer of the same height so rows
/// don't jump when the badge appears/disappears.
fn unread_badge(n: u32) -> iced::widget::Text<'static> {
    if n > 0 {
        text(format!("{n}")).color(theme::ACCENT).size(12)
    } else {
        text("")
    }
}

pub fn contact_list(app: &UmApp) -> Element<'_, Message> {
    // ---- Header bar: status dot + title + settings button.
    let status_dot = if app.connected {
        text("●").color(theme::OK)
    } else {
        text("○").color(theme::MUTED)
    };
    let status_label = if app.connected {
        text("connected")
    } else {
        text("disconnected")
    }
    .color(theme::MUTED)
    .size(12);
    let header = row![
        status_dot,
        status_label,
        Space::new().width(Fill),
        button(text("⚙ settings"))
            .style(theme::secondary_button_style)
            .on_press(Message::OpenSettings),
    ]
    .spacing(8)
    .align_y(alignment::Vertical::Center);

    // ---- Contacts list (scrollable).
    let mut list = column![text("Contacts").size(20),].spacing(4);
    if app.contacts.is_empty() {
        list = list.push(
            text("No contacts yet — add one by pasting their identity pub below.")
                .color(theme::MUTED)
                .size(13),
        );
    }
    for c in &app.contacts {
        let badge = app
            .unread
            .get(&ChatId::Peer(c.identity_pub))
            .copied()
            .filter(|n| *n > 0)
            .map_or_else(|| unread_badge(0), unread_badge);
        let verified = if c.verified { "✓ " } else { "" };
        let row = row![
            text(format!("{verified}{}", c.nickname)).size(15),
            text(short_hex(&c.identity_pub))
                .color(theme::MUTED)
                .size(11),
            Space::new().width(Fill),
            badge,
            button(text("open"))
                .style(theme::secondary_button_style)
                .on_press(Message::OpenChat(c.identity_pub)),
        ]
        .spacing(10)
        .align_y(alignment::Vertical::Center);
        // Fingerprint on a muted sub-line.
        let sub = text(hex32(&c.fingerprint)).color(theme::MUTED).size(9);
        list = list.push(column![row, sub].spacing(2));
    }

    // ---- Add-contact form.
    let add_form = column![
        section("Add contact"),
        text_input("identity pub (64 hex chars)", &app.add_contact_hex)
            .on_input(Message::AddContactHexChanged)
            .padding(6),
        text_input("nickname", &app.add_contact_nick)
            .on_input(Message::AddContactNickChanged)
            .padding(6),
        button(text("add"))
            .style(theme::primary_button_style)
            .on_press(Message::AddContact),
    ]
    .spacing(6);

    // ---- Groups section.
    let mut groups = column![section("Groups"),].spacing(4);
    if app.groups.is_empty() {
        groups = groups.push(text("(no groups yet)").color(theme::MUTED).size(13));
    }
    for g in &app.groups {
        let badge = app
            .unread
            .get(&ChatId::Group(g.id))
            .copied()
            .filter(|n| *n > 0)
            .map_or_else(|| unread_badge(0), unread_badge);
        groups = groups.push(
            row![
                text(g.name.clone()).size(15),
                text(short_hex(&g.id)).color(theme::MUTED).size(11),
                Space::new().width(Fill),
                badge,
                button(text("open"))
                    .style(theme::secondary_button_style)
                    .on_press(Message::OpenGroup(g.id)),
            ]
            .spacing(10)
            .align_y(alignment::Vertical::Center),
        );
    }

    // ---- New-group form.
    let new_group_form = column![
        section("New group"),
        row![
            text_input("group name", &app.new_group_name)
                .on_input(Message::NewGroupNameChanged)
                .padding(6),
            button(text("create"))
                .style(theme::primary_button_style)
                .on_press(Message::CreateGroupPressed),
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center),
    ]
    .spacing(6);

    // ---- Assemble. The contacts list grows to fill; the forms sit below it.
    let body = column![
        header,
        scrollable(list).height(Fill).spacing(4),
        add_form,
        new_group_form,
        groups,
    ]
    .spacing(16)
    .padding(20);

    container(body).width(Length::Fixed(520.0)).into()
}
