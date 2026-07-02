//! Settings view: identity pub + fingerprint + server addr + key rotation +
//! replenish + logout + quit + back. Card layout with section labels.

use iced::alignment;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp, hex32};
use crate::theme;

fn section(label: &str) -> iced::widget::Text<'_> {
    text(label).size(13).color(theme::ACCENT)
}

pub fn settings(app: &UmApp) -> Element<'_, Message> {
    let identity = app
        .identity_pub
        .map_or_else(|| "(not unlocked)".to_string(), |bytes| hex32(&bytes));
    let fingerprint = app
        .identity_fingerprint
        .map_or_else(|| "(not unlocked)".to_string(), |bytes| hex32(&bytes));

    let body = column![
        text("Settings").size(24),
        section("Identity"),
        text("Your identity pub:").color(theme::MUTED).size(12),
        text(identity).color(theme::MUTED).size(10),
        text("Your fingerprint:").color(theme::MUTED).size(12),
        text(fingerprint).color(theme::MUTED).size(10),
        text(""),
        section("Server"),
        text_input("server address", &app.server_input)
            .on_input(Message::ServerChanged)
            .padding(6),
        button(text("apply server change"))
            .style(theme::primary_button_style)
            .on_press(Message::ChangeServer),
        text(""),
        section("Prekeys"),
        row![
            text_input("count", &app.replenish_count)
                .on_input(Message::ReplenishCountChanged)
                .padding(6)
                .width(Length::Fixed(80.0)),
            button(text("replenish one-time prekeys"))
                .style(theme::secondary_button_style)
                .on_press(Message::ReplenishOneTimePrekeys),
        ]
        .spacing(8)
        .align_y(alignment::Vertical::Center),
        button(text("rotate signed prekey"))
            .style(theme::secondary_button_style)
            .on_press(Message::RotateSignedPrekey),
        text(""),
        section("Session"),
        button(text("logout"))
            .style(theme::danger_button_style)
            .on_press(Message::Logout),
        button(text("quit"))
            .style(theme::secondary_button_style)
            .on_press(Message::Quit),
        text(""),
        button(text("← back"))
            .style(theme::secondary_button_style)
            .on_press(Message::Back),
    ]
    .spacing(10);

    container(
        container(body)
            .style(|_| theme::panel_style())
            .padding(24)
            .width(Length::Fixed(520.0)),
    )
    .align_x(alignment::Horizontal::Center)
    .width(Fill)
    .padding(20)
    .into()
}
