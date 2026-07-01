//! Settings view: identity pub + fingerprint + server addr + key rotation +
//! logout.

use iced::widget::{button, column, row, text, text_input};
use iced::Element;

use super::{hex32, Message, UmApp};

pub fn settings(app: &UmApp) -> Element<'_, Message> {
    let identity = app
        .identity_pub
        .map(|bytes| hex32(&bytes))
        .unwrap_or_else(|| "(not unlocked)".to_string());

    column![
        text("Settings").size(24),
        text("Your identity pub:"),
        text(identity).size(10),
        text("Server address:"),
        text_input("server address", &app.server_input).on_input(Message::ServerChanged),
        button("apply server change").on_press(Message::ChangeServer),
        row![
            button("rotate signed prekey").on_press(Message::RotateSignedPrekey),
            button("replenish one-time prekeys").on_press(Message::ReplenishOneTimePrekeys),
        ]
        .spacing(10),
        button("logout").on_press(Message::Logout),
        button("quit").on_press(Message::Quit),
        button("← back").on_press(Message::Back),
    ]
    .spacing(10)
    .padding(20)
    .into()
}
