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
    // The identity fingerprint (SHA-256 of the identity pub) — surfaced by
    // `Event::Ready` so the user can read/compare it here without the display
    // layer re-deriving it. Falls back to a placeholder before Ready.
    let fingerprint = app
        .identity_fingerprint
        .map(|bytes| hex32(&bytes))
        .unwrap_or_else(|| "(not unlocked)".to_string());

    column![
        text("Settings").size(24),
        text("Your identity pub:"),
        text(identity).size(10),
        text("Your fingerprint:"),
        text(fingerprint).size(10),
        text("Server address:"),
        text_input("server address", &app.server_input).on_input(Message::ServerChanged),
        button("apply server change").on_press(Message::ChangeServer),
        row![button("rotate signed prekey").on_press(Message::RotateSignedPrekey),].spacing(10),
        // Replenish one-time prekeys with an editable count (spec: count
        // input). The count is parsed on press; a non-positive/empty value
        // surfaces a banner instead of sending a no-op command.
        row![
            text_input("count", &app.replenish_count).on_input(Message::ReplenishCountChanged),
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
