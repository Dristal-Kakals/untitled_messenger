//! Setup view (first run, no store file): passphrase + confirm + server addr
//! + "Create identity" button.

use iced::Element;
use iced::widget::{button, column, text, text_input};

use super::{Message, UmApp};

pub fn setup(app: &UmApp) -> Element<'_, Message> {
    column![
        text("Create a new identity").size(24),
        text("Choose a passphrase (≥ 8 chars). It encrypts your local store;"),
        text("there is no recovery if you lose it."),
        text_input("passphrase", &app.passphrase_input)
            .secure(true)
            .on_input(Message::PassphraseChanged),
        text_input("confirm passphrase", &app.passphrase_confirm)
            .secure(true)
            .on_input(Message::PassphraseConfirmChanged),
        text_input("server address", &app.server_input).on_input(Message::ServerChanged),
        button("Create identity").on_press(Message::SetupSubmit),
    ]
    .spacing(10)
    .padding(20)
    .into()
}
