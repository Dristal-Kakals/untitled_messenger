//! Login view (existing store file): passphrase + "Unlock" button.

use iced::widget::{button, column, text, text_input};
use iced::Element;

use super::{Message, UmApp};

pub fn login(app: &UmApp) -> Element<'_, Message> {
    column![
        text("Unlock your store").size(24),
        text("Enter your passphrase to decrypt your local store."),
        text_input("passphrase", &app.passphrase_input)
            .secure(true)
            .on_input(Message::PassphraseChanged)
            .on_submit(Message::UnlockSubmit),
        button("Unlock").on_press(Message::UnlockSubmit),
    ]
    .spacing(10)
    .padding(20)
    .into()
}
