//! Login view (existing store file): passphrase + "Unlock" button. Centered
//! card layout matching [`super::setup`].

use iced::alignment;
use iced::widget::{button, column, container, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp};
use crate::theme;

pub fn login(app: &UmApp) -> Element<'_, Message> {
    let form = column![
        text("Unlock your store").size(28),
        text("Enter your passphrase to decrypt your local store.").color(theme::MUTED),
        text(""),
        text_input("passphrase", &app.passphrase_input)
            .secure(true)
            .on_input(Message::PassphraseChanged)
            .on_submit(Message::UnlockSubmit)
            .padding(8),
        text(""),
        button(text("Unlock"))
            .style(theme::primary_button_style)
            .padding(10)
            .on_press(Message::UnlockSubmit),
    ]
    .spacing(10)
    .align_x(alignment::Horizontal::Center);

    container(
        container(form)
            .style(|_| theme::panel_style())
            .padding(30)
            .width(Length::Fixed(440.0)),
    )
    .align_x(alignment::Horizontal::Center)
    .width(Fill)
    .padding(40)
    .into()
}
