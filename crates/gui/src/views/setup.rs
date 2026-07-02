//! Setup view (first run, no store file): passphrase + confirm + server addr
//! + "Create identity" button. Centered card layout.

use iced::alignment;
use iced::widget::{button, column, container, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp};
use crate::theme;

/// A centered card container: a fixed-width panel with the panel background,
/// rounded, centered horizontally.
fn card(content: iced::widget::Column<'_, Message>) -> Element<'_, Message> {
    container(
        container(content)
            .style(|_| theme::panel_style())
            .padding(30)
            .width(Length::Fixed(440.0)),
    )
    .align_x(alignment::Horizontal::Center)
    .width(Fill)
    .padding(40)
    .into()
}

pub fn setup(app: &UmApp) -> Element<'_, Message> {
    let mut form = column![
        text("Create a new identity").size(28),
        text("Choose a passphrase (≥ 8 chars). It encrypts your local store;"),
        text("there is no recovery if you lose it.").color(theme::MUTED),
        text(""),
        text_input("passphrase", &app.passphrase_input)
            .secure(true)
            .on_input(Message::PassphraseChanged)
            .on_submit(Message::SetupSubmit)
            .padding(8),
        text_input("confirm passphrase", &app.passphrase_confirm)
            .secure(true)
            .on_input(Message::PassphraseConfirmChanged)
            .on_submit(Message::SetupSubmit)
            .padding(8),
        text_input("server address", &app.server_input)
            .on_input(Message::ServerChanged)
            .padding(8),
        text(""),
        button(text("Create identity"))
            .style(theme::primary_button_style)
            .padding(10)
            .on_press(Message::SetupSubmit),
    ]
    .spacing(10)
    .align_x(alignment::Horizontal::Center);

    if app.passphrase_input.len() < 8 {
        form = form.push(
            text("passphrase must be at least 8 characters")
                .color(theme::MUTED)
                .size(12),
        );
    }

    card(form)
}
