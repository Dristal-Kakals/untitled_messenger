//! Shared visual theme + styling helpers for the GUI.
//!
//! A single place for colors, spacing, and the per-widget `Style` functions
//! (`iced::widget::button::Style`, `...::container::Style`) so the six views
//! stay consistent and the look is decoupled from layout. Everything here is
//! pure data / pure functions — no iced runtime, fully unit-testable.
//!
//! The app runs on the built-in `iced::Theme::Dracula` dark palette (set in
//! `main.rs` via `.theme(...)`). The accent / bubble colors below are tuned to
//! read well on top of it; they are NOT derived from the palette at runtime,
//! which keeps the helpers `const`-friendly and deterministic in tests.

use iced::border::Radius;
use iced::{Background, Border, Color, Shadow};

/// The iced theme the app uses (set once in `main.rs`).
pub const THEME: iced::Theme = iced::Theme::Dracula;

/// Brand accent — buttons, links, unread badges.
pub const ACCENT: Color = Color::from_rgb8(0xBD, 0x93, 0xF9);

/// Outgoing chat bubble fill.
pub const BUBBLE_OUT: Color = Color::from_rgb8(0x44, 0x47, 0x5A);

/// Incoming chat bubble fill.
pub const BUBBLE_IN: Color = Color::from_rgb8(0x28, 0x2A, 0x36);

/// Error banner text.
pub const ERROR: Color = Color::from_rgb8(0xFF, 0x55, 0x55);

/// Muted secondary text (fingerprints, ids, hints).
pub const MUTED: Color = Color::from_rgb8(0x8B, 0xE9, 0xFD);

/// "Connected" status dot.
pub const OK: Color = Color::from_rgb8(0x50, 0xFA, 0x7B);

/// Bubble corner radius (px).
const BUBBLE_RADIUS: f32 = 12.0;

/// Standard padding inside a bubble / card (px).
pub const BUBBLE_PAD: f32 = 8.0;

/// `iced::widget::container::Style` for an outgoing message bubble: filled
/// with `BUBBLE_OUT`, rounded, no border. The text color is left to the theme.
pub fn bubble_out_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        text_color: None,
        background: Some(Background::Color(BUBBLE_OUT)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: rounded(BUBBLE_RADIUS),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// `iced::widget::container::Style` for an incoming message bubble: filled
/// with `BUBBLE_IN`, rounded, no border.
pub fn bubble_in_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        text_color: None,
        background: Some(Background::Color(BUBBLE_IN)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: rounded(BUBBLE_RADIUS),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// A thin panel background (used for headers / side cards): slightly lighter
/// than the theme background, no border.
pub fn panel_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        text_color: None,
        background: Some(Background::Color(Color::from_rgb8(0x31, 0x33, 0x3D))),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: rounded(8.0),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// A `Radius` with the same value on every corner.
fn rounded(v: f32) -> Radius {
    Radius {
        top_left: v,
        top_right: v,
        bottom_right: v,
        bottom_left: v,
    }
}

/// Primary button style: accent fill, white text, rounded. Hovered/pressed
/// states keep the accent (the theme already animates press; we just fix the
/// base look so it reads as a primary action).
pub fn primary_button_style(
    _theme: &iced::Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let (bg, text) = match status {
        iced::widget::button::Status::Hovered => (Color::from_rgb8(0xC9, 0xAA, 0xFF), Color::BLACK),
        iced::widget::button::Status::Pressed => (Color::from_rgb8(0xA6, 0x78, 0xE6), Color::WHITE),
        _ => (ACCENT, Color::WHITE),
    };
    iced::widget::button::Style {
        background: Some(Background::Color(bg)),
        text_color: text,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: rounded(8.0),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Secondary button style: transparent fill, muted border, theme text.
pub fn secondary_button_style(
    _theme: &iced::Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let border_color = match status {
        iced::widget::button::Status::Hovered => ACCENT,
        _ => MUTED,
    };
    iced::widget::button::Style {
        background: Some(Background::Color(Color::TRANSPARENT)),
        text_color: Color::WHITE,
        border: Border {
            color: border_color,
            width: 1.0,
            radius: rounded(8.0),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Danger button style (logout, destructive actions): red-tinted.
pub fn danger_button_style(
    _theme: &iced::Theme,
    status: iced::widget::button::Status,
) -> iced::widget::button::Style {
    let bg = match status {
        iced::widget::button::Status::Hovered => Color::from_rgb8(0xFF, 0x77, 0x77),
        iced::widget::button::Status::Pressed => Color::from_rgb8(0xCC, 0x44, 0x44),
        _ => ERROR,
    };
    iced::widget::button::Style {
        background: Some(Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: rounded(8.0),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_is_dracula() {
        assert!(matches!(THEME, iced::Theme::Dracula));
    }

    #[test]
    fn bubble_styles_differ() {
        assert_ne!(bubble_out_style(), bubble_in_style());
    }

    #[test]
    fn bubble_styles_have_radius_and_fill() {
        let s = bubble_out_style();
        assert!(matches!(s.background, Some(Background::Color(_))));
        assert_eq!(s.border.width, 0.0);
        let s = bubble_in_style();
        assert!(matches!(s.background, Some(Background::Color(_))));
    }

    #[test]
    fn primary_button_hover_lightens() {
        let base = primary_button_style(&THEME, iced::widget::button::Status::Active);
        let hover = primary_button_style(&THEME, iced::widget::button::Status::Hovered);
        // Hovered background differs from active.
        assert_ne!(base.background, hover.background);
    }

    #[test]
    fn danger_button_is_red() {
        let s = danger_button_style(&THEME, iced::widget::button::Status::Active);
        match s.background {
            Some(Background::Color(c)) => {
                assert!(c.r >= 0.9 && c.g < 0.6 && c.b < 0.6, "red-ish: {c:?}");
            }
            other => panic!("expected color bg, got {other:?}"),
        }
    }

    #[test]
    fn accent_is_purple() {
        // Dracula purple-ish: r and b high, g mid. Read the fields through a
        // non-const binding so clippy does not flag `assertions_on_constants`.
        let c = ACCENT;
        assert!(c.r > 0.7 && c.b > 0.9 && c.g < 0.7);
    }
}
