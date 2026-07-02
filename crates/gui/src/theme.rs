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

/// Match-highlight background for the sidebar search: a translucent accent
/// wash that marks the substring the query matched. Paired with
/// `HIGHLIGHT_FG` so the highlighted fragment stays readable on the wash.
pub const HIGHLIGHT: Color = Color::from_rgba8(0xBD, 0x93, 0xF9, 0.45);

/// Text color for a search match fragment: dark on the light accent wash so
/// the matched substring pops without fighting the rest of the row.
pub const HIGHLIGHT_FG: Color = Color::from_rgb8(0x1E, 0x1F, 0x29);

/// Bubble corner radius (px).
const BUBBLE_RADIUS: f32 = 12.0;

/// Standard padding inside a bubble / card (px).
pub const BUBBLE_PAD: f32 = 8.0;

/// Sidebar (contact list) width in the two-column layout (px). Fixed so the
/// list column does not flex with the window; the active chat fills the rest.
pub const SIDEBAR_WIDTH: f32 = 300.0;

/// Estimated height of one message row (px), used only by scroll-position
/// restoration when an older history page is prepended to a thread. iced 0.14
/// has no "scroll to widget by id" operation, so after prepending N rows the
/// app scrolls down by `N * EST_ROW_HEIGHT` to keep the previously-topmost row
/// in view. The estimate (bubble text ~14px + `BUBBLE_PAD` top/bottom + a
/// 9px timestamp + inter-row spacing) need not be exact: a small error just
/// leaves the user a few pixels off the original anchor instead of jumping to
/// the very top or bottom of the thread.
pub const EST_ROW_HEIGHT: f32 = 50.0;

/// Sidebar background fill — a touch darker than `panel_style` so the sidebar
/// reads as a distinct column against the window background and the active
/// chat panel.
pub fn sidebar_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        text_color: None,
        background: Some(Background::Color(Color::from_rgb8(0x21, 0x22, 0x2C))),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::default(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// A row style for the currently-selected contact / group: accent-tinted fill
/// so the open chat is visually marked in the sidebar.
pub fn active_row_style() -> iced::widget::container::Style {
    iced::widget::container::Style {
        text_color: Some(Color::WHITE),
        background: Some(Background::Color(Color::from_rgba8(0xBD, 0x93, 0xF9, 0.22))),
        border: Border {
            color: ACCENT,
            width: 0.0,
            radius: rounded(8.0),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

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

    #[test]
    fn sidebar_style_has_fill_and_no_radius() {
        let s = sidebar_style();
        assert!(matches!(s.background, Some(Background::Color(_))));
        assert_eq!(s.border.radius.top_left, 0.0);
    }

    #[test]
    fn active_row_style_is_accent_tinted() {
        let s = active_row_style();
        // Accent-tinted fill + accent border + white text.
        match s.background {
            Some(Background::Color(c)) => assert!(c.a > 0.0 && c.a < 1.0, "semi-transparent"),
            other => panic!("expected color bg, got {other:?}"),
        }
        assert_eq!(s.border.color, ACCENT);
        assert_eq!(s.text_color, Some(Color::WHITE));
    }

    #[test]
    fn sidebar_width_is_fixed_and_reasonable() {
        // A fixed sidebar width that fits a contact row + leaves the bulk of a
        // 900px window for the active chat. Read through a non-const binding so
        // clippy does not flag `assertions_on_constants`.
        let w = SIDEBAR_WIDTH;
        assert!((200.0..=400.0).contains(&w));
    }

    #[test]
    fn highlight_is_translucent_accent_wash() {
        // The match highlight is the accent purple at <1.0 alpha so it reads as
        // a wash over the row, not a solid block.
        let c = HIGHLIGHT;
        assert!(c.a > 0.0 && c.a < 1.0, "semi-transparent wash, got {c:?}");
        assert!(c.r > 0.7 && c.b > 0.9, "accent-tinted: {c:?}");
    }

    #[test]
    fn highlight_fg_is_dark_for_contrast() {
        // Highlighted fragment text is dark so it stays legible on the light
        // accent wash (luminance well below 0.5 on all channels).
        let c = HIGHLIGHT_FG;
        assert!(c.r < 0.3 && c.g < 0.3 && c.b < 0.3, "dark fg: {c:?}");
    }
}
