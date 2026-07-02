//! Contact list view. In the two-column layout this is the **sidebar**: a
//! fixed-width, panel-styled column with a header (status + settings), a
//! scrollable contacts list with unread badges + active-chat highlight, an
//! add-contact form, a groups section, and a new-group form. The active chat
//! (or settings) renders in the right pane built by `app::view`.
//!
//! `contact_list` remains as a standalone (sidebar-only) element for the
//! `View::ContactList` route — the router wraps it with a right-pane
//! placeholder so the window is fully used even before a chat is opened.

use iced::alignment;
use iced::widget::{Space, button, column, container, rich_text, row, scrollable, text, text_input};
use iced::{Element, Fill, Length};

use super::{Message, UmApp, hex32, highlighted_name, query_rank, short_hex};
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

/// The fixed-width sidebar column: header + scrollable contacts + forms. This
/// is reused by every post-login route (ContactList, ChatThread, GroupChat,
/// Settings) so the contact list stays visible while a chat or settings panel
/// fills the right side of the window.
pub fn sidebar(app: &UmApp) -> Element<'_, Message> {
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

    // Total-unread badge: sum across every chat. Shown in the header so it
    // stays visible even when the contacts list is scrolled or filtered — a
    // glance at the sidebar is enough to know something new arrived. Hidden
    // (empty spacer) when there is nothing unread so the header doesn't jump.
    let total = app.total_unread();
    let total_badge = if total > 0 {
        text(format!("{total} unread"))
            .color(theme::ACCENT)
            .size(12)
    } else {
        text("")
    };

    let header = row![
        status_dot,
        status_label,
        total_badge,
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
    // Rank every contact against the query and drop non-matches, then sort
    // by rank (best first). Stable sort preserves the original `app.contacts`
    // order for ties (e.g. empty query → rank 0 for all → original order),
    // so an unfiltered list keeps its insertion order.
    let mut ranked: Vec<(u32, &um_gui::types::ContactView)> = app
        .contacts
        .iter()
        .filter_map(|c| {
            let id_hex = hex32(&c.identity_pub);
            query_rank(
                &app.search_query,
                &[&c.nickname, &id_hex, &short_hex(&c.identity_pub)],
            )
            .map(|r| (r, c))
        })
        .collect();
    ranked.sort_by_key(|(r, _)| *r);
    let shown_contacts = ranked.len() as u32;
    for (_, c) in &ranked {
        let chat = ChatId::Peer(c.identity_pub);
        let is_open = app.open_chat == Some(chat);
        let badge = app
            .unread
            .get(&chat)
            .copied()
            .filter(|n| *n > 0)
            .map_or_else(|| unread_badge(0), unread_badge);
        let verified = if c.verified { "✓ " } else { "" };
        // Highlight the matched fragment of the nickname when a search query
        // is active. `rich_text` renders the spans; the hex id / fingerprint
        // sub-lines stay plain `text` (matches there are less useful to mark
        // and would clutter the row).
        let name_spans = {
            let mut spans = Vec::with_capacity(2);
            if !verified.is_empty() {
                spans.push(iced::widget::span(verified));
            }
            spans.extend(highlighted_name(&app.search_query, &c.nickname));
            spans
        };
        let row = row![
            rich_text(name_spans).size(15),
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
        let entry = column![row, sub].spacing(2);
        // Highlight the open chat's row.
        let entry = if is_open {
            container(entry)
                .style(|_| theme::active_row_style())
                .padding(4)
        } else {
            container(entry).padding(4)
        };
        list = list.push(entry);
    }
    if !app.contacts.is_empty() && shown_contacts == 0 {
        list = list.push(
            text("No contacts match your search.")
                .color(theme::MUTED)
                .size(13),
        );
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
    // Rank + sort groups the same way as contacts (best match first, stable
    // for ties so the persisted roster order holds when the query is empty).
    let mut ranked_groups: Vec<(u32, &um_gui::types::GroupView)> = app
        .groups
        .iter()
        .filter_map(|g| {
            let id_hex = hex32(&g.id);
            query_rank(&app.search_query, &[&g.name, &id_hex, &short_hex(&g.id)])
                .map(|r| (r, g))
        })
        .collect();
    ranked_groups.sort_by_key(|(r, _)| *r);
    let shown_groups = ranked_groups.len() as u32;
    for (_, g) in &ranked_groups {
        let chat = ChatId::Group(g.id);
        let is_open = app.open_chat == Some(chat);
        let badge = app
            .unread
            .get(&chat)
            .copied()
            .filter(|n| *n > 0)
            .map_or_else(|| unread_badge(0), unread_badge);
        let row = row![
            rich_text(highlighted_name(&app.search_query, &g.name)).size(15),
            text(short_hex(&g.id)).color(theme::MUTED).size(11),
            Space::new().width(Fill),
            badge,
            button(text("open"))
                .style(theme::secondary_button_style)
                .on_press(Message::OpenGroup(g.id)),
        ]
        .spacing(10)
        .align_y(alignment::Vertical::Center);
        let row = if is_open {
            container(row)
                .style(|_| theme::active_row_style())
                .padding(4)
        } else {
            container(row).padding(4)
        };
        groups = groups.push(row);
    }
    if !app.groups.is_empty() && shown_groups == 0 {
        groups = groups.push(
            text("No groups match your search.")
                .color(theme::MUTED)
                .size(13),
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

    // ---- Search / filter box. Filters both contacts and groups by nickname /
    // group name / lowercase hex id. Empty query shows everything.
    let search = text_input("search contacts & groups…", &app.search_query)
        .on_input(Message::SearchChanged)
        .padding(6);

    // ---- Assemble. The contacts list grows to fill; the forms sit below it.
    let body = column![
        header,
        search,
        scrollable(list).height(Fill).spacing(4),
        add_form,
        new_group_form,
        groups,
    ]
    .spacing(16)
    .padding(20);

    // Fixed-width, panel-styled column. The router places this on the left of
    // a row whose right side is the active chat / settings / placeholder.
    container(body)
        .style(|_| theme::sidebar_style())
        .width(Length::Fixed(theme::SIDEBAR_WIDTH))
        .height(Fill)
        .into()
}

/// The standalone `ContactList` route element: the sidebar with a right-pane
/// placeholder ("select a chat") so the window is fully used before any chat
/// is opened. Kept as the `View::ContactList` view so `Back` has a target.
pub fn contact_list(app: &UmApp) -> Element<'_, Message> {
    let placeholder = container(
        column![
            text("untitled_messenger").size(22),
            text("select a contact or group to start chatting")
                .color(theme::MUTED)
                .size(14),
        ]
        .spacing(8)
        .align_x(alignment::Horizontal::Center),
    )
    .align_x(alignment::Horizontal::Center)
    .align_y(alignment::Vertical::Center)
    .width(Fill)
    .height(Fill);

    row![sidebar(app), placeholder]
        .width(Fill)
        .height(Fill)
        .into()
}
