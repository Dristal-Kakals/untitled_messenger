//! um_gui — native desktop GUI for untitled_messenger, built with `iced`.
//!
//! Architecture (see `docs/superpowers/specs/2026-07-01-messenger-gui-design.md`):
//! a thin iced presentation layer over the existing headless `um_client` core.
//! All crypto, networking, and encrypted-storage logic stays in `um_client`,
//! driven asynchronously from a background tokio runtime that talks to iced
//! over two `mpsc` channels.
//!
//! This library crate holds the **non-rendering** pieces so they are testable
//! without a window: `Command`/`Event` enums, plain view-data `types`, plain
//! TOML `config`, and the async `Bridge` (owning `ClientSession` + `Store` +
//! `Client`). The iced `Application`, views, and binary entrypoint live in the
//! `um-gui` bin target (`src/main.rs`, `src/app.rs`, `src/views/`) and depend
//! on this lib for the shared types and the bridge.
//!
//! No `unsafe`, no panics in non-test code; `#![forbid(unsafe_code)]` matches
//! `um_client`.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod command;
pub mod config;
pub mod event;
pub mod types;

pub use bridge::Bridge;
pub use command::Command;
pub use config::Config;
pub use event::Event;
pub use types::{ChatId, ContactView, Direction, MessageView, Status};
