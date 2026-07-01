//! um-gui — native desktop GUI binary entrypoint for untitled_messenger.
//!
//! The bridge owns a `rusqlite::Connection` (not `Sync`), so it runs on a
//! dedicated **current-thread** tokio runtime + `LocalSet` pinned to one
//! background thread (`"um-bridge"`). That thread lives for the whole process:
//! `LocalSet::block_on` drives the local set with a pending future, so the
//! bridge task (spawned via `spawn_local`) runs in the background while the
//! handle's channels cross over to the main thread.
//!
//! iced builds and drives its **own** tokio runtime internally, so the GUI runs
//! on the main thread and the bridge on its own — the two communicate only
//! through the `Command`/`Event` channels, which are `Send` and work across
//! runtimes.
//!
//! The app decides its initial view (Setup vs Login) by checking store-file
//! existence itself (cheap `Path::exists`), avoiding a startup race with the
//! bridge.
//!
//! No `unsafe`, no panics in non-test code.

#![forbid(unsafe_code)]

mod app;
mod views;

use std::sync::{mpsc as std_mpsc, Arc};

use tokio::sync::mpsc;
use tokio::task::LocalSet;
use um_client::session::ClientSession;
// The view submodules (and their unit tests) reference these shared view-data
// types as `crate::ChatId`, `crate::Direction`, etc. They live in the `um_gui`
// lib; re-binding them at the binary crate root makes them crate-local. Some
// are only touched by the view tests, hence `unused_imports` is allowed.
#[allow(unused_imports)]
use um_gui::types::{ChatId, Direction, MessageView, Status};
use um_gui::{Bridge, Config, Event};

fn main() -> iced::Result {
    // tracing for the bridge's diagnostic output (decrypt failures, etc.).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let config = um_gui::config::load();

    // Decide the initial view from store-file existence, without a bridge
    // round trip. First run (no last identity) → Setup; otherwise Login.
    let initial_view = if config.last_identity_pub.is_empty()
        || !um_gui::config::store_exists(&config.last_identity_pub)
    {
        app::View::Setup
    } else {
        app::View::Login
    };

    // Spawn the bridge on its own current-thread runtime + LocalSet, pinned to
    // a background thread. The handle's channels come back over a std channel.
    let (command_tx, event_rx) = spawn_bridge(config.clone());

    let bridge_cmd = Arc::new(command_tx);

    let mut um_app = app::UmApp::new(bridge_cmd, initial_view, config);
    um_app.set_event_rx(event_rx);

    iced::application("UM", app::update, app::view)
        .subscription(app::subscription)
        .run_with(move || (um_app, iced::Task::none()))
}

/// Spawn the async bridge on a dedicated background thread with its own
/// current-thread tokio runtime and `LocalSet` (the bridge owns a
/// `rusqlite::Connection`, which is not `Sync`, so its future is `!Send`).
///
/// Returns the bridge's command sender and event receiver. The thread lives for
/// the lifetime of the process: the `LocalSet` is driven by a pending future so
/// the `spawn_local` bridge task keeps running in the background.
fn spawn_bridge(config: Config) -> (mpsc::Sender<um_gui::Command>, mpsc::Receiver<um_gui::Event>) {
    let (tx, rx) =
        std_mpsc::channel::<(mpsc::Sender<um_gui::Command>, mpsc::Receiver<um_gui::Event>)>();

    std::thread::Builder::new()
        .name("um-bridge".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build bridge tokio runtime");

            let local = LocalSet::new();
            local.block_on(&runtime, async move {
                // Fresh identity for the Setup path. On the Login path the
                // bridge loads the persisted session from the store on Unlock;
                // this fresh session is a placeholder until then (discarded
                // once Unlock replaces `self.session`).
                let session = ClientSession::generate(10);
                let bridge = Bridge::new(session, None, config);
                let handle = bridge.spawn();
                // Hand the channels to the main thread before parking.
                let _ = tx.send((handle.command_tx, handle.event_rx));
                // Keep the LocalSet alive forever so the spawned bridge task
                // keeps running. The bridge exits when the command channel
                // closes (GUI dropped), but the thread itself stays until the
                // process exits.
                std::future::pending::<()>().await;
            });
        })
        .expect("spawn bridge thread");

    rx.recv().expect("bridge thread failed to initialize")
}
