# untitled_messenger — GUI design (`um_gui`)

**Status:** Draft (pending user review)
**Date:** 2026-07-01
**Branch:** `dev`

## Overview

A native desktop GUI for untitled_messenger, built with `iced`. Covers all six
views from the original design spec: `Setup`, `Login`, `ContactList`,
`ChatThread` (1:1), `GroupChat`, `Settings`. The GUI is a thin presentation
layer over the existing headless `um_client` core; all crypto, networking, and
encrypted-storage logic stays in `um_client`, driven asynchronously from a
background tokio runtime that talks to iced over two channels.

This spec resolves a contradiction in the original design doc, which placed the
GUI inside `crates/client/` (`main.rs`, `app.rs`, `views/`). The `um_client`
`lib.rs` already promises a separate `um_gui` crate. **The GUI lives in a new
`um_gui` crate; `um_client` remains headless.** The original design doc's
in-crate layout is superseded by this spec.

## Prerequisites (separate specs, built before `um_gui`)

`um_gui` depends on two pieces of work that do not yet exist. Each gets its own
spec → plan → implementation cycle, in this order:

1. **Server Subscribe push** — `um_server` + possibly `um_protocol`. Today
   `ClientMessage::Subscribe` is a no-op (the handler replies `AckOk`; the
   listener does not hold a long-lived push connection). The GUI's receive loop
   requires real push: after `Subscribe`, the server forwards `Delivered` frames
   as envelopes arrive for that connection, without the client polling. Spec:
   `2026-07-01-server-subscribe-push-design.md`.
2. **Group sessions in `um_client`** — `um_crypto::sender_keys` exists but is not
   wired into `ClientSession`. This work adds `HashMap<GroupId, GroupSession>`
   to the session, extends `store.rs` with group state + group message rows, and
   exposes group send/receive operations (final names are set by that spec). Spec: `2026-07-01-client-group-sessions-design.md`.

This spec describes the group-related `Command`/`Event` variants as **interface
contracts** — what `um_gui` will call. If the group-sessions spec exposes a
different API, the variants here update to match; the GUI architecture does not
change.

### Store schema context (decided by the group-sessions spec, not here)
- `groups(group_id BLOB PK, name TEXT)`
- `group_members(group_id BLOB, identity_pub BLOB)`
- `messages` gains a `kind`/chat discriminator, or a separate `group_messages`
  table — the group-sessions spec decides.

## Architecture

### Crate layout

New workspace member `crates/gui`, depends on `um_client` + `iced` + `tokio`.
`um_client` stays headless; its 105 existing tests never compile iced.

```
crates/gui/
├── Cargo.toml
├── src/
│   ├── main.rs          # binary entrypoint: build tokio runtime, spawn bridge, launch iced
│   ├── app.rs           # UmApp: iced Application — state, Message enum, update(), subscription(), view()
│   ├── bridge.rs        # async core: owns ClientSession + Store + Client, command loop + recv-loop
│   ├── command.rs       # Command enum (GUI → bridge)
│   ├── event.rs         # Event enum (bridge → GUI)
│   ├── config.rs        # server host:port + last identity pub, plain TOML at $XDG_CONFIG_HOME/um
│   ├── types.rs         # ChatId, ContactView, MessageView, Direction, Status — plain data shared with views
│   └── views/
│       ├── mod.rs       # View enum + router in app::view()
│       ├── setup.rs
│       ├── login.rs
│       ├── contact_list.rs
│       ├── chat_thread.rs
│       ├── group_chat.rs
│       └── settings.rs
└── tests/
    └── bridge_headless.rs   # drives bridge with a real relay, no iced
```

### Dependency direction (one-way)

`views/` → `app.rs` → `bridge` (via `command_tx`); `bridge` → `app.rs` (via
`event_tx`, streamed through `iced::subscription::run`). Views never touch
`um_client` or async directly.

### Two runtimes

iced runs its own event loop on the main thread. A dedicated
`tokio::Runtime` (multi-thread, 2+ workers) owns the bridge. They communicate
only through the two `mpsc` channels — no shared state, no locks.

### Why `um_gui` is separate

iced + windowing dependencies are large and platform-specific. Keeping them out
of `um_client` means the headless core and its tests stay lean, and `bridge.rs`
is testable without a window by driving `command_rx` / `event_tx` directly.

## State & the two-channel bridge

### `bridge.rs` — async side, owns real state

```rust
pub struct Bridge {
    session: ClientSession,      // identity, ratchets (1:1), group sessions (after prereq)
    store: Option<Store>,        // Some after unlock; None until Login/Setup done
    net: Option<Client>,         // Some after connect + register + subscribe
    config: Config,
    command_rx: mpsc::Receiver<Command>,
    event_tx: mpsc::Sender<Event>,
    last_delivered_id: u64,      // Subscribe push cursor / reconnect
}
```

Runs two tasks on the tokio runtime:

- **command task** — `while let Some(cmd) = command_rx.recv().await { handle(cmd) }`.
  Each command mutates session/store/net, may `send_msg`, emits `Event`s.
- **recv-loop task** — active only while `net` is connected:
  `loop { net.recv_msg() → match Delivered(envelopes) → session.receive(each) → event_tx.send(Event::Decrypted) }`.
  On EOF/error → `Event::Disconnected` + exponential-backoff reconnect.

### `app.rs` — sync side, display-only state

```rust
pub struct UmApp {
    view: View,                  // current screen
    identity_pub: Option<[u8;32]>,
    contacts: Vec<ContactView>,  // mirror of store.contacts()
    open_chat: Option<ChatId>,   // which thread is open (peer or group)
    threads: HashMap<ChatId, ThreadView>,  // messages per open thread (in-memory cache)
    next_local_id: u64,          // monotonic id for optimistic-send matching
    passphrase_input: String,    // transient form state
    server_input: String,
    error: Option<String>,
    bridge_cmd: mpsc::Sender<Command>,           // clone, given to app at launch
    event_rx: Option<mpsc::Receiver<Event>>,     // moved into subscription::run
}
```

`ThreadView = Vec<MessageView>`. This is a **cache** — the store is source of
truth. On `Event::Decrypted`, app appends to `threads` (the bridge already
persisted it). On startup after unlock, bridge emits
`Event::HistoryLoaded(ChatId, Vec<MessageView>)` so the app hydrates the cache.

### Channel contract

- `Command` (GUI → bridge): fire-and-forget. Bridge acks via `Event` when
  relevant. GUI never blocks on a command.
- `Event` (bridge → GUI): delivered through `iced::subscription::run` as
  `Message::Event(Event)`. Bounded channel (cap 256); if the GUI is slow, the
  bridge logs and drops the oldest non-critical events, always keeping
  `Decrypted` and `Error`.

### No shared mutable state

`ClientSession` / `Store` / `Client` live only in the bridge, only on the tokio
runtime. The app holds clones of *data* (pubkeys, message text), never the live
objects.

## Command & Event enums

### `command.rs` — GUI → bridge

```rust
pub enum Command {
    // Setup / Login
    Setup { passphrase: String, one_time_count: u32 },   // generate identity, create store
    Unlock { passphrase: String },                        // open existing store
    Connect { addr: SocketAddr },                         // connect + register + subscribe

    // Contacts
    AddContact { identity_pub: [u8;32], nickname: String },
    VerifyFingerprint { identity_pub: [u8;32] },          // mark verified in store

    // 1:1 chat
    StartSession { peer: [u8;32], first_message: String, local_id: u64 }, // X3DH via fetched bundle
    SendMessage { peer: [u8;32], text: String, local_id: u64 },           // existing session
    LoadThread { peer: [u8;32] },                         // hydrate cache from store

    // Group chat (depends on group-sessions prereq)
    CreateGroup { name: String, members: Vec<[u8;32]> },
    SendGroupMessage { group: [u8;32], text: String, local_id: u64 },
    LoadGroupThread { group: [u8;32] },

    // Settings
    RotateSignedPrekey,
    ReplenishOneTimePrekeys { count: u32 },
    ChangeServer { addr: SocketAddr },                    // disconnect + reconnect
    Logout,                                               // drop store + net, back to Login
}
```

### `event.rs` — bridge → GUI

```rust
pub enum Event {
    // Lifecycle
    Ready { identity_pub: [u8;32] },                      // setup/unlock succeeded
    Connected,
    Disconnected { reason: String },                      // recv-loop died, will retry
    Error(String),                                        // surfaced as banner

    // Data
    ContactsLoaded(Vec<ContactView>),
    HistoryLoaded(ChatId, Vec<MessageView>),
    Decrypted { chat: ChatId, msg: MessageView },         // incoming (1:1 or group)
    Sent { chat: ChatId, local_id: u64, msg: MessageView }, // our message persisted + sent
    SendFailed { chat: ChatId, local_id: u64, reason: String },
    FingerprintVerified { identity_pub: [u8;32] },

    // Group
    GroupCreated { group: [u8;32], name: String },
    GroupInvited { group: [u8;32], name: String },        // we were added
}
```

### Shared view types (`types.rs`) — plain data, no `um_client` types leak

```rust
pub enum ChatId { Peer([u8;32]), Group([u8;32]) }

pub struct ContactView {
    pub identity_pub: [u8;32],
    pub nickname: String,
    pub fingerprint: [u8;32],
    pub verified: bool,
}

pub struct MessageView {
    pub local_id: u64,
    pub text: String,
    pub dir: Direction,
    pub timestamp: u64,
    pub status: Status,
}

pub enum Direction { Out, In }
pub enum Status { Sending, Sent, Delivered, Failed }
```

### Mapping rules

- `StartSession` → bridge fetches peer bundle (`FetchBundle`), runs
  `session.start_session`, `send_msg(Send)`, persists ratchet state + message,
  emits `Event::Sent`. Bundle-fetch failure → `Event::SendFailed` +
  `Event::Error`.
- `SendMessage` → `session.send`, `send_msg`, persist, `Event::Sent`.
- Incoming `Delivered` envelope → `session.receive` → persist →
  `Event::Decrypted`. If `receive` returns `NoSession` and an init is present,
  the ratchet is seeded automatically (Bob path) — no user action.
- Group variants delegate to the group-sessions API (prereq); this spec
  describes them as the interface `um_gui` will call.

### Error discipline

Every bridge fallible path → `Event::Error(human_string)`. The bridge never
panics; `unwrap` / `expect` / `panic!` are forbidden in non-test code. The crate
carries `#![forbid(unsafe_code)]`, matching `um_client`.

## The six views

Each view is a function returning `iced::Element<Message>`. The router in
`app::view()` matches `self.view`. All user input → `Message` → `update()` →
`Command` to the bridge.

**`View` enum:** `Setup | Login | ContactList | ChatThread([u8;32]) |
GroupChat([u8;32]) | Settings`

`ChatThread` carries the peer identity pub; `GroupChat` carries the group id.
Both are `[u8;32]`; the variant distinguishes 1:1 from group.

### Setup (first-run, no store file)
- Widgets: passphrase input, confirm-passphrase input, one-time-prekey count
  (default 10), server-addr input (prefilled `127.0.0.1:7000`), "Create
  identity" button.
- On submit → `Message::SetupSubmit` → `Command::Setup`. Bridge generates
  identity, creates store, persists. `Event::Ready` → switch to `ContactList`.
- Validation: passphrase ≥ 8 chars, confirm matches, non-empty server. Errors
  → banner.

### Login (existing store file)
- Widgets: passphrase input, "Unlock" button.
- On submit → `Command::Unlock`. Bridge opens store, loads identity + contacts,
  emits `Event::Ready` + `Event::ContactsLoaded`. → `ContactList`.
- Wrong passphrase → `Event::Error("wrong passphrase")` → banner, stay on Login.

### ContactList
- Widgets: list of contacts (nickname + fingerprint hex + ✓ if verified), "Add
  contact" form (paste 32-byte hex pubkey + nickname), "Open" button per
  contact, "New group" button, "Settings" button, connection-status indicator.
- Add → `Command::AddContact`. Open → `Command::LoadThread` then switch to
  `ChatThread(Peer(pub))`.
- New group → modal: name + member multi-select from contacts →
  `Command::CreateGroup` → `Event::GroupCreated` → switch to `GroupChat`.
- Groups appear in a separate "Groups" section of the list.

### ChatThread (1:1, peer identity pub)
- Widgets: message list (scrollable, in/out aligned), compose input, "Send"
  button, header with peer nickname + fingerprint (tap → verify dialog).
- Send → `Command::StartSession` (if no session yet) or `Command::SendMessage`.
  Compose clears on `Event::Sent`.
- Incoming `Event::Decrypted` appends. If the thread is not open, increment an
  unread badge on ContactList.
- Verify dialog → `Command::VerifyFingerprint` → `Event::FingerprintVerified`
  → ✓ on contact.

### GroupChat([u8;32])
- Same layout as ChatThread. Incoming events arrive as
  `Event::Decrypted{chat: ChatId::Group(..)}`. Send →
  `Command::SendGroupMessage`. Header shows group name + member count. Incoming
  `Event::GroupInvited` (we were added) → notification + thread appears in the
  ContactList "Groups" section.

### Settings
- Widgets: identity pubkey hex (copyable), fingerprint, server addr (editable →
  `Command::ChangeServer`), "Rotate signed prekey" button, "Replenish one-time
  prekeys" (count input), "Logout" button.
- Rotate → `Command::RotateSignedPrekey` → re-register bundle. Replenish →
  `Command::ReplenishOneTimePrekeys` → re-register. Both emit `Event::Connected`
  or `Event::Error`.
- Logout → `Command::Logout` → bridge drops store + net →
  `Event::Disconnected` → switch to `Login`.

### Navigation model

A linear stack is overkill for v1. The `view` field holds the single active
screen; back-actions set it explicitly (ChatThread → ContactList, Settings →
ContactList). No deep nesting.

## Data flow

### Startup sequence
1. `main.rs`: build `tokio::Runtime` (multi-thread), create
   `mpsc::channel::<Command>(256)` + `mpsc::channel::<Event>(256)`.
2. Spawn `Bridge::run(command_rx, event_tx)` on the runtime. The bridge does not
   emit until the user acts. **The app decides the initial view by checking
   store-file existence itself** (cheap `Path::exists`) — this avoids a startup
   race. App starts on `Setup` if no store file, else `Login`.
3. `main.rs`:
   `iced::application("UM", UmApp::update, UmApp::view).subscription(UmApp::subscription).run()`.
   `event_rx` is moved into `subscription::run`.
4. On `Login`/`Setup` success → `Event::Ready{identity_pub}` → app sends
   `Command::Connect` with the configured server → bridge connect + register +
   subscribe → `Event::Connected`.

### Send flow (1:1, no session yet)
```
user types "hi", hits Send (ChatThread)
 → Message::SendPressed
 → update(): app appends MessageView{local_id, status:Sending} to the thread cache (optimistic)
            → command_tx.send(Command::StartSession{peer, first_message:"hi", local_id})
 → bridge: FetchBundle(peer) → session.start_session(bundle, "hi") → send_msg(Send)
            → store.put(ratchet state) → store.put(message)
            → event_tx.send(Event::Sent{chat, local_id, msg{status:Sent}})
 → subscription → Message::Event(Event::Sent) → update(): flip cached msg status Sending→Sent
```
Bundle-fetch / send failure → `Event::SendFailed{chat, local_id, reason}` →
cached msg → Failed, banner.

**Optimistic UI:** the app shows the message immediately at `Sending`; the
bridge confirms via `Event::Sent` keyed by `local_id` (a monotonic counter in
the app). Without `local_id` the app cannot know which cached row to update.

### Send flow (existing session)
Same, but `Command::SendMessage` → `session.send` (no `FetchBundle`).

### Receive flow (Subscribe push, depends on server-push prereq)
```
bridge recv-loop: net.recv_msg() → ServerMessage::Delivered(envelopes)
 → for each envelope: session.receive(env) → (plaintext, sender)
    → store.put(message, dir:In)
    → event_tx.send(Event::Decrypted{chat: Peer(sender), msg})
 → subscription → Message::Event(Decrypted) → update():
    if chat == open_chat: append to the thread cache
    else: bump unread count on that contact
```
Bob path (no session + init present): `session.receive` seeds the ratchet
internally → transparent, same `Event::Decrypted`.

### Persistence flow (write-through)
Every ratchet state change in the bridge →
`store.put("ratchet:<peer>", &ratchet_state)` immediately. Every sent/received
message → `store.put_message(...)`. The store is source of truth; the app cache
is rebuildable. On `Command::LoadThread` → bridge reads store history →
`Event::HistoryLoaded(chat, Vec<MessageView>)` → app replaces the cache for that
chat.

### Reconnect flow
recv-loop EOF/error → `Event::Disconnected{reason}` → app shows a "reconnecting…"
banner, keeps the cache. Bridge backs off (1s → 2s → 4s → … → 30s cap), retries
connect + register + subscribe; on success `Event::Connected` → banner clears.
Messages typed during disconnect are **not queued in v1** —
`Command::SendMessage` while disconnected → `Event::Error("disconnected")` +
`Event::SendFailed` → msg → Failed. (Outbound queue = future work.)

## Error handling & config

### Error handling
- **Bridge never panics.** All fallible paths → `Event::Error(human)`.
  `#![forbid(unsafe_code)]` + no `unwrap`/`expect`/`panic!` in non-test code.
- **Error surface:** a single `Option<String>` banner in app state, shown at the
  top of any view. A new error overwrites; cleared on the next successful
  `Event` or user dismiss. Transient errors (`Disconnected`) auto-clear on
  recovery; fatal ones (`Store corrupt`) persist until Logout.
- **Human strings:** one `fn humanize(&ClientError) -> String` in `bridge.rs`
  maps variants to readable text (e.g. `NoSession` → "no secure session with
  this contact yet"; `Store("wrong passphrase")` → "wrong passphrase";
  `NotConnected` → "not connected to server"). No crypto/stack details leak to
  the UI.
- **Wrong passphrase** on Login: stay on Login, banner "wrong passphrase", clear
  input.
- **Bundle-fetch fail** (StartSession): `Event::Error("contact not registered or
  offline")`, message → Failed, stay in thread.
- **Decrypt fail** (incoming): `Event::Error("failed to decrypt message from
  <peer>")`, drop that envelope (do not crash the recv-loop), continue. Logged
  via `tracing::warn`.
- **Store corruption** (canary open fail at unlock, or schema mismatch):
  `Event::Error("local store unreadable")` — fatal-ish; app offers Logout (drops
  to Login). No auto-recovery.
- **Reconnect exhaustion:** unbounded in v1 — retries to the 30s cap forever.
  User can Logout / ChangeServer to break out.

### Config (`config.rs`)
- Plain TOML at `$XDG_CONFIG_HOME/um/config.toml` (fallback
  `~/.config/um/config.toml`). **Not encrypted** — holds only non-sensitive
  data: `server_addr`, `last_identity_pub` (to locate the store file), optional
  `theme`.
- Store file path: `$XDG_DATA_HOME/um/<identity_pub_hex>.db` (fallback
  `~/.local/share/um/...`). Keyed by identity pub so multiple identities
  coexist. The app picks the store file from `last_identity_pub` in config; if
  absent → Setup.
- No config on first run → Setup prefills server `127.0.0.1:7000` (the
  `um-server` default, `UM_SERVER_ADDR` env, `crates/server/src/main.rs:13`)
  and lets the user edit.
- Config is read at startup (sync, before iced launch — small file). Written on
  Connect (persist chosen server) and on Setup (persist `last_identity_pub`).
  The bridge owns config writes; the app reads an initial copy for
  view-decision.

**Why not encrypted config:** server addr + identity pub are non-secret (the
pub key is public). The passphrase is never stored. The store file holds all
secrets, encrypted. Keeping config plain avoids a key-chicken-egg.

## Testing

The original spec (line 256) says GUI views are tested manually and iced
snapshot tests are skipped in v1 — this spec follows that. But the **bridge is
fully testable without iced**, and that is where the logic lives.

### Bridge headless tests (`tests/bridge_headless.rs`)
Drive `Bridge` through `command_tx` / `event_rx` against a **real `um_server`**
on localhost (same pattern as existing `crates/client/tests/e2e.rs` + `net.rs`
tests — spawn `serve`, real TCP). No iced.

1. **setup_unlock_round_trip** — `Command::Setup` → `Event::Ready` → drop
   bridge → reopen store via `Command::Unlock` → `Event::Ready` with the same
   `identity_pub`.
2. **connect_register_subscribe** — Setup + Connect → `Event::Connected`.
3. **two_bridges_exchange_1to1** — two bridges (alice, bob) on one relay; alice
   `StartSession{bob, "hi"}` → bob receives
   `Event::Decrypted{chat:Peer(alice), text:"hi"}`. Asserts full X3DH + ratchet
   through the bridge + real TCP + Subscribe push.
4. **optimistic_send_status** — alice `SendMessage` → assert
   `Event::Sent{status:Sent}` with matching `local_id`.
5. **wrong_passphrase** — `Command::Unlock{wrong}` on an existing store →
   `Event::Error("wrong passphrase")`, no `Ready`.
6. **reconnect** — kill the relay mid-session, restart →
   `Event::Disconnected` then `Event::Connected`.
7. **history_load** — exchange messages, drop the thread cache,
   `Command::LoadThread` → `Event::HistoryLoaded` with the prior messages.
8. **group_exchange** (gated on the group-sessions prereq) — two+ bridges,
   `CreateGroup` + `SendGroupMessage` → members get
   `Event::Decrypted{chat:Group}`. `#[ignore]` until the prereq lands.

### View-logic tests (pure functions, no iced rendering)
Extract non-rendering logic from views into testable pure functions only where
it pays off:
- `views::contact_list::parse_pubkey_hex(&str) -> Result<[u8;32], ParseError>`
  — tested directly.
- `app::route_after_event(&Event, &View) -> View` — pure transition function,
  tested without iced.
- Fingerprint hex-formatting helper.

Keep these minimal — do not over-extract. Only where logic is non-trivial and
bug-prone.

### Not tested automatically
- Visual layout, widget interaction, iced rendering — manual.
- Real window/keyboard — manual.
- Theme/appearance — manual.

### Test posture target
Bridge tests + pure-function tests keep the **logic** green in CI. The iced
layer is thin (binds state to widgets + emits `Message`s), so a manual smoke
per release is acceptable per the original spec. The existing 105 tests in
`um_client` / `um_crypto` / `um_protocol` / `um_server` stay green; `um_gui`
adds its own and does not touch theirs.

## Dependencies

### `crates/gui/Cargo.toml` (new)
```toml
[package]
name = "um_gui"
edition.workspace = true
version.workspace = true
license.workspace = true

[dependencies]
um_client = { path = "../client" }
um_protocol = { path = "../protocol" }   # SocketAddr + wire types the bridge uses
iced = { version = "0.13", features = ["tokio"] }
tokio = { version = "1", features = ["rt-multi-thread", "sync", "macros", "time", "net"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"                             # config
dirs = "5"                               # XDG config/data paths
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
hex = "0.4"                              # pubkey/fingerprint display + parse
thiserror = "1"

[dev-dependencies]
um_server = { path = "../server" }
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "sync", "macros", "time", "test-util"] }
```

`#![forbid(unsafe_code)]` at the crate root. Binary name `um-gui`.

`iced` is pinned to the `0.13` line (current stable at spec time). The exact
patch is resolved by Cargo at lock time; if `0.13` is superseded before
implementation, bump within the `0.13`/next-stable migration and re-check the
`subscription` / `application` API shape.

## Out of scope (v1, noted as TODO)

- Outbound message queue during disconnect (messages → Failed; user retries).
- File/media attachments (the original spec mentions them; defer to a separate
  spec).
- QR-code add-contact (paste-hex only in v1).
- iced snapshot/visual tests (manual per the original spec).
- Multi-account in-app switcher (one identity per store file; multiple store
  files are selectable via config `last_identity_pub`, but no switcher UI in
  v1).
- OS notification integration — future.
- Message search.
- Read receipts beyond `Delivered` status.
