# untitled_messenger — Server Subscribe push design

**Status:** Draft (pending user review)
**Date:** 2026-07-01
**Branch:** `dev`

## Overview

Implement real server-side push for `ClientMessage::Subscribe`. Today
`Subscribe` is a no-op: `handler.rs` replies `AckOk`, and the listener does not
hold a long-lived push connection. After this work, a subscribed connection
receives `ServerMessage::Delivered` frames as envelopes arrive for it, without
polling.

This is the **first prerequisite** for the `um_gui` crate (see
`2026-07-01-messenger-gui-design.md`), whose bridge receive loop depends on
real push. Build order agreed across the three specs: **Push → Groups → GUI**.

The protocol (`um_protocol`) is **not changed**. `Subscribe` stays parameterless;
`Delivered(Vec<EncryptedEnvelope>)` stays as-is. All work is inside `um_server`.

## Current state (what exists)

- `listener.rs handle_conn` — per-connection loop, sync dispatch via `handle()`,
  owns `self_id` + the write half. No registry of live connections.
- `handler.rs handle()` — pure sync fn over `&Store`, returns `ServerMessage`.
  `Subscribe` → `AckOk`. No access to connections.
- `store.rs` — `bundles`, `outboxes` (per-recipient FIFO `Vec<EncryptedEnvelope>`),
  `registered`, `next_envelope_id`. `deliver()` appends to outboxes and assigns
  each recipient a monotonic id. `poll(since)` reads without removing (until
  `Ack`). No push mechanism.
- `main.rs` — `Arc<Store>` + `serve` + `std::future::pending`.

## Architecture

### New state: `Subscribers` (`crates/server/src/subscribers.rs`)

```rust
pub struct Subscribers {
    inner: Mutex<HashMap<[u8;32], mpsc::Sender<ServerMessage>>>,
}

impl Subscribers {
    pub fn new() -> Self;

    /// Register `tx` as the push sender for `id`. If an entry exists, evict it
    /// and return the old `Sender` (so the caller can drop it and close the
    /// old connection via a `None` recv). Last-Subscribe-wins.
    pub fn register(&self, id: [u8;32], tx: mpsc::Sender<ServerMessage>) -> Option<mpsc::Sender<ServerMessage>>;

    /// Remove the entry for `id` only if its channel matches `tx`
    /// (`Sender::same_channel`). Prevents a disconnect-cleanup from removing a
    /// newer subscriber that evicted this one.
    pub fn unregister_if_match(&self, id: &[u8;32], tx: &mpsc::Sender<ServerMessage>);

    /// Clone the push sender for `id`, if present.
    pub fn get(&self, id: &[u8;32]) -> Option<mpsc::Sender<ServerMessage>>;
}
```

`Arc<Subscribers>` is created in `main.rs` alongside `Arc<Store>` and passed into
`serve()` and every `handle_conn`.

### `handle()` signature change

```rust
// before:
pub fn handle(store: &Store, self_id: &[u8;32], msg: ClientMessage) -> ServerMessage;
// after:
pub fn handle(store: &Store, subs: &Subscribers, self_id: &[u8;32], msg: ClientMessage) -> ServerMessage;
```

`handle` stays **sync** — push is performed via `mpsc::Sender::try_send`, which
is sync and non-blocking. All existing `handler.rs` tests are updated to pass
`&Subscribers::new()` (mechanical, 11 tests).

### `serve()` signature change

```rust
// before:
pub async fn serve(addr: &str, store: Arc<Store>) -> std::io::Result<std::net::SocketAddr>;
// after:
pub async fn serve(addr: &str, store: Arc<Store>, subs: Arc<Subscribers>) -> std::io::Result<std::net::SocketAddr>;
```

`net.rs`, `e2e.rs`, and `integration.rs` tests are updated to pass
`Arc::new(Subscribers::new())`.

### Why `try_send` does not block `handle`

The push channel is bounded (cap 256). If the connection's drain path falls
behind a slow client, `try_send` returns `Full`; `handle` logs a warning and
skips the push for that envelope. The envelope **remains in the outbox**
(deliver already appended it; push never removes from the outbox). The client
recovers it on the next Subscribe-flush or `Poll`. Delivery is not lost — only
the immediate push notification.

### I/O outside the mutex

The `Subscribers` mutex holds only `Sender` values (cheap to clone). `get()`
clones a sender under a short lock, releases, then `try_send`s. The actual
socket write happens in `handle_conn` (the `select!` branch), with no registry
lock held.

## Connection lifecycle & drain

### `handle_conn` reworked (`listener.rs`)

```rust
async fn handle_conn(stream: TcpStream, store: Arc<Store>, subs: Arc<Subscribers>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    let mut self_id: Option<[u8;32]> = None;
    // Push channel: None until Subscribe. Drain is inline via select!.
    let mut push_rx: Option<mpsc::Receiver<ServerMessage>> = None;
    // The connection's own sender clone, kept for match-based cleanup.
    let mut push_tx: Option<mpsc::Sender<ServerMessage>> = None;

    loop {
        // Two modes (see below): not-subscribed reads frames as today;
        // subscribed races frame-read vs push-recv via select!.
        ...
    }

    // Cleanup: remove our subscriber entry only if it is still ours.
    if let (Some(id), Some(tx)) = (self_id, push_tx) {
        subs.unregister_if_match(&id, &tx);
    }
}
```

### Two modes in one loop

- **Not subscribed** (`push_rx = None`): reads frames as today, dispatches via
  `handle`, writes the reply to `writer` directly. Existing behavior.
- **Subscribed** (`push_rx = Some`): `tokio::select!` between `reader.read()`
  and `push_rx.recv()`.
  - `push_rx.recv() → Some(msg)` → encode + `writer.write_all`. Push frame out.
  - `reader.read() → n` → decode frames → dispatch via `handle`. The reply also
    goes to `writer`. Replies and pushes interleave on the socket; the client
    distinguishes by `ServerMessage` variant (`Delivered` = push,
    `AckOk`/`Bundle`/`Error` = reply to its own command).
  - `push_rx.recv() → None` → the sender was dropped (evicted by a newer
    Subscribe) → close the connection.

### Subscribe handling (in `handle_conn`, not `handle`)

`handle()` cannot register a sender (it has no `tx` — the channel is created
*inside* Subscribe). So Subscribe is handled entirely in `handle_conn`:

```rust
ClientMessage::Subscribe => {
    let (tx, rx) = mpsc::channel(256);
    let _evicted = subs.register(id, tx.clone());
    push_tx = Some(tx);
    push_rx = Some(rx);
    // Flush unacked outbox (poll since 0) as immediate Delivered, batched.
    let pending = store.poll(&id, 0);
    for chunk in pending.chunks(64) {
        let frame = encode(&ServerMessage::Delivered(chunk.to_vec()));
        writer.write_all(&frame).await;
    }
    // Reply AckOk (mode accepted).
    writer.write_all(&encode(&ServerMessage::AckOk)).await;
}
```

`handle()` keeps a `Subscribe → AckOk` arm for the stateless unit tests; it is
documented as "real work is in the listener." `handle()` for Subscribe does not
touch `subs`.

### Drain is inline, not a separate task

Push frames are written in the same `handle_conn` loop via `select!`. There is
a single writer; `select!` gives exclusive access to it in each branch, so
there is no concurrent write. No separate drain task, no second owner of the
write half.

### Disconnect cleanup

On loop exit (EOF / error / malformed frame / `None` push recv), if the
connection registered as a subscriber, call
`subs.unregister_if_match(&id, &push_tx)`. Because of last-Subscribe-wins, an
evicted older connection's `push_tx` no longer matches the registry entry (the
newer Subscribe replaced it), so `same_channel` is false and the newer
subscriber is untouched. Dropping `push_rx` closes the channel.

## Push trigger in `Send` / `deliver`

### `handle()` Send arm

```rust
ClientMessage::Send { recipients, envelope } => {
    if !recipients.iter().all(|r| store.is_registered(r)) {
        return ServerMessage::Error(ServerError::UnknownRecipient);
    }
    let delivered = store.deliver(&recipients, envelope); // new return shape
    for (recipient, _id, env) in delivered {
        if let Some(tx) = subs.get(&recipient) {
            let _ = tx.try_send(ServerMessage::Delivered(vec![env]));
        }
    }
    ServerMessage::AckOk
}
```

### `store.deliver` signature change

```rust
// before:
pub fn deliver(&self, recipients: &[[u8;32]], envelope: EncryptedEnvelope) -> Vec<u64>;
// after:
pub fn deliver(&self, recipients: &[[u8;32]], envelope: EncryptedEnvelope) -> Vec<([u8;32], u64, EncryptedEnvelope)>;
```

The returned vec contains **only registered recipients** (id > 0). Unregistered
recipients are skipped from the return (they are not delivered to and not
pushed). Existing `store.rs` tests that assert on ids are updated to
`delivered.iter().map(|(_, id, _)| *id)`.

### `try_send` failure handling

- `Full` → warn log; the envelope stays in the outbox. The client recovers it
  on the next Subscribe-flush or `Poll`. Push skipped, delivery not lost.
- `Closed` → the subscriber vanished between `get()` and `try_send`. Ignored;
  the envelope is in the outbox and re-flushes on reconnect + Subscribe.
- Neither is fatal; `handle` returns `AckOk` (the sender is not at fault).

### Group fan-out

`deliver` already handles multiple recipients. Push iterates all returned
recipients; each live member gets its own `Delivered`. Unregistered members are
absent from the return. Group sender-key distribution is the group-sessions
prereq spec's concern; the server simply fans out by recipient and does not
know about groups.

### Lock ordering

`handle` holds no lock itself. `store.deliver` takes the store mutex and
releases it. `subs.get` takes the subs mutex, releases it, then `try_send`. The
two mutexes are never held simultaneously — deadlock is impossible.

## Protocol, Poll coexistence, dedup

### `um_protocol` unchanged

`ClientMessage::Subscribe` stays parameterless. `ServerMessage::Delivered(Vec<EncryptedEnvelope>)`
stays. No new wire types.

### Poll stays working (dual mode)

- `Poll { since }` → `Delivered(poll(since))` as today. Does not depend on
  subscription.
- A client may Poll without Subscribe (legacy mode), Subscribe and receive
  pushes, or both. Existing Poll tests stay green; the Poll arm in `handle` is
  unchanged.

### Dedup is the client's job, not the server's

- The outbox retains envelopes **until Ack**. Push sends a copy but does not
  remove from the outbox.
- Scenario: a client receives a push (env id=5) but has not Acked. It
  reconnects and Subscribe-flushes → id=5 is re-pushed. The client sees a
  duplicate.
- The `um_gui` bridge holds `last_delivered_id` and dedups by envelope id. The
  headless `ClientSession` / `Client` do not dedup (caller's job). The server
  does not dedup.
- `Ack` removes from the outbox → after Ack, re-push does not return it. The
  GUI bridge Acks after persist + decrypt.

### Subscribe-flush semantics

- Subscribe → `store.poll(id, 0)` → all unacked envelopes (id > 0) → pushed as
  `Delivered` frames, batched at 64 envelopes per frame.
- Flush `since` = 0 (all unacked). The server does not track the client's
  cursor; 0 plus client-side dedup is simpler and correct.
- Large outboxes are chunked into batches of 64 to keep frames within sane
  size limits.

### Frame ordering on the client

Push `Delivered` and reply `AckOk` / `Bundle` / `Error` interleave in one TCP
stream. The client matches by `ServerMessage` variant: `Delivered` is incoming,
the rest are responses to its own commands. `um_client::Client::recv_msg`
returns `ServerMessage` generically; the GUI bridge recv-loop matches
`Delivered` → decrypt, ignores the rest (or logs).

### Backpressure summary

- Push channel cap 256. Overflow → `try_send` `Full` → skip push, env in outbox.
- A slow client does not block `handle` (`try_send` is non-blocking); other
  clients are unaffected.
- The outbox grows without bound for offline/slow clients — a known limitation
  of the in-memory store (the design spec already fixes "lost on restart", no
  persistence). v1: unbounded, noted. Future: outbox cap + drop-oldest or
  persistence.

## Testing

### Existing tests — updated, not broken

- `handler.rs` (11 tests): `handle(store, subs, &id, msg)` — add `subs:
  &Subscribers` arg. Mechanical. `subscribe_returns_ackok` stays (Subscribe arm
  → `AckOk` in `handle`).
- `store.rs`: `deliver` returns `Vec<([u8;32], u64, EncryptedEnvelope)>` —
  `deliver_*` tests updated to map ids. Mechanical.
- `net.rs` (2) + `e2e.rs` (2) + `integration.rs` (5): `serve(addr, store,
  Arc::new(Subscribers::new()))` — add `subs` arg. Mechanical.
- All 105 existing tests stay green.

### New tests

`subscribers.rs` unit tests:
1. `register_returns_none_first` — first register → None.
2. `register_evicts_old_returns_tx` — second register same id → returns old tx.
3. `unregister_if_match_removes_only_matching` — unregister with own tx removes;
   with a foreign tx (`same_channel` false) does not.
4. `get_returns_cloned_sender` — get after register → Some; clone works.

`handler.rs` new:
5. `send_pushes_to_live_subscriber` — register alice+bob, register bob's tx in
   `subs`, alice Send → `rx.try_recv()` → `Delivered(vec)`.
6. `send_to_offline_recipient_no_push_but_delivered` — recipient without
   subscription → deliver appends, `subs.get` → None, push skipped; outbox has
   the env (`poll` confirms).
7. `send_push_full_channel_skips_keeps_outbox` — cap-1 channel, fill it, Send →
   `try_send` `Full` → env in outbox (`poll` confirms); `handle` → `AckOk`.

`listener.rs` / integration (async, real TCP):
8. `subscribe_receives_push_for_new_message` — two connections, bob
   Register+Subscribe, alice Register+Send → bob recv → `Delivered` with the
   env. Real push over TCP.
9. `subscribe_flushes_unacked_outbox` — bob offline, alice Send (env in outbox),
   bob reconnect Register+Subscribe → flush → `Delivered` with that env.
10. `reconnect_repushes_unacked` — bob Subscribe, gets env, no Ack, disconnect,
    reconnect Subscribe → re-push of that env (dedup is the client's).
11. `last_subscribe_wins_evicts_old` — bob Subscribe (conn1), bob Subscribe
    (conn2) → conn1 recv → `None` (push_rx closed) / conn1 closes.
12. `poll_still_works_alongside_subscribe` — bob Subscribe, alice Send (push),
    bob `Poll since 0` → also `Delivered` (env still in outbox, not acked).
    Dual mode.

`store.rs` new:
13. `deliver_returns_only_registered_recipients` — deliver with 1 registered +
    1 unregistered → vec contains only the registered recipient (id > 0).

### Test posture

+13 tests, total ~118. All async tests use `#[tokio::test]` + real `serve` on
an ephemeral port (same pattern as existing tests).

## Scope

### In scope (exactly)

- `crates/server/src/subscribers.rs` — new `Subscribers` module.
- `crates/server/src/handler.rs` — `handle()` +`&Subscribers`; Send arm push;
  Subscribe arm stays `AckOk`.
- `crates/server/src/listener.rs` — `handle_conn` +`subs`; Subscribe intercept
  (channel + register + flush); `select!` push vs read; cleanup
  `unregister_if_match`.
- `crates/server/src/store.rs` — `deliver` signature →
  `Vec<([u8;32], u64, EncryptedEnvelope)>`; return only registered recipients.
- `crates/server/src/main.rs` — `Arc::new(Subscribers::new())`, pass to `serve`.
- `crates/server/src/lib.rs` — `pub mod subscribers; pub use subscribers::Subscribers;`.
- All affected tests updated. +13 new tests.

### Out of scope (v1, noted TODO)

- Outbox cap / bounded growth — in-memory store grows without bound for
  offline clients. Future: cap + drop-oldest or persistence.
- WebSocket / multiplexed transport — stays raw TCP framed.
- Multi-device / multi-connection per identity — last-Subscribe-wins; one
  active push connection per identity. Future: fan-out to multiple devices.
- Server-side dedup — client's responsibility (GUI bridge
  `last_delivered_id`).
- Persisted outbox across restart — the design spec already fixes "lost on
  restart".
- Push for group sender-key distribution — group sessions are a separate spec
  (prereq 2). The server fans out by recipient and does not know about groups.
- Auth/TLS — plaintext TCP, as today.
- Flow control beyond the mpsc cap of 256.

## Resolved decisions (no placeholders)

1. Flush `since` = 0 + client-side dedup.
2. Flush batch size = 64 envelopes per `Delivered` frame.
3. Push channel cap = 256.
4. `unregister` = `unregister_if_match(id, &Sender)` via `same_channel`.
5. Subscribe handled in `handle_conn`; `handle` arm = `AckOk` for stateless
   tests.
6. `deliver` returns only registered recipients (id > 0).
7. Poll coexists with Subscribe (dual mode).
