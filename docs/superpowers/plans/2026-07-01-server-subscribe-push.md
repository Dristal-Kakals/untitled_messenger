# Server Subscribe Push Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement real server-side push so a subscribed connection receives `ServerMessage::Delivered` frames as envelopes arrive, without polling.

**Architecture:** A new `Subscribers` registry (`identity_pub → mpsc::Sender<ServerMessage>`) lives alongside `Arc<Store>`. `handle_conn` intercepts `Subscribe` to register a push channel and flush the unacked outbox, then `select!`s between frame reads and push recv. `handle()` gains `&Subscribers` and `try_send`-pushes `Delivered` on `Send`. `deliver()` returns `(recipient, id, env)` triples for registered recipients only. `um_protocol` is unchanged; `Poll` stays working (dual mode).

**Tech Stack:** Rust 2021, tokio 1 (mpsc, sync, net, io-util, macros), `um_protocol` (postcard framing), `um_crypto` (bundle sig verify in tests). `#![forbid(unsafe_code)]` throughout.

## Global Constraints

- `#![forbid(unsafe_code)]` in `crates/server/src/lib.rs` — keep it; new module `subscribers.rs` is safe-only.
- No `unwrap`/`expect`/`panic!` in non-test code (matches existing `um_client` ethos; existing `store.rs` uses `.expect("store mutex poisoned")` on mutex locks — that pattern is pre-existing and acceptable to keep consistent, but new code should prefer `unwrap_or`/logging where reasonable).
- `um_protocol` is NOT modified by this plan — no wire-type changes.
- Push channel cap = 256. Flush batch size = 64 envelopes per `Delivered` frame.
- `Subscribers::unregister` uses `Sender::same_channel` (confirmed available in tokio 1.52.3, `crates/server` resolves tokio 1).
- `deliver()` returns only registered recipients (id > 0); unregistered recipients are absent from the return.
- All 105 existing tests must stay green; signature changes are updated mechanically in the same task that introduces them.
- Commits: Conventional Commits, end every commit message with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run tests from workspace root: `cargo test -p um_server` for server tests; `cargo test` for full suite. `./build.sh` for the full pipeline (fmt + clippy + build + test).

## File Structure

- **Create** `crates/server/src/subscribers.rs` — `Subscribers` registry: `Mutex<HashMap<[u8;32], mpsc::Sender<ServerMessage>>>` with `register` (evict-and-return-old), `unregister_if_match` (same_channel guard), `get` (clone sender).
- **Modify** `crates/server/src/lib.rs` — add `pub mod subscribers;` and `pub use subscribers::Subscribers;`.
- **Modify** `crates/server/src/store.rs` — `deliver()` return type `Vec<u64>` → `Vec<([u8;32], u64, EncryptedEnvelope)>`, returning only registered recipients; update its 3 `deliver_*` tests.
- **Modify** `crates/server/src/handler.rs` — `handle()` signature +`&Subscribers`; `Send` arm pushes to live subscribers; `Subscribe` arm stays `AckOk`; update all 11 `handle()` call sites in tests.
- **Modify** `crates/server/src/listener.rs` — `serve()` +`Arc<Subscribers>`; `handle_conn` +`subs`, Subscribe intercept (channel + register + flush + AckOk), `select!` push vs read, cleanup `unregister_if_match`.
- **Modify** `crates/server/src/main.rs` — construct `Arc::new(Subscribers::new())`, pass to `serve`.
- **Modify** `crates/client/src/net.rs` tests (2), `crates/client/tests/e2e.rs` (2), `crates/server/tests/integration.rs` (5) — `serve(addr, store, Arc::new(Subscribers::new()))` arg.

---

### Task 1: `Subscribers` registry module

**Files:**
- Create: `crates/server/src/subscribers.rs`
- Modify: `crates/server/src/lib.rs`
- Test: `crates/server/src/subscribers.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `um_protocol::ServerMessage` (for the channel type), `tokio::sync::mpsc`, `std::sync::Mutex`, `std::collections::HashMap`.
- Produces:
  - `pub struct Subscribers`
  - `pub fn Subscribers::new() -> Self`
  - `pub fn Subscribers::register(&self, id: [u8;32], tx: mpsc::Sender<ServerMessage>) -> Option<mpsc::Sender<ServerMessage>>`
  - `pub fn Subscribers::unregister_if_match(&self, id: &[u8;32], tx: &mpsc::Sender<ServerMessage>)`
  - `pub fn Subscribers::get(&self, id: &[u8;32]) -> Option<mpsc::Sender<ServerMessage>>`

- [ ] **Step 1: Write the failing tests**

Create `crates/server/src/subscribers.rs` with only the test module and a stub `Subscribers` that does not compile meaningfully (we add impl after). Actually write the tests first against the intended API; the file will fail to compile until the impl exists. Put this content in `crates/server/src/subscribers.rs`:

```rust
//! Registry of live push subscribers: identity_pub -> mpsc sender. Used by
//! the listener to route `Delivered` pushes to the connection that owns an
//! identity. Last-Subscribe-wins: registering a new sender for an identity
//! evicts the old one. All access goes through an internal mutex.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use um_protocol::ServerMessage;

pub struct Subscribers {
    inner: Mutex<HashMap<[u8; 32], mpsc::Sender<ServerMessage>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_returns_none_first() {
        let subs = Subscribers::new();
        let (tx, _rx) = mpsc::channel::<ServerMessage>(256);
        assert!(subs.register([0x11; 32], tx).is_none());
    }

    #[test]
    fn register_evicts_old_returns_tx() {
        let subs = Subscribers::new();
        let (tx1, rx1) = mpsc::channel::<ServerMessage>(256);
        let (tx2, _rx2) = mpsc::channel::<ServerMessage>(256);
        assert!(subs.register([0x11; 32], tx1).is_none());
        let evicted = subs.register([0x11; 32], tx2);
        assert!(evicted.is_some());
        // The evicted sender must be the one we registered first.
        assert!(evicted.unwrap().same_channel(&tx1));
        // rx1 is still owned here; dropping it later closes the old channel.
        drop(rx1);
    }

    #[test]
    fn unregister_if_match_removes_only_matching() {
        let subs = Subscribers::new();
        let (tx1, _rx1) = mpsc::channel::<ServerMessage>(256);
        let (tx2, _rx2) = mpsc::channel::<ServerMessage>(256);
        subs.register([0x11; 32], tx1);
        // A second connection for the same identity evicts tx1.
        subs.register([0x11; 32], tx2);
        // The first connection cleans up with its own (now-evicted) tx1.
        subs.unregister_if_match(&[0x11; 32], &tx1);
        // The registry still holds tx2 (the current subscriber).
        assert!(subs.get(&[0x11; 32]).map_or(false, |s| s.same_channel(&tx2)));
    }

    #[test]
    fn get_returns_cloned_sender() {
        let subs = Subscribers::new();
        let (tx, _rx) = mpsc::channel::<ServerMessage>(256);
        subs.register([0x22; 32], tx);
        let got = subs.get(&[0x22; 32]);
        assert!(got.is_some());
        // The clone shares the channel with the registered sender.
        assert!(got.unwrap().same_channel(&subs.get(&[0x22; 32]).unwrap()));
    }

    #[test]
    fn get_missing_returns_none() {
        let subs = Subscribers::new();
        assert!(subs.get(&[0xFF; 32]).is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p um_server subscribers`
Expected: FAIL — `Subscribers::new` and the methods are not defined (compile error: `no function or associated item named new`).

- [ ] **Step 3: Add the module to lib.rs**

Modify `crates/server/src/lib.rs`:

```rust
//! um_server — the UM relay. A dumb encrypted mailbox + key directory.
//! Stores prekey bundles and forwards ciphertext; never holds private keys,
//! never decrypts. In-memory only (lost on restart).

#![forbid(unsafe_code)]

pub mod handler;
pub mod listener;
pub mod store;
pub mod subscribers;

pub use store::Store;
pub use subscribers::Subscribers;
```

- [ ] **Step 4: Write the implementation**

Append to `crates/server/src/subscribers.rs` (above the `#[cfg(test)]` block):

```rust
impl Subscribers {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register `tx` as the push sender for `id`. If an entry already exists,
    /// evict it and return the old `Sender` so the caller can drop it (which
    /// closes the old channel and surfaces as `None` on the old connection's
    /// `recv`). Last-Subscribe-wins.
    pub fn register(
        &self,
        id: [u8; 32],
        tx: mpsc::Sender<ServerMessage>,
    ) -> Option<mpsc::Sender<ServerMessage>> {
        let mut g = self.inner.lock().expect("subscribers mutex poisoned");
        g.insert(id, tx)
    }

    /// Remove the entry for `id` only if its channel matches `tx`
    /// (`Sender::same_channel`). This prevents a disconnect-cleanup from
    /// removing a newer subscriber that evicted this connection.
    pub fn unregister_if_match(&self, id: &[u8; 32], tx: &mpsc::Sender<ServerMessage>) {
        let mut g = self.inner.lock().expect("subscribers mutex poisoned");
        if let Some(existing) = g.get(id) {
            if existing.same_channel(tx) {
                g.remove(id);
            }
        }
    }

    /// Clone the push sender for `id`, if present.
    pub fn get(&self, id: &[u8; 32]) -> Option<mpsc::Sender<ServerMessage>> {
        self.inner
            .lock()
            .expect("subscribers mutex poisoned")
            .get(id)
            .cloned()
    }
}

impl Default for Subscribers {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p um_server subscribers`
Expected: PASS — 5 tests.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/subscribers.rs crates/server/src/lib.rs
git commit -m "feat(server): add Subscribers push registry

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `store.deliver` returns `(recipient, id, env)` triples

**Files:**
- Modify: `crates/server/src/store.rs:69-87` (the `deliver` method)
- Modify: `crates/server/src/store.rs` tests `deliver_to_registered_assigns_monotonic_ids`, `deliver_skips_unregistered_recipient`, `deliver_to_group_fans_out_to_each_registered_member`
- Modify: `crates/server/src/handler.rs:38-48` (the `Send` arm — adapt to new return shape, push comes in Task 4)

**Interfaces:**
- Consumes: `um_protocol::EncryptedEnvelope` (unchanged).
- Produces: `pub fn Store::deliver(&self, recipients: &[[u8;32]], envelope: EncryptedEnvelope) -> Vec<([u8;32], u64, EncryptedEnvelope)>` — only registered recipients appear (id > 0).

- [ ] **Step 1: Update the `deliver_*` tests to the new return shape**

In `crates/server/src/store.rs`, find the test `deliver_to_registered_assigns_monotonic_ids` and replace its id assertions. Change:

```rust
        // Alice sends two messages to bob.
        let ids1 = store.deliver(&[bob], envelope(0));
        let ids2 = store.deliver(&[bob], envelope(0));
        assert_eq!(ids1, vec![1]);
        assert_eq!(ids2, vec![2]);
```

to:

```rust
        // Alice sends two messages to bob.
        let d1 = store.deliver(&[bob], envelope(0));
        let d2 = store.deliver(&[bob], envelope(0));
        let ids1: Vec<u64> = d1.iter().map(|(_, id, _)| *id).collect();
        let ids2: Vec<u64> = d2.iter().map(|(_, id, _)| *id).collect();
        assert_eq!(ids1, vec![1]);
        assert_eq!(ids2, vec![2]);
```

Find the test `deliver_skips_unregistered_recipient` and change:

```rust
        // bob is NOT registered.
        let ids = store.deliver(&[bob], envelope(0));
        assert_eq!(ids, vec![0]);
        assert!(store.poll(&bob, 0).is_empty());
```

to:

```rust
        // bob is NOT registered.
        let delivered = store.deliver(&[bob], envelope(0));
        // Unregistered recipients are absent from the return (not id=0 entries).
        assert!(delivered.is_empty());
        assert!(store.poll(&bob, 0).is_empty());
```

Find the test `deliver_to_group_fans_out_to_each_registered_member` and change:

```rust
        let ids = store.deliver(&[m1, m2, m3], envelope(0));
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], 1);
        assert_eq!(ids[1], 2);
        assert_eq!(ids[2], 0); // m3 skipped
        assert_eq!(store.poll(&m1, 0).len(), 1);
        assert_eq!(store.poll(&m2, 0).len(), 1);
        assert_eq!(store.poll(&m3, 0).len(), 0);
```

to:

```rust
        let delivered = store.deliver(&[m1, m2, m3], envelope(0));
        // Only registered recipients (m1, m2) appear; m3 is absent.
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].0, m1);
        assert_eq!(delivered[0].1, 1);
        assert_eq!(delivered[1].0, m2);
        assert_eq!(delivered[1].1, 2);
        assert_eq!(store.poll(&m1, 0).len(), 1);
        assert_eq!(store.poll(&m2, 0).len(), 1);
        assert_eq!(store.poll(&m3, 0).len(), 0);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p um_server store::tests`
Expected: FAIL — compile error: `deliver` still returns `Vec<u64>`, the test code expects tuples.

- [ ] **Step 3: Update the `deliver` implementation**

In `crates/server/src/store.rs`, replace the `deliver` method (currently lines 69-87):

```rust
    /// Append `envelope` to every recipient's outbox, assigning each copy a
    /// fresh monotonic id. Returns the ids in recipient order. Recipients
    /// that are not registered are skipped (the caller decides whether to
    /// surface `UnknownRecipient`).
    pub fn deliver(&self, recipients: &[[u8; 32]], mut envelope: EncryptedEnvelope) -> Vec<u64> {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        let mut ids = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            if !g.registered.contains(recipient) {
                ids.push(0);
                continue;
            }
            envelope.id = g.next_envelope_id;
            g.next_envelope_id += 1;
            let id = envelope.id;
            g.outboxes
                .entry(*recipient)
                .or_default()
                .push(envelope.clone());
            ids.push(id);
        }
        ids
    }
```

with:

```rust
    /// Append `envelope` to every registered recipient's outbox, assigning
    /// each copy a fresh monotonic id. Returns `(recipient, id, envelope)`
    /// triples for the recipients that were actually delivered to, in
    /// recipient order. Unregistered recipients are skipped (absent from the
    /// return; the caller decides whether to surface `UnknownRecipient`).
    pub fn deliver(
        &self,
        recipients: &[[u8; 32]],
        mut envelope: EncryptedEnvelope,
    ) -> Vec<([u8; 32], u64, EncryptedEnvelope)> {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        let mut out = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            if !g.registered.contains(recipient) {
                continue;
            }
            envelope.id = g.next_envelope_id;
            g.next_envelope_id += 1;
            let id = envelope.id;
            g.outboxes
                .entry(*recipient)
                .or_default()
                .push(envelope.clone());
            out.push((*recipient, id, envelope.clone()));
        }
        out
    }
```

- [ ] **Step 4: Update the `Send` arm in `handler.rs` to compile (push comes in Task 4)**

In `crates/server/src/handler.rs`, the `Send` arm currently uses the old return. Replace:

```rust
        ClientMessage::Send {
            recipients,
            envelope,
        } => {
            // Reject if any recipient is not registered.
            if !recipients.iter().all(|r| store.is_registered(r)) {
                return ServerMessage::Error(um_protocol::ServerError::UnknownRecipient);
            }
            store.deliver(&recipients, envelope);
            ServerMessage::AckOk
        }
```

with (push wiring added in Task 4; for now just adapt to the new return shape):

```rust
        ClientMessage::Send {
            recipients,
            envelope,
        } => {
            // Reject if any recipient is not registered.
            if !recipients.iter().all(|r| store.is_registered(r)) {
                return ServerMessage::Error(um_protocol::ServerError::UnknownRecipient);
            }
            let _delivered = store.deliver(&recipients, envelope);
            ServerMessage::AckOk
        }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p um_server`
Expected: PASS — all server tests (store + handler + subscribers). The handler `Send` tests still pass because `deliver` still appends to outboxes.

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/store.rs crates/server/src/handler.rs
git commit -m "refactor(server): deliver returns (recipient, id, env) triples

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `handle()` gains `&Subscribers` signature

**Files:**
- Modify: `crates/server/src/handler.rs:28` (signature) and all 11 `handle()` call sites in the test module
- Modify: `crates/server/src/listener.rs:84` (the one `handle()` call in `handle_conn`)

**Interfaces:**
- Consumes: `crate::Subscribers` (from Task 1).
- Produces: `pub fn handle(store: &Store, subs: &Subscribers, self_id: &[u8;32], msg: ClientMessage) -> ServerMessage` — the `subs` parameter is unused by non-`Send` arms in this task; Task 4 wires the push. `Subscribe` arm stays `AckOk`.

- [ ] **Step 1: Update the `handle` signature and the `Subscribe` arm doc**

In `crates/server/src/handler.rs`, replace:

```rust
/// Process one client message against the shared store, on behalf of the
/// authenticated identity `self_id`. Returns the server reply.
pub fn handle(store: &Store, self_id: &[u8; 32], msg: ClientMessage) -> ServerMessage {
    match msg {
```

with:

```rust
/// Process one client message against the shared store and subscriber
/// registry, on behalf of the authenticated identity `self_id`. Returns the
/// server reply. `subs` is used by the `Send` arm to push `Delivered` to
/// live subscribers; the `Subscribe` arm returns `AckOk` here (the real
/// subscription work — channel creation, outbox flush — is done in the
/// listener's `handle_conn`, which has the connection's write half).
pub fn handle(
    store: &Store,
    subs: &Subscribers,
    self_id: &[u8; 32],
    msg: ClientMessage,
) -> ServerMessage {
    match msg {
```

Add the import at the top of `handler.rs` (after `use crate::Store;`):

```rust
use crate::Subscribers;
```

- [ ] **Step 2: Update the `handle_conn` call site in `listener.rs`**

In `crates/server/src/listener.rs`, the `handle_conn` function does not yet receive `subs` (that is Task 5). To keep this task compiling, we pass a throwaway `Subscribers` here temporarily — NO, that would be wrong (it would not be the real registry). Instead, this task must be done together with giving `handle_conn` access to `subs`. Since Task 5 rewrites `handle_conn` fully, we instead make `handle_conn` accept `subs` now and thread it through `serve` now, leaving the Subscribe/push logic for Task 4 and Task 5.

Update `listener.rs` `serve` and `handle_conn` signatures and the `handle` call. Replace the `serve` function:

```rust
pub async fn serve(addr: &str, store: Arc<Store>) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let store = store.clone();
            tokio::spawn(handle_conn(stream, store));
        }
    });
    Ok(local)
}
```

with:

```rust
pub async fn serve(
    addr: &str,
    store: Arc<Store>,
    subs: Arc<Subscribers>,
) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let store = store.clone();
            let subs = subs.clone();
            tokio::spawn(handle_conn(stream, store, subs));
        }
    });
    Ok(local)
}
```

Add the import in `listener.rs` (after `use crate::Store;`):

```rust
use crate::Subscribers;
```

Update the `handle_conn` signature and the `handle` call. Replace:

```rust
async fn handle_conn(stream: TcpStream, store: Arc<Store>) {
```

with:

```rust
async fn handle_conn(stream: TcpStream, store: Arc<Store>, subs: Arc<Subscribers>) {
```

Replace the `handle` call (currently `let reply = handle(&store, &id, msg);`):

```rust
            let reply = handle(&store, &subs, &id, msg);
```

- [ ] **Step 3: Update `main.rs` to construct and pass `Subscribers`**

In `crates/server/src/main.rs`, replace:

```rust
use std::sync::Arc;
use um_server::{listener::serve, Store};
```

with:

```rust
use std::sync::Arc;
use um_server::{listener::serve, Store, Subscribers};
```

Replace:

```rust
    let store = Arc::new(Store::new());
    let bound = serve(&addr, store).await?;
```

with:

```rust
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    let bound = serve(&addr, store, subs).await?;
```

- [ ] **Step 4: Update all 11 `handle()` call sites in `handler.rs` tests**

Every `handle(&store, &id, ...)` and `handle(&store, &[..; 32], ...)` call in `crates/server/src/handler.rs` `#[cfg(test)] mod tests` needs a `&Subscribers::new()` argument inserted as the second parameter. The test module currently has no `Subscribers` in scope. Add at the top of the test module (after `use super::*;`):

```rust
    use crate::Subscribers;
```

Then update each call. The calls and their replacements (search for `handle(` in the test module):

- `register_with_valid_signature_stores_bundle`: `handle(&store, &id, ClientMessage::Register { bundle: bundle.clone() })` → `handle(&store, &Subscribers::new(), &id, ClientMessage::Register { bundle: bundle.clone() })`
- `register_with_bad_signature_rejected_and_not_stored`: `handle(&store, &id, ClientMessage::Register { bundle })` → `handle(&store, &Subscribers::new(), &id, ClientMessage::Register { bundle })`
- `fetch_bundle_returns_some_for_registered`: `handle(&store, &id, ClientMessage::Register { bundle })` → `handle(&store, &Subscribers::new(), &id, ClientMessage::Register { bundle })`; and `handle(&store, &id, ClientMessage::FetchBundle { target: id })` → `handle(&store, &Subscribers::new(), &id, ClientMessage::FetchBundle { target: id })`
- `fetch_bundle_returns_none_for_unregistered`: `handle(&store, &id, ClientMessage::FetchBundle { target: [0xFF; 32] })` → `handle(&store, &Subscribers::new(), &id, ClientMessage::FetchBundle { target: [0xFF; 32] })`
- `send_to_registered_recipient_delivers`: both `handle(&store, &alice, ClientMessage::Register { bundle: bundle_a })` and `handle(&store, &bob, ClientMessage::Register { bundle: bundle_b })` → insert `&Subscribers::new()`; and `handle(&store, &alice, ClientMessage::Send { recipients: vec![bob], envelope: envelope(0) })` → `handle(&store, &Subscribers::new(), &alice, ClientMessage::Send { recipients: vec![bob], envelope: envelope(0) })`
- `send_to_unregistered_recipient_rejected`: `handle(&store, &alice, ClientMessage::Register { bundle: bundle_a })` → insert `&Subscribers::new()`; and the `Send` call → insert `&Subscribers::new()`
- `poll_before_register_returns_not_registered`: `handle(&store, &[0x77; 32], ClientMessage::Poll { since: 0 })` → `handle(&store, &Subscribers::new(), &[0x77; 32], ClientMessage::Poll { since: 0 })`
- `poll_after_register_returns_delivered_envelopes`: both `Register` calls and the `Send` call → insert `&Subscribers::new()`; and `handle(&store, &bob, ClientMessage::Poll { since: 0 })` → `handle(&store, &Subscribers::new(), &bob, ClientMessage::Poll { since: 0 })`
- `ack_drops_envelopes`: both `Register` calls, the `Send` call, and the `Ack` call → insert `&Subscribers::new()`
- `subscribe_returns_ackok`: `handle(&store, &id, ClientMessage::Subscribe)` → `handle(&store, &Subscribers::new(), &id, ClientMessage::Subscribe)`

- [ ] **Step 5: Update the client `net.rs` tests (2) and `e2e.rs` (2) and `integration.rs` (5)**

These call `serve(addr, store)` and need the `subs` argument.

In `crates/client/src/net.rs` test module, both `client_registers_and_fetches_bundle` and `two_clients_exchange_envelopes` call `let addr = serve("127.0.0.1:0", store).await.expect("serve");`. Change both to:

```rust
        let addr = serve("127.0.0.1:0", store, std::sync::Arc::new(um_server::Subscribers::new()))
            .await
            .expect("serve");
```

In `crates/client/tests/e2e.rs`, find the `serve(...)` call(s) (the test spawns the relay). Change each `serve("127.0.0.1:0", store)` (or equivalent) to add the third argument:

```rust
serve(
    "127.0.0.1:0",
    store,
    std::sync::Arc::new(um_server::Subscribers::new()),
)
```

In `crates/server/tests/integration.rs`, find the `serve(...)` call(s) and add the third argument `std::sync::Arc::new(um_server::Subscribers::new())` (or `use um_server::Subscribers;` + `Arc::new(Subscribers::new())` if `Arc` is already imported — check the file's existing imports first and follow its style).

- [ ] **Step 6: Run the full test suite to verify it passes**

Run: `cargo test`
Expected: PASS — all 105 tests green (signatures updated everywhere, behavior unchanged).

- [ ] **Step 7: Commit**

```bash
git add crates/server/src/handler.rs crates/server/src/listener.rs crates/server/src/main.rs crates/client/src/net.rs crates/client/tests/e2e.rs crates/server/tests/integration.rs
git commit -m "refactor(server): thread Subscribers through handle and serve

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `handle()` `Send` arm pushes to live subscribers

**Files:**
- Modify: `crates/server/src/handler.rs:38-48` (the `Send` arm)
- Test: `crates/server/src/handler.rs` (new tests in the test module)

**Interfaces:**
- Consumes: `Subscribers::get` (Task 1), `store.deliver` new shape (Task 2), `mpsc::Sender::try_send`, `ServerMessage::Delivered`.
- Produces: the `Send` arm now pushes `Delivered(vec![env])` to each live subscriber via `try_send`; on `Full`/`Closed` it logs and skips (envelope stays in outbox).

- [ ] **Step 1: Write the failing tests**

Add these tests to the `#[cfg(test)] mod tests` block in `crates/server/src/handler.rs`:

```rust
    #[test]
    fn send_pushes_to_live_subscriber() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(&store, &subs, &alice, ClientMessage::Register { bundle: bundle_a });
        handle(&store, &subs, &bob, ClientMessage::Register { bundle: bundle_b });
        // Bob subscribes: register a push channel for bob.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ServerMessage>(256);
        subs.register(bob, tx);
        // Alice sends to bob.
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope(0),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // Bob's push channel received a Delivered frame.
        let pushed = rx.try_recv().expect("push delivered");
        match pushed {
            ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn send_to_offline_recipient_no_push_but_delivered() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(&store, &subs, &alice, ClientMessage::Register { bundle: bundle_a });
        handle(&store, &subs, &bob, ClientMessage::Register { bundle: bundle_b });
        // Bob is NOT subscribed (no push channel registered).
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope(0),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // No push channel exists for bob, so nothing to recv. The envelope is
        // still in bob's outbox.
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    #[test]
    fn send_push_full_channel_skips_keeps_outbox() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(&store, &subs, &alice, ClientMessage::Register { bundle: bundle_a });
        handle(&store, &subs, &bob, ClientMessage::Register { bundle: bundle_b });
        // Bob's push channel has capacity 1 and is already full.
        let (tx, _rx) = tokio::sync::mpsc::channel::<ServerMessage>(1);
        tx.try_send(ServerMessage::AckOk).expect("seed full");
        subs.register(bob, tx);
        // Alice sends to bob; try_send hits Full, push is skipped.
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope(0),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // The envelope is still in bob's outbox (recoverable on flush/poll).
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p um_server send_pushes_to_live_subscriber send_to_offline_recipient_no_push_but_delivered send_push_full_channel_skips_keeps_outbox`
Expected: FAIL — `send_pushes_to_live_subscriber` panics at `try_recv` ("push delivered") because the `Send` arm does not push yet. The other two may pass already (no push, env in outbox) — that is fine; the first test is the gate.

- [ ] **Step 3: Wire the push into the `Send` arm**

In `crates/server/src/handler.rs`, replace the `Send` arm:

```rust
        ClientMessage::Send {
            recipients,
            envelope,
        } => {
            // Reject if any recipient is not registered.
            if !recipients.iter().all(|r| store.is_registered(r)) {
                return ServerMessage::Error(um_protocol::ServerError::UnknownRecipient);
            }
            let _delivered = store.deliver(&recipients, envelope);
            ServerMessage::AckOk
        }
```

with:

```rust
        ClientMessage::Send {
            recipients,
            envelope,
        } => {
            // Reject if any recipient is not registered.
            if !recipients.iter().all(|r| store.is_registered(r)) {
                return ServerMessage::Error(um_protocol::ServerError::UnknownRecipient);
            }
            let delivered = store.deliver(&recipients, envelope);
            // Push to any live subscriber. try_send is non-blocking; on Full
            // (slow client) or Closed (subscriber gone) we skip the push — the
            // envelope remains in the outbox and is recovered on the next
            // Subscribe-flush or Poll.
            for (recipient, _id, env) in delivered {
                if let Some(tx) = subs.get(&recipient) {
                    match tx.try_send(ServerMessage::Delivered(vec![env])) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "push channel full for recipient, envelope stays in outbox"
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Subscriber vanished between get and send; ignore.
                        }
                    }
                }
            }
            ServerMessage::AckOk
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p um_server`
Expected: PASS — all server tests including the 3 new push tests.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/handler.rs
git commit -m "feat(server): push Delivered to live subscribers on Send

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `handle_conn` Subscribe intercept + `select!` push loop

**Files:**
- Modify: `crates/server/src/listener.rs` (the `handle_conn` function body)
- Test: `crates/server/tests/integration.rs` (new async tests) — or a new `crates/server/tests/push.rs` integration test file

**Interfaces:**
- Consumes: `Subscribers::register`/`unregister_if_match` (Task 1), `store.poll` (existing), `tokio::select!`, `mpsc::channel`, framing `encode`/`decode`.
- Produces: `handle_conn` now (a) intercepts `ClientMessage::Subscribe` before `handle`, creating a push channel, registering it, flushing the unacked outbox in batches of 64, and replying `AckOk`; (b) when subscribed, `select!`s between socket reads and push recv; (c) on disconnect, calls `unregister_if_match` with its own sender.

- [ ] **Step 1: Write the failing integration tests**

Create `crates/server/tests/push.rs` with the full, correct test set below. These tests assert push behavior that does not exist yet (the `handle_conn` Subscribe intercept and `select!` loop land in Step 3), so they fail red.

```rust
//! Integration tests for server Subscribe push over real TCP.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, EncryptedEnvelope, PreKeyBundle, ServerMessage};
use um_server::{listener::serve, Store, Subscribers};

/// A framed client over a raw TcpStream (test helper).
struct TestClient {
    stream: TcpStream,
    read_buf: Vec<u8>,
}

impl TestClient {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }

    async fn send(&mut self, msg: &ClientMessage) {
        let frame = encode(msg).expect("encode");
        self.stream.write_all(&frame).await.expect("write");
    }

    async fn recv(&mut self) -> ServerMessage {
        loop {
            if let Ok((msg, consumed)) = decode::<ServerMessage>(&self.read_buf) {
                self.read_buf.drain(0..consumed);
                return msg;
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await.expect("read");
            assert!(n > 0, "unexpected EOF waiting for server message");
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn real_bundle() -> ([u8; 32], PreKeyBundle) {
    let id = IdentityKey::generate();
    let spk = SignedPreKey::generate(1, &id);
    let otpk = OneTimePreKey::generate(10);
    let crypto_bundle = um_crypto::identity::PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
    let bundle = PreKeyBundle {
        identity_pub: id.verifying.to_bytes(),
        signed_prekey_id: crypto_bundle.signed_prekey_id,
        signed_prekey_pub: crypto_bundle.signed_prekey_pub.to_bytes(),
        signed_prekey_sig: crypto_bundle.signed_prekey_sig.to_bytes().to_vec(),
        one_time_prekeys: crypto_bundle
            .one_time_prekeys
            .iter()
            .map(|(k, v)| (*k, v.to_bytes()))
            .collect(),
    };
    (id.verifying.to_bytes(), bundle)
}

fn envelope() -> EncryptedEnvelope {
    EncryptedEnvelope {
        id: 0,
        sender: [0x55; 32],
        header: vec![1, 2, 3],
        init: None,
        ciphertext: vec![0xAA; 8],
    }
}

async fn spawn_server() -> std::net::SocketAddr {
    let store = Arc::new(Store::new());
    let subs = Arc::new(Subscribers::new());
    serve("127.0.0.1:0", store, subs).await.expect("serve")
}

#[tokio::test]
async fn subscribe_receives_push_for_new_message() {
    let addr = spawn_server().await;
    let (alice_pub, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle: alice_bundle }).await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle }).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    // Alice sends to bob.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob receives the push without polling.
    let pushed = bob.recv().await;
    match pushed {
        ServerMessage::Delivered(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].sender, alice_pub);
        }
        other => panic!("expected Delivered push, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_flushes_unacked_outbox() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle: alice_bundle }).await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob registers (connection stays open) but has NOT subscribed yet.
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle }).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    // Alice sends while bob is registered-but-not-subscribed. The envelope
    // lands in bob's outbox.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Now bob subscribes; the unacked outbox is flushed as Delivered.
    bob.send(&ClientMessage::Subscribe).await;
    // The listener flushes the outbox BEFORE writing the AckOk reply, so
    // Delivered arrives first, then AckOk. Accept either order defensively.
    let first = bob.recv().await;
    let second = bob.recv().await;
    let (delivered, ack) = match (first, second) {
        (ServerMessage::Delivered(_), ServerMessage::AckOk) => (first, second),
        (ServerMessage::AckOk, ServerMessage::Delivered(_)) => (second, first),
        other => panic!("expected Delivered + AckOk, got {other:?}"),
    };
    match delivered {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered, got {other:?}"),
    }
    assert!(matches!(ack, ServerMessage::AckOk));
}

#[tokio::test]
async fn reconnect_repushes_unacked() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle: alice_bundle }).await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob subscribes and receives a push, but does NOT ack.
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle.clone() }).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    let _first_push = bob.recv().await; // Delivered, not acked

    // Bob disconnects (drop) and reconnects with the SAME identity pub (the
    // same bundle, which carries the same identity_pub).
    drop(bob);
    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle }).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    // The unacked envelope is re-pushed on the flush, then AckOk.
    let first = bob.recv().await;
    let second = bob.recv().await;
    let delivered = match (first, second) {
        (ServerMessage::Delivered(_), _) => first,
        (_, ServerMessage::Delivered(_)) => second,
        other => panic!("expected a Delivered re-push, got {other:?}"),
    };
    match delivered {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered, got {other:?}"),
    }
}

#[tokio::test]
async fn last_subscribe_wins_evicts_old() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle: alice_bundle }).await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    // Bob conn1 subscribes.
    let mut bob1 = TestClient::connect(addr).await;
    bob1.send(&ClientMessage::Register { bundle: bob_bundle.clone() }).await;
    assert!(matches!(bob1.recv().await, ServerMessage::AckOk));
    bob1.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob1.recv().await, ServerMessage::AckOk));

    // Bob conn2 subscribes — evicts conn1.
    let mut bob2 = TestClient::connect(addr).await;
    bob2.send(&ClientMessage::Register { bundle: bob_bundle }).await;
    assert!(matches!(bob2.recv().await, ServerMessage::AckOk));
    bob2.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob2.recv().await, ServerMessage::AckOk));

    // conn1's push channel is closed by the eviction; its next recv hits EOF.
    // Give the server a moment to close conn1, then assert EOF.
    let mut buf = [0u8; 64];
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        bob1.stream.read(&mut buf),
    )
    .await;
    match res {
        Ok(Ok(0)) => {}            // EOF — expected
        Ok(Ok(_)) => panic!("conn1 should have been closed, got data"),
        Ok(Err(_)) => {}           // connection error — also acceptable
        Err(_) => panic!("conn1 read did not resolve (no eviction)"),
    }

    // conn2 still works: alice sends, conn2 gets the push.
    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    match bob2.recv().await {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered on conn2, got {other:?}"),
    }
}

#[tokio::test]
async fn poll_still_works_alongside_subscribe() {
    let addr = spawn_server().await;
    let (_, alice_bundle) = real_bundle();
    let (bob_pub, bob_bundle) = real_bundle();

    let mut alice = TestClient::connect(addr).await;
    alice.send(&ClientMessage::Register { bundle: alice_bundle }).await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));

    let mut bob = TestClient::connect(addr).await;
    bob.send(&ClientMessage::Register { bundle: bob_bundle }).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));
    bob.send(&ClientMessage::Subscribe).await;
    assert!(matches!(bob.recv().await, ServerMessage::AckOk));

    alice
        .send(&ClientMessage::Send {
            recipients: vec![bob_pub],
            envelope: envelope(),
        })
        .await;
    assert!(matches!(alice.recv().await, ServerMessage::AckOk));
    // Bob receives the push.
    assert!(matches!(bob.recv().await, ServerMessage::Delivered(_)));

    // Bob also polls — the envelope is still in the outbox (not acked).
    bob.send(&ClientMessage::Poll { since: 0 }).await;
    match bob.recv().await {
        ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Delivered from Poll, got {other:?}"),
    }
}
```

The file contains: helpers + `subscribe_receives_push_for_new_message` + `subscribe_flushes_unacked_outbox` + `reconnect_repushes_unacked` + `last_subscribe_wins_evicts_old` + `poll_still_works_alongside_subscribe` (5 tests).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p um_server --test push`
Expected: FAIL — `subscribe_receives_push_for_new_message` hangs or times out at `bob.recv().await` after the `AckOk` for Subscribe, because the `handle_conn` Subscribe intercept and `select!` push loop are not implemented yet (bob never receives `Delivered`). The other tests fail similarly or on the same blocking recv.

- [ ] **Step 3: Implement the `handle_conn` Subscribe intercept and `select!` loop**

Replace the entire `handle_conn` function in `crates/server/src/listener.rs` with:

```rust
/// Handle one connection to completion.
async fn handle_conn(stream: TcpStream, store: Arc<Store>, subs: Arc<Subscribers>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    // The connection is unauthenticated until the first `Register` arrives.
    let mut self_id: Option<[u8; 32]> = None;
    // Push channel: None until Subscribe. When Some, the loop select!s
    // between socket reads and push recv.
    let mut push_rx: Option<mpsc::Receiver<ServerMessage>> = None;
    // The connection's own sender clone, kept for match-based cleanup so an
    // evicted older connection does not remove a newer subscriber.
    let mut push_tx: Option<mpsc::Sender<ServerMessage>> = None;

    loop {
        // Read more bytes into the buffer, unless we are racing push recv.
        if push_rx.is_some() {
            // Subscribed mode: race a socket read against a push recv.
            let mut chunk = [0u8; 4096];
            tokio::select! {
                read = reader.read(&mut chunk) => {
                    match read {
                        Ok(0) => break, // EOF
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                msg = push_rx.as_mut().unwrap().recv() => {
                    match msg {
                        Some(server_msg) => {
                            let frame = match encode(&server_msg) {
                                Ok(f) => f,
                                Err(_) => break,
                            };
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                            // Continue the loop; do not also read this iteration.
                            continue;
                        }
                        None => break, // sender dropped (evicted) -> close
                    }
                }
            }
        } else {
            // Not-subscribed mode: just read.
            let mut chunk = [0u8; 4096];
            match reader.read(&mut chunk).await {
                Ok(0) => break, // EOF
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }

        // Decode as many full frames as are present.
        loop {
            let (msg, consumed): (ClientMessage, usize) = match decode(&buf) {
                Ok((msg, consumed)) => (msg, consumed),
                Err(um_protocol::ProtocolError::Incomplete) => break, // need more bytes
                Err(_) => {
                    // Malformed frame: close the connection.
                    return;
                }
            };
            buf.drain(0..consumed);

            // First frame must be Register; it binds the connection.
            let id = match (&msg, self_id) {
                (ClientMessage::Register { ref bundle }, _) => {
                    let id = bundle.identity_pub;
                    self_id = Some(id);
                    id
                }
                (_, Some(id)) => id,
                (_, None) => {
                    // Non-Register before auth: reject and close.
                    let err = ServerMessage::Error(um_protocol::ServerError::NotRegistered);
                    if let Ok(frame) = encode(&err) {
                        let _ = writer.write_all(&frame).await;
                    }
                    return;
                }
            };

            // Subscribe is handled here (not in `handle`): create the push
            // channel, register it (evicting any prior subscriber for this
            // identity), flush the unacked outbox in batches of 64, then
            // reply AckOk.
            if let ClientMessage::Subscribe = msg {
                let (tx, rx) = mpsc::channel(256);
                let _evicted = subs.register(id, tx.clone());
                push_tx = Some(tx);
                push_rx = Some(rx);
                // Flush unacked outbox (poll since 0) as Delivered frames.
                let pending = store.poll(&id, 0);
                for chunk in pending.chunks(64) {
                    let frame = match encode(&ServerMessage::Delivered(chunk.to_vec())) {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                // Reply AckOk (mode accepted).
                let ack = match encode(&ServerMessage::AckOk) {
                    Ok(f) => f,
                    Err(_) => return,
                };
                if writer.write_all(&ack).await.is_err() {
                    return;
                }
                continue;
            }

            let reply = handle(&store, &subs, &id, msg);
            match encode(&reply) {
                Ok(frame) => {
                    if writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    // Cleanup: remove our subscriber entry only if it is still ours.
    if let (Some(id), Some(tx)) = (self_id, push_tx.as_ref()) {
        subs.unregister_if_match(&id, tx);
    }
}
```

Add the import at the top of `listener.rs` (with the other `tokio` imports):

```rust
use tokio::sync::mpsc;
```

- [ ] **Step 4: Run the push integration tests to verify they pass**

Run: `cargo test -p um_server --test push`
Expected: PASS — all 5 push tests.

- [ ] **Step 5: Run the full test suite**

Run: `cargo test`
Expected: PASS — all tests green (105 prior + 5 subscribers + 3 handler push + 5 push integration = 118).

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/listener.rs crates/server/tests/push.rs
git commit -m "feat(server): Subscribe push with outbox flush and select loop

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Full pipeline verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full build pipeline**

Run: `./build.sh`
Expected: PASS — fmt check, clippy (warnings as errors), release build, all tests pass. If clippy flags the `push_rx.as_mut().unwrap()` in the `select!` arm, replace it with a pattern that does not unwrap: hoist the receiver into an `Option` and match it. Specifically, if clippy complains, change the `select!` branch to:

```rust
                msg = async {
                    match push_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
```

(But prefer the `unwrap` form first since `push_rx.is_some()` is checked immediately above; only change if clippy errors.)

- [ ] **Step 2: Run clippy specifically on the server crate**

Run: `cargo clippy -p um_server -- -D warnings`
Expected: PASS — no warnings.

- [ ] **Step 3: Verify the server binary still builds and runs**

Run: `cargo build -p um_server --release`
Expected: PASS — `target/release/um-server` built.

- [ ] **Step 4: Final commit if any fixes were needed in steps 1-3**

If the pipeline required changes (e.g. the clippy fix above), commit them:

```bash
git add -A
git commit -m "fix(server): clippy cleanups for push loop

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

If no fixes were needed, skip this step.
