# untitled_messenger

An end-to-end-encrypted (E2EE) messenger built in Rust. The server is a signed
mailbox + key directory: it validates prekey-bundle signatures, stores
ciphertext, and pushes deliveries to live subscribers, but it never holds
private keys, never decrypts, and never sees plaintext. Compromise of the
server yields ciphertext and metadata (who-talks-to-whom, timing), not
plaintext. Metadata protection (mixmaster, padding, sealed sender) is
acknowledged and **out of scope for v1**.

## Crypto primitives

- **X3DH** (`um_crypto::x3dh`) — session establishment. `RK = HKDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4, salt="UM-X3DH-v1")`.
- **Hybrid PQXDH** (`um_crypto::kem` + `x3dh`) — post-quantum hybrid on top of
  X3DH. Bob publishes an ML-KEM-768 (FIPS 203) encapsulation key alongside his
  X25519 signed prekey. Alice runs classical X3DH *and* encapsulates a fresh
  32-byte secret to Bob's PQ key; Bob decapsulates it. Both secrets feed the
  X3DH HKDF as additional IKM, so the root key is bound to **both** the
  classical DH outputs and the lattice secret. An attacker must break X25519
  (or Ed25519→X25519) **and** ML-KEM-768 to recover the session key — the
  hybrid property. The PQ layer is byte-sized behind `um_crypto::kem`, so the
  wire protocol stays crypto-free and the KEM can be swapped (e.g. ML-KEM-1024)
  without touching anything outside that module.
- **Double Ratchet** (`um_crypto::double_ratchet`) — per-message forward secrecy for 1:1 chats. A bad AEAD tag drops the message without poisoning the ratchet (skipped-key cache handles gaps).
- **Sender Keys** (`um_crypto::sender_keys`) — group messaging with per-sender chains. Group distribution state rides the hybrid 1:1 ratchet, so groups inherit PQ protection indirectly.
- **Identity keys** (`um_crypto::identity`) — Ed25519 signing + X25519 DH.
- **AEAD** (`um_crypto::aead`) — XChaCha20-Poly1305 + HKDF helpers.

## Workspace layout

```
crates/
  crypto/     um_crypto   — X3DH, Double Ratchet, Sender Keys, identity, AEAD. Pure, no async/IO.
  protocol/   um_protocol — wire types + length-prefixed framing (postcard). No crypto logic.
  server/     um_server   — TCP relay, in-memory store, signature verification, Subscribe push.
  client/     um_client   — headless core: ClientSession, async framed TCP, Argon2id+XChaCha SQLite store.
  gui/        um_gui      — iced desktop shell over um_client (lib + um-gui bin).
```

Dependency edges: `gui → client → {crypto, protocol}`, `server → {crypto, protocol}`. `crypto` and `protocol` depend on nothing in the workspace.

## Binaries

| Crate      | Binary     | Purpose                                                        |
|------------|------------|----------------------------------------------------------------|
| `um_server`| `um_server`| TCP relay. `UM_SERVER_ADDR=127.0.0.1:7000` (default).          |
| `um_client`| `um_client`| Headless REPL over real TCP. For smoke testing without a GUI. |
| `um_gui`   | `um-gui`   | Desktop GUI (iced).                                            |

## Build & test

```sh
# Full release pipeline: fmt check + clippy (-D warnings) + release build + tests.
./build.sh

# Or step by step:
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Artifacts land under `target/release`.

## Running

Start a relay:

```sh
cargo run --release -p um_server
# um_server listening on 127.0.0.1:7000
```

Headless smoke (two terminals):

```sh
cargo run --release -p um_client
# registered + subscribed. type /help for commands.
# /whoami                       # print this client's identity pub (hex)
# /add <hex> <nick>             # record a contact
# /contacts                     # list contacts
# /msg <hex> <text>             # send (starts an X3DH session on first send)
# /quit
```

GUI:

```sh
cargo run --release -p um_gui
```

First run shows the **Setup** view (choose a passphrase ≥ 8 chars — it encrypts
the local store; there is no recovery if lost). Subsequent runs show the
**Login** view. After unlock the GUI connects to the configured relay,
registers its prekey bundle, and subscribes for push.

## GUI features

- **Theming** — Dracula dark palette via a single `um_gui::theme` module (colors, bubble/panel/sidebar/button styles), so the views stay visually consistent and the look is decoupled from layout.
- **Two-column layout** — post-login routes (chat, group, settings) render a persistent contact-list sidebar (fixed 300px, panel-styled) on the left and the active panel on the right, so the full 900px window width is used instead of a single 520px column. The open chat is highlighted in the sidebar; a "select a chat" placeholder fills the right pane before any chat is opened.
- **Contact list** — add contacts by 32-byte identity pub (hex) + nickname, per-contact unread badges, fingerprint display, manual fingerprint verification (✓), connection status header.
- **1:1 chat** — full Double-Ratchet sessions, optimistic send with `…/✓/✗` status, per-message UTC timestamps, fingerprint-verify button, auto-scroll that snaps to the latest message on send/receive.
- **Groups** — Sender Keys group sessions; founder distributes sender-key state to each member over their 1:1 ratchet; group list with unread badges; member count in the group header; incoming rows are prefixed with the author's nickname (or short hex for unknown senders).
- **Settings** — identity pub + fingerprint, editable server address (disconnect + reconnect), signed-prekey rotation, one-time-prekey replenish with editable count, logout, quit.
- **Push** — live `Delivered` push via `Subscribe`; offline mail recovered on reconnect; unacked outbox flushed on re-subscribe; exponential-backoff reconnect.
- **Headless-safe startup** — a pre-flight display check exits cleanly with guidance when no Wayland/X11 session is reachable, instead of panicking inside winit.

## Local store

`um_client::Store` is an Argon2id-keyed, XChaCha20-Poly1305-sealed SQLite
database. The session (ratchet state + group state), contacts, group rosters,
and per-chat history are persisted encrypted across restarts. A wrong
passphrase still runs Argon2id (constant time) and then fails decryption — no
data is leaked.

## Testing posture

- **`um_crypto`** — proptest + integration tests over X3DH / Double Ratchet / Sender Keys.
- **`um_client`** — session tests over an in-memory transport, plus a full E2E smoke test over real TCP (1:1 + 3-member group, real ciphertext, asserts plaintext).
- **`um_server`** — handler tests, push tests, subscribers unit tests.
- **`um_gui`** — pure state-logic unit tests (no iced window) + headless E2E bridge tests over a real `um_server` (1:1 round trip + full group exchange).

Automated UI snapshot tests are intentionally skipped in v1.

## Out of scope (v1)

- Multi-device support (each device is a separate identity).
- Voice/video calls.
- Read receipts, typing indicators.
- Server-side metadata protection (mixmaster, padding, sealed sender).
- Server persistence (in-memory only; lost on restart).
- Federation between multiple servers.
- File and media attachments (specified but not yet implemented).
