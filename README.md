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
- **Double Ratchet** (`um_crypto::double_ratchet`) — per-message forward secrecy for 1:1 chats. A bad AEAD tag drops the message without poisoning the ratchet (skipped-key cache handles gaps).
- **Sender Keys** (`um_crypto::sender_keys`) — group messaging with per-sender chains.
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

- **Contact list** — add contacts by 32-byte identity pub (hex) + nickname, per-contact unread badges, fingerprint display, manual fingerprint verification (✓).
- **1:1 chat** — full Double-Ratchet sessions, optimistic send with `…/✓/✗` status, fingerprint-verify button.
- **Groups** — Sender Keys group sessions; founder distributes sender-key state to each member over their 1:1 ratchet; group list with unread badges; member count in the group header.
- **Settings** — identity pub + fingerprint, editable server address (disconnect + reconnect), signed-prekey rotation, one-time-prekey replenish with editable count, logout.
- **Push** — live `Delivered` push via `Subscribe`; offline mail recovered on reconnect; unacked outbox flushed on re-subscribe; exponential-backoff reconnect.

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
