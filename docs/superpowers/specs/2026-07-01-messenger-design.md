# Untitled Messenger — Design Spec

**Date:** 2026-07-01
**Status:** Draft (pending user review)
**Author:** kuroki

## Overview

A self-hosted, end-to-end encrypted (E2EE) messenger written in Rust with a native GUI. One-on-one text chat, group chat, and encrypted file/media attachments. The server is a dumb encrypted relay: it stores prekey bundles and forwards ciphertext, but never holds private keys and never decrypts. All cryptographic protocol logic is implemented from primitives (no `libsignal`).

## Decisions (locked)

| Area | Decision |
|------|----------|
| Network model | Client-server relay; server holds encrypted envelopes + prekeys, never sees plaintext |
| GUI toolkit | `iced` (native, declarative, cross-platform) |
| Crypto protocol | X3DH + Double Ratchet (1:1), Sender Keys (groups) — Signal-style |
| Transport | Raw TCP, length-prefixed framed binary (`postcard`) |
| First milestone | Core 1:1 text + groups + file/media attachments |
| Group crypto | Sender Keys (Signal-style) |
| Identity / discovery | Key-only: identity = Ed25519 public key, add contacts by pasted key / QR, no directory |
| Crypto implementation | From primitives (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`) |
| Server storage | In-memory only (lost on restart) |
| Client at-rest storage | Encrypted local store; key derived from user passphrase via Argon2id |

## Workspace layout

Cargo workspace, four crates. Dependency edges are one-way with no cycles.

```
untitled_messenger/
├── Cargo.toml                    # [workspace], members, shared deps
├── README.md
├── docs/superpowers/specs/
└── crates/
    ├── crypto/                   # Pure protocol logic, no I/O, no async
    │   └── src/
    │       ├── lib.rs
    │       ├── identity.rs       # Ed25519 id key, X25519 signed/one-time prekeys, fingerprint
    │       ├── x3dh.rs           # Session init: 4-DH derivation, root key
    │       ├── double_ratchet.rs # Per-message DH + symmetric ratchet, out-of-order handling
    │       ├── sender_keys.rs    # Group: per-sender chain, group key distribution
    │       ├── aead.rs           # XChaCha20-Poly1305 wrapper, HKDF chains
    │       └── error.rs
    ├── protocol/                 # Wire format + framing, no crypto logic, no async
    │   └── src/
    │       ├── lib.rs
    │       ├── messages.rs       # Envelope, PreKeyBundle, Plaintext, Group structs
    │       └── frame.rs          # Length-prefixed framing codec (sync)
    ├── server/                   # Relay binary
    │   └── src/
    │       ├── main.rs
    │       ├── listener.rs       # TCP accept loop, per-conn task
    │       ├── store.rs          # In-memory: prekey bundles, outbox, presence
    │       └── handler.rs        # Dispatch: register, fetch-bundle, send, poll, ack
    └── client/                   # iced GUI + session state + encrypted store + TCP client
        └── src/
            ├── main.rs
            ├── app.rs            # iced Application: state, Message enum, update(), view()
            ├── views/            # login, setup, contact_list, chat_thread, group, settings
            ├── net/              # TCP client, framed reader/writer, reconnect
            ├── session/          # Ratchet states (1:1 + group), send/receive
            ├── store/            # Encrypted SQLite: keys, ratchet state, messages, contacts
            └── crypto_bridge.rs  # Thin wrapper calling crates/crypto
```

### Dependency edges

- `crypto` ← depends on nothing but crypto crates (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`)
- `protocol` ← depends on `crypto` (uses its types for bundle/envelope fields) + `serde` + `postcard`
- `server` ← depends on `protocol` + `crypto` (validates bundle signatures, never decrypts) + `tokio`
- `client` ← depends on `protocol` + `crypto` + `iced` + `rusqlite` + `argon2` + `tokio`

### Key property

The `crypto` crate has zero `async`, zero `std::net`, zero `iced`. It is pure functions over byte arrays and key structs. This makes the entire X3DH + Double Ratchet + Sender Keys state machine testable in isolation with no network and no GUI.

The server validates prekey bundle signatures (Ed25519) on registration but never holds private keys, never decrypts, and never sees plaintext. It is a signed mailbox + key directory. Compromise of the server yields ciphertext and metadata (who-talks-to-whom, timing), not plaintext. Metadata leakage is acknowledged and not solved in v1 (no mixmaster/padding).

## Crypto crate (the core)

### Primitives

All `*-dalek` + RustCrypto, no FFI, no C:

- `ed25519-dalek` — identity signing keys
- `x25519-dalek` — ECDH for X3DH + DH ratchet
- `chacha20poly1305` — XChaCha20-Poly1305, 24-byte nonce, AEAD for messages + local store
- `hkdf` + `sha2` (SHA-256) — KDF chains
- `argon2` — passphrase → local-store key (used in client, not in crypto crate)

### Identity and keys (`identity.rs`)

- `IdentityKey { ed25519_pub, ed25519_priv }` — long-term identity, signed by user. Fingerprint = `SHA-256(ed25519_pub)` shown as hex groups and encodable as QR.
- `SignedPreKey { x25519_pub, x25519_priv, signature }` — medium-term, rotated, signed by identity key.
- `OneTimePreKey { id, x25519_pub, x25519_priv }` — single-use, consumed on X3DH.
- `PreKeyBundle` — the public half a client uploads to the server: identity pub + signed prekey + signature + N one-time prekey pubs. Server stores this and hands it to anyone who asks.
- `fingerprint(key) -> [u8; 32]` → formatted for manual or QR verification.

### X3DH (`x3dh.rs`) — session establishment

Alice wants to talk to Bob and fetches Bob's `PreKeyBundle` from the server.

1. Alice generates an ephemeral X25519 keypair `(E_pub, E_priv)`.
2. Derive the root key `RK` from four ECDH shared secrets, concatenated and HKDF'd:
   - `DH1 = DH(Alice identity priv, Bob signed prekey pub)`
   - `DH2 = DH(Alice ephemeral priv, Bob identity pub)`
   - `DH3 = DH(Alice ephemeral priv, Bob signed prekey pub)`
   - `DH4 = DH(Alice ephemeral priv, Bob one-time prekey pub)` — if available
   - `RK = HKDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4, salt="UM-X3DH-v1")`
3. Alice's initial message carries: Alice identity pub, Alice ephemeral pub, id of Bob's one-time prekey used. Bob reconstructs the same four DHs with his private keys and derives the same `RK`.
4. Output: `SessionInit { root_key, alice_identity, alice_ephemeral, bob_signed_prekey_id, bob_one_time_prekey_id }` → seeds the Double Ratchet.

### Double Ratchet (`double_ratchet.rs`) — per-message

Root chain (DH ratchet) + send/recv chain (symmetric ratchet).

- State: `root_key`, `dh_priv`/`dh_pub` (current DH keypair), `ns`/`nr` (send/recv counts), `pn` (previous chain count), `CKs`/`CKr` (chain keys).
- **DH ratchet step** (on receiving a message with a new DH pub): generate a new DH keypair, derive a new root key + chain key via HKDF from `DH(new_priv, their_pub)`.
- **Symmetric ratchet** (each message in a chain): `msg_key = HMAC(CKs, 0x01)`, `CKs = HMAC(CKs, 0x02)` — advances the chain key and yields a fresh AEAD key per message, giving forward secrecy.
- **Out-of-order:** keep skipped message keys in a bounded `HashMap<(dh_pub, nr), msg_key>` capped at 2000 entries (drop oldest on overflow) so late or reordered messages decrypt.
- Header on every message: `(dh_pub, pn, n)` — lets the receiver locate the right chain.
- AEAD: `XChaCha20-Poly1305(key=msg_key, nonce=random24, aad=header_bytes, plaintext)`.
- Associated data = serialized header, binding ciphertext to sender DH key + counters (tamper-evident).

### Sender Keys (`sender_keys.rs`) — groups

- Each member, per group, holds a `SenderChainKey` (symmetric ratchet) plus a signing keypair for sender authentication.
- On join, a member generates a `SenderKeyState` (chain key + signing pub) and distributes it to every other member **individually encrypted** via their 1:1 Double Ratchet session (the "sender key distribution" message).
- Sending to a group: advance the sender's own chain → `msg_key`, AEAD-encrypt, header = `(sender_id, generation, signing_pub)`, sign with the sender signing key.
- New member added: existing members send fresh sender keys to the new member via the new 1:1 session. Sender Keys give forward secrecy within a group and post-compromise security on member addition.
- The server has no knowledge of group membership. The outer envelope carries an explicit `recipients: Vec<identity_pub>` list; the server iterates it. The server never needs to understand group semantics.

### AEAD + HKDF helpers (`aead.rs`)

Thin wrappers so protocol code never calls raw cipher APIs directly: one `seal`/`open` function, one `kdf_chain` function. Centralizes nonce handling (random 24-byte nonce; never reused because a fresh key is derived per message).

### Error type (`error.rs`)

`CryptoError` enum: `InvalidSignature`, `DecryptionFailed`, `MissingPreKey`, `SkippedMessageLimit`, `MalformedBundle`. No panics in crypto code — all fallible paths return `Result`.

### Testing posture

Property tests via `proptest`: random keypairs, random message orderings (shuffle a sequence of sends, assert all still decrypt), fuzz the skipped-message cache. Unit tests for the X3DH four-DH derivation (hand-derived HKDF vectors). No network, no async anywhere in this crate.

## Protocol crate

Wire types serialized with `serde` + `postcard` (compact binary, `no_std`-friendly). Length-prefixed framing: `[u32 BE length][postcard payload]`. Sync encode/decode, no async.

### Client → Server messages

- `Register { identity_pub, signed_prekey_pub, signed_prekey_sig, one_time_prekeys: Vec<(id, pub)> }`
- `FetchBundle { target_identity_pub }` → server replies with the stored `PreKeyBundle`
- `Send { recipients: Vec<identity_pub>, envelope: EncryptedEnvelope }` — the server iterates `recipients` and appends the envelope to each outbox. The server is group-oblivious: for a 1:1 message `recipients` has one entry, for a group message it has every member's identity pub. The `group_id` is metadata inside the encrypted payload only (a client-side concept the server never sees).
- `Poll { since: u64 }` → server returns undelivered envelopes addressed to this client
- `Ack { envelope_ids }` → server drops the delivered envelopes
- `Subscribe` → server pushes new envelopes on this connection (long-lived poll)

### Server → Client messages

- `Bundle(PreKeyBundle)`
- `Delivered(Vec<EncryptedEnvelope>)`
- `AckOk`
- `Error(code)`

### EncryptedEnvelope

`{ id, sender_identity_pub, ciphertext, header }` — opaque to the server. The outer `Send` message carries the `recipients: Vec<identity_pub>` list; the server iterates it without understanding group semantics. A `group_id` exists only as a field inside the encrypted plaintext (a client-side concept), so the server never learns group membership or which sends are group sends. This keeps the server dumb.

## Server crate

Single binary `um-server`. Tokio runtime.

- `listener.rs`: `tokio::net::TcpListener`, spawn a task per connection. Each connection reads framed messages in a loop.
- `store.rs`: `Arc<Mutex<Stores>>` — `HashMap<identity_pub, PreKeyBundle>`, `HashMap<identity_pub, Vec<EncryptedEnvelope>>` (outbox per recipient), `HashSet<identity_pub>` (presence/registered). In-memory only; lost on restart (per the locked decision).
- `handler.rs`: dispatch.
  - `Register` verifies `signed_prekey_sig` against `identity_pub` (Ed25519) — rejects bad signatures.
  - `FetchBundle` returns the bundle minus the consumed one-time prekey (server marks it consumed).
  - `Send` appends the envelope to each recipient's outbox.
  - `Poll` / `Subscribe` drain the outbox.
  - `Ack` removes delivered envelopes.
- The server never holds private keys and never decrypts. It is a signed mailbox + key directory.

## Client crate

### Startup flow

1. Launch → iced `Login` view. No existing identity → `Setup` view: generate identity keypair + signed prekey + one-time prekeys, choose a passphrase. Derive the store key via `Argon2id(passphrase, salt)` → XChaCha key. Store keys + ratchet state as one XChaCha-encrypted blob; store message history in SQLite rows whose **content** columns are XChaCha-encrypted with the same key. (Pragmatic at-rest encryption without a SQLCipher FFI dependency.)
2. Existing identity → passphrase prompt → derive key → decrypt blob → load ratchet states + contacts + message history.
3. Connect to the server (host:port from config), `Register` / `Subscribe`.

### Views (`views/`)

`Login`, `Setup`, `ContactList` (contacts + fingerprints + "add contact" via paste-key/QR), `ChatThread` (1:1), `GroupChat`, `Settings` (rotate signed prekey, replenish one-time prekeys, change server, verify fingerprint side-by-side).

### `session/`

Owns `HashMap<PeerIdentity, RatchetSession>` (1:1) + `HashMap<GroupId, GroupSession>` (sender keys). `send_message(peer, plaintext)` → ratchet encrypt → `net::send`. `receive(envelope)` → locate session → ratchet decrypt → emit a `DecryptedMessage` event to iced. New-session detection (no existing ratchet, sender included an X3DH init header) → run the X3DH receive path → seed a new ratchet.

### `net/`

TCP client, framed reader/writer over `tokio` (the client is async on the network side; iced runs on its own runtime, bridged via channels). Reconnect with exponential backoff. A background task drains `Subscribe` pushes → channel → iced `update`.

### `store/`

Encrypted SQLite. Tables: `contacts(identity_pub, nickname, fingerprint)`, `messages(id, peer/group, direction, ciphertext, timestamp, status)`, `kv(key, blob)` for ratchet state + identity (blob = XChaCha-encrypted with the Argon2id-derived key). On every ratchet state change, re-encrypt + persist (write-through).

### `crypto_bridge.rs`

Thin — maps protocol wire types ↔ crypto crate types, no logic.

## File and media attachments

Attachments are encrypted as part of the message plaintext and routed through the same relay as text — the server is never a file server and never sees cleartext.

- A message plaintext is a tagged enum: `Plaintext::Text(String) | Plaintext::Attachment(AttachmentMeta)`.
- `AttachmentMeta { name, mime, len, chunks: Vec<EncryptedChunk> }` where `EncryptedChunk { seq, ciphertext }`.
- Each chunk is at most 64 KiB of plaintext, AEAD-encrypted with a per-attachment key derived via `HKDF(root_key, "UM-attach-v1" ‖ attachment_id)` and a per-chunk nonce `seq` (24-byte, big-endian). The per-attachment key is fresh per attachment; chunk nonces never repeat because `seq` is monotonic.
- The whole `Plaintext` (text or `AttachmentMeta`) is then Double-Ratchet-encrypted like any other message, so attachment metadata (name, mime, size) is also hidden from the server.
- The client UI renders an attachment as a placeholder until all chunks arrive, then writes the decrypted file to disk under a user-chosen directory. Partial attachments are buffered in the encrypted local store and resumed.
- For groups, the same `AttachmentMeta` is encrypted once under the Sender Keys group ratchet and fanned out to every member via the `recipients` list.
- Size guard: the server rejects any single framed payload over 1 MiB to bound memory; larger attachments are split across multiple `Send` frames by the client (each chunk is its own framed message), all carrying the same attachment id for reassembly.

## Data flow — send a 1:1 message

```
User types "hi" in ChatThread
  → iced update(Message::SendPressed)
  → session.send_message(peer, "hi")
  → crypto: double_ratchet.encrypt("hi") → (header, ciphertext)
  → protocol: EncryptedEnvelope{ recipient: Direct(bob), header, ciphertext }
  → net: frame + write to TCP
  → server: append to bob's outbox
  → (bob's client via Subscribe) → bob's net reads envelope
  → bob's session.receive → crypto: locate ratchet, decrypt → "hi"
  → bob's iced: append to ChatThread, persist (encrypted) to store
  → bob's client: Ack{ envelope_id } → server drops from outbox
```

First message to Bob (no session yet): Alice `FetchBundle(bob)` → server returns bundle → Alice runs X3DH → seeds ratchet → first encrypted message carries the X3DH init header (Alice identity pub + Alice ephemeral pub + Bob one-time prekey id) alongside the ratchet header. Bob recognizes the init header, runs X3DH receive, seeds the matching ratchet, decrypts.

## Error handling

- **Crypto:** all fallible paths return `CryptoError`, no panics. `DecryptionFailed` on a bad AEAD tag = message dropped + logged, session intact (a single bad message does not poison the ratchet; the skipped-key cache handles gaps).
- **Network:** reconnect with exponential backoff (1s → 30s cap). Send failures queue in client memory and retry on reconnect. Server down = UI shows a "disconnected" banner; local history remains browsable.
- **Server:** malformed frame → close the connection. Bad bundle signature on `Register` → `Error(InvalidSignature)`, reject. Unknown recipient on `Send` → `Error(UnknownRecipient)`, envelope dropped (sender UI shows "contact not registered").
- **Local store:** wrong passphrase = Argon2id still runs (constant time), decryption of the blob fails → `CryptoError::DecryptionFailed` → UI shows "wrong passphrase", no data leaked. Corrupt DB → refuse to start, prompt restore-from-backup (v1: error out, no auto-repair).
- **No silent drops:** every path that drops a message logs the reason and surfaces it to the UI as a status line.

## Testing

- **`crypto` crate (heavy):** unit tests for X3DH (Alice/Bob derive identical root key), Double Ratchet (round-trip, out-of-order via shuffled sends, skipped-message cache bounds), Sender Keys (3-member group, member add/remove). `proptest` for random orderings + fuzz AEAD tamper detection. Hand-derived HKDF vector test.
- **`protocol` crate:** frame round-trip, truncation handling, max-size guard.
- **`server` crate:** integration test — spin up the server on an ephemeral port, two mock clients register + exchange, assert envelope delivery + ack removal + bundle fetch + signature rejection.
- **`client` `session/`:** test ratchet sessions over a fake in-memory transport (no real TCP, no iced) — same crypto tests but through the session API. GUI views tested manually (iced snapshot testing is brittle; skip automated UI tests in v1).
- **E2E smoke test:** one binary spawns the server + two headless client sessions on localhost, exchanges messages, asserts plaintext received. Lives in a `tests/` integration crate.

## Out of scope (v1)

- Multi-device support (each device is a separate identity).
- Voice/video calls.
- Read receipts, typing indicators (can be added later as encrypted control messages).
- Server-side metadata protection (mixmaster, padding, sealed sender).
- Server persistence (in-memory only; lost on restart).
- Automated UI snapshot tests.
- Federation between multiple servers.
