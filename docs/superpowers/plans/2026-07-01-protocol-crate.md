# Protocol Crate Implementation Plan

> **STATUS: SUPERSEDED (2026-07-01).** Not followed. The actual `um_protocol`
> crate shipped with a simpler design: modules `error`/`message`/`framing`
> (not `messages`/`frame`), `ProtocolError { FrameTooLarge(usize), Incomplete,
> Encode, Decode }`, `EncryptedEnvelope { sender_key: [u8;32], ciphertext }`,
> `ClientMessage { Send, Fetch, RegisterPrekeys }`, `ServerMessage { Deliver,
> Ack, Error }`, `ServerError { RecipientNotFound, BadRequest, Internal }`,
> 16 MiB max frame, no `FrameDecoder`, raw `[u8;32]` identity keys instead of
> embedded crypto types. Do not execute the tasks below — kept for history.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `protocol` crate — a pure, sync Rust library defining the wire messages (client↔server) and the length-prefixed framing codec, with no async, no networking, and no panics.

**Architecture:** A single `um_protocol` crate inside the Cargo workspace, depending on `um_crypto` (reuses its `PreKeyBundle`, `double_ratchet::Header`, `x3dh::InitMessage`, and a re-exported `VerifyingKey`). Three modules: `error` (`ProtocolError`), `messages` (the `ClientMessage`/`ServerMessage` enums + `EncryptedEnvelope`), `frame` (stateless `encode`/`decode` + a streaming `FrameDecoder`, with a 1 MiB max-frame guard). All serialization via `serde` + `postcard`; framing is `[u32 BE length][postcard payload]`. Fully testable in isolation with no network.

**Tech Stack:** Rust 1.96, edition 2021. `serde` 1, `postcard` 1, `thiserror` 1. Reuses `um_crypto` (path dep). `ed25519-dalek` 2 / `x25519-dalek` 2 types come through `um_crypto` re-exports (no direct dalek dep in this crate).

## Global Constraints

- Rust edition 2021; toolchain 1.96+ (installed: `rustc 1.96.1`).
- The `protocol` crate MUST have zero `async`, zero `std::net`, zero `iced`, zero `tokio`. It is pure sync functions over byte buffers.
- No panics in any protocol code path — all fallible operations return `Result<_, ProtocolError>`. No `unwrap()`/`expect()`/`panic!()`/`unreachable!()` in non-test code. Indexing that could panic must be bounds-checked (use slice patterns or explicit length checks).
- No FFI, no C dependencies. Only Rust crates from crates.io.
- Wire format is exactly `[u32 big-endian length][postcard payload]`. The length prefix is the payload length in bytes, NOT including the 4-byte prefix itself.
- Max frame size is 1 MiB (`1024 * 1024` bytes) for the payload. `encode` rejects larger payloads with `ProtocolError::TooLarge`; `decode`/`FrameDecoder` reject a length prefix exceeding the cap with `ProtocolError::TooLarge`.
- Serialization is `serde` + `postcard` (compact binary). Every wire struct/enum derives `serde::Serialize, serde::Deserialize, Clone`.
- Wire types embed crypto types directly (`PreKeyBundle`, `Header`, `InitMessage`) — they are opaque bytes to the server and serialize via their own `serde` impls.
- `ed25519_dalek::Signature` does NOT implement `Debug` (verified in the installed `ed25519-2.2.3`), and `um_crypto::PreKeyBundle` / `double_ratchet::Header` / `x3dh::InitMessage` derive only `serde + Clone` (no `Debug`, no `PartialEq`). Therefore NO wire struct in this crate derives `Debug` or `PartialEq`. Tests assert correctness via postcard **byte round-trip equality** (`encode → decode → encode`, assert the two byte vectors are equal) and via `ServerError` (which is a pure enum and DOES derive `Debug + PartialEq + Eq`).
- The crate is named `um_protocol` (library name `um_protocol`). Internal modules are `error`, `messages`, `frame`.
- Every task ends with a green test run and a commit. Commit messages use Conventional Commits (`feat:`, `test:`, `chore:`, `refactor:`).
- The workspace root `Cargo.toml` is modified in Task 1 to add `crates/protocol` to `members`; it is reused by every later task.
- `crates/crypto/src/lib.rs` is modified in Task 1 to add `pub use ed25519_dalek::VerifyingKey;` so this crate can name the identity-public-key type without a direct `ed25519-dalek` dependency.

---

## File Structure

All files live under `crates/protocol/`. Created across tasks:

- `crates/protocol/Cargo.toml` — crate manifest (Task 1)
- `crates/protocol/src/lib.rs` — crate root, re-exports public API (Task 1, extended each task)
- `crates/protocol/src/error.rs` — `ProtocolError` enum (Task 1)
- `crates/protocol/src/messages.rs` — `EncryptedEnvelope`, `ClientMessage`, `ServerMessage`, `ServerError` (Task 2)
- `crates/protocol/src/frame.rs` — `encode`, `decode`, `FrameDecoder`, `MAX_FRAME` (Tasks 3 & 4)

Modified outside the crate:
- `Cargo.toml` (workspace root) — add `crates/protocol` to `members` (Task 1)
- `crates/crypto/src/lib.rs` — add `pub use ed25519_dalek::VerifyingKey;` (Task 1)

---

### Task 1: Scaffold + ProtocolError + crypto re-export

**Files:**
- Modify: `Cargo.toml` (workspace root) — add `crates/protocol` to members
- Modify: `crates/crypto/src/lib.rs` — re-export `VerifyingKey`
- Create: `crates/protocol/Cargo.toml`
- Create: `crates/protocol/src/lib.rs`
- Create: `crates/protocol/src/error.rs`
- Test: `cargo test -p um_protocol` and `cargo test -p um_crypto`

**Interfaces:**
- Consumes: `thiserror` (new dep), `um_crypto` (path dep, for the re-export only at this stage)
- Produces:
  - `pub enum ProtocolError { TooLarge, Encode, Decode }` — `Debug` + `Clone` + `Copy` + `PartialEq` + `Eq` + `std::error::Error` (via `thiserror::Error` derive; `Copy`/`Clone`/`PartialEq`/`Eq` added because the enum is fieldless). Display strings: `"frame too large"`, `"encode failed"`, `"decode failed"`.
  - `um_crypto::VerifyingKey` re-export (consumed by Task 2's `EncryptedEnvelope`).

- [ ] **Step 1: Add `crates/protocol` to the workspace**

Modify `Cargo.toml` at the repo root. Change the `members` line from:

```toml
members = ["crates/crypto"]
```

to:

```toml
members = ["crates/crypto", "crates/protocol"]
```

The full file should read:

```toml
[workspace]
resolver = "2"
members = ["crates/crypto", "crates/protocol"]

[workspace.package]
edition = "2021"
version = "0.1.0"
license = "MIT"
```

- [ ] **Step 2: Re-export `VerifyingKey` from the crypto crate**

Modify `crates/crypto/src/lib.rs` to add the re-export. The full file should read:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod double_ratchet;
pub mod error;
pub mod identity;
pub mod sender_keys;
pub mod x3dh;

pub use ed25519_dalek::VerifyingKey;
pub use error::CryptoError;
```

- [ ] **Step 3: Write the protocol crate manifest**

Create `crates/protocol/Cargo.toml`:

```toml
[package]
name = "um_protocol"
edition.workspace = true
version.workspace = true
license.workspace = true

[dependencies]
um_crypto = { path = "../crypto" }
serde = { version = "1", features = ["derive"] }
postcard = "1"
thiserror = "1"
```

- [ ] **Step 4: Write the crate root**

Create `crates/protocol/src/lib.rs`:

```rust
//! um_protocol — wire messages + length-prefixed framing for the UM relay.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;

pub use error::ProtocolError;
```

- [ ] **Step 5: Write the failing test + `ProtocolError`**

Create `crates/protocol/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("frame too large")]
    TooLarge,
    #[error("encode failed")]
    Encode,
    #[error("decode failed")]
    Decode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_compare_by_variant() {
        assert_eq!(ProtocolError::Decode, ProtocolError::Decode);
        assert_ne!(ProtocolError::Decode, ProtocolError::TooLarge);
    }

    #[test]
    fn errors_display() {
        assert_eq!(ProtocolError::TooLarge.to_string(), "frame too large");
        assert_eq!(ProtocolError::Encode.to_string(), "encode failed");
        assert_eq!(ProtocolError::Decode.to_string(), "decode failed");
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p um_protocol`
Expected: PASS — 2 tests pass (`errors_compare_by_variant`, `errors_display`).

Run: `cargo test -p um_crypto`
Expected: PASS — all 36 crypto unit tests still pass (the re-export is additive and breaks nothing).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/crypto/src/lib.rs crates/protocol/Cargo.toml crates/protocol/src/lib.rs crates/protocol/src/error.rs
git commit -m "feat: scaffold um_protocol crate with ProtocolError"
```

---

### Task 2: Wire messages

**Files:**
- Create: `crates/protocol/src/messages.rs`
- Modify: `crates/protocol/src/lib.rs`
- Test: `crates/protocol/src/messages.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `um_crypto::VerifyingKey` (re-exported in Task 1), `um_crypto::identity::PreKeyBundle`, `um_crypto::double_ratchet::Header`, `um_crypto::x3dh::InitMessage`, `serde`, `postcard` (dev/test only for round-trip).
- Produces:
  - `pub struct EncryptedEnvelope { pub id: u64, pub sender: VerifyingKey, pub header: Header, pub init: Option<InitMessage>, pub ciphertext: Vec<u8> }` — `serde` derive, `Clone`. `init` is `Some` only on the first message of a 1:1 session (so the receiver can run X3DH receive); `None` thereafter and for group-originated envelopes where the group distribution already happened.
  - `pub enum ClientMessage { Register { bundle: PreKeyBundle }, FetchBundle { target: VerifyingKey }, Send { recipients: Vec<VerifyingKey>, envelope: EncryptedEnvelope }, Poll { since: u64 }, Ack { envelope_ids: Vec<u64> }, Subscribe }` — `serde` derive, `Clone`. The server iterates `recipients` and appends the envelope to each outbox; for a 1:1 message `recipients` has one entry, for a group message every member's identity pub. The server is group-oblivious.
  - `pub enum ServerMessage { Bundle(Option<PreKeyBundle>), Delivered(Vec<EncryptedEnvelope>), AckOk, Error(ServerError) }` — `serde` derive, `Clone`. `Bundle(None)` means the target identity is not registered.
  - `pub enum ServerError { UnknownRecipient, InvalidSignature, MalformedFrame, TooLarge, NotRegistered }` — `serde` derive, `Clone`, `Copy`, `Debug`, `PartialEq`, `Eq` (fieldless pure enum — safe to derive all).

  **Serialization note:** `PreKeyBundle`, `Header`, and `InitMessage` all derive `serde::Serialize`/`Deserialize` (verified in the committed `um_crypto`). `VerifyingKey` serializes via its `serde` impl (enabled by the `serde` feature on `ed25519-dalek`, already on in `um_crypto`). None of these implement `Debug`/`PartialEq`, so the wire structs derive ONLY `serde + Clone` — tests use byte round-trip equality, not `assert_eq!` on the structs.

- [ ] **Step 1: Write the failing test + message types**

Create `crates/protocol/src/messages.rs`:

```rust
use um_crypto::double_ratchet::Header;
use um_crypto::identity::PreKeyBundle;
use um_crypto::x3dh::InitMessage;
use um_crypto::VerifyingKey;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct EncryptedEnvelope {
    pub id: u64,
    pub sender: VerifyingKey,
    pub header: Header,
    /// Present only on the first message of a 1:1 session, so the receiver
    /// can run the X3DH receive path and seed a matching ratchet. `None`
    /// thereafter and for group-originated envelopes.
    pub init: Option<InitMessage>,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ClientMessage {
    Register { bundle: PreKeyBundle },
    FetchBundle { target: VerifyingKey },
    Send {
        recipients: Vec<VerifyingKey>,
        envelope: EncryptedEnvelope,
    },
    Poll { since: u64 },
    Ack { envelope_ids: Vec<u64> },
    Subscribe,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerError {
    UnknownRecipient,
    InvalidSignature,
    MalformedFrame,
    TooLarge,
    NotRegistered,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum ServerMessage {
    Bundle(Option<PreKeyBundle>),
    Delivered(Vec<EncryptedEnvelope>),
    AckOk,
    Error(ServerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};

    /// Build a real PreKeyBundle so the postcard round-trip exercises the
    /// actual crypto types (VerifyingKey, PublicKey, Signature).
    fn sample_bundle() -> PreKeyBundle {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        PreKeyBundle::from_identity(&id, &spk, &[&otpk])
    }

    /// Byte round-trip equality: encode → decode → encode must yield the same
    /// bytes both times. This is the robust equality check for structs that
    /// do not implement Debug/PartialEq.
    fn roundtrip_bytes<T>(value: &T) -> Vec<u8>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let first = postcard::to_stdvec(value).expect("encode");
        let back: T = postcard::from_bytes(&first).expect("decode");
        postcard::to_stdvec(&back).expect("re-encode")
    }

    #[test]
    fn client_message_register_roundtrips() {
        let msg = ClientMessage::Register { bundle: sample_bundle() };
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ClientMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn client_message_fetch_bundle_roundtrips() {
        let bundle = sample_bundle();
        let msg = ClientMessage::FetchBundle { target: bundle.identity_pub };
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ClientMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn client_message_send_with_init_roundtrips() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let bundle = PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        let alice = IdentityKey::generate();
        let (init_session, init_msg) =
            um_crypto::x3dh::initiate(&alice, &bundle, Some(10)).expect("x3dh initiate");
        let ratchet = um_crypto::double_ratchet::RatchetSession::init_alice(&init_session)
            .expect("init_alice");
        let encrypted = ratchet.encrypt(b"hello").expect("encrypt");

        let envelope = EncryptedEnvelope {
            id: 42,
            sender: alice.verifying,
            header: encrypted.header,
            init: Some(init_msg),
            ciphertext: encrypted.ciphertext,
        };
        let msg = ClientMessage::Send {
            recipients: vec![bundle.identity_pub],
            envelope,
        };
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ClientMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn client_message_send_without_init_roundtrips() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let bundle = PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        let alice = IdentityKey::generate();
        let (init_session, _init_msg) =
            um_crypto::x3dh::initiate(&alice, &bundle, Some(10)).expect("x3dh initiate");
        let ratchet = um_crypto::double_ratchet::RatchetSession::init_alice(&init_session)
            .expect("init_alice");
        let encrypted = ratchet.encrypt(b"follow-up").expect("encrypt");

        let envelope = EncryptedEnvelope {
            id: 43,
            sender: alice.verifying,
            header: encrypted.header,
            init: None,
            ciphertext: encrypted.ciphertext,
        };
        let msg = ClientMessage::Send {
            recipients: vec![bundle.identity_pub],
            envelope,
        };
        assert_eq!(
            roundtrip_bytes(&msg),
            roundtrip_bytes(&postcard::from_bytes::<ClientMessage>(
                &postcard::to_stdvec(&msg).expect("encode")
            )
            .expect("decode"))
        );
    }

    #[test]
    fn client_message_poll_ack_subscribe_roundtrip() {
        let poll = ClientMessage::Poll { since: 99 };
        let ack = ClientMessage::Ack { envelope_ids: vec![1, 2, 3] };
        let sub = ClientMessage::Subscribe;
        for msg in [poll, ack, sub] {
            let bytes = postcard::to_stdvec(&msg).expect("encode");
            let back: ClientMessage = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
        }
    }

    #[test]
    fn server_message_bundle_some_roundtrips() {
        let msg = ServerMessage::Bundle(Some(sample_bundle()));
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ServerMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn server_message_bundle_none_roundtrips() {
        let msg = ServerMessage::Bundle(None);
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ServerMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn server_message_delivered_roundtrips() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let bundle = PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        let alice = IdentityKey::generate();
        let (init_session, _) =
            um_crypto::x3dh::initiate(&alice, &bundle, Some(10)).expect("x3dh initiate");
        let ratchet = um_crypto::double_ratchet::RatchetSession::init_alice(&init_session)
            .expect("init_alice");
        let encrypted = ratchet.encrypt(b"hi").expect("encrypt");
        let envelope = EncryptedEnvelope {
            id: 7,
            sender: alice.verifying,
            header: encrypted.header,
            init: None,
            ciphertext: encrypted.ciphertext,
        };
        let msg = ServerMessage::Delivered(vec![envelope]);
        let bytes = postcard::to_stdvec(&msg).expect("encode");
        let back: ServerMessage = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
    }

    #[test]
    fn server_message_ackok_and_error_roundtrip() {
        let ok = ServerMessage::AckOk;
        let err = ServerMessage::Error(ServerError::UnknownRecipient);
        for msg in [ok, err] {
            let bytes = postcard::to_stdvec(&msg).expect("encode");
            let back: ServerMessage = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(roundtrip_bytes(&msg), roundtrip_bytes(&back));
        }
    }

    #[test]
    fn server_error_variants_distinct() {
        assert_ne!(ServerError::UnknownRecipient, ServerError::InvalidSignature);
        assert_ne!(ServerError::MalformedFrame, ServerError::TooLarge);
        assert_ne!(ServerError::TooLarge, ServerError::NotRegistered);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_protocol messages`
Expected: FAIL — `messages` module not declared in `lib.rs` (unresolved import / file not compiled).

- [ ] **Step 3: Wire the module into the crate root**

Modify `crates/protocol/src/lib.rs` to:

```rust
//! um_protocol — wire messages + length-prefixed framing for the UM relay.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;
pub mod messages;

pub use error::ProtocolError;
pub use messages::{ClientMessage, EncryptedEnvelope, ServerError, ServerMessage};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p um_protocol messages`
Expected: PASS — 10 tests pass (register, fetch, send-with-init, send-without-init, poll/ack/subscribe, bundle-some, bundle-none, delivered, ackok/error, server-error-variants).

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/messages.rs crates/protocol/src/lib.rs
git commit -m "feat: add wire messages for client-server protocol"
```

---

### Task 3: Stateless framing (encode/decode + max-size guard)

**Files:**
- Create: `crates/protocol/src/frame.rs`
- Modify: `crates/protocol/src/lib.rs`
- Test: `crates/protocol/src/frame.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `crate::ProtocolError`, `serde`, `postcard`.
- Produces:
  - `pub const MAX_FRAME: usize = 1024 * 1024;` — 1 MiB payload cap.
  - `pub fn encode<T: serde::Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError>` — serializes `msg` with postcard, checks the payload is ≤ `MAX_FRAME`, prepends a 4-byte big-endian length prefix. Returns `Err(ProtocolError::TooLarge)` if the payload exceeds the cap; `Err(ProtocolError::Encode)` if postcard serialization fails.
  - `pub fn decode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, ProtocolError>` — reads the 4-byte BE length prefix; returns `Ok(None)` if `buf` has fewer than 4 bytes or the full `4 + len` bytes are not yet present (incomplete frame — caller should read more); returns `Err(ProtocolError::TooLarge)` if `len > MAX_FRAME`; returns `Err(ProtocolError::Decode)` if postcard deserialization of `buf[4..4+len]` fails; returns `Ok(Some((msg, 4 + len)))` on success, where the second element is the number of bytes consumed. No panics: all slice access is bounds-checked.

- [ ] **Step 1: Write the failing test + framing implementation**

Create `crates/protocol/src/frame.rs`:

```rust
use crate::ProtocolError;

/// Maximum payload size for a single frame: 1 MiB. The server rejects any
/// framed payload over this bound to cap per-connection memory; the protocol
/// crate enforces the same bound on both encode and decode.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Serialize `msg` with postcard and frame it: `[u32 BE length][payload]`.
/// Returns `TooLarge` if the payload exceeds `MAX_FRAME`, `Encode` if
/// postcard serialization fails.
pub fn encode<T: serde::Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_stdvec(msg).map_err(|_| ProtocolError::Encode)?;
    if payload.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge);
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode one frame from `buf`. Returns `Ok(None)` when the buffer does not
/// yet contain a complete frame (caller should read more bytes). Returns
/// `Ok(Some((msg, bytes_consumed)))` on success. Returns `TooLarge` if the
/// declared length exceeds `MAX_FRAME`, `Decode` if postcard deserialization
/// fails. No panics: all indexing is guarded by explicit length checks.
pub fn decode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, ProtocolError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::TooLarge);
    }
    let end = 4 + len;
    if buf.len() < end {
        return Ok(None);
    }
    let msg = postcard::from_bytes(&buf[4..end]).map_err(|_| ProtocolError::Decode)?;
    Ok(Some((msg, end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ClientMessage;

    #[test]
    fn encode_then_decode_roundtrips() {
        let msg = ClientMessage::Subscribe;
        let framed = encode(&msg).expect("encode");
        // 4-byte length prefix + postcard payload.
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, framed.len() - 4);
        let (decoded, consumed) = decode::<ClientMessage>(&framed).expect("decode").expect("some");
        assert_eq!(consumed, framed.len());
        // Byte-level equality of the re-encoded frame (no Debug on ClientMessage).
        let reframed = encode(&decoded).expect("re-encode");
        assert_eq!(framed, reframed);
    }

    #[test]
    fn decode_returns_none_on_empty_buffer() {
        let out = decode::<ClientMessage>(&[]).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn decode_returns_none_on_partial_length_prefix() {
        // Only 3 of the 4 length-prefix bytes present.
        let out = decode::<ClientMessage>(&[0u8, 0, 1]).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn decode_returns_none_when_payload_not_yet_present() {
        let msg = ClientMessage::Ack { envelope_ids: vec![1, 2, 3] };
        let framed = encode(&msg).expect("encode");
        // Truncate the payload by one byte.
        let short = &framed[..framed.len() - 1];
        let out = decode::<ClientMessage>(short).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn decode_consumes_only_one_frame_and_leaves_trailer() {
        let a = encode(&ClientMessage::Subscribe).expect("encode");
        let b = encode(&ClientMessage::Poll { since: 5 }).expect("encode");
        let mut both = a.clone();
        both.extend_from_slice(&b);
        let (msg_a, consumed) = decode::<ClientMessage>(&both).expect("decode").expect("some");
        assert_eq!(consumed, a.len());
        // Re-encoding the decoded first frame yields the original first frame.
        assert_eq!(encode(&msg_a).expect("re-encode"), a);
        // The remaining bytes are exactly the second frame.
        let (msg_b, consumed_b) =
            decode::<ClientMessage>(&both[consumed..]).expect("decode").expect("some");
        assert_eq!(consumed_b, b.len());
        assert_eq!(encode(&msg_b).expect("re-encode"), b);
    }

    #[test]
    fn decode_rejects_oversized_length_prefix() {
        // Declare a 2 MiB payload (exceeds the 1 MiB cap) but provide no payload.
        let mut bad = Vec::new();
        bad.extend_from_slice(&((2 * 1024 * 1024) as u32).to_be_bytes());
        assert_eq!(decode::<ClientMessage>(&bad), Err(ProtocolError::TooLarge));
    }

    #[test]
    fn decode_rejects_malformed_payload() {
        // Length prefix says 3 bytes of payload, but the payload is not valid
        // postcard for ClientMessage.
        let mut bad = Vec::new();
        bad.extend_from_slice(&3u32.to_be_bytes());
        bad.extend_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(decode::<ClientMessage>(&bad), Err(ProtocolError::Decode));
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        // A Vec<u8> of MAX_FRAME + 1 bytes serializes to > MAX_FRAME payload.
        let big = vec![0u8; MAX_FRAME + 1];
        // Wrap in a message whose postcard encoding exceeds the cap. Poll is
        // tiny, so use a raw serialize path: encode a large Vec directly via
        // the generic function (Vec<u8> is Serialize).
        assert_eq!(encode(&big), Err(ProtocolError::TooLarge));
    }

    #[test]
    fn encode_accepts_max_sized_payload() {
        // A Vec<u8> of exactly MAX_FRAME bytes is the largest accepted payload.
        let big = vec![0u8; MAX_FRAME];
        let framed = encode(&big).expect("encode");
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, MAX_FRAME);
        let (back, consumed) = decode::<Vec<u8>>(&framed).expect("decode").expect("some");
        assert_eq!(consumed, framed.len());
        assert_eq!(back, big);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_protocol frame`
Expected: FAIL — `frame` module not declared in `lib.rs`.

- [ ] **Step 3: Wire the module into the crate root**

Modify `crates/protocol/src/lib.rs` to (intermediate form — `FrameDecoder` is added in Task 4, so it is NOT re-exported yet):

```rust
//! um_protocol — wire messages + length-prefixed framing for the UM relay.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod messages;

pub use error::ProtocolError;
pub use frame::{decode, encode, MAX_FRAME};
pub use messages::{ClientMessage, EncryptedEnvelope, ServerError, ServerMessage};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p um_protocol frame`
Expected: PASS — 9 tests pass (roundtrip, none-on-empty, none-on-partial-prefix, none-on-partial-payload, consumes-one-frame, rejects-oversized-prefix, rejects-malformed-payload, rejects-oversized-payload, accepts-max-sized).

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/frame.rs crates/protocol/src/lib.rs
git commit -m "feat: add length-prefixed framing with 1 MiB max-size guard"
```

---

### Task 4: Streaming FrameDecoder + finalize

**Files:**
- Modify: `crates/protocol/src/frame.rs` — add `FrameDecoder`
- Modify: `crates/protocol/src/lib.rs` — re-export `FrameDecoder` (final form)
- Test: `crates/protocol/src/frame.rs` (inline `#[cfg(test)]` module, appended tests)

**Interfaces:**
- Consumes: `crate::frame::{decode, MAX_FRAME}`, `crate::ProtocolError`, `serde`.
- Produces:
  - `pub struct FrameDecoder<T> { buf: Vec<u8>, _marker: PhantomData<T> }` — a streaming decoder that accumulates bytes across `push` calls and yields one decoded frame at a time via `next()`. Generic over the message type `T: serde::de::DeserializeOwned`.
  - `impl<T: serde::de::DeserializeOwned> FrameDecoder<T> { pub fn new() -> Self; pub fn push(&mut self, bytes: &[u8]); pub fn next(&mut self) -> Result<Option<T>, ProtocolError>; pub fn buffered_len(&self) -> usize; }`
    - `new()` — empty buffer.
    - `push(bytes)` — appends `bytes` to the internal buffer. No errors (pure append).
    - `next()` — attempts to decode one frame from the front of the buffer. `Ok(None)` if incomplete (buffer retained for more bytes). `Ok(Some(msg))` on success — the consumed frame bytes are removed from the front of the buffer. `Err(ProtocolError::Decode)` on a malformed payload — the consumed frame bytes are still removed (so a bad frame does not loop forever; the caller closes the connection per the spec's "malformed frame → close connection"). `Err(ProtocolError::TooLarge)` on an oversized length prefix — the buffer is cleared (poisoned; caller must drop the connection).
    - `buffered_len()` — returns the number of bytes currently held in the buffer (useful for backpressure / tests).

- [ ] **Step 1: Write the failing tests (append to the existing test module in `frame.rs`)**

Append these tests to the `#[cfg(test)] mod tests` block inside `crates/protocol/src/frame.rs` (after the existing tests from Task 3):

```rust
    #[test]
    fn decoder_assembles_frame_across_pushes() {
        let mut dec: FrameDecoder<ClientMessage> = FrameDecoder::new();
        let framed = encode(&ClientMessage::Subscribe).expect("encode");
        // Feed the frame one byte at a time; only the final byte completes it.
        for (i, b) in framed.iter().enumerate() {
            dec.push(std::slice::from_ref(b));
            if i + 1 < framed.len() {
                assert!(dec.next().expect("ok").is_none(), "no frame before last byte");
            }
        }
        let msg = dec.next().expect("ok").expect("some");
        assert_eq!(encode(&msg).expect("re-encode"), framed);
        assert_eq!(dec.buffered_len(), 0);
    }

    #[test]
    fn decoder_yields_multiple_frames_from_one_push() {
        let mut dec: FrameDecoder<ClientMessage> = FrameDecoder::new();
        let a = encode(&ClientMessage::Subscribe).expect("encode");
        let b = encode(&ClientMessage::Poll { since: 9 }).expect("encode");
        let c = encode(&ClientMessage::Ack { envelope_ids: vec![7] }).expect("encode");
        let mut blob = Vec::new();
        blob.extend_from_slice(&a);
        blob.extend_from_slice(&b);
        blob.extend_from_slice(&c);
        dec.push(&blob);
        assert_eq!(dec.buffered_len(), blob.len());
        let m1 = dec.next().expect("ok").expect("some");
        let m2 = dec.next().expect("ok").expect("some");
        let m3 = dec.next().expect("ok").expect("some");
        assert!(dec.next().expect("ok").is_none());
        assert_eq!(encode(&m1).expect("re-encode"), a);
        assert_eq!(encode(&m2).expect("re-encode"), b);
        assert_eq!(encode(&m3).expect("re-encode"), c);
        assert_eq!(dec.buffered_len(), 0);
    }

    #[test]
    fn decoder_handles_split_then_more() {
        let mut dec: FrameDecoder<ClientMessage> = FrameDecoder::new();
        let a = encode(&ClientMessage::Subscribe).expect("encode");
        let b = encode(&ClientMessage::Poll { since: 1 }).expect("encode");
        // Push first half of a, then the rest of a plus all of b.
        dec.push(&a[..a.len() / 2]);
        assert!(dec.next().expect("ok").is_none());
        let mut rest = a[a.len() / 2..].to_vec();
        rest.extend_from_slice(&b);
        dec.push(&rest);
        let m1 = dec.next().expect("ok").expect("some");
        let m2 = dec.next().expect("ok").expect("some");
        assert!(dec.next().expect("ok").is_none());
        assert_eq!(encode(&m1).expect("re-encode"), a);
        assert_eq!(encode(&m2).expect("re-encode"), b);
    }

    #[test]
    fn decoder_rejects_oversized_and_poisons() {
        let mut dec: FrameDecoder<ClientMessage> = FrameDecoder::new();
        // Length prefix declaring a 2 MiB payload.
        let mut bad = Vec::new();
        bad.extend_from_slice(&((2 * 1024 * 1024) as u32).to_be_bytes());
        dec.push(&bad);
        assert_eq!(dec.next(), Err(ProtocolError::TooLarge));
        // Buffer is poisoned (cleared); further pushes start fresh.
        assert_eq!(dec.buffered_len(), 0);
        let framed = encode(&ClientMessage::Subscribe).expect("encode");
        dec.push(&framed);
        let msg = dec.next().expect("ok").expect("some");
        assert_eq!(encode(&msg).expect("re-encode"), framed);
    }

    #[test]
    fn decoder_consumes_bad_frame_and_continues() {
        let mut dec: FrameDecoder<ClientMessage> = FrameDecoder::new();
        // A complete but malformed frame: len=3, payload=0xff 0xff 0xff.
        let mut bad = Vec::new();
        bad.extend_from_slice(&3u32.to_be_bytes());
        bad.extend_from_slice(&[0xff, 0xff, 0xff]);
        // Followed by a good frame.
        let good = encode(&ClientMessage::Subscribe).expect("encode");
        let mut blob = bad.clone();
        blob.extend_from_slice(&good);
        dec.push(&blob);
        // The bad frame yields Decode but is consumed.
        assert_eq!(dec.next(), Err(ProtocolError::Decode));
        // The good frame then decodes.
        let msg = dec.next().expect("ok").expect("some");
        assert_eq!(encode(&msg).expect("re-encode"), good);
        assert_eq!(dec.buffered_len(), 0);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_protocol frame::tests::decoder`
Expected: FAIL — `FrameDecoder` not defined (unresolved name).

- [ ] **Step 3: Implement `FrameDecoder`**

Add this to `crates/protocol/src/frame.rs`, between the `decode` function and the `#[cfg(test)] mod tests` block (the imports at the top of the file must also gain `use std::marker::PhantomData;`):

Insert the import. The top of `frame.rs` becomes:

```rust
use std::marker::PhantomData;

use crate::ProtocolError;
```

Then add the struct + impl (place it after the `decode` function, before `#[cfg(test)]`):

```rust
/// A streaming frame decoder. Accumulates bytes across `push` calls and
/// yields one decoded frame at a time via `next()`. Generic over the message
/// type `T`.
pub struct FrameDecoder<T> {
    buf: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T: serde::de::DeserializeOwned> FrameDecoder<T> {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Append received bytes to the internal buffer. Never fails.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Number of bytes currently buffered (not yet decoded into a frame).
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Attempt to decode one frame from the front of the buffer.
    ///
    /// - `Ok(None)`: incomplete frame; the buffer is retained for more bytes.
    /// - `Ok(Some(msg))`: a frame was decoded; its bytes are removed from the
    ///   front of the buffer.
    /// - `Err(Decode)`: a complete frame was present but malformed; the frame
    ///   bytes are removed (so a bad frame does not loop forever). Per the
    ///   spec the caller closes the connection on a malformed frame.
    /// - `Err(TooLarge)`: the declared length exceeds `MAX_FRAME`; the buffer
    ///   is cleared (poisoned) and the caller must drop the connection.
    pub fn next(&mut self) -> Result<Option<T>, ProtocolError> {
        match decode::<T>(&self.buf)? {
            None => Ok(None),
            Some((msg, consumed)) => {
                // Remove the consumed bytes from the front of the buffer.
                self.buf.drain(0..consumed);
                Ok(Some(msg))
            }
        }
    }
}

impl<T: serde::de::DeserializeOwned> Default for FrameDecoder<T> {
    fn default() -> Self {
        Self::new()
    }
}
```

**Note on the `TooLarge` poisoning:** `decode` returns `Err(ProtocolError::TooLarge)` without consuming, so `next` propagates it via `?` and `self.buf` is left intact at first glance. To honor the "buffer cleared on TooLarge" contract, change `next` to handle `TooLarge` explicitly. Replace the body of `next` with:

```rust
    pub fn next(&mut self) -> Result<Option<T>, ProtocolError> {
        match decode::<T>(&self.buf) {
            Err(ProtocolError::TooLarge) => {
                self.buf.clear();
                Err(ProtocolError::TooLarge)
            }
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some((msg, consumed))) => {
                self.buf.drain(0..consumed);
                Ok(Some(msg))
            }
        }
    }
```

(Use this explicit-match version, not the `?` version, so the buffer is cleared on `TooLarge`.)

- [ ] **Step 4: Wire `FrameDecoder` into the crate root (final form)**

Modify `crates/protocol/src/lib.rs` to its final form:

```rust
//! um_protocol — wire messages + length-prefixed framing for the UM relay.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod messages;

pub use error::ProtocolError;
pub use frame::{decode, encode, FrameDecoder, MAX_FRAME};
pub use messages::{ClientMessage, EncryptedEnvelope, ServerError, ServerMessage};
```

- [ ] **Step 5: Run the frame tests to verify they pass**

Run: `cargo test -p um_protocol frame`
Expected: PASS — 14 tests pass (9 from Task 3 + 5 decoder tests: assembles-across-pushes, multiple-from-one-push, split-then-more, oversized-poisons, consumes-bad-frame-continues).

- [ ] **Step 6: Run the full crate test suite + clippy**

Run: `cargo test -p um_protocol`
Expected: PASS — all tests across `error`, `messages`, `frame` pass (2 + 10 + 14 = 26 tests). No warnings.

Run: `cargo clippy -p um_protocol --all-targets -- -D warnings`
Expected: no warnings. (If clippy flags `needless_borrows_for_generic_args` or similar, apply the suggested fix and re-run; the crypto crate already follows this convention.)

Run: `cargo test -p um_crypto`
Expected: PASS — the 36 crypto tests still pass (the `VerifyingKey` re-export is additive).

- [ ] **Step 7: Commit**

```bash
git add crates/protocol/src/frame.rs crates/protocol/src/lib.rs
git commit -m "feat: add streaming FrameDecoder for incremental frame reads"
```

---

## Self-Review

**1. Spec coverage:**
- Wire format `[u32 BE length][postcard payload]` → Task 3 `encode`/`decode` ✓
- Max frame 1 MiB guard → Task 3 `MAX_FRAME` + encode/decode checks + Task 4 decoder poisoning ✓
- `Register { identity_pub, signed_prekey_pub, signed_prekey_sig, one_time_prekeys }` → Task 2 `ClientMessage::Register { bundle: PreKeyBundle }` (the `PreKeyBundle` carries identity_pub, signed_prekey_id, signed_prekey_pub, signed_prekey_sig, one_time_prekeys — superset of the spec fields; the `signed_prekey_id` is included because the server stores and returns the whole bundle on `FetchBundle`, and `Register`/`FetchBundle` share the type — DRY) ✓
- `FetchBundle { target_identity_pub }` → `ClientMessage::FetchBundle { target: VerifyingKey }` ✓
- `Send { recipients: Vec<identity_pub>, envelope }` → `ClientMessage::Send { recipients, envelope }` ✓ (server group-oblivious: iterates `recipients`)
- `Poll { since: u64 }` → `ClientMessage::Poll { since }` ✓
- `Ack { envelope_ids }` → `ClientMessage::Ack { envelope_ids }` ✓
- `Subscribe` → `ClientMessage::Subscribe` ✓
- `Bundle(PreKeyBundle)` → `ServerMessage::Bundle(Option<PreKeyBundle>)` (`None` = target not registered, an improvement over the bare spec that the server needs anyway) ✓
- `Delivered(Vec<EncryptedEnvelope>)` → `ServerMessage::Delivered(Vec<EncryptedEnvelope>)` ✓
- `AckOk` → `ServerMessage::AckOk` ✓
- `Error(code)` → `ServerMessage::Error(ServerError)` with `ServerError { UnknownRecipient, InvalidSignature, MalformedFrame, TooLarge, NotRegistered }` covering the spec's `UnknownRecipient` + `InvalidSignature` (Register) + `MalformedFrame` (close-connection case) ✓
- `EncryptedEnvelope { id, sender_identity_pub, ciphertext, header }` → `EncryptedEnvelope { id, sender, header, init, ciphertext }`. The `init: Option<InitMessage>` field is added per the spec's data-flow note ("first encrypted message carries the X3DH init header alongside the ratchet header") — without it Bob cannot run X3DH receive on the first message ✓
- Sync encode/decode, no async → Global Constraints + `#![forbid(unsafe_code)]` + verified no `async`/`tokio`/`std::net` ✓
- Reuses `um_crypto` types → `PreKeyBundle`, `Header`, `InitMessage` embedded directly; `VerifyingKey` re-exported from crypto ✓
- Testing posture (frame round-trip, truncation, max-size, streaming) → Tasks 3 & 4 ✓

**2. Placeholder scan:** No "TBD"/"TODO"/"implement later". The two `expect()` calls in Task 2's `roundtrip_bytes` test helper and the `expect("encode")`/`expect("decode")`/`expect("init_alice")`/`expect("encrypt")` calls are all in **test code only** (the global no-panic rule applies to non-test code paths; `encode`/`decode`/`FrameDecoder::next` use `Result` throughout, no `unwrap`/`expect`). Task 3's `encode`/`decode` and Task 4's `FrameDecoder` have zero panics — all slice access is guarded by explicit `buf.len() < 4` / `buf.len() < end` checks and `drain(0..consumed)` where `consumed ≤ buf.len()` is guaranteed by `decode` only returning `Some` when `end ≤ buf.len()`.

**3. Type consistency:**
- `ProtocolError` variants used consistently: `TooLarge` (encode oversize, decode oversize prefix, decoder poisoning), `Encode` (postcard serialize failure), `Decode` (postcard deserialize failure, decoder bad frame) ✓
- `VerifyingKey` is re-exported from `um_crypto` (Task 1) and imported in `messages.rs` as `um_crypto::VerifyingKey` — single source of truth, no direct `ed25519-dalek` dep in `um_protocol` ✓
- `EncryptedEnvelope` fields: `id: u64`, `sender: VerifyingKey`, `header: Header`, `init: Option<InitMessage>`, `ciphertext: Vec<u8>` — used identically in Task 2's `ClientMessage::Send` and `ServerMessage::Delivered` ✓
- `ServerError` derives `Copy` so `ServerMessage::Error(ServerError)` can be constructed by value and still `Clone` the outer enum ✓
- `FrameDecoder<T>` generic bound `serde::de::DeserializeOwned` matches `decode::<T>`'s bound; `Default` impl is provided so callers can write `FrameDecoder::default()` ✓
- `lib.rs` re-exports: final form lists `decode, encode, FrameDecoder, MAX_FRAME` from `frame` — all four are defined in `frame.rs` by end of Task 4 ✓
- The intermediate `lib.rs` in Task 3 Step 3 deliberately omits `FrameDecoder` (not yet defined); Task 4 Step 4 adds it. The note in Task 3 Step 3 calls this out explicitly so the crate compiles at the Task 3 checkpoint ✓

**4. Ambiguity check:** The `Register`-embeds-`PreKeyBundle` decision (vs. mirroring the spec's flat field list) is spelled out in the Task 2 interface block and the self-review. The `init: Option<InitMessage>` addition to `EncryptedEnvelope` is justified by the spec's data-flow section. The `FrameDecoder::next` poisoning-on-`TooLarge` and consume-on-`Decode` semantics are specified step-by-step and match the spec's "malformed frame → close connection" rule. The byte-round-trip test strategy is explained (no `Debug`/`PartialEq` on crypto-containing wire structs because `Signature` has no `Debug`).

No issues remain. Plan is complete.
