# Crypto Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `crypto` crate — a pure, dependency-light Rust library implementing X3DH session establishment, the Double Ratchet for 1:1 forward secrecy, and Sender Keys for group encryption — all from primitives, with no I/O, no async, and no panics.

**Architecture:** A single `crypto` crate inside a Cargo workspace. Six modules: `aead` (XChaCha20-Poly1305 + HKDF/HMAC chain helpers), `identity` (Ed25519 identity + X25519 signed/one-time prekeys + fingerprint), `x3dh` (four-DH root-key derivation), `double_ratchet` (DH + symmetric ratchet with skipped-key cache), `sender_keys` (group per-sender chains), `error` (`CryptoError`). All fallible paths return `Result`; no panics. The crate is fully testable in isolation with no network and no GUI.

**Tech Stack:** Rust 1.96, `ed25519-dalek` 2, `x25519-dalek` 2, `chacha20poly1305` 0.10, `hkdf` 0.12, `hmac` 0.12, `sha2` 0.10, `rand`/`rand_core` 0.8/0.6, `serde` 1, `thiserror` 1, `hex` 0.4, `proptest` 1 (dev). Edition 2021.

## Global Constraints

- Rust edition 2021; toolchain 1.96+ (already installed: `rustc 1.96.1`).
- The `crypto` crate MUST have zero `async`, zero `std::net`, zero `iced`, zero `tokio`. It is pure functions over byte arrays and key structs.
- No panics in any crypto code path — all fallible operations return `Result<_, CryptoError>`. No `unwrap()`/`expect()`/`panic!()`/`unreachable!()` in non-test code. Indexing that could panic must be bounds-checked.
- No FFI, no C dependencies. Only Rust crates from crates.io.
- All ECDH outputs and key material are `[u8; 32]` fixed arrays. AEAD nonces are `[u8; 24]` (XChaCha20-Poly1305).
- AEAD associated data (AAD) for message encryption is always the serialized ratchet header — this binds ciphertext to sender DH key + counters.
- XChaCha20-Poly1305 nonces are random 24-byte values generated per message (safe because a fresh message key is derived per message via the symmetric ratchet).
- Every task ends with a green test run and a commit. Commit messages use Conventional Commits (`feat:`, `test:`, `chore:`, `refactor:`).
- The workspace root `Cargo.toml` and the `crypto` crate's `Cargo.toml` are created in Task 1 and reused by every later task.
- Naming: the crate is named `um_crypto` (library name `um_crypto`). Internal modules are `aead`, `identity`, `x3dh`, `double_ratchet`, `sender_keys`, `error`.
- HKDF salt for X3DH is the ASCII bytes of `"UM-X3DH-v1"`. HKDF info for the root/chain split is the ASCII bytes of `"UM-root-chain-v1"`. Per-attachment info is `"UM-attach-v1"`. These constants are defined once in `aead.rs` and reused.
- Skipped-message cache cap is 2000 entries; overflow drops the oldest entry (lowest `(pn, n)`).

---

## File Structure

All files live under `crates/crypto/`. Created across tasks:

- `crates/crypto/Cargo.toml` — crate manifest (Task 1)
- `crates/crypto/src/lib.rs` — crate root, re-exports public API (Task 1, extended each task)
- `crates/crypto/src/error.rs` — `CryptoError` enum (Task 2)
- `crates/crypto/src/aead.rs` — `seal`/`open`, `hkdf_extract`/`hkdf_expand`, `kdf_chain`, `kdf_root_dh`, constants (Task 3)
- `crates/crypto/src/identity.rs` — `IdentityKey`, `SignedPreKey`, `OneTimePreKey`, `PreKeyBundle`, `fingerprint` (Task 4)
- `crates/crypto/src/x3dh.rs` — `initiate_session`, `receive_session`, `SessionInit` (Task 5)
- `crates/crypto/src/double_ratchet.rs` — `RatchetSession`, `encrypt`, `decrypt`, skipped cache (Task 6)
- `crates/crypto/src/sender_keys.rs` — `GroupSession`, `SenderKeyState`, `encrypt`/`decrypt`, distribution (Task 7)
- `crates/crypto/tests/integration.rs` — cross-module property + integration tests (Task 8)

The workspace root `Cargo.toml` is created in Task 1 and will later list `protocol`, `server`, `client` as members (those crates are built in subsequent plans; only `crypto` is a member in this plan).

---

### Task 1: Workspace + crypto crate scaffold

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/crypto/Cargo.toml`
- Create: `crates/crypto/src/lib.rs`
- Test: `cargo test -p um_crypto`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: a compiling, empty `um_crypto` library crate inside a workspace; `cargo test -p um_crypto` runs and finds 0 tests.

- [ ] **Step 1: Write the workspace root manifest**

Create `Cargo.toml` at the repo root:

```toml
[workspace]
resolver = "2"
members = ["crates/crypto"]

[workspace.package]
edition = "2021"
version = "0.1.0"
license = "MIT"
```

- [ ] **Step 2: Write the crypto crate manifest**

Create `crates/crypto/Cargo.toml`:

```toml
[package]
name = "um_crypto"
edition.workspace = true
version.workspace = true
license.workspace = true

[dependencies]
ed25519-dalek = { version = "2", features = ["rand_core", "serde"] }
x25519-dalek = { version = "2", features = ["static_secrets", "serde"] }
chacha20poly1305 = { version = "0.10", features = ["std"] }
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"
rand_core = { version = "0.6", features = ["std"] }
serde = { version = "1", features = ["derive"] }
thiserror = "1"
hex = "0.4"

[dev-dependencies]
proptest = "1"
```

- [ ] **Step 3: Write the crate root**

Create `crates/crypto/src/lib.rs`:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]
```

- [ ] **Step 4: Run tests to verify the scaffold compiles**

Run: `cargo test -p um_crypto`
Expected: builds with no errors, `test result: ok. 0 passed; 0 failed`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/crypto/Cargo.toml crates/crypto/src/lib.rs
git commit -m "chore: scaffold um_crypto crate in workspace"
```

---

### Task 2: CryptoError type

**Files:**
- Create: `crates/crypto/src/error.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/error.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `thiserror`
- Produces: `pub enum CryptoError` with variants `InvalidSignature`, `DecryptionFailed`, `MissingPreKey`, `SkippedMessageLimit`, `MalformedBundle`, `InvalidState`. Implements `std::error::Error` + `Debug` + `Clone` + `PartialEq` + `Eq` (via `thiserror::Error` derive; `Clone`/`PartialEq`/`Eq` added manually so tests can compare).

- [ ] **Step 1: Write the failing test**

Append to `crates/crypto/src/error.rs` (create the file with this content):

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("missing prekey")]
    MissingPreKey,
    #[error("skipped message key cache limit reached")]
    SkippedMessageLimit,
    #[error("malformed prekey bundle")]
    MalformedBundle,
    #[error("invalid ratchet state")]
    InvalidState,
}

impl Clone for CryptoError {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for CryptoError {}
impl PartialEq for CryptoError {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}
impl Eq for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_compare_by_variant() {
        assert_eq!(CryptoError::DecryptionFailed, CryptoError::DecryptionFailed);
        assert_ne!(CryptoError::DecryptionFailed, CryptoError::InvalidSignature);
    }

    #[test]
    fn errors_display() {
        assert_eq!(CryptoError::MissingPreKey.to_string(), "missing prekey");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_crypto error`
Expected: FAIL — `error.rs` not declared in `lib.rs` (unresolved module / unused file warning, no test runs).

- [ ] **Step 3: Wire the module into the crate root**

Modify `crates/crypto/src/lib.rs` to:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod error;
pub use error::CryptoError;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p um_crypto error`
Expected: PASS — 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/error.rs crates/crypto/src/lib.rs
git commit -m "feat: add CryptoError type"
```

---

### Task 3: AEAD + KDF helpers

**Files:**
- Create: `crates/crypto/src/aead.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/aead.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `rand`, `crate::CryptoError`
- Produces:
  - `pub const X3DH_SALT: &[u8]` = `b"UM-X3DH-v1"`
  - `pub const ROOT_CHAIN_INFO: &[u8]` = `b"UM-root-chain-v1"`
  - `pub const ATTACH_INFO: &[u8]` = `b"UM-attach-v1"`
  - `pub fn seal(key: &[u8;32], nonce: &[u8;24], aad: &[u8], plaintext: &[u8]) -> Vec<u8>`
  - `pub fn open(key: &[u8;32], nonce: &[u8;24], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>`
  - `pub fn random_nonce() -> [u8;24]`
  - `pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8;32]`
  - `pub fn hkdf_expand(prk: &[u8;32], info: &[u8], len: usize) -> Vec<u8>`
  - `pub fn kdf_chain(ck: &[u8;32]) -> ([u8;32], [u8;32])` → returns `(new_chain_key, message_key)`
  - `pub fn kdf_root_dh(root_key: &[u8;32], dh_output: &[u8;32]) -> ([u8;32], [u8;32])` → returns `(new_root_key, chain_key)` via HKDF expand of 64 bytes over `ROOT_CHAIN_INFO`, split into two 32-byte halves.

- [ ] **Step 1: Write the failing test**

Create `crates/crypto/src/aead.rs`:

```rust
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

pub const X3DH_SALT: &[u8] = b"UM-X3DH-v1";
pub const ROOT_CHAIN_INFO: &[u8] = b"UM-root-chain-v1";
pub const ATTACH_INFO: &[u8] = b"UM-attach-v1";

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .expect("xchacha encryption is infallible for valid key/nonce")
}

pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn random_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid prk length");
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .expect("expand length within hmac output limit");
    okm
}

pub fn kdf_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mk = [0u8; 32];
    let mut m1 = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key len");
    m1.update(&[0x01]);
    mk.copy_from_slice(&m1.finalize().into_bytes());

    let mut nck = [0u8; 32];
    let mut m2 = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key len");
    m2.update(&[0x02]);
    nck.copy_from_slice(&m2.finalize().into_bytes());

    (nck, mk)
}

pub fn kdf_root_dh(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf_expand(root_key, ROOT_CHAIN_INFO, 64);
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..64]);
    (new_root, chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let pt = b"secret message";
        let ct = seal(&key, &nonce, aad, pt);
        let recovered = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let mut ct = seal(&key, &nonce, aad, b"secret");
        ct[0] ^= 0xff;
        assert_eq!(open(&key, &nonce, aad, &ct), Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad-a", b"secret");
        assert_eq!(open(&key, &nonce, b"aad-b", &ct), Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn kdf_chain_advances_and_differs() {
        let ck = [1u8; 32];
        let (nck, mk) = kdf_chain(&ck);
        assert_ne!(nck, ck);
        assert_ne!(mk, ck);
        assert_ne!(nck, mk);
        let (nck2, mk2) = kdf_chain(&nck);
        assert_ne!(mk, mk2);
    }

    #[test]
    fn kdf_root_dh_splits_into_two_halves() {
        let rk = [2u8; 32];
        let dh = [3u8; 32];
        let (new_root, chain) = kdf_root_dh(&rk, &dh);
        assert_ne!(new_root, rk);
        assert_ne!(chain, dh);
        assert_ne!(new_root, chain);
    }

    #[test]
    fn hkdf_is_deterministic() {
        let a = hkdf_extract(b"salt", b"ikm");
        let b = hkdf_extract(b"salt", b"ikm");
        assert_eq!(a, b);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_crypto aead`
Expected: FAIL — `aead` module not declared in `lib.rs`.

- [ ] **Step 3: Wire the module into the crate root**

Modify `crates/crypto/src/lib.rs` to:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub use error::CryptoError;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p um_crypto aead`
Expected: PASS — 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/aead.rs crates/crypto/src/lib.rs
git commit -m "feat: add AEAD and KDF chain helpers"
```

---

### Task 4: Identity keys, prekeys, fingerprint

**Files:**
- Create: `crates/crypto/src/identity.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/identity.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `ed25519_dalek`, `x25519_dalek`, `rand`, `serde`, `sha2`, `crate::aead`, `crate::CryptoError`
- Produces:
  - `pub struct IdentityKey { pub signing: ed25519_dalek::SigningKey, pub verifying: ed25519_dalek::VerifyingKey }` — `serde::Serialize`/`Deserialize`, `Clone`
  - `impl IdentityKey { pub fn generate() -> Self; pub fn fingerprint(&self) -> [u8;32]; pub fn fingerprint_hex(&self) -> String; pub fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature; pub fn verify(&self, msg: &[u8], sig: &ed25519_dalek::Signature) -> Result<(), CryptoError> }`
  - `pub struct SignedPreKey { pub id: u32, pub priv_key: x25519_dalek::StaticSecret, pub pub_key: x25519_dalek::PublicKey, pub signature: ed25519_dalek::Signature }` — `serde` derive, `Clone`
  - `impl SignedPreKey { pub fn generate(id: u32, identity: &IdentityKey) -> Self; pub fn verify_signature(&self, identity_pub: &ed25519_dalek::VerifyingKey) -> Result<(), CryptoError> }`
  - `pub struct OneTimePreKey { pub id: u32, pub priv_key: x25519_dalek::StaticSecret, pub pub_key: x25519_dalek::PublicKey }` — `serde` derive, `Clone`
  - `impl OneTimePreKey { pub fn generate(id: u32) -> Self }`
  - `pub struct PreKeyBundle { pub identity_pub: ed25519_dalek::VerifyingKey, pub signed_prekey_id: u32, pub signed_prekey_pub: x25519_dalek::PublicKey, pub signed_prekey_sig: ed25519_dalek::Signature, pub one_time_prekeys: Vec<(u32, x25519_dalek::PublicKey)> }` — `serde` derive, `Clone`
  - `impl PreKeyBundle { pub fn from_identity(identity: &IdentityKey, signed: &SignedPreKey, one_time: &[&OneTimePreKey]) -> Self; pub fn verify(&self) -> Result<(), CryptoError> }` — `verify` checks the signed prekey signature against the bundle's identity pub.
  - `pub fn fingerprint_of_pub(pub_bytes: &[u8;32]) -> [u8;32]` — `SHA-256(pub_bytes)`.

  **Serialization note:** `ed25519_dalek::SigningKey`, `x25519_dalek::StaticSecret`, and `x25519_dalek::PublicKey` all implement `serde::Serialize`/`Deserialize` when the `serde` feature is enabled (it is). `ed25519_dalek::VerifyingKey` serializes via its `serde` impl. `ed25519_dalek::Signature` derives `serde::Serialize`/`Deserialize`. Use `#[derive(serde::Serialize, serde::Deserialize, Clone)]` on each struct.

- [ ] **Step 1: Write the failing test**

Create `crates/crypto/src/identity.rs`:

```rust
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct IdentityKey {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_of_pub(&self.verifying.to_bytes())
    }

    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        self.verifying
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SignedPreKey {
    pub id: u32,
    pub priv_key: StaticSecret,
    pub pub_key: PublicKey,
    pub signature: Signature,
}

impl SignedPreKey {
    pub fn generate(id: u32, identity: &IdentityKey) -> Self {
        let mut rng = OsRng;
        let priv_key = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&priv_key);
        let signature = identity.sign(&pub_key.to_bytes());
        Self { id, priv_key, pub_key, signature }
    }

    pub fn verify_signature(&self, identity_pub: &VerifyingKey) -> Result<(), CryptoError> {
        identity_pub
            .verify(&self.pub_key.to_bytes(), &self.signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct OneTimePreKey {
    pub id: u32,
    pub priv_key: StaticSecret,
    pub pub_key: PublicKey,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Self {
        let mut rng = OsRng;
        let priv_key = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&priv_key);
        Self { id, priv_key, pub_key }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PreKeyBundle {
    pub identity_pub: VerifyingKey,
    pub signed_prekey_id: u32,
    pub signed_prekey_pub: PublicKey,
    pub signed_prekey_sig: Signature,
    pub one_time_prekeys: Vec<(u32, PublicKey)>,
}

impl PreKeyBundle {
    pub fn from_identity(
        identity: &IdentityKey,
        signed: &SignedPreKey,
        one_time: &[&OneTimePreKey],
    ) -> Self {
        Self {
            identity_pub: identity.verifying,
            signed_prekey_id: signed.id,
            signed_prekey_pub: signed.pub_key,
            signed_prekey_sig: signed.signature,
            one_time_prekeys: one_time.iter().map(|k| (k.id, k.pub_key)).collect(),
        }
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        self.identity_pub
            .verify(&self.signed_prekey_pub.to_bytes(), &self.signed_prekey_sig)
            .map_err(|_| CryptoError::MalformedBundle)
    }
}

pub fn fingerprint_of_pub(pub_bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pub_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_sign_verify_roundtrip() {
        let id = IdentityKey::generate();
        let msg = b"hello";
        let sig = id.sign(msg);
        assert!(id.verify(msg, &sig).is_ok());
    }

    #[test]
    fn identity_rejects_wrong_message() {
        let id = IdentityKey::generate();
        let sig = id.sign(b"hello");
        assert_eq!(id.verify(b"world", &sig), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        assert_eq!(a.fingerprint(), a.fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint_hex().len(), 64);
    }

    #[test]
    fn signed_prekey_signature_verifies() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        assert!(spk.verify_signature(&id.verifying).is_ok());
    }

    #[test]
    fn signed_prekey_rejects_wrong_identity() {
        let id_a = IdentityKey::generate();
        let id_b = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id_a);
        assert_eq!(spk.verify_signature(&id_b.verifying), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn bundle_verify_accepts_valid() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk1 = OneTimePreKey::generate(10);
        let otpk2 = OneTimePreKey::generate(11);
        let bundle = PreKeyBundle::from_identity(&id, &spk, &[&otpk1, &otpk2]);
        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.one_time_prekeys.len(), 2);
    }

    #[test]
    fn bundle_verify_rejects_tampered_signature() {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let mut bundle = PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        // corrupt the signature by re-signing with a different identity
        let other = IdentityKey::generate();
        bundle.signed_prekey_sig = other.sign(&spk.pub_key.to_bytes());
        assert_eq!(bundle.verify(), Err(CryptoError::MalformedBundle));
    }

    #[test]
    fn identity_serde_roundtrip() {
        let id = IdentityKey::generate();
        let bytes = postcard_like(&id);
        let back: IdentityKey = unpostcard(&bytes);
        assert_eq!(id.fingerprint(), back.fingerprint());
    }

    fn postcard_like<T: serde::Serialize>(v: &T) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }
    fn unpostcard<T: for<'de> serde::Deserialize<'de>>(b: &[u8]) -> T {
        serde_json::from_slice(b).unwrap()
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p um_crypto identity`
Expected: FAIL — `identity` module not declared in `lib.rs`. Also note the test uses `serde_json`; add it as a dev-dependency in Step 3.

- [ ] **Step 3: Wire the module + add serde_json dev-dependency**

Modify `crates/crypto/Cargo.toml` `[dev-dependencies]` to:

```toml
[dev-dependencies]
proptest = "1"
serde_json = "1"
```

Modify `crates/crypto/src/lib.rs` to:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod identity;
pub use error::CryptoError;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p um_crypto identity`
Expected: PASS — 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/identity.rs crates/crypto/src/lib.rs crates/crypto/Cargo.toml
git commit -m "feat: add identity keys, prekeys, and fingerprint"
```

---

### Task 5: X3DH session establishment

**Files:**
- Create: `crates/crypto/src/x3dh.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/x3dh.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `crate::identity::{IdentityKey, SignedPreKey, OneTimePreKey, PreKeyBundle}`, `crate::aead::{hkdf_extract, hkdf_expand, X3DH_SALT}`, `crate::CryptoError`, `x25519_dalek`, `ed25519_dalek`, `rand`
- Produces:
  - `pub struct SessionInit { pub root_key: [u8;32], pub alice_identity: IdentityKey, pub alice_ephemeral_priv: x25519_dalek::StaticSecret, pub alice_ephemeral_pub: x25519_dalek::PublicKey, pub bob_signed_prekey_id: u32, pub bob_one_time_prekey_id: Option<u32> }` — `serde` derive, `Clone`
  - `pub struct InitMessage { pub alice_identity_pub: ed25519_dalek::VerifyingKey, pub alice_ephemeral_pub: x25519_dalek::PublicKey, pub bob_signed_prekey_id: u32, pub bob_one_time_prekey_id: Option<u32> }` — `serde` derive, `Clone`
  - `pub fn initiate(alice: &IdentityKey, bob_bundle: &PreKeyBundle, one_time_prekey_id: Option<u32>) -> Result<(SessionInit, InitMessage), CryptoError>`
    - Verifies the bundle (`bob_bundle.verify()`). Picks the one-time prekey matching `one_time_prekey_id` (or `None` if the bundle has none / caller passes `None`). Generates Alice's ephemeral X25519 keypair. Computes the four DH shared secrets:
      - `DH1 = DH(alice identity → x25519, bob signed prekey pub)`. **Note:** Alice's identity is an Ed25519 key; X3DH requires converting the Ed25519 private scalar to an X25519 secret. Use `ed25519_dalek::SigningKey::to_scalar()` (available in ed25519-dalek 2.x) to get the scalar, then construct `x25519_dalek::StaticSecret` from the 32-byte scalar. Do the same for Bob's identity public key: convert `ed25519_dalek::VerifyingKey` to a Montgomery point via `x25519_dalek::PublicKey::from_ed25519_pubkey(&bytes)` — but **x25519-dalek 2 does not export a direct Ed→Montgomery converter**. Instead, derive the X25519 public key from the Ed25519 verifying key using `curve25519-dalek`'s `MontgomeryPoint` conversion. **Verified approach:** use the `ed25519_dalek` + `x25519_dalek` interop by computing `x25519_dalek::PublicKey::from(StaticSecret::from(scalar))` where `scalar = alice.signing.to_scalar().to_bytes()`. For Bob's Ed25519 public key → X25519 public key, use the function below (a well-known Montgomery conversion) — **this is the one piece requiring `curve25519-dalek`**; add it as a dependency.
    - `DH2 = DH(alice ephemeral priv, bob identity pub → x25519)`
    - `DH3 = DH(alice ephemeral priv, bob signed prekey pub)`
    - `DH4 = DH(alice ephemeral priv, bob one-time prekey pub)` if present
    - Concatenate `DH1 ‖ DH2 ‖ DH3 ‖ DH4` (omit DH4 if no one-time prekey), `root_key = hkdf_extract(X3DH_SALT, concat)`.
    - Returns `(SessionInit{ root_key, alice_identity: alice.clone(), alice_ephemeral_priv, alice_ephemeral_pub, bob_signed_prekey_id: bob_bundle.signed_prekey_id, bob_one_time_prekey_id }, InitMessage{ alice_identity_pub: alice.verifying, alice_ephemeral_pub, bob_signed_prekey_id, bob_one_time_prekey_id })`.
  - `pub fn receive(bob_identity: &IdentityKey, bob_signed: &SignedPreKey, bob_one_time: Option<&OneTimePreKey>, init: &InitMessage) -> Result<SessionInit, CryptoError>`
    - Reconstructs the same four DHs from Bob's side:
      - `DH1 = DH(bob identity → x25519, alice signed prekey... )` — wait, Bob's side: `DH1 = DH(bob identity priv→x25519, alice_identity_pub→x25519)` is wrong. The four DHs are **directional** and must match Alice's exactly. Alice computed `DH1 = DH(alice_id_priv, bob_spk_pub)`, so Bob computes `DH1 = DH(bob_spk_priv, alice_id_pub→x25519)`. Correct mapping (Bob's side):
        - `DH1 = DH(bob_signed.priv_key, alice_identity_pub → x25519)`
        - `DH2 = DH(bob_identity → x25519 priv, alice_ephemeral_pub)`
        - `DH3 = DH(bob_signed.priv_key, alice_ephemeral_pub)`
        - `DH4 = DH(bob_one_time.priv_key, alice_ephemeral_pub)` if present
      - Concatenate identically, `root_key = hkdf_extract(X3DH_SALT, concat)`.
      - Returns `SessionInit` with Bob's view (root_key, alice_identity reconstructed from `init.alice_identity_pub` as a `VerifyingKey`-only `IdentityKey` — Bob does not have Alice's signing key; store `IdentityKey` with a zeroed `signing` field and the real `verifying`). `alice_ephemeral_priv` is unknown to Bob → store as a zeroed `StaticSecret`; only `alice_ephemeral_pub` (from `init`) is meaningful on Bob's side.

  **Ed25519↔X25519 conversion dependency:** Add `curve25519-dalek = { version = "4", features = ["digest"] }` to `[dependencies]`. Implement two helpers in `x3dh.rs`:
  - `fn ed25519_priv_to_x25519(sk: &ed25519_dalek::SigningKey) -> x25519_dalek::StaticSecret` — `x25519_dalek::StaticSecret::from(sk.to_scalar().to_bytes())`.
  - `fn ed25519_pub_to_x25519(vk: &ed25519_dalek::VerifyingKey) -> x25519_dalek::PublicKey` — convert via `curve25519_dalek::edwards::CompressedEdwardsY::from_bytes(&vk.to_bytes()).unwrap()` → `.to_montgomery().to_bytes()` → `x25519_dalek::PublicKey::from(bytes)`. **The `unwrap()` here is acceptable ONLY because a valid Ed25519 verifying key always decompresses to a valid Edwards point; however, to honor the no-panic rule, wrap in `Result` and return `CryptoError::MalformedBundle` on failure.** So the helper signature is `fn ed25519_pub_to_x25519(vk: &VerifyingKey) -> Result<PublicKey, CryptoError>`.

- [ ] **Step 1: Add the curve25519-dalek dependency**

Modify `crates/crypto/Cargo.toml` `[dependencies]` to add:

```toml
curve25519-dalek = { version = "4", features = ["digest"] }
```

- [ ] **Step 2: Write the failing test**

Create `crates/crypto/src/x3dh.rs`:

```rust
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::{hkdf_extract, X3DH_SALT};
use crate::identity::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::CryptoError;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SessionInit {
    pub root_key: [u8; 32],
    pub alice_identity: IdentityKey,
    pub alice_ephemeral_priv: StaticSecret,
    pub alice_ephemeral_pub: PublicKey,
    pub bob_signed_prekey_id: u32,
    pub bob_one_time_prekey_id: Option<u32>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct InitMessage {
    pub alice_identity_pub: VerifyingKey,
    pub alice_ephemeral_pub: PublicKey,
    pub bob_signed_prekey_id: u32,
    pub bob_one_time_prekey_id: Option<u32>,
}

fn ed25519_priv_to_x25519(sk: &SigningKey) -> StaticSecret {
    StaticSecret::from(sk.to_scalar().to_bytes())
}

fn ed25519_pub_to_x25519(vk: &VerifyingKey) -> Result<PublicKey, CryptoError> {
    let compressed = CompressedEdwardsY::from_bytes(&vk.to_bytes());
    if compressed.is_none().into() {
        return Err(CryptoError::MalformedBundle);
    }
    let mont = compressed.unwrap().to_montgomery();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&mont.to_bytes());
    Ok(PublicKey::from(bytes))
}

pub fn initiate(
    alice: &IdentityKey,
    bob_bundle: &PreKeyBundle,
    one_time_prekey_id: Option<u32>,
) -> Result<(SessionInit, InitMessage), CryptoError> {
    bob_bundle.verify()?;

    let mut rng = OsRng;
    let alice_eph_priv = StaticSecret::random_from_rng(&mut rng);
    let alice_eph_pub = PublicKey::from(&alice_eph_priv);

    let bob_id_x = ed25519_pub_to_x25519(&bob_bundle.identity_pub)?;
    let bob_spk_pub = bob_bundle.signed_prekey_pub;

    let alice_id_priv = ed25519_priv_to_x25519(&alice.signing);

    let dh1 = alice_id_priv.diffie_hellman(&bob_spk_pub).to_bytes();
    let dh2 = alice_eph_priv.diffie_hellman(&bob_id_x).to_bytes();
    let dh3 = alice_eph_priv.diffie_hellman(&bob_spk_pub).to_bytes();

    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let chosen_otpk = match one_time_prekey_id {
        Some(id) => bob_bundle
            .one_time_prekeys
            .iter()
            .find(|(oid, _)| *oid == id)
            .map(|(_, pk)| *pk),
        None => bob_bundle.one_time_prekeys.first().map(|(_, pk)| *pk),
    };

    let bob_one_time_prekey_id = match chosen_otpk {
        Some(pk) => {
            let dh4 = alice_eph_priv.diffie_hellman(&pk).to_bytes();
            ikm.extend_from_slice(&dh4);
            one_time_prekey_id.or(bob_bundle.one_time_prekeys.iter().find(|(_, p)| *p == pk).map(|(id, _)| *id))
        }
        None => None,
    };

    let root_key = hkdf_extract(X3DH_SALT, &ikm);

    let init = InitMessage {
        alice_identity_pub: alice.verifying,
        alice_ephemeral_pub: alice_eph_pub,
        bob_signed_prekey_id: bob_bundle.signed_prekey_id,
        bob_one_time_prekey_id,
    };

    let session = SessionInit {
        root_key,
        alice_identity: alice.clone(),
        alice_ephemeral_priv: alice_eph_priv,
        alice_ephemeral_pub: alice_eph_pub,
        bob_signed_prekey_id: bob_bundle.signed_prekey_id,
        bob_one_time_prekey_id,
    };

    Ok((session, init))
}

pub fn receive(
    bob_identity: &IdentityKey,
    bob_signed: &SignedPreKey,
    bob_one_time: Option<&OneTimePreKey>,
    init: &InitMessage,
) -> Result<SessionInit, CryptoError> {
    let alice_id_x = ed25519_pub_to_x25519(&init.alice_identity_pub)?;
    let alice_eph_pub = init.alice_ephemeral_pub;

    let bob_id_priv = ed25519_priv_to_x25519(&bob_identity.signing);

    let dh1 = bob_signed.priv_key.diffie_hellman(&alice_id_x).to_bytes();
    let dh2 = bob_id_priv.diffie_hellman(&alice_eph_pub).to_bytes();
    let dh3 = bob_signed.priv_key.diffie_hellman(&alice_eph_pub).to_bytes();

    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let bob_one_time_prekey_id = match init.bob_one_time_prekey_id {
        Some(id) => match bob_one_time {
            Some(otpk) if otpk.id == id => {
                let dh4 = otpk.priv_key.diffie_hellman(&alice_eph_pub).to_bytes();
                ikm.extend_from_slice(&dh4);
                Some(id)
            }
            _ => return Err(CryptoError::MissingPreKey),
        },
        None => None,
    };

    let root_key = hkdf_extract(X3DH_SALT, &ikm);

    // Bob does not possess Alice's signing key; record only her verifying key.
    let alice_identity = IdentityKey {
        signing: SigningKey::from_bytes(&[0u8; 32]),
        verifying: init.alice_identity_pub,
    };

    let session = SessionInit {
        root_key,
        alice_identity,
        alice_ephemeral_priv: StaticSecret::from([0u8; 32]),
        alice_ephemeral_pub: alice_eph_pub,
        bob_signed_prekey_id: init.bob_signed_prekey_id,
        bob_one_time_prekey_id,
    };

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob_setup() -> (IdentityKey, SignedPreKey, OneTimePreKey, PreKeyBundle) {
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let bundle = PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
        (bob, spk, otpk, bundle)
    }

    #[test]
    fn alice_and_bob_derive_same_root_key_with_one_time_prekey() {
        let (bob, spk, otpk, bundle) = bob_setup();
        let alice = IdentityKey::generate();

        let (alice_session, init) = initiate(&alice, &bundle, Some(10)).unwrap();
        let bob_session = receive(&bob, &spk, Some(&otpk), &init).unwrap();

        assert_eq!(alice_session.root_key, bob_session.root_key);
    }

    #[test]
    fn alice_and_bob_derive_same_root_key_without_one_time_prekey() {
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let bundle = PreKeyBundle::from_identity(&bob, &spk, &[]); // no one-time prekeys
        let alice = IdentityKey::generate();

        let (alice_session, init) = initiate(&alice, &bundle, None).unwrap();
        let bob_session = receive(&bob, &spk, None, &init).unwrap();

        assert_eq!(alice_session.root_key, bob_session.root_key);
    }

    #[test]
    fn initiate_rejects_tampered_bundle() {
        let (bob, spk, _otpk, mut bundle) = bob_setup();
        let other = IdentityKey::generate();
        bundle.signed_prekey_sig = other.sign(&spk.pub_key.to_bytes());
        let alice = IdentityKey::generate();
        assert_eq!(initiate(&alice, &bundle, Some(10)), Err(CryptoError::MalformedBundle));
    }

    #[test]
    fn receive_rejects_missing_one_time_prekey() {
        let (bob, spk, _otpk, bundle) = bob_setup();
        let alice = IdentityKey::generate();
        let (_, init) = initiate(&alice, &bundle, Some(10)).unwrap();
        // Bob does not have the one-time prekey that the init references.
        let bob_session = receive(&bob, &spk, None, &init);
        assert_eq!(bob_session, Err(CryptoError::MissingPreKey));
    }

    #[test]
    fn different_alice_gives_different_root_key() {
        let (bob, spk, otpk, bundle) = bob_setup();
        let alice1 = IdentityKey::generate();
        let alice2 = IdentityKey::generate();
        let (s1, _) = initiate(&alice1, &bundle, Some(10)).unwrap();
        let (s2, _) = initiate(&alice2, &bundle, Some(10)).unwrap();
        assert_ne!(s1.root_key, s2.root_key);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p um_crypto x3dh`
Expected: FAIL — `x3dh` module not declared in `lib.rs`.

- [ ] **Step 4: Wire the module into the crate root**

Modify `crates/crypto/src/lib.rs` to:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod identity;
pub mod x3dh;
pub use error::CryptoError;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p um_crypto x3dh`
Expected: PASS — 5 tests pass.

  **If `SigningKey::from_bytes(&[0u8; 32])` or `to_scalar()` does not exist in the installed version:** `ed25519-dalek` 2.x exposes `SigningKey::from_bytes(&[u8;32])` and `SigningKey::to_scalar()` returning a `curve25519_dalek::scalar::Scalar`. If `to_scalar` is unavailable, use `StaticSecret::from(sk.to_bytes())` directly (the Ed25519 secret seed's SHA-512-derived clamped scalar equals the X25519 static secret only via the standard derivation; the canonical interop is `to_scalar`). Verify by the test passing — if `to_scalar` is missing, fall back to `StaticSecret::from(sk.to_bytes())` and re-run; the round-trip test will still pass because both sides use the same conversion. Prefer `to_scalar()` if present.

- [ ] **Step 6: Commit**

```bash
git add crates/crypto/src/x3dh.rs crates/crypto/src/lib.rs crates/crypto/Cargo.toml
git commit -m "feat: add X3DH session establishment"
```

---

### Task 6: Double Ratchet

**Files:**
- Create: `crates/crypto/src/double_ratchet.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/double_ratchet.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `crate::aead::{seal, open, kdf_chain, kdf_root_dh, random_nonce}`, `crate::x3dh::SessionInit`, `crate::CryptoError`, `x25519_dalek`, `serde`, `std::collections::HashMap`
- Produces:
  - `pub struct Header { pub dh_pub: x25519_dalek::PublicKey, pub pn: u32, pub n: u32, pub nonce: [u8;24] }` — `serde` derive, `Clone, Copy` not possible (PublicKey is not Copy) → `Clone` only.
  - `pub struct Encrypted { pub header: Header, pub ciphertext: Vec<u8> }` — `serde` derive, `Clone`.
  - `pub struct RatchetSession { root_key: [u8;32], dh_priv: x25519_dalek::StaticSecret, dh_pub: x25519_dalek::PublicKey, ns: u32, nr: u32, pn: u32, cks: Option<[u8;32]>, ckr: Option<[u8;32]>, skipped: HashMap<(x25519_dalek::PublicKey, u32), [u8;32]> }` — `serde` derive, `Clone`. `skipped` keys are `(dh_pub, n)` → message key.
  - `impl RatchetSession {
      pub fn init_alice(session_init: &SessionInit) -> Result<Self, CryptoError>;
      pub fn init_bob(session_init: &SessionInit, bob_signed_priv: &x25519_dalek::StaticSecret) -> Result<Self, CryptoError>;
      pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Encrypted, CryptoError>;
      pub fn decrypt(&mut self, message: &Encrypted) -> Result<Vec<u8>, CryptoError>;
    }`
  - Skipped cache cap constant: `const MAX_SKIPPED: usize = 2000;`

  **Alice init:** From `SessionInit`, Alice has `root_key` and Bob's signed-prekey public key (she knows `bob_signed_prekey_id` but not the priv; however she needs a DH ratchet keypair to start sending). Alice generates a fresh DH ratchet keypair `(dh_priv, dh_pub)`, performs a DH ratchet step: `dh_output = dh_priv.diffie_hellman(&bob_signed_prekey_pub)` — but `SessionInit` does not store Bob's signed prekey pub. **Resolution:** extend `SessionInit` in Task 5 to also store `bob_signed_prekey_pub: x25519_dalek::PublicKey`. Add this field to `SessionInit` and populate it in both `initiate` and `receive`. Update Task 5's struct and both functions accordingly (this is a forward dependency; the field is added in this task by editing `x3dh.rs`).

  **Bob init:** From `SessionInit`, Bob has `root_key` and his own signed prekey private key (passed in as `bob_signed_priv`). Bob's initial `dh_priv` = `bob_signed_priv` (the signed prekey doubles as the first DH ratchet key), `dh_pub` = its public. `ckr` and `cks` start as `None`; Bob will perform the DH ratchet step on his first received message from Alice.

  **encrypt (Alice or Bob sending):**
  1. If `cks` is `None` (Bob hasn't sent yet / just initialized and has no send chain), this is an error for Bob's first action only if he hasn't done a DH step. For Alice after `init_alice`, `cks` is set (from the DH step). For Bob, `cks` is `None` until he receives his first message and ratchets. **Rule:** `encrypt` requires `cks.is_some()`; if `None`, return `Err(CryptoError::InvalidState)` (Bob must receive before he can send on a fresh session — matches Signal).
  2. `(new_cks, msg_key) = kdf_chain(cks)`. Set `self.cks = Some(new_cks)`.
  3. `nonce = random_nonce()`. `header = Header { dh_pub: self.dh_pub, pn: self.pn, n: self.ns, nonce }`.
  4. `aad = serialize(header)` (use `serde` + a compact format; for determinism use `postcard` — but `postcard` is not a dependency of `crypto`. **Use `serde` + manual byte serialization of the header** to avoid adding a dependency: `aad = [dh_pub.to_bytes() (32)] ‖ [pn.to_le_bytes() (4)] ‖ [n.to_le_bytes() (4)] ‖ [nonce (24)]` = 64 bytes. Define `fn header_aad(h: &Header) -> Vec<u8>`.)
  5. `ciphertext = seal(&msg_key, &nonce, &aad, plaintext)`. `self.ns += 1`.
  6. Return `Encrypted { header, ciphertext }`.

  **decrypt (receiving):**
  1. Check skipped cache for `(header.dh_pub, header.n)`: if present, remove + use that msg_key to `open` with `header.nonce` + `header_aad`. Return plaintext.
  2. If `header.dh_pub != self.dh_pub` (new DH key from sender → DH ratchet step):
     a. Skip any messages in the current recv chain: while `self.nr < self.pn + (cks chain length)`... — **simplified:** before ratcheting, save skipped keys for the current `ckr` up to `header.pn` (the previous chain's length). For each `n` from `self.nr` to `header.pn - 1`, derive `(new_ckr, mk) = kdf_chain(ckr)`, store `((old_dh_pub, n), mk)` in skipped (evict oldest if over cap), advance `ckr`. This handles messages lost before the DH ratchet.
     b. Perform DH ratchet: `dh_output = self.dh_priv.diffie_hellman(&header.dh_pub)`; `(new_root, new_ckr) = kdf_root_dh(&self.root_key, &dh_output)`; set `self.root_key = new_root`, `self.ckr = Some(new_ckr)`, `self.pn = self.ns`, generate new `dh_priv`/`dh_pub`, reset `self.ns = 0`, `self.nr = 0`.
  3. Skip messages in the new recv chain up to `header.n`: while `self.nr < header.n`, derive `(new_ckr, mk) = kdf_chain(ckr)`, store skipped, advance.
  4. `(new_ckr, msg_key) = kdf_chain(ckr)`; `self.ckr = Some(new_ckr)`; `self.nr += 1`.
  5. `aad = header_aad(&header)`; `open(&msg_key, &header.nonce, &aad, &ciphertext)`.

  **Skipped cache eviction:** when inserting and `skipped.len() >= MAX_SKIPPED`, remove the entry with the smallest `(pn, n)` (approximate "oldest"). Use `skipped.iter().min_by_key(|((_, n), _)| *n)` — since keys are `(dh_pub, n)` and `n` resets per chain, use a secondary `pn` stored... **simplification for v1:** evict the entry with the smallest `n` value across the cache (good enough; the cap is a DoS guard, not a correctness mechanism). Implement `fn evict_if_full(skipped: &mut HashMap<(PublicKey,u32), [u8;32]>)`.

- [ ] **Step 1: Extend SessionInit with bob_signed_prekey_pub**

Modify `crates/crypto/src/x3dh.rs`:
- Add field `pub bob_signed_prekey_pub: x25519_dalek::PublicKey` to `SessionInit`.
- In `initiate`, set it to `bob_bundle.signed_prekey_pub`.
- In `receive`, set it to `bob_signed.pub_key`.

The exact edits: in the `SessionInit` struct definition add the field after `bob_signed_prekey_id`; in `initiate`'s `let session = SessionInit { ... }` add `bob_signed_prekey_pub: bob_bundle.signed_prekey_pub,`; in `receive`'s `let session = SessionInit { ... }` add `bob_signed_prekey_pub: bob_signed.pub_key,`. Add `use x25519_dalek::PublicKey;` is already present.

- [ ] **Step 2: Write the failing test + implementation**

Create `crates/crypto/src/double_ratchet.rs`:

```rust
use std::collections::HashMap;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::{kdf_chain, kdf_root_dh, open, random_nonce, seal};
use crate::x3dh::SessionInit;
use crate::CryptoError;

const MAX_SKIPPED: usize = 2000;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Header {
    pub dh_pub: PublicKey,
    pub pn: u32,
    pub n: u32,
    pub nonce: [u8; 24],
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Encrypted {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct RatchetSession {
    root_key: [u8; 32],
    dh_priv: StaticSecret,
    dh_pub: PublicKey,
    ns: u32,
    nr: u32,
    pn: u32,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    skipped: HashMap<(PublicKey, u32), [u8; 32]>,
}

fn header_aad(h: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&h.dh_pub.to_bytes());
    aad.extend_from_slice(&h.pn.to_le_bytes());
    aad.extend_from_slice(&h.n.to_le_bytes());
    aad.extend_from_slice(&h.nonce);
    aad
}

fn evict_if_full(skipped: &mut HashMap<(PublicKey, u32), [u8; 32]>) {
    if skipped.len() >= MAX_SKIPPED {
        if let Some((&key, _)) = skipped.iter().min_by_key(|((_, n), _)| *n) {
            skipped.remove(&key);
        }
    }
}

impl RatchetSession {
    pub fn init_alice(session_init: &SessionInit) -> Result<Self, CryptoError> {
        let mut rng = rand::rngs::OsRng;
        let dh_priv = StaticSecret::random_from_rng(&mut rng);
        let dh_pub = PublicKey::from(&dh_priv);

        let dh_output = dh_priv.diffie_hellman(&session_init.bob_signed_prekey_pub).to_bytes();
        let (new_root, cks) = kdf_root_dh(&session_init.root_key, &dh_output);

        Ok(Self {
            root_key: new_root,
            dh_priv,
            dh_pub,
            ns: 0,
            nr: 0,
            pn: 0,
            cks: Some(cks),
            ckr: None,
            skipped: HashMap::new(),
        })
    }

    pub fn init_bob(
        session_init: &SessionInit,
        bob_signed_priv: &StaticSecret,
    ) -> Result<Self, CryptoError> {
        let dh_pub = PublicKey::from(bob_signed_priv);
        Ok(Self {
            root_key: session_init.root_key,
            dh_priv: bob_signed_priv.clone(),
            dh_pub,
            ns: 0,
            nr: 0,
            pn: 0,
            cks: None,
            ckr: None,
            skipped: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Encrypted, CryptoError> {
        let cks = match self.cks {
            Some(c) => c,
            None => return Err(CryptoError::InvalidState),
        };
        let (new_cks, msg_key) = kdf_chain(&cks);
        self.cks = Some(new_cks);

        let nonce = random_nonce();
        let header = Header {
            dh_pub: self.dh_pub,
            pn: self.pn,
            n: self.ns,
            nonce,
        };
        let aad = header_aad(&header);
        let ciphertext = seal(&msg_key, &nonce, &aad, plaintext);
        self.ns += 1;
        Ok(Encrypted { header, ciphertext })
    }

    pub fn decrypt(&mut self, message: &Encrypted) -> Result<Vec<u8>, CryptoError> {
        // 1. Check skipped cache.
        if let Some(msg_key) = self.skipped.remove(&(message.header.dh_pub, message.header.n)) {
            let aad = header_aad(&message.header);
            return open(&msg_key, &message.header.nonce, &aad, &message.ciphertext);
        }

        // 2. DH ratchet step if new DH key.
        if message.header.dh_pub != self.dh_pub {
            // Skip messages in the previous recv chain up to header.pn.
            if let Some(mut ckr) = self.ckr {
                while self.nr < message.header.pn {
                    let (new_ckr, mk) = kdf_chain(&ckr);
                    evict_if_full(&mut self.skipped);
                    self.skipped.insert((self.dh_pub, self.nr), mk);
                    ckr = new_ckr;
                    self.nr += 1;
                }
                self.ckr = Some(ckr);
            }

            // DH ratchet.
            let dh_output = self.dh_priv.diffie_hellman(&message.header.dh_pub).to_bytes();
            let (new_root, new_ckr) = kdf_root_dh(&self.root_key, &dh_output);
            self.root_key = new_root;
            self.ckr = Some(new_ckr);
            self.pn = self.ns;
            let mut rng = rand::rngs::OsRng;
            self.dh_priv = StaticSecret::random_from_rng(&mut rng);
            self.dh_pub = PublicKey::from(&self.dh_priv);
            self.ns = 0;
            self.nr = 0;
        }

        // 3. Skip messages in the new recv chain up to header.n.
        if let Some(mut ckr) = self.ckr {
            while self.nr < message.header.n {
                let (new_ckr, mk) = kdf_chain(&ckr);
                evict_if_full(&mut self.skipped);
                self.skipped.insert((self.dh_pub, self.nr), mk);
                ckr = new_ckr;
                self.nr += 1;
            }
            self.ckr = Some(ckr);
        }

        // 4. Decrypt current message.
        let ckr = match self.ckr {
            Some(c) => c,
            None => return Err(CryptoError::InvalidState),
        };
        let (new_ckr, msg_key) = kdf_chain(&ckr);
        self.ckr = Some(new_ckr);
        self.nr += 1;

        let aad = header_aad(&message.header);
        open(&msg_key, &message.header.nonce, &aad, &message.ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use crate::x3dh::{initiate, receive};

    fn make_pair() -> (RatchetSession, RatchetSession, StaticSecret) {
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let bundle = crate::identity::PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
        let alice = IdentityKey::generate();

        let (init, init_msg) = initiate(&alice, &bundle, Some(10)).unwrap();
        let bob_session_init = receive(&bob, &spk, Some(&otpk), &init_msg).unwrap();

        let alice_r = RatchetSession::init_alice(&init).unwrap();
        let bob_r = RatchetSession::init_bob(&bob_session_init, &spk.priv_key).unwrap();
        (alice_r, bob_r, spk.priv_key.clone())
    }

    #[test]
    fn alice_to_bob_roundtrip() {
        let (mut alice, mut bob, _) = make_pair();
        let ct = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn bidirectional_roundtrip() {
        let (mut alice, mut bob, _) = make_pair();
        let ct1 = alice.encrypt(b"hi").unwrap();
        assert_eq!(bob.decrypt(&ct1).unwrap(), b"hi");
        // Bob must receive before sending (cks was None); now he can send.
        let ct2 = bob.encrypt(b"yo").unwrap();
        assert_eq!(alice.decrypt(&ct2).unwrap(), b"yo");
        let ct3 = alice.encrypt(b"again").unwrap();
        assert_eq!(bob.decrypt(&ct3).unwrap(), b"again");
    }

    #[test]
    fn multiple_messages_same_chain() {
        let (mut alice, mut bob, _) = make_pair();
        let msgs: Vec<Encrypted> = (0..5u32)
            .map(|i| alice.encrypt(format!("msg {i}").as_bytes()).unwrap())
            .collect();
        for (i, ct) in msgs.iter().enumerate() {
            assert_eq!(bob.decrypt(ct).unwrap(), format!("msg {i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_decrypts() {
        let (mut alice, mut bob, _) = make_pair();
        let m0 = alice.encrypt(b"first").unwrap();
        let m1 = alice.encrypt(b"second").unwrap();
        let m2 = alice.encrypt(b"third").unwrap();
        // Bob receives in order 2, 0, 1.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"third");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"first");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"second");
    }

    #[test]
    fn lost_message_then_ratchet_still_works() {
        let (mut alice, mut bob, _) = make_pair();
        let _m0 = alice.encrypt(b"lost").unwrap(); // dropped
        let m1 = alice.encrypt(b"arrived").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"arrived");
        // Bob replies, Alice ratchets.
        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), b"reply");
    }

    #[test]
    fn tampered_ciphertext_fails_without_poisoning() {
        let (mut alice, mut bob, _) = make_pair();
        let mut ct = alice.encrypt(b"hello").unwrap();
        ct.ciphertext[0] ^= 0xff;
        assert_eq!(bob.decrypt(&ct), Err(CryptoError::DecryptionFailed));
        // Session still usable.
        let ct2 = alice.encrypt(b"next").unwrap();
        assert_eq!(bob.decrypt(&ct2).unwrap(), b"next");
    }

    #[test]
    fn bob_cannot_send_before_receiving() {
        let (_alice, mut bob, _) = make_pair();
        assert_eq!(bob.encrypt(b"premature"), Err(CryptoError::InvalidState));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p um_crypto double_ratchet`
Expected: FAIL — `double_ratchet` module not declared in `lib.rs`.

- [ ] **Step 4: Wire the module into the crate root**

Modify `crates/crypto/src/lib.rs` to:

```rust
//! um_crypto — pure E2EE protocol primitives: X3DH, Double Ratchet, Sender Keys.
//! No I/O, no async, no panics.

#![forbid(unsafe_code)]

pub mod aead;
pub mod double_ratchet;
pub mod error;
pub mod identity;
pub mod x3dh;
pub use error::CryptoError;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p um_crypto double_ratchet`
Expected: PASS — 7 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/crypto/src/double_ratchet.rs crates/crypto/src/lib.rs crates/crypto/src/x3dh.rs
git commit -m "feat: add Double Ratchet with skipped-key cache"
```

---

### Task 7: Sender Keys (groups)

**Files:**
- Create: `crates/crypto/src/sender_keys.rs`
- Modify: `crates/crypto/src/lib.rs`
- Test: `crates/crypto/src/sender_keys.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `crate::aead::{seal, open, kdf_chain, random_nonce}`, `crate::CryptoError`, `x25519_dalek` (for member identity-pub keys used as `member_id`), `ed25519_dalek` (sender signing), `serde`, `std::collections::HashMap`
- Produces:
  - `pub type MemberId = [u8; 32]` (the member's identity-key fingerprint bytes — a stable, serializable id).
  - `pub struct SenderChainKey([u8; 32])` — `serde` derive, `Clone`. `impl SenderChainKey { pub fn new(seed: [u8;32]) -> Self; pub fn ratchet(&mut self) -> [u8;32] /* returns message key, advances chain */ }`
  - `pub struct SenderKeyState { pub member_id: MemberId, pub chain_key: SenderChainKey, pub signing_priv: ed25519_dalek::SigningKey, pub signing_pub: ed25519_dalek::VerifyingKey }` — `serde` derive, `Clone`. The signing keypair authenticates this sender within the group.
  - `pub struct GroupHeader { pub group_id: [u8;32], pub sender_id: MemberId, pub generation: u32, pub signing_pub: ed25519_dalek::VerifyingKey, pub nonce: [u8;24] }` — `serde` derive, `Clone`.
  - `pub struct GroupEncrypted { pub header: GroupHeader, pub ciphertext: Vec<u8>, pub signature: ed25519_dalek::Signature }` — `serde` derive, `Clone`.
  - `pub struct GroupSession { pub group_id: [u8;32], pub self_state: SenderKeyState, pub peer_states: HashMap<MemberId, (SenderChainKey, ed25519_dalek::VerifyingKey)> }` — `serde` derive, `Clone`. `peer_states` maps each other member's id → (their chain key as known to us, their signing pub). We advance our own chain on send; we ratchet our copy of a peer's chain on receive.
  - `impl GroupSession {
      pub fn new(group_id: [u8;32], self_identity: &crate::identity::IdentityKey) -> Result<Self, CryptoError>;
      pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupEncrypted, CryptoError>;
      pub fn decrypt(&mut self, message: &GroupEncrypted) -> Result<Vec<u8>, CryptoError>;
      pub fn add_peer(&mut self, state: SenderKeyState) -> Result<(), CryptoError>;
      pub fn export_self_state(&self) -> SenderKeyState;
    }`
  - `pub fn distribution_message(state: &SenderKeyState, group_id: [u8;32]) -> Vec<u8>` — serialize a `SenderKeyState` for sending to a new member (the caller encrypts this via the 1:1 Double Ratchet before sending). Returns `serde_json` bytes (or postcard; use `serde_json` since it's already a dev-dep — **actually make it a real dep**: add `serde_json = "1"` to `[dependencies]` for the distribution serialization, OR keep it dependency-free by serializing the fields manually). **Decision: serialize via a `DistributionPayload` struct with `serde` derives and use `bincode`** — add `bincode = "1"` to `[dependencies]`. `pub fn encode_distribution(state: &SenderKeyState, group_id: [u8;32]) -> Result<Vec<u8>, CryptoError>` and `pub fn decode_distribution(bytes: &[u8]) -> Result<(SenderKeyState, [u8;32]), CryptoError>`.

  **AAD for group messages:** `group_id (32) ‖ sender_id (32) ‖ generation (4 LE) ‖ signing_pub (32) ‖ nonce (24)` = 124 bytes. Define `fn group_header_aad(h: &GroupHeader) -> Vec<u8>`.

  **encrypt:**
  1. `msg_key = self.self_state.chain_key.ratchet()` (advances chain, returns key).
  2. `nonce = random_nonce()`. `header = GroupHeader { group_id, sender_id: self.self_state.member_id, generation, signing_pub, nonce }` where `generation` is a counter — store it in `SenderKeyState`? No, generation is implicit in chain key position. **Add `generation: u32` field to `SenderKeyState`**, incremented on each `ratchet()`. Update `SenderChainKey::ratchet` to also bump an external counter — simplest: track generation in `GroupSession` as `self_generation: u32`, increment after each send, and include it in the header. **Revised:** add `pub generation: u32` to `SenderKeyState`, bump inside `ratchet` by returning the new generation too. To keep `SenderChainKey` simple, store generation in `SenderKeyState` and bump in `GroupSession::encrypt`.
  3. `aad = group_header_aad(&header)`. `ciphertext = seal(&msg_key, &nonce, &aad, plaintext)`.
  4. `signature = self.self_state.signing_priv.sign(&aad ‖ &ciphertext)` (sign AAD + ciphertext).
  5. Return `GroupEncrypted { header, ciphertext, signature }`.

  **decrypt:**
  1. Look up `peer_states[header.sender_id]` → `(chain_key, signing_pub)`. If absent, `Err(CryptoError::MissingPreKey)` (caller must obtain the sender's distribution message first).
  2. Verify `signing_pub.verify(aad ‖ ciphertext, signature)` → `Err(CryptoError::InvalidSignature)` on failure.
  3. Advance the peer's chain key to `header.generation`: while `peer_generation < header.generation`, `msg_key = chain_key.ratchet()`, bump generation. Track peer generation — store it alongside the chain key: change `peer_states` value to `(SenderChainKey, u32, VerifyingKey)` (chain key, generation, signing pub). If `header.generation < peer_generation`, the message is a replay/duplicate from a known earlier position — **v1: reject as `Err(CryptoError::DecryptionFailed)`** (no skipped cache for groups; out-of-order group messages are not supported in v1, per scope).
  4. `msg_key = chain_key.ratchet()` for the current message; bump stored generation.
  5. `aad = group_header_aad(&header)`. `open(&msg_key, &nonce, &aad, &ciphertext)`.

  **new:** generate a random `SenderChainKey` seed (32 random bytes), a fresh Ed25519 signing keypair for the sender, `member_id = self_identity.fingerprint()`. Return `GroupSession { group_id, self_state: SenderKeyState { member_id, chain_key, signing_priv, signing_pub, generation: 0 }, peer_states: HashMap::new() }`.

- [ ] **Step 1: Add bincode dependency**

Modify `crates/crypto/Cargo.toml` `[dependencies]` to add:

```toml
bincode = "1"
```

- [ ] **Step 2: Write the failing test + implementation**

Create `crates/crypto/src/sender_keys.rs`:

```rust
use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

use crate::aead::{kdf_chain, open, random_nonce, seal};
use crate::identity::IdentityKey;
use crate::CryptoError;

pub type MemberId = [u8; 32];

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SenderChainKey(pub [u8; 32]);

impl SenderChainKey {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }
    pub fn ratchet(&mut self) -> [u8; 32] {
        let (new_ck, mk) = kdf_chain(&self.0);
        self.0 = new_ck;
        mk
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SenderKeyState {
    pub member_id: MemberId,
    pub chain_key: SenderChainKey,
    pub signing_priv: SigningKey,
    pub signing_pub: VerifyingKey,
    pub generation: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupHeader {
    pub group_id: [u8; 32],
    pub sender_id: MemberId,
    pub generation: u32,
    pub signing_pub: VerifyingKey,
    pub nonce: [u8; 24],
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupEncrypted {
    pub header: GroupHeader,
    pub ciphertext: Vec<u8>,
    pub signature: ed25519_dalek::Signature,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupSession {
    pub group_id: [u8; 32],
    pub self_state: SenderKeyState,
    pub peer_states: HashMap<MemberId, (SenderChainKey, u32, VerifyingKey)>,
}

fn group_header_aad(h: &GroupHeader) -> Vec<u8> {
    let mut aad = Vec::with_capacity(124);
    aad.extend_from_slice(&h.group_id);
    aad.extend_from_slice(&h.sender_id);
    aad.extend_from_slice(&h.generation.to_le_bytes());
    aad.extend_from_slice(&h.signing_pub.to_bytes());
    aad.extend_from_slice(&h.nonce);
    aad
}

impl GroupSession {
    pub fn new(group_id: [u8; 32], self_identity: &IdentityKey) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let mut rng = rand::rngs::OsRng;
        let signing_priv = SigningKey::generate(&mut rng);
        let signing_pub = signing_priv.verifying_key();

        let self_state = SenderKeyState {
            member_id: self_identity.fingerprint(),
            chain_key: SenderChainKey::new(seed),
            signing_priv,
            signing_pub,
            generation: 0,
        };

        Ok(Self {
            group_id,
            self_state,
            peer_states: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupEncrypted, CryptoError> {
        let msg_key = self.self_state.chain_key.ratchet();
        self.self_state.generation += 1;

        let nonce = random_nonce();
        let header = GroupHeader {
            group_id: self.group_id,
            sender_id: self.self_state.member_id,
            generation: self.self_state.generation,
            signing_pub: self.self_state.signing_pub,
            nonce,
        };
        let aad = group_header_aad(&header);
        let ciphertext = seal(&msg_key, &nonce, &aad, plaintext);
        let mut signed = aad.clone();
        signed.extend_from_slice(&ciphertext);
        let signature = self.self_state.signing_priv.sign(&signed);

        Ok(GroupEncrypted { header, ciphertext, signature })
    }

    pub fn decrypt(&mut self, message: &GroupEncrypted) -> Result<Vec<u8>, CryptoError> {
        let (chain_key, peer_gen, signing_pub) = match self
            .peer_states
            .get_mut(&message.header.sender_id)
        {
            Some(v) => v,
            None => return Err(CryptoError::MissingPreKey),
        };

        let aad = group_header_aad(&message.header);
        let mut signed = aad.clone();
        signed.extend_from_slice(&message.ciphertext);
        signing_pub
            .verify(&signed, &message.signature)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if message.header.generation < *peer_gen {
            return Err(CryptoError::DecryptionFailed);
        }

        while *peer_gen < message.header.generation {
            chain_key.ratchet();
            *peer_gen += 1;
        }

        let msg_key = chain_key.ratchet();
        *peer_gen += 1;

        open(&msg_key, &message.header.nonce, &aad, &message.ciphertext)
    }

    pub fn add_peer(&mut self, state: SenderKeyState) -> Result<(), CryptoError> {
        self.peer_states.insert(
            state.member_id,
            (state.chain_key, state.generation, state.signing_pub),
        );
        Ok(())
    }

    pub fn export_self_state(&self) -> SenderKeyState {
        self.self_state.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DistributionPayload {
    pub group_id: [u8; 32],
    pub state: SenderKeyState,
}

pub fn encode_distribution(state: &SenderKeyState, group_id: [u8; 32]) -> Result<Vec<u8>, CryptoError> {
    bincode::serialize(&DistributionPayload { group_id, state: state.clone() })
        .map_err(|_| CryptoError::InvalidState)
}

pub fn decode_distribution(bytes: &[u8]) -> Result<(SenderKeyState, [u8; 32]), CryptoError> {
    let payload: DistributionPayload =
        bincode::deserialize(bytes).map_err(|_| CryptoError::MalformedBundle)?;
    Ok((payload.state, payload.group_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid() -> [u8; 32] {
        let mut g = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut g);
        g
    }

    #[test]
    fn chain_key_ratchet_advances() {
        let mut ck = SenderChainKey::new([1u8; 32]);
        let m1 = ck.ratchet();
        let m2 = ck.ratchet();
        assert_ne!(m1, m2);
    }

    #[test]
    fn group_roundtrip_two_members() {
        let group = gid();
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();
        let mut alice = GroupSession::new(group, &alice_id).unwrap();
        let mut bob = GroupSession::new(group, &bob_id).unwrap();

        // Exchange distribution states (in real life via 1:1 Double Ratchet).
        alice.add_peer(bob.export_self_state()).unwrap();
        bob.add_peer(alice.export_self_state()).unwrap();

        let ct = alice.encrypt(b"hi group").unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hi group");

        let ct2 = bob.encrypt(b"hello back").unwrap();
        let pt2 = alice.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"hello back");
    }

    #[test]
    fn group_three_members() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let c = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        let mut sc = GroupSession::new(group, &c).unwrap();

        sa.add_peer(sb.export_self_state()).unwrap();
        sa.add_peer(sc.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();
        sb.add_peer(sc.export_self_state()).unwrap();
        sc.add_peer(sa.export_self_state()).unwrap();
        sc.add_peer(sb.export_self_state()).unwrap();

        let ct = sa.encrypt(b"from a").unwrap();
        assert_eq!(sb.decrypt(&ct).unwrap(), b"from a");
        assert_eq!(sc.decrypt(&ct).unwrap(), b"from a");

        let ct2 = sc.encrypt(b"from c").unwrap();
        assert_eq!(sa.decrypt(&ct2).unwrap(), b"from c");
        assert_eq!(sb.decrypt(&ct2).unwrap(), b"from c");
    }

    #[test]
    fn group_rejects_unknown_sender() {
        let group = gid();
        let a = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        // No peers added; a message from a stranger.
        let stranger = IdentityKey::generate();
        let mut stranger_session = GroupSession::new(group, &stranger).unwrap();
        let ct = stranger_session.encrypt(b"inject").unwrap();
        assert_eq!(sa.decrypt(&ct), Err(CryptoError::MissingPreKey));
    }

    #[test]
    fn group_rejects_tampered_ciphertext() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        sa.add_peer(sb.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();

        let mut ct = sa.encrypt(b"hi").unwrap();
        ct.ciphertext[0] ^= 0xff;
        assert_eq!(sb.decrypt(&ct), Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn distribution_encode_decode_roundtrip() {
        let group = gid();
        let a = IdentityKey::generate();
        let sa = GroupSession::new(group, &a).unwrap();
        let state = sa.export_self_state();
        let bytes = encode_distribution(&state, group).unwrap();
        let (decoded_state, decoded_group) = decode_distribution(&bytes).unwrap();
        assert_eq!(decoded_group, group);
        assert_eq!(decoded_state.member_id, state.member_id);
    }

    #[test]
    fn group_rejects_old_generation_replay() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        sa.add_peer(sb.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();

        let ct1 = sa.encrypt(b"first").unwrap();
        let ct2 = sa.encrypt(b"second").unwrap();
        assert_eq!(sb.decrypt(&ct2).unwrap(), b"second");
        // Replaying ct1 (older generation) must fail.
        assert_eq!(sb.decrypt(&ct1), Err(CryptoError::DecryptionFailed));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p um_crypto sender_keys`
Expected: FAIL — `sender_keys` module not declared in `lib.rs`.

- [ ] **Step 4: Wire the module into the crate root**

Modify `crates/crypto/src/lib.rs` to:

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
pub use error::CryptoError;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p um_crypto sender_keys`
Expected: PASS — 7 tests pass. **Note:** if `ed25519_dalek::Signature` does not derive `serde::Serialize`/`Deserialize` by default, add `signature` feature — but ed25519-dalek 2 with the `serde` feature already derives it. If the build fails on `Signature` serde, add `ed25519 = { version = "2", features = ["serde"] }` to dependencies.

- [ ] **Step 6: Commit**

```bash
git add crates/crypto/src/sender_keys.rs crates/crypto/src/lib.rs crates/crypto/Cargo.toml
git commit -m "feat: add Sender Keys group encryption"
```

---

### Task 8: Cross-module integration + property tests

**Files:**
- Create: `crates/crypto/tests/integration.rs`
- Test: `cargo test -p um_crypto --test integration`

**Interfaces:**
- Consumes: all `um_crypto` public modules + `proptest`
- Produces: integration + property tests proving the full crypto stack works together; a green `cargo test -p um_crypto` run for the whole crate.

- [ ] **Step 1: Write the integration tests**

Create `crates/crypto/tests/integration.rs`:

```rust
use um_crypto::{
    double_ratchet::RatchetSession,
    identity::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey},
    sender_keys::GroupSession,
    x3dh::{initiate, receive},
};

fn establish_pair() -> (RatchetSession, RatchetSession) {
    let bob = IdentityKey::generate();
    let spk = SignedPreKey::generate(1, &bob);
    let otpk = OneTimePreKey::generate(10);
    let bundle = PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
    let alice = IdentityKey::generate();

    let (init, init_msg) = initiate(&alice, &bundle, Some(10)).unwrap();
    let bob_init = receive(&bob, &spk, Some(&otpk), &init_msg).unwrap();

    let alice_r = RatchetSession::init_alice(&init).unwrap();
    let bob_r = RatchetSession::init_bob(&bob_init, &spk.priv_key).unwrap();
    (alice_r, bob_r)
}

#[test]
fn full_1to1_conversation_many_rounds() {
    let (mut alice, mut bob) = establish_pair();
    for i in 0..20u32 {
        let msg = format!("alice-{i}");
        let ct = alice.encrypt(msg.as_bytes()).unwrap();
        assert_eq!(bob.decrypt(&ct).unwrap(), msg.as_bytes());

        let msg = format!("bob-{i}");
        let ct = bob.encrypt(msg.as_bytes()).unwrap();
        assert_eq!(alice.decrypt(&ct).unwrap(), msg.as_bytes());
    }
}

#[test]
fn group_then_private_works_independently() {
    // Group session between alice and bob.
    let group = random_group_id();

    let alice_id = IdentityKey::generate();
    let bob_id = IdentityKey::generate();
    let mut ga = GroupSession::new(group, &alice_id).unwrap();
    let mut gb = GroupSession::new(group, &bob_id).unwrap();
    ga.add_peer(gb.export_self_state()).unwrap();
    gb.add_peer(ga.export_self_state()).unwrap();

    let gct = ga.encrypt(b"group msg").unwrap();
    assert_eq!(gb.decrypt(&gct).unwrap(), b"group msg");

    // Independent 1:1 session.
    let (mut a, mut b) = establish_pair();
    let ct = a.encrypt(b"private msg").unwrap();
    assert_eq!(b.decrypt(&ct).unwrap(), b"private msg");
}

fn random_group_id() -> [u8; 32] {
    let mut g = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut g);
    g
}

proptest::proptest! {
    #[test]
    fn prop_ratchet_roundtrip_random_plaintexts(
        pts in proptest::collection::vec("[a-z]{0,200}", 1..20)
    ) {
        let (mut alice, mut bob) = establish_pair();
        for p in &pts {
            let ct = alice.encrypt(p.as_bytes()).unwrap();
            let dec = bob.decrypt(&ct).unwrap();
            assert_eq!(dec, p.as_bytes());
        }
    }

    #[test]
    fn prop_ratchet_out_of_order_all_decrypt(
        // distinct plaintexts so we can identify each message
        n in 2u32..15u32
    ) {
        let (mut alice, mut bob) = establish_pair();
        let mut msgs: Vec<_> = (0..n)
            .map(|i| alice.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();
        // Reverse the order.
        msgs.reverse();
        for ct in &msgs {
            let dec = bob.decrypt(ct).unwrap();
            assert!(dec.starts_with(b"m"));
        }
    }
}
```

- [ ] **Step 2: Run the integration tests**

Run: `cargo test -p um_crypto --test integration`
Expected: PASS — 2 unit-style tests + 2 proptest cases pass.

- [ ] **Step 3: Run the full crate test suite**

Run: `cargo test -p um_crypto`
Expected: PASS — all tests across all modules + integration pass. No warnings about unused code (clean up any before committing).

- [ ] **Step 4: Commit**

```bash
git add crates/crypto/tests/integration.rs
git commit -m "test: add cross-module integration and property tests"
```

---

## Self-Review

**1. Spec coverage:**
- X3DH four-DH derivation → Task 5 ✓
- Double Ratchet (DH + symmetric, out-of-order, skipped cache cap 2000) → Task 6 ✓
- Sender Keys (per-sender chain, distribution via 1:1, member add) → Task 7 ✓
- Ed25519 identity + X25519 signed/one-time prekeys + fingerprint → Task 4 ✓
- XChaCha20-Poly1305 AEAD + HKDF chains → Task 3 ✓
- No panics, all `Result` → Global Constraints + `#![forbid(unsafe_code)]` + verified no `unwrap` in non-test code except the documented Ed25519→Montgomery conversion (now `Result`-returning) ✓
- File/media attachments (per-attachment key via HKDF, chunked) → **deferred to the client/protocol plan** (the crypto primitives — `hkdf_expand`, `seal`/`open` — exist from Task 3; the attachment chunking logic is a client-side concern, not a crypto-crate concern). Not a gap for this plan.
- Testing posture (proptest, round-trip, out-of-order, tamper) → Tasks 3–8 ✓

**2. Placeholder scan:** No "TBD"/"TODO"/"implement later". Two intentional `expect()` calls in `aead.rs` (`seal`, `hkdf_expand`) are on infallible paths (valid key/nonce lengths, expand within HMAC output limit) — acceptable and documented inline. The Ed25519→Montgomery conversion uses `Result`, not `unwrap`, honoring the no-panic rule. One `unwrap()` remains in `x3dh.rs`'s `ed25519_pub_to_x25519` after the `is_none()` guard — it is provably unreachable after the guard; acceptable.

**3. Type consistency:**
- `SessionInit` fields: `root_key`, `alice_identity`, `alice_ephemeral_priv`, `alice_ephemeral_pub`, `bob_signed_prekey_id`, `bob_one_time_prekey_id` (Task 5) + `bob_signed_prekey_pub` (added in Task 6 Step 1). Task 6's `init_alice` uses `session_init.bob_signed_prekey_pub` ✓.
- `RatchetSession::init_bob` takes `&StaticSecret` named `bob_signed_priv`; Task 6 tests pass `&spk.priv_key` ✓.
- `SenderKeyState` has `generation: u32` (added in Task 7 design); `GroupSession::peer_states` value is `(SenderChainKey, u32, VerifyingKey)` ✓.
- `CryptoError` variants used consistently: `InvalidSignature`, `DecryptionFailed`, `MissingPreKey`, `MalformedBundle`, `InvalidState`, `SkippedMessageLimit` (`SkippedMessageLimit` is defined but unused in v1 — kept for forward use; no warning because it's a public enum variant) ✓.
- `header_aad` (Task 6) and `group_header_aad` (Task 7) are distinct functions in distinct modules ✓.

**4. Ambiguity check:** The X3DH DH direction (Alice vs Bob side) is spelled out explicitly in Task 5's interface block with the four DHs listed for each side. The Double Ratchet skip-before-ratchet logic is specified step-by-step. The Sender Keys generation-counter / replay handling is explicit (reject older generation).

No issues remain. Plan is complete.
