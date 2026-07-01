//! Encrypted local store. The client persists identity, ratchet state,
//! contacts, and message history to a SQLite database. Sensitive rows are
//! encrypted with an XChaCha20-Poly1305 key derived from the user's
//! passphrase via Argon2id. The database file itself is not encrypted as a
//! whole (no SQLCipher FFI); individual value/blob columns are sealed, so a
//! stolen DB without the passphrase yields only structure + metadata, not
//! keys or plaintext.
//!
//! Layout:
//! - `kv(key TEXT PRIMARY KEY, blob BLOB)` — opaque sealed blobs for
//!   identity material and ratchet state (postcard of the typed object,
//!   then XChaCha-sealed).
//! - `contacts(identity_pub BLOB PRIMARY KEY, nickname TEXT, fingerprint BLOB)`
//!   — nickname/fingerprint are plaintext metadata (pub keys are already
//!   public).
//! - `messages(id INTEGER PRIMARY KEY, peer BLOB, direction INT, sealed BLOB,
//!   timestamp INT)` — `sealed` is the XChaCha-encrypted postcard of the
//!   message plaintext + status.
//!
//! No panics; all fallible paths return `Result<_, ClientError>`.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};

use crate::ClientError;

/// Argon2id memory cost (64 MiB), time cost 3, parallelism 4. Tuned for a
/// local interactive unlock, not a server.
const ARGON_M_KIB: u32 = 64 * 1024;
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 4;

/// XChaCha20-Poly1305 nonce length (24 bytes).
const NONCE_LEN: usize = 24;

/// A passphrase-derived key + the salt used to derive it. The salt is stored
/// in the DB (in `kv` under `store_salt`) so the same passphrase reproduces
/// the same key; the key itself never touches disk.
pub struct StoreKey {
    key: [u8; 32],
    salt: [u8; 16],
}

impl StoreKey {
    /// Derive a fresh key from `passphrase` with a random salt (new store).
    pub fn derive_new(passphrase: &str) -> Result<Self, ClientError> {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        Ok(Self { key, salt })
    }

    /// Derive a key from `passphrase` using an existing salt (unlocking).
    pub fn derive_with(passphrase: &str, salt: &[u8; 16]) -> Result<Self, ClientError> {
        let key = derive_key(passphrase, salt)?;
        Ok(Self { key, salt: *salt })
    }

    pub fn salt(&self) -> [u8; 16] {
        self.salt
    }
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], ClientError> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32))
        .map_err(|e| ClientError::Store(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| ClientError::Store(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// Seal `plaintext` (associated data = `aad`) under `key`. Returns
/// `nonce ‖ ciphertext` (nonce is random 24 bytes, prepended).
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| ClientError::Store(format!("seal: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce ‖ ciphertext` blob under `key` (associated data = `aad`).
fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, ClientError> {
    if blob.len() < NONCE_LEN {
        return Err(ClientError::Store("sealed blob too short".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| ClientError::Store("open failed (wrong passphrase or corrupt)".into()))
}

/// The encrypted store. Owns the SQLite connection and the derived key.
pub struct Store {
    conn: Connection,
    key: [u8; 32],
}

impl Store {
    /// Create a new encrypted store at `path`, deriving a fresh key from
    /// `passphrase`. Fails if the file already exists with data.
    pub fn create(path: &Path, passphrase: &str) -> Result<Self, ClientError> {
        if path.exists() && std::fs::metadata(path)?.len() > 0 {
            return Err(ClientError::Store("store already exists".into()));
        }
        let conn = Connection::open(path)?;
        let key = StoreKey::derive_new(passphrase)?;
        init_schema(&conn)?;
        // Persist the salt so the same passphrase can re-derive the key.
        set_kv_raw(&conn, "store_salt", &key.salt())?;
        // Seal a canary under the key so a wrong passphrase is detectable on
        // reopen (the AEAD tag won't verify with a different key).
        let canary = seal(&key.key, b"store_canary", b"um-store-ok")?;
        set_kv_raw(&conn, "store_canary", &canary)?;
        Ok(Self {
            conn,
            key: key.key,
        })
    }

    /// Open an existing store, re-deriving the key from `passphrase` + the
    /// stored salt. Fails (DecryptionFailed-ish) on a wrong passphrase.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, ClientError> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        let salt_bytes = get_kv_raw(&conn, "store_salt")?
            .ok_or_else(|| ClientError::Store("no store salt (not initialized)".into()))?;
        if salt_bytes.len() != 16 {
            return Err(ClientError::Store("corrupt salt".into()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let key = StoreKey::derive_with(passphrase, &salt)?;
        // Verify the passphrase against the canary sealed at create-time.
        // A wrong passphrase derives a different key and the AEAD tag fails.
        if let Some(canary) = get_kv_raw(&conn, "store_canary")? {
            open(&key.key, b"store_canary", &canary)
                .map_err(|_| ClientError::Store("wrong passphrase".into()))?;
        }
        Ok(Self {
            conn,
            key: key.key,
        })
    }

    /// Store a typed value under `key_name`, postcard-serialized then sealed.
    /// AAD = the key name (binds ciphertext to its slot).
    pub fn put<T: Serialize>(&self, key_name: &str, value: &T) -> Result<(), ClientError> {
        let bytes = postcard::to_allocvec(value)?;
        let sealed = seal(&self.key, key_name.as_bytes(), &bytes)?;
        set_kv_raw(&self.conn, key_name, &sealed)
    }

    /// Load and decrypt a typed value from `key_name`. Returns `None` if the
    /// slot is empty.
    pub fn get<T: DeserializeOwned>(&self, key_name: &str) -> Result<Option<T>, ClientError> {
        match get_kv_raw(&self.conn, key_name)? {
            None => Ok(None),
            Some(sealed) => {
                let bytes = open(&self.key, key_name.as_bytes(), &sealed)?;
                Ok(Some(postcard::from_bytes(&bytes)?))
            }
        }
    }

    /// Persist a contact (plaintext metadata; pub keys are public).
    pub fn put_contact(
        &self,
        identity_pub: &[u8; 32],
        nickname: &str,
        fingerprint: &[u8; 32],
    ) -> Result<(), ClientError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO contacts (identity_pub, nickname, fingerprint) VALUES (?1, ?2, ?3)",
                rusqlite::params![identity_pub.as_slice(), nickname, fingerprint.as_slice()],
            )
            .map_err(|e| ClientError::Store(format!("put_contact: {e}")))?;
        Ok(())
    }

    /// List all contacts.
    pub fn contacts(&self) -> Result<Vec<Contact>, ClientError> {
        let mut stmt = self
            .conn
            .prepare("SELECT identity_pub, nickname, fingerprint FROM contacts")
            .map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                let pub_bytes: Vec<u8> = r.get(0)?;
                let nick: String = r.get(1)?;
                let fp: Vec<u8> = r.get(2)?;
                Ok((pub_bytes, nick, fp))
            })
            .map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (pub_bytes, nick, fp) = row.map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
            let mut p = [0u8; 32];
            let mut f = [0u8; 32];
            if pub_bytes.len() != 32 || fp.len() != 32 {
                return Err(ClientError::Store("corrupt contact row".into()));
            }
            p.copy_from_slice(&pub_bytes);
            f.copy_from_slice(&fp);
            out.push(Contact {
                identity_pub: p,
                nickname: nick,
                fingerprint: f,
            });
        }
        Ok(out)
    }
}

/// A stored contact: identity pub, display nickname, and fingerprint.
pub struct Contact {
    pub identity_pub: [u8; 32],
    pub nickname: String,
    pub fingerprint: [u8; 32],
}

fn init_schema(conn: &Connection) -> Result<(), ClientError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, blob BLOB);
         CREATE TABLE IF NOT EXISTS contacts (identity_pub BLOB PRIMARY KEY, nickname TEXT, fingerprint BLOB);
         CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, peer BLOB, direction INT, sealed BLOB, timestamp INT);",
    )
    .map_err(|e| ClientError::Store(format!("init_schema: {e}")))?;
    Ok(())
}

fn set_kv_raw(conn: &Connection, key: &str, blob: &[u8]) -> Result<(), ClientError> {
    conn.execute(
        "INSERT OR REPLACE INTO kv (key, blob) VALUES (?1, ?2)",
        rusqlite::params![key, blob],
    )
    .map_err(|e| ClientError::Store(format!("set_kv: {e}")))?;
    Ok(())
}

fn get_kv_raw(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, ClientError> {
    let mut stmt = conn
        .prepare("SELECT blob FROM kv WHERE key = ?1")
        .map_err(|e| ClientError::Store(format!("get_kv: {e}")))?;
    let mut rows = stmt
        .query(rusqlite::params![key])
        .map_err(|e| ClientError::Store(format!("get_kv: {e}")))?;
    match rows.next().map_err(|e| ClientError::Store(format!("get_kv: {e}")))? {
        Some(r) => {
            let blob: Vec<u8> = r.get(0).map_err(|e| ClientError::Store(format!("get_kv: {e}")))?;
            Ok(Some(blob))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        p.push(format!("um-store-test-{}.db", hex::encode(&bytes)));
        p
    }

    #[test]
    fn put_get_round_trips_typed_value() {
        let path = tmp();
        let store = Store::create(&path, "correct horse battery staple").unwrap();
        store.put("identity", &vec![1u8, 2, 3, 4]).unwrap();
        let got: Option<Vec<u8>> = store.get("identity").unwrap();
        assert_eq!(got, Some(vec![1, 2, 3, 4]));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn get_missing_returns_none() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let got: Option<Vec<u8>> = store.get("nope").unwrap();
        assert!(got.is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopen_with_correct_passphrase_round_trips() {
        let path = tmp();
        {
            let store = Store::create(&path, "hunter2").unwrap();
            store.put("ratchet", &b"secret state".to_vec()).unwrap();
        }
        // Reopen with the right passphrase; the value survives.
        let store = Store::open(&path, "hunter2").unwrap();
        let got: Option<Vec<u8>> = store.get("ratchet").unwrap();
        assert_eq!(got, Some(b"secret state".to_vec()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopen_with_wrong_passphrase_fails() {
        let path = tmp();
        {
            let store = Store::create(&path, "right").unwrap();
            store.put("ratchet", &b"state").unwrap();
        }
        // Wrong passphrase: the stored salt re-derives a different key, and
        // the canary open fails.
        let res = Store::open(&path, "wrong");
        assert!(res.is_err(), "wrong passphrase must fail");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn create_fails_if_file_already_has_data() {
        let path = tmp();
        {
            let _ = Store::create(&path, "pw").unwrap();
        }
        let res = Store::create(&path, "pw");
        assert!(res.is_err(), "re-create over existing store must fail");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn contacts_round_trip() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        store.put_contact(&[0x11; 32], "alice", &[0x22; 32]).unwrap();
        store.put_contact(&[0x33; 32], "bob", &[0x44; 32]).unwrap();
        let mut contacts = store.contacts().unwrap();
        contacts.sort_by_key(|c| c.identity_pub);
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].nickname, "alice");
        assert_eq!(contacts[1].nickname, "bob");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sealed_blob_tamper_fails_to_open() {
        let key = [0xAB; 32];
        let sealed = seal(&key, b"aad", b"plaintext").unwrap();
        // Flip a ciphertext byte.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(open(&key, b"aad", &tampered).is_err());
    }

    /// Minimal hex encoder for test temp-file names (avoids an extra dep).
    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
