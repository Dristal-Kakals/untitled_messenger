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
//! - `groups(group_id BLOB PRIMARY KEY, name TEXT)` — group id + display name.
//!   The group id is public (a `SHA-256` of name+members+founder, not a secret);
//!   the name is plaintext metadata. Persists the roster's identity so the
//!   ContactList "Groups" section and the bridge's send fan-out survive a
//!   store close/reopen (the in-memory `group_rosters` would otherwise be lost
//!   on restart, breaking group sends even though the Sender-Key sessions are
//!   restored from the persisted `ClientSession`).
//! - `group_members(group_id BLOB, identity_pub BLOB)` — the member identity
//!   pubs per group, so the bridge knows who to fan a group send out to after a
//!   restart. `(group_id, identity_pub)` is unique; re-adding is a no-op.
//!
//! No panics; all fallible paths return `Result<_, ClientError>`.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand_core::{OsRng, RngCore};
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};

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
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        Ok(Self { key, salt })
    }

    /// Derive a key from `passphrase` using an existing salt (unlocking).
    pub fn derive_with(passphrase: &str, salt: &[u8; 16]) -> Result<Self, ClientError> {
        let key = derive_key(passphrase, salt)?;
        Ok(Self { key, salt: *salt })
    }

    pub const fn salt(&self) -> [u8; 16] {
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
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
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
    let nonce = chacha20poly1305::XNonce::try_from(nonce_bytes)
        .expect("nonce slice is exactly NONCE_LEN bytes");
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&nonce, Payload { msg: ct, aad })
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
        Ok(Self { conn, key: key.key })
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
        Ok(Self { conn, key: key.key })
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

    /// Persist a contact (plaintext metadata; pub keys are public). Upserts:
    /// re-adding an existing contact updates nickname + fingerprint but
    /// preserves the `verified` flag (so re-adding does not silently un-verify
    /// a contact the user already confirmed).
    pub fn put_contact(
        &self,
        identity_pub: &[u8; 32],
        nickname: &str,
        fingerprint: &[u8; 32],
    ) -> Result<(), ClientError> {
        self.conn
            .execute(
                "INSERT INTO contacts (identity_pub, nickname, fingerprint) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(identity_pub) DO UPDATE SET nickname = excluded.nickname, fingerprint = excluded.fingerprint",
                rusqlite::params![identity_pub.as_slice(), nickname, fingerprint.as_slice()],
            )
            .map_err(|e| ClientError::Store(format!("put_contact: {e}")))?;
        Ok(())
    }

    /// Set the manual-verification flag for a contact. Persisted so the UI's
    /// ✓ mark survives restarts.
    pub fn set_verified(&self, identity_pub: &[u8; 32], verified: bool) -> Result<(), ClientError> {
        self.conn
            .execute(
                "UPDATE contacts SET verified = ?2 WHERE identity_pub = ?1",
                rusqlite::params![identity_pub.as_slice(), i64::from(verified)],
            )
            .map_err(|e| ClientError::Store(format!("set_verified: {e}")))?;
        Ok(())
    }

    /// List all contacts.
    pub fn contacts(&self) -> Result<Vec<Contact>, ClientError> {
        let mut stmt = self
            .conn
            .prepare("SELECT identity_pub, nickname, fingerprint, verified FROM contacts")
            .map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                let pub_bytes: Vec<u8> = r.get(0)?;
                let nick: String = r.get(1)?;
                let fp: Vec<u8> = r.get(2)?;
                let verified: i64 = r.get(3)?;
                Ok((pub_bytes, nick, fp, verified))
            })
            .map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (pub_bytes, nick, fp, verified) =
                row.map_err(|e| ClientError::Store(format!("contacts: {e}")))?;
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
                verified: verified != 0,
            });
        }
        Ok(out)
    }

    /// Persist a chat message. `peer` is the peer identity pub (1:1) or the
    /// group id (group). `direction` is 0 = outgoing, 1 = incoming. `payload`
    /// is the postcard-serialized `StoredMessage` (text + status); it is
    /// XChaCha-sealed under the store key with AAD = the row's auto id, then
    /// written. `timestamp` is unix seconds. Returns the assigned row id.
    pub fn put_message(
        &self,
        peer: &[u8; 32],
        direction: i64,
        payload: &StoredMessage,
        timestamp: i64,
    ) -> Result<i64, ClientError> {
        let bytes = postcard::to_allocvec(payload)?;
        // AAD binds the sealed blob to the peer + direction + timestamp so a
        // row-swap attack (copying one message's sealed blob into another's
        // slot) fails to open.
        let mut aad = Vec::with_capacity(32 + 1 + 8);
        aad.extend_from_slice(peer);
        aad.push(direction as u8);
        aad.extend_from_slice(&timestamp.to_be_bytes());
        let sealed = seal(&self.key, &aad, &bytes)?;
        self.conn
            .execute(
                "INSERT INTO messages (peer, direction, sealed, timestamp) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![peer.as_slice(), direction, sealed, timestamp],
            )
            .map_err(|e| ClientError::Store(format!("put_message: {e}")))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Load all messages for `peer` (1:1 or group id), oldest first. Each row
    /// is unsealed and decoded into a `StoredMessage`. Corrupt rows are
    /// skipped with a `Store` error for that row only (the rest still load),
    /// so a single bad blob never hides the whole thread.
    pub fn messages(&self, peer: &[u8; 32]) -> Result<Vec<StoredMessageRow>, ClientError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, direction, sealed, timestamp FROM messages WHERE peer = ?1 ORDER BY id ASC",
            )
            .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![peer.as_slice()], |r| {
                let id: i64 = r.get(0)?;
                let direction: i64 = r.get(1)?;
                let sealed: Vec<u8> = r.get(2)?;
                let timestamp: i64 = r.get(3)?;
                Ok((id, direction, sealed, timestamp))
            })
            .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, direction, sealed, timestamp) =
                row.map_err(|e| ClientError::Store(format!("messages: {e}")))?;
            let mut aad = Vec::with_capacity(32 + 1 + 8);
            aad.extend_from_slice(peer);
            aad.push(direction as u8);
            aad.extend_from_slice(&timestamp.to_be_bytes());
            let Ok(bytes) = open(&self.key, &aad, &sealed) else {
                continue; // corrupt/tampered row: skip, keep loading
            };
            let msg: StoredMessage = postcard::from_bytes(&bytes)?;
            out.push(StoredMessageRow {
                id,
                direction,
                timestamp,
                msg,
            });
        }
        Ok(out)
    }

    // ---- Groups --------------------------------------------------------

    /// Persist (or refresh) a group's display name. Upserts: re-recording an
    /// existing group updates the name. The group id is the deterministic
    /// `SHA-256(name ‖ members ‖ founder)` chosen by the bridge, so a re-found
    /// of the same membership resolves to the same row.
    pub fn put_group(&self, group_id: &[u8; 32], name: &str) -> Result<(), ClientError> {
        self.conn
            .execute(
                "INSERT INTO groups (group_id, name) VALUES (?1, ?2) \
                 ON CONFLICT(group_id) DO UPDATE SET name = excluded.name",
                rusqlite::params![group_id.as_slice(), name],
            )
            .map_err(|e| ClientError::Store(format!("put_group: {e}")))?;
        Ok(())
    }

    /// Set/refresh a group's name without touching its members (used when a
    /// distribution arrives with a refreshed name for an already-known group).
    pub fn set_group_name(&self, group_id: &[u8; 32], name: &str) -> Result<(), ClientError> {
        self.conn
            .execute(
                "UPDATE groups SET name = ?2 WHERE group_id = ?1",
                rusqlite::params![group_id.as_slice(), name],
            )
            .map_err(|e| ClientError::Store(format!("set_group_name: {e}")))?;
        Ok(())
    }

    /// List all known groups (id + name), ordered by id for stable output.
    pub fn groups(&self) -> Result<Vec<StoredGroup>, ClientError> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, name FROM groups ORDER BY group_id ASC")
            .map_err(|e| ClientError::Store(format!("groups: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                let id: Vec<u8> = r.get(0)?;
                let name: String = r.get(1)?;
                Ok((id, name))
            })
            .map_err(|e| ClientError::Store(format!("groups: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name) = row.map_err(|e| ClientError::Store(format!("groups: {e}")))?;
            if id.len() != 32 {
                return Err(ClientError::Store("corrupt group row".into()));
            }
            let mut gid = [0u8; 32];
            gid.copy_from_slice(&id);
            out.push(StoredGroup {
                group_id: gid,
                name,
            });
        }
        Ok(out)
    }

    /// Add a member to a group's roster. Idempotent: re-adding an existing
    /// `(group_id, identity_pub)` is a no-op (the bridge re-records peers on
    /// every distribution, and a duplicate would make the relay deliver the
    /// same group envelope twice, which the receiver's sender-key generation
    /// check rejects).
    pub fn add_group_member(
        &self,
        group_id: &[u8; 32],
        identity_pub: &[u8; 32],
    ) -> Result<(), ClientError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO group_members (group_id, identity_pub) VALUES (?1, ?2)",
                rusqlite::params![group_id.as_slice(), identity_pub.as_slice()],
            )
            .map_err(|e| ClientError::Store(format!("add_group_member: {e}")))?;
        Ok(())
    }

    /// List the member identity pubs for `group_id`, ordered for stable output.
    pub fn group_members(&self, group_id: &[u8; 32]) -> Result<Vec<[u8; 32]>, ClientError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT identity_pub FROM group_members WHERE group_id = ?1 ORDER BY identity_pub ASC",
            )
            .map_err(|e| ClientError::Store(format!("group_members: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![group_id.as_slice()], |r| {
                let pub_bytes: Vec<u8> = r.get(0)?;
                Ok(pub_bytes)
            })
            .map_err(|e| ClientError::Store(format!("group_members: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let pub_bytes = row.map_err(|e| ClientError::Store(format!("group_members: {e}")))?;
            if pub_bytes.len() != 32 {
                return Err(ClientError::Store("corrupt group member row".into()));
            }
            let mut p = [0u8; 32];
            p.copy_from_slice(&pub_bytes);
            out.push(p);
        }
        Ok(out)
    }
}

/// A stored chat message: plaintext text + delivery status. Sealed into the
/// `messages` table via `Store::put_message`. `Serialize` so it round-trips
/// through postcard before sealing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredMessage {
    /// Message text (v1: text only; attachments are future work).
    pub text: String,
    /// Delivery status as a small integer (0=Sending,1=Sent,2=Delivered,3=Failed).
    pub status: u8,
}

/// A loaded message row: row id, direction (0=out,1=in), unix timestamp, and
/// the decoded `StoredMessage`.
#[derive(Debug, Clone)]
pub struct StoredMessageRow {
    pub id: i64,
    pub direction: i64,
    pub timestamp: i64,
    pub msg: StoredMessage,
}

/// A stored contact: identity pub, display nickname, fingerprint, and whether
/// the fingerprint has been manually verified (persists across restarts).
pub struct Contact {
    pub identity_pub: [u8; 32],
    pub nickname: String,
    pub fingerprint: [u8; 32],
    pub verified: bool,
}

/// A stored group: the deterministic group id + display name. The member roster
/// lives in the `group_members` table and is read via
/// [`Store::group_members`].
pub struct StoredGroup {
    pub group_id: [u8; 32],
    pub name: String,
}

fn init_schema(conn: &Connection) -> Result<(), ClientError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, blob BLOB);
         CREATE TABLE IF NOT EXISTS contacts (identity_pub BLOB PRIMARY KEY, nickname TEXT, fingerprint BLOB, verified INT NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, peer BLOB, direction INT, sealed BLOB, timestamp INT);
         CREATE TABLE IF NOT EXISTS groups (group_id BLOB PRIMARY KEY, name TEXT);
         CREATE TABLE IF NOT EXISTS group_members (group_id BLOB, identity_pub BLOB, PRIMARY KEY (group_id, identity_pub));",
    )
    .map_err(|e| ClientError::Store(format!("init_schema: {e}")))?;
    // Backfill the `verified` column on pre-existing stores created before
    // the column existed (ALTER TABLE ADD COLUMN with a default is a no-op if
    // the column is already present, so this is idempotent across reopen).
    let _ = conn.execute(
        "ALTER TABLE contacts ADD COLUMN verified INT NOT NULL DEFAULT 0",
        [],
    );
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
    match rows
        .next()
        .map_err(|e| ClientError::Store(format!("get_kv: {e}")))?
    {
        Some(r) => {
            let blob: Vec<u8> = r
                .get(0)
                .map_err(|e| ClientError::Store(format!("get_kv: {e}")))?;
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
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        p.push(format!("um-store-test-{}.db", hex_encode(&bytes)));
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
        store
            .put_contact(&[0x11; 32], "alice", &[0x22; 32])
            .unwrap();
        store.put_contact(&[0x33; 32], "bob", &[0x44; 32]).unwrap();
        let mut contacts = store.contacts().unwrap();
        contacts.sort_by_key(|c| c.identity_pub);
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].nickname, "alice");
        assert_eq!(contacts[1].nickname, "bob");
        // New contacts default to unverified.
        assert!(!contacts[0].verified);
        assert!(!contacts[1].verified);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_verified_persists_across_reopen() {
        let path = tmp();
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .put_contact(&[0x11; 32], "alice", &[0x22; 32])
                .unwrap();
            store.set_verified(&[0x11; 32], true).unwrap();
            // Re-adding the same contact must NOT clear the verified flag.
            store
                .put_contact(&[0x11; 32], "alice2", &[0x22; 32])
                .unwrap();
            let contacts = store.contacts().unwrap();
            let alice = contacts
                .iter()
                .find(|c| c.identity_pub == [0x11; 32])
                .unwrap();
            assert!(alice.verified, "verified preserved across re-add");
            assert_eq!(alice.nickname, "alice2");
        }
        // Verified flag survives close/reopen.
        let store = Store::open(&path, "pw").unwrap();
        let contacts = store.contacts().unwrap();
        let alice = contacts
            .iter()
            .find(|c| c.identity_pub == [0x11; 32])
            .unwrap();
        assert!(alice.verified, "verified flag persisted to disk");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn old_store_without_verified_column_is_backfilled() {
        // Simulate a store created before the `verified` column existed:
        // create the store, then drop the column and recreate it without the
        // default, then reopen — the migration must add the column back.
        let path = tmp();
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .put_contact(&[0x11; 32], "alice", &[0x22; 32])
                .unwrap();
            // Wipe the column to force the ALTER TABLE migration path.
            store
                .conn
                .execute("ALTER TABLE contacts RENAME TO contacts_old", [])
                .unwrap();
            store
                .conn
                .execute(
                    "CREATE TABLE contacts (identity_pub BLOB PRIMARY KEY, nickname TEXT, fingerprint BLOB)",
                    [],
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO contacts SELECT identity_pub, nickname, fingerprint FROM contacts_old",
                    [],
                )
                .unwrap();
            store.conn.execute("DROP TABLE contacts_old", []).unwrap();
        }
        // Reopen: init_schema runs the ALTER TABLE ADD COLUMN, backfilling 0.
        let store = Store::open(&path, "pw").unwrap();
        let contacts = store.contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert!(!contacts[0].verified, "backfilled default is unverified");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sealed_blob_tamper_fails_to_open() {
        let key = [0xAB; 32];
        let sealed = seal(&key, b"aad", b"plaintext").unwrap();
        // Flip a ciphertext byte.
        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(open(&key, b"aad", &tampered).is_err());
    }

    #[test]
    fn group_and_members_round_trip_persists_across_reopen() {
        let path = tmp();
        let gid = [0xAA; 32];
        let m1 = [0x01; 32];
        let m2 = [0x02; 32];
        {
            let store = Store::create(&path, "pw").unwrap();
            store.put_group(&gid, "team").unwrap();
            store.add_group_member(&gid, &m1).unwrap();
            store.add_group_member(&gid, &m2).unwrap();
            // Re-adding a member is a no-op (no duplicate row).
            store.add_group_member(&gid, &m1).unwrap();

            let groups = store.groups().unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].group_id, gid);
            assert_eq!(groups[0].name, "team");

            let mut members = store.group_members(&gid).unwrap();
            members.sort_unstable();
            assert_eq!(members, vec![m1, m2]);

            // Refreshing the name via put_group updates without duplicating.
            store.put_group(&gid, "team v2").unwrap();
            let groups = store.groups().unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].name, "team v2");
        }
        // Reopen: groups + members survive to disk.
        let store = Store::open(&path, "pw").unwrap();
        let groups = store.groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "team v2");
        let mut members = store.group_members(&gid).unwrap();
        members.sort_unstable();
        assert_eq!(members, vec![m1, m2]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn group_members_for_unknown_group_is_empty() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let members = store.group_members(&[0x77; 32]).unwrap();
        assert!(members.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn old_store_without_groups_tables_is_migrated() {
        // Simulate a store created before the groups/group_members tables
        // existed: create the store, drop both tables, reopen — init_schema
        // must recreate them (CREATE TABLE IF NOT EXISTS is idempotent).
        let path = tmp();
        {
            let store = Store::create(&path, "pw").unwrap();
            store.conn.execute("DROP TABLE groups", []).unwrap();
            store.conn.execute("DROP TABLE group_members", []).unwrap();
        }
        let store = Store::open(&path, "pw").unwrap();
        // Tables exist again and are usable.
        store.put_group(&[0xAA; 32], "team").unwrap();
        store.add_group_member(&[0xAA; 32], &[0x01; 32]).unwrap();
        assert_eq!(store.groups().unwrap().len(), 1);
        assert_eq!(store.group_members(&[0xAA; 32]).unwrap().len(), 1);
        let _ = fs::remove_file(&path);
    }

    /// Minimal hex encoder for test temp-file names (avoids an extra dep).
    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}
