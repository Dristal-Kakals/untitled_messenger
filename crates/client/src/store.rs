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
//!   timestamp INT, sender BLOB, server_id INT)` — `sealed` is the
//!   XChaCha-encrypted postcard of the message plaintext + status. `sender`
//!   is the author identity pub for an incoming group message (so the view
//!   can prefix "author: …" after a restart), `NULL` for 1:1 (the peer is
//!   implied by the thread) and for outgoing messages. `sender` is public
//!   metadata — a pub key, like `peer` — so it is stored in plaintext
//!   alongside the row, NOT inside the sealed blob, and is NOT part of the
//!   AEAD associated data (changing it does not break the seal). The sealed
//!   `StoredMessage` is unchanged, so existing rows (written before this
//!   column existed) re-open unchanged; the `ALTER TABLE ADD COLUMN`
//!   migration backfills `NULL`. `server_id` is the relay-assigned monotonic
//!   envelope id for an incoming message (`NULL` for outgoing): it is the
//!   stable dedup key the relay uses when re-flushing an unacked outbox, so
//!   a partial-index `idx_messages_peer_server_id` on `(peer, server_id)`
//!   WHERE `server_id IS NOT NULL` makes a re-delivered envelope
//!   `INSERT OR IGNORE`-collide with the original row instead of creating a
//!   duplicate. `server_id` is also public metadata (a server counter, not a
//!   secret), stored in plaintext and excluded from the sealed blob + AAD,
//!   so the migration does not invalidate any existing seal. Indexed by
//!   `(peer, id)` (`idx_messages_peer_id`) so `load_history`'s
//!   `WHERE peer = ?1 ORDER BY id ASC` is an index range scan, not a full
//!   table scan + sort.
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
//! - `unread(peer BLOB PRIMARY KEY, count INT NOT NULL)` — per-chat unread
//!   message counts so the sidebar badges survive a restart. `peer` is the
//!   32-byte chat key (1:1 identity pub or group id, both public) and `count`
//!   is a small integer, so both are plaintext metadata — like `contacts` and
//!   the `sender` column, not sealed. A count of `0` is stored as an absent row
//!   (DELETE), mirroring the in-memory `unread` map which `remove`s on open.
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
    /// written. `sender` is the author identity pub for an incoming group
    /// message (so the view can label it after a restart); pass `None` for 1:1
    /// messages and for all outgoing messages. `sender` is stored as a
    /// plaintext column — it is a public key, not secret — and is deliberately
    /// kept OUT of the sealed blob and the AEAD AAD so adding it never
    /// invalidates existing rows. `timestamp` is unix seconds.
    ///
    /// `server_id` is the relay-assigned monotonic envelope id for an incoming
    /// message (`None` for outgoing and for callers that do not dedup). It is
    /// the stable key the relay uses when re-flushing an unacked outbox: the
    /// same envelope re-delivered on the next Subscribe carries the same
    /// `server_id`, so the `(peer, server_id)` partial unique index makes the
    /// re-delivery collide with the original row. The insert is
    /// `INSERT OR IGNORE`: a collision (a re-delivered envelope) inserts
    /// nothing and returns `Ok(None)`, letting the caller suppress the
    /// duplicate `Event::Decrypted` while still acking the envelope so the
    /// relay drops it from the outbox. A fresh row returns `Ok(Some(rowid))`.
    /// Outgoing rows pass `server_id = None` and always insert (NULLs are
    /// distinct under the partial index), returning `Ok(Some(rowid))`.
    pub fn put_message(
        &self,
        peer: &[u8; 32],
        direction: i64,
        payload: &StoredMessage,
        timestamp: i64,
        sender: Option<&[u8; 32]>,
        server_id: Option<i64>,
    ) -> Result<Option<i64>, ClientError> {
        let bytes = postcard::to_allocvec(payload)?;
        // AAD binds the sealed blob to the peer + direction + timestamp so a
        // row-swap attack (copying one message's sealed blob into another's
        // slot) fails to open. `sender` and `server_id` are intentionally
        // excluded: both are public metadata and excluding them keeps the AAD
        // identical to pre-column rows (so the migrations do not invalidate
        // existing seals).
        let mut aad = Vec::with_capacity(32 + 1 + 8);
        aad.extend_from_slice(peer);
        aad.push(direction as u8);
        aad.extend_from_slice(&timestamp.to_be_bytes());
        let sealed = seal(&self.key, &aad, &bytes)?;
        // `INSERT OR IGNORE`: a re-delivered incoming envelope (same `peer` +
        // `server_id`, caught by the partial unique index) inserts no row and
        // `changes()` returns 0 → we report `None` so the caller can suppress
        // the duplicate. A fresh row (or any outgoing row, whose `server_id`
        // NULL is not constrained by the partial index) inserts normally.
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO messages \
                 (peer, direction, sealed, timestamp, sender, server_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    peer.as_slice(),
                    direction,
                    sealed,
                    timestamp,
                    sender.map(|s| s.as_slice()),
                    server_id,
                ],
            )
            .map_err(|e| ClientError::Store(format!("put_message: {e}")))?;
        if changed == 0 {
            // No row inserted: a (peer, server_id) collision — a re-delivered
            // envelope. `last_insert_rowid()` is stale here, so do not report
            // it; the caller treats `None` as "already had this message".
            Ok(None)
        } else {
            Ok(Some(self.conn.last_insert_rowid()))
        }
    }

    /// Returns `true` if an incoming message with relay-assigned `server_id`
    /// is already persisted for `peer`. This is the dedup probe: a
    /// re-delivered envelope (same `peer` + `server_id`, e.g. an unacked
    /// outbox re-flushed on the next Subscribe) reports `true`, letting the
    /// bridge skip the decrypt entirely instead of advancing the Double
    /// Ratchet past a message number it has already consumed and then
    /// surfacing a spurious decrypt-failure `Event::Error`. Outgoing rows
    /// (`server_id IS NULL`) are never matched. A `None` `server_id` (no
    /// dedup key) reports `false`.
    pub fn has_server_id(&self, peer: &[u8; 32], server_id: Option<i64>) -> bool {
        let Some(sid) = server_id else {
            return false;
        };
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM messages \
                 WHERE peer = ?1 AND server_id = ?2 LIMIT 1)",
                rusqlite::params![peer.as_slice(), sid],
                |r| r.get(0),
            )
            .unwrap_or(false);
        exists
    }

    /// Load all messages for `peer` (1:1 or group id), oldest first. Each row
    /// is unsealed and decoded into a `StoredMessage`. Corrupt rows are
    /// skipped with a `Store` error for that row only (the rest still load),
    /// so a single bad blob never hides the whole thread. The `sender` column
    /// (author pub for incoming group messages) is read back as plaintext
    /// metadata; rows written before the column existed have `NULL` and load
    /// as `sender = None`.
    ///
    /// **Deprecated:** this pulls the *entire* thread into memory. Production
    /// callers (the GUI bridge) use [`Store::messages_page`] for keyset
    /// pagination. This method is now itself a thin wrapper that assembles the
    /// full thread by looping `messages_page` (so there is a single SQL path —
    /// the old direct `ORDER BY id ASC` query is gone), kept for tests and any
    /// future caller that genuinely wants the whole thread at once. Prefer
    /// `messages_page` for anything user-facing.
    #[deprecated(since = "0.1.0", note = "use messages_page for keyset pagination")]
    pub fn messages(&self, peer: &[u8; 32]) -> Result<Vec<StoredMessageRow>, ClientError> {
        // Assemble the full thread by paging backward from the newest row.
        // Each page is oldest-first within its slice; older pages are strictly
        // older than the current cursor, so prepend each older page before the
        // accumulated rows to end up oldest-first overall. `PAGE` is sized for
        // few round-trips on typical threads while staying bounded per query.
        const PAGE: usize = 500;
        let mut acc: Vec<StoredMessageRow> = Vec::new();
        let mut before_id: Option<i64> = None;
        loop {
            let page = self.messages_page(peer, before_id, PAGE)?;
            // `messages_page` returns oldest-first; an older page precedes the
            // already-collected (newer) rows, so splice it in front.
            let older = page.rows;
            let mut combined = older;
            combined.append(&mut acc);
            acc = combined;
            if !page.has_more {
                break;
            }
            // Next page is strictly older than the smallest id now held.
            before_id = acc.first().map(|r| r.id);
            // If a page reported `has_more` but yielded no rows (e.g. every row
            // on it was corrupt and skipped), there is no cursor to advance —
            // stop to avoid an infinite loop. `has_more` is a hint, not a
            // guarantee that a decodeable older row exists.
            if before_id.is_none() {
                break;
            }
        }
        Ok(acc)
    }

    /// Load one keyset page of messages for `peer`, oldest-first within the
    /// returned slice. Pagination is by row `id` (monotonic with arrival
    /// order), walking the `(peer, id)` index in reverse so each page is a
    /// single index range scan — no full table scan, no sort.
    ///
    /// `before_id = None` returns the **newest** `limit` rows (the initial
    /// page shown when a thread opens). `before_id = Some(id)` returns up to
    /// `limit` rows strictly older than `id` (the next page up, fetched on
    /// scroll-to-top). The caller passes the smallest loaded `id` as
    /// `before_id` to page further back.
    ///
    /// To distinguish "no more history" from "an empty page happened to load",
    /// the query fetches `limit + 1` rows; the extra row (if any) is dropped
    /// before returning and signals `has_more = true`. A returned `has_more =
    /// false` means the caller has reached the oldest row and should stop
    /// requesting older pages.
    ///
    /// Rows are unsealed + decoded exactly as in [`Store::messages`]; corrupt
    /// rows are skipped (the rest of the page still loads), and the `sender`
    /// column is read as plaintext metadata. The slice is returned oldest-first
    /// so the caller can prepend it to the cached thread directly.
    pub fn messages_page(
        &self,
        peer: &[u8; 32],
        before_id: Option<i64>,
        limit: usize,
    ) -> Result<MessagePage, ClientError> {
        // Fetch limit + 1 so a present (limit+1)th row proves there is more
        // history without a second count query. The extra row is dropped below.
        let fetch = limit.saturating_add(1) as i64;
        // Keyset by row `id`: `before_id = None` → newest page; `Some(id)` →
        // the page strictly older than `id`. Both walk the `(peer, id)` index
        // in reverse (DESC), so each is a single index range scan, no sort.
        // `decode_message_rows` fully consumes the `MappedRows` iterator (which
        // borrows the prepared statement) and returns an owned `Vec`, so the
        // statement is released before we leave each arm.
        let mut rows = match before_id {
            None => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT id, direction, sealed, timestamp, sender FROM messages \
                         WHERE peer = ?1 ORDER BY id DESC LIMIT ?2",
                    )
                    .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
                let raw = stmt
                    .query_map(rusqlite::params![peer.as_slice(), fetch], map_message_row)
                    .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
                decode_message_rows(&self.key, peer, raw)?
            }
            Some(id) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT id, direction, sealed, timestamp, sender FROM messages \
                         WHERE peer = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
                    )
                    .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
                let raw = stmt
                    .query_map(
                        rusqlite::params![peer.as_slice(), id, fetch],
                        map_message_row,
                    )
                    .map_err(|e| ClientError::Store(format!("messages: {e}")))?;
                decode_message_rows(&self.key, peer, raw)?
            }
        };
        // `decode_message_rows` preserves query order (DESC here). The probe
        // row at index `limit` (if present) proves older history exists.
        let has_more = rows.len() > limit;
        if has_more {
            rows.truncate(limit); // drop the probe row
        }
        rows.reverse(); // DESC → oldest-first for display
        Ok(MessagePage { rows, has_more })
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

    /// Persist the unread-message count for a chat (`peer` is the 32-byte chat
    /// key — a 1:1 identity pub or a group id). A count of `0` clears the row
    /// (DELETE) so the `unread` table only ever holds chats with pending
    /// messages, mirroring the in-memory `app.unread` map which `remove`s on
    /// open. Upsert semantics: re-writing a count for an existing chat replaces
    /// it. The chat key is public (a pub/group id) and the count is a small
    /// integer, so both are plaintext metadata — like `contacts` and the
    /// `sender` column, not sealed.
    pub fn put_unread(&self, peer: &[u8; 32], count: u32) -> Result<(), ClientError> {
        if count == 0 {
            self.conn
                .execute(
                    "DELETE FROM unread WHERE peer = ?1",
                    rusqlite::params![peer.as_slice()],
                )
                .map_err(|e| ClientError::Store(format!("put_unread: {e}")))?;
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO unread (peer, count) VALUES (?1, ?2) \
                 ON CONFLICT(peer) DO UPDATE SET count = excluded.count",
                rusqlite::params![peer.as_slice(), i64::from(count)],
            )
            .map_err(|e| ClientError::Store(format!("put_unread: {e}")))?;
        Ok(())
    }

    /// Load every persisted unread count (`peer`, `count`), for chats that had
    /// pending messages at last shutdown. Chats opened (and thus cleared)
    /// before shutdown are absent. Returned in arbitrary order; the caller
    /// rebuilds its in-memory `unread` map from this. Rows with a corrupt
    /// (non-32-byte) peer are skipped rather than failing the whole load — a
    /// single bad row never hides every badge.
    pub fn unread_counts(&self) -> Result<Vec<([u8; 32], u32)>, ClientError> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer, count FROM unread")
            .map_err(|e| ClientError::Store(format!("unread_counts: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                let peer: Vec<u8> = r.get(0)?;
                let count: i64 = r.get(1)?;
                Ok((peer, count))
            })
            .map_err(|e| ClientError::Store(format!("unread_counts: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (peer, count) =
                row.map_err(|e| ClientError::Store(format!("unread_counts: {e}")))?;
            if peer.len() != 32 {
                continue; // corrupt row: skip, keep loading the rest
            }
            let mut p = [0u8; 32];
            p.copy_from_slice(&peer);
            out.push((p, count.max(0) as u32));
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

/// A loaded message row: row id, direction (0=out,1=in), unix timestamp, the
/// decoded `StoredMessage`, and the author identity pub for an incoming group
/// message (`None` for 1:1 and for outgoing). `sender` is plaintext metadata
/// read from a dedicated column, not unsealed from the blob.
#[derive(Debug, Clone)]
pub struct StoredMessageRow {
    pub id: i64,
    pub direction: i64,
    pub timestamp: i64,
    /// Author identity pub for an incoming group message; `None` for 1:1
    /// messages (the peer is the thread key) and for all outgoing messages.
    pub sender: Option<[u8; 32]>,
    pub msg: StoredMessage,
}

/// One keyset page of message rows from [`Store::messages_page`]. `rows` is
/// oldest-first within the page (ready to prepend to a cached thread), and
/// `has_more` is `true` when older history exists beyond this page — the
/// caller uses it to decide whether to fetch another page on scroll-up.
#[derive(Debug, Clone)]
pub struct MessagePage {
    pub rows: Vec<StoredMessageRow>,
    pub has_more: bool,
}

/// Unseal + decode a stream of raw `messages`-table rows for `peer`. Shared by
/// [`Store::messages`] (full thread, ASC) and [`Store::messages_page`] (keyset
/// page, DESC) so the AAD/sender/skip-corrupt logic lives in one place. The
/// rows are returned in the order the iterator yields them — callers that want
/// oldest-first from a DESC query reverse the result themselves.
///
/// Corrupt/tampered rows are skipped (the rest still load), so a single bad
/// blob never hides the whole thread or page. A present-but-wrong-length
/// `sender` is corruption, not a 1:1 row, and is surfaced rather than silently
/// dropping the author label.
fn decode_message_rows<I>(
    key: &[u8; 32],
    peer: &[u8; 32],
    rows: I,
) -> Result<Vec<StoredMessageRow>, ClientError>
where
    I: Iterator<Item = rusqlite::Result<RawMessageRow>>,
{
    let mut out = Vec::new();
    for row in rows {
        let (id, direction, sealed, timestamp, sender_bytes) =
            row.map_err(|e| ClientError::Store(format!("messages: {e}")))?;
        // Re-derive the per-row AAD exactly as `put_message` built it: peer +
        // direction + timestamp. The peer is the same for every row in this
        // thread (the WHERE pins it); direction + timestamp vary per row and
        // must match what was sealed.
        let mut aad = Vec::with_capacity(32 + 1 + 8);
        aad.extend_from_slice(peer);
        aad.push(direction as u8);
        aad.extend_from_slice(&timestamp.to_be_bytes());
        let Ok(bytes) = open(key, &aad, &sealed) else {
            continue; // corrupt/tampered row: skip, keep loading
        };
        let msg: StoredMessage = postcard::from_bytes(&bytes)?;
        let sender = match sender_bytes {
            None => None,
            Some(s) if s.len() == 32 => {
                let mut p = [0u8; 32];
                p.copy_from_slice(&s);
                Some(p)
            }
            Some(_) => return Err(ClientError::Store("corrupt sender in message row".into())),
        };
        out.push(StoredMessageRow {
            id,
            direction,
            timestamp,
            sender,
            msg,
        });
    }
    Ok(out)
}

/// The raw five-column tuple read off a `messages`-table row by
/// [`map_message_row`]: `(id, direction, sealed, timestamp, sender)`. A type
/// alias (rather than an inline tuple) keeps `map_message_row`'s signature and
/// `decode_message_rows`'s bound readable and shared.
type RawMessageRow = (i64, i64, Vec<u8>, i64, Option<Vec<u8>>);

/// `query_map` row mapper for the `messages` table: reads the five columns
/// (`id, direction, sealed, timestamp, sender`) into a tuple. A free function
/// (not a closure) so both `messages` and `messages_page` can pass it without
/// each spawning a distinct closure type (which would make the two `query_map`
/// calls' `MappedRows` types incompatible).
fn map_message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessageRow> {
    let id: i64 = r.get(0)?;
    let direction: i64 = r.get(1)?;
    let sealed: Vec<u8> = r.get(2)?;
    let timestamp: i64 = r.get(3)?;
    let sender: Option<Vec<u8>> = r.get(4)?;
    Ok((id, direction, sealed, timestamp, sender))
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
         CREATE TABLE IF NOT EXISTS group_members (group_id BLOB, identity_pub BLOB, PRIMARY KEY (group_id, identity_pub));
         CREATE TABLE IF NOT EXISTS unread (peer BLOB PRIMARY KEY, count INT NOT NULL);",
    )
    .map_err(|e| ClientError::Store(format!("init_schema: {e}")))?;
    // Backfill the `verified` column on pre-existing stores created before
    // the column existed (ALTER TABLE ADD COLUMN with a default is a no-op if
    // the column is already present, so this is idempotent across reopen).
    let _ = conn.execute(
        "ALTER TABLE contacts ADD COLUMN verified INT NOT NULL DEFAULT 0",
        [],
    );
    // Backfill the `sender` column on pre-existing message stores created
    // before the column existed. `sender` is public metadata (an author pub
    // key), stored in plaintext, deliberately excluded from the sealed blob
    // and the AEAD AAD — so adding the column does NOT invalidate any existing
    // sealed row: old rows simply load with `sender = NULL` (no author label
    // in reloaded group history, same as before this column shipped). The
    // `ALTER TABLE ADD COLUMN` is a no-op if the column already exists, so
    // this is idempotent across reopen.
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN sender BLOB", []);
    // Backfill the `server_id` column on pre-existing message stores created
    // before the column existed. `server_id` is the relay-assigned monotonic
    // envelope id for an incoming message (`NULL` for outgoing): the stable
    // dedup key the relay uses when re-flushing an unacked outbox, so a
    // re-delivered envelope collides with the original row on the
    // `(peer, server_id)` partial index instead of creating a duplicate. It
    // is public metadata (a server counter, not a secret), stored in
    // plaintext and excluded from the sealed blob + AEAD AAD — so adding the
    // column does NOT invalidate any existing seal: old rows load with
    // `server_id = NULL` (treated as outgoing / pre-dedup, inserted
    // unconditionally). The `ALTER TABLE ADD COLUMN` is a no-op if the
    // column already exists, so this is idempotent across reopen.
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN server_id INTEGER", []);
    // Partial unique index on `(peer, server_id)` for incoming rows only
    // (`server_id IS NOT NULL`). Outgoing rows have `server_id = NULL` and
    // SQLite treats multiple NULLs as distinct under a unique index, so this
    // partial form lets outgoing rows coexist without colliding while still
    // rejecting a re-delivered incoming envelope (same `peer` + same
    // `server_id`). `CREATE INDEX IF NOT EXISTS` is a no-op on reopen, so
    // this is idempotent across migrations. A partial index is smaller than
    // a full one and never constrains outgoing inserts.
    let _ = conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_peer_server_id \
         ON messages (peer, server_id) WHERE server_id IS NOT NULL",
        [],
    );
    // Cover the `load_history` query (`WHERE peer = ?1 ORDER BY id ASC`). Without
    // this index SQLite scans the whole `messages` table and sorts the matches;
    // with it the planner walks a single index range per peer, no sort step.
    // `(peer, id)` is chosen over `(peer, timestamp)` because `id` is the actual
    // `ORDER BY` key and is monotonic with insert order, which matches the
    // arrival order we want to display. `CREATE INDEX IF NOT EXISTS` is a no-op
    // on reopen, so this is idempotent across migrations.
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_peer_id ON messages (peer, id)",
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
#[allow(deprecated)] // tests exercise the deprecated `messages` wrapper on purpose
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

    #[test]
    fn put_message_with_sender_round_trips() {
        let path = tmp();
        let peer = [0x11; 32];
        let author = [0x22; 32];
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .put_message(
                    &peer,
                    1,
                    &StoredMessage {
                        text: "hi group".into(),
                        status: 2,
                    },
                    1_700_000_000,
                    Some(&author),
                    Some(101),
                )
                .unwrap();
            // A 1:1 incoming message carries no sender.
            store
                .put_message(
                    &peer,
                    1,
                    &StoredMessage {
                        text: "hi dm".into(),
                        status: 2,
                    },
                    1_700_000_001,
                    None,
                    Some(102),
                )
                .unwrap();
            // An outgoing message carries no sender (and no server_id).
            store
                .put_message(
                    &peer,
                    0,
                    &StoredMessage {
                        text: "out".into(),
                        status: 1,
                    },
                    1_700_000_002,
                    None,
                    None,
                )
                .unwrap();
        }
        let store = Store::open(&path, "pw").unwrap();
        let msgs = store.messages(&peer).unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].sender, Some(author));
        assert_eq!(msgs[0].msg.text, "hi group");
        assert_eq!(msgs[1].sender, None);
        assert_eq!(msgs[2].sender, None);
        assert_eq!(msgs[2].direction, 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn old_store_without_sender_column_is_migrated() {
        // Simulate a store created before the `sender` column existed: write a
        // row via the old 5-column schema, drop the column, reopen — the
        // migration must add `sender` back, and the pre-existing row must
        // still load (the seal is unchanged) with `sender = None`.
        let path = tmp();
        let peer = [0x11; 32];
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .put_message(
                    &peer,
                    1,
                    &StoredMessage {
                        text: "legacy".into(),
                        status: 2,
                    },
                    1_700_000_000,
                    None,
                    None,
                )
                .unwrap();
            // Wipe the column to force the ALTER TABLE migration path.
            store
                .conn
                .execute("ALTER TABLE messages RENAME TO messages_old", [])
                .unwrap();
            store
                .conn
                .execute(
                    "CREATE TABLE messages (id INTEGER PRIMARY KEY, peer BLOB, direction INT, sealed BLOB, timestamp INT)",
                    [],
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO messages SELECT id, peer, direction, sealed, timestamp FROM messages_old",
                    [],
                )
                .unwrap();
            store.conn.execute("DROP TABLE messages_old", []).unwrap();
        }
        // Reopen: init_schema runs ALTER TABLE ADD COLUMN sender, backfilling
        // NULL. The legacy row re-opens (seal untouched) with no author.
        let store = Store::open(&path, "pw").unwrap();
        let msgs = store.messages(&peer).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg.text, "legacy");
        assert_eq!(msgs[0].sender, None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_peer_id_index_exists_and_is_used() {
        // `load_history` does `WHERE peer = ?1 ORDER BY id ASC`. We added
        // `idx_messages_peer_id` to make that an index range scan instead of a
        // full table scan + sort. Assert the index exists after init_schema and
        // that the planner actually picks it for the load_history query.
        let path = tmp();
        let peer = [0x33; 32];
        let store = Store::create(&path, "pw").unwrap();

        // Index present in the schema.
        let has_index: bool = store
            .conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_messages_peer_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(has_index, "idx_messages_peer_id missing after create");

        // Insert a few rows so the planner has a reason to prefer the index.
        for i in 0..5 {
            store
                .put_message(
                    &peer,
                    i % 2,
                    &StoredMessage {
                        text: format!("m{i}"),
                        status: 2,
                    },
                    1_700_000_000 + i,
                    None,
                    None,
                )
                .unwrap();
        }

        // The load-history query plan must mention the covering index.
        let plan: String = store
            .conn
            .prepare(
                "EXPLAIN QUERY PLAN \
                 SELECT id, direction, sealed, timestamp, sender FROM messages \
                 WHERE peer = ?1 ORDER BY id ASC",
            )
            .unwrap()
            .query_map(rusqlite::params![peer.as_slice()], |r| {
                let s: String = r.get(3)?;
                Ok(s)
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            plan.contains("idx_messages_peer_id") || plan.contains("COVERING INDEX"),
            "planner did not use idx_messages_peer_id; plan = {plan:?}"
        );

        // Index survives a reopen (CREATE INDEX IF NOT EXISTS is idempotent).
        drop(store);
        let store = Store::open(&path, "pw").unwrap();
        let still: bool = store
            .conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_messages_peer_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(still, "idx_messages_peer_id lost after reopen");
        let _ = fs::remove_file(&path);
    }

    /// Insert `n` numbered messages for `peer` ("m0".."m{n-1}") with ascending
    /// timestamps, returning the assigned row ids in insertion order. Other
    /// peers get a single message each so cross-peer isolation can be checked.
    fn seed_thread(store: &Store, peer: &[u8; 32], n: u32) -> Vec<i64> {
        let mut ids = Vec::with_capacity(n as usize);
        for i in 0..n {
            let id = store
                .put_message(
                    peer,
                    (i % 2) as i64,
                    &StoredMessage {
                        text: format!("m{i}"),
                        status: 2,
                    },
                    1_700_000_000 + i as i64,
                    if i % 2 == 1 { Some(peer) } else { None },
                    // No server_id: these are mixed in/out test rows, and a
                    // NULL server_id is never constrained by the partial
                    // unique index, so every insert returns Some(rowid).
                    None,
                )
                .unwrap()
                .expect("NULL server_id always inserts");
            ids.push(id);
        }
        ids
    }

    #[test]
    fn messages_page_newest_returns_last_n_oldest_first() {
        // Seed 5 messages; ask for the newest 3. The page must be the last 3
        // in oldest-first order (m2, m3, m4), and `has_more` must be true
        // because older rows exist beyond the page.
        let path = tmp();
        let peer = [0x44; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &peer, 5);
        let page = store.messages_page(&peer, None, 3).unwrap();
        assert!(page.has_more, "older rows exist → has_more true");
        assert_eq!(page.rows.len(), 3);
        assert_eq!(
            page.rows
                .iter()
                .map(|r| r.msg.text.clone())
                .collect::<Vec<_>>(),
            vec!["m2", "m3", "m4"],
            "newest page is oldest-first within the slice"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_before_id_pages_older() {
        // Seed 5; take newest 3 (m2,m3,m4), then page older with before_id =
        // the smallest id in that page. The next page must be the remaining
        // oldest rows (m0,m1) with has_more = false (no rows older than m0).
        let path = tmp();
        let peer = [0x55; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &peer, 5);
        let first = store.messages_page(&peer, None, 3).unwrap();
        let oldest_in_page = first.rows.first().unwrap().id;
        let second = store.messages_page(&peer, Some(oldest_in_page), 3).unwrap();
        assert!(
            !second.has_more,
            "no rows older than the oldest in the first page → has_more false"
        );
        assert_eq!(
            second.rows.len(),
            2,
            "only 2 rows remain older than the page"
        );
        assert_eq!(
            second
                .rows
                .iter()
                .map(|r| r.msg.text.clone())
                .collect::<Vec<_>>(),
            vec!["m0", "m1"],
            "older page is oldest-first"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_union_equals_full_thread() {
        // The union of all pages (newest-first walk) must cover exactly the
        // full `messages()` result — no gaps, no duplicates. The pages
        // themselves arrive newest-page-first (so the walk yields rows in
        // reverse-arrival order); compare by id set + per-id content, not by
        // sequence, since the walk order differs from oldest-first display.
        let path = tmp();
        let peer = [0x66; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &peer, 7);
        let full = store.messages(&peer).unwrap();
        let mut collected: Vec<StoredMessageRow> = Vec::new();
        let mut before: Option<i64> = None;
        loop {
            let page = store.messages_page(&peer, before, 3).unwrap();
            collected.extend_from_slice(&page.rows);
            if !page.has_more {
                break;
            }
            // The oldest id in this page is the keyset cursor for the next.
            before = Some(page.rows.first().unwrap().id);
        }
        assert_eq!(collected.len(), full.len(), "no rows lost or duplicated");
        // Same set of ids, same text per id — order-independent.
        let mut col_by_id: Vec<(i64, String)> = collected
            .iter()
            .map(|r| (r.id, r.msg.text.clone()))
            .collect();
        let mut full_by_id: Vec<(i64, String)> =
            full.iter().map(|r| (r.id, r.msg.text.clone())).collect();
        col_by_id.sort_by_key(|(id, _)| *id);
        full_by_id.sort_by_key(|(id, _)| *id);
        assert_eq!(col_by_id, full_by_id, "paged walk covers full thread");
        // No id appears twice across pages.
        let mut ids: Vec<i64> = collected.iter().map(|r| r.id).collect();
        ids.sort();
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len(),
            "no duplicate ids across pages"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_isolates_peer() {
        // Rows for a different peer must never leak into another peer's page.
        let path = tmp();
        let a = [0x77; 32];
        let b = [0x88; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &a, 3);
        seed_thread(&store, &b, 3);
        let page = store.messages_page(&a, None, 10).unwrap();
        assert_eq!(page.rows.len(), 3, "only peer a's rows");
        assert!(
            page.rows.iter().all(|r| r.msg.text.starts_with('m')),
            "peer a rows present"
        );
        assert!(
            !page.has_more,
            "peer a has exactly 3 rows, page of 10 → no more"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_empty_thread_returns_empty_no_more() {
        let path = tmp();
        let peer = [0x99; 32];
        let store = Store::create(&path, "pw").unwrap();
        let page = store.messages_page(&peer, None, 20).unwrap();
        assert!(page.rows.is_empty());
        assert!(!page.has_more, "empty thread → no older history");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_limit_zero_returns_empty_but_reports_more() {
        // A zero-width page fetches limit+1 = 1 probe row, so it returns no
        // display rows yet still reports `has_more` if any history exists.
        // This documents the probe-row semantics; callers should use limit ≥ 1.
        let path = tmp();
        let peer = [0xAA; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &peer, 2);
        let page = store.messages_page(&peer, None, 0).unwrap();
        assert!(page.rows.is_empty(), "limit 0 → no display rows");
        assert!(page.has_more, "probe row proves history exists");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_preserves_sender_metadata() {
        // The `sender` column (author pub for incoming group messages) must
        // round-trip through the paged path exactly as through `messages()`.
        let path = tmp();
        let peer = [0xBB; 32];
        let author = [0xCC; 32];
        let store = Store::create(&path, "pw").unwrap();
        store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "hi".into(),
                    status: 2,
                },
                1_700_000_000,
                Some(&author),
                Some(201),
            )
            .unwrap();
        let page = store.messages_page(&peer, None, 10).unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(
            page.rows[0].sender,
            Some(author),
            "sender preserved in page"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_page_uses_index_not_full_scan() {
        // The keyset query (`WHERE peer = ?1 AND id < ?2 ORDER BY id DESC
        // LIMIT ?3`) must use `idx_messages_peer_id` (a reverse range scan),
        // not a full table scan + sort. Assert the plan mentions the index.
        let path = tmp();
        let peer = [0xDD; 32];
        let store = Store::create(&path, "pw").unwrap();
        seed_thread(&store, &peer, 5);
        let plan: String = store
            .conn
            .prepare(
                "EXPLAIN QUERY PLAN \
                 SELECT id, direction, sealed, timestamp, sender FROM messages \
                 WHERE peer = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )
            .unwrap()
            .query_map(rusqlite::params![peer.as_slice(), 3i64, 2i64], |r| {
                let s: String = r.get(3)?;
                Ok(s)
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            plan.contains("idx_messages_peer_id") || plan.contains("COVERING INDEX"),
            "paged query did not use the index; plan = {plan:?}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_wrapper_assembles_full_thread_oldest_first() {
        // The deprecated `messages()` is now a thin wrapper that loops
        // `messages_page`. It must still return the whole thread oldest-first,
        // with ids contiguous and no gaps/dups, even when the page size is
        // smaller than the thread (so the wrapper's backward walk + prepend
        // runs more than one iteration). Seed more rows than the wrapper's
        // internal `PAGE` would not be practical, but a thread larger than a
        // tiny page proves the multi-page prepend path; here we just assert
        // the wrapper's own output is the full contiguous oldest-first thread.
        let path = tmp();
        let peer = [0xEE; 32];
        let store = Store::create(&path, "pw").unwrap();
        let ids = seed_thread(&store, &peer, 9);
        let full = store.messages(&peer).unwrap();
        assert_eq!(full.len(), 9, "wrapper returns every row");
        // Oldest-first = ids ascending, matching insertion order.
        let got_ids: Vec<i64> = full.iter().map(|r| r.id).collect();
        assert_eq!(got_ids, ids, "oldest-first, insertion order preserved");
        // Text round-trips through the wrapper path too.
        assert_eq!(full[0].msg.text, "m0");
        assert_eq!(full[8].msg.text, "m8");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn messages_wrapper_empty_thread_is_empty() {
        // A peer with no rows must yield an empty vec, not an error or a
        // spurious `has_more` loop.
        let path = tmp();
        let peer = [0xEF; 32];
        let store = Store::create(&path, "pw").unwrap();
        let full = store.messages(&peer).unwrap();
        assert!(full.is_empty(), "empty thread → empty wrapper result");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_unread_then_counts_round_trips() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let a = [0x01; 32];
        let b = [0x02; 32];
        store.put_unread(&a, 3).unwrap();
        store.put_unread(&b, 7).unwrap();
        let mut counts: Vec<([u8; 32], u32)> = store.unread_counts().unwrap();
        counts.sort();
        assert_eq!(counts, vec![(a, 3), (b, 7)]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_unread_replaces_existing_count() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let a = [0x01; 32];
        store.put_unread(&a, 3).unwrap();
        store.put_unread(&a, 10).unwrap();
        let counts = store.unread_counts().unwrap();
        assert_eq!(counts, vec![(a, 10)]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_unread_zero_deletes_row() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let a = [0x01; 32];
        store.put_unread(&a, 3).unwrap();
        // Clearing the count drops the row entirely (mirror of the in-memory
        // `unread.remove` on chat open), so `unread_counts` no longer lists it.
        store.put_unread(&a, 0).unwrap();
        assert!(store.unread_counts().unwrap().is_empty());
        // Re-clearing an already-absent row is a no-op (DELETE matches nothing).
        store.put_unread(&a, 0).unwrap();
        assert!(store.unread_counts().unwrap().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unread_counts_empty_when_none_written() {
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        assert!(store.unread_counts().unwrap().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unread_counts_survive_reopen() {
        let path = tmp();
        {
            let store = Store::create(&path, "pw").unwrap();
            store.put_unread(&[0x01; 32], 5).unwrap();
            store.put_unread(&[0x02; 32], 1).unwrap();
        }
        // Reopen with the same passphrase: the `unread` table persists, so the
        // sidebar badges reappear after restart instead of resetting to 0.
        let store = Store::open(&path, "pw").unwrap();
        let mut counts: Vec<([u8; 32], u32)> = store.unread_counts().unwrap();
        counts.sort();
        assert_eq!(counts, vec![([0x01; 32], 5), ([0x02; 32], 1)]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unread_table_created_on_old_store_via_migration() {
        // A store created before the `unread` table existed must still open and
        // expose an (empty) unread_counts after init_schema runs the CREATE
        // TABLE IF NOT EXISTS migration.
        let path = tmp();
        {
            let store = Store::create(&path, "pw").unwrap();
            // Drop the table to simulate a pre-unread store.
            store
                .conn
                .execute("DROP TABLE unread", [])
                .expect("drop unread");
        }
        let store = Store::open(&path, "pw").unwrap();
        assert!(store.unread_counts().unwrap().is_empty());
        // Writing after migration works.
        store.put_unread(&[0x09; 32], 2).unwrap();
        assert_eq!(store.unread_counts().unwrap(), vec![([0x09; 32], 2)]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_message_dedups_incoming_by_server_id() {
        // The relay re-flushes an unacked outbox on the next Subscribe, so the
        // SAME envelope (same relay-assigned `server_id`) is re-delivered. The
        // `(peer, server_id)` partial unique index must make the re-delivery
        // `INSERT OR IGNORE`-collide with the original row: `put_message`
        // returns `Ok(None)` and NO second row is created. A different
        // `server_id` (a genuinely new message) still inserts `Ok(Some)`.
        let path = tmp();
        let peer = [0x12; 32];
        let store = Store::create(&path, "pw").unwrap();

        // First delivery of envelope 501.
        let first = store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "hello".into(),
                    status: 2,
                },
                1_700_000_000,
                None,
                Some(501),
            )
            .unwrap();
        assert!(first.is_some(), "first delivery inserts a row");

        // Re-delivery of the SAME envelope 501 → collision, no new row.
        let dup = store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "hello".into(),
                    status: 2,
                },
                1_700_000_001, // different timestamp must NOT bypass dedup
                None,
                Some(501),
            )
            .unwrap();
        assert!(dup.is_none(), "re-delivery of same server_id is a no-op");

        // A genuinely new envelope (502) still inserts.
        let second = store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "world".into(),
                    status: 2,
                },
                1_700_000_002,
                None,
                Some(502),
            )
            .unwrap();
        assert!(second.is_some(), "different server_id inserts normally");

        // Exactly two rows, no duplicate.
        let msgs = store.messages(&peer).unwrap();
        assert_eq!(msgs.len(), 2, "no duplicate row for re-delivered envelope");
        assert_eq!(msgs[0].msg.text, "hello");
        assert_eq!(msgs[1].msg.text, "world");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_message_outgoing_null_server_id_always_inserts() {
        // Outgoing rows carry `server_id = NULL`. The partial unique index
        // only constrains rows WHERE `server_id IS NOT NULL`, so multiple
        // outgoing rows (which all have NULL) must coexist without colliding
        // — SQLite treats NULLs as distinct under a unique index. Each
        // outgoing `put_message` returns `Ok(Some(rowid))`.
        let path = tmp();
        let peer = [0x13; 32];
        let store = Store::create(&path, "pw").unwrap();
        for i in 0..3 {
            let r = store
                .put_message(
                    &peer,
                    0,
                    &StoredMessage {
                        text: format!("out{i}"),
                        status: 1,
                    },
                    1_700_000_000 + i,
                    None,
                    None,
                )
                .unwrap();
            assert!(r.is_some(), "outgoing row {i} always inserts");
        }
        assert_eq!(store.messages(&peer).unwrap().len(), 3);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn put_message_server_id_isolated_per_peer() {
        // `server_id` is relay-global, but the dedup key is `(peer,
        // server_id)`: the same `server_id` delivered to two different peers
        // (two different threads) are distinct messages and must BOTH insert.
        // (The relay assigns a fresh id per recipient copy, but the index
        // must not over-dedup if ids ever coincide across peers.)
        let path = tmp();
        let a = [0x14; 32];
        let b = [0x15; 32];
        let store = Store::create(&path, "pw").unwrap();
        let ra = store
            .put_message(
                &a,
                1,
                &StoredMessage {
                    text: "to a".into(),
                    status: 2,
                },
                1_700_000_000,
                None,
                Some(777),
            )
            .unwrap();
        let rb = store
            .put_message(
                &b,
                1,
                &StoredMessage {
                    text: "to b".into(),
                    status: 2,
                },
                1_700_000_000,
                None,
                Some(777),
            )
            .unwrap();
        assert!(
            ra.is_some() && rb.is_some(),
            "same server_id, diff peer → both insert"
        );
        assert_eq!(store.messages(&a).unwrap().len(), 1);
        assert_eq!(store.messages(&b).unwrap().len(), 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn old_store_without_server_id_column_is_migrated() {
        // A store created before the `server_id` column existed must reopen,
        // run the ALTER TABLE ADD COLUMN migration (backfilling NULL), and
        // still load pre-existing rows (the seal is untouched). New incoming
        // rows written after the migration dedup normally.
        let path = tmp();
        let peer = [0x16; 32];
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .put_message(
                    &peer,
                    1,
                    &StoredMessage {
                        text: "legacy".into(),
                        status: 2,
                    },
                    1_700_000_000,
                    None,
                    None,
                )
                .unwrap();
            // Wipe `server_id` to force the ALTER TABLE migration path.
            store
                .conn
                .execute("ALTER TABLE messages RENAME TO messages_old", [])
                .unwrap();
            store
                .conn
                .execute(
                    "CREATE TABLE messages (id INTEGER PRIMARY KEY, peer BLOB, direction INT, \
                     sealed BLOB, timestamp INT, sender BLOB)",
                    [],
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO messages SELECT id, peer, direction, sealed, timestamp, sender \
                     FROM messages_old",
                    [],
                )
                .unwrap();
            store.conn.execute("DROP TABLE messages_old", []).unwrap();
        }
        // Reopen: init_schema adds `server_id` (NULL backfill) + the partial
        // unique index. The legacy row still loads.
        let store = Store::open(&path, "pw").unwrap();
        let msgs = store.messages(&peer).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg.text, "legacy");
        // Dedup works on the migrated store: a fresh incoming row with a
        // server_id inserts, and its re-delivery collides.
        let first = store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "new".into(),
                    status: 2,
                },
                1_700_000_010,
                None,
                Some(999),
            )
            .unwrap();
        let dup = store
            .put_message(
                &peer,
                1,
                &StoredMessage {
                    text: "new".into(),
                    status: 2,
                },
                1_700_000_011,
                None,
                Some(999),
            )
            .unwrap();
        assert!(first.is_some(), "first delivery on migrated store inserts");
        assert!(dup.is_none(), "re-delivery on migrated store dedups");
        assert_eq!(
            store.messages(&peer).unwrap().len(),
            2,
            "legacy + one new, no dup"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn peer_server_id_partial_index_exists_and_is_unique() {
        // The dedup guarantee rests on `idx_messages_peer_server_id` being a
        // UNIQUE partial index over `(peer, server_id) WHERE server_id IS NOT
        // NULL`. Assert it exists, is unique, and is partial (so outgoing
        // NULL-server_id rows are unconstrained). Survives a reopen.
        let path = tmp();
        let store = Store::create(&path, "pw").unwrap();
        let row: (String, String) = store
            .conn
            .query_row(
                "SELECT sql, 'x' FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_messages_peer_server_id'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .unwrap();
        let sql = row.0.to_ascii_lowercase();
        assert!(
            sql.contains("unique"),
            "index must be UNIQUE; sql = {sql:?}"
        );
        assert!(
            sql.contains("server_id is not null"),
            "index must be partial (WHERE server_id IS NOT NULL); sql = {sql:?}"
        );
        // Reopen: idempotent CREATE INDEX IF NOT EXISTS.
        drop(store);
        let store = Store::open(&path, "pw").unwrap();
        let still: bool = store
            .conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_messages_peer_server_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(still, "partial index lost after reopen");
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
