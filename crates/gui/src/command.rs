//! Commands the GUI sends to the bridge (GUI → bridge), fire-and-forget. The
//! bridge acknowledges via [`crate::Event`] when relevant. The GUI never blocks
//! on a command.

use std::net::SocketAddr;

/// A command from the iced UI to the async bridge.
#[derive(Debug, Clone)]
pub enum Command {
    // ---- Setup / Login -------------------------------------------------
    /// First-run: generate a fresh identity + create the encrypted store.
    Setup {
        passphrase: String,
        one_time_count: u32,
    },
    /// Open an existing store with a passphrase.
    Unlock { passphrase: String },
    /// Connect to the relay + register the bundle + subscribe for push.
    Connect { addr: SocketAddr },

    // ---- Contacts ------------------------------------------------------
    /// Record a contact by 32-byte identity pub + nickname.
    AddContact {
        identity_pub: [u8; 32],
        nickname: String,
    },
    /// Mark a contact's fingerprint as manually verified.
    VerifyFingerprint { identity_pub: [u8; 32] },

    // ---- 1:1 chat ------------------------------------------------------
    /// Start a new 1:1 session with `peer` (X3DH via fetched bundle) and send
    /// `first_message` as the first ratchet message. `local_id` matches the
    /// optimistic UI row to the later `Event::Sent` / `Event::SendFailed`.
    StartSession {
        peer: [u8; 32],
        first_message: String,
        local_id: u64,
    },
    /// Send to an existing 1:1 session.
    SendMessage {
        peer: [u8; 32],
        text: String,
        local_id: u64,
    },
    /// Hydrate the thread cache for `peer` from the store history.
    LoadThread { peer: [u8; 32] },

    // ---- Group chat (Sender Keys) --------------------------------------
    /// Create a new group `name` with `members`; the founder distributes their
    /// sender-key state to each member over their 1:1 ratchet.
    CreateGroup {
        name: String,
        members: Vec<[u8; 32]>,
    },
    /// Send a group message.
    SendGroupMessage {
        group: [u8; 32],
        text: String,
        local_id: u64,
    },
    /// Hydrate the group thread cache from the store history.
    LoadGroupThread { group: [u8; 32] },

    // ---- Settings ------------------------------------------------------
    /// Rotate the signed prekey and re-register the bundle.
    RotateSignedPrekey,
    /// Generate + register `count` fresh one-time prekeys.
    ReplenishOneTimePrekeys { count: u32 },
    /// Disconnect from the current server and reconnect to `addr`.
    ChangeServer { addr: SocketAddr },
    /// Drop the store + net, return to the Login view.
    Logout,
}
