//! Client session state: identity, prekeys, per-peer Double Ratchet
//! sessions, and per-group Sender Keys sessions. This is the crypto-facing
//! core of the client — it owns the keys and drives X3DH + the ratchet for
//! 1:1 traffic and Sender Keys for group traffic. No networking; callers hand
//! it bundles/envelopes and it returns envelopes/plaintext.

use std::collections::HashMap;

use um_crypto::double_ratchet::RatchetSession;
use um_crypto::identity::{IdentityKey, OneTimePreKey, PreKeyBundle as CryptoBundle, SignedPreKey};
use um_crypto::sender_keys::{GroupEncrypted, GroupSession, SenderKeyState};
use um_crypto::x3dh;
use um_protocol::{EncryptedEnvelope, MessageKind, PreKeyBundle};

use crate::ClientError;
use crate::crypto_bridge::{
    encrypted_from_envelope, envelope_from_encrypted, envelope_from_group_encrypted,
    group_encrypted_from_envelope, init_from_envelope,
};

/// A client's cryptographic session state. Owns the identity key, the
/// signed prekey, the one-time prekeys, a ratchet session per peer (keyed by
/// the peer's identity pub), and a Sender Keys `GroupSession` per group id.
///
/// Previous signed prekeys are retained after rotation so that an X3DH
/// initiation made against a stale (cached) bundle — carrying an old signed
/// prekey id — can still be completed: the receiver looks up the matching
/// signed prekey by `init.bob_signed_prekey_id` instead of always using the
/// current one. Without this, rotating the signed prekey would break any
/// in-flight initiation that had not yet re-fetched the bundle.
///
/// `Serialize`/`Deserialize` so the GUI bridge can persist the whole session
/// (encrypted) to the local store under a single key and restore it on unlock.
/// All fields are serde-capable crypto types; the derived impl round-trips
/// through postcard in `Store::put`/`get`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ClientSession {
    identity: IdentityKey,
    signed_prekey: SignedPreKey,
    /// Signed prekeys superseded by [`rotate_signed_prekey`], keyed by id.
    /// Retained so stale X3DH initiations against an old bundle still decrypt.
    ///
    /// [`rotate_signed_prekey`]: ClientSession::rotate_signed_prekey
    #[serde(default)]
    previous_signed_prekeys: HashMap<u32, SignedPreKey>,
    one_time_prekeys: HashMap<u32, OneTimePreKey>,
    ratchets: HashMap<[u8; 32], RatchetSession>,
    groups: HashMap<[u8; 32], GroupSession>,
}

impl ClientSession {
    /// Generate a fresh session: new identity, signed prekey (id 1), and
    /// `n` one-time prekeys (ids 1..=n).
    pub fn generate(one_time_count: u32) -> Self {
        let identity = IdentityKey::generate();
        let signed_prekey = SignedPreKey::generate(1, &identity);
        let one_time_prekeys = (1..=one_time_count)
            .map(|i| {
                let k = OneTimePreKey::generate(i);
                (k.id, k)
            })
            .collect();
        Self {
            identity,
            signed_prekey,
            previous_signed_prekeys: HashMap::new(),
            one_time_prekeys,
            ratchets: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    /// This client's identity public key (32 bytes).
    pub fn identity_pub(&self) -> [u8; 32] {
        self.identity.verifying.to_bytes()
    }

    /// This client's identity fingerprint (`SHA-256` of the identity pub),
    /// for manual/QR verification in the UI.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint()
    }

    /// Build the protocol `PreKeyBundle` to register with the server.
    pub fn registration_bundle(&self) -> PreKeyBundle {
        let crypto_bundle = CryptoBundle::from_identity(
            &self.identity,
            &self.signed_prekey,
            self.one_time_prekeys
                .values()
                .collect::<Vec<_>>()
                .as_slice(),
        );
        PreKeyBundle {
            identity_pub: self.identity_pub(),
            signed_prekey_id: crypto_bundle.signed_prekey_id,
            signed_prekey_pub: crypto_bundle.signed_prekey_pub.to_bytes(),
            signed_prekey_sig: crypto_bundle.signed_prekey_sig.to_bytes().to_vec(),
            one_time_prekeys: crypto_bundle
                .one_time_prekeys
                .iter()
                .map(|(k, v)| (*k, v.to_bytes()))
                .collect(),
        }
    }

    /// Rotate the signed prekey: generate a fresh signed prekey with a new
    /// id (one greater than the current), retiring the old one into
    /// `previous_signed_prekeys` so an in-flight X3DH initiation against the
    /// old bundle still decrypts. Existing Double-Ratchet sessions are
    /// unaffected — their root key is already established; only future X3DH
    /// initiations use the new prekey. The caller re-registers the resulting
    /// bundle with the server. Returns the new signed-prekey id.
    pub fn rotate_signed_prekey(&mut self) -> u32 {
        let new_id = self.signed_prekey.id + 1;
        let old = std::mem::replace(
            &mut self.signed_prekey,
            SignedPreKey::generate(new_id, &self.identity),
        );
        self.previous_signed_prekeys.insert(old.id, old);
        new_id
    }

    /// Generate + add `count` fresh one-time prekeys with new ids (continuing
    /// past the highest existing id). Existing one-time prekeys are kept
    /// (the server bundle advertises all of them). The caller re-registers.
    /// Returns the ids of the newly added prekeys.
    pub fn replenish_one_time_prekeys(&mut self, count: u32) -> Vec<u32> {
        let next_id = self.one_time_prekeys.keys().copied().max().unwrap_or(0) + 1;
        let mut new_ids = Vec::with_capacity(count as usize);
        for i in 0..count {
            let id = next_id + i;
            let k = OneTimePreKey::generate(id);
            self.one_time_prekeys.insert(id, k);
            new_ids.push(id);
        }
        new_ids
    }

    /// The number of one-time prekeys currently held (for tests/UI).
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// The current signed-prekey id (for tests/UI).
    pub fn signed_prekey_id(&self) -> u32 {
        self.signed_prekey.id
    }

    /// Start a new 1:1 session with `peer` by running X3DH against their
    /// fetched bundle. Returns the first encrypted message (which carries
    /// the X3DH init) as a wire envelope. The envelope id is left 0; the
    /// server assigns the real id.
    pub fn start_session(
        &mut self,
        peer_bundle: &PreKeyBundle,
        first_plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, ClientError> {
        // Reconstruct a crypto bundle from the protocol bundle (opaque bytes
        // -> typed). The signed-prekey signature is verified inside
        // `x3dh::initiate` via `bundle.verify()`.
        let crypto_bundle = Self::reconstruct_peer_bundle(peer_bundle)?;
        let one_time_id = peer_bundle.one_time_prekeys.first().map(|(id, _)| *id);

        let (session_init, init_msg) = x3dh::initiate(&self.identity, &crypto_bundle, one_time_id)?;
        let mut ratchet = RatchetSession::init_alice(&session_init)?;
        let encrypted = ratchet.encrypt(first_plaintext)?;
        let peer_pub = peer_bundle.identity_pub;
        self.ratchets.insert(peer_pub, ratchet);

        let envelope =
            envelope_from_encrypted(0, self.identity_pub(), &encrypted, Some(&init_msg))?;
        Ok(envelope)
    }

    /// Encrypt a follow-up message to an existing peer session. Fails if no
    /// session exists.
    pub fn send(
        &mut self,
        peer: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, ClientError> {
        let ratchet = self.ratchets.get_mut(peer).ok_or(ClientError::NoSession)?;
        let encrypted = ratchet.encrypt(plaintext)?;
        let envelope = envelope_from_encrypted(0, self.identity_pub(), &encrypted, None)?;
        Ok(envelope)
    }

    // ---- Group (Sender Keys) ------------------------------------------------

    /// Create a fresh group session for `group_id`. The caller is the group
    /// founder; their own sender-key state is generated and stored. Peers are
    /// added later via `add_group_peer` after their distribution state is
    /// received (typically sent individually-encrypted over each 1:1 ratchet).
    pub fn create_group(&mut self, group_id: [u8; 32]) -> Result<(), ClientError> {
        let session = GroupSession::new(group_id, &self.identity)?;
        self.groups.insert(group_id, session);
        Ok(())
    }

    /// Export this client's own sender-key distribution state for `group_id`,
    /// to be sent to every other member of the group. In a real client this is
    /// individually-encrypted to each peer over their 1:1 Double Ratchet and
    /// sent via the relay; here we just hand back the typed state so the
    /// caller can transport it however they like. Fails if the group is
    /// unknown.
    pub fn group_distribution(&self, group_id: &[u8; 32]) -> Result<SenderKeyState, ClientError> {
        let session = self
            .groups
            .get(group_id)
            .ok_or(ClientError::NoGroupSession(hex_id(group_id)))?;
        Ok(session.export_self_state())
    }

    /// Import a peer's sender-key distribution state into the group session
    /// for `group_id`. After this the client can decrypt group messages from
    /// that peer. Fails if the local group session does not exist (the peer
    /// must already have `create_group`'d or otherwise imported the group).
    pub fn add_group_peer(
        &mut self,
        group_id: &[u8; 32],
        state: SenderKeyState,
    ) -> Result<(), ClientError> {
        let session = self
            .groups
            .get_mut(group_id)
            .ok_or(ClientError::NoGroupSession(hex_id(group_id)))?;
        session.add_peer(state)?;
        Ok(())
    }

    /// Encrypt a group message for `group_id`. Returns a wire envelope with
    /// `kind = Group`. The envelope id is left 0; the server assigns the real
    /// id. The caller is responsible for fanning the envelope out to every
    /// group member's identity pub via the relay's `recipients` list.
    pub fn send_group(
        &mut self,
        group_id: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, ClientError> {
        let session = self
            .groups
            .get_mut(group_id)
            .ok_or(ClientError::NoGroupSession(hex_id(group_id)))?;
        let group_encrypted: GroupEncrypted = session.encrypt(plaintext)?;
        let envelope = envelope_from_group_encrypted(0, self.identity_pub(), &group_encrypted)?;
        Ok(envelope)
    }

    /// True if a group session for `group_id` exists locally.
    pub fn has_group(&self, group_id: &[u8; 32]) -> bool {
        self.groups.contains_key(group_id)
    }

    /// Receive and decrypt an envelope. Routes by `kind`: `Direct` runs the
    /// 1:1 Double Ratchet path (seeding a new ratchet from the X3DH init on
    /// first contact); `Group` runs the Sender Keys path against the matching
    /// `GroupSession`. Returns the decrypted plaintext and the sender's
    /// identity pub.
    pub fn receive(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<(Vec<u8>, [u8; 32]), ClientError> {
        match envelope.kind {
            MessageKind::Direct => self.receive_direct(envelope),
            MessageKind::Group => self.receive_group(envelope),
        }
    }

    /// 1:1 Double Ratchet receive path.
    fn receive_direct(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<(Vec<u8>, [u8; 32]), ClientError> {
        let sender = envelope.sender;

        // No session yet: must be an initial message carrying an init.
        if !self.ratchets.contains_key(&sender) {
            let init = init_from_envelope(envelope)?.ok_or(ClientError::NoSession)?;
            // Select the signed prekey the sender used. An initiation against
            // a stale bundle carries the old id; we look it up in
            // `previous_signed_prekeys` so the DH matches. Falls back to the
            // current signed prekey when ids match (the common case) or when
            // the init predates rotation tracking.
            let spk = self
                .previous_signed_prekeys
                .get(&init.bob_signed_prekey_id)
                .unwrap_or(&self.signed_prekey);
            // Find the one-time prekey the sender used.
            let otpk = match init.bob_one_time_prekey_id {
                Some(id) => Some(
                    self.one_time_prekeys
                        .get(&id)
                        .ok_or(ClientError::NoOneTimePreKey(id))?,
                ),
                None => None,
            };
            let session_init = x3dh::receive(&self.identity, spk, otpk, &init)?;
            let mut ratchet = RatchetSession::init_bob(&session_init, &spk.priv_key)?;
            let encrypted = encrypted_from_envelope(envelope)?;
            let plaintext = ratchet.decrypt(&encrypted)?;
            self.ratchets.insert(sender, ratchet);
            return Ok((plaintext, sender));
        }

        // Existing session: decrypt in place.
        let encrypted = encrypted_from_envelope(envelope)?;
        let ratchet = self
            .ratchets
            .get_mut(&sender)
            .ok_or(ClientError::NoSession)?;
        let plaintext = ratchet.decrypt(&encrypted)?;
        Ok((plaintext, sender))
    }

    /// Group Sender Keys receive path. Looks up the `GroupSession` by the
    /// `group_id` encoded in the group header and decrypts with it.
    ///
    /// Sender authentication: the Sender-Key `header.sender_id` is the sender's
    /// `fingerprint(identity_pub)` (set in `GroupSession::new`), and the group
    /// AEAD signature is over the header + ciphertext — **not** over
    /// `envelope.sender`. So a group member could sign a valid group message
    /// with their own Sender-Key key while setting `envelope.sender` to another
    /// member's pub, fooling the receiver into attributing the message to that
    /// other member. We bind the two: `header.sender_id` must equal
    /// `fingerprint_of_pub(envelope.sender)`, else the message is rejected with
    /// `GroupSenderMismatch` (before any decrypt work).
    fn receive_group(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<(Vec<u8>, [u8; 32]), ClientError> {
        let group_encrypted = group_encrypted_from_envelope(envelope)?;
        // Bind the wire-level sender to the crypto-level sender id. The header
        // is deserialized above, so `sender_id` is attacker-controlled only in
        //sofar as the envelope bytes are; the fingerprint check ties it to the
        // identity pub the relay attributed the envelope to.
        let expected_sender_id = um_crypto::fingerprint_of_pub(&envelope.sender);
        if group_encrypted.header.sender_id != expected_sender_id {
            return Err(ClientError::GroupSenderMismatch);
        }
        let group_id = group_encrypted.header.group_id;
        let session = self
            .groups
            .get_mut(&group_id)
            .ok_or(ClientError::NoGroupSession(hex_id(&group_id)))?;
        let plaintext = session.decrypt(&group_encrypted)?;
        Ok((plaintext, envelope.sender))
    }

    /// Reconstruct a typed crypto `PreKeyBundle` from a protocol bundle.
    fn reconstruct_peer_bundle(bundle: &PreKeyBundle) -> Result<CryptoBundle, ClientError> {
        use um_crypto::{Signature, VerifyingKey};
        let identity_pub = VerifyingKey::from_bytes(&bundle.identity_pub)
            .map_err(|_| ClientError::Store("bad peer identity pub".into()))?;
        let signed_prekey_pub = x25519_pub(&bundle.signed_prekey_pub);
        let signed_prekey_sig = Signature::from_slice(&bundle.signed_prekey_sig)
            .map_err(|_| ClientError::Store("bad peer signature".into()))?;
        let one_time_prekeys = bundle
            .one_time_prekeys
            .iter()
            .map(|(id, pub_bytes)| (*id, x25519_pub(pub_bytes)))
            .collect::<Vec<_>>();
        Ok(CryptoBundle {
            identity_pub,
            signed_prekey_id: bundle.signed_prekey_id,
            signed_prekey_pub,
            signed_prekey_sig,
            one_time_prekeys,
        })
    }
}

/// Decode 32 bytes into an X25519 `PublicKey`.
fn x25519_pub(bytes: &[u8; 32]) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(*bytes)
}

/// Render a 32-byte id as a short hex string for error messages.
fn hex_id(id: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &id[..4] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two sessions exchange a first message + a follow-up, end to end
    /// through the session API (no network).
    #[test]
    fn first_message_and_follow_up_decrypt() {
        let mut alice = ClientSession::generate(5);
        let mut bob = ClientSession::generate(5);
        let bob_bundle = bob.registration_bundle();

        // Alice starts a session with Bob and sends "hi".
        let env1 = alice
            .start_session(&bob_bundle, b"hi")
            .expect("alice start");
        assert!(env1.init.is_some());

        // Bob receives and decrypts.
        let (pt1, sender) = bob.receive(&env1).expect("bob receive");
        assert_eq!(pt1, b"hi");
        assert_eq!(sender, alice.identity_pub());

        // Alice sends a follow-up (no init).
        let env2 = alice
            .send(&bob.identity_pub(), b"second")
            .expect("alice send");
        assert!(env2.init.is_none());
        let (pt2, _) = bob.receive(&env2).expect("bob receive 2");
        assert_eq!(pt2, b"second");
    }

    #[test]
    fn registration_bundle_is_self_consistent() {
        let alice = ClientSession::generate(3);
        let bundle = alice.registration_bundle();
        assert_eq!(bundle.identity_pub, alice.identity_pub());
        assert_eq!(bundle.one_time_prekeys.len(), 3);
        // The signed-prekey signature verifies against the identity pub.
        use um_crypto::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&bundle.identity_pub).unwrap();
        let sig = Signature::from_slice(&bundle.signed_prekey_sig).unwrap();
        use ed25519_dalek::Verifier;
        assert!(vk.verify(&bundle.signed_prekey_pub, &sig).is_ok());
    }

    #[test]
    fn send_without_session_errors() {
        let mut alice = ClientSession::generate(1);
        let err = alice.send(&[0xFF; 32], b"hi").unwrap_err();
        assert!(matches!(err, ClientError::NoSession));
    }

    #[test]
    fn receive_without_init_and_no_session_errors() {
        let mut alice = ClientSession::generate(1);
        // An envelope with no init and no existing session.
        let env = EncryptedEnvelope {
            id: 1,
            sender: [0x77; 32],
            kind: MessageKind::Direct,
            header: vec![1, 2, 3],
            init: None,
            ciphertext: vec![0xAA; 8],
            signature: vec![],
        };
        let err = alice.receive(&env).unwrap_err();
        assert!(matches!(err, ClientError::NoSession));
    }

    #[test]
    fn bidirectional_exchange() {
        let mut alice = ClientSession::generate(5);
        let mut bob = ClientSession::generate(5);
        let bob_bundle = bob.registration_bundle();

        // Alice -> Bob.
        let env_a = alice.start_session(&bob_bundle, b"hello").unwrap();
        let (pt, _) = bob.receive(&env_a).unwrap();
        assert_eq!(pt, b"hello");

        // Bob -> Alice (Bob now has a session with Alice; he can send).
        let env_b = bob.send(&alice.identity_pub(), b"world").unwrap();
        let (pt, _) = alice.receive(&env_b).unwrap();
        assert_eq!(pt, b"world");
    }

    // ---- Group (Sender Keys) session tests ----------------------------------

    /// Two members create a group, exchange distributions, and each can
    /// encrypt + decrypt group messages through the session API.
    #[test]
    fn group_two_members_round_trip() {
        let mut alice = ClientSession::generate(1);
        let mut bob = ClientSession::generate(1);
        let gid = [0xAA; 32];

        alice.create_group(gid).unwrap();
        bob.create_group(gid).unwrap();

        // Exchange distributions (in-band this rides the 1:1 ratchet; here we
        // pass the typed state directly).
        let alice_state = alice.group_distribution(&gid).unwrap();
        let bob_state = bob.group_distribution(&gid).unwrap();
        alice.add_group_peer(&gid, bob_state).unwrap();
        bob.add_group_peer(&gid, alice_state).unwrap();

        // Alice -> group.
        let env = alice.send_group(&gid, b"hi group").unwrap();
        assert_eq!(env.kind, MessageKind::Group);
        assert!(env.init.is_none());
        assert!(
            !env.signature.is_empty(),
            "group env must carry a signature"
        );
        let (pt, sender) = bob.receive(&env).unwrap();
        assert_eq!(pt, b"hi group");
        assert_eq!(sender, alice.identity_pub());

        // Bob -> group.
        let env2 = bob.send_group(&gid, b"hello back").unwrap();
        let (pt2, _) = alice.receive(&env2).unwrap();
        assert_eq!(pt2, b"hello back");
    }

    /// A three-member group: each member distributes to the other two, and
    /// any member's message decrypts for both peers.
    #[test]
    fn group_three_members_all_decrypt() {
        let mut a = ClientSession::generate(1);
        let mut b = ClientSession::generate(1);
        let mut c = ClientSession::generate(1);
        let gid = [0xBB; 32];

        for s in [&mut a, &mut b, &mut c] {
            s.create_group(gid).unwrap();
        }
        // Full mesh distribution.
        let a_state = a.group_distribution(&gid).unwrap();
        let b_state = b.group_distribution(&gid).unwrap();
        let c_state = c.group_distribution(&gid).unwrap();
        b.add_group_peer(&gid, a_state.clone()).unwrap();
        c.add_group_peer(&gid, a_state).unwrap();
        a.add_group_peer(&gid, b_state.clone()).unwrap();
        c.add_group_peer(&gid, b_state).unwrap();
        a.add_group_peer(&gid, c_state.clone()).unwrap();
        b.add_group_peer(&gid, c_state).unwrap();

        // A sends; b and c both decrypt.
        let env = a.send_group(&gid, b"from a").unwrap();
        assert_eq!(b.receive(&env).unwrap().0, b"from a");
        assert_eq!(c.receive(&env).unwrap().0, b"from a");

        // C sends; a and b both decrypt.
        let env2 = c.send_group(&gid, b"from c").unwrap();
        assert_eq!(a.receive(&env2).unwrap().0, b"from c");
        assert_eq!(b.receive(&env2).unwrap().0, b"from c");
    }

    /// Receiving a group message with no local group session errors.
    #[test]
    fn group_receive_without_session_errors() {
        let mut alice = ClientSession::generate(1);
        // Build a real group envelope from a stranger's group alice never
        // joined, so the header/signature are well-formed and the only failure
        // is the missing local group session.
        let mut stranger = ClientSession::generate(1);
        let gid = [0x77; 32];
        stranger.create_group(gid).unwrap();
        let env = stranger.send_group(&gid, b"injected").unwrap();
        let err = alice.receive(&env).unwrap_err();
        assert!(matches!(err, ClientError::NoGroupSession(_)));
    }

    /// `send_group` on an unknown group errors rather than panicking.
    #[test]
    fn send_group_without_session_errors() {
        let mut alice = ClientSession::generate(1);
        let err = alice.send_group(&[0x99; 32], b"hi").unwrap_err();
        assert!(matches!(err, ClientError::NoGroupSession(_)));
    }

    /// A group message whose `envelope.sender` does not match the Sender-Key
    /// `header.sender_id` is rejected with `GroupSenderMismatch`. This is the
    /// spoofing fix: a group member signs a valid group message with their own
    /// Sender-Key key but sets `envelope.sender` to another member's pub to
    /// misattribute. The receiver binds the two via
    /// `fingerprint_of_pub(envelope.sender) == header.sender_id` and rejects.
    #[test]
    fn group_receive_rejects_spoofed_sender() {
        let mut alice = ClientSession::generate(1);
        let mut bob = ClientSession::generate(1);
        let gid = [0xCC; 32];
        alice.create_group(gid).unwrap();
        bob.create_group(gid).unwrap();
        let alice_state = alice.group_distribution(&gid).unwrap();
        let bob_state = bob.group_distribution(&gid).unwrap();
        alice.add_group_peer(&gid, bob_state).unwrap();
        bob.add_group_peer(&gid, alice_state).unwrap();

        // Alice sends a legitimate group message.
        let mut env = alice.send_group(&gid, b"from alice").unwrap();
        // Sanity: it decrypts cleanly before tampering.
        assert_eq!(bob.receive(&env).unwrap().0, b"from alice");

        // Spoof: rewrite the wire sender to bob's own pub. The header + signature
        // are still alice's (header.sender_id = fingerprint(alice)), so the AEAD
        // would decrypt — but the sender binding now fails: the envelope claims
        // to be from bob while the Sender-Key state is alice's.
        env.sender = bob.identity_pub();
        let err = bob.receive(&env).unwrap_err();
        assert!(
            matches!(err, ClientError::GroupSenderMismatch),
            "spoofed sender must be rejected, got {err:?}"
        );
    }

    // ---- Signed-prekey rotation + one-time replenishment --------------------

    /// Rotating the signed prekey bumps the id and changes the pub key; the
    /// new bundle verifies against the (unchanged) identity.
    #[test]
    fn rotate_signed_prekey_bumps_id_and_keeps_signature_valid() {
        let mut alice = ClientSession::generate(1);
        let old_id = alice.signed_prekey_id();
        let old_bundle = alice.registration_bundle();
        let new_id = alice.rotate_signed_prekey();
        assert_eq!(new_id, old_id + 1);
        assert_eq!(alice.signed_prekey_id(), new_id);
        let new_bundle = alice.registration_bundle();
        // The signed prekey pub changed.
        assert_ne!(old_bundle.signed_prekey_pub, new_bundle.signed_prekey_pub);
        // The new signature still verifies against the identity pub.
        use um_crypto::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&new_bundle.identity_pub).unwrap();
        let sig = Signature::from_slice(&new_bundle.signed_prekey_sig).unwrap();
        use ed25519_dalek::Verifier;
        assert!(vk.verify(&new_bundle.signed_prekey_pub, &sig).is_ok());
    }

    /// Replenishing one-time prekeys adds new ids past the current max and
    /// keeps the old ones (the bundle advertises all of them).
    #[test]
    fn replenish_one_time_prekeys_adds_past_max_and_keeps_old() {
        let mut alice = ClientSession::generate(3);
        assert_eq!(alice.one_time_prekey_count(), 3);
        let added = alice.replenish_one_time_prekeys(2);
        assert_eq!(added, vec![4, 5]);
        assert_eq!(alice.one_time_prekey_count(), 5);
        // Old ids still present.
        let bundle = alice.registration_bundle();
        let ids: Vec<u32> = bundle.one_time_prekeys.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&1) && ids.contains(&4) && ids.contains(&5));
    }

    /// An X3DH initiation made against a STALE bundle (old signed prekey id)
    /// still decrypts after rotation, because the retired signed prekey is
    /// retained and selected by id. This is the core correctness guarantee of
    /// rotation.
    #[test]
    fn stale_bundle_initiation_decrypts_after_rotation() {
        let mut alice = ClientSession::generate(2);
        let mut bob = ClientSession::generate(2);
        // Alice caches bob's CURRENT bundle, then bob rotates his signed
        // prekey (simulating a re-register alice has not seen yet).
        let stale_bundle = bob.registration_bundle();
        bob.rotate_signed_prekey();
        // Alice initiates against the STALE bundle.
        let env = alice
            .start_session(&stale_bundle, b"hi after rotation")
            .expect("alice start against stale bundle");
        // Bob decrypts: the init carries the old signed-prekey id, which bob
        // looks up in previous_signed_prekeys.
        let (pt, sender) = bob.receive(&env).expect("bob decrypt stale initiation");
        assert_eq!(pt, b"hi after rotation");
        assert_eq!(sender, alice.identity_pub());
    }

    /// A fresh initiation against the CURRENT (post-rotation) bundle also
    /// decrypts, so rotation does not break new sessions either.
    #[test]
    fn fresh_bundle_initiation_decrypts_after_rotation() {
        let mut alice = ClientSession::generate(2);
        let mut bob = ClientSession::generate(2);
        bob.rotate_signed_prekey();
        let fresh_bundle = bob.registration_bundle();
        let env = alice
            .start_session(&fresh_bundle, b"hi fresh")
            .expect("alice start against fresh bundle");
        let (pt, _) = bob.receive(&env).expect("bob decrypt fresh initiation");
        assert_eq!(pt, b"hi fresh");
    }

    /// An existing ratchet session survives signed-prekey rotation (the root
    /// key is already established and independent of the signed prekey).
    #[test]
    fn existing_ratchet_survives_signed_prekey_rotation() {
        let mut alice = ClientSession::generate(2);
        let mut bob = ClientSession::generate(2);
        let bob_bundle = bob.registration_bundle();
        // Establish a session.
        let env1 = alice.start_session(&bob_bundle, b"first").unwrap();
        let _ = bob.receive(&env1).unwrap();
        // Bob rotates; alice has not seen it. Alice sends a follow-up on the
        // existing ratchet (no X3DH) — bob must still decrypt it.
        bob.rotate_signed_prekey();
        let env2 = alice.send(&bob.identity_pub(), b"second").unwrap();
        let (pt, _) = bob.receive(&env2).unwrap();
        assert_eq!(pt, b"second");
    }

    /// A session round-trips through postcard after rotation, so the
    /// `previous_signed_prekeys` map persists to the encrypted store.
    #[test]
    fn session_with_rotated_prekey_serializes() {
        let mut alice = ClientSession::generate(1);
        alice.rotate_signed_prekey();
        alice.replenish_one_time_prekeys(2);
        let bytes = postcard::to_allocvec(&alice).expect("serialize");
        let back: ClientSession = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back.signed_prekey_id(), alice.signed_prekey_id());
        assert_eq!(back.one_time_prekey_count(), alice.one_time_prekey_count());
        // previous_signed_prekeys survived (serde default made it backward-safe).
        assert!(back.previous_signed_prekeys.contains_key(&1));
    }
}
