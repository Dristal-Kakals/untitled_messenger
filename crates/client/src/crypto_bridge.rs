//! Thin bridge between `um_crypto` typed objects and `um_protocol` opaque
//! byte fields. The protocol crate carries crypto material as `Vec<u8>` so
//! the server stays crypto-free; this module (client-side only) serializes
//! and deserializes those bytes with postcard using the crypto types' own
//! `serde` impls. No logic — just encoding.

use um_crypto::double_ratchet::{Encrypted, Header};
use um_crypto::sender_keys::{GroupEncrypted, GroupHeader};
use um_crypto::x3dh::InitMessage;
use um_protocol::{EncryptedEnvelope, MessageKind};

use crate::ClientError;

/// Build a wire `EncryptedEnvelope` from a 1:1 ratchet `Encrypted` payload.
///
/// `sender` is the sender's identity pub. `init` is the X3DH init message,
/// present only on the first message of a 1:1 session. The `kind` is set to
/// `Direct` and `signature` is empty (1:1 auth is via the ratchet AEAD + DH).
pub fn envelope_from_encrypted(
    id: u64,
    sender: [u8; 32],
    encrypted: &Encrypted,
    init: Option<&InitMessage>,
) -> Result<EncryptedEnvelope, ClientError> {
    let header = postcard::to_allocvec(&encrypted.header)?;
    let init_bytes = match init {
        Some(im) => Some(postcard::to_allocvec(im)?),
        None => None,
    };
    Ok(EncryptedEnvelope {
        id,
        sender,
        kind: MessageKind::Direct,
        header,
        init: init_bytes,
        ciphertext: encrypted.ciphertext.clone(),
        signature: Vec::new(),
    })
}

/// Build a wire `EncryptedEnvelope` from a group `GroupEncrypted` payload.
///
/// `sender` is the sender's identity pub (the group-oblivious outer sender).
/// The group header, ciphertext, and the sender's group signing signature are
/// carried opaquely; `kind` is `Group` and `init` is `None`.
pub fn envelope_from_group_encrypted(
    id: u64,
    sender: [u8; 32],
    group: &GroupEncrypted,
) -> Result<EncryptedEnvelope, ClientError> {
    let header = postcard::to_allocvec(&group.header)?;
    Ok(EncryptedEnvelope {
        id,
        sender,
        kind: MessageKind::Group,
        header,
        init: None,
        ciphertext: group.ciphertext.clone(),
        signature: group.signature.to_bytes().to_vec(),
    })
}

/// Recover a ratchet `Header` from a wire envelope's opaque `header` bytes.
pub fn header_from_envelope(env: &EncryptedEnvelope) -> Result<Header, ClientError> {
    Ok(postcard::from_bytes(&env.header)?)
}

/// Recover a group `GroupHeader` from a wire envelope's opaque `header` bytes.
pub fn group_header_from_envelope(env: &EncryptedEnvelope) -> Result<GroupHeader, ClientError> {
    Ok(postcard::from_bytes(&env.header)?)
}

/// Recover an X3DH `InitMessage` from a wire envelope's opaque `init` bytes,
/// if present.
pub fn init_from_envelope(env: &EncryptedEnvelope) -> Result<Option<InitMessage>, ClientError> {
    match &env.init {
        Some(bytes) => Ok(Some(postcard::from_bytes(bytes)?)),
        None => Ok(None),
    }
}

/// Reconstruct the ratchet `Encrypted` (header + ciphertext) from a wire
/// envelope. The header is deserialized; the ciphertext is taken verbatim.
pub fn encrypted_from_envelope(env: &EncryptedEnvelope) -> Result<Encrypted, ClientError> {
    let header = header_from_envelope(env)?;
    Ok(Encrypted {
        header,
        ciphertext: env.ciphertext.clone(),
    })
}

/// Reconstruct a group `GroupEncrypted` (header + ciphertext + signature) from
/// a wire envelope. The header and signature are deserialized; the ciphertext
/// is taken verbatim.
pub fn group_encrypted_from_envelope(
    env: &EncryptedEnvelope,
) -> Result<GroupEncrypted, ClientError> {
    let header = group_header_from_envelope(env)?;
    let signature = um_crypto::Signature::from_slice(&env.signature)
        .map_err(|_| ClientError::Store("bad group signature".into()))?;
    Ok(GroupEncrypted {
        header,
        ciphertext: env.ciphertext.clone(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};

    /// Full round trip: Alice encrypts under a fresh ratchet, bridge to a
    /// wire envelope, bridge back, Bob decrypts and gets the plaintext.
    #[test]
    fn envelope_round_trips_through_bridge() {
        // Bob's keys.
        let bob = IdentityKey::generate();
        let bob_spk = SignedPreKey::generate(1, &bob);
        let bob_otpk = OneTimePreKey::generate(10);
        let bob_bundle =
            um_crypto::identity::PreKeyBundle::from_identity(&bob, &bob_spk, &[&bob_otpk]);

        // Alice initiates X3DH against Bob's bundle.
        let alice = IdentityKey::generate();
        let (session_init, init_msg) =
            um_crypto::x3dh::initiate(&alice, &bob_bundle, Some(10)).expect("x3dh initiate");
        let mut alice_ratchet =
            um_crypto::double_ratchet::RatchetSession::init_alice(&session_init)
                .expect("init_alice");

        // Alice encrypts the first message (carries init).
        let encrypted = alice_ratchet.encrypt(b"hello bob").expect("encrypt");
        let alice_pub = alice.verifying.to_bytes();
        let envelope = envelope_from_encrypted(1, alice_pub, &encrypted, Some(&init_msg))
            .expect("bridge to envelope");

        // Bridge back on Bob's side.
        let recovered = encrypted_from_envelope(&envelope).expect("bridge from envelope");
        let recovered_init = init_from_envelope(&envelope).expect("init from envelope");
        assert!(recovered_init.is_some());

        // Bob runs X3DH receive + seeds his ratchet.
        let bob_session = um_crypto::x3dh::receive(
            &bob,
            &bob_spk,
            Some(&bob_otpk),
            recovered_init.as_ref().unwrap(),
        )
        .expect("x3dh receive");
        let mut bob_ratchet =
            um_crypto::double_ratchet::RatchetSession::init_bob(&bob_session, &bob_spk.priv_key)
                .expect("init_bob");

        let plaintext = bob_ratchet.decrypt(&recovered).expect("decrypt");
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn follow_up_message_has_no_init() {
        // Reuse the setup above but send a second message (init=None).
        let bob = IdentityKey::generate();
        let bob_spk = SignedPreKey::generate(1, &bob);
        let bob_otpk = OneTimePreKey::generate(10);
        let bob_bundle =
            um_crypto::identity::PreKeyBundle::from_identity(&bob, &bob_spk, &[&bob_otpk]);
        let alice = IdentityKey::generate();
        let (session_init, _init_msg) =
            um_crypto::x3dh::initiate(&alice, &bob_bundle, Some(10)).expect("x3dh initiate");
        let mut alice_ratchet =
            um_crypto::double_ratchet::RatchetSession::init_alice(&session_init)
                .expect("init_alice");

        // Second message: no init.
        let encrypted = alice_ratchet.encrypt(b"follow up").expect("encrypt");
        let envelope = envelope_from_encrypted(2, alice.verifying.to_bytes(), &encrypted, None)
            .expect("bridge");
        assert!(envelope.init.is_none());
        assert!(init_from_envelope(&envelope).expect("init").is_none());
    }
}
