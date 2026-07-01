//! Client session state: identity, prekeys, and per-peer Double Ratchet
//! sessions. This is the crypto-facing core of the client — it owns the
//! keys and drives X3DH + the ratchet. No networking; callers hand it
//! bundles/envelopes and it returns envelopes/plaintext.

use std::collections::HashMap;

use um_crypto::double_ratchet::RatchetSession;
use um_crypto::identity::{IdentityKey, OneTimePreKey, PreKeyBundle as CryptoBundle, SignedPreKey};
use um_crypto::x3dh;
use um_protocol::{EncryptedEnvelope, PreKeyBundle};

use crate::crypto_bridge::{encrypted_from_envelope, envelope_from_encrypted, init_from_envelope};
use crate::ClientError;

/// A client's cryptographic session state. Owns the identity key, the
/// signed prekey, the one-time prekeys, and a ratchet session per peer
/// (keyed by the peer's identity pub).
pub struct ClientSession {
    identity: IdentityKey,
    signed_prekey: SignedPreKey,
    one_time_prekeys: HashMap<u32, OneTimePreKey>,
    ratchets: HashMap<[u8; 32], RatchetSession>,
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
            one_time_prekeys,
            ratchets: HashMap::new(),
        }
    }

    /// This client's identity public key (32 bytes).
    pub fn identity_pub(&self) -> [u8; 32] {
        self.identity.verifying.to_bytes()
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
        let crypto_bundle = self.reconstruct_peer_bundle(peer_bundle)?;
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

    /// Receive and decrypt an envelope. If it carries an X3DH init and no
    /// session exists yet, seeds a new ratchet (Bob's side). Returns the
    /// decrypted plaintext and the sender's identity pub.
    pub fn receive(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<(Vec<u8>, [u8; 32]), ClientError> {
        let sender = envelope.sender;

        // No session yet: must be an initial message carrying an init.
        if !self.ratchets.contains_key(&sender) {
            let init = init_from_envelope(envelope)?.ok_or(ClientError::NoSession)?;
            // Find the one-time prekey the sender used.
            let otpk = match init.bob_one_time_prekey_id {
                Some(id) => Some(
                    self.one_time_prekeys
                        .get(&id)
                        .ok_or(ClientError::NoOneTimePreKey(id))?,
                ),
                None => None,
            };
            let session_init = x3dh::receive(&self.identity, &self.signed_prekey, otpk, &init)?;
            let mut ratchet =
                RatchetSession::init_bob(&session_init, &self.signed_prekey.priv_key)?;
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

    /// Reconstruct a typed crypto `PreKeyBundle` from a protocol bundle.
    fn reconstruct_peer_bundle(&self, bundle: &PreKeyBundle) -> Result<CryptoBundle, ClientError> {
        use um_crypto::{Signature, VerifyingKey};
        let identity_pub = VerifyingKey::from_bytes(&bundle.identity_pub)
            .map_err(|_| ClientError::Store("bad peer identity pub".into()))?;
        let signed_prekey_pub = x25519_pub(&bundle.signed_prekey_pub)?;
        let signed_prekey_sig = Signature::from_slice(&bundle.signed_prekey_sig)
            .map_err(|_| ClientError::Store("bad peer signature".into()))?;
        let one_time_prekeys = bundle
            .one_time_prekeys
            .iter()
            .map(|(id, pub_bytes)| Ok((*id, x25519_pub(pub_bytes)?)))
            .collect::<Result<Vec<_>, ClientError>>()?;
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
fn x25519_pub(bytes: &[u8; 32]) -> Result<x25519_dalek::PublicKey, ClientError> {
    Ok(x25519_dalek::PublicKey::from(*bytes))
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
            header: vec![1, 2, 3],
            init: None,
            ciphertext: vec![0xAA; 8],
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
}
