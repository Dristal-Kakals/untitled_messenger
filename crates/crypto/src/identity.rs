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
