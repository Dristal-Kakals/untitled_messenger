use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;
use crate::aead::{X3DH_SALT, hkdf_extract};
use crate::identity::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SessionInit {
    pub root_key: [u8; 32],
    pub alice_identity: IdentityKey,
    pub alice_ephemeral_priv: StaticSecret,
    pub alice_ephemeral_pub: PublicKey,
    pub bob_signed_prekey_id: u32,
    pub bob_signed_prekey_pub: PublicKey,
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
    let mut h = Sha512::new();
    h.update(sk.to_bytes());
    let digest = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest[..32]);
    StaticSecret::from(k)
}

fn ed25519_pub_to_x25519(vk: &VerifyingKey) -> Result<PublicKey, CryptoError> {
    let compressed =
        CompressedEdwardsY::from_slice(&vk.to_bytes()).map_err(|_| CryptoError::MalformedBundle)?;
    let mont = compressed
        .decompress()
        .ok_or(CryptoError::MalformedBundle)?
        .to_montgomery();
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

    let rng = OsRng;
    let alice_eph_priv = StaticSecret::random_from_rng(rng);
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
            one_time_prekey_id.or(bob_bundle
                .one_time_prekeys
                .iter()
                .find(|(_, p)| *p == pk)
                .map(|(id, _)| *id))
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
        bob_signed_prekey_pub: bob_bundle.signed_prekey_pub,
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
    let dh3 = bob_signed
        .priv_key
        .diffie_hellman(&alice_eph_pub)
        .to_bytes();

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
        bob_signed_prekey_pub: bob_signed.pub_key,
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
        let (_bob, spk, _otpk, mut bundle) = bob_setup();
        let other = IdentityKey::generate();
        bundle.signed_prekey_sig = other.sign(&spk.pub_key.to_bytes());
        let alice = IdentityKey::generate();
        assert!(matches!(
            initiate(&alice, &bundle, Some(10)),
            Err(CryptoError::MalformedBundle)
        ));
    }

    #[test]
    fn receive_rejects_missing_one_time_prekey() {
        let (bob, spk, _otpk, bundle) = bob_setup();
        let alice = IdentityKey::generate();
        let (_, init) = initiate(&alice, &bundle, Some(10)).unwrap();
        // Bob does not have the one-time prekey that the init references.
        let bob_session = receive(&bob, &spk, None, &init);
        assert!(matches!(bob_session, Err(CryptoError::MissingPreKey)));
    }

    #[test]
    fn different_alice_gives_different_root_key() {
        let (_bob, _spk, _otpk, bundle) = bob_setup();
        let alice1 = IdentityKey::generate();
        let alice2 = IdentityKey::generate();
        let (s1, _) = initiate(&alice1, &bundle, Some(10)).unwrap();
        let (s2, _) = initiate(&alice2, &bundle, Some(10)).unwrap();
        assert_ne!(s1.root_key, s2.root_key);
    }
}
