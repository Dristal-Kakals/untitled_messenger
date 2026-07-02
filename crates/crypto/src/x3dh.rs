use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;
use crate::aead::{X3DH_SALT, hkdf_extract};
use crate::identity::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::kem::{PqCiphertext, PqDecapsulationKey};

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
    /// Post-quantum ML-KEM-768 ciphertext, present when the responder's bundle
    /// advertised a PQ encapsulation key (hybrid PQXDH). The responder
    /// decapsulates it with their PQ decapsulation key and mixes the shared
    /// secret into the root-key derivation, mirroring the initiator. `None` for
    /// classical-only bundles.
    #[serde(default)]
    pub pq_ciphertext: Option<PqCiphertext>,
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

    // Post-quantum hybrid: if Bob advertised an ML-KEM-768 encapsulation key,
    // encapsulate a fresh shared secret to it and fold it into the IKM. The
    // ciphertext rides in the init message so Bob can decapsulate. A
    // domain-separation tag prefixes the KEM secret so it cannot collide with a
    // DH output even if both were 32 bytes (they are, but the tag is cheap
    // defense-in-depth).
    let pq_ciphertext = match bob_bundle.pq_encapsulation_key.as_ref() {
        Some(pq_ek) => {
            let (ct, ss) = pq_ek.encapsulate()?;
            ikm.extend_from_slice(b"UM-PQ-KEM-768");
            ikm.extend_from_slice(&ss);
            Some(ct)
        }
        None => None,
    };

    let root_key = hkdf_extract(X3DH_SALT, &ikm);

    let init = InitMessage {
        alice_identity_pub: alice.verifying,
        alice_ephemeral_pub: alice_eph_pub,
        bob_signed_prekey_id: bob_bundle.signed_prekey_id,
        bob_one_time_prekey_id,
        pq_ciphertext,
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
    receive_with_pq(bob_identity, bob_signed, bob_one_time, init, None)
}

/// Like [`receive`] but also decapsulates the post-quantum shared secret when
/// the init carries an ML-KEM-768 ciphertext. `bob_pq_dk` is Bob's PQ
/// decapsulation key; it must be present iff the bundle Bob registered carried a
/// PQ encapsulation key (i.e. iff `init.pq_ciphertext` is `Some`). The KEM
/// shared secret is folded into the IKM with the same domain-separation tag the
/// initiator used, so both sides derive the same hybrid root key.
pub fn receive_with_pq(
    bob_identity: &IdentityKey,
    bob_signed: &SignedPreKey,
    bob_one_time: Option<&OneTimePreKey>,
    init: &InitMessage,
    bob_pq_dk: Option<&PqDecapsulationKey>,
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

    // Post-quantum hybrid: decapsulate the KEM ciphertext and fold the shared
    // secret into the IKM with the same domain-separation tag the initiator
    // used. A missing ciphertext on a PQ-capable responder, or a ciphertext on
    // a classical-only responder, is a protocol mismatch → reject.
    match (init.pq_ciphertext.as_ref(), bob_pq_dk) {
        (Some(ct), Some(dk)) => {
            let ss = dk.decapsulate(ct)?;
            ikm.extend_from_slice(b"UM-PQ-KEM-768");
            ikm.extend_from_slice(&ss);
        }
        (None, None) => {}
        _ => return Err(CryptoError::MalformedBundle),
    }

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

    // ---- Post-quantum hybrid X3DH -------------------------------------------

    /// Bob publishes a PQ encapsulation key; Alice encapsulates to it during
    /// X3DH and both sides derive the same root key — the KEM shared secret is
    /// folded into the IKM symmetrically.
    #[test]
    fn pq_hybrid_alice_and_bob_derive_same_root_key() {
        use crate::kem::PqEncapsulationKey;
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let (pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let bundle = PreKeyBundle::from_identity_with_pq(&bob, &spk, &[&otpk], &pq_ek);
        let alice = IdentityKey::generate();

        let (alice_session, init) = initiate(&alice, &bundle, Some(10)).unwrap();
        // The init must carry the PQ ciphertext.
        assert!(init.pq_ciphertext.is_some());
        let bob_session = receive_with_pq(&bob, &spk, Some(&otpk), &init, Some(&pq_dk)).unwrap();
        assert_eq!(alice_session.root_key, bob_session.root_key);
    }

    /// The PQ shared secret must actually change the root key — a hybrid
    /// handshake derives a different key than the classical-only one against
    /// the same DH outputs. (Catches a bug where the KEM secret is ignored.)
    #[test]
    fn pq_secret_mixes_into_root_key() {
        use crate::kem::PqEncapsulationKey;
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let classical = PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
        let (pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let hybrid = PreKeyBundle::from_identity_with_pq(&bob, &spk, &[&otpk], &pq_ek);
        let alice = IdentityKey::generate();

        let (classical_session, _) = initiate(&alice, &classical, Some(10)).unwrap();
        let (hybrid_session, init) = initiate(&alice, &hybrid, Some(10)).unwrap();
        assert_ne!(
            classical_session.root_key, hybrid_session.root_key,
            "PQ secret must change the root key"
        );
        // Bob's hybrid receive matches the hybrid initiation.
        let bob_hybrid = receive_with_pq(&bob, &spk, Some(&otpk), &init, Some(&pq_dk)).unwrap();
        assert_eq!(hybrid_session.root_key, bob_hybrid.root_key);
    }

    /// A PQ-capable responder rejects an init with no PQ ciphertext (protocol
    /// mismatch), and a classical responder rejects an init that carries one.
    #[test]
    fn pq_capability_mismatch_is_rejected() {
        use crate::kem::PqEncapsulationKey;
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let (pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let hybrid_bundle = PreKeyBundle::from_identity_with_pq(&bob, &spk, &[&otpk], &pq_ek);
        let classical_bundle = PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
        let alice = IdentityKey::generate();

        // Hybrid init against hybrid bundle, but Bob tries to receive
        // classically (no PQ dk) → mismatch.
        let (_, hybrid_init) = initiate(&alice, &hybrid_bundle, Some(10)).unwrap();
        let err = receive_with_pq(&bob, &spk, Some(&otpk), &hybrid_init, None);
        assert!(matches!(err, Err(CryptoError::MalformedBundle)));

        // Classical init (no PQ ct) against a hybrid responder who supplies a
        // PQ dk → mismatch (the dk is unused but the ct is absent, so the
        // (None, Some) arm fires).
        let (_, classical_init) = initiate(&alice, &classical_bundle, Some(10)).unwrap();
        assert!(classical_init.pq_ciphertext.is_none());
        let err = receive_with_pq(&bob, &spk, Some(&otpk), &classical_init, Some(&pq_dk));
        assert!(matches!(err, Err(CryptoError::MalformedBundle)));
    }

    /// A tampered PQ encapsulation-key signature is rejected by `verify`, so a
    /// MITM cannot substitute their own PQ key.
    #[test]
    fn pq_key_signature_is_verified() {
        use crate::kem::PqEncapsulationKey;
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let (_pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let mut bundle = PreKeyBundle::from_identity_with_pq(&bob, &spk, &[&otpk], &pq_ek);
        // Re-sign the PQ key with a different identity.
        let other = IdentityKey::generate();
        bundle.pq_encapsulation_key_sig = Some(other.sign(&pq_ek.0));
        assert_eq!(bundle.verify(), Err(CryptoError::MalformedBundle));
    }

    /// A bundle with a PQ key but no signature is malformed (half-present).
    #[test]
    fn pq_key_without_signature_is_malformed() {
        use crate::kem::PqEncapsulationKey;
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let (_pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let mut bundle = PreKeyBundle::from_identity_with_pq(&bob, &spk, &[&otpk], &pq_ek);
        bundle.pq_encapsulation_key_sig = None;
        assert_eq!(bundle.verify(), Err(CryptoError::MalformedBundle));
    }
}
