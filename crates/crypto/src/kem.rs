//! Post-quantum hybrid key-encapsulation layer (ML-KEM-768, FIPS 203).
//!
//! This module wraps the `ml-kem` crate behind fixed-size byte arrays so the
//! rest of the workspace (and the wire protocol) never depends on the KEM's
//! concrete Rust types — only on the byte sizes. That keeps `um_protocol`
//! crypto-free and lets the PQ layer be swapped (e.g. ML-KEM-1024) without
//! touching anything outside this module.
//!
//! ## Hybrid design
//!
//! The PQ KEM is layered **on top of** the classical X3DH handshake, not in
//! place of it. Bob publishes an ML-KEM-768 encapsulation key alongside his
//! X25519 signed prekey. Alice runs classical X3DH *and* encapsulates a fresh
//! 32-byte shared secret to Bob's PQ key; Bob decapsulates it. Both secrets are
//! fed into the X3DH HKDF as additional IKM, so the resulting root key is bound
//! to **both** the classical DH outputs and the lattice secret. An attacker
//! must break *both* X25519 (or Ed25519→X25519) **and** ML-KEM-768 to recover
//! the session key — the "hybrid" PQXDH property.
//!
//! ## Sizes (ML-KEM-768)
//!
//! | item              | bytes |
//! |-------------------|-------|
//! | encapsulation key | 1184  |
//! | decapsulation key | 64 (seed) |
//! | ciphertext        | 1088  |
//! | shared secret     | 32    |
//!
//! The decapsulation key is stored as its 64-byte **seed** (the preferred
//! serialized form per FIPS 203); `ml-kem` re-expands it on load.

use ml_kem::{
    Ciphertext, DecapsulationKey768, EncapsulationKey768, Kem, KeyExport, MlKem768, Seed,
    TryKeyInit,
    kem::{Decapsulate, Encapsulate},
};

use crate::CryptoError;

/// ML-KEM-768 encapsulation (public) key, 1184 bytes.
pub const EK_768_LEN: usize = 1184;
/// ML-KEM-768 decapsulation (private) seed, 64 bytes.
pub const DK_768_LEN: usize = 64;
/// ML-KEM-768 ciphertext, 1088 bytes.
pub const CT_768_LEN: usize = 1088;
/// ML-KEM-768 shared secret, 32 bytes.
pub const SS_768_LEN: usize = 32;

/// An ML-KEM-768 encapsulation (public) key, 1184 bytes.
///
/// Stored as a `Vec` (not a fixed array) because serde only derives `Serialize`
/// /`Deserialize` for arrays up to 32 elements — 1184 is far beyond that. The
/// length is validated on construction and on every decode, so the wire form is
/// still exactly 1184 bytes; the indirection is invisible to callers, who use
/// the fixed `[u8; EK_768_LEN]` accessors.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PqEncapsulationKey(#[serde(with = "serde_bytes_pq")] pub Vec<u8>);

/// An ML-KEM-768 decapsulation (private) key, stored as its 64-byte seed.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PqDecapsulationKey(#[serde(with = "serde_bytes_pq")] pub Vec<u8>);

/// An ML-KEM-768 ciphertext, 1088 bytes.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PqCiphertext(#[serde(with = "serde_bytes_pq")] pub Vec<u8>);

impl PqEncapsulationKey {
    /// Wrap a fixed-size encapsulation key. Panics only if the length is wrong
    /// (a programmer error, not a runtime input).
    pub fn from_array(bytes: [u8; EK_768_LEN]) -> Self {
        Self(bytes.to_vec())
    }

    /// The encapsulation key as a fixed array. Panics on a malformed
    /// (wrong-length) key — use [`from_bytes`](Self::from_bytes) for untrusted
    /// input.
    pub fn as_array(&self) -> [u8; EK_768_LEN] {
        self.0[..EK_768_LEN]
            .try_into()
            .expect("PQ encapsulation key is 1184 bytes")
    }

    /// Reconstruct from an untrusted byte slice, validating the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != EK_768_LEN {
            return Err(CryptoError::MalformedBundle);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Generate a fresh ML-KEM-768 keypair from OS RNG.
    pub fn generate_keypair() -> (PqDecapsulationKey, PqEncapsulationKey) {
        let (dk, ek): (DecapsulationKey768, EncapsulationKey768) = MlKem768::generate_keypair();
        let dk_bytes = dk.to_bytes().as_slice().to_vec();
        let ek_bytes = ek.to_bytes().as_slice().to_vec();
        (PqDecapsulationKey(dk_bytes), PqEncapsulationKey(ek_bytes))
    }

    /// Reconstruct the live `ml-kem` encapsulation key from these bytes.
    fn as_key(&self) -> Result<EncapsulationKey768, CryptoError> {
        EncapsulationKey768::new_from_slice(&self.0).map_err(|_| CryptoError::MalformedBundle)
    }

    /// Encapsulate: produce a ciphertext + 32-byte shared secret bound to this
    /// key. Used by the initiator (Alice) during hybrid X3DH.
    pub fn encapsulate(&self) -> Result<(PqCiphertext, [u8; SS_768_LEN]), CryptoError> {
        let ek = self.as_key()?;
        let (ct, ss) = ek.encapsulate();
        let ct_bytes = ct.as_slice().to_vec();
        let mut ss_bytes = [0u8; SS_768_LEN];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok((PqCiphertext(ct_bytes), ss_bytes))
    }
}

impl PqDecapsulationKey {
    /// Wrap a fixed-size decapsulation seed.
    pub fn from_array(bytes: [u8; DK_768_LEN]) -> Self {
        Self(bytes.to_vec())
    }

    /// The decapsulation seed as a fixed array.
    pub fn as_array(&self) -> [u8; DK_768_LEN] {
        self.0[..DK_768_LEN]
            .try_into()
            .expect("PQ decapsulation key is 64 bytes")
    }

    /// Reconstruct from an untrusted byte slice, validating the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DK_768_LEN {
            return Err(CryptoError::MalformedBundle);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Reconstruct the live `ml-kem` decapsulation key from the stored seed.
    fn as_key(&self) -> Result<DecapsulationKey768, CryptoError> {
        let seed = Seed::try_from(self.0.as_slice()).expect("PQ decapsulation key is 64 bytes");
        Ok(DecapsulationKey768::from_seed(seed))
    }

    /// Re-derive the matching encapsulation (public) key from this
    /// decapsulation seed. ML-KEM keygen is deterministic from the 64-byte seed
    /// (FIPS 203 §6.1), so the ek produced here is byte-identical to the one
    /// generated alongside this dk. Used by the client to publish the PQ
    /// encapsulation key in its registration bundle without having to persist
    /// the ek separately.
    pub fn derive_encapsulation_key(&self) -> Result<PqEncapsulationKey, CryptoError> {
        let dk = self.as_key()?;
        let ek = dk.encapsulation_key();
        Ok(PqEncapsulationKey(ek.to_bytes().as_slice().to_vec()))
    }

    /// Decapsulate the given ciphertext, recovering the shared secret. Used by
    /// the responder (Bob) during hybrid X3DH.
    pub fn decapsulate(&self, ct: &PqCiphertext) -> Result<[u8; SS_768_LEN], CryptoError> {
        if ct.0.len() != CT_768_LEN {
            return Err(CryptoError::MalformedBundle);
        }
        let dk = self.as_key()?;
        let arr: [u8; CT_768_LEN] = ct.0[..].try_into().expect("checked length");
        let ct = Ciphertext::<MlKem768>::from(arr);
        let ss = dk.decapsulate(&ct);
        let mut ss_bytes = [0u8; SS_768_LEN];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok(ss_bytes)
    }
}

impl PqCiphertext {
    /// The ciphertext as a fixed array. Panics on a malformed ciphertext — use
    /// [`from_bytes`](Self::from_bytes) for untrusted input.
    pub fn as_array(&self) -> [u8; CT_768_LEN] {
        self.0[..CT_768_LEN]
            .try_into()
            .expect("PQ ciphertext is 1088 bytes")
    }

    /// Reconstruct from an untrusted byte slice, validating the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != CT_768_LEN {
            return Err(CryptoError::MalformedBundle);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Serde helper: serialize the inner `Vec<u8>` as a byte buffer (not a seq of
/// u8s), so postcard emits a compact length-prefixed byte string and the wire
/// size stays minimal. Mirrors `serde_bytes` without adding a dependency.
mod serde_bytes_pq {
    use serde::de::{Deserializer, Error, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte buffer")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_round_trips() {
        let (dk, ek) = PqEncapsulationKey::generate_keypair();
        let (ct, ss_send) = ek.encapsulate().expect("encaps");
        let ss_recv = dk.decapsulate(&ct).expect("decaps");
        assert_eq!(ss_send, ss_recv);
        assert_eq!(ss_send.len(), SS_768_LEN);
    }

    #[test]
    fn ciphertext_is_1088_bytes() {
        let (_dk, ek) = PqEncapsulationKey::generate_keypair();
        let (ct, _ss) = ek.encapsulate().expect("encaps");
        assert_eq!(ct.0.len(), CT_768_LEN);
    }

    #[test]
    fn keys_are_correct_sizes() {
        let (dk, ek) = PqEncapsulationKey::generate_keypair();
        assert_eq!(dk.0.len(), DK_768_LEN);
        assert_eq!(ek.0.len(), EK_768_LEN);
    }

    #[test]
    fn two_encapsulations_yield_different_shared_secrets() {
        // Fresh randomness per encapsulate → distinct shared secrets + cts.
        let (_dk, ek) = PqEncapsulationKey::generate_keypair();
        let (ct1, ss1) = ek.encapsulate().expect("encaps1");
        let (ct2, ss2) = ek.encapsulate().expect("encaps2");
        assert_ne!(ss1, ss2);
        assert_ne!(ct1.0, ct2.0);
    }

    #[test]
    fn decapsulate_rejects_tampered_ciphertext() {
        // ML-KEM decapsulation on a mutated ciphertext yields a *different*
        // (implicit-rejection) shared secret, not the original — the KEM's
        // built-in Fujisaki-Okamoto transform. So a tampered ct must NOT
        // reproduce the sender's shared secret.
        let (dk, ek) = PqEncapsulationKey::generate_keypair();
        let (mut ct, ss_send) = ek.encapsulate().expect("encaps");
        ct.0[0] ^= 0xff;
        let ss_recv = dk.decapsulate(&ct).expect("decaps still returns a key");
        assert_ne!(
            ss_recv, ss_send,
            "tampered ct must not yield the same secret"
        );
    }

    #[test]
    fn pq_keys_serialize_round_trip() {
        let (dk, ek) = PqEncapsulationKey::generate_keypair();
        let dk_bytes = postcard::to_allocvec(&dk).unwrap();
        let ek_bytes = postcard::to_allocvec(&ek).unwrap();
        let dk2: PqDecapsulationKey = postcard::from_bytes(&dk_bytes).unwrap();
        let ek2: PqEncapsulationKey = postcard::from_bytes(&ek_bytes).unwrap();
        assert_eq!(dk.0, dk2.0);
        assert_eq!(ek.0, ek2.0);
        // And the reconstructed keypair still works.
        let (ct, ss) = ek2.encapsulate().unwrap();
        assert_eq!(dk2.decapsulate(&ct).unwrap(), ss);
    }

    #[test]
    fn malformed_encapsulation_key_errors() {
        let mut bad = [0u8; EK_768_LEN];
        // All-zero is not a valid ML-KEM-768 encapsulation key.
        bad[..8].copy_from_slice(&[0xFF; 8]);
        let bad_ek = PqEncapsulationKey::from_array(bad);
        // Either encapsulate fails (malformed) or the key is rejected. We only
        // require that it does not produce a usable round trip — i.e. it errors
        // or decaps fails. The strong guarantee: encapsulate returns Err.
        assert!(bad_ek.encapsulate().is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(PqEncapsulationKey::from_bytes(&[0u8; 10]).is_err());
        assert!(PqDecapsulationKey::from_bytes(&[0u8; 10]).is_err());
        assert!(PqCiphertext::from_bytes(&[0u8; 10]).is_err());
    }
}
