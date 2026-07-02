use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

pub const X3DH_SALT: &[u8] = b"UM-X3DH-v1";
pub const ROOT_CHAIN_INFO: &[u8] = b"UM-root-chain-v1";
pub const ATTACH_INFO: &[u8] = b"UM-attach-v1";

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("xchacha encryption is infallible for valid key/nonce")
}

pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn random_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid prk length");
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .expect("expand length within hmac output limit");
    okm
}

pub fn kdf_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mk = [0u8; 32];
    let mut m1 = HmacSha256::new_from_slice(ck).expect("hmac key len");
    m1.update(&[0x01]);
    mk.copy_from_slice(&m1.finalize().into_bytes());

    let mut nck = [0u8; 32];
    let mut m2 = HmacSha256::new_from_slice(ck).expect("hmac key len");
    m2.update(&[0x02]);
    nck.copy_from_slice(&m2.finalize().into_bytes());

    (nck, mk)
}

pub fn kdf_root_dh(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let prk = hkdf_extract(root_key, dh_output);
    let okm = hkdf_expand(&prk, ROOT_CHAIN_INFO, 64);
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..64]);
    (new_root, chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let pt = b"secret message";
        let ct = seal(&key, &nonce, aad, pt);
        let recovered = open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let mut ct = seal(&key, &nonce, aad, b"secret");
        ct[0] ^= 0xff;
        assert_eq!(
            open(&key, &nonce, aad, &ct),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let key = [7u8; 32];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad-a", b"secret");
        assert_eq!(
            open(&key, &nonce, b"aad-b", &ct),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn kdf_chain_advances_and_differs() {
        let ck = [1u8; 32];
        let (nck, mk) = kdf_chain(&ck);
        assert_ne!(nck, ck);
        assert_ne!(mk, ck);
        assert_ne!(nck, mk);
        let (_nck2, mk2) = kdf_chain(&nck);
        assert_ne!(mk, mk2);
    }

    #[test]
    fn kdf_root_dh_splits_into_two_halves() {
        let rk = [2u8; 32];
        let dh = [3u8; 32];
        let (new_root, chain) = kdf_root_dh(&rk, &dh);
        assert_ne!(new_root, rk);
        assert_ne!(chain, dh);
        assert_ne!(new_root, chain);
    }

    #[test]
    fn kdf_root_dh_mixes_dh_output() {
        // The DH output is new entropy and MUST change the result.
        // (Catches the bug where kdf_root_dh ignored dh_output.)
        let rk = [2u8; 32];
        let dh_a = [3u8; 32];
        let dh_b = [4u8; 32];
        let (root_a, chain_a) = kdf_root_dh(&rk, &dh_a);
        let (root_b, chain_b) = kdf_root_dh(&rk, &dh_b);
        assert_ne!(root_a, root_b);
        assert_ne!(chain_a, chain_b);
    }

    #[test]
    fn hkdf_is_deterministic() {
        let a = hkdf_extract(b"salt", b"ikm");
        let b = hkdf_extract(b"salt", b"ikm");
        assert_eq!(a, b);
    }
}
