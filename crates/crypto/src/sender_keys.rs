use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

use crate::CryptoError;
use crate::aead::{kdf_chain, open, random_nonce, seal};
use crate::identity::IdentityKey;

pub type MemberId = [u8; 32];

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SenderChainKey(pub [u8; 32]);

impl SenderChainKey {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }
    pub fn ratchet(&mut self) -> [u8; 32] {
        let (new_ck, mk) = kdf_chain(&self.0);
        self.0 = new_ck;
        mk
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SenderKeyState {
    pub member_id: MemberId,
    pub chain_key: SenderChainKey,
    pub signing_priv: SigningKey,
    pub signing_pub: VerifyingKey,
    pub generation: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupHeader {
    pub group_id: [u8; 32],
    pub sender_id: MemberId,
    pub generation: u32,
    pub signing_pub: VerifyingKey,
    pub nonce: [u8; 24],
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupEncrypted {
    pub header: GroupHeader,
    pub ciphertext: Vec<u8>,
    pub signature: ed25519_dalek::Signature,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupSession {
    pub group_id: [u8; 32],
    pub self_state: SenderKeyState,
    pub peer_states: HashMap<MemberId, (SenderChainKey, u32, VerifyingKey)>,
}

fn group_header_aad(h: &GroupHeader) -> Vec<u8> {
    let mut aad = Vec::with_capacity(124);
    aad.extend_from_slice(&h.group_id);
    aad.extend_from_slice(&h.sender_id);
    aad.extend_from_slice(&h.generation.to_le_bytes());
    aad.extend_from_slice(&h.signing_pub.to_bytes());
    aad.extend_from_slice(&h.nonce);
    aad
}

impl GroupSession {
    pub fn new(group_id: [u8; 32], self_identity: &IdentityKey) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = OsRng;
        let signing_priv = SigningKey::generate(&mut rng);
        let signing_pub = signing_priv.verifying_key();

        let self_state = SenderKeyState {
            member_id: self_identity.fingerprint(),
            chain_key: SenderChainKey::new(seed),
            signing_priv,
            signing_pub,
            generation: 0,
        };

        Ok(Self {
            group_id,
            self_state,
            peer_states: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupEncrypted, CryptoError> {
        let msg_key = self.self_state.chain_key.ratchet();
        self.self_state.generation += 1;

        let nonce = random_nonce();
        let header = GroupHeader {
            group_id: self.group_id,
            sender_id: self.self_state.member_id,
            generation: self.self_state.generation,
            signing_pub: self.self_state.signing_pub,
            nonce,
        };
        let aad = group_header_aad(&header);
        let ciphertext = seal(&msg_key, &nonce, &aad, plaintext);
        let mut signed = aad.clone();
        signed.extend_from_slice(&ciphertext);
        let signature = self.self_state.signing_priv.sign(&signed);

        Ok(GroupEncrypted {
            header,
            ciphertext,
            signature,
        })
    }

    pub fn decrypt(&mut self, message: &GroupEncrypted) -> Result<Vec<u8>, CryptoError> {
        let (chain_key, peer_gen, signing_pub) =
            match self.peer_states.get_mut(&message.header.sender_id) {
                Some(v) => v,
                None => return Err(CryptoError::MissingPreKey),
            };

        let aad = group_header_aad(&message.header);
        let mut signed = aad.clone();
        signed.extend_from_slice(&message.ciphertext);
        signing_pub
            .verify(&signed, &message.signature)
            .map_err(|_| CryptoError::InvalidSignature)?;

        if message.header.generation <= *peer_gen {
            return Err(CryptoError::DecryptionFailed);
        }

        // Ratchet the peer's chain forward until the next ratchet lands on
        // the message's generation. Each `ratchet()` produces the message key
        // for generation `peer_gen + 1`; we discard keys for any generations
        // we skipped (v1 has no group skipped-message cache) and use the final
        // one for this message.
        while *peer_gen + 1 < message.header.generation {
            chain_key.ratchet();
            *peer_gen += 1;
        }

        let msg_key = chain_key.ratchet();
        *peer_gen += 1;

        open(&msg_key, &message.header.nonce, &aad, &message.ciphertext)
    }

    pub fn add_peer(&mut self, state: SenderKeyState) -> Result<(), CryptoError> {
        self.peer_states.insert(
            state.member_id,
            (state.chain_key, state.generation, state.signing_pub),
        );
        Ok(())
    }

    pub fn export_self_state(&self) -> SenderKeyState {
        self.self_state.clone()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DistributionPayload {
    pub group_id: [u8; 32],
    pub state: SenderKeyState,
}

pub fn encode_distribution(
    state: &SenderKeyState,
    group_id: [u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    postcard::to_allocvec(&DistributionPayload {
        group_id,
        state: state.clone(),
    })
    .map_err(|_| CryptoError::InvalidState)
}

pub fn decode_distribution(bytes: &[u8]) -> Result<(SenderKeyState, [u8; 32]), CryptoError> {
    let payload: DistributionPayload =
        postcard::from_bytes(bytes).map_err(|_| CryptoError::MalformedBundle)?;
    Ok((payload.state, payload.group_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid() -> [u8; 32] {
        let mut g = [0u8; 32];
        OsRng.fill_bytes(&mut g);
        g
    }

    #[test]
    fn chain_key_ratchet_advances() {
        let mut ck = SenderChainKey::new([1u8; 32]);
        let m1 = ck.ratchet();
        let m2 = ck.ratchet();
        assert_ne!(m1, m2);
    }

    #[test]
    fn group_roundtrip_two_members() {
        let group = gid();
        let alice_id = IdentityKey::generate();
        let bob_id = IdentityKey::generate();
        let mut alice = GroupSession::new(group, &alice_id).unwrap();
        let mut bob = GroupSession::new(group, &bob_id).unwrap();

        // Exchange distribution states (in real life via 1:1 Double Ratchet).
        alice.add_peer(bob.export_self_state()).unwrap();
        bob.add_peer(alice.export_self_state()).unwrap();

        let ct = alice.encrypt(b"hi group").unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hi group");

        let ct2 = bob.encrypt(b"hello back").unwrap();
        let pt2 = alice.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"hello back");
    }

    #[test]
    fn group_three_members() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let c = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        let mut sc = GroupSession::new(group, &c).unwrap();

        sa.add_peer(sb.export_self_state()).unwrap();
        sa.add_peer(sc.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();
        sb.add_peer(sc.export_self_state()).unwrap();
        sc.add_peer(sa.export_self_state()).unwrap();
        sc.add_peer(sb.export_self_state()).unwrap();

        let ct = sa.encrypt(b"from a").unwrap();
        assert_eq!(sb.decrypt(&ct).unwrap(), b"from a");
        assert_eq!(sc.decrypt(&ct).unwrap(), b"from a");

        let ct2 = sc.encrypt(b"from c").unwrap();
        assert_eq!(sa.decrypt(&ct2).unwrap(), b"from c");
        assert_eq!(sb.decrypt(&ct2).unwrap(), b"from c");
    }

    #[test]
    fn group_rejects_unknown_sender() {
        let group = gid();
        let a = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        // No peers added; a message from a stranger.
        let stranger = IdentityKey::generate();
        let mut stranger_session = GroupSession::new(group, &stranger).unwrap();
        let ct = stranger_session.encrypt(b"inject").unwrap();
        assert!(matches!(sa.decrypt(&ct), Err(CryptoError::MissingPreKey)));
    }

    #[test]
    fn group_rejects_tampered_ciphertext() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        sa.add_peer(sb.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();

        let mut ct = sa.encrypt(b"hi").unwrap();
        ct.ciphertext[0] ^= 0xff;
        assert!(matches!(
            sb.decrypt(&ct),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn distribution_encode_decode_roundtrip() {
        let group = gid();
        let a = IdentityKey::generate();
        let sa = GroupSession::new(group, &a).unwrap();
        let state = sa.export_self_state();
        let bytes = encode_distribution(&state, group).unwrap();
        let (decoded_state, decoded_group) = decode_distribution(&bytes).unwrap();
        assert_eq!(decoded_group, group);
        assert_eq!(decoded_state.member_id, state.member_id);
    }

    #[test]
    fn group_rejects_old_generation_replay() {
        let group = gid();
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut sa = GroupSession::new(group, &a).unwrap();
        let mut sb = GroupSession::new(group, &b).unwrap();
        sa.add_peer(sb.export_self_state()).unwrap();
        sb.add_peer(sa.export_self_state()).unwrap();

        let ct1 = sa.encrypt(b"first").unwrap();
        let ct2 = sa.encrypt(b"second").unwrap();
        assert_eq!(sb.decrypt(&ct2).unwrap(), b"second");
        // Replaying ct1 (older generation) must fail.
        assert!(matches!(
            sb.decrypt(&ct1),
            Err(CryptoError::DecryptionFailed)
        ));
    }
}
