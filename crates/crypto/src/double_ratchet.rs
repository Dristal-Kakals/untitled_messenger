use std::collections::HashMap;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;
use crate::aead::{kdf_chain, kdf_root_dh, open, random_nonce, seal};
use crate::x3dh::SessionInit;

const MAX_SKIPPED: usize = 2000;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Header {
    pub dh_pub: PublicKey,
    pub pn: u32,
    pub n: u32,
    pub nonce: [u8; 24],
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Encrypted {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct RatchetSession {
    root_key: [u8; 32],
    dh_priv: StaticSecret,
    dh_pub: PublicKey,
    /// The peer's current DH ratchet public key, used to detect when the
    /// sender has performed a new DH ratchet. `None` until the first
    /// received message (Bob's initial state).
    peer_dh_pub: Option<PublicKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    skipped: HashMap<(PublicKey, u32), [u8; 32]>,
}

fn header_aad(h: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&h.dh_pub.to_bytes());
    aad.extend_from_slice(&h.pn.to_le_bytes());
    aad.extend_from_slice(&h.n.to_le_bytes());
    aad.extend_from_slice(&h.nonce);
    aad
}

fn evict_if_full(skipped: &mut HashMap<(PublicKey, u32), [u8; 32]>) {
    if skipped.len() >= MAX_SKIPPED
        && let Some((&key, _)) = skipped.iter().min_by_key(|((_, n), _)| *n)
    {
        skipped.remove(&key);
    }
}

impl RatchetSession {
    pub fn init_alice(session_init: &SessionInit) -> Result<Self, CryptoError> {
        let rng = rand_core::OsRng;
        let dh_priv = StaticSecret::random_from_rng(rng);
        let dh_pub = PublicKey::from(&dh_priv);

        let dh_output = dh_priv
            .diffie_hellman(&session_init.bob_signed_prekey_pub)
            .to_bytes();
        let (new_root, cks) = kdf_root_dh(&session_init.root_key, &dh_output);

        Ok(Self {
            root_key: new_root,
            dh_priv,
            dh_pub,
            peer_dh_pub: Some(session_init.bob_signed_prekey_pub),
            ns: 0,
            nr: 0,
            pn: 0,
            cks: Some(cks),
            ckr: None,
            skipped: HashMap::new(),
        })
    }

    pub fn init_bob(
        session_init: &SessionInit,
        bob_signed_priv: &StaticSecret,
    ) -> Result<Self, CryptoError> {
        let dh_pub = PublicKey::from(bob_signed_priv);
        Ok(Self {
            root_key: session_init.root_key,
            dh_priv: bob_signed_priv.clone(),
            dh_pub,
            peer_dh_pub: None,
            ns: 0,
            nr: 0,
            pn: 0,
            cks: None,
            ckr: None,
            skipped: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Encrypted, CryptoError> {
        let cks = self.cks.ok_or(CryptoError::InvalidState)?;
        let (new_cks, msg_key) = kdf_chain(&cks);
        self.cks = Some(new_cks);

        let nonce = random_nonce();
        let header = Header {
            dh_pub: self.dh_pub,
            pn: self.pn,
            n: self.ns,
            nonce,
        };
        let aad = header_aad(&header);
        let ciphertext = seal(&msg_key, &nonce, &aad, plaintext);
        self.ns += 1;
        Ok(Encrypted { header, ciphertext })
    }

    pub fn decrypt(&mut self, message: &Encrypted) -> Result<Vec<u8>, CryptoError> {
        // 1. Check skipped cache. A cached key is already committed state
        //    (it was staged when the chain was advanced past it), so decrypt
        //    directly and remove the entry on success.
        if let Some(msg_key) = self
            .skipped
            .remove(&(message.header.dh_pub, message.header.n))
        {
            let aad = header_aad(&message.header);
            return open(&msg_key, &message.header.nonce, &aad, &message.ciphertext);
        }

        // 2. DH ratchet step if the sender used a new DH ratchet key.
        //
        //    All state mutations below are STAGED into locals and committed
        //    only after the final `open` succeeds. A tampered or corrupt
        //    ciphertext must NOT advance the chain key / counter / skipped
        //    cache: if it did, the next legitimate message at this `n` would
        //    decrypt with the wrong key, permanently poisoning the receive
        //    chain. (The relay re-delivers unacked envelopes, so a single
        //    corrupt frame is an ordinary occurrence, not a rare edge case.)
        let new_sender = match self.peer_dh_pub {
            Some(p) => message.header.dh_pub != p,
            None => true,
        };

        // Staged DH-ratchet + previous-chain skip state. Committed at the end.
        let mut prev_chain_skipped: Vec<((PublicKey, u32), [u8; 32])> = Vec::new();
        let mut staged_nr = self.nr;
        let mut staged_ckr = self.ckr;
        let mut staged_peer_dh = self.peer_dh_pub;
        let mut staged_root_key = self.root_key;
        let mut staged_pn = self.pn;
        let mut staged_ns = self.ns;
        let mut staged_cks = self.cks;
        let mut staged_dh_priv = None::<StaticSecret>;
        let mut staged_dh_pub = self.dh_pub;

        if new_sender {
            // Skip messages in the previous recv chain up to header.pn. The
            // derived keys are staged into `prev_chain_skipped` for commit on
            // success; the chain key itself is discarded — the DH ratchet
            // step below replaces `ckr` with the new chain, so advancing the
            // old chain's `ckr` here would only be overwritten.
            if let (Some(old_peer), Some(mut ckr)) = (self.peer_dh_pub, staged_ckr) {
                while staged_nr < message.header.pn {
                    let (new_ckr, mk) = kdf_chain(&ckr);
                    prev_chain_skipped.push(((old_peer, staged_nr), mk));
                    ckr = new_ckr;
                    staged_nr += 1;
                }
            }

            // DH ratchet (receiving): old self priv × new peer pub.
            staged_peer_dh = Some(message.header.dh_pub);
            let dh_recv = self
                .dh_priv
                .diffie_hellman(&message.header.dh_pub)
                .to_bytes();
            let (new_root, new_ckr) = kdf_root_dh(&staged_root_key, &dh_recv);
            staged_root_key = new_root;
            staged_ckr = Some(new_ckr);
            staged_pn = self.ns;
            staged_nr = 0;

            // DH ratchet (sending): new self priv × new peer pub.
            let rng = rand_core::OsRng;
            let new_dh_priv = StaticSecret::random_from_rng(rng);
            let new_dh_pub = PublicKey::from(&new_dh_priv);
            let dh_send = new_dh_priv
                .diffie_hellman(&message.header.dh_pub)
                .to_bytes();
            let (new_root2, new_cks) = kdf_root_dh(&staged_root_key, &dh_send);
            staged_root_key = new_root2;
            staged_cks = Some(new_cks);
            staged_ns = 0;
            staged_dh_priv = Some(new_dh_priv);
            staged_dh_pub = new_dh_pub;
        }

        // 3. Skip messages in the current recv chain up to header.n.
        //    Staged into `cur_chain_skipped`; committed on success.
        let mut cur_chain_skipped: Vec<(u32, [u8; 32])> = Vec::new();
        let peer = staged_peer_dh;
        if let (Some(_), Some(mut ckr)) = (peer, staged_ckr) {
            while staged_nr < message.header.n {
                let (new_ckr, mk) = kdf_chain(&ckr);
                cur_chain_skipped.push((staged_nr, mk));
                ckr = new_ckr;
                staged_nr += 1;
            }
            staged_ckr = Some(ckr);
        }

        // 4. Derive the message key for the current `n`, then decrypt BEFORE
        //    advancing the chain. On failure, leave all state untouched.
        let ckr = staged_ckr.ok_or(CryptoError::InvalidState)?;
        let (new_ckr, msg_key) = kdf_chain(&ckr);
        let aad = header_aad(&message.header);
        let plaintext = open(&msg_key, &message.header.nonce, &aad, &message.ciphertext)?;

        // 5. Commit all staged state only after authentication succeeded.
        //    Previous-chain skipped keys (from the DH ratchet step).
        for (key, mk) in prev_chain_skipped {
            evict_if_full(&mut self.skipped);
            self.skipped.insert(key, mk);
        }
        // Current-chain skipped keys.
        for (n, mk) in cur_chain_skipped {
            if let Some(peer) = peer {
                evict_if_full(&mut self.skipped);
                self.skipped.insert((peer, n), mk);
            }
        }
        self.nr = staged_nr + 1;
        self.ckr = Some(new_ckr);
        if new_sender {
            self.peer_dh_pub = staged_peer_dh;
            self.root_key = staged_root_key;
            self.pn = staged_pn;
            self.cks = staged_cks;
            self.ns = staged_ns;
            if let Some(priv_) = staged_dh_priv {
                self.dh_priv = priv_;
            }
            self.dh_pub = staged_dh_pub;
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use crate::x3dh::{initiate, receive};

    fn make_pair() -> (RatchetSession, RatchetSession, StaticSecret) {
        let bob = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &bob);
        let otpk = OneTimePreKey::generate(10);
        let bundle = crate::identity::PreKeyBundle::from_identity(&bob, &spk, &[&otpk]);
        let alice = IdentityKey::generate();

        let (init, init_msg) = initiate(&alice, &bundle, Some(10)).unwrap();
        let bob_session_init = receive(&bob, &spk, Some(&otpk), &init_msg).unwrap();

        let alice_r = RatchetSession::init_alice(&init).unwrap();
        let bob_r = RatchetSession::init_bob(&bob_session_init, &spk.priv_key).unwrap();
        (alice_r, bob_r, spk.priv_key)
    }

    #[test]
    fn alice_to_bob_roundtrip() {
        let (mut alice, mut bob, _) = make_pair();
        let ct = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn bidirectional_roundtrip() {
        let (mut alice, mut bob, _) = make_pair();
        let ct1 = alice.encrypt(b"hi").unwrap();
        assert_eq!(bob.decrypt(&ct1).unwrap(), b"hi");
        // Bob must receive before sending (cks was None); now he can send.
        let ct2 = bob.encrypt(b"yo").unwrap();
        assert_eq!(alice.decrypt(&ct2).unwrap(), b"yo");
        let ct3 = alice.encrypt(b"again").unwrap();
        assert_eq!(bob.decrypt(&ct3).unwrap(), b"again");
    }

    #[test]
    fn multiple_messages_same_chain() {
        let (mut alice, mut bob, _) = make_pair();
        let msgs: Vec<Encrypted> = (0..5u32)
            .map(|i| alice.encrypt(format!("msg {i}").as_bytes()).unwrap())
            .collect();
        for (i, ct) in msgs.iter().enumerate() {
            assert_eq!(bob.decrypt(ct).unwrap(), format!("msg {i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_decrypts() {
        let (mut alice, mut bob, _) = make_pair();
        let m0 = alice.encrypt(b"first").unwrap();
        let m1 = alice.encrypt(b"second").unwrap();
        let m2 = alice.encrypt(b"third").unwrap();
        // Bob receives in order 2, 0, 1.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"third");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"first");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"second");
    }

    #[test]
    fn lost_message_then_ratchet_still_works() {
        let (mut alice, mut bob, _) = make_pair();
        let _m0 = alice.encrypt(b"lost").unwrap(); // dropped
        let m1 = alice.encrypt(b"arrived").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"arrived");
        // Bob replies, Alice ratchets.
        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), b"reply");
    }

    #[test]
    fn tampered_ciphertext_fails_without_poisoning() {
        let (mut alice, mut bob, _) = make_pair();
        let mut ct = alice.encrypt(b"hello").unwrap();
        ct.ciphertext[0] ^= 0xff;
        assert!(matches!(
            bob.decrypt(&ct),
            Err(CryptoError::DecryptionFailed)
        ));
        // Session still usable.
        let ct2 = alice.encrypt(b"next").unwrap();
        assert_eq!(bob.decrypt(&ct2).unwrap(), b"next");
    }

    /// A tampered message at `n` must NOT advance the receive chain, so the
    /// SAME `n` re-sent (untampered) still decrypts. This is the real
    /// poisoning regression: the relay re-delivers unacked envelopes, so a
    /// corrupt frame followed by the genuine re-delivery must recover. The
    /// `tampered_ciphertext_fails_without_poisoning` test above only checks
    /// the *next sequential* `n`, which happens to align with an already-
    /// advanced counter and so hides the bug.
    #[test]
    fn tampered_then_resend_same_n_decrypts() {
        let (mut alice, mut bob, _) = make_pair();
        let ct = alice.encrypt(b"hello").unwrap(); // n=0
        let mut tampered = ct.clone();
        tampered.ciphertext[0] ^= 0xff;
        // Tampered n=0 fails.
        assert!(matches!(
            bob.decrypt(&tampered),
            Err(CryptoError::DecryptionFailed)
        ));
        // The genuine n=0 re-delivered MUST still decrypt: the chain key and
        // counter were not advanced by the failed attempt.
        assert_eq!(bob.decrypt(&ct).unwrap(), b"hello");
        // And the chain continues normally afterward.
        let ct2 = alice.encrypt(b"second").unwrap(); // n=1
        assert_eq!(bob.decrypt(&ct2).unwrap(), b"second");
    }

    /// Same poisoning check across a DH ratchet boundary: a tampered message
    /// carrying a NEW DH key must not commit the new chain, so the genuine
    /// re-delivery (same new DH key, same `n`) still decrypts.
    #[test]
    fn tampered_dh_ratchet_message_does_not_commit_new_chain() {
        let (mut alice, mut bob, _) = make_pair();
        // Establish + advance so bob has replied (forcing alice's next send to
        // carry a fresh DH ratchet key).
        let _ct0 = alice.encrypt(b"first").unwrap();
        let _ = bob.decrypt(&_ct0).unwrap();
        let reply = bob.encrypt(b"reply").unwrap();
        let _ = alice.decrypt(&reply).unwrap();

        // Alice's next message uses a new DH key (DH ratchet on her side).
        let ct = alice.encrypt(b"ratcheted").unwrap();
        let mut tampered = ct.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert!(matches!(
            bob.decrypt(&tampered),
            Err(CryptoError::DecryptionFailed)
        ));
        // Genuine re-delivery of the same ratcheted message must decrypt.
        assert_eq!(bob.decrypt(&ct).unwrap(), b"ratcheted");
    }

    #[test]
    fn bob_cannot_send_before_receiving() {
        let (_alice, mut bob, _) = make_pair();
        assert!(matches!(
            bob.encrypt(b"premature"),
            Err(CryptoError::InvalidState)
        ));
    }
}
