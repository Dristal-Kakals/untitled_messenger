//! Connection dispatch: decode a `ClientMessage`, mutate the `Store`, reply
//! with a `ServerMessage`. Stateless except for the shared `Store`; one
//! `handle` call per inbound frame.

use um_crypto::kem::EK_768_LEN;
use um_crypto::{Signature, VerifyingKey};
use um_protocol::{ClientMessage, ServerMessage};

use crate::{Store, Subscribers};

/// Verify a registered prekey bundle's signed-prekey signature against its
/// identity pub, and — when a post-quantum encapsulation key is present — its
/// PQ-ek signature too. Returns `true` only if every present signature is
/// valid and the PQ fields are not in a half-present state.
///
/// This mirrors `um_crypto::identity::PreKeyBundle::verify` so the relay
/// rejects malformed/tampered bundles at `Register` time (defense-in-depth)
/// rather than storing them for a fetcher to fail on later with a confusing
/// `MalformedBundle` during X3DH initiation. The relay is not a crypto
/// authority, but it is the natural choke point to keep garbage out of the
/// registry.
pub fn verify_bundle_signature(bundle: &um_protocol::PreKeyBundle) -> bool {
    // The signed prekey pub is an X25519 pub (32 bytes). The signature is an
    // Ed25519 signature over those 32 bytes by the identity key. Reconstruct
    // the verifying key and verify.
    let Ok(vk) = VerifyingKey::from_bytes(&bundle.identity_pub) else {
        return false;
    };
    let Ok(spk_sig) = Signature::from_slice(&bundle.signed_prekey_sig) else {
        return false;
    };
    use ed25519_dalek::Verifier;
    if vk.verify(&bundle.signed_prekey_pub, &spk_sig).is_err() {
        return false;
    }

    // Post-quantum encapsulation key + its identity signature. Both present
    // → verify the signature over the ek bytes (and reject a wrong-length ek,
    // which can never be a real ML-KEM-768 key). Half-present (key without
    // sig or vice versa) → malformed, reject. Both absent → classical-only
    // bundle, accept.
    match (
        bundle.pq_encapsulation_key.as_ref(),
        bundle.pq_encapsulation_key_sig.as_ref(),
    ) {
        (Some(ek), Some(pq_sig)) => {
            if ek.len() != EK_768_LEN {
                return false;
            }
            let Ok(sig) = Signature::from_slice(pq_sig) else {
                return false;
            };
            vk.verify(ek, &sig).is_ok()
        }
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => true,
    }
}

/// Process one client message against the shared store and subscriber
/// registry, on behalf of the authenticated identity `self_id`. Returns the
/// server reply. `subs` is used by the `Send` arm to push `Delivered` to
/// live subscribers; the `Subscribe` arm returns `AckOk` here (the real
/// subscription work — channel creation, outbox flush — is done in the
/// listener's `handle_conn`, which has the connection's write half).
pub fn handle(
    store: &Store,
    subs: &Subscribers,
    self_id: &[u8; 32],
    msg: ClientMessage,
) -> ServerMessage {
    match msg {
        ClientMessage::Register { bundle } => {
            if !verify_bundle_signature(&bundle) {
                return ServerMessage::Error(um_protocol::ServerError::InvalidSignature);
            }
            store.register(bundle);
            ServerMessage::AckOk
        }
        ClientMessage::FetchBundle { target } => ServerMessage::Bundle(store.fetch_bundle(&target)),
        ClientMessage::Send {
            recipients,
            envelope,
        } => {
            // The envelope must claim to come from the authenticated identity.
            // The relay is not a crypto authority, but it is the one place that
            // knows which connection owns `self_id`, so it can stop a client
            // from sending envelopes attributed to a different identity (a
            // cheap impersonation that the E2E crypto layer cannot detect on
            // its own for group traffic, where `envelope.sender` is not covered
            // by the Sender-Key signature). Defense-in-depth alongside the
            // client's `GroupSenderMismatch` check.
            if envelope.sender != *self_id {
                return ServerMessage::Error(um_protocol::ServerError::BadSender);
            }
            // Reject if any recipient is not registered.
            if !recipients.iter().all(|r| store.is_registered(r)) {
                return ServerMessage::Error(um_protocol::ServerError::UnknownRecipient);
            }
            let delivered = store.deliver(&recipients, envelope);
            // Push to any live subscriber. try_send is non-blocking; on Full
            // (slow client) or Closed (subscriber gone) we skip the push — the
            // envelope remains in the outbox and is recovered on the next
            // Subscribe-flush or Poll.
            for (recipient, _id, env) in delivered {
                if let Some(tx) = subs.get(&recipient) {
                    match tx.try_send(ServerMessage::Delivered(vec![env])) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "push channel full for recipient, envelope stays in outbox"
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Subscriber vanished between get and send; ignore.
                        }
                    }
                }
            }
            ServerMessage::AckOk
        }
        ClientMessage::Poll { since } => {
            if !store.is_registered(self_id) {
                return ServerMessage::Error(um_protocol::ServerError::NotRegistered);
            }
            ServerMessage::Delivered(store.poll(self_id, since))
        }
        ClientMessage::Ack { envelope_ids } => {
            store.ack(self_id, &envelope_ids);
            ServerMessage::AckOk
        }
        ClientMessage::Subscribe => {
            // Subscribe is a connection-mode flag handled by the listener
            // (long-lived push). At the message level it is a no-op ack so
            // the client knows the mode was accepted.
            ServerMessage::AckOk
        }
        ClientMessage::Ping => {
            // Application-level liveness probe. The client sends `Ping` on a
            // fixed interval to detect a half-open connection (a NAT/firewall
            // that dropped the path without a FIN — the socket looks idle but
            // is dead). The server echoes `Pong` so the client's grace timer
            // resets; no store mutation, no subscriber interaction.
            ServerMessage::Pong
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subscribers;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use um_crypto::kem::PqEncapsulationKey;
    use um_protocol::{EncryptedEnvelope, PreKeyBundle, ServerError};

    /// Build a real, correctly-signed protocol PreKeyBundle from a fresh
    /// identity. `valid_sig` = false corrupts the signed-prekey signature so
    /// verification must fail.
    fn real_bundle(valid_sig: bool) -> ([u8; 32], PreKeyBundle) {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let crypto_bundle = um_crypto::identity::PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        let mut bundle = PreKeyBundle {
            identity_pub: id.verifying.to_bytes(),
            signed_prekey_id: crypto_bundle.signed_prekey_id,
            signed_prekey_pub: crypto_bundle.signed_prekey_pub.to_bytes(),
            signed_prekey_sig: crypto_bundle.signed_prekey_sig.to_bytes().to_vec(),
            one_time_prekeys: crypto_bundle
                .one_time_prekeys
                .iter()
                .map(|(k, v)| (*k, v.to_bytes()))
                .collect(),
            pq_encapsulation_key: None,
            pq_encapsulation_key_sig: None,
        };
        if !valid_sig {
            // Flip one byte of the signature.
            bundle.signed_prekey_sig[0] ^= 0xFF;
        }
        (id.verifying.to_bytes(), bundle)
    }

    /// Like [`real_bundle`](Self::real_bundle) but attaches a real ML-KEM-768
    /// encapsulation key signed by the identity (hybrid PQXDH bundle).
    /// `valid_pq_sig` = false corrupts the PQ-ek signature; `half_present` =
    /// `Some("key")`/`Some("sig")` drops one PQ field to test the half-present
    /// rejection.
    fn real_pq_bundle(valid_pq_sig: bool, half_present: Option<&str>) -> ([u8; 32], PreKeyBundle) {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let (_pq_dk, pq_ek) = PqEncapsulationKey::generate_keypair();
        let crypto_bundle =
            um_crypto::identity::PreKeyBundle::from_identity_with_pq(&id, &spk, &[&otpk], &pq_ek);
        let mut bundle = PreKeyBundle {
            identity_pub: id.verifying.to_bytes(),
            signed_prekey_id: crypto_bundle.signed_prekey_id,
            signed_prekey_pub: crypto_bundle.signed_prekey_pub.to_bytes(),
            signed_prekey_sig: crypto_bundle.signed_prekey_sig.to_bytes().to_vec(),
            one_time_prekeys: crypto_bundle
                .one_time_prekeys
                .iter()
                .map(|(k, v)| (*k, v.to_bytes()))
                .collect(),
            pq_encapsulation_key: Some(pq_ek.0.clone()),
            pq_encapsulation_key_sig: Some(
                crypto_bundle
                    .pq_encapsulation_key_sig
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            ),
        };
        if !valid_pq_sig {
            // Corrupt the PQ-ek signature, not the signed-prekey signature,
            // so the test isolates the PQ check (the SPK check still passes).
            bundle.pq_encapsulation_key_sig.as_mut().unwrap()[0] ^= 0xFF;
        }
        match half_present {
            Some("key") => bundle.pq_encapsulation_key_sig = None,
            Some("sig") => bundle.pq_encapsulation_key = None,
            _ => {}
        }
        (id.verifying.to_bytes(), bundle)
    }

    /// Build an envelope claiming to be from `sender`. The Send arm checks
    /// `envelope.sender == self_id`, so a test that drives `Send` as `alice`
    /// must pass `alice` here.
    fn envelope_from(id: u64, sender: [u8; 32]) -> EncryptedEnvelope {
        EncryptedEnvelope {
            id,
            sender,
            kind: um_protocol::MessageKind::Direct,
            header: vec![1, 2, 3],
            init: None,
            ciphertext: vec![0xAA; 8],
            signature: vec![],
        }
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let (_, bundle) = real_bundle(true);
        assert!(verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_rejects_corrupt_signature() {
        let (_, bundle) = real_bundle(false);
        assert!(!verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_accepts_valid_pq_bundle() {
        let (_, bundle) = real_pq_bundle(true, None);
        assert!(verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_rejects_corrupt_pq_signature() {
        // SPK signature is valid; only the PQ-ek signature is corrupted. The
        // PQ check must fail the whole bundle.
        let (_, bundle) = real_pq_bundle(false, None);
        assert!(!verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_rejects_pq_key_without_sig() {
        let (_, bundle) = real_pq_bundle(true, Some("key"));
        assert!(!verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_rejects_pq_sig_without_key() {
        let (_, bundle) = real_pq_bundle(true, Some("sig"));
        assert!(!verify_bundle_signature(&bundle));
    }

    #[test]
    fn verify_rejects_wrong_length_pq_ek() {
        let (_, mut bundle) = real_pq_bundle(true, None);
        // A real ML-KEM-768 ek is 1184 bytes; shrink to break the length check
        // while keeping the (now mismatched) signature intact.
        bundle.pq_encapsulation_key = Some(vec![0u8; 32]);
        assert!(!verify_bundle_signature(&bundle));
    }

    #[test]
    fn register_with_valid_pq_bundle_stores_bundle() {
        let store = Store::new();
        let (id, bundle) = real_pq_bundle(true, None);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register { bundle },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        assert!(store.is_registered(&id));
        // The PQ ek survives the round-trip through the store.
        let stored = store.fetch_bundle(&id).unwrap();
        assert!(stored.pq_encapsulation_key.is_some());
        assert!(stored.pq_encapsulation_key_sig.is_some());
    }

    #[test]
    fn register_with_corrupt_pq_sig_rejected_and_not_stored() {
        let store = Store::new();
        let (id, bundle) = real_pq_bundle(false, None);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register { bundle },
        );
        assert_eq!(reply, ServerMessage::Error(ServerError::InvalidSignature));
        assert!(!store.is_registered(&id));
    }

    #[test]
    fn register_with_valid_signature_stores_bundle() {
        let store = Store::new();
        let (id, bundle) = real_bundle(true);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register { bundle },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        assert!(store.is_registered(&id));
        assert_eq!(store.fetch_bundle(&id).unwrap().identity_pub, id);
    }

    #[test]
    fn register_with_bad_signature_rejected_and_not_stored() {
        let store = Store::new();
        let (id, bundle) = real_bundle(false);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register { bundle },
        );
        assert_eq!(reply, ServerMessage::Error(ServerError::InvalidSignature));
        assert!(!store.is_registered(&id));
    }

    #[test]
    fn fetch_bundle_returns_some_for_registered() {
        let store = Store::new();
        let (id, bundle) = real_bundle(true);
        handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register { bundle },
        );
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::FetchBundle { target: id },
        );
        assert!(matches!(reply, ServerMessage::Bundle(Some(_))));
    }

    #[test]
    fn fetch_bundle_returns_none_for_unregistered() {
        let store = Store::new();
        let (id, _) = real_bundle(true);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::FetchBundle { target: [0xFF; 32] },
        );
        assert_eq!(reply, ServerMessage::Bundle(None));
    }

    #[test]
    fn send_to_registered_recipient_delivers() {
        let store = Store::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &Subscribers::new(),
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        let reply = handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    #[test]
    fn send_to_unregistered_recipient_rejected() {
        let store = Store::new();
        let (alice, bundle_a) = real_bundle(true);
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        let reply = handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Send {
                recipients: vec![[0xFF; 32]],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::Error(ServerError::UnknownRecipient));
        // Nothing delivered.
        assert!(store.poll(&[0xFF; 32], 0).is_empty());
    }

    #[test]
    fn poll_before_register_returns_not_registered() {
        let store = Store::new();
        let reply = handle(
            &store,
            &Subscribers::new(),
            &[0x77; 32],
            ClientMessage::Poll { since: 0 },
        );
        assert_eq!(reply, ServerMessage::Error(ServerError::NotRegistered));
    }

    #[test]
    fn poll_after_register_returns_delivered_envelopes() {
        let store = Store::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &Subscribers::new(),
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        let reply = handle(
            &store,
            &Subscribers::new(),
            &bob,
            ClientMessage::Poll { since: 0 },
        );
        match reply {
            ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
            _ => panic!("expected Delivered"),
        }
    }

    #[test]
    fn ack_drops_envelopes() {
        let store = Store::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &Subscribers::new(),
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        handle(
            &store,
            &Subscribers::new(),
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        let reply = handle(
            &store,
            &Subscribers::new(),
            &bob,
            ClientMessage::Ack {
                envelope_ids: vec![1],
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        assert!(store.poll(&bob, 0).is_empty());
    }

    #[test]
    fn subscribe_returns_ackok() {
        let store = Store::new();
        let (id, _) = real_bundle(true);
        let reply = handle(&store, &Subscribers::new(), &id, ClientMessage::Subscribe);
        assert_eq!(reply, ServerMessage::AckOk);
    }

    /// `Ping` is answered with `Pong` — a stateless liveness echo. No store
    /// mutation, no subscriber interaction; the relay is just confirming the
    /// connection is alive so the client's grace timer can reset.
    #[test]
    fn ping_replies_pong() {
        let store = Store::new();
        let (id, _) = real_bundle(true);
        let reply = handle(&store, &Subscribers::new(), &id, ClientMessage::Ping);
        assert_eq!(reply, ServerMessage::Pong);
    }

    /// `Ping` does not require the connection to be registered first — it is a
    /// pure liveness echo with no store dependency, so it works on a fresh
    /// (pre-Register) connection too. This keeps the heartbeat robust even if
    /// it races the handshake.
    #[test]
    fn ping_replies_pong_even_unregistered() {
        let store = Store::new();
        let reply = handle(
            &store,
            &Subscribers::new(),
            &[0x77; 32],
            ClientMessage::Ping,
        );
        assert_eq!(reply, ServerMessage::Pong);
    }

    #[test]
    fn send_pushes_to_live_subscriber() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &subs,
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        // Bob subscribes: register a push channel for bob.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ServerMessage>(256);
        subs.register(bob, tx);
        // Alice sends to bob.
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // Bob's push channel received a Delivered frame.
        let pushed = rx.try_recv().expect("push delivered");
        match pushed {
            ServerMessage::Delivered(v) => assert_eq!(v.len(), 1),
            other => panic!("expected Delivered, got {other:?}"),
        }
    }

    #[test]
    fn send_to_offline_recipient_no_push_but_delivered() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &subs,
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        // Bob is NOT subscribed (no push channel registered).
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // No push channel exists for bob, so nothing to recv. The envelope is
        // still in bob's outbox.
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    #[test]
    fn send_push_full_channel_skips_keeps_outbox() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &subs,
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        // Bob's push channel has capacity 1 and is already full.
        let (tx, _rx) = tokio::sync::mpsc::channel::<ServerMessage>(1);
        tx.try_send(ServerMessage::AckOk).expect("seed full");
        subs.register(bob, tx);
        // Alice sends to bob; try_send hits Full, push is skipped.
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // The envelope is still in bob's outbox (recoverable on flush/poll).
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    /// `Send` with `envelope.sender != self_id` is rejected with `BadSender`.
    /// A connection may only send envelopes attributed to its own identity.
    #[test]
    fn send_with_wrong_sender_rejected() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &subs,
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        // Alice's connection sends an envelope claiming to be from bob.
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, bob),
            },
        );
        assert_eq!(reply, ServerMessage::Error(ServerError::BadSender));
        // Nothing was delivered: the sender check runs before delivery.
        assert!(store.poll(&bob, 0).is_empty());
    }

    /// `Send` with `envelope.sender == self_id` is accepted (the happy path the
    /// BadSender check must not break).
    #[test]
    fn send_with_correct_sender_accepted() {
        let store = Store::new();
        let subs = Subscribers::new();
        let (alice, bundle_a) = real_bundle(true);
        let (bob, bundle_b) = real_bundle(true);
        handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Register { bundle: bundle_a },
        );
        handle(
            &store,
            &subs,
            &bob,
            ClientMessage::Register { bundle: bundle_b },
        );
        let reply = handle(
            &store,
            &subs,
            &alice,
            ClientMessage::Send {
                recipients: vec![bob],
                envelope: envelope_from(0, alice),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }
}
