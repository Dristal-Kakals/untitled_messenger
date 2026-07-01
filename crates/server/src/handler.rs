//! Connection dispatch: decode a `ClientMessage`, mutate the `Store`, reply
//! with a `ServerMessage`. Stateless except for the shared `Store`; one
//! `handle` call per inbound frame.

use um_crypto::{Signature, VerifyingKey};
use um_protocol::{ClientMessage, ServerMessage};

use crate::{Store, Subscribers};

/// Verify a registered prekey bundle's signed-prekey signature against its
/// identity pub. Returns `true` if the signature is valid.
pub fn verify_bundle_signature(bundle: &um_protocol::PreKeyBundle) -> bool {
    // The signed prekey pub is an X25519 pub (32 bytes). The signature is an
    // Ed25519 signature over those 32 bytes by the identity key. Reconstruct
    // the verifying key and verify.
    let Ok(vk) = VerifyingKey::from_bytes(&bundle.identity_pub) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&bundle.signed_prekey_sig) else {
        return false;
    };
    use ed25519_dalek::Verifier;
    vk.verify(&bundle.signed_prekey_pub, &sig).is_ok()
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subscribers;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use um_protocol::{EncryptedEnvelope, PreKeyBundle, ServerError};

    /// Build a real, correctly-signed protocol PreKeyBundle from a fresh
    /// identity. `valid_sig` = false corrupts the signature so verification
    /// must fail.
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
        };
        if !valid_sig {
            // Flip one byte of the signature.
            bundle.signed_prekey_sig[0] ^= 0xFF;
        }
        (id.verifying.to_bytes(), bundle)
    }

    fn envelope(id: u64) -> EncryptedEnvelope {
        EncryptedEnvelope {
            id,
            sender: [0x55; 32],
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
    fn register_with_valid_signature_stores_bundle() {
        let store = Store::new();
        let (id, bundle) = real_bundle(true);
        let reply = handle(
            &store,
            &Subscribers::new(),
            &id,
            ClientMessage::Register {
                bundle: bundle.clone(),
            },
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
                envelope: envelope(0),
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
                envelope: envelope(0),
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
                envelope: envelope(0),
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
                envelope: envelope(0),
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
                envelope: envelope(0),
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
                envelope: envelope(0),
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
                envelope: envelope(0),
            },
        );
        assert_eq!(reply, ServerMessage::AckOk);
        // The envelope is still in bob's outbox (recoverable on flush/poll).
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }
}
