//! In-memory server state: prekey registry, per-recipient outbox, presence.
//!
//! Lost on restart (per the locked design decision). All access goes through
//! `Store`, which is `Send + Sync` via an internal mutex.

use std::collections::{HashMap, HashSet};
use um_protocol::{EncryptedEnvelope, PreKeyBundle};

/// In-memory relay state. One instance shared across all connections
/// (`Arc<Store>`). All mutations go through the internal mutex.
pub struct Store {
    inner: std::sync::Mutex<StoreInner>,
}

struct StoreInner {
    /// Registered identity pub -> prekey bundle.
    bundles: HashMap<[u8; 32], PreKeyBundle>,
    /// Recipient identity pub -> undelivered envelopes (FIFO outbox).
    outboxes: HashMap<[u8; 32], Vec<EncryptedEnvelope>>,
    /// Identities that have completed `Register`.
    registered: HashSet<[u8; 32]>,
    /// Monotonic envelope id counter.
    next_envelope_id: u64,
}

impl Store {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(StoreInner {
                bundles: HashMap::new(),
                outboxes: HashMap::new(),
                registered: HashSet::new(),
                next_envelope_id: 1,
            }),
        }
    }

    /// Register/refresh a prekey bundle. Overwrites any prior bundle for the
    /// same identity. Marks the identity registered.
    pub fn register(&self, bundle: PreKeyBundle) {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        g.registered.insert(bundle.identity_pub);
        g.bundles.insert(bundle.identity_pub, bundle);
    }

    /// True if `identity` has registered.
    pub fn is_registered(&self, identity: &[u8; 32]) -> bool {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .registered
            .contains(identity)
    }

    /// Fetch a clone of the bundle for `target`, if registered.
    pub fn fetch_bundle(&self, target: &[u8; 32]) -> Option<PreKeyBundle> {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .bundles
            .get(target)
            .cloned()
    }

    /// Append `envelope` to every registered recipient's outbox, assigning
    /// each copy a fresh monotonic id. Returns `(recipient, id, envelope)`
    /// triples for the recipients that were actually delivered to, in
    /// recipient order. Unregistered recipients are skipped (absent from the
    /// return; the caller decides whether to surface `UnknownRecipient`).
    pub fn deliver(
        &self,
        recipients: &[[u8; 32]],
        mut envelope: EncryptedEnvelope,
    ) -> Vec<([u8; 32], u64, EncryptedEnvelope)> {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        let mut out = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            if !g.registered.contains(recipient) {
                continue;
            }
            envelope.id = g.next_envelope_id;
            g.next_envelope_id += 1;
            let id = envelope.id;
            g.outboxes
                .entry(*recipient)
                .or_default()
                .push(envelope.clone());
            out.push((*recipient, id, envelope.clone()));
        }
        out
    }

    /// Drain all undelivered envelopes for `identity` with id > `since`.
    /// Returns them in FIFO order. Does NOT remove them from the outbox
    /// (the client must `Ack` to drop them).
    pub fn poll(&self, identity: &[u8; 32], since: u64) -> Vec<EncryptedEnvelope> {
        let g = self.inner.lock().expect("store mutex poisoned");
        g.outboxes
            .get(identity)
            .map(|v| v.iter().filter(|e| e.id > since).cloned().collect())
            .unwrap_or_default()
    }

    /// Drop the acknowledged envelopes (by id) from `identity`'s outbox.
    pub fn ack(&self, identity: &[u8; 32], envelope_ids: &[u64]) {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        if let Some(outbox) = g.outboxes.get_mut(identity) {
            outbox.retain(|e| !envelope_ids.contains(&e.id));
        }
    }

    /// Test-only: re-insert an already-delivered envelope into `identity`'s
    /// outbox **with its existing id**, simulating an ack that never reached
    /// the relay (network drop / relay restart before processing the ack). The
    /// next `Subscribe` flush or `Poll { since < id }` re-delivers the SAME
    /// envelope (same `id`) to the client, which is exactly the duplicate the
    /// store-level `(peer, server_id)` dedup must collapse. Used by the
    /// headless bridge dedup E2E test; not wired into any production path.
    #[cfg(feature = "test-helpers")]
    pub fn reinsert_envelope(&self, identity: &[u8; 32], envelope: EncryptedEnvelope) {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        g.outboxes.entry(*identity).or_default().push(envelope);
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(identity: [u8; 32]) -> PreKeyBundle {
        PreKeyBundle {
            identity_pub: identity,
            signed_prekey_id: 1,
            signed_prekey_pub: [0x22; 32],
            signed_prekey_sig: vec![0xAB; 64],
            one_time_prekeys: vec![(10, [0x33; 32])],
            pq_encapsulation_key: None,
            pq_encapsulation_key_sig: None,
        }
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
    fn register_then_fetch_returns_bundle() {
        let store = Store::new();
        let id = [0x11; 32];
        assert!(!store.is_registered(&id));
        store.register(bundle(id));
        assert!(store.is_registered(&id));
        let fetched = store.fetch_bundle(&id).expect("bundle present");
        assert_eq!(fetched.identity_pub, id);
    }

    #[test]
    fn fetch_unregistered_returns_none() {
        let store = Store::new();
        assert!(store.fetch_bundle(&[0x99; 32]).is_none());
    }

    #[test]
    fn deliver_to_registered_assigns_monotonic_ids() {
        let store = Store::new();
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        store.register(bundle(alice));
        store.register(bundle(bob));
        // Alice sends two messages to bob.
        let d1 = store.deliver(&[bob], envelope(0));
        let d2 = store.deliver(&[bob], envelope(0));
        let ids1: Vec<u64> = d1.iter().map(|(_, id, _)| *id).collect();
        let ids2: Vec<u64> = d2.iter().map(|(_, id, _)| *id).collect();
        assert_eq!(ids1, vec![1]);
        assert_eq!(ids2, vec![2]);
        // Bob's outbox has both, in order.
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 2);
        assert_eq!(polled[0].id, 1);
        assert_eq!(polled[1].id, 2);
    }

    #[test]
    fn deliver_skips_unregistered_recipient() {
        let store = Store::new();
        let bob = [0x02; 32];
        // bob is NOT registered.
        let delivered = store.deliver(&[bob], envelope(0));
        // Unregistered recipients are absent from the return (not id=0 entries).
        assert!(delivered.is_empty());
        assert!(store.poll(&bob, 0).is_empty());
    }

    #[test]
    fn deliver_to_group_fans_out_to_each_registered_member() {
        let store = Store::new();
        let m1 = [0x01; 32];
        let m2 = [0x02; 32];
        let m3 = [0x03; 32];
        store.register(bundle(m1));
        store.register(bundle(m2));
        // m3 not registered.
        let delivered = store.deliver(&[m1, m2, m3], envelope(0));
        // Only registered recipients (m1, m2) appear; m3 is absent.
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].0, m1);
        assert_eq!(delivered[0].1, 1);
        assert_eq!(delivered[1].0, m2);
        assert_eq!(delivered[1].1, 2);
        assert_eq!(store.poll(&m1, 0).len(), 1);
        assert_eq!(store.poll(&m2, 0).len(), 1);
        assert_eq!(store.poll(&m3, 0).len(), 0);
    }

    #[test]
    fn poll_with_since_filters_already_seen() {
        let store = Store::new();
        let bob = [0x02; 32];
        store.register(bundle(bob));
        store.deliver(&[bob], envelope(0));
        store.deliver(&[bob], envelope(0));
        store.deliver(&[bob], envelope(0));
        // Bob already saw up to id 2; poll returns only id 3.
        let polled = store.poll(&bob, 2);
        assert_eq!(polled.len(), 1);
        assert_eq!(polled[0].id, 3);
    }

    #[test]
    fn poll_does_not_remove_until_acked() {
        let store = Store::new();
        let bob = [0x02; 32];
        store.register(bundle(bob));
        store.deliver(&[bob], envelope(0));
        // Poll twice — both see the envelope (not yet acked).
        assert_eq!(store.poll(&bob, 0).len(), 1);
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    #[test]
    fn ack_drops_delivered_envelopes() {
        let store = Store::new();
        let bob = [0x02; 32];
        store.register(bundle(bob));
        store.deliver(&[bob], envelope(0));
        store.deliver(&[bob], envelope(0));
        // Bob acks id 1.
        store.ack(&bob, &[1]);
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 1);
        assert_eq!(polled[0].id, 2);
    }

    #[test]
    fn ack_for_unknown_identity_is_noop() {
        let store = Store::new();
        // Should not panic.
        store.ack(&[0xFF; 32], &[1, 2, 3]);
    }
}
