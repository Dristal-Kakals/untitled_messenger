//! In-memory server state: prekey registry, per-recipient outbox, presence.
//!
//! Lost on restart (per the locked design decision). All access goes through
//! `Store`, which is `Send + Sync` via an internal mutex.

use std::collections::{HashMap, HashSet, VecDeque};
use um_protocol::{EncryptedEnvelope, PreKeyBundle};

/// Maximum undelivered envelopes buffered per recipient outbox. A recipient
/// that never `Ack`s (gone offline long-term, or a malicious/buggy client
/// that polls but never acks) would otherwise let a sender flood its outbox
/// without bound → relay OOM. The connection-flood / write-timeout guards
/// bound the *rate* of arrival, but not the *accumulated* backlog for a
/// single never-acking recipient; this cap is the memory backstop.
///
/// Eviction is FIFO: when a `deliver` would exceed the cap the oldest
/// undelivered envelope is dropped. Newer envelopes survive; the dropped id
/// is simply absent from future `poll`/`Subscribe`-flush results (the
/// recipient never acked it, so it was never displayed). A legitimate
/// recipient polls and acks promptly and never approaches the cap; only a
/// never-acking recipient accumulates, which is exactly the vector bounded
/// here.
pub const MAX_OUTBOX_PER_RECIPIENT: usize = 4096;

/// In-memory relay state. One instance shared across all connections
/// (`Arc<Store>`). All mutations go through the internal mutex.
pub struct Store {
    inner: std::sync::Mutex<StoreInner>,
}

struct StoreInner {
    /// Registered identity pub -> prekey bundle.
    bundles: HashMap<[u8; 32], PreKeyBundle>,
    /// Recipient identity pub -> undelivered envelopes (FIFO outbox). A
    /// `VecDeque` for O(1) back-push / front-evict; bounded to
    /// `max_outbox_per_recipient` entries per recipient.
    outboxes: HashMap<[u8; 32], VecDeque<EncryptedEnvelope>>,
    /// Identities that have completed `Register`.
    registered: HashSet<[u8; 32]>,
    /// Monotonic envelope id counter.
    next_envelope_id: u64,
    /// Per-recipient outbox cap (see [`MAX_OUTBOX_PER_RECIPIENT`]).
    max_outbox_per_recipient: usize,
}

impl Store {
    /// Create an empty store with the production outbox cap
    /// ([`MAX_OUTBOX_PER_RECIPIENT`]).
    pub fn new() -> Self {
        Self::with_outbox_cap(MAX_OUTBOX_PER_RECIPIENT)
    }

    /// Create an empty store with a caller-supplied per-recipient outbox cap.
    /// Production uses [`Store::new`] (the default constant); tests shrink the
    /// cap so eviction is exercised with a handful of delivers instead of 4097.
    pub fn with_outbox_cap(max_outbox_per_recipient: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(StoreInner {
                bundles: HashMap::new(),
                outboxes: HashMap::new(),
                registered: HashSet::new(),
                next_envelope_id: 1,
                max_outbox_per_recipient,
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
        let cap = g.max_outbox_per_recipient;
        let mut out = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            if !g.registered.contains(recipient) {
                continue;
            }
            envelope.id = g.next_envelope_id;
            g.next_envelope_id += 1;
            let id = envelope.id;
            let outbox = g.outboxes.entry(*recipient).or_default();
            // FIFO eviction: if the recipient has never acked and the outbox
            // is at the cap, drop the oldest undelivered envelope to make
            // room. Keeps the per-recipient backlog bounded against an
            // un-acking recipient flood; a promptly-acking recipient never
            // triggers this.
            if outbox.len() >= cap {
                outbox.pop_front();
            }
            outbox.push_back(envelope.clone());
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
    /// Builds a `HashSet` of acked ids so each outbox scan is O(outbox) not
    /// O(outbox × acks) — a batched `Ack` of N ids against an outbox of M
    /// envelopes was O(M·N) with `Vec::contains`; now O(M + N).
    pub fn ack(&self, identity: &[u8; 32], envelope_ids: &[u64]) {
        let mut g = self.inner.lock().expect("store mutex poisoned");
        if let Some(outbox) = g.outboxes.get_mut(identity) {
            if envelope_ids.is_empty() {
                return;
            }
            let acked: HashSet<u64> = envelope_ids.iter().copied().collect();
            outbox.retain(|e| !acked.contains(&e.id));
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
        let cap = g.max_outbox_per_recipient;
        let outbox = g.outboxes.entry(*identity).or_default();
        if outbox.len() >= cap {
            outbox.pop_front();
        }
        outbox.push_back(envelope);
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

    #[test]
    fn outbox_cap_evicts_oldest_when_full() {
        // Cap of 3 so a 4th deliver evicts id 1 (the oldest).
        let store = Store::with_outbox_cap(3);
        let bob = [0x02; 32];
        store.register(bundle(bob));
        // Bob never acks; deliver 4 envelopes. Only the newest 3 survive.
        for _ in 0..4 {
            store.deliver(&[bob], envelope(0));
        }
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 3, "capped at 3, oldest evicted");
        // FIFO eviction: ids 2, 3, 4 remain; id 1 was dropped.
        assert_eq!(polled[0].id, 2);
        assert_eq!(polled[1].id, 3);
        assert_eq!(polled[2].id, 4);
    }

    #[test]
    fn outbox_cap_preserves_newest_under_flood() {
        // A never-acking recipient under a flood keeps only the newest cap
        // envelopes; the backlog cannot grow unbounded.
        let store = Store::with_outbox_cap(8);
        let bob = [0x02; 32];
        store.register(bundle(bob));
        for _ in 0..100 {
            store.deliver(&[bob], envelope(0));
        }
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 8, "backlog bounded at cap after 100 delivers");
        // The newest 8 ids are 93..=100.
        assert_eq!(polled[0].id, 93);
        assert_eq!(polled[7].id, 100);
    }

    #[test]
    fn outbox_cap_per_recipient_isolation() {
        // Eviction is per-recipient: flooding bob's outbox does not evict
        // from alice's.
        let store = Store::with_outbox_cap(2);
        let alice = [0x01; 32];
        let bob = [0x02; 32];
        store.register(bundle(alice));
        store.register(bundle(bob));
        store.deliver(&[alice], envelope(0));
        // Flood bob past its cap.
        for _ in 0..5 {
            store.deliver(&[bob], envelope(0));
        }
        // Alice's single envelope survives untouched.
        assert_eq!(store.poll(&alice, 0).len(), 1);
        assert_eq!(store.poll(&alice, 0)[0].id, 1);
        // Bob is capped at 2. Alice got id 1; bob's 5 delivers got ids 2..=6,
        // so the newest 2 (ids 5, 6) survive — ids 2, 3, 4 evicted FIFO.
        let bob_polled = store.poll(&bob, 0);
        assert_eq!(bob_polled.len(), 2);
        assert_eq!(bob_polled[0].id, 5);
        assert_eq!(bob_polled[1].id, 6);
    }

    #[test]
    fn outbox_cap_ack_frees_room_then_no_eviction() {
        // A promptly-acking recipient frees room as it acks, so subsequent
        // delivers do not evict — the cap only bites never-acking recipients.
        let store = Store::with_outbox_cap(3);
        let bob = [0x02; 32];
        store.register(bundle(bob));
        for _ in 0..3 {
            store.deliver(&[bob], envelope(0));
        }
        // Bob acks all 3; outbox is now empty.
        store.ack(&bob, &[1, 2, 3]);
        assert!(store.poll(&bob, 0).is_empty());
        // 3 more delivers fit without eviction (outbox was empty).
        for _ in 0..3 {
            store.deliver(&[bob], envelope(0));
        }
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 3);
        // ids 4, 5, 6 — none evicted (all present).
        assert_eq!(polled[0].id, 4);
        assert_eq!(polled[2].id, 6);
    }

    #[test]
    fn ack_batched_is_efficient_and_correct() {
        // Ack a batch of ids; only those are dropped, the rest survive. This
        // exercises the HashSet-based retain against the old O(M·N) contains.
        let store = Store::new();
        let bob = [0x02; 32];
        store.register(bundle(bob));
        for _ in 0..6 {
            store.deliver(&[bob], envelope(0));
        }
        // Ack a non-contiguous batch: ids 2, 4, 6.
        store.ack(&bob, &[6, 2, 4]);
        let polled = store.poll(&bob, 0);
        let remaining: Vec<u64> = polled.iter().map(|e| e.id).collect();
        assert_eq!(remaining, vec![1, 3, 5]);
    }

    #[test]
    fn ack_empty_batch_is_noop() {
        let store = Store::new();
        let bob = [0x02; 32];
        store.register(bundle(bob));
        store.deliver(&[bob], envelope(0));
        store.ack(&bob, &[]);
        assert_eq!(store.poll(&bob, 0).len(), 1);
    }

    #[cfg(feature = "test-helpers")]
    #[test]
    fn reinsert_envelope_respects_cap() {
        // The test-helper reinsert path also bounds the outbox; reinserting
        // past the cap evicts the oldest (so a test simulating lost-ack
        // re-delivery cannot itself grow the outbox unbounded).
        let store = Store::with_outbox_cap(2);
        let bob = [0x02; 32];
        store.register(bundle(bob));
        store.deliver(&[bob], envelope(0)); // id 1
        store.deliver(&[bob], envelope(0)); // id 2
        // Reinsert a third (lost-ack sim) — evicts id 1.
        store.reinsert_envelope(&bob, envelope(99));
        let polled = store.poll(&bob, 0);
        assert_eq!(polled.len(), 2);
        assert_eq!(polled[0].id, 2);
        assert_eq!(polled[1].id, 99);
    }
}
