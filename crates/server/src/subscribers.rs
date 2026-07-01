//! Registry of live push subscribers: identity_pub -> mpsc sender. Used by
//! the listener to route `Delivered` pushes to the connection that owns an
//! identity. Last-Subscribe-wins: registering a new sender for an identity
//! evicts the old one. All access goes through an internal mutex.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use um_protocol::ServerMessage;

pub struct Subscribers {
    inner: Mutex<HashMap<[u8; 32], mpsc::Sender<ServerMessage>>>,
}

impl Subscribers {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register `tx` as the push sender for `id`. If an entry already exists,
    /// evict it and return the old `Sender` so the caller can drop it (which
    /// closes the old channel and surfaces as `None` on the old connection's
    /// `recv`). Last-Subscribe-wins.
    pub fn register(
        &self,
        id: [u8; 32],
        tx: mpsc::Sender<ServerMessage>,
    ) -> Option<mpsc::Sender<ServerMessage>> {
        let mut g = self.inner.lock().expect("subscribers mutex poisoned");
        g.insert(id, tx)
    }

    /// Remove the entry for `id` only if its channel matches `tx`
    /// (`Sender::same_channel`). This prevents a disconnect-cleanup from
    /// removing a newer subscriber that evicted this connection.
    pub fn unregister_if_match(&self, id: &[u8; 32], tx: &mpsc::Sender<ServerMessage>) {
        let mut g = self.inner.lock().expect("subscribers mutex poisoned");
        if let Some(existing) = g.get(id) {
            if existing.same_channel(tx) {
                g.remove(id);
            }
        }
    }

    /// Clone the push sender for `id`, if present.
    pub fn get(&self, id: &[u8; 32]) -> Option<mpsc::Sender<ServerMessage>> {
        self.inner
            .lock()
            .expect("subscribers mutex poisoned")
            .get(id)
            .cloned()
    }
}

impl Default for Subscribers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_returns_none_first() {
        let subs = Subscribers::new();
        let (tx, _rx) = mpsc::channel::<ServerMessage>(256);
        assert!(subs.register([0x11; 32], tx).is_none());
    }

    #[test]
    fn register_evicts_old_returns_tx() {
        let subs = Subscribers::new();
        let (tx1, rx1) = mpsc::channel::<ServerMessage>(256);
        let (tx2, _rx2) = mpsc::channel::<ServerMessage>(256);
        let tx1_clone = tx1.clone();
        assert!(subs.register([0x11; 32], tx1).is_none());
        let evicted = subs.register([0x11; 32], tx2);
        assert!(evicted.is_some());
        // The evicted sender must be the one we registered first.
        assert!(evicted.unwrap().same_channel(&tx1_clone));
        // rx1 is still owned here; dropping it later closes the old channel.
        drop(rx1);
    }

    #[test]
    fn unregister_if_match_removes_only_matching() {
        let subs = Subscribers::new();
        let (tx1, _rx1) = mpsc::channel::<ServerMessage>(256);
        let (tx2, _rx2) = mpsc::channel::<ServerMessage>(256);
        let tx1_clone = tx1.clone();
        let tx2_clone = tx2.clone();
        subs.register([0x11; 32], tx1);
        // A second connection for the same identity evicts tx1.
        subs.register([0x11; 32], tx2);
        // The first connection cleans up with its own (now-evicted) tx1.
        subs.unregister_if_match(&[0x11; 32], &tx1_clone);
        // The registry still holds tx2 (the current subscriber).
        assert!(subs
            .get(&[0x11; 32])
            .map_or(false, |s| s.same_channel(&tx2_clone)));
    }

    #[test]
    fn get_returns_cloned_sender() {
        let subs = Subscribers::new();
        let (tx, _rx) = mpsc::channel::<ServerMessage>(256);
        let tx_clone = tx.clone();
        subs.register([0x22; 32], tx);
        let got = subs.get(&[0x22; 32]);
        assert!(got.is_some());
        // The clone shares the channel with the registered sender.
        assert!(got.unwrap().same_channel(&subs.get(&[0x22; 32]).unwrap()));
        assert!(subs.get(&[0x22; 32]).unwrap().same_channel(&tx_clone));
    }

    #[test]
    fn get_missing_returns_none() {
        let subs = Subscribers::new();
        assert!(subs.get(&[0xFF; 32]).is_none());
    }
}
