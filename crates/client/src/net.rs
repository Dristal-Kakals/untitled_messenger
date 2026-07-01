//! Async TCP client for the UM relay. Framed reader/writer over tokio.
//! One `Client` per connection. The caller drives send/recv; no background
//! task here (the headless client polls or subscribes explicitly).

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};

use crate::ClientError;

/// A framed TCP client connected to the relay.
pub struct Client {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    buf: Vec<u8>,
}

impl Client {
    /// Connect to the relay at `addr`.
    pub async fn connect(addr: std::net::SocketAddr) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(r),
            writer: w,
            buf: Vec::new(),
        })
    }

    /// Send one client message (framed).
    pub async fn send_msg(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        let frame = encode(msg)?;
        self.writer.write_all(&frame).await?;
        Ok(())
    }

    /// Receive one server message. Returns `None` on EOF.
    pub async fn recv_msg(&mut self) -> Result<Option<ServerMessage>, ClientError> {
        loop {
            if let Ok((msg, consumed)) = decode::<ServerMessage>(&self.buf) {
                self.buf.drain(0..consumed);
                return Ok(Some(msg));
            }
            let mut chunk = [0u8; 4096];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use um_protocol::PreKeyBundle;
    use um_server::{listener::serve, Store};

    fn real_bundle() -> (IdentityKey, PreKeyBundle) {
        let id = IdentityKey::generate();
        let spk = SignedPreKey::generate(1, &id);
        let otpk = OneTimePreKey::generate(10);
        let crypto_bundle = um_crypto::identity::PreKeyBundle::from_identity(&id, &spk, &[&otpk]);
        let bundle = PreKeyBundle {
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
        (id, bundle)
    }

    #[tokio::test]
    async fn client_registers_and_fetches_bundle() {
        let store = Arc::new(Store::new());
        let addr = serve("127.0.0.1:0", store).await.expect("serve");

        let (id, bundle) = real_bundle();
        let mut client = Client::connect(addr).await.expect("connect");
        client
            .send_msg(&ClientMessage::Register { bundle })
            .await
            .expect("send");
        let reply = client.recv_msg().await.expect("recv");
        assert!(matches!(reply, Some(ServerMessage::AckOk)));

        // Fetch own bundle.
        client
            .send_msg(&ClientMessage::FetchBundle {
                target: id.verifying.to_bytes(),
            })
            .await
            .expect("send");
        let reply = client.recv_msg().await.expect("recv");
        match reply {
            Some(ServerMessage::Bundle(Some(b))) => {
                assert_eq!(b.identity_pub, id.verifying.to_bytes())
            }
            other => panic!("expected Bundle(Some), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_clients_exchange_envelopes() {
        let store = Arc::new(Store::new());
        let addr = serve("127.0.0.1:0", store).await.expect("serve");

        let (alice_id, alice_bundle) = real_bundle();
        let (bob_id, bob_bundle) = real_bundle();
        let alice_pub = alice_id.verifying.to_bytes();
        let bob_pub = bob_id.verifying.to_bytes();

        let mut alice = Client::connect(addr).await.expect("connect");
        alice
            .send_msg(&ClientMessage::Register {
                bundle: alice_bundle,
            })
            .await
            .expect("send");
        assert!(matches!(
            alice.recv_msg().await.unwrap(),
            Some(ServerMessage::AckOk)
        ));

        let mut bob = Client::connect(addr).await.expect("connect");
        bob.send_msg(&ClientMessage::Register { bundle: bob_bundle })
            .await
            .expect("send");
        assert!(matches!(
            bob.recv_msg().await.unwrap(),
            Some(ServerMessage::AckOk)
        ));

        // Alice sends an opaque envelope to Bob.
        alice
            .send_msg(&ClientMessage::Send {
                recipients: vec![bob_pub],
                envelope: um_protocol::EncryptedEnvelope {
                    id: 0,
                    sender: alice_pub,
                    header: vec![1, 2, 3],
                    init: None,
                    ciphertext: vec![0xAA; 8],
                },
            })
            .await
            .expect("send");
        assert!(matches!(
            alice.recv_msg().await.unwrap(),
            Some(ServerMessage::AckOk)
        ));

        // Bob polls.
        bob.send_msg(&ClientMessage::Poll { since: 0 })
            .await
            .expect("send");
        let reply = bob.recv_msg().await.expect("recv");
        match reply {
            Some(ServerMessage::Delivered(v)) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].sender, alice_pub);
            }
            other => panic!("expected Delivered, got {other:?}"),
        }
    }
}
