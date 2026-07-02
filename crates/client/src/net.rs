//! Async TCP client for the UM relay. Framed reader/writer over tokio.
//!
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
    ///
    /// `ProtocolError::Incomplete` means the buffered bytes do not yet hold a
    /// full frame, so we read another chunk and retry. Any other decode error
    /// (`FrameTooLarge` from a corrupt length header, or `Decode` from a
    /// malformed payload) is fatal for this stream: the framing state is
    /// unrecoverable and looping would buffer forever. We surface it instead
    /// of hanging the recv side on a single bad byte.
    pub async fn recv_msg(&mut self) -> Result<Option<ServerMessage>, ClientError> {
        loop {
            match decode::<ServerMessage>(&self.buf) {
                Ok((msg, consumed)) => {
                    self.buf.drain(0..consumed);
                    return Ok(Some(msg));
                }
                Err(um_protocol::ProtocolError::Incomplete) => {}
                Err(e) => return Err(ClientError::Protocol(e)),
            }
            let mut chunk = [0u8; 4096];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Split this client into a reader and a writer that can be moved to
    /// separate tasks (the GUI bridge runs a recv-loop and a command loop
    /// concurrently). The reader owns the read half + framing buffer; the
    /// writer owns the write half. Both are `Send`.
    pub fn into_split(self) -> (ClientReader, ClientWriter) {
        let Self {
            reader,
            writer,
            buf,
        } = self;
        (ClientReader { reader, buf }, ClientWriter { writer })
    }
}

/// The read half of a split [`Client`]. Owns the framed read buffer.
pub struct ClientReader {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: Vec<u8>,
}

impl ClientReader {
    /// Receive one server message. Returns `None` on EOF.
    ///
    /// Same fatal-error handling as [`Client::recv_msg`]: `Incomplete` waits
    /// for more bytes, any other decode error is surfaced rather than looping
    /// forever on a corrupt frame.
    pub async fn recv_msg(&mut self) -> Result<Option<ServerMessage>, ClientError> {
        loop {
            match decode::<ServerMessage>(&self.buf) {
                Ok((msg, consumed)) => {
                    self.buf.drain(0..consumed);
                    return Ok(Some(msg));
                }
                Err(um_protocol::ProtocolError::Incomplete) => {}
                Err(e) => return Err(ClientError::Protocol(e)),
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

/// The write half of a split [`Client`].
pub struct ClientWriter {
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl ClientWriter {
    /// Send one client message (framed).
    pub async fn send_msg(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        let frame = encode(msg)?;
        self.writer.write_all(&frame).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use um_crypto::identity::{IdentityKey, OneTimePreKey, SignedPreKey};
    use um_protocol::PreKeyBundle;
    use um_server::{Store, Subscribers, listener::serve};

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
            pq_encapsulation_key: None,
            pq_encapsulation_key_sig: None,
        };
        (id, bundle)
    }

    #[tokio::test]
    async fn client_registers_and_fetches_bundle() {
        let store = Arc::new(Store::new());
        let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
            .await
            .expect("serve");
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
                assert_eq!(b.identity_pub, id.verifying.to_bytes());
            }
            other => panic!("expected Bundle(Some), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_clients_exchange_envelopes() {
        let store = Arc::new(Store::new());
        let addr = serve("127.0.0.1:0", store, Arc::new(Subscribers::new()))
            .await
            .expect("serve");
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
                    kind: um_protocol::MessageKind::Direct,
                    header: vec![1, 2, 3],
                    init: None,
                    ciphertext: vec![0xAA; 8],
                    signature: vec![],
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

    /// A minimal raw TCP peer: accepts one connection and writes `bytes`
    /// directly to it (bypassing the framing encoder), so we can feed the
    /// client a deliberately malformed frame. Returns the bound address.
    async fn raw_peer_writing(bytes: Vec<u8>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(&bytes).await.expect("write raw bytes");
            // Keep the connection open so the client does not see EOF first;
            // the malformed frame must be surfaced before any EOF.
            std::future::pending::<()>().await;
        });
        addr
    }

    /// `recv_msg` must surface a `Decode` error (a frame with a valid length
    /// header but a payload that is not a valid `ServerMessage`) instead of
    /// looping forever waiting for a decode that will never succeed. Before
    /// the fix this hung the recv side on a single bad byte and buffered
    /// forever.
    #[tokio::test]
    async fn recv_msg_surfaces_decode_error_instead_of_hanging() {
        // Length-prefixed frame claiming 4 bytes of payload, with garbage that
        // postcard cannot deserialize as a ServerMessage.
        let mut frame = Vec::new();
        frame.extend_from_slice(&4u32.to_be_bytes());
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let addr = raw_peer_writing(frame).await;

        let mut client = Client::connect(addr).await.expect("connect");
        let result = client.recv_msg().await;
        assert!(
            matches!(result, Err(ClientError::Protocol(_))),
            "expected Protocol error, got {result:?}"
        );
    }

    /// `recv_msg` must surface a `FrameTooLarge` error (a length header
    /// claiming more than `MAX_FRAME_SIZE`) instead of trying to buffer
    /// 16+ MiB and looping.
    #[tokio::test]
    async fn recv_msg_surfaces_frame_too_large_instead_of_hanging() {
        let len = (um_protocol::MAX_FRAME_SIZE + 1) as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&len.to_be_bytes());
        let addr = raw_peer_writing(frame).await;

        let mut client = Client::connect(addr).await.expect("connect");
        let result = client.recv_msg().await;
        assert!(
            matches!(result, Err(ClientError::Protocol(_))),
            "expected Protocol error, got {result:?}"
        );
    }

    /// `Incomplete` is still handled correctly: a partial frame (length header
    /// claims more bytes than were sent) returns `Ok(None)` only on EOF, and
    /// otherwise keeps waiting. Here the peer closes after a partial frame,
    /// so the client should observe EOF as `Ok(None)` — proving the Incomplete
    /// branch still drives a read and does not error out.
    #[tokio::test]
    async fn recv_msg_incomplete_then_eof_returns_none() {
        // Claim 16 bytes of payload but send only 2, then drop the peer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut partial = Vec::new();
            partial.extend_from_slice(&16u32.to_be_bytes());
            partial.extend_from_slice(&[1, 2]);
            sock.write_all(&partial).await.expect("write partial");
            // Drop sock -> EOF on the client side.
        });

        let mut client = Client::connect(addr).await.expect("connect");
        let result = client.recv_msg().await.expect("recv should not error");
        assert_eq!(result, None, "partial frame + EOF should yield None");
    }

    /// Same fatal-error contract for the split `ClientReader`.
    #[tokio::test]
    async fn client_reader_surfaces_decode_error() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&4u32.to_be_bytes());
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let addr = raw_peer_writing(frame).await;

        let client = Client::connect(addr).await.expect("connect");
        let (mut reader, _writer) = client.into_split();
        let result = reader.recv_msg().await;
        assert!(
            matches!(result, Err(ClientError::Protocol(_))),
            "expected Protocol error, got {result:?}"
        );
    }
}
