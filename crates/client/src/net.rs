//! Async TCP client for the UM relay. Framed reader/writer over tokio.
//!
//! One `Client` per connection. The caller drives send/recv; no background
//! task here (the headless client polls or subscribes explicitly).
//!
//! All socket reads and writes are deadline-bounded so a hung or malicious
//! relay cannot stall the client indefinitely: a read that yields no bytes
//! within [`READ_TIMEOUT`] (e.g. the relay accepted the connection but stops
//! responding, or drip-feeds one byte per minute) surfaces as
//! [`ClientError::Timeout`], and a write the relay stops draining surfaces
//! the same way after [`WRITE_TIMEOUT`]. The caller tears down and reconnects.

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};

use crate::ClientError;

/// Maximum idle time on a socket read. A read that produces no bytes within
/// this window is treated as a hung relay and surfaced as
/// [`ClientError::Timeout`]. Large enough that a legitimately slow link still
/// completes a frame (each `read` resets the clock), small enough that a
/// drip-feed or dead relay is detected in bounded time.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum time to flush a frame to the socket. A relay that stops draining
/// its receive buffer stalls `write_all` via TCP backpressure; bounding it
/// surfaces [`ClientError::Timeout`] so the caller can reconnect instead of
/// wedging the send path.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A framed TCP client connected to the relay.
pub struct Client {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    buf: Vec<u8>,
    read_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
}

impl Client {
    /// Connect to the relay at `addr`.
    pub async fn connect(addr: std::net::SocketAddr) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        // Disable Nagle: framed messages are length-prefixed and
        // self-delimiting, so there is no benefit to coalescing small frames
        // (acks, single envelopes) and a ~40ms Nagle delay hurts latency on
        // chatty 1:1 conversations.
        let _ = stream.set_nodelay(true);
        // Enable OS TCP keepalive as a backstop liveness probe. A subscribed
        // connection may idle for hours between pushes; without keepalive the
        // OS never probes a quiet socket, so a NAT/firewall that silently
        // dropped the path (no FIN, no RST) leaves the socket looking idle
        // forever — `recv_msg` blocks indefinitely and the client never
        // reconnects to recover offline mail. Keepalive makes the kernel probe
        // after an idle window and surface a dead path as an EOF/error that the
        // caller's reconnect logic handles. This complements (does not replace)
        // the application-level `Ping`/`Pong` heartbeat, which detects dead
        // links on platforms/configs where keepalive is unavailable or tuned
        // conservatively. Best-effort: a failure to set the option (unsupported
        // platform, permission) is ignored — the heartbeat still guards the
        // connection.
        enable_tcp_keepalive(&stream);
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(r),
            writer: w,
            buf: Vec::new(),
            read_timeout: READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
        })
    }

    /// Override the bounded-read deadline (used by [`recv_msg_timeout`]).
    /// Production callers leave the default; tests shrink it to keep the
    /// "hung relay" case fast.
    pub fn set_read_timeout(&mut self, d: std::time::Duration) {
        self.read_timeout = d;
    }

    /// Override the bounded-write deadline (used by [`send_msg`]).
    pub fn set_write_timeout(&mut self, d: std::time::Duration) {
        self.write_timeout = d;
    }

    /// Send one client message (framed).
    pub async fn send_msg(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        let frame = encode(msg)?;
        write_frame(&mut self.writer, &frame, self.write_timeout).await?;
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
    ///
    /// This is the **unbounded** receive — it blocks indefinitely waiting for
    /// the next frame, which is correct for a long-lived subscribed
    /// connection (the GUI bridge's recv loop may idle for hours between
    /// pushes). For request/response handshakes where a hung relay must be
    /// detected in bounded time, use [`Client::recv_msg_timeout`].
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

    /// Like [`Client::recv_msg`] but bounded by the configured read deadline
    /// (default [`READ_TIMEOUT`]). Use this for request/response handshakes
    /// (Register, Subscribe drain, FetchBundle) where the client expects a
    /// prompt reply: a relay that accepts the connection but stops responding
    /// — or drip-feeds one byte per minute — surfaces [`ClientError::Timeout`]
    /// instead of hanging the handshake forever. Do NOT use this for the
    /// long-lived subscribed recv loop.
    pub async fn recv_msg_timeout(&mut self) -> Result<Option<ServerMessage>, ClientError> {
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
            let n =
                match tokio::time::timeout(self.read_timeout, self.reader.read(&mut chunk)).await {
                    Ok(r) => r?,
                    Err(_) => return Err(ClientError::Timeout),
                };
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Split this client into a reader and a writer that can be moved to
    /// separate tasks (the GUI bridge runs a recv-loop and a command loop
    /// concurrently). The reader owns the read half + framing buffer; the
    /// writer owns the write half. Both are `Send`. The configured read/write
    /// deadlines are carried into the halves.
    pub fn into_split(self) -> (ClientReader, ClientWriter) {
        let Self {
            reader,
            writer,
            buf,
            read_timeout,
            write_timeout,
        } = self;
        (
            ClientReader {
                reader,
                buf,
                read_timeout,
            },
            ClientWriter {
                writer,
                write_timeout,
            },
        )
    }
}

/// The read half of a split [`Client`]. Owns the framed read buffer.
pub struct ClientReader {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: Vec<u8>,
    read_timeout: std::time::Duration,
}

impl ClientReader {
    /// Receive one server message. Returns `None` on EOF.
    ///
    /// Same fatal-error handling as [`Client::recv_msg`]: `Incomplete` waits
    /// for more bytes, any other decode error is surfaced rather than looping
    /// forever on a corrupt frame. This is the **unbounded** receive used by
    /// the GUI bridge's long-lived subscribed recv loop (which may idle for
    /// hours between pushes); for bounded handshakes use
    /// [`ClientReader::recv_msg_timeout`].
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

    /// Like [`ClientReader::recv_msg`] but bounded by the configured read
    /// deadline (default [`READ_TIMEOUT`]) for request/response handshakes.
    /// See [`Client::recv_msg_timeout`].
    pub async fn recv_msg_timeout(&mut self) -> Result<Option<ServerMessage>, ClientError> {
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
            let n =
                match tokio::time::timeout(self.read_timeout, self.reader.read(&mut chunk)).await {
                    Ok(r) => r?,
                    Err(_) => return Err(ClientError::Timeout),
                };
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
    write_timeout: std::time::Duration,
}

impl ClientWriter {
    /// Send one client message (framed), bounded by the configured write
    /// deadline (default [`WRITE_TIMEOUT`]).
    pub async fn send_msg(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        let frame = encode(msg)?;
        write_frame(&mut self.writer, &frame, self.write_timeout).await?;
        Ok(())
    }
}

/// Write a full frame with a `write_timeout` deadline. Maps an elapsed
/// deadline to [`ClientError::Timeout`] (so the caller distinguishes a hung
/// peer from an ordinary I/O error and can trigger reconnect logic).
async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &[u8],
    write_timeout: std::time::Duration,
) -> Result<(), ClientError> {
    match tokio::time::timeout(write_timeout, writer.write_all(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ClientError::Io(e)),
        Err(_) => Err(ClientError::Timeout),
    }
}

/// Idle time before the kernel starts sending TCP keepalive probes on a quiet
/// socket. Tuned to detect a silently-dropped NAT/firewall path well within a
/// typical session: a subscribed connection that has gone quiet for this long
/// is either legitimately idle (the probe is cheap and ignored by a live peer)
/// or dead (the probe fails and the OS surfaces an error). Sub-second
/// precision is dropped on platforms that round to seconds.
const TCP_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// Interval between keepalive probes once probing starts, and the number of
/// failed probes before the OS declares the connection dead. Together with
/// [`TCP_KEEPALIVE_IDLE`] this bounds detection of a half-open path to roughly
/// idle + interval × retries. Only applied on platforms whose `socket2` build
/// exposes the interval/retries knobs; on others the idle-only keepalive still
/// runs (the OS defaults take over for the probe cadence).
const TCP_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 4;

/// Enable TCP keepalive on `stream` (best-effort). Borrows the socket via
/// `socket2::SockRef` so the tokio `TcpStream` stays owned. On platforms where
/// `socket2` exposes `set_tcp_keepalive` (Linux, macOS, Windows, the BSDs,
/// etc.) the full idle/interval/retries profile is applied; everywhere else
/// the bare `SO_KEEPALIVE` flag is enabled so the OS at least probes with its
/// defaults. Any error is ignored — keepalive is a backstop, not a guarantee,
/// and the application-level heartbeat still guards the connection.
fn enable_tcp_keepalive(stream: &TcpStream) {
    // Platforms with a full keepalive profile via `socket2` `set_tcp_keepalive`.
    // The `all` feature on our `socket2` dependency unlocks the interval/retries
    // builders; the call itself is only available on these targets.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
    ))]
    {
        use socket2::{SockRef, TcpKeepalive};
        let ka = TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_IDLE)
            .with_interval(TCP_KEEPALIVE_INTERVAL)
            .with_retries(TCP_KEEPALIVE_RETRIES);
        let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
    }
    // Fallback: platforms without the full profile still get the bare
    // `SO_KEEPALIVE` flag so the OS probes with its default cadence.
    #[cfg(not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
    )))]
    {
        use socket2::SockRef;
        let _ = SockRef::from(stream).set_keepalive(true);
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

    /// A raw peer that accepts the connection but never writes anything — a
    /// hung/slowloris relay. Keeps the connection open so the client sees no
    /// EOF, only silence.
    async fn raw_peer_silent() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            // Hold the connection open forever without writing.
            std::future::pending::<()>().await;
        });
        addr
    }

    /// `recv_msg_timeout` must surface `ClientError::Timeout` when the relay
    /// accepts the connection but never replies — instead of hanging the
    /// handshake forever. Uses a short deadline so the test is fast.
    #[tokio::test]
    async fn recv_msg_timeout_surfaces_timeout_for_silent_relay() {
        let addr = raw_peer_silent().await;
        let mut client = Client::connect(addr).await.expect("connect");
        client.set_read_timeout(std::time::Duration::from_millis(150));
        let result = client.recv_msg_timeout().await;
        assert!(
            matches!(result, Err(ClientError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    /// The unbounded `recv_msg` does NOT time out on a silent relay (it is
    /// meant for the long-lived subscribed loop). We can't assert "blocks
    /// forever" in a test, but we CAN assert that a short deadline on the
    /// *timeout* variant fires while the plain variant would keep waiting —
    /// covered by the test above. Here we verify the split reader's timeout
    /// variant also fires.
    #[tokio::test]
    async fn client_reader_recv_msg_timeout_surfaces_timeout() {
        let addr = raw_peer_silent().await;
        let mut client = Client::connect(addr).await.expect("connect");
        client.set_read_timeout(std::time::Duration::from_millis(150));
        let (mut reader, _writer) = client.into_split();
        let result = reader.recv_msg_timeout().await;
        assert!(
            matches!(result, Err(ClientError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    /// `send_msg` must surface `ClientError::Timeout` when the relay stops
    /// draining its socket (TCP backpressure stalls `write_all`). We fill the
    /// kernel send buffer by writing large payloads to a peer that never
    /// reads; once the buffer saturates the bounded write times out.
    #[tokio::test]
    async fn send_msg_times_out_when_relay_stops_draining() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            // Never read — the client's writes back up against the kernel
            // send buffer until write_all blocks.
            std::future::pending::<()>().await;
        });
        let mut client = Client::connect(addr).await.expect("connect");
        client.set_write_timeout(std::time::Duration::from_millis(200));
        // A large envelope so each frame is ~256 KiB; a few of these saturate
        // the kernel send buffer (typically a few MiB) against a non-reading
        // peer. Each send_msg is bounded, so the first call that cannot
        // complete within the deadline returns Timeout.
        let big = ClientMessage::Send {
            recipients: vec![[0u8; 32]],
            envelope: um_protocol::EncryptedEnvelope {
                id: 0,
                sender: [0u8; 32],
                kind: um_protocol::MessageKind::Direct,
                header: vec![],
                init: None,
                ciphertext: vec![0xAB; 256 * 1024],
                signature: vec![],
            },
        };
        let mut got_timeout = false;
        for _ in 0..256 {
            if matches!(client.send_msg(&big).await, Err(ClientError::Timeout)) {
                got_timeout = true;
                break;
            }
        }
        assert!(
            got_timeout,
            "expected a write to time out against a non-draining relay"
        );
    }

    /// `Client::connect` enables TCP keepalive on its socket. We cannot
    /// observe the kernel probing within a unit test, but we can assert the
    /// `SO_KEEPALIVE` option is set on the connected socket — the precondition
    /// for the OS to probe a quiet, half-open path instead of leaving it
    /// looking idle forever. The probe cadence (idle/interval/retries) is
    /// platform-dependent and not asserted here.
    #[tokio::test]
    async fn connect_enables_tcp_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        // Accept the connection so `connect` completes; we do not need to read.
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });
        let client = Client::connect(addr).await.expect("connect");
        // Re-borrow the underlying socket via socket2 to read SO_KEEPALIVE. The
        // client owns the split halves; `OwnedWriteHalf: AsRef<TcpStream>` and
        // `TcpStream: AsFd`, so `SockRef::from` can borrow through the writer.
        use socket2::SockRef;
        let sock_ref = SockRef::from(client.writer.as_ref());
        let keepalive = sock_ref
            .keepalive()
            .expect("SO_KEEPALIVE is readable on a connected TCP socket");
        assert!(
            keepalive,
            "Client::connect must enable TCP keepalive so a half-open subscribed connection is detected by the OS instead of hanging forever"
        );
    }
}
