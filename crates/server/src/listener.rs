//! TCP listener: accept loop, per-connection framed read/write.
//!
//! Each connection reads `ClientMessage` frames, dispatches via `handler`,
//! and writes `ServerMessage` frames back. The first frame on a connection
//! MUST be `Register`, which binds the connection to that identity pub;
//! subsequent frames (`Send`/`Poll`/`Ack`/`Subscribe`/`FetchBundle`) are
//! handled on behalf of that identity. A malformed frame closes the
//! connection (per the spec).

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};

use crate::handler::handle;
use crate::{Store, Subscribers};

/// Maximum number of concurrent connections the relay will service. Each
/// extra connection holds a task + its read/write buffers; an unbounded
/// accept loop lets a connection-flood attacker exhaust memory. Acquiring a
/// permit before `handle_conn` caps live tasks at this many; a flood queues
/// on the semaphore (backpressure) instead of spawning unbounded tasks.
const MAX_CONNECTIONS: usize = 4096;

/// Read timeout during the pre-auth (not-yet-subscribed) phase. A client that
/// opens a connection and sends nothing — a slowloris — holds the task and
/// its buffers forever without this. Once a connection `Subscribe`s it is
/// long-lived by design (it may idle for hours waiting for pushes), so the
/// timeout is NOT applied to the subscribed `select!` read branch.
const PREAUTH_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Write timeout for every frame write. A client that stops draining its
/// socket stalls `write_all` via TCP backpressure; bounding it drops the
/// connection instead of letting one slow peer wedge a push branch of the
/// `select!` (which would also stall socket reads for that connection).
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Tunable limits for [`serve_with`]. Production uses [`ServeConfig::default`]
/// (the constants above); tests shrink the timeouts and connection cap so the
/// slowloris / connection-flood cases run in milliseconds instead of minutes.
#[derive(Clone, Copy)]
pub struct ServeConfig {
    /// Max concurrent connections (semaphore permits).
    pub max_connections: usize,
    /// Pre-auth idle read timeout (slowloris guard).
    pub preauth_read_timeout: std::time::Duration,
    /// Per-frame write timeout (backpressure guard).
    pub write_timeout: std::time::Duration,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            preauth_read_timeout: PREAUTH_READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
        }
    }
}

/// Serve the relay on `addr` until the task is cancelled. Returns the bound
/// address (useful for ephemeral-port tests). Uses production defaults for
/// all limits; see [`serve_with`] to override them (e.g. in tests).
pub async fn serve(
    addr: &str,
    store: Arc<Store>,
    subs: Arc<Subscribers>,
) -> std::io::Result<std::net::SocketAddr> {
    serve_with(addr, store, subs, ServeConfig::default()).await
}

/// Like [`serve`] but with caller-supplied [`ServeConfig`]. Used by tests to
/// shrink the slowloris / write timeouts and the connection cap so resource-
/// exhaustion cases are fast and deterministic.
pub async fn serve_with(
    addr: &str,
    store: Arc<Store>,
    subs: Arc<Subscribers>,
    cfg: ServeConfig,
) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    // Per-process connection cap. Cloned per accept (cheap — it's an
    // `Arc<Semaphore>`); `acquire_owned` returns a guard that releases on
    // drop, so a connection task ending frees its permit for the next
    // accept.
    let conn_limit = Arc::new(Semaphore::new(cfg.max_connections));
    let preauth_read_timeout = cfg.preauth_read_timeout;
    let write_timeout = cfg.write_timeout;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            // Backpressure: if max_connections are live, wait for one to
            // finish before accepting more. `acquire_owned` moves the guard
            // into the task so it is released when the task ends.
            let permit = match conn_limit.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue, // semaphore closed (server shutting down)
            };
            let store = store.clone();
            let subs = subs.clone();
            tokio::spawn(handle_conn(
                stream,
                store,
                subs,
                permit,
                preauth_read_timeout,
                write_timeout,
            ));
        }
    });
    Ok(local)
}

/// Handle one connection to completion. `_permit` is the connection-cap
/// guard; dropping it (when this function returns) frees a slot for the next
/// accept. `preauth_read_timeout` bounds idle reads before the first frame
/// (slowloris guard); `write_timeout` bounds every frame write (backpressure
/// guard).
async fn handle_conn(
    stream: TcpStream,
    store: Arc<Store>,
    subs: Arc<Subscribers>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    preauth_read_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
) {
    // Reduce per-frame latency for small framed messages (acks, single
    // envelopes) that would otherwise be Nagle-delayed up to ~40ms.
    let _ = stream.set_nodelay(true);
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    // The connection is unauthenticated until the first `Register` arrives.
    let mut self_id: Option<[u8; 32]> = None;
    // Push channel: None until Subscribe. When Some, the loop select!s
    // between socket reads and push recv.
    let mut push_rx: Option<mpsc::Receiver<ServerMessage>> = None;
    // The connection's own sender clone, kept for match-based cleanup so an
    // evicted older connection does not remove a newer subscriber.
    let mut push_tx: Option<mpsc::Sender<ServerMessage>> = None;

    loop {
        // Read more bytes into the buffer, unless we are racing push recv.
        if let (Some(rx), Some(tx)) = (&mut push_rx, push_tx.as_ref()) {
            // Subscribed mode: race a socket read against a push recv and a
            // periodic eviction check. The eviction check closes this
            // connection if a newer Subscribe for the same identity replaced
            // our entry in the registry (last-Subscribe-wins).
            //
            // No read timeout here: a subscribed connection may legitimately
            // idle for hours waiting for a push. A slow client is bounded by
            // the write timeout on push frames instead.
            let mut chunk = [0u8; 4096];
            tokio::select! {
                read = reader.read(&mut chunk) => {
                    match read {
                        Ok(0) => break, // EOF
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                msg = rx.recv() => {
                    match msg {
                        Some(server_msg) => {
                            let Ok(frame) = encode(&server_msg) else {
                                break;
                            };
                            if !write_frame(&mut writer, &frame, write_timeout).await {
                                break;
                            }
                            // Continue the loop; do not also read this iteration.
                            continue;
                        }
                        None => break, // sender dropped -> close
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    // Eviction check: if the registry no longer holds our
                    // channel, a newer Subscribe evicted us. Drop our sender
                    // clone and close.
                    let id = self_id.expect("subscribed implies authenticated");
                    let still_ours = subs
                        .get(&id)
                        .is_some_and(|s| s.same_channel(tx));
                    if !still_ours {
                        break;
                    }
                    // Still ours: loop and race again (re-reads below).
                    continue;
                }
            }
        } else {
            // Not-subscribed mode: just read, with a slowloris timeout. A
            // client that connects but never sends a frame (or sends one
            // byte per minute) is dropped after `preauth_read_timeout` of
            // idle rather than holding the task forever.
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(preauth_read_timeout, reader.read(&mut chunk)).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break,
                Err(_) => break, // timed out waiting for bytes
            }
        }

        // Decode as many full frames as are present.
        loop {
            let (msg, consumed): (ClientMessage, usize) = match decode(&buf) {
                Ok((msg, consumed)) => (msg, consumed),
                Err(um_protocol::ProtocolError::Incomplete) => break, // need more bytes
                Err(um_protocol::ProtocolError::FrameTooLarge(_)) => {
                    // A frame whose length header exceeds MAX_FRAME_SIZE. Tell
                    // the client why before closing, so it can log a precise
                    // error instead of a bare EOF. Per the spec the connection
                    // is still closed — the oversized frame cannot be skipped
                    // because the length prefix is untrusted and the stream is
                    // no longer frame-aligned.
                    send_error(
                        &mut writer,
                        um_protocol::ServerError::TooLarge,
                        write_timeout,
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    // A complete-length frame that failed to deserialize
                    // (postcard decode error). The bytes were frame-aligned, so
                    // we *could* drain and continue, but a malformed frame
                    // indicates a protocol/version mismatch; per the spec we
                    // surface the error and close the connection.
                    send_error(
                        &mut writer,
                        um_protocol::ServerError::MalformedFrame,
                        write_timeout,
                    )
                    .await;
                    return;
                }
            };
            buf.drain(0..consumed);

            // First frame must be Register; it binds the connection.
            let id = match (&msg, self_id) {
                (ClientMessage::Register { bundle }, _) => {
                    let id = bundle.identity_pub;
                    self_id = Some(id);
                    id
                }
                (_, Some(id)) => id,
                (_, None) => {
                    // Non-Register before auth: reject and close.
                    let err = ServerMessage::Error(um_protocol::ServerError::NotRegistered);
                    if let Ok(frame) = encode(&err) {
                        let _ = write_frame(&mut writer, &frame, write_timeout).await;
                    }
                    return;
                }
            };

            // Subscribe is handled here (not in `handle`): create the push
            // channel, register it (evicting any prior subscriber for this
            // identity), flush the unacked outbox in batches of 64, then
            // reply AckOk.
            if msg == ClientMessage::Subscribe {
                let (tx, rx) = mpsc::channel(256);
                let _evicted = subs.register(id, tx.clone());
                push_tx = Some(tx);
                push_rx = Some(rx);
                // Flush unacked outbox (poll since 0) as Delivered frames.
                let pending = store.poll(&id, 0);
                for chunk in pending.chunks(64) {
                    let Ok(frame) = encode(&ServerMessage::Delivered(chunk.to_vec())) else {
                        return;
                    };
                    if !write_frame(&mut writer, &frame, write_timeout).await {
                        return;
                    }
                }
                // Reply AckOk (mode accepted).
                let Ok(ack) = encode(&ServerMessage::AckOk) else {
                    return;
                };
                if !write_frame(&mut writer, &ack, write_timeout).await {
                    return;
                }
                continue;
            }

            let reply = handle(&store, &subs, &id, msg);
            match encode(&reply) {
                Ok(frame) => {
                    if !write_frame(&mut writer, &frame, write_timeout).await {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    // Cleanup: remove our subscriber entry only if it is still ours.
    if let (Some(id), Some(tx)) = (self_id, push_tx.as_ref()) {
        subs.unregister_if_match(&id, tx);
    }
}

/// Write one framed message with a `write_timeout` deadline. Returns `false`
/// if the write timed out or errored, signaling the caller to close the
/// connection. A slow client that stops draining its socket would otherwise
/// stall `write_all` indefinitely via TCP backpressure.
async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &[u8],
    write_timeout: std::time::Duration,
) -> bool {
    match tokio::time::timeout(write_timeout, writer.write_all(frame)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

/// Best-effort write of a single `ServerError` frame, then the caller closes
/// the connection. A write failure is ignored — the connection is being torn
/// down regardless, and the error frame is advisory (the client observes it if
/// it can, EOF otherwise). Uses the same `write_timeout` as normal frames.
async fn send_error(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    err: um_protocol::ServerError,
    write_timeout: std::time::Duration,
) {
    if let Ok(frame) = encode(&ServerMessage::Error(err)) {
        let _ = write_frame(writer, &frame, write_timeout).await;
    }
}
