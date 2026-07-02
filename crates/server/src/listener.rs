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
use tokio::sync::mpsc;
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};

use crate::handler::handle;
use crate::{Store, Subscribers};

/// Serve the relay on `addr` until the task is cancelled. Returns the bound
/// address (useful for ephemeral-port tests).
pub async fn serve(
    addr: &str,
    store: Arc<Store>,
    subs: Arc<Subscribers>,
) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let store = store.clone();
            let subs = subs.clone();
            tokio::spawn(handle_conn(stream, store, subs));
        }
    });
    Ok(local)
}

/// Handle one connection to completion.
async fn handle_conn(stream: TcpStream, store: Arc<Store>, subs: Arc<Subscribers>) {
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
                            let frame = match encode(&server_msg) {
                                Ok(f) => f,
                                Err(_) => break,
                            };
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                            // Continue the loop; do not also read this iteration.
                            continue;
                        }
                        None => break, // sender dropped -> close
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
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
            // Not-subscribed mode: just read.
            let mut chunk = [0u8; 4096];
            match reader.read(&mut chunk).await {
                Ok(0) => break, // EOF
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
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
                    send_error(&mut writer, um_protocol::ServerError::TooLarge).await;
                    return;
                }
                Err(_) => {
                    // A complete-length frame that failed to deserialize
                    // (postcard decode error). The bytes were frame-aligned, so
                    // we *could* drain and continue, but a malformed frame
                    // indicates a protocol/version mismatch; per the spec we
                    // surface the error and close the connection.
                    send_error(&mut writer, um_protocol::ServerError::MalformedFrame).await;
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
                        let _ = writer.write_all(&frame).await;
                    }
                    return;
                }
            };

            // Subscribe is handled here (not in `handle`): create the push
            // channel, register it (evicting any prior subscriber for this
            // identity), flush the unacked outbox in batches of 64, then
            // reply AckOk.
            if let ClientMessage::Subscribe = msg {
                let (tx, rx) = mpsc::channel(256);
                let _evicted = subs.register(id, tx.clone());
                push_tx = Some(tx);
                push_rx = Some(rx);
                // Flush unacked outbox (poll since 0) as Delivered frames.
                let pending = store.poll(&id, 0);
                for chunk in pending.chunks(64) {
                    let frame = match encode(&ServerMessage::Delivered(chunk.to_vec())) {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if writer.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                // Reply AckOk (mode accepted).
                let ack = match encode(&ServerMessage::AckOk) {
                    Ok(f) => f,
                    Err(_) => return,
                };
                if writer.write_all(&ack).await.is_err() {
                    return;
                }
                continue;
            }

            let reply = handle(&store, &subs, &id, msg);
            match encode(&reply) {
                Ok(frame) => {
                    if writer.write_all(&frame).await.is_err() {
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

/// Best-effort write of a single `ServerError` frame, then the caller closes
/// the connection. A write failure is ignored — the connection is being torn
/// down regardless, and the error frame is advisory (the client observes it if
/// it can, EOF otherwise).
async fn send_error(writer: &mut tokio::net::tcp::OwnedWriteHalf, err: um_protocol::ServerError) {
    if let Ok(frame) = encode(&ServerMessage::Error(err)) {
        let _ = writer.write_all(&frame).await;
    }
}
