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
use um_protocol::framing::{decode, encode};
use um_protocol::{ClientMessage, ServerMessage};

use crate::handler::handle;
use crate::Store;

/// Serve the relay on `addr` until the task is cancelled. Returns the bound
/// address (useful for ephemeral-port tests).
pub async fn serve(addr: &str, store: Arc<Store>) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let store = store.clone();
            tokio::spawn(handle_conn(stream, store));
        }
    });
    Ok(local)
}

/// Handle one connection to completion.
async fn handle_conn(stream: TcpStream, store: Arc<Store>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    // The connection is unauthenticated until the first `Register` arrives.
    let mut self_id: Option<[u8; 32]> = None;

    loop {
        // Read more bytes into the buffer.
        let mut chunk = [0u8; 4096];
        match reader.read(&mut chunk).await {
            Ok(0) => break, // EOF
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }

        // Decode as many full frames as are present.
        loop {
            let (msg, consumed): (ClientMessage, usize) = match decode(&buf) {
                Ok((msg, consumed)) => (msg, consumed),
                Err(um_protocol::ProtocolError::Incomplete) => break, // need more bytes
                Err(_) => {
                    // Malformed frame: close the connection.
                    return;
                }
            };
            buf.drain(0..consumed);

            // First frame must be Register; it binds the connection.
            let id = match (&msg, self_id) {
                (ClientMessage::Register { ref bundle }, _) => {
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

            let reply = handle(&store, &id, msg);
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
}
