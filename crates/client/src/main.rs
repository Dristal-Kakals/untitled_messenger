//! um-client — headless CLI binary entrypoint for the UM client.
//!
//! Drives the full E2EE stack over a real TCP relay: generates an ephemeral
//! identity, registers its prekey bundle, subscribes for push, and runs an
//! interactive REPL that can add contacts (by hex identity pub), start X3DH
//! sessions on first send, exchange 1:1 Double Ratchet messages, and print
//! incoming decrypted messages as they are pushed.
//!
//! This is the headless counterpart to `um_server`'s `um_server` binary. It
//! depends only on the existing `um_client` library + `um_protocol`; no GUI
//! dependencies. Identity, ratchet state, and contacts are ephemeral for the
//! process lifetime (persisting them to the encrypted store is GUI-bridge
//! work; see `docs/superpowers/specs/2026-07-01-messenger-gui-design.md`).
//!
//! Usage:
//!   um_client [--server <addr>]        # addr defaults to $UM_SERVER_ADDR
//!                                        then 127.0.0.1:7000
//!
//! REPL commands:
//!   /help                 show commands
//!   /whoami               print this client's identity pub (hex)
//!   /add <hex> <nick>     record a contact by 32-byte hex identity pub
//!   /contacts             list recorded contacts
//!   /msg <hex> <text>     send to a contact (starts a session on first send)
//!   /quit                 exit
//!
//! No `unsafe`, no panics in non-test code; all fallible paths are reported.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, BufReader};
use um_client::net::Client;
use um_client::session::ClientSession;
use um_client::ClientError;
use um_protocol::{ClientMessage, EncryptedEnvelope, ServerMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = server_addr();
    run(addr).await
}

/// Resolve the relay address from `--server`, then `$UM_SERVER_ADDR`, then the
/// `127.0.0.1:7000` default (matching `um_server`'s default).
fn server_addr() -> SocketAddr {
    server_addr_from(
        std::env::args().skip(1),
        std::env::var("UM_SERVER_ADDR").ok(),
    )
}

/// Pure, testable core of [`server_addr`]: takes the arg iterator and the env
/// override explicitly so unit tests can drive both fallback paths.
fn server_addr_from(args: impl Iterator<Item = String>, env: Option<String>) -> SocketAddr {
    let mut args = args;
    while let Some(a) = args.next() {
        if a == "--server" {
            if let Some(v) = args.next() {
                if let Ok(parsed) = v.parse() {
                    return parsed;
                }
            }
        }
    }
    env.and_then(|v| v.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 7000)))
}

/// Top-level run loop: generate identity, register + subscribe, then `select!`
/// over stdin lines and incoming server frames so sends and receives interleave
/// without a background task or shared mutable state.
async fn run(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut session = ClientSession::generate(10);
    let me = session.identity_pub();
    eprintln!("um-client: identity pub = {}", hex_encode(&me));
    eprintln!("connecting to {addr} ...");

    let mut client = Client::connect(addr).await?;

    // Register our prekey bundle, then subscribe for push delivery.
    client
        .send_msg(&ClientMessage::Register {
            bundle: session.registration_bundle(),
        })
        .await?;
    drain_until_ack(&mut client).await?;
    client.send_msg(&ClientMessage::Subscribe).await?;
    // The Subscribe handshake does NOT discard `Delivered`: the server flushes
    // the unacked outbox as `Delivered` *before* the Subscribe `AckOk`, so
    // those frames are mail that arrived while we were offline. Decrypt + ack
    // them inline so a reconnect recovers them instead of dropping them.
    subscribe_until_ack(&mut client, &mut session).await?;
    eprintln!("registered + subscribed. type /help for commands.");

    let mut contacts: HashMap<[u8; 32], String> = HashMap::new();
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        tokio::select! {
            n = reader.read_line(&mut line_buf) => {
                match n? {
                    0 => break, // EOF
                    _ => {
                        match handle_line(line_buf.trim(), &mut session, &mut client, &mut contacts).await {
                            Ok(Action::Continue) => {}
                            Ok(Action::Quit) => break,
                            Err(e) => eprintln!("error: {e}"),
                        }
                    }
                }
            }
            msg = client.recv_msg() => {
                match msg? {
                    Some(ServerMessage::Delivered(envs)) => {
                        let mut ack_ids = Vec::new();
                        for env in envs {
                            if handle_incoming(&env, &mut session) {
                                ack_ids.push(env.id);
                            }
                        }
                        // Ack decrypted envelopes so the server drops them
                        // from the outbox and does not re-flush them as
                        // duplicates on the next reconnect (a repeated
                        // ratchet message number fails to decrypt).
                        if !ack_ids.is_empty() {
                            let _ = client
                                .send_msg(&ClientMessage::Ack {
                                    envelope_ids: ack_ids,
                                })
                                .await;
                        }
                    }
                    Some(ServerMessage::AckOk) => {}
                    Some(ServerMessage::Bundle(_)) => {
                        // A stray bundle reply outside of /msg (e.g. a late
                        // FetchBundle answer). Nothing to do with it here.
                    }
                    Some(ServerMessage::Error(e)) => eprintln!("server error: {e:?}"),
                    None => {
                        eprintln!("server disconnected");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// What a REPL line should do next.
enum Action {
    Continue,
    Quit,
}

/// Parse and dispatch one REPL line.
async fn handle_line(
    line: &str,
    session: &mut ClientSession,
    client: &mut Client,
    contacts: &mut HashMap<[u8; 32], String>,
) -> Result<Action, ClientError> {
    let (cmd, rest) = match line.split_once(char::is_whitespace) {
        Some((c, r)) => (c, r.trim()),
        None => (line, ""),
    };
    match cmd {
        "" => Ok(Action::Continue),
        "/quit" | "/exit" => Ok(Action::Quit),
        "/help" => {
            print_help();
            Ok(Action::Continue)
        }
        "/whoami" => {
            eprintln!("{}", hex_encode(&session.identity_pub()));
            Ok(Action::Continue)
        }
        "/contacts" => {
            if contacts.is_empty() {
                eprintln!("(no contacts)");
            }
            for (pub_, nick) in contacts {
                eprintln!("{}  {}", hex_encode(pub_), nick);
            }
            Ok(Action::Continue)
        }
        "/add" => {
            let (hex, nick) = split_two(rest)?;
            let pub_ = parse_pub(&hex)?;
            contacts.insert(pub_, nick.clone());
            eprintln!("added contact {nick}: {}", hex_encode(&pub_));
            Ok(Action::Continue)
        }
        "/msg" => {
            let (hex, text) = split_two(rest)?;
            let peer = parse_pub(&hex)?;
            send_message(session, client, &peer, text.as_bytes()).await?;
            Ok(Action::Continue)
        }
        other => {
            eprintln!("unknown command: {other} (try /help)");
            Ok(Action::Continue)
        }
    }
}

/// Send a 1:1 message to `peer`. If no ratchet session exists yet, fetch the
/// peer's bundle and run X3DH (`start_session`) so the first message carries
/// the init. Any envelopes the server pushes while we wait for the bundle are
/// decrypted and printed inline (the single-task `select!` model means there
/// is no separate recv loop during this call).
async fn send_message(
    session: &mut ClientSession,
    client: &mut Client,
    peer: &[u8; 32],
    text: &[u8],
) -> Result<(), ClientError> {
    let envelope = match session.send(peer, text) {
        Ok(env) => env,
        Err(ClientError::NoSession) => {
            client
                .send_msg(&ClientMessage::FetchBundle { target: *peer })
                .await?;
            let bundle = loop {
                match client.recv_msg().await? {
                    Some(ServerMessage::Bundle(b)) => break b,
                    Some(ServerMessage::Delivered(envs)) => {
                        let mut ack_ids = Vec::new();
                        for env in envs {
                            if handle_incoming(&env, session) {
                                ack_ids.push(env.id);
                            }
                        }
                        if !ack_ids.is_empty() {
                            let _ = client
                                .send_msg(&ClientMessage::Ack {
                                    envelope_ids: ack_ids,
                                })
                                .await;
                        }
                    }
                    Some(ServerMessage::AckOk) => {}
                    Some(ServerMessage::Error(e)) => {
                        return Err(ClientError::Store(format!("server: {e:?}")));
                    }
                    None => return Err(ClientError::NotConnected),
                }
            };
            let bundle = bundle.ok_or_else(|| ClientError::Store("peer not registered".into()))?;
            session.start_session(&bundle, text)?
        }
        Err(e) => return Err(e),
    };
    client
        .send_msg(&ClientMessage::Send {
            recipients: vec![*peer],
            envelope,
        })
        .await?;
    eprintln!("sent.");
    Ok(())
}

/// Decrypt and print one incoming envelope. Returns `true` if it decrypted
/// successfully (so the caller can ack it to the server). A decrypt failure
/// is logged and dropped (the relay may forward malformed or duplicate
/// traffic); it never panics and returns `false` so the envelope is not
/// acked (it stays in the outbox and may be re-flushed, which is harmless
/// because it will keep failing to decrypt).
fn handle_incoming(env: &EncryptedEnvelope, session: &mut ClientSession) -> bool {
    match session.receive(env) {
        Ok((plaintext, sender)) => {
            let text = String::from_utf8_lossy(&plaintext);
            eprintln!("<- {}: {}", hex_encode(&sender), text);
            true
        }
        Err(e) => {
            eprintln!("<- failed to decrypt from {}: {e}", hex_encode(&env.sender));
            false
        }
    }
}

/// Consume server frames until an `AckOk` arrives. Used for the Register
/// handshake only — the server does not flush the outbox on Register, so
/// only the `AckOk` is expected. Any stray `Delivered` (none in practice)
/// is discarded.
async fn drain_until_ack(client: &mut Client) -> Result<(), ClientError> {
    loop {
        match client.recv_msg().await? {
            Some(ServerMessage::AckOk) => return Ok(()),
            Some(ServerMessage::Delivered(envs)) => {
                eprintln!(
                    "(discarded {} early envelope(s) during register)",
                    envs.len()
                );
            }
            Some(ServerMessage::Error(e)) => {
                return Err(ClientError::Store(format!("server: {e:?}")));
            }
            Some(_) => {}
            None => return Err(ClientError::NotConnected),
        }
    }
}

/// Subscribe handshake: read frames until the Subscribe `AckOk`, decrypting
/// and acking every `Delivered` batch inline. The server flushes the unacked
/// outbox as `Delivered` *before* the `AckOk`, so this recovers mail that
/// arrived while we were offline instead of dropping it. Each recovered
/// envelope is acked so it is not re-flushed on the next reconnect.
async fn subscribe_until_ack(
    client: &mut Client,
    session: &mut ClientSession,
) -> Result<(), ClientError> {
    loop {
        match client.recv_msg().await? {
            Some(ServerMessage::AckOk) => return Ok(()),
            Some(ServerMessage::Delivered(envs)) => {
                let mut ack_ids = Vec::new();
                for env in envs {
                    if handle_incoming(&env, session) {
                        ack_ids.push(env.id);
                    }
                }
                if !ack_ids.is_empty() {
                    client
                        .send_msg(&ClientMessage::Ack {
                            envelope_ids: ack_ids,
                        })
                        .await?;
                }
            }
            Some(ServerMessage::Error(e)) => {
                return Err(ClientError::Store(format!("server: {e:?}")));
            }
            Some(_) => {}
            None => return Err(ClientError::NotConnected),
        }
    }
}

/// Print the REPL command list.
fn print_help() {
    eprintln!("commands:");
    eprintln!("  /help                 show commands");
    eprintln!("  /whoami               print this client's identity pub (hex)");
    eprintln!("  /add <hex> <nick>     record a contact by 32-byte hex identity pub");
    eprintln!("  /contacts             list recorded contacts");
    eprintln!("  /msg <hex> <text>     send to a contact (starts a session on first send)");
    eprintln!("  /quit                 exit");
}

/// Split `s` into `(first, rest)` on the first run of whitespace. `rest`
/// preserves internal whitespace (so message text may contain spaces).
fn split_two(s: &str) -> Result<(String, String), ClientError> {
    let s = s.trim();
    let (a, b) = s
        .split_once(char::is_whitespace)
        .ok_or_else(|| ClientError::Store("expected <arg> <value>".into()))?;
    Ok((a.trim().to_string(), b.trim().to_string()))
}

/// Parse a 64-char hex string into a 32-byte identity pub.
fn parse_pub(s: &str) -> Result<[u8; 32], ClientError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(ClientError::Store(
            "expected 64 hex chars (32 bytes)".into(),
        ));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

/// Decode one hex character to its nibble value.
fn hex_nibble(b: u8) -> Result<u8, ClientError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ClientError::Store("bad hex digit".into())),
    }
}

/// Render bytes as lowercase hex. Local helper to avoid adding a `hex` crate
/// dependency for the binary (matches the approach in `store.rs` tests).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trips_32_bytes() {
        let v = [0xAB; 32];
        let s = hex_encode(&v);
        assert_eq!(s.len(), 64);
        assert_eq!(parse_pub(&s).unwrap(), v);
    }

    #[test]
    fn parse_pub_accepts_mixed_case() {
        let s = "DeAdBeEf".to_string() + &"00".repeat(28);
        let got = parse_pub(&s).unwrap();
        assert_eq!(got[0], 0xDE);
        assert_eq!(got[1], 0xAD);
        assert_eq!(got[2], 0xBE);
        assert_eq!(got[3], 0xEF);
    }

    #[test]
    fn parse_pub_rejects_short_input() {
        assert!(parse_pub("ab").is_err());
    }

    #[test]
    fn parse_pub_rejects_bad_digit() {
        let bad = "zz".to_string() + &"00".repeat(31);
        assert!(parse_pub(&bad).is_err());
    }

    #[test]
    fn split_two_preserves_internal_whitespace() {
        let (a, b) = split_two("deadbeef  hello world").unwrap();
        assert_eq!(a, "deadbeef");
        assert_eq!(b, "hello world");
    }

    #[test]
    fn split_two_missing_value_errors() {
        assert!(split_two("onlyone").is_err());
        assert!(split_two("   ").is_err());
    }

    #[test]
    fn server_addr_from_flag_wins_over_env() {
        let args = ["--server".to_string(), "1.2.3.4:99".to_string()].into_iter();
        let env = Some("5.6.7.8:1".to_string());
        assert_eq!(
            server_addr_from(args, env),
            "1.2.3.4:99".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn server_addr_from_env_when_no_flag() {
        let env = Some("9.9.9.9:1".to_string());
        assert_eq!(
            server_addr_from(std::iter::empty(), env),
            "9.9.9.9:1".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn server_addr_from_default_when_nothing_given() {
        assert_eq!(
            server_addr_from(std::iter::empty(), None),
            SocketAddr::from(([127, 0, 0, 1], 7000))
        );
    }

    #[test]
    fn server_addr_from_ignores_unknown_flag() {
        let args = ["--verbose".to_string(), "1.2.3.4:99".to_string()].into_iter();
        assert_eq!(
            server_addr_from(args, None),
            SocketAddr::from(([127, 0, 0, 1], 7000))
        );
    }
}
