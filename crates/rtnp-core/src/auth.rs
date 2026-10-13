//! Shared-key mutual authentication for the control and log channels.
//!
//! The server sends a random nonce; the client proves knowledge of the key with
//! HMAC-SHA256 over the nonce, and the server answers with its own proof so the client
//! knows it is talking to a key holder too. This authenticates peers; it does **not**
//! encrypt traffic or protect against someone who can hijack an already-authenticated
//! connection. Use a VPN or SSH tunnel where that matters.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::control::{read_msg_max, write_msg};
use crate::error::{Error, Result};
use crate::util::{hex_decode, hex_encode};

type HmacSha256 = Hmac<Sha256>;

const CLIENT_LABEL: &[u8] = b"rtnp-v1 client";
const SERVER_LABEL: &[u8] = b"rtnp-v1 server";
/// Frames exchanged before a peer is trusted stay small.
const AUTH_FRAME_MAX: usize = 4096;
const MAX_NONCE_LEN: usize = 64;

#[derive(Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case")]
enum AuthMsg {
    Challenge { nonce: String },
    Response { mac: String },
    Accepted { server_mac: String },
    Denied,
}

fn mac(key: &[u8], label: &[u8], nonce: &[u8]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(label);
    m.update(nonce);
    m
}

pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    key: &[u8],
) -> Result<()> {
    let nonce: [u8; 32] = rand::random();
    write_msg(
        s,
        &AuthMsg::Challenge {
            nonce: hex_encode(&nonce),
        },
    )
    .await?;
    let ok = match read_msg_max::<_, AuthMsg>(s, AUTH_FRAME_MAX).await? {
        Some(AuthMsg::Response { mac: m }) => {
            hex_decode(&m).is_some_and(|b| mac(key, CLIENT_LABEL, &nonce).verify_slice(&b).is_ok())
        }
        _ => false,
    };
    if !ok {
        let _ = write_msg(s, &AuthMsg::Denied).await;
        return Err(Error::Protocol("authentication failed".into()));
    }
    let proof = mac(key, SERVER_LABEL, &nonce).finalize().into_bytes();
    write_msg(
        s,
        &AuthMsg::Accepted {
            server_mac: hex_encode(&proof),
        },
    )
    .await
}

pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    key: &[u8],
) -> Result<()> {
    let nonce = match read_msg_max::<_, AuthMsg>(s, AUTH_FRAME_MAX).await? {
        Some(AuthMsg::Challenge { nonce }) => hex_decode(&nonce)
            .filter(|n| !n.is_empty() && n.len() <= MAX_NONCE_LEN)
            .ok_or_else(|| Error::Protocol("malformed authentication challenge".into()))?,
        _ => {
            return Err(Error::Protocol(
                "peer did not send an authentication challenge".into(),
            ));
        }
    };
    let response = mac(key, CLIENT_LABEL, &nonce).finalize().into_bytes();
    write_msg(
        s,
        &AuthMsg::Response {
            mac: hex_encode(&response),
        },
    )
    .await?;
    match read_msg_max::<_, AuthMsg>(s, AUTH_FRAME_MAX).await? {
        Some(AuthMsg::Accepted { server_mac }) => {
            let ok = hex_decode(&server_mac)
                .is_some_and(|b| mac(key, SERVER_LABEL, &nonce).verify_slice(&b).is_ok());
            if ok {
                Ok(())
            } else {
                Err(Error::Protocol(
                    "peer failed to prove it holds the key".into(),
                ))
            }
        }
        Some(AuthMsg::Denied) => Err(Error::Protocol("peer rejected our key".into())),
        _ => Err(Error::Protocol("unexpected authentication reply".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(server_key: &[u8], client_key: &[u8]) -> (Result<()>, Result<()>) {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let (s, c) = tokio::join!(
            server_handshake(&mut a, server_key),
            client_handshake(&mut b, client_key)
        );
        (s, c)
    }

    #[tokio::test]
    async fn matching_keys_succeed() {
        let (s, c) = run(b"correct horse", b"correct horse").await;
        assert!(s.is_ok() && c.is_ok());
    }

    #[tokio::test]
    async fn wrong_key_is_rejected_both_ways() {
        let (s, c) = run(b"correct horse", b"wrong").await;
        assert!(s.is_err());
        assert!(c.is_err());
    }
}
