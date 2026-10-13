//! Control channel between sender and receiver: length-prefixed JSON frames over TCP.
//!
//! The channel lets a sender announce a session and flows, then ask the receiver for
//! its view of the results once traffic has finished. It is unauthenticated and
//! unencrypted: run it on trusted networks only.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::flow::{Codec, FlowSpec, Proto};
use crate::report::FlowReport;
use crate::stats::Summary;

pub const MAX_CONTROL_FRAME: usize = 1024 * 1024;

/// The stream the receiver is asked to send back to the sender (a two-way call): constant
/// plain-RTP voice at the given cadence, from the receiver's data port to wherever the forward
/// stream comes from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReverseSpec {
    pub codec: Codec,
    pub idt_ms: f64,
    /// UDP payload size including the 12-byte RTP header.
    pub packet_bytes: usize,
    pub ssrc: u32,
    /// TOS byte (DSCP << 2) to mark the return stream with, e.g. 184 for EF.
    #[serde(default)]
    pub tos: Option<u8>,
}

impl ReverseSpec {
    /// Bounds that keep a peer from turning the receiver into a traffic cannon.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !(self.idt_ms.is_finite() && (10.0..=200.0).contains(&self.idt_ms)) {
            return Err("reverse stream interval must be between 10 and 200 ms".into());
        }
        if !(20..=1400).contains(&self.packet_bytes) {
            return Err("reverse stream packets must be between 20 and 1400 bytes".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAnnounce {
    pub flow: u32,
    pub name: String,
    pub proto: Proto,
    /// SSRC of a plain-RTP flow, so the receiver can attribute the stream.
    #[serde(default)]
    pub ssrc: Option<u32>,
    /// Ask the receiver for a return stream (two-way call).
    #[serde(default)]
    pub reverse: Option<ReverseSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello {
        version: u8,
        session: u32,
        flows: Vec<FlowAnnounce>,
    },
    /// Sent after the last packet; the receiver waits `grace_ms` (capped) for in-flight
    /// packets before replying with a [`ServerMsg::Report`].
    Done { session: u32, grace_ms: u64 },
    /// Ask for the receiver's view of the traffic since the previous `Poll` of this session
    /// (the first poll covers everything so far). Answered with [`ServerMsg::Window`].
    Poll { session: u32 },
    /// Ask a receiver started with `--allow-launch` to generate the given flows from its own
    /// host. `control` is the far end's control address, used for the agent's own session.
    Launch {
        flows: Vec<FlowSpec>,
        control: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteFlowSummary {
    pub flow: u32,
    pub name: String,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ServerMsg {
    Ready {
        version: u8,
        /// The receiver accepts return streams (`--allow-reverse`).
        #[serde(default)]
        reverse: bool,
    },
    Report {
        session: u32,
        flows: Vec<RemoteFlowSummary>,
    },
    Window {
        session: u32,
        flows: Vec<RemoteFlowSummary>,
    },
    Error {
        message: String,
    },
    LaunchReport {
        reports: Vec<FlowReport>,
        errors: Vec<String>,
    },
}

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_CONTROL_FRAME {
        return Err(Error::Protocol("control message too large".into()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Returns `Ok(None)` on a clean EOF at a frame boundary.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    read_msg_max(r, MAX_CONTROL_FRAME).await
}

/// Like [`read_msg`] with a caller-chosen frame size limit (use a small one before a peer is trusted).
pub async fn read_msg_max<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
    max: usize,
) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(Error::Protocol(format!(
            "control frame of {len} bytes exceeds limit"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_msg(
            &mut a,
            &ClientMsg::Done {
                session: 7,
                grace_ms: 250,
            },
        )
        .await
        .unwrap();
        drop(a);
        let got: Option<ClientMsg> = read_msg(&mut b).await.unwrap();
        assert!(matches!(
            got,
            Some(ClientMsg::Done {
                session: 7,
                grace_ms: 250
            })
        ));
        let eof: Option<ClientMsg> = read_msg(&mut b).await.unwrap();
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
        let r: Result<Option<ClientMsg>> = read_msg(&mut b).await;
        assert!(r.is_err());
    }
}
