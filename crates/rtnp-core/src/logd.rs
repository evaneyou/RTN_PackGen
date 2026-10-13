//! Central log server: accepts JSONL streams from senders and receivers and stores one file
//! per connection. Optionally authenticated with the shared key.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::auth;
use crate::control::read_msg_max;
use crate::error::Result;
use crate::log::LogHello;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HELLO_FRAME_MAX: usize = 4096;
const MAX_TAG_LEN: usize = 48;
const MAX_CONNECTIONS: usize = 64;

pub struct LogdConfig {
    pub out_dir: PathBuf,
    pub key: Option<Vec<u8>>,
    /// Each connection is cut off after this many bytes.
    pub max_bytes_per_conn: u64,
    /// Called with a one-line description of notable events (connections, errors).
    pub on_event: Arc<dyn Fn(String) + Send + Sync>,
}

/// Reduce a client-supplied tag to a safe file name component.
pub fn sanitize_tag(tag: &str) -> String {
    let t: String = tag
        .chars()
        .take(MAX_TAG_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if t.is_empty() { "log".to_string() } else { t }
}

pub async fn serve(listener: TcpListener, cfg: LogdConfig) -> Result<()> {
    let cfg = Arc::new(cfg);
    let counter = Arc::new(AtomicU64::new(0));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (stream, peer) = r?;
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    (cfg.on_event)(format!("rejected {peer}: too many connections"));
                    continue;
                };
                let cfg = cfg.clone();
                let n = counter.fetch_add(1, Ordering::Relaxed);
                conns.spawn(async move {
                    if let Err(e) = handle(stream, peer, &cfg, n).await {
                        (cfg.on_event)(format!("{peer}: {e}"));
                    }
                    drop(permit);
                });
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn handle(
    mut s: TcpStream,
    peer: std::net::SocketAddr,
    cfg: &LogdConfig,
    n: u64,
) -> Result<()> {
    if let Some(key) = &cfg.key {
        timeout(HANDSHAKE_TIMEOUT, auth::server_handshake(&mut s, key))
            .await
            .map_err(|_| crate::Error::Protocol("authentication timed out".into()))??;
    }
    let hello: LogHello = timeout(HANDSHAKE_TIMEOUT, read_msg_max(&mut s, HELLO_FRAME_MAX))
        .await
        .map_err(|_| crate::Error::Protocol("timed out waiting for hello".into()))??
        .ok_or_else(|| crate::Error::Protocol("connection closed before hello".into()))?;

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ip = peer.ip().to_string().replace(':', "_");
    let name = format!("{}-{ip}-{secs}-{n}.jsonl", sanitize_tag(&hello.tag));
    let path = cfg.out_dir.join(&name);
    // create_new: never overwrite or append to an existing file
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await?;
    (cfg.on_event)(format!("{peer}: logging to {}", path.display()));

    let copied = tokio::io::copy(&mut (&mut s).take(cfg.max_bytes_per_conn), &mut file).await?;
    file.flush().await?;
    (cfg.on_event)(format!("{peer}: closed, {copied} bytes written to {name}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_sanitised() {
        assert_eq!(sanitize_tag("lab-1_a"), "lab-1_a");
        assert_eq!(sanitize_tag("../../etc/passwd"), "______etc_passwd");
        assert_eq!(sanitize_tag(""), "log");
        assert_eq!(sanitize_tag(&"x".repeat(200)).len(), MAX_TAG_LEN);
    }
}
