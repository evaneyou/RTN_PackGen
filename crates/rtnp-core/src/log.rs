//! Structured JSON-lines logging. One record per line, written by a background task so
//! that disk I/O (or a slow log server) never blocks packet pacing. If the queue
//! overflows, records are dropped and counted rather than slowing the data path.
//!
//! Records can go to a local file ([`LogSink::to_file`]) or to a central `rtnp-logd`
//! server ([`LogSink::to_remote`]).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::client::connect_control_with;
use crate::control::write_msg;
use crate::error::{Error, Result};
use crate::tls::TlsClient;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum LogRecord {
    FlowStart {
        session: u32,
        flow: u32,
        role: String,
        name: String,
        proto: String,
        peer: String,
        t_ns: u64,
    },
    Tx {
        session: u32,
        flow: u32,
        seq: u64,
        size: u32,
        t_ns: u64,
    },
    Rx {
        session: u32,
        flow: u32,
        seq: u64,
        size: u32,
        tx_ns: u64,
        t_ns: u64,
    },
    Rtt {
        session: u32,
        flow: u32,
        seq: u64,
        size: u32,
        t_ns: u64,
        rtt_ns: u64,
    },
    FlowEnd {
        session: u32,
        flow: u32,
        t_ns: u64,
        sent: u64,
        bytes: u64,
        late: u64,
    },
}

/// First frame a client sends to a log server (after authentication, if any); everything
/// after it on the connection is raw JSON lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHello {
    pub tag: String,
}

#[derive(Clone)]
pub struct LogHandle {
    tx: Option<mpsc::Sender<LogRecord>>,
    dropped: Arc<AtomicU64>,
}

impl LogHandle {
    pub fn send(&self, rec: LogRecord) {
        if let Some(tx) = &self.tx
            && tx.try_send(rec).is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub struct LogSink {
    handle: LogHandle,
    closer: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<std::io::Result<()>>>,
}

impl LogSink {
    /// A sink that discards everything.
    pub fn none() -> Self {
        LogSink {
            handle: LogHandle {
                tx: None,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            closer: None,
            join: None,
        }
    }

    pub async fn to_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = tokio::fs::File::create(path.as_ref()).await?;
        Ok(Self::spawn(file))
    }

    /// Stream records to a `rtnp-logd` server. `tag` names the stream on the server.
    pub async fn to_remote(addr: &str, tag: &str, key: Option<&[u8]>) -> Result<Self> {
        Self::to_remote_with(addr, tag, key, None).await
    }

    /// Like [`LogSink::to_remote`], inside TLS when `tls` is given.
    pub async fn to_remote_with(
        addr: &str,
        tag: &str,
        key: Option<&[u8]>,
        tls: Option<&TlsClient>,
    ) -> Result<Self> {
        let mut s = connect_control_with(addr, key, tls).await?;
        write_msg(
            &mut s,
            &LogHello {
                tag: tag.to_string(),
            },
        )
        .await?;
        Ok(Self::spawn(s))
    }

    fn spawn<W: AsyncWrite + Unpin + Send + 'static>(out: W) -> Self {
        let (tx, mut rx) = mpsc::channel::<LogRecord>(131_072);
        let (closer, mut close_rx) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let mut w = BufWriter::with_capacity(256 * 1024, out);
            let mut line = Vec::with_capacity(256);
            let mut closing = false;
            loop {
                let rec = if closing {
                    rx.recv().await
                } else {
                    tokio::select! {
                        r = rx.recv() => r,
                        _ = &mut close_rx => {
                            closing = true;
                            rx.close();
                            continue;
                        }
                    }
                };
                let Some(rec) = rec else { break };
                line.clear();
                serde_json::to_writer(&mut line, &rec).map_err(std::io::Error::other)?;
                line.push(b'\n');
                w.write_all(&line).await?;
            }
            w.shutdown().await
        });
        LogSink {
            handle: LogHandle {
                tx: Some(tx),
                dropped: Arc::new(AtomicU64::new(0)),
            },
            closer: Some(closer),
            join: Some(join),
        }
    }

    pub fn handle(&self) -> LogHandle {
        self.handle.clone()
    }

    /// Flush and stop the writer. Returns the number of records dropped due to overflow.
    pub async fn close(mut self) -> Result<u64> {
        if let Some(c) = self.closer.take() {
            let _ = c.send(());
        }
        if let Some(j) = self.join.take() {
            j.await
                .map_err(|e| Error::Protocol(format!("log writer task failed: {e}")))??;
        }
        Ok(self.handle.dropped())
    }
}

pub fn read_records(path: impl AsRef<Path>) -> Result<Vec<LogRecord>> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path.as_ref())?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec = serde_json::from_str(&line)
            .map_err(|e| Error::Protocol(format!("{}:{}: {e}", path.as_ref().display(), i + 1)))?;
        out.push(rec);
    }
    Ok(out)
}
