//! Minimal Prometheus text-format endpoint served by the receiver (`GET /metrics`).

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::Result;
use crate::receiver::Shared;
use crate::stats::Summary;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type Extract = fn(&Summary) -> f64;

const FLOW_METRICS: &[(&str, &str, &str, Extract)] = &[
    (
        "rtnp_rx_packets_total",
        "counter",
        "Packets received.",
        |s| s.packets as f64,
    ),
    ("rtnp_rx_bytes_total", "counter", "Bytes received.", |s| {
        s.bytes as f64
    }),
    (
        "rtnp_rx_reordered_packets_total",
        "counter",
        "Packets that arrived out of order.",
        |s| s.reordered as f64,
    ),
    (
        "rtnp_rx_lost_packets",
        "gauge",
        "Packets missing relative to the highest sequence number seen.",
        |s| s.lost as f64,
    ),
    (
        "rtnp_rx_bitrate_bits_per_second",
        "gauge",
        "Average received bitrate over the flow's lifetime.",
        |s| s.bitrate_kbps * 1000.0,
    ),
    (
        "rtnp_rx_delay_avg_seconds",
        "gauge",
        "Average one-way delay (needs synchronised clocks).",
        |s| s.delay_avg_ms / 1000.0,
    ),
    (
        "rtnp_rx_delay_max_seconds",
        "gauge",
        "Maximum one-way delay.",
        |s| s.delay_max_ms / 1000.0,
    ),
    (
        "rtnp_rx_jitter_seconds",
        "gauge",
        "Mean absolute difference of consecutive one-way delays.",
        |s| s.jitter_ms / 1000.0,
    ),
];

pub fn render(shared: &Shared) -> String {
    let snap = shared.snapshot();
    let mut out = String::new();
    for (name, kind, help, f) in FLOW_METRICS {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        for ((session, flow), s) in &snap {
            let _ = writeln!(
                out,
                "{name}{{session=\"{session:08x}\",flow=\"{flow}\"}} {}",
                f(s)
            );
        }
    }
    let _ = writeln!(out, "# HELP rtnp_tracked_flows Flows currently tracked.");
    let _ = writeln!(out, "# TYPE rtnp_tracked_flows gauge");
    let _ = writeln!(out, "rtnp_tracked_flows {}", snap.len());
    let _ = writeln!(
        out,
        "# HELP rtnp_malformed_packets_total Packets that failed header validation."
    );
    let _ = writeln!(out, "# TYPE rtnp_malformed_packets_total counter");
    let _ = writeln!(
        out,
        "rtnp_malformed_packets_total {}",
        shared.malformed.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# HELP rtnp_overflow_packets_total Packets ignored because the flow table was full."
    );
    let _ = writeln!(out, "# TYPE rtnp_overflow_packets_total counter");
    let _ = writeln!(
        out,
        "rtnp_overflow_packets_total {}",
        shared.overflow.load(Ordering::Relaxed)
    );
    out
}

pub(crate) async fn serve(listener: TcpListener, shared: Arc<Shared>) -> Result<()> {
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (s, _) = r?;
                conns.spawn(handle(s, shared.clone()));
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn handle(mut s: TcpStream, shared: Arc<Shared>) {
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    let read = timeout(REQUEST_TIMEOUT, async {
        loop {
            let k = s.read(&mut buf[n..]).await?;
            if k == 0 {
                break;
            }
            n += k;
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    if !matches!(read, Ok(Ok(()))) {
        return;
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let mut parts = req.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (parts.next(), parts.next());
    let resp = if method == Some("GET") && path == Some("/metrics") {
        let body = render(&shared);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}
