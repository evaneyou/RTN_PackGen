//! Offline analysis of JSONL logs (the engine behind `rtnp-decode`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::log::LogRecord;
use crate::stats::{FlowStats, Summary};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RttSummary {
    pub count: u64,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    pub jitter_ms: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowReport {
    pub session: u32,
    pub flow: u32,
    pub name: String,
    pub proto: String,
    pub sent: Option<u64>,
    pub sent_bytes: Option<u64>,
    pub late: Option<u64>,
    pub rx: Option<Summary>,
    pub rtt: Option<RttSummary>,
    /// `sent - received`, when both sender and receiver logs are available.
    pub lost_vs_tx: Option<u64>,
    /// Two-way calls: the return stream (receiver to sender) as measured by the sender.
    #[serde(default)]
    pub reverse: Option<Summary>,
    /// Present when quality limits were given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<crate::verdict::Verdict>,
}

#[derive(Default)]
struct Acc {
    name: String,
    proto: String,
    sent: Option<u64>,
    sent_bytes: Option<u64>,
    late: Option<u64>,
    tx_records: u64,
    tx_bytes: u64,
    rx: FlowStats,
    rtts: Vec<f64>, // ms, in log order
}

/// Summarise round-trip times (ms) given in probe order.
pub fn rtt_summary(rtts: &[f64]) -> Option<RttSummary> {
    if rtts.is_empty() {
        return None;
    }
    let n = rtts.len() as f64;
    let jitter = if rtts.len() > 1 {
        rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    Some(RttSummary {
        count: rtts.len() as u64,
        min_ms: rtts.iter().cloned().fold(f64::INFINITY, f64::min),
        avg_ms: rtts.iter().sum::<f64>() / n,
        max_ms: rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        jitter_ms: jitter,
    })
}

/// Build one report per `(session, flow)` from any mix of sender and receiver records.
pub fn aggregate(records: &[LogRecord], flow_filter: Option<u32>) -> Vec<FlowReport> {
    let mut map: BTreeMap<(u32, u32), Acc> = BTreeMap::new();
    let keep = |f: u32| flow_filter.is_none_or(|x| x == f);
    for r in records {
        match r {
            LogRecord::FlowStart {
                session,
                flow,
                name,
                proto,
                ..
            } if keep(*flow) => {
                let a = map.entry((*session, *flow)).or_default();
                if !name.is_empty() {
                    a.name = name.clone();
                }
                a.proto = proto.clone();
            }
            LogRecord::Tx {
                session,
                flow,
                size,
                ..
            } if keep(*flow) => {
                let a = map.entry((*session, *flow)).or_default();
                a.tx_records += 1;
                a.tx_bytes += *size as u64;
            }
            LogRecord::Rx {
                session,
                flow,
                seq,
                size,
                tx_ns,
                t_ns,
            } if keep(*flow) => {
                map.entry((*session, *flow)).or_default().rx.observe(
                    *seq,
                    *size as usize,
                    *tx_ns,
                    *t_ns,
                );
            }
            LogRecord::Rtt {
                session,
                flow,
                rtt_ns,
                ..
            } if keep(*flow) => {
                map.entry((*session, *flow))
                    .or_default()
                    .rtts
                    .push(*rtt_ns as f64 / 1e6);
            }
            LogRecord::FlowEnd {
                session,
                flow,
                sent,
                bytes,
                late,
                ..
            } if keep(*flow) => {
                let a = map.entry((*session, *flow)).or_default();
                a.sent = Some(*sent);
                a.sent_bytes = Some(*bytes);
                a.late = Some(*late);
            }
            _ => {}
        }
    }

    map.into_iter()
        .map(|((session, flow), a)| {
            let sent = a.sent.or((a.tx_records > 0).then_some(a.tx_records));
            let sent_bytes = a.sent_bytes.or((a.tx_records > 0).then_some(a.tx_bytes));
            let rx = (a.rx.packets() > 0).then(|| a.rx.summary());
            let lost_vs_tx = match (&rx, sent) {
                (Some(r), Some(s)) => Some(s.saturating_sub(r.packets)),
                (None, Some(s)) if a.rtts.is_empty() && a.proto != "icmp" => Some(s),
                (None, Some(s)) if a.proto != "icmp" => Some(s.saturating_sub(a.rtts.len() as u64)),
                _ => None,
            };
            let rtt = rtt_summary(&a.rtts);
            FlowReport {
                session,
                flow,
                name: a.name,
                proto: a.proto,
                sent,
                sent_bytes,
                late: a.late,
                rx,
                rtt,
                lost_vs_tx,
                reverse: None,
                verdict: None,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct IntervalRow {
    pub session: u32,
    pub flow: u32,
    /// Start of the interval, relative to the flow's first received packet.
    pub t_ms: f64,
    pub packets: u64,
    pub bitrate_kbps: f64,
    pub pps: f64,
    pub delay_avg_ms: f64,
    pub jitter_ms: f64,
}

/// Per-interval bitrate, packet rate, delay and jitter from receiver records.
pub fn interval_series(
    records: &[LogRecord],
    interval_ms: u64,
    flow_filter: Option<u32>,
) -> Vec<IntervalRow> {
    let interval_ns = interval_ms.max(1) * 1_000_000;
    // (rx time, seq, size, tx time) per received packet
    type RxSample = (u64, u64, u32, u64);
    let mut per_flow: BTreeMap<(u32, u32), Vec<RxSample>> = BTreeMap::new();
    for r in records {
        if let LogRecord::Rx {
            session,
            flow,
            seq,
            size,
            tx_ns,
            t_ns,
        } = r
            && flow_filter.is_none_or(|f| f == *flow)
        {
            per_flow
                .entry((*session, *flow))
                .or_default()
                .push((*t_ns, *seq, *size, *tx_ns));
        }
    }
    let mut rows = Vec::new();
    for ((session, flow), mut v) in per_flow {
        v.sort_by_key(|x| x.0);
        let t0 = v[0].0;
        let mut buckets: BTreeMap<u64, FlowStats> = BTreeMap::new();
        for (t, seq, size, tx) in v {
            buckets
                .entry((t - t0) / interval_ns)
                .or_default()
                .observe(seq, size as usize, tx, t);
        }
        let secs = interval_ns as f64 / 1e9;
        for (idx, st) in buckets {
            let s = st.summary();
            rows.push(IntervalRow {
                session,
                flow,
                t_ms: (idx * interval_ns) as f64 / 1e6,
                packets: s.packets,
                bitrate_kbps: s.bytes as f64 * 8.0 / 1000.0 / secs,
                pps: s.packets as f64 / secs,
                delay_avg_ms: s.delay_avg_ms,
                jitter_ms: s.jitter_ms,
            });
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx(seq: u64, t: u64) -> LogRecord {
        LogRecord::Rx {
            session: 1,
            flow: 1,
            seq,
            size: 100,
            tx_ns: t - 1_000_000,
            t_ns: t,
        }
    }

    #[test]
    fn merges_sender_and_receiver_logs() {
        let recs = vec![
            LogRecord::FlowStart {
                session: 1,
                flow: 1,
                role: "tx".into(),
                name: "voip".into(),
                proto: "udp".into(),
                peer: "x".into(),
                t_ns: 0,
            },
            rx(0, 10_000_000),
            rx(1, 20_000_000),
            rx(3, 40_000_000),
            LogRecord::FlowEnd {
                session: 1,
                flow: 1,
                t_ns: 50_000_000,
                sent: 5,
                bytes: 500,
                late: 0,
            },
        ];
        let rep = aggregate(&recs, None);
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].name, "voip");
        assert_eq!(rep[0].sent, Some(5));
        assert_eq!(rep[0].rx.as_ref().unwrap().packets, 3);
        assert_eq!(rep[0].lost_vs_tx, Some(2));
    }

    #[test]
    fn intervals_bucket_correctly() {
        let recs: Vec<_> = (0..20)
            .map(|i| rx(i, 1_000_000_000 + i * 10_000_000))
            .collect();
        let rows = interval_series(&recs, 100, None);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].packets, 10);
        assert!((rows[0].pps - 100.0).abs() < 1e-9);
        assert!((rows[0].bitrate_kbps - 80.0).abs() < 1e-9);
    }

    #[test]
    fn total_loss_detected_when_nothing_received() {
        let recs = vec![
            LogRecord::FlowStart {
                session: 2,
                flow: 1,
                role: "tx".into(),
                name: "x".into(),
                proto: "udp".into(),
                peer: "p".into(),
                t_ns: 0,
            },
            LogRecord::FlowEnd {
                session: 2,
                flow: 1,
                t_ns: 1,
                sent: 10,
                bytes: 1000,
                late: 0,
            },
        ];
        let rep = aggregate(&recs, None);
        assert_eq!(rep[0].lost_vs_tx, Some(10));
    }
}
