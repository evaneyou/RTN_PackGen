//! Streaming per-flow statistics shared by the live receiver and the offline decoder.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    packets: u64,
    bytes: u64,
    first_ns: u64,
    last_ns: u64,
    max_seq: Option<u64>,
    reordered: u64,
    // one-way delay in ns, Welford accumulation
    delay_mean: f64,
    delay_m2: f64,
    delay_min: i64,
    delay_max: i64,
    last_transit: Option<i64>,
    jitter_rfc: f64,
    jitter_abs_sum: f64,
    jitter_n: u64,
    relative_delay: bool,
    last_tos: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub packets: u64,
    pub bytes: u64,
    /// Packets missing relative to the highest sequence number seen.
    pub lost: u64,
    pub loss_pct: f64,
    pub reordered: u64,
    pub duration_s: f64,
    pub bitrate_kbps: f64,
    pub pps: f64,
    pub delay_min_ms: f64,
    pub delay_avg_ms: f64,
    pub delay_max_ms: f64,
    pub delay_stddev_ms: f64,
    /// Mean absolute difference of consecutive one-way delays.
    pub jitter_ms: f64,
    /// Smoothed interarrival jitter as defined by RFC 3550.
    pub jitter_rfc3550_ms: f64,
    /// Plain-RTP streams carry no send timestamp, so the delay figures are relative to the
    /// first packet (and can be negative); jitter is unaffected.
    #[serde(default)]
    pub delay_relative: bool,
    /// TOS byte (DSCP << 2 | ECN) of the most recent packet, when the platform reports it.
    /// Compare with what was sent to see whether the network preserved the marking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos: Option<u8>,
}

impl FlowStats {
    pub fn observe(&mut self, seq: u64, size: usize, tx_ns: u64, rx_ns: u64) {
        let delay = rx_ns as i64 - tx_ns as i64;
        if self.packets == 0 {
            self.first_ns = rx_ns;
            self.delay_min = delay;
            self.delay_max = delay;
        }
        self.last_ns = self.last_ns.max(rx_ns);
        self.first_ns = self.first_ns.min(rx_ns);
        self.packets += 1;
        self.bytes += size as u64;

        match self.max_seq {
            Some(m) if seq < m => self.reordered += 1,
            Some(m) => self.max_seq = Some(m.max(seq)),
            None => self.max_seq = Some(seq),
        }

        self.delay_min = self.delay_min.min(delay);
        self.delay_max = self.delay_max.max(delay);
        let d = delay as f64;
        let n = self.packets as f64;
        let diff = d - self.delay_mean;
        self.delay_mean += diff / n;
        self.delay_m2 += diff * (d - self.delay_mean);

        if let Some(prev) = self.last_transit {
            let dd = (delay - prev).unsigned_abs() as f64;
            self.jitter_rfc += (dd - self.jitter_rfc) / 16.0;
            self.jitter_abs_sum += dd;
            self.jitter_n += 1;
        }
        self.last_transit = Some(delay);
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Remember the TOS byte of the latest packet.
    pub fn note_tos(&mut self, tos: Option<u8>) {
        if tos.is_some() {
            self.last_tos = tos;
        }
    }

    /// Mark delays as relative to the first packet (streams without a send timestamp).
    pub fn mark_relative_delay(&mut self) {
        self.relative_delay = true;
    }

    /// Highest sequence number seen so far.
    pub fn max_seq(&self) -> Option<u64> {
        self.max_seq
    }

    /// Arrival time (ns since the epoch) of the most recent packet; 0 before the first.
    pub fn last_seen_ns(&self) -> u64 {
        self.last_ns
    }

    pub fn summary(&self) -> Summary {
        self.summary_from(0)
    }

    /// Like [`summary`](Self::summary) for a window of a flow whose earlier sequence numbers
    /// (below `base`) were accounted for in previous windows: loss is measured against
    /// `max_seq + 1 - base` expected packets.
    pub fn summary_from(&self, base: u64) -> Summary {
        if self.packets == 0 {
            return Summary::default();
        }
        let expected = self
            .max_seq
            .map(|m| (m + 1).saturating_sub(base))
            .unwrap_or(self.packets);
        let lost = expected.saturating_sub(self.packets);
        let duration_s = (self.last_ns.saturating_sub(self.first_ns)) as f64 / 1e9;
        let (bitrate_kbps, pps) = if duration_s > 0.0 {
            (
                self.bytes as f64 * 8.0 / 1000.0 / duration_s,
                self.packets as f64 / duration_s,
            )
        } else {
            (0.0, 0.0)
        };
        let ms = 1e-6;
        Summary {
            packets: self.packets,
            bytes: self.bytes,
            lost,
            loss_pct: if expected > 0 {
                lost as f64 * 100.0 / expected as f64
            } else {
                0.0
            },
            reordered: self.reordered,
            duration_s,
            bitrate_kbps,
            pps,
            delay_min_ms: self.delay_min as f64 * ms,
            delay_avg_ms: self.delay_mean * ms,
            delay_max_ms: self.delay_max as f64 * ms,
            delay_stddev_ms: if self.packets > 1 {
                (self.delay_m2 / (self.packets - 1) as f64).sqrt() * ms
            } else {
                0.0
            },
            jitter_ms: if self.jitter_n > 0 {
                self.jitter_abs_sum / self.jitter_n as f64 * ms
            } else {
                0.0
            },
            jitter_rfc3550_ms: self.jitter_rfc * ms,
            delay_relative: self.relative_delay,
            tos: self.last_tos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_and_delay() {
        let mut s = FlowStats::default();
        // seq 0,1,3,4 received (2 lost), constant 1 ms delay, 10 ms spacing
        for (i, seq) in [0u64, 1, 3, 4].into_iter().enumerate() {
            let tx = 1_000_000_000 + i as u64 * 10_000_000;
            s.observe(seq, 100, tx, tx + 1_000_000);
        }
        let r = s.summary();
        assert_eq!(r.packets, 4);
        assert_eq!(r.lost, 1);
        assert!((r.loss_pct - 20.0).abs() < 1e-9);
        assert!((r.delay_avg_ms - 1.0).abs() < 1e-9);
        assert!(r.jitter_ms.abs() < 1e-9);
        assert_eq!(r.reordered, 0);
    }

    #[test]
    fn windowed_loss_uses_base() {
        let mut w = FlowStats::default();
        // previous windows covered seq 0..10; this one saw 10, 11, 13 (12 missing)
        for seq in [10u64, 11, 13] {
            w.observe(seq, 10, 0, 1_000);
        }
        let r = w.summary_from(10);
        assert_eq!(r.packets, 3);
        assert_eq!(r.lost, 1);
        assert_eq!(w.max_seq(), Some(13));
    }

    #[test]
    fn reorder_counted() {
        let mut s = FlowStats::default();
        s.observe(0, 10, 0, 10);
        s.observe(2, 10, 0, 20);
        s.observe(1, 10, 0, 30);
        assert_eq!(s.summary().reordered, 1);
        assert_eq!(s.summary().lost, 0);
    }

    #[test]
    fn jitter_measured() {
        let mut s = FlowStats::default();
        // delays alternate 1 ms / 2 ms => |D| = 1 ms every step
        for i in 0..100u64 {
            let tx = i * 10_000_000;
            let delay = if i % 2 == 0 { 1_000_000 } else { 2_000_000 };
            s.observe(i, 50, tx, tx + delay);
        }
        let r = s.summary();
        assert!((r.jitter_ms - 1.0).abs() < 1e-9);
        assert!(r.jitter_rfc3550_ms > 0.9 && r.jitter_rfc3550_ms <= 1.0);
    }
}
