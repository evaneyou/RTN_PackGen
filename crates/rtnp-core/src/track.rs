//! Per-stream measurement state shared by the receiver and by senders that listen for a
//! return stream: whole-run statistics, a resettable window for interval reports, and (for
//! plain RTP) sequence-number and timestamp unwrapping.

use crate::proto::{RtpHeader, rtp_clock_hz};
use crate::stats::{FlowStats, Summary};

/// Whole-run statistics plus a resettable window for interval reporting.
#[derive(Default, Debug)]
pub(crate) struct Tracked {
    total: FlowStats,
    window: FlowStats,
    /// Sequence numbers below this were accounted for by earlier windows.
    next_base: u64,
    /// Present for plain-RTP streams.
    rtp: Option<RtpTrack>,
}

impl Tracked {
    pub fn observe(&mut self, seq: u64, size: usize, tx_ns: u64, rx_ns: u64) {
        self.total.observe(seq, size, tx_ns, rx_ns);
        self.window.observe(seq, size, tx_ns, rx_ns);
    }

    /// Account for one plain-RTP packet of `size` bytes. Returns the (unwrapped sequence,
    /// synthetic send time) it was recorded under, or `None` if it predates the stream's start.
    pub fn observe_rtp(&mut self, h: &RtpHeader, size: usize, rx_ns: u64) -> Option<(u64, u64)> {
        if self.rtp.is_none() {
            self.total.mark_relative_delay();
            self.window.mark_relative_delay();
        }
        let track = self.rtp.get_or_insert_with(|| RtpTrack::new(h, rx_ns));
        let (seq, tx_ns) = track.map(h)?;
        self.observe(seq, size, tx_ns, rx_ns);
        Some((seq, tx_ns))
    }

    /// Remember the TOS byte of the latest packet (total and window).
    pub fn note_tos(&mut self, tos: Option<u8>) {
        self.total.note_tos(tos);
        self.window.note_tos(tos);
    }

    pub fn summary(&self) -> Summary {
        self.total.summary()
    }

    pub fn last_seen_ns(&self) -> u64 {
        self.total.last_seen_ns()
    }

    /// What arrived since the previous call, then start a new window. Loss is measured by
    /// sequence gaps, so packets still in flight at a window edge are not mistaken for loss; a
    /// gap shows up in the first window that sees a later packet.
    pub fn take_window(&mut self) -> Summary {
        let summary = self.window.summary_from(self.next_base);
        if let Some(m) = self.window.max_seq() {
            self.next_base = self.next_base.max(m + 1);
        }
        self.window = FlowStats::default();
        if self.rtp.is_some() {
            self.window.mark_relative_delay();
        }
        self.window.note_tos(self.total.summary().tos);
        summary
    }
}

/// Unwraps 16-bit RTP sequence numbers and 32-bit timestamps and maps them onto the sequence
/// and send-time inputs of [`FlowStats`]. Sequence 0 is the first packet seen; the synthetic send
/// time is the first arrival plus the RTP timestamp distance, so "delay" is relative to the first
/// packet and jitter is exactly the RFC 3550 interarrival jitter.
#[derive(Debug)]
struct RtpTrack {
    clock_hz: f64,
    first_rx_ns: u64,
    /// Highest sequence number seen (16-bit), its unwrapped value and its timestamp.
    last_seq: u16,
    ext_seq: i64,
    last_ts: u32,
    ext_ts: i64,
}

impl RtpTrack {
    fn new(h: &RtpHeader, rx_ns: u64) -> Self {
        RtpTrack {
            clock_hz: rtp_clock_hz(h.payload_type),
            first_rx_ns: rx_ns,
            last_seq: h.seq,
            ext_seq: 0,
            last_ts: h.ts,
            ext_ts: 0,
        }
    }

    fn map(&mut self, h: &RtpHeader) -> Option<(u64, u64)> {
        let dseq = h.seq.wrapping_sub(self.last_seq) as i16 as i64;
        let dts = h.ts.wrapping_sub(self.last_ts) as i32 as i64;
        let seq = self.ext_seq + dseq;
        let ts = self.ext_ts + dts;
        if seq < 0 {
            return None;
        }
        if dseq > 0 {
            self.last_seq = h.seq;
            self.ext_seq = seq;
            self.last_ts = h.ts;
            self.ext_ts = ts;
        }
        let tx = self.first_rx_ns as i64 + (ts as f64 * 1e9 / self.clock_hz) as i64;
        Some((seq as u64, tx.max(0) as u64))
    }
}
