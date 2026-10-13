//! Minimal RTCP (RFC 3550 section 6): sender reports, receiver reports and an SDES CNAME,
//! enough to measure round-trip time the standard way (LSR/DLSR) without synchronised clocks.
//! Packets are multiplexed on the RTP port (RFC 5761).

use std::time::{SystemTime, UNIX_EPOCH};

pub const PT_SR: u8 = 200;
pub const PT_RR: u8 = 201;
pub const PT_SDES: u8 = 202;

const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
/// Largest round trip we are willing to believe.
const MAX_RTT_S: f64 = 30.0;

/// RTCP and RTP share a port (RFC 5761): packet types 192-223 in the second byte are RTCP.
pub fn is_rtcp(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[0] >> 6 == 2 && (192..=223).contains(&buf[1])
}

/// Current time as 64-bit NTP (seconds since 1900, 32-bit fraction).
pub fn ntp_now() -> (u32, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() + NTP_UNIX_OFFSET;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs as u32, frac as u32)
}

/// The middle 32 bits of an NTP timestamp (units of 1/65536 s): the form used in LSR/DLSR.
pub fn middle32(msw: u32, lsw: u32) -> u32 {
    (msw << 16) | (lsw >> 16)
}

pub fn ntp_mid_now() -> u32 {
    let (m, l) = ntp_now();
    middle32(m, l)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderInfo {
    pub ntp_msw: u32,
    pub ntp_lsw: u32,
    pub rtp_ts: u32,
    pub packets: u32,
    pub octets: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    /// Signed 24-bit on the wire.
    pub cumulative_lost: i32,
    pub ext_highest_seq: u32,
    /// Interarrival jitter in RTP timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP time in the last SR received from the reported source.
    pub lsr: u32,
    /// Delay since that SR arrived, in 1/65536 s.
    pub dlsr: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rtcp {
    Sr {
        ssrc: u32,
        info: SenderInfo,
        blocks: Vec<ReportBlock>,
    },
    Rr {
        ssrc: u32,
        blocks: Vec<ReportBlock>,
    },
    /// Anything else (SDES, BYE, APP, ...) is skipped.
    Other(u8),
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn parse_blocks(b: &[u8], count: usize) -> Option<Vec<ReportBlock>> {
    if b.len() < count * 24 {
        return None;
    }
    Some(
        (0..count)
            .map(|i| {
                let o = i * 24;
                let lost24 = u32_at(b, o + 4) & 0x00ff_ffff;
                ReportBlock {
                    ssrc: u32_at(b, o),
                    fraction_lost: b[o + 4],
                    // sign-extend the 24-bit field
                    cumulative_lost: ((lost24 << 8) as i32) >> 8,
                    ext_highest_seq: u32_at(b, o + 8),
                    jitter: u32_at(b, o + 12),
                    lsr: u32_at(b, o + 16),
                    dlsr: u32_at(b, o + 20),
                }
            })
            .collect(),
    )
}

/// Parse a compound RTCP packet. Parsing stops at the first malformed element; whatever
/// was understood before it is returned.
pub fn parse(mut buf: &[u8]) -> Vec<Rtcp> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        if buf[0] >> 6 != 2 {
            break;
        }
        let count = (buf[0] & 0x1f) as usize;
        let pt = buf[1];
        let total = (u16::from_be_bytes([buf[2], buf[3]]) as usize + 1) * 4;
        if total > buf.len() {
            break;
        }
        let body = &buf[4..total];
        let parsed = match pt {
            PT_SR if body.len() >= 24 => parse_blocks(&body[24..], count).map(|blocks| Rtcp::Sr {
                ssrc: u32_at(body, 0),
                info: SenderInfo {
                    ntp_msw: u32_at(body, 4),
                    ntp_lsw: u32_at(body, 8),
                    rtp_ts: u32_at(body, 12),
                    packets: u32_at(body, 16),
                    octets: u32_at(body, 20),
                },
                blocks,
            }),
            PT_RR if body.len() >= 4 => parse_blocks(&body[4..], count).map(|blocks| Rtcp::Rr {
                ssrc: u32_at(body, 0),
                blocks,
            }),
            PT_SR | PT_RR => None,
            other => Some(Rtcp::Other(other)),
        };
        match parsed {
            Some(p) => out.push(p),
            None => break,
        }
        buf = &buf[total..];
    }
    out
}

fn header(out: &mut Vec<u8>, count: u8, pt: u8, words_after_header: usize) {
    out.push(0x80 | (count & 0x1f));
    out.push(pt);
    out.extend_from_slice(&(words_after_header as u16).to_be_bytes());
}

fn push_sdes(out: &mut Vec<u8>, ssrc: u32, cname: &str) {
    let cname = &cname.as_bytes()[..cname.len().min(60)];
    // chunk: ssrc + (type, len, text) + at least one null, padded to 32 bits
    let item = 2 + cname.len();
    let chunk = (4 + item + 1).div_ceil(4) * 4;
    header(out, 1, PT_SDES, chunk / 4);
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.push(1); // CNAME
    out.push(cname.len() as u8);
    out.extend_from_slice(cname);
    let written = 4 + item;
    out.extend(std::iter::repeat_n(0u8, chunk - written));
}

fn push_block(out: &mut Vec<u8>, b: &ReportBlock) {
    out.extend_from_slice(&b.ssrc.to_be_bytes());
    out.push(b.fraction_lost);
    out.extend_from_slice(&(b.cumulative_lost as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&b.ext_highest_seq.to_be_bytes());
    out.extend_from_slice(&b.jitter.to_be_bytes());
    out.extend_from_slice(&b.lsr.to_be_bytes());
    out.extend_from_slice(&b.dlsr.to_be_bytes());
}

/// A sender report (no report blocks) followed by the mandatory SDES CNAME.
pub fn build_sr(ssrc: u32, info: &SenderInfo, cname: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    header(&mut out, 0, PT_SR, 6);
    out.extend_from_slice(&ssrc.to_be_bytes());
    for v in [
        info.ntp_msw,
        info.ntp_lsw,
        info.rtp_ts,
        info.packets,
        info.octets,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    push_sdes(&mut out, ssrc, cname);
    out
}

/// A receiver report with an optional single block, followed by the SDES CNAME.
pub fn build_rr(ssrc: u32, block: Option<&ReportBlock>, cname: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let rc = block.is_some() as usize;
    header(&mut out, rc as u8, PT_RR, 1 + 6 * rc);
    out.extend_from_slice(&ssrc.to_be_bytes());
    if let Some(b) = block {
        push_block(&mut out, b);
    }
    push_sdes(&mut out, ssrc, cname);
    out
}

/// Round-trip time in ms from a report block about our SR, received at `arrival_mid`
/// (middle-32 NTP). `None` if the block has no SR reference or the result is implausible.
pub fn rtt_ms(block: &ReportBlock, arrival_mid: u32) -> Option<f64> {
    if block.lsr == 0 {
        return None;
    }
    let units = arrival_mid.wrapping_sub(block.lsr).wrapping_sub(block.dlsr);
    if units > 0x8000_0000 {
        return None; // negative: clocks stepped or the report is bogus
    }
    let s = units as f64 / 65536.0;
    (s <= MAX_RTT_S).then_some(s * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr_roundtrip_with_sdes() {
        let info = SenderInfo {
            ntp_msw: 0xE000_0001,
            ntp_lsw: 0x8000_0000,
            rtp_ts: 123_456,
            packets: 50,
            octets: 8000,
        };
        let b = build_sr(0xAABB_CCDD, &info, "rtnp@test");
        assert_eq!(b.len() % 4, 0);
        assert!(is_rtcp(&b));
        let p = parse(&b);
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[0],
            Rtcp::Sr {
                ssrc: 0xAABB_CCDD,
                info,
                blocks: vec![]
            }
        );
        assert_eq!(p[1], Rtcp::Other(PT_SDES));
    }

    #[test]
    fn rr_roundtrip_and_negative_loss() {
        let blk = ReportBlock {
            ssrc: 1,
            fraction_lost: 25,
            cumulative_lost: -3,
            ext_highest_seq: 0x0001_0005,
            jitter: 12,
            lsr: 0x1234_5678,
            dlsr: 65536,
        };
        let b = build_rr(9, Some(&blk), "x");
        match &parse(&b)[0] {
            Rtcp::Rr { ssrc, blocks } => {
                assert_eq!(*ssrc, 9);
                assert_eq!(blocks, &vec![blk]);
            }
            other => panic!("{other:?}"),
        }
        // an RR without a block is valid (no SR seen yet)
        assert!(
            matches!(&parse(&build_rr(9, None, "x"))[0], Rtcp::Rr { blocks, .. } if blocks.is_empty())
        );
    }

    #[test]
    fn malformed_input_is_contained() {
        assert!(parse(&[]).is_empty());
        assert!(
            parse(&[0x80, 200, 0, 50, 1, 2, 3, 4]).is_empty(),
            "length beyond buffer"
        );
        assert!(parse(&[0x40, 200, 0, 0]).is_empty(), "wrong version");
        // SR header claiming 3 blocks with no room for them
        let mut sr = build_sr(1, &SenderInfo::default(), "c");
        sr[0] |= 3;
        assert!(parse(&sr).is_empty());
        // truncated mid-stream: the first element survives
        let sr = build_sr(1, &SenderInfo::default(), "cname");
        assert_eq!(parse(&sr[..sr.len() - 4]).len(), 1);
        assert!(
            !is_rtcp(&[0x80, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            "RTP is not RTCP"
        );
        assert!(
            !is_rtcp(&[0x80, 0xe0, 0, 1, 0, 0, 0, 0]),
            "RTP pt 96 with marker"
        );
    }

    #[test]
    fn rtt_from_lsr_and_dlsr() {
        let sr_sent = middle32(0xE000_0000, 0x4000_0000); // some instant
        // reply held for 50 ms at the receiver, 20 ms each way
        let dlsr = (0.05 * 65536.0) as u32;
        let arrival = sr_sent.wrapping_add((0.09 * 65536.0) as u32);
        let blk = ReportBlock {
            lsr: sr_sent,
            dlsr,
            ..Default::default()
        };
        let r = rtt_ms(&blk, arrival).unwrap();
        assert!((r - 40.0).abs() < 0.1, "{r}");
        assert!(rtt_ms(&ReportBlock { lsr: 0, ..blk }, arrival).is_none());
        // reply claims to have been held longer than it took to come back
        assert!(
            rtt_ms(
                &ReportBlock {
                    dlsr: dlsr * 10,
                    ..blk
                },
                arrival
            )
            .is_none()
        );
    }

    #[test]
    fn ntp_middle_bits() {
        assert_eq!(middle32(0x0000_ABCD, 0x1234_0000), 0xABCD_1234);
        let (m, _) = ntp_now();
        assert!(m as u64 > NTP_UNIX_OFFSET);
    }
}
