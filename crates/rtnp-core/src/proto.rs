//! Versioned wire format carried at the start of every generated packet/frame.
//!
//! ```text
//!  0      2    3     4          8          12         20         28       32
//!  +------+----+-----+----------+----------+----------+----------+--------+
//!  |magic |ver |flags| session  |  flow    |   seq    | tx_ns    |  len   |
//!  +------+----+-----+----------+----------+----------+----------+--------+
//! ```
//! All integers are big-endian. `len` is the total packet length including this
//! header, which lets TCP receivers reframe the byte stream. Bytes after the
//! header are padding.

use crate::error::{Error, Result};

pub const MAGIC: u16 = 0x4454; // "DT"
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
/// Set by a sender that wants the receiver to reflect the packet (round-trip metering).
pub const FLAG_ECHO_REQ: u8 = 0x01;
/// Set on a reflected packet.
pub const FLAG_ECHO_REPLY: u8 = 0x02;
pub const RTP_HEADER_LEN: usize = 12;
/// Largest UDP payload over IPv4.
pub const MAX_UDP_PACKET: usize = 65_507;
/// Largest TCP frame the receiver will accept.
pub const MAX_TCP_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub session: u32,
    pub flow: u32,
    pub seq: u64,
    pub tx_ns: u64,
    pub len: u32,
}

impl Header {
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HEADER_LEN, "buffer smaller than header");
        buf[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        buf[2] = VERSION;
        buf[3] = self.flags;
        buf[4..8].copy_from_slice(&self.session.to_be_bytes());
        buf[8..12].copy_from_slice(&self.flow.to_be_bytes());
        buf[12..20].copy_from_slice(&self.seq.to_be_bytes());
        buf[20..28].copy_from_slice(&self.tx_ns.to_be_bytes());
        buf[28..32].copy_from_slice(&self.len.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Header> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Protocol(format!(
                "short packet ({} bytes)",
                buf.len()
            )));
        }
        if u16::from_be_bytes([buf[0], buf[1]]) != MAGIC {
            return Err(Error::Protocol("bad magic".into()));
        }
        if buf[2] != VERSION {
            return Err(Error::Protocol(format!("unsupported version {}", buf[2])));
        }
        let u32_at = |i: usize| u32::from_be_bytes(buf[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_be_bytes(buf[i..i + 8].try_into().unwrap());
        let h = Header {
            flags: buf[3],
            session: u32_at(4),
            flow: u32_at(8),
            seq: u64_at(12),
            tx_ns: u64_at(20),
            len: u32_at(28),
        };
        if (h.len as usize) < HEADER_LEN {
            return Err(Error::Protocol(format!("invalid length field {}", h.len)));
        }
        Ok(h)
    }
}

/// Write a minimal RTP (RFC 3550) fixed header: version 2, no padding/extension/CSRC.
pub fn write_rtp(out: &mut [u8], payload_type: u8, marker: bool, seq: u16, ts: u32, ssrc: u32) {
    out[0] = 0x80;
    out[1] = (payload_type & 0x7f) | if marker { 0x80 } else { 0 };
    out[2..4].copy_from_slice(&seq.to_be_bytes());
    out[4..8].copy_from_slice(&ts.to_be_bytes());
    out[8..12].copy_from_slice(&ssrc.to_be_bytes());
}

/// Parsed fixed RTP header (RFC 3550); CSRCs and extensions are skipped over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub payload_type: u8,
    pub marker: bool,
    pub seq: u16,
    pub ts: u32,
    pub ssrc: u32,
    /// Offset of the payload within the packet.
    pub payload_offset: usize,
}

impl RtpHeader {
    /// Returns `None` unless the buffer starts with a well-formed version-2 RTP header.
    pub fn parse(buf: &[u8]) -> Option<RtpHeader> {
        if buf.len() < RTP_HEADER_LEN || buf[0] >> 6 != 2 {
            return None;
        }
        let csrc = (buf[0] & 0x0f) as usize;
        let mut off = RTP_HEADER_LEN + csrc * 4;
        if buf[0] & 0x10 != 0 {
            let ext = buf.get(off + 2..off + 4)?;
            off += 4 + u16::from_be_bytes([ext[0], ext[1]]) as usize * 4;
        }
        if off > buf.len() {
            return None;
        }
        Some(RtpHeader {
            payload_type: buf[1] & 0x7f,
            marker: buf[1] & 0x80 != 0,
            seq: u16::from_be_bytes([buf[2], buf[3]]),
            ts: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ssrc: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            payload_offset: off,
        })
    }
}

/// RTP clock rate implied by a payload type (static audio types use 8 kHz, video and dynamic
/// types 90 kHz, as is conventional).
pub fn rtp_clock_hz(payload_type: u8) -> f64 {
    match payload_type {
        0..=13 | 15..=18 => 8000.0,
        _ => 90_000.0,
    }
}

/// SSRC of the return stream of a bidirectional call.
pub fn reverse_ssrc(session: u32, flow: u32) -> u32 {
    ssrc_for(session, flow) ^ 0x5a5a_5a5a
}

/// SSRC a sender uses for a flow in plain-RTP mode; announced to the receiver on the control
/// channel so it can attribute the stream to the right session and flow.
pub fn ssrc_for(session: u32, flow: u32) -> u32 {
    session ^ flow.rotate_left(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = Header {
            flags: 0,
            session: 0xdead_beef,
            flow: 3,
            seq: 42,
            tx_ns: 1_700_000_000_123_456_789,
            len: 172,
        };
        let mut buf = [0u8; 64];
        h.encode(&mut buf);
        assert_eq!(Header::decode(&buf).unwrap(), h);
    }

    #[test]
    fn rtp_header_layout() {
        let mut b = [0u8; 12];
        write_rtp(&mut b, 18, true, 0x0102, 0x0a0b0c0d, 0xdeadbeef);
        assert_eq!(b[0], 0x80);
        assert_eq!(b[1], 0x80 | 18);
        assert_eq!(&b[2..4], &[1, 2]);
        assert_eq!(&b[4..8], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(&b[8..12], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rtp_parse_roundtrip_and_extensions() {
        let mut b = [0u8; 20];
        write_rtp(&mut b, 96, true, 65535, 7, 0x01020304);
        let h = RtpHeader::parse(&b).unwrap();
        assert_eq!(
            (h.payload_type, h.marker, h.seq, h.ts),
            (96, true, 65535, 7)
        );
        assert_eq!((h.ssrc, h.payload_offset), (0x01020304, 12));
        // one CSRC and a one-word extension
        let mut c = [0u8; 40];
        write_rtp(&mut c, 0, false, 1, 2, 3);
        c[0] |= 0x10 | 1;
        c[12 + 4 + 3] = 1; // extension length = 1 word
        assert_eq!(RtpHeader::parse(&c).unwrap().payload_offset, 12 + 4 + 4 + 4);
        assert!(RtpHeader::parse(&[0x40; 20]).is_none()); // version 1 (and our own magic)
        assert!(RtpHeader::parse(&[0x80; 5]).is_none());
        assert_eq!(rtp_clock_hz(0), 8000.0);
        assert_eq!(rtp_clock_hz(96), 90_000.0);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Header::decode(&[0u8; 10]).is_err());
        assert!(Header::decode(&[0u8; 40]).is_err());
        let mut buf = [0u8; 40];
        Header {
            flags: 0,
            session: 1,
            flow: 1,
            seq: 0,
            tx_ns: 0,
            len: 5,
        }
        .encode(&mut buf);
        assert!(Header::decode(&buf).is_err());
    }
}
