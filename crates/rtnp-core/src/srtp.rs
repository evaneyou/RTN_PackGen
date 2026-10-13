//! SRTP (RFC 3711), profile `AES_CM_128_HMAC_SHA1_80`: AES-128 counter-mode encryption of the RTP
//! payload and a 10-byte HMAC-SHA1 authentication tag, with keys derived from a 16-byte master key
//! and a 14-byte master salt (key derivation rate 0).
//!
//! Scope: RTP only. RTCP stays unencrypted (SRTCP is not implemented), there is no replay window,
//! and keys are supplied by the user (or exchanged in SDP with SDES), not negotiated.

use std::collections::HashMap;
use std::fmt;

use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

/// Length of the authentication tag appended to every SRTP packet.
pub const TAG_LEN: usize = 10;
/// Master key (16) plus master salt (14).
pub const MASTER_LEN: usize = 30;

type Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// A master key and salt. `Debug` never prints the key material.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey([u8; MASTER_LEN]);

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl<'de> serde::Deserialize<'de> for MasterKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MasterKey::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl MasterKey {
    pub fn from_bytes(b: [u8; MASTER_LEN]) -> Self {
        MasterKey(b)
    }

    /// Parse 60 hex characters or the 40-character base64 form used by SDP `a=crypto` lines.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let bytes = if s.len() == MASTER_LEN * 2 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
            (0..MASTER_LEN)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
                .map_err(|_| Error::Config("invalid SRTP key".into()))?
        } else {
            B64.decode(s).map_err(|_| {
                Error::Config("SRTP key must be 60 hex or 40 base64 characters".into())
            })?
        };
        let arr: [u8; MASTER_LEN] = bytes.try_into().map_err(|_| {
            Error::Config(
                "SRTP key must be 30 bytes (16-byte key + 14-byte salt): 60 hex or 40 base64 characters"
                    .into(),
            )
        })?;
        Ok(MasterKey(arr))
    }

    /// A random key from the operating system's RNG.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; MASTER_LEN];
        rand::rng().fill_bytes(&mut b);
        MasterKey(b)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn session(&self) -> SessionKeys {
        derive(&self.0[..16], &self.0[16..])
    }
}

/// Session keys derived from a [`MasterKey`].
#[derive(Clone)]
pub struct SessionKeys {
    cipher_key: [u8; 16],
    salt: [u8; 14],
    auth_key: [u8; 20],
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

/// RFC 3711 section 4.3: `x = label || index DIV kdr` XOR master salt, keystream from AES-CM
/// with IV `x * 2^16`. With a key derivation rate of 0 the index term is zero.
fn kdf(master_key: &[u8], master_salt: &[u8], label: u8, out: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(master_salt);
    iv[7] ^= label;
    out.fill(0);
    let mut c = Ctr::new(
        GenericArray::from_slice(master_key),
        GenericArray::from_slice(&iv),
    );
    c.apply_keystream(out);
}

fn derive(master_key: &[u8], master_salt: &[u8]) -> SessionKeys {
    let mut k = SessionKeys {
        cipher_key: [0; 16],
        salt: [0; 14],
        auth_key: [0; 20],
    };
    kdf(master_key, master_salt, 0x00, &mut k.cipher_key);
    kdf(master_key, master_salt, 0x01, &mut k.auth_key);
    kdf(master_key, master_salt, 0x02, &mut k.salt);
    k
}

/// Length of the RTP header including CSRCs and an extension, if the packet is long enough.
fn header_len(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 12 || pkt[0] >> 6 != 2 {
        return None;
    }
    let cc = (pkt[0] & 0x0f) as usize;
    let mut len = 12 + cc * 4;
    if pkt[0] & 0x10 != 0 {
        let ext = pkt.get(len + 2..len + 4)?;
        len += 4 + u16::from_be_bytes([ext[0], ext[1]]) as usize * 4;
    }
    (pkt.len() >= len).then_some(len)
}

impl SessionKeys {
    /// Keystream IV for a packet: `(salt * 2^16) XOR (ssrc * 2^64) XOR (index * 2^16)`.
    fn iv(&self, ssrc: u32, index: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        for (i, b) in index.to_be_bytes()[2..].iter().enumerate() {
            iv[8 + i] ^= b;
        }
        iv
    }

    fn tag(&self, authenticated: &[u8], roc: u32) -> [u8; TAG_LEN] {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key).expect("HMAC accepts any key size");
        mac.update(authenticated);
        mac.update(&roc.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(&full[..TAG_LEN]);
        t
    }

    /// Encrypt the payload of the RTP packet in `buf[..len]` in place and append the tag.
    /// `buf` must have room for `len + TAG_LEN` bytes. `roc` is the rollover counter for the
    /// packet's sequence number. Returns the new length.
    pub fn protect(&self, buf: &mut [u8], len: usize, roc: u32) -> usize {
        let hl = header_len(&buf[..len]).expect("protect needs a valid RTP header");
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let index = ((roc as u64) << 16) | seq as u64;
        let iv = self.iv(ssrc, index);
        let mut c = Ctr::new(
            GenericArray::from_slice(&self.cipher_key),
            GenericArray::from_slice(&iv),
        );
        c.apply_keystream(&mut buf[hl..len]);
        let tag = self.tag(&buf[..len], roc);
        buf[len..len + TAG_LEN].copy_from_slice(&tag);
        len + TAG_LEN
    }

    /// Verify the tag and decrypt in place. Returns the plaintext RTP packet length, or `None`
    /// if the packet is malformed or fails authentication.
    pub fn unprotect(&self, buf: &mut [u8], roc: u32) -> Option<usize> {
        if buf.len() < 12 + TAG_LEN {
            return None;
        }
        let body = buf.len() - TAG_LEN;
        let hl = header_len(&buf[..body])?;
        let mut mac = HmacSha1::new_from_slice(&self.auth_key).expect("HMAC accepts any key size");
        mac.update(&buf[..body]);
        mac.update(&roc.to_be_bytes());
        // constant-time comparison of the (truncated) tag
        if mac.verify_truncated_left(&buf[body..]).is_err() {
            return None;
        }
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let index = ((roc as u64) << 16) | seq as u64;
        let iv = self.iv(ssrc, index);
        let mut c = Ctr::new(
            GenericArray::from_slice(&self.cipher_key),
            GenericArray::from_slice(&iv),
        );
        c.apply_keystream(&mut buf[hl..body]);
        Some(body)
    }
}

/// Resolve an SRTP master key from an inline value or a file (first line, trimmed).
pub fn load_key(inline: Option<&str>, file: Option<&std::path::Path>) -> Result<Option<MasterKey>> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(Error::Config(
            "use either --srtp-key or --srtp-key-file, not both".into(),
        )),
        (Some(k), None) => MasterKey::parse(k).map(Some),
        (None, Some(f)) => {
            let text = std::fs::read_to_string(f).map_err(|e| {
                Error::Config(format!("cannot read SRTP key file {}: {e}", f.display()))
            })?;
            MasterKey::parse(text.trim()).map(Some)
        }
        (None, None) => Ok(None),
    }
}

/// Sender-side packet counter: gives the rollover counter for each sequence number.
#[derive(Debug, Clone, Copy)]
pub struct TxIndex {
    first_seq: u16,
}

impl TxIndex {
    pub fn new(first_seq: u16) -> Self {
        TxIndex { first_seq }
    }

    /// Rollover counter for the `n`th packet (0-based) of the stream.
    pub fn roc(&self, n: u64) -> u32 {
        ((self.first_seq as u64 + n) >> 16) as u32
    }
}

/// Receiver-side state for one SSRC (RFC 3711 section 3.3.1 and appendix A).
#[derive(Debug, Default, Clone, Copy)]
struct RxState {
    s_l: Option<u16>,
    roc: u32,
}

impl RxState {
    /// Guess the rollover counter that goes with `seq`.
    fn guess_roc(&self, seq: u16) -> u32 {
        let Some(s_l) = self.s_l else {
            return self.roc;
        };
        if s_l < 32768 {
            if seq as i32 - s_l as i32 > 32768 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if s_l as i32 - 32768 > seq as i32 {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        }
    }

    fn update(&mut self, seq: u16, guessed: u32) {
        match self.s_l {
            None => {
                self.s_l = Some(seq);
                self.roc = guessed;
            }
            Some(s_l) => {
                if guessed > self.roc || (guessed == self.roc && seq > s_l) {
                    self.s_l = Some(seq);
                    self.roc = guessed;
                }
            }
        }
    }
}

/// Receiver side: keys plus rollover state per SSRC.
#[derive(Debug)]
pub struct SrtpReceiver {
    keys: SessionKeys,
    streams: HashMap<u32, RxState>,
}

/// Cap on tracked SSRCs so unauthenticated traffic cannot grow the table (only authenticated
/// packets create entries, and this bounds even those).
const MAX_STREAMS: usize = 4096;

impl SrtpReceiver {
    pub fn new(key: &MasterKey) -> Self {
        SrtpReceiver {
            keys: key.session(),
            streams: HashMap::new(),
        }
    }

    /// Authenticate and decrypt the packet in `buf` in place; returns the plaintext length.
    pub fn unprotect(&mut self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < 12 + TAG_LEN {
            return None;
        }
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let state = self.streams.get(&ssrc).copied().unwrap_or_default();
        let roc = state.guess_roc(seq);
        let len = self.keys.unprotect(buf, roc)?;
        if self.streams.len() >= MAX_STREAMS && !self.streams.contains_key(&ssrc) {
            return Some(len); // authenticated but untracked: no rollover state kept
        }
        let mut st = state;
        st.update(seq, roc);
        self.streams.insert(ssrc, st);
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // RFC 3711 appendix B.3: AES-CM key derivation with a key derivation rate of 0.
    #[test]
    fn key_derivation_matches_rfc3711_vectors() {
        let mk = unhex("E1F97A0D3E018BE0D64FA32C06DE4139");
        let ms = unhex("0EC675AD498AFEEBB6960B3AABE6");
        let k = derive(&mk, &ms);
        assert_eq!(
            k.cipher_key.to_vec(),
            unhex("C61E7A93744F39EE10734AFE3FF7A087")
        );
        assert_eq!(k.salt.to_vec(), unhex("30CBBC08863D8C85D49DB34A9AE1"));
        assert_eq!(
            k.auth_key.to_vec(),
            unhex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4")
        );
    }

    fn packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p[8..12].copy_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn protect_then_unprotect_round_trips() {
        let keys = MasterKey::random().session();
        let plain = packet(7, 0xdead_beef, &[0xd5; 240]);
        let mut buf = plain.clone();
        buf.resize(plain.len() + TAG_LEN, 0);
        let n = keys.protect(&mut buf, plain.len(), 0);
        assert_eq!(n, plain.len() + TAG_LEN);
        assert_eq!(&buf[..12], &plain[..12], "header stays in the clear");
        assert_ne!(&buf[12..plain.len()], &plain[12..], "payload is encrypted");
        let m = keys.unprotect(&mut buf[..n], 0).expect("authentic");
        assert_eq!(&buf[..m], &plain[..]);
    }

    #[test]
    fn tampering_and_wrong_keys_are_rejected() {
        let keys = MasterKey::random().session();
        let other = MasterKey::random().session();
        let plain = packet(1, 5, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut buf = plain.clone();
        buf.resize(plain.len() + TAG_LEN, 0);
        let n = keys.protect(&mut buf, plain.len(), 0);
        let mut flipped = buf[..n].to_vec();
        flipped[14] ^= 1;
        assert!(keys.unprotect(&mut flipped, 0).is_none());
        let mut wrong = buf[..n].to_vec();
        assert!(other.unprotect(&mut wrong, 0).is_none());
        let mut wrong_roc = buf[..n].to_vec();
        assert!(keys.unprotect(&mut wrong_roc, 1).is_none());
    }

    #[test]
    fn receiver_follows_sequence_rollover() {
        let key = MasterKey::random();
        let keys = key.session();
        let mut rx = SrtpReceiver::new(&key);
        let tx = TxIndex::new(65_530);
        for n in 0..20u64 {
            let seq = (65_530u64 + n) as u16;
            let plain = packet(seq, 99, &[0x55; 160]);
            let mut buf = plain.clone();
            buf.resize(plain.len() + TAG_LEN, 0);
            let len = keys.protect(&mut buf, plain.len(), tx.roc(n));
            let got = rx
                .unprotect(&mut buf[..len])
                .expect("authentic across the wrap");
            assert_eq!(&buf[..got], &plain[..], "packet {n}");
        }
    }

    #[test]
    fn key_parsing_accepts_hex_and_base64() {
        let k = MasterKey::random();
        assert_eq!(MasterKey::parse(&k.to_hex()).unwrap(), k);
        assert_eq!(MasterKey::parse(&k.to_base64()).unwrap(), k);
        assert!(MasterKey::parse("abcd").is_err());
        assert!(format!("{k:?}").contains("redacted"));
    }
}
