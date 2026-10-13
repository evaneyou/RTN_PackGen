//! Flow specifications (TOML scripts / CLI) and their resolved form.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::dist::Dist;
use crate::error::{Error, Result};
use crate::preset;
use crate::util::{hex_decode, hex_encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Udp,
    Tcp,
    Icmp,
    /// One-to-one (stream-style) SCTP, framed like TCP. Needs kernel SCTP support.
    Sctp,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Icmp => "icmp",
            Proto::Sctp => "sctp",
        }
    }

    /// Byte-stream transports that use length-framed packets.
    pub fn is_stream(&self) -> bool {
        matches!(self, Proto::Tcp | Proto::Sctp)
    }
}

impl FromStr for Proto {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(Proto::Udp),
            "tcp" => Ok(Proto::Tcp),
            "icmp" => Ok(Proto::Icmp),
            "sctp" => Ok(Proto::Sctp),
            _ => Err(Error::Config(format!(
                "unknown protocol '{s}' (udp, tcp, icmp, sctp)"
            ))),
        }
    }
}

/// What the receiver measures: one-way delay (needs synchronised clocks) or round trip
/// (the receiver reflects every packet and the sender times it on its own clock).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Meter {
    #[default]
    Owd,
    Rtt,
}

impl FromStr for Meter {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "owd" => Ok(Meter::Owd),
            "rtt" => Ok(Meter::Rtt),
            _ => Err(Error::Config(format!("unknown meter '{s}' (owd, rtt)"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// G.711 µ-law (PCMU, payload type 0)
    G711,
    /// G.711 A-law (PCMA, payload type 8)
    G711a,
    G729,
    G723,
}

impl Codec {
    pub fn payload_type(self) -> u8 {
        match self {
            Codec::G711 => 0,
            Codec::G711a => 8,
            Codec::G729 => 18,
            Codec::G723 => 4,
        }
    }

    /// Codec payload bytes per millisecond of audio (G.723.1 is fixed-frame, see `frame`).
    fn bytes_per_ms(self) -> Option<usize> {
        match self {
            Codec::G711 | Codec::G711a => Some(8),
            Codec::G729 => Some(1),
            Codec::G723 => None,
        }
    }

    /// Usual packetisation: (ptime ms, UDP payload bytes with a 12-byte RTP header).
    pub fn default_packet(self) -> (f64, usize) {
        match self {
            Codec::G711 | Codec::G711a => (20.0, 172),
            Codec::G729 => (20.0, 32),
            Codec::G723 => (30.0, 36),
        }
    }

    /// The byte value the codec uses for digital silence, if it has a simple one.
    pub fn silence_byte(self) -> Option<u8> {
        match self {
            Codec::G711 => Some(0xff),
            Codec::G711a => Some(0xd5),
            _ => None,
        }
    }

    /// Payload bytes for `ptime_ms` of audio, if this codec supports choosing the ptime.
    fn payload_for_ptime(self, ptime_ms: f64) -> Result<usize> {
        let per_ms = self.bytes_per_ms().ok_or_else(|| {
            Error::Config("ptime cannot be changed for G.723.1 (fixed 30 ms frames)".into())
        })?;
        let step = if self == Codec::G729 { 10.0 } else { 1.0 };
        if !(ptime_ms.is_finite()
            && (10.0..=200.0).contains(&ptime_ms)
            && (ptime_ms / step).fract() == 0.0)
        {
            return Err(Error::Config(format!(
                "ptime must be a whole number of milliseconds between 10 and 200{}",
                if step > 1.0 {
                    " (multiple of 10 for G.729)"
                } else {
                    ""
                }
            )));
        }
        Ok(ptime_ms as usize * per_ms)
    }
}

impl FromStr for Codec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "g711" | "g711u" | "pcmu" => Ok(Codec::G711),
            "g711a" | "pcma" => Ok(Codec::G711a),
            "g729" => Ok(Codec::G729),
            "g723" => Ok(Codec::G723),
            _ => Err(Error::Config(format!(
                "unknown codec '{s}' (g711, g711a, g729, g723)"
            ))),
        }
    }
}

/// How packets are laid out on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Wire {
    /// Our 32-byte measurement header first (optionally followed by an RTP header). Gives
    /// one-way delay, round-trip metering and exact sequence/timestamp bookkeeping.
    #[default]
    Rtnp,
    /// Plain RTP (RFC 3550) and nothing else: the UDP payload is exactly an RTP packet, as a
    /// real VoIP phone or video encoder would send. UDP only; no round-trip metering.
    Rtp,
}

impl FromStr for Wire {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rtnp" => Ok(Wire::Rtnp),
            "rtp" => Ok(Wire::Rtp),
            _ => Err(Error::Config(format!(
                "unknown wire format '{s}' (rtnp, rtp)"
            ))),
        }
    }
}

/// Synthetic video: frames at a fixed rate, one large I-frame per GOP followed by smaller
/// P-frames, each frame split into RTP packets of at most `payload_bytes`. All packets of a
/// frame share a timestamp (90 kHz clock) and the last one has the marker bit set. Packets of
/// a frame are sent back to back, as most encoders/packetisers do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VideoSpec {
    pub fps: f64,
    /// Frames per group of pictures (one I-frame, the rest P-frames).
    pub gop: u32,
    /// I-frame size distribution in bytes.
    pub i_bytes: Dist,
    /// P-frame size distribution in bytes.
    pub p_bytes: Dist,
    /// Maximum RTP payload per packet (the packet is 12 bytes larger).
    pub payload_bytes: usize,
    /// RTP payload type (dynamic range 96-127).
    pub payload_type: u8,
}

impl Default for VideoSpec {
    fn default() -> Self {
        VideoSpec {
            fps: 30.0,
            gop: 30,
            i_bytes: Dist::Normal {
                mean: 30_000.0,
                std_dev: 3_000.0,
            },
            p_bytes: Dist::Normal {
                mean: 4_000.0,
                std_dev: 1_200.0,
            },
            payload_bytes: 1200,
            payload_type: 96,
        }
    }
}

impl VideoSpec {
    pub fn validate(&self) -> Result<()> {
        if !(self.fps.is_finite() && self.fps > 0.0 && self.fps <= 240.0) {
            return Err(Error::Config("video fps must be between 0 and 240".into()));
        }
        if self.gop == 0 {
            return Err(Error::Config("video gop must be at least 1".into()));
        }
        if !(100..=1400).contains(&self.payload_bytes) {
            return Err(Error::Config(
                "video payload_bytes must be between 100 and 1400".into(),
            ));
        }
        if !(96..=127).contains(&self.payload_type) {
            return Err(Error::Config(
                "video payload_type must be in the dynamic range 96-127".into(),
            ));
        }
        self.i_bytes.build()?;
        self.p_bytes.build()?;
        Ok(())
    }
}

/// Packet body content after the headers.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Zero,
    Random,
    /// Repeated byte pattern, written as hex (`pattern:deadbeef`).
    Pattern(Vec<u8>),
    /// Contents of a local file, repeated as needed (`file:/path`).
    File(String),
}

impl FromStr for Payload {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        match s.to_ascii_lowercase().as_str() {
            "zero" => return Ok(Payload::Zero),
            "random" => return Ok(Payload::Random),
            _ => {}
        }
        if let Some(h) = s.strip_prefix("pattern:") {
            let bytes = hex_decode(h).filter(|b| !b.is_empty()).ok_or_else(|| {
                Error::Config("pattern must be non-empty hex, e.g. pattern:deadbeef".into())
            })?;
            return Ok(Payload::Pattern(bytes));
        }
        if let Some(p) = s.strip_prefix("file:") {
            if p.is_empty() {
                return Err(Error::Config("file payload needs a path".into()));
            }
            return Ok(Payload::File(p.to_string()));
        }
        Err(Error::Config(format!(
            "unknown payload '{s}' (zero, random, pattern:<hex>, file:<path>)"
        )))
    }
}

impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Payload::Zero => write!(f, "zero"),
            Payload::Random => write!(f, "random"),
            Payload::Pattern(b) => write!(f, "pattern:{}", hex_encode(b)),
            Payload::File(p) => write!(f, "file:{p}"),
        }
    }
}

impl Serialize for Payload {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// User-facing description of one flow. Every field except `target` is optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSpec {
    pub name: Option<String>,
    pub proto: Option<Proto>,
    /// `host:port` for UDP/TCP/SCTP, `host` (or `host:0`) for ICMP.
    pub target: String,
    pub preset: Option<String>,
    /// Inter-departure time distribution in milliseconds.
    pub idt_ms: Option<Dist>,
    /// Packet size distribution in bytes (total payload including the 32-byte header).
    pub size: Option<Dist>,
    /// Shorthand for a constant IDT of `1000 / rate_pps` ms.
    pub rate_pps: Option<f64>,
    pub duration_ms: Option<u64>,
    pub count: Option<u64>,
    pub max_bytes: Option<u64>,
    /// Run until stopped (Ctrl-C or the caller's stop signal) instead of for a fixed time.
    /// Conflicts with `duration_ms`, `count` and `max_bytes`; use interval reports to watch it.
    #[serde(default)]
    pub forever: bool,
    #[serde(default)]
    pub start_delay_ms: u64,
    pub ttl: Option<u32>,
    pub tos: Option<u8>,
    pub seed: Option<u64>,
    /// `owd` (default) or `rtt`.
    pub meter: Option<Meter>,
    /// `zero` (default), `random`, `pattern:<hex>` or `file:<path>`.
    pub payload: Option<Payload>,
    /// Write an RTP header for this codec (UDP only; payload type follows the codec).
    pub rtp: Option<Codec>,
    /// Packetisation time in ms for `rtp` voice (G.711: 10-200, G.729: multiples of 10):
    /// sets both the packet interval and the payload size. Conflicts with idt_ms/size/rate_pps.
    pub ptime_ms: Option<f64>,
    /// A two-way call: the receiver sends its own constant RTP stream back to this flow's source
    /// address for as long as the flow runs. Plain-RTP voice only (no VAD); needs the control
    /// channel and a receiver started with `--allow-reverse`.
    #[serde(default)]
    pub bidirectional: bool,
    /// Plain-RTP flows send an RTCP sender report this often (ms, default 5000, 0 = off) and the
    /// receiver answers, which yields a standard round-trip time (RFC 3550) with no clock sync.
    pub rtcp_interval_ms: Option<u64>,
    /// Set the RTP marker bit on the first packet of the stream, as most phones do. Plain-RTP
    /// voice only; off by default. (VAD already marks the start of each talkspurt.)
    #[serde(default)]
    pub first_marker: bool,
    /// `rtnp` (default) or `rtp`: plain RTP on the wire, see [`Wire::Rtp`].
    pub wire: Option<Wire>,
    /// Synthetic video stream (implies `wire = "rtp"`); see [`VideoSpec`].
    pub video: Option<VideoSpec>,
    /// Voice-activity detection: alternate talkspurts and silences.
    #[serde(default)]
    pub vad: bool,
    /// Talkspurt length distribution in ms (default `exp:1004`).
    pub vad_talk_ms: Option<Dist>,
    /// Silence length distribution in ms (default `exp:1587`).
    pub vad_silence_ms: Option<Dist>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    #[serde(default)]
    pub flow: Vec<FlowSpec>,
}

impl Script {
    pub fn from_toml(text: &str) -> Result<Script> {
        let s: Script = toml::from_str(text)?;
        if s.flow.is_empty() {
            return Err(Error::Config("script contains no [[flow]] entries".into()));
        }
        Ok(s)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StopCond {
    pub duration: Option<Duration>,
    pub count: Option<u64>,
    pub bytes: Option<u64>,
}

/// Resolved packet body source.
#[derive(Debug, Clone)]
pub enum PayloadData {
    Zero,
    Bytes(Arc<Vec<u8>>),
}

#[derive(Debug, Clone)]
pub struct ResolvedFlow {
    pub name: String,
    pub proto: Proto,
    pub target: String,
    pub idt_ms: Dist,
    pub size: Dist,
    pub stop: StopCond,
    pub start_delay: Duration,
    pub ttl: Option<u32>,
    pub tos: Option<u8>,
    pub seed: Option<u64>,
    pub meter: Meter,
    pub payload: PayloadData,
    pub rtp: Option<Codec>,
    /// (talkspurt ms, silence ms) when VAD is on.
    pub vad: Option<(Dist, Dist)>,
    pub wire: Wire,
    pub video: Option<VideoSpec>,
    pub bidirectional: bool,
    /// RTCP sender-report period (plain RTP only).
    pub rtcp_interval: Option<Duration>,
    /// Mark the first RTP packet of the stream (plain-RTP voice only).
    pub first_marker: bool,
}

/// Restrictions applied when resolving flows that came from an untrusted peer.
#[derive(Debug, Clone)]
pub struct ResolveOpts {
    /// Whether `file:` payloads may read local files.
    pub allow_file_payload: bool,
    /// Upper bound applied to every flow's duration (flows without one get this value).
    pub max_duration: Option<Duration>,
}

impl Default for ResolveOpts {
    fn default() -> Self {
        ResolveOpts {
            allow_file_payload: true,
            max_duration: None,
        }
    }
}

/// Defaults: 1000 pps, 512-byte packets, 10 s.
const DEFAULT_IDT_MS: f64 = 1.0;
const DEFAULT_SIZE: f64 = 512.0;
const DEFAULT_DURATION: Duration = Duration::from_secs(10);
const RANDOM_PAYLOAD_LEN: usize = 64 * 1024;
const MAX_PAYLOAD_FILE: u64 = 16 * 1024 * 1024;

impl FlowSpec {
    pub fn resolve(&self, index: usize) -> Result<ResolvedFlow> {
        self.resolve_with(index, &ResolveOpts::default())
    }

    pub fn resolve_with(&self, index: usize, opts: &ResolveOpts) -> Result<ResolvedFlow> {
        let preset = match &self.preset {
            Some(p) => Some(preset::lookup(p).ok_or_else(|| {
                let names: Vec<_> = preset::all().iter().map(|p| p.name).collect();
                Error::Config(format!(
                    "unknown preset '{p}' (available: {})",
                    names.join(", ")
                ))
            })?),
            None => None,
        };

        if self.rate_pps.is_some() && self.idt_ms.is_some() {
            return Err(Error::Config(
                "specify either rate_pps or idt_ms, not both".into(),
            ));
        }

        let proto = self
            .proto
            .or(preset.as_ref().map(|p| p.proto))
            .unwrap_or(Proto::Udp);

        let video = self.video.clone();
        let wire = self.wire.unwrap_or(if video.is_some() {
            Wire::Rtp
        } else {
            Wire::Rtnp
        });

        let rtp_audio = wire == Wire::Rtp && video.is_none();
        let codec_default = |c: Codec| {
            let (ptime, size) = c.default_packet();
            (ptime, size as f64)
        };
        // Header bytes that precede the codec payload on this wire.
        let header_bytes = if wire == Wire::Rtp {
            crate::proto::RTP_HEADER_LEN
        } else {
            crate::proto::HEADER_LEN + crate::proto::RTP_HEADER_LEN
        };
        let ptime_codec = self.rtp.or(preset.as_ref().and_then(|p| p.rtp));
        let ptime_dists = match (self.ptime_ms, ptime_codec) {
            (None, _) => None,
            (Some(_), None) => {
                return Err(Error::Config("ptime needs an rtp codec".into()));
            }
            (Some(p), Some(c)) => {
                if self.idt_ms.is_some() || self.size.is_some() || self.rate_pps.is_some() {
                    return Err(Error::Config(
                        "ptime sets the packet interval and size: drop idt_ms, size and rate_pps"
                            .into(),
                    ));
                }
                let payload = c.payload_for_ptime(p)?;
                Some((
                    Dist::Constant { value: p },
                    Dist::Constant {
                        value: (header_bytes + payload) as f64,
                    },
                ))
            }
        };

        let idt_ms = if let Some((idt, _)) = &ptime_dists {
            idt.clone()
        } else if let Some(rate) = self.rate_pps {
            if !(rate.is_finite() && rate > 0.0) {
                return Err(Error::Config("rate_pps must be a positive number".into()));
            }
            Dist::Constant {
                value: 1000.0 / rate,
            }
        } else if let Some(d) = &self.idt_ms {
            d.clone()
        } else if let Some(p) = &preset {
            p.idt_ms.clone()
        } else if let (true, Some(c)) = (rtp_audio, self.rtp) {
            Dist::Constant {
                value: codec_default(c).0,
            }
        } else {
            Dist::Constant {
                value: DEFAULT_IDT_MS,
            }
        };

        // Preset sizes include our 32-byte header; on a plain-RTP wire that header is absent.
        let preset_size = preset.as_ref().map(|p| match (&p.size, rtp_audio, p.rtp) {
            (Dist::Constant { value }, true, Some(_)) => Dist::Constant {
                value: value - crate::proto::HEADER_LEN as f64,
            },
            (d, _, _) => d.clone(),
        });
        let size = self
            .size
            .clone()
            .or(ptime_dists.map(|(_, size)| size))
            .or(preset_size)
            .or_else(|| {
                self.rtp.filter(|_| rtp_audio).map(|c| Dist::Constant {
                    value: codec_default(c).1,
                })
            })
            .unwrap_or(Dist::Constant {
                value: DEFAULT_SIZE,
            });

        idt_ms.build()?;
        size.build()?;

        if let Some(t) = self.ttl
            && (t == 0 || t > 255)
        {
            return Err(Error::Config("ttl must be between 1 and 255".into()));
        }

        let rtp = self.rtp.or(preset.as_ref().and_then(|p| p.rtp));
        if rtp.is_some() && proto != Proto::Udp {
            return Err(Error::Config("rtp is only supported over udp".into()));
        }

        if wire == Wire::Rtp {
            if proto != Proto::Udp {
                return Err(Error::Config(
                    "wire = rtp is only supported over udp".into(),
                ));
            }
            if self.meter.unwrap_or_default() == Meter::Rtt {
                return Err(Error::Config(
                    "round-trip metering needs our own header: use wire = rtnp".into(),
                ));
            }
            if video.is_none() && rtp.is_none() {
                return Err(Error::Config(
                    "wire = rtp needs a codec (rtp = g711|g729|g723) or a video stream".into(),
                ));
            }
        }
        let rtcp_interval = match self.rtcp_interval_ms {
            Some(_) if wire != Wire::Rtp => {
                return Err(Error::Config("rtcp_interval needs wire = rtp".into()));
            }
            Some(0) => None,
            Some(ms) if ms < 100 => {
                return Err(Error::Config(
                    "rtcp_interval must be 0 or at least 100 ms".into(),
                ));
            }
            Some(ms) => Some(Duration::from_millis(ms)),
            None => (wire == Wire::Rtp).then_some(Duration::from_secs(5)),
        };
        if self.first_marker && (wire != Wire::Rtp || video.is_some() || rtp.is_none()) {
            return Err(Error::Config(
                "first_marker needs plain-RTP voice (wire = rtp and an rtp codec)".into(),
            ));
        }
        if self.bidirectional {
            if wire != Wire::Rtp || video.is_some() || rtp.is_none() {
                return Err(Error::Config(
                    "bidirectional calls need plain-RTP voice (wire = rtp and an rtp codec)".into(),
                ));
            }
            if !matches!(idt_ms, Dist::Constant { .. }) || !matches!(size, Dist::Constant { .. }) {
                return Err(Error::Config(
                    "a bidirectional call needs a constant packet interval and size (use ptime)"
                        .into(),
                ));
            }
            if self.vad {
                return Err(Error::Config(
                    "a bidirectional call is constant in both directions: vad does not apply"
                        .into(),
                ));
            }
        }
        if let Some(v) = &video {
            v.validate()?;
            if wire != Wire::Rtp {
                return Err(Error::Config("video streams need wire = rtp".into()));
            }
            if self.rtp.is_some()
                || self.vad
                || self.idt_ms.is_some()
                || self.size.is_some()
                || self.rate_pps.is_some()
            {
                return Err(Error::Config(
                    "video flows are shaped by the video settings: rtp, vad, idt_ms, size and rate_pps do not apply".into(),
                ));
            }
        }

        let vad = if self.vad {
            let talk = self
                .vad_talk_ms
                .clone()
                .unwrap_or(Dist::Exponential { mean: 1004.0 });
            let silence = self
                .vad_silence_ms
                .clone()
                .unwrap_or(Dist::Exponential { mean: 1587.0 });
            talk.build()?;
            silence.build()?;
            Some((talk, silence))
        } else if self.vad_talk_ms.is_some() || self.vad_silence_ms.is_some() {
            return Err(Error::Config(
                "vad_talk_ms / vad_silence_ms require vad = true".into(),
            ));
        } else {
            None
        };

        let mut stop = StopCond {
            duration: self.duration_ms.map(Duration::from_millis),
            count: self.count,
            bytes: self.max_bytes,
        };
        if self.forever {
            if stop.duration.is_some() || stop.count.is_some() || stop.bytes.is_some() {
                return Err(Error::Config(
                    "forever cannot be combined with duration, count or max_bytes".into(),
                ));
            }
            if opts.max_duration.is_some() {
                return Err(Error::Config(
                    "open-ended flows are not allowed for this flow source".into(),
                ));
            }
        } else {
            if stop.duration.is_none() && stop.count.is_none() && stop.bytes.is_none() {
                stop.duration = Some(DEFAULT_DURATION);
            }
            if let Some(cap) = opts.max_duration {
                stop.duration = Some(stop.duration.map_or(cap, |d| d.min(cap)));
            }
        }

        if self.target.trim().is_empty() {
            return Err(Error::Config("flow target is empty".into()));
        }

        // Plain-RTP voice defaults to the codec's digital silence, not raw zeros.
        let silence = if wire == Wire::Rtp {
            rtp.and_then(|c| c.silence_byte())
        } else {
            None
        };
        let payload = match self.payload.clone().unwrap_or_else(|| match silence {
            Some(b) => Payload::Pattern(vec![b]),
            None => Payload::Zero,
        }) {
            Payload::Zero => PayloadData::Zero,
            Payload::Random => {
                let mut rng = StdRng::seed_from_u64(self.seed.unwrap_or_else(rand::random));
                let mut v = vec![0u8; RANDOM_PAYLOAD_LEN];
                rng.fill(&mut v[..]);
                PayloadData::Bytes(Arc::new(v))
            }
            Payload::Pattern(b) => PayloadData::Bytes(Arc::new(b)),
            Payload::File(path) => {
                if !opts.allow_file_payload {
                    return Err(Error::Config(
                        "file payloads are not allowed for this flow source".into(),
                    ));
                }
                let meta = std::fs::metadata(Path::new(&path))
                    .map_err(|e| Error::Config(format!("payload file '{path}': {e}")))?;
                if meta.len() == 0 || meta.len() > MAX_PAYLOAD_FILE {
                    return Err(Error::Config(format!(
                        "payload file '{path}' must be between 1 byte and {MAX_PAYLOAD_FILE} bytes"
                    )));
                }
                let data = std::fs::read(&path)
                    .map_err(|e| Error::Config(format!("payload file '{path}': {e}")))?;
                PayloadData::Bytes(Arc::new(data))
            }
        };

        Ok(ResolvedFlow {
            name: self
                .name
                .clone()
                .unwrap_or_else(|| format!("flow{}", index + 1)),
            proto,
            target: self.target.clone(),
            idt_ms,
            size,
            stop,
            start_delay: Duration::from_millis(self.start_delay_ms),
            ttl: self.ttl,
            tos: self.tos,
            seed: self.seed,
            meter: self.meter.unwrap_or_default(),
            payload,
            rtp,
            vad,
            wire,
            video,
            bidirectional: self.bidirectional,
            rtcp_interval,
            first_marker: self.first_marker,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_roundtrip_and_defaults() {
        let s = Script::from_toml(
            r#"
            [[flow]]
            target = "127.0.0.1:8998"
            preset = "voip-g711"
            duration_ms = 2000

            [[flow]]
            name = "bulk"
            proto = "tcp"
            target = "127.0.0.1:8998"
            rate_pps = 500
            size = "normal:700,150"
            count = 1000
            "#,
        )
        .unwrap();
        let a = s.flow[0].resolve(0).unwrap();
        assert_eq!(a.proto, Proto::Udp);
        assert_eq!(a.idt_ms, Dist::Constant { value: 20.0 });
        assert_eq!(a.rtp, Some(Codec::G711));
        assert_eq!(a.stop.duration, Some(Duration::from_secs(2)));
        let b = s.flow[1].resolve(1).unwrap();
        assert_eq!(b.proto, Proto::Tcp);
        assert_eq!(b.idt_ms, Dist::Constant { value: 2.0 });
        assert_eq!(b.stop.count, Some(1000));
    }

    #[test]
    fn rejects_conflicts_and_unknowns() {
        let both = FlowSpec {
            target: "x:1".into(),
            rate_pps: Some(10.0),
            idt_ms: Some(Dist::Constant { value: 5.0 }),
            ..Default::default()
        };
        assert!(both.resolve(0).is_err());
        let bad_preset = FlowSpec {
            target: "x:1".into(),
            preset: Some("nope".into()),
            ..Default::default()
        };
        assert!(bad_preset.resolve(0).is_err());
        assert!(Script::from_toml("[[flow]]\ntarget='x:1'\nbogus=1").is_err());
        let rtp_tcp = FlowSpec {
            target: "x:1".into(),
            proto: Some(Proto::Tcp),
            rtp: Some(Codec::G711),
            ..Default::default()
        };
        assert!(rtp_tcp.resolve(0).is_err());
        let orphan_vad = FlowSpec {
            target: "x:1".into(),
            vad_talk_ms: Some(Dist::Constant { value: 100.0 }),
            ..Default::default()
        };
        assert!(orphan_vad.resolve(0).is_err());
    }

    #[test]
    fn default_stop_is_ten_seconds() {
        let f = FlowSpec {
            target: "x:1".into(),
            ..Default::default()
        }
        .resolve(0)
        .unwrap();
        assert_eq!(f.stop.duration, Some(Duration::from_secs(10)));
    }

    #[test]
    fn payload_parsing_and_untrusted_restrictions() {
        assert_eq!("zero".parse::<Payload>().unwrap(), Payload::Zero);
        assert_eq!(
            "pattern:dead".parse::<Payload>().unwrap(),
            Payload::Pattern(vec![0xde, 0xad])
        );
        assert!("pattern:xyz".parse::<Payload>().is_err());
        assert!("bogus".parse::<Payload>().is_err());

        let spec = FlowSpec {
            target: "x:1".into(),
            payload: Some(Payload::File("/etc/hostname".into())),
            ..Default::default()
        };
        let untrusted = ResolveOpts {
            allow_file_payload: false,
            max_duration: Some(Duration::from_secs(5)),
        };
        assert!(spec.resolve_with(0, &untrusted).is_err());

        let long = FlowSpec {
            target: "x:1".into(),
            duration_ms: Some(3_600_000),
            ..Default::default()
        };
        let r = long.resolve_with(0, &untrusted).unwrap();
        assert_eq!(r.stop.duration, Some(Duration::from_secs(5)));
    }

    #[test]
    fn forever_rules() {
        let f = FlowSpec {
            target: "x:1".into(),
            forever: true,
            ..Default::default()
        };
        let r = f.resolve(0).unwrap();
        assert!(r.stop.duration.is_none() && r.stop.count.is_none() && r.stop.bytes.is_none());
        let with_limit = FlowSpec {
            count: Some(5),
            ..f.clone()
        };
        assert!(with_limit.resolve(0).is_err());
        let untrusted = ResolveOpts {
            allow_file_payload: false,
            max_duration: Some(Duration::from_secs(5)),
        };
        assert!(f.resolve_with(0, &untrusted).is_err());
    }

    #[test]
    fn rtcp_defaults_to_five_seconds_and_first_marker_needs_rtp_voice() {
        let voice = FlowSpec {
            target: "x:1".into(),
            rtp: Some(Codec::G711a),
            wire: Some(Wire::Rtp),
            ..Default::default()
        };
        assert_eq!(
            voice.resolve(0).unwrap().rtcp_interval,
            Some(Duration::from_secs(5))
        );
        let off = FlowSpec {
            rtcp_interval_ms: Some(0),
            ..voice.clone()
        };
        assert_eq!(off.resolve(0).unwrap().rtcp_interval, None);
        let marked = FlowSpec {
            first_marker: true,
            ..voice.clone()
        };
        assert!(marked.resolve(0).unwrap().first_marker);
        let rtnp_wire = FlowSpec {
            target: "x:1".into(),
            rtp: Some(Codec::G711a),
            first_marker: true,
            ..Default::default()
        };
        assert!(rtnp_wire.resolve(0).is_err());
        let preset_ptime = FlowSpec {
            target: "x:1".into(),
            preset: Some("voip-g711a".into()),
            ptime_ms: Some(30.0),
            wire: Some(Wire::Rtp),
            ..Default::default()
        };
        assert!(preset_ptime.resolve(0).is_ok());
    }

    #[test]
    fn plain_rtp_rules() {
        let voice = FlowSpec {
            target: "x:1".into(),
            preset: Some("voip-g711".into()),
            wire: Some(Wire::Rtp),
            ..Default::default()
        };
        let r = voice.resolve(0).unwrap();
        assert_eq!(r.wire, Wire::Rtp);
        // the 32-byte measurement header is gone: 12 RTP + 160 payload
        assert_eq!(r.size, Dist::Constant { value: 172.0 });
        let by_codec = FlowSpec {
            target: "x:1".into(),
            rtp: Some(Codec::G729),
            wire: Some(Wire::Rtp),
            ..Default::default()
        }
        .resolve(0)
        .unwrap();
        assert_eq!(by_codec.idt_ms, Dist::Constant { value: 20.0 });
        assert_eq!(by_codec.size, Dist::Constant { value: 32.0 });

        let bad = |f: FlowSpec| f.resolve(0).is_err();
        let base = FlowSpec {
            target: "x:1".into(),
            wire: Some(Wire::Rtp),
            rtp: Some(Codec::G711),
            ..Default::default()
        };
        assert!(bad(FlowSpec {
            proto: Some(Proto::Tcp),
            ..base.clone()
        }));
        assert!(bad(FlowSpec {
            meter: Some(Meter::Rtt),
            ..base.clone()
        }));
        assert!(
            bad(FlowSpec {
                rtp: None,
                ..base.clone()
            }),
            "needs a codec or video"
        );
        assert!(
            bad(FlowSpec {
                video: Some(VideoSpec::default()),
                ..base.clone()
            }),
            "video excludes a codec"
        );

        let video = FlowSpec {
            target: "x:1".into(),
            video: Some(VideoSpec::default()),
            ..Default::default()
        };
        assert_eq!(video.resolve(0).unwrap().wire, Wire::Rtp);
        assert!(bad(FlowSpec {
            rate_pps: Some(10.0),
            ..video.clone()
        }));
        assert!(bad(FlowSpec {
            wire: Some(Wire::Rtnp),
            ..video.clone()
        }));
        let v = VideoSpec {
            payload_bytes: 5000,
            ..VideoSpec::default()
        };
        assert!(v.validate().is_err());
    }

    #[test]
    fn toml_accepts_new_fields() {
        let s = Script::from_toml(
            r#"
            [[flow]]
            target = "h:1"
            meter = "rtt"
            payload = "random"
            rtp = "g729"
            vad = true
            vad_talk_ms = "exp:800"
            "#,
        )
        .unwrap();
        let f = s.flow[0].resolve(0).unwrap();
        assert_eq!(f.meter, Meter::Rtt);
        assert!(f.vad.is_some());
        assert!(matches!(f.payload, PayloadData::Bytes(_)));
    }
}
