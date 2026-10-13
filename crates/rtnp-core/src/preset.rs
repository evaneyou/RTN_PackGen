//! Built-in traffic presets.
//!
//! These are *approximations* of common application traffic patterns. Sizes are the full UDP/TCP
//! payload including the 32-byte measurement header (and the 12-byte RTP header for
//! voice), so the codec payload matches the real codec; on the wire a voice packet is
//! therefore 32 bytes larger than a real VoIP packet, unless the flow uses `wire = rtp`,
//! where the 32-byte header is dropped and the packet is exactly what a phone would send. Inter-departure times are in
//! milliseconds.

use crate::dist::Dist;
use crate::flow::{Codec, Proto, VideoSpec};

#[derive(Debug, Clone)]
pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub proto: Proto,
    pub idt_ms: Dist,
    pub size: Dist,
    /// Voice presets write a real RTP header after the measurement header.
    pub rtp: Option<Codec>,
    /// Video presets are plain-RTP frame streams.
    pub video: Option<VideoSpec>,
}

pub fn all() -> Vec<Preset> {
    vec![
        Preset {
            name: "voip-g711",
            description: "G.711 voice: 160 B payload + RTP every 20 ms (50 pps)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 20.0 },
            size: Dist::Constant { value: 204.0 },
            rtp: Some(Codec::G711),
            video: None,
        },
        Preset {
            name: "voip-g711a",
            description: "G.711 A-law voice: 160 B payload + RTP every 20 ms (50 pps), payload type 8",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 20.0 },
            size: Dist::Constant { value: 204.0 },
            rtp: Some(Codec::G711a),
            video: None,
        },
        Preset {
            name: "voip-g729",
            description: "G.729 voice: 20 B payload + RTP every 20 ms (50 pps)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 20.0 },
            size: Dist::Constant { value: 64.0 },
            rtp: Some(Codec::G729),
            video: None,
        },
        Preset {
            name: "voip-g723",
            description: "G.723.1 voice: 24 B payload + RTP every 30 ms (~33 pps)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 30.0 },
            size: Dist::Constant { value: 68.0 },
            rtp: Some(Codec::G723),
            video: None,
        },
        Preset {
            name: "dns",
            description: "DNS-like queries: small UDP datagrams with exponential gaps (mean 200 ms)",
            proto: Proto::Udp,
            idt_ms: Dist::Exponential { mean: 200.0 },
            size: Dist::Uniform {
                min: 64.0,
                max: 120.0,
            },
            rtp: None,
            video: None,
        },
        Preset {
            name: "telnet",
            description: "Interactive TCP keystrokes: small frames with heavy-tailed (Pareto) gaps",
            proto: Proto::Tcp,
            idt_ms: Dist::Pareto {
                scale: 30.0,
                shape: 2.2,
            },
            size: Dist::Uniform {
                min: 40.0,
                max: 80.0,
            },
            rtp: None,
            video: None,
        },
        Preset {
            name: "quake3",
            description: "FPS game updates: ~75 pps, ~100 B normally distributed",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 13.0 },
            size: Dist::Normal {
                mean: 100.0,
                std_dev: 20.0,
            },
            rtp: None,
            video: None,
        },
        Preset {
            name: "counter-strike",
            description: "Tactical shooter updates: ~30 pps, ~80 B normally distributed",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 33.0 },
            size: Dist::Normal {
                mean: 80.0,
                std_dev: 15.0,
            },
            rtp: None,
            video: None,
        },
        Preset {
            name: "video-720p",
            description: "720p30 video over plain RTP: ~2.2 Mbit/s, 2 s GOP (needs --wire rtp, implied)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 1.0 },
            size: Dist::Constant { value: 1212.0 },
            rtp: None,
            video: Some(VideoSpec {
                fps: 30.0,
                gop: 60,
                i_bytes: Dist::Normal {
                    mean: 80_000.0,
                    std_dev: 8_000.0,
                },
                p_bytes: Dist::Normal {
                    mean: 7_800.0,
                    std_dev: 2_500.0,
                },
                ..VideoSpec::default()
            }),
        },
        Preset {
            name: "video-1080p",
            description: "1080p30 video over plain RTP: ~4.6 Mbit/s, 2 s GOP",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 1.0 },
            size: Dist::Constant { value: 1212.0 },
            rtp: None,
            video: Some(VideoSpec {
                fps: 30.0,
                gop: 60,
                i_bytes: Dist::Normal {
                    mean: 200_000.0,
                    std_dev: 20_000.0,
                },
                p_bytes: Dist::Normal {
                    mean: 17_000.0,
                    std_dev: 5_000.0,
                },
                ..VideoSpec::default()
            }),
        },
    ]
}

pub fn lookup(name: &str) -> Option<Preset> {
    all()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}
