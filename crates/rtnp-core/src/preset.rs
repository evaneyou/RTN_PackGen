//! Built-in traffic presets.
//!
//! These are *approximations* of common application traffic patterns (the business presets are
//! estimates, not captures). Sizes are the full UDP/TCP
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
            description: "G.711 µ-law voice: 160 B payload + RTP every 20 ms (50 pps), payload type 0",
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
        // The business presets below are ESTIMATES (typical behaviour, not captures).
        Preset {
            name: "video-conference",
            description: "ESTIMATE of a video-call video stream over plain RTP: 30 fps, ~1.1 Mbit/s, rare keyframes (pair with a voice flow, see examples/video-conference.toml)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 1.0 },
            size: Dist::Constant { value: 1212.0 },
            rtp: None,
            video: Some(VideoSpec {
                fps: 30.0,
                gop: 90,
                i_bytes: Dist::Normal {
                    mean: 25_000.0,
                    std_dev: 5_000.0,
                },
                p_bytes: Dist::Normal {
                    mean: 4_200.0,
                    std_dev: 1_500.0,
                },
                ..VideoSpec::default()
            }),
        },
        Preset {
            name: "video-1080p60",
            description: "MEASURED from one capture of a 1080p60 H.265 camera stream over RTP (Wireshark sample 1920x1080_H.265.pcapng): 60 fps, keyframe every 30 frames, ~2.3 Mbit/s, 1440 B RTP packets",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 1.0 },
            size: Dist::Constant { value: 1440.0 },
            rtp: None,
            video: Some(VideoSpec {
                fps: 60.0,
                gop: 30,
                i_bytes: Dist::Normal {
                    mean: 45_600.0,
                    std_dev: 1_900.0,
                },
                p_bytes: Dist::Normal {
                    mean: 3_300.0,
                    std_dev: 800.0,
                },
                payload_bytes: 1428,
                ..VideoSpec::default()
            }),
        },
        Preset {
            name: "remote-desktop",
            description: "ESTIMATE of remote desktop / VDI over UDP: bursty, heavy-tailed gaps (mean ~17 ms), ~600 B, ~0.27 Mbit/s on average, varies run to run",
            proto: Proto::Udp,
            idt_ms: Dist::Pareto {
                scale: 5.0,
                shape: 1.4,
            },
            size: Dist::Normal {
                mean: 600.0,
                std_dev: 250.0,
            },
            rtp: None,
            video: None,
        },
        Preset {
            name: "market-data",
            description: "ESTIMATE of a unicast market-data feed: many small packets with microbursts (mean gap ~2 ms), ~200 B, ~0.75 Mbit/s; sub-ms gaps can run late",
            proto: Proto::Udp,
            idt_ms: Dist::Pareto {
                scale: 0.5,
                shape: 1.3,
            },
            size: Dist::Normal {
                mean: 200.0,
                std_dev: 80.0,
            },
            rtp: None,
            video: None,
        },
    ]
}

pub fn lookup(name: &str) -> Option<Preset> {
    all()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}
