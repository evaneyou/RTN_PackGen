//! Built-in traffic presets.
//!
//! These are *approximations* of common application traffic patterns (the game presets are
//! estimates from public figures, not captures). Sizes are the full UDP/TCP
//! payload including the 32-byte measurement header (and the 12-byte RTP header for
//! voice), so the codec payload matches the real codec; on the wire a voice packet is
//! therefore 32 bytes larger than a real VoIP packet, unless the flow uses `wire = rtp`,
//! where the 32-byte header is dropped and the packet is exactly what a phone would send. Inter-departure times are in
//! milliseconds.

use crate::dist::Dist;
use crate::flow::{Codec, Proto};

#[derive(Debug, Clone)]
pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub proto: Proto,
    pub idt_ms: Dist,
    pub size: Dist,
    /// Voice presets write a real RTP header after the measurement header.
    pub rtp: Option<Codec>,
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
        },
        Preset {
            name: "voip-g711a",
            description: "G.711 A-law voice: 160 B payload + RTP every 20 ms (50 pps), payload type 8",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 20.0 },
            size: Dist::Constant { value: 204.0 },
            rtp: Some(Codec::G711a),
        },
        Preset {
            name: "voip-g729",
            description: "G.729 voice: 20 B payload + RTP every 20 ms (50 pps)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 20.0 },
            size: Dist::Constant { value: 64.0 },
            rtp: Some(Codec::G729),
        },
        Preset {
            name: "voip-g723",
            description: "G.723.1 voice: 24 B payload + RTP every 30 ms (~33 pps)",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 30.0 },
            size: Dist::Constant { value: 68.0 },
            rtp: Some(Codec::G723),
        },
        // The game presets are ESTIMATES built from public figures (server update rates and
        // reported data use), not from packet captures. Each is a single stream; real games
        // send different traffic in each direction. Replace with measured values when captures
        // are available.
        Preset {
            name: "fortnite",
            description: "ESTIMATE of Fortnite gameplay: 30 updates/s (30 Hz server tick), ~250 B, ~60 kbps",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 33.33 },
            size: Dist::Normal {
                mean: 250.0,
                std_dev: 60.0,
            },
            rtp: None,
        },
        Preset {
            name: "call-of-duty",
            description: "ESTIMATE of Call of Duty / Warzone gameplay: ~22 updates/s (20-25 Hz tick), ~900 B, ~160 kbps",
            proto: Proto::Udp,
            idt_ms: Dist::Constant { value: 45.0 },
            size: Dist::Normal {
                mean: 900.0,
                std_dev: 150.0,
            },
            rtp: None,
        },
    ]
}

pub fn lookup(name: &str) -> Option<Preset> {
    all()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}
