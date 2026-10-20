//! Real G.711 audio for plain-RTP voice flows: a built-in sine tone or a WAV file, encoded to
//! µ-law or A-law. The encoded samples loop and are cut into packets, so the receiver (or a
//! packet capture decoded in Wireshark) gets actual, playable audio instead of silence.

use crate::error::{Error, Result};
use crate::flow::Codec;

/// Largest WAV file accepted (bytes).
const MAX_WAV: u64 = 16 * 1024 * 1024;
/// Level of the built-in tone: about -10 dBFS.
const TONE_AMPLITUDE: f64 = 0.316 * 32767.0;

/// Encode one 16-bit linear sample as µ-law (ITU-T G.711).
pub fn linear_to_ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;
    let mut s = sample as i32;
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    let s = s.min(CLIP) + BIAS;
    let exponent = {
        // position of the highest set bit among bits 7..14
        let mut e = 7;
        let mut mask = 0x4000;
        while e > 0 && s & mask == 0 {
            e -= 1;
            mask >>= 1;
        }
        e
    };
    let mantissa = (s >> (exponent + 3)) & 0x0f;
    !(sign | (exponent << 4) | mantissa) as u8
}

/// Decode a µ-law byte to a 16-bit linear sample.
pub fn ulaw_to_linear(b: u8) -> i16 {
    let b = !b as i32;
    let t = (((b & 0x0f) << 3) + 0x84) << ((b & 0x70) >> 4);
    (if b & 0x80 != 0 { 0x84 - t } else { t - 0x84 }) as i16
}

/// Encode one 16-bit linear sample as A-law (ITU-T G.711).
pub fn linear_to_alaw(sample: i16) -> u8 {
    let mut s = sample as i32 >> 3; // 13-bit
    let mask = if s >= 0 {
        0xd5
    } else {
        s = -s - 1;
        0x55
    };
    let mut seg = 0;
    while seg < 8 && s >= (0x20 << seg) {
        seg += 1;
    }
    let v = if seg >= 8 {
        0x7f
    } else {
        let shift = if seg < 2 { 1 } else { seg };
        (seg << 4) | ((s >> shift) & 0x0f)
    };
    (v ^ mask) as u8
}

/// Decode an A-law byte to a 16-bit linear sample.
pub fn alaw_to_linear(b: u8) -> i16 {
    let b = (b ^ 0x55) as i32;
    let seg = (b & 0x70) >> 4;
    let mut t = (b & 0x0f) << 4;
    t += match seg {
        0 => 8,
        _ => 0x108,
    };
    if seg > 1 {
        t <<= seg - 1;
    }
    (if b & 0x80 != 0 { t } else { -t }) as i16
}

fn encode(samples: &[i16], codec: Codec) -> Result<Vec<u8>> {
    let f = match codec {
        Codec::G711 => linear_to_ulaw,
        Codec::G711a => linear_to_alaw,
        _ => {
            return Err(Error::Config(
                "real audio needs a G.711 codec (rtp = g711 or g711a)".into(),
            ));
        }
    };
    Ok(samples.iter().map(|s| f(*s)).collect())
}

/// One second of a sine tone at `hz` (a whole number of cycles, so it loops without a click).
pub fn tone(hz: u32, codec: Codec) -> Result<Vec<u8>> {
    if !(1..=3999).contains(&hz) {
        return Err(Error::Config("tone frequency must be 1-3999 Hz".into()));
    }
    let samples: Vec<i16> = (0..8000)
        .map(|n| {
            let phase = 2.0 * std::f64::consts::PI * hz as f64 * n as f64 / 8000.0;
            (TONE_AMPLITUDE * phase.sin()).round() as i16
        })
        .collect();
    encode(&samples, codec)
}

/// Read an 8 kHz, mono, 16-bit PCM WAV file and encode it.
pub fn wav_file(path: &str, codec: Codec) -> Result<Vec<u8>> {
    let meta =
        std::fs::metadata(path).map_err(|e| Error::Config(format!("audio file '{path}': {e}")))?;
    if meta.len() > MAX_WAV {
        return Err(Error::Config(format!(
            "audio file '{path}' is larger than {} MiB",
            MAX_WAV >> 20
        )));
    }
    let data =
        std::fs::read(path).map_err(|e| Error::Config(format!("audio file '{path}': {e}")))?;
    let samples =
        parse_wav(&data).map_err(|m| Error::Config(format!("audio file '{path}': {m}")))?;
    if samples.is_empty() {
        return Err(Error::Config(format!("audio file '{path}' has no audio")));
    }
    encode(&samples, codec)
}

const HINT: &str = "convert it with: ffmpeg -i in.wav -ar 8000 -ac 1 -c:a pcm_s16le out.wav";

fn parse_wav(d: &[u8]) -> std::result::Result<Vec<i16>, String> {
    if d.len() < 12 || &d[..4] != b"RIFF" || &d[8..12] != b"WAVE" {
        return Err("not a WAV file".into());
    }
    let u16_at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
    let mut fmt_ok = false;
    let mut pos = 12;
    while pos + 8 <= d.len() {
        let id = &d[pos..pos + 4];
        let len = u32_at(pos + 4) as usize;
        let body = pos + 8;
        let end = body.saturating_add(len).min(d.len());
        if id == b"fmt " {
            if end - body < 16 {
                return Err("truncated fmt chunk".into());
            }
            let (tag, ch, rate, bits) = (
                u16_at(body),
                u16_at(body + 2),
                u32_at(body + 4),
                u16_at(body + 14),
            );
            if tag != 1 || ch != 1 || rate != 8000 || bits != 16 {
                return Err(format!(
                    "needs 8 kHz mono 16-bit PCM (this file: format {tag}, {ch} ch, {rate} Hz, {bits} bit); {HINT}"
                ));
            }
            fmt_ok = true;
        } else if id == b"data" {
            if !fmt_ok {
                return Err("data chunk before fmt chunk".into());
            }
            return Ok(d[body..end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| i16::from_le_bytes(*c))
                .collect());
        }
        pos = body.saturating_add(len).saturating_add(len & 1);
    }
    Err("no data chunk".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digital_silence_matches_the_codec_silence_bytes() {
        assert_eq!(linear_to_ulaw(0), Codec::G711.silence_byte().unwrap());
        assert_eq!(linear_to_alaw(0), Codec::G711a.silence_byte().unwrap());
    }

    #[test]
    fn both_laws_round_trip_within_quantisation_error() {
        for s in (-32768i32..=32767).step_by(7) {
            let s = s as i16;
            let u = ulaw_to_linear(linear_to_ulaw(s)) as i32;
            let a = alaw_to_linear(linear_to_alaw(s)) as i32;
            // companding error is at most ~3% of the level, plus one step near zero
            let tol = (s as i32).abs() / 16 + 70;
            assert!((u - s as i32).abs() <= tol, "ulaw {s} -> {u}");
            assert!((a - s as i32).abs() <= tol, "alaw {s} -> {a}");
        }
    }

    #[test]
    fn known_g711_code_points() {
        assert_eq!(linear_to_ulaw(32767), 0x80);
        assert_eq!(linear_to_ulaw(-32768), 0x00);
        assert_eq!(linear_to_alaw(32767), 0xaa);
        assert_eq!(linear_to_alaw(-32768), 0x2a);
    }

    #[test]
    fn tone_is_one_second_and_loops_seamlessly() {
        let t = tone(440, Codec::G711).unwrap();
        assert_eq!(t.len(), 8000);
        // 440 Hz: the signal repeats every 200 samples (8000 / gcd(8000, 440) = 200)
        assert_eq!(t[..200], t[200..400]);
        let peak = t
            .iter()
            .map(|b| ulaw_to_linear(*b).unsigned_abs())
            .max()
            .unwrap();
        assert!((9_500..=10_500).contains(&peak), "{peak}");
        assert!(tone(0, Codec::G711).is_err());
        assert!(tone(440, Codec::G729).is_err());
    }

    fn wav(rate: u32, ch: u16, samples: &[i16]) -> Vec<u8> {
        let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut v = b"RIFF".to_vec();
        v.extend((36 + data.len() as u32).to_le_bytes());
        v.extend(b"WAVEfmt ");
        v.extend(16u32.to_le_bytes());
        v.extend(1u16.to_le_bytes());
        v.extend(ch.to_le_bytes());
        v.extend(rate.to_le_bytes());
        v.extend((rate * 2 * ch as u32).to_le_bytes());
        v.extend((2 * ch).to_le_bytes());
        v.extend(16u16.to_le_bytes());
        v.extend(b"data");
        v.extend((data.len() as u32).to_le_bytes());
        v.extend(data);
        v
    }

    #[test]
    fn wav_parsing_accepts_8k_mono_and_explains_everything_else() {
        assert_eq!(
            parse_wav(&wav(8000, 1, &[1, -2, 3])).unwrap(),
            vec![1, -2, 3]
        );
        let e = parse_wav(&wav(16000, 1, &[0])).unwrap_err();
        assert!(e.contains("16000 Hz") && e.contains("ffmpeg"), "{e}");
        assert!(parse_wav(&wav(8000, 2, &[0, 0])).is_err());
        assert!(parse_wav(b"not a wav file at all").is_err());
    }
}
