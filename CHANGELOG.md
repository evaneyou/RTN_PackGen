# Changelog

## 0.2.0

Added
* G.711 µ-law now matches A-law everywhere: `ulaw`/`alaw` aliases, help and error text, tests for both laws.
* Measured preset `video-1080p60` (60 fps, keyframe every 30 frames, about 2.3 Mbit/s, 1440 B packets).
* Real-link checks: `scripts/monitor-g711-call.sh` (continuous two-way G.711 monitor), `scripts/check-sctp.sh`,
  systemd units, and `docs/real-link-tests.md`.
* Opt-in SRTP, real G.711 audio (`--payload tone|wav:`), SIP/SDP call setup and TLS on the control and log
  channels (all off by default).

Changed
* `rtnp-send` default `--codec` is now `g711` (µ-law) instead of `g711a`.
* Video payloads may be up to 1460 bytes (was 1400).

Removed
* The `fortnite` and `call-of-duty` presets.

The measurement-header version (`proto::VERSION`) is unchanged; mixed 0.1 and 0.2 deployments have not been tested.

## 0.1.0

First public release.
