# rtnp-rs

A Rust distributed Internet traffic generator: generate UDP, TCP, SCTP and ICMP traffic with configurable
inter-departure-time and packet-size distributions, measure it at the receiver, and analyse the logs offline.

## Layout

| Crate | Contents |
|---|---|
| `rtnp-core` | The library: distributions, presets, flow specs, wire protocol, sender and receiver engines, control channel with auth, remote-launch agent, log server, metrics, log analysis. Start with `rtnp_core::client`. |
| `rtnp-cli` | Binaries `rtnp-send`, `rtnp-recv`, `rtnp-logd`, `rtnp-decode`. |

## Quick start

```sh
cargo build --release
echo 'a-long-shared-secret' > key          # optional but recommended, see Security

# terminal 1: receiver (UDP+TCP data on 8998, control on 8999, metrics on 9100)
target/release/rtnp-recv --key-file key --metrics-port 9100 --log rx.jsonl

# terminal 2: one flow, or a script of concurrent flows
target/release/rtnp-send flow -t 127.0.0.1:8998 --preset voip-g711 -d 10s -c 127.0.0.1:8999 --key-file key -l tx.jsonl
target/release/rtnp-send run examples/mixed.toml -c 127.0.0.1:8999 --key-file key -l tx.jsonl

# offline analysis: totals, CSV, or a time series
target/release/rtnp-decode tx.jsonl rx.jsonl
target/release/rtnp-decode tx.jsonl rx.jsonl -f csv
target/release/rtnp-decode rx.jsonl --flow 1 -i 1000
```

Distribution syntax (for `--idt` in ms and `--size` in bytes, and for TOML values): a bare number, or
`const:v`, `exp:mean`, `normal:mean,sd`, or `pareto:scale,shape`. Constant suits codec traffic,
exponential random arrivals and talk/silence lengths, Pareto bursty heavy-tailed gaps, and normal sizes
that cluster around an average. TOML also accepts tables such as
`{ kind = "pareto", scale = 2.0, shape = 1.6 }`.

Defaults: 1000 packets/s, 512-byte packets, 10 s.

## Features

* **Round-trip metering** (`--meter rtt`): the receiver reflects each packet (same size, so no
  amplification) and the sender times it on its own clock, so no clock sync is needed. Works over UDP and
  TCP/SCTP. ICMP flows always report RTT.
* **Voice** (`--rtp g711|g729|g723`, `voip-*` presets): writes a real RTP header (payload type, sequence,
  8 kHz timestamp, SSRC, marker on talkspurt start). `--vad` alternates talkspurts and silences
  (defaults `exp:1004` / `exp:1587` ms, override with `--vad-talk` / `--vad-silence`).
* **Plain RTP** (`--wire rtp`, `--video`, `video-*` presets): the UDP payload is exactly an RTP packet,
  with no measurement header; see below.
* **Payloads** (`--payload zero|random|pattern:<hex>|file:<path>`): packet body content after the headers.
* **Remote launch** (`rtnp-send ... --agent host:port`): run the flows from another host that runs
  `rtnp-recv --allow-launch`. See Security.
* **Central logging**: `rtnp-logd` collects JSONL streams; senders and receivers use `--log-server host:port
  --log-tag name`. Decode the per-connection files with `rtnp-decode`.
* **Prometheus metrics**: `rtnp-recv --metrics-port N` serves `GET /metrics` with per-flow packets, bytes,
  loss, reordering, bitrate, delay and jitter.
* **SCTP**: `-p sctp` / `rtnp-recv --sctp-port N` use one-to-one (stream-style) SCTP sockets with the same
  framing as TCP.
* **Continuous monitoring** (`--forever`, `--interval 10s`): flows run until Ctrl-C and print a rolling
  summary every interval; see below.
* **Library API**: `rtnp_core::client::run_session` and `remote_launch` run what the CLI runs.

## Plain-RTP mode

By default every packet starts with our 32-byte measurement header. With `--wire rtp` (UDP only) the
header is dropped and the datagram is a bare RTP packet (RFC 3550, version 2, random initial sequence
number, timestamp and SSRC), so it looks to Wireshark, a gateway or an SBC like a real stream.

```sh
rtnp-send flow -t 10.0.0.2:8998 -c 10.0.0.2:8999 --preset voip-g711 --wire rtp -d 30s   # 172-byte packets
rtnp-send flow -t 10.0.0.2:8998 --video --video-fps 25 --video-gop 50 \
    --video-i-size normal:60000,5000 --video-p-size normal:6000,2000 -d 30s
```

* **Voice**: payload types 0 (G.711 µ-law, `g711`), 8 (A-law, `g711a`), 18 (G.729), 4 (G.723.1), 8 kHz timestamps that follow the schedule (so silences from `--vad`
  appear as timestamp jumps, as in RFC 3551), marker bit on the first packet of each talkspurt.
* **Packetisation**: `--ptime 30` (G.711: 10-200 ms, G.729: multiples of 10) sets interval and size
  together, e.g. `--rtp g711a --ptime 30` gives 252-byte packets every 30 ms with timestamp steps of 240.
  Plain-RTP G.711 payloads default to the codec's digital silence (`0xD5` A-law, `0xFF` µ-law); use
  `--payload random` or `pattern:<hex>` for other content.
* **Video**: frames at `--video-fps`; one I-frame per GOP and P-frames in between, sizes drawn from the
  given distributions; each frame is split into packets of at most `--video-payload` bytes (default
  1200) that share a 90 kHz timestamp and are sent back to back, with the marker bit on the last
  packet of the frame. Payload type 96. The payload bytes are synthetic, not an H.264/VP8 bitstream.
* **Receiver**: recognises RTP automatically on the UDP data port. Streams announced over the control
  channel are reported under their flow; any other RTP source is tracked as session 0, flow = SSRC
  (so it also works as a passive RTP monitor). Loss comes from the unwrapped 16-bit sequence number,
  jitter is the RFC 3550 interarrival jitter computed from RTP timestamps and arrival times.
* **Limits**: RTP carries no send time, so there is no one-way delay (the delay figures are relative to
  the first packet and flagged `delay_relative`), and no round-trip metering (`--meter rtt` is
  refused). Preset sizes drop the 32-byte header (G.711 is 172 bytes). Not implemented: RTCP, SIP/SDP
  call setup, SRTP, RTP over TCP, real codec bitstreams.

### Choosing voice options

Each of these is independent, so you decide what a flow does. Everything is off or at its default unless
you set it. TOML scripts use the field names instead of flags (for example `rtcp_interval_ms`,
`first_marker`, `ptime_ms`).

| Option | Flag | Default |
|---|---|---|
| RTCP sender reports (and round trip from the receiver's answers) | `--rtcp-interval 5s`, `0` = off | on, every 5 s |
| Marker bit on the first packet | `--first-marker` | off |
| Talkspurts and silences | `--vad` (`--vad-talk`, `--vad-silence`) | off, continuous stream |
| Two-way call | `--bidir` (receiver needs `--allow-reverse`) | off |
| Packet interval and size from the codec | `--ptime 30`, also with `--preset` | codec default |
| Payload content | `--payload zero\|random\|pattern:<hex>\|file:<path>` | codec silence |
| IP type of service / TTL | `--tos 16`, `--ttl 64` | OS default |
| Run length | `-d 30s`, `--count`, `--max-bytes`, `--forever` | 10 s |

## Two-way calls

```sh
rtnp-recv --allow-reverse
rtnp-send flow -t 10.0.0.2:8998 -c 10.0.0.2:8999 --wire rtp --rtp g711a --ptime 30 --bidir --forever -i 10s --json
```

A normal flow is one-directional. With `--bidir` the flow is a call: the receiver sends its own constant
RTP stream (same codec, interval and size, its own SSRC) back to the address the forward stream came from,
from its data port, so it also works through NAT and over WireGuard. Both streams run non-stop (no VAD) until
the session ends or you press Ctrl-C. The sender measures the return stream on the flow's own socket, so
reports and interval lines carry `rx` (forward, measured at the receiver) and `reverse` (return, measured at
the sender) with loss, RFC 3550 jitter and rate. `--bidir` needs `--wire rtp`, `--rtp <codec>` and `-c`.

* The receiver must opt in with `--allow-reverse`; otherwise `rtnp-send` stops with a clear error. Return
  streams are bounded: at most 64 at once, 10-200 ms cadence, packets up to 1400 bytes, sent only to the
  address the announced forward stream came from, and stopped 5 s after that stream goes quiet or when the
  session ends.
* The return stream starts with the first forward packet and ends when the session ends, so over a run it
  can carry a few more packets than the forward stream. Loss and gap rules are the same as for the forward
  direction (see Continuous mode).
* Jitter of the two streams is measured independently, each at its receiving end, so no clock sync is
  needed. There is no one-way delay in plain-RTP mode.

## Voice quality: round trip, marking, verdicts

**Round trip over RTCP.** Plain-RTP flows send an RTCP sender report every 5 seconds
(`--rtcp-interval 1s` to change it, `0` to turn off) and `rtnp-recv` answers it, so the sender gets a standard
RFC 3550 round-trip time (arrival - LSR - DLSR) with no clock sync and no control channel. It
appears as `rtt` in reports. Mouth-to-ear delay is roughly half the round trip plus the jitter
buffer; ITU-T G.114's 150 ms one-way budget is about 300 ms round trip.

**DSCP.** `--tos 184` marks EF (DSCP 46 << 2). In a two-way call the receiver marks its return
stream the same way. The receiver reports the marking it actually saw (`marking seen: dscp=46`),
so a router or ISP that rewrites it is visible. Linux only for the observed value.

**Verdicts.** `--max-rtt 300 --max-jitter 30 --max-loss 1 --expect-dscp 46` judge every interval
and the final report: `PASS`/`FAIL` with reasons, a `verdict` object in JSON, and exit status 3 if
the final verdict fails. Limits that could not be measured are listed as not checked rather than
silently passing. Round trip is the mean; jitter and loss are the worse direction.

**Does the priority queue work?** Runs the same call twice under the same background load, once
marked and once unmarked, and compares them:

```sh
rtnp-recv --allow-reverse
rtnp-send compare -t host:8998 -c host:8999 --bidir --baseline \
    --background-kbps 20000 -d 30s
```

Exit status 0 = protected, 3 = not protected (or the marking was lost on the way), 4 =
inconclusive. Inconclusive means the load did not hurt the unmarked call, so set
`--background-kbps` above the bottleneck link's rate. Marking is only honoured by a queue that is
configured to; many home routers ignore or clear DSCP, and WireGuard copies the inner DSCP to the
outer packet but the ISP in between usually does not honour it. Run it against the congested hop
you care about.

## Continuous mode

```sh
rtnp-send flow -t 10.0.0.2:8998 -c 10.0.0.2:8999 --meter rtt --rate-pps 5 --size 100 --forever -i 10s --json
```

`--forever` (or `forever = true` in a script) removes the time limit; it cannot be combined with `-d`,
`--count` or `--max-bytes`, and is refused for `--agent` launches. `--interval` (default 10 s with
`--forever`, minimum 100 ms, works for finite runs too) prints one report per interval. With `--json`
each report is one line, ready for a log shipper:

```json
{"type":"interval","session":123,"index":7,"unix_ms":1760000000000,"elapsed_s":70.0,"interval_s":10.0,
 "flows":[{"flow":1,"name":"rtt-udp","proto":"udp","sent":50,"tx_kbps":4.0,
           "rx":{"packets":50,"bitrate_kbps":4.0,"delay_avg_ms":..,"jitter_ms":..,..},
           "rtt":{"count":50,"min_ms":..,"avg_ms":..,"max_ms":..,"jitter_ms":..},
           "lost":0,"loss_pct":0.0}],
 "warnings":[]}
```

On Ctrl-C a final `{"type":"final","session":..,"flows":[..]}` line carries the whole-run totals.

* `rx` (delay, jitter, receiver-side loss) needs `-c`/`--control`; `rtt` needs `--meter rtt` or ICMP.
* **Loss** per interval comes from sequence gaps, so a packet still in flight at an interval edge is
  not counted as lost. A gap is reported in the first interval that sees a later packet. An interval
  in which nothing arrived is charged with what the *previous* interval sent but did not get answered,
  so a total outage shows as 100 % one interval after it starts. ICMP loss is probes that timed out
  (2 s), also attributed when the timeout fires. Flows with neither a control channel nor ICMP report
  `lost: null`.
* Memory stays bounded: the receiver keeps running statistics rather than samples, evicts flows idle for
  over 5 minutes when its table is full, and forgets a session's flow names when it reports. The sender
  keeps at most one million round-trip samples per flow for the final totals (the interval reports
  keep covering everything after that).
* If the receiver restarts, interval reports continue without `rx` (a warning is printed once); restart
  `rtnp-send` to resume receiver-side numbers.

## How it works

* Every packet starts with a 32-byte versioned header (session, flow, sequence, TX timestamp, length);
  the rest is the optional RTP header and the payload. TCP/SCTP flows are length-framed with the same
  header. Because that header is part of the packet, voice presets are 32 bytes larger on the wire than a
  real VoIP packet.
* Departures follow an absolute schedule so timer jitter does not turn into rate drift. If the sender falls
  behind it catches up, but resynchronises after 1 s of lag to avoid unbounded bursts. `late` counts
  departures more than 1 ms behind schedule.
* The control channel (`--control`) carries a session announcement and an end-of-run report, so the sender
  prints receiver-side loss, delay and jitter, including for flows that received nothing.
* Logs are JSON lines written by a background task. If the queue overflows, records are dropped and counted
  instead of disturbing pacing.

## Security

* **Authentication.** With `--key`/`--key-file`/`RTNP_KEY`, the control channel and log server require a
  shared key (HMAC-SHA256 challenge-response, mutual). Keys must be at least 8 bytes. Prefer the
  environment variable or a key file: `--key` is visible in the process list.
* **No encryption.** Authentication does not encrypt traffic or stop someone who can hijack an established
  connection. Use a VPN or SSH tunnel across untrusted networks. Without a key the control channel is open
  and `rtnp-recv` warns about it.
* **Agent mode lets key holders generate traffic from that host to any destination.** It is off by default,
  requires a key and a control port, accepts at most 64 flows per launch, runs at most 2 launches at once,
  caps every flow at one hour, and refuses `file:` payloads (so a controller cannot read files on the
  agent). It does not restrict destinations: use network ACLs if that matters.
* The receiver tracks at most 10,000 distinct flows; when full it evicts flows idle for more than
  5 minutes, otherwise new ones are counted and ignored.
* Log server client tags are sanitised into file names; files are never overwritten and each connection
  is size-capped. There is no total disk quota.

## Things to know

* **One-way delay needs synchronised clocks** (NTP/PTP). On loopback it is exact. Jitter is reported as the
  mean absolute delay difference and as the RFC 3550 smoothed value.
* **Loss** is derived from sequence gaps at the receiver, and against the sender's count when both logs
  are decoded together. Duplicates are not tracked separately.
* **Presets** (`rtnp-send presets`) are approximations. The voice presets are G.711, G.711 A-law, G.729 and G.723.1. `fortnite` (30 packets/s,
  ~250 B) and `call-of-duty` (~22 packets/s, ~900 B) are **estimates** built from public tick-rate and
  data-use figures, not from packet captures, and each sends one stream rather than the different traffic
  per direction a real game uses.
* **ICMP** needs privileges (root, `CAP_NET_RAW`, or a suitable `net.ipv4.ping_group_range`).
* **SCTP is implemented but has not been run:** the development kernel has no SCTP support, so only the
  "unsupported" path is tested. Please try it on a host with `sctp` loaded before relying on it.
* Sub-millisecond pacing is limited by OS timer granularity. At 20 kpps on a test machine every packet
  arrived, but about 8% of departures were flagged late.
* Developed and tested on Linux only.

## Not implemented

* **DCCP**: removed from recent mainline Linux kernels (the development kernel has none).
* **Parquet output**: JSONL, CSV and JSON are supported; Parquet would add a large dependency tree.
* **RTCP / SIP / SDP / SRTP**, and real codec bitstreams (see Plain-RTP mode).
* **Encrypted control/log channels** (see Security) and SCTP multi-streaming/multi-homing.
