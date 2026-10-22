# Tests that need real hardware or a real link

The automated test suite runs on loopback. Two things cannot be checked that way: SCTP (it needs kernel
support that many sandboxes and containers lack) and two-way G.711 monitoring over a real network path.
These scripts do both. They are not part of `cargo test`.

## 1. SCTP

```sh
sudo modprobe sctp                          # Debian/Ubuntu may first need: sudo apt install linux-modules-extra-$(uname -r)
scripts/check-sctp.sh                       # loopback self-test on this host
```

To test across a network, run the receiver on the far host and point the check at it:

```sh
# far host
rtnp-recv --no-udp --no-tcp --sctp-port 8998 --control-port 8999
# this host
scripts/check-sctp.sh far.example.net
```

It sends 200 packets at 500 pps and prints `PASS` when the receiver saw all of them. Anything else prints
`FAIL` with the reason (most often "SCTP sockets are not available here", meaning the kernel module is
missing). Firewalls must allow SCTP (IP protocol 132) in addition to the control port. `COUNT`, `SCTP_PORT`
and `CONTROL_PORT` change the defaults.

What this proves: stream-style one-to-one SCTP carries our framing and the receiver measures it. It does not
cover SCTP multi-streaming or multi-homing, which are not implemented.

## 2. Continuous two-way G.711 monitoring

Far end (any host that can reach this one; add `--key-file` on both ends to require a shared key):

```sh
rtnp-recv --allow-reverse
```

This end:

```sh
TARGET=far.example.net scripts/monitor-g711-call.sh
```

It runs one non-stop plain-RTP G.711 call in both directions, marked EF, and prints one JSON line per
interval (default 10 s), also appended to `./g711-monitor.jsonl`. Each interval is judged against
`MAX_RTT=300` ms, `MAX_JITTER=30` ms and `MAX_LOSS=1` %, and the sender checks that the receiver saw the
marking it sent (`DSCP=46`). Useful settings: `CODEC=g711a` for A-law, `PTIME=30`, `INTERVAL=5s`,
`DSCP=0` to send unmarked, `KEY_FILE`, `TLS_CA`. See the top of the script for all of them.

Reading the output (`jq` examples):

```sh
# forward = measured at the far end, reverse = measured here
jq -c '.flows[] | {name, loss: .loss_pct, rev_loss: .reverse_loss_pct, jit: .rx.jitter_rfc3550_ms, rev_jit: .reverse.jitter_rfc3550_ms, rtt: .rtt.avg_ms, dscp: .rx.tos}' g711-monitor.jsonl
```

Good looks like: about 50 pps each way (20 ms) and 68.8 kbit/s at the receiver, 0 % loss, jitter of a few
ms, `tos` 184 (EF) seen in both directions. A `tos` of 0 means something on the path cleared the marking.

Run it as a service on both hosts with `scripts/systemd/rtnp-recv.service` (far end) and
`scripts/systemd/rtnp-monitor.service` (this end); the comments in the files give the install steps.

Limits to keep in mind:

* Plain RTP carries no send time, so there is no one-way delay: delays are relative to the first packet.
  Round trip comes from RTCP and is reported about every 5 s (`RTCP_INTERVAL` is not set by the script).
* The monitor is a single stream. To compare marked and unmarked treatment under load, use
  `rtnp-send compare` instead.
* SRTP works on two-way calls (add `--srtp-key-file` on both ends, or `--sip --srtp`); the monitor script does not turn it on by itself.
