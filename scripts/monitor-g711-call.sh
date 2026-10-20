#!/usr/bin/env bash
# Continuous two-way G.711 call monitor over a real link.
#
#   far end:   rtnp-recv --allow-reverse [--key-file key]
#   this end:  TARGET=203.0.113.10 scripts/monitor-g711-call.sh
#
# It runs one non-stop G.711 call (plain RTP, both directions), prints one JSON line per
# interval and appends the same lines to $OUT. Loss, RFC 3550 jitter and round trip are
# judged every interval against the limits below.
#
# Settings (environment variables):
#   TARGET        far end host or IP (required)
#   UDP_PORT      far end RTP port            (default 8998)
#   CONTROL_PORT  far end control port        (default 8999)
#   CODEC         g711 (µ-law) or g711a (A-law)  (default g711)
#   PTIME         packet interval in ms       (default 20)
#   DSCP          marking to send and expect  (default 46 = EF; set 0 to send unmarked and skip the check)
#   INTERVAL      report period               (default 10s)
#   MAX_RTT       mean round trip limit, ms   (default 300)
#   MAX_JITTER    jitter limit, ms            (default 30)
#   MAX_LOSS      loss limit, percent         (default 1)
#   KEY_FILE      shared key file for the control channel (optional)
#   TLS_CA        CA file when the far end runs TLS (optional)
#   OUT           JSON-lines output file      (default ./g711-monitor.jsonl)
#   RTNP_SEND     path to rtnp-send           (default: rtnp-send from PATH)
set -euo pipefail

: "${TARGET:?set TARGET to the far end host or IP}"
UDP_PORT=${UDP_PORT:-8998}
CONTROL_PORT=${CONTROL_PORT:-8999}
CODEC=${CODEC:-g711}
PTIME=${PTIME:-20}
DSCP=${DSCP:-46}
INTERVAL=${INTERVAL:-10s}
MAX_RTT=${MAX_RTT:-300}
MAX_JITTER=${MAX_JITTER:-30}
MAX_LOSS=${MAX_LOSS:-1}
OUT=${OUT:-./g711-monitor.jsonl}
RTNP_SEND=${RTNP_SEND:-rtnp-send}

args=(flow -t "$TARGET:$UDP_PORT" -c "$TARGET:$CONTROL_PORT"
  --wire rtp --rtp "$CODEC" --ptime "$PTIME" --first-marker --bidir --forever
  -i "$INTERVAL" --json
  --max-rtt "$MAX_RTT" --max-jitter "$MAX_JITTER" --max-loss "$MAX_LOSS")
if [ "$DSCP" != "0" ]; then
  args+=(--tos "$((DSCP << 2))" --expect-dscp "$DSCP")
fi
[ -n "${KEY_FILE:-}" ] && args+=(--key-file "$KEY_FILE")
[ -n "${TLS_CA:-}" ] && args+=(--tls-ca "$TLS_CA")

echo "monitoring $TARGET with $CODEC, ptime ${PTIME} ms, every $INTERVAL -> $OUT (Ctrl-C to stop)" >&2
# stdout is the JSON stream; tee keeps a copy. pipefail keeps rtnp-send's exit status.
exec "$RTNP_SEND" "${args[@]}" | tee -a "$OUT"
