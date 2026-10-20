#!/usr/bin/env bash
# Check that SCTP flows work on this host, or against another one.
#
#   scripts/check-sctp.sh              loopback self-test (starts its own receiver)
#   scripts/check-sctp.sh HOST         against HOST, where you already run:
#                                        rtnp-recv --sctp-port 8998 --control-port 8999
#
# Needs kernel SCTP support (Linux: `sudo modprobe sctp`; on Debian/Ubuntu you may first need
# `sudo apt install linux-modules-extra-$(uname -r)`). Prints PASS or FAIL and exits 0 or 1.
set -uo pipefail

RTNP_SEND=${RTNP_SEND:-rtnp-send}
RTNP_RECV=${RTNP_RECV:-rtnp-recv}
COUNT=${COUNT:-200}
HOST=${1:-}
PORT=${SCTP_PORT:-8998}
CTL=${CONTROL_PORT:-8999}
recv_pid=""
cleanup() { [ -n "$recv_pid" ] && kill "$recv_pid" 2>/dev/null; wait 2>/dev/null; true; }
trap cleanup EXIT

if [ -z "$HOST" ]; then
  HOST=127.0.0.1
  "$RTNP_RECV" --bind 127.0.0.1 --no-udp --no-tcp --sctp-port "$PORT" --control-port "$CTL" \
    >/tmp/rtnp-sctp-recv.log 2>&1 &
  recv_pid=$!
  sleep 1
  if ! kill -0 "$recv_pid" 2>/dev/null; then
    echo "FAIL: the receiver could not start: $(grep -m1 'config error' /tmp/rtnp-sctp-recv.log | sed 's/^ *//')"
    echo "(full output: /tmp/rtnp-sctp-recv.log)"
    echo "SCTP is probably not available in this kernel: try 'sudo modprobe sctp'."
    exit 1
  fi
fi

echo "sending $COUNT SCTP packets to $HOST:$PORT ..."
out=$("$RTNP_SEND" flow -t "$HOST:$PORT" -c "$HOST:$CTL" -p sctp --rate-pps 500 --count "$COUNT" 2>&1)
rc=$?
echo "$out"
rx=$(printf '%s\n' "$out" | sed -n 's/.*rx: packets=\([0-9]*\).*/\1/p' | head -1)
if [ "$rc" -eq 0 ] && [ "${rx:-0}" -eq "$COUNT" ]; then
  echo "PASS: all $COUNT packets arrived over SCTP"
else
  echo "FAIL: exit status $rc, receiver saw ${rx:-0} of $COUNT packets"
  exit 1
fi
