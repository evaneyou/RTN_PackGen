#!/usr/bin/env bash
# Make a private CA and a server certificate for rtnp's TLS control/log channels.
#
#   scripts/make-test-certs.sh <server-name> [out-dir]
#
# <server-name> is what clients type to reach the server: an IP address (192.0.2.10) or a DNS
# name (rtnp-recv.lab.example). Give ca.pem to clients (--tls-ca); give server.pem and
# server-key.pem to rtnp-recv / rtnp-logd (--tls-cert / --tls-key). Keep ca-key.pem private.
set -euo pipefail
name="${1:?usage: $0 <server-name> [out-dir]}"
out="${2:-certs}"
mkdir -p "$out"
cd "$out"
if [[ "$name" =~ ^[0-9.]+$ || "$name" == *:* ]]; then san="IP:$name"; else san="DNS:$name"; fi

if [[ ! -f ca.pem ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -subj "/CN=rtnp private CA" -keyout ca-key.pem -out ca.pem 2>/dev/null
fi
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=$name" -keyout server-key.pem -out server.csr 2>/dev/null
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$san" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 825 -extfile ext.cnf -out server.pem 2>/dev/null
rm -f server.csr ext.cnf
chmod 600 ca-key.pem server-key.pem
echo "wrote $out/ca.pem (clients), $out/server.pem + $out/server-key.pem (server) for $san"
