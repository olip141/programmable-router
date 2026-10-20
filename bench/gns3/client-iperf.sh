#!/usr/bin/env bash
# Run on GNS3 client; ROUTER is iperf3 server on LAN.
set -euo pipefail
ROUTER="${1:?router IP}"
DURATION="${2:-30}"
for par in 1 4 8; do
  echo "=== iperf3 parallel $par ==="
  iperf3 -c "$ROUTER" -t "$DURATION" -P "$par"
done
