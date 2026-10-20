#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:?interface}"
PCAP="${2:?pcap file}"
for mbps in 10 50 100 200 500; do
  echo "=== tcpreplay ${mbps}mbit on $IFACE ==="
  tcpreplay --mbps="$mbps" -i "$IFACE" "$PCAP" || break
done
