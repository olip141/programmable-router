#!/usr/bin/env bash
# Compares router classification with ndpiReader results shipped in the nDPI
# test suite. The test pcaps/results must match the linked libndpi version:
# by default an existing checkout in NDPI_SRC (/tmp/nDPI, used to build the
# library) is reused, otherwise NDPI_REF (default: master) is cloned.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bench/results"
NDPI_SRC="${NDPI_SRC:-/tmp/nDPI}"
NDPI_REF="${NDPI_REF:-dev}"
mkdir -p "$OUT"
export PATH="/usr/local/go/bin:${PATH:-}"

if [ ! -d "$NDPI_SRC/tests/cfgs/default/pcap" ]; then
  NDPI_SRC="$OUT/ndpi-src-$NDPI_REF"
  if [ ! -d "$NDPI_SRC" ]; then
    git clone --depth 1 --branch "$NDPI_REF" https://github.com/ntop/nDPI.git "$NDPI_SRC"
  fi
fi
PCAP_DIR="$NDPI_SRC/tests/cfgs/default/pcap"
RESULT_DIR="$NDPI_SRC/tests/cfgs/default/result"

cd "$ROOT"
go build -o "$OUT/evalpcap" ./cmd/evalpcap
for n in 4 8 16 32; do
  "$OUT/evalpcap" -dir "$PCAP_DIR" -truth "$RESULT_DIR" -dpi-max-packets "$n" \
    -out "$OUT/eval-max$n.csv" | tee "$OUT/eval-max$n.summary"
done
