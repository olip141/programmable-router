#!/usr/bin/env bash
# Run on GNS3 router while router binary is active.
set -euo pipefail
PID="${1:?router pid}"
INTERVAL="${2:-1}"
DURATION="${3:-60}"
OUT="${4:-/tmp/router-monitor.log}"
end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
  date -Is
  pidstat -p "$PID" 1 1 || true
  sleep "$INTERVAL"
done | tee "$OUT"
