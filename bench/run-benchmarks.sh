#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bench/results"
mkdir -p "$OUT"
export PATH="/usr/local/go/bin:${PATH:-}"
cd "$ROOT"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
go test -bench=. -benchmem -run='^$' ./internal/dpi/ ./internal/flow/ ./internal/policy/ ./internal/control/ \
  | tee "$OUT/bench-$ts.txt"
