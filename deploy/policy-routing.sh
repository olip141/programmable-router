#!/bin/sh
# Policy routing for flows marked 0x30 (example: guest / alternate WAN).
# Usage: policy-routing.sh <gateway> [table_id]
set -eu
GW="${1:?gateway IP}"
TABLE="${2:-200}"

ip rule add fwmark 0x30 table "$TABLE" 2>/dev/null || true
ip route replace default via "$GW" table "$TABLE"
echo "Policy routing: fwmark 0x30 -> table $TABLE via $GW"
