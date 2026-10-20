#!/bin/sh
# HTB + fq_codel classes keyed by nftables fwmark (meta mark / ct mark).
# Usage: qos.sh <interface> <rate>   e.g. qos.sh eth1 100mbit
set -eu
PATH="/usr/sbin:/sbin:/usr/bin:/bin${PATH:+:$PATH}"
export PATH
IF="${1:?interface}"
RATE="${2:?rate e.g. 100mbit}"

tc qdisc del dev "$IF" root 2>/dev/null || true
tc qdisc add dev "$IF" root handle 1: htb default 999
tc class add dev "$IF" parent 1: classid 1:1 htb rate "$RATE" ceil "$RATE"

# Default class
tc class add dev "$IF" parent 1:1 classid 1:999 htb rate "$RATE" ceil "$RATE" prio 7
tc qdisc add dev "$IF" parent 1:999 handle 999: fq_codel

# Mark 0x10 — low priority (e.g. media)
tc class add dev "$IF" parent 1:1 classid 1:10 htb rate 2mbit ceil "$RATE" prio 5
tc qdisc add dev "$IF" parent 1:10 handle 10: fq_codel
tc filter add dev "$IF" parent 1: protocol all handle 0x10 fw classid 1:10

# Mark 0x20 — high priority (e.g. SSH)
tc class add dev "$IF" parent 1:1 classid 1:20 htb rate 3mbit ceil "$RATE" prio 2
tc qdisc add dev "$IF" parent 1:20 handle 20: fq_codel
tc filter add dev "$IF" parent 1: protocol all handle 0x20 fw classid 1:20

# Mark 0x30 — alternate path (policy routing companion)
tc class add dev "$IF" parent 1:1 classid 1:30 htb rate 1mbit ceil "$RATE" prio 4
tc qdisc add dev "$IF" parent 1:30 handle 30: fq_codel
tc filter add dev "$IF" parent 1: protocol all handle 0x30 fw classid 1:30

echo "QoS configured on $IF at $RATE"
