// Package flow groups packets into bidirectional flows and drives nDPI
// classification for each of them.
package flow

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"

	"edge-router/internal/dpi"
)

// Key identifies a bidirectional flow. It is normalised so that both
// directions of a conversation map to the same key: (A, PortA) is the
// smaller endpoint.
type Key struct {
	A, B         netip.Addr
	PortA, PortB uint16
	Proto        layers.IPProtocol
}

// NewKey builds a normalised key. forward is true when (src, sport) became
// endpoint A.
func NewKey(src, dst netip.Addr, sport, dport uint16, proto layers.IPProtocol) (k Key, forward bool) {
	c := src.Compare(dst)
	if c < 0 || (c == 0 && sport <= dport) {
		return Key{A: src, B: dst, PortA: sport, PortB: dport, Proto: proto}, true
	}
	return Key{A: dst, B: src, PortA: dport, PortB: sport, Proto: proto}, false
}

func (k Key) String() string {
	return fmt.Sprintf("%s %s <-> %s", protoName(k.Proto),
		endpoint(k.A, k.PortA, k.Proto), endpoint(k.B, k.PortB, k.Proto))
}

func hasPorts(p layers.IPProtocol) bool {
	return p == layers.IPProtocolTCP || p == layers.IPProtocolUDP
}

func endpoint(a netip.Addr, port uint16, p layers.IPProtocol) string {
	if !hasPorts(p) {
		return a.String()
	}
	return netip.AddrPortFrom(a, port).String()
}

func protoName(p layers.IPProtocol) string {
	switch p {
	case layers.IPProtocolTCP:
		return "TCP"
	case layers.IPProtocolUDP:
		return "UDP"
	case layers.IPProtocolICMPv4:
		return "ICMP"
	case layers.IPProtocolICMPv6:
		return "ICMPv6"
	}
	return fmt.Sprintf("IP/%d", uint8(p))
}

// Flow is the state kept for one bidirectional conversation.
type Flow struct {
	Key Key
	// Client and Server are the endpoints in the direction of the first
	// packet seen, which is usually the connection initiator.
	Client, Server netip.AddrPort

	FirstSeen, LastSeen time.Time
	Packets, Bytes      uint64
	DPIPackets          int

	// Result and Protocol are final once Done is set.
	Result   dpi.Result
	Protocol string
	Category string
	// Done means nDPI inspection has finished for this flow.
	Done bool
	// GaveUp means the classification comes from ndpi_detection_giveup
	// (packet limit or flow end) rather than from a final nDPI verdict.
	GaveUp bool

	state *dpi.FlowState
}

func (f *Flow) String() string {
	return fmt.Sprintf("%s %s -> %s", protoName(f.Key.Proto),
		endpoint(f.Client.Addr(), f.Client.Port(), f.Key.Proto),
		endpoint(f.Server.Addr(), f.Server.Port(), f.Key.Proto))
}
