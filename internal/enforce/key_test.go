package enforce

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket/layers"

	"edge-router/internal/flow"
)

func TestFlowElementKeyIPv4(t *testing.T) {
	f := &flow.Flow{
		Key: flow.Key{Proto: layers.IPProtocolTCP},
		Client: netip.MustParseAddrPort("10.0.0.1:31337"),
		Server: netip.MustParseAddrPort("213.199.149.251:443"),
	}
	key, ipv6, ok := flowElementKey(f)
	if !ok || ipv6 {
		t.Fatalf("ok=%v ipv6=%v", ok, ipv6)
	}
	if len(key) != 20 {
		t.Fatalf("key len %d want 20", len(key))
	}
}

func TestFlowElementKeySkipsICMP(t *testing.T) {
	f := &flow.Flow{Key: flow.Key{Proto: layers.IPProtocolICMPv4}}
	if _, _, ok := flowElementKey(f); ok {
		t.Fatal("expected skip")
	}
}
