package flow_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func TestNewKeyBidirectional(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	k1, _ := flow.NewKey(a, b, 1000, 80, layers.IPProtocolTCP)
	k2, _ := flow.NewKey(b, a, 80, 1000, layers.IPProtocolTCP)
	if k1 != k2 {
		t.Fatalf("keys differ: %+v vs %+v", k1, k2)
	}
}

func TestTableBothDirectionsOneFlow(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatalf("dpi.New: %v", err)
	}
	defer eng.Close()

	table := flow.NewTable(eng, flow.Config{})
	defer table.Close()

	a := netip.MustParseAddr("192.168.1.1")
	b := netip.MustParseAddr("192.168.1.2")
	ts := time.Unix(1_700_000_000, 0)

	table.Handle(&capture.Packet{Src: a, Dst: b, SrcPort: 1234, DstPort: 443, Proto: layers.IPProtocolTCP, L3: []byte{0x45}, Timestamp: ts, WireLen: 64})
	table.Handle(&capture.Packet{Src: b, Dst: a, SrcPort: 443, DstPort: 1234, Proto: layers.IPProtocolTCP, L3: []byte{0x45}, Timestamp: ts, WireLen: 64})

	if table.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", table.Len())
	}
}

func TestExpireRemovesOnlyIdle(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatalf("dpi.New: %v", err)
	}
	defer eng.Close()

	table := flow.NewTable(eng, flow.Config{})
	defer table.Close()

	base := time.Unix(1_700_000_000, 0)
	a1, b1 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	a2, b2 := netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.0.4")

	table.Handle(&capture.Packet{Src: a1, Dst: b1, SrcPort: 1, DstPort: 2, Proto: layers.IPProtocolUDP, L3: []byte{0x45}, Timestamp: base, WireLen: 10})
	table.Handle(&capture.Packet{Src: a2, Dst: b2, SrcPort: 3, DstPort: 4, Proto: layers.IPProtocolUDP, L3: []byte{0x45}, Timestamp: base.Add(30 * time.Second), WireLen: 10})

	table.Expire(base.Add(61 * time.Second))
	if table.Len() != 1 {
		t.Fatalf("expected 1 flow after partial expire, got %d", table.Len())
	}

	table.Expire(base.Add(91 * time.Second))
	if table.Len() != 0 {
		t.Fatalf("expected 0 flows, got %d", table.Len())
	}
}

func TestSummaryCountsEndedFlows(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatalf("dpi.New: %v", err)
	}
	defer eng.Close()

	summary := flow.Summary{}
	table := flow.NewTable(eng, flow.Config{OnEnd: summary.Add})

	ts := time.Unix(1_700_000_000, 0)
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	table.Handle(&capture.Packet{Src: a, Dst: b, SrcPort: 1, DstPort: 2, Proto: layers.IPProtocolUDP, L3: []byte{0x45}, Timestamp: ts, WireLen: 10})
	table.Handle(&capture.Packet{Src: b, Dst: a, SrcPort: 2, DstPort: 1, Proto: layers.IPProtocolUDP, L3: []byte{0x45}, Timestamp: ts, WireLen: 20})
	table.Expire(ts.Add(time.Hour))
	table.Close()

	got := summary.Sorted()
	if len(got) != 1 || got[0].Flows != 1 || got[0].Packets != 2 || got[0].Bytes != 30 {
		t.Fatalf("unexpected summary %+v", got)
	}
}
