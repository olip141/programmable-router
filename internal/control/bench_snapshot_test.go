package control_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func BenchmarkPublishSnapshot10k(b *testing.B) {
	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	table := flow.NewTable(eng, flow.Config{MaxDPIPackets: 1})
	now := time.Now()
	for i := 0; i < 10_000; i++ {
		p := &capture.Packet{
			Timestamp: now,
			Src:       netip.MustParseAddr("10.2.0.1"),
			Dst:       netip.MustParseAddr("10.2.0.2"),
			SrcPort:   uint16(3000 + i%8000),
			DstPort:   443,
			Proto:     layers.IPProtocolTCP,
			L3:        []byte{0x45, 0x00, 0x00, 0x28},
			WireLen:   60,
		}
		table.Handle(p)
	}
	ctrl := control.New(eng, table, nil, nil, nil, "", false, nil, "", 0)
	cap := capture.Stats{Delivered: 10_000}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctrl.Tick(now, cap)
	}
}
