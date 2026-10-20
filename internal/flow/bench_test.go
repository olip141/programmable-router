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

func BenchmarkHandle10k(b *testing.B)  { benchmarkHandleFlows(b, 10_000) }
func BenchmarkHandle100k(b *testing.B) { benchmarkHandleFlows(b, 100_000) }

func benchmarkHandleFlows(b *testing.B, n int) {
	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	pkts := make([]*capture.Packet, n)
	base := time.Now()
	for i := 0; i < n; i++ {
		pkts[i] = &capture.Packet{
			Timestamp: base.Add(time.Microsecond * time.Duration(i)),
			Src:       netip.MustParseAddr("10.0.0.1"),
			Dst:       netip.MustParseAddr("10.0.0.2"),
			SrcPort:   uint16(1000 + i%1000),
			DstPort:   443,
			Proto:     layers.IPProtocolTCP,
			L3:        []byte{0x45, 0x00, 0x00, 0x28},
			WireLen:   60,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table := flow.NewTable(eng, flow.Config{MaxDPIPackets: 4})
		for _, p := range pkts {
			table.Handle(p)
		}
		table.Close()
	}
	b.ReportMetric(float64(n), "flows/op")
}

func BenchmarkExpire10k(b *testing.B)  { benchmarkExpire(b, 10_000) }
func BenchmarkExpire100k(b *testing.B) { benchmarkExpire(b, 100_000) }

func benchmarkExpire(b *testing.B, n int) {
	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()
	table := flow.NewTable(eng, flow.Config{MaxDPIPackets: 1, TCPTimeout: time.Second})
	now := time.Now()
	for i := 0; i < n; i++ {
		p := &capture.Packet{
			Timestamp: now,
			Src:       netip.MustParseAddr("10.1.0.1"),
			Dst:       netip.MustParseAddr("10.1.0.2"),
			SrcPort:   uint16(2000 + i%5000),
			DstPort:   80,
			Proto:     layers.IPProtocolTCP,
			L3:        []byte{0x45, 0x00, 0x00, 0x28},
			WireLen:   60,
		}
		table.Handle(p)
	}
	deadline := now.Add(2 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.Expire(deadline)
	}
	b.ReportMetric(float64(n), "flows")
}
