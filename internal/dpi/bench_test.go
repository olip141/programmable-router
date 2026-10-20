package dpi_test

import (
	"context"
	"path/filepath"
	"testing"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
)

func BenchmarkProcessSSH(b *testing.B) {
	benchmarkPcapDPI(b, "ssh.pcap")
}

func BenchmarkProcessDNS(b *testing.B) {
	benchmarkPcapDPI(b, "dns.pcap")
}

func BenchmarkProcessHTTP(b *testing.B) {
	benchmarkPcapDPI(b, "http.pcapng")
}

func benchmarkPcapDPI(b *testing.B, name string) {
	path := filepath.Join("..", "..", "testdata", name)
	src, err := capture.OpenFile(path, "")
	if err != nil {
		b.Fatal(err)
	}
	var packets [][]byte
	var ts []uint64
	_ = src.Run(context.Background(), func(p *capture.Packet) {
		packets = append(packets, append([]byte(nil), p.L3...))
		ts = append(ts, uint64(p.Timestamp.UnixMilli()))
	}, nil)
	src.Close()
	if len(packets) == 0 {
		b.Fatal("no packets")
	}

	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := eng.NewFlow()
		if err != nil {
			b.Fatal(err)
		}
		for j, pkt := range packets {
			eng.Process(st, pkt, ts[j])
		}
		_ = eng.GiveUp(st)
		st.Free()
	}
	b.ReportMetric(float64(len(packets)), "pkts/op")
}
