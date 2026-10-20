package control_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func BenchmarkPcapPipeline(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "ssh.pcap")
	benchmarkPcap(b, path, false)
}

func BenchmarkPcapPipelineWithTick(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "ssh.pcap")
	benchmarkPcap(b, path, true)
}

func benchmarkPcap(b *testing.B, path string, withTick bool) {
	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table := flow.NewTable(eng, flow.Config{})
		ctrl := control.New(eng, table, nil, nil, nil, "", false, nil, "", 0)
		src2, err := capture.OpenFile(path, "")
		if err != nil {
			b.Fatal(err)
		}
		var last, lastTick time.Time
		_ = src2.Run(context.Background(), func(p *capture.Packet) {
			if withTick {
				ctrl.TryProcessCommands()
				if lastTick.IsZero() || p.Timestamp.Sub(lastTick) >= time.Second {
					lastTick = p.Timestamp
					ctrl.Tick(p.Timestamp, src2.Stats())
				}
			}
			last = p.Timestamp
			table.Handle(p)
		}, nil)
		if withTick && !last.IsZero() {
			ctrl.Tick(last, src2.Stats())
		}
		table.Close()
		src2.Close()
	}
}
