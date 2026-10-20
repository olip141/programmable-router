package flow_test

import (
	"context"
	"strings"
	"testing"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/metrics"
)

func replay(t *testing.T, table *flow.Table, file string) {
	t.Helper()
	src, err := capture.OpenFile("../../testdata/"+file, "")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := src.Run(context.Background(), func(p *capture.Packet) { table.Handle(p) }, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNoDPISkipsInspection(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	m := metrics.New(1)
	classified := 0
	table := flow.NewTable(eng, flow.Config{NoDPI: true, Metrics: m, OnClassified: func(*flow.Flow) { classified++ }})
	replay(t, table, "ssh.pcap")

	if table.Len() == 0 {
		t.Fatal("no flows tracked")
	}
	if n := table.ActiveDPIStates(); n != 0 {
		t.Fatalf("NoDPI flows hold %d nDPI states", n)
	}
	table.Range(func(f *flow.Flow) {
		if !f.Done || f.Protocol != "Unknown" || f.DPIPackets != 0 {
			t.Errorf("flow %s: done=%v protocol=%q dpi=%d", f.Key, f.Done, f.Protocol, f.DPIPackets)
		}
	})
	table.Close()
	if classified != 0 {
		t.Fatalf("OnClassified called %d times without DPI", classified)
	}
	s := m.Snapshot()
	if s.Packets == 0 || s.FlowsNew == 0 || s.FlowsClassified != 0 {
		t.Fatalf("metrics: %+v", s)
	}
}

func TestMetricsHooksWithDPI(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	m := metrics.New(1)
	var packets, bytes uint64
	table := flow.NewTable(eng, flow.Config{Metrics: m, OnEnd: func(f *flow.Flow) {
		packets += f.Packets
		bytes += f.Bytes
	}})
	replay(t, table, "dns.pcap")
	if table.ActiveDPIStates() > table.Len() {
		t.Fatalf("ActiveDPIStates %d > Len %d", table.ActiveDPIStates(), table.Len())
	}
	table.Close()

	s := m.Snapshot()
	if s.Packets != packets || s.Bytes != bytes {
		t.Fatalf("metrics packets/bytes %d/%d, flows %d/%d", s.Packets, s.Bytes, packets, bytes)
	}
	if s.FlowsNew == 0 || s.FlowsClassified != s.FlowsNew {
		t.Fatalf("every flow should end classified after Close: %+v", s)
	}
	var histTotal uint64
	for _, n := range s.DPIPacketsHist {
		histTotal += n
	}
	if histTotal != s.FlowsClassified {
		t.Fatalf("DPI packet histogram counts %d flows, want %d", histTotal, s.FlowsClassified)
	}
	if s.HandleNsP50 == 0 {
		t.Fatal("latency not sampled with latencyEvery=1")
	}
}

func TestMasterFallsBackToApp(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	byProto := map[string]*flow.Flow{}
	table := flow.NewTable(eng, flow.Config{OnClassified: func(f *flow.Flow) { byProto[f.Protocol] = f }})
	replay(t, table, "ssh.pcap")
	replay(t, table, "tls-rdn-extract.pcap")
	table.Close()

	ssh := byProto["SSH"]
	if ssh == nil {
		t.Fatalf("no SSH flow, got %v", keys(byProto))
	}
	if ssh.Master != "SSH" || ssh.App != "SSH" {
		t.Fatalf("SSH flow master=%q app=%q, want SSH/SSH", ssh.Master, ssh.App)
	}
	for name, f := range byProto {
		if strings.Contains(name, ".") && f.Master != strings.SplitN(name, ".", 2)[0] {
			t.Errorf("%s: master %q should stay the carrier protocol", name, f.Master)
		}
	}
}

func keys(m map[string]*flow.Flow) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestClassifiedFlowKeepsMetadata(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	var got []*flow.Flow
	table := flow.NewTable(eng, flow.Config{OnClassified: func(f *flow.Flow) { got = append(got, f) }})
	replay(t, table, "dns.pcap")
	table.Close()
	if len(got) == 0 {
		t.Fatal("no classified flows")
	}
	for _, f := range got {
		if f.ClassifiedAt.IsZero() || f.ClassifiedAt.Before(f.FirstSeen) {
			t.Errorf("flow %s: ClassifiedAt %v, FirstSeen %v", f.Key, f.ClassifiedAt, f.FirstSeen)
		}
		if f.Protocol == "DNS" && f.Meta.Host == "" {
			t.Errorf("DNS flow %s without host", f.Key)
		}
	}
}
