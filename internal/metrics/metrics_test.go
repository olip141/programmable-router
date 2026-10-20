package metrics

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCountersAndHistograms(t *testing.T) {
	c := New(0)
	c.OnPacket(100)
	c.OnPacket(50)
	c.OnFlowNew()
	c.OnFlowNew()
	c.OnFlowClassified(false, false, 3, 12)
	c.OnFlowClassified(true, true, 0, -5)
	c.OnFlowClassified(false, false, 10_000, 10_000_000)

	s := c.Snapshot()
	if s.Packets != 2 || s.Bytes != 150 || s.FlowsNew != 2 {
		t.Fatalf("packet/flow counters: %+v", s)
	}
	if s.FlowsClassified != 3 || s.FlowsGaveUp != 1 || s.FlowsUnknown != 1 {
		t.Fatalf("classification counters: %+v", s)
	}
	wantDPI := map[int]uint64{3: 1, 1: 1, maxDPIPacketsBucket: 1}
	for k, v := range wantDPI {
		if s.DPIPacketsHist[k] != v {
			t.Errorf("DPIPacketsHist[%d] = %d, want %d (%v)", k, s.DPIPacketsHist[k], v, s.DPIPacketsHist)
		}
	}
	wantMs := map[int]uint64{12: 1, 0: 1, maxClassifyMsBucket: 1}
	for k, v := range wantMs {
		if s.ClassifyMsHist[k] != v {
			t.Errorf("ClassifyMsHist[%d] = %d, want %d (%v)", k, s.ClassifyMsHist[k], v, s.ClassifyMsHist)
		}
	}

	s.DPIPacketsHist[3] = 99
	if c.Snapshot().DPIPacketsHist[3] != 1 {
		t.Fatal("snapshot histogram aliases collector state")
	}
}

func TestSampleHandleEveryN(t *testing.T) {
	c := New(4)
	sampled := 0
	for i := 0; i < 20; i++ {
		start, ok := c.SampleHandle()
		if ok {
			if start.IsZero() {
				t.Fatal("sampled call without start time")
			}
			sampled++
			c.ObserveHandle(start.Add(-time.Microsecond))
		} else if !start.IsZero() {
			t.Fatal("unsampled call returned a start time")
		}
	}
	if sampled != 5 {
		t.Fatalf("sampled %d of 20 calls, want 5", sampled)
	}
	s := c.Snapshot()
	if s.HandleNsP50 < 1000 || s.HandleNsP95 < s.HandleNsP50 {
		t.Fatalf("latency percentiles p50=%d p95=%d", s.HandleNsP50, s.HandleNsP95)
	}
}

func TestEnforceLeakBounded(t *testing.T) {
	c := New(1)
	for i := 0; i < 3*maxSamples; i++ {
		c.OnEnforceApply(uint64(i % 10))
	}
	if n := len(c.enforceLeakPkts); n > maxSamples || n < maxSamples/2 {
		t.Fatalf("leak samples len %d, want %d..%d", n, maxSamples/2, maxSamples)
	}
	s := c.Snapshot()
	if s.EnforceLeakP50 > 9 || s.EnforceLeakP95 < s.EnforceLeakP50 {
		t.Fatalf("leak percentiles p50=%d p95=%d", s.EnforceLeakP50, s.EnforceLeakP95)
	}
}

func TestPercentile(t *testing.T) {
	if got := percentile(nil, 50); got != 0 {
		t.Fatalf("empty percentile = %d", got)
	}
	samples := []uint64{50, 10, 40, 20, 30, 100, 90, 80, 70, 60}
	cases := map[int]uint64{0: 10, 50: 50, 95: 90, 100: 100}
	for p, want := range cases {
		if got := percentile(samples, p); got != want {
			t.Errorf("p%d = %d, want %d", p, got, want)
		}
	}
	if samples[0] != 50 {
		t.Fatal("percentile sorted the caller's slice")
	}
}

func TestSnapshotResources(t *testing.T) {
	c := New(0)
	c.SetActiveNDPIFlows(3)
	s := c.Snapshot()
	if s.RSSBytes == 0 {
		t.Error("RSSBytes is zero")
	}
	if s.ActiveNDPIFlows != 3 || s.NDPIFlowBytesEst == 0 || s.NDPIFlowBytesEst%3 != 0 {
		t.Errorf("nDPI estimate: active=%d bytes=%d", s.ActiveNDPIFlows, s.NDPIFlowBytesEst)
	}
	if s.CPUTimeUserSec+s.CPUTimeSysSec <= 0 {
		t.Error("CPU time is zero")
	}
}

func TestWriteNDJSONAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.ndjson")
	c := New(0)
	c.OnPacket(10)
	if err := WriteNDJSON(path, c.Snapshot()); err != nil {
		t.Fatal(err)
	}
	c.OnPacket(10)
	if err := WriteNDJSON(path, c.Snapshot()); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []Snapshot
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s Snapshot
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		got = append(got, s)
	}
	if len(got) != 2 || got[0].Packets != 1 || got[1].Packets != 2 || got[1].Bytes != 20 {
		t.Fatalf("ndjson lines: %+v", got)
	}
}

func TestPrometheusText(t *testing.T) {
	text := PrometheusText(Snapshot{Packets: 7, FlowsGaveUp: 2, CPUTimeUserSec: 1.5, ActiveNDPIFlows: 4})
	for _, want := range []string{
		"# TYPE router_packets_total counter\nrouter_packets_total 7\n",
		"router_flows_gave_up_total 2\n",
		"router_cpu_user_seconds_total 1.5\n",
		"router_ndpi_active_flows 4\n",
		"# TYPE router_rss_bytes gauge\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if f := strings.Fields(line); len(f) != 2 || !strings.HasPrefix(f[0], "router_") {
			t.Errorf("malformed sample line %q", line)
		}
	}
}
