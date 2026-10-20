package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"edge-router/internal/dpi"
)

// Collector gathers runtime counters (packet pipeline goroutine only).
type Collector struct {
	Packets         uint64
	Bytes           uint64
	FlowsNew        uint64
	FlowsClassified uint64
	FlowsGaveUp     uint64
	FlowsUnknown    uint64
	enforceLeakPkts []uint64 // packets before nft apply per flow sample

	dpiPacketsHist  map[int]uint64
	classifyMsHist  map[int]uint64
	handleNsSamples []uint64
	latencyEvery    uint64
	sampleCounter   uint64

	activeNDPIFlows int
}

const (
	maxDPIPacketsBucket = 255
	maxClassifyMsBucket = 60000
	maxSamples          = 2048
)

// New creates a collector. latencyEvery is sample 1/N handle calls for latency (0 = default 64).
func New(latencyEvery uint64) *Collector {
	if latencyEvery == 0 {
		latencyEvery = 64
	}
	return &Collector{
		dpiPacketsHist:  make(map[int]uint64),
		classifyMsHist:  make(map[int]uint64),
		latencyEvery:    latencyEvery,
		enforceLeakPkts: make([]uint64, 0, 1024),
	}
}

func (c *Collector) OnPacket(wireLen int) {
	c.Packets++
	c.Bytes += uint64(wireLen)
}

func (c *Collector) OnFlowNew() { c.FlowsNew++ }

func (c *Collector) OnFlowClassified(gaveUp bool, unknown bool, dpiPackets int, classifyMs int64) {
	c.FlowsClassified++
	if gaveUp {
		c.FlowsGaveUp++
	}
	if unknown {
		c.FlowsUnknown++
	}
	if dpiPackets < 1 {
		dpiPackets = 1
	}
	if dpiPackets > maxDPIPacketsBucket {
		dpiPackets = maxDPIPacketsBucket
	}
	c.dpiPacketsHist[dpiPackets]++
	if classifyMs < 0 {
		classifyMs = 0
	}
	bucket := int(classifyMs)
	if bucket > maxClassifyMsBucket {
		bucket = maxClassifyMsBucket
	}
	c.classifyMsHist[bucket]++
}

func (c *Collector) OnEnforceApply(packetsBeforeMark uint64) {
	c.enforceLeakPkts = appendBounded(c.enforceLeakPkts, packetsBeforeMark)
}

func (c *Collector) SetActiveNDPIFlows(n int) { c.activeNDPIFlows = n }

// SampleHandle reports whether this Handle call is sampled for latency and,
// if so, its start time. Only sampled calls pay for time.Now.
func (c *Collector) SampleHandle() (time.Time, bool) {
	c.sampleCounter++
	if c.sampleCounter%c.latencyEvery != 0 {
		return time.Time{}, false
	}
	return time.Now(), true
}

// ObserveHandle records the latency of a call sampled by SampleHandle.
func (c *Collector) ObserveHandle(start time.Time) {
	c.handleNsSamples = appendBounded(c.handleNsSamples, uint64(time.Since(start).Nanoseconds()))
}

// appendBounded keeps the most recent maxSamples/2..maxSamples values.
func appendBounded(s []uint64, v uint64) []uint64 {
	s = append(s, v)
	if len(s) > maxSamples {
		s = append(s[:0], s[len(s)-maxSamples/2:]...)
	}
	return s
}

// Snapshot is a point-in-time metrics view for export.
type Snapshot struct {
	At               time.Time
	Packets          uint64
	Bytes            uint64
	FlowsNew         uint64
	FlowsClassified  uint64
	FlowsGaveUp      uint64
	FlowsUnknown     uint64
	DPIPacketsHist   map[int]uint64
	ClassifyMsHist   map[int]uint64
	HandleNsP50      uint64
	HandleNsP95      uint64
	EnforceLeakP50   uint64
	EnforceLeakP95   uint64
	RSSBytes         uint64
	CPUTimeUserSec   float64
	CPUTimeSysSec    float64
	NumGC            uint32
	ActiveNDPIFlows  int
	NDPIFlowBytesEst uint64
}

func (c *Collector) Snapshot() Snapshot {
	s := Snapshot{
		At:               time.Now(),
		Packets:          c.Packets,
		Bytes:            c.Bytes,
		FlowsNew:         c.FlowsNew,
		FlowsClassified:  c.FlowsClassified,
		FlowsGaveUp:      c.FlowsGaveUp,
		FlowsUnknown:     c.FlowsUnknown,
		DPIPacketsHist:   copyMap(c.dpiPacketsHist),
		ClassifyMsHist:   copyMap(c.classifyMsHist),
		HandleNsP50:      percentile(c.handleNsSamples, 50),
		HandleNsP95:      percentile(c.handleNsSamples, 95),
		EnforceLeakP50:   percentile(c.enforceLeakPkts, 50),
		EnforceLeakP95:   percentile(c.enforceLeakPkts, 95),
		RSSBytes:         readRSS(),
		ActiveNDPIFlows:  c.activeNDPIFlows,
		NDPIFlowBytesEst: uint64(c.activeNDPIFlows) * uint64(dpi.FlowStructSize()),
	}
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err == nil {
		s.CPUTimeUserSec = float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
		s.CPUTimeSysSec = float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.NumGC = ms.NumGC
	return s
}

func copyMap(m map[int]uint64) map[int]uint64 {
	out := make(map[int]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func percentile(samples []uint64, p int) uint64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]uint64(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := (len(cp) - 1) * p / 100
	return cp[idx]
}

func readRSS() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

var fileMu sync.Mutex

// WriteNDJSON appends one JSON line to path.
func WriteNDJSON(path string, snap Snapshot) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(snap)
}

// PrometheusText renders snap as Prometheus exposition format.
func PrometheusText(snap Snapshot) string {
	var b strings.Builder
	metric := func(name, typ, help string, value any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, value)
	}
	metric("router_packets_total", "counter", "Packets delivered to the pipeline.", snap.Packets)
	metric("router_bytes_total", "counter", "Wire bytes delivered to the pipeline.", snap.Bytes)
	metric("router_flows_new_total", "counter", "Flows created.", snap.FlowsNew)
	metric("router_flows_classified_total", "counter", "Flows whose inspection ended.", snap.FlowsClassified)
	metric("router_flows_gave_up_total", "counter", "Flows that hit the DPI packet limit.", snap.FlowsGaveUp)
	metric("router_flows_unknown_total", "counter", "Flows that ended as Unknown.", snap.FlowsUnknown)
	metric("router_handle_ns_p50", "gauge", "Median per-packet handle latency (sampled).", snap.HandleNsP50)
	metric("router_handle_ns_p95", "gauge", "95th percentile per-packet handle latency (sampled).", snap.HandleNsP95)
	metric("router_enforce_leak_packets_p50", "gauge", "Median packets seen before the nft verdict was installed.", snap.EnforceLeakP50)
	metric("router_enforce_leak_packets_p95", "gauge", "95th percentile packets seen before the nft verdict was installed.", snap.EnforceLeakP95)
	metric("router_rss_bytes", "gauge", "Resident set size.", snap.RSSBytes)
	metric("router_cpu_user_seconds_total", "counter", "User CPU time.", snap.CPUTimeUserSec)
	metric("router_cpu_system_seconds_total", "counter", "System CPU time.", snap.CPUTimeSysSec)
	metric("router_go_gc_total", "counter", "Completed Go GC cycles.", snap.NumGC)
	metric("router_ndpi_active_flows", "gauge", "Flows holding nDPI state.", snap.ActiveNDPIFlows)
	metric("router_ndpi_flow_bytes_est", "gauge", "Estimated nDPI flow state memory.", snap.NDPIFlowBytesEst)
	return b.String()
}
