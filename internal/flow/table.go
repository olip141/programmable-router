package flow

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket/layers"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/metrics"
)

// Config tunes a Table. Zero values select the defaults.
type Config struct {
	// MaxDPIPackets is the number of packets fed to nDPI before giving up.
	MaxDPIPackets int
	TCPTimeout    time.Duration
	UDPTimeout    time.Duration
	// OtherTimeout applies to protocols other than TCP and UDP.
	OtherTimeout time.Duration

	// OnNew is called after a flow has been created.
	OnNew func(*Flow)
	// OnClassified is called once, when nDPI inspection of a flow ends.
	OnClassified func(*Flow)
	// OnEnd is called when a flow is removed by Expire or Close.
	OnEnd func(*Flow)

	// NoDPI skips nDPI inspection (baseline capture overhead).
	NoDPI bool
	// Metrics receives pipeline counters when non-nil.
	Metrics *metrics.Collector
}

const (
	DefaultMaxDPIPackets = 32
	DefaultTCPTimeout    = 300 * time.Second
	DefaultUDPTimeout    = 60 * time.Second
	DefaultOtherTimeout  = 60 * time.Second
)

// Table maps flow keys to flows. It is not safe for concurrent use.
type Table struct {
	eng   *dpi.Engine
	cfg   Config
	flows map[Key]*Flow
}

func NewTable(eng *dpi.Engine, cfg Config) *Table {
	if cfg.MaxDPIPackets <= 0 {
		cfg.MaxDPIPackets = DefaultMaxDPIPackets
	}
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = DefaultTCPTimeout
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = DefaultUDPTimeout
	}
	if cfg.OtherTimeout <= 0 {
		cfg.OtherTimeout = DefaultOtherTimeout
	}
	return &Table{eng: eng, cfg: cfg, flows: make(map[Key]*Flow)}
}

// Len returns the number of active flows.
func (t *Table) Len() int { return len(t.flows) }

// Lookup returns the active flow for k, if any.
func (t *Table) Lookup(k Key) *Flow { return t.flows[k] }

// Range calls fn for each active flow. fn must not retain the Flow pointer.
func (t *Table) Range(fn func(*Flow)) {
	for _, f := range t.flows {
		fn(f)
	}
}

// Handle accounts p to its flow and, while inspection is still running,
// feeds it to nDPI. The returned flow stays valid after p is reused.
func (t *Table) Handle(p *capture.Packet) *Flow {
	var start time.Time
	var sampled bool
	if m := t.cfg.Metrics; m != nil {
		m.OnPacket(p.WireLen)
		start, sampled = m.SampleHandle()
	}
	key, _ := NewKey(p.Src, p.Dst, p.SrcPort, p.DstPort, p.Proto)
	f := t.flows[key]
	if f == nil {
		f = &Flow{
			Key:       key,
			Client:    netip.AddrPortFrom(p.Src, p.SrcPort),
			Server:    netip.AddrPortFrom(p.Dst, p.DstPort),
			FirstSeen: p.Timestamp,
		}
		if t.cfg.NoDPI {
			f.Done = true
			f.Protocol = "Unknown"
		} else if st, err := t.eng.NewFlow(); err == nil {
			f.state = st
		} else {
			f.Done = true
			f.Protocol = "Unknown"
		}
		t.flows[key] = f
		if t.cfg.Metrics != nil {
			t.cfg.Metrics.OnFlowNew()
		}
		if t.cfg.OnNew != nil {
			t.cfg.OnNew(f)
		}
	}

	f.Packets++
	f.Bytes += uint64(p.WireLen)
	if p.Timestamp.After(f.LastSeen) {
		f.LastSeen = p.Timestamp
	}

	if f.Done {
		if sampled {
			t.cfg.Metrics.ObserveHandle(start)
		}
		return f
	}
	f.Result = t.eng.Process(f.state, p.L3, uint64(p.Timestamp.UnixMilli()))
	f.DPIPackets++
	switch {
	case f.Result.State.Final():
		t.finish(f, false)
	case f.DPIPackets >= t.cfg.MaxDPIPackets:
		t.finish(f, true)
	}
	if sampled {
		t.cfg.Metrics.ObserveHandle(start)
	}
	return f
}

// ActiveDPIStates counts flows still holding nDPI C state.
func (t *Table) ActiveDPIStates() int {
	n := 0
	for _, f := range t.flows {
		if !f.Done && f.state != nil {
			n++
		}
	}
	return n
}

// finish ends inspection and frees the nDPI state right away, so that
// long-lived classified flows do not hold C memory.
func (t *Table) finish(f *Flow, giveUp bool) {
	if giveUp {
		f.Result = t.eng.GiveUp(f.state)
		f.GaveUp = true
	}
	f.Master = t.eng.ProtoName(f.Result.Master)
	if f.Result.App != 0 {
		f.App = t.eng.ProtoName(f.Result.App)
	}
	// nDPI reports plain protocols (SSH, DNS) as app with no master; the
	// protocol is then its own base protocol, so "master: SSH" matches.
	if f.Master == "" {
		f.Master = f.App
	}
	f.Protocol = t.eng.ProtocolName(f.Result)
	f.Category = t.eng.CategoryName(f.Result)
	f.Meta = t.eng.Metadata(f.state, f.Result)
	f.ClassifiedAt = f.LastSeen
	f.Done = true
	if t.cfg.Metrics != nil {
		unknown := f.Protocol == "" || f.Protocol == "Unknown"
		ms := f.ClassifiedAt.Sub(f.FirstSeen).Milliseconds()
		t.cfg.Metrics.OnFlowClassified(giveUp, unknown, f.DPIPackets, ms)
	}
	f.state.Free()
	f.state = nil
	if t.cfg.OnClassified != nil {
		t.cfg.OnClassified(f)
	}
}

func (t *Table) timeout(p layers.IPProtocol) time.Duration {
	switch p {
	case layers.IPProtocolTCP:
		return t.cfg.TCPTimeout
	case layers.IPProtocolUDP:
		return t.cfg.UDPTimeout
	}
	return t.cfg.OtherTimeout
}

// Expire removes flows idle for longer than their protocol timeout and
// returns how many were removed. now should come from packet timestamps so
// that offline replay behaves like live capture.
func (t *Table) Expire(now time.Time) int {
	n := 0
	for k, f := range t.flows {
		if now.Sub(f.LastSeen) > t.timeout(k.Proto) {
			t.remove(k, f)
			n++
		}
	}
	return n
}

// Close ends all remaining flows. The engine may be closed afterwards.
func (t *Table) Close() {
	for k, f := range t.flows {
		t.remove(k, f)
	}
}

func (t *Table) remove(k Key, f *Flow) {
	if !f.Done {
		t.finish(f, true)
	}
	delete(t.flows, k)
	if t.cfg.OnEnd != nil {
		t.cfg.OnEnd(f)
	}
}

// ProtocolSummary aggregates traffic by nDPI protocol name.
type ProtocolSummary struct {
	Name    string
	Flows   int
	Packets uint64
	Bytes   uint64
}

// Summary groups flows by their L7 protocol label. Feed it from Config.OnEnd
// so that flows removed by Expire are counted as well.
type Summary map[string]*ProtocolSummary

// Add accounts f to its protocol.
func (s Summary) Add(f *Flow) {
	name := f.Protocol
	if name == "" {
		name = "Unknown"
	}
	ps, ok := s[name]
	if !ok {
		ps = &ProtocolSummary{Name: name}
		s[name] = ps
	}
	ps.Flows++
	ps.Packets += f.Packets
	ps.Bytes += f.Bytes
}

// Sorted returns the per-protocol totals ordered by name.
func (s Summary) Sorted() []ProtocolSummary {
	out := make([]ProtocolSummary, 0, len(s))
	for _, ps := range s {
		out = append(out, *ps)
	}
	slices.SortFunc(out, func(a, b ProtocolSummary) int { return strings.Compare(a.Name, b.Name) })
	return out
}
