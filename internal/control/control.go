// Package control owns runtime state for the admin GUI. All mutation and
// snapshot building run on the packet pipeline goroutine via Tick.
package control

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/enforce"
	"edge-router/internal/flow"
	"edge-router/internal/metrics"
	"edge-router/internal/netinfo"
	"edge-router/internal/policy"
	"edge-router/internal/qos"
	"edge-router/internal/routing"
)

const maxFlowsInSnapshot = 500

// FlowView is a read-only flow row for the GUI.
type FlowView struct {
	Key        string
	Client     string
	Server     string
	Protocol   string
	Master     string
	App        string
	Category   string
	Packets    uint64
	Bytes      uint64
	PolicyRule string
	PolicyMark uint32
	GaveUp     bool
	Done       bool
	Host       string
	Confidence string
	Risks      []string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Snapshot is an immutable view published for HTTP handlers.
type Snapshot struct {
	At              time.Time
	Uptime          time.Duration
	PacketsPerSec   float64
	ActiveFlows     int
	Capture         capture.Stats
	Enforcer        enforce.Stats
	RuleHits        map[string]int
	ProtocolSummary []flow.ProtocolSummary
	Flows           []FlowView
	PolicyEditable  bool
	ConfigPath      string
	Rules           []policy.Rule
	NFTables        policy.NFTConfig
	QoS             policy.QoSConfig
	Routing         policy.RoutingConfig
	Metrics         metrics.Snapshot
}

// Meta holds static lists for policy editor dropdowns.
type Meta struct {
	Protocols   []string
	Categories  []string
	MatchFields []string
	Actions     []string
	Risks       []string
	Confidences []string
}

type setRulesCmd struct {
	rules []policy.Rule
	reply chan error
}

type setNetworkCmd struct {
	qos     policy.QoSConfig
	routing policy.RoutingConfig
	reply   chan error
}

// Controller coordinates policy hot-reload and GUI snapshots.
type Controller struct {
	eng        *dpi.Engine
	table      *flow.Table
	cfg        *policy.Config
	matcher    *policy.Matcher
	enf        enforce.Enforcer
	configPath string
	editable   bool

	started  time.Time
	lastTick time.Time
	lastSnap capture.Stats
	lastCap  capture.Stats
	endedSum flow.Summary

	cmdCh          chan setRulesCmd
	netCmdCh       chan setNetworkCmd
	snap           atomic.Pointer[Snapshot]
	meta           Meta
	metrics        *metrics.Collector
	statsFile      string
	statsInterval  time.Duration
	lastStatsWrite time.Time

	// netMu serialises SetNetwork calls: tc/ip changes and the matching
	// config update must not interleave between HTTP requests.
	netMu     sync.Mutex
	netDryRun bool
	host      *netinfo.Host
}

// IfaceBinding shows which device a configured QoS interface maps to.
type IfaceBinding struct {
	Name   string `json:"name"`
	Device string `json:"device,omitempty"`
	Error  string `json:"error,omitempty"`
}

// InterfacesView is the host interface report plus the QoS bindings.
type InterfacesView struct {
	netinfo.Report
	QoS []IfaceBinding `json:"qos"`
}

// New builds a controller. editable is false when no policy file was loaded.
func New(eng *dpi.Engine, table *flow.Table, cfg *policy.Config, matcher *policy.Matcher, enf enforce.Enforcer, configPath string, editable bool, m *metrics.Collector, statsFile string, statsInterval time.Duration) *Controller {
	c := &Controller{
		eng:           eng,
		table:         table,
		cfg:           cfg,
		matcher:       matcher,
		enf:           enf,
		configPath:    configPath,
		editable:      editable,
		started:       time.Now(),
		lastTick:      time.Now(),
		endedSum:      make(flow.Summary),
		cmdCh:         make(chan setRulesCmd, 16),
		netCmdCh:      make(chan setNetworkCmd, 8),
		metrics:       m,
		statsFile:     statsFile,
		statsInterval: statsInterval,
		meta: Meta{
			Protocols:   eng.Protocols(),
			Categories:  eng.Categories(),
			MatchFields: []string{"protocol", "master", "app", "category", "host", "risk", "confidence"},
			Actions:     []string{"mark", "drop"},
			Risks:       eng.Risks(),
			Confidences: eng.Confidences(),
		},
	}
	initial := &Snapshot{At: time.Now(), PolicyEditable: editable, ConfigPath: configPath}
	if cfg != nil {
		cp := cfg.Clone()
		initial.Rules = cp.Rules
		initial.NFTables = cp.NFTables
		initial.QoS = cp.QoS
		initial.Routing = cp.Routing
	}
	c.snap.Store(initial)
	return c
}

// SetNetworkDryRun makes SetNetwork log tc/ip commands instead of running
// them. Call before the HTTP server starts.
func (c *Controller) SetNetworkDryRun(on bool) { c.netDryRun = on }

// SetHost sets how interface names and aliases are resolved. Call before the
// HTTP server starts. Without it the live system is used with no capture
// interface.
func (c *Controller) SetHost(h *netinfo.Host) { c.host = h }

// Interfaces reports host interfaces, aliases and the QoS bindings (HTTP goroutine).
func (c *Controller) Interfaces() (InterfacesView, error) {
	rep, err := c.host.Report()
	if err != nil {
		return InterfacesView{}, err
	}
	view := InterfacesView{Report: rep, QoS: []IfaceBinding{}}
	for _, ifc := range c.Snapshot().QoS.Interfaces {
		b := IfaceBinding{Name: ifc.Name}
		if dev, err := netinfo.Resolve(ifc.Name, rep.Capture, rep.Interfaces); err != nil {
			b.Error = err.Error()
		} else {
			b.Device = dev
		}
		view.QoS = append(view.QoS, b)
	}
	return view, nil
}

// Meta returns static editor metadata.
func (c *Controller) Meta() Meta { return c.meta }

// Snapshot loads the latest published snapshot.
func (c *Controller) Snapshot() *Snapshot {
	if p := c.snap.Load(); p != nil {
		return p
	}
	return &Snapshot{}
}

// Matcher returns the current matcher (pipeline goroutine only).
func (c *Controller) Matcher() *policy.Matcher { return c.matcher }

// Config returns the current policy config (pipeline goroutine only).
func (c *Controller) Config() *policy.Config { return c.cfg }

// SetMatcher replaces matcher and config rules on the pipeline goroutine.
func (c *Controller) setMatcher(cfg *policy.Config, m *policy.Matcher) {
	c.cfg = cfg
	c.matcher = m
}

// OnFlowEnd feeds ended-flow summary accounting.
func (c *Controller) OnFlowEnd(f *flow.Flow) {
	c.endedSum.Add(f)
}

// Tick runs once per second (or on idle): expire flows, process commands, publish snapshot.
func (c *Controller) Tick(now time.Time, capStats capture.Stats) {
	c.lastCap = capStats
	c.table.Expire(now)
	c.processCommands()
	if c.metrics != nil {
		c.metrics.SetActiveNDPIFlows(c.table.ActiveDPIStates())
		if c.statsFile != "" && c.statsInterval > 0 {
			if c.lastStatsWrite.IsZero() || now.Sub(c.lastStatsWrite) >= c.statsInterval {
				_ = metrics.WriteNDJSON(c.statsFile, c.metrics.Snapshot())
				c.lastStatsWrite = now
			}
		}
	}
	c.publishSnapshot(now, capStats)
	c.lastTick = now
}

// processCommands drains pending set-rules commands (non-blocking between packets).
func (c *Controller) processCommands() {
	for {
		select {
		case cmd := <-c.cmdCh:
			err := c.applyRules(cmd.rules)
			cmd.reply <- err
		case ncmd := <-c.netCmdCh:
			err := c.applyNetwork(ncmd.qos, ncmd.routing)
			ncmd.reply <- err
		default:
			return
		}
	}
}

func (c *Controller) applyRules(rules []policy.Rule) error {
	if c.cfg == nil {
		return fmt.Errorf("control: no policy config loaded")
	}
	newCfg, err := c.cfg.WithRules(rules)
	if err != nil {
		return err
	}
	if err := newCfg.Validate(c.eng); err != nil {
		return err
	}
	policy.WarnOrphanMarks(newCfg)
	c.setMatcher(newCfg, policy.NewMatcher(newCfg))
	c.publishSnapshot(time.Now(), c.lastCap)
	return nil
}

func (c *Controller) publishSnapshot(now time.Time, capStats capture.Stats) {
	var enfStats enforce.Stats
	if c.enf != nil {
		enfStats = c.enf.Stats()
	}
	hits := map[string]int{}
	if c.matcher != nil {
		for k, v := range c.matcher.Hits() {
			hits[k] = v
		}
	}

	elapsed := now.Sub(c.lastTick).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	pps := float64(capStats.Delivered-c.lastSnap.Delivered) / elapsed

	combined := flow.Summary{}
	for name, ps := range c.endedSum {
		combined[name] = &flow.ProtocolSummary{
			Name:    ps.Name,
			Flows:   ps.Flows,
			Packets: ps.Packets,
			Bytes:   ps.Bytes,
		}
	}
	c.table.Range(func(f *flow.Flow) {
		name := f.Protocol
		if name == "" {
			name = "Unknown"
		}
		ps, ok := combined[name]
		if !ok {
			ps = &flow.ProtocolSummary{Name: name}
			combined[name] = ps
		}
		ps.Flows++
		ps.Packets += f.Packets
		ps.Bytes += f.Bytes
	})

	flows := make([]FlowView, 0, c.table.Len())
	c.table.Range(func(f *flow.Flow) {
		flows = append(flows, flowToView(f))
	})
	slices.SortFunc(flows, func(a, b FlowView) int {
		if a.Bytes != b.Bytes {
			if a.Bytes > b.Bytes {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(flows) > maxFlowsInSnapshot {
		flows = flows[:maxFlowsInSnapshot]
	}

	var rules []policy.Rule
	var nft policy.NFTConfig
	var qosCfg policy.QoSConfig
	var rtCfg policy.RoutingConfig
	if c.cfg != nil {
		cp := c.cfg.Clone()
		rules = cp.Rules
		nft = cp.NFTables
		qosCfg = cp.QoS
		rtCfg = cp.Routing
	}
	var mSnap metrics.Snapshot
	if c.metrics != nil {
		mSnap = c.metrics.Snapshot()
	}
	snap := &Snapshot{
		At:              now,
		Uptime:          now.Sub(c.started),
		PacketsPerSec:   pps,
		ActiveFlows:     c.table.Len(),
		Capture:         capStats,
		Enforcer:        enfStats,
		RuleHits:        hits,
		ProtocolSummary: combined.Sorted(),
		Flows:           flows,
		PolicyEditable:  c.editable,
		ConfigPath:      c.configPath,
		Rules:           rules,
		NFTables:        nft,
		QoS:             qosCfg,
		Routing:         rtCfg,
		Metrics:         mSnap,
	}
	c.snap.Store(snap)
	c.lastSnap = capStats
}

func flowToView(f *flow.Flow) FlowView {
	return FlowView{
		Key:        f.Key.String(),
		Client:     f.Client.String(),
		Server:     f.Server.String(),
		Protocol:   f.Protocol,
		Master:     f.Master,
		App:        f.App,
		Category:   f.Category,
		Packets:    f.Packets,
		Bytes:      f.Bytes,
		PolicyRule: f.PolicyRule,
		PolicyMark: f.PolicyMark,
		GaveUp:     f.GaveUp,
		Done:       f.Done,
		Host:       f.Meta.Host,
		Confidence: f.Meta.Confidence,
		Risks:      append([]string(nil), f.Meta.Risks...),
		FirstSeen:  f.FirstSeen,
		LastSeen:   f.LastSeen,
	}
}

func (c *Controller) applyNetwork(qosCfg policy.QoSConfig, rtCfg policy.RoutingConfig) error {
	if c.cfg == nil {
		return fmt.Errorf("control: no policy config loaded")
	}
	newCfg, err := c.cfg.WithNetwork(qosCfg, rtCfg)
	if err != nil {
		return err
	}
	if err := newCfg.Validate(c.eng); err != nil {
		return err
	}
	policy.WarnOrphanMarks(newCfg)
	c.cfg = newCfg
	c.publishSnapshot(time.Now(), c.lastCap)
	return nil
}

// SetNetwork applies tc/ip on the caller goroutine, then updates config on the pipeline.
func (c *Controller) SetNetwork(qosCfg policy.QoSConfig, rtCfg policy.RoutingConfig) error {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	snap := c.Snapshot()
	if !snap.PolicyEditable {
		return fmt.Errorf("control: no policy config loaded")
	}
	trial := &policy.Config{NFTables: snap.NFTables, QoS: qosCfg, Routing: rtCfg}
	trial = trial.Clone()
	if err := trial.ValidateNetwork(); err != nil {
		return err
	}
	if err := policy.ResolveQoSInterfaces(&trial.QoS, c.host.Resolve); err != nil {
		if !c.netDryRun {
			return err
		}
		log.Printf("dry-run: %v", err)
	}
	if err := c.replaceNetwork(snap.QoS, snap.Routing, trial.QoS, trial.Routing); err != nil {
		return err
	}

	cmd := setNetworkCmd{qos: trial.QoS, routing: trial.Routing, reply: make(chan error, 1)}
	deadline := time.Now().Add(10 * time.Second)
	select {
	case c.netCmdCh <- cmd:
	case <-time.After(time.Until(deadline)):
		return fmt.Errorf("control: network update timed out")
	}
	select {
	case err := <-cmd.reply:
		return err
	case <-time.After(time.Until(deadline)):
		return fmt.Errorf("control: network update timed out")
	}
}

// replaceNetwork removes the old tc/ip setup and installs the new one. On
// failure it tries to restore the old setup.
func (c *Controller) replaceNetwork(oldQ policy.QoSConfig, oldR policy.RoutingConfig, newQ policy.QoSConfig, newR policy.RoutingConfig) error {
	if c.netDryRun {
		for _, argv := range append(qos.Commands(newQ), routing.Commands(newR)...) {
			log.Printf("dry-run: %s", strings.Join(argv, " "))
		}
		return nil
	}
	qos.Teardown(oldQ)
	routing.Teardown(oldR)
	err := qos.Apply(newQ)
	if err == nil {
		err = routing.Apply(newR)
	}
	if err != nil {
		qos.Teardown(newQ)
		routing.Teardown(newR)
		_ = qos.Apply(oldQ)
		_ = routing.Apply(oldR)
	}
	return err
}

// QoSStats returns tc class stats for iface, which may be an alias (HTTP goroutine).
func (c *Controller) QoSStats(iface string) ([]qos.ClassStats, error) {
	if netinfo.IsAlias(iface) {
		dev, err := c.host.Resolve(iface)
		if err != nil {
			return nil, err
		}
		iface = dev
	}
	return qos.Stats(iface, c.Snapshot().QoS)
}

// SetRules validates and applies rules from another goroutine (e.g. HTTP).
// The packet pipeline must call TryProcessCommands to apply the update.
func (c *Controller) SetRules(rules []policy.Rule) error {
	cmd := setRulesCmd{rules: rules, reply: make(chan error, 1)}
	deadline := time.Now().Add(5 * time.Second)
	select {
	case c.cmdCh <- cmd:
	case <-time.After(time.Until(deadline)):
		return fmt.Errorf("control: policy update timed out")
	}
	select {
	case err := <-cmd.reply:
		return err
	case <-time.After(time.Until(deadline)):
		return fmt.Errorf("control: policy update timed out")
	}
}

// TryProcessCommands non-blocking command drain for the hot packet path.
func (c *Controller) TryProcessCommands() {
	c.processCommands()
}

// ConfigForSave returns a copy of the current policy for persisting to disk.
func (c *Controller) ConfigForSave() *policy.Config {
	snap := c.Snapshot()
	if snap == nil || !snap.PolicyEditable {
		return nil
	}
	return (&policy.Config{
		NFTables: snap.NFTables,
		QoS:      snap.QoS,
		Routing:  snap.Routing,
		Rules:    snap.Rules,
	}).Clone()
}
