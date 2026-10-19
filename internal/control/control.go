// Package control owns runtime state for the admin GUI. All mutation and
// snapshot building run on the packet pipeline goroutine via Tick.
package control

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/enforce"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

const maxFlowsInSnapshot = 500

// FlowView is a read-only flow row for the GUI.
type FlowView struct {
	Key       string
	Client    string
	Server    string
	Protocol  string
	Master    string
	App       string
	Category  string
	Packets   uint64
	Bytes     uint64
	PolicyRule string
	PolicyMark uint32
	GaveUp    bool
	Done      bool
	FirstSeen time.Time
	LastSeen  time.Time
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
}

// Meta holds static lists for policy editor dropdowns.
type Meta struct {
	Protocols  []string
	Categories []string
	MatchFields []string
	Actions    []string
}

type setRulesCmd struct {
	rules []policy.Rule
	reply chan error
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

	started    time.Time
	lastTick   time.Time
	lastSnap   capture.Stats
	lastCap    capture.Stats
	endedSum   flow.Summary

	cmdCh      chan setRulesCmd
	snap       atomic.Pointer[Snapshot]
	meta       Meta
}

// New builds a controller. editable is false when no policy file was loaded.
func New(eng *dpi.Engine, table *flow.Table, cfg *policy.Config, matcher *policy.Matcher, enf enforce.Enforcer, configPath string, editable bool) *Controller {
	c := &Controller{
		eng:        eng,
		table:      table,
		cfg:        cfg,
		matcher:    matcher,
		enf:        enf,
		configPath: configPath,
		editable:   editable,
		started:    time.Now(),
		lastTick:   time.Now(),
		endedSum:   make(flow.Summary),
		cmdCh:      make(chan setRulesCmd, 16),
		meta: Meta{
			Protocols:   eng.Protocols(),
			Categories:  eng.Categories(),
			MatchFields: []string{"protocol", "master", "app", "category"},
			Actions:     []string{"mark", "drop"},
		},
	}
	initial := &Snapshot{At: time.Now(), PolicyEditable: editable, ConfigPath: configPath}
	if cfg != nil {
		initial.Rules = append([]policy.Rule(nil), cfg.Rules...)
		initial.NFTables = cfg.NFTables
	}
	c.snap.Store(initial)
	return c
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
	if c.cfg != nil {
		rules = append([]policy.Rule(nil), c.cfg.Rules...)
		nft = c.cfg.NFTables
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
		FirstSeen:  f.FirstSeen,
		LastSeen:   f.LastSeen,
	}
}

// SetRules validates and applies rules from another goroutine (e.g. HTTP).
func (c *Controller) SetRules(rules []policy.Rule) error {
	cmd := setRulesCmd{rules: rules, reply: make(chan error, 1)}
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case c.cmdCh <- cmd:
			goto waitReply
		case <-time.After(time.Until(deadline)):
			return fmt.Errorf("control: policy update timed out")
		default:
			c.TryProcessCommands()
		}
	}
waitReply:
	for {
		select {
		case err := <-cmd.reply:
			return err
		case <-time.After(time.Until(deadline)):
			return fmt.Errorf("control: policy update timed out")
		default:
			c.TryProcessCommands()
			time.Sleep(time.Millisecond)
		}
	}
}

// TryProcessCommands non-blocking command drain for the hot packet path.
func (c *Controller) TryProcessCommands() {
	c.processCommands()
}

// ConfigForSave returns a copy of the current policy for persisting to disk.
func (c *Controller) ConfigForSave() *policy.Config {
	snap := c.Snapshot()
	if snap == nil || c.cfg == nil {
		return nil
	}
	return &policy.Config{
		NFTables: snap.NFTables,
		Rules:    append([]policy.Rule(nil), snap.Rules...),
	}
}
