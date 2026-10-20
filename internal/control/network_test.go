package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/metrics"
	"edge-router/internal/netinfo"
	"edge-router/internal/policy"
)

func newController(t *testing.T, editable bool, m *metrics.Collector, statsFile string) (*dpi.Engine, *flow.Table, *control.Controller) {
	t.Helper()
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
rules:
  - name: ssh-mark
    match: { master: SSH }
    action: mark
    mark: 0x20
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	table := flow.NewTable(eng, flow.Config{Metrics: m})
	ctrl := control.New(eng, table, cfg, policy.NewMatcher(cfg), nil, "", editable, m, statsFile, time.Second)
	ctrl.SetNetworkDryRun(true)
	return eng, table, ctrl
}

func networkConfig() (policy.QoSConfig, policy.RoutingConfig) {
	return policy.QoSConfig{
		Enabled:    true,
		Interfaces: []policy.QoSInterface{{Name: "eth1", Rate: "100mbit"}},
		Classes:    []policy.QoSClass{{Name: "ssh", Mark: 0x20, Rate: "5mbit"}},
	}, policy.RoutingConfig{
		Enabled: true,
		Routes:  []policy.RoutingRoute{{Name: "alt", Mark: 0x30, Table: 200, Gateway: "10.0.0.1"}},
	}
}

func TestSetNetworkDryRunUpdatesConfig(t *testing.T) {
	_, _, ctrl := newController(t, true, nil, "")
	stop := startCommandPump(ctrl)
	defer stop()

	q, r := networkConfig()
	if err := ctrl.SetNetwork(q, r); err != nil {
		t.Fatal(err)
	}
	snap := ctrl.Snapshot()
	if !snap.QoS.Enabled || len(snap.QoS.Classes) != 1 || snap.Routing.Routes[0].Table != 200 {
		t.Fatalf("network config not published: %+v %+v", snap.QoS, snap.Routing)
	}
	if len(snap.Rules) != 1 || snap.Rules[0].Name != "ssh-mark" {
		t.Fatalf("rules changed by SetNetwork: %+v", snap.Rules)
	}
	saved := ctrl.ConfigForSave()
	if saved == nil || !saved.QoS.Enabled || !saved.Routing.Enabled {
		t.Fatalf("ConfigForSave lacks network sections: %+v", saved)
	}

	// The caller's slices must not leak into the published snapshot.
	q.Classes[0].Rate = "1bit"
	if ctrl.Snapshot().QoS.Classes[0].Rate != "5mbit" {
		t.Fatal("snapshot aliases caller's QoS classes")
	}
	saved.Rules[0].Match["master"] = "DNS"
	if ctrl.Snapshot().Rules[0].Match["master"] != "SSH" {
		t.Fatal("ConfigForSave aliases snapshot rules")
	}
}

// fakeHost is a router with eth0 as WAN and eth1 as the only LAN.
func fakeHost(capture string, names ...string) *netinfo.Host {
	return &netinfo.Host{Capture: capture, List: func() ([]netinfo.Interface, error) {
		all := []netinfo.Interface{
			{Name: "eth0", Up: true, OperState: "up", Addrs: []string{"203.0.113.10/24"}},
			{Name: "eth1", Up: true, OperState: "up", Addrs: []string{"192.168.1.1/24"}},
		}
		var ifs []netinfo.Interface
		for _, i := range all {
			if len(names) == 0 || slices.Contains(names, i.Name) {
				ifs = append(ifs, i)
			}
		}
		netinfo.Classify(ifs, []netinfo.Route{{Dev: "eth0", Gateway: "203.0.113.1", Metric: 100}})
		return ifs, nil
	}}
}

func TestSetNetworkResolvesAliases(t *testing.T) {
	_, _, ctrl := newController(t, true, nil, "")
	ctrl.SetHost(fakeHost("eth1"))
	stop := startCommandPump(ctrl)
	defer stop()

	q, r := networkConfig()
	q.Interfaces = []policy.QoSInterface{{Name: "wan", Rate: "20mbit"}, {Name: "lan", Rate: "100mbit"}}
	if err := ctrl.SetNetwork(q, r); err != nil {
		t.Fatal(err)
	}
	ifs := ctrl.Snapshot().QoS.Interfaces
	if ifs[0].Device() != "eth0" || ifs[1].Device() != "eth1" {
		t.Fatalf("aliases not resolved: %+v", ifs)
	}
	data, err := ctrl.ConfigForSave().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "name: wan") || strings.Contains(string(data), "eth0") {
		t.Fatalf("saved config must keep the alias:\n%s", data)
	}

	view, err := ctrl.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	want := []control.IfaceBinding{{Name: "wan", Device: "eth0"}, {Name: "lan", Device: "eth1"}}
	if !slices.Equal(view.QoS, want) || view.Aliases["wan"] != "eth0" || view.Capture != "eth1" {
		t.Fatalf("interfaces view %+v", view)
	}
}

func TestSetNetworkRejectsUnknownInterface(t *testing.T) {
	_, _, ctrl := newController(t, true, nil, "")
	ctrl.SetHost(fakeHost(""))
	q, r := networkConfig()
	q.Interfaces[0].Name = "ens9"

	// Live mode fails before any tc/ip command runs.
	ctrl.SetNetworkDryRun(false)
	if err := ctrl.SetNetwork(q, r); err == nil || !strings.Contains(err.Error(), `interface "ens9" does not exist; available: eth0 (WAN), eth1 (LAN)`) {
		t.Fatalf("expected missing interface error, got %v", err)
	}
	if ctrl.Snapshot().QoS.Enabled {
		t.Fatal("rejected update was published")
	}

	// Dry-run only warns, and the GUI view shows the broken binding.
	ctrl.SetNetworkDryRun(true)
	stop := startCommandPump(ctrl)
	defer stop()
	if err := ctrl.SetNetwork(q, r); err != nil {
		t.Fatal(err)
	}
	view, err := ctrl.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(view.QoS) != 1 || view.QoS[0].Device != "" || !strings.Contains(view.QoS[0].Error, "does not exist") {
		t.Fatalf("binding error not reported: %+v", view.QoS)
	}
}

func TestQoSStatsResolvesAlias(t *testing.T) {
	_, _, ctrl := newController(t, true, nil, "")
	ctrl.SetHost(fakeHost("", "eth0"))
	if _, err := ctrl.QoSStats("lan"); err == nil || !strings.Contains(err.Error(), "no LAN interface") {
		t.Fatalf("expected lan resolution error, got %v", err)
	}
}

func TestSetNetworkRejectsInvalid(t *testing.T) {
	_, _, ctrl := newController(t, true, nil, "")
	stop := startCommandPump(ctrl)
	defer stop()

	q, r := networkConfig()
	q.Classes[0].Mark = 0xdead
	if err := ctrl.SetNetwork(q, r); err == nil || !strings.Contains(err.Error(), "drop_mark") {
		t.Fatalf("expected drop_mark conflict, got %v", err)
	}
	q, r = networkConfig()
	r.Routes[0].Table = 0
	if err := ctrl.SetNetwork(q, r); err == nil {
		t.Fatal("expected invalid table error")
	}
	if snap := ctrl.Snapshot(); snap.QoS.Enabled || snap.Routing.Enabled {
		t.Fatalf("invalid update was published: %+v %+v", snap.QoS, snap.Routing)
	}
}

func TestSetNetworkReadOnly(t *testing.T) {
	_, _, ctrl := newController(t, false, nil, "")
	q, r := networkConfig()
	if err := ctrl.SetNetwork(q, r); err == nil {
		t.Fatal("SetNetwork succeeded on a read-only policy")
	}
	if ctrl.ConfigForSave() != nil {
		t.Fatal("ConfigForSave should be nil when policy is read-only")
	}
}

// Run with -race: HTTP-side readers encode snapshots while the pipeline
// applies rule and network updates.
func TestPolicyUpdatesConcurrentWithReaders(t *testing.T) {
	_, table, ctrl := newController(t, true, metrics.New(1), "")
	path := filepath.Join("..", "..", "testdata", "dns.pcap")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			src, err := capture.OpenFile(path, "")
			if err != nil {
				t.Error(err)
				return
			}
			_ = src.Run(ctx, func(p *capture.Packet) {
				ctrl.TryProcessCommands()
				table.Handle(p)
			}, func(now time.Time) {
				ctrl.Tick(now, src.Stats())
			})
			ctrl.Tick(time.Now(), src.Stats())
			src.Close()
		}
	}()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			snap := ctrl.Snapshot()
			if _, err := json.Marshal(snap); err != nil {
				t.Error(err)
				return
			}
			if cfg := ctrl.ConfigForSave(); cfg != nil {
				if _, err := cfg.Marshal(); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()

	q, r := networkConfig()
	for i := 0; i < 20; i++ {
		q.Classes[0].Rate = []string{"5mbit", "6mbit"}[i%2]
		if err := ctrl.SetNetwork(q, r); err != nil {
			t.Fatal(err)
		}
		if err := ctrl.SetRules([]policy.Rule{
			{Name: "dns", Match: map[string]string{"protocol": "dns", "host": "*.example.com"}, Action: "mark", Mark: 0x20},
		}); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	wg.Wait()
	if got := ctrl.Snapshot().Rules[0].Match["protocol"]; got != "DNS" {
		t.Fatalf("rule not canonicalised: %q", got)
	}
}

func TestTickWritesStatsAtInterval(t *testing.T) {
	statsFile := filepath.Join(t.TempDir(), "stats.ndjson")
	m := metrics.New(1)
	_, _, ctrl := newController(t, true, m, statsFile)

	t0 := time.Unix(1_700_000_000, 0)
	for _, d := range []time.Duration{0, 300 * time.Millisecond, 999 * time.Millisecond, time.Second, 1500 * time.Millisecond, 2 * time.Second} {
		ctrl.Tick(t0.Add(d), capture.Stats{})
	}
	data, err := os.ReadFile(statsFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("got %d NDJSON lines at t=0,1s,2s, want 3:\n%s", len(lines), data)
	}
	var s metrics.Snapshot
	if err := json.Unmarshal(lines[0], &s); err != nil {
		t.Fatal(err)
	}
	if ctrl.Snapshot().Metrics.RSSBytes == 0 {
		t.Fatal("snapshot lacks metrics")
	}
}
