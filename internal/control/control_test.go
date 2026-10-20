package control_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func TestSetRulesValidatesAndUpdates(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

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
	m := policy.NewMatcher(cfg)
	table := flow.NewTable(eng, flow.Config{})
	ctrl := control.New(eng, table, cfg, m, nil, "/tmp/policy.yaml", true, nil, "", 0)
	stop := startCommandPump(ctrl)
	defer stop()

	if err := ctrl.SetRules([]policy.Rule{
		{Name: "dns-mark", Match: map[string]string{"protocol": "DNS"}, Action: "mark", Mark: 0x11},
	}); err != nil {
		t.Fatal(err)
	}
	snap := ctrl.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].Name != "dns-mark" {
		t.Fatalf("rules: %+v", snap.Rules)
	}

	err = ctrl.SetRules([]policy.Rule{
		{Name: "bad", Match: map[string]string{"master": "SSHh"}, Action: "mark", Mark: 1},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	snap = ctrl.Snapshot()
	if snap.Rules[0].Name != "dns-mark" {
		t.Fatal("matcher should be unchanged after failed update")
	}
}

func TestSetRulesConcurrentWithPipeline(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
rules:
  - name: base
    match: { protocol: DNS }
    action: mark
    mark: 0x10
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	m := policy.NewMatcher(cfg)
	table := flow.NewTable(eng, flow.Config{})
	ctrl := control.New(eng, table, cfg, m, nil, "/tmp/policy.yaml", true, nil, "", 0)

	path := filepath.Join("..", "..", "testdata", "dns.pcap")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			src, err := capture.OpenFile(path, "")
			if err != nil {
				t.Error(err)
				return
			}
			var last time.Time
			_ = src.Run(ctx, func(p *capture.Packet) {
				ctrl.TryProcessCommands()
				last = p.Timestamp
				table.Handle(p)
			}, func(now time.Time) {
				ctrl.TryProcessCommands()
				ctrl.Tick(now, src.Stats())
			})
			src.Close()
			if !last.IsZero() {
				ctrl.Tick(last.Add(time.Second), capture.Stats{})
			}
		}
	}()

	for i := 0; i < 50; i++ {
		name := "rule-" + string(rune('a'+i%26))
		err := ctrl.SetRules([]policy.Rule{
			{Name: name, Match: map[string]string{"protocol": "DNS"}, Action: "mark", Mark: uint32(0x10 + i)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	wg.Wait()
}

func TestSnapshotFromPcap(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	table := flow.NewTable(eng, flow.Config{
		OnEnd: func(f *flow.Flow) {},
	})
	ctrl := control.New(eng, table, nil, nil, nil, "", false, nil, "", 0)

	path := filepath.Join("..", "..", "testdata", "dns.pcap")
	src, err := capture.OpenFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	var last time.Time
	_ = src.Run(context.Background(), func(p *capture.Packet) {
		last = p.Timestamp
		table.Handle(p)
	}, nil)
	if !last.IsZero() {
		ctrl.Tick(last.Add(time.Second), src.Stats())
	}
	snap := ctrl.Snapshot()
	if snap.ActiveFlows == 0 && len(snap.ProtocolSummary) == 0 {
		t.Fatalf("expected flows in snapshot, got %+v", snap)
	}
}

func startCommandPump(ctrl *control.Controller) func() {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				ctrl.TryProcessCommands()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	return func() { close(done) }
}
