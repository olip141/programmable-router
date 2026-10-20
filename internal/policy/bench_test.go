package policy_test

import (
	"fmt"
	"testing"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func BenchmarkDecide10Rules(b *testing.B)  { benchmarkDecide(b, 10) }
func BenchmarkDecide100Rules(b *testing.B) { benchmarkDecide(b, 100) }

func benchmarkDecide(b *testing.B, n int) {
	eng, err := dpi.New()
	if err != nil {
		b.Fatal(err)
	}
	defer eng.Close()

	var rules []policy.Rule
	for i := 0; i < n; i++ {
		rules = append(rules, policy.Rule{
			Name:   fmt.Sprintf("r%d", i),
			Match:  map[string]string{"master": "SSH"},
			Action: "mark",
			Mark:   uint32(0x10 + i),
		})
	}
	cfg, err := policy.LoadBytes([]byte("rules: []\nnftables:\n  drop_mark: 0xdead"))
	if err != nil {
		b.Fatal(err)
	}
	cfg.Rules = rules
	if err := cfg.Validate(eng); err != nil {
		b.Fatal(err)
	}
	m := policy.NewMatcher(cfg)
	f := &flow.Flow{Master: "SSH", Protocol: "SSH"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Decide(f)
	}
}
