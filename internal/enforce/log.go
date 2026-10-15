package enforce

import (
	"log"

	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

// LogEnforcer prints decisions without touching the kernel (dry-run).
type LogEnforcer struct {
	stats Stats
}

func NewLogEnforcer() *LogEnforcer { return &LogEnforcer{} }

func (e *LogEnforcer) Apply(f *flow.Flow, d policy.Decision) error {
	e.stats.Applied++
	if d.Drop {
		log.Printf("enforce [dry-run] rule %q DROP mark=0x%x %s", d.Rule, d.Mark, f.Key.String())
	} else {
		log.Printf("enforce [dry-run] rule %q mark=0x%x %s", d.Rule, d.Mark, f.Key.String())
	}
	return nil
}

func (e *LogEnforcer) Release(f *flow.Flow) error {
	e.stats.Released++
	return nil
}

func (e *LogEnforcer) Close() error { return nil }

func (e *LogEnforcer) Stats() Stats { return e.stats }
