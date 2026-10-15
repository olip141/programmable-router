package enforce

import (
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

// Enforcer applies policy decisions to the kernel (or logs them in dry-run).
type Enforcer interface {
	Apply(f *flow.Flow, d policy.Decision) error
	Release(f *flow.Flow) error
	Close() error
	Stats() Stats
}

// Stats counts enforcement operations.
type Stats struct {
	Applied  uint64
	Released uint64
	Skipped  uint64
	Errors   uint64
}
