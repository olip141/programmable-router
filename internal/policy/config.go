package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

// Config is the administrator policy file (YAML).
type Config struct {
	NFTables NFTConfig `yaml:"nftables"`
	Rules    []Rule    `yaml:"rules"`
}

// NFTConfig controls the kernel ruleset installed by the enforcer.
type NFTConfig struct {
	Table           string        `yaml:"table"`
	Hooks           []string      `yaml:"hooks"`
	DropMark        uint32        `yaml:"drop_mark"`
	ElementTimeout  time.Duration `yaml:"element_timeout"`
	DropMarkParsed  uint32        `yaml:"-"`
}

// Rule maps a match (AND of fields) to an action.
type Rule struct {
	Name   string            `yaml:"name"`
	Match  map[string]string `yaml:"match"`
	Action string            `yaml:"action"`
	Mark   uint32            `yaml:"mark"`
}

// Decision is the enforcement outcome for a classified flow.
type Decision struct {
	Rule string
	Mark uint32
	Drop bool
}

// LoadBytes parses policy YAML from memory.
func LoadBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadFile reads and normalises a policy file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	if c.NFTables.Table == "" {
		c.NFTables.Table = "dpi"
	}
	if len(c.NFTables.Hooks) == 0 {
		c.NFTables.Hooks = []string{"forward"}
	}
	for i, h := range c.NFTables.Hooks {
		c.NFTables.Hooks[i] = strings.ToLower(strings.TrimSpace(h))
		switch c.NFTables.Hooks[i] {
		case "forward", "input", "output":
		default:
			return fmt.Errorf("policy: nftables.hooks: unknown hook %q", h)
		}
	}
	if c.NFTables.DropMark == 0 {
		c.NFTables.DropMark = 0xdead
	}
	c.NFTables.DropMarkParsed = c.NFTables.DropMark
	if c.NFTables.ElementTimeout <= 0 {
		c.NFTables.ElementTimeout = 300 * time.Second
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Name == "" {
			return fmt.Errorf("policy: rule %d: missing name", i)
		}
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		switch r.Action {
		case "mark", "drop":
		default:
			return fmt.Errorf("policy: rule %q: unknown action %q", r.Name, r.Action)
		}
		if r.Action == "mark" && r.Mark == 0 {
			return fmt.Errorf("policy: rule %q: mark action requires mark", r.Name)
		}
		if len(r.Match) == 0 {
			return fmt.Errorf("policy: rule %q: empty match", r.Name)
		}
		for k := range r.Match {
			switch strings.ToLower(k) {
			case "protocol", "master", "app", "category":
			default:
				return fmt.Errorf("policy: rule %q: unknown match field %q", r.Name, k)
			}
		}
	}
	return nil
}

// Validate checks protocol and category names against nDPI.
func (c *Config) Validate(eng *dpi.Engine) error {
	for _, r := range c.Rules {
		for k, v := range r.Match {
			v = strings.TrimSpace(v)
			if v == "" {
				return fmt.Errorf("policy: rule %q: empty %s", r.Name, k)
			}
			switch strings.ToLower(k) {
			case "protocol":
				if _, ok := eng.LookupProtocol(v); !ok {
					return fmt.Errorf("policy: rule %q: unknown protocol %q", r.Name, v)
				}
			case "master", "app":
				if _, ok := eng.ProtoByName(v); !ok {
					return fmt.Errorf("policy: rule %q: unknown %s %q", r.Name, k, v)
				}
			case "category":
				if _, ok := eng.CategoryID(v); !ok {
					return fmt.Errorf("policy: rule %q: unknown category %q", r.Name, v)
				}
			}
		}
	}
	return nil
}

// Matcher applies rules in file order (first match wins).
type Matcher struct {
	cfg  *Config
	hits map[string]int
}

func NewMatcher(cfg *Config) *Matcher {
	return &Matcher{cfg: cfg, hits: make(map[string]int)}
}

// Hits returns how many flows matched each rule name.
func (m *Matcher) Hits() map[string]int {
	out := make(map[string]int, len(m.hits))
	for k, v := range m.hits {
		out[k] = v
	}
	return out
}

// Decide returns a decision when a rule matches f.
func (m *Matcher) Decide(f *flow.Flow) (Decision, bool) {
	for _, r := range m.cfg.Rules {
		if !matchRule(r, f) {
			continue
		}
		m.hits[r.Name]++
		d := Decision{Rule: r.Name}
		if r.Action == "drop" {
			d.Drop = true
			d.Mark = m.cfg.NFTables.DropMarkParsed
		} else {
			d.Mark = r.Mark
		}
		return d, true
	}
	return Decision{}, false
}

func matchRule(r Rule, f *flow.Flow) bool {
	for k, want := range r.Match {
		want = strings.TrimSpace(want)
		switch strings.ToLower(k) {
		case "protocol":
			if f.Protocol != want {
				return false
			}
		case "master":
			if f.Master != want {
				return false
			}
		case "app":
			if f.App != want {
				return false
			}
		case "category":
			if f.Category != want {
				return false
			}
		default:
			return false
		}
	}
	return true
}
