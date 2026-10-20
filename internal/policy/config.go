package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

var qosRateRe = regexp.MustCompile(`^\d+(\.\d+)?(bit|kbit|mbit|gbit)$`)

// Config is the administrator policy file (YAML).
type Config struct {
	NFTables NFTConfig     `yaml:"nftables" json:"nftables"`
	QoS      QoSConfig     `yaml:"qos,omitempty" json:"qos"`
	Routing  RoutingConfig `yaml:"routing,omitempty" json:"routing"`
	Rules    []Rule        `yaml:"rules" json:"rules"`
}

// QoSConfig describes HTB shaping applied via tc.
type QoSConfig struct {
	Enabled    bool           `yaml:"enabled" json:"enabled"`
	Interfaces []QoSInterface `yaml:"interfaces" json:"interfaces"`
	Classes    []QoSClass     `yaml:"classes" json:"classes"`
}

// QoSInterface is one egress interface to shape. Name may be an alias
// ("wan", "lan", "auto"); Resolved holds the device it maps to and is never
// written back, so a saved file keeps the alias.
type QoSInterface struct {
	Name     string `yaml:"name" json:"name"`
	Rate     string `yaml:"rate" json:"rate"`
	Resolved string `yaml:"-" json:"-"`
}

// Device returns the interface tc should configure.
func (i QoSInterface) Device() string {
	if i.Resolved != "" {
		return i.Resolved
	}
	return strings.TrimSpace(i.Name)
}

// ResolveQoSInterfaces fills Resolved for every interface. Interfaces that
// fail to resolve, or map to a device already listed, are left with Resolved
// empty and reported in the joined error.
func ResolveQoSInterfaces(q *QoSConfig, resolve func(string) (string, error)) error {
	if !q.Enabled {
		return nil
	}
	var errs []error
	seen := map[string]string{}
	for i := range q.Interfaces {
		ifc := &q.Interfaces[i]
		ifc.Resolved = ""
		dev, err := resolve(ifc.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("qos: interface %q: %w", ifc.Name, err))
			continue
		}
		if prev, ok := seen[dev]; ok {
			errs = append(errs, fmt.Errorf("qos: interfaces %q and %q are both %s", prev, ifc.Name, dev))
			continue
		}
		seen[dev] = ifc.Name
		ifc.Resolved = dev
	}
	return errors.Join(errs...)
}

// QoSClass maps an nftables fwmark to an HTB class.
type QoSClass struct {
	Name string `yaml:"name" json:"name"`
	Mark uint32 `yaml:"mark" json:"mark"`
	Rate string `yaml:"rate" json:"rate"`
	Ceil string `yaml:"ceil,omitempty" json:"ceil,omitempty"`
	Prio int    `yaml:"prio,omitempty" json:"prio,omitempty"`
}

// RoutingConfig describes policy routing via ip rule/route.
type RoutingConfig struct {
	Enabled bool           `yaml:"enabled" json:"enabled"`
	Routes  []RoutingRoute `yaml:"routes" json:"routes"`
}

// RoutingRoute sends marked traffic to an alternate routing table.
type RoutingRoute struct {
	Name    string `yaml:"name" json:"name"`
	Mark    uint32 `yaml:"mark" json:"mark"`
	Table   int    `yaml:"table" json:"table"`
	Gateway string `yaml:"gateway" json:"gateway"`
	Dev     string `yaml:"dev,omitempty" json:"dev,omitempty"`
	Pref    int    `yaml:"pref,omitempty" json:"pref,omitempty"`
}

// NFTConfig controls the kernel ruleset installed by the enforcer.
type NFTConfig struct {
	Table              string        `yaml:"table" json:"table"`
	Hooks              []string      `yaml:"hooks" json:"hooks"`
	DropMark           uint32        `yaml:"drop_mark" json:"drop_mark"`
	ElementTimeout     time.Duration `yaml:"element_timeout" json:"element_timeout"`
	RestoreMark        *bool         `yaml:"restore_mark,omitempty" json:"restore_mark,omitempty"`
	DropMarkParsed     uint32        `yaml:"-" json:"-"`
	RestoreMarkEnabled bool          `yaml:"-" json:"-"`
}

// Rule maps a match (AND of fields) to an action.
type Rule struct {
	Name   string            `yaml:"name" json:"name"`
	Match  map[string]string `yaml:"match" json:"match"`
	Action string            `yaml:"action" json:"action"`
	Mark   uint32            `yaml:"mark,omitempty" json:"mark"`
}

// Clone returns a deep copy, so the result can be normalised or validated
// while other goroutines read c.
func (c *Config) Clone() *Config {
	out := *c
	out.NFTables.Hooks = append([]string(nil), c.NFTables.Hooks...)
	if c.NFTables.RestoreMark != nil {
		v := *c.NFTables.RestoreMark
		out.NFTables.RestoreMark = &v
	}
	out.QoS.Interfaces = append([]QoSInterface(nil), c.QoS.Interfaces...)
	out.QoS.Classes = append([]QoSClass(nil), c.QoS.Classes...)
	out.Routing.Routes = append([]RoutingRoute(nil), c.Routing.Routes...)
	out.Rules = CloneRules(c.Rules)
	return &out
}

// CloneRules deep-copies rules including their match maps.
func CloneRules(rules []Rule) []Rule {
	if rules == nil {
		return nil
	}
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = r
		if r.Match != nil {
			out[i].Match = make(map[string]string, len(r.Match))
			for k, v := range r.Match {
				out[i].Match[k] = v
			}
		}
	}
	return out
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

// Marshal serialises the config as YAML.
func (c *Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
}

// SaveFile writes cfg to path atomically (temp file in the same directory, then rename).
func SaveFile(path string, cfg *Config) error {
	data, err := cfg.Marshal()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".router-policy-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	// CreateTemp uses 0600; keep the original mode and owner so that saving
	// from a root-run router does not lock the admin out of the file.
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = tmp.Chown(int(sys.Uid), int(sys.Gid))
		}
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
	c.NFTables.RestoreMarkEnabled = true
	if c.NFTables.RestoreMark != nil {
		c.NFTables.RestoreMarkEnabled = *c.NFTables.RestoreMark
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
			case "protocol", "master", "app", "category", "host", "risk", "confidence":
			default:
				return fmt.Errorf("policy: rule %q: unknown match field %q", r.Name, k)
			}
		}
	}
	return nil
}

// WithRules returns a copy of c with rules replaced and normalised.
func (c *Config) WithRules(rules []Rule) (*Config, error) {
	out := c.Clone()
	out.Rules = CloneRules(rules)
	if err := out.normalize(); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateNetwork checks the qos and routing sections. Unlike Validate it
// does not touch the nDPI engine, so it is safe on any goroutine.
func (c *Config) ValidateNetwork() error {
	if err := validateQoS(c.QoS, c.NFTables.DropMarkParsed); err != nil {
		return err
	}
	return validateRouting(c.Routing)
}

// Validate checks protocol and category names against nDPI and canonicalises match values.
func (c *Config) Validate(eng *dpi.Engine) error {
	if err := c.ValidateNetwork(); err != nil {
		return err
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		for k, v := range r.Match {
			v = strings.TrimSpace(v)
			if v == "" {
				return fmt.Errorf("policy: rule %q: empty %s", r.Name, k)
			}
			switch strings.ToLower(k) {
			case "protocol":
				res, ok := eng.LookupProtocol(v)
				if !ok {
					return fmt.Errorf("policy: rule %q: unknown protocol %q", r.Name, v)
				}
				r.Match[k] = eng.ProtocolName(res)
			case "master", "app":
				id, ok := eng.ProtoByName(v)
				if !ok {
					return fmt.Errorf("policy: rule %q: unknown %s %q", r.Name, k, v)
				}
				r.Match[k] = eng.ProtoName(id)
			case "category":
				id, ok := eng.CategoryID(v)
				if !ok {
					return fmt.Errorf("policy: rule %q: unknown category %q", r.Name, v)
				}
				r.Match[k] = eng.CategoryNameByID(id)
			case "host":
				r.Match[k] = v
			case "risk":
				if !riskKnown(eng, v) {
					return fmt.Errorf("policy: rule %q: unknown risk %q", r.Name, v)
				}
				r.Match[k] = canonicalRiskName(eng, v)
			case "confidence":
				if !confidenceKnown(eng, v) {
					return fmt.Errorf("policy: rule %q: unknown confidence %q", r.Name, v)
				}
				r.Match[k] = canonicalConfidenceName(eng, v)
			}
		}
	}
	return nil
}

// WarnOrphanMarks logs when a rule mark has no QoS class or routing entry.
func WarnOrphanMarks(c *Config) {
	for _, msg := range OrphanMarks(c) {
		log.Printf("policy: warning: %s", msg)
	}
}

// OrphanMarks lists mark rules whose mark has no QoS class or routing route.
func OrphanMarks(c *Config) []string {
	var out []string
	qosMarks := map[uint32]bool{}
	for _, cl := range c.QoS.Classes {
		qosMarks[cl.Mark] = true
	}
	rtMarks := map[uint32]bool{}
	for _, r := range c.Routing.Routes {
		rtMarks[r.Mark] = true
	}
	for _, rule := range c.Rules {
		if rule.Action != "mark" || rule.Mark == 0 {
			continue
		}
		if !qosMarks[rule.Mark] && !rtMarks[rule.Mark] {
			out = append(out, fmt.Sprintf("rule %q mark 0x%x has no qos class or routing route", rule.Name, rule.Mark))
		}
	}
	return out
}

// WithNetwork returns a copy with QoS and routing replaced.
func (c *Config) WithNetwork(qosCfg QoSConfig, rtCfg RoutingConfig) (*Config, error) {
	out := c.Clone()
	net := (&Config{QoS: qosCfg, Routing: rtCfg}).Clone()
	out.QoS = net.QoS
	out.Routing = net.Routing
	if err := out.normalize(); err != nil {
		return nil, err
	}
	return out, nil
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
			if !strings.EqualFold(f.Protocol, want) {
				return false
			}
		case "master":
			if !strings.EqualFold(f.Master, want) {
				return false
			}
		case "app":
			if !strings.EqualFold(f.App, want) {
				return false
			}
		case "category":
			if !strings.EqualFold(f.Category, want) {
				return false
			}
		case "host":
			if !hostMatch(want, f.Meta.Host) {
				return false
			}
		case "risk":
			if !flowHasRisk(f, want) {
				return false
			}
		case "confidence":
			if !strings.EqualFold(f.Meta.Confidence, want) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func hostMatch(pattern, host string) bool {
	pattern = strings.TrimSpace(pattern)
	host = strings.TrimSpace(host)
	if pattern == "" || host == "" {
		return false
	}
	pl := strings.ToLower(pattern)
	hl := strings.ToLower(host)
	if pl == hl {
		return true
	}
	if !strings.Contains(pl, "*") {
		return false
	}
	// "*.example.com" also covers the apex "example.com".
	if apex, ok := strings.CutPrefix(pl, "*."); ok && hl == apex {
		return true
	}
	ok, err := path.Match(pl, hl)
	return err == nil && ok
}

func flowHasRisk(f *flow.Flow, want string) bool {
	for _, r := range f.Meta.Risks {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

func riskKnown(eng *dpi.Engine, name string) bool {
	for _, r := range eng.Risks() {
		if strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}

func canonicalRiskName(eng *dpi.Engine, name string) string {
	for _, r := range eng.Risks() {
		if strings.EqualFold(r, name) {
			return r
		}
	}
	return name
}

func confidenceKnown(eng *dpi.Engine, name string) bool {
	for _, c := range eng.Confidences() {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

func canonicalConfidenceName(eng *dpi.Engine, name string) string {
	for _, c := range eng.Confidences() {
		if strings.EqualFold(c, name) {
			return c
		}
	}
	return name
}

func validateQoS(cfg QoSConfig, dropMark uint32) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.Interfaces) == 0 {
		return fmt.Errorf("qos: enabled but no interfaces")
	}
	seenMark := map[uint32]string{}
	for _, ifc := range cfg.Interfaces {
		if strings.TrimSpace(ifc.Name) == "" {
			return fmt.Errorf("qos: interface missing name")
		}
		if !qosRateRe.MatchString(strings.TrimSpace(ifc.Rate)) {
			return fmt.Errorf("qos: interface %q: invalid rate %q", ifc.Name, ifc.Rate)
		}
	}
	for _, cl := range cfg.Classes {
		if strings.TrimSpace(cl.Name) == "" {
			return fmt.Errorf("qos: class missing name")
		}
		if cl.Mark == 0 {
			return fmt.Errorf("qos: class %q: mark required", cl.Name)
		}
		if cl.Mark == dropMark {
			return fmt.Errorf("qos: class %q: mark conflicts with drop_mark", cl.Name)
		}
		if prev, ok := seenMark[cl.Mark]; ok {
			return fmt.Errorf("qos: duplicate mark 0x%x (%s and %s)", cl.Mark, prev, cl.Name)
		}
		seenMark[cl.Mark] = cl.Name
		if !qosRateRe.MatchString(strings.TrimSpace(cl.Rate)) {
			return fmt.Errorf("qos: class %q: invalid rate %q", cl.Name, cl.Rate)
		}
	}
	return nil
}

func validateRouting(cfg RoutingConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("routing: enabled but no routes")
	}
	seenPref := map[int]string{}
	for _, r := range cfg.Routes {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("routing: route missing name")
		}
		if r.Mark == 0 {
			return fmt.Errorf("routing: route %q: mark required", r.Name)
		}
		if r.Table < 1 || r.Table > 252 {
			return fmt.Errorf("routing: route %q: table must be 1-252", r.Name)
		}
		if strings.TrimSpace(r.Gateway) == "" {
			return fmt.Errorf("routing: route %q: gateway required", r.Name)
		}
		pref := r.Pref
		if pref == 0 {
			pref = 1000
		}
		if prev, ok := seenPref[pref]; ok {
			return fmt.Errorf("routing: duplicate pref %d (%s and %s)", pref, prev, r.Name)
		}
		seenPref[pref] = r.Name
	}
	return nil
}
