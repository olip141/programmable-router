package policy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"edge-router/internal/policy"
)

func validNetworkConfig(t *testing.T) *policy.Config {
	t.Helper()
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
qos:
  enabled: true
  interfaces:
    - { name: eth1, rate: 100mbit }
  classes:
    - { name: video, mark: 0x10, rate: 2mbit }
    - { name: ssh, mark: 0x20, rate: 1.5mbit, ceil: 10mbit, prio: 1 }
routing:
  enabled: true
  routes:
    - { name: alt, mark: 0x30, table: 200, gateway: 10.0.0.1 }
    - { name: alt6, mark: 0x31, table: 201, gateway: "2001:db8::1", pref: 1001 }
rules:
  - name: video
    match: { category: Media }
    action: mark
    mark: 0x10
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestValidateNetworkErrors(t *testing.T) {
	if err := validNetworkConfig(t).ValidateNetwork(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *policy.Config){
		"qos no interfaces":      func(c *policy.Config) { c.QoS.Interfaces = nil },
		"qos iface no name":      func(c *policy.Config) { c.QoS.Interfaces[0].Name = " " },
		"qos iface bad rate":     func(c *policy.Config) { c.QoS.Interfaces[0].Rate = "100 mbit" },
		"qos class bad rate":     func(c *policy.Config) { c.QoS.Classes[0].Rate = "fast" },
		"qos class no name":      func(c *policy.Config) { c.QoS.Classes[0].Name = "" },
		"qos class zero mark":    func(c *policy.Config) { c.QoS.Classes[0].Mark = 0 },
		"qos class drop mark":    func(c *policy.Config) { c.QoS.Classes[0].Mark = 0xdead },
		"qos duplicate mark":     func(c *policy.Config) { c.QoS.Classes[1].Mark = 0x10 },
		"routing no routes":      func(c *policy.Config) { c.Routing.Routes = nil },
		"routing no name":        func(c *policy.Config) { c.Routing.Routes[0].Name = "" },
		"routing zero mark":      func(c *policy.Config) { c.Routing.Routes[0].Mark = 0 },
		"routing table 0":        func(c *policy.Config) { c.Routing.Routes[0].Table = 0 },
		"routing table 253":      func(c *policy.Config) { c.Routing.Routes[0].Table = 253 },
		"routing no gateway":     func(c *policy.Config) { c.Routing.Routes[0].Gateway = "" },
		"routing duplicate pref": func(c *policy.Config) { c.Routing.Routes[1].Pref = 1000 },
	}
	for name, mutate := range cases {
		cfg := validNetworkConfig(t)
		mutate(cfg)
		if err := cfg.ValidateNetwork(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	cfg := validNetworkConfig(t)
	cfg.QoS.Enabled = false
	cfg.QoS.Interfaces = nil
	cfg.Routing.Enabled = false
	cfg.Routing.Routes = nil
	if err := cfg.ValidateNetwork(); err != nil {
		t.Fatalf("disabled sections must not be validated: %v", err)
	}
}

func TestOrphanMarks(t *testing.T) {
	cfg := validNetworkConfig(t)
	if got := policy.OrphanMarks(cfg); len(got) != 0 {
		t.Fatalf("unexpected orphans: %v", got)
	}
	cfg, err := cfg.WithRules(append(policy.CloneRules(cfg.Rules),
		policy.Rule{Name: "lonely", Match: map[string]string{"master": "DNS"}, Action: "mark", Mark: 0x77},
		policy.Rule{Name: "routed", Match: map[string]string{"master": "SSH"}, Action: "mark", Mark: 0x30},
		policy.Rule{Name: "dropper", Match: map[string]string{"master": "FTP"}, Action: "drop"},
	))
	if err != nil {
		t.Fatal(err)
	}
	got := policy.OrphanMarks(cfg)
	if len(got) != 1 || !strings.Contains(got[0], "lonely") {
		t.Fatalf("orphans = %v, want only lonely", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	orig := validNetworkConfig(t)
	cp := orig.Clone()
	cp.Rules[0].Match["category"] = "Other"
	cp.NFTables.Hooks[0] = "input"
	cp.QoS.Classes[0].Mark = 0x99
	cp.Routing.Routes[0].Table = 7
	if orig.Rules[0].Match["category"] != "Media" || orig.NFTables.Hooks[0] != "forward" ||
		orig.QoS.Classes[0].Mark != 0x10 || orig.Routing.Routes[0].Table != 200 {
		t.Fatalf("clone shares state with original: %+v", orig)
	}
}

func TestWithRulesAndNetworkDoNotAliasInput(t *testing.T) {
	base := validNetworkConfig(t)
	rules := []policy.Rule{{Name: "x", Match: map[string]string{"master": "SSH"}, Action: "mark", Mark: 0x20}}
	out, err := base.WithRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Match["master"] = "DNS"
	if out.Rules[0].Match["master"] != "SSH" {
		t.Fatal("WithRules aliases caller's match map")
	}

	q := base.QoS
	q.Classes = append([]policy.QoSClass(nil), q.Classes...)
	out, err = base.WithNetwork(q, base.Routing)
	if err != nil {
		t.Fatal(err)
	}
	q.Classes[0].Rate = "1bit"
	out.Routing.Routes[0].Gateway = "10.9.9.9"
	if out.QoS.Classes[0].Rate != "2mbit" || base.Routing.Routes[0].Gateway != "10.0.0.1" {
		t.Fatal("WithNetwork aliases input slices")
	}
}

func TestJSONFieldNamesMatchYAML(t *testing.T) {
	data, err := json.Marshal(validNetworkConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	rule := raw["rules"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "match", "action", "mark"} {
		if _, ok := rule[k]; !ok {
			t.Errorf("rule JSON missing %q: %v", k, rule)
		}
	}
	nft := raw["nftables"].(map[string]any)
	for _, k := range []string{"table", "hooks", "drop_mark"} {
		if _, ok := nft[k]; !ok {
			t.Errorf("nftables JSON missing %q: %v", k, nft)
		}
	}
	if _, ok := nft["DropMarkParsed"]; ok {
		t.Error("internal DropMarkParsed exported to JSON")
	}
	cls := raw["qos"].(map[string]any)["classes"].([]any)[0].(map[string]any)
	if cls["mark"] != float64(0x10) || cls["name"] != "video" {
		t.Errorf("qos class JSON: %v", cls)
	}

	var back policy.Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Routing.Routes[1].Gateway != "2001:db8::1" || back.Rules[0].Match["category"] != "Media" {
		t.Fatalf("JSON round trip: %+v", back)
	}
}

func TestSaveFilePreservesModeAndOmitsEmptySections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("rules: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.LoadBytes([]byte(`
rules:
  - name: drop-torrent
    match: { protocol: BitTorrent }
    action: drop
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SaveFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	for _, unwanted := range []string{"qos:", "routing:", "restore_mark", "mark: 0"} {
		if strings.Contains(string(data), unwanted) {
			t.Errorf("saved file contains %q:\n%s", unwanted, data)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}

	fresh := filepath.Join(t.TempDir(), "new.yaml")
	if err := policy.SaveFile(fresh, validNetworkConfig(t)); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(fresh); st.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode %v, want 0644", st.Mode().Perm())
	}
	loaded, err := policy.LoadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.QoS.Enabled || len(loaded.QoS.Classes) != 2 || loaded.QoS.Classes[1].Ceil != "10mbit" ||
		!loaded.Routing.Enabled || loaded.Routing.Routes[1].Pref != 1001 {
		t.Fatalf("network sections lost on save: %+v %+v", loaded.QoS, loaded.Routing)
	}
}

func TestResolveQoSInterfaces(t *testing.T) {
	devices := map[string]string{"wan": "ens3", "lan": "ens4", "ens4": "ens4"}
	resolve := func(name string) (string, error) {
		if dev, ok := devices[name]; ok {
			return dev, nil
		}
		return "", fmt.Errorf("no such interface")
	}

	cfg := validNetworkConfig(t)
	cfg.QoS.Interfaces = []policy.QoSInterface{{Name: "wan", Rate: "20mbit"}, {Name: "lan", Rate: "100mbit"}}
	if err := policy.ResolveQoSInterfaces(&cfg.QoS, resolve); err != nil {
		t.Fatal(err)
	}
	if d0, d1 := cfg.QoS.Interfaces[0].Device(), cfg.QoS.Interfaces[1].Device(); d0 != "ens3" || d1 != "ens4" {
		t.Fatalf("devices %q %q", d0, d1)
	}
	// Saving and the JSON API keep the alias, never the resolved device.
	data, _ := cfg.Marshal()
	js, _ := json.Marshal(cfg.QoS)
	for _, out := range []string{string(data), string(js)} {
		if strings.Contains(out, "ens3") || !strings.Contains(out, "wan") {
			t.Fatalf("resolved device leaked or alias lost:\n%s", out)
		}
	}
	if cfg.Clone().QoS.Interfaces[0].Resolved != "ens3" {
		t.Fatal("Clone dropped the resolved device")
	}

	cfg.QoS.Interfaces = []policy.QoSInterface{{Name: "lan", Rate: "1mbit"}, {Name: "ens4", Rate: "1mbit"}, {Name: "eth9", Rate: "1mbit"}}
	err := policy.ResolveQoSInterfaces(&cfg.QoS, resolve)
	if err == nil || !strings.Contains(err.Error(), `interfaces "lan" and "ens4" are both ens4`) ||
		!strings.Contains(err.Error(), `interface "eth9": no such interface`) {
		t.Fatalf("expected duplicate and missing errors, got %v", err)
	}
	if cfg.QoS.Interfaces[1].Resolved != "" || cfg.QoS.Interfaces[2].Device() != "eth9" {
		t.Fatalf("failed interfaces must stay unresolved: %+v", cfg.QoS.Interfaces)
	}

	cfg.QoS.Enabled = false
	if err := policy.ResolveQoSInterfaces(&cfg.QoS, resolve); err != nil {
		t.Fatalf("disabled QoS must not be resolved: %v", err)
	}
}

func TestRestoreMarkDefaultAndOverride(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte("rules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NFTables.RestoreMarkEnabled {
		t.Fatal("restore_mark should default to true")
	}
	cfg, err = policy.LoadBytes([]byte("nftables: { restore_mark: false }\nrules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NFTables.RestoreMarkEnabled {
		t.Fatal("restore_mark: false ignored")
	}
	data, _ := cfg.Marshal()
	if !strings.Contains(string(data), "restore_mark: false") {
		t.Fatalf("explicit restore_mark not saved:\n%s", data)
	}
}
