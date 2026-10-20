package policy_test

import (
	"testing"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func TestLoadYAML(t *testing.T) {
	const yamlDoc = `
nftables:
  table: dpi
  hooks: [forward]
  drop_mark: 57005
  element_timeout: 60s
rules:
  - name: ssh-mark
    match: { master: SSH }
    action: mark
    mark: 0x20
`
	cfg, err := policy.LoadBytes([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NFTables.Table != "dpi" || cfg.NFTables.DropMarkParsed != 57005 {
		t.Fatalf("nft: %+v", cfg.NFTables)
	}
}

func TestMatcherOrderAndDrop(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
rules:
  - name: first
    match: { master: SSH }
    action: mark
    mark: 0x20
  - name: second
    match: { master: SSH }
    action: mark
    mark: 0x30
`))
	if err != nil {
		t.Fatal(err)
	}
	m := policy.NewMatcher(cfg)
	f := &flow.Flow{Master: "SSH", Protocol: "SSH"}
	d, ok := m.Decide(f)
	if !ok || d.Rule != "first" || d.Mark != 0x20 {
		t.Fatalf("got %+v ok=%v", d, ok)
	}

	cfg2, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
rules:
  - name: drop-torrent
    match: { protocol: BitTorrent }
    action: drop
`))
	if err != nil {
		t.Fatal(err)
	}
	m2 := policy.NewMatcher(cfg2)
	d2, ok := m2.Decide(&flow.Flow{Protocol: "BitTorrent"})
	if !ok || !d2.Drop || d2.Mark != 0xdead {
		t.Fatalf("drop: %+v ok=%v", d2, ok)
	}
}

func TestSaveFileRoundTrip(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  table: dpi
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
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	if err := policy.SaveFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := policy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Name != "ssh-mark" {
		t.Fatalf("loaded: %+v", loaded.Rules)
	}
}

func TestValidateCanonicalizesMatchNames(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg, err := policy.LoadBytes([]byte(`
rules:
  - name: yt
    match: { app: youtube }
    action: mark
    mark: 0x10
  - name: ssh-low
    match: { master: ssh }
    action: mark
    mark: 0x20
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].Match["app"] != "YouTube" {
		t.Fatalf("canonical app: %q", cfg.Rules[0].Match["app"])
	}
	if cfg.Rules[1].Match["master"] != "SSH" {
		t.Fatalf("canonical master: %q", cfg.Rules[1].Match["master"])
	}
	m := policy.NewMatcher(cfg)
	d, ok := m.Decide(&flow.Flow{App: "YouTube", Protocol: "TLS.YouTube"})
	if !ok || d.Rule != "yt" {
		t.Fatalf("youtube match: %+v ok=%v", d, ok)
	}
	d, ok = m.Decide(&flow.Flow{Master: "SSH", Protocol: "SSH"})
	if !ok || d.Rule != "ssh-low" {
		t.Fatalf("ssh match: %+v ok=%v", d, ok)
	}
}

func TestQoSRoutingValidate(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
qos:
  enabled: true
  interfaces:
    - { name: eth1, rate: 100mbit }
  classes:
    - { name: video, mark: 0x10, rate: 2mbit }
routing:
  enabled: true
  routes:
    - { name: alt, mark: 0x30, table: 200, gateway: 10.0.0.1 }
rules: []
`))
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := dpi.New()
	defer eng.Close()
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
}

func TestHostPolicyMatch(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg, err := policy.LoadBytes([]byte(`
rules:
  - name: google
    match: { host: "*.google.com" }
    action: mark
    mark: 0x11
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	m := policy.NewMatcher(cfg)
	f := &flow.Flow{
		Meta: dpi.Metadata{Host: "www.google.com"},
	}
	d, ok := m.Decide(f)
	if !ok || d.Rule != "google" {
		t.Fatalf("host match: %+v ok=%v", d, ok)
	}
}

func TestValidateProtocols(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg, err := policy.LoadBytes([]byte(`
rules:
  - name: ok
    match: { master: SSH }
    action: mark
    mark: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	cfg.Rules[0].Match["master"] = "SSHh"
	if err := cfg.Validate(eng); err == nil {
		t.Fatal("expected unknown master error")
	}
}
