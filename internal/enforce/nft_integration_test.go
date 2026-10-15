package enforce

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func requireRootNFT(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath(nftBin); err != nil {
		t.Skip("nft not installed")
	}
}

func TestNFTSetupApplyReleaseForward(t *testing.T) {
	requireRootNFT(t)
	pol, err := policy.LoadBytes([]byte(`
nftables:
  table: dpi_test
  hooks: [forward]
  drop_mark: 0xdead
  element_timeout: 300s
rules:
  - name: dummy
    match: { master: SSH }
    action: mark
    mark: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	pol.NFTables.Table = "dpi_test"

	e, err := NewNFTEnforcer(pol.NFTables, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = e.Close()
		_ = exec.Command(nftBin, "delete", "table", "inet", "dpi_test").Run()
	}()
	if err := e.Setup(); err != nil {
		t.Fatal(err)
	}

	f := &flow.Flow{
		Key:    flow.Key{Proto: layers.IPProtocolTCP},
		Client: netip.MustParseAddrPort("192.0.2.1:1234"),
		Server: netip.MustParseAddrPort("192.0.2.2:443"),
	}
	if err := e.Apply(f, policy.Decision{Rule: "test", Mark: 0x10}); err != nil {
		t.Fatal(err)
	}
	if err := e.Release(f); err != nil {
		t.Fatal(err)
	}
}

func TestNFTRulesetInputOutputHooks(t *testing.T) {
	requireRootNFT(t)
	pol, err := policy.LoadBytes([]byte(`
nftables:
  table: dpi_test_io
  hooks: [input, output]
  drop_mark: 0xdead
  element_timeout: 60s
rules:
  - name: dummy
    match: { master: SSH }
    action: mark
    mark: 1
`))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := renderRuleset(pol.NFTables)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(rules, "hook input", "hook output", "chain dpi_input", "chain dpi_output", "map flows4") {
		t.Fatalf("ruleset missing hooks:\n%s", rules)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
