package enforce

import (
	"strings"
	"testing"

	"edge-router/internal/policy"
)

func renderFor(t *testing.T, yamlDoc string) string {
	t.Helper()
	pol, err := policy.LoadBytes([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderRuleset(pol.NFTables)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenderRulesetRestoreMarkDefault(t *testing.T) {
	out := renderFor(t, "nftables: { table: t1, hooks: [forward], drop_mark: 0xbeef, element_timeout: 90s }\nrules: []\n")
	for _, want := range []string{
		"table inet t1 {",
		"timeout 90s",
		"meta mark 0xbeef drop",
		"chain dpi_forward {",
		"type filter hook forward priority mangle;",
		"chain dpi_restore {",
		"type filter hook prerouting priority mangle;",
		"chain dpi_reroute {",
		"type route hook output priority mangle;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRulesetRestoreMarkDisabled(t *testing.T) {
	out := renderFor(t, "nftables: { hooks: [input, output], restore_mark: false }\nrules: []\n")
	if strings.Contains(out, "dpi_restore") || strings.Contains(out, "dpi_reroute") {
		t.Fatalf("restore chains rendered with restore_mark: false:\n%s", out)
	}
	if !strings.Contains(out, "chain dpi_input {") || !strings.Contains(out, "chain dpi_output {") {
		t.Fatalf("missing hook chains:\n%s", out)
	}
	if !strings.Contains(out, "timeout 300s") || !strings.Contains(out, "meta mark 0xdead drop") {
		t.Fatalf("defaults not applied:\n%s", out)
	}
}
