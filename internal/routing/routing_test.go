package routing_test

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"edge-router/internal/policy"
	"edge-router/internal/routing"
)

func requireRootRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func joined(cmds [][]string) []string {
	var out []string
	for _, c := range cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestCommandsRenderIPRule(t *testing.T) {
	cfg := policy.RoutingConfig{
		Enabled: true,
		Routes: []policy.RoutingRoute{
			{Name: "alt", Mark: 0x30, Table: 200, Gateway: "192.168.2.1", Pref: 1500},
		},
	}
	cmds := routing.Commands(cfg)
	if len(cmds) == 0 {
		t.Fatal("no commands")
	}
	found := false
	for _, c := range cmds {
		if strings.Join(c, " ") == "ip rule add pref 1500 fwmark 0x30 table 200" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ip rule add: %v", cmds)
	}
}

func TestCommandsIPv4DefaultPrefAndDev(t *testing.T) {
	cfg := policy.RoutingConfig{
		Enabled: true,
		Routes:  []policy.RoutingRoute{{Name: "alt", Mark: 0x30, Table: 200, Gateway: "192.168.2.1", Dev: "eth2"}},
	}
	want := []string{
		"ip rule del pref 1000",
		"ip rule add pref 1000 fwmark 0x30 table 200",
		"ip route replace default via 192.168.2.1 table 200 dev eth2",
	}
	if got := joined(routing.Commands(cfg)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCommandsIPv6Gateway(t *testing.T) {
	cfg := policy.RoutingConfig{
		Enabled: true,
		Routes:  []policy.RoutingRoute{{Name: "v6", Mark: 0x31, Table: 201, Gateway: "2001:db8::1", Pref: 1001}},
	}
	want := []string{
		"ip rule del pref 1001",
		"ip rule add pref 1001 fwmark 0x31 table 201",
		"ip route replace default via 2001:db8::1 table 201",
		"ip -6 rule del pref 1001",
		"ip -6 rule add pref 1001 fwmark 0x31 table 201",
		"ip -6 route replace default via 2001:db8::1 table 201",
	}
	if got := joined(routing.Commands(cfg)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDisabledIsNoop(t *testing.T) {
	cfg := policy.RoutingConfig{
		Routes: []policy.RoutingRoute{{Name: "alt", Mark: 0x30, Table: 200, Gateway: "192.168.2.1"}},
	}
	if cmds := routing.Commands(cfg); cmds != nil {
		t.Fatalf("disabled routing rendered %v", cmds)
	}
	// Without root a real "ip rule add" would fail, so success proves nothing ran.
	if err := routing.Apply(cfg); err != nil {
		t.Fatalf("disabled Apply ran commands: %v", err)
	}
	routing.Teardown(cfg)
}

func TestApplyDummyGateway(t *testing.T) {
	requireRootRoute(t)
	cfg := policy.RoutingConfig{
		Enabled: true,
		Routes: []policy.RoutingRoute{
			{Name: "test", Mark: 0x30, Table: 250, Gateway: "127.0.0.1", Pref: 31990},
		},
	}
	if err := routing.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	defer routing.Teardown(cfg)
	// Re-applying must not duplicate the rule.
	if err := routing.Apply(cfg); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	out, err := exec.Command("ip", "rule", "list", "pref", "31990").Output()
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "fwmark 0x30"); n != 1 {
		t.Fatalf("want exactly one fwmark rule, got %d:\n%s", n, out)
	}
	out, err = exec.Command("ip", "route", "show", "table", "250").Output()
	if err != nil || !strings.Contains(string(out), "default via 127.0.0.1") {
		t.Fatalf("route table 250: %v %s", err, out)
	}

	routing.Teardown(cfg)
	out, _ = exec.Command("ip", "rule", "list", "pref", "31990").Output()
	if strings.Contains(string(out), "0x30") {
		t.Fatalf("rule left after Teardown:\n%s", out)
	}
	_ = exec.Command("ip", "route", "flush", "table", "250").Run()
}
