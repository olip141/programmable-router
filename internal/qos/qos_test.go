package qos_test

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"edge-router/internal/policy"
	"edge-router/internal/qos"
)

func requireRootQoS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func TestCommandsRenderHTB(t *testing.T) {
	cfg := policy.QoSConfig{
		Enabled: true,
		Interfaces: []policy.QoSInterface{
			{Name: "eth1", Rate: "100mbit"},
		},
		Classes: []policy.QoSClass{
			{Name: "video", Mark: 0x10, Rate: "2mbit", Prio: 5},
		},
	}
	cmds := qos.Commands(cfg)
	if len(cmds) < 6 {
		t.Fatalf("expected several tc commands, got %d", len(cmds))
	}
	found := false
	for _, c := range cmds {
		if len(c) >= 2 && c[0] == "tc" && c[1] == "filter" {
			s := strings.Join(c, " ")
			if strings.Contains(s, "protocol all") && strings.Contains(s, "fw") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing protocol all fw filter")
	}
}

func TestCommandsExact(t *testing.T) {
	cfg := policy.QoSConfig{
		Enabled:    true,
		Interfaces: []policy.QoSInterface{{Name: "eth1", Rate: "100mbit"}, {Name: "eth2", Rate: "50mbit"}},
		Classes: []policy.QoSClass{
			{Name: "video", Mark: 0x10, Rate: "2mbit"},
			{Name: "ssh", Mark: 0x20, Rate: "3mbit", Ceil: "5mbit", Prio: 1},
		},
	}
	var got []string
	for _, c := range qos.Commands(cfg) {
		got = append(got, strings.Join(c, " "))
	}
	want := []string{
		"tc qdisc del dev eth1 root",
		"tc qdisc add dev eth1 root handle 1: htb default 999",
		"tc class add dev eth1 parent 1: classid 1:1 htb rate 100mbit ceil 100mbit",
		"tc class add dev eth1 parent 1:1 classid 1:999 htb rate 100mbit ceil 100mbit prio 7",
		"tc qdisc add dev eth1 parent 1:999 handle 999: fq_codel",
		"tc class add dev eth1 parent 1:1 classid 1:10 htb rate 2mbit ceil 100mbit prio 5",
		"tc qdisc add dev eth1 parent 1:10 handle 10: fq_codel",
		"tc filter add dev eth1 parent 1: protocol all handle 0x10 fw classid 1:10",
		"tc class add dev eth1 parent 1:1 classid 1:11 htb rate 3mbit ceil 5mbit prio 1",
		"tc qdisc add dev eth1 parent 1:11 handle 11: fq_codel",
		"tc filter add dev eth1 parent 1: protocol all handle 0x20 fw classid 1:11",
	}
	if len(got) != 2*len(want) {
		t.Fatalf("got %d commands, want %d:\n%s", len(got), 2*len(want), strings.Join(got, "\n"))
	}
	if !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("eth1 commands:\n%s\nwant:\n%s", strings.Join(got[:len(want)], "\n"), strings.Join(want, "\n"))
	}
	if got[len(want)+2] != "tc class add dev eth2 parent 1: classid 1:1 htb rate 50mbit ceil 50mbit" {
		t.Fatalf("eth2 uses wrong rate: %q", got[len(want)+2])
	}
}

func TestCommandsUseResolvedDevice(t *testing.T) {
	cfg := policy.QoSConfig{
		Enabled:    true,
		Interfaces: []policy.QoSInterface{{Name: "wan", Rate: "20mbit", Resolved: "ens3"}},
	}
	for _, argv := range qos.Commands(cfg) {
		line := strings.Join(argv, " ")
		if !strings.Contains(line, " dev ens3 ") {
			t.Fatalf("command does not target the resolved device: %s", line)
		}
	}
}

func TestCommandsDisabled(t *testing.T) {
	cfg := policy.QoSConfig{Interfaces: []policy.QoSInterface{{Name: "eth1", Rate: "1mbit"}}}
	if cmds := qos.Commands(cfg); cmds != nil {
		t.Fatalf("disabled QoS rendered %v", cmds)
	}
	if err := qos.Apply(cfg); err != nil {
		t.Fatalf("disabled Apply: %v", err)
	}
}

// Output of `tc -s class show dev X` (iproute2 6.1) for the HTB tree built by Apply.
const tcClassShow = `class htb 1:10 parent 1:1 leaf 10: prio 5 rate 3Mbit ceil 10Mbit burst 1599b cburst 1600b 
 Sent 1200 bytes 10 pkt (dropped 2, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
 lended: 0 borrowed: 0 giants: 0
 tokens: 66656 ctokens: 20000

class htb 1:999 parent 1:1 leaf 999: prio 7 rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b 
 Sent 294 bytes 3 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
 lended: 3 borrowed: 0 giants: 0
 tokens: 18775 ctokens: 18775

class htb 1:1 root rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b 
 Sent 1494 bytes 13 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
 lended: 0 borrowed: 0 giants: 0
 tokens: 18775 ctokens: 18775

class fq_codel 999:1b8 parent 999: 
 (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
  deficit 1220 count 0 lastcount 0 ldelay 2us
`

func TestParseClassStats(t *testing.T) {
	got := qos.ParseClassStats(tcClassShow)
	want := []qos.ClassStats{
		{ClassID: "1:10", Bytes: 1200, Packets: 10, Drops: 2},
		{ClassID: "1:999", Bytes: 294, Packets: 3},
		{ClassID: "1:1", Bytes: 1494, Packets: 13},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got := qos.ParseClassStats(""); len(got) != 0 {
		t.Fatalf("empty input: %+v", got)
	}
}

func TestApplyDummy0(t *testing.T) {
	requireRootQoS(t)
	_ = exec.Command("ip", "link", "del", "dummy0").Run()
	if out, err := exec.Command("ip", "link", "add", "dummy0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("ip link add: %v %s", err, out)
	}
	defer exec.Command("ip", "link", "del", "dummy0").Run()
	_ = exec.Command("ip", "link", "set", "dummy0", "up").Run()

	cfg := policy.QoSConfig{
		Enabled: true,
		Interfaces: []policy.QoSInterface{
			{Name: "dummy0", Rate: "10mbit"},
		},
		Classes: []policy.QoSClass{
			{Name: "ssh", Mark: 0x20, Rate: "3mbit"},
		},
	}
	if err := qos.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	// Apply must be repeatable (it replaces the root qdisc).
	if err := qos.Apply(cfg); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	stats, err := qos.Stats("dummy0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, s := range stats {
		names[s.ClassID] = s.Name
	}
	if names["1:10"] != "ssh" || names["1:999"] != "default" {
		t.Fatalf("class stats: %+v", stats)
	}

	qos.Teardown(cfg)
	stats, err = qos.Stats("dummy0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 0 {
		t.Fatalf("classes left after Teardown: %+v", stats)
	}
}

func TestStatsUnknownInterface(t *testing.T) {
	if _, err := qos.Stats("no-such-if0", policy.QoSConfig{}); err == nil {
		t.Fatal("expected error for missing interface")
	}
}
