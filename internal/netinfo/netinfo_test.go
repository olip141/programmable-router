package netinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// /proc/net/route and /proc/net/ipv6_route from a single-NIC VPS.
const procRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
ens3	00000000	01B87194	0003	0	0	100	00000000	0	0	0
ens3	01B87194	00000000	0005	0	0	100	FFFFFFFF	0	0	0
eth9	00000000	00000000	0201	0	0	0	00000000	0	0	0
`

const procIPv6Route = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     ens3
00000000000000000000000000000000 00 00000000000000000000000000000000 00 26075300020502000000000000000001 00000400 00000003 00000000 00000003     ens3
`

func TestParseRouteV4(t *testing.T) {
	got := ParseRouteV4(strings.NewReader(procRoute))
	// The eth9 entry is a reject route and the second ens3 entry is not a default.
	want := []Route{{Dev: "ens3", Gateway: "148.113.184.1", Metric: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRouteV6(t *testing.T) {
	got := ParseRouteV6(strings.NewReader(procIPv6Route))
	want := []Route{{Dev: "ens3", Gateway: "2607:5300:205:200::1", Metric: 1024, IPv6: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func routerIfaces() []Interface {
	ifs := []Interface{
		{Name: "lo", Up: true, Loopback: true, Addrs: []string{"127.0.0.1/8"}},
		{Name: "eth0", Up: true, OperState: "up", Addrs: []string{"203.0.113.10/24"}},
		{Name: "eth1", Up: true, OperState: "up", Addrs: []string{"192.168.1.1/24", "fe80::1/64"}},
		{Name: "eth2", Up: true, OperState: "up", Addrs: []string{"192.168.2.1/24"}},
		{Name: "eth3", Up: true, OperState: "up", Addrs: []string{"fe80::3/64"}},
		{Name: "eth4", Up: false, OperState: "down", Addrs: []string{"10.4.0.1/24"}},
		{Name: "docker0", Up: true, OperState: "up", Addrs: []string{"172.17.0.1/16"}},
	}
	Classify(ifs, []Route{
		{Dev: "eth0", Gateway: "203.0.113.1", Metric: 100},
		{Dev: "eth0", Gateway: "fe80::1", Metric: 1024, IPv6: true},
	})
	return ifs
}

func roles(ifs []Interface) map[string]string {
	out := map[string]string{}
	for _, i := range ifs {
		out[i.Name] = i.Role
	}
	return out
}

func TestClassifyRoles(t *testing.T) {
	ifs := routerIfaces()
	want := map[string]string{
		"lo": "", "eth0": RoleWAN, "eth1": RoleLAN, "eth2": RoleLAN,
		// eth3 has only a link-local address, eth4 is down, docker0 is a container bridge.
		"eth3": "", "eth4": "", "docker0": "",
	}
	if got := roles(ifs); !reflect.DeepEqual(got, want) {
		t.Fatalf("roles %v, want %v", got, want)
	}
	if ifs[1].Gateway != "203.0.113.1" {
		t.Fatalf("WAN gateway %q, want the IPv4 one", ifs[1].Gateway)
	}
}

func TestResolve(t *testing.T) {
	ifs := routerIfaces()
	cases := []struct {
		name, capture, want, errHas string
	}{
		{name: "wan", want: "eth0"},
		{name: " WAN ", want: "eth0"},
		{name: "lan", capture: "eth2", want: "eth2"},
		{name: "lan", errHas: "ambiguous, candidates eth1, eth2"},
		// Capturing on the WAN does not make it the LAN.
		{name: "lan", capture: "eth0", errHas: "ambiguous"},
		{name: "auto", capture: "eth1", want: "eth1"},
		{name: "auto", errHas: "ambiguous"},
		{name: "eth3", want: "eth3"},
		{name: "ens3", errHas: `interface "ens3" does not exist; available: eth0 (WAN), eth1 (LAN), eth2 (LAN), eth3, eth4, docker0`},
	}
	for _, c := range cases {
		got, err := Resolve(c.name, c.capture, ifs)
		if c.errHas != "" {
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Errorf("Resolve(%q, %q) = %q, %v; want error containing %q", c.name, c.capture, got, err, c.errHas)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, %v; want %q", c.name, c.capture, got, err, c.want)
		}
	}
}

func TestResolveSingleInterfaceHost(t *testing.T) {
	ifs := []Interface{
		{Name: "lo", Up: true, Loopback: true, Addrs: []string{"127.0.0.1/8"}},
		{Name: "ens3", Up: true, OperState: "up", Addrs: []string{"148.113.184.150/32"}},
	}
	Classify(ifs, ParseRouteV4(strings.NewReader(procRoute)))
	if got, err := Resolve("auto", "", ifs); err != nil || got != "ens3" {
		t.Fatalf("auto = %q, %v; want ens3 (WAN fallback)", got, err)
	}
	if _, err := Resolve("lan", "", ifs); err == nil || !strings.Contains(err.Error(), "no LAN interface") {
		t.Fatalf("lan on a single-NIC host: %v", err)
	}
	if _, err := Resolve("wan", "", []Interface{ifs[0]}); err == nil || !strings.Contains(err.Error(), "no interface has a default route") {
		t.Fatalf("wan without default route: %v", err)
	}
}

func TestPrimaryWANPrefersIPv4ThenMetric(t *testing.T) {
	ifs := []Interface{
		{Name: "wan6", Up: true, Addrs: []string{"2001:db8::2/64"}},
		{Name: "wan1", Up: true, Addrs: []string{"198.51.100.2/24"}},
		{Name: "wan2", Up: true, Addrs: []string{"192.0.2.2/24"}},
	}
	Classify(ifs, []Route{
		{Dev: "wan6", Metric: 1, IPv6: true},
		{Dev: "wan1", Metric: 200},
		{Dev: "wan2", Metric: 100},
	})
	if got, err := Resolve("wan", "", ifs); err != nil || got != "wan2" {
		t.Fatalf("wan = %q, %v; want wan2 (lowest IPv4 metric)", got, err)
	}
	for _, i := range ifs {
		if i.Role != RoleWAN {
			t.Errorf("%s role %q, want wan", i.Name, i.Role)
		}
	}
}

func TestHostReport(t *testing.T) {
	h := &Host{Capture: "eth1", List: func() ([]Interface, error) { return routerIfaces(), nil }}
	rep, err := h.Report()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Capture != "eth1" || rep.Aliases["wan"] != "eth0" || rep.Aliases["lan"] != "eth1" || len(rep.AliasErrors) != 0 {
		t.Fatalf("report %+v", rep)
	}
	h.Capture = ""
	rep, _ = h.Report()
	if _, ok := rep.Aliases["lan"]; ok || !strings.Contains(rep.AliasErrors["lan"], "ambiguous") {
		t.Fatalf("ambiguous lan not reported: %+v", rep)
	}
	if got, err := h.Resolve("wan"); err != nil || got != "eth0" {
		t.Fatalf("Host.Resolve(wan) = %q, %v", got, err)
	}
}

func TestReadSysfs(t *testing.T) {
	root := t.TempDir()
	devices := filepath.Join(root, "devices")
	write := func(dir, name, data string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(devices, "pci0000:00", "net", "eth0"), "speed", "1000\n")
	write(filepath.Join(devices, "pci0000:00", "net", "eth0"), "operstate", "up\n")
	write(filepath.Join(devices, "virtual", "net", "br0"), "speed", "-1\n")
	write(filepath.Join(devices, "virtual", "net", "br0"), "operstate", "unknown\n")
	classNet := filepath.Join(root, "class", "net")
	if err := os.MkdirAll(classNet, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"eth0": "pci0000:00", "br0": "virtual"} {
		if err := os.Symlink(filepath.Join(devices, target, "net", name), filepath.Join(classNet, name)); err != nil {
			t.Fatal(err)
		}
	}

	eth0 := Interface{Name: "eth0"}
	readSysfs(classNet, &eth0)
	if eth0.SpeedMbps != 1000 || eth0.OperState != "up" || eth0.Virtual {
		t.Fatalf("eth0 %+v", eth0)
	}
	br0 := Interface{Name: "br0"}
	readSysfs(classNet, &br0)
	if br0.SpeedMbps != 0 || br0.OperState != "unknown" || !br0.Virtual {
		t.Fatalf("br0 %+v", br0)
	}
}

func TestIsAlias(t *testing.T) {
	for name, want := range map[string]bool{"wan": true, "LAN": true, " auto ": true, "eth0": false, "any": false, "": false} {
		if got := IsAlias(name); got != want {
			t.Errorf("IsAlias(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestListOnThisHost(t *testing.T) {
	ifs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	var lo bool
	for _, i := range ifs {
		if i.Loopback {
			lo = true
			if i.Role != "" {
				t.Errorf("loopback %s has role %q", i.Name, i.Role)
			}
		}
	}
	if !lo {
		t.Fatalf("no loopback interface in %+v", ifs)
	}
}
