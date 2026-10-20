package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"edge-router/internal/netinfo"
	"edge-router/internal/policy"
)

func TestApplyNetworkStackDryRunOnlyLogs(t *testing.T) {
	cfg, err := policy.LoadBytes([]byte(`
qos:
  enabled: true
  interfaces: [{ name: eth1, rate: 100mbit }]
  classes: [{ name: ssh, mark: 0x20, rate: 3mbit }]
routing:
  enabled: true
  routes: [{ name: alt, mark: 0x30, table: 200, gateway: 192.168.2.1 }]
rules: []
`))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	// Without root a real run would fail; dry-run must not exec anything.
	if err := applyNetworkStack(cfg, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"dry-run: tc qdisc add dev eth1 root handle 1: htb default 999",
		"dry-run: tc filter add dev eth1 parent 1: protocol all handle 0x20 fw classid 1:10",
		"dry-run: ip rule add pref 1000 fwmark 0x30 table 200",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in log:\n%s", want, out)
		}
	}
	if err := applyNetworkStack(nil, false); err != nil {
		t.Fatalf("nil config: %v", err)
	}
}

func TestResolveQoSInterfacesAtStartup(t *testing.T) {
	host := &netinfo.Host{List: func() ([]netinfo.Interface, error) {
		ifs := []netinfo.Interface{{Name: "ens3", Up: true, OperState: "up", Addrs: []string{"198.51.100.2/24"}}}
		netinfo.Classify(ifs, []netinfo.Route{{Dev: "ens3", Gateway: "198.51.100.1"}})
		return ifs, nil
	}}
	load := func(iface string) *policy.Config {
		cfg, err := policy.LoadBytes([]byte(`
qos:
  enabled: true
  interfaces: [{ name: ` + iface + `, rate: 20mbit }]
  classes: [{ name: ssh, mark: 0x20, rate: 3mbit }]
rules: []
`))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	cfg := load("wan")
	if err := resolveQoSInterfaces(cfg, host, false); err != nil || cfg.QoS.Interfaces[0].Device() != "ens3" {
		t.Fatalf("wan: %v %+v", err, cfg.QoS.Interfaces)
	}
	if !strings.Contains(buf.String(), "qos interface: wan -> ens3") {
		t.Fatalf("resolution not logged:\n%s", buf.String())
	}

	// A policy written for the GNS3 router fails on a live host without eth1,
	// but dry-run only logs so the file can still be tested on the build VM.
	if err := resolveQoSInterfaces(load("eth1"), host, false); err == nil || !strings.Contains(err.Error(), "available: ens3 (WAN)") {
		t.Fatalf("live: expected missing interface error, got %v", err)
	}
	if err := resolveQoSInterfaces(load("eth1"), host, true); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(buf.String(), `dry-run: qos: interface "eth1"`) {
		t.Fatalf("dry-run warning not logged:\n%s", buf.String())
	}
}
