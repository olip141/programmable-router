package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

// Lines copied from nDPI tests/cfgs/default/result/*.pcap.out.
const ndpiResultExcerpt = `DPI Packets (UDP):	2	(2.00 pkts/flow)
Confidence DPI              : 1 (flows)

DNS	2	262	1

	1	UDP 192.168.1.168:65311 <-> 8.8.8.8:53 [proto: 5/DNS][Stack: DNS][IP: 126/Google][ClearText][Confidence: DPI][DPI packets: 2][cat: Network/14]
	2	TCP [2001:470:1f17:13f:3e97:eff:fe73:4dec]:60205 <-> [2604:a880:1:20::224:b001]:443 [proto: 91/TLS][Stack: TLS][IP: 442/DigitalOcean][Encrypted]
	3	TCP 178.62.197.130:443 -> 192.168.1.13:53059 [proto: 91/TLS][Stack: TLS][Confidence: Match by port]
	4	UDP 10.10.100.25:62367 -> 10.10.101.2:17000 [VLAN: 505][proto: 0/Unknown][Stack: Unknown]
	5	TCP 10.0.0.1:1000 <-> 10.0.0.2:80 [proto: 7.295/HTTP.1kxun][Stack: HTTP]
	6	UDP 192.168.1.168:65311 <-> 8.8.8.8:53 [proto: 5/Other][Stack: DNS]
`

func TestParseTruthLine(t *testing.T) {
	cases := []struct {
		line, key, proto string
	}{
		{"\t1\tUDP 192.168.1.168:65311 <-> 8.8.8.8:53 [proto: 5/DNS][Stack: DNS]", "UDP|192.168.1.168:65311|8.8.8.8:53", "DNS"},
		{"\t3\tTCP 178.62.197.130:443 -> 192.168.1.13:53059 [proto: 91/TLS]", "TCP|178.62.197.130:443|192.168.1.13:53059", "TLS"},
		{"\t4\tUDP 10.10.100.25:62367 -> 10.10.101.2:17000 [VLAN: 505][proto: 0/Unknown]", "UDP|10.10.100.25:62367|10.10.101.2:17000", "Unknown"},
		{"\t5\tTCP 10.0.0.1:1000 <-> 10.0.0.2:80 [proto: 7.295/HTTP.1kxun]", "TCP|10.0.0.1:1000|10.0.0.2:80", "HTTP.1kxun"},
		{"\t7\tICMPV6 [fe80::1]:0 <-> [ff02::1]:0 [proto: 102/ICMPV6]", "ICMPV6|[fe80::1]:0|[ff02::1]:0", "ICMPV6"},
	}
	for _, tc := range cases {
		key, proto, ok := parseTruthLine(tc.line)
		if !ok || key != tc.key || proto != tc.proto {
			t.Errorf("parseTruthLine(%q) = %q, %q, %v; want %q, %q", tc.line, key, proto, ok, tc.key, tc.proto)
		}
	}
	for _, line := range []string{"", "DNS\t2\t262\t1", "Confidence DPI : 1 (flows)", "\t1\tUDP 1.2.3.4:1 <-> 5.6.7.8:2 [Stack: DNS]"} {
		if _, _, ok := parseTruthLine(line); ok {
			t.Errorf("parseTruthLine(%q) matched a non-flow line", line)
		}
	}
}

func TestParseTruthKeepsFirstDuplicate(t *testing.T) {
	got, err := parseTruth(strings.NewReader(ndpiResultExcerpt))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("parsed %d flows, want 5: %v", len(got), got)
	}
	if p := got[flowKey("UDP", "8.8.8.8:53", "192.168.1.168:65311")]; p != "DNS" {
		t.Fatalf("direction-independent lookup = %q, want DNS (first entry)", p)
	}
	if p := got[flowKey("tcp", "[2604:a880:1:20::224:b001]:443", "[2001:470:1f17:13f:3e97:eff:fe73:4dec]:60205")]; p != "TLS" {
		t.Fatalf("IPv6 lookup = %q", p)
	}
}

func TestEvaluateAgainstTruth(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	testdata := filepath.Join("..", "..", "testdata")

	rows, err := runFile(eng, filepath.Join(testdata, "dns.pcap"), flow.DefaultMaxDPIPackets)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("need at least 2 flows in dns.pcap, got %d", len(rows))
	}

	// Write truth in ndpiReader format with server first (reverse direction)
	// and a wrong label for the first flow.
	truthDir := t.TempDir()
	var b strings.Builder
	for i, r := range rows {
		label := r.protocol
		if i == 0 {
			label = "NotTheRightProto"
		}
		fmt.Fprintf(&b, "\t%d\t%s %s <-> %s [proto: 1/%s][Stack: X]\n", i+1, r.proto, r.dst, r.src, label)
	}
	if err := os.WriteFile(filepath.Join(truthDir, "dns.pcap.out"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	truth, err := loadTruth(truthDir)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	sum, err := evaluate(eng, testdata, truth, flow.DefaultMaxDPIPackets, &out)
	if err != nil {
		t.Fatal(err)
	}
	if sum.files != 4 {
		t.Errorf("files = %d, want 4 (testdata captures)", sum.files)
	}
	if sum.flows <= len(rows) {
		t.Errorf("flows = %d, want more than the %d dns.pcap flows", sum.flows, len(rows))
	}
	if sum.truthFlows != len(rows) || sum.compared != len(rows) || sum.correct != len(rows)-1 || sum.notInTruth != 0 {
		t.Errorf("truth stats: %+v (dns.pcap flows %d)", sum, len(rows))
	}

	records, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != sum.flows+1 {
		t.Fatalf("csv rows %d, want %d + header", len(records), sum.flows)
	}
	header := records[0]
	col := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		t.Fatalf("missing column %q", name)
		return -1
	}
	matches := map[string]int{}
	for _, rec := range records[1:] {
		if rec[col("file")] == "dns.pcap" {
			matches[rec[col("match")]]++
		} else if rec[col("match")] != "n/a" {
			t.Errorf("file without truth has match=%q", rec[col("match")])
		}
	}
	if matches["0"] != 1 || matches["1"] != len(rows)-1 {
		t.Errorf("dns.pcap match column: %v", matches)
	}
	if !strings.Contains(sum.String(), fmt.Sprintf("flows=%d ", sum.flows)) {
		t.Errorf("summary line: %s", sum)
	}
}

// Runs against the nDPI test suite when it is checked out (used to build libndpi).
func TestEvaluateNDPISuiteSample(t *testing.T) {
	const suite = "/tmp/nDPI/tests/cfgs/default"
	sample := []string{"dns_long_domainname.pcap", "443-chrome.pcap", "ssh.pcap"}
	for _, f := range sample {
		if _, err := os.Stat(filepath.Join(suite, "pcap", f)); err != nil {
			t.Skipf("nDPI test suite not available: %v", err)
		}
	}
	dir := t.TempDir()
	for _, f := range sample {
		if err := os.Symlink(filepath.Join(suite, "pcap", f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	truth, err := loadTruth(filepath.Join(suite, "result"))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	var out bytes.Buffer
	sum, err := evaluate(eng, dir, truth, flow.DefaultMaxDPIPackets, &out)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(sum)
	if sum.files != len(sample) || sum.compared == 0 {
		t.Fatalf("nothing compared: %+v", sum)
	}
	if sum.compared < sum.flows/2 {
		t.Errorf("only %d of %d flows found in truth; key format mismatch?", sum.compared, sum.flows)
	}
	if ratio(sum.correct, sum.compared) < 0.8 {
		t.Errorf("accuracy %.2f on nDPI's own captures is implausibly low:\n%s", ratio(sum.correct, sum.compared), out.String())
	}
}
