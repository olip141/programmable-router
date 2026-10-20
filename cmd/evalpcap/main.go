// Command evalpcap classifies every flow in a directory of captures and,
// optionally, compares the labels with ndpiReader results
// (nDPI tests/cfgs/default/result/*.pcap.out).
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func main() {
	dir := flag.String("dir", "", "directory of pcap/pcapng files")
	out := flag.String("out", "flows.csv", "output CSV path")
	truthDir := flag.String("truth", "", "nDPI tests result directory (optional)")
	maxDPI := flag.Int("dpi-max-packets", flow.DefaultMaxDPIPackets, "max DPI packets per flow")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: evalpcap -dir <pcapdir> [-truth resultdir]")
		os.Exit(2)
	}

	eng, err := dpi.New()
	if err != nil {
		fatal(err)
	}
	defer eng.Close()

	truth := truthSet{}
	if *truthDir != "" {
		if truth, err = loadTruth(*truthDir); err != nil {
			fatal(err)
		}
	}

	f, err := os.Create(*out)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	sum, err := evaluate(eng, *dir, truth, *maxDPI, f)
	if err != nil {
		fatal(err)
	}
	fmt.Println(sum)
}

type summary struct {
	files, flows                  int
	compared, correct, notInTruth int
	unknown, gaveUp               int
	truthFlows                    int
}

func (s summary) String() string {
	return fmt.Sprintf("files=%d flows=%d truth_flows=%d truth_compared=%d correct=%d accuracy=%.3f not_in_truth=%d unknown=%d gave_up=%d",
		s.files, s.flows, s.truthFlows, s.compared, s.correct, ratio(s.correct, s.compared), s.notInTruth, s.unknown, s.gaveUp)
}

// evaluate classifies every capture in dir and writes one CSV row per flow.
func evaluate(eng *dpi.Engine, dir string, truth truthSet, maxDPI int, out io.Writer) (summary, error) {
	var sum summary
	for _, ft := range truth {
		sum.truthFlows += len(ft)
	}
	w := csv.NewWriter(out)
	_ = w.Write([]string{
		"file", "src", "dst", "sport", "dport", "proto", "protocol", "master", "app", "category",
		"confidence", "host", "gave_up", "dpi_packets", "ms_to_classify", "truth", "match",
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		return sum, err
	}
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".pcap" && ext != ".pcapng") {
			continue
		}
		rows, err := runFile(eng, filepath.Join(dir, e.Name()), maxDPI)
		if err != nil {
			fmt.Fprintf(os.Stderr, "evalpcap: %s: %v\n", e.Name(), err)
			continue
		}
		sum.files++
		fileTruth := truth[e.Name()]
		for _, r := range rows {
			sum.flows++
			want, match := "", "n/a"
			if fileTruth != nil {
				var ok bool
				want, ok = fileTruth[r.key]
				switch {
				case !ok:
					sum.notInTruth++
				case strings.EqualFold(r.protocol, want):
					match = "1"
					sum.correct++
					sum.compared++
				default:
					match = "0"
					sum.compared++
				}
			}
			if r.protocol == "" || r.protocol == "Unknown" {
				sum.unknown++
			}
			if r.gaveUp {
				sum.gaveUp++
			}
			_ = w.Write([]string{
				r.file, r.src.Addr().String(), r.dst.Addr().String(),
				strconv.Itoa(int(r.src.Port())), strconv.Itoa(int(r.dst.Port())), r.proto,
				r.protocol, r.master, r.app, r.category, r.confidence, r.host,
				boolStr(r.gaveUp), strconv.Itoa(r.dpiPackets), strconv.FormatInt(r.msClassify, 10),
				want, match,
			})
		}
	}
	w.Flush()
	return sum, w.Error()
}

type row struct {
	file, proto, key                                  string
	src, dst                                          netip.AddrPort
	protocol, master, app, category, confidence, host string
	gaveUp                                            bool
	dpiPackets                                        int
	msClassify                                        int64
}

func runFile(eng *dpi.Engine, path string, maxDPI int) ([]row, error) {
	src, err := capture.OpenFile(path, "")
	if err != nil {
		return nil, err
	}
	defer src.Close()
	file := filepath.Base(path)
	var out []row
	table := flow.NewTable(eng, flow.Config{
		MaxDPIPackets: maxDPI,
		OnClassified: func(f *flow.Flow) {
			proto := l4Name(f.Key.Proto)
			out = append(out, row{
				file:       file,
				proto:      proto,
				key:        flowKey(proto, f.Client.String(), f.Server.String()),
				src:        f.Client,
				dst:        f.Server,
				protocol:   f.Protocol,
				master:     f.Master,
				app:        f.App,
				category:   f.Category,
				confidence: f.Meta.Confidence,
				host:       f.Meta.Host,
				gaveUp:     f.GaveUp,
				dpiPackets: f.DPIPackets,
				msClassify: f.ClassifiedAt.Sub(f.FirstSeen).Milliseconds(),
			})
		},
	})
	err = src.Run(context.Background(), func(p *capture.Packet) { table.Handle(p) }, nil)
	table.Close()
	return out, err
}

// truthSet maps capture file name -> flow key -> nDPI protocol label.
type truthSet map[string]map[string]string

// truthLine matches flow lines of ndpiReader output, e.g.
//
//	1	UDP 192.168.1.168:65311 <-> 8.8.8.8:53 [proto: 5/DNS][Stack: DNS]...
//	2	TCP [2001:db8::1]:443 -> [2001:db8::2]:5000 [VLAN: 5][proto: 91.126/TLS.Google]...
var truthLine = regexp.MustCompile(`^\s*\d+\s+(\S+)\s+(\S+)\s+<?->\s+(\S+)\s.*?\[proto:\s*[\d.]+/([^\]]+)\]`)

// parseTruthLine returns the flow key and protocol label for one result line.
func parseTruthLine(line string) (key, proto string, ok bool) {
	m := truthLine.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	return flowKey(m[1], m[2], m[3]), strings.TrimSpace(m[4]), true
}

func parseTruth(r io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, proto, ok := parseTruthLine(line)
		if !ok {
			continue
		}
		if _, dup := out[key]; !dup {
			out[key] = proto
		}
	}
	return out, nil
}

func loadTruth(dir string) (truthSet, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := truthSet{}
	for _, f := range files {
		pcap, ok := strings.CutSuffix(f.Name(), ".out")
		if !ok || f.IsDir() {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			return nil, err
		}
		t, err := parseTruth(fh)
		fh.Close()
		if err != nil {
			return nil, err
		}
		if len(t) > 0 {
			out[pcap] = t
		}
	}
	return out, nil
}

// flowKey identifies a flow independently of direction, since ndpiReader
// and the flow table may disagree on which side is the client.
func flowKey(l4, a, b string) string {
	if b < a {
		a, b = b, a
	}
	return strings.ToUpper(l4) + "|" + a + "|" + b
}

func l4Name(p layers.IPProtocol) string {
	switch p {
	case layers.IPProtocolTCP:
		return "TCP"
	case layers.IPProtocolUDP:
		return "UDP"
	case layers.IPProtocolICMPv4:
		return "ICMP"
	case layers.IPProtocolICMPv6:
		return "ICMPV6"
	default:
		return strconv.Itoa(int(p))
	}
}

func boolStr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
