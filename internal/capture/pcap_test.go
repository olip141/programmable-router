package capture_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func TestPcapSSHFlow(t *testing.T) {
	l7 := runPcap(t, "ssh.pcap")
	key, _ := flow.NewKey(
		netip.MustParseAddr("172.16.238.1"),
		netip.MustParseAddr("172.16.238.168"),
		58395, 22, layers.IPProtocolTCP,
	)
	got, ok := l7[key]
	if !ok {
		t.Fatalf("missing flow %v, have %d flows", key, len(l7))
	}
	if got != "SSH" {
		t.Fatalf("expected SSH, got %q", got)
	}
}

func TestPcapDNSFlows(t *testing.T) {
	l7 := runPcap(t, "dns.pcap")
	if len(l7) != 4 {
		t.Fatalf("expected 4 classified flows, got %d", len(l7))
	}
	var dns, mdns int
	for _, name := range l7 {
		switch name {
		case "DNS":
			dns++
		case "MDNS":
			mdns++
		default:
			t.Fatalf("unexpected protocol %q", name)
		}
	}
	if dns != 3 || mdns != 1 {
		t.Fatalf("expected 3 DNS and 1 MDNS, got dns=%d mdns=%d", dns, mdns)
	}
}

func TestPcapHTTPGoogle(t *testing.T) {
	l7 := runPcap(t, "http.pcapng")
	if len(l7) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(l7))
	}
	for _, name := range l7 {
		if name != "HTTP.Google" {
			t.Fatalf("expected HTTP.Google, got %q", name)
		}
	}
}

func TestPcapTLSMicrosoft365(t *testing.T) {
	l7, meta := runPcapWithMeta(t, "tls-rdn-extract.pcap")
	if len(l7) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(l7))
	}
	for key, name := range l7 {
		if name != "TLS.Microsoft365" {
			t.Fatalf("expected TLS.Microsoft365, got %q", name)
		}
		m := meta[key]
		if m.Host == "" {
			t.Fatal("expected non-empty TLS host/SNI")
		}
		if m.TLS.Version == "" {
			t.Fatal("expected TLS version metadata")
		}
	}
}

func TestPcapHTTPMetadata(t *testing.T) {
	l7, meta := runPcapWithMeta(t, "http.pcapng")
	if len(l7) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(l7))
	}
	for key := range l7 {
		m := meta[key]
		if m.Host == "" && m.HTTP.URL == "" {
			t.Fatalf("expected HTTP host or URL metadata, got %+v", m)
		}
	}
}

func TestPcapDNSMetadata(t *testing.T) {
	_, meta := runPcapWithMeta(t, "dns.pcap")
	if len(meta) == 0 {
		t.Fatal("no flows")
	}
	var withQType int
	for _, m := range meta {
		if m.DNS.QType != 0 {
			withQType++
		}
	}
	if withQType == 0 {
		t.Fatal("expected DNS QType on at least one flow")
	}
}

func runPcap(t *testing.T, name string) map[flow.Key]string {
	l7, _ := runPcapWithMeta(t, name)
	return l7
}

func runPcapWithMeta(t *testing.T, name string) (map[flow.Key]string, map[flow.Key]dpi.Metadata) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)

	eng, err := dpi.New()
	if err != nil {
		t.Fatalf("dpi.New: %v", err)
	}
	defer eng.Close()

	classified := make(map[flow.Key]string)
	meta := make(map[flow.Key]dpi.Metadata)
	table := flow.NewTable(eng, flow.Config{
		OnClassified: func(f *flow.Flow) {
			classified[f.Key] = f.Protocol
			meta[f.Key] = f.Meta
		},
	})
	defer table.Close()

	src, err := capture.OpenFile(path, "")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer src.Close()

	var last time.Time
	ctx := context.Background()
	if err := src.Run(ctx, func(p *capture.Packet) {
		last = p.Timestamp
		table.Expire(p.Timestamp)
		table.Handle(p)
	}, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !last.IsZero() {
		table.Expire(last.Add(24 * time.Hour))
	}
	if table.Len() != 0 {
		t.Fatalf("expected 0 active flows after expire, got %d", table.Len())
	}

	if len(classified) == 0 {
		t.Fatal("no classified flows")
	}
	return classified, meta
}
