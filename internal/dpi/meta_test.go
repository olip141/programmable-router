package dpi

import (
	"slices"
	"testing"
)

func TestRiskNames(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	all := e.Risks()
	if len(all) < 10 {
		t.Fatalf("only %d risks known: %v", len(all), all)
	}
	if slices.Contains(all, "No risk") || slices.Contains(all, "") {
		t.Fatalf("Risks() contains placeholder entries: %v", all)
	}
	if e.RiskNames(0) != nil {
		t.Fatal("RiskNames(0) should be nil")
	}
	// Bit 0 is NDPI_NO_RISK; any two real risks must be reported in bit order.
	mask := uint64(1)<<1 | uint64(1)<<2
	got := e.RiskNames(mask)
	if len(got) != 2 || got[0] == got[1] {
		t.Fatalf("RiskNames(0b110) = %v", got)
	}
	for _, name := range got {
		if !slices.Contains(all, name) {
			t.Errorf("RiskNames returned %q not present in Risks()", name)
		}
	}
	if !slices.Contains(all, "Unidirectional Traffic") {
		t.Errorf("expected Unidirectional Traffic among risks: %v", all)
	}
}

func TestConfidences(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got := e.Confidences()
	for _, want := range []string{"Unknown", "DPI", "Match by port"} {
		if !slices.Contains(got, want) {
			t.Errorf("Confidences() = %v, missing %q", got, want)
		}
	}
}

func TestCategoryNameByIDRoundTrip(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, name := range []string{"Media", "Web", "Network", "Streaming"} {
		id, ok := e.CategoryID(name)
		if !ok {
			t.Errorf("CategoryID(%q) not found", name)
			continue
		}
		if back := e.CategoryNameByID(id); back != name {
			t.Errorf("CategoryNameByID(%d) = %q, want %q", id, back, name)
		}
	}
	if _, ok := e.CategoryID("media"); !ok {
		t.Error("CategoryID should be case-insensitive")
	}
}

func TestMetadataWithoutState(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if m := e.Metadata(nil, Result{}); m.Host != "" || m.Risks != nil {
		t.Fatalf("nil state metadata: %+v", m)
	}
	fs, err := e.NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	fs.Free()
	if m := e.Metadata(fs, Result{}); m.Host != "" || m.Confidence != "" {
		t.Fatalf("freed state metadata: %+v", m)
	}
	if FlowStructSize() < 100 {
		t.Fatalf("implausible ndpi_flow_struct size %d", FlowStructSize())
	}
}

func TestMetadataDNSQuery(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	fs, err := e.NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Free()
	r := e.Process(fs, dnsQuery(), 1_700_000_000_000)
	if !r.State.Final() {
		r = e.GiveUp(fs)
	}
	m := e.Metadata(fs, r)
	if m.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", m.Host)
	}
	if m.DNS.QType != 1 {
		t.Errorf("DNS.QType = %d, want 1 (A)", m.DNS.QType)
	}
	if m.Confidence == "" {
		t.Error("empty confidence")
	}
}
