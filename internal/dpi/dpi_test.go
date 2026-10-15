package dpi

import (
	"encoding/binary"
	"testing"
)

func TestEngineLifecycle(t *testing.T) {
	if Revision() == "" {
		t.Fatal("empty nDPI revision")
	}
	if APIVersion() == 0 {
		t.Fatal("zero nDPI API version")
	}
	t.Logf("nDPI %s, API %d", Revision(), APIVersion())

	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	fs, err := e.NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	fs.Free()
	fs.Free()

	if got := e.Process(fs, []byte{0x45}, 0); got != (Result{}) {
		t.Errorf("Process on freed flow = %+v, want zero", got)
	}
	if got := e.ProtocolName(Result{}); got != "Unknown" {
		t.Errorf("ProtocolName(unknown) = %q, want %q", got, "Unknown")
	}
}

// dnsQuery returns an IPv4/UDP DNS query for example.com with zero checksums.
func dnsQuery() []byte {
	dns := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	udpLen := 8 + len(dns)
	pkt := make([]byte, 20+udpLen)
	ip := pkt[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(pkt)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], []byte{192, 168, 1, 10})
	copy(ip[16:], []byte{192, 168, 1, 1})
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], dns)
	return pkt
}

func TestProcessDNS(t *testing.T) {
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
	if !r.Known() {
		t.Fatalf("DNS query not detected: %+v", r)
	}
	if name := e.ProtocolName(r); name != "DNS" {
		t.Errorf("ProtocolName = %q, want DNS (result %+v)", name, r)
	}
	if cat := e.CategoryName(r); cat == "" {
		t.Error("empty category name")
	}
}
