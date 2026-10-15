// Package capture reads packets from a live interface or a capture file and
// decodes them into the L3/L4 fields needed by the flow table.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen       = 65535
	readTimeout   = 500 * time.Millisecond
	sll2LinkType  = 276 // DLT_LINUX_SLL2
	sll2HeaderLen = 20
)

// Packet is a decoded packet handed to the handler. It is reused between
// calls: neither the struct nor L3 may be retained after the handler returns.
type Packet struct {
	Timestamp time.Time
	Src, Dst  netip.Addr
	// SrcPort and DstPort are zero for protocols other than TCP and UDP.
	SrcPort, DstPort uint16
	Proto            layers.IPProtocol
	// L3 starts at the IP header and ends at the IP total length, so link
	// layer headers and Ethernet padding are excluded.
	L3 []byte
	// WireLen is the original frame length on the wire.
	WireLen int
}

// Stats counts what happened to the packets read from the source.
type Stats struct {
	Read      uint64 // packets returned by libpcap
	Delivered uint64 // packets passed to the handler
	NonIP     uint64 // packets without an IPv4/IPv6 header
	Malformed uint64 // decode errors, truncated L4, IP fragments without L4
	// Kernel counters, available only for live captures.
	KernelReceived, KernelDropped, IfDropped int
}

// Source is an open live interface or capture file.
type Source struct {
	handle *pcap.Handle
	live   bool
	link   layers.LinkType
	sll2   bool

	eth   layers.Ethernet
	sll   layers.LinuxSLL
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP

	linkParser *gopacket.DecodingLayerParser
	ip4Parser  *gopacket.DecodingLayerParser
	ip6Parser  *gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType

	pkt   Packet
	stats Stats
}

// OpenLive opens iface for capturing. bpf may be empty.
func OpenLive(iface, bpf string, promisc bool) (*Source, error) {
	h, err := pcap.OpenLive(iface, snapLen, promisc, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("capture: open %s: %w", iface, err)
	}
	if bpf != "" {
		if err := h.SetBPFFilter(bpf); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture: BPF filter %q: %w", bpf, err)
		}
	}
	s, err := newSource(h, true)
	if err != nil {
		h.Close()
		return nil, err
	}
	return s, nil
}

// OpenFile opens a pcap or pcapng file. bpf may be empty.
func OpenFile(path, bpf string) (*Source, error) {
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("capture: open %s: %w", path, err)
	}
	if bpf != "" {
		if err := h.SetBPFFilter(bpf); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture: BPF filter %q: %w", bpf, err)
		}
	}
	s, err := newSource(h, false)
	if err != nil {
		h.Close()
		return nil, err
	}
	return s, nil
}

func newSource(h *pcap.Handle, live bool) (*Source, error) {
	s := &Source{handle: h, live: live, link: h.LinkType(), decoded: make([]gopacket.LayerType, 0, 8)}
	s.sll2 = s.link == layers.LinkType(sll2LinkType&0xff) && hasDatalink(h, "LINUX_SLL2")
	common := []gopacket.DecodingLayer{&s.dot1q, &s.ip4, &s.ip6, &s.tcp, &s.udp}

	switch {
	case s.sll2:
	case s.link == layers.LinkTypeEthernet:
		s.linkParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, append([]gopacket.DecodingLayer{&s.eth}, common...)...)
	case s.link == layers.LinkTypeLinuxSLL:
		s.linkParser = gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL, append([]gopacket.DecodingLayer{&s.sll}, common...)...)
	case s.link == layers.LinkTypeRaw, s.link == layers.LinkTypeIPv4, s.link == layers.LinkTypeIPv6:
	default:
		return nil, fmt.Errorf("capture: unsupported link type %v", s.link)
	}
	s.ip4Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, common...)
	s.ip6Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, common...)
	for _, p := range []*gopacket.DecodingLayerParser{s.linkParser, s.ip4Parser, s.ip6Parser} {
		if p != nil {
			p.IgnoreUnsupported = true
		}
	}
	return s, nil
}

// hasDatalink reports whether libpcap lists a datalink called name for h.
// gopacket truncates DLT values to uint8, so DLT_LINUX_SLL2 (276) can only be
// told apart by its name.
func hasDatalink(h *pcap.Handle, name string) bool {
	dls, err := h.ListDataLinks()
	if err != nil {
		return false
	}
	for _, dl := range dls {
		if dl.Name == name {
			return true
		}
	}
	return false
}

// LinkType returns the data link type of the source.
func (s *Source) LinkType() layers.LinkType { return s.link }

// Close releases the pcap handle.
func (s *Source) Close() {
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}
}

// Stats returns the counters collected so far.
func (s *Source) Stats() Stats {
	st := s.stats
	if s.live && s.handle != nil {
		if ks, err := s.handle.Stats(); err == nil {
			st.KernelReceived = ks.PacketsReceived
			st.KernelDropped = ks.PacketsDropped
			st.IfDropped = ks.PacketsIfDropped
		}
	}
	return st
}

// Run reads packets until ctx is cancelled or the file ends, calling fn for
// every decoded IP packet. It returns nil on a clean stop.
func (s *Source) Run(ctx context.Context, fn func(*Packet)) error {
	var stop atomic.Bool
	defer context.AfterFunc(ctx, func() { stop.Store(true) })()

	for !stop.Load() {
		data, ci, err := s.handle.ZeroCopyReadPacketData()
		switch {
		case err == nil:
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		case errors.Is(err, io.EOF), errors.Is(err, pcap.NextErrorNoMorePackets):
			return nil
		default:
			return fmt.Errorf("capture: read: %w", err)
		}
		s.stats.Read++
		if s.decode(data, ci) {
			s.stats.Delivered++
			fn(&s.pkt)
		}
	}
	return nil
}

func (s *Source) decodedHasIP() bool {
	for _, t := range s.decoded {
		if t == layers.LayerTypeIPv4 || t == layers.LayerTypeIPv6 {
			return true
		}
	}
	return false
}

// tryPPPoEIP decodes IP inside PPPoE, including Q-in-Q VLAN stacks before 0x8864.
func (s *Source) tryPPPoEIP(data []byte) {
	const pppoeType = uint16(layers.EthernetTypePPPoESession)
	for i := 12; i+14 <= len(data); i++ {
		if binary.BigEndian.Uint16(data[i:i+2]) != pppoeType {
			continue
		}
		base := i + 2
		if base+8 > len(data) {
			continue
		}
		switch binary.BigEndian.Uint16(data[base+6 : base+8]) {
		case 0x0021:
			_ = s.ip4Parser.DecodeLayers(data[base+8:], &s.decoded)
		case 0x0057:
			_ = s.ip6Parser.DecodeLayers(data[base+8:], &s.decoded)
		}
		if s.decodedHasIP() {
			return
		}
	}
}

// decode fills s.pkt from data and reports whether it holds a usable packet.
func (s *Source) decode(data []byte, ci gopacket.CaptureInfo) bool {
	s.decoded = s.decoded[:0]
	var err error
	switch {
	case s.sll2:
		if len(data) < sll2HeaderLen {
			s.stats.Malformed++
			return false
		}
		switch layers.EthernetType(binary.BigEndian.Uint16(data[0:2])) {
		case layers.EthernetTypeIPv4:
			err = s.ip4Parser.DecodeLayers(data[sll2HeaderLen:], &s.decoded)
		case layers.EthernetTypeIPv6:
			err = s.ip6Parser.DecodeLayers(data[sll2HeaderLen:], &s.decoded)
		default:
			s.stats.NonIP++
			return false
		}
	case s.link == layers.LinkTypeEthernet || s.link == layers.LinkTypeLinuxSLL:
		err = s.linkParser.DecodeLayers(data, &s.decoded)
	case s.link == layers.LinkTypeRaw || s.link == layers.LinkTypeIPv4 || s.link == layers.LinkTypeIPv6:
		if len(data) == 0 {
			s.stats.Malformed++
			return false
		}
		switch data[0] >> 4 {
		case 4:
			err = s.ip4Parser.DecodeLayers(data, &s.decoded)
		case 6:
			err = s.ip6Parser.DecodeLayers(data, &s.decoded)
		default:
			s.stats.NonIP++
			return false
		}
	default:
		s.stats.Malformed++
		return false
	}
	_ = err
	if !s.decodedHasIP() && s.link == layers.LinkTypeEthernet {
		s.tryPPPoEIP(data)
	}

	// The last IP layer wins, so that L3 and L4 always describe the same
	// (innermost) packet for IP-in-IP tunnels.
	var ipLayer, l4Layer gopacket.LayerType
	for _, t := range s.decoded {
		switch t {
		case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
			ipLayer, l4Layer = t, 0
		case layers.LayerTypeTCP, layers.LayerTypeUDP:
			l4Layer = t
		}
	}
	if ipLayer == 0 {
		if err != nil {
			s.stats.Malformed++
		} else {
			s.stats.NonIP++
		}
		return false
	}

	p := &s.pkt
	var hdr []byte
	var ipLen int
	if ipLayer == layers.LayerTypeIPv4 {
		if len(s.ip4.SrcIP) != 4 || len(s.ip4.DstIP) != 4 {
			s.stats.Malformed++
			return false
		}
		p.Src = netip.AddrFrom4([4]byte(s.ip4.SrcIP))
		p.Dst = netip.AddrFrom4([4]byte(s.ip4.DstIP))
		p.Proto = s.ip4.Protocol
		hdr, ipLen = s.ip4.Contents, int(s.ip4.Length)
	} else {
		if len(s.ip6.SrcIP) != 16 || len(s.ip6.DstIP) != 16 {
			s.stats.Malformed++
			return false
		}
		p.Src = netip.AddrFrom16([16]byte(s.ip6.SrcIP))
		p.Dst = netip.AddrFrom16([16]byte(s.ip6.DstIP))
		p.Proto = s.ip6.NextHeader
		hdr, ipLen = s.ip6.Contents, 40+int(s.ip6.Length)
		if s.ip6.Length == 0 { // jumbogram
			ipLen = 0
		}
	}

	switch l4Layer {
	case layers.LayerTypeTCP:
		p.Proto = layers.IPProtocolTCP
		p.SrcPort, p.DstPort = uint16(s.tcp.SrcPort), uint16(s.tcp.DstPort)
	case layers.LayerTypeUDP:
		p.Proto = layers.IPProtocolUDP
		p.SrcPort, p.DstPort = uint16(s.udp.SrcPort), uint16(s.udp.DstPort)
	default:
		// TCP/UDP that could not be decoded (snaplen, non-first fragment)
		// would create a bogus port-less flow.
		if p.Proto == layers.IPProtocolTCP || p.Proto == layers.IPProtocolUDP {
			s.stats.Malformed++
			return false
		}
		p.SrcPort, p.DstPort = 0, 0
	}

	off := bytes.Index(data, hdr)
	if off < 0 {
		needle := hdr
		if len(needle) > 8 {
			needle = needle[:8]
		}
		off = bytes.Index(data, needle)
	}
	if off < 0 || off >= len(data) {
		s.stats.Malformed++
		return false
	}
	end := len(data)
	if ipLen > 0 && off+ipLen < end {
		end = off + ipLen
	}
	p.L3 = data[off:end]
	p.Timestamp = ci.Timestamp
	p.WireLen = ci.Length
	return true
}
