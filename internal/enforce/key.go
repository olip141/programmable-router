package enforce

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/gopacket/layers"

	"edge-router/internal/flow"
)

// flowElementKey builds the concatenated nftables map key for a flow (client -> server).
func flowElementKey(f *flow.Flow) (key []byte, ipv6 bool, ok bool) {
	if f.Key.Proto != layers.IPProtocolTCP && f.Key.Proto != layers.IPProtocolUDP {
		return nil, false, false
	}
	client := f.Client.Addr()
	server := f.Server.Addr()
	if client.Is4() && server.Is4() {
		return concatFlowKey(client, server, f.Client.Port(), f.Server.Port(), uint8(f.Key.Proto)), false, true
	}
	if client.Is6() && server.Is6() {
		return concatFlowKey(client, server, f.Client.Port(), f.Server.Port(), uint8(f.Key.Proto)), true, true
	}
	return nil, false, false
}

func concatFlowKey(src, dst netip.Addr, sport, dport uint16, proto uint8) []byte {
	var key []byte
	key = append(key, src.AsSlice()...)
	key = append(key, dst.AsSlice()...)
	key = append(key, padField([]byte{proto})...)
	key = append(key, padField(binary.BigEndian.AppendUint16(nil, sport))...)
	key = append(key, padField(binary.BigEndian.AppendUint16(nil, dport))...)
	return key
}

// padField pads a concat field to a 4-byte register (nftables concat set rules).
func padField(raw []byte) []byte {
	out := make([]byte, 4)
	copy(out, raw)
	return out
}

// reverseFlowKey swaps client/server for bidirectional map lookup on first packets.
func reverseFlowKey(f *flow.Flow) ([]byte, bool) {
	if f.Key.Proto != layers.IPProtocolTCP && f.Key.Proto != layers.IPProtocolUDP {
		return nil, false
	}
	client := f.Client.Addr()
	server := f.Server.Addr()
	if client.Is4() && server.Is4() {
		return concatFlowKey(server, client, f.Server.Port(), f.Client.Port(), uint8(f.Key.Proto)), true
	}
	if client.Is6() && server.Is6() {
		return concatFlowKey(server, client, f.Server.Port(), f.Client.Port(), uint8(f.Key.Proto)), true
	}
	return nil, false
}
