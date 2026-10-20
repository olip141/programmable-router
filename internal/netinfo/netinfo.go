// Package netinfo discovers network interfaces on the host and resolves the
// aliases "wan", "lan" and "auto" used in the policy file and the -i flag.
// It reads only net.Interfaces, /sys/class/net and /proc/net, so it needs no
// privileges.
package netinfo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Interface roles.
const (
	RoleWAN = "wan"
	RoleLAN = "lan"
)

// Aliases accepted in place of an interface name.
const (
	AliasWAN  = "wan"
	AliasLAN  = "lan"
	AliasAuto = "auto"
)

// Interface describes one host network interface.
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	OperState string   `json:"oper_state,omitempty"`
	SpeedMbps int      `json:"speed_mbps,omitempty"`
	Loopback  bool     `json:"loopback,omitempty"`
	Virtual   bool     `json:"virtual,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	Role      string   `json:"role,omitempty"`

	defaultRoute bool
	// rank orders default routes: IPv4 before IPv6 (their metrics use
	// different scales), then by metric.
	rank routeRank
}

type routeRank struct {
	ipv6   bool
	metric int
}

func (a routeRank) less(b routeRank) bool {
	if a.ipv6 != b.ipv6 {
		return !a.ipv6
	}
	return a.metric < b.metric
}

// Route is a default route read from /proc/net/route or /proc/net/ipv6_route.
type Route struct {
	Dev     string
	Gateway string
	Metric  int
	IPv6    bool
}

// Report is the host view served to the admin GUI.
type Report struct {
	Interfaces  []Interface       `json:"interfaces"`
	Capture     string            `json:"capture,omitempty"`
	Aliases     map[string]string `json:"aliases"`
	AliasErrors map[string]string `json:"alias_errors,omitempty"`
}

// IsAlias reports whether name is one of the interface aliases.
func IsAlias(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case AliasWAN, AliasLAN, AliasAuto:
		return true
	}
	return false
}

// Host resolves names against the live system. Capture is the resolved
// live-capture interface ("" for offline replay); "lan" prefers it.
type Host struct {
	Capture string
	// List overrides interface discovery (tests). Nil means List.
	List func() ([]Interface, error)
}

func (h *Host) list() ([]Interface, error) {
	if h != nil && h.List != nil {
		return h.List()
	}
	return List()
}

func (h *Host) capture() string {
	if h == nil {
		return ""
	}
	return h.Capture
}

// Resolve maps an alias or interface name to an existing interface.
func (h *Host) Resolve(name string) (string, error) {
	ifs, err := h.list()
	if err != nil {
		return "", err
	}
	return Resolve(name, h.capture(), ifs)
}

// Report lists interfaces and how the aliases resolve right now.
func (h *Host) Report() (Report, error) {
	ifs, err := h.list()
	if err != nil {
		return Report{}, err
	}
	rep := Report{Interfaces: ifs, Capture: h.capture(), Aliases: map[string]string{}}
	for _, a := range []string{AliasWAN, AliasLAN} {
		dev, err := Resolve(a, h.capture(), ifs)
		if err != nil {
			if rep.AliasErrors == nil {
				rep.AliasErrors = map[string]string{}
			}
			rep.AliasErrors[a] = err.Error()
			continue
		}
		rep.Aliases[a] = dev
	}
	return rep, nil
}

// Resolve maps name to an interface in ifs:
//   - "wan": the interface holding the default route with the lowest metric;
//   - "lan": capture when it is not a WAN, else the only LAN candidate;
//   - "auto": like "lan", falling back to "wan" on single-interface hosts;
//   - anything else must be an existing interface name.
func Resolve(name, capture string, ifs []Interface) (string, error) {
	name = strings.TrimSpace(name)
	switch strings.ToLower(name) {
	case AliasWAN:
		if w := primaryWAN(ifs); w != "" {
			return w, nil
		}
		return "", fmt.Errorf("netinfo: wan: no interface has a default route; available: %s", describe(ifs))
	case AliasLAN:
		return resolveLAN(capture, ifs)
	case AliasAuto:
		dev, err := resolveLAN(capture, ifs)
		if err == nil {
			return dev, nil
		}
		if len(lanCandidates(ifs)) == 0 {
			if w := primaryWAN(ifs); w != "" {
				return w, nil
			}
		}
		return "", fmt.Errorf("netinfo: auto: %w", err)
	}
	for _, ifc := range ifs {
		if ifc.Name == name {
			return name, nil
		}
	}
	return "", fmt.Errorf("netinfo: interface %q does not exist; available: %s", name, describe(ifs))
}

func resolveLAN(capture string, ifs []Interface) (string, error) {
	if capture != "" {
		for _, ifc := range ifs {
			if ifc.Name == capture && ifc.Role != RoleWAN {
				return capture, nil
			}
		}
	}
	cands := lanCandidates(ifs)
	switch len(cands) {
	case 1:
		return cands[0], nil
	case 0:
		return "", fmt.Errorf("netinfo: lan: no LAN interface found; available: %s", describe(ifs))
	default:
		return "", fmt.Errorf("netinfo: lan: ambiguous, candidates %s; give the interface name explicitly", strings.Join(cands, ", "))
	}
}

func primaryWAN(ifs []Interface) string {
	best := -1
	for i, ifc := range ifs {
		if !ifc.defaultRoute {
			continue
		}
		if best < 0 || ifc.rank.less(ifs[best].rank) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return ifs[best].Name
}

func lanCandidates(ifs []Interface) []string {
	var out []string
	for _, ifc := range ifs {
		if ifc.Role == RoleLAN {
			out = append(out, ifc.Name)
		}
	}
	return out
}

func describe(ifs []Interface) string {
	var parts []string
	for _, ifc := range ifs {
		if ifc.Loopback {
			continue
		}
		s := ifc.Name
		if ifc.Role != "" {
			s += " (" + strings.ToUpper(ifc.Role) + ")"
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// Container and hypervisor bridges are never a router LAN.
var ignoredLAN = regexp.MustCompile(`^(docker|veth|virbr|lxcbr|cni|flannel|br-[0-9a-f]{12}$)`)

// Classify sets Role, Gateway and the default-route flag from routes.
func Classify(ifs []Interface, routes []Route) {
	for i := range ifs {
		ifc := &ifs[i]
		ifc.Role, ifc.Gateway, ifc.defaultRoute, ifc.rank = "", "", false, routeRank{}
		for _, r := range routes {
			if r.Dev != ifc.Name {
				continue
			}
			rank := routeRank{ipv6: r.IPv6, metric: r.Metric}
			if !ifc.defaultRoute || rank.less(ifc.rank) {
				ifc.rank = rank
				ifc.Gateway = r.Gateway
			}
			ifc.defaultRoute = true
		}
		switch {
		case ifc.Loopback:
		case ifc.defaultRoute:
			ifc.Role = RoleWAN
		case ifc.Up && ifc.OperState != "down" && !ignoredLAN.MatchString(ifc.Name) && hasRoutableAddr(ifc.Addrs):
			ifc.Role = RoleLAN
		}
	}
}

func hasRoutableAddr(addrs []string) bool {
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

const (
	sysClassNet = "/sys/class/net"
	procNet     = "/proc/net"
)

// List reads the host interfaces, sorted by name.
func List() ([]Interface, error) {
	nifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("netinfo: %w", err)
	}
	ifs := make([]Interface, 0, len(nifs))
	for _, n := range nifs {
		ifc := Interface{
			Name:     n.Name,
			MAC:      n.HardwareAddr.String(),
			MTU:      n.MTU,
			Up:       n.Flags&net.FlagUp != 0,
			Loopback: n.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := n.Addrs(); err == nil {
			for _, a := range addrs {
				ifc.Addrs = append(ifc.Addrs, a.String())
			}
		}
		readSysfs(sysClassNet, &ifc)
		ifs = append(ifs, ifc)
	}
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
	Classify(ifs, readDefaultRoutes(procNet))
	return ifs, nil
}

func readSysfs(root string, ifc *Interface) {
	dir := filepath.Join(root, ifc.Name)
	if target, err := os.Readlink(dir); err == nil {
		ifc.Virtual = strings.Contains(target, "/virtual/")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "operstate")); err == nil {
		ifc.OperState = strings.TrimSpace(string(b))
	}
	// Reading speed fails with EINVAL on links that are down or have no
	// fixed speed (Wi-Fi, many virtual NICs); -1 means the same.
	if b, err := os.ReadFile(filepath.Join(dir, "speed")); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && v > 0 {
			ifc.SpeedMbps = v
		}
	}
}

func readDefaultRoutes(root string) []Route {
	var routes []Route
	if f, err := os.Open(filepath.Join(root, "route")); err == nil {
		routes = append(routes, ParseRouteV4(f)...)
		f.Close()
	}
	if f, err := os.Open(filepath.Join(root, "ipv6_route")); err == nil {
		routes = append(routes, ParseRouteV6(f)...)
		f.Close()
	}
	return routes
}

const (
	rtfUp     = 0x1
	rtfReject = 0x200
)

// ParseRouteV4 returns default routes from /proc/net/route (main table only).
func ParseRouteV4(r io.Reader) []Route {
	var out []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		if f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		rt := Route{Dev: f[0], Metric: metric}
		if gw, err := strconv.ParseUint(f[2], 16, 32); err == nil && gw != 0 {
			// The kernel prints the network-order address as a host integer.
			ip := make(net.IP, 4)
			binary.NativeEndian.PutUint32(ip, uint32(gw))
			rt.Gateway = ip.String()
		}
		out = append(out, rt)
	}
	return out
}

// ParseRouteV6 returns default routes from /proc/net/ipv6_route.
func ParseRouteV6(r io.Reader) []Route {
	var out []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[9] == "lo" {
			continue
		}
		if f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 32)
		rt := Route{Dev: f[9], Metric: int(metric), IPv6: true}
		if gw := parseHexIPv6(f[4]); gw != nil && !gw.IsUnspecified() {
			rt.Gateway = gw.String()
		}
		out = append(out, rt)
	}
	return out
}

func parseHexIPv6(s string) net.IP {
	if len(s) != 32 {
		return nil
	}
	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil
		}
		ip[i] = byte(v)
	}
	return ip
}
