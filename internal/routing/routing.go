package routing

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"edge-router/internal/policy"
)

const defaultPref = 1000

// families returns the ip(8) family flags for gateway: IPv4 rules always,
// IPv6 rules too when the gateway is an IPv6 address.
func families(gateway string) []string {
	if strings.Contains(gateway, ":") {
		return []string{"", "-6"}
	}
	return []string{""}
}

func ipArgs(family string, args ...string) []string {
	argv := []string{"ip"}
	if family != "" {
		argv = append(argv, family)
	}
	return append(argv, args...)
}

func pref(r policy.RoutingRoute) string {
	if r.Pref == 0 {
		return strconv.Itoa(defaultPref)
	}
	return strconv.Itoa(r.Pref)
}

// Commands renders ip argv slices for Apply.
func Commands(cfg policy.RoutingConfig) [][]string {
	if !cfg.Enabled {
		return nil
	}
	var cmds [][]string
	for _, r := range cfg.Routes {
		mark := fmt.Sprintf("0x%x", r.Mark)
		table := strconv.Itoa(r.Table)
		for _, family := range families(r.Gateway) {
			cmds = append(cmds, ipArgs(family, "rule", "del", "pref", pref(r)))
			cmds = append(cmds, ipArgs(family, "rule", "add", "pref", pref(r), "fwmark", mark, "table", table))
			rt := ipArgs(family, "route", "replace", "default", "via", r.Gateway, "table", table)
			if d := strings.TrimSpace(r.Dev); d != "" {
				rt = append(rt, "dev", d)
			}
			cmds = append(cmds, rt)
		}
	}
	return cmds
}

func ipBin() string {
	if p, err := exec.LookPath("ip"); err == nil {
		return p
	}
	return "/usr/sbin/ip"
}

func isRuleDel(argv []string) bool {
	for i := 1; i+1 < len(argv); i++ {
		if argv[i] == "rule" && argv[i+1] == "del" {
			return true
		}
	}
	return false
}

// Apply installs policy routing rules (idempotent per pref).
func Apply(cfg policy.RoutingConfig) error {
	if !cfg.Enabled {
		return nil
	}
	warnStrictRPFilter()
	for _, argv := range Commands(cfg) {
		if isRuleDel(argv) {
			// Several rules may share a pref; delete until none is left.
			for i := 0; i < 64; i++ {
				if exec.Command(ipBin(), argv[1:]...).Run() != nil {
					break
				}
			}
			continue
		}
		if out, err := exec.Command(ipBin(), argv[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("routing: %s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Teardown removes rules by pref from configuration.
func Teardown(cfg policy.RoutingConfig) {
	for _, argv := range Commands(cfg) {
		if isRuleDel(argv) {
			_ = exec.Command(ipBin(), argv[1:]...).Run()
		}
	}
}

func warnStrictRPFilter() {
	glob := filepath.Join("/proc/sys/net/ipv4/conf", "*", "rp_filter")
	matches, _ := filepath.Glob(glob)
	for _, p := range matches {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil && v == 1 {
			log.Printf("routing: warning: %s rp_filter=1 (strict); policy routing may behave unexpectedly", p)
		}
	}
}
