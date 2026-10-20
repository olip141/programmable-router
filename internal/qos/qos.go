package qos

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"edge-router/internal/policy"
)

// ClassStats is parsed tc class statistics for one classid.
type ClassStats struct {
	ClassID string
	Name    string
	Bytes   uint64
	Packets uint64
	Drops   uint64
}

// ClassID returns the HTB classid Commands assigns to cfg.Classes[i].
func ClassID(i int) string { return fmt.Sprintf("1:%d", 10+i) }

// DefaultClassID is the HTB class for unmarked traffic.
const DefaultClassID = "1:999"

// Commands renders tc argv slices for Apply (for tests and dry-run).
func Commands(cfg policy.QoSConfig) [][]string {
	if !cfg.Enabled {
		return nil
	}
	var cmds [][]string
	for _, ifc := range cfg.Interfaces {
		dev := ifc.Device()
		rate := ifc.Rate
		cmds = append(cmds, []string{"tc", "qdisc", "del", "dev", dev, "root"})
		cmds = append(cmds, []string{"tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "999"})
		cmds = append(cmds, []string{"tc", "class", "add", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", rate, "ceil", rate})
		cmds = append(cmds, []string{"tc", "class", "add", "dev", dev, "parent", "1:1", "classid", DefaultClassID, "htb", "rate", rate, "ceil", rate, "prio", "7"})
		cmds = append(cmds, []string{"tc", "qdisc", "add", "dev", dev, "parent", DefaultClassID, "handle", "999:", "fq_codel"})
		for i, cl := range cfg.Classes {
			cid := ClassID(i)
			h := fmt.Sprintf("%d:", 10+i)
			ceil := cl.Ceil
			if strings.TrimSpace(ceil) == "" {
				ceil = rate
			}
			prio := cl.Prio
			if prio == 0 {
				prio = 5
			}
			cmds = append(cmds, []string{"tc", "class", "add", "dev", dev, "parent", "1:1", "classid", cid, "htb", "rate", cl.Rate, "ceil", ceil, "prio", fmt.Sprintf("%d", prio)})
			cmds = append(cmds, []string{"tc", "qdisc", "add", "dev", dev, "parent", cid, "handle", h, "fq_codel"})
			cmds = append(cmds, []string{"tc", "filter", "add", "dev", dev, "parent", "1:", "protocol", "all", "handle", fmt.Sprintf("0x%x", cl.Mark), "fw", "classid", cid})
		}
	}
	return cmds
}

func tcBin() string {
	if p, err := exec.LookPath("tc"); err == nil {
		return p
	}
	return "/usr/sbin/tc"
}

// Apply runs tc commands for cfg.
func Apply(cfg policy.QoSConfig) error {
	for _, argv := range Commands(cfg) {
		out, err := exec.Command(tcBin(), argv[1:]...).CombinedOutput()
		if err != nil {
			// tc qdisc del fails when no root qdisc exists yet.
			if argv[1] == "qdisc" && argv[2] == "del" {
				continue
			}
			return fmt.Errorf("qos: %s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Teardown removes root qdisc from configured interfaces.
func Teardown(cfg policy.QoSConfig) {
	if !cfg.Enabled {
		return
	}
	for _, ifc := range cfg.Interfaces {
		_ = exec.Command(tcBin(), "qdisc", "del", "dev", ifc.Device(), "root").Run()
	}
}

// Stats reads per-class counters for iface. Names are filled from cfg.
// iproute2 has no JSON output for HTB classes, so the text form is parsed.
func Stats(iface string, cfg policy.QoSConfig) ([]ClassStats, error) {
	out, err := exec.Command(tcBin(), "-s", "class", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qos: tc -s class show dev %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}
	stats := ParseClassStats(string(out))
	names := map[string]string{DefaultClassID: "default"}
	for i, cl := range cfg.Classes {
		names[ClassID(i)] = cl.Name
	}
	for i := range stats {
		stats[i].Name = names[stats[i].ClassID]
	}
	return stats, nil
}

// ParseClassStats parses `tc -s class show` output:
//
//	class htb 1:10 parent 1:1 leaf 10: prio 5 rate 2Mbit ...
//	 Sent 1234 bytes 10 pkt (dropped 0, overlimits 0 requeues 0)
func ParseClassStats(text string) []ClassStats {
	var stats []ClassStats
	var cur *ClassStats
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) >= 3 && f[0] == "class":
			// Leaf fq_codel qdiscs list their flows as classes too; skip them.
			if f[1] != "htb" {
				cur = nil
				continue
			}
			stats = append(stats, ClassStats{ClassID: f[2]})
			cur = &stats[len(stats)-1]
		case cur != nil && len(f) >= 6 && f[0] == "Sent" && f[2] == "bytes" && f[4] == "pkt":
			cur.Bytes, _ = strconv.ParseUint(f[1], 10, 64)
			cur.Packets, _ = strconv.ParseUint(f[3], 10, 64)
			if len(f) >= 7 && f[5] == "(dropped" {
				cur.Drops, _ = strconv.ParseUint(strings.TrimSuffix(f[6], ","), 10, 64)
			}
		}
	}
	return stats
}
