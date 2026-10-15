package enforce

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"

	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

const nftBin = "/usr/sbin/nft"

// NFTEnforcer installs nftables rules and adds timed set elements via netlink.
type NFTEnforcer struct {
	cfg      policy.NFTConfig
	conn     *nftables.Conn
	table    *nftables.Table
	set4     *nftables.Set
	set6     *nftables.Set
	tracked  map[flow.Key]trackedElem
	stats    Stats
	setup    bool
}

type trackedElem struct {
	key     []byte
	reverse []byte
	ipv6    bool
}

// NewNFTEnforcer creates an enforcer. When doSetup is true, Setup must be called once.
func NewNFTEnforcer(cfg policy.NFTConfig, doSetup bool) (*NFTEnforcer, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("enforce: nftables conn: %w", err)
	}
	e := &NFTEnforcer{
		cfg:     cfg,
		conn:    conn,
		table:   &nftables.Table{Family: nftables.TableFamilyINet, Name: cfg.Table},
		tracked: make(map[flow.Key]trackedElem),
		setup:   doSetup,
	}
	if !doSetup {
		if err := e.loadSets(); err != nil {
			conn.CloseLasting()
			return nil, err
		}
	}
	return e, nil
}

// Setup loads the ruleset template when configured, then resolves set handles.
func (e *NFTEnforcer) Setup() error {
	if e.setup {
		_ = exec.Command(nftBin, "delete", "table", "inet", e.cfg.Table).Run()
		rules, err := renderRuleset(e.cfg)
		if err != nil {
			return err
		}
		cmd := exec.Command(nftBin, "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("enforce: nft -f: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return e.loadSets()
}

func (e *NFTEnforcer) loadSets() error {
	sets, err := e.conn.GetSets(e.table)
	if err != nil {
		return fmt.Errorf("enforce: get sets: %w", err)
	}
	for _, s := range sets {
		switch s.Name {
		case "flows4":
			e.set4 = s
		case "flows6":
			e.set6 = s
		}
	}
	if e.set4 == nil || e.set6 == nil {
		return fmt.Errorf("enforce: flows4/flows6 maps not found in table %q", e.cfg.Table)
	}
	return nil
}

func (e *NFTEnforcer) Apply(f *flow.Flow, d policy.Decision) error {
	key, ipv6, ok := flowElementKey(f)
	if !ok {
		e.stats.Skipped++
		return nil
	}
	set := e.set4
	if ipv6 {
		set = e.set6
	}
	// nftables "mark" data is host-endian (see datatype.h BYTEORDER_HOST_ENDIAN).
	val := binaryutil.NativeEndian.PutUint32(d.Mark)
	elem := nftables.SetElement{
		Key:     key,
		Val:     val,
		Timeout: e.cfg.ElementTimeout,
	}
	elems := []nftables.SetElement{elem}
	var rev []byte
	if r, ok := reverseFlowKey(f); ok {
		rev = r
		elems = append(elems, nftables.SetElement{Key: rev, Val: val, Timeout: e.cfg.ElementTimeout})
	}
	if err := e.conn.SetAddElements(set, elems); err != nil {
		e.stats.Errors++
		log.Printf("enforce: SetAddElements: %v", err)
		return err
	}
	if err := e.conn.Flush(); err != nil {
		e.stats.Errors++
		log.Printf("enforce: Flush after add: %v", err)
		return err
	}
	e.tracked[f.Key] = trackedElem{key: key, reverse: rev, ipv6: ipv6}
	e.stats.Applied++
	return nil
}

func (e *NFTEnforcer) Release(f *flow.Flow) error {
	te, ok := e.tracked[f.Key]
	if !ok {
		return nil
	}
	delete(e.tracked, f.Key)
	set := e.set4
	if te.ipv6 {
		set = e.set6
	}
	toDel := []nftables.SetElement{{Key: te.key}}
	if len(te.reverse) > 0 {
		toDel = append(toDel, nftables.SetElement{Key: te.reverse})
	}
	if err := e.conn.SetDeleteElements(set, toDel); err != nil {
		e.stats.Errors++
		log.Printf("enforce: SetDeleteElements: %v", err)
		return err
	}
	if err := e.conn.Flush(); err != nil {
		// Element may already have timed out; count but do not fail the pipeline hard.
		e.stats.Errors++
		log.Printf("enforce: Flush after delete: %v", err)
		return err
	}
	e.stats.Released++
	return nil
}

func (e *NFTEnforcer) Close() error {
	e.conn.CloseLasting()
	return nil
}

func (e *NFTEnforcer) Stats() Stats { return e.stats }
