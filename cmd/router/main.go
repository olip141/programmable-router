package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/enforce"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func main() {
	iface := flag.String("i", "", "live capture interface")
	pcapFile := flag.String("r", "", "offline pcap/pcapng file")
	bpf := flag.String("f", "", "BPF filter (live capture)")
	promisc := flag.Bool("promisc", false, "promiscuous mode")
	verbose := flag.Bool("v", false, "log new flows and classifications")
	configPath := flag.String("c", "", "policy YAML file (enables traffic control)")
	dryRun := flag.Bool("dry-run", false, "log policy actions without nftables")
	noNftSetup := flag.Bool("no-nft-setup", false, "do not install nftables ruleset (sets must already exist)")
	flag.Parse()

	if (*iface == "") == (*pcapFile == "") {
		fmt.Fprintln(os.Stderr, "specify exactly one of -i or -r")
		os.Exit(2)
	}

	eng, err := dpi.New()
	if err != nil {
		log.Fatalf("dpi: %v", err)
	}
	defer eng.Close()

	var polCfg *policy.Config
	var matcher *policy.Matcher
	if *configPath != "" {
		polCfg, err = policy.LoadFile(*configPath)
		if err != nil {
			log.Fatalf("policy: %v", err)
		}
		if err := polCfg.Validate(eng); err != nil {
			log.Fatalf("policy: %v", err)
		}
		matcher = policy.NewMatcher(polCfg)
	}

	var enf enforce.Enforcer
	if matcher != nil {
		useLog := *dryRun || *pcapFile != ""
		if useLog {
			enf = enforce.NewLogEnforcer()
		} else {
			nft, err := enforce.NewNFTEnforcer(polCfg.NFTables, !*noNftSetup)
			if err != nil {
				log.Fatalf("enforce: %v", err)
			}
			if err := nft.Setup(); err != nil {
				log.Fatalf("enforce setup: %v", err)
			}
			enf = nft
			defer func() { _ = enf.Close() }()
		}
	}

	summary := flow.Summary{}
	cfg := flow.Config{
		OnEnd: func(f *flow.Flow) {
			summary.Add(f)
			if enf != nil {
				_ = enf.Release(f)
			}
		},
	}
	if *verbose {
		cfg.OnNew = func(f *flow.Flow) {
			log.Printf("flow %s", f.Key.String())
		}
	}
	cfg.OnClassified = func(f *flow.Flow) {
		if *verbose {
			log.Printf("classified %s -> %s", f.Key.String(), f.Protocol)
		}
		if matcher != nil && enf != nil {
			if d, ok := matcher.Decide(f); ok {
				if *verbose {
					log.Printf("policy %q mark=0x%x %s", d.Rule, d.Mark, f.Key.String())
				}
				if err := enf.Apply(f, d); err != nil {
					log.Printf("enforce apply: %v", err)
				}
			}
		}
	}
	table := flow.NewTable(eng, cfg)

	var src *capture.Source
	if *pcapFile != "" {
		src, err = capture.OpenFile(*pcapFile, *bpf)
	} else {
		src, err = capture.OpenLive(*iface, *bpf, *promisc)
	}
	if err != nil {
		log.Fatalf("capture: %v", err)
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = src.Run(ctx, func(p *capture.Packet) {
		table.Expire(p.Timestamp)
		table.Handle(p)
	})
	if err != nil {
		log.Printf("capture stopped: %v", err)
	}

	active := table.Len()
	table.Close()
	printSummary(summary, active, table.Len(), matcher, enf)
}

func printSummary(summary flow.Summary, activeAtStop, remaining int, matcher *policy.Matcher, enf enforce.Enforcer) {
	fmt.Println("\nProtocol summary:")
	fmt.Printf("%-24s %8s %10s %12s\n", "Protocol", "Flows", "Packets", "Bytes")
	for _, s := range summary.Sorted() {
		fmt.Printf("%-24s %8d %10d %12d\n", s.Name, s.Flows, s.Packets, s.Bytes)
	}
	if matcher != nil {
		fmt.Println("\nPolicy rule hits:")
		hits := matcher.Hits()
		names := make([]string, 0, len(hits))
		for name := range hits {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("  %-20s %8d\n", name, hits[name])
		}
	}
	if enf != nil {
		st := enf.Stats()
		fmt.Printf("\nEnforcer: applied=%d released=%d skipped=%d errors=%d\n",
			st.Applied, st.Released, st.Skipped, st.Errors)
	}
	fmt.Printf("\nFlows active at stop: %d, after close: %d\n", activeAtStop, remaining)
}
