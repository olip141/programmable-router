package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/enforce"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
	"edge-router/internal/webui"
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
	httpAddr := flag.String("http", "", "admin GUI listen address (e.g. 127.0.0.1:8080)")
	httpUser := flag.String("http-user", "admin", "admin GUI HTTP basic auth user")
	httpPassFile := flag.String("http-pass-file", "", "file containing admin GUI password")
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
	var ctrl *control.Controller

	cfg := flow.Config{
		OnEnd: func(f *flow.Flow) {
			summary.Add(f)
			if ctrl != nil {
				ctrl.OnFlowEnd(f)
			}
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
		m := matcher
		if ctrl != nil {
			m = ctrl.Matcher()
		}
		if m != nil && enf != nil {
			if d, ok := m.Decide(f); ok {
				f.PolicyRule = d.Rule
				f.PolicyMark = d.Mark
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

	policyEditable := *configPath != ""
	ctrl = control.New(eng, table, polCfg, matcher, enf, *configPath, policyEditable)

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

	var webSrv *webui.Server
	if *httpAddr != "" {
		webSrv, err = webui.New(webui.Options{
			Addr:         *httpAddr,
			User:         *httpUser,
			PassFile:     *httpPassFile,
			Controller:   ctrl,
			ConfigPath:   *configPath,
		})
		if err != nil {
			log.Fatalf("http: %v", err)
		}
		go func() {
			log.Printf("admin GUI listening on http://%s/", *httpAddr)
			if err := webSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("http: %v", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = webSrv.Shutdown(shutdownCtx)
		}()
	}

	var lastTick time.Time
	tick := func(now time.Time) {
		if !lastTick.IsZero() && now.Sub(lastTick) < time.Second {
			return
		}
		lastTick = now
		ctrl.Tick(now, src.Stats())
	}

	err = src.Run(ctx, func(p *capture.Packet) {
		ctrl.TryProcessCommands()
		tick(p.Timestamp)
		table.Handle(p)
	}, func(now time.Time) {
		ctrl.TryProcessCommands()
		tick(now)
	})
	if err != nil {
		log.Printf("capture stopped: %v", err)
	}

	active := table.Len()
	table.Close()
	printSummary(summary, active, table.Len(), ctrl.Matcher(), enf)
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
