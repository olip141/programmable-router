package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"edge-router/internal/capture"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
)

func main() {
	iface := flag.String("i", "", "live capture interface")
	pcapFile := flag.String("r", "", "offline pcap/pcapng file")
	bpf := flag.String("f", "", "BPF filter (live capture)")
	promisc := flag.Bool("promisc", false, "promiscuous mode")
	verbose := flag.Bool("v", false, "log new flows and classifications")
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

	summary := flow.Summary{}
	cfg := flow.Config{OnEnd: summary.Add}
	if *verbose {
		cfg.OnNew = func(f *flow.Flow) {
			log.Printf("flow %s", f.Key.String())
		}
		cfg.OnClassified = func(f *flow.Flow) {
			log.Printf("classified %s -> %s", f.Key.String(), f.Protocol)
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
	printSummary(summary, active, table.Len())
}

func printSummary(summary flow.Summary, activeAtStop, remaining int) {
	fmt.Println("\nProtocol summary:")
	fmt.Printf("%-24s %8s %10s %12s\n", "Protocol", "Flows", "Packets", "Bytes")
	for _, s := range summary.Sorted() {
		fmt.Printf("%-24s %8d %10d %12d\n", s.Name, s.Flows, s.Packets, s.Bytes)
	}
	fmt.Printf("\nFlows active at stop: %d, after close: %d\n", activeAtStop, remaining)
}
