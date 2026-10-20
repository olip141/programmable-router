# Benchmark and evaluation methodology

## Unit benchmarks (GCP dev VM)

```bash
./bench/run-benchmarks.sh
```

Results land in `bench/results/bench-*.txt` (ns/op, allocs, custom metrics).

## Classification accuracy vs nDPI corpus

```bash
./bench/eval-ndpi-pcaps.sh                      # reuses /tmp/nDPI (the libndpi build tree)
NDPI_SRC= NDPI_REF=dev ./bench/eval-ndpi-pcaps.sh  # or clone a fresh checkout
python3 bench/summarize.py bench/results/
```

The pcaps and `result/*.pcap.out` must come from the same nDPI revision as
the linked `libndpi.a`, otherwise label differences reflect version drift.

`evalpcap` writes per-flow CSV and prints one summary line:
`files` (captures read), `flows` (flows classified), `truth_flows` (flows in
ndpiReader results), `truth_compared` / `correct` / `accuracy` (flows found in
the results and how many got the same label), `not_in_truth`, `unknown`,
`gave_up`. Flows are matched by L4 protocol and endpoint pair regardless of
direction. Captures with link types other than Ethernet/Linux SLL are skipped
with a message on stderr.

## Live router metrics

```bash
./bin/router -i eth1 -c deploy/router.yaml -stats-file /tmp/router.ndjson -stats-interval 1s -http 127.0.0.1:8080
curl -s http://127.0.0.1:8080/metrics
```

## GNS3 / hardware (manual)

1. Copy `bin/router` to the router VM.
2. On router: run with `-stats-file` and collect `bench/gns3/router-monitor.sh <pid>`.
3. On client: `bench/gns3/client-iperf.sh <router-ip>` for throughput/RTT scenarios.
4. Optional line-rate stress: `bench/gns3/replay.sh eth1 testdata/ssh.pcap` until `KernelDropped` rises in GUI/API status.

Compare scenarios: baseline forwarding, `-no-dpi`, full DPI, DPI+nftables, DPI+nftables+QoS from YAML.
