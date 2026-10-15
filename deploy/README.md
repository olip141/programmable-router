# Deploying programmable-router on a Linux router

## Dependencies

- `libpcap0.8` (runtime)
- `nftables`, `conntrack`, `iproute2` (`tc`, `ip`)
- Binary built on the dev machine (static nDPI, dynamic libpcap only)

## Install binary

```bash
sudo install -m 755 bin/router /usr/local/bin/router
sudo install -m 644 deploy/router.yaml /etc/edge-router/router.yaml
```

Optional capabilities instead of full root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/router
```

## Enable forwarding (GNS3 router)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

## Policy + capture

```bash
sudo router -i eth1 -f "not port 22" -c /etc/edge-router/router.yaml -v
```

On a host without forwarding (e.g. GCP), use `deploy/router-gcp.yaml` with hooks `[input, output]`.

## QoS and routing (after policy marks are set)

```bash
sudo deploy/qos.sh eth1 100mbit
sudo deploy/policy-routing.sh 192.168.2.1 200
```

## systemd

Adjust interface and paths in `router.service`, then:

```bash
sudo cp deploy/router.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now router
```

## GNS3 functional test (outline)

1. Client -- router -- server topology, router runs `router` on LAN/WAN interfaces.
2. Generate traffic (`curl`, `iperf3`, `tcpreplay` pcaps from `testdata/`).
3. Verify `nft list set inet dpi flows4`, `tc -s class show`, and dropped/blocked flows for `drop` rules.
