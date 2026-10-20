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
sudo router -i lan -f "not port 22" -c /etc/edge-router/router.yaml -v
```

### Interface names and aliases

`-i` and `qos.interfaces[].name` accept an interface name or an alias, so the same
policy file works in GNS3 (`ens3`, `ens4`) and on a Raspberry Pi (`eth0`, `end0`):

| Alias | Resolves to |
|---|---|
| `wan` | interface holding the default route (lowest IPv4 metric) |
| `lan` | the capture interface (`-i`) when it is not the WAN, else the only other up interface with a routable address |
| `auto` | like `lan`; on a single-interface host it falls back to `wan` |

Container bridges (`docker*`, `veth*`, `virbr*`, …) are never picked as LAN. When an
alias is ambiguous (e.g. two LAN ports) or a name does not exist, the router stops
with the list of available interfaces. Saving from the GUI keeps the alias in the file.
The detected interfaces, their roles and the QoS bindings are shown in the GUI tab
**QoS i routing** and served by `GET /api/interfaces`.

Interfaces are resolved at startup and on every QoS change from the GUI; an
interface that is recreated later (`ppp0`, `wg0`) needs **Zastosuj QoS** again.

## Admin GUI (L7 policy)

Enable the built-in web UI (static HTML/JS embedded in the binary):

```bash
# On the router LAN (password required when not on loopback):
echo 'your-password' | sudo tee /etc/edge-router/http-pass
sudo chmod 600 /etc/edge-router/http-pass
sudo router -i lan -f "not port 22" -c /etc/edge-router/router.yaml \
  -http 0.0.0.0:8080 -http-user admin -http-pass-file /etc/edge-router/http-pass
```

On the GCP dev VM (loopback only, password optional):

```bash
./bin/router -i auto -f "not port 22" -c deploy/router-gcp.yaml -http 127.0.0.1:8080
```

From your laptop, tunnel to the VM:

```bash
ssh -L 8080:127.0.0.1:8080 user@gcp-host
# open http://127.0.0.1:8080/
```

The GUI provides overview stats, active flows, and live editing of policy rules (`PUT /api/rules`) with optional save to the YAML file (`POST /api/rules/save`). New rules apply to flows classified after the change; existing conntrack marks persist until expiry.

On a host without forwarding (e.g. GCP), use `deploy/router-gcp.yaml` with hooks `[input, output]`.

## QoS and routing

When `-c router.yaml` is used, the router applies `qos:` and `routing:` sections from the YAML via `tc` and `ip` on startup. Edit them in the admin GUI tab **QoS i routing** or adjust `deploy/router.yaml`.

Manual alternative (same defaults as the example YAML):

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
