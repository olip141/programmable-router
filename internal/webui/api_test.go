package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edge-router/internal/capture"
	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/metrics"
	"edge-router/internal/netinfo"
	"edge-router/internal/policy"
	"edge-router/internal/webui"
)

type apiEnv struct {
	handler    http.Handler
	ctrl       *control.Controller
	table      *flow.Table
	configPath string
}

func newAPIEnv(t *testing.T, pprof bool) *apiEnv {
	t.Helper()
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	cfg, err := policy.LoadBytes([]byte(`
nftables:
  drop_mark: 0xdead
rules:
  - name: ssh-mark
    match: { master: SSH }
    action: mark
    mark: 0x20
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	m := metrics.New(1)
	table := flow.NewTable(eng, flow.Config{Metrics: m})
	configPath := filepath.Join(t.TempDir(), "policy.yaml")
	ctrl := control.New(eng, table, cfg, policy.NewMatcher(cfg), nil, configPath, true, m, "", 0)
	ctrl.SetNetworkDryRun(true)
	srv, err := webui.New(webui.Options{
		Addr:        "127.0.0.1:0",
		Controller:  ctrl,
		ConfigPath:  configPath,
		EnablePprof: pprof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &apiEnv{handler: srv.Handler(), ctrl: ctrl, table: table, configPath: configPath}
}

func (e *apiEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestAPIRulesUseLowercaseJSON(t *testing.T) {
	env := newAPIEnv(t, false)
	rec := env.do(t, http.MethodGet, "/api/rules", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	payload := decode[map[string]any](t, rec)
	rule := payload["rules"].([]any)[0].(map[string]any)
	if rule["name"] != "ssh-mark" || rule["action"] != "mark" || rule["mark"] != float64(0x20) {
		t.Fatalf("rule JSON does not match GUI field names: %v", rule)
	}
	if rule["match"].(map[string]any)["master"] != "SSH" {
		t.Fatalf("match JSON: %v", rule["match"])
	}
	nft := payload["nftables"].(map[string]any)
	if nft["drop_mark"] != float64(0xdead) || nft["table"] != "dpi" {
		t.Fatalf("nftables JSON: %v", nft)
	}
}

func TestAPIInterfaces(t *testing.T) {
	env := newAPIEnv(t, false)
	env.ctrl.SetHost(&netinfo.Host{Capture: "eth1", List: func() ([]netinfo.Interface, error) {
		ifs := []netinfo.Interface{
			{Name: "eth0", Up: true, OperState: "up", SpeedMbps: 1000, Addrs: []string{"203.0.113.10/24"}},
			{Name: "eth1", Up: true, OperState: "up", Addrs: []string{"192.168.1.1/24"}},
		}
		netinfo.Classify(ifs, []netinfo.Route{{Dev: "eth0", Gateway: "203.0.113.1"}})
		return ifs, nil
	}})
	rec := env.do(t, http.MethodGet, "/api/interfaces", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	payload := decode[map[string]any](t, rec)
	ifs := payload["interfaces"].([]any)
	wan := ifs[0].(map[string]any)
	if wan["name"] != "eth0" || wan["role"] != "wan" || wan["gateway"] != "203.0.113.1" || wan["speed_mbps"] != float64(1000) {
		t.Fatalf("wan JSON: %v", wan)
	}
	aliases := payload["aliases"].(map[string]any)
	if payload["capture"] != "eth1" || aliases["wan"] != "eth0" || aliases["lan"] != "eth1" {
		t.Fatalf("aliases JSON: %v", payload)
	}
	if qos, ok := payload["qos"].([]any); !ok || len(qos) != 0 {
		t.Fatalf("qos bindings must be an empty list without QoS: %v", payload["qos"])
	}
	if rec := env.do(t, http.MethodPost, "/api/interfaces", map[string]any{}); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", rec.Code)
	}
}

func TestAPIQoSAndRoutingLifecycle(t *testing.T) {
	env := newAPIEnv(t, false)
	stop := startCommandPump(env.ctrl)
	defer stop()

	if got := decode[policy.QoSConfig](t, env.do(t, http.MethodGet, "/api/qos", nil)); got.Enabled {
		t.Fatalf("initial qos: %+v", got)
	}

	qosBody := map[string]any{
		"enabled":    true,
		"interfaces": []map[string]any{{"name": "eth1", "rate": "100mbit"}},
		"classes":    []map[string]any{{"name": "ssh", "mark": 0x20, "rate": "5mbit"}},
	}
	rec := env.do(t, http.MethodPut, "/api/qos", qosBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("qos put: %d %s", rec.Code, rec.Body.String())
	}
	if got := decode[policy.QoSConfig](t, rec); !got.Enabled || got.Classes[0].Mark != 0x20 {
		t.Fatalf("qos put response: %+v", got)
	}

	rtBody := map[string]any{
		"enabled": true,
		"routes":  []map[string]any{{"name": "alt", "mark": 0x30, "table": 200, "gateway": "10.0.0.1"}},
	}
	rec = env.do(t, http.MethodPut, "/api/routing", rtBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("routing put: %d %s", rec.Code, rec.Body.String())
	}
	// Updating routing must keep the QoS set earlier.
	if got := decode[policy.QoSConfig](t, env.do(t, http.MethodGet, "/api/qos", nil)); !got.Enabled {
		t.Fatalf("qos lost after routing update: %+v", got)
	}
	if got := decode[policy.RoutingConfig](t, env.do(t, http.MethodGet, "/api/routing", nil)); got.Routes[0].Table != 200 {
		t.Fatalf("routing get: %+v", got)
	}

	rec = env.do(t, http.MethodPost, "/api/rules/save", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	saved, err := policy.LoadFile(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.QoS.Enabled || saved.QoS.Classes[0].Name != "ssh" || saved.Routing.Routes[0].Gateway != "10.0.0.1" || len(saved.Rules) != 1 {
		t.Fatalf("saved config: %+v", saved)
	}
}

func TestAPIQoSRejectsBadInput(t *testing.T) {
	env := newAPIEnv(t, false)
	stop := startCommandPump(env.ctrl)
	defer stop()

	bad := map[string]any{
		"enabled":    true,
		"interfaces": []map[string]any{{"name": "eth1", "rate": "lots"}},
	}
	if rec := env.do(t, http.MethodPut, "/api/qos", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid qos: %d %s", rec.Code, rec.Body.String())
	}
	badRt := map[string]any{"enabled": true, "routes": []map[string]any{{"name": "x", "mark": 1, "table": 999, "gateway": "10.0.0.1"}}}
	if rec := env.do(t, http.MethodPut, "/api/routing", badRt); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid routing: %d %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPut, "/api/qos", strings.NewReader(`{"enabled":false}`))
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type: %d", rec.Code)
	}
	if rec := env.do(t, http.MethodDelete, "/api/routing", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE routing: %d", rec.Code)
	}
	if rec := env.do(t, http.MethodGet, "/api/qos/stats", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("stats without iface: %d", rec.Code)
	}
	if rec := env.do(t, http.MethodGet, "/api/qos/stats?iface=no-such-if0", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("stats for missing iface: %d", rec.Code)
	}
	if got := decode[policy.QoSConfig](t, env.do(t, http.MethodGet, "/api/qos", nil)); got.Enabled {
		t.Fatal("rejected update was applied")
	}
}

func TestAPIMetricsEndpoint(t *testing.T) {
	env := newAPIEnv(t, false)
	replayInto(t, env, "dns.pcap")

	rec := env.do(t, http.MethodGet, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE router_packets_total counter") || strings.Contains(body, "router_packets_total 0\n") {
		t.Fatalf("metrics body:\n%s", body)
	}
	if rec := env.do(t, http.MethodPost, "/metrics", map[string]any{}); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics: %d", rec.Code)
	}
}

func TestMetricsRequireAuth(t *testing.T) {
	eng, srv, stop := testServer(t, true)
	defer stop()
	defer eng.Close()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics without credentials: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("admin", "secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics with credentials: %d", rec.Code)
	}
}

func TestPprofOnlyWhenEnabled(t *testing.T) {
	if rec := newAPIEnv(t, false).do(t, http.MethodGet, "/debug/pprof/", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("pprof disabled: %d", rec.Code)
	}
	rec := newAPIEnv(t, true).do(t, http.MethodGet, "/debug/pprof/", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "goroutine") {
		t.Fatalf("pprof enabled: %d", rec.Code)
	}
}

func TestAPIFlowsFilterByHost(t *testing.T) {
	env := newAPIEnv(t, false)
	replayInto(t, env, "tls-rdn-extract.pcap")

	all := decode[[]control.FlowView](t, env.do(t, http.MethodGet, "/api/flows", nil))
	host := ""
	for _, f := range all {
		if f.Host != "" {
			host = f.Host
			break
		}
	}
	if host == "" {
		t.Fatalf("no flow with host among %d flows", len(all))
	}
	got := decode[[]control.FlowView](t, env.do(t, http.MethodGet, "/api/flows?q="+strings.ToUpper(host), nil))
	if len(got) == 0 {
		t.Fatalf("host filter %q returned nothing", host)
	}
	for _, f := range got {
		if !strings.EqualFold(f.Host, host) && !strings.Contains(strings.ToLower(f.Key+f.Protocol), strings.ToLower(host)) {
			t.Errorf("flow %s does not match %q", f.Key, host)
		}
	}
	none := decode[[]control.FlowView](t, env.do(t, http.MethodGet, "/api/flows?q=zz-no-such-host-zz", nil))
	if len(none) != 0 {
		t.Fatalf("unexpected matches: %+v", none)
	}
	limited := decode[[]control.FlowView](t, env.do(t, http.MethodGet, "/api/flows?limit=1", nil))
	if len(all) > 1 && len(limited) != 1 {
		t.Fatalf("limit=1 returned %d flows", len(limited))
	}
}

// replayInto feeds a capture through the table and publishes a snapshot,
// standing in for the packet pipeline goroutine.
func replayInto(t *testing.T, env *apiEnv, file string) {
	t.Helper()
	src, err := capture.OpenFile(filepath.Join("..", "..", "testdata", file), "")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var last time.Time
	if err := src.Run(context.Background(), func(p *capture.Packet) {
		last = p.Timestamp
		env.table.Handle(p)
	}, nil); err != nil {
		t.Fatal(err)
	}
	env.ctrl.Tick(last, src.Stats())
}
