package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"edge-router/internal/control"
	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
	"edge-router/internal/webui"
)

func TestUnauthorizedWithoutPassword(t *testing.T) {
	eng, srv, stop := testServer(t, true)
	defer stop()
	defer eng.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAPIRulesAndStatic(t *testing.T) {
	eng, srv, stop := testServer(t, false)
	defer stop()
	defer eng.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`id="panel-rules"`)) {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.Bytes()[:min(80, rec.Body.Len())])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules get: %d", rec.Code)
	}

	body, _ := json.Marshal(map[string]any{
		"rules": []policy.Rule{
			{Name: "x", Match: map[string]string{"master": "SSH"}, Action: "mark", Mark: 0x20},
		},
	})
	req = httptest.NewRequest(http.MethodPut, "/api/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules put: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/rules/save", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules save: %d %s", rec.Code, rec.Body.String())
	}
}

func testServer(t *testing.T, requireAuth bool) (*dpi.Engine, *webui.Server, func()) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
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
	m := policy.NewMatcher(cfg)
	table := flow.NewTable(eng, flow.Config{})
	ctrl := control.New(eng, table, cfg, m, nil, t.TempDir()+"/policy.yaml", true, nil, "", 0)
	stop := startCommandPump(ctrl)

	passFile := ""
	if requireAuth {
		passFile = filepath.Join(t.TempDir(), "pass")
		_ = os.WriteFile(passFile, []byte("secret\n"), 0600)
	}
	srv, err := webui.New(webui.Options{
		Addr:       "127.0.0.1:0",
		User:       "admin",
		PassFile:   passFile,
		Controller: ctrl,
		ConfigPath: filepath.Join(t.TempDir(), "policy.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng, srv, stop
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func startCommandPump(ctrl *control.Controller) func() {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				ctrl.TryProcessCommands()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	return func() { close(done) }
}
