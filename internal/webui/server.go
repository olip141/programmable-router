package webui

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"edge-router/internal/control"
	"edge-router/internal/metrics"
	"edge-router/internal/policy"
)

const maxBodyBytes = 1 << 20

// Server serves the admin GUI and JSON API.
type Server struct {
	ctrl       *control.Controller
	user       string
	pass       []byte
	configPath string
	http       *http.Server
}

// Options configures the web UI.
type Options struct {
	Addr        string
	User        string
	PassFile    string
	Controller  *control.Controller
	ConfigPath  string
	EnablePprof bool
}

// New validates options and builds a Server. PassFile must contain the password (trimmed).
func New(opts Options) (*Server, error) {
	if opts.Controller == nil {
		return nil, errors.New("webui: nil controller")
	}
	if opts.Addr == "" {
		return nil, errors.New("webui: empty listen address")
	}
	user := opts.User
	if user == "" {
		user = "admin"
	}
	pass, err := readPassFile(opts.PassFile)
	if err != nil {
		return nil, err
	}
	if !isLoopback(opts.Addr) && len(pass) == 0 {
		return nil, errors.New("webui: non-loopback listen address requires -http-pass-file")
	}
	s := &Server{
		ctrl:       opts.Controller,
		user:       user,
		pass:       pass,
		configPath: opts.ConfigPath,
	}
	mux := http.NewServeMux()
	webRoot, err := fs.Sub(staticFS, "web")
	if err != nil {
		return nil, err
	}
	mux.HandleFunc("/", s.handleIndex)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(webRoot))))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/save", s.handleRulesSave)
	mux.HandleFunc("/api/meta", s.handleMeta)
	mux.HandleFunc("/api/qos", s.handleQoS)
	mux.HandleFunc("/api/qos/stats", s.handleQoSStats)
	mux.HandleFunc("/api/routing", s.handleRouting)
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/metrics", s.handleMetrics)
	if opts.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprofIndex)
		mux.HandleFunc("/debug/pprof/cmdline", pprofCmdline)
		mux.HandleFunc("/debug/pprof/profile", pprofProfile)
		mux.HandleFunc("/debug/pprof/symbol", pprofSymbol)
		mux.HandleFunc("/debug/pprof/trace", pprofTrace)
	}

	s.http = &http.Server{
		Addr:              opts.Addr,
		Handler:           s.withAuth(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

func readPassFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("webui: pass file: %w", err)
	}
	p := strings.TrimSpace(string(data))
	if p == "" {
		return nil, errors.New("webui: pass file is empty")
	}
	return []byte(p), nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Handler exposes the HTTP handler (for tests).
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.pass) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), s.pass) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="edge-router"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireJSON(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "missing index", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := s.ctrl.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"at":              snap.At,
		"uptime_sec":      snap.Uptime.Seconds(),
		"packets_per_s":   snap.PacketsPerSec,
		"active_flows":    snap.ActiveFlows,
		"capture":         snap.Capture,
		"enforcer":        snap.Enforcer,
		"rule_hits":       snap.RuleHits,
		"policy_editable": snap.PolicyEditable,
		"config_path":     snap.ConfigPath,
		"policy_note":     "Nowe reguły obowiązują dla przepływów sklasyfikowanych po zmianie. Dotychczasowe znaczniki w conntracku pozostają do wygaśnięcia wpisu.",
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.ctrl.Snapshot().ProtocolSummary)
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := parsePositiveInt(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	flows := s.ctrl.Snapshot().Flows
	if q != "" {
		filtered := make([]control.FlowView, 0, len(flows))
		for _, f := range flows {
			if flowMatchesQuery(f, q) {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}
	if len(flows) > limit {
		flows = flows[:limit]
	}
	writeJSON(w, http.StatusOK, flows)
}

func flowMatchesQuery(f control.FlowView, q string) bool {
	fields := []string{f.Key, f.Client, f.Server, f.Protocol, f.Master, f.App, f.Category, f.Host, f.Confidence, f.PolicyRule}
	for _, r := range f.Risks {
		fields = append(fields, r)
	}
	for _, s := range fields {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.rulesPayload())
	case http.MethodPut:
		if !s.ctrl.Snapshot().PolicyEditable {
			http.Error(w, "policy read-only (no config file)", http.StatusForbidden)
			return
		}
		if !s.requireJSON(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var body struct {
			Rules []policy.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.ctrl.SetRules(body.Rules); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, s.rulesPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) rulesPayload() map[string]any {
	snap := s.ctrl.Snapshot()
	return map[string]any{
		"nftables": snap.NFTables,
		"rules":    snap.Rules,
	}
}

func (s *Server) handleRulesSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.ctrl.Snapshot().PolicyEditable {
		http.Error(w, "policy read-only", http.StatusForbidden)
		return
	}
	if !s.requireJSON(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	io.Copy(io.Discard, r.Body)
	if s.configPath == "" {
		http.Error(w, "no config path", http.StatusBadRequest)
		return
	}
	cfg := s.ctrl.ConfigForSave()
	if cfg == nil {
		http.Error(w, "no policy loaded", http.StatusBadRequest)
		return
	}
	if err := policy.SaveFile(s.configPath, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"saved": s.configPath})
}

func (s *Server) handleQoS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.ctrl.Snapshot().QoS)
	case http.MethodPut:
		if !s.ctrl.Snapshot().PolicyEditable {
			http.Error(w, "policy read-only", http.StatusForbidden)
			return
		}
		if !s.requireJSON(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var body policy.QoSConfig
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rt := s.ctrl.Snapshot().Routing
		if err := s.ctrl.SetNetwork(body, rt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, s.ctrl.Snapshot().QoS)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleQoSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	iface := strings.TrimSpace(r.URL.Query().Get("iface"))
	if iface == "" {
		http.Error(w, "iface query required", http.StatusBadRequest)
		return
	}
	stats, err := s.ctrl.QoSStats(iface)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleRouting(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.ctrl.Snapshot().Routing)
	case http.MethodPut:
		if !s.ctrl.Snapshot().PolicyEditable {
			http.Error(w, "policy read-only", http.StatusForbidden)
			return
		}
		if !s.requireJSON(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var body policy.RoutingConfig
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := s.ctrl.Snapshot().QoS
		if err := s.ctrl.SetNetwork(q, body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, s.ctrl.Snapshot().Routing)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	view, err := s.ctrl.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(metrics.PrometheusText(s.ctrl.Snapshot().Metrics)))
}

var (
	pprofIndex   = pprof.Index
	pprofCmdline = pprof.Cmdline
	pprofProfile = pprof.Profile
	pprofSymbol  = pprof.Symbol
	pprofTrace   = pprof.Trace
)

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := s.ctrl.Meta()
	writeJSON(w, http.StatusOK, m)
}

func parsePositiveInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
