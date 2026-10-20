package policy_test

import (
	"testing"

	"edge-router/internal/dpi"
	"edge-router/internal/flow"
	"edge-router/internal/policy"
)

func matcherFor(t *testing.T, match map[string]string) *policy.Matcher {
	t.Helper()
	cfg, err := policy.LoadBytes([]byte("rules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = cfg.WithRules([]policy.Rule{{Name: "r", Match: match, Action: "mark", Mark: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return policy.NewMatcher(cfg)
}

func TestHostMatchPatterns(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"www.google.com", "www.google.com", true},
		{"WWW.Google.com", "www.google.COM", true},
		{"www.google.com", "mail.google.com", false},
		{"*.google.com", "www.google.com", true},
		{"*.google.com", "a.b.google.com", true},
		{"*.google.com", "google.com", true},
		{"*.google.com", "notgoogle.com", false},
		{"*.google.com", "google.com.evil.net", false},
		{"*google*", "www.google.com", true},
		{"*.google.com", "", false},
		{"[", "[", true},
		{"[*", "[x", false},
	}
	for _, tc := range cases {
		m := matcherFor(t, map[string]string{"host": tc.pattern})
		_, got := m.Decide(&flow.Flow{Meta: dpi.Metadata{Host: tc.host}})
		if got != tc.want {
			t.Errorf("host %q vs pattern %q: got %v, want %v", tc.host, tc.pattern, got, tc.want)
		}
	}
}

func TestRiskAndConfidenceMatch(t *testing.T) {
	m := matcherFor(t, map[string]string{"risk": "Known Proto on Non Std Port"})
	if _, ok := m.Decide(&flow.Flow{Meta: dpi.Metadata{Risks: []string{"Unidirectional Traffic", "known proto on non std port"}}}); !ok {
		t.Error("risk present (case-insensitive) did not match")
	}
	if _, ok := m.Decide(&flow.Flow{Meta: dpi.Metadata{Risks: []string{"Unidirectional Traffic"}}}); ok {
		t.Error("absent risk matched")
	}

	m = matcherFor(t, map[string]string{"confidence": "DPI"})
	if _, ok := m.Decide(&flow.Flow{Meta: dpi.Metadata{Confidence: "dpi"}}); !ok {
		t.Error("confidence did not match")
	}
	if _, ok := m.Decide(&flow.Flow{Meta: dpi.Metadata{Confidence: "Match by port"}}); ok {
		t.Error("different confidence matched")
	}
}

func TestMatchFieldsAreANDed(t *testing.T) {
	m := matcherFor(t, map[string]string{"master": "TLS", "host": "*.example.com"})
	if _, ok := m.Decide(&flow.Flow{Master: "TLS", Meta: dpi.Metadata{Host: "www.example.com"}}); !ok {
		t.Error("both fields set: no match")
	}
	if _, ok := m.Decide(&flow.Flow{Master: "TLS", Meta: dpi.Metadata{Host: "www.other.com"}}); ok {
		t.Error("host mismatch still matched")
	}
	if _, ok := m.Decide(&flow.Flow{Master: "QUIC", Meta: dpi.Metadata{Host: "www.example.com"}}); ok {
		t.Error("master mismatch still matched")
	}
}

func TestValidateRiskConfidenceCategory(t *testing.T) {
	eng, err := dpi.New()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	cfg, err := policy.LoadBytes([]byte(`
rules:
  - name: risky
    match: { risk: "unidirectional traffic", confidence: "dpi", category: "media" }
    action: drop
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(eng); err != nil {
		t.Fatal(err)
	}
	got := cfg.Rules[0].Match
	if got["risk"] != "Unidirectional Traffic" || got["confidence"] != "DPI" || got["category"] != "Media" {
		t.Fatalf("not canonicalised: %v", got)
	}

	for field, value := range map[string]string{
		"risk":       "No Such Risk",
		"confidence": "certain",
		"category":   "NoSuchCategory",
		"protocol":   "NoSuchProto",
		"app":        "NoSuchApp",
		"host":       "  ",
	} {
		cfg, err := policy.LoadBytes([]byte("rules: []\n"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err = cfg.WithRules([]policy.Rule{{Name: "bad", Match: map[string]string{field: value}, Action: "drop"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(eng); err == nil {
			t.Errorf("%s=%q: expected validation error", field, value)
		}
	}
}

func TestNormalizeRejectsUnknownMatchField(t *testing.T) {
	_, err := policy.LoadBytes([]byte(`
rules:
  - name: x
    match: { port: "443" }
    action: drop
`))
	if err == nil {
		t.Fatal("expected unknown match field error")
	}
}
