package webui

import (
	"testing"

	"edge-router/internal/control"
)

func TestFlowMatchesQueryFields(t *testing.T) {
	f := control.FlowView{
		Key:        "TCP 10.0.0.1:1234 <-> 1.2.3.4:443",
		Protocol:   "TLS.YouTube",
		Category:   "Media",
		Host:       "www.youtube.com",
		Confidence: "DPI",
		Risks:      []string{"Unidirectional Traffic"},
		PolicyRule: "video-low-prio",
	}
	for _, q := range []string{"youtube.com", "media", "dpi", "unidirectional", "video-low", "1.2.3.4"} {
		if !flowMatchesQuery(f, q) {
			t.Errorf("query %q did not match", q)
		}
	}
	if flowMatchesQuery(f, "netflix") {
		t.Error("unrelated query matched")
	}
}
