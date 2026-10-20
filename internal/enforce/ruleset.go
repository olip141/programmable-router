package enforce

import (
	"bytes"
	"fmt"
	"text/template"

	"edge-router/internal/policy"
)

const rulesetTmpl = `table inet {{.Table}} {
	map flows4 {
		type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service : mark
		flags timeout
		timeout {{.TimeoutSec}}s
	}
	map flows6 {
		type ipv6_addr . ipv6_addr . inet_proto . inet_service . inet_service : mark
		flags timeout
		timeout {{.TimeoutSec}}s
	}
	chain verdict {
		meta mark {{.DropMarkHex}} drop
		accept
	}
{{if .RestoreMark}}
	chain dpi_restore {
		type filter hook prerouting priority mangle; policy accept;
		ct mark != 0 meta mark set ct mark
	}
	chain dpi_reroute {
		type route hook output priority mangle; policy accept;
		ct mark != 0 meta mark set ct mark
	}
{{end}}
{{range .Hooks}}
	chain dpi_{{.}} {
		type filter hook {{.}} priority mangle; policy accept;
		ct mark != 0 meta mark set ct mark goto verdict
		ct mark 0 meta nfproto ipv4 ct mark set ip saddr . ip daddr . meta l4proto . th sport . th dport map @flows4
		ct mark 0 meta nfproto ipv6 ct mark set ip6 saddr . ip6 daddr . meta l4proto . th sport . th dport map @flows6
		meta mark set ct mark
		goto verdict
	}
{{end}}
}
`

type rulesetData struct {
	Table       string
	Hooks       []string
	DropMarkHex string
	TimeoutSec  int
	RestoreMark bool
}

func renderRuleset(cfg policy.NFTConfig) (string, error) {
	tmpl, err := template.New("ruleset").Parse(rulesetTmpl)
	if err != nil {
		return "", err
	}
	data := rulesetData{
		Table:       cfg.Table,
		Hooks:       cfg.Hooks,
		DropMarkHex: fmt.Sprintf("0x%x", cfg.DropMarkParsed),
		TimeoutSec:  int(cfg.ElementTimeout.Seconds()),
		RestoreMark: cfg.RestoreMarkEnabled,
	}
	if data.TimeoutSec <= 0 {
		data.TimeoutSec = 300
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
