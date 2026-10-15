package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireRootE2E(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

func TestQoSScriptDummy0(t *testing.T) {
	requireRootE2E(t)
	tcBin := "/usr/sbin/tc"
	if _, err := os.Stat(tcBin); err != nil {
		if p, err := exec.LookPath("tc"); err == nil {
			tcBin = p
		} else {
			t.Skip("tc not installed (iproute2)")
		}
	}
	script := filepath.Join("..", "..", "deploy", "qos.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skip("deploy/qos.sh missing")
	}
	_ = exec.Command("ip", "link", "del", "dummy0").Run()
	if out, err := exec.Command("ip", "link", "add", "dummy0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("ip link add: %v %s", err, out)
	}
	defer exec.Command("ip", "link", "del", "dummy0").Run()
	_ = exec.Command("ip", "link", "set", "dummy0", "up").Run()

	cmd := exec.Command("sh", script, "dummy0", "10mbit")
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/sbin:/usr/bin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("qos.sh: %v\n%s", err, out)
	}
	if out, err := exec.Command(tcBin, "-s", "class", "show", "dev", "dummy0").CombinedOutput(); err != nil {
		t.Fatalf("tc class show: %v", err)
	} else if len(out) == 0 {
		t.Fatal("no tc classes on dummy0")
	}
}
