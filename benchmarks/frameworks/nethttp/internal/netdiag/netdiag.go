// Package netdiag runs network diagnostics for the support dashboard.
package netdiag

import (
	"os/exec"
)

func Ping(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput() // EVAL-SINK
}
