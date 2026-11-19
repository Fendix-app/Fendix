//go:build !linux

package semgrep

import "os/exec"

// preferAsOOMVictim is a no-op without /proc/<pid>/oom_score_adj; the hosted
// engine runs on Linux (oomvictim_linux.go).
func preferAsOOMVictim(cmd *exec.Cmd) {}
