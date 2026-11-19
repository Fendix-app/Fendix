//go:build linux

package semgrep

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// OR-78: the shell in front of Semgrep is the system's /bin/sh (then
// /usr/bin/sh), never an sh a PATH names first.
func TestWse3OOMVictimShellIsTheSystemShellNotThePathOne(t *testing.T) {
	system := ""
	for _, c := range []string{"/bin/sh", "/usr/bin/sh"} {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			system = c
			break
		}
	}
	if system == "" {
		t.Skip("no system shell to prefer")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "sh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 97\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if got, _ := exec.LookPath("sh"); got != fake {
		t.Fatalf("the test's PATH does not put the fake sh first: %s", got)
	}
	if got := oomVictimShell(); got != system {
		t.Errorf("oomVictimShell() = %q, want the system shell %q even with a different sh first on PATH", got, system)
	}
	// And the rewritten command runs it.
	cmd := exec.Command("/bin/true")
	if _, err := os.Stat("/bin/true"); err != nil {
		cmd = exec.Command("/usr/bin/true")
	}
	preferAsOOMVictim(cmd)
	if cmd.Path != system {
		t.Errorf("the wrapped command runs %q, want %q", cmd.Path, system)
	}
}
