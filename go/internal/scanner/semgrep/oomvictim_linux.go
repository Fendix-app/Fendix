//go:build linux

package semgrep

import (
	"os"
	"os/exec"
)

// oomVictimMargin is how far above the engine's own oom_score_adj every
// Semgrep process runs: half the badness scale (-1000..1000), so a Semgrep
// process outranks an engine holding up to half the machine's memory more than
// it does.
const oomVictimMargin = 500

// oomVictimScript runs in a shell that has exec'd, as the child, before
// Semgrep. It reads the score the child inherited from the engine, writes that
// plus oomVictimMargin (capped at 1000) to its own /proc/self/oom_score_adj and
// then replaces itself with the command ($@), so the score is in place before
// Semgrep executes its first instruction and every process Semgrep starts
// (semgrep-core among them) inherits it. Raising one's own score needs no
// privilege. A failure to read or write it is not an error: the command still
// runs, at the score it inherited.
//
// It is a shell and not a hook in the forked child: a hook runs in the engine's
// memory image, which a hardened parent may have made non-dumpable
// (PR_SET_DUMPABLE=0), and then /proc/self/oom_score_adj is not writable by
// its owner; exec resets the flag, so after the exec of the shell it is.
const oomVictimScript = `{ read a < /proc/self/oom_score_adj; } 2>/dev/null || a=0
a=$((a + 500))
[ "$a" -gt 1000 ] && a=1000
{ echo "$a" > /proc/self/oom_score_adj; } 2>/dev/null
exec "$@"`

// preferAsOOMVictim makes cmd start with an oom_score_adj of at least the
// engine's own plus oomVictimMargin, so that under memory pressure the kernel
// takes Semgrep before the engine: the engine records semgrep failed and writes
// the report, instead of dying without one (round 6, R6-P2). The engine's own
// score is never changed.
//
// The command is rewritten to run through `sh -c oomVictimScript sh <program>
// <args...>`; the process is the same pid throughout (the shell execs), so the
// kill of the tree, the waits and the exit status are Semgrep's own. A command
// that cannot start, or a host without a shell, is left as it is.
func preferAsOOMVictim(cmd *exec.Cmd) {
	if cmd == nil || cmd.Err != nil || cmd.Path == "" || len(cmd.Args) == 0 {
		return
	}
	// A program that is missing keeps its own start error (the caller reports
	// it as a failed start); the shell would turn it into an exit status.
	if info, err := os.Stat(cmd.Path); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return
	}
	sh := oomVictimShell()
	if sh == "" {
		return
	}
	args := make([]string, 0, len(cmd.Args)+4)
	args = append(args, sh, "-c", oomVictimScript, "sh", cmd.Path)
	args = append(args, cmd.Args[1:]...)
	cmd.Path = sh
	cmd.Args = args
}

// oomVictimShell is the shell the wrapper runs in: the system's /bin/sh, then
// /usr/bin/sh, and only then an sh found on PATH. The system shell comes first
// so that a PATH the scanned repository or the environment can influence never
// decides which program runs in front of Semgrep. "" when there is none.
func oomVictimShell() string {
	for _, c := range []string{"/bin/sh", "/usr/bin/sh"} {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return c
		}
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		return sh
	}
	return ""
}
