package engine

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireSemgrepEnv is the variable CI's semgrep-enabled job sets (see the e2e
// job in .github/workflows/ci.yml). The semgrep package's tests read it the
// same way (rule_behaviour_test.go).
const requireSemgrepEnv = "FENDIX_REQUIRE_SEMGREP"

// skipOrFail is the part of *testing.T the helpers below use, so a test can
// give them a recorder.
type skipOrFail interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// requireSemgrep returns when semgrep is on PATH. When it is not, the test is
// skipped, or fails when FENDIX_REQUIRE_SEMGREP is set, so a job that is meant
// to run the semgrep-dependent tests cannot pass by skipping them.
func requireSemgrep(t skipOrFail) {
	t.Helper()
	_, err := exec.LookPath("semgrep")
	if err == nil {
		return
	}
	skipUnlessRequired(t, "semgrep not on PATH: %v", err)
}

// skipUnlessRequired skips the test with the message, or fails it when
// FENDIX_REQUIRE_SEMGREP is set: for a scan whose analyzers did not run in an
// environment that promised them.
func skipUnlessRequired(t skipOrFail, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireSemgrepEnv) != "" {
		t.Fatalf("%s is set but %s", requireSemgrepEnv, fmt.Sprintf(format, args...))
		return
	}
	t.Skipf(format, args...)
}

type recorder struct{ skipped, failed string }

func (*recorder) Helper() {}
func (r *recorder) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
}

func TestSkipUnlessRequired_SkipsByDefault(t *testing.T) {
	t.Setenv(requireSemgrepEnv, "")
	var r recorder
	skipUnlessRequired(&r, "semgrep did not run: %s", "x")
	if r.skipped != "semgrep did not run: x" || r.failed != "" {
		t.Fatalf("skipped=%q failed=%q; want a skip", r.skipped, r.failed)
	}
}

func TestSkipUnlessRequired_FailsWhenSemgrepIsRequired(t *testing.T) {
	t.Setenv(requireSemgrepEnv, "1")
	var r recorder
	skipUnlessRequired(&r, "semgrep did not run: %s", "x")
	if r.skipped != "" || !strings.Contains(r.failed, "FENDIX_REQUIRE_SEMGREP is set") || !strings.Contains(r.failed, "semgrep did not run: x") {
		t.Fatalf("skipped=%q failed=%q; want a failure naming the variable", r.skipped, r.failed)
	}
}

func TestRequireSemgrep_FailsWhenRequiredAndMissing(t *testing.T) {
	t.Setenv(requireSemgrepEnv, "1")
	t.Setenv("PATH", t.TempDir()) // no semgrep here
	var r recorder
	requireSemgrep(&r)
	if r.skipped != "" || r.failed == "" {
		t.Fatalf("skipped=%q failed=%q; want a failure when semgrep is required and absent", r.skipped, r.failed)
	}
}

func TestRequireSemgrep_SkipsWhenMissingAndNotRequired(t *testing.T) {
	t.Setenv(requireSemgrepEnv, "")
	t.Setenv("PATH", t.TempDir())
	var r recorder
	requireSemgrep(&r)
	if r.skipped == "" || r.failed != "" {
		t.Fatalf("skipped=%q failed=%q; want a skip", r.skipped, r.failed)
	}
}
