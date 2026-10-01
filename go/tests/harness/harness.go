// Package harness builds the fendix binary once per test run so that
// subprocess-based smoke and regression tests invoke the real CLI exactly
// as a user would. It is test-support code, not part of the shipped binary.
package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	once     sync.Once
	binPath  string
	buildErr error

	releaseOnce     sync.Once
	releaseBinPath  string
	releaseBuildErr error
)

// ReleaseVersion is the version Release stamps into its binary. It has a
// release's shape, which managed evidence requires, and no release uses it.
const ReleaseVersion = "v0.0.0-harness"

// Fendix returns the path to a freshly-built fendix binary, building it on
// first call and caching the result for the rest of the test run.
func Fendix(t testing.TB) string {
	t.Helper()
	once.Do(build)
	if buildErr != nil {
		t.Fatalf("building fendix test binary: %v", buildErr)
	}
	return binPath
}

// Release returns a fendix binary stamped with ReleaseVersion, built on
// first call and cached like Fendix. Managed evidence is refused from a
// "dev" build — the backend accepts allowlisted release builds only — so a
// subprocess test of managed mode needs a release-shaped version.
func Release(t testing.TB) string {
	t.Helper()
	releaseOnce.Do(func() {
		releaseBinPath, releaseBuildErr = buildBinary("-X main.Version=" + ReleaseVersion)
	})
	if releaseBuildErr != nil {
		t.Fatalf("building release-stamped fendix test binary: %v", releaseBuildErr)
	}
	return releaseBinPath
}

func build() {
	binPath, buildErr = buildBinary("")
}

func buildBinary(ldflags string) (string, error) {
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "fendix-test-bin-*")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	bin := filepath.Join(dir, "fendix")
	args := []string{"build", "-o", bin}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	cmd := exec.Command("go", append(args, "./cmd/fendix")...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./cmd/fendix: %w\n%s", err, out)
	}
	return bin, nil
}

// moduleRoot walks up from the working directory to the dir containing
// go.mod (the Go module root, i.e. <repo>/go).
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found walking up from working dir")
		}
		dir = parent
	}
}

// RepoRoot returns the repository root (the parent of the Go module dir),
// where engine-level artifacts like benchmarks/ and tests/fixtures/ live.
func RepoRoot(t testing.TB) string {
	t.Helper()
	mod, err := moduleRoot()
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}
	return filepath.Dir(mod)
}

// Run executes the fendix binary with args (60s timeout) and returns
// stdout, stderr, and the process exit code.
func Run(t testing.TB, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	return RunEnv(t, nil, args...)
}

// RunEnv is Run with extra environment entries ("KEY=value") appended to
// the inherited environment.
func RunEnv(t testing.TB, env []string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	return RunBin(t, Fendix(t), env, args...)
}

// RunBin is RunEnv against a specific binary, such as the one Release builds.
func RunBin(t testing.TB, bin string, env []string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("running fendix %v: %v", args, err)
		}
	}
	return out.String(), errb.String(), exit
}
