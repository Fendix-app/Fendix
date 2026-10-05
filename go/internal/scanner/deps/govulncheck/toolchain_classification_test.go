package govulncheck

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
)

// A Go module that needs a toolchain it does not have fails in one of two
// ways, and they must stay distinguishable. A download that could not reach
// the network is transient: it is retried once and reported as
// network_error. A toolchain that is unavailable, or a local go that is too
// old under GOTOOLCHAIN=local, is deterministic: execution_error, never
// retried. Both are failures; neither may become ErrNoGoMod (not_applicable).
//
// These run the real go command, offline, and classify its real stderr the
// way Scan does when x/vuln's package loading fails.
func TestToolchainFailures_KeepNetworkAndLocalCausesApart(t *testing.T) {
	requireGo(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module example.com/needsnewer\n\ngo 1.999\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A proxy address that refuses connections: a port that was just free.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := "http://" + l.Addr().String()
	l.Close()

	cases := []struct {
		name, toolchain, proxy string
		want                   neterr.Kind
	}{
		{"toolchain download cannot reach the proxy", "auto", unreachable, neterr.KindNetwork},
		{"toolchain not available (downloads disabled)", "auto", "off", neterr.KindOther},
		{"local go too old under GOTOOLCHAIN=local", "local", unreachable, neterr.KindOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("go", "list", "./...")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOTOOLCHAIN="+tc.toolchain, "GOPROXY="+tc.proxy, "GOFLAGS=")
			out, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatalf("go list succeeded on a module declaring go 1.999: %s", out)
			}
			err := classifyRunErr(runErr, string(out))
			if errors.Is(err, ErrNoGoMod) {
				t.Fatalf("classified as not-a-Go-module: %v", err)
			}
			if got := neterr.Classify(err); got != tc.want {
				t.Errorf("kind = %v, want %v\nstderr: %s", got, tc.want, out)
			}
		})
	}
}

// The failure that blocked v3.5.0 came from an engine built with an older Go
// than the one on PATH. That is a local incompatibility, not a network one,
// even though x/vuln's wording mentions "loading".
func TestBuildToolchainMismatch_IsAnExecutionFailure(t *testing.T) {
	stderr := "govulncheck: loading packages: There are errors with the provided package patterns:\n" +
		"/usr/local/go/src/math/rand/v2/rand.go:1:1: file requires newer Go version go1.27 (application built with go1.25)\n" +
		"Loading packages failed, possibly due to a mismatch between the Go version used to build govulncheck and the Go version on PATH."
	err := classifyRunErr(errors.New("exit status 1"), stderr)
	if got := neterr.Classify(err); got != neterr.KindOther {
		t.Errorf("kind = %v, want an execution failure", got)
	}
}
