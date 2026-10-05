package govulncheck

import (
	"context"
	"errors"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
)

// writeModule writes a one-package module that calls language.Parse from
// golang.org/x/text v0.3.0 (GO-2021-0113) and returns its directory.
func writeModule(t *testing.T, goDirective string, imports ...string) string {
	t.Helper()
	dir := t.TempDir()
	goMod := "module example.com/fixture\n\ngo " + goDirective + "\n\nrequire golang.org/x/text v0.3.0\n"
	goSum := "golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\n" +
		"golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n"
	var extra strings.Builder
	for _, imp := range imports {
		extra.WriteString("\t_ \"" + imp + "\"\n")
	}
	mainGo := "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n" + extra.String() +
		"\n\t\"golang.org/x/text/language\"\n)\n\n" +
		"func main() {\n\ttag, err := language.Parse(os.Args[1])\n\tfmt.Println(tag, err)\n}\n"
	for name, body := range map[string]string{"go.mod": goMod, "go.sum": goSum, "main.go": mainGo} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func requireGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command on PATH")
	}
}

// A Go module whose go command cannot run is a Go module that went unscanned.
// x/vuln reports it as "no go.mod file", which reads as not-applicable; Scan
// must instead fail with the go command's own reason, and never return the
// ErrNoGoMod sentinel the orchestrator turns into a not_applicable skip.
func TestScan_GoModWithoutGoCommand_FailsWithTheRealCause(t *testing.T) {
	dir := writeModule(t, "1.25")
	t.Setenv("PATH", t.TempDir())

	findings, err := Scan(context.Background(), dir)
	if err == nil {
		t.Fatalf("Scan succeeded with no go command; findings = %v", findings)
	}
	if errors.Is(err, ErrNoGoMod) {
		t.Fatalf("an unrunnable go command was reported as ErrNoGoMod: %v", err)
	}
	if !errors.Is(err, ErrGoCommand) {
		t.Errorf("error does not wrap ErrGoCommand: %v", err)
	}
	if strings.Contains(err.Error(), "no go.mod file") {
		t.Errorf("error repeats x/vuln's misleading wording: %v", err)
	}
	if !strings.Contains(err.Error(), "executable file not found") {
		t.Errorf("error does not name the missing go command: %v", err)
	}
	if kind := neterr.Classify(err); kind != neterr.KindOther {
		t.Errorf("a missing go command classified as %v, want an execution failure", kind)
	}
}

func TestScan_GoModWithModuleModeOff_FailsWithTheRealCause(t *testing.T) {
	requireGo(t)
	dir := writeModule(t, "1.25")
	t.Setenv("GO111MODULE", "off")

	_, err := Scan(context.Background(), dir)
	if err == nil || errors.Is(err, ErrNoGoMod) || !errors.Is(err, ErrGoCommand) {
		t.Fatalf("module mode off: err = %v, want ErrGoCommand and not ErrNoGoMod", err)
	}
	if strings.Contains(err.Error(), "no go.mod file") {
		t.Errorf("error repeats x/vuln's misleading wording: %v", err)
	}
}

// A module that declares a newer Go than the toolchain can load is a failure
// with the go command's reason — not a skip, and not a clean run with no
// findings.
func TestScan_ModuleNeedingANewerGo_IsAFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real x/vuln scan, which also queries vuln.go.dev metadata")
	}
	requireGo(t)
	dir := writeModule(t, "1.999")
	t.Setenv("GOTOOLCHAIN", "local") // never download a toolchain mid-test

	findings, err := Scan(context.Background(), dir)
	if err == nil {
		t.Fatalf("Scan succeeded on a module it cannot load; findings = %v", findings)
	}
	if errors.Is(err, ErrNoGoMod) {
		t.Fatalf("an unloadable module was reported as ErrNoGoMod: %v", err)
	}
	if !strings.Contains(err.Error(), "1.999") {
		t.Errorf("error does not carry the go command's reason: %v", err)
	}
}

// The release blocker: an engine built with an older Go than the toolchain
// on PATH could not type-check that toolchain's standard library (Go 1.27
// uses generic methods in math/rand/v2, reached from net/http) or a module
// declaring that Go version, so govulncheck failed on every real Go module.
// `go test` puts the toolchain that built this test first on PATH, so this
// loads a module declaring that exact version through the engine's own
// x/vuln and x/tools and requires the reachable advisory to be reported.
// CI runs it with the Go patch the release binaries are built with.
func TestScan_ModuleDeclaringTheRunningGoVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live vuln-DB call in -short mode")
	}
	requireGo(t)
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v", err)
	}
	goVersion := strings.Fields(strings.TrimSpace(string(out)))[0]
	if !version.IsValid(goVersion) {
		t.Skipf("toolchain %q is not a release; nothing to declare", goVersion)
	}
	dir := writeModule(t, strings.TrimPrefix(goVersion, "go"), "net/http", "crypto/tls", "log/slog")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOFLAGS", "-mod=readonly")

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		msg := err.Error()
		if kind := neterr.Classify(err); kind != neterr.KindOther ||
			strings.Contains(msg, "no such host") || strings.Contains(msg, "dial tcp") || strings.Contains(msg, "i/o timeout") {
			t.Skipf("network unavailable, skipping live vuln-DB test: %v", err)
		}
		t.Fatalf("Scan failed on a module declaring %s: %v", goVersion, err)
	}
	for _, f := range findings {
		if f.RuleID == "GO-2021-0113" {
			return
		}
	}
	t.Fatalf("no GO-2021-0113 finding for a reachable language.Parse call under %s; findings = %+v", goVersion, findings)
}
