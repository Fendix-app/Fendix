// Package govulncheck runs the upstream govulncheck logic in-process and
// emits fendix Findings for Go-module CVEs that the user's code actually
// calls.
//
// Behavioural parity with python/analyzers/deps.py::_check_go_modules:
//   - One Finding per OSV ID that has at least one call-trace frame with
//     a non-empty function — i.e. the user's code actually reaches the
//     vulnerable symbol. Vendored-but-uncalled vulns are dropped (that's
//     the value-add of govulncheck over a plain `go list -m -u` check).
//   - Title format: "Vulnerable Go module: <summary> (<osv-id>)".
//   - Fix line picks the first `affected[].ranges[].events[].fixed` entry
//     per OSV schema (https://ossf.github.io/osv-schema/).
//   - References include the OSV ID followed by every alias.
//
// This package replaces the deps.py subprocess-shells-out-to-govulncheck
// path for Go modules; the Python deps path stays in place for Python
// (pip-audit) and Node (npm-audit) until TASK-119's remaining sub-
// deliverables ship.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/vuln/scan"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
)

// ErrNoGoMod is returned by Scan when the given path doesn't contain a
// go.mod at its root. Callers use this to decide whether to skip silently
// (the package isn't a Go module) versus surface an error.
var ErrNoGoMod = errors.New("govulncheck: no go.mod at path root")

// ErrGoCommand is wrapped by Scan when the path DOES contain a go.mod but
// the go command cannot resolve it: no `go` on PATH, a failed toolchain
// switch, module mode turned off. The target is a Go module that went
// unscanned, so this is a failure and never ErrNoGoMod. x/vuln reports every
// one of these as "no go.mod file" and discards the go command's own
// diagnosis, which is why Scan asks the go command itself first.
var ErrGoCommand = errors.New("govulncheck: go command cannot resolve the module")

// Scan runs govulncheck against the Go module rooted at modulePath and
// returns one Finding per OSV-with-call-trace.
//
// The vuln DB defaults to https://vuln.go.dev — same default as the
// upstream binary. Network unreachable: returns the underlying error so
// the orchestrator can log + skip. Context cancellation propagates.
//
// Returns ErrNoGoMod when modulePath has no go.mod — callers should
// check errors.Is(err, ErrNoGoMod) and treat it as "not a Go module,
// nothing to do" rather than a real failure. Every other error, ErrGoCommand
// included, means a Go module went unscanned and is a failure.
func Scan(ctx context.Context, modulePath string) ([]evidence.Evidence, error) {
	abs, err := filepath.Abs(modulePath)
	if err != nil {
		return nil, fmt.Errorf("govulncheck: resolve path: %w", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoGoMod
		}
		return nil, fmt.Errorf("govulncheck: stat go.mod: %w", err)
	}
	if err := resolveGoMod(ctx, abs); err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, "-json", "-C", abs, "./...")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("govulncheck: start: %w", err)
	}
	runErr := cmd.Wait()
	// Upstream govulncheck exits 0 (no vulns) or 3 (vulns found in called
	// code); both are clean parses for us. Other exit codes mean the tool
	// itself failed — surface stderr so users know what to fix.
	if runErr != nil && !isFoundVulnsExit(runErr) {
		return nil, classifyRunErr(runErr, stderr.String())
	}

	return parseFindings(stdout.Bytes(), filepath.Base(abs))
}

// resolveGoMod runs the probe x/vuln runs before loading packages — `go env
// GOMOD` in the module directory, with the same inherited environment — and
// returns the go command's own reason when it fails. x/vuln collapses every
// failure of that probe into "no go.mod file", which misreports a Go module
// the scan could not load as a directory that is not a Go module at all.
//
// The go command's stderr is typed like govulncheck's (a toolchain download
// that could not reach the network is a network failure); everything else
// stays an execution failure. dir is known to contain go.mod.
func resolveGoMod(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, "go", "env", "GOMOD")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: go env GOMOD: %w", ErrGoCommand, ctxErr)
		}
		excerpt := firstLines(stderr.String(), 3)
		switch neterr.ClassifyText(stderr.String()) {
		case neterr.KindNetwork:
			return fmt.Errorf("%w: %w: go env GOMOD: %v (stderr: %s)", ErrGoCommand, neterr.ErrSubprocessNetwork, err, excerpt)
		case neterr.KindTimeout:
			return fmt.Errorf("%w: %w: go env GOMOD: %v (stderr: %s)", ErrGoCommand, neterr.ErrSubprocessTimeout, err, excerpt)
		}
		if excerpt != "" {
			return fmt.Errorf("%w: go env GOMOD: %v (stderr: %s)", ErrGoCommand, err, excerpt)
		}
		return fmt.Errorf("%w: go env GOMOD: %v", ErrGoCommand, err)
	}
	// Module mode off reports "" and a directory outside any module reports
	// os.DevNull; either way the go command will not load this go.mod.
	if gomod := strings.TrimSpace(string(out)); gomod == "" || gomod == os.DevNull {
		return fmt.Errorf("%w: go env GOMOD reported %q although go.mod exists (module mode disabled?)", ErrGoCommand, gomod)
	}
	return nil
}

// classifyRunErr wraps a govulncheck failure with a transport sentinel when
// its stderr shows the vulnerability database was unreachable, so the
// orchestrator can type it without reading prose. x/vuln/scan's library
// errors are untyped, so stderr text is the only signal available here —
// classified against a fixed list of Go's own net error wordings
// (neterr.ClassifyText), never surfaced past this package.
func classifyRunErr(runErr error, stderr string) error {
	excerpt := firstLines(stderr, 3)
	switch neterr.ClassifyText(stderr) {
	case neterr.KindNetwork:
		return fmt.Errorf("govulncheck: %w: %v (stderr: %s)", neterr.ErrSubprocessNetwork, runErr, excerpt)
	case neterr.KindTimeout:
		return fmt.Errorf("govulncheck: %w: %v (stderr: %s)", neterr.ErrSubprocessTimeout, runErr, excerpt)
	}
	return fmt.Errorf("govulncheck: %w (stderr: %s)", runErr, excerpt)
}

// isFoundVulnsExit returns true when govulncheck exited with the
// documented "vulnerabilities found in called code" status (3). The
// x/vuln/scan package wraps this in a plain error whose message contains
// the exit code; the lib doesn't expose a sentinel.
func isFoundVulnsExit(err error) bool {
	if err == nil {
		return false
	}
	// x/vuln/scan returns errors.New("vulnerabilities found") (or similar
	// wording) when exit=3. Be loose in matching to survive minor wording
	// changes across x/vuln releases.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "vulnerabilities found") ||
		strings.Contains(msg, "vulnerability found")
}

// vulnMessage models the relevant subset of govulncheck's NDJSON output.
// We only care about two message types:
//   - osv: vulnerability record (one per CVE/OSV id)
//   - finding: ties an OSV id to a specific call trace. A finding counts
//     as "reachable" when any trace frame has a non-empty Function name.
type vulnMessage struct {
	OSV     *osvRecord   `json:"osv,omitempty"`
	Finding *vulnFinding `json:"finding,omitempty"`
}

type osvRecord struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Aliases  []string      `json:"aliases"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	// Type is the OSV range type: "ECOSYSTEM", "SEMVER" or "GIT".
	// vuln.go.dev emits SEMVER in practice, so the practical impact here
	// is nil — the field is decoded for the same reason the pip and npm
	// scanners decode it (FIX-06): a GIT range's `fixed` event carries a
	// commit SHA, and one leaking into "Upgrade to <sha> or later" would
	// be a lie. Empty is treated as ECOSYSTEM-equivalent.
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

type vulnFinding struct {
	OSV   string       `json:"osv"`
	Trace []traceFrame `json:"trace"`
}

type traceFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// parseFindings consumes govulncheck's NDJSON stdout and returns one
// Finding per OSV id whose `findings` carry at least one trace frame
// with a non-empty `function`.
//
// govulncheck's NDJSON is genuinely line-delimited in -json mode (the
// pretty-printed multi-line form is only emitted in text mode), so a
// straight Scanner suffices.
func parseFindings(stdout []byte, modName string) ([]evidence.Evidence, error) {
	osvs := map[string]*osvRecord{}
	calledIDs := map[string]bool{}

	// json.Decoder handles whitespace between objects cleanly — works
	// whether the stream is strict NDJSON or pretty-printed-with-newlines.
	dec := json.NewDecoder(bytes.NewReader(stdout))
	for {
		var msg vulnMessage
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// One malformed object shouldn't tank the rest. Skip to next
			// top-level JSON value.
			if !skipToNextObject(dec) {
				break
			}
			continue
		}
		switch {
		case msg.OSV != nil && msg.OSV.ID != "":
			osvs[msg.OSV.ID] = msg.OSV
		case msg.Finding != nil && msg.Finding.OSV != "":
			for _, t := range msg.Finding.Trace {
				if t.Function != "" {
					calledIDs[msg.Finding.OSV] = true
					break
				}
			}
		}
	}

	ids := make([]string, 0, len(calledIDs))
	for id := range calledIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic output

	findings := make([]evidence.Evidence, 0, len(ids))
	for _, id := range ids {
		osv := osvs[id]
		if osv == nil {
			osv = &osvRecord{ID: id}
		}
		findings = append(findings, buildFinding(osv, modName))
	}
	return findings, nil
}

// buildFinding constructs the Finding for one OSV record. Matches the
// Python deps.py output shape so existing dedup logic collapses overlap
// during the transition window before TASK-118 drops the Python deps
// path entirely.
func buildFinding(osv *osvRecord, modName string) evidence.Evidence {
	summary := osv.Summary
	if summary == "" {
		summary = osv.ID
	}
	details := osv.Details
	if len(details) > 200 {
		details = details[:200]
	}

	fix := firstFixVersion(osv)
	fixMsg := "Upgrade to a patched version (no fix listed)."
	if fix != "" {
		fixMsg = fmt.Sprintf("Upgrade to %s or later.", fix)
	}

	refs := append([]string{osv.ID}, osv.Aliases...)

	// Mirror the Python finding shape exactly so dedup catches the
	// overlap during the transition window.
	idSlug := strings.ReplaceAll(osv.ID, "-", "_")
	line := modName
	return evidence.Evidence{
		ID:         "SEC-DEPS-GO-" + idSlug,
		RuleID:     osv.ID, // v0.22 native provenance (OSV/CVE id)
		Title:      fmt.Sprintf("Vulnerable Go module: %s (%s)", summary, osv.ID),
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "deps",
		Endpoint:   modName,
		Evidence:   fmt.Sprintf("%s: %s", osv.ID, details),
		Fix:        fixMsg,
		References: refs,
		Confidence: models.ConfidenceHigh,
		Line:       &line,
		// The v2 fingerprint keys this finding on advisory + ecosystem +
		// package. The Go module IS the package here, and govulncheck reports
		// against the module graph rather than a single manifest file, so
		// Manifest is left empty rather than asserting a file that was never
		// read.
		Dependency: &models.DependencyRef{
			Ecosystem: "Go",
			Package:   modName,
		},
	}
}

// firstFixVersion walks the OSV schema's affected[].ranges[].events[]
// list and returns the first `fixed` version it finds. Per OSV schema,
// that's the canonical "upgrade to this" target.
func firstFixVersion(osv *osvRecord) string {
	for _, a := range osv.Affected {
		for _, r := range a.Ranges {
			// A GIT range's `fixed` is a commit SHA, not a version.
			if r.Type == "GIT" {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// firstLines returns up to n leading lines of s joined with " | ", capped
// at 300 chars total. Used for shaping stderr excerpts into a single log
// line.
func firstLines(s string, n int) string {
	parts := strings.Split(strings.TrimSpace(s), "\n")
	if len(parts) > n {
		parts = parts[:n]
	}
	out := strings.Join(parts, " | ")
	if len(out) > 300 {
		out = out[:300]
	}
	return out
}

// skipToNextObject advances the decoder past a malformed value by
// discarding tokens until the next '{' boundary. Returns false when the
// stream is exhausted.
func skipToNextObject(dec *json.Decoder) bool {
	for dec.More() {
		_, err := dec.Token()
		if err != nil {
			return false
		}
	}
	return false
}
