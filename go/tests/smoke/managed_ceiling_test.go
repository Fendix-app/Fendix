package smoke

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// Managed evidence over a contract ceiling (managed-ci/v2: 10,000 findings,
// 8 MiB body, each independent) is a terminal error, end to end, through the
// real binary: exit 2, ONE line naming the ceiling, the actual and the
// maximum, no evidence document, and no request to the backend. Nothing is
// truncated or split to fit, and no managed PASS, WARN or BLOCK exists.

const ceilingTail = ". Nothing was submitted; there is no managed PASS, WARN or BLOCK decision for this run."

// bodyRefusal matches the request-body line; its byte count depends on the
// document, so only its shape and its bound are pinned.
var bodyRefusal = regexp.MustCompile(`^fendix: managed evidence exceeds a contract ceiling: ` +
	`request body (\d+) bytes > maximum 8388608 bytes` + regexp.QuoteMeta(ceilingTail) + `$`)

const managedContextJSON = `{
  "evidence_submission_id": "44444444-4444-4444-8444-444444444444",
  "context": {
    "schema_version": "managed-scan-context/v1",
    "scan_execution_id": "33333333-3333-4333-8333-333333333333",
    "tenant_id": "11111111-1111-4111-8111-111111111111",
    "asset_id": "22222222-2222-4222-8222-222222222222",
    "environment": "staging", "provider": "github",
    "repository_id": "123456", "repository_owner_id": "7654321",
    "repository": "acme/payments",
    "head_sha": "1111111111111111111111111111111111111111",
    "base_sha": null, "pull_request": null,
    "workflow_name": "Fendix managed scan",
    "workflow_ref": "acme/payments/.github/workflows/fendix.yml@refs/heads/main",
    "run_id": "987654", "run_attempt": 1, "event_name": "push"
  }
}`

// backend is an httptest stand-in for the managed API that counts every
// request it receives. A ceiling refusal must leave the count at zero.
func backend(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

// githubEnv points the step files at fresh paths, so a test run inside
// GitHub Actions never writes to the real job's outputs or summary, and so
// the test can prove nothing was published there.
func githubEnv(t *testing.T) (env []string, outputs, summary string) {
	t.Helper()
	dir := t.TempDir()
	outputs = filepath.Join(dir, "github_output")
	summary = filepath.Join(dir, "github_step_summary")
	return []string{"GITHUB_OUTPUT=" + outputs, "GITHUB_STEP_SUMMARY=" + summary}, outputs, summary
}

func assertAbsent(t *testing.T, what, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s exists at %s (stat error %v); a refused run must not leave one", what, path, err)
	}
}

// vulnerableTree writes a Python project pinning `count` packages, each with
// a known advisory in an offline database, so an --offline scan reports
// exactly one dependency finding per package with no network. Padding the
// package names makes each finding larger without adding findings.
func vulnerableTree(t *testing.T, bin string, count, namePad int) (code, db string) {
	t.Helper()
	dir := t.TempDir()
	code = filepath.Join(dir, "src")
	if err := os.MkdirAll(code, 0o755); err != nil {
		t.Fatal(err)
	}
	type advisory struct {
		ID         string              `json:"id"`
		Aliases    []string            `json:"aliases"`
		Package    map[string]string   `json:"package"`
		Ranges     []map[string]string `json:"ranges"`
		Summary    string              `json:"summary"`
		References []string            `json:"references"`
	}
	var requirements strings.Builder
	advisories := make([]advisory, 0, count)
	pad := strings.Repeat("x", namePad)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("pkg%d%s", i, pad)
		fmt.Fprintf(&requirements, "%s==1.0.0\n", name)
		advisories = append(advisories, advisory{
			ID:         fmt.Sprintf("FENDIX-CEILING-%05d", i),
			Aliases:    []string{fmt.Sprintf("CVE-2099-%d", 10000+i)},
			Package:    map[string]string{"ecosystem": "PyPI", "name": name},
			Ranges:     []map[string]string{{"introduced": "0", "fixed": "2.0.0"}},
			Summary:    "ceiling fixture",
			References: []string{},
		})
	}
	if err := os.WriteFile(filepath.Join(code, "requirements.txt"), []byte(requirements.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	export, err := json.Marshal(advisories)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "osv-export.json")
	if err := os.WriteFile(source, export, 0o600); err != nil {
		t.Fatal(err)
	}
	db = filepath.Join(dir, "offline-db.json")
	if _, stderr, exit := harness.RunBin(t, bin, nil, "db", "update", "--source", source, "--output", db); exit != 0 {
		t.Fatalf("fendix db update: exit %d\n%s", exit, stderr)
	}
	return code, db
}

// managedScan runs the managed scan exactly as the Action's scan step does,
// offline, and returns its stderr, exit code and the evidence path.
func managedScan(t *testing.T, bin, code, db string, env []string) (stderr string, exit int, evidence string) {
	t.Helper()
	dir := t.TempDir()
	context := filepath.Join(dir, "context.json")
	if err := os.WriteFile(context, []byte(managedContextJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence = filepath.Join(dir, "evidence.json")
	_, stderr, exit = harness.RunBin(t, bin, env,
		"scan", "--code", code, "--offline", "--offline-db", db,
		"--format", "json", "--output", filepath.Join(dir, "report.json"),
		"--managed-evidence", evidence, "--managed-context", context)
	return stderr, exit, evidence
}

// managedSubmit runs `fendix managed submit` exactly as the Action's submit
// step does, against the counting backend.
func managedSubmit(t *testing.T, bin, evidence, apiBase string, env []string) (stdout, stderr string, exit int, decision string) {
	t.Helper()
	decision = filepath.Join(t.TempDir(), "decision.json")
	env = append([]string{"FENDIX_CI_TOKEN=" + ceilingToken}, env...)
	stdout, stderr, exit = harness.RunBin(t, bin, env,
		"managed", "submit", "--evidence", evidence, "--api-base", apiBase, "--decision-output", decision)
	return stdout, stderr, exit, decision
}

const ceilingToken = "fxci_ceilingtest_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// refusalLines returns every stderr line that opens with the ceiling prefix.
func refusalLines(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "fendix: managed evidence exceeds a contract ceiling: ") {
			out = append(out, line)
		}
	}
	return out
}

// TestManagedScanOverTheFindingCeiling: 10,001 real findings. The scan
// refuses to write evidence, names the ceiling, and leaves the Action's
// submit step nothing to send.
func TestManagedScanOverTheFindingCeiling(t *testing.T) {
	bin := harness.Release(t)
	code, db := vulnerableTree(t, bin, 10001, 0)
	env, outputs, summary := githubEnv(t)
	stderr, exit, evidence := managedScan(t, bin, code, db, env)

	if exit != 2 {
		t.Fatalf("exit = %d, want 2 (no managed evidence, no decision)\n%s", exit, tail(stderr))
	}
	want := "fendix: managed evidence exceeds a contract ceiling: finding count 10001 > maximum 10000" + ceilingTail
	if lines := refusalLines(stderr); len(lines) != 1 || lines[0] != want {
		t.Fatalf("refusal lines = %q\nwant exactly [%q]\n%s", lines, want, tail(stderr))
	}
	if strings.Contains(stderr, "managed evidence: ") {
		t.Errorf("the generic managed-evidence error was printed as well:\n%s", tail(stderr))
	}
	assertAbsent(t, "an evidence document", evidence)
	assertAbsent(t, "a step output", outputs)
	assertAbsent(t, "a step summary", summary)

	// What the Action's next step would do with this run: there is no
	// document, so the backend hears nothing.
	server, requests := backend(t)
	_, _, submitExit, decision := managedSubmit(t, bin, evidence, server.URL, env)
	if submitExit != 2 {
		t.Errorf("submit of a missing document: exit = %d, want 2", submitExit)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the backend received %d request(s) after a ceiling refusal", n)
	}
	assertAbsent(t, "a decision", decision)
}

// TestManagedScanOverTheBodyCeilingWithFewerFindings: 4,000 findings, far
// under the finding ceiling, whose document still exceeds 8 MiB. The two
// ceilings are independent.
func TestManagedScanOverTheBodyCeilingWithFewerFindings(t *testing.T) {
	bin := harness.Release(t)
	code, db := vulnerableTree(t, bin, 4000, 1500)
	env, outputs, summary := githubEnv(t)
	stderr, exit, evidence := managedScan(t, bin, code, db, env)

	if exit != 2 {
		t.Fatalf("exit = %d, want 2 (no managed evidence, no decision)\n%s", exit, tail(stderr))
	}
	lines := refusalLines(stderr)
	if len(lines) != 1 {
		t.Fatalf("refusal lines = %q, want exactly one\n%s", lines, tail(stderr))
	}
	match := bodyRefusal.FindStringSubmatch(lines[0])
	if match == nil {
		t.Fatalf("refusal = %q, want the request-body ceiling", lines[0])
	}
	if size, _ := strconv.Atoi(match[1]); size <= 8388608 {
		t.Errorf("reported body %d bytes is within the ceiling it claims to exceed", size)
	}
	assertAbsent(t, "an evidence document", evidence)
	assertAbsent(t, "a step output", outputs)
	assertAbsent(t, "a step summary", summary)
}

// TestManagedSubmitRefusesADocumentOverEitherCeiling: a document the engine
// would never write — edited, from another build, or assembled by hand —
// is refused by the submit command before any request, with the same line.
func TestManagedSubmitRefusesADocumentOverEitherCeiling(t *testing.T) {
	bin := harness.Release(t)
	cases := map[string]struct {
		findings, pad int
		want          *regexp.Regexp
	}{
		"10,001 findings within 8 MiB": {
			findings: 10001,
			want: regexp.MustCompile(`^` + regexp.QuoteMeta(
				"fendix: managed evidence exceeds a contract ceiling: finding count 10001 > maximum 10000"+ceilingTail) + `$`),
		},
		"100 findings over 8 MiB": {findings: 100, pad: 90000, want: bodyRefusal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			evidence := filepath.Join(t.TempDir(), "evidence.json")
			if err := os.WriteFile(evidence, submissionDocument(tc.findings, tc.pad), 0o600); err != nil {
				t.Fatal(err)
			}
			server, requests := backend(t)
			env, outputs, summary := githubEnv(t)
			stdout, stderr, exit, decision := managedSubmit(t, bin, evidence, server.URL, env)

			if exit != 2 {
				t.Fatalf("exit = %d, want 2 (no decision)\nstdout: %s\nstderr: %s", exit, stdout, stderr)
			}
			// The refusal is the command's whole output: no "Error:" prefix,
			// no receipt, no decision.
			if got := strings.TrimSuffix(stderr, "\n"); !tc.want.MatchString(got) {
				t.Errorf("stderr = %q, want one line matching %s", stderr, tc.want)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("the backend received %d request(s); evidence over a ceiling must never be sent", n)
			}
			if strings.Contains(stdout+stderr, ceilingToken) {
				t.Error("the credential reached the command's output")
			}
			assertAbsent(t, "a decision", decision)
			assertAbsent(t, "a step output", outputs)
			assertAbsent(t, "a step summary", summary)
		})
	}
}

// submissionDocument is a submission-shaped document with the given number
// of findings, each padded by pad bytes. Only the ceilings are under test,
// so the findings need not be valid: they must never be sent at all.
func submissionDocument(findings, pad int) []byte {
	items := make([]map[string]string, findings)
	for i := range items {
		items[i] = map[string]string{"finding_id": fmt.Sprintf("SEC-%d%s", i, strings.Repeat("x", pad))}
	}
	body, _ := json.Marshal(map[string]any{
		"api_version": "managed-ci/v2",
		"manifest":    map[string]any{"analyzers": []any{}, "findings": items},
	})
	return body
}

// tail keeps a failure message readable: a scan's stderr is long.
func tail(stderr string) string {
	if len(stderr) > 4000 {
		return "…" + stderr[len(stderr)-4000:]
	}
	return stderr
}
