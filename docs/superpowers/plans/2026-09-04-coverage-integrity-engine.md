# Coverage Integrity — Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the engine record every analyzer that can silently degrade, with a closed machine-readable reason, so a scan whose configured analyzers did not all run can never be mistaken for a complete scan — in JSON, SARIF, HTML, PDF, the exit code and the scan-end output.

**Architecture:** Four layers, built bottom-up. (1) `reporters` gains the closed `ScannerReason` enumeration, the `attempts` field, the `metadata.coverage` block and `metadata.policy_version`, plus passthrough fields the hosted backend sets on re-render. (2) `engine` gains a fixed analyzer registry and rewrites every status call site so each registry analyzer is recorded exactly once per scan with a reason; the five untracked subsystems (discovery, spec, active probes, the Python engine and its sub-checks, plugins) join the list. (3) The dependency scanners learn to surface transport failures as typed errors, and the orchestrator retries one transient failure per analyzer in process. (4) Two opt-in CLI flags, SARIF notifications and a property bag, an HTML/PDF coverage table, docs, and a release-time image smoke test make the contract visible and enforced.

**Tech Stack:** Go 1.26.6 standard library only (no new module dependencies); Python 3 for `python/engine.py`; `go test -race ./...` from `go/`; `python3 -m pytest python/tests/ -v` from the repo root (CI runs it if pytest is absent locally).

**Spec:** `../fendix-backend/docs/superpowers/specs/2026-09-04-coverage-integrity-contract-design.md` (sections 4, 5 and 10 are the engine's contract; section 6.4 defines the in-process retry). This plan implements the engine release the spec calls `v3.4.0`.

## Global Constraints

- **Contract version.** `metadata.coverage.contract_version` is `1`. `metadata.schema_version` stays `2`: every change here is additive.
- **Wire `state` keeps three values** — `ok`, `skipped`, `failed`. Classification lives in `reason`. A `skipped` entry carries a skip reason; a `failed` entry carries a fail reason; an `ok` entry carries none. The schema test enforces the pairing.
- **Registry order is fixed** (spec §4.1): `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, `python-engine/auth`, `python-engine/injection`, `python-engine/deps`, `plugins`. Every non-import scan that reaches the analyzer stage emits exactly one entry per base analyzer; the three children appear exactly once each when the Python engine declares protocol version 2, and not at all otherwise. **One accepted exception:** an explicit `--python-engine` whose tree cannot be resolved exits 2 in preflight, before any analyzer runs, and renders no report (Task 5; spec §4.4). That is the only path on which a non-import scan produces no `scanner_status`.
- **Default CLI exit behaviour does not change.** `0`/`1` from `decision.ExitCode`; `--fail-on-scanner-error` exits `2` only on `failed`. New strictness is behind `--fail-on-coverage-gap` and `--require-analyzers`, both off by default. Exit `2` always outranks `1`.
- **Constitution Rule 3 — evidence is never dropped.** Findings gathered by an analyzer are appended whether or not that analyzer is later recorded `failed`. A retry replaces only the retried analyzer's evidence with its second attempt's evidence.
- **No whole-engine re-run.** Retry is one in-process re-invocation of a single dependency scanner, only for `network_error` or `timeout`.
- **Determinism.** `scanner_status` is emitted in registry order; two runs of one input render byte-identical `scanner_status` and `coverage`.
- **Bounds.** `name` ≤ 64 bytes, `reason` ≤ 32, `detail` ≤ 240 (existing `truncateErr`), list ≤ 48 entries.
- **No prose classification in the contract.** Reasons are assigned from typed errors and sentinels. The one textual fallback (`govulncheck` subprocess stderr) is engine-internal transport typing, documented in Task 7, and never reaches ownership or refund logic.
- **Baseline.** `go test -race ./...` from `go/` is green at HEAD `5bccf89` (tag `v3.3.0`). Any red after a change is caused by that change.
- **Commit messages** carry no tool or model attribution.
- **Working directory** for Go commands: `/Users/asaied/WorkDir/Fendix/fendix-services/Fendix/go`. For Python and docs: `/Users/asaied/WorkDir/Fendix/fendix-services/Fendix`.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `internal/reporters/coverage.go` | `ScannerReason` enum, `Class()`, `Coverage`, `BuildCoverage` | **create** |
| `internal/reporters/coverage_test.go` | reason pairing, class table, coverage build, JSON shape | **create** |
| `internal/reporters/json.go` | `ScannerStatus` fields, `ScanMetadata` additions | modify |
| `internal/reporters/schema_test.go` | validate reason/attempts/coverage | modify |
| `internal/reporters/sarif.go` | notifications for every non-ok entry, property bag, `executionSuccessful` modes | modify |
| `internal/reporters/sarif_test.go` | notification levels, three modes | modify |
| `internal/reporters/html.go`, `pdf.go`, `i18n/*.go` | coverage table and verdict line | modify |
| `internal/engine/registry.go` | analyzer names, order, `IsRegisteredAnalyzer` | **create** |
| `internal/engine/registry_test.go` | order and membership | **create** |
| `internal/engine/scannerstatus.go` | reasoned `skip`/`fail`, `attempts`, `sorted()`, `classifyErr` | modify |
| `internal/engine/scannerstatus_test.go` | new signatures, sorting, attempts | modify |
| `internal/engine/orchestrator.go` | exactly-once recording, code-path validation, discovery/spec/probes/plugins entries, zero-endpoint report, Python outcome mapping, retry, coverage block, strict exits, scan-end table | modify |
| `internal/engine/coverage_test.go` | registry exactly-once property test, strict exits, retry | **create** |
| `internal/engine/discovery_status_test.go` | dast/spec/active-probes pure-function table | **create** |
| `internal/engine/spawner.go` | outcome classification, status lines, total reconciliation | modify |
| `internal/engine/spawner_test.go` | fake engines for each outcome | modify |
| `internal/engine/summary.go` | scan-end coverage table on stderr | **create** |
| `internal/scanner/crawler.go` | expose spec parse failure | modify |
| `internal/scanner/semgrep/scanner.go` | `ErrTimeout` sentinel | modify |
| `internal/scanner/deps/neterr/neterr.go` | transport error classification, `StatusError`, `LookupError` | **create** |
| `internal/scanner/deps/neterr/neterr_test.go` | classification table | **create** |
| `internal/scanner/deps/pip/scanner.go` | `ErrNoManifests`, typed status errors, lookup-failure accounting | modify |
| `internal/scanner/deps/npm/scanner.go` | typed status errors, lookup-failure accounting | modify |
| `internal/scanner/deps/govulncheck/scanner.go` | stderr transport typing | modify |
| `internal/models/config.go` | `FailOnCoverageGap`, `RequiredAnalyzers` | modify |
| `internal/decision/policy_version.go` | `PolicyVersion = "1.0.0"` | **create** |
| `cmd/fendix/main.go` | two flags, name validation | modify |
| `python/engine.py` | status lines per check | modify |
| `python/analyzers/ast_analyzer.py` | per-language file counts | modify |
| `python/tests/test_engine_contract.py` | status-line contract | modify |
| `docs/schema.json`, `docs/schema.md`, `docs/INTEGRATION_GUIDE.md`, `README.md`, `CHANGELOG.md`, `docs/adr/ADR-002-ndjson-ipc.md`, `docs/DECISION_POLICY.md` | contract documentation | modify |
| `.github/workflows/release.yml`, `tests/fixtures/coverage-smoke/` (incl. `osv-export.json`), `scripts/coverage-smoke-check.sh` | candidate build, deterministic and network smokes, promotion gate | modify / **create** |

Tasks 1–2 are the vocabulary. Tasks 3–6 make every subsystem record itself. Tasks 7–8 are transport typing and retry. Task 9 is the CLI surface. Tasks 10–11 are SARIF and human renderers. Tasks 12–13 are docs and the release gate.

---

### Task 1: Reason enumeration, coverage block and metadata fields

**Files:**
- Create: `internal/reporters/coverage.go`
- Create: `internal/reporters/coverage_test.go`
- Modify: `internal/reporters/json.go:99-128` (ScannerStatus), `:32-81` (ScanMetadata)
- Modify: `internal/reporters/schema_test.go:18-45`
- Modify: `docs/schema.json` (ScannerStatus, ScanMetadata definitions)

**Interfaces:**
- Produces: `type ScannerReason string` with the thirteen constants below; `(ScannerReason).IsSkip() bool`, `.IsFail() bool`, `.Valid() bool`; `ScannerStatus{Name, State, Reason, Detail, Attempts}`; `(ScannerStatus).Class() string`, `.IsGap() bool`; `const CoverageContractVersion = 1`; `type Coverage struct{ContractVersion int; Strict bool; ConfiguredComplete bool; Gaps, Limitations, RequiredAnalyzers, RequiredGaps, Retried []string}`; `func BuildCoverage(status []ScannerStatus, required []string, strict bool) Coverage`; `(Coverage).StrictOK() bool`; `ScanMetadata.Coverage *Coverage`, `.PolicyVersion string`, `.ReleaseDecision string`, `.CoverageState string`, `.DecisionPolicyVersion string`, `.DecisionRationale json.RawMessage`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/reporters/coverage_test.go
package reporters

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestScannerReason_PairingWithState(t *testing.T) {
	skips := []ScannerReason{ReasonNotApplicable, ReasonDiffUnchanged, ReasonDisabledByFlag, ReasonDisabledOffline, ReasonDependencyMissing, ReasonUnsupportedTarget}
	fails := []ScannerReason{ReasonNetworkError, ReasonTimeout, ReasonExecutionError, ReasonMalformedOutput, ReasonTruncatedOutput, ReasonInputError, ReasonNoEndpoints}
	for _, r := range skips {
		if !r.IsSkip() || r.IsFail() || !r.Valid() {
			t.Errorf("%s must be a valid skip reason", r)
		}
	}
	for _, r := range fails {
		if !r.IsFail() || r.IsSkip() || !r.Valid() {
			t.Errorf("%s must be a valid fail reason", r)
		}
	}
	if ScannerReason("bogus").Valid() {
		t.Error("bogus must not validate")
	}
	if got := len(skips) + len(fails); got != 13 {
		t.Fatalf("contract version 1 defines 13 reasons, test lists %d", got)
	}
}

func TestScannerStatus_Class(t *testing.T) {
	for _, tc := range []struct {
		in   ScannerStatus
		want string
	}{
		{ScannerStatus{Name: "secrets", State: ScannerOK}, "ok"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonNotApplicable}, "not_applicable"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonDiffUnchanged}, "not_applicable"},
		{ScannerStatus{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag}, "disabled"},
		{ScannerStatus{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline}, "disabled"},
		{ScannerStatus{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing}, "unavailable"},
		{ScannerStatus{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget}, "unsupported"},
		{ScannerStatus{Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError}, "failed"},
		{ScannerStatus{Name: "pip", State: ScannerFailed}, "failed"},   // legacy failed entry, no reason
		{ScannerStatus{Name: "pip", State: ScannerSkipped}, "unknown"}, // legacy skip, no reason
		{ScannerStatus{Name: "pip", State: "weird"}, "unknown"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonNetworkError}, "unknown"}, // mismatched pairing
	} {
		if got := tc.in.Class(); got != tc.want {
			t.Errorf("%+v: Class() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildCoverage(t *testing.T) {
	status := []ScannerStatus{
		{Name: "dast", State: ScannerSkipped, Reason: ReasonNotApplicable},
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag, Detail: "--fast"},
		{Name: "pip", State: ScannerOK, Attempts: 2},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget, Detail: "package.json without package-lock.json"},
		{Name: "python-engine", State: ScannerOK},
		{Name: "python-engine/deps", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "No module named 'packaging'"},
	}
	got := BuildCoverage(status, []string{"semgrep", "python-engine"}, true)
	want := Coverage{
		ContractVersion:    1,
		Strict:             true,
		ConfiguredComplete: false,
		Gaps:               []string{"python-engine/deps"},
		Limitations:        []string{"npm: package.json without package-lock.json"},
		RequiredAnalyzers:  []string{"semgrep", "python-engine"},
		RequiredGaps:       []string{"semgrep"},
		Retried:            []string{"pip"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildCoverage mismatch\n got: %+v\nwant: %+v", got, want)
	}
	if got.StrictOK() {
		t.Error("StrictOK must be false when required_gaps is non-empty")
	}
}

func TestBuildCoverage_RequiredSatisfiedOnlyByOkOrNotApplicable(t *testing.T) {
	status := []ScannerStatus{
		{Name: "semgrep", State: ScannerOK},
		{Name: "pip", State: ScannerSkipped, Reason: ReasonNotApplicable},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget},
		{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline},
	}
	got := BuildCoverage(status, []string{"semgrep", "pip", "npm", "govulncheck", "textscan"}, true)
	want := []string{"npm", "govulncheck", "textscan"} // unsupported, disabled and missing do not satisfy an explicit requirement
	if !reflect.DeepEqual(got.RequiredGaps, want) {
		t.Fatalf("RequiredGaps = %v, want %v", got.RequiredGaps, want)
	}
	if !got.ConfiguredComplete {
		t.Error("no engine gap classes present, ConfiguredComplete must be true regardless of required_gaps")
	}
}

func TestBuildCoverage_EmptyListsAreArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(BuildCoverage(nil, nil, false)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"gaps":[]`, `"limitations":[]`, `"required_analyzers":[]`, `"required_gaps":[]`, `"retried":[]`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("encoded coverage must contain %s, got %s", key, buf.String())
		}
	}
	if !strings.Contains(buf.String(), `"configured_complete":true`) {
		t.Error("an empty status list is trivially complete")
	}
}

func TestScannerStatus_JSONOmitsEmptyReasonAndAttempts(t *testing.T) {
	b, _ := json.Marshal(ScannerStatus{Name: "secrets", State: ScannerOK})
	if strings.Contains(string(b), "reason") || strings.Contains(string(b), "attempts") {
		t.Fatalf("ok entry must omit reason and attempts: %s", b)
	}
	b, _ = json.Marshal(ScannerStatus{Name: "pip", State: ScannerOK, Attempts: 2})
	if !strings.Contains(string(b), `"attempts":2`) {
		t.Fatalf("attempts > 1 must be emitted: %s", b)
	}
}

func TestScanMetadata_CoverageRoundTripsThroughRenderJSON(t *testing.T) {
	cov := BuildCoverage([]ScannerStatus{{Name: "secrets", State: ScannerOK}}, nil, false)
	meta := ScanMetadata{Version: "dev", Mode: "whitebox", Coverage: &cov, PolicyVersion: "1.0.0"}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, nil, meta); err != nil {
		t.Fatal(err)
	}
	var back JSONReport
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Metadata.Coverage == nil || back.Metadata.Coverage.ContractVersion != 1 {
		t.Fatalf("coverage did not round-trip: %+v", back.Metadata.Coverage)
	}
	if back.Metadata.PolicyVersion != "1.0.0" {
		t.Fatalf("policy_version = %q", back.Metadata.PolicyVersion)
	}
	// A live scan never sets the backend passthrough fields; they must not appear.
	if strings.Contains(buf.String(), "release_decision") || strings.Contains(buf.String(), "coverage_state") {
		t.Fatalf("passthrough fields must be omitted when unset: %s", buf.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/reporters/ -run 'TestScannerReason|TestScannerStatus_Class|TestBuildCoverage|TestScannerStatus_JSON|TestScanMetadata_Coverage' -v`
Expected: FAIL to compile with `undefined: ScannerReason`, `undefined: BuildCoverage`.

- [ ] **Step 3: Create `internal/reporters/coverage.go`**

```go
package reporters

// ScannerReason is the closed, machine-readable explanation for a
// non-ok scanner_status entry (coverage contract version 1). A skipped
// entry carries a skip reason, a failed entry carries a fail reason, an
// ok entry carries none. The set is closed: a consumer may switch on it.
type ScannerReason string

const (
	// Skip reasons.
	ReasonNotApplicable     ScannerReason = "not_applicable"
	ReasonDiffUnchanged     ScannerReason = "diff_unchanged"
	ReasonDisabledByFlag    ScannerReason = "disabled_by_flag"
	ReasonDisabledOffline   ScannerReason = "disabled_offline"
	ReasonDependencyMissing ScannerReason = "dependency_missing"
	ReasonUnsupportedTarget ScannerReason = "unsupported_target"
	// Fail reasons.
	ReasonNetworkError    ScannerReason = "network_error"
	ReasonTimeout         ScannerReason = "timeout"
	ReasonExecutionError  ScannerReason = "execution_error"
	ReasonMalformedOutput ScannerReason = "malformed_output"
	ReasonTruncatedOutput ScannerReason = "truncated_output"
	ReasonInputError      ScannerReason = "input_error"
	ReasonNoEndpoints     ScannerReason = "no_endpoints"
)

var skipReasons = map[ScannerReason]bool{
	ReasonNotApplicable: true, ReasonDiffUnchanged: true, ReasonDisabledByFlag: true,
	ReasonDisabledOffline: true, ReasonDependencyMissing: true, ReasonUnsupportedTarget: true,
}

var failReasons = map[ScannerReason]bool{
	ReasonNetworkError: true, ReasonTimeout: true, ReasonExecutionError: true, ReasonMalformedOutput: true,
	ReasonTruncatedOutput: true, ReasonInputError: true, ReasonNoEndpoints: true,
}

// IsSkip reports whether r pairs with state "skipped".
func (r ScannerReason) IsSkip() bool { return skipReasons[r] }

// IsFail reports whether r pairs with state "failed".
func (r ScannerReason) IsFail() bool { return failReasons[r] }

// Valid reports whether r is one of the contract's reasons.
func (r ScannerReason) Valid() bool { return r.IsSkip() || r.IsFail() }

// Lifecycle classes (spec §4.2). Strings, not a type, because the backend
// and the frontend use the same words and neither imports this package.
const (
	ClassOK            = "ok"
	ClassNotApplicable = "not_applicable"
	ClassDisabled      = "disabled"
	ClassUnavailable   = "unavailable"
	ClassUnsupported   = "unsupported"
	ClassFailed        = "failed"
	ClassUnknown       = "unknown"
)

// Class maps an entry to its lifecycle class. A failed entry without a
// reason is still failed (pre-contract reports recorded failures without
// one); a skipped entry without a reason, or with a reason that does not
// pair with its state, is unknown — the consumer must not guess.
func (s ScannerStatus) Class() string {
	switch s.State {
	case ScannerOK:
		return ClassOK
	case ScannerFailed:
		if s.Reason == "" || s.Reason.IsFail() {
			return ClassFailed
		}
		return ClassUnknown
	case ScannerSkipped:
		switch s.Reason {
		case ReasonNotApplicable, ReasonDiffUnchanged:
			return ClassNotApplicable
		case ReasonDisabledByFlag, ReasonDisabledOffline:
			return ClassDisabled
		case ReasonDependencyMissing:
			return ClassUnavailable
		case ReasonUnsupportedTarget:
			return ClassUnsupported
		}
		return ClassUnknown
	}
	return ClassUnknown
}

// IsGap reports whether this entry is an engine gap class: configured to
// run and did not deliver. Disabled, not-applicable and unsupported are
// not gaps; the hosted policy layers its own requirements on top.
func (s ScannerStatus) IsGap() bool {
	c := s.Class()
	return c == ClassUnavailable || c == ClassFailed
}

// CoverageContractVersion is the version of the registry-and-reason
// contract this build writes. Bump when a name or reason is added,
// removed or re-meant. Independent of SchemaVersion.
const CoverageContractVersion = 1

// Coverage is the engine's own statement about what it was configured to
// run (spec §5.2). It knows nothing about what a hosted plan promises.
type Coverage struct {
	ContractVersion    int      `json:"contract_version"`
	Strict             bool     `json:"strict"`
	ConfiguredComplete bool     `json:"configured_complete"`
	Gaps               []string `json:"gaps"`
	Limitations        []string `json:"limitations"`
	RequiredAnalyzers  []string `json:"required_analyzers"`
	RequiredGaps       []string `json:"required_gaps"`
	Retried            []string `json:"retried"`
}

// BuildCoverage derives the coverage block from the recorded entries.
// `required` is the --require-analyzers list (nil when none). An explicit
// requirement is satisfied only by ok or not_applicable: the operator asked
// for that analyzer by name, so disabled and unsupported do not satisfy it.
// Slices are never nil so the JSON always carries arrays.
func BuildCoverage(status []ScannerStatus, required []string, strict bool) Coverage {
	cov := Coverage{
		ContractVersion:    CoverageContractVersion,
		Strict:             strict,
		ConfiguredComplete: true,
		Gaps:               []string{},
		Limitations:        []string{},
		RequiredAnalyzers:  []string{},
		RequiredGaps:       []string{},
		Retried:            []string{},
	}
	byName := make(map[string]ScannerStatus, len(status))
	for _, s := range status {
		byName[s.Name] = s
		if s.IsGap() {
			cov.ConfiguredComplete = false
			cov.Gaps = append(cov.Gaps, s.Name)
		}
		if s.Class() == ClassUnsupported {
			lim := s.Name
			if s.Detail != "" {
				lim += ": " + s.Detail
			}
			cov.Limitations = append(cov.Limitations, lim)
		}
		if s.Attempts > 1 {
			cov.Retried = append(cov.Retried, s.Name)
		}
	}
	for _, name := range required {
		cov.RequiredAnalyzers = append(cov.RequiredAnalyzers, name)
		s, ok := byName[name]
		if !ok {
			cov.RequiredGaps = append(cov.RequiredGaps, name)
			continue
		}
		if c := s.Class(); c != ClassOK && c != ClassNotApplicable {
			cov.RequiredGaps = append(cov.RequiredGaps, name)
		}
	}
	return cov
}

// StrictOK reports whether a strict run delivered everything it was asked
// for: no engine gap and no unsatisfied explicit requirement.
func (c Coverage) StrictOK() bool {
	return c.ConfiguredComplete && len(c.RequiredGaps) == 0
}
```

- [ ] **Step 4: Extend the structs in `internal/reporters/json.go`**

Replace the `ScannerStatus` struct (lines 118-124) with:

```go
// ScannerStatus is the recorded outcome of a single analyzer pass. Name is
// the registry identity (see engine.Registry); Reason is the closed
// explanation for a non-ok state (coverage contract v1); Detail is a short
// human-readable excerpt; Attempts is present only when an in-process
// retry ran (>1) and State/Reason describe the final attempt.
type ScannerStatus struct {
	Name     string             `json:"name"`
	State    ScannerStatusState `json:"state"`
	Reason   ScannerReason      `json:"reason,omitempty"`
	Detail   string             `json:"detail,omitempty"`
	Attempts int                `json:"attempts,omitempty"`
}
```

Add to `ScanMetadata`, after the `Imports` field:

```go
	// Coverage is the engine's configured-completeness statement (coverage
	// contract v1). Nil on reports that predate the contract; a re-render
	// passes it through verbatim.
	Coverage *Coverage `json:"coverage,omitempty"`
	// PolicyVersion is the finding-decision policy version
	// (docs/DECISION_POLICY.md) this build applies.
	PolicyVersion string `json:"policy_version,omitempty"`
	// Backend passthrough. A live scan never sets these; the hosted backend
	// embeds them in the input it hands to `fendix report --input` so the
	// verdict it derived travels into SARIF/HTML/PDF. They are opaque here.
	ReleaseDecision       string          `json:"release_decision,omitempty"`
	CoverageState         string          `json:"coverage_state,omitempty"`
	DecisionPolicyVersion string          `json:"decision_policy_version,omitempty"`
	DecisionRationale     json.RawMessage `json:"decision_rationale,omitempty"`
```

- [ ] **Step 5: Run the new tests**

Run: `go test ./internal/reporters/ -run 'TestScannerReason|TestScannerStatus_Class|TestBuildCoverage|TestScannerStatus_JSON|TestScanMetadata_Coverage' -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Extend the schema validator and `docs/schema.json`**

In `internal/reporters/schema_test.go`, after the `checks_run` block (line ~45), add:

```go
	if raw, ok := meta["scanner_status"]; ok {
		for i, item := range requireArray(t, "metadata.scanner_status", raw) {
			entry := requireObject(t, "metadata.scanner_status[]", item)
			path := "metadata.scanner_status[" + itoa(i) + "]"
			requireKeys(t, path, entry, []string{"name", "state"})
			state, _ := entry["state"].(string)
			requireEnum(t, path+".state", entry["state"], []string{"ok", "skipped", "failed"})
			reason, hasReason := entry["reason"].(string)
			switch state {
			case "ok":
				if hasReason {
					t.Errorf("%s: ok entry must not carry a reason, got %q", path, reason)
				}
			case "skipped":
				if !hasReason || !ScannerReason(reason).IsSkip() {
					t.Errorf("%s: skipped entry needs a skip reason, got %q", path, reason)
				}
			case "failed":
				if !hasReason || !ScannerReason(reason).IsFail() {
					t.Errorf("%s: failed entry needs a fail reason, got %q", path, reason)
				}
			}
			if a, ok := entry["attempts"]; ok {
				requireInt(t, path+".attempts", a)
			}
		}
	}
	if raw, ok := meta["coverage"]; ok {
		cov := requireObject(t, "metadata.coverage", raw)
		requireKeys(t, "metadata.coverage", cov, []string{"contract_version", "strict", "configured_complete", "gaps", "limitations", "required_analyzers", "required_gaps", "retried"})
		requireInt(t, "metadata.coverage.contract_version", cov["contract_version"])
		requireBool(t, "metadata.coverage.strict", cov["strict"])
		requireBool(t, "metadata.coverage.configured_complete", cov["configured_complete"])
		for _, k := range []string{"gaps", "limitations", "required_analyzers", "required_gaps", "retried"} {
			for _, v := range requireArray(t, "metadata.coverage."+k, cov[k]) {
				requireString(t, "metadata.coverage."+k+"[]", v)
			}
		}
	}
	if pv, ok := meta["policy_version"]; ok {
		requireString(t, "metadata.policy_version", pv)
	}
```

In `docs/schema.json`, replace the `ScannerStatus` definition and add the new metadata keys:

```json
    "ScannerStatus": {
      "type": "object",
      "required": ["name", "state"],
      "additionalProperties": false,
      "properties": {
        "name":     { "type": "string" },
        "state":    { "type": "string", "enum": ["ok", "skipped", "failed"] },
        "reason":   { "type": "string", "enum": ["not_applicable", "diff_unchanged", "disabled_by_flag", "disabled_offline", "dependency_missing", "unsupported_target", "network_error", "timeout", "execution_error", "malformed_output", "truncated_output", "input_error", "no_endpoints"] },
        "detail":   { "type": "string" },
        "attempts": { "type": "integer", "minimum": 2 }
      }
    },
    "Coverage": {
      "type": "object",
      "required": ["contract_version", "strict", "configured_complete", "gaps", "limitations", "required_analyzers", "required_gaps", "retried"],
      "additionalProperties": false,
      "properties": {
        "contract_version":    { "type": "integer", "minimum": 1 },
        "strict":              { "type": "boolean" },
        "configured_complete": { "type": "boolean" },
        "gaps":                { "type": "array", "items": { "type": "string" } },
        "limitations":         { "type": "array", "items": { "type": "string" } },
        "required_analyzers":  { "type": "array", "items": { "type": "string" } },
        "required_gaps":       { "type": "array", "items": { "type": "string" } },
        "retried":             { "type": "array", "items": { "type": "string" } }
      }
    },
```

and inside `ScanMetadata.properties`:

```json
        "scanner_status":    { "type": "array", "items": { "$ref": "#/definitions/ScannerStatus" } },
        "coverage":          { "$ref": "#/definitions/Coverage" },
        "policy_version":    { "type": "string" },
        "release_decision":  { "type": "string", "enum": ["pass", "warn", "block", "incomplete"] },
        "coverage_state":    { "type": "string", "enum": ["complete", "incomplete", "unknown"] },
        "decision_policy_version": { "type": "string" },
        "decision_rationale": { "type": "object" }
```

- [ ] **Step 7: Run the whole reporters package**

Run: `go test -race ./internal/reporters/`
Expected: PASS. If `schema_drift_test.go` fails naming a metadata key, add that key to `docs/schema.json` exactly as the test prints it; the drift test is the guard that struct tags and the published schema agree.

- [ ] **Step 8: Commit**

```bash
git add internal/reporters/coverage.go internal/reporters/coverage_test.go internal/reporters/json.go internal/reporters/schema_test.go docs/schema.json
git commit -m "feat(reporters): coverage contract v1 vocabulary

Adds the closed ScannerReason enumeration, the attempts field on
scanner_status entries, the metadata.coverage block with BuildCoverage,
metadata.policy_version, and the backend passthrough fields a hosted
re-render carries. All additive; schema_version stays 2."
```

---

### Task 2: Analyzer registry and reasoned status recording

**Files:**
- Create: `internal/engine/registry.go`
- Create: `internal/engine/registry_test.go`
- Modify: `internal/engine/scannerstatus.go` (whole file)
- Modify: `internal/engine/scannerstatus_test.go`
- Modify: `internal/engine/orchestrator.go:322-500` (every existing `skip`/`fail` call)
- Modify: `internal/scanner/semgrep/scanner.go:176-181`

**Interfaces:**
- Consumes: `reporters.ScannerReason`, `reporters.ScannerStatus` from Task 1.
- Produces: `engine.Registry []string`; the `Analyzer*` name constants; `IsRegisteredAnalyzer(name string) bool`; `(*scannerStatusList).okDetail(name, detail string)`; `(*scannerStatusList).skip(name string, reason reporters.ScannerReason, detail string)`; `(*scannerStatusList).fail(name string, reason reporters.ScannerReason, err error)`; `(*scannerStatusList).failDetail(name string, reason reporters.ScannerReason, detail string)`; `(*scannerStatusList).set(entry reporters.ScannerStatus)`; `(*scannerStatusList).markAttempts(name string, n int)`; `(scannerStatusList).has(name string) bool`; `(scannerStatusList).sorted() scannerStatusList`; `classifyErr(err error) reporters.ScannerReason` (minimal here, extended in Task 7); `semgrep.ErrTimeout`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/engine/registry_test.go
package engine

import (
	"reflect"
	"testing"
)

func TestRegistry_OrderIsTheContract(t *testing.T) {
	want := []string{
		"dast", "spec", "active-probes", "secrets", "textscan", "semgrep",
		"govulncheck", "pip", "npm", "python-engine",
		"python-engine/auth", "python-engine/injection", "python-engine/deps", "plugins",
	}
	if !reflect.DeepEqual(Registry, want) {
		t.Fatalf("Registry = %v\nwant %v", Registry, want)
	}
}

func TestIsRegisteredAnalyzer(t *testing.T) {
	for _, n := range Registry {
		if !IsRegisteredAnalyzer(n) {
			t.Errorf("%q must be registered", n)
		}
	}
	for _, n := range []string{"", "Semgrep", "python-taint-engine", "python-engine/secrets"} {
		if IsRegisteredAnalyzer(n) {
			t.Errorf("%q must not be registered", n)
		}
	}
}
```

Append to `internal/engine/scannerstatus_test.go`:

```go
func TestScannerStatusList_ReasonedRecording(t *testing.T) {
	var l scannerStatusList
	l.ok("secrets")
	l.skip("semgrep", reporters.ReasonDependencyMissing, "semgrep binary not installed")
	l.fail("pip", reporters.ReasonNetworkError, errors.New("post batch to https://api.osv.dev: connection reset"))
	l.failDetail("dast", reporters.ReasonNoEndpoints, "URL configured, discovery found zero endpoints")
	l.markAttempts("pip", 2)

	if got := l[1]; got.State != reporters.ScannerSkipped || got.Reason != reporters.ReasonDependencyMissing || got.Detail == "" {
		t.Fatalf("skip recorded wrong: %+v", got)
	}
	if got := l[2]; got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonNetworkError || got.Attempts != 2 {
		t.Fatalf("fail/attempts recorded wrong: %+v", got)
	}
	if !l.has("dast") || l.has("npm") {
		t.Fatal("has() must reflect recorded names")
	}
	if !l.hasFailure() {
		t.Fatal("a failed entry must still count as a failure for --fail-on-scanner-error")
	}
}

func TestScannerStatusList_SortedIsRegistryOrder(t *testing.T) {
	var l scannerStatusList
	l.ok("npm")
	l.ok("python-engine/deps")
	l.ok("dast")
	l.ok("python-engine")
	l.ok("secrets")
	l.ok("custom-plugin-thing") // not in the registry: stable, last
	got := l.sorted()
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	want := []string{"dast", "secrets", "npm", "python-engine", "python-engine/deps", "custom-plugin-thing"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("sorted names = %v, want %v", names, want)
	}
}

func TestClassifyErr_MinimalMapping(t *testing.T) {
	if got := classifyErr(context.DeadlineExceeded); got != reporters.ReasonTimeout {
		t.Errorf("deadline → %s, want timeout", got)
	}
	if got := classifyErr(errors.New("boom")); got != reporters.ReasonExecutionError {
		t.Errorf("plain error → %s, want execution_error", got)
	}
	if got := classifyErr(fmt.Errorf("wrap: %w", semgrep.ErrTimeout)); got != reporters.ReasonTimeout {
		t.Errorf("semgrep.ErrTimeout → %s, want timeout", got)
	}
}
```

(Add `"context"`, `"errors"`, `"fmt"`, `"reflect"` and `"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"` to that test file's imports.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ -run 'TestRegistry|TestIsRegisteredAnalyzer|TestScannerStatusList_Reasoned|TestScannerStatusList_Sorted|TestClassifyErr' -v`
Expected: FAIL to compile (`undefined: Registry`, wrong argument count for `skip`).

- [ ] **Step 3: Create `internal/engine/registry.go`**

```go
package engine

// Analyzer names are the coverage contract's stable identities (spec §4.1).
// Registry order is the emission order of scanner_status; a consumer may
// rely on it being byte-identical across runs of the same input.
const (
	AnalyzerDAST            = "dast"
	AnalyzerSpec            = "spec"
	AnalyzerActiveProbes    = "active-probes"
	AnalyzerSecrets         = "secrets"
	AnalyzerTextscan        = "textscan"
	AnalyzerSemgrep         = "semgrep"
	AnalyzerGovulncheck     = "govulncheck"
	AnalyzerPip             = "pip"
	AnalyzerNpm             = "npm"
	AnalyzerPythonEngine    = "python-engine"
	AnalyzerPythonAuth      = "python-engine/auth"
	AnalyzerPythonInjection = "python-engine/injection"
	AnalyzerPythonDeps      = "python-engine/deps"
	AnalyzerPlugins         = "plugins"
)

// Registry is the ordered list of every analyzer a scan records. The first
// ten and "plugins" are emitted on every non-import scan; the three
// python-engine children only when the Python protocol reports them.
var Registry = []string{
	AnalyzerDAST, AnalyzerSpec, AnalyzerActiveProbes,
	AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep,
	AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm,
	AnalyzerPythonEngine, AnalyzerPythonAuth, AnalyzerPythonInjection, AnalyzerPythonDeps,
	AnalyzerPlugins,
}

// BaseAnalyzers are the entries that must appear exactly once on every
// non-import scan (the registry minus the protocol-dependent children).
var BaseAnalyzers = []string{
	AnalyzerDAST, AnalyzerSpec, AnalyzerActiveProbes,
	AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep,
	AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm,
	AnalyzerPythonEngine, AnalyzerPlugins,
}

var registryRank = func() map[string]int {
	m := make(map[string]int, len(Registry))
	for i, n := range Registry {
		m[n] = i
	}
	return m
}()

// IsRegisteredAnalyzer reports whether name is one of the registry names.
// Used to validate --require-analyzers before a scan starts.
func IsRegisteredAnalyzer(name string) bool {
	_, ok := registryRank[name]
	return ok
}
```

- [ ] **Step 4: Rewrite the recording API in `internal/engine/scannerstatus.go`**

Replace lines 22-37 (`ok`, `skip`, `fail`) with:

```go
// ok records a clean run.
func (l *scannerStatusList) ok(name string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerOK})
}

// okDetail records a clean run that carries a note the reader should see
// (for example partial probe responses). The state is still ok.
func (l *scannerStatusList) okDetail(name, detail string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerOK, Detail: truncateDetail(detail)})
}

// skip records an analyzer that did not run, with the closed reason that
// says why. A skip is never a failure; whether it is a coverage gap is
// decided by the reason's class (dependency_missing is, disabled is not).
func (l *scannerStatusList) skip(name string, reason reporters.ScannerReason, detail string) {
	if !reason.IsSkip() {
		panic("scannerStatusList.skip called with a non-skip reason: " + string(reason))
	}
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerSkipped, Reason: reason, Detail: truncateDetail(detail)})
}

// fail records an analyzer that started and did not deliver. The error text
// is truncated to keep the metadata payload bounded.
func (l *scannerStatusList) fail(name string, reason reporters.ScannerReason, err error) {
	l.failDetail(name, reason, truncateErr(err))
}

// failDetail is fail with a hand-written detail (no error value).
func (l *scannerStatusList) failDetail(name string, reason reporters.ScannerReason, detail string) {
	if !reason.IsFail() {
		panic("scannerStatusList.fail called with a non-fail reason: " + string(reason))
	}
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerFailed, Reason: reason, Detail: truncateDetail(detail)})
}

// set appends a fully-formed entry (used for python-engine children, whose
// state and reason arrive over the protocol and are validated there).
func (l *scannerStatusList) set(entry reporters.ScannerStatus) {
	entry.Detail = truncateDetail(entry.Detail)
	*l = append(*l, entry)
}

// markAttempts stamps the in-process retry count on the named entry.
func (l *scannerStatusList) markAttempts(name string, n int) {
	for i := range *l {
		if (*l)[i].Name == name {
			(*l)[i].Attempts = n
			return
		}
	}
}

// has reports whether an entry for name was recorded.
func (l scannerStatusList) has(name string) bool {
	for _, s := range l {
		if s.Name == name {
			return true
		}
	}
	return false
}

// sorted returns a copy in registry order. Names outside the registry keep
// their relative order after every registered name. Stable, so a scan
// renders identically on every run.
func (l scannerStatusList) sorted() scannerStatusList {
	out := make(scannerStatusList, len(l))
	copy(out, l)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := registryRank[out[i].Name]
		rj, jok := registryRank[out[j].Name]
		switch {
		case iok && jok:
			return ri < rj
		case iok:
			return true
		default:
			return false
		}
	})
	return out
}

// truncateDetail bounds a detail string the same way truncateErr does.
func truncateDetail(s string) string {
	const max = 240
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// classifyErr maps an analyzer error to a fail reason. Task 7 extends it
// with transport typing; here only the two deterministic cases exist:
// a context deadline or the semgrep timeout sentinel is a timeout, and
// everything else is an execution error.
func classifyErr(err error) reporters.ScannerReason {
	if err == nil {
		return reporters.ReasonExecutionError
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, semgrep.ErrTimeout) {
		return reporters.ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return reporters.ReasonTimeout
	}
	return reporters.ReasonExecutionError
}
```

Add `"context"`, `"net"`, `"sort"` and `"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"` to the imports. Update `recordDepScanResult` (lines 79-93) and `recordNpmScanResult` (lines 99-131) so every call carries a reason, and so findings gathered before a failure are kept (Rule 3):

```go
func (o *Orchestrator) recordDepScanResult(status *scannerStatusList, name, label string, findings *[]evidence.Evidence, scanFindings []evidence.Evidence, err error) {
	if len(scanFindings) > 0 {
		*findings = append(*findings, scanFindings...)
	}
	switch {
	case err == nil:
		slog.Info(label+" complete", "findings", len(scanFindings))
		status.ok(name)
	case errors.Is(err, pip.ErrNoManifests):
		slog.Debug(label + " found no manifests under code path")
		status.skip(name, reporters.ReasonNotApplicable, "no Python manifest under --code")
	default:
		slog.Warn(label+" failed", "error", err)
		status.fail(name, classifyErr(err), err)
	}
}

func (o *Orchestrator) recordNpmScanResult(status *scannerStatusList, findings *[]evidence.Evidence, npmFindings []evidence.Evidence, err error) []evidence.Evidence {
	if len(npmFindings) > 0 {
		*findings = append(*findings, npmFindings...)
	}
	switch {
	case err == nil:
		slog.Info("native npm deps scan complete", "findings", len(npmFindings))
		status.ok("npm")
	case errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent):
		slog.Info("npm deps scan: package.json present but lock file missing — emitting advisory finding")
		*findings = append(*findings, evidence.Evidence{
			ID:         "SEC-NPM_LOCKFILE_MISSING",
			RuleID:     "scanstatus/npm-lockfile-missing",
			Title:      "npm dep-CVE scan skipped — package-lock.json missing",
			Severity:   models.SeverityInfo,
			Source:     models.SourceWhitebox,
			Category:   "config",
			Endpoint:   filepath.Join(o.cfg.CodePath, "package.json"),
			Evidence:   "package.json was found at the scan root but no package-lock.json. Without the lock file, fendix's npm-audit scanner can't resolve transitive versions and skips the dep-CVE pass.",
			Fix:        "Run `npm install` (or `npm ci`) to materialise package-lock.json, then re-scan. For yarn or pnpm projects this scanner is currently silent; that gap is tracked separately. CWE-1395.",
			References: []string{"https://cwe.mitre.org/data/definitions/1395.html"},
			Confidence: models.ConfidenceHigh,
		})
		status.skip("npm", reporters.ReasonUnsupportedTarget, "package.json without package-lock.json")
	case errors.Is(err, npm.ErrNoLockfile):
		slog.Debug("no package-lock.json at code path, skipping native npm deps scan")
		status.skip("npm", reporters.ReasonNotApplicable, "no package.json under --code")
	default:
		slog.Warn("native npm deps scan failed", "error", err)
		status.fail("npm", classifyErr(err), err)
	}
	return *findings
}
```

`pip.ErrNoManifests` is created in Task 3; until then define it as a placeholder at the top of `internal/scanner/deps/pip/scanner.go`: `var ErrNoManifests = errors.New("pip: no Python manifest under code path")` (Task 3 wires it into the walk).

- [ ] **Step 5: Add the semgrep timeout sentinel**

In `internal/scanner/semgrep/scanner.go`, next to `ErrSemgrepUnavailable`:

```go
// ErrTimeout is wrapped into the error returned when the semgrep process
// exceeds defaultTimeout, so the orchestrator can classify it as a timeout
// rather than a generic execution error.
var ErrTimeout = errors.New("semgrep: timed out")
```

and change line 180 to `return nil, fmt.Errorf("%w after %s", ErrTimeout, defaultTimeout)`.

- [ ] **Step 6: Update every existing call site in `orchestrator.go`**

Mechanical replacements, all inside `Run` (lines 322-500):

| Old | New |
|---|---|
| `scanStatus.skip("secrets", "diff: no changed files")` | `scanStatus.skip(AnalyzerSecrets, reporters.ReasonDiffUnchanged, "diff: no changed files")` |
| `scanStatus.skip("textscan", "diff: no changed files")` | `scanStatus.skip(AnalyzerTextscan, reporters.ReasonDiffUnchanged, "diff: no changed files")` |
| `scanStatus.skip("semgrep", "diff: no changed files")` | `scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDiffUnchanged, "diff: no changed files")` |
| `scanStatus.skip("govulncheck", "offline mode: requires vuln.go.dev")` | `scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonDisabledOffline, "--offline: govulncheck requires vuln.go.dev")` |
| `scanStatus.skip("govulncheck", "diff: go.mod/go.sum unchanged")` | `scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonDiffUnchanged, "diff: go.mod/go.sum unchanged")` |
| `scanStatus.skip("govulncheck", "no go.mod at code path")` | `scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonNotApplicable, "no go.mod under --code")` |
| `scanStatus.fail("govulncheck", err)` | `scanStatus.fail(AnalyzerGovulncheck, classifyErr(err), err)` |
| `scanStatus.skip("pip", "diff: no python manifest changed")` | `scanStatus.skip(AnalyzerPip, reporters.ReasonDiffUnchanged, "diff: no python manifest changed")` |
| `scanStatus.skip("pip", "offline mode: no usable snapshot")` | `scanStatus.skip(AnalyzerPip, reporters.ReasonDependencyMissing, "--offline: no usable snapshot at "+dbPathForLog(o.cfg))` |
| `scanStatus.skip("npm", "diff: no npm manifest changed")` | `scanStatus.skip(AnalyzerNpm, reporters.ReasonDiffUnchanged, "diff: no npm manifest changed")` |
| `scanStatus.skip("npm", "offline mode: no usable snapshot")` | `scanStatus.skip(AnalyzerNpm, reporters.ReasonDependencyMissing, "--offline: no usable snapshot at "+dbPathForLog(o.cfg))` |
| `scanStatus.skip("secrets", "code path missing")` | `scanStatus.fail(AnalyzerSecrets, reporters.ReasonInputError, err)` |
| `scanStatus.fail("secrets", err)` | `scanStatus.fail(AnalyzerSecrets, classifyErr(err), err)` |
| `scanStatus.skip("semgrep", "semgrep binary not installed")` | `scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDependencyMissing, "semgrep binary not installed")` |
| `scanStatus.skip("semgrep", "code path missing")` | `scanStatus.fail(AnalyzerSemgrep, reporters.ReasonInputError, err)` |
| `scanStatus.fail("semgrep", err)` | `scanStatus.fail(AnalyzerSemgrep, classifyErr(err), err)` |
| `scanStatus.fail("textscan", err)` | `scanStatus.fail(AnalyzerTextscan, classifyErr(err), err)` |

Add the helper next to `absPathOrEmpty`:

```go
// dbPathForLog names the offline snapshot path a skip detail refers to.
func dbPathForLog(cfg *models.ScanConfig) string {
	if cfg.OfflineDBPath != "" {
		return cfg.OfflineDBPath
	}
	return offline.DefaultDBPath()
}
```

- [ ] **Step 7: Fix the existing tests that used the old signatures**

`internal/engine/scannerstatus_test.go` lines 13-28 and 92-106 call `skip(name, detail)` and `fail(name, err)`. Update them to `skip(name, reporters.ReasonNotApplicable, detail)` and `fail(name, reporters.ReasonExecutionError, err)`. In `TestRecordNpmScanResult_LockfileMissingIsSkip` assert `Reason == reporters.ReasonUnsupportedTarget`. `offline_failopen_test.go:112-114` and `:146-155` assert only `State`; they keep passing.

- [ ] **Step 8: Run the engine and semgrep packages**

Run: `go test -race ./internal/engine/ ./internal/scanner/semgrep/`
Expected: PASS. `checksrun_test.go` is unchanged and still passes because `codeScannerLabels` reads only `State`.

- [ ] **Step 9: Commit**

```bash
git add internal/engine/registry.go internal/engine/registry_test.go internal/engine/scannerstatus.go internal/engine/scannerstatus_test.go internal/engine/orchestrator.go internal/scanner/semgrep/scanner.go internal/scanner/deps/pip/scanner.go
git commit -m "feat(engine): analyzer registry and reasoned scanner_status recording

Every existing skip/fail call site now carries a closed reason; entries
sort in registry order; a failed dependency scan keeps the findings it
gathered before failing. Adds semgrep.ErrTimeout so a timeout is typed
rather than read from prose."
```

---

### Task 3: Every code analyzer records exactly once

**Files:**
- Modify: `internal/engine/orchestrator.go:255-500` (gates around the dependency, secrets, semgrep and textscan blocks)
- Modify: `internal/scanner/deps/pip/scanner.go:330-348` (`ErrNoManifests` from the walk), `:235-260` (offline walk)
- Create: `internal/engine/coverage_test.go`

**Interfaces:**
- Consumes: Task 2's recording API and constants.
- Produces: `pip.ErrNoManifests` returned by `ScanRecursiveWithOptions` and `ScanOffline` when the walk finds no manifest; `(*Orchestrator).validateCodePath() error`; the invariant that every base code analyzer has one entry whenever `Run` renders a report.

- [ ] **Step 1: Write the failing property test**

```go
// internal/engine/coverage_test.go
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// codeAnalyzers are the base entries every --code scan must record once.
var codeAnalyzers = []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm, AnalyzerPythonEngine, AnalyzerPlugins}

func writeCodeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint(os.environ.get('X'))\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func countByName(report reporters.JSONReport) map[string]int {
	counts := map[string]int{}
	for _, s := range report.Metadata.ScannerStatus {
		counts[s.Name]++
	}
	return counts
}

// TestOrchestrator_CodeAnalyzersRecordedExactlyOnce is the registry
// invariant (spec §10): whatever the flag combination, each base code
// analyzer appears exactly once, with a reason when not ok. Offline mode
// with no snapshot keeps the dependency scanners off the network.
func TestOrchestrator_CodeAnalyzersRecordedExactlyOnce(t *testing.T) {
	dir := writeCodeDir(t)
	for _, tc := range []struct {
		name string
		mut  func(cfg *models.ScanConfig)
	}{
		{"default", func(cfg *models.ScanConfig) {}},
		{"fast", func(cfg *models.ScanConfig) { cfg.Fast = true }},
		{"no-native-deps", func(cfg *models.ScanConfig) { cfg.NoNativeDeps = true }},
		{"no-plugins", func(cfg *models.ScanConfig) { cfg.NoPlugins = true }},
		{"python-engine-off", func(cfg *models.ScanConfig) { cfg.PythonEngine = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.json")
			cfg := &models.ScanConfig{
				CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
				Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"),
			}
			tc.mut(cfg)
			if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
				t.Fatalf("exit %d, want 0 (no strict flags set)", code)
			}
			counts := countByName(readReport(t, out))
			for _, name := range codeAnalyzers {
				if counts[name] != 1 {
					t.Errorf("%s recorded %d times, want exactly 1 (entries: %v)", name, counts[name], counts)
				}
			}
			for _, s := range readReport(t, out).Metadata.ScannerStatus {
				if s.State != reporters.ScannerOK && !s.Reason.Valid() {
					t.Errorf("%s is %s without a valid reason", s.Name, s.State)
				}
				if s.State == reporters.ScannerOK && s.Reason != "" {
					t.Errorf("%s is ok but carries reason %q", s.Name, s.Reason)
				}
			}
		})
	}
}

func TestOrchestrator_FastAndNoNativeDepsRecordDisabled(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: true}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	for _, name := range []string{AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
		s, ok := statusFor(report, name)
		if !ok || s.State != reporters.ScannerSkipped || s.Reason != reporters.ReasonDisabledByFlag {
			t.Errorf("%s under --fast = %+v, want skipped/disabled_by_flag", name, s)
		}
	}
}

func TestOrchestrator_PipNoManifestIsNotApplicable(t *testing.T) {
	dir := writeCodeDir(t) // has app.py, no requirements.txt
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	s, ok := statusFor(readReport(t, out), AnalyzerPip)
	if !ok || s.State != reporters.ScannerSkipped || s.Reason != reporters.ReasonNotApplicable {
		t.Fatalf("pip with no manifest = %+v, want skipped/not_applicable (was ok before the contract)", s)
	}
}

func TestOrchestrator_UnreadableCodePathIsInputErrorEverywhere(t *testing.T) {
	file := filepath.Join(t.TempDir(), "code.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: file, Workers: 1, Timeout: 5, Format: "json", OutputPath: out}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d, want 0: input_error changes recording, not the default exit", code)
	}
	report := readReport(t, out)
	for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
		s, ok := statusFor(report, name)
		if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonInputError {
			t.Errorf("%s = %+v, want failed/input_error", name, s)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ -run 'TestOrchestrator_CodeAnalyzersRecordedExactlyOnce|TestOrchestrator_FastAndNoNativeDeps|TestOrchestrator_PipNoManifest|TestOrchestrator_UnreadableCodePath' -v`
Expected: FAIL — missing entries under `fast`, `pip` recorded `ok` with no manifest, secrets `failed/execution_error` instead of `input_error`.

- [ ] **Step 3: Return `ErrNoManifests` from the pip walks**

In `internal/scanner/deps/pip/scanner.go`, keep the `ErrNoManifests` var from Task 2 and change both "no manifests" returns:

```go
	if len(manifests) == 0 {
		return nil, ErrNoManifests
	}
```

at line ~345 (`scanViaOSV`) and at the equivalent point in `ScanOffline` (line ~258, after `findRequirementsManifests`). The pip-audit path (`scanViaPipAudit`) gets the same change where it walks manifests. Update `scanner_offline_test.go` / `scanner_test.go` cases that asserted an empty slice on a manifest-less directory to assert `errors.Is(err, ErrNoManifests)`.

- [ ] **Step 4: Validate the code path once and add the else branches**

In `orchestrator.go`, immediately after `var scanStatus scannerStatusList` (line 266):

```go
	// Validate --code once. An unreadable path is an input error for every
	// code analyzer (spec §4.4), recorded identically so a consumer sees one
	// cause, not six different scanner-specific messages.
	codeConfigured := o.cfg.CodePath != ""
	var codeErr error
	if codeConfigured {
		codeErr = o.validateCodePath()
		if codeErr != nil {
			slog.Error("--code is not a readable directory", "path", o.cfg.CodePath, "error", codeErr)
			for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
				scanStatus.fail(name, reporters.ReasonInputError, codeErr)
			}
		}
	}
	codeUsable := codeConfigured && codeErr == nil
```

and add the method next to `absPathOrEmpty`:

```go
// validateCodePath reports why --code cannot be scanned: missing, not a
// directory, or unreadable. nil means every code analyzer may walk it.
func (o *Orchestrator) validateCodePath() error {
	info, err := os.Stat(o.cfg.CodePath)
	if err != nil {
		return fmt.Errorf("code path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("code path %q is not a directory", o.cfg.CodePath)
	}
	if _, err := os.ReadDir(o.cfg.CodePath); err != nil {
		return fmt.Errorf("code path: %w", err)
	}
	return nil
}
```

Then rewrite the four gates so each has an explicit else branch. Dependency block (replace the condition at line 343 and add the else):

```go
	switch {
	case !codeConfigured:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonNotApplicable, "no --code")
		}
	case !codeUsable:
		// already recorded input_error above
	case o.cfg.Fast:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonDisabledByFlag, "--fast")
		}
	case o.cfg.NoNativeDeps:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonDisabledByFlag, "--no-native-deps")
		}
	default:
		// ... existing govulncheck / pip / npm body, unchanged apart from Task 2's reasons ...
	}
```

Secrets (line 441) becomes:

```go
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerSecrets, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
	case diffEmpty:
		// recorded diff_unchanged above
	default:
		// ... existing secrets body ...
	}
```

Semgrep (line 466):

```go
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerSemgrep, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
	case o.cfg.Fast:
		scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDisabledByFlag, "--fast")
	case diffEmpty:
	default:
		// ... existing semgrep body ...
	}
```

Textscan (line 489):

```go
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerTextscan, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
	case diffEmpty:
	default:
		// ... existing textscan body ...
	}
```

The diff short-circuit at line 320 must not record `semgrep` twice: it already guards with `if !o.cfg.Fast`; keep that, and in the semgrep switch above the `o.cfg.Fast` case comes before `diffEmpty`, so a fast diff-empty run records semgrep once as disabled.

For `python-engine` and `plugins`, record placeholders now so the property test passes; Tasks 4 and 5 replace them with the real logic:

```go
	if !scanStatus.has(AnalyzerPythonEngine) {
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonNotApplicable, "recorded in Task 5")
	}
	if !scanStatus.has(AnalyzerPlugins) {
		scanStatus.skip(AnalyzerPlugins, reporters.ReasonNotApplicable, "recorded in Task 4")
	}
```

(Place both immediately before `scanMode` is computed, line ~565. They are removed in Tasks 4–5.)

Finally, sort before building metadata: change `ScannerStatus: []reporters.ScannerStatus(scanStatus),` (line ~601) to `ScannerStatus: []reporters.ScannerStatus(scanStatus.sorted()),`.

- [ ] **Step 5: Run the tests**

Run: `go test -race ./internal/engine/ ./internal/scanner/deps/pip/`
Expected: PASS. `TestOrchestrator_FailOnScannerError` still passes: the regular-file code path now records `secrets` as `failed/input_error`, which is still `failed` for the flag.

- [ ] **Step 6: Commit**

```bash
git add internal/engine/orchestrator.go internal/engine/coverage_test.go internal/scanner/deps/pip/
git commit -m "feat(engine): every code analyzer records exactly once

--fast and --no-native-deps now record disabled_by_flag instead of
leaving no entry; an absent manifest is not_applicable instead of ok; an
unreadable --code is input_error on every code analyzer, validated once."
```

---

### Task 4: Discovery, spec, active probes and plugins join the registry; zero endpoints emit a report

**Files:**
- Modify: `internal/scanner/crawler.go:85-100` (struct), `:150-156` (spec branch)
- Modify: `internal/engine/orchestrator.go:190-230` (discovery), `:1057-1135` (`runPlugins`), and the exit path (`:680-700`)
- Create: `internal/engine/discovery_status_test.go`

**Interfaces:**
- Consumes: Task 2 API.
- Produces: `scanner.Crawler.SpecErr error`; `type checkPhaseOutcome struct{Attempted, NoResponse int; Rejected int64; Deadline bool}`; `summarizeCheckPhase(ctx context.Context, records []scanner.ProbeRecord, sent, rejected int64) checkPhaseOutcome`; `recordBlackbox(status *scannerStatusList, cfg *models.ScanConfig, endpoints int, discoveryErr, specErr error, phase checkPhaseOutcome)`; `pluginOutcome{Discovered int; Failed []string; DiscoverErr error}` returned by `runPlugins`; `Run` renders a report before returning `2` for zero endpoints or a discovery error.

**Why the check pass is observable.** Every active check records each probe it sends in the scan-wide probe audit log (`scanner.GlobalAuditRecords()`; `injection.go` through `auditLog.Record`, the other six through `cc.Audit.Record`, which alias the same log). A `ProbeRecord` with `Status == 0` is a probe that got no HTTP response. The `--max-requests` budget counts refused requests (`budget.Stats()`), and a `--max-duration` cut leaves `ctx.Err() == context.DeadlineExceeded`. Those three signals are the aggregate execution outcome; `ok` is recorded only after the pool has returned and none of them says the pass was cut short or got nothing back.

- [ ] **Step 1: Write the failing tests**

```go
// internal/engine/discovery_status_test.go
package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
)

func find(l scannerStatusList, name string) reporters.ScannerStatus {
	for _, s := range l {
		if s.Name == name {
			return s
		}
	}
	return reporters.ScannerStatus{}
}

func TestRecordBlackbox_Table(t *testing.T) {
	url := models.ScanConfig{URL: "http://t"}
	active := models.ScanConfig{URL: "http://t", EnableActive: true}
	for _, tc := range []struct {
		name         string
		cfg          models.ScanConfig
		endpoints    int
		discoveryErr error
		specErr      error
		phase        checkPhaseOutcome
		wantDAST     [2]string // state, reason
		wantSpec     [2]string
		wantProbes   [2]string
	}{
		{"code only", models.ScanConfig{CodePath: "x"}, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"url with endpoints, passive only", url, 3, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"url zero endpoints", url, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"failed", "no_endpoints"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"discovery error", url, 0, errors.New("dns"), nil, checkPhaseOutcome{},
			[2]string{"failed", "execution_error"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"spec parsed", models.ScanConfig{URL: "http://t", SpecPath: "s.yaml"}, 2, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"ok", ""}, [2]string{"skipped", "disabled_by_flag"}},
		{"spec parse failure", models.ScanConfig{URL: "http://t", SpecPath: "s.yaml"}, 2, nil, errors.New("yaml: bad"), checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"failed", "input_error"}, [2]string{"skipped", "disabled_by_flag"}},
		{"active, probes completed with responses", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"ok", ""}},
		{"active, some probes got no response", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 3},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"ok", ""}},
		{"active, no probe got any response", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 40},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "network_error"}},
		{"active, nothing probe-eligible", active, 2, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}},
		{"active without endpoints", active, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"failed", "no_endpoints"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}},
		{"request budget exhausted mid-pass", active, 2, nil, nil, checkPhaseOutcome{Attempted: 10, Rejected: 25},
			[2]string{"failed", "execution_error"}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "execution_error"}},
		{"duration cap hit mid-pass", active, 2, nil, nil, checkPhaseOutcome{Attempted: 10, Deadline: true},
			[2]string{"failed", "timeout"}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "timeout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l scannerStatusList
			recordBlackbox(&l, &tc.cfg, tc.endpoints, tc.discoveryErr, tc.specErr, tc.phase)
			check := func(name string, want [2]string) {
				got := find(l, name)
				if string(got.State) != want[0] || string(got.Reason) != want[1] {
					t.Errorf("%s = %s/%s, want %s/%s", name, got.State, got.Reason, want[0], want[1])
				}
			}
			check(AnalyzerDAST, tc.wantDAST)
			check(AnalyzerSpec, tc.wantSpec)
			check(AnalyzerActiveProbes, tc.wantProbes)
		})
	}
	// Partial probe failures stay visible in the detail of an ok entry.
	var l scannerStatusList
	recordBlackbox(&l, &active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 3})
	if got := find(l, AnalyzerActiveProbes); !strings.Contains(got.Detail, "3 of 40") {
		t.Fatalf("partial failures must be named in detail, got %+v", got)
	}
}

func TestSummarizeCheckPhase(t *testing.T) {
	records := []scanner.ProbeRecord{{Status: 200}, {Status: 0}, {Status: 500}, {Status: 0}}
	got := summarizeCheckPhase(context.Background(), records, 120, 0)
	if got.Attempted != 4 || got.NoResponse != 2 || got.Rejected != 0 || got.Deadline {
		t.Fatalf("phase = %+v", got)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := summarizeCheckPhase(ctx, nil, 10, 5); !got.Deadline || got.Rejected != 5 {
		t.Fatalf("deadline/rejected not captured: %+v", got)
	}
}

// A URL that accepts and immediately closes every connection yields zero
// endpoints. Before the contract that was exit 2 with no report; now the
// report is written first and exit 2 is kept.
func TestOrchestrator_ZeroEndpointsWritesReportThenExits2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{URL: "http://" + ln.Addr().String(), AllowPrivate: true, Workers: 1, Timeout: 1, CrawlDepth: 0, Format: "json", OutputPath: out}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 2 {
		t.Fatalf("exit %d, want 2 (unchanged CLI contract)", code)
	}
	report := readReport(t, out)
	s, ok := statusFor(report, AnalyzerDAST)
	if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonNoEndpoints {
		t.Fatalf("dast = %+v, want failed/no_endpoints", s)
	}
	if report.Metadata.Coverage == nil || report.Metadata.Coverage.ConfiguredComplete {
		t.Fatalf("coverage must be present and incomplete, got %+v", report.Metadata.Coverage)
	}
}

func TestRunPlugins_OutcomeRecorded(t *testing.T) {
	// No plugin roots exist in a temp HOME: not_applicable, never ok.
	t.Setenv("HOME", t.TempDir())
	var l scannerStatusList
	o := &Orchestrator{cfg: &models.ScanConfig{CodePath: t.TempDir()}}
	_, outcome := o.runPlugins(context.Background())
	recordPlugins(&l, o.cfg, outcome)
	if got := find(l, AnalyzerPlugins); got.State != reporters.ScannerSkipped || got.Reason != reporters.ReasonNotApplicable {
		t.Fatalf("plugins with none configured = %+v, want skipped/not_applicable", got)
	}
	l = nil
	recordPlugins(&l, &models.ScanConfig{NoPlugins: true}, pluginOutcome{})
	if got := find(l, AnalyzerPlugins); got.Reason != reporters.ReasonDisabledByFlag {
		t.Fatalf("--no-plugins = %+v, want disabled_by_flag", got)
	}
	l = nil
	recordPlugins(&l, &models.ScanConfig{}, pluginOutcome{Discovered: 2, Failed: []string{"custom-secret"}})
	if got := find(l, AnalyzerPlugins); got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError || got.Detail == "" {
		t.Fatalf("plugin failure = %+v, want failed/execution_error naming the plugin", got)
	}
}
```

Note: `report.Metadata.Coverage` is populated in Task 9; until then the zero-endpoint test asserts only exit code and the `dast` entry — comment out the coverage assertion and restore it in Task 9, Step 6.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ -run 'TestRecordDiscovery|TestOrchestrator_ZeroEndpoints|TestRunPlugins_Outcome' -v`
Expected: FAIL to compile (`undefined: recordBlackbox`, `undefined: checkPhaseOutcome`, `runPlugins` returns one value).

- [ ] **Step 3: Expose the spec parse failure on the crawler**

In `internal/scanner/crawler.go`, add to the struct after `Discovered`:

```go
	// SpecErr is the error fromSpec returned, when --spec was given and the
	// document could not be parsed. Discovery continues with the other
	// strategies (unchanged), but the orchestrator reads this to record the
	// `spec` analyzer as failed/input_error instead of leaving a silent WARN.
	SpecErr error
```

and in `CrawlEndpoints` change the spec branch to:

```go
	if c.cfg.SpecPath != "" {
		specEndpoints, err := c.fromSpec(ctx)
		if err != nil {
			c.SpecErr = err
			slog.Warn("spec parsing failed, continuing with other strategies", "error", err)
		} else {
			endpoints = append(endpoints, specEndpoints...)
		}
	}
```

- [ ] **Step 4: Record dast, spec and active-probes from what the check pass did; render before exit 2**

In `orchestrator.go` replace lines 197-224 (discovery through the zero-endpoint exit) with:

```go
	// 1. Discover endpoints. A hard discovery failure and a zero-endpoint
	// result both used to exit 2 before any report existed; the coverage
	// contract needs the evidence, so both now record `dast` and render the
	// report first. The exit code is unchanged (hardExit below).
	crawler := scanner.NewCrawler(o.cfg)
	endpoints, discoveryErr := crawler.CrawlEndpoints(ctx)
	if discoveryErr != nil {
		slog.Error("endpoint discovery failed — check --url is reachable and --spec is valid YAML/JSON", "error", discoveryErr)
		endpoints = nil
	}

	budget.Reset()
	budget.SetMaxRequests(o.cfg.MaxRequests)
	budget.SetCancelFunc(cancelBudget)

	hardExit := 0
	if discoveryErr != nil {
		hardExit = 2
	}
	if len(endpoints) == 0 && o.cfg.CodePath == "" {
		slog.Warn("no endpoints discovered — nothing to scan")
		fmt.Fprintln(os.Stderr, "fendix: no endpoints discovered. Provide --url, --spec, or --code.")
		hardExit = 2
	}
	if len(endpoints) > 0 {
		slog.Info("scanning endpoints", "count", len(endpoints))
	}
```

Immediately after `var scanStatus scannerStatusList` (which sits after `evid := pool.RunEvidence(...)`, so the check pass has finished; and before the code-path validation from Task 3) add:

```go
	// The black-box entries describe what the check pass did, not what was
	// configured: budget.Stats() covers the check phase because Reset() ran
	// after discovery, and the probe audit log holds every active probe sent.
	sent, rejected := budget.Stats()
	recordBlackbox(&scanStatus, o.cfg, len(endpoints), discoveryErr, crawler.SpecErr,
		summarizeCheckPhase(ctx, scanner.GlobalAuditRecords(), sent, rejected))
```

Add the pure functions next to `absPathOrEmpty`:

```go
// checkPhaseOutcome is what the black-box check pass observably did: how
// many active probes were sent, how many got no HTTP response at all, how
// many requests the --max-requests budget refused, and whether the
// --max-duration deadline cut the pass short.
type checkPhaseOutcome struct {
	Attempted  int
	NoResponse int
	Rejected   int64
	Deadline   bool
}

// summarizeCheckPhase derives the outcome from the probe audit log (every
// active check records each probe it sends; Status 0 means no HTTP response
// came back), the budget counters, and the context.
func summarizeCheckPhase(ctx context.Context, records []scanner.ProbeRecord, sent, rejected int64) checkPhaseOutcome {
	out := checkPhaseOutcome{Attempted: len(records), Rejected: rejected, Deadline: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	for _, r := range records {
		if r.Status == 0 {
			out.NoResponse++
		}
	}
	_ = sent // reported in the budget summary line; not a coverage signal on its own
	return out
}

// recordBlackbox records dast, spec and active-probes (spec §4.4) once the
// check pass has finished. `ok` means the pass ran to completion: nothing
// cut it short and, for probes, at least one probe got an HTTP response.
func recordBlackbox(status *scannerStatusList, cfg *models.ScanConfig, endpoints int, discoveryErr, specErr error, phase checkPhaseOutcome) {
	switch {
	case cfg.URL == "":
		status.skip(AnalyzerDAST, reporters.ReasonNotApplicable, "no --url")
	case discoveryErr != nil:
		status.fail(AnalyzerDAST, classifyErr(discoveryErr), discoveryErr)
	case endpoints == 0:
		status.failDetail(AnalyzerDAST, reporters.ReasonNoEndpoints, "URL configured, discovery found zero endpoints")
	case phase.Deadline:
		status.failDetail(AnalyzerDAST, reporters.ReasonTimeout, "--max-duration elapsed before the check pass completed")
	case phase.Rejected > 0:
		status.failDetail(AnalyzerDAST, reporters.ReasonExecutionError, fmt.Sprintf("--max-requests exhausted: %d requests refused before the check pass completed", phase.Rejected))
	default:
		status.ok(AnalyzerDAST)
	}
	switch {
	case cfg.SpecPath == "":
		status.skip(AnalyzerSpec, reporters.ReasonNotApplicable, "no --spec")
	case specErr != nil:
		status.fail(AnalyzerSpec, reporters.ReasonInputError, specErr)
	default:
		status.ok(AnalyzerSpec)
	}
	switch {
	case !cfg.EnableActive:
		status.skip(AnalyzerActiveProbes, reporters.ReasonDisabledByFlag, "--enable-active not set")
	case endpoints == 0:
		status.skip(AnalyzerActiveProbes, reporters.ReasonNotApplicable, "no endpoints to probe")
	case phase.Deadline:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonTimeout, "--max-duration elapsed before the probe pass completed")
	case phase.Rejected > 0:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonExecutionError, fmt.Sprintf("--max-requests exhausted: %d requests refused before the probe pass completed", phase.Rejected))
	case phase.Attempted == 0:
		status.skip(AnalyzerActiveProbes, reporters.ReasonNotApplicable, "no probe-eligible parameters on the discovered endpoints")
	case phase.NoResponse == phase.Attempted:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonNetworkError, fmt.Sprintf("%d probe requests sent, none received an HTTP response", phase.Attempted))
	case phase.NoResponse > 0:
		status.okDetail(AnalyzerActiveProbes, fmt.Sprintf("%d of %d probe requests received no HTTP response", phase.NoResponse, phase.Attempted))
	default:
		status.ok(AnalyzerActiveProbes)
	}
}
```

`classifyErr(discoveryErr)` yields `execution_error` for ordinary errors and `timeout` for a deadline. The `dast` entry shares the budget and deadline rules: a check pass cut short by `--max-requests` or `--max-duration` did not deliver the coverage that was configured, whatever the operator's reason for the cap, and the entry says so. Before wiring, confirm every active check writes to the audit log — `grep -c 'Audit.Record\|auditLog.Record' internal/scanner/{injection,ssrf,xss,openredirect,hostheader,graphql,methodtamper}.go` must be non-zero for all seven — and add `"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"` to the orchestrator's imports if it is not already there.

Then, at the exit path, insert before `return decision.ExitCode(decisions)` (after the `--fail-on-scanner-error` block):

```go
	if hardExit != 0 {
		return hardExit
	}
```

- [ ] **Step 5: Make `runPlugins` report an outcome**

Change the signature and the body's error handling:

```go
// pluginOutcome is what runPlugins observed, for the `plugins` entry.
type pluginOutcome struct {
	Discovered  int
	Failed      []string
	DiscoverErr error
}

func (o *Orchestrator) runPlugins(ctx context.Context) ([]evidence.Evidence, pluginOutcome) {
	var outcome pluginOutcome
	cwd, _ := os.Getwd()
	roots := plugin.DefaultRoots(cwd, o.cfg.AllowRepoLocalPlugins)
	plugins, err := plugin.Discover(roots)
	if err != nil {
		slog.Warn("plugin discovery failed", "error", err)
		outcome.DiscoverErr = err
		return nil, outcome
	}
	outcome.Discovered = len(plugins)
	if len(plugins) == 0 {
		return nil, outcome
	}
	// ... existing loop unchanged, except inside `if err != nil {` after
	// `slog.Warn("plugin failed (continuing)", ...)` add:
	//     outcome.Failed = append(outcome.Failed, p.Name)
	return evidence.FromFindings(out), outcome
}

// recordPlugins records the aggregate plugins entry.
func recordPlugins(status *scannerStatusList, cfg *models.ScanConfig, outcome pluginOutcome) {
	switch {
	case cfg.NoPlugins:
		status.skip(AnalyzerPlugins, reporters.ReasonDisabledByFlag, "--no-plugins")
	case outcome.DiscoverErr != nil:
		status.fail(AnalyzerPlugins, reporters.ReasonExecutionError, outcome.DiscoverErr)
	case outcome.Discovered == 0:
		status.skip(AnalyzerPlugins, reporters.ReasonNotApplicable, "no plugins configured")
	case len(outcome.Failed) > 0:
		status.failDetail(AnalyzerPlugins, reporters.ReasonExecutionError, "plugin(s) failed: "+strings.Join(outcome.Failed, ", "))
	default:
		status.ok(AnalyzerPlugins)
	}
}
```

Replace the call at line 528-530 with:

```go
	var pluginsOut pluginOutcome
	if !o.cfg.NoPlugins {
		var pluginEvid []evidence.Evidence
		pluginEvid, pluginsOut = o.runPlugins(ctx)
		evid = append(evid, pluginEvid...)
	}
	recordPlugins(&scanStatus, o.cfg, pluginsOut)
```

and delete the Task 3 placeholder for `plugins`.

- [ ] **Step 6: Run the tests**

Run: `go test -race ./internal/engine/ ./internal/scanner/`
Expected: PASS. If an existing test asserted that a zero-endpoint run produces no output file, update it to assert the file exists and the exit is 2; the changelog entry in Task 12 records this as "Changed".

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/crawler.go internal/engine/orchestrator.go internal/engine/discovery_status_test.go
git commit -m "feat(engine): record dast, spec, active-probes and plugins; report before exit 2

Zero endpoints and discovery failures now render the report (dast recorded
failed/no_endpoints or failed/execution_error) and keep exit 2. Spec parse
failures surface as spec failed/input_error instead of a WARN. Plugins get
one aggregate entry."
```

---

### Task 5: Python engine outcome, status lines and total reconciliation (Go side)

**Files:**
- Modify: `internal/engine/spawner.go:37-73` (types), `:74-153` (`Run`), `:155-211` (`readFindings`)
- Modify: `internal/engine/orchestrator.go:40-100` (`engineMissing`), `:504-521` (python block), `:1156-1195` (`runWhiteboxScan`)
- Modify: `internal/engine/spawner_test.go`
- Modify: `internal/engine/coverage_test.go` (remove the Task 3 placeholder expectation)

**Interfaces:**
- Consumes: Task 2 recording API; `CheckPython`, `EnsureEngine` (unchanged).
- Produces: `type SpawnOutcome int` with `SpawnOK, SpawnExitError, SpawnMalformed, SpawnTruncated, SpawnCancelled, SpawnStartError`; `type CheckStatus struct{Check, State, Reason, Detail string}`; `DoneMessage.Protocol int`; `SpawnResult{Findings []models.Finding; Total int; Protocol int; Err error; Outcome SpawnOutcome; Checks []CheckStatus; Malformed int; SawDone bool}`; `type streamResult struct{...}` returned by `readFindings(io.Reader) streamResult`; `var expectedPythonChecks = []string{"auth", "injection", "deps"}`; `childProtocolError(checks []CheckStatus) error`; `missingPythonChecks(checks []CheckStatus) []string`; `(*Orchestrator).runWhiteboxScan(ctx) ([]evidence.Evidence, SpawnResult)`; `recordPythonEngine(status *scannerStatusList, res SpawnResult)`; `Orchestrator.engineMissing error`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/engine/spawner_test.go` (the file already writes fake `engine.py` scripts into a temp dir and runs them with `python3`; reuse its helper that writes the script, or add this one):

```go
func writeFakeEngine(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "engine.py"), []byte("import json, sys\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadFindings_StatusLinesAreNotFindings(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"status": {"check": "auth", "state": "skipped", "reason": "not_applicable", "detail": "no spec supplied"}}`,
		`{"title": "SQLi", "severity": "HIGH", "category": "injection", "endpoint": "app.py:3"}`,
		`{"status": {"check": "injection", "state": "ok"}}`,
		`{"status": {"check": "deps", "state": "skipped", "reason": "dependency_missing", "detail": "No module named 'packaging'"}}`,
		`{"done": true, "total": 1, "protocol": 2}`,
	}, "\n"))
	sr := readFindings(in)
	if len(sr.findings) != 1 || sr.doneTotal != 1 || !sr.sawDone || sr.malformed != 0 || sr.protocol != 2 {
		t.Fatalf("unexpected stream result: %+v", sr)
	}
	if len(sr.checks) != 3 || sr.checks[0].Check != "auth" || sr.checks[0].Reason != "not_applicable" || sr.checks[1].State != "ok" || sr.checks[2].Detail == "" {
		t.Fatalf("status lines not parsed: %+v", sr.checks)
	}
}

func TestReadFindings_MissingDoneAndMalformedCounted(t *testing.T) {
	sr := readFindings(strings.NewReader(`{"title": "x", "severity": "LOW"}` + "\n" + `this is not json` + "\n"))
	if sr.sawDone || sr.malformed != 1 || len(sr.findings) != 1 {
		t.Fatalf("unexpected: %+v", sr)
	}
}

func TestSpawner_OutcomeClassification(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	finding := `{"title": "SQLi", "severity": "HIGH", "category": "injection", "endpoint": "app.py:3"}`
	for _, tc := range []struct {
		name string
		body string
		want SpawnOutcome
	}{
		{"ok", "print('" + finding + "', flush=True)\nprint(json.dumps({'done': True, 'total': 1}), flush=True)\n", SpawnOK},
		{"truncated: no done", "print('" + finding + "', flush=True)\n", SpawnTruncated},
		{"truncated: total mismatch", "print('" + finding + "', flush=True)\nprint(json.dumps({'done': True, 'total': 5}), flush=True)\n", SpawnTruncated},
		{"malformed line", "print('not json at all', flush=True)\nprint(json.dumps({'done': True, 'total': 0}), flush=True)\n", SpawnMalformed},
		{"exit error wins over done", "print(json.dumps({'done': True, 'total': 0}), flush=True)\nsys.exit(3)\n", SpawnExitError},
		{"done.error", "print(json.dumps({'done': True, 'total': 0, 'error': 'boom'}), flush=True)\n", SpawnExitError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFakeEngine(t, tc.body)
			res := NewPythonSpawner("python3", dir).Run(context.Background(), ScanRequest{Mode: "whitebox", Checks: []string{"injection"}})
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %v (err=%v), want %v", res.Outcome, res.Err, tc.want)
			}
			if tc.want != SpawnOK && res.Err == nil {
				t.Fatal("a non-ok outcome must carry an error")
			}
		})
	}
}

func TestSpawner_ProtocolV2ChildCompleteness(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	st := func(check, state string) string {
		return "print(json.dumps({'status': {'check': '" + check + "', 'state': '" + state + "'}}), flush=True)\n"
	}
	done := "print(json.dumps({'done': True, 'total': 0, 'protocol': 2}), flush=True)\n"
	legacyDone := "print(json.dumps({'done': True, 'total': 0}), flush=True)\n"
	for _, tc := range []struct {
		name       string
		body       string
		want       SpawnOutcome
		wantChecks int
	}{
		{"all three exactly once", st("auth", "ok") + st("injection", "ok") + st("deps", "ok") + done, SpawnOK, 3},
		{"missing one is truncated", st("auth", "ok") + st("deps", "ok") + done, SpawnTruncated, 2},
		{"duplicate is malformed", st("auth", "ok") + st("injection", "ok") + st("injection", "ok") + st("deps", "ok") + done, SpawnMalformed, 4},
		{"unknown child is malformed", st("auth", "ok") + st("injection", "ok") + st("deps", "ok") + st("secrets", "ok") + done, SpawnMalformed, 4},
		{"legacy stream: children ignored, parent ok", st("auth", "ok") + legacyDone, SpawnOK, 0},
		{"legacy stream without any status lines", legacyDone, SpawnOK, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFakeEngine(t, tc.body)
			res := NewPythonSpawner("python3", dir).Run(context.Background(), ScanRequest{Mode: "whitebox", Checks: []string{"auth", "injection", "deps"}})
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %v (err=%v), want %v", res.Outcome, res.Err, tc.want)
			}
			if len(res.Checks) != tc.wantChecks {
				t.Fatalf("checks kept = %d, want %d: %+v", len(res.Checks), tc.wantChecks, res.Checks)
			}
		})
	}
}

func TestRecordPythonEngine_ChildrenParticipateParentStaysOK(t *testing.T) {
	var l scannerStatusList
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: []CheckStatus{
		{Check: "auth", State: "skipped", Reason: "not_applicable", Detail: "no spec supplied"},
		{Check: "injection", State: "ok"},
		{Check: "deps", State: "skipped", Reason: "dependency_missing", Detail: "No module named 'packaging'"},
	}})
	if got := find(l, AnalyzerPythonEngine); got.State != reporters.ScannerOK {
		t.Fatalf("parent = %+v, want ok", got)
	}
	if got := find(l, AnalyzerPythonDeps); got.Reason != reporters.ReasonDependencyMissing {
		t.Fatalf("deps child = %+v, want dependency_missing", got)
	}
	if n := len(l); n != 4 {
		t.Fatalf("expected parent + 3 children, got %d entries: %+v", n, l)
	}

	l = nil
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: []CheckStatus{{Check: "injection", State: "failed", Reason: "not_applicable"}}})
	if got := find(l, AnalyzerPythonInjection); got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonMalformedOutput {
		t.Fatalf("mismatched pairing must be recorded as failed/malformed_output, got %+v", got)
	}

	l = nil
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnTruncated, Protocol: 2, Err: errors.New("python engine (protocol 2) omitted status for: deps"),
		Checks: []CheckStatus{{Check: "auth", State: "ok"}, {Check: "injection", State: "ok"}}})
	if got := find(l, AnalyzerPythonEngine); got.Reason != reporters.ReasonTruncatedOutput {
		t.Fatalf("missing child → parent %+v, want truncated_output", got)
	}
	if !l.has(AnalyzerPythonAuth) || l.has(AnalyzerPythonDeps) {
		t.Fatal("reported children are kept; the missing one has no entry — the parent failure carries the gap")
	}
}

Add `"errors"`, `"os"`, `"os/exec"`, `"path/filepath"`, `"strings"` and the `reporters` import to the test file as needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ -run 'TestReadFindings|TestSpawner_Outcome|TestSpawner_ProtocolV2|TestRecordPythonEngine' -v`
Expected: FAIL to compile (`readFindings` returns three values; `SpawnOutcome` undefined).

- [ ] **Step 3: Rewrite the spawner types and reader**

In `internal/engine/spawner.go` replace `DoneMessage` through `SpawnResult` with:

```go
// DoneMessage is the terminal JSON line from the Python engine. Protocol
// is the version the Python side declares; absent (0) or 1 means a legacy
// tree whose status lines, if any, are ignored. 2 means one status line per
// expected check is mandatory and verified.
type DoneMessage struct {
	Done     bool   `json:"done"`
	Total    int    `json:"total"`
	Error    string `json:"error,omitempty"`
	Protocol int    `json:"protocol,omitempty"`
}

// expectedPythonChecks is the set a protocol-v2 Python engine must report
// exactly once each. Adding a check to engine.py means adding it here and
// to the registry in the same change.
var expectedPythonChecks = []string{"auth", "injection", "deps"}

// CheckStatus is one `{"status": {...}}` protocol line (protocol v2): the
// Python engine's own report of one check's outcome. State and Reason use
// the coverage contract's vocabulary and are validated by the caller.
type CheckStatus struct {
	Check  string `json:"check"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// SpawnOutcome classifies how the Python engine run ended, in the order the
// coverage contract ranks them: an exit error outranks malformed output,
// which outranks a truncated stream.
type SpawnOutcome int

const (
	SpawnOK         SpawnOutcome = iota
	SpawnStartError              // process could not be started
	SpawnExitError               // non-zero exit, or a done line carrying error
	SpawnMalformed               // at least one unparseable or shape-invalid line
	SpawnTruncated               // no done line, or done.total != findings received
	SpawnCancelled               // context cancelled
)

// SpawnResult is what the caller learns about one engine run. Findings are
// always returned, whatever the outcome (Rule 3).
type SpawnResult struct {
	Findings  []models.Finding
	Total     int
	Protocol  int
	Err       error
	Outcome   SpawnOutcome
	Checks    []CheckStatus
	Malformed int
	SawDone   bool
}

// streamResult is readFindings' raw observation of the stdout stream.
type streamResult struct {
	findings  []models.Finding
	doneTotal int
	protocol  int
	sawDone   bool
	doneErr   string
	malformed int
	checks    []CheckStatus
	readErr   error
}
```

In `Run`, replace from `// Read streaming findings from stdout` to the end of the function with:

```go
	sr := readFindings(stdout)
	waitErr := cmd.Wait()

	duration := time.Since(startTime)
	slog.Info("python engine finished",
		"duration", duration.Round(time.Millisecond),
		"findings", len(sr.findings),
		"exit_code", cmd.ProcessState.ExitCode(),
		"status_lines", len(sr.checks),
	)
	if stderrStr := stderrBuf.String(); stderrStr != "" {
		for _, line := range strings.Split(strings.TrimSpace(stderrStr), "\n") {
			slog.Debug("python engine stderr", "line", line)
		}
	}

	res := SpawnResult{Findings: sr.findings, Total: sr.doneTotal, Protocol: sr.protocol, Checks: sr.checks, Malformed: sr.malformed, SawDone: sr.sawDone}
	if sr.protocol < 2 {
		// A legacy tree made no completeness promise; only the parent entry
		// is meaningful, so any stray status lines are dropped.
		res.Checks = nil
	}
	childErr := error(nil)
	if sr.protocol >= 2 {
		childErr = childProtocolError(sr.checks)
	}
	switch {
	case ctx.Err() != nil:
		res.Outcome, res.Err = SpawnCancelled, ctx.Err()
	case waitErr != nil:
		res.Outcome, res.Err = SpawnExitError, fmt.Errorf("python engine exited with error: %w", waitErr)
	case sr.doneErr != "":
		res.Outcome, res.Err = SpawnExitError, fmt.Errorf("python engine error: %s", sr.doneErr)
	case sr.readErr != nil:
		res.Outcome, res.Err = SpawnMalformed, fmt.Errorf("reading python output: %w", sr.readErr)
	case sr.malformed > 0:
		res.Outcome, res.Err = SpawnMalformed, fmt.Errorf("%d unparseable line(s) from python engine", sr.malformed)
	case !sr.sawDone:
		res.Outcome, res.Err = SpawnTruncated, fmt.Errorf("python engine stream ended without a done line (%d findings received)", len(sr.findings))
	case childErr != nil:
		res.Outcome, res.Err = SpawnMalformed, childErr
	case sr.protocol >= 2 && len(missingPythonChecks(sr.checks)) > 0:
		res.Outcome, res.Err = SpawnTruncated, fmt.Errorf("python engine (protocol %d) omitted status for: %s", sr.protocol, strings.Join(missingPythonChecks(sr.checks), ", "))
	case sr.doneTotal != len(sr.findings):
		res.Outcome, res.Err = SpawnTruncated, fmt.Errorf("python engine reported %d findings, received %d", sr.doneTotal, len(sr.findings))
	default:
		res.Outcome = SpawnOK
	}
	return res
}

// readFindings reads the NDJSON stream: finding lines, optional
// `{"status": {...}}` lines (protocol v2), and the terminal done line. It
// never returns early on a bad line — every line is observed so the
// caller can classify the whole stream.
func readFindings(r io.Reader) streamResult {
	var sr streamResult
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var probe struct {
			Status json.RawMessage `json:"status"`
			Done   bool            `json:"done"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			sr.malformed++
			logagg.Warn("python_engine", "skipping malformed line from python", "error", err, "line", line)
			continue
		}
		if probe.Done {
			var done DoneMessage
			_ = json.Unmarshal([]byte(line), &done)
			sr.sawDone, sr.doneTotal, sr.doneErr, sr.protocol = true, done.Total, done.Error, done.Protocol
			continue
		}
		// A status line's `status` is an object; a finding's `status` (its
		// decision) is a string, so the first byte tells them apart.
		if len(probe.Status) > 0 && probe.Status[0] == '{' {
			var sl struct {
				Status CheckStatus `json:"status"`
			}
			if err := json.Unmarshal([]byte(line), &sl); err != nil || sl.Status.Check == "" {
				sr.malformed++
				continue
			}
			sr.checks = append(sr.checks, sl.Status)
			continue
		}
		var finding models.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			sr.malformed++
			logagg.Warn("python_engine", "skipping malformed finding JSON from python", "error", err, "line", line)
			continue
		}
		if finding.Title == "" || finding.Severity == "" {
			sr.malformed++
			logagg.Warn("python_engine", "skipping finding with missing required fields", "line", line)
			continue
		}
		if finding.Source == "" {
			finding.Source = models.SourceWhitebox
		}
		sr.findings = append(sr.findings, finding)
	}
	if err := scanner.Err(); err != nil {
		sr.readErr = fmt.Errorf("scanning stdout: %w", err)
	}
	return sr
}

// childProtocolError returns the first protocol violation among status
// lines under protocol v2: an unknown check identity or a duplicate check.
func childProtocolError(checks []CheckStatus) error {
	seen := map[string]bool{}
	for _, c := range checks {
		if !IsRegisteredAnalyzer(AnalyzerPythonEngine + "/" + c.Check) {
			return fmt.Errorf("python engine reported unknown check %q", c.Check)
		}
		if seen[c.Check] {
			return fmt.Errorf("python engine reported check %q twice", c.Check)
		}
		seen[c.Check] = true
	}
	return nil
}

// missingPythonChecks lists expected checks with no status line.
func missingPythonChecks(checks []CheckStatus) []string {
	seen := map[string]bool{}
	for _, c := range checks {
		seen[c.Check] = true
	}
	var missing []string
	for _, want := range expectedPythonChecks {
		if !seen[want] {
			missing = append(missing, want)
		}
	}
	return missing
}
```

Also in `Run`, the three early `return SpawnResult{Err: ...}` sites before `cmd.Start()` and the `cmd.Start()` failure become `return SpawnResult{Outcome: SpawnStartError, Err: ...}`.

- [ ] **Step 4: Remember why the engine is missing, and map the outcome in the orchestrator**

In `orchestrator.go` add the field after `engineErr`:

```go
	// engineMissing records why EnsureEngine could not resolve the Python
	// tree, on the explicit AND the implicit path. Read when recording the
	// python-engine entry so an implicit --code scan without a tree is a
	// visible dependency_missing rather than a stderr line.
	engineMissing error
```

In `NewOrchestrator`, inside `if err != nil {` add `engineMissing = err` (declare `var engineMissing error` next to `engineErr`) and pass `engineMissing: engineMissing,` in the struct literal.

Replace the python block (lines 504-521) with:

```go
	// 4. Python whitebox engine — registry entry python-engine plus the
	// children the protocol reports (spec §4.4, §5.4).
	switch {
	case !o.cfg.PythonEngine && !codeConfigured && o.cfg.SpecPath == "":
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonNotApplicable, "no --code or --spec")
	case !o.cfg.PythonEngine:
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonDisabledByFlag, "--python-engine=false")
	case !codeConfigured && o.cfg.SpecPath == "":
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonNotApplicable, "no --code or --spec")
	case codeConfigured && !codeUsable && o.cfg.SpecPath == "":
		scanStatus.fail(AnalyzerPythonEngine, reporters.ReasonInputError, codeErr)
	case o.engineMissing != nil:
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonDependencyMissing, "engine tree not found: "+o.engineMissing.Error())
	default:
		pyStatus := CheckPython(o.spawner.pythonBin)
		if !pyStatus.Available {
			slog.Warn("python not available — skipping whitebox analysis")
			fmt.Fprintln(os.Stderr, "fendix: "+PythonRequiredMessage())
			scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonDependencyMissing, "python3 interpreter not found ("+pyStatus.Binary+")")
		} else {
			slog.Info("python available", "version", pyStatus.Version, "binary", pyStatus.Binary)
			bundle.SetPythonVersion(pyStatus.Version)
			wbFindings, result := o.runWhiteboxScan(ctx)
			evid = append(evid, wbFindings...)
			recordPythonEngine(&scanStatus, result)
		}
	}
```

and delete the Task 3 placeholder for `python-engine`. Change `runWhiteboxScan` to return the result as well:

```go
func (o *Orchestrator) runWhiteboxScan(ctx context.Context) ([]evidence.Evidence, SpawnResult) {
	// ... unchanged request construction ...
	result := o.spawner.Run(ctx, req)
	if result.Err != nil {
		slog.Error("python engine did not complete cleanly — findings received so far are kept", "outcome", result.Outcome, "error", result.Err)
	} else {
		slog.Info("whitebox scan complete", "findings", len(result.Findings))
	}
	return evidence.FromFindings(result.Findings), result
}
```

Add next to `recordBlackbox`:

```go
// recordPythonEngine maps a spawn outcome onto the python-engine entry and
// records each protocol-v2 status line as a child entry. The spawner has
// already enforced completeness (one line per expected check, no unknown
// checks); this function validates the state/reason pairing and keeps the
// parent's process semantics separate from any child's final state.
func recordPythonEngine(status *scannerStatusList, res SpawnResult) {
	switch res.Outcome {
	case SpawnOK:
		status.ok(AnalyzerPythonEngine)
	case SpawnMalformed:
		status.fail(AnalyzerPythonEngine, reporters.ReasonMalformedOutput, res.Err)
	case SpawnTruncated:
		status.fail(AnalyzerPythonEngine, reporters.ReasonTruncatedOutput, res.Err)
	default: // SpawnStartError, SpawnExitError, SpawnCancelled
		status.fail(AnalyzerPythonEngine, reporters.ReasonExecutionError, res.Err)
	}
	for _, c := range res.Checks {
		name := AnalyzerPythonEngine + "/" + c.Check
		if !IsRegisteredAnalyzer(name) || status.has(name) {
			continue // unreachable after spawner validation; defensive only
		}
		entry := reporters.ScannerStatus{Name: name, State: reporters.ScannerStatusState(c.State), Reason: reporters.ScannerReason(c.Reason), Detail: c.Detail}
		valid := (entry.State == reporters.ScannerOK && entry.Reason == "") ||
			(entry.State == reporters.ScannerSkipped && entry.Reason.IsSkip()) ||
			(entry.State == reporters.ScannerFailed && entry.Reason.IsFail())
		if !valid {
			entry = reporters.ScannerStatus{Name: name, State: reporters.ScannerFailed, Reason: reporters.ReasonMalformedOutput,
				Detail: fmt.Sprintf("invalid status line: state=%q reason=%q", c.State, c.Reason)}
		}
		status.set(entry)
	}
}
```

- [ ] **Step 5: Run the engine package**

Run: `go test -race ./internal/engine/`
Expected: PASS. `TestOrchestrator_CodeAnalyzersRecordedExactlyOnce` now sees `python-engine` as `skipped/disabled_by_flag` (config built directly, `PythonEngine` false) — still exactly once. Existing spawner tests that read `result.Total` and `result.Err` keep passing; the one that fed a stream without a done line and expected `Err == nil` must now expect `Outcome == SpawnTruncated` — update it.

- [ ] **Step 6: Commit**

```bash
git add internal/engine/spawner.go internal/engine/spawner_test.go internal/engine/orchestrator.go
git commit -m "feat(engine): python-engine joins scanner_status with protocol v2 status lines

The spawn outcome is classified (exit error > malformed > truncated,
done.total reconciled against findings received) and recorded as the
python-engine entry. Under protocol v2 (declared on the done line) exactly
one status line per expected check is required: a duplicate or unknown
check is malformed_output, a missing one is truncated_output; legacy trees
stay parent-only. A missing interpreter or engine
tree is dependency_missing instead of a stderr line."
```

---

### Task 6: Python engine emits status lines

**Files:**
- Modify: `python/engine.py:27-52` (`_run_check`), `:112-142` (dispatch)
- Modify: `python/analyzers/ast_analyzer.py:100-145` (file counts)
- Modify: `python/tests/test_engine_contract.py`
- Modify: `docs/adr/ADR-002-ndjson-ipc.md` (protocol v2 addendum)

**Interfaces:**
- Produces: `PROTOCOL_VERSION = 2` in `engine.py`; exactly one `{"status": {"check": <auth|injection|deps>, "state": ..., "reason"?: ..., "detail"?: ...}}` line per check, before the done line; the done line declares `"protocol": 2`; `ASTAnalyzer.file_stats = {"python": int, "javascript": int}` after `run`.

- [ ] **Step 1: Write the failing tests**

Append to `python/tests/test_engine_contract.py`:

```python
import importlib.util


def _statuses(objects: list[dict]) -> dict[str, dict]:
    return {o["status"]["check"]: o["status"] for o in objects if isinstance(o.get("status"), dict)}


def _load_engine_module():
    spec = importlib.util.spec_from_file_location("fendix_engine_under_test", ENGINE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_status_lines_for_every_check_even_when_none_run() -> None:
    result = _run({"mode": "whitebox", "checks": [], "verbose": False})
    objects = _parse_output(result)
    statuses = _statuses(objects)
    assert set(statuses) == {"auth", "injection", "deps"}
    for s in statuses.values():
        assert s["state"] == "skipped"
        assert s["reason"] == "disabled_by_flag"
    assert objects[-1]["protocol"] == 2


def test_exactly_one_status_line_per_check() -> None:
    result = _run({"mode": "whitebox", "checks": ["auth", "injection", "deps"], "code_path": "/nonexistent"})
    lines = [o["status"]["check"] for o in _parse_output(result) if isinstance(o.get("status"), dict)]
    assert sorted(lines) == ["auth", "deps", "injection"]


def test_status_not_applicable_when_input_missing() -> None:
    result = _run({"mode": "whitebox", "checks": ["auth", "injection", "deps"], "verbose": False})
    statuses = _statuses(_parse_output(result))
    assert statuses["auth"]["reason"] == "not_applicable"
    assert statuses["injection"]["reason"] == "not_applicable"
    assert statuses["deps"]["reason"] == "not_applicable"


def test_done_total_ignores_status_lines() -> None:
    result = _run({"mode": "whitebox", "checks": ["injection"], "code_path": "/nonexistent"})
    objects = _parse_output(result)
    findings = [o for o in objects if "title" in o]
    assert objects[-1]["done"] is True
    assert objects[-1]["total"] == len(findings)


def test_injection_ok_on_python_and_unsupported_on_js_only() -> None:
    with tempfile.TemporaryDirectory() as py_dir, tempfile.TemporaryDirectory() as js_dir:
        Path(py_dir, "app.py").write_text("import os\nx = os.environ.get('X')\n")
        Path(js_dir, "app.js").write_text("const x = 1;\n")
        py = _statuses(_parse_output(_run({"mode": "whitebox", "checks": ["injection"], "code_path": py_dir})))
        js = _statuses(_parse_output(_run({"mode": "whitebox", "checks": ["injection"], "code_path": js_dir})))
    assert py["injection"]["state"] == "ok"
    assert js["injection"]["state"] == "skipped"
    assert js["injection"]["reason"] == "unsupported_target"
    assert "JavaScript" in js["injection"]["detail"]


def test_run_check_classifies_import_error_and_exception(capsys) -> None:
    engine = _load_engine_module()

    def missing() -> None:
        raise ImportError("No module named 'packaging'")

    def broken() -> None:
        raise ValueError("bad spec")

    assert engine._run_check("deps", "deps", missing, False) == ("skipped", "dependency_missing", "No module named 'packaging'")
    state, reason, detail = engine._run_check("auth", "auth (spec)", broken, False)
    assert (state, reason) == ("failed", "execution_error")
    assert detail == "ValueError: bad spec"
    assert engine._run_check("injection", "injection (ast)", lambda: None, False) == ("ok", None, None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest python/tests/test_engine_contract.py -v -k "status or run_check or injection_ok"`
Expected: FAIL — no status lines, `_run_check` returns None. If `pytest` is not installed locally, `pip install pytest` in a venv or rely on the CI job; do not skip the step.

- [ ] **Step 3: Implement status lines in `python/engine.py`**

Replace `_run_check` and the dispatch section (lines 27-52 and 112-142) with:

```python
from typing import Callable, Optional, Tuple

StatusTuple = Tuple[str, Optional[str], Optional[str]]


PROTOCOL_VERSION = 2  # declared on the done line; the Go side verifies one status per check


def _status(check: str, state: str, reason: Optional[str] = None, detail: Optional[str] = None) -> None:
    """Emit one protocol-v2 status line: the Go side records it as the
    python-engine/<check> entry. Never a finding, never counted in total."""
    payload: dict = {"check": check, "state": state}
    if reason:
        payload["reason"] = reason
    if detail:
        payload["detail"] = detail
    print(json.dumps({"status": payload}), flush=True)


def _run_check(check: str, label: str, fn: Callable[[], None], verbose: bool) -> StatusTuple:
    """Run a single check and classify its outcome for the status line.

    ImportError is a missing optional dependency (skipped/dependency_missing);
    any other exception is an execution error. Importing inside `fn` is what
    keeps one missing package from killing the whole engine.
    """
    try:
        if verbose:
            _log(f"starting check: {label}")
        fn()
        if verbose:
            _log(f"finished check: {label}")
        return ("ok", None, None)
    except ImportError as exc:
        _log(f"check '{label}' skipped: missing dependency ({exc}). Install python/requirements.txt to enable it.")
        return ("skipped", "dependency_missing", str(exc))
    except Exception as exc:  # noqa: BLE001
        _log(f"check '{label}' failed: {exc}")
        return ("failed", "execution_error", f"{type(exc).__name__}: {exc}")


def _injection_support(stats: dict) -> StatusTuple:
    """Taint analysis applies to Python only. A JavaScript-only tree got
    pattern checks, not dataflow — say so with unsupported_target."""
    py = int(stats.get("python", 0))
    js = int(stats.get("javascript", 0))
    if py == 0 and js > 0:
        return ("skipped", "unsupported_target", f"{js} JavaScript/TypeScript file(s): pattern checks ran, taint analysis does not apply")
    if js > 0:
        return ("ok", None, f"{js} JavaScript/TypeScript file(s) got pattern checks only; taint analysis covered {py} Python file(s)")
    return ("ok", None, None)
```

and in `main()`:

```python
    injection_stats: dict = {}

    def _run_spec_auth() -> None:
        from analyzers.spec_parser import SpecParser

        SpecParser(spec_path).check_auth(emit_finding)

    def _run_injection() -> None:
        from analyzers.ast_analyzer import ASTAnalyzer

        analyzer = ASTAnalyzer(code_path, language or "python")
        analyzer.run(emit_finding)
        injection_stats.update(getattr(analyzer, "file_stats", {}))

    def _run_deps() -> None:
        from analyzers.deps import DepsAnalyzer

        DepsAnalyzer(code_path).run(emit_finding)

    for check_id, needs_input, missing_detail, label, fn in (
        ("auth", spec_path, "no spec supplied", "auth (spec)", _run_spec_auth),
        ("injection", code_path, "no code_path supplied", "injection (ast)", _run_injection),
        ("deps", code_path, "no code_path supplied", "deps", _run_deps),
    ):
        if check_id not in checks:
            _status(check_id, "skipped", "disabled_by_flag", "not in checks")
            continue
        if not needs_input:
            _status(check_id, "skipped", "not_applicable", missing_detail)
            continue
        state, reason, detail = _run_check(check_id, label, fn, verbose)
        if check_id == "injection" and state == "ok":
            state, reason, detail = _injection_support(injection_stats)
        _status(check_id, state, reason, detail)

    if verbose:
        _log(f"engine completed {counter} findings")

    print(json.dumps({"done": True, "total": counter, "protocol": PROTOCOL_VERSION}), flush=True)
```

Keep the existing `secrets`/`semgrep` notice block above the loop unchanged. The loop is the completeness guarantee: every expected check produces exactly one status line on every path, including "not in checks" and "input missing".

- [ ] **Step 4: Count files per language in `ast_analyzer.py`**

In `ASTAnalyzer.__init__` add `self.file_stats = {"python": 0, "javascript": 0}`. In `run`, inside the walk:

```python
                if fpath.suffix == ".py":
                    self.file_stats["python"] += 1
                    self._analyze_python(fpath, rel, emit_fn)
                elif fpath.suffix in {".js", ".ts", ".jsx", ".tsx"}:
                    self.file_stats["javascript"] += 1
                    self._analyze_js_heuristic(fpath, rel, emit_fn)
```

- [ ] **Step 5: Run the Python tests**

Run: `python3 -m pytest python/tests/ -v`
Expected: PASS, including `test_engine_done_total_matches_finding_count` (status lines carry neither `id` nor `title`, so its filter still counts only findings).

- [ ] **Step 6: Document protocol v2 in ADR-002**

Append to `docs/adr/ADR-002-ndjson-ipc.md`:

```markdown
## Addendum (coverage contract v1, engine v3.4.0): status lines

The stream gains one optional line type, emitted once per check before the
done line:

    {"status": {"check": "injection", "state": "ok"}}
    {"status": {"check": "deps", "state": "skipped", "reason": "dependency_missing", "detail": "No module named 'packaging'"}}

`state` ∈ `ok|skipped|failed`; `reason` is the coverage contract's closed
enumeration (see `docs/schema.md`); a status line is never a finding and is
never counted in `done.total`. The done line declares the protocol:
`{"done": true, "total": N, "protocol": 2}`. Under protocol 2 the Go side
requires exactly one status line for each of `auth`, `injection`, `deps`: a
duplicate or an unknown check is a protocol violation recorded on the parent
as `failed/malformed_output`; a missing check is recorded on the parent as
`failed/truncated_output`. Reported children are recorded as
`python-engine/<check>` entries with their state/reason pairing validated
(an invalid pairing is `failed/malformed_output` for that child). A done
line without `protocol`, or with a value below 2, is a legacy tree: its
status lines are ignored and only the parent entry is recorded. An older Go
binary logs status lines and ignores them. `done.total` is reconciled
against the findings received: a mismatch records the parent as
`failed/truncated_output`.
```

- [ ] **Step 7: Commit**

```bash
git add python/engine.py python/analyzers/ast_analyzer.py python/tests/test_engine_contract.py docs/adr/ADR-002-ndjson-ipc.md
git commit -m "feat(python-engine): emit a status line per check (protocol v2)

Each of auth/injection/deps reports ok, skipped (disabled_by_flag,
not_applicable, dependency_missing, unsupported_target) or failed
(execution_error). A JavaScript-only tree is reported as
unsupported_target for taint analysis instead of a silent ok."
```

---

### Task 7: Typed transport errors in the dependency scanners

**Files:**
- Create: `internal/scanner/deps/neterr/neterr.go`
- Create: `internal/scanner/deps/neterr/neterr_test.go`
- Modify: `internal/scanner/deps/pip/scanner.go` (`OSVBaseURL`, status errors, lookup accounting in `Scan`, `scanViaOSV`, `runBatchOrFallback`, `runSerialFallback`)
- Modify: `internal/scanner/deps/npm/scanner.go` (same four places)
- Modify: `internal/scanner/deps/govulncheck/scanner.go:75-81`
- Modify: `internal/engine/scannerstatus.go` (`classifyErr`)
- Modify: existing pip/npm tests that reference `osvAPIBase`

**Interfaces:**
- Produces: `neterr.Kind` (`KindOther`, `KindNetwork`, `KindTimeout`); `neterr.StatusError{Host string; Code int}` with `Transient() bool`; `neterr.LookupError{Scanner string; Failed, Total int; Cause error}` with `Unwrap()`; `neterr.ErrSubprocessNetwork`, `neterr.ErrSubprocessTimeout`; `neterr.Classify(err error) Kind`; `neterr.ClassifyText(stderr string) Kind`; `pip.OSVBaseURL`, `npm.OSVBaseURL` (exported, test-overridable); `classifyErr` now returns `network_error` for `KindNetwork`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/scanner/deps/neterr/neterr_test.go
package neterr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want Kind
	}{
		{"nil", nil, KindOther},
		{"plain", errors.New("boom"), KindOther},
		{"deadline", context.DeadlineExceeded, KindTimeout},
		{"net timeout", timeoutErr{}, KindTimeout},
		{"url error wrapping refused", &url.Error{Op: "Post", URL: "https://api.osv.dev", Err: syscall.ECONNREFUSED}, KindNetwork},
		{"dns", &net.DNSError{Err: "no such host", Name: "api.osv.dev"}, KindNetwork},
		{"reset wrapped", fmt.Errorf("post batch: %w", syscall.ECONNRESET), KindNetwork},
		{"503", fmt.Errorf("osv batch: %w", &StatusError{Host: "https://api.osv.dev", Code: 503}), KindNetwork},
		{"429", &StatusError{Host: "h", Code: 429}, KindNetwork},
		{"404 is not transient", &StatusError{Host: "h", Code: 404}, KindOther},
		{"lookup error unwraps", &LookupError{Scanner: "pip", Failed: 3, Total: 3, Cause: &StatusError{Host: "h", Code: 502}}, KindNetwork},
		{"subprocess network sentinel", fmt.Errorf("govulncheck: %w", ErrSubprocessNetwork), KindNetwork},
		{"subprocess timeout sentinel", fmt.Errorf("govulncheck: %w", ErrSubprocessTimeout), KindTimeout},
	} {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("%s: Classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClassifyText(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Kind
	}{
		{"Get \"https://vuln.go.dev/index/db.json\": dial tcp: lookup vuln.go.dev: no such host", KindNetwork},
		{"dial tcp 1.2.3.4:443: connect: connection refused", KindNetwork},
		{"read tcp: connection reset by peer", KindNetwork},
		{"tls: handshake failure", KindNetwork},
		{"context deadline exceeded (Client.Timeout exceeded while awaiting headers)", KindTimeout},
		{"i/o timeout", KindTimeout},
		{"govulncheck: package x: no Go files", KindOther},
		{"", KindOther},
	} {
		if got := ClassifyText(tc.in); got != tc.want {
			t.Errorf("%q: ClassifyText = %v, want %v", tc.in, got, tc.want)
		}
	}
}
```

Add to `internal/scanner/deps/pip/scanner_total_failure_test.go` (replacing the tolerant assertion with the new contract):

```go
func TestScanViaOSV_TotalFailureIsLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1\nrequests==2.25.0\n")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	var le *neterr.LookupError
	if !errors.As(err, &le) {
		t.Fatalf("expected *neterr.LookupError, got %v", err)
	}
	if le.Failed != 2 || le.Total != 2 || neterr.Classify(err) != neterr.KindNetwork {
		t.Fatalf("lookup error = %+v (kind %v)", le, neterr.Classify(err))
	}
	if len(findings) != 0 {
		t.Fatalf("no lookup succeeded, expected no findings, got %d", len(findings))
	}
}

func TestScanViaOSV_BatchFailsSerialSucceedsIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/querybatch") {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns": []}`))
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())
	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1\n")
	if _, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth); err != nil {
		t.Fatalf("serial fallback covered every package, expected nil error, got %v", err)
	}
}
```

Mirror the two tests in `internal/scanner/deps/npm/scanner_batch_test.go` using its `newFakeOSVBatchServer` helper style with a `package-lock.json` fixture (one resolved package), asserting `*neterr.LookupError` on total failure and `nil` when serial succeeds.

For govulncheck, extract the wrapping into a pure function and test it:

```go
// internal/scanner/deps/govulncheck/scanner_test.go (append)
func TestClassifyRunErr(t *testing.T) {
	base := errors.New("exit status 1")
	if err := classifyRunErr(base, "Get \"https://vuln.go.dev/index/db.json\": dial tcp: lookup vuln.go.dev: no such host"); neterr.Classify(err) != neterr.KindNetwork {
		t.Fatalf("dns failure must classify as network, got %v", err)
	}
	if err := classifyRunErr(base, "context deadline exceeded"); neterr.Classify(err) != neterr.KindTimeout {
		t.Fatalf("deadline must classify as timeout, got %v", err)
	}
	if err := classifyRunErr(base, "package ./...: no Go files"); neterr.Classify(err) != neterr.KindOther {
		t.Fatalf("tool error must stay other, got %v", err)
	}
}
```

And in `internal/engine/scannerstatus_test.go`, extend `TestClassifyErr_MinimalMapping`:

```go
	if got := classifyErr(&neterr.LookupError{Scanner: "pip", Failed: 1, Total: 1, Cause: &neterr.StatusError{Host: "h", Code: 503}}); got != reporters.ReasonNetworkError {
		t.Errorf("lookup 503 → %s, want network_error", got)
	}
	if got := classifyErr(&neterr.StatusError{Host: "h", Code: 404}); got != reporters.ReasonExecutionError {
		t.Errorf("404 → %s, want execution_error (never transient)", got)
	}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/deps/... ./internal/engine/ -run 'TestClassify|TestScanViaOSV_Total|TestScanViaOSV_Batch|TestClassifyErr' -v`
Expected: FAIL to compile (`neterr` package missing, `OSVBaseURL` undefined).

- [ ] **Step 3: Create the `neterr` package**

```go
// internal/scanner/deps/neterr/neterr.go
// Package neterr types the transport failures the dependency scanners see
// so the orchestrator can classify them as network_error or timeout
// without reading error prose. Only the govulncheck subprocess, whose
// library returns untyped errors, falls back to a fixed list of Go's own
// net error wordings (ClassifyText) — an engine-internal transport hint,
// never a contract value.
package neterr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// Kind is the transport classification of an error.
type Kind int

const (
	KindOther Kind = iota
	KindNetwork
	KindTimeout
)

func (k Kind) String() string {
	switch k {
	case KindNetwork:
		return "network"
	case KindTimeout:
		return "timeout"
	}
	return "other"
}

// StatusError is a non-2xx answer from a vulnerability database. 5xx and
// 429 are transient (the service, not the request, is the problem); every
// other status is a request-side fact and is never retried.
type StatusError struct {
	Host string
	Code int
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s returned HTTP %d", e.Host, e.Code) }

// Transient reports whether the status is worth one retry.
func (e *StatusError) Transient() bool { return e.Code == 429 || e.Code >= 500 }

// LookupError reports that some package lookups failed after every
// fallback. Findings for the packages that did resolve are still returned
// by the scanner alongside this error (Rule 3); the coverage entry says
// the pass did not deliver.
type LookupError struct {
	Scanner string
	Failed  int
	Total   int
	Cause   error
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("%s: %d of %d package lookups failed: %v", e.Scanner, e.Failed, e.Total, e.Cause)
}

func (e *LookupError) Unwrap() error { return e.Cause }

// Sentinels a subprocess-based scanner wraps after typing its stderr.
var (
	ErrSubprocessNetwork = errors.New("network failure reported by subprocess")
	ErrSubprocessTimeout = errors.New("timeout reported by subprocess")
)

// Classify types err by unwrapping to a known transport error.
func Classify(err error) Kind {
	if err == nil {
		return KindOther
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSubprocessTimeout) {
		return KindTimeout
	}
	if errors.Is(err, ErrSubprocessNetwork) {
		return KindNetwork
	}
	var se *StatusError
	if errors.As(err, &se) {
		if se.Transient() {
			return KindNetwork
		}
		return KindOther
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return KindTimeout
		}
		return KindNetwork
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return KindNetwork
	}
	var rhe tls.RecordHeaderError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &rhe) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) {
		return KindNetwork
	}
	return KindOther
}

// textNetworkMarkers are Go's own net/http and net wordings for transport
// failures, used only to type a subprocess's stderr.
var textNetworkMarkers = []string{
	"dial tcp", "no such host", "connection refused", "connection reset",
	"network is unreachable", "no route to host", "tls: ", "tls handshake",
	"temporary failure in name resolution", "server misbehaving",
	" 502", " 503", " 504", " 429",
}

// ClassifyText types a subprocess's stderr.
func ClassifyText(stderr string) Kind {
	l := strings.ToLower(stderr)
	if l == "" {
		return KindOther
	}
	if strings.Contains(l, "i/o timeout") || strings.Contains(l, "deadline exceeded") || strings.Contains(l, "timeout exceeded") {
		return KindTimeout
	}
	for _, m := range textNetworkMarkers {
		if strings.Contains(l, m) {
			return KindNetwork
		}
	}
	return KindOther
}
```

- [ ] **Step 4: Type the OSV client errors and account for failed lookups (pip)**

In `internal/scanner/deps/pip/scanner.go`:

1. Rename `var osvAPIBase = "https://api.osv.dev"` to `var OSVBaseURL = "https://api.osv.dev"` with the comment `// OSVBaseURL is the OSV API base; tests point it at an httptest server.` and update every reference in the package and its tests.
2. In `queryOSVBatch`, replace `return nil, fmt.Errorf("osv batch returned %d: %s", resp.StatusCode, snippet)` with `return nil, fmt.Errorf("osv batch: %w: %s", &neterr.StatusError{Host: OSVBaseURL, Code: resp.StatusCode}, snippet)`. Do the same in `queryOSV`'s non-2xx branch (line ~930).
3. Add the accumulator:

```go
// lookupFailures counts packages whose lookup failed after every fallback,
// keeping the last cause for classification. Safe for concurrent chunks.
type lookupFailures struct {
	mu     sync.Mutex
	failed int
	last   error
}

func (l *lookupFailures) note(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed++
	l.last = err
}

func (l *lookupFailures) err(scanner string, total int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed == 0 {
		return nil
	}
	return &neterr.LookupError{Scanner: scanner, Failed: l.failed, Total: total, Cause: l.last}
}
```

4. Thread `lf *lookupFailures` through `runBatchOrFallback(ctx, client, cache, chunk, lf)` and `runSerialFallback(ctx, client, cache, chunk, lf)`. In `runSerialFallback`, the per-package `continue` after a failed `queryOSV` becomes `lf.note(err); continue`. A batch failure that falls back does not count on its own; hydration failure (the degraded-record path) does not count either — the finding is still emitted.
5. In `scanViaOSV`, declare `var lf lookupFailures` before the chunk loop, pass `&lf`, and replace the final `return findings, nil` with `return findings, lf.err("pip", len(misses))`. In `Scan` (the single-manifest function), the per-package `continue` likewise notes the failure and the function ends with `return findings, lf.err("pip", len(pkgs))`.

- [ ] **Step 5: Same for npm and govulncheck**

`internal/scanner/deps/npm/scanner.go`: rename `osvAPIBase` → `OSVBaseURL`; wrap non-2xx responses in `queryOSVBatch` and `queryOSV` with `&neterr.StatusError{Host: OSVBaseURL, Code: resp.StatusCode}`; add the same `lookupFailures` type (or move it to `neterr` as `neterr.Failures` and use it from both packages — preferred: put `type Failures` with `Note` and `Err` in `neterr.go` and use it in both); thread it through `runBatchOrFallback` / `runSerialFallback`; return `lf.Err("npm", len(misses))` from `Scan`.

`internal/scanner/deps/govulncheck/scanner.go`: replace lines 78-81 with

```go
	if runErr != nil && !isFoundVulnsExit(runErr) {
		return nil, classifyRunErr(runErr, stderr.String())
	}
```

and add:

```go
// classifyRunErr wraps a govulncheck failure with a transport sentinel when
// its stderr shows the vulnerability database was unreachable, so the
// orchestrator can type it without reading prose.
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
```

- [ ] **Step 6: Extend `classifyErr` in the engine**

Replace the body of `classifyErr` in `internal/engine/scannerstatus.go`:

```go
func classifyErr(err error) reporters.ScannerReason {
	if err == nil {
		return reporters.ReasonExecutionError
	}
	if errors.Is(err, semgrep.ErrTimeout) {
		return reporters.ReasonTimeout
	}
	switch neterr.Classify(err) {
	case neterr.KindTimeout:
		return reporters.ReasonTimeout
	case neterr.KindNetwork:
		return reporters.ReasonNetworkError
	}
	return reporters.ReasonExecutionError
}
```

(The `net` import from Task 2 is no longer needed here; `neterr` covers it.)

- [ ] **Step 7: Run the affected packages**

Run: `go test -race ./internal/scanner/deps/... ./internal/engine/`
Expected: PASS. `TestScanViaOSV_BothBatchAndSerialFail` (the old tolerant test) is replaced by `TestScanViaOSV_TotalFailureIsLookupError`; delete the old one.

- [ ] **Step 8: Commit**

```bash
git add internal/scanner/deps/neterr internal/scanner/deps/pip internal/scanner/deps/npm internal/scanner/deps/govulncheck internal/engine/scannerstatus.go internal/engine/scannerstatus_test.go
git commit -m "feat(deps): type transport failures; a failed lookup is no longer a silent ok

pip and npm return a LookupError naming how many package lookups failed
after every fallback, wrapping the typed cause (HTTP 5xx/429, transport
errors); govulncheck wraps a sentinel when its stderr shows the database
was unreachable. The engine maps these to network_error and timeout."
```

---

### Task 8: One in-process retry per transient dependency-scanner failure

**Files:**
- Modify: `internal/engine/orchestrator.go` (dependency block; new `retryTransient` helper)
- Modify: `internal/engine/coverage_test.go` (retry tests)

**Interfaces:**
- Consumes: `neterr.Classify`, `markAttempts`, `pip.OSVBaseURL`.
- Produces: `var retryDelay = 2 * time.Second`; `func retryTransient(ctx context.Context, name string, fn func() ([]evidence.Evidence, error)) ([]evidence.Evidence, int, error)`; `isTransient(err error) bool`; `attempts` stamped on `govulncheck`, `pip`, `npm` entries when a retry ran.

- [ ] **Step 1: Write the failing tests**

Append to `internal/engine/coverage_test.go`:

```go
// osvFlaky answers 503 to the first `failures` requests, then a clean
// "no vulns" batch/query response.
func osvFlaky(t *testing.T, failures int) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(n.Add(1)) <= failures {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/querybatch") {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
}

func pipScanConfig(t *testing.T, srvURL string) (*models.ScanConfig, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("HOME", t.TempDir()) // fresh OSV cache
	return &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: false}, out
}

func TestOrchestrator_TransientPipFailureIsRetriedOnce(t *testing.T) {
	srv := osvFlaky(t, 2) // first batch 503, serial fallback 503 → attempt 1 fails; attempt 2 clean
	defer srv.Close()
	saved := pip.OSVBaseURL
	pip.OSVBaseURL = srv.URL
	defer func() { pip.OSVBaseURL = saved }()
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()

	cfg, out := pipScanConfig(t, srv.URL)
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	s, _ := statusFor(readReport(t, out), AnalyzerPip)
	if s.State != reporters.ScannerOK || s.Attempts != 2 {
		t.Fatalf("pip = %+v, want ok with attempts 2", s)
	}
}

func TestOrchestrator_PersistentPipFailureRecordsSecondAttempt(t *testing.T) {
	srv := osvFlaky(t, 1000)
	defer srv.Close()
	saved := pip.OSVBaseURL
	pip.OSVBaseURL = srv.URL
	defer func() { pip.OSVBaseURL = saved }()
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()

	cfg, out := pipScanConfig(t, srv.URL)
	NewOrchestrator(cfg, "dev").Run(context.Background())
	s, _ := statusFor(readReport(t, out), AnalyzerPip)
	if s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonNetworkError || s.Attempts != 2 {
		t.Fatalf("pip = %+v, want failed/network_error with attempts 2", s)
	}
}

func TestRetryTransient_DeterministicFailuresAreNotRetried(t *testing.T) {
	calls := 0
	_, attempts, err := retryTransient(context.Background(), "pip", func() ([]evidence.Evidence, error) {
		calls++
		return nil, errors.New("pip: parse requirements: bad line")
	})
	if calls != 1 || attempts != 1 || err == nil {
		t.Fatalf("deterministic error must run once: calls=%d attempts=%d err=%v", calls, attempts, err)
	}
	calls = 0
	_, attempts, _ = retryTransient(context.Background(), "pip", func() ([]evidence.Evidence, error) {
		calls++
		return nil, &neterr.StatusError{Host: "h", Code: 404}
	})
	if calls != 1 || attempts != 1 {
		t.Fatalf("404 is not transient: calls=%d attempts=%d", calls, attempts)
	}
}

func TestRetryTransient_SecondAttemptFindingsReplaceFirst(t *testing.T) {
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()
	calls := 0
	findings, attempts, err := retryTransient(context.Background(), "npm", func() ([]evidence.Evidence, error) {
		calls++
		if calls == 1 {
			return []evidence.Evidence{{ID: "SEC-PARTIAL"}}, &neterr.LookupError{Scanner: "npm", Failed: 1, Total: 2, Cause: &neterr.StatusError{Host: "h", Code: 503}}
		}
		return []evidence.Evidence{{ID: "SEC-A"}, {ID: "SEC-B"}}, nil
	})
	if err != nil || attempts != 2 || len(findings) != 2 || findings[0].ID != "SEC-A" {
		t.Fatalf("second attempt must be authoritative: findings=%v attempts=%d err=%v", findings, attempts, err)
	}
}
```

Add imports: `"errors"`, `"net/http"`, `"net/http/httptest"`, `"strings"`, `"sync/atomic"`, `"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"`, `"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"`, `"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ -run 'TestOrchestrator_TransientPip|TestOrchestrator_PersistentPip|TestRetryTransient' -v`
Expected: FAIL to compile (`retryTransient`, `retryDelay` undefined).

- [ ] **Step 3: Add the helper**

Next to `recordBlackbox` in `orchestrator.go`:

```go
// retryDelay is the pause before the single in-process retry of a
// transient dependency-scanner failure. Tests set it to zero.
var retryDelay = 2 * time.Second

// isTransient reports whether err is worth one retry: a network failure
// or a timeout. Everything else is deterministic and is never retried.
func isTransient(err error) bool {
	k := neterr.Classify(err)
	return k == neterr.KindNetwork || k == neterr.KindTimeout
}

// retryTransient runs fn and, when it fails transiently, runs it once more
// after retryDelay. The second attempt is authoritative for this analyzer:
// its findings and its error replace the first attempt's entirely, and no
// other analyzer's evidence is touched (spec §6.4). Returns the attempt
// count so the caller can stamp `attempts`.
func retryTransient(ctx context.Context, name string, fn func() ([]evidence.Evidence, error)) ([]evidence.Evidence, int, error) {
	findings, err := fn()
	if err == nil || !isTransient(err) || ctx.Err() != nil {
		return findings, 1, err
	}
	slog.Warn("transient dependency-scanner failure — retrying once", "scanner", name, "error", err)
	select {
	case <-ctx.Done():
		return findings, 1, err
	case <-time.After(retryDelay):
	}
	findings, err = fn()
	return findings, 2, err
}
```

- [ ] **Step 4: Wrap the three online scanner calls**

In the dependency block's `default:` arm (Task 3), wrap the three network paths. govulncheck:

```go
			nativeFindings, attempts, err := retryTransient(ctx, AnalyzerGovulncheck, func() ([]evidence.Evidence, error) {
				return govulncheck.Scan(ctx, o.cfg.CodePath)
			})
			switch {
			case err == nil:
				slog.Info("native go deps scan complete", "findings", len(nativeFindings))
				evid = append(evid, nativeFindings...)
				scanStatus.ok(AnalyzerGovulncheck)
			case errors.Is(err, govulncheck.ErrNoGoMod):
				slog.Debug("no go.mod at code path, skipping native go deps scan")
				scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonNotApplicable, "no go.mod under --code")
			default:
				slog.Warn("native go deps scan failed", "error", err)
				evid = append(evid, nativeFindings...)
				scanStatus.fail(AnalyzerGovulncheck, classifyErr(err), err)
			}
			if attempts > 1 {
				scanStatus.markAttempts(AnalyzerGovulncheck, attempts)
			}
```

pip online path (the `default:` case of the pip switch):

```go
		default:
			pipMode := "OSV.dev"
			if o.cfg.UsePipAudit {
				pipMode = "pip-audit subprocess"
			}
			slog.Debug("native pypi dep-CVE scan starting", "mode", pipMode)
			var attempts int
			pipFindings, attempts, pipErr = retryTransient(ctx, AnalyzerPip, func() ([]evidence.Evidence, error) {
				return pip.ScanRecursiveWithOptions(ctx, o.cfg.CodePath, pip.DefaultRecurseDepth, pip.Options{UsePipAudit: o.cfg.UsePipAudit})
			})
			o.recordDepScanResult(&scanStatus, AnalyzerPip, "native pypi deps scan", &evid, pipFindings, pipErr)
			if attempts > 1 {
				scanStatus.markAttempts(AnalyzerPip, attempts)
			}
```

npm online path (the `default:` case of the npm switch):

```go
		default:
			var attempts int
			npmFindings, attempts, npmErr = retryTransient(ctx, AnalyzerNpm, func() ([]evidence.Evidence, error) {
				return npm.Scan(ctx, o.cfg.CodePath)
			})
			evid = o.recordNpmScanResult(&scanStatus, &evid, npmFindings, npmErr)
			if attempts > 1 {
				scanStatus.markAttempts(AnalyzerNpm, attempts)
			}
```

The offline snapshot paths are not wrapped: they make no network call.

- [ ] **Step 5: Run the engine package**

Run: `go test -race ./internal/engine/`
Expected: PASS. The flaky-server test proves attempt one's empty result is replaced and `attempts` is stamped; the persistent-failure test proves the second attempt's `failed/network_error` is what lands.

- [ ] **Step 6: Commit**

```bash
git add internal/engine/orchestrator.go internal/engine/coverage_test.go
git commit -m "feat(engine): retry a transient dependency-scanner failure once, in process

network_error and timeout on govulncheck, pip or npm get one re-invocation
of that scanner after a short pause. The second attempt is authoritative;
no other analyzer's evidence is touched; attempts is stamped on the entry.
Deterministic failures are never retried."
```

---

### Task 9: Coverage block, policy version, strict flags, exit codes and the scan-end table

**Files:**
- Create: `internal/decision/policy_version.go`
- Create: `internal/engine/summary.go`
- Modify: `internal/models/config.go` (two fields)
- Modify: `cmd/fendix/main.go` (flags, validation, config wiring)
- Modify: `cmd/fendix/main_test.go`
- Modify: `internal/engine/orchestrator.go` (coverage build, exits, summary; `RunImport` metadata)
- Modify: `internal/engine/coverage_test.go`, `internal/engine/discovery_status_test.go` (restore the coverage assertion)

**Interfaces:**
- Produces: `decision.PolicyVersion = "1.0.0"`; `ScanConfig.FailOnCoverageGap bool`, `ScanConfig.RequiredAnalyzers []string`; `validateRequiredAnalyzers(names []string) error` in `cmd/fendix`; `printCoverageSummary(w io.Writer, status scannerStatusList, cov reporters.Coverage, requiredGiven bool)`; `metadata.coverage` and `metadata.policy_version` on every scan report; exit 2 on `--fail-on-coverage-gap` with a gap or `--require-analyzers` with an unsatisfied name.

- [ ] **Step 1: Write the failing tests**

Append to `internal/engine/coverage_test.go`:

```go
func TestOrchestrator_CoverageBlockPresentAndSorted(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json")}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	cov := report.Metadata.Coverage
	if cov == nil || cov.ContractVersion != 1 || cov.Strict {
		t.Fatalf("coverage = %+v", cov)
	}
	if report.Metadata.PolicyVersion != decision.PolicyVersion {
		t.Fatalf("policy_version = %q, want %q", report.Metadata.PolicyVersion, decision.PolicyVersion)
	}
	// offline with no snapshot: pip and npm are dependency_missing → gaps
	if cov.ConfiguredComplete || !reflect.DeepEqual(cov.Gaps, []string{"pip", "npm"}) {
		t.Fatalf("gaps = %v, configured_complete = %v", cov.Gaps, cov.ConfiguredComplete)
	}
	var names []string
	for _, s := range report.Metadata.ScannerStatus {
		names = append(names, s.Name)
	}
	want := []string{"dast", "spec", "active-probes", "secrets", "textscan", "semgrep", "govulncheck", "pip", "npm", "python-engine", "plugins"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("entries are not in registry order: %v", names)
	}
}

func TestOrchestrator_FailOnCoverageGapExits2(t *testing.T) {
	dir := writeCodeDir(t)
	mk := func(strict bool) *models.ScanConfig {
		return &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: filepath.Join(t.TempDir(), "r.json"),
			Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"), FailOnCoverageGap: strict}
	}
	if code := NewOrchestrator(mk(false), "dev").Run(context.Background()); code != 0 {
		t.Fatalf("without the flag: exit %d, want 0", code)
	}
	if code := NewOrchestrator(mk(true), "dev").Run(context.Background()); code != 2 {
		t.Fatalf("with --fail-on-coverage-gap and a dependency_missing gap: exit %d, want 2", code)
	}
}

func TestOrchestrator_RequireAnalyzersIsStricterThanConfiguredComplete(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: true, RequiredAnalyzers: []string{"semgrep"}}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 2 {
		t.Fatalf("--fast --require-analyzers semgrep: exit %d, want 2", code)
	}
	cov := readReport(t, out).Metadata.Coverage
	if !cov.Strict || !cov.ConfiguredComplete || !reflect.DeepEqual(cov.RequiredGaps, []string{"semgrep"}) {
		t.Fatalf("coverage = %+v: --fast is not an engine gap, but semgrep was required and not delivered", cov)
	}

	cfg2 := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: filepath.Join(t.TempDir(), "r2.json"), Fast: true, RequiredAnalyzers: []string{"secrets"}}
	if code := NewOrchestrator(cfg2, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("required secrets ran: exit %d, want 0", code)
	}
}
```

Add `"reflect"` and `"github.com/Abdel-RahmanSaied/Fendix/internal/decision"` imports. In `discovery_status_test.go`, restore the two coverage assertions in `TestOrchestrator_ZeroEndpointsWritesReportThenExits2`.

Append to `cmd/fendix/main_test.go`:

```go
func TestValidateRequiredAnalyzers(t *testing.T) {
	if err := validateRequiredAnalyzers([]string{"semgrep", "python-engine/injection"}); err != nil {
		t.Fatalf("registered names must validate: %v", err)
	}
	err := validateRequiredAnalyzers([]string{"semgrep", "Semgrep"})
	if err == nil || !strings.Contains(err.Error(), `"Semgrep"`) || !strings.Contains(err.Error(), "dast") {
		t.Fatalf("unknown name must be rejected and the message must list the registry, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ ./cmd/fendix/ -run 'TestOrchestrator_CoverageBlock|TestOrchestrator_FailOnCoverageGap|TestOrchestrator_RequireAnalyzers|TestValidateRequiredAnalyzers' -v`
Expected: FAIL to compile (`FailOnCoverageGap`, `RequiredAnalyzers`, `decision.PolicyVersion`, `validateRequiredAnalyzers` undefined).

- [ ] **Step 3: Config fields and the policy version constant**

`internal/models/config.go`, after `FailOnScannerError`:

```go
	// FailOnCoverageGap exits 2 when metadata.coverage.configured_complete
	// is false: an analyzer this run was configured to execute was
	// unavailable or failed. Disabled, not-applicable and unsupported never
	// trip it. Off by default (coverage contract v1).
	FailOnCoverageGap bool
	// RequiredAnalyzers names analyzers that must be delivered — recorded ok
	// or not_applicable — for the run to exit 0. Stricter than
	// FailOnCoverageGap: a disabled or unsupported required analyzer exits 2,
	// because the operator asked for it by name. Names are validated
	// against engine.Registry before the scan starts.
	RequiredAnalyzers []string
```

`internal/decision/policy_version.go`:

```go
package decision

// PolicyVersion is the version of the finding-decision policy described in
// docs/DECISION_POLICY.md (the RC-1/RC-2/RC-3 semantics shipped in v3.2.0).
// Stamped into every report as metadata.policy_version. Bump when a rule in
// applyConfidenceGate or the corroboration taxonomy changes meaning.
const PolicyVersion = "1.0.0"
```

- [ ] **Step 4: CLI flags and validation in `cmd/fendix/main.go`**

Register the flags next to `fail-on-scanner-error` (line 596):

```go
	flags.Bool("fail-on-coverage-gap", false, "Exit 2 when an analyzer this run was configured to execute was unavailable or failed (metadata.coverage.configured_complete=false). Disabled, not-applicable and unsupported analyzers never trip it.")
	flags.StringSlice("require-analyzers", nil, "Comma-separated analyzer names that must be delivered (recorded ok or not_applicable) for exit 0; anything else exits 2. Stricter than --fail-on-coverage-gap: a required analyzer disabled by another flag is a contradiction and exits 2. Names: "+strings.Join(engine.Registry, ", "))
```

Read them with the other flags (near line 391):

```go
			failOnCoverageGapFlag, _ := flags.GetBool("fail-on-coverage-gap")
			requireAnalyzersFlag, _ := flags.GetStringSlice("require-analyzers")
			if err := validateRequiredAnalyzers(requireAnalyzersFlag); err != nil {
				return cli.ExitWithCode(2, "fendix: "+err.Error())
			}
```

Wire into the `ScanConfig` literal after `FailOnScannerError`:

```go
				FailOnCoverageGap:     failOnCoverageGapFlag,
				RequiredAnalyzers:     requireAnalyzersFlag,
```

Add the validator at package level:

```go
// validateRequiredAnalyzers rejects any --require-analyzers name that is
// not in the registry before a scan starts, so a typo cannot silently
// require nothing.
func validateRequiredAnalyzers(names []string) error {
	for _, n := range names {
		if !engine.IsRegisteredAnalyzer(n) {
			return fmt.Errorf("unknown analyzer %q in --require-analyzers; known analyzers: %s", n, strings.Join(engine.Registry, ", "))
		}
	}
	return nil
}
```

- [ ] **Step 5: Build the coverage block, decide the strict exits, print the table**

In `orchestrator.go`, replace `ScannerStatus: []reporters.ScannerStatus(scanStatus.sorted()),` (from Task 3) with building the block first. Immediately before `meta := reporters.ScanMetadata{`:

```go
	scanStatus = scanStatus.sorted()
	strict := o.cfg.FailOnCoverageGap || len(o.cfg.RequiredAnalyzers) > 0
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(scanStatus), o.cfg.RequiredAnalyzers, strict)
```

and in the literal:

```go
		ScannerStatus:        []reporters.ScannerStatus(scanStatus),
		Coverage:             &cov,
		PolicyVersion:        decision.PolicyVersion,
```

Replace the "scanner status summary" block (the `if len(scanStatus) > 0 {...}` after `logagg.Summary()`) with:

```go
	// Scan-end coverage table (spec §5.8): every registry entry, unconditionally.
	printCoverageSummary(os.Stderr, scanStatus, cov, len(o.cfg.RequiredAnalyzers) > 0)
```

After the `--fail-on-scanner-error` block and before `if hardExit != 0`:

```go
	if o.cfg.FailOnCoverageGap && !cov.ConfiguredComplete {
		slog.Error("coverage gap recorded and --fail-on-coverage-gap set — exiting non-zero", "gaps", strings.Join(cov.Gaps, ","))
		fmt.Fprintf(os.Stderr, "fendix: coverage incomplete and --fail-on-coverage-gap is set: %s\n", describeGaps(scanStatus, cov.Gaps))
		return 2
	}
	if len(cov.RequiredGaps) > 0 {
		slog.Error("required analyzer(s) not delivered — exiting non-zero", "required_gaps", strings.Join(cov.RequiredGaps, ","))
		fmt.Fprintf(os.Stderr, "fendix: required analyzer(s) not delivered: %s\n", describeGaps(scanStatus, cov.RequiredGaps))
		return 2
	}
```

In `RunImport` (line ~880-900), where its `ScanMetadata` is built, add `Coverage: func() *reporters.Coverage { c := reporters.BuildCoverage(nil, nil, false); return &c }(),` and `PolicyVersion: decision.PolicyVersion,` — import mode records no analyzers and is trivially complete.

Create `internal/engine/summary.go`:

```go
package engine

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// printCoverageSummary writes the scan-end coverage table (spec §5.8):
// one row per recorded entry, then one line for coverage and, when
// --require-analyzers was given, one for the explicit requirements. It is
// unconditional — strict flags change the exit code, never the report.
func printCoverageSummary(w io.Writer, status scannerStatusList, cov reporters.Coverage, requiredGiven bool) {
	fmt.Fprintln(w, "\nCoverage:")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  analyzer\tclass\treason\tattempts\tdetail")
	for _, s := range status {
		attempts := ""
		if s.Attempts > 1 {
			attempts = fmt.Sprintf("%d", s.Attempts)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", s.Name, s.Class(), s.Reason, attempts, s.Detail)
	}
	tw.Flush()
	if cov.ConfiguredComplete {
		fmt.Fprintln(w, "coverage: complete")
	} else {
		fmt.Fprintf(w, "coverage: incomplete (%s)\n", strings.Join(cov.Gaps, ", "))
	}
	if requiredGiven {
		if len(cov.RequiredGaps) == 0 {
			fmt.Fprintln(w, "required: satisfied")
		} else {
			fmt.Fprintf(w, "required: not delivered (%s)\n", strings.Join(cov.RequiredGaps, ", "))
		}
	}
}

// describeGaps renders "name: class (reason)" for each named entry, and
// for a required analyzer disabled by another flag names the contradiction.
func describeGaps(status scannerStatusList, names []string) string {
	byName := map[string]reporters.ScannerStatus{}
	for _, s := range status {
		byName[s.Name] = s
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		s, ok := byName[n]
		if !ok {
			parts = append(parts, n+": not recorded")
			continue
		}
		desc := fmt.Sprintf("%s: %s (%s)", n, s.Class(), s.Reason)
		if s.Class() == reporters.ClassDisabled && s.Detail != "" {
			desc = fmt.Sprintf("required analyzer %s was disabled by %s", n, s.Detail)
		}
		parts = append(parts, desc)
	}
	return strings.Join(parts, "; ")
}
```

Add a small test in `coverage_test.go`:

```go
func TestPrintCoverageSummary_ListsEveryEntryAndTheVerdictLines(t *testing.T) {
	var buf bytes.Buffer
	status := scannerStatusList{
		{Name: "secrets", State: reporters.ScannerOK},
		{Name: "semgrep", State: reporters.ScannerSkipped, Reason: reporters.ReasonDisabledByFlag, Detail: "--fast"},
		{Name: "pip", State: reporters.ScannerOK, Attempts: 2},
	}
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(status), []string{"semgrep"}, true)
	printCoverageSummary(&buf, status, cov, true)
	out := buf.String()
	for _, want := range []string{"secrets", "semgrep", "disabled", "disabled_by_flag", "coverage: complete", "required: not delivered (semgrep)", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	if got := describeGaps(status, []string{"semgrep"}); !strings.Contains(got, "disabled by --fast") {
		t.Errorf("describeGaps must name the contradiction, got %q", got)
	}
}
```

- [ ] **Step 6: Run everything**

Run: `go test -race ./...`
Expected: PASS across all packages. `go vet ./...` clean.

- [ ] **Step 7: Commit**

```bash
git add internal/decision/policy_version.go internal/engine/summary.go internal/models/config.go cmd/fendix/main.go cmd/fendix/main_test.go internal/engine/orchestrator.go internal/engine/coverage_test.go internal/engine/discovery_status_test.go
git commit -m "feat(cli): metadata.coverage, policy_version, --fail-on-coverage-gap and --require-analyzers

Every scan report carries the engine's configured-completeness block and
the decision policy version. Two opt-in flags turn a coverage gap or an
undelivered explicit requirement into exit 2; default exit behaviour is
unchanged. The scan-end summary is now a per-analyzer table on stderr."
```

---

### Task 10: SARIF — every non-ok analyzer, the property bag, and `executionSuccessful` in three modes

**Files:**
- Modify: `internal/reporters/sarif.go:55-67` (`SARIFRun`), `:1177-1214` (invocation and run)
- Modify: `internal/reporters/sarif_test.go:811-873`

**Interfaces:**
- Consumes: `ScannerStatus.Class()`, `Coverage.StrictOK()`, `ScanMetadata.CoverageState` (Task 1).
- Produces: `SARIFRun.Properties map[string]any`; `executionSuccessful(meta ScanMetadata) bool`; `notificationLevel(s ScannerStatus) string`; `notificationText(s ScannerStatus) string`; `runs[0].properties["fendix/coverage"]` and `["fendix/release"]`.

- [ ] **Step 1: Write the failing tests**

Replace `TestRenderSARIF_ExecutionSuccessfulTrueOnSkipOnly` and append the new tests in `sarif_test.go`:

```go
func renderSARIFLog(t *testing.T, meta ScanMetadata) SARIFLog {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, sampleFindings(), meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	return log
}

// Skips alone keep executionSuccessful=true (default CLI mode is
// unchanged) but every non-ok analyzer is now itemised as a note.
func TestRenderSARIF_SkipOnlyIsSuccessfulWithNotes(t *testing.T) {
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: []ScannerStatus{
		{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline, Detail: "--offline"},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonNotApplicable, Detail: "no --code"},
	}})
	inv := log.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Error("skips alone must not flip executionSuccessful in default mode")
	}
	if len(inv.ToolExecutionNotifications) != 2 {
		t.Fatalf("expected one notification per non-ok entry, got %d", len(inv.ToolExecutionNotifications))
	}
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level != "note" {
			t.Errorf("disabled/not_applicable must be level note, got %q", n.Level)
		}
	}
}

func TestRenderSARIF_NotificationLevelsFollowClass(t *testing.T) {
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: []ScannerStatus{
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "semgrep binary not installed"},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget, Detail: "yarn.lock"},
		{Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError, Detail: "osv.dev returned HTTP 503"},
		{Name: "textscan", State: ScannerSkipped}, // legacy: no reason → unknown
	}})
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("a failed entry must flip executionSuccessful in default mode")
	}
	got := map[string]string{}
	for _, n := range inv.ToolExecutionNotifications {
		name := strings.SplitN(n.Message.Text, ":", 2)[0]
		got[name] = n.Level
	}
	want := map[string]string{"semgrep": "warning", "npm": "note", "pip": "error", "textscan": "warning"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("levels = %v, want %v", got, want)
	}
	if _, ok := got["secrets"]; ok {
		t.Error("ok entries must not produce notifications")
	}
}

func TestRenderSARIF_StrictModeFailsOnRequiredGap(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}, {Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag, Detail: "--fast"}}
	cov := BuildCoverage(status, []string{"semgrep"}, true)
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: status, Coverage: &cov})
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Fatal("strict run with required_gaps must be unsuccessful even though configured_complete is true")
	}
	found := false
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "error" && strings.Contains(n.Message.Text, "required analyzer semgrep not delivered") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an error notification for the required gap, got %+v", inv.ToolExecutionNotifications)
	}
	// The same status without strict is successful: disabled is not an engine gap.
	covLoose := BuildCoverage(status, nil, false)
	if !renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: status, Coverage: &covLoose}).Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("non-strict run with only a disabled analyzer must be successful")
	}
}

func TestRenderSARIF_HostedIncompleteIsUnsuccessfulAndKeepsBlockResults(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}}
	cov := BuildCoverage(status, nil, false)
	meta := ScanMetadata{Version: "3.4.0", ScannerStatus: status, Coverage: &cov,
		ReleaseDecision: "block", CoverageState: "incomplete", DecisionPolicyVersion: "2.0.0",
		DecisionRationale: json.RawMessage(`{"missing_coverage":[{"scanner":"python-engine","state":"unavailable"}]}`)}
	log := renderSARIFLog(t, meta)
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Fatal("hosted export with coverage_state=incomplete must be unsuccessful regardless of the verdict")
	}
	warned := false
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "warning" && strings.HasPrefix(n.Message.Text, "Required coverage incomplete") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected the coverage warning, got %+v", inv.ToolExecutionNotifications)
	}
	if len(log.Runs[0].Results) != len(sampleFindings()) {
		t.Fatal("results must be untouched by the coverage state")
	}
	props := log.Runs[0].Properties
	if props["fendix/release"] == nil || props["fendix/coverage"] == nil {
		t.Fatalf("property bag must carry release and coverage, got %v", props)
	}
	rel := props["fendix/release"].(map[string]any)
	if rel["release_decision"] != "block" || rel["coverage_state"] != "incomplete" {
		t.Fatalf("release properties = %v", rel)
	}
}
```

`SARIFLog`/`SARIFRun` decoding needs `Properties map[string]any` on the struct for the test to read it; that is the Step 3 change.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/reporters/ -run 'TestRenderSARIF_SkipOnly|TestRenderSARIF_NotificationLevels|TestRenderSARIF_StrictMode|TestRenderSARIF_HostedIncomplete' -v`
Expected: FAIL (`Properties` undefined; notification counts wrong).

- [ ] **Step 3: Implement**

Add to `SARIFRun` (after `Invocations`):

```go
	// Properties is the run-level property bag (SARIF §3.14.29). Carries the
	// coverage contract ("fendix/coverage") and, on hosted re-renders, the
	// backend's verdict ("fendix/release"). Additive; omitted when empty.
	Properties map[string]any `json:"properties,omitempty"`
```

Replace the invocation construction (lines 1177-1194) with:

```go
	invocation := SARIFInvocation{ExecutionSuccessful: executionSuccessful(meta)}
	for _, s := range meta.ScannerStatus {
		if s.State == ScannerOK {
			continue
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{
			Level:   notificationLevel(s),
			Message: SARIFMessage{Text: notificationText(s)},
		})
	}
	if meta.Coverage != nil && meta.Coverage.Strict {
		byName := map[string]ScannerStatus{}
		for _, s := range meta.ScannerStatus {
			byName[s.Name] = s
		}
		for _, name := range meta.Coverage.RequiredGaps {
			s := byName[name]
			text := fmt.Sprintf("required analyzer %s not delivered: %s (%s)", name, s.Class(), s.Reason)
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{Level: "error", Message: SARIFMessage{Text: NeutralizeText(text)}})
		}
	}
	if meta.CoverageState == "incomplete" {
		var gaps []string
		for _, s := range meta.ScannerStatus {
			if s.IsGap() || s.Class() == ClassUnknown {
				gaps = append(gaps, s.Name)
			}
		}
		if meta.Coverage != nil && len(meta.Coverage.Gaps) > 0 {
			gaps = meta.Coverage.Gaps
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{
			Level:   "warning",
			Message: SARIFMessage{Text: "Required coverage incomplete: " + strings.Join(gaps, ", ")},
		})
	}

	var runProps map[string]any
	if meta.Coverage != nil || len(meta.ScannerStatus) > 0 {
		runProps = map[string]any{"fendix/coverage": map[string]any{"coverage": meta.Coverage, "scanner_status": meta.ScannerStatus}}
	}
	if meta.ReleaseDecision != "" || meta.CoverageState != "" {
		if runProps == nil {
			runProps = map[string]any{}
		}
		rel := map[string]any{"release_decision": meta.ReleaseDecision, "coverage_state": meta.CoverageState, "decision_policy_version": meta.DecisionPolicyVersion}
		if len(meta.DecisionRationale) > 0 {
			rel["decision_rationale"] = meta.DecisionRationale
		}
		runProps["fendix/release"] = rel
	}
```

and add `Properties: runProps,` to the `SARIFRun` literal. Add the helpers at file end:

```go
// executionSuccessful implements the three modes of spec §5.6, decided from
// the input alone so a re-render is faithful:
//  1. hosted export (coverage_state present): false iff incomplete;
//  2. strict CLI run: false iff a configured analyzer was not delivered or
//     an explicit requirement was not satisfied;
//  3. default CLI run: false iff an analyzer failed — unchanged behaviour.
func executionSuccessful(meta ScanMetadata) bool {
	anyFailed := false
	for _, s := range meta.ScannerStatus {
		if s.Failed() {
			anyFailed = true
			break
		}
	}
	if meta.CoverageState != "" {
		return meta.CoverageState != "incomplete" && !anyFailed
	}
	if meta.Coverage != nil && meta.Coverage.Strict {
		return meta.Coverage.StrictOK() && !anyFailed
	}
	return !anyFailed
}

// notificationLevel maps a lifecycle class to a SARIF notification level:
// a failure is an error, an unavailable dependency or an unclassifiable
// entry is a warning, an intentional or structural skip is a note.
func notificationLevel(s ScannerStatus) string {
	switch s.Class() {
	case ClassFailed:
		return "error"
	case ClassUnavailable, ClassUnknown:
		return "warning"
	}
	return "note"
}

// notificationText renders "<name>: <class> (<reason>): <detail>". Detail
// is neutralized because under `fendix report --input` it is operator
// supplied.
func notificationText(s ScannerStatus) string {
	text := s.Name + ": " + s.Class()
	if s.Reason != "" {
		text += " (" + string(s.Reason) + ")"
	}
	if s.Detail != "" {
		text += ": " + s.Detail
	}
	return NeutralizeText(text)
}
```

`TestRenderSARIF_ExecutionSuccessfulFalseOnScannerFailure` (line 811) asserted exactly one notification with `{ok, skipped, failed}`; it now gets two (the skip is a note). Change its expectation to "exactly one notification at level error, naming pip and 503" and allow the extra note.

- [ ] **Step 4: Run the reporters package**

Run: `go test -race ./internal/reporters/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/reporters/sarif.go internal/reporters/sarif_test.go
git commit -m "feat(sarif): itemise every non-ok analyzer; coverage and verdict in the run property bag

executionSuccessful keeps its default meaning (false only on a failed
analyzer), becomes strict under --fail-on-coverage-gap / --require-analyzers
(false on any engine gap or undelivered requirement), and is false on any
hosted export whose coverage_state is incomplete. Notification levels follow
the lifecycle class: error, warning, note."
```

---

### Task 11: HTML and PDF — the coverage table and the verdict presentation rule

**Files:**
- Modify: `internal/reporters/i18n/i18n.go` (fields), `i18n/en.go`, `i18n/ar.go`
- Modify: `internal/reporters/html.go` (template section, funcs)
- Modify: `internal/reporters/pdf.go:250-267` (appendix rows)
- Modify: `internal/reporters/html_test.go`, `pdf_test.go`, `i18n` test (`lang_test.go`)

**Interfaces:**
- Produces: `i18n.Strings` fields `CoverageTitle, CoverageAnalyzer, CoverageClass, CoverageReason, CoverageAttempts, CoverageDetail, CoverageComplete, CoverageIncomplete, CoverageRequiredMissing, CoverageNotRecorded, CoverageNotMeasured, VerdictPass, VerdictWarn, VerdictBlocked, VerdictBlockedCoverageIncomplete, VerdictCoverageIncomplete, ClassOK, ClassNotApplicable, ClassDisabled, ClassUnavailable, ClassUnsupported, ClassFailed, ClassUnknown`; `i18n.ClassLabel(s Strings, class string) string`; `i18n.VerdictLabel(s Strings, decision, coverageState string) string`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/reporters/html_test.go`:

```go
func TestRenderHTML_CoverageTableAndVerdict(t *testing.T) {
	status := []ScannerStatus{
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "semgrep binary not installed"},
		{Name: "pip", State: ScannerOK, Attempts: 2},
	}
	cov := BuildCoverage(status, nil, false)
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "3.4.0", Mode: "whitebox", ScannerStatus: status, Coverage: &cov,
		ReleaseDecision: "block", CoverageState: "incomplete"}
	if err := RenderHTML(&buf, sampleFindings(), meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Scanner coverage", "semgrep", "unavailable", "dependency_missing", "semgrep binary not installed", "Blocked — coverage also incomplete", "coverage incomplete: semgrep"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if !strings.Contains(out, ">2<") {
		t.Error("attempts column must show the retry count")
	}
}

func TestRenderHTML_IncompleteIsPrimaryOnlyWhenDecisionIsIncomplete(t *testing.T) {
	var buf bytes.Buffer
	cov := BuildCoverage(nil, nil, false)
	_ = RenderHTML(&buf, nil, ScanMetadata{Version: "3.4.0", Mode: "whitebox", Coverage: &cov, ReleaseDecision: "incomplete", CoverageState: "incomplete"})
	if !strings.Contains(buf.String(), "Coverage incomplete") || strings.Contains(buf.String(), "Blocked") {
		t.Fatalf("release_decision=incomplete must render the incomplete verdict alone")
	}
}

func TestRenderHTML_NoCoverageBlockSaysNotRecorded(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderHTML(&buf, nil, ScanMetadata{Version: "3.3.0", Mode: "blackbox"})
	if !strings.Contains(buf.String(), "not recorded by this engine version") {
		t.Fatal("pre-contract input must say coverage was not recorded")
	}
}

func TestRenderHTML_ArabicCoverageTitle(t *testing.T) {
	var buf bytes.Buffer
	cov := BuildCoverage([]ScannerStatus{{Name: "secrets", State: ScannerOK}}, nil, false)
	_ = RenderHTMLOpts(&buf, nil, ScanMetadata{Version: "3.4.0", Mode: "whitebox", Coverage: &cov}, HTMLOptions{Lang: "ar"})
	if !strings.Contains(buf.String(), i18n.Get("ar").CoverageTitle) {
		t.Fatal("Arabic report must use the Arabic coverage title")
	}
}
```

Append to `internal/reporters/i18n/lang_test.go` (or create `i18n/strings_test.go`):

```go
func TestStrings_EveryFieldTranslatedInEveryLanguage(t *testing.T) {
	for _, lang := range []string{"en", "ar"} {
		v := reflect.ValueOf(Get(lang))
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Kind() == reflect.String && v.Field(i).String() == "" {
				t.Errorf("%s: field %s is empty", lang, v.Type().Field(i).Name)
			}
		}
	}
}

func TestVerdictLabel_PresentationRule(t *testing.T) {
	s := Get("en")
	for _, tc := range []struct{ d, c, want string }{
		{"block", "complete", s.VerdictBlocked},
		{"block", "incomplete", s.VerdictBlockedCoverageIncomplete},
		{"incomplete", "incomplete", s.VerdictCoverageIncomplete},
		{"warn", "complete", s.VerdictWarn},
		{"pass", "complete", s.VerdictPass},
		{"pass", "unknown", s.VerdictPass + " — " + s.CoverageNotMeasured},
	} {
		if got := VerdictLabel(s, tc.d, tc.c); got != tc.want {
			t.Errorf("VerdictLabel(%s,%s) = %q, want %q", tc.d, tc.c, got, tc.want)
		}
	}
}
```

Append to `pdf_test.go`:

```go
func TestRenderPDF_WithCoverageAndVerdictSucceeds(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}, {Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError, Detail: "HTTP 503", Attempts: 2}}
	cov := BuildCoverage(status, nil, false)
	var buf bytes.Buffer
	if err := RenderPDF(&buf, sampleFindings(), ScanMetadata{Version: "3.4.0", Mode: "whitebox", ScannerStatus: status, Coverage: &cov, ReleaseDecision: "block", CoverageState: "incomplete"}, PDFOptions{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", buf.Len())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/reporters/... -run 'TestRenderHTML_Coverage|TestRenderHTML_Incomplete|TestRenderHTML_NoCoverage|TestRenderHTML_Arabic|TestStrings_Every|TestVerdictLabel|TestRenderPDF_WithCoverage' -v`
Expected: FAIL (`CoverageTitle` undefined, missing text).

- [ ] **Step 3: Strings and helpers in `i18n`**

Add to `Strings`:

```go
	// Coverage (coverage contract v1)
	CoverageTitle           string
	CoverageAnalyzer        string
	CoverageClass           string
	CoverageReason          string
	CoverageAttempts        string
	CoverageDetail          string
	CoverageComplete        string
	CoverageIncomplete      string // followed by the gap list
	CoverageRequiredMissing string // followed by the required_gaps list
	CoverageNotRecorded     string
	CoverageNotMeasured     string
	VerdictPass             string
	VerdictWarn             string
	VerdictBlocked          string
	VerdictBlockedCoverageIncomplete string
	VerdictCoverageIncomplete        string
	ClassOK, ClassNotApplicable, ClassDisabled, ClassUnavailable, ClassUnsupported, ClassFailed, ClassUnknown string
```

`en.go` values:

```go
		CoverageTitle:           "Scanner coverage",
		CoverageAnalyzer:        "Analyzer",
		CoverageClass:           "State",
		CoverageReason:          "Reason",
		CoverageAttempts:        "Attempts",
		CoverageDetail:          "Detail",
		CoverageComplete:        "coverage complete",
		CoverageIncomplete:      "coverage incomplete:",
		CoverageRequiredMissing: "required analyzers not delivered:",
		CoverageNotRecorded:     "coverage not recorded by this engine version",
		CoverageNotMeasured:     "coverage not measured",
		VerdictPass:             "Passed",
		VerdictWarn:             "Warning",
		VerdictBlocked:          "Blocked",
		VerdictBlockedCoverageIncomplete: "Blocked — coverage also incomplete",
		VerdictCoverageIncomplete:        "Coverage incomplete",
		ClassOK: "ran", ClassNotApplicable: "not applicable", ClassDisabled: "disabled", ClassUnavailable: "unavailable",
		ClassUnsupported: "unsupported", ClassFailed: "failed", ClassUnknown: "unknown",
```

`ar.go` values (mark each `// TRANSLATION_REVIEW_NEEDED` per the package policy):

```go
		CoverageTitle:           "تغطية الماسحات",
		CoverageAnalyzer:        "المحلل",
		CoverageClass:           "الحالة",
		CoverageReason:          "السبب",
		CoverageAttempts:        "المحاولات",
		CoverageDetail:          "التفاصيل",
		CoverageComplete:        "التغطية كاملة",
		CoverageIncomplete:      "التغطية غير كاملة:",
		CoverageRequiredMissing: "محللات مطلوبة لم تُنفَّذ:",
		CoverageNotRecorded:     "لم تُسجَّل التغطية في هذه النسخة من المحرك",
		CoverageNotMeasured:     "لم تُقَس التغطية",
		VerdictPass:             "ناجح",
		VerdictWarn:             "تحذير",
		VerdictBlocked:          "محجوب",
		VerdictBlockedCoverageIncomplete: "محجوب — والتغطية غير كاملة أيضًا",
		VerdictCoverageIncomplete:        "التغطية غير كاملة",
		ClassOK: "اشتغل", ClassNotApplicable: "غير قابل للتطبيق", ClassDisabled: "معطَّل", ClassUnavailable: "غير متاح",
		ClassUnsupported: "غير مدعوم", ClassFailed: "فشل", ClassUnknown: "غير معروف",
```

Helpers in `i18n.go`:

```go
// ClassLabel returns the localised label for a lifecycle class string.
func ClassLabel(s Strings, class string) string {
	switch class {
	case "ok":
		return s.ClassOK
	case "not_applicable":
		return s.ClassNotApplicable
	case "disabled":
		return s.ClassDisabled
	case "unavailable":
		return s.ClassUnavailable
	case "unsupported":
		return s.ClassUnsupported
	case "failed":
		return s.ClassFailed
	}
	return s.ClassUnknown
}

// VerdictLabel implements the verdict presentation rule: the release
// decision is primary; incomplete coverage qualifies a BLOCK and is the
// headline only when the decision itself is INCOMPLETE.
func VerdictLabel(s Strings, decision, coverageState string) string {
	var label string
	switch decision {
	case "block":
		if coverageState == "incomplete" {
			return s.VerdictBlockedCoverageIncomplete
		}
		label = s.VerdictBlocked
	case "incomplete":
		return s.VerdictCoverageIncomplete
	case "warn":
		label = s.VerdictWarn
	case "pass":
		label = s.VerdictPass
	default:
		return ""
	}
	if coverageState == "unknown" {
		label += " — " + s.CoverageNotMeasured
	}
	return label
}
```

- [ ] **Step 4: HTML template and funcs**

In `RenderHTMLOpts`, resolve `strs := i18n.Get(lang)` before building `funcMap` (move the `lang` defaulting above it) and add:

```go
		"classLabel":   func(c string) string { return i18n.ClassLabel(strs, c) },
		"verdictLabel": func(d, c string) string { return i18n.VerdictLabel(strs, d, c) },
		"itoa":         func(n int) string { return strconv.Itoa(n) },
```

At the top of the `<body>` content (before the summary stat blocks) insert the verdict banner:

```html
{{if .Metadata.ReleaseDecision}}<div class="verdict verdict-{{.Metadata.ReleaseDecision}}{{if eq .Metadata.CoverageState "incomplete"}} verdict-partial{{end}}">{{verdictLabel .Metadata.ReleaseDecision .Metadata.CoverageState}}</div>{{end}}
```

After the `<div class="meta">…</div>` block insert the coverage section:

```html
<section class="coverage">
<h2>{{.I18n.CoverageTitle}}</h2>
{{if .Metadata.Coverage}}
<p class="coverage-verdict {{if .Metadata.Coverage.ConfiguredComplete}}ok{{else}}gap{{end}}">{{if .Metadata.Coverage.ConfiguredComplete}}{{.I18n.CoverageComplete}}{{else}}{{.I18n.CoverageIncomplete}} {{joinRefs .Metadata.Coverage.Gaps}}{{end}}</p>
{{if .Metadata.Coverage.RequiredGaps}}<p class="coverage-verdict gap">{{.I18n.CoverageRequiredMissing}} {{joinRefs .Metadata.Coverage.RequiredGaps}}</p>{{end}}
<table class="coverage-table">
<thead><tr><th>{{.I18n.CoverageAnalyzer}}</th><th>{{.I18n.CoverageClass}}</th><th>{{.I18n.CoverageReason}}</th><th>{{.I18n.CoverageAttempts}}</th><th>{{.I18n.CoverageDetail}}</th></tr></thead>
<tbody>
{{range .Metadata.ScannerStatus}}<tr class="cov-{{.Class}}"><td>{{.Name}}</td><td>{{classLabel .Class}} <span class="muted">({{.Class}})</span></td><td>{{.Reason}}</td><td>{{if gt .Attempts 1}}{{itoa .Attempts}}{{end}}</td><td>{{.Detail}}</td></tr>
{{end}}</tbody></table>
{{else}}<p class="muted">{{.I18n.CoverageNotRecorded}}</p>{{end}}
</section>
```

Add matching CSS to the template's `<style>` block:

```css
.verdict{padding:12px 16px;border-radius:8px;font-weight:600;margin:0 0 16px}
.verdict-block{background:#3b0d0d;color:#ffb4b4}.verdict-incomplete{background:#3a2e08;color:#ffd97a}
.verdict-warn{background:#3a2e08;color:#ffd97a}.verdict-pass{background:#0f2e1a;color:#9ae6b4}
.coverage-table{width:100%;border-collapse:collapse;font-size:13px}.coverage-table th,.coverage-table td{text-align:start;padding:4px 8px;border-bottom:1px solid #2a2a2a}
.coverage-verdict.gap{color:#ffd97a}.coverage-verdict.ok{color:#9ae6b4}
tr.cov-failed td,tr.cov-unavailable td,tr.cov-unknown td{color:#ffb4b4}tr.cov-unsupported td,tr.cov-disabled td{color:#bdbdbd}
```

Add `"strconv"` to `html.go` imports.

- [ ] **Step 5: PDF appendix rows**

In `pdf.go` after the `rows := [][2]string{...}` literal (line 259-266):

```go
	if meta.ReleaseDecision != "" {
		rows = append(rows, [2]string{"Release decision", i18n.VerdictLabel(i18n.Get("en"), meta.ReleaseDecision, meta.CoverageState)})
	}
	if meta.Coverage != nil {
		cov := "complete"
		if !meta.Coverage.ConfiguredComplete {
			cov = "incomplete: " + strings.Join(meta.Coverage.Gaps, ", ")
		}
		rows = append(rows, [2]string{"Coverage", cov})
		if len(meta.Coverage.RequiredGaps) > 0 {
			rows = append(rows, [2]string{"Required, not delivered", strings.Join(meta.Coverage.RequiredGaps, ", ")})
		}
		for _, s := range meta.ScannerStatus {
			val := s.Class()
			if s.Reason != "" {
				val += " (" + string(s.Reason) + ")"
			}
			if s.Attempts > 1 {
				val += fmt.Sprintf(", %d attempts", s.Attempts)
			}
			if s.Detail != "" {
				val += " — " + s.Detail
			}
			rows = append(rows, [2]string{"  " + s.Name, val})
		}
	} else {
		rows = append(rows, [2]string{"Coverage", "not recorded by this engine version"})
	}
```

Add `"strings"` and the `i18n` import to `pdf.go` if absent.

- [ ] **Step 6: Run the reporters tree**

Run: `go test -race ./internal/reporters/...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/reporters/i18n internal/reporters/html.go internal/reporters/pdf.go internal/reporters/html_test.go internal/reporters/pdf_test.go
git commit -m "feat(report): coverage table and verdict presentation in HTML and PDF

Every analyzer's class, reason, attempts and detail render under the
verdict. A hosted re-render shows the backend's release decision with the
presentation rule: BLOCK stays primary and gains 'coverage also
incomplete'; 'Coverage incomplete' leads only when the decision itself is
INCOMPLETE. English and Arabic."
```

---

### Task 12: Documentation, changelog and the decision-policy version statement

**Files:**
- Modify: `docs/schema.md:67-110`
- Modify: `docs/INTEGRATION_GUIDE.md:318-328`, `:449-454`
- Modify: `README.md:412` (flag table)
- Modify: `docs/DECISION_POLICY.md` (header)
- Modify: `CHANGELOG.md:8` (`[Unreleased]`)

- [ ] **Step 1: `docs/schema.md`**

Replace the `scanner_status` row and the `### ScannerStatus` section with:

```markdown
| `scanner_status` | array of `ScannerStatus` | no | Per-analyzer outcome, one entry per registry analyzer, in registry order: `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, `python-engine/auth`, `python-engine/injection`, `python-engine/deps`, `plugins`. The three `python-engine/*` children appear only when the Python engine reports them. Empty for `import` mode. See below. |
| `coverage` | `Coverage` | no (present on every report from v3.4.0) | The engine's configured-completeness statement. See below. |
| `policy_version` | string | no (present from v3.4.0) | Version of the finding-decision policy (`docs/DECISION_POLICY.md`) this build applied. `"1.0.0"` for the RC-3 semantics shipped in v3.2.0. |
| `release_decision`, `coverage_state`, `decision_policy_version`, `decision_rationale` | string / string / string / object | no | Present only on reports re-rendered by Fendix Cloud, which embeds its release verdict in the input it hands to `fendix report`. A live `fendix scan` never writes them. |

### ScannerStatus

```json
{"name": "semgrep", "state": "skipped", "reason": "dependency_missing", "detail": "semgrep binary not installed"}
{"name": "pip", "state": "ok", "attempts": 2}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Registry identity (list above). |
| `state` | string enum | yes | `ok`, `skipped`, `failed`. |
| `reason` | string enum | when `state` ≠ `ok` | Skip reasons: `not_applicable`, `diff_unchanged`, `disabled_by_flag`, `disabled_offline`, `dependency_missing`, `unsupported_target`. Fail reasons: `network_error`, `timeout`, `execution_error`, `malformed_output`, `truncated_output`, `input_error`, `no_endpoints`. Closed set. |
| `detail` | string | no | Short human-readable excerpt. Never used for classification. |
| `attempts` | integer ≥ 2 | no | Present when the analyzer was retried in process (one retry, `network_error`/`timeout` on the dependency scanners only). `state`/`reason` describe the final attempt. |

Lifecycle classes, derived from `(state, reason)`: `ok`; `not_applicable` (`not_applicable`, `diff_unchanged`); `disabled` (`disabled_by_flag`, `disabled_offline`); `unavailable` (`dependency_missing`); `unsupported` (`unsupported_target`); `failed` (any fail reason). Only `unavailable` and `failed` are engine gaps: the analyzer was configured to run and did not deliver. `disabled` and `unsupported` are visible, intentional or structural, and never a gap on their own.

### Coverage

```json
{"contract_version": 1, "strict": false, "configured_complete": false, "gaps": ["semgrep"], "limitations": ["npm: package.json without package-lock.json"], "required_analyzers": [], "required_gaps": [], "retried": ["pip"]}
```

| Field | Type | Description |
|---|---|---|
| `contract_version` | integer | Version of the registry-and-reason contract (`1`). Independent of `schema_version`. |
| `strict` | boolean | The run used `--fail-on-coverage-gap` or `--require-analyzers`. |
| `configured_complete` | boolean | `true` iff no entry is `unavailable` or `failed`. Not changed by `--require-analyzers`. |
| `gaps` | array of string | Names of `unavailable` or `failed` entries. |
| `limitations` | array of string | `"<name>: <detail>"` for every `unsupported` entry. |
| `required_analyzers` | array of string | The `--require-analyzers` list; empty when none. |
| `required_gaps` | array of string | Required names not `ok` or `not_applicable`. An explicit requirement is stricter than `configured_complete`: `disabled` and `unsupported` do not satisfy it. |
| `retried` | array of string | Entries with `attempts > 1`. |

A consumer that wants "was this scan complete?" should read `coverage.configured_complete` and, on a strict run, `coverage.required_gaps`; `gaps` and `limitations` carry the detail. Checking only for a `failed` entry is no longer sufficient: a missing dependency is `skipped/dependency_missing`, and it is a gap.
```

- [ ] **Step 2: `docs/INTEGRATION_GUIDE.md`**

Replace the `scanner_status[].state` bullet with:

```markdown
- **`scanner_status`** carries one entry per analyzer (`dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, its `python-engine/*` children when reported, `plugins`) with `state` ∈ `ok`/`skipped`/`failed` and a closed `reason` on every non-ok entry. **`metadata.coverage.configured_complete`** answers "did everything this run was configured to execute run?"; **`coverage.required_gaps`** answers "did `--require-analyzers` get what it asked for?". Only `failed` feeds `--fail-on-scanner-error` (unchanged); `--fail-on-coverage-gap` also trips on `skipped/dependency_missing`.
```

In the exit-code table replace the `2` row with:

```markdown
| `2` | Scan error (engine unresolvable, discovery failed, render failure), `--fail-on-scanner-error` with a failed analyzer, `--fail-on-coverage-gap` with `configured_complete=false`, or `--require-analyzers` with an undelivered name. From v3.4.0 a URL scan that discovers zero endpoints still exits 2 but now writes the report first, with `dast` recorded `failed/no_endpoints`. |
```

- [ ] **Step 3: `README.md` flag table**

After the `--fail-on-scanner-error` row add:

```markdown
| `--fail-on-coverage-gap` | bool | `false` | Exit 2 when an analyzer this run was configured to execute was unavailable or failed (`metadata.coverage.configured_complete=false`). Disabled, not-applicable and unsupported analyzers never trip it. |
| `--require-analyzers` | list | | Analyzers that must be delivered (recorded `ok` or `not_applicable`) for exit 0; anything else exits 2. Stricter than `--fail-on-coverage-gap`: `--fast --require-analyzers semgrep` is a contradiction and exits 2. |
```

- [ ] **Step 4: `docs/DECISION_POLICY.md`**

Under the `**Status:**` header line add:

```markdown
**Policy version:** `1.0.0` — stamped into every report as `metadata.policy_version` (`decision.PolicyVersion`). Bumped when a rule in `applyConfidenceGate` or the corroboration taxonomy changes meaning; the report schema version does not move for that.
```

- [ ] **Step 5: `CHANGELOG.md` under `## [Unreleased]`**

```markdown
### Added

- **Coverage contract v1.** Every analyzer that can silently degrade is now
  recorded once per scan in `metadata.scanner_status`, in a fixed registry
  order, with a closed machine-readable `reason` on every non-ok entry:
  `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`,
  `govulncheck`, `pip`, `npm`, `python-engine` (plus `python-engine/auth`,
  `/injection`, `/deps` when the Python engine reports them) and `plugins`.
  `metadata.coverage` states whether everything the run was configured to
  execute actually ran (`configured_complete`), names the `gaps`, lists
  `limitations` (unsupported targets), and echoes `required_analyzers` /
  `required_gaps`. `metadata.policy_version` names the decision policy.
- **`--fail-on-coverage-gap`** exits 2 when `configured_complete` is false.
  **`--require-analyzers a,b`** exits 2 when a named analyzer was not
  delivered — `disabled` and `unsupported` do not satisfy an explicit
  requirement. Both off by default; default exit behaviour is unchanged.
- **One in-process retry** for a `network_error` or `timeout` on
  `govulncheck`, `pip` or `npm`; the entry carries `attempts: 2`. Nothing
  else is retried. There is no whole-engine re-run.
- **Python engine protocol v2** — one `{"status": {...}}` line per check.
- **SARIF** itemises every non-ok analyzer as a `toolExecutionNotification`
  (error / warning / note by class) and carries the coverage block and, on
  Fendix Cloud re-renders, the release verdict in `runs[].properties`.
  `executionSuccessful` is unchanged in default mode, strict under the new
  flags, and false on any hosted export whose coverage is incomplete.
- **HTML and PDF** gain a coverage table under the verdict.

### Changed

- **A URL scan that discovers zero endpoints now writes the report before
  exiting 2**, with `dast` recorded `failed/no_endpoints`. Previously it
  exited with no report and Fendix Cloud stored it as a clean scan.
- **`pip` with no manifest is `skipped/not_applicable`**, not `ok`. **An npm
  `package.json` without a lockfile is `skipped/unsupported_target`.**
- **A failed OSV lookup is no longer a silent `ok`.** `pip` and `npm` record
  `failed/network_error` when package lookups fail after every fallback,
  keeping the findings that did resolve.
- **A missing Python interpreter or engine tree is `python-engine`
  `skipped/dependency_missing`** instead of a stderr line; a Python engine
  crash, unparseable stream, missing done line or `done.total` mismatch is
  recorded as `failed` with the matching reason, and the findings received
  are kept.
- **`--fast`, `--no-native-deps`, `--offline`, `--no-plugins` and
  `--python-engine=false` record `disabled` entries** instead of leaving
  the analyzer absent from the list. Blackbox scans gain `not_applicable`
  entries where the list used to be empty.
- **SARIF `fendix report --input` of a pre-contract report** now emits a
  `warning` notification for a skipped entry that has no reason (class
  `unknown`), where it emitted nothing.
```

- [ ] **Step 6: Verify the docs render and the schema agrees**

Run: `go test -race ./internal/reporters/ -run 'Schema|Drift'` and `grep -c "coverage" docs/schema.md`
Expected: tests PASS; grep ≥ 10.

- [ ] **Step 7: Commit**

```bash
git add docs/schema.md docs/INTEGRATION_GUIDE.md README.md docs/DECISION_POLICY.md CHANGELOG.md
git commit -m "docs: coverage contract v1 — schema, integration guide, flags, policy version, changelog"
```

---

### Task 13: Release gate — candidate image, deterministic smoke, promotion, then mirror

**Files:**
- Create: `tests/fixtures/coverage-smoke/{app.py,requirements.txt,go.mod,main.go,package.json,package-lock.json,osv-export.json}`
- Create: `scripts/coverage-smoke-check.sh`
- Modify: `.github/workflows/release.yml` (`docker` job: build a candidate, smoke it, promote the smoked digest, then sign; `mirror` unchanged and still gated on `docker`)
- Modify: `Makefile` (`coverage-smoke` target)

**Interfaces:**
- Produces: `scripts/coverage-smoke-check.sh --deterministic <report.json>` (blocks promotion) and `--network <report.json>` (warns); the candidate package `ghcr.io/<owner>/fendix-candidate:<tag>-<sha12>`; promotion of the smoked digest to `ghcr.io/<owner>/fendix:<tag>` and `:latest` by manifest copy, never by rebuild; `steps.promote.outputs.digest`, consumed by the existing signing, SBOM and provenance steps.

**What the two smokes assert.**

| Smoke | Runs with | Proves | Blocks promotion |
|---|---|---|---|
| deterministic | `--offline` against the fixture's own snapshot, `docker run --network none` | the image contains and can invoke every runtime capability it promises: the Go scanners, semgrep, the Python engine and its three checks, the offline dependency path for PyPI and npm; the coverage block is present and complete; no entry is `dependency_missing` | yes |
| network | online, default flags | the live OSV and vuln.go.dev integration: the three dependency scanners are `ok`, or `failed` with a transport reason (`network_error`, `timeout`) | no — a transport failure is a warning annotation; any other non-ok state is an error annotation but still does not block, because it is not a property of the image |

A healthy image is therefore never unreleasable because a vulnerability database is temporarily unavailable, and a defective image never reaches a release reference.

- [ ] **Step 1: Write the fixture**

```
tests/fixtures/coverage-smoke/app.py
```
```python
import os
import subprocess

def run(cmd: str) -> None:
    subprocess.call(cmd, shell=True)  # a sink the AST analyzer reports

API_KEY = os.environ.get("API_KEY", "")
```

```
tests/fixtures/coverage-smoke/requirements.txt
```
```
flask==2.0.1
```

```
tests/fixtures/coverage-smoke/go.mod
```
```
module example.com/coverage-smoke

go 1.22
```

```
tests/fixtures/coverage-smoke/main.go
```
```go
package main

func main() {}
```

```
tests/fixtures/coverage-smoke/package.json
```
```json
{"name": "coverage-smoke", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}
```

```
tests/fixtures/coverage-smoke/package-lock.json
```
```json
{
  "name": "coverage-smoke",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "coverage-smoke", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
    "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="}
  }
}
```

```
tests/fixtures/coverage-smoke/osv-export.json
```
```json
[
  {"id": "FENDIX-SMOKE-PYPI-0001", "aliases": ["CVE-2026-0001"], "package": {"ecosystem": "PyPI", "name": "flask"}, "ranges": [{"introduced": "0", "fixed": "2.3.0"}], "summary": "Smoke fixture: flask below 2.3.0", "references": ["https://example.invalid/flask"]},
  {"id": "FENDIX-SMOKE-NPM-0001", "aliases": ["CVE-2026-0002"], "package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"introduced": "0", "fixed": "4.17.21"}], "summary": "Smoke fixture: lodash below 4.17.21", "references": ["https://example.invalid/lodash"]}
]
```

The export is the shape `fendix db update --source` ingests (`offline.Advisory`). It exists so the deterministic smoke can prove the pip and npm paths work end to end without any network.

- [ ] **Step 2: Write the check script**

```sh
#!/usr/bin/env sh
# scripts/coverage-smoke-check.sh --deterministic|--network <report.json>
#
# --deterministic  the packaging/capability gate. The report must come from a
#                  scan of tests/fixtures/coverage-smoke run with --offline
#                  against the fixture's own snapshot and with no network at
#                  all. It proves the image contains and can invoke every
#                  runtime capability it promises. Any failure blocks
#                  promotion of the candidate image.
# --network        the live-integration check. The same fixture scanned online:
#                  govulncheck, pip and npm must be ok, or failed with a
#                  transport reason. A transport failure is a warning, not a
#                  release blocker — it is not a property of the image.
set -eu
mode="$1"; report="$2"; fail=0; warn=0

state_of()  { jq -r --arg n "$1" '[.metadata.scanner_status[] | select(.name==$n) | .state]  | first // "MISSING"' "$report"; }
reason_of() { jq -r --arg n "$1" '[.metadata.scanner_status[] | select(.name==$n) | .reason] | first // "none"' "$report"; }
expect_state()  { got=$(state_of "$1");  [ "$got" = "$2" ] || { echo "::error::$1 state is '$got', expected '$2'";  fail=1; }; }
expect_reason() { got=$(reason_of "$1"); [ "$got" = "$2" ] || { echo "::error::$1 reason is '$got', expected '$2'"; fail=1; }; }

case "$mode" in
  --deterministic)
    for name in secrets textscan semgrep pip npm python-engine python-engine/injection python-engine/deps; do
      expect_state "$name" ok
    done
    expect_reason govulncheck disabled_offline
    expect_reason python-engine/auth not_applicable
    expect_reason dast not_applicable
    expect_reason spec not_applicable
    expect_reason active-probes disabled_by_flag
    expect_reason plugins not_applicable
    dm=$(jq -r '[.metadata.scanner_status[] | select(.reason=="dependency_missing") | .name] | join(",")' "$report")
    [ -z "$dm" ] || { echo "::error::dependency_missing inside the image: $dm"; fail=1; }
    [ "$(jq -r '.metadata.coverage.contract_version // "MISSING"' "$report")" = "1" ] || { echo "::error::coverage.contract_version missing"; fail=1; }
    [ "$(jq -r '.metadata.coverage.configured_complete // "MISSING"' "$report")" = "true" ] || { echo "::error::configured_complete is not true; gaps: $(jq -c '.metadata.coverage.gaps' "$report")"; fail=1; }
    [ "$(jq -r '.metadata.policy_version // "MISSING"' "$report")" != "MISSING" ] || { echo "::error::policy_version missing"; fail=1; }
    deps=$(jq '[.findings[] | select(.category=="deps")] | length' "$report")
    [ "$deps" -ge 2 ] || { echo "::error::offline snapshot findings missing: expected >= 2 dependency findings, got $deps"; fail=1; }
    ;;
  --network)
    for name in govulncheck pip npm; do
      st=$(state_of "$name"); rs=$(reason_of "$name")
      case "$st" in
        ok) ;;
        failed)
          case "$rs" in
            network_error|timeout) echo "::warning::$name: live vulnerability database unavailable ($rs); not a packaging defect"; warn=1 ;;
            *) echo "::error::$name failed online with '$rs' (not a transport reason)"; fail=1 ;;
          esac ;;
        *) echo "::error::$name is '$st/$rs' online"; fail=1 ;;
      esac
    done
    ;;
  *) echo "usage: $0 --deterministic|--network <report.json>" >&2; exit 2 ;;
esac

[ "$fail" = 0 ] && echo "coverage smoke ($mode): ok (warnings=$warn)"
exit $fail
```

`chmod +x scripts/coverage-smoke-check.sh`.

- [ ] **Step 3: Makefile target (deterministic mode, local binary)**

```make
# Coverage contract smoke, deterministic mode: build the fixture's offline
# snapshot, scan the fixture with --offline and the local binary, assert
# every capability recorded ok. Needs semgrep and python3 on PATH; needs NO
# network. The release workflow runs the same script against the candidate
# image with --network none, then a separate online check that only warns.
coverage-smoke: build
	./bin/fendix db update --source tests/fixtures/coverage-smoke/osv-export.json --output /tmp/fendix-smoke-db.json
	./bin/fendix scan --code tests/fixtures/coverage-smoke --python-engine --offline --offline-db /tmp/fendix-smoke-db.json \
	  --format json --output /tmp/fendix-coverage-smoke.json || true
	scripts/coverage-smoke-check.sh --deterministic /tmp/fendix-coverage-smoke.json
```

(The `|| true` is deliberate: the fixture contains a shell-injection sink and two vulnerable pins, so the scan may exit 1 on findings; the assertion is the script.)

- [ ] **Step 4: Restructure the `docker` job in `release.yml`**

Replace the "Compute image tags" and "Build & push image" steps (lines 413-446) with a candidate build, two smokes and a promotion; the existing cosign, syft and SLSA steps then read `steps.promote.outputs.digest` instead of `steps.build.outputs.digest`.

```yaml
      - name: Compute image references
        id: tags
        run: |
          REPO_LC="$(echo '${{ github.repository }}' | tr '[:upper:]' '[:lower:]')"
          OWNER_LC="${REPO_LC%%/*}"
          TAG="${GITHUB_REF_NAME}"
          {
            echo "image=ghcr.io/${REPO_LC}"
            echo "candidate=ghcr.io/${OWNER_LC}/fendix-candidate"
            echo "candidate_tag=${TAG}-${GITHUB_SHA::12}"
            echo "tag=${TAG}"
            echo "version=${TAG#v}"
          } >> "$GITHUB_OUTPUT"

      # The candidate lives in a separate package. Nothing under the release
      # package name exists until the deterministic smoke has passed, so a
      # consumer pinning ghcr.io/<owner>/fendix:<tag> or :latest can never
      # observe an unverified image.
      - name: Build & push candidate image
        id: build
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf # v7.2.0
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          build-args: |
            VERSION=${{ steps.tags.outputs.tag }}
          tags: ${{ steps.tags.outputs.candidate }}:${{ steps.tags.outputs.candidate_tag }}
          labels: |
            org.opencontainers.image.source=https://github.com/${{ github.repository }}
            org.opencontainers.image.version=${{ steps.tags.outputs.version }}
            org.opencontainers.image.licenses=MIT

      - name: Smoke (deterministic, no network) — packaging and capability gate
        env:
          CANDIDATE: ${{ steps.tags.outputs.candidate }}@${{ steps.build.outputs.digest }}
        run: |
          set -eu
          docker run --rm --network none --entrypoint sh \
            -v "$PWD/tests/fixtures/coverage-smoke:/src:ro" "$CANDIDATE" -c '
              /usr/local/bin/fendix db update --source /src/osv-export.json --output /tmp/offline-db.json >/dev/null
              /usr/local/bin/fendix scan --code /src --python-engine --offline --offline-db /tmp/offline-db.json \
                --format json --output /tmp/report.json >/dev/null 2>&1 || true
              cat /tmp/report.json' > smoke-deterministic.json
          scripts/coverage-smoke-check.sh --deterministic smoke-deterministic.json

      - name: Smoke (network) — live vulnerability databases
        continue-on-error: true
        env:
          CANDIDATE: ${{ steps.tags.outputs.candidate }}@${{ steps.build.outputs.digest }}
        run: |
          set -eu
          docker run --rm --entrypoint sh \
            -v "$PWD/tests/fixtures/coverage-smoke:/src:ro" "$CANDIDATE" -c '
              /usr/local/bin/fendix scan --code /src --python-engine --format json --output /tmp/report.json >/dev/null 2>&1 || true
              cat /tmp/report.json' > smoke-network.json
          scripts/coverage-smoke-check.sh --network smoke-network.json

      # Promotion is a manifest copy of the exact digest that passed the gate.
      # No rebuild, so the promoted image is byte-identical to the smoked one;
      # the digest equality check makes that a hard assertion.
      - name: Promote smoked candidate to release references
        id: promote
        run: |
          set -eu
          SRC="${{ steps.tags.outputs.candidate }}@${{ steps.build.outputs.digest }}"
          docker buildx imagetools create \
            -t "${{ steps.tags.outputs.image }}:${{ steps.tags.outputs.tag }}" \
            -t "${{ steps.tags.outputs.image }}:latest" \
            "$SRC"
          DIGEST="$(docker buildx imagetools inspect "${{ steps.tags.outputs.image }}:${{ steps.tags.outputs.tag }}" --format '{{json .Manifest.Digest}}' | tr -d '"')"
          [ "$DIGEST" = "${{ steps.build.outputs.digest }}" ] || { echo "::error::promoted digest $DIGEST differs from smoked candidate ${{ steps.build.outputs.digest }}"; exit 1; }
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
```

Then, in every later step of the job that references the image digest (`Sign Docker image`, `Generate + attest image SBOM`, `Attest SLSA provenance (image)`), replace `${{ steps.build.outputs.digest }}` with `${{ steps.promote.outputs.digest }}` and keep `${{ steps.tags.outputs.image }}` as the reference. The `mirror` job already depends on `docker`; a failed deterministic smoke fails the job before promotion, so neither a release tag nor a mirror entry is created.

Add, as the last step of the job, a best-effort cleanup so rejected candidates do not accumulate (the promoted digest is retained because it is now referenced by the release package):

```yaml
      - name: Prune old candidate images
        if: always()
        continue-on-error: true
        uses: actions/delete-package-versions@e5bc658cc4c965c472efe991f8beea3981499c55 # v5.0.0
        with:
          package-name: fendix-candidate
          package-type: container
          min-versions-to-keep: 5
```

Two things to know when this runs for the first time: pushing to a new package needs the job's existing `packages: write` permission and the package should be made **private** in the GHCR package settings (a candidate is not a release reference; keeping it private removes any chance of it being pulled as one); and if semgrep fails under `--network none`, fix the invocation (`--metrics=off`, `--disable-version-check`) rather than relaxing the test — an air-gapped run that needs the network is exactly what the gate exists to catch.

- [ ] **Step 5: Run locally**

Run: `make coverage-smoke`
Expected: `coverage smoke (--deterministic): ok (warnings=0)` when semgrep and python3 are on PATH. A missing local semgrep is reported by the script as `semgrep state is 'skipped', expected 'ok'`, which is the gate doing its job; install semgrep or run the same commands through a locally built image with `docker run --network none`.

Also validate the workflow file: `actionlint .github/workflows/release.yml` (the CI job already runs actionlint; run it locally to catch a mis-nested step before pushing a tag).

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/coverage-smoke scripts/coverage-smoke-check.sh Makefile .github/workflows/release.yml
git commit -m "ci(release): gate promotion on a deterministic coverage smoke of the candidate image

The image is built and pushed as a candidate under a separate package,
scanned offline with no network against the fixture's own snapshot to
prove every promised capability is present and invocable, then promoted
to the release references by manifest copy of the identical digest. A
separate online check covers the live vulnerability databases and only
warns, so a database outage cannot block a healthy release."
```

---

## Plan self-review

**Spec coverage.**

| Spec section | Task |
|---|---|
| §4.1 registry, exactly-once, children when reported | 2, 3, 4, 5 |
| §4.2 lifecycle classes, `attempts` | 1, 8 |
| §4.3 reason codes incl. `network_error` | 1, 7 |
| §4.4 assignment matrix; zero-endpoint report; code-path validation once | 3, 4, 5, 6 |
| §5.1 entry fields and bounds | 1, 2 |
| §5.2 coverage block incl. `required_analyzers`, `required_gaps`, `retried`, strict outcome | 1, 9 |
| §5.3 `policy_version` | 9 |
| §5.4 Python protocol v2, total reconciliation | 5, 6 |
| §5.5 `checks_run` unchanged | 2 (test retained) |
| §5.6 SARIF three modes, property bag, HTML/PDF table and presentation rule | 10, 11 |
| §5.7 documentation | 12 |
| §5.8 CLI flags, exit precedence, scan-end table, re-render passthrough | 9 |
| §6.4 in-process analyzer retry, `attempts`, no whole-engine re-run | 8 |
| §10 engine invariants: exactly-once, determinism, pairing, coverage, spawner outcomes incl. protocol completeness, observable check pass, strict exits, SARIF, re-render, deterministic image smoke | 1, 3, 4, 5, 7, 8, 9, 10, 13 |

**Deltas against the spec that the owner should record as clarifications** (none contradicts a decision; each is stated where it applies):

1. **Explicit `--python-engine` with an unresolvable tree keeps today's immediate exit 2 with no report** (Task 5). Spec §4.4 says the entry is "additionally recorded"; recording requires running the scan, which would change the explicit path's contract. The implicit path, which is what Fendix Cloud uses, records `dependency_missing` as specified.
2. **Findings gathered before a dependency-scanner failure are kept** (Tasks 2, 7, 8), and the second attempt's partial findings are kept when the retry also fails. Spec §6.4 point 3 assumed a failed lookup produced nothing to keep; a partial `LookupError` can carry findings, and Rule 3 says they are never dropped. The retried analyzer's first-attempt findings are still discarded in favour of the second attempt's.
3. **`active-probes` and `dast` derive `ok` from the observed check pass** (Task 4), not from configuration: the probe audit log (every active probe with its HTTP status, `0` meaning no response), the request budget's refused count, and a `--max-duration` deadline. All probes unanswered is `failed/network_error`; a pass cut short by the budget or the deadline is `failed/execution_error` or `failed/timeout`; partial unanswered probes stay visible in the detail of an `ok` entry. The spec's matrix rows for `dast` and `active-probes` are amended to this rule.
4. **Re-rendering a pre-contract report emits SARIF `warning` notifications for reason-less skips** (Task 10), because their class is `unknown`. Listed under "Changed" in the changelog.
5. **Python protocol v2 completeness is verified** (Tasks 5–6): the done line declares `protocol: 2`, and the Go side requires exactly one status line per expected check — duplicate or unknown is `malformed_output`, missing is `truncated_output`, both on the parent. A tree that declares no protocol is parent-only. The spec's §5.4 is amended to this rule.

Recorded after implementation (final review 2026-09-06; mirrored in spec §11):

6. **`checks_run` keeps its derivation rule but not always its value** (Tasks 2, 12). `pip` with no manifest is now `not_applicable`, so a `--code` scan with no dependency manifest at all loses the coarse `deps` label; `checksrun_test.go` pins both directions and the changelog lists it under "Changed". Spec §8.1's "byte-identical" claim is amended to "derived by the same rule".
7. **Hosted SARIF mode is exactly `coverage_state != "incomplete"`** (Task 10). The `&& !anyFailed` in this plan's Task 10 snippet was dropped: in a hosted re-render the backend's classification is authoritative. The "Required coverage incomplete" warning names gaps from `decision_rationale.missing_coverage[].scanner` first, then `coverage.gaps`, then gap/unknown entries, and omits the list when nothing can be named.
8. **An unrecognised `release_decision` renders verbatim** (Task 11), not as a blank banner: `VerdictLabel`'s `default: return ""` in this plan was overruled.
9. **`fendix verify` fails closed on a partial lookup** (Task 7): a `*neterr.LookupError` from `pip.Scan`/`npm.Scan` makes `verifyDep` answer `unknown` (exit 2) where it could previously answer "resolved". Documented in the changelog and the integration guide.
10. **The official image ships no Go toolchain** (Task 13, parked for the owner): `govulncheck` records `failed/execution_error` on any image scan of a Go module, which the warn-only network smoke surfaces as a non-blocking annotation. Spec §11 risk 13 carries it into the backend plan.

**Placeholder scan.** No `TBD`/`TODO`; every code step carries the code; the only forward references are to symbols defined in earlier tasks (`pip.ErrNoManifests` is declared in Task 2 and wired in Task 3; `Coverage` assertions in Task 4's zero-endpoint test are commented until Task 9 restores them, as the step says).

**Type consistency.** `retryTransient` returns `([]evidence.Evidence, int, error)` everywhere (Tasks 8 and 9). `skip(name, reason, detail)` / `fail(name, reason, err)` / `failDetail(name, reason, detail)` are the only recording signatures used after Task 2. `SpawnResult.Outcome` values are used identically in Tasks 5 and 9. `Coverage.StrictOK()` is used by Task 9's exits and Task 10's SARIF mode.

**Order of execution.** Tasks 1→2→3→4→5 are sequential (each depends on the previous API). Task 6 (Python) can run in parallel with 3–5 once Task 5's Go-side reader exists only for the integration test; its unit tests are independent. Task 7 depends on 2; Task 8 on 3 and 7; Task 9 on 4, 5 and 8; Task 10 on 1 and 9; Task 11 on 1 and 9; Task 12 on everything; Task 13 last.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-04-coverage-integrity-engine.md`. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, two-stage review between tasks, fast iteration (`superpowers:subagent-driven-development`).
2. **Inline Execution** — tasks executed in this session with checkpoints (`superpowers:executing-plans`).

No implementation starts until the owner reviews this plan.
