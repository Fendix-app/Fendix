package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ScanRequest is the JSON payload sent to the Python engine via stdin.
//
// A `language` field used to sit here. Nothing in production ever set it, so
// the key was never emitted and the Python side always fell through to its
// default; the AST analyzer routes by file extension during the walk anyway,
// which is strictly more accurate than one whole-scan language hint. It was
// removed rather than left as an unset field pretending to be a knob. Omitting
// the key is wire-compatible: engine.py reads it with `request.get("language")`
// and defaults to "python".
type ScanRequest struct {
	Mode     string   `json:"mode"`
	Spec     string   `json:"spec,omitempty"`
	CodePath string   `json:"code_path,omitempty"`
	Checks   []string `json:"checks"`
	Verbose  bool     `json:"verbose"`
}

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

// PythonSpawner manages the lifecycle of the Python engine subprocess.
type PythonSpawner struct {
	pythonBin string // path to python3 binary
	engineDir string // directory containing engine.py
}

// NewPythonSpawner creates a spawner that will invoke the Python engine.
// pythonBin defaults to "python3" if empty.
// engineDir defaults to "python" relative to CWD if empty.
func NewPythonSpawner(pythonBin, engineDir string) *PythonSpawner {
	if pythonBin == "" {
		pythonBin = "python3"
	}
	if engineDir == "" {
		engineDir = "python"
	}
	return &PythonSpawner{
		pythonBin: pythonBin,
		engineDir: engineDir,
	}
}

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

// Run spawns the Python engine, sends the ScanRequest, and collects findings.
// It respects context cancellation and kills the subprocess if cancelled.
func (ps *PythonSpawner) Run(ctx context.Context, req ScanRequest) SpawnResult {
	// Resolve to absolute paths up front. engineDir is often the local
	// fallback "python" (relative), and we set cmd.Dir = engineDir; if
	// enginePath were also relative, the spawned process resolves it
	// against cmd.Dir → "python/python/engine.py". Pre-existing latent
	// bug surfaced once TASK-118 made the relative-path branch the
	// default-non-embedded path.
	absEngineDir, err := filepath.Abs(ps.engineDir)
	if err != nil {
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("resolving engine dir: %w", err)}
	}
	enginePath := filepath.Join(absEngineDir, "engine.py")

	cmd := exec.CommandContext(ctx, ps.pythonBin, enginePath)
	cmd.Dir = absEngineDir

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("creating stdin pipe: %w", err)}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("creating stdout pipe: %w", err)}
	}

	// Capture stderr for diagnostics
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	// Send ScanRequest and close stdin
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("marshaling scan request: %w", err)}
	}
	startTime := time.Now()

	if err := cmd.Start(); err != nil {
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("starting python engine: %w", err)}
	}

	if _, err := stdin.Write(reqJSON); err != nil {
		cmd.Process.Kill()
		return SpawnResult{Outcome: SpawnStartError, Err: fmt.Errorf("writing scan request to stdin: %w", err)}
	}
	stdin.Close()

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
