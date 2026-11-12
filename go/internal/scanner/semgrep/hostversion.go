package semgrep

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A host `semgrep` on PATH is supported, not only the one the images pin, and
// Fendix has checked it as far back as 1.45.0. The options added since are not
// in every release, and an option a Semgrep does not know fails the whole run
// ("No such option"), so a Semgrep older than an option's first release is run
// without it. Whether that run is still a complete one depends on the option
// (optionalArgs): one whose absence changes what is scanned or matched makes
// the run a coverage gap (decision D1), one whose absence only changes
// explanation, run time or what else is scanned leaves it ok with a note.
//
// The first release of each option, from Semgrep's CHANGELOG and checked by
// running the release (a project-root probe of 1.45, 1.70, 1.90, 1.100, 1.110
// and 1.111..1.125):
//
//	--exclude        0.12.0   (collapsed --exclude-dir into it)
//	--timeout        0.17.0
//	--jobs, --max-memory  before 1.0.0 (both are in every release the engine
//	                 supports; the budget adds them from 1.0.0 on and a host
//	                 older than that runs without them)
//	--dataflow-traces 0.107.0
//	--project-root   1.111.0  (1.110.0 answers "No such option '--project-root'")
//	--x-ignore-semgrepignore-files 1.96.0 (in semgrep/commands/scan.py of the
//	                 1.96.0 wheel and every later one checked, 1.97.0 ..
//	                 1.182.1; not in 1.95.0 or earlier)

// runOptions are the per-invocation values optionalArgs puts on the command
// line; a zero value passes Semgrep's own default (--timeout: the engine's
// first-pass bound).
type runOptions struct {
	timeout   int // --timeout seconds
	jobs      int // --jobs
	maxMemory int // --max-memory MiB
}

// semgrepVersion is a Semgrep release; known is false when it could not be
// read, which is taken to be a current one.
type semgrepVersion struct {
	major, minor, patch int
	known               bool
}

// atLeast reports whether v is the release (major, minor, patch) or a later
// one. A version that could not be read is at least every release.
func (v semgrepVersion) atLeast(major, minor, patch int) bool {
	if !v.known {
		return true
	}
	if v.major != major {
		return v.major > major
	}
	if v.minor != minor {
		return v.minor > minor
	}
	return v.patch >= patch
}

// versionLine matches the whole of `semgrep --version`'s output: one release
// number. Anything else (a banner, a JSON document a stand-in prints for every
// call) is not read as a version.
var versionLine = regexp.MustCompile(`^\s*(\d+)\.(\d+)\.(\d+)\s*$`)

// parseSemgrepVersion reads the version off the last non-empty line of
// `semgrep --version` output: Semgrep prints notices before it on some hosts.
func parseSemgrepVersion(out string) semgrepVersion {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		m := versionLine.FindStringSubmatch(lines[i])
		if m == nil {
			return semgrepVersion{}
		}
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		patch, _ := strconv.Atoi(m[3])
		return semgrepVersion{major: major, minor: minor, patch: patch, known: true}
	}
	return semgrepVersion{}
}

var (
	versionMu      sync.Mutex
	versionCache   = map[string]semgrepVersion{}
	versionProblem = map[string]string{}
)

// versionProbeTimeout bounds `semgrep --version`. With the version check off
// it answers in about a second (Semgrep 1.182.1, offline); without, it waits
// on semgrep.dev for about 98 s when there is no route out (R-018).
var versionProbeTimeout = 10 * time.Second

// probeEnv is the environment of the version probe: the caller's, with
// Semgrep's version check and metrics off, so the probe never touches the
// network. Semgrep's `--version` has no --disable-version-check of its own in
// every supported release, and every release reads these variables.
func probeEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SEMGREP_ENABLE_VERSION_CHECK=") || strings.HasPrefix(kv, "SEMGREP_SEND_METRICS=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SEND_METRICS=off")
}

// semgrepVersionOf is the release of the semgrep at bin, read by running
// `bin --version` once per binary path for the life of the process, with the
// version check off and within versionProbeTimeout. A binary that answers
// with anything but a version is unknown, and that is remembered. A probe that
// failed on its own (it timed out, the binary did not run) is unknown and is
// remembered too, so a scan that follows does not wait again; the reason is
// kept for versionProbeProblem. A probe cut short because ctx ended says
// nothing about the binary and is not remembered.
//
// An unknown version is run as a current one: every option is passed, so
// nothing is dropped silently, and a Semgrep that does not know one fails the
// run loudly ("No such option"), recorded failed.
func semgrepVersionOf(ctx context.Context, bin string) semgrepVersion {
	versionMu.Lock()
	defer versionMu.Unlock()
	if v, ok := versionCache[bin]; ok {
		return v
	}
	vctx, cancel := context.WithTimeout(ctx, versionProbeTimeout)
	defer cancel()
	cmd := commandContext(vctx, bin, "--version")
	cmd.Env = probeEnv()
	// A child that keeps stdout open must not hold the probe past its bound.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return semgrepVersion{}
		}
		why := err.Error()
		if vctx.Err() != nil {
			why = fmt.Sprintf("no answer within %s", versionProbeTimeout)
		}
		slog.Warn("semgrep: could not read the version; running with every option", "semgrep", bin, "error", why)
		versionCache[bin] = semgrepVersion{}
		versionProblem[bin] = why
		return semgrepVersion{}
	}
	v := parseSemgrepVersion(string(out))
	versionCache[bin] = v
	return v
}

// versionProbeProblem is why the version of the semgrep at bin could not be
// read, or "" when it was read or not tried.
func versionProbeProblem(bin string) string {
	versionMu.Lock()
	defer versionMu.Unlock()
	return versionProblem[bin]
}

func resetVersionCacheForTesting() {
	versionMu.Lock()
	defer versionMu.Unlock()
	versionCache = map[string]semgrepVersion{}
	versionProblem = map[string]string{}
}

// optionalArgs is the options a run passes beyond the ones every supported
// Semgrep has: --dataflow-traces, --timeout, --project-root,
// --x-ignore-semgrepignore-files and the build output --excludes, each left
// out when v is older than the release that added it. It also returns the
// options left out, each with the release that added it ("--project-root
// (needs 1.111.0)"), and of those, the ones whose absence changes what the run
// scans or matches (lossy), which make the run a coverage gap, with what each
// lossy one costs (why). Each option's class:
//
//   - --dataflow-traces: explanation only. A trace adds the steps before a
//     reachable finding's own location; reachability, identity and status
//     never read it (taintReachable, taintChain), and a logged-out Semgrep
//     never sends one anyway. Not lossy.
//   - --timeout: run time only. Without it Semgrep's own per-rule bound
//     applies, and every rule it stops on a file is still reported as a
//     Timeout, which the orchestrator records as lost evaluation. Not lossy.
//   - --project-root: what is scanned. Semgrep then matches the packs'
//     paths.exclude against the enclosing git root, so a target under
//     <gitroot>/fixtures/ (or tests/, spec/ ...) can have every file
//     excluded without an error. Lossy.
//   - --x-ignore-semgrepignore-files: what is scanned. Without it Semgrep
//     reads every .semgrepignore in the scanned tree, so the repository under
//     scan (a pull request's author, say) decides which of its files Semgrep
//     skips, and when the tree has none at its root Semgrep applies its
//     built-in default list, which drops tests/ and test/ at any depth,
//     *.min.js, and more (redteam-semgrep-02, redteam2-semgrep-02). With it
//     only the engine's own --excludes, the packs' path filters and the size
//     cap decide, the same for every project. Lossy.
//   - --exclude (the paths declared out of scope on evidence): more is scanned,
//     never less. Without it the vendored or minified files the engine listed
//     are scanned too; findings there are extra, none in the project's own code
//     is lost. Not lossy.
//   - --jobs, --max-memory (round 4, the budget, budget.go): run time and
//     resource use only. A host that predates them runs Semgrep with its own
//     defaults, which is the behaviour before the budget; no file is skipped
//     and no rule dropped either way. Not lossy.
func optionalArgs(v semgrepVersion, codePath string, excludes []string, opt runOptions) (args, dropped, lossy, why []string) {
	add := func(major, minor, patch int, cost, name string, values ...string) {
		if !v.atLeast(major, minor, patch) {
			d := fmt.Sprintf("%s (needs %d.%d.%d)", name, major, minor, patch)
			dropped = append(dropped, d)
			if cost != "" {
				lossy = append(lossy, d)
				why = append(why, cost)
			}
			return
		}
		args = append(args, values...)
	}
	// A taint rule's trace details a reachable finding's chain when
	// semgrep sends it (ADR-011). Pattern rules have no trace.
	add(0, 107, 0, "", "--dataflow-traces", "--dataflow-traces")
	// A slow rule loses its matches on one file, not the whole run.
	timeout := opt.timeout
	if timeout <= 0 {
		timeout = ruleTimeoutSeconds
	}
	add(0, 17, 0, "", "--timeout", "--timeout", strconv.Itoa(timeout))
	// The CPU and memory the container gives the scan, not the host's
	// (budget.go): Semgrep's own defaults are sized from the host's cores and
	// leave memory unbounded.
	if opt.jobs > 0 {
		add(1, 0, 0, "", "--jobs", "--jobs", strconv.Itoa(opt.jobs))
	}
	if opt.maxMemory > 0 {
		add(1, 0, 0, "", "--max-memory", "--max-memory", strconv.Itoa(opt.maxMemory))
	}
	// Semgrep matches a rule's paths.exclude and its default ignore list
	// relative to its project root, which inside a git work tree is the
	// git root. Scanning <gitroot>/fixtures/repo would then apply the
	// packs' "fixtures/" exclusion to every file of the target and scan
	// nothing, with no error. The scan target is the root.
	add(1, 111, 0, "the packs' path filters need --project-root", "--project-root", "--project-root", codePath)
	// The scanned tree's .semgrepignore files and Semgrep's built-in default
	// ignore list are not the engine's scope; only its own exclusions are.
	add(1, 96, 0, "Semgrep's default ignore list and the tree's .semgrepignore files apply",
		"--x-ignore-semgrepignore-files", "--x-ignore-semgrepignore-files")
	// The paths the engine declared out of scope on evidence (decision D6'),
	// each an anchored pattern. Without --exclude more is scanned, never less.
	var excludeArgs []string
	for _, pattern := range excludes {
		excludeArgs = append(excludeArgs, "--exclude", pattern)
	}
	add(0, 12, 0, "", "--exclude", excludeArgs...)
	if len(dropped) > 0 {
		slog.Warn("semgrep: this Semgrep is older than the release that added some options, so the run goes without them",
			"semgrep", versionString(v), "dropped", dropped)
	}
	return args, dropped, lossy, why
}

// droppedWhy is Report.DroppedWhy for the costs optionalArgs returned, or ""
// when nothing lossy was dropped.
func droppedWhy(why []string) string {
	if len(why) == 0 {
		return ""
	}
	return "files may be skipped: " + strings.Join(why, "; ")
}

// droppedNote is the scanner-status detail for a run that went without
// options, "semgrep 1.45.0: dropped --project-root (needs 1.111.0)", or ""
// when none were dropped.
func droppedNote(v semgrepVersion, dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return "semgrep " + versionString(v) + ": dropped " + strings.Join(dropped, ", ")
}

func versionString(v semgrepVersion) string {
	if !v.known {
		return "unknown"
	}
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}
