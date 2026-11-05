package semgrep

import (
	"context"
	"log/slog"
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
// without it: its matches are the same, less what the option adds.
//
// The first release of each option, from Semgrep's CHANGELOG and checked by
// running the release (a project-root probe of 1.45, 1.70, 1.90, 1.100, 1.110
// and 1.111..1.125):
//
//	--exclude        0.12.0   (collapsed --exclude-dir into it)
//	--timeout        0.17.0
//	--dataflow-traces 0.107.0
//	--project-root   1.111.0  (1.110.0 answers "No such option '--project-root'")

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
	versionMu    sync.Mutex
	versionCache = map[string]semgrepVersion{}
)

// semgrepVersionOf is the release of the semgrep at bin, read by running
// `bin --version` once per binary path for the life of the process. A binary
// that does not answer, or answers with anything but a version, is unknown.
func semgrepVersionOf(ctx context.Context, bin string) semgrepVersion {
	versionMu.Lock()
	defer versionMu.Unlock()
	if v, ok := versionCache[bin]; ok {
		return v
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := commandContext(vctx, bin, "--version").Output()
	v := semgrepVersion{}
	if err == nil {
		v = parseSemgrepVersion(string(out))
	}
	versionCache[bin] = v
	return v
}

func resetVersionCacheForTesting() {
	versionMu.Lock()
	defer versionMu.Unlock()
	versionCache = map[string]semgrepVersion{}
}

// optionalArgs is the options a run passes beyond the ones every supported
// Semgrep has: --dataflow-traces, --timeout, --project-root and the build
// output --excludes, each left out when v is older than the release that
// added it.
func optionalArgs(v semgrepVersion, codePath string) []string {
	var args []string
	var dropped []string
	add := func(major, minor, patch int, name string, values ...string) {
		if !v.atLeast(major, minor, patch) {
			dropped = append(dropped, name)
			return
		}
		args = append(args, values...)
	}
	// A taint rule's trace details a reachable finding's chain when
	// semgrep sends it (ADR-011). Pattern rules have no trace.
	add(0, 107, 0, "--dataflow-traces", "--dataflow-traces")
	// A slow rule loses its matches on one file, not the whole run.
	add(0, 17, 0, "--timeout", "--timeout", strconv.Itoa(ruleTimeoutSeconds))
	// Semgrep matches a rule's paths.exclude and its default ignore list
	// relative to its project root, which inside a git work tree is the
	// git root. Scanning <gitroot>/fixtures/repo would then apply the
	// packs' "fixtures/" exclusion to every file of the target and scan
	// nothing, with no error. The scan target is the root.
	add(1, 111, 0, "--project-root", "--project-root", codePath)
	var excludes []string
	for _, pattern := range buildOutputExcludes {
		excludes = append(excludes, "--exclude", pattern)
	}
	add(0, 12, 0, "--exclude", excludes...)
	if len(dropped) > 0 {
		slog.Warn("semgrep: this Semgrep is older than the release that added some options, so the run goes without them",
			"semgrep", versionString(v), "dropped", dropped)
	}
	return args
}

func versionString(v semgrepVersion) string {
	if !v.known {
		return "unknown"
	}
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}
