// Package textscan ships a regex-based SAST engine that drives the
// Sprint-04 (Go), Sprint-05 (JS/TS), and Sprint-06 (Dockerfile + k8s
// YAML) rulesets in one unified scanner. The brief originally
// scoped these as three separate sprints with three separate code
// trees; consolidating them is the plan-finish session's deliberate
// scope decision — see PLAN.md and the per-sprint Status notes.
//
// Design constraints:
//
//   - No new external deps (per PLAN.md). Pure stdlib + the
//     existing models package.
//   - No CGo. The engine walks files with filepath.WalkDir and
//     runs regexes (regexp package).
//   - Conservative rule design. Each rule has a FP/FN class
//     documented in its inline comment; LOW-confidence patterns
//     ship with severity capped at MEDIUM (the orchestrator's
//     consistency rule from docs/semgrep-rules.md).
//   - Filename-extension routing. .go → Go rules, .js/.ts/.jsx/.tsx
//     → JS rules, .dockerfile / Dockerfile / Dockerfile.* → Docker
//     rules, .yaml/.yml under detection of k8s shape (apiVersion +
//     kind) → k8s rules.
//
// What this package deliberately does NOT do (vs. the briefs):
//
//   - **No Go AST walking.** GO_XXE and GO_INSECURE_RAND from
//     Sprint 04's brief need cross-function context to avoid
//     drowning the user in stdlib false-positives. They're cut to
//     Sprint 04.5 (genuine AST-walker work).
//   - **No JS proximity context.** JS_PROTO_POLLUTION and
//     JS_INSECURE_RAND from Sprint 05's brief are cut to Sprint
//     5.5 for the same reason — the regex+window approach has too
//     many false positives.
//   - **No Terraform HCL.** Sprint 06's D2 gate is at its default
//     (no TF). Sprint 06 ships Dockerfile + k8s only.
//
// Each shipped rule has a deliberately small surface — fewer rules,
// higher precision, no trust-eroding flood of FPs. Customers can
// layer in their own via the existing semgrep rule-pack mechanism.
package textscan

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// Rule describes one SAST pattern. A file matches a rule when its
// path passes Applies() and the rule's Pattern matches any line.
type Rule struct {
	ID         string
	Title      string
	Severity   models.Severity
	Confidence models.Confidence
	Category   string // "injection" | "secrets" | "auth" | "iac" | "crypto" ...
	CWE        string
	Pattern    *regexp.Regexp
	NegPattern *regexp.Regexp // optional: line must NOT also match
	Fix        string
	// RedactMatch replaces every Pattern match inside the emitted evidence
	// snippet with the shared secrets marker. Set it on any rule whose
	// Pattern matches CREDENTIAL MATERIAL itself — without it the raw source
	// line is published, and textscan evidence travels into SARIF, HTML, Jira
	// tickets and GitHub PR comments.
	//
	// Deliberately per-rule rather than keyed off Category == "secrets":
	// GO_WEAK_HASH_PASSWORD is also a secrets-category rule, but its Pattern
	// matches an md5/sha1 CALL, not a credential, and blanking that would
	// destroy the only useful part of its evidence.
	RedactMatch bool
	// Applies returns true when path falls under this rule's
	// language-extension set.
	Applies func(path string) bool
}

// Scan walks rootDir and returns a Finding per (rule, line) match.
// Files larger than maxFileBytes are skipped (the scanner is meant
// for source, not data blobs). Default cap: 1 MiB per file.
//
// Errors during file reads are logged via the slog default and
// skipped — one unreadable file doesn't fail the scan.
func Scan(rootDir string, rules []Rule) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(rootDir, rules, nil)
}

// ScanWithAllowlist is Scan scoped to a diff-aware file allowlist. When
// allow is nil the behaviour is identical to Scan (full walk). When set,
// only files whose absolute path is in the allowlist are scanned — the
// engine half of `fendix scan --diff`. Directories are still walked (so
// skip-dir pruning still happens) but non-allowlisted files are skipped
// before they are read, keeping diff scans sub-second on large trees.
func ScanWithAllowlist(rootDir string, rules []Rule, allow *gitdiff.Allowlist) ([]evidence.Evidence, error) {
	var findings []evidence.Evidence

	if rootDir == "" {
		return nil, fmt.Errorf("textscan: rootDir is required")
	}
	if _, err := os.Stat(rootDir); err != nil {
		return nil, fmt.Errorf("textscan: %s: %w", rootDir, err)
	}

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (the orchestrator also short-circuits) since this is exported.
	if allow.Empty() {
		return nil, nil
	}

	// Diff-aware fast path: when the allowlist names specific changed files,
	// scan exactly those — O(changed files) — instead of walking the whole
	// tree to filter down to them. The reachable set stays a strict subset of
	// the walk's: skip symlinks (the walk refuses them) AND any file reached
	// through a symlinked parent dir (which WalkDir never descends, and which
	// could escape rootDir), plus the same pruned dirs; then run the shared
	// scanCandidate body. (Empty allowlists already returned above.)
	if allow != nil {
		for _, path := range allow.AbsPaths() {
			info, err := os.Lstat(path)
			if err != nil || info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
				continue
			}
			if underSkipDir(rootDir, path) || gitdiff.TraversesSymlink(rootDir, path) {
				continue
			}
			findings = append(findings, scanCandidate(rootDir, path, fs.FileInfoToDirEntry(info), rules)...)
		}
		return findings, nil
	}

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries; don't fail the walk
		}
		// Skip symlinks unconditionally — both file and directory
		// symlinks. filepath.WalkDir does not follow symlinks (it uses
		// lstat), so a directory symlink shows up here with
		// d.Type()&fs.ModeSymlink != 0 and IsDir() == false; refuse
		// to descend or read either way. Prevents loops and silent
		// privilege boundary crossings (e.g. /tmp symlink to /etc).
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			// Skip noisy build / vendor / VCS dirs.
			if _, skip := textSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		// Diff-aware scoping: skip files outside the allowlist before any
		// read. A nil allowlist allows everything (full-scan default).
		if !allow.Allows(path) {
			return nil
		}
		findings = append(findings, scanCandidate(rootDir, path, d, rules)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	return findings, nil
}

// textSkipDirs are the build / vendor / VCS directories pruned from the scan.
// Single-sourced so the full walk and the diff-aware fast path agree on what
// to skip.
var textSkipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "__pycache__": {},
	".venv": {}, "build": {}, "dist": {}, ".pytest_cache": {},
	".next": {}, ".nuxt": {}, ".svelte-kit": {}, ".cache": {}, "target": {},
}

const textMaxFileBytes = 1 << 20 // 1 MiB

// scanCandidate runs the applicable rules against a single file that has
// already passed the symlink / dir / allowlist gates. Shared by the full walk
// and the diff-aware fast path so both apply identical rule-applicability,
// size, and binary-sniff logic — no parity drift between the two code paths.
func scanCandidate(rootDir, path string, d fs.DirEntry, rules []Rule) []evidence.Evidence {
	applicable := make([]*Rule, 0, len(rules))
	for i := range rules {
		if rules[i].Applies != nil && rules[i].Applies(path) {
			applicable = append(applicable, &rules[i])
		}
	}
	if len(applicable) == 0 {
		return nil
	}
	info, err := d.Info()
	if err != nil || info.Size() > textMaxFileBytes {
		return nil
	}
	// Skip binary blobs. Reading PNGs/jars/sqlite line-by-line against every
	// regex is CPU waste and produces false-positive AKIA hits in binary
	// noise; sniff the first 512 bytes so the AWS-key et al. rules never run
	// on non-text.
	if looksBinary, _ := isBinaryFile(path); looksBinary {
		return nil
	}
	got, err := scanFile(rootDir, path, applicable)
	if err != nil {
		return nil
	}
	return got
}

// underSkipDir reports whether any directory component of abs (relative to
// root) is a pruned directory — preserving walk parity for the diff-aware
// fast path (e.g. a committed vendor/ file the walk would never reach).
func underSkipDir(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, part := range parts[:len(parts)-1] { // dir components only, not the file
		if _, skip := textSkipDirs[part]; skip {
			return true
		}
	}
	return false
}

// dockerfileUserRe matches a `USER <name>` directive. Package-level because
// dockerfileHasUSER used to compile it INSIDE its per-line loop — a recompile
// for every line of every Dockerfile scanned.
var dockerfileUserRe = regexp.MustCompile(`^USER\s+\S`)

// dockerfileFromRe parses a Dockerfile FROM instruction:
//
//	group 1 = leading BuildKit flags (--platform=…, --chmod=…), if any
//	group 2 = the image reference OR the stage alias being referenced
//	group 3 = the `AS <alias>` name, empty when the stage is unnamed
//
// Case-insensitive on both FROM and AS: Dockerfile keywords are
// case-insensitive and the builder lower-cases stage names. Deliberately NOT
// anchored at the end, so a trailing `# comment` does not defeat the parse.
//
// This is intentionally MORE permissive than IAC_DOCKER_LATEST_TAG's detection
// pattern, which is `$`-anchored and requires an upper-case `AS`. A pre-pass
// that shared the detection pattern's blind spots would fail to register an
// alias declared with a lower-case `as` or a `--platform=` flag, and the false
// positive it exists to kill would survive on exactly those files.
var dockerfileFromRe = regexp.MustCompile(`(?i)^\s*FROM\s+((?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?`)

// dockerfileCopyFromRe extracts the source of a `COPY --from=<ref>`. The ref
// is either a stage alias, a numeric stage index, or an external image.
var dockerfileCopyFromRe = regexp.MustCompile(`(?i)^\s*COPY\s+(?:--\S+\s+)*--from=(\S+)`)

// dockerfileDigestRe matches a content-addressable image pin —
// `@sha256:<64 hex>` and, generically, any `@<algo>:<hex>` form. A digest is
// the ONLY thing that makes a base image reproducible: a tag, however
// specific-looking, is a mutable pointer the publisher can move.
var dockerfileDigestRe = regexp.MustCompile(`@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z0-9]+)*:[0-9a-fA-F]{32,}`)

// dockerfileNumericRe matches a bare stage INDEX (`COPY --from=0`), which
// refers to a previous stage by position and is not an image reference.
var dockerfileNumericRe = regexp.MustCompile(`^[0-9]+$`)

// dockerfileHasUSER reports whether a Dockerfile-shaped file
// contains a `USER` directive. Used to suppress IAC_DOCKER_RUNS_AS_ROOT
// when the image actually drops privileges. Cheap whole-file pre-pass
// so the per-line scan can stay stateless.
func dockerfileHasUSER(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if dockerfileUserRe.MatchString(line) {
			return true
		}
	}
	return false
}

// dockerfileStageAliases returns the set of LOWER-CASED stage names declared
// by `FROM <image> AS <alias>` anywhere in the file. Dockerfile stage names
// are case-insensitive (the builder lower-cases them), so the set is keyed
// lower-case and callers must lower-case before lookup.
//
// Whole-file rather than prefix-of-file, matching the dockerfileHasUSER
// precedent: a Dockerfile may not forward-reference a stage, so any alias in
// the file is either already declared above the reference or the Dockerfile
// does not build at all.
//
// Returns nil (not an empty map) when the file declares no aliases, so the
// caller can skip installing the predicate entirely.
func dockerfileStageAliases(path string) map[string]struct{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var aliases map[string]struct{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		m := dockerfileFromRe.FindStringSubmatch(line)
		if m == nil || m[3] == "" {
			continue
		}
		if aliases == nil {
			aliases = map[string]struct{}{}
		}
		aliases[strings.ToLower(m[3])] = struct{}{}
	}
	return aliases
}

// dockerfileLineImageRef returns the image reference a FROM or
// `COPY --from=` line points at, and whether the line has one at all.
//
// For FROM it is group 2 — the token AFTER any BuildKit flag group, so
// `FROM --platform=$BUILDPLATFORM base AS x` resolves to `base` and not to the
// flag.
func dockerfileLineImageRef(line string) (string, bool) {
	if m := dockerfileFromRe.FindStringSubmatch(line); m != nil {
		return m[2], true
	}
	if m := dockerfileCopyFromRe.FindStringSubmatch(line); m != nil {
		return m[1], true
	}
	return "", false
}

// refIsKnownStage reports whether ref names a build stage declared in this
// same Dockerfile.
func refIsKnownStage(ref string, aliases map[string]struct{}) bool {
	if len(aliases) == 0 {
		return false
	}
	_, ok := aliases[strings.ToLower(ref)]
	return ok
}

// lineRefsKnownStage reports whether this FROM / COPY --from line's SOURCE is
// a stage declared elsewhere in the same Dockerfile (`FROM base AS production`
// after `FROM python:3.14-slim AS base`).
//
// Such a line is not an image reference at all, so it cannot be pinned: it
// inherits a base whose pinning was already judged on its own line. Flagging
// it a second time is a pure false positive that double-counts one decision
// and — because Deduplicate collapses the group and keeps the
// lexicographically smallest endpoint — points the surviving finding at the
// wrong line.
func lineRefsKnownStage(line string, aliases map[string]struct{}) bool {
	ref, ok := dockerfileLineImageRef(line)
	return ok && refIsKnownStage(ref, aliases)
}

// dockerfileRefIsPinned reports whether an image reference is reproducible, or
// is something this scanner has no business judging.
//
// Four exemptions, each a genuine non-finding rather than a suppression:
//
//   - a stage alias — judged on the line that declared it (see
//     lineRefsKnownStage);
//   - a `@sha256:` (or other algo) digest — the actual pin;
//   - `scratch` — the empty base image, which has no registry entry and
//     therefore no tag or digest to give it;
//   - a build-arg / variable reference (`${BASE_IMAGE}`, `$BASE`) and a bare
//     numeric stage index — the value is not knowable from the file, so any
//     verdict would be a guess.
func dockerfileRefIsPinned(ref string, aliases map[string]struct{}) bool {
	if ref == "" || refIsKnownStage(ref, aliases) {
		return true
	}
	if strings.EqualFold(ref, "scratch") {
		return true
	}
	if strings.ContainsAny(ref, "$") || dockerfileNumericRe.MatchString(ref) {
		return true
	}
	return dockerfileDigestRe.MatchString(ref)
}

// scanFile reads one file line-by-line and applies the supplied
// rules. We use bufio.Scanner with a generous buffer to handle
// auto-generated source files with long lines.
func scanFile(rootDir, path string, rules []*Rule) ([]evidence.Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel := pathRel(rootDir, path)

	// Whole-file pre-passes for rules that need context outside one line.
	//
	//   IAC_DOCKER_RUNS_AS_ROOT   — off for the WHOLE FILE when any
	//                               `USER <name>` directive exists.
	//   IAC_DOCKER_LATEST_TAG     — off for the specific LINES whose FROM
	//                               source is a stage declared in this file.
	//   IAC_DOCKER_FLOATING_TAG   — on only for the lines carrying an image
	//                               reference that is not digest-pinned.
	//
	// suppressRule is the whole-FILE channel; lineSuppress is the per-LINE
	// channel. They are deliberately distinct: routing alias suppression
	// through suppressRule would disable IAC_DOCKER_LATEST_TAG for every
	// multi-stage Dockerfile, including one whose first stage really is
	// `FROM golang:latest`.
	//
	// Both live only for this file. Rule values are shared BY POINTER across
	// the whole walk (scanCandidate appends &rules[i] from one slice reused
	// for every file), so per-file state must never be stored on a Rule — it
	// would leak the first Dockerfile's alias set into every later file.
	suppressRule := map[string]bool{}
	lineSuppress := map[string]func(string) bool{}
	if IsDockerfile(path) {
		if dockerfileHasUSER(path) {
			suppressRule["IAC_DOCKER_RUNS_AS_ROOT"] = true
		}
		aliases := dockerfileStageAliases(path)
		if len(aliases) > 0 {
			lineSuppress["IAC_DOCKER_LATEST_TAG"] = func(line string) bool {
				return lineRefsKnownStage(line, aliases)
			}
		}
		// IAC_DOCKER_FLOATING_TAG's Pattern matches every FROM and every
		// COPY --from; the pinning judgement lives here, where the whole
		// file's stage aliases are known. Installed unconditionally (not
		// gated on len(aliases)) because the exemptions for scratch, build
		// args and digests apply to single-stage files too.
		lineSuppress["IAC_DOCKER_FLOATING_TAG"] = func(line string) bool {
			ref, ok := dockerfileLineImageRef(line)
			return !ok || dockerfileRefIsPinned(ref, aliases)
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // 1 MiB max line

	var findings []evidence.Evidence
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		// Strip leading/trailing whitespace for the snippet but use
		// the original for pattern matching (some rules care about
		// leading whitespace).
		for _, r := range rules {
			if suppressRule[r.ID] {
				continue
			}
			if !r.Pattern.MatchString(line) {
				continue
			}
			if r.NegPattern != nil && r.NegPattern.MatchString(line) {
				continue
			}
			// Per-line suppression runs LAST, after Pattern and NegPattern,
			// so its cost is only paid on a line that already matched.
			if sup := lineSuppress[r.ID]; sup != nil && sup(line) {
				continue
			}
			endpoint := fmt.Sprintf("%s:%d", rel, lineNo)
			endpointCopy := endpoint
			snippet := strings.TrimSpace(line)
			// Redact credential material BEFORE truncation, so a long line
			// cannot smuggle a key past the 200-rune cut, and so the marker
			// itself is never sliced in half.
			if r.RedactMatch {
				snippet = r.Pattern.ReplaceAllStringFunc(snippet, secrets.RedactValue)
			}
			if utf8.RuneCountInString(snippet) > 200 {
				runes := []rune(snippet)
				snippet = string(runes[:199]) + "…"
			}
			findings = append(findings, evidence.Evidence{
				ID:         r.ID,
				RuleID:     r.ID,
				Title:      r.Title,
				Severity:   r.Severity,
				Source:     models.SourceWhitebox,
				SourceTier: models.TierNativeGo,
				Category:   r.Category,
				Endpoint:   endpoint,
				Evidence:   snippet,
				Fix:        r.Fix,
				References: []string{r.CWE},
				Confidence: r.Confidence,
				Line:       &endpointCopy,
			})
		}
	}
	return findings, sc.Err()
}

// pathRel returns path relative to rootDir using forward slashes.
// Errors degrade to the absolute path.
func pathRel(rootDir, path string) string {
	if rel, err := filepath.Rel(rootDir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// HasGoExtension is a small exported helper used by Applies funcs.
func HasGoExtension(path string) bool {
	return strings.HasSuffix(path, ".go")
}

// HasJSExtension reports JavaScript / TypeScript files.
func HasJSExtension(path string) bool {
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// HasJavaExtension reports Java source files (v0.27 Java regex SAST).
func HasJavaExtension(path string) bool {
	return strings.HasSuffix(path, ".java")
}

// IsDockerfile reports paths the Dockerfile rules apply to.
// Matches `Dockerfile`, `Dockerfile.<anything>`, and `*.dockerfile`.
func IsDockerfile(path string) bool {
	base := filepath.Base(path)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(base), ".dockerfile")
}

// IsYAML reports paths with a YAML extension. Caller (the k8s rule)
// is responsible for checking content shape (`apiVersion:` + `kind:`)
// before flagging anything.
func IsYAML(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// isBinaryFile sniffs the first 512 bytes of path and reports whether
// the file looks binary. The heuristic: any NUL byte → binary. This
// is the same shape stdlib http.DetectContentType uses internally and
// is robust enough for the scanner's "skip blobs" need. Returns
// (false, nil) when the file can't be opened — the caller will then
// try to scan it (and probably fail similarly), which is fine.
func isBinaryFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}
