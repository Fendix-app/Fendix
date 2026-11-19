package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/npm"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/pip"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// scannerStatusList accumulates the per-scanner outcome for the dep-CVE,
// secrets, semgrep, and textscan passes (F-L7/F-L13/F-L14). It replaces
// the old fail-open behaviour where a scanner crash was logged at WARN
// and silently dropped: every failure is now recorded, surfaced in a
// scan-end summary, exposed in ScanMetadata, and (with
// --fail-on-scanner-error) able to force a non-zero exit.
type scannerStatusList []reporters.ScannerStatus

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

// hasFailure reports whether any recorded scanner ran and errored.
// Skipped scanners do not count.
func (l scannerStatusList) hasFailure() bool {
	for _, s := range l {
		if s.Failed() {
			return true
		}
	}
	return false
}

// failedNames returns the names of every scanner that errored, for the
// scan-end summary line.
func (l scannerStatusList) failedNames() []string {
	var out []string
	for _, s := range l {
		if s.Failed() {
			out = append(out, s.Name)
		}
	}
	return out
}

// truncateErr renders an error to a bounded single-line detail string.
func truncateErr(err error) string {
	if err == nil {
		return ""
	}
	return truncateDetail(err.Error())
}

// detailMax is the byte bound of a scanner-status detail.
const detailMax = 240

// truncateDetail bounds a detail string the same way truncateErr does.
func truncateDetail(s string) string {
	if len(s) > detailMax {
		return s[:detailMax] + "…"
	}
	return s
}

// classifyErr maps an analyzer error to a fail reason. semgrep.ErrTimeout
// (or a bare context deadline) is a timeout; everything else is typed via
// neterr.Classify against the typed transport errors pip/npm/govulncheck
// now produce (Task 7): a *neterr.LookupError or *neterr.StatusError
// wrapping a transient (429/5xx) status, or a subprocess sentinel, maps to
// network_error; a deadline or subprocess-timeout sentinel maps to
// timeout. Everything else stays execution_error — in particular a 4xx
// StatusError other than 429, which is never transient.
func classifyErr(err error) reporters.ScannerReason {
	if err == nil {
		return reporters.ReasonExecutionError
	}
	if errors.Is(err, semgrep.ErrTimeout) {
		return reporters.ReasonTimeout
	}
	if errors.Is(err, semgrep.ErrMalformedOutput) {
		return reporters.ReasonMalformedOutput
	}
	switch neterr.Classify(err) {
	case neterr.KindTimeout:
		return reporters.ReasonTimeout
	case neterr.KindNetwork:
		return reporters.ReasonNetworkError
	}
	return reporters.ReasonExecutionError
}

// recordSemgrepRun records a semgrep run that completed and keeps its
// findings. Decision D1 (R-004, R-007): a run that did not evaluate every
// selected rule on every in-scope file is failed, whatever Semgrep's own exit
// says, and the findings it did produce are kept:
//
//   - reason timeout: a rule stopped on a file at --timeout, the remaining
//     rules skipped on a file after --timeout-threshold rule timeouts, a taint
//     fixpoint timeout (reported only in the --time profile), an interfile
//     timeout;
//   - reason execution_error: any other lost evaluation (a per-file out of
//     memory, stack overflow, internal matching error or too many matches, a
//     rule Semgrep loaded and skipped, and, decision D1', a file Semgrep could
//     not parse at all or parsed with more than a few lines skipped), a run
//     whose profile cannot show taint analysis finished, an option dropped for
//     an old host Semgrep that changes what is scanned, and a rule Semgrep
//     could not load. When both classes are present the reason is
//     execution_error.
//
// The detail is segments joined by "; " (contract C1/C2), loss segments first,
// then notes, then the declared exclusions, composed by scope.Compose so that
// none is ever cut: it names as many entries as fit and, when the budget runs
// out, ends with "and N more (see report metadata)"; semgrepLimitations writes
// the complete lists to the report's metadata. A file that only partially
// parses with few skipped lines loses no evaluation Semgrep can name: the run
// stays ok, the detail naming the skipped lines, as do options whose absence
// only changes explanation, run time or adds files.
func recordSemgrepRun(status *scannerStatusList, findings *[]evidence.Evidence, run semgrep.Run) {
	*findings = append(*findings, run.Findings...)
	lost, examples, timeoutOnly := semgrepLostEvaluation(run)
	// A rule Semgrep could not load means the pack did not run in full: the
	// run is failed, so a broken pack is neither read as a clean scan nor
	// allowed to stand in for the checks that cover for Semgrep (see
	// dropFallbackJSPatterns). Semgrep exits non-zero with a parseable
	// document in that case, and ScanRun accepts it.
	if len(run.RuleErrors) > 0 {
		noun := "rule errors"
		if len(run.RuleErrors) == 1 {
			noun = "rule error"
		}
		parts := make([]string, 0, len(run.RuleErrors))
		for _, e := range run.RuleErrors {
			parts = append(parts, scope.CleanText(e.Type+": "+e.Message))
		}
		detail := fmt.Sprintf("%d %s, rules not loaded: %s", len(parts), noun, strings.Join(parts, "; "))
		if len(run.Timeouts) > 0 {
			detail += fmt.Sprintf("; %d rule timeout(s) as well", len(run.Timeouts))
		}
		if len(run.FixpointTimeouts) > 0 {
			detail += fmt.Sprintf("; %d taint fixpoint timeout(s) as well", len(run.FixpointTimeouts))
		}
		status.failDetail(AnalyzerSemgrep, reporters.ReasonExecutionError, detail)
		return
	}

	var loss []scope.Seg
	if lost != "" {
		// The counts, and at each level the first entries that were lost.
		loss = append(loss, func(k int) string {
			if examples == nil || k == 0 {
				return lost
			}
			if e := examples(k); e != "" {
				return lost + "; " + e
			}
			return lost
		})
	}
	// qa-engine-01: Semgrep counted lost-evaluation entries the decoders could
	// not turn into a named loss. They fail the run all the same.
	if unread, unreadTimeoutOnly := semgrepUnreadLosses(run); unread != "" {
		if lost == "" {
			timeoutOnly = unreadTimeoutOnly
		} else {
			timeoutOnly = timeoutOnly && unreadTimeoutOnly
		}
		loss = append(loss, fixedSeg(unread))
	}
	// Decision D6 and D1': in-scope files the run left unread (over the size
	// cap, unreadable, never in Semgrep's paths.scanned, not parsed).
	if run.Coverage.Lost() {
		timeoutOnly = false
		loss = append(loss, run.Coverage.LostSeg())
	}
	// Execution-class gaps that are not about one file.
	if run.FixpointUnreported {
		timeoutOnly = false
		loss = append(loss, fixedSeg("semgrep reported no taint fixpoint timeouts list (--time), so a taint rule that ran out of time would be silent"))
	}
	if run.Report.DroppedDetection != "" {
		timeoutOnly = false
		why := run.Report.DroppedWhy
		if why == "" {
			why = "files may be skipped: an option that changes what is scanned was dropped"
		}
		loss = append(loss, fixedSeg(run.Report.Dropped+"; "+why))
	}
	failed := len(loss) > 0

	// Notes: per-file problems Semgrep reports as non-fatal that lose no rule
	// evaluation (a partial parse with few skipped lines) leave the run ok,
	// counted in the detail so they are not invisible. Lost evaluation is named
	// above.
	var notes []scope.Seg
	other := run.Report
	other.Incomplete = make(map[string]int, len(run.Report.Incomplete))
	for typ, n := range run.Report.Incomplete {
		if !semgrep.IsLossType(typ) {
			other.Incomplete[typ] = n
		}
	}
	if summary := other.Summary(); summary != "" {
		notes = append(notes, fixedSeg(summary))
	}
	if seg := partialParseSeg(run); seg != nil {
		notes = append(notes, seg)
	}
	// Options dropped for an older host Semgrep whose absence does not change
	// what is matched leave the run ok; the detail shows the run went without.
	if run.Report.Dropped != "" && run.Report.DroppedDetection == "" {
		notes = append(notes, fixedSeg(run.Report.Dropped))
	}
	// A nosemgrep comment removed results: each is reported, never silent.
	if seg := suppressedSeg(run); seg != nil {
		notes = append(notes, seg)
	}

	segs := append(append(loss, notes...), run.Coverage.DeclaredSeg())
	detail := scope.Compose(detailMax, segs...)
	switch {
	case failed && timeoutOnly:
		status.failDetail(AnalyzerSemgrep, reporters.ReasonTimeout, detail)
	case failed:
		status.failDetail(AnalyzerSemgrep, reporters.ReasonExecutionError, detail)
	case detail != "":
		status.okDetail(AnalyzerSemgrep, detail)
	default:
		status.ok(AnalyzerSemgrep)
	}
}

// fixedSeg is a segment that names no entries, so it reads the same at every
// level.
func fixedSeg(text string) scope.Seg { return func(int) string { return text } }

// partialParseSeg is the note for the files Semgrep parsed in part with few
// skipped lines (so the run is ok), "partial parse, skipped lines: a.py 4,
// b.js 10-12": the file and the lines Semgrep did not evaluate. nil when there
// are none. Names are safe tokens: this segment is one a classifier reads.
func partialParseSeg(run semgrep.Run) scope.Seg {
	kept := keptPartialParses(run)
	if len(kept) == 0 {
		return nil
	}
	return func(k int) string {
		shown := kept
		if k >= 0 && k < len(shown) {
			shown = shown[:k]
		}
		s := "partial parse, " + plural(len(kept), "file") + " with skipped lines"
		if len(shown) == 0 {
			return s
		}
		items := make([]string, len(shown))
		for i, p := range shown {
			items[i] = p.Describe(scope.SafeToken)
		}
		s += ": " + strings.Join(items, ", ")
		if more := len(kept) - len(shown); more > 0 {
			s += " +" + strconv.Itoa(more) + " more"
		}
		return s
	}
}

// keptPartialParses are the partial parses that did not fail the run: their
// skipped lines were reported and few.
func keptPartialParses(run semgrep.Run) []semgrep.PartialParse {
	var out []semgrep.PartialParse
	for _, p := range run.PartialParses {
		if p.Reported && !p.Lost && p.Total > 0 && p.Skipped > 0 {
			out = append(out, p)
		}
	}
	return out
}

// suppressedSeg is the note for the results a nosemgrep comment removed,
// "nosemgrep suppressed 2 results (js-sqli-taint routes.js:12, ...)".
func suppressedSeg(run semgrep.Run) scope.Seg {
	if len(run.Suppressed) == 0 {
		return nil
	}
	return func(k int) string {
		s := "nosemgrep suppressed " + plural(len(run.Suppressed), "result")
		shown := run.Suppressed
		if k >= 0 && k < len(shown) {
			shown = shown[:k]
		}
		if len(shown) == 0 {
			return s
		}
		items := make([]string, len(shown))
		for i, r := range shown {
			items[i] = scope.SafeToken(r.RuleID) + " " + scope.SafeToken(r.Path) + ":" + strconv.Itoa(r.Line)
		}
		s += " (" + strings.Join(items, ", ")
		if more := len(run.Suppressed) - len(shown); more > 0 {
			s += " +" + strconv.Itoa(more) + " more"
		}
		return s + ")"
	}
}

// maxLimitations bounds how many entries of metadata.coverage.limitations the
// listing of excluded and lost files may add; past it one entry says how many
// were not listed. The counts in the scanner-status details stay exact.
const maxLimitations = 400

// capLimitations keeps at most max entries; the last says how many it dropped.
func capLimitations(entries []string, max int) []string {
	if len(entries) <= max {
		return entries
	}
	out := append([]string(nil), entries[:max-1]...)
	return append(out, "and "+strconv.Itoa(len(entries)-(max-1))+" more entries not listed (limit "+strconv.Itoa(max)+")")
}

// semgrepLimitations is the complete listing of what the Semgrep run lost,
// skipped or suppressed, for the report's metadata.coverage.limitations: every
// kept name, sanitised, in entries of at most 240 bytes (contracts C1, C2). The
// scanner-status detail names the first few and points here.
func semgrepLimitations(run semgrep.Run) []string {
	var out []string
	cov := run.Coverage
	out = append(out, cov.Limitations(AnalyzerSemgrep)...)
	if len(run.Timeouts) > 0 {
		items := make([]string, len(run.Timeouts))
		for i, t := range run.Timeouts {
			items[i] = scope.Sanitize(t.Path) + " (" + scope.Sanitize(orUnknown(t.RuleID, "unknown rule")) + ")"
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": lost evaluation, rule timeout: ", items)...)
	}
	if len(run.ThresholdFiles) > 0 {
		items := make([]string, len(run.ThresholdFiles))
		for i, p := range run.ThresholdFiles {
			items[i] = scope.Sanitize(p)
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": lost evaluation, every other rule skipped after rule timeouts: ", items)...)
	}
	if len(run.FixpointTimeouts) > 0 {
		items := make([]string, len(run.FixpointTimeouts))
		for i, f := range run.FixpointTimeouts {
			item := scope.Sanitize(orUnknown(f.Path, "unknown file"))
			if f.Line > 0 {
				item += ":" + strconv.Itoa(f.Line)
			}
			items[i] = item
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": lost evaluation, taint fixpoint timeout: ", items)...)
	}
	if len(run.FileErrors) > 0 {
		items := make([]string, len(run.FileErrors))
		for i, e := range run.FileErrors {
			items[i] = scope.Sanitize(orUnknown(e.Path, "unknown file")) + " (" + scope.Sanitize(e.Type) + ")"
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": lost evaluation, per-file error: ", items)...)
	}
	if len(run.ParseFailures) > 0 {
		items := make([]string, len(run.ParseFailures))
		for i, f := range run.ParseFailures {
			items[i] = scope.Sanitize(orUnknown(f.Path, "unknown file")) + " (" + scope.Sanitize(f.Type) + ")"
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": lost evaluation, parse failure: ", items)...)
	}
	if kept := keptPartialParses(run); len(kept) > 0 {
		items := make([]string, len(kept))
		for i, p := range kept {
			items[i] = p.Describe(scope.Sanitize)
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": partial parse, skipped lines: ", items)...)
	}
	if len(run.Suppressed) > 0 {
		items := make([]string, len(run.Suppressed))
		for i, r := range run.Suppressed {
			items[i] = scope.Sanitize(r.RuleID) + " " + scope.Sanitize(r.Path) + ":" + strconv.Itoa(r.Line)
		}
		out = append(out, scope.ChunkEntries(AnalyzerSemgrep+": nosemgrep suppressed: ", items)...)
	}
	return out
}

// semgrepUnreadLosses compares what Semgrep counted (Report.Incomplete) with
// what the decoders named (Timeouts, the fixpoint timeouts reported in
// `errors`, FileErrors, ParseFailures), type by type, for every lost-evaluation
// type. Any surplus is an entry Semgrep reported that could not be read; it
// returns the detail for them, "2 lost-evaluation entries semgrep reported
// could not be read (Timeout 2)", and whether every one is a timeout class, or
// "" when every entry was read.
func semgrepUnreadLosses(run semgrep.Run) (string, bool) {
	const fixpoint = "Fixpoint timeout"
	key := func(typ string) string {
		if typ == "FixpointTimeout" {
			return fixpoint
		}
		return typ
	}
	reported := map[string]int{}
	for typ, n := range run.Report.Incomplete {
		if semgrep.IsLossType(typ) {
			reported[key(typ)] += n
		}
	}
	if len(reported) == 0 {
		return "", false
	}
	decoded := map[string]int{"Timeout": len(run.Timeouts)}
	for _, f := range run.FixpointTimeouts {
		if f.InErrors {
			decoded[fixpoint]++
		}
	}
	for _, e := range run.FileErrors {
		decoded[key(e.Type)]++
	}
	for _, f := range run.ParseFailures {
		decoded[key(f.Type)]++
	}
	types := make([]string, 0, len(reported))
	total := 0
	timeoutOnly := true
	for typ, n := range reported {
		if surplus := n - decoded[typ]; surplus > 0 {
			types = append(types, typ)
			total += surplus
			reported[typ] = surplus
			if !semgrep.IsTimeoutType(typ) {
				timeoutOnly = false
			}
		}
	}
	if total == 0 {
		return "", false
	}
	sort.Strings(types)
	for i, typ := range types {
		types[i] = fmt.Sprintf("%s %d", typ, reported[typ])
	}
	noun := "lost-evaluation entries semgrep reported"
	if total == 1 {
		noun = "lost-evaluation entry semgrep reported"
	}
	return fmt.Sprintf("%d %s could not be read (%s)", total, noun, strings.Join(types, ", ")), timeoutOnly
}

// semgrepLossExamples bounds how many rule/file pairs the detail names at most.
const semgrepLossExamples = 3

// semgrepLostEvaluation describes what a run lost: the counts part
// ("lost evaluation: 3 rule timeouts on 1 file, ..."), the examples segment
// ("first: <path> (<rule>, <rule>); ..."), and whether every loss is a timeout
// class. The counts are "" and the segment nil when the run lost no rule
// evaluation on any file.
func semgrepLostEvaluation(run semgrep.Run) (counts string, examples scope.Seg, timeoutOnly bool) {
	var parts []string
	timeoutOnly = true
	if n := len(run.Timeouts); n > 0 {
		files := map[string]bool{}
		for _, t := range run.Timeouts {
			files[t.Path] = true
		}
		parts = append(parts, fmt.Sprintf("%s on %s", plural(n, "rule timeout"), plural(len(files), "file")))
	}
	if n := len(run.ThresholdFiles); n > 0 {
		parts = append(parts, fmt.Sprintf("every other rule skipped on %s after %d rule timeouts", plural(n, "file"), semgrep.TimeoutThreshold()))
	}
	if n := len(run.FixpointTimeouts); n > 0 {
		files := map[string]bool{}
		for _, f := range run.FixpointTimeouts {
			files[f.Path] = true
		}
		parts = append(parts, fmt.Sprintf("%s on %s", plural(n, "taint fixpoint timeout"), plural(len(files), "file")))
	}
	if n := len(run.FileErrors); n > 0 {
		byType := map[string]int{}
		for _, e := range run.FileErrors {
			byType[e.Type]++
			if !e.IsTimeout() {
				timeoutOnly = false
			}
		}
		types := make([]string, 0, len(byType))
		for t := range byType {
			types = append(types, t)
		}
		sort.Strings(types)
		for i, t := range types {
			types[i] = fmt.Sprintf("%s %d", t, byType[t])
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", plural(n, "per-file error"), strings.Join(types, ", ")))
	}
	if n := len(run.SkippedRules); n > 0 {
		timeoutOnly = false
		parts = append(parts, plural(n, "rule")+" skipped by semgrep")
	}
	if len(parts) == 0 {
		return "", nil, false
	}

	// Examples, grouped by file in first-seen order, at most k items in all.
	type example struct{ file, item string }
	var items []example
	for _, t := range run.Timeouts {
		items = append(items, example{t.Path, orUnknown(t.RuleID, "unknown rule")})
	}
	for _, f := range run.FixpointTimeouts {
		item := "taint fixpoint"
		if f.Line > 0 {
			item += " at line " + strconv.Itoa(f.Line)
		}
		if f.Rules > 0 {
			item += fmt.Sprintf(", %s from %s", plural(f.Rules, "taint rule"), orUnknown(f.FirstRule, "unknown rule"))
		}
		items = append(items, example{f.Path, item})
	}
	for _, e := range run.FileErrors {
		item := e.Type
		if e.RuleID != "" {
			item += " running " + e.RuleID
		}
		items = append(items, example{e.Path, item})
	}
	examples = func(k int) string {
		if k < 0 || k > semgrepLossExamples {
			k = semgrepLossExamples
		}
		var order []string
		byFile := map[string][]string{}
		for i, it := range items {
			if i >= k {
				break
			}
			file := scope.Sanitize(orUnknown(it.file, "unknown file"))
			if _, ok := byFile[file]; !ok {
				order = append(order, file)
			}
			byFile[file] = append(byFile[file], it.item)
		}
		groups := make([]string, 0, len(order)+1)
		for _, file := range order {
			groups = append(groups, file+" ("+strings.Join(byFile[file], ", ")+")")
		}
		if len(run.SkippedRules) > 0 && k > 0 {
			skipped := run.SkippedRules
			if len(skipped) > semgrepLossExamples {
				skipped = skipped[:semgrepLossExamples]
			}
			groups = append(groups, "skipped rules ("+strings.Join(skipped, ", ")+")")
		}
		if len(groups) == 0 {
			return ""
		}
		return "first: " + strings.Join(groups, "; ")
	}
	return "lost evaluation: " + strings.Join(parts, ", "), examples, timeoutOnly
}

// plural is "1 file" or "3 files".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func orUnknown(s, unknown string) string {
	if s == "" {
		return unknown
	}
	return s
}

// recordDepScanResult records the outcome of a pip-style dep scan (one
// that returns an empty slice rather than a sentinel when no manifest is
// found) and appends any findings. Used by both the online and offline
// pip paths so they record status identically.
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

// recordNpmScanResult records the npm dep-scan outcome, preserving the
// existing sentinel handling (lockfile-missing advisory finding,
// no-lockfile silent skip). Shared by the online and offline npm paths.
// Returns the updated findings slice.
func (o *Orchestrator) recordNpmScanResult(status *scannerStatusList, findings *[]evidence.Evidence, npmFindings []evidence.Evidence, err error) []evidence.Evidence {
	if len(npmFindings) > 0 {
		*findings = append(*findings, npmFindings...)
	}
	switch {
	case err == nil:
		slog.Info("native npm deps scan complete", "findings", len(npmFindings))
		status.ok("npm")
	case errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent):
		// Single INFO finding — flag the gap without producing noise.
		// Surfaced by the Track 4 heavy-eval on Juice Shop / dvna / etc.
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

// depScanners are the three dependency-CVE passes that the report's
// `checks_run` list has always summarised under the single coarse label
// "deps". Kept as one label for backward compatibility: consumers parse
// checks_run for that exact string.
var depScanners = map[string]bool{"govulncheck": true, "pip": true, "npm": true}

// codeScannerLabels returns the coarse `checks_run` labels for the code
// analysis passes that ACTUALLY completed, derived from the recorded
// per-scanner status rather than from the scan configuration.
//
// The list used to be hand-appended whenever a code path was configured,
// which meant a scan reported semgrep under "checks_run" while
// scanner_status simultaneously recorded it as skipped because the binary
// was missing — the same document asserting a check both ran and did not.
// A consumer cannot audit a release decision made from evidence that was
// never gathered, so only an `ok` pass earns its label here.
//
// Order is fixed (secrets, semgrep, deps) rather than derived from map or
// slice iteration, so two identical scans render byte-identical reports.
func codeScannerLabels(status scannerStatusList) []string {
	ran := make(map[string]bool, len(status))
	for _, s := range status {
		if s.State == reporters.ScannerOK {
			ran[s.Name] = true
		}
	}
	deps := false
	for name := range depScanners {
		if ran[name] {
			deps = true
			break
		}
	}

	var out []string
	if ran["secrets"] {
		out = append(out, "secrets")
	}
	if ran["semgrep"] {
		out = append(out, "semgrep")
	}
	if deps {
		out = append(out, "deps")
	}
	return out
}

// jsFallbackPrefix starts the rule ids of the Python engine's JavaScript
// pattern checks (SEC-JS_EVAL, SEC-JS_INNER_HTML, SEC-JS_DOCUMENT_WRITE,
// SEC-JS_SQL_TEMPLATE).
const jsFallbackPrefix = "SEC-JS_"

// semgrepRunSucceeded reports whether the run-level semgrep entry is ok. There
// is one status for the whole Semgrep run and none per pack; the JavaScript
// pack is always part of it.
func (l scannerStatusList) semgrepRunSucceeded() bool {
	for _, s := range l {
		if s.Name == AnalyzerSemgrep {
			return s.State == reporters.ScannerOK
		}
	}
	return false
}

// jsSemgrepPackBlocks reports whether Semgrep's JavaScript and TypeScript taint
// matches can block: both languages are in semgrep.ReachabilityLanguages
// (ADR-011). While they are not (ruling R-pf81: real-world precision is too low),
// every JS/TS Semgrep taint match is a plain warning, and the Python engine's
// JS_SQL_TEMPLATE pattern is the only JavaScript SQL finding that can block.
// Dropping it then would turn nine blocking corpus cases (express, nestjs and
// nextjs sqli direct, indirect and cross_file) into warnings.
func jsSemgrepPackBlocks() bool {
	return semgrep.ReachabilityLanguages["javascript"] && semgrep.ReachabilityLanguages["typescript"]
}

// dropFallbackJSPatterns removes the Python engine's JavaScript pattern
// findings (rule ids SEC-JS_*) when Semgrep's JavaScript pack has taken over:
// the Semgrep run succeeded AND its JS/TS taint findings can block
// (jsSemgrepPackBlocks). They are the fallback for a scan without Semgrep
// (--fast, or no binary), where nothing else reads JavaScript beyond textscan;
// once the pack answers they only repeat it, less precisely (D4). A Semgrep run
// that is skipped or failed, including one that could not load a rule, keeps
// them, and so does a run whose JS/TS taint gate is closed.
//
// evid is the Python engine's output only. A Semgrep finding's ID also starts
// with SEC-JS_ (js-cmdi-taint reports as SEC-JS_CMDI_TAINT), but its RuleID is
// the bundled rule's own, and Semgrep findings are never passed here.
func dropFallbackJSPatterns(evid []evidence.Evidence, status scannerStatusList) []evidence.Evidence {
	if !status.semgrepRunSucceeded() || !jsSemgrepPackBlocks() {
		return evid
	}
	kept := evid[:0:0]
	for _, e := range evid {
		id := e.RuleID
		if id == "" {
			id = e.ID
		}
		if strings.HasPrefix(id, jsFallbackPrefix) {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}
