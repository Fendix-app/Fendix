package semgrep

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ReachabilityLanguages is the per-language gate on Semgrep taint findings
// (ADR-011, owner decision D1). A match of a taint-mode rule that sets
// fendix_reachability: taint is Reachable, in tier models.TierSemgrepTaint,
// only when EVERY language the rule declares is in this set. A language is
// added only after its taint pack reaches precision >= 0.90 on the corpus v2
// development set within the noise budget; the release gate checks holdout
// precision. Keys are Semgrep's canonical language names ("javascript",
// "typescript", "java", "go").
//
// JavaScript and TypeScript met it with Task 4.3's pack
// (rules/javascript-*.yaml): precision 0.97 on the corpus v2 JS/TS cases
// (96 true and 3 false positives, none of the three from the pack) and no new
// finding on the clean node-express-realworld application. Every rule of that
// pack declares both, so neither is enabled without the other.
var ReachabilityLanguages = map[string]bool{
	"javascript": true,
	"typescript": true,
}

// A rule asks for its matches to count as reachability with this metadata.
const (
	reachabilityMetadataKey = "fendix_reachability"
	reachabilityTaint       = "taint"
)

// semgrepLanguageAliases maps the other names Semgrep accepts in a rule's
// `languages` to the canonical name ReachabilityLanguages is keyed by, so a
// rule written `languages: [ts]` is not silently left out of the gate.
var semgrepLanguageAliases = map[string]string{
	"js":     "javascript",
	"ts":     "typescript",
	"golang": "go",
}

// ruleSpec is what the gate reads from a rule's YAML. Semgrep's result names
// neither: it carries the rule's metadata, but not its `mode` or its
// `languages`.
type ruleSpec struct {
	Mode      string   `yaml:"mode"`
	Languages []string `yaml:"languages"`
}

// parseRuleSpecs reads the mode and languages of every rule in one rule file,
// keyed by rule id.
func parseRuleSpecs(data []byte) (map[string]ruleSpec, error) {
	var doc struct {
		Rules []struct {
			ID       string `yaml:"id"`
			ruleSpec `yaml:",inline"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]ruleSpec, len(doc.Rules))
	for _, r := range doc.Rules {
		out[r.ID] = r.ruleSpec
	}
	return out, nil
}

// ruleSpecs returns the mode and languages of a rule by id, and false for a
// rule the bundled pack does not contain. A var so tests can stand in a rule
// that is not bundled.
var ruleSpecs = bundledRuleSpec

var bundledSpecs = sync.OnceValue(func() map[string]ruleSpec {
	out := map[string]ruleSpec{}
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || filepath.Ext(path) != ".yaml" {
			return walkErr
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return err
		}
		specs, err := parseRuleSpecs(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for id, spec := range specs {
			out[id] = spec
		}
		return nil
	})
	if err != nil {
		slog.Warn("semgrep: cannot read the rule pack; no taint finding counts as reachable", "error", err)
		return nil
	}
	return out
})

func bundledRuleSpec(ruleID string) (ruleSpec, bool) {
	spec, ok := bundledSpecs()[ruleID]
	return spec, ok
}

// declaresTaintReachability reports whether a rule's metadata asks for its
// matches to count as reachability. It is a property of the rule alone, never
// of the gate or of what semgrep sent, so the identity rules keyed on it
// (taintRuleSink) hold whether or not the finding ends up reachable.
func declaresTaintReachability(metadata map[string]interface{}) bool {
	v, ok := metadata[reachabilityMetadataKey].(string)
	return ok && strings.EqualFold(strings.TrimSpace(v), reachabilityTaint)
}

// taintReachable decides whether a match counts as reachability (R-pf56).
// All three must hold:
//
//  1. the rule declares fendix_reachability: taint;
//  2. the rule is a taint-mode rule (`mode: taint` in the bundled pack): a
//     taint match exists only because a declared source reached the sink
//     within one function, which is the proof — a pattern match proves no
//     flow whatever its metadata says;
//  3. every language in the rule's `languages` is in ReachabilityLanguages (a
//     rule with no languages fails: an empty "every" must not pass).
//
// The dataflow trace is NOT a condition. A logged-out Semgrep never sends one,
// and a finding must not be reachable or not depending on a login.
func taintReachable(r *semgrepResult, ruleID string) bool {
	if !declaresTaintReachability(r.Extra.Metadata) {
		return false
	}
	spec, ok := ruleSpecs(ruleID)
	if !ok || !strings.EqualFold(strings.TrimSpace(spec.Mode), "taint") {
		return false
	}
	return languagesEnabled(spec.Languages)
}

func languagesEnabled(languages []string) bool {
	if len(languages) == 0 {
		return false
	}
	for _, l := range languages {
		l = strings.ToLower(strings.TrimSpace(l))
		if canonical, ok := semgrepLanguageAliases[l]; ok {
			l = canonical
		}
		if !ReachabilityLanguages[l] {
			return false
		}
	}
	return true
}

// taintRuleSink is the Sink of a rule that declares fendix_reachability: the
// match's own first line — read from disk, else the first line semgrep sent —
// masked, then bounded.
//
// Not the trace's sink and not the whole `extra.lines`: a logged-in run sends
// every line of a multi-line match there, a logged-out run sends
// "requires login" and the scanner reads one line from disk. The Sink is an
// identity input, so it must be the same text either way. Masking runs before
// the cut, so a literal the cut splits cannot slip through unmasked.
func taintRuleSink(r *semgrepResult) string {
	line := readSourceLine(r.Path, r.Start.Line)
	if line == "" {
		if sent := strings.TrimSpace(r.Extra.Lines); sent != semgrepRedactedLines {
			line, _, _ = strings.Cut(sent, "\n")
			line = strings.TrimSpace(line)
		}
	}
	return boundExpr(maskStringLiterals(line))
}

// taintChain is a reachable finding's chain. It always ends at the finding's
// own location and operation (own): models.Fingerprint reads the file, and the
// operation when there is no Sink, off the last link, so ending there keeps
// identity the same with or without a trace.
//
// A trace, when semgrep sends one (a logged-in run), adds the detail before
// it: the source, the intermediate variables, then the sink. The trace's sink
// step is replaced by own when it is that location, and own follows it
// otherwise (a sink reached through a call). A trace this decoder cannot read,
// or one without a source, adds nothing: the chain is own alone.
func taintChain(raw json.RawMessage, absRoot string, own models.TaintLink) []models.TaintLink {
	steps, ok := traceLinks(raw, absRoot)
	if !ok {
		return []models.TaintLink{own}
	}
	if last := steps[len(steps)-1]; last.File == own.File && last.Line == own.Line {
		steps[len(steps)-1] = own
		return steps
	}
	return append(steps, own)
}

// traceLinks decodes a dataflow trace into chain links in dataflow order. It
// fails for an absent or unreadable trace, a trace without a source, and a
// step without a file or line.
func traceLinks(raw json.RawMessage, absRoot string) ([]models.TaintLink, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var trace semgrepTrace
	if err := json.Unmarshal(raw, &trace); err != nil {
		return nil, false
	}
	steps, ok := sourceSteps(trace.TaintSource, 0)
	if !ok {
		return nil, false
	}
	steps = append(steps, trace.IntermediateVars...)
	if trace.TaintSink != nil {
		sinkPart, ok := sinkSteps(trace.TaintSink, 0)
		if !ok {
			return nil, false
		}
		steps = append(steps, sinkPart...)
	}
	links := make([]models.TaintLink, 0, len(steps)+1)
	for _, s := range steps {
		if s.Location.Path == "" || s.Location.Start.Line <= 0 {
			return nil, false
		}
		links = append(links, models.TaintLink{
			File: relPath(s.Location.Path, absRoot),
			Line: s.Location.Start.Line,
			Expr: traceExpr(s.Content),
		})
	}
	return links, true
}

// traceExpr renders a trace step's matched code as a chain link's Expr: on
// one line, credential-shaped literals masked (the chain is published, like
// Sink), then bounded like the evidence snippet.
func traceExpr(content string) string {
	return boundExpr(maskStringLiterals(strings.Join(strings.Fields(content), " ")))
}

func boundExpr(expr string) string {
	if len(expr) > evidenceMaxLen {
		return expr[:evidenceMaxLen] + "..."
	}
	return expr
}

// The trace types mirror match_dataflow_trace in Semgrep's output schema
// (semgrep_output_v1.atd), as Semgrep 1.141.0 encodes it:
//
//	"dataflow_trace": {
//	  "taint_source":      <match_call_trace>,
//	  "intermediate_vars": [{"location": <location>, "content": "name"}, ...],
//	  "taint_sink":        <match_call_trace>
//	}
//
// All three fields are optional in the schema.
type semgrepTrace struct {
	TaintSource      *semgrepCallTrace        `json:"taint_source"`
	IntermediateVars []semgrepIntermediateVar `json:"intermediate_vars"`
	TaintSink        *semgrepCallTrace        `json:"taint_sink"`
}

// semgrepLocation is the schema's location; only the file and the start line
// become a chain link.
type semgrepLocation struct {
	Path  string         `json:"path"`
	Start semgrepLineCol `json:"start"`
}

// semgrepIntermediateVar is match_intermediate_var, and also the shape every
// decoded trace step is flattened into.
type semgrepIntermediateVar struct {
	Location semgrepLocation `json:"location"`
	Content  string          `json:"content"`
}

// semgrepCallTrace is match_call_trace, an ATD variant. ATD encodes a variant
// as a TAGGED ARRAY, not an object:
//
//	["CliLoc",  [<location>, "content"]]
//	["CliCall", [[<location>, "content"], [<intermediate_var>, ...], <match_call_trace>]]
//
// CliLoc is the step itself. CliCall is a call the taint passes through: the
// call site, the callee's intermediate variables, and the trace inside it.
type semgrepCallTrace struct {
	step  semgrepIntermediateVar
	vars  []semgrepIntermediateVar
	inner *semgrepCallTrace // nil for CliLoc
}

var errMalformedTrace = errors.New("semgrep: malformed dataflow trace")

// maxCallDepth bounds how many nested calls a trace may pass through before
// it is treated as unreadable.
const maxCallDepth = 32

func (c *semgrepCallTrace) UnmarshalJSON(data []byte) error {
	var variant []json.RawMessage
	if err := json.Unmarshal(data, &variant); err != nil {
		return err
	}
	if len(variant) != 2 {
		return errMalformedTrace
	}
	var tag string
	if err := json.Unmarshal(variant[0], &tag); err != nil {
		return err
	}
	switch tag {
	case "CliLoc":
		return decodeLocAndContent(variant[1], &c.step)
	case "CliCall":
		var call []json.RawMessage
		if err := json.Unmarshal(variant[1], &call); err != nil {
			return err
		}
		if len(call) != 3 {
			return errMalformedTrace
		}
		if err := decodeLocAndContent(call[0], &c.step); err != nil {
			return err
		}
		if err := json.Unmarshal(call[1], &c.vars); err != nil {
			return err
		}
		c.inner = new(semgrepCallTrace)
		return json.Unmarshal(call[2], c.inner)
	default:
		return fmt.Errorf("semgrep: unknown dataflow trace variant %q", tag)
	}
}

// decodeLocAndContent decodes the schema's loc_and_content: [location, content].
func decodeLocAndContent(data json.RawMessage, step *semgrepIntermediateVar) error {
	var pair []json.RawMessage
	if err := json.Unmarshal(data, &pair); err != nil {
		return err
	}
	if len(pair) != 2 {
		return errMalformedTrace
	}
	if err := json.Unmarshal(pair[0], &step.Location); err != nil {
		return err
	}
	return json.Unmarshal(pair[1], &step.Content)
}

// sourceSteps flattens a source trace in dataflow order: taint returned by a
// call starts at the innermost source, passes the callee's variables, and
// leaves through the call site.
func sourceSteps(c *semgrepCallTrace, depth int) ([]semgrepIntermediateVar, bool) {
	if c == nil || depth > maxCallDepth {
		return nil, false
	}
	if c.inner == nil {
		return []semgrepIntermediateVar{c.step}, true
	}
	inner, ok := sourceSteps(c.inner, depth+1)
	if !ok {
		return nil, false
	}
	return append(append(inner, c.vars...), c.step), true
}

// sinkSteps flattens a sink trace in dataflow order: taint passed into a call
// enters at the call site, passes the callee's variables, and reaches the
// innermost sink.
func sinkSteps(c *semgrepCallTrace, depth int) ([]semgrepIntermediateVar, bool) {
	if c == nil || depth > maxCallDepth {
		return nil, false
	}
	if c.inner == nil {
		return []semgrepIntermediateVar{c.step}, true
	}
	inner, ok := sinkSteps(c.inner, depth+1)
	if !ok {
		return nil, false
	}
	steps := append([]semgrepIntermediateVar{c.step}, c.vars...)
	return append(steps, inner...), true
}
