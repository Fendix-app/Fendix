package semgrep

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ReachabilityLanguages is the per-language gate on Semgrep taint proofs
// (ADR-011, owner decision D1). A finding of a taint rule counts as Reachable,
// in tier models.TierSemgrepTaint with its dataflow trace as the TaintChain,
// only when EVERY language the rule declares is in this set. A language is
// added only after its taint pack reaches precision >= 0.90 on the corpus v2
// development set within the noise budget; the release gate checks holdout
// precision. Keys are Semgrep's canonical language names ("javascript",
// "typescript", "java", "go").
//
// Empty: no language has met the gate, so every Semgrep finding is a
// models.TierSemgrepShim finding.
var ReachabilityLanguages = map[string]bool{}

// A rule asks for its trace to count as reachability with this metadata.
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

// ruleLanguages returns the `languages` a rule declares, by rule id, or nil
// when the bundled pack has no such rule. Semgrep's result carries no
// language, so the rule pack is the only place to read it from. A var so
// tests can stand in a rule that is not bundled.
var ruleLanguages = bundledRuleLanguages

var bundledLanguages = sync.OnceValue(func() map[string][]string {
	rules, err := CatalogRules()
	if err != nil {
		slog.Warn("semgrep: cannot read the rule pack's languages; no taint finding counts as reachable", "error", err)
		return nil
	}
	out := make(map[string][]string, len(rules))
	for _, r := range rules {
		out[r.ID] = r.Languages
	}
	return out
})

func bundledRuleLanguages(ruleID string) []string { return bundledLanguages()[ruleID] }

// taintProof decides whether a result's dataflow trace counts as
// reachability and, when it does, returns the trace as a TaintChain: the
// source first, then the intermediate variables, then the sink.
//
// All three must hold, in this order:
//
//  1. the rule declares fendix_reachability: taint;
//  2. every language in the rule's `languages` is in ReachabilityLanguages
//     (a rule with no known languages fails: an empty "every" must not pass);
//  3. the trace has a source that decodes.
//
// The chain is decoded ONLY when all three hold. A shim finding therefore
// never carries a chain, and the chain can never become an identity input of
// a finding that is not reachable.
//
// The chain always ends at the finding's own location and operation (rel,
// the result's line, sink). The trace's sink step is replaced by it when it is
// that location, and it is appended otherwise (a sink reached through a call,
// or no sink in the trace). models.Fingerprint reads the file and, when the
// finding has no Sink, the operation off the last link, so ending there is
// what keeps a finding's identity the same whether or not its language is
// enabled.
func taintProof(r *semgrepResult, ruleID, absRoot, rel, sink string) ([]models.TaintLink, bool) {
	if !declaresTaintReachability(r.Extra.Metadata) {
		return nil, false
	}
	if !languagesEnabled(ruleLanguages(ruleID)) {
		return nil, false
	}
	if len(r.Extra.DataflowTrace) == 0 {
		return nil, false
	}
	var trace semgrepTrace
	if err := json.Unmarshal(r.Extra.DataflowTrace, &trace); err != nil {
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

	chain := make([]models.TaintLink, 0, len(steps)+1)
	for _, s := range steps {
		if s.Location.Path == "" || s.Location.Start.Line <= 0 {
			return nil, false
		}
		chain = append(chain, models.TaintLink{
			File: relPath(s.Location.Path, absRoot),
			Line: s.Location.Start.Line,
			Expr: traceExpr(s.Content),
		})
	}
	own := models.TaintLink{File: rel, Line: r.Start.Line, Expr: sink}
	if last := chain[len(chain)-1]; trace.TaintSink != nil && last.File == own.File && last.Line == own.Line {
		chain[len(chain)-1] = own
	} else {
		chain = append(chain, own)
	}
	return chain, true
}

func declaresTaintReachability(metadata map[string]interface{}) bool {
	v, ok := metadata[reachabilityMetadataKey].(string)
	return ok && strings.EqualFold(strings.TrimSpace(v), reachabilityTaint)
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

// traceExpr renders a trace step's matched code as a chain link's Expr: on
// one line, credential-shaped literals masked (the chain is published, like
// Sink), then bounded like the evidence snippet. Masking runs before the cut
// so a literal split by it cannot slip through unmasked.
func traceExpr(content string) string {
	expr := maskStringLiterals(strings.Join(strings.Fields(content), " "))
	if len(expr) > evidenceMaxLen {
		expr = expr[:evidenceMaxLen] + "..."
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
