package engine

// RC-9 (1a) + V2 (Round 6 closure, owner ruling OR-85).
//
// CollapseDuplicateLocations used to fold every cross-analyzer finding on one
// (category, file:line) into the single most trusted one. On a line with two
// different constructs that dropped one of them (its title, rule, SARIF result
// and fingerprint), and strongestClaim / proofDonor then moved the dropped
// construct's confidence and proof onto the survivor: `eval(x); require(y)` on
// one line became one `require()` finding that BLOCKed on the eval's grade.
//
// Approved: fold only members that describe the SAME construct, and transfer
// confidence and proof only inside one construct. These tests build the findings
// the real analyzers emit (their rule ids, CWE references, tiers and grades,
// read from textscan/rules.go, the Python check registry and the Semgrep rule
// pack) and pin both halves, and the pairs the real Tier B corpus folds.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

type c9Member struct {
	rule  string
	title string
	cat   string
	cwe   []string
	tier  models.SourceTier
	conf  models.Confidence
	sev   models.Severity
}

func (m c9Member) at(endpoint string) models.Finding {
	refs := append([]string(nil), m.cwe...)
	return models.Finding{
		RuleID: m.rule, Title: m.title, Category: m.cat, Endpoint: endpoint,
		Severity: m.sev, Source: models.SourceWhitebox, SourceTier: m.tier,
		Confidence: m.conf, References: refs,
		Evidence: "e:" + m.rule, Fix: "f:" + m.rule,
	}
}

// The members, as their analyzers emit them.
var (
	// textscan (tier native_go, MEDIUM).
	c9TsEval = c9Member{"JS_EVAL_LITERAL", "eval() with non-literal argument", "injection", []string{"CWE-95"}, models.TierNativeGo, models.ConfidenceMedium, models.SeverityHigh}
	c9TsReq  = c9Member{"JS_REQUIRE_INTERPOLATION", "require() called with a non-literal path", "injection", []string{"CWE-95"}, models.TierNativeGo, models.ConfidenceMedium, models.SeverityHigh}
	c9TsExec = c9Member{"JS_CHILD_PROCESS_SHELL", "child_process.exec with shell semantics", "injection", []string{"CWE-78"}, models.TierNativeGo, models.ConfidenceMedium, models.SeverityHigh}
	// The Python engine's JavaScript regex heuristics (tier "", HIGH or MEDIUM).
	c9PyJSEval = c9Member{"SEC-JS_EVAL", "Unsafe use of eval() in JavaScript", "injection", []string{"CWE-95"}, "", models.ConfidenceHigh, models.SeverityHigh}
	c9PyJSSQL  = c9Member{"SEC-JS_SQL_TEMPLATE", "SQL query built via template literal — injection risk", "injection", []string{"CWE-89"}, "", models.ConfidenceHigh, models.SeverityHigh}
	c9PyJSHTML = c9Member{"SEC-JS_INNER_HTML", "Unsafe assignment to innerHTML — XSS risk", "injection", []string{"CWE-79"}, "", models.ConfidenceMedium, models.SeverityHigh}
	// Semgrep (tier semgrep_shim, MEDIUM).
	c9SgCmdiSink = c9Member{"js-cmdi-sink", "Command injection (sink)", "injection", []string{"CWE-78"}, models.TierSemgrepShim, models.ConfidenceMedium, models.SeverityHigh}
	c9SgSQLTaint = c9Member{"js-sqli-taint", "SQL injection (taint)", "injection", []string{"CWE-89"}, models.TierSemgrepShim, models.ConfidenceMedium, models.SeverityHigh}
)

func c9RuleIDs(fs []models.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	sort.Strings(out)
	return out
}

func c9ByRule(t *testing.T, fs []models.Finding, rule string) models.Finding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no finding for rule %s among %v", rule, c9RuleIDs(fs))
	return models.Finding{}
}

func c9HasRef(f models.Finding, ref string) bool {
	for _, r := range f.References {
		if r == ref {
			return true
		}
	}
	return false
}

// c9Permutations returns every ordering of in (n <= 5).
func c9Permutations(in []models.Finding) [][]models.Finding {
	if len(in) <= 1 {
		return [][]models.Finding{append([]models.Finding(nil), in...)}
	}
	var out [][]models.Finding
	for i := range in {
		rest := append(append([]models.Finding(nil), in[:i]...), in[i+1:]...)
		for _, p := range c9Permutations(rest) {
			out = append(out, append([]models.Finding{in[i]}, p...))
		}
	}
	return out
}

// TestCollapse_DifferentConstructsOnOneLineStaySeparate: each case is a real
// pair of rules that fired on one line. They describe different constructs, so
// each keeps its own finding, rule, title and grade, and neither leaves a
// `rule:` reference on the other.
func TestCollapse_DifferentConstructsOnOneLineStaySeparate(t *testing.T) {
	cases := []struct {
		name  string
		in    []c9Member
		rules []string // the rules that must survive as findings, sorted
	}{
		{"eval-and-require", []c9Member{c9TsEval, c9TsReq, c9PyJSEval}, []string{"JS_EVAL_LITERAL", "JS_REQUIRE_INTERPOLATION"}},
		{"require-and-python-eval", []c9Member{c9TsReq, c9PyJSEval}, []string{"JS_REQUIRE_INTERPOLATION", "SEC-JS_EVAL"}},
		{"eval-and-innerhtml", []c9Member{c9TsEval, c9PyJSHTML}, []string{"JS_EVAL_LITERAL", "SEC-JS_INNER_HTML"}},
		{"require-and-innerhtml", []c9Member{c9TsReq, c9PyJSHTML}, []string{"JS_REQUIRE_INTERPOLATION", "SEC-JS_INNER_HTML"}},
		{"eval-and-sql-template", []c9Member{c9TsEval, c9PyJSSQL}, []string{"JS_EVAL_LITERAL", "SEC-JS_SQL_TEMPLATE"}},
		{"exec-and-sql-template", []c9Member{c9TsExec, c9PyJSSQL, c9SgCmdiSink}, []string{"JS_CHILD_PROCESS_SHELL", "SEC-JS_SQL_TEMPLATE"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var in []models.Finding
			for _, m := range c.in {
				in = append(in, m.at("n.js:2"))
			}
			for _, p := range c9Permutations(in) {
				got := CollapseDuplicateLocations(p)
				if !reflect.DeepEqual(c9RuleIDs(got), c.rules) {
					t.Fatalf("surviving rules = %v, want %v (a different construct was folded away)", c9RuleIDs(got), c.rules)
				}
			}
		})
	}
}

// TestCollapse_ConfidenceDoesNotCrossConstructs is the V2 rule. Each survivor
// carries the grade of its own construct: the eval keeps the HIGH its same
// construct partner asserted, the require() and the exec keep their own MEDIUM
// and never adopt the SQL template's HIGH or the eval's.
func TestCollapse_ConfidenceDoesNotCrossConstructs(t *testing.T) {
	t.Run("oneline-eval-and-require", func(t *testing.T) {
		in := []models.Finding{c9TsEval.at("app.js:3"), c9TsReq.at("app.js:3"), c9PyJSEval.at("app.js:3")}
		got := CollapseDuplicateLocations(in)
		if len(got) != 2 {
			t.Fatalf("eval(x); require(y) on one line must stay two findings, got %v", c9RuleIDs(got))
		}
		ev, rq := c9ByRule(t, got, "JS_EVAL_LITERAL"), c9ByRule(t, got, "JS_REQUIRE_INTERPOLATION")
		if ev.Confidence != models.ConfidenceHigh {
			t.Errorf("eval confidence = %s: it must keep the HIGH its same-construct partner SEC-JS_EVAL asserted", ev.Confidence)
		}
		if !c9HasRef(ev, "rule:SEC-JS_EVAL") {
			t.Errorf("eval references = %v: the folded same-construct rule must stay visible", ev.References)
		}
		if rq.Confidence != models.ConfidenceMedium {
			t.Errorf("require() confidence = %s: it inherited the eval's grade across constructs", rq.Confidence)
		}
		for _, r := range rq.References {
			if strings.HasPrefix(r, "rule:") {
				t.Errorf("require() carries %q: nothing of the eval was folded into it", r)
			}
		}
	})
	t.Run("neighbours-exec-must-not-borrow-the-sql-grade", func(t *testing.T) {
		in := []models.Finding{c9TsExec.at("n.js:2"), c9PyJSSQL.at("n.js:2"), c9SgCmdiSink.at("n.js:2")}
		got := CollapseDuplicateLocations(in)
		ex := c9ByRule(t, got, "JS_CHILD_PROCESS_SHELL")
		if ex.Confidence != models.ConfidenceMedium {
			t.Errorf("exec confidence = %s: it borrowed the SQL template's grade", ex.Confidence)
		}
		if !c9HasRef(ex, "rule:js-cmdi-sink") {
			t.Errorf("exec references = %v: the Semgrep command-injection twin is the same construct and folds in", ex.References)
		}
		if sq := c9ByRule(t, got, "SEC-JS_SQL_TEMPLATE"); sq.Confidence != models.ConfidenceHigh {
			t.Errorf("SQL template confidence = %s, want its own HIGH", sq.Confidence)
		}
	})
	t.Run("same-construct-transfer-stays", func(t *testing.T) {
		// captcha.ts / the first-party eval: textscan MEDIUM + the Python regex
		// HIGH on the SAME eval. Still one finding at HIGH (Round 5, security5-05).
		got := CollapseDuplicateLocations([]models.Finding{c9TsEval.at("calc.js:4"), c9PyJSEval.at("calc.js:4")})
		if len(got) != 1 || got[0].RuleID != "JS_EVAL_LITERAL" || got[0].Confidence != models.ConfidenceHigh {
			t.Fatalf("same-construct pair = %v conf %v, want one JS_EVAL_LITERAL at HIGH", c9RuleIDs(got), got[0].Confidence)
		}
	})
}

// TestCollapse_ProofDoesNotCrossConstructs: a taint chain proves ITS construct.
func TestCollapse_ProofDoesNotCrossConstructs(t *testing.T) {
	chain := []models.TaintLink{{File: "n.js", Line: 1, Expr: "req.query.q"}, {File: "n.js", Line: 2, Expr: "db.query"}}
	proved := c9PySQL("n.js:2")
	proved.TaintChain, proved.Reachable = chain, true
	other := c9TsExec.at("n.js:2")
	got := CollapseDuplicateLocations([]models.Finding{other, proved})
	ex := c9ByRule(t, got, "JS_CHILD_PROCESS_SHELL")
	if len(ex.TaintChain) != 0 || ex.Reachable {
		t.Errorf("exec adopted the SQL injection's proof (reachable=%v chain=%d)", ex.Reachable, len(ex.TaintChain))
	}
	sq := c9ByRule(t, got, "python.ast/PY_SQL_INJECTION")
	if len(sq.TaintChain) != 2 || !sq.Reachable {
		t.Errorf("the proving finding lost its own proof: reachable=%v chain=%d", sq.Reachable, len(sq.TaintChain))
	}
}

func c9PySQL(endpoint string) models.Finding {
	return models.Finding{
		RuleID: "python.ast/PY_SQL_INJECTION", Title: "SQL query built via string formatting — injection risk",
		Category: "injection", Endpoint: endpoint, Severity: models.SeverityCritical,
		Source: models.SourceWhitebox, SourceTier: models.TierTreeSitter, Confidence: models.ConfidenceMedium,
		References: []string{"CWE-89"}, Evidence: "e:sql", Fix: "f:sql",
	}
}

// TestCollapse_SameConstructPairsFromTheCorpusStillFold: every pair of rules the
// real Tier B corpus folded (93 findings, 27 rule pairs; the rc reports'
// `rule:` references), with the CWE references the analyzers attach. The
// native secrets scanner and Semgrep disagree on the CWE of a hardcoded
// password (259 and 798) and are the same line's same credential: they must
// keep folding (the intent of 910095f).
func TestCollapse_SameConstructPairsFromTheCorpusStillFold(t *testing.T) {
	mk := func(rule, cat string, tier models.SourceTier, conf models.Confidence, cwe ...string) c9Member {
		return c9Member{rule, "t:" + rule, cat, cwe, tier, conf, models.SeverityHigh}
	}
	ast, ts, sg, nat := models.TierTreeSitter, models.TierNativeGo, models.TierSemgrepShim, models.SourceTier("")
	M, H := models.ConfidenceMedium, models.ConfidenceHigh
	pairs := []struct{ a, b c9Member }{
		{c9TsEval, c9PyJSEval},
		{mk("python.ast/PY_EVAL", "injection", ast, M, "CWE-95"), mk("python-eval-injection", "injection", sg, M, "CWE-95")},
		{mk("python.ast/PY_SQL_INJECTION", "injection", ast, M, "CWE-89"), mk("python-sql-injection-string-format", "injection", sg, M, "CWE-89")},
		{mk("python.ast/PY_SQL_INJECTION", "injection", ast, M, "CWE-89"), mk("django-orm-raw-sql", "injection", sg, M, "CWE-89")},
		{c9TsExec, c9SgCmdiSink},
		{mk("python.ast/PY_SUBPROCESS_SHELL", "injection", ast, M, "CWE-78"), mk("python-subprocess-shell-true-with-variable", "injection", sg, M, "CWE-78")},
		{mk("python.ast/PY_OS_SYSTEM", "injection", ast, M, "CWE-78"), mk("python-command-injection-shell-true", "injection", sg, M, "CWE-78")},
		{mk("python.ast/PY_PICKLE_LOAD", "injection", ast, H, "CWE-502"), mk("python-pickle-loads-untrusted", "injection", sg, M, "CWE-502")},
		{mk("python.ast/PY_YAML_UNSAFE_LOAD", "injection", ast, H, "CWE-502"), mk("python-yaml-load-unsafe", "injection", sg, M, "CWE-502")},
		{c9PyJSSQL, c9SgSQLTaint},
		{mk("js-sqli-taint", "injection", sg, M, "CWE-89"), mk("js-sqli-sink", "injection", sg, M, "CWE-89")},
		{mk("JAVA_WEAK_RANDOM", "crypto", ts, M, "CWE-330"), mk("java-weak_random_token-taint", "crypto", sg, M, "CWE-330")},
		{mk("python.ast/PY_WEAK_CRYPTO_PASSWORD", "secrets", ast, M, "CWE-916"), mk("python-md5-used-for-password", "secrets", sg, M, "CWE-327")},
		{mk("python.ast/PY_WEAK_CRYPTO_PASSWORD", "secrets", ast, M, "CWE-916"), mk("python-sha1-used-for-password", "secrets", sg, M, "CWE-327")},
		// The credential family: the native scanner, textscan and Semgrep, with
		// the CWE each one chose.
		{mk("secrets/GENERIC_API_KEY", "secrets", nat, H, "CWE-798"), mk("python-hardcoded-secret-assignment", "secrets", sg, M, "CWE-798")},
		{mk("secrets/HARDCODED_SECRET_CONFIG", "secrets", nat, H, "CWE-798"), mk("python-hardcoded-secret-assignment", "secrets", sg, M, "CWE-798")},
		{mk("secrets/HARDCODED_PASSWORD", "secrets", nat, H, "CWE-259"), mk("python-hardcoded-secret-assignment", "secrets", sg, M, "CWE-798")},
		{mk("secrets/AWS_ACCESS_KEY", "secrets", nat, H, "CWE-798"), mk("python-aws-access-key-id-literal", "secrets", sg, M, "CWE-798")},
		{mk("secrets/AWS_ACCESS_KEY", "secrets", nat, H, "CWE-798"), mk("GO_HARDCODED_AWS_KEY", "secrets", ts, H, "CWE-798")},
		{mk("secrets/PRIVATE_KEY", "secrets", nat, H, "CWE-321"), mk("python-pem-private-key-literal", "secrets", sg, M, "CWE-798")},
		{mk("secrets/PRIVATE_KEY", "secrets", nat, H, "CWE-321"), mk("python-hardcoded-secret-assignment", "secrets", sg, M, "CWE-798")},
		{mk("secrets/DB_CONNECTION_STRING", "secrets", nat, H, "CWE-214"), mk("python-hardcoded-db-url", "secrets", sg, M, "CWE-214")},
	}
	for _, p := range pairs {
		t.Run(p.a.rule+"+"+p.b.rule, func(t *testing.T) {
			in := []models.Finding{p.a.at("x:1"), p.b.at("x:1")}
			for _, perm := range c9Permutations(in) {
				got := CollapseDuplicateLocations(perm)
				if len(got) != 1 {
					t.Fatalf("one construct reported by two analyzers must fold to one finding, got %v", c9RuleIDs(got))
				}
			}
		})
	}
}

// TestCollapse_AnUnidentifiedMemberIsNeverFoldedIntoAnother: a finding that
// names no rule family and no CWE gives the collapse nothing to say it is the
// same construct as its neighbour, so it is kept, not absorbed.
func TestCollapse_AnUnidentifiedMemberIsNeverFoldedIntoAnother(t *testing.T) {
	a := models.Finding{Title: "A", Category: "injection", Endpoint: "x:1", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, SourceTier: models.TierTreeSitter, Confidence: models.ConfidenceMedium, Evidence: "a", Fix: "a"}
	b := a
	b.Title, b.SourceTier = "B", models.TierSemgrepShim
	if got := CollapseDuplicateLocations([]models.Finding{a, b}); len(got) != 2 {
		t.Fatalf("members with no identity must not fold, got %d: %s", len(got), fmt.Sprint(collapseTitles(got)))
	}
}

// TestCollapse_CrossConstructOutcomeIsOrderIndependent (F-L6) for the new
// partition: every ordering of a mixed line gives the same survivors, the same
// grades and the same folded references.
func TestCollapse_CrossConstructOutcomeIsOrderIndependent(t *testing.T) {
	in := []models.Finding{c9TsEval.at("a.js:1"), c9TsReq.at("a.js:1"), c9PyJSEval.at("a.js:1"), c9PyJSSQL.at("a.js:1"), c9PyJSHTML.at("a.js:1")}
	var want []models.Finding
	for i, p := range c9Permutations(in) {
		got := CollapseDuplicateLocations(p)
		sort.Slice(got, func(a, b int) bool { return got[a].RuleID < got[b].RuleID })
		if i == 0 {
			want = got
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ordering %d changed the outcome:\n got  %v\n want %v", i, c9RuleIDs(got), c9RuleIDs(want))
		}
	}
}
