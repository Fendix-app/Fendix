"""E-1 (Round 6 closure, RC-9 (1a)+V2+E-1): `SEC-JS_EVAL` reports real `eval` only.

`ast_analyzer._JS_PATTERNS` used to find `JS_EVAL` with the raw-text regex
`\\beval\\s*\\(` on each line. It graded HIGH inside comments, string and
template-literal text, regex literals, on Angular's `scope.$eval(...)` and on a
member call `x.eval(...)`, and the cross-analyzer collapse let that HIGH vouch
for another rule's finding on the same line (Tier B: `scope.$eval` in apollo,
openfaas and syncthing, a RuoYi comment, a hoppscotch spec's string literal, the
frontend's prose `eval()` strings).

The approved reading (decision package RC-9 (1a)+V2+E-1):

* no match in a comment, string or template-literal text, a regex literal, a
  `$eval` identifier, or a `.eval` member call on an arbitrary object;
* real eval stays: bare `eval(`, `window.eval(`, `globalThis.eval(`,
  `self.eval(`, `eval?.(`, `(0, eval)(`, and `eval (x)` with spacing or comments
  between the name and the parenthesis.

Every source line quoted below that comes from a Tier A or Tier B tree is the
real line (the file is named next to it); the rest are minimal shapes. All of it
is fixture text the analyzer reads; none of it is executed or imported.

CL2-1 (owner ruling OR-88, "the recognisers may lower a finding, never remove
it"): the tokenizer only decides the GRADE of an `eval` site, never whether it is
reported. Every site the v3.7.0 line pattern `\\beval\\s*\\(` matches is reported;
a site a complete reading confirms as code keeps the corroborating HIGH/HIGH grade
(`_lines` below), every other one is reported at the demoted grade MEDIUM/LOW that
WARNs and never lends confidence to another finding (`_floor_lines` is every
reported line). The tests that used to assert "not reported" for a comment, a
string, template text, a regex literal, `$eval` or `x.eval` now assert that the
site is not CONFIRMED and that it is still reported at the demoted grade.

Only a site a COMPLETE reading puts outside code is lowered. When the tokenizer gives
up (no reading completes, the readings outgrow their budget, or it crashes) it has
decided nothing, so every raw match is reported at HIGH/HIGH as in rc.3 and v3.7.0:
a doubt reports, and a budget an adversary can exhaust must not be a way to lower a
BLOCK (owner's rc.4 brief, "no unsafe reduction in BLOCK severity").
"""

from __future__ import annotations

import contextlib
import json
import re
import signal
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

EVAL = "SEC-JS_EVAL"


@contextlib.contextmanager
def _deadline(seconds: int):
    """Fail, rather than hang, when a pass that must be linear is not."""

    def expired(_signum, _frame):
        raise TimeoutError(f"not finished in {seconds}s")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _scan(src: str, name: str = "app.js") -> list[dict]:
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        Path(d, name).write_text(src, encoding="utf-8")
        try:
            ASTAnalyzer(d, "python").run(findings.append)
        except AnalysisIncomplete:
            pass
    return findings


# The v3.7.0 line pattern: every site it matches is reported, whatever the tokenizer says.
_RAW = re.compile(r"\beval\s*\(")
# The two grades. Confirmed: a complete reading puts the site in code (it can
# corroborate textscan's finding under D20). Demoted: no reading does; it WARNs
# and, at LOW confidence, can neither earn the deterministic-detection delta nor
# lend a stronger claim to another finding.
CONFIRMED = ("HIGH", "HIGH")
DEMOTED = ("MEDIUM", "LOW")


def _eval_findings(src: str, name: str = "app.js") -> list[dict]:
    return [f for f in _scan(src, name) if f["id"] == EVAL]


def _line_of(finding: dict) -> int:
    return int(finding["endpoint"].rsplit(":", 1)[1])


def _grade(finding: dict) -> tuple[str, str]:
    return (finding["severity"], finding["confidence"])


def _lines(src: str, name: str = "app.js") -> list[int]:
    """The 1-based lines `SEC-JS_EVAL` is reported on at the CONFIRMED grade
    (a complete reading puts the call in code), in order.

    Before CL2-1 this was every line the rule reported; a site the tokenizer ruled
    out was not reported at all. OR-88 keeps those sites at the demoted grade
    (`_floor_lines`), so "not reported" in an older test now means "not confirmed"."""
    return sorted(_line_of(f) for f in _eval_findings(src, name) if _grade(f) == CONFIRMED)


def _floor_lines(src: str, name: str = "app.js") -> list[int]:
    """Every line `SEC-JS_EVAL` is reported on, whatever the grade, in order."""
    return sorted(_line_of(f) for f in _eval_findings(src, name))


def _raw_lines(src: str) -> list[int]:
    """The lines the v3.7.0 pattern matches, numbered as the analyzer numbers them."""
    return [i for i, line in enumerate(src.splitlines(), 1) if _RAW.search(line)]


# ---------------------------------------------------------------------------
# Real eval stays reported
# ---------------------------------------------------------------------------

REAL_EVAL = [
    pytest.param("eval(code);", id="bare"),
    pytest.param("var r = eval(req.body.expr);", id="assigned"),
    pytest.param("eval (x);", id="space-before-paren"),
    pytest.param("eval\t(x);", id="tab-before-paren"),
    pytest.param("eval /* why */ (x);", id="block-comment-between"),
    pytest.param("eval/**/(x);", id="empty-block-comment-between"),
    pytest.param("window.eval(x);", id="window"),
    pytest.param("globalThis.eval(x);", id="globalThis"),
    pytest.param("self.eval(x);", id="self"),
    pytest.param("global.eval(x);", id="node-global"),
    pytest.param("window . eval (x);", id="window-spaced"),
    pytest.param("eval?.(x);", id="optional-call"),
    pytest.param("window.eval?.(x);", id="window-optional-call"),
    pytest.param("(0, eval)(x);", id="indirect-comma"),
    pytest.param("(0,eval)(x);", id="indirect-comma-tight"),
    pytest.param("(void 0, eval)(x);", id="indirect-comma-void"),
    pytest.param("(0, window.eval)(x);", id="indirect-comma-window"),
    pytest.param("(eval)(x);", id="parenthesised"),
    pytest.param("return eval(x);", id="after-return"),
    pytest.param("a = b ? eval(x) : 0;", id="in-ternary"),
    pytest.param("f(eval(x));", id="as-argument"),
    pytest.param("x = {k: eval(v)};", id="in-object-literal"),
    pytest.param("`${eval(x)}`;", id="template-expression"),
    pytest.param("`a ${`b ${eval(x)}`} c`;", id="nested-template-expression"),
    pytest.param("`ok`; eval(x);", id="after-a-template"),
    pytest.param("s = '// not a comment'; eval(x);", id="after-a-comment-lookalike-string"),
    pytest.param("u = 'http://x/y'; eval(z);", id="after-a-url-string"),
    pytest.param("s = 'it\\'s'; eval(x);", id="after-an-escaped-quote"),
    pytest.param("s = \"say \\\"hi\\\"\"; eval(x);", id="after-an-escaped-double-quote"),
    pytest.param("r = /eval/g; eval(x);", id="after-a-regex-literal"),
    pytest.param("r = /\"/.test(s); eval(x);", id="after-a-regex-with-a-double-quote"),
    pytest.param("r = /'/g; eval(x);", id="after-a-regex-with-a-quote"),
    pytest.param("r = /`/g; eval(x);", id="after-a-regex-with-a-backtick"),
    pytest.param("r = /[/]/; eval(x);", id="after-a-regex-with-a-slash-class"),
    pytest.param("r = /\\//; eval(x);", id="after-a-regex-with-an-escaped-slash"),
    pytest.param("r = /[*]/; eval(x);", id="after-a-regex-with-a-star"),
    pytest.param("var r = a / b; eval(x); var q = c / d;", id="between-two-divisions"),
    pytest.param("var r = (a + b) / 2; eval(x); var q = d / 3;", id="division-after-a-paren"),
    pytest.param("var r = c[0] / 2; eval(x); var q = d / 3;", id="division-after-a-bracket"),
    pytest.param("var r = 4 / 2; eval(x); var q = 6 / 3;", id="division-after-a-number"),
    pytest.param("var r = 's' / 2; eval(x); var q = d / 3;", id="division-after-a-string"),
    pytest.param("var r = `t` / 2; eval(x); var q = d / 3;", id="division-after-a-template"),
    pytest.param("var r = /a/.lastIndex / 2; eval(x); var q = d / 3;", id="division-after-a-regex-member"),
    pytest.param("var r = a++ / 2; eval(x); var q = b / 3;", id="division-after-postfix"),
    pytest.param("if (x) /\"/.test(s); eval(z);", id="regex-after-control-paren"),
    pytest.param("while (x) /'/.test(s); eval(z);", id="regex-after-while-paren"),
    pytest.param("x = (/\"/.test(s)); eval(z);", id="regex-after-open-paren"),
    pytest.param("x = a || /\"/.test(s); eval(z);", id="regex-after-an-operator"),
    pytest.param("typeof /\"/; eval(z);", id="regex-after-typeof"),
    pytest.param("x = o.in / 2; eval(z); y = p / 3;", id="keyword-named-property-in"),
    pytest.param("v = o.return / 2; eval(x); w = p / 3;", id="keyword-named-property-then-division"),
    pytest.param("x = a /* c */ / b; eval(y); z = a / b;", id="comment-between-divisions"),
    pytest.param("r = x => /\"/.test(x); eval(y);", id="regex-after-arrow"),
    pytest.param("{}\n/\"/.test(s); eval(x);", id="regex-after-block"),
    pytest.param("function f() {}\n/\"/.test(s); eval(x);", id="regex-after-a-function-body"),
    pytest.param("x = `a ${b}`; /\"/.test(s); eval(x);", id="regex-after-a-template-statement"),
    pytest.param("x = {a: 1}; /\"/.test(s); eval(x);", id="regex-after-a-semicolon"),
    pytest.param("x = <li>{a}</li><li>{eval(b)}</li>;", id="jsx-closing-tags-around-an-expression"),
    pytest.param("x = <a>{b}</a>; y = <br />; eval(z);", id="jsx-self-closing-then-eval"),
    pytest.param("\\u0065val(x);", id="identifier-escape-u4"),
    pytest.param("\\u{65}val(x);", id="identifier-escape-braced"),
    pytest.param("ev\\u0061l(x);", id="identifier-escape-inside"),
    pytest.param("// eval(a)\neval(b);", id="after-a-comment-line"),
    # CL2-1: three constructs the rc.3 verifier showed the lexer read one way only
    # (a regex after `extends` or `default`, and the paren of `for await`).
    pytest.param("class A extends /\"/.constructor {} eval(x);", id="regex-after-extends"),
    pytest.param("export default /\"/.test(s) && eval(x);", id="regex-after-export-default"),
    pytest.param("(async () => { for await (const x of y) /\"/.test(s) && eval(z); })();", id="regex-after-for-await-paren"),
    pytest.param("x = o.default / 2; eval(x); y = p / 3;", id="keyword-named-property-default"),
    pytest.param("x = o.extends / 2; eval(x); y = p / 3;", id="keyword-named-property-extends"),
    pytest.param("export default {a: 1}; eval(x); y = \"/\" / 2;", id="object-literal-after-export-default"),
]


@pytest.mark.parametrize("src", REAL_EVAL)
def test_real_eval_is_reported(src: str) -> None:
    # Each case ends with the eval, on the last line of the shape.
    assert _lines("var pad = 1;\n" + src + "\n") == [2 + src.count("\n")], src


def test_eval_split_from_its_paren_by_a_newline_is_reported_on_the_eval_line() -> None:
    assert _lines("var a = 1;\neval\n(x);\n") == [2]
    assert _lines("var a = 1;\neval // call it\n(x);\n") == [2]
    assert _lines("var a = 1;\nwindow\n  .eval\n  (x);\n") == [3]


def test_every_eval_on_separate_lines_is_reported_once_per_line() -> None:
    src = "eval(a);\nx = 1;\nwindow.eval(b); eval(c);\n// eval(d)\n(0, eval)(e);\n"
    assert _lines(src) == [1, 3, 5]


def test_eval_after_a_multiline_template_and_a_multiline_comment() -> None:
    src = "var t = `line one\nline two eval(x)\nline three`;\n/* a\n eval(y)\n*/\neval(z);\n"
    assert _lines(src) == [7]


# ---------------------------------------------------------------------------
# The real lines from the Tier A and Tier B trees that must stay reported
# ---------------------------------------------------------------------------


def test_juice_shop_user_profile_real_rce_is_reported() -> None:
    # juice-shop routes/userProfile.ts:65, the real RCE.
    src = textwrap.dedent(
        """\
        try {
          if (!code) {
            throw new Error('Username is null')
          }
          username = eval(code) // eslint-disable-line no-eval
        } catch (err) {
          username = '\\\\' + username
        }
        """
    )
    assert _lines(src, "userProfile.ts") == [5]


def test_juice_shop_captcha_line_is_reported() -> None:
    # juice-shop routes/captcha.ts:22
    src = (
        "    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()\n"
        "    const answer = eval(expression).toString() // eslint-disable-line no-eval\n"
    )
    assert _lines(src, "captcha.ts") == [2]


def test_nodegoat_contributions_eval_is_reported_and_its_comments_are_not() -> None:
    # OWASP NodeGoat app/routes/contributions.js:28-34 (comments included).
    src = (
        "        /*jslint evil: true */\n"
        "        // Insecure use of eval() to parse inputs\n"
        "        const preTax = eval(req.body.preTax);\n"
        "        const afterTax = eval(req.body.afterTax);\n"
        "        const roth = eval(req.body.roth);\n"
    )
    assert _lines(src, "contributions.js") == [3, 4, 5]


# ---------------------------------------------------------------------------
# Not eval: comments, string and template text, regex literals, $eval, members
# ---------------------------------------------------------------------------

NOT_EVAL = [
    # --- comments -------------------------------------------------------
    pytest.param("// eval(x)", id="line-comment"),
    pytest.param("foo(); // eval(x) is dangerous", id="trailing-line-comment"),
    pytest.param("/* eval(x) */", id="block-comment"),
    pytest.param("foo(); /* eval(x) */ bar();", id="inline-block-comment"),
    pytest.param("/**\n * Never call eval(x) here.\n */", id="jsdoc"),
    pytest.param("/*\neval(x)\n*/", id="multiline-block-comment"),
    pytest.param("#!/usr/bin/env node\n// eval(x)", id="shebang-then-comment"),
    # RuoYi jquery.tablednd.js:30, a trailing comment after real code.
    pytest.param(
        "onDrop: $(this).data('ondrop') && new Function('table', 'row', $(this).data('ondrop')), "
        "// 'return eval(\"'+$(this).data('ondrop')+'\");') || null,",
        id="ruoyi-tablednd-comment",
    ),
    # --- string literals --------------------------------------------------
    pytest.param('x = "eval(code)";', id="double-quoted-string"),
    pytest.param("x = 'eval(code)';", id="single-quoted-string"),
    pytest.param('["eval(code)"],', id="hoppscotch-spec-string"),
    pytest.param("x = 'a \\' eval(x) b';", id="string-with-escaped-quote"),
    pytest.param('x = "a \\" eval(x) b";', id="double-string-with-escaped-quote"),
    pytest.param("x = 'a \\\n eval(x)';", id="string-with-line-continuation"),
    pytest.param('x = "/* eval(x) */";', id="comment-markers-inside-a-string"),
    pytest.param('x = "// eval(x)";', id="line-comment-marker-inside-a-string"),
    pytest.param('["HIGH", "Unsafe eval() with dynamic arg", "introduction/mitre.py:218"],', id="fe-accuracy-page-prose"),
    pytest.param(
        '"python-eval-injection": { en: "eval() or exec() with a dynamic argument", ar: "x" },',
        id="fe-security-reference-prose",
    ),
    # --- template literal text ---------------------------------------------
    pytest.param("x = `use eval(x) here`;", id="template-text"),
    pytest.param("x = `a\nuse eval(x) here\nb`;", id="multiline-template-text"),
    pytest.param("x = `a ${b} eval(c) ${d}`;", id="template-text-between-expressions"),
    pytest.param("x = `a ${`inner eval(c)`} d`;", id="nested-template-text"),
    pytest.param("x = `a \\` eval(x) b`;", id="template-with-an-escaped-backtick"),
    pytest.param("x = `a ${ {k: 1}.k } eval(c)`;", id="template-text-after-an-object-expression"),
    pytest.param("x = `${a}${b} eval(c)`;", id="template-text-after-two-expressions"),
    # --- regex literals -----------------------------------------------------
    pytest.param("ok = /eval(\\d+)/.test(s);", id="regex-with-a-group"),
    pytest.param("s.replace(/eval(x)/g, '');", id="regex-in-a-call"),
    pytest.param("m = s.match(/foo[/]eval(\\d)/);", id="regex-with-a-slash-class"),
    pytest.param("return /eval(\\d)/.test(s);", id="regex-after-return"),
    pytest.param("x = a ? /eval(\\d)/ : null;", id="regex-after-a-ternary-question"),
    pytest.param("x = [/eval(\\d)/, 2];", id="regex-in-an-array"),
    pytest.param("f(/eval(\\d)/);", id="regex-as-an-argument"),
    # --- $eval and other identifiers that merely contain the word -----------
    # apollo angular-route.min.js:25, syncthing angular-dirPagination.js:291
    pytest.param(
        "scope.directionLinks = angular.isDefined(attrs.directionLinks) ? scope.$parent.$eval(attrs.directionLinks) : true;",
        id="syncthing-scope-parent-$eval",
    ),
    pytest.param("v = scope.$eval(attrs.x);", id="scope-$eval"),
    pytest.param("v = $eval(x);", id="bare-$eval"),
    pytest.param("v = a$eval(x);", id="a$eval"),
    pytest.param("v = $rootScope.$eval('a');", id="$rootScope-$eval"),
    pytest.param("v = _eval(x);", id="underscore-eval"),
    pytest.param("v = eval2(x);", id="eval2"),
    pytest.param("v = evalSync(x);", id="evalSync"),
    pytest.param("v = evaluate(x);", id="evaluate"),
    pytest.param("v = retrieval(x);", id="retrieval"),
    pytest.param("v = my_eval(x);", id="my_eval"),
    # --- a member call on an arbitrary object --------------------------------
    pytest.param("v = math.eval('1+2');", id="mathjs-eval"),
    pytest.param("v = x.eval(y);", id="x.eval"),
    pytest.param("v = obj.eval (y);", id="obj.eval-spaced"),
    pytest.param("v = a.b.c.eval(y);", id="a.b.c.eval"),
    pytest.param("v = ctx?.eval(y);", id="optional-member"),
    pytest.param("v = Foo.prototype.eval(y);", id="prototype-eval"),
    pytest.param("v = expr\n  .eval(y);", id="member-on-the-next-line"),
    pytest.param("v = expr.\n  eval(y);", id="dot-then-newline"),
    pytest.param("v = this.eval(y);", id="this.eval"),
    pytest.param("v = foo.window.eval(y);", id="window-as-a-member-is-not-the-global"),
    pytest.param("v = foo(a, eval)(x);", id="eval-passed-to-a-call-then-called"),
    # --- eval that is not called --------------------------------------------
    pytest.param("x = { eval: 1 };", id="property-name"),
    pytest.param("x = eval;", id="reference-only"),
    pytest.param("x = [eval, 2];", id="array-element"),
]


@pytest.mark.parametrize("src", NOT_EVAL)
def test_not_eval_is_not_reported(src: str) -> None:
    # OR-88 (CL2-1): the recognisers may lower a finding, never remove it.
    #   old: assert _lines(full) == []            (no SEC-JS_EVAL finding at all)
    #   new: not CONFIRMED as a call, and every site the v3.7.0 pattern matches
    #        (`x.eval(`, `$eval(`, the word in a comment, a string, template text
    #        or a regex) is still reported, at the demoted grade.
    full = "var pad = 1;\n" + src + "\n"
    assert _lines(full) == [], src
    assert _floor_lines(full) == _raw_lines(full), src
    assert {_grade(f) for f in _eval_findings(full)} <= {DEMOTED}, src


def test_a_commented_out_call_does_not_hide_the_real_one_on_the_next_line() -> None:
    assert _lines("// eval(a)\n/* eval(b) */\neval(c);\n") == [3]
    assert _floor_lines("// eval(a)\n/* eval(b) */\neval(c);\n") == [1, 2, 3]  # OR-88: the comments stay, demoted


def test_unterminated_string_is_cut_at_the_newline_like_the_runtime_does() -> None:
    # An unterminated string is a syntax error; it must not swallow the file.
    assert _lines("x = 'broken\neval(y);\n") == [2]


def test_hashbang_line_is_a_comment() -> None:
    assert _lines("#!/usr/bin/env node -e eval(x)\neval(y);\n") == [2]
    assert _floor_lines("#!/usr/bin/env node -e eval(x)\neval(y);\n") == [1, 2]  # OR-88


def test_typescript_sources_follow_the_same_rule() -> None:
    src = "const a: string = 'eval(x)';\n// eval(y)\nconst b = eval(z) as number;\nconst c = <T,>(v: T) => v;\n"
    assert _lines(src, "a.ts") == [3]
    assert _lines(src, "a.tsx") == [3]
    assert _floor_lines(src, "a.ts") == [1, 2, 3]  # OR-88: the string and the comment stay, demoted
    assert _floor_lines(src, "a.tsx") == [1, 2, 3]


def test_line_numbers_follow_the_analyzers_own_line_splitting() -> None:
    # splitlines() also breaks at U+2028, so the reported line must too.
    src = "var a = 1; var b = eval(x);\nvar c = 2;\n"
    assert _lines(src) == [2]


# ---------------------------------------------------------------------------
# A constant string through a form the old pattern never matched is not injectable
# (orchestrator follow-up to E-1). Only the forms E-1 newly reads: `(0, eval)(`,
# `(eval)(`, `eval?.(`, `eval` split from `(` by a comment or a newline, and an
# identifier spelled with escapes. Whatever the old `\beval\s*\(` matched, bare
# `eval("...")` and `window.eval("...")` included, is reported exactly as before.
# ---------------------------------------------------------------------------

CONSTANT_THROUGH_A_NEW_FORM = [
    # the corpus lines (JeecgBoot echarts-wordcloud.js:9135, pig doT.js:34)
    pytest.param('g = g || Function("return this")() || (1,eval)("this");', id="corpus-echarts-wordcloud"),
    pytest.param("(function(){ return this || (0,eval)('this'); }()).doT = doT;", id="corpus-doT"),
    pytest.param("(0, eval)('this');", id="comma-single-quoted"),
    pytest.param('(0,eval)("this");', id="comma-tight"),
    pytest.param('(void 0, eval)("x");', id="comma-void"),
    pytest.param('(eval)("x");', id="parenthesised"),
    pytest.param('(0, window.eval)("x");', id="comma-window"),
    pytest.param("(0, eval)(`no substitution`);", id="comma-template-without-substitution"),
    pytest.param('eval?.("x");', id="optional-call"),
    pytest.param('window.eval?.("x");', id="window-optional-call"),
    pytest.param('eval /* c */ ("x");', id="comment-before-the-paren"),
    pytest.param('eval // c\n("x");', id="line-comment-and-newline-before-the-paren"),
    pytest.param('eval\n("x");', id="newline-before-the-paren"),
    pytest.param('\\u0065val("x");', id="identifier-escape"),
    pytest.param('ev\\u0061l("x");', id="identifier-escape-inside"),
    pytest.param('(0, eval)( "x" );', id="comma-spaces-inside"),
    pytest.param('(0, eval)(/* a */ "x" /* b */);', id="comma-comments-inside"),
]


@pytest.mark.parametrize("src", CONSTANT_THROUGH_A_NEW_FORM)
def test_a_constant_string_through_a_newly_matched_form_is_not_reported(src: str) -> None:
    # The exemption is an addition on top of the v3.7.0 floor: these are forms the
    # old pattern never matched (`_raw_lines` is empty), so nothing it matched is
    # removed (OR-88).
    full = "var pad = 1;\n" + src + "\n"
    assert _lines(full) == [], src
    assert _raw_lines(full) == [], src
    assert _floor_lines(full) == [], src


STILL_REPORTED_THROUGH_A_NEW_FORM = [
    # the other two corpus lines: the argument is not a literal
    pytest.param("return (0, eval)(parsed_value);", id="corpus-frappe-utils"),
    pytest.param("then(function(e){return(0,eval)(e),r.getRegister()})", id="corpus-systemjs-system-min"),
    pytest.param("(0, eval)(x);", id="comma-variable"),
    pytest.param('(0, eval)("a" + x);', id="comma-concatenation"),
    pytest.param('(0, eval)(x + "a");', id="comma-concatenation-first-operand-variable"),
    pytest.param("(0, eval)(`${x}`);", id="comma-template-with-substitution"),
    pytest.param("(0, eval)(`a ${x} b`);", id="comma-template-text-and-substitution"),
    pytest.param('(0, eval)("a", x);', id="comma-two-arguments"),
    pytest.param('(0, eval)("a"[0]);', id="comma-indexed-string"),
    pytest.param('(0, eval)("a".concat(x));', id="comma-method-on-a-string"),
    pytest.param("(0, eval)();", id="comma-no-argument"),
    pytest.param('(0, eval)(("x"));', id="comma-parenthesised-literal-stays-reported"),
    pytest.param("eval?.(x);", id="optional-call-variable"),
    pytest.param('eval?.("a" + x);', id="optional-call-concatenation"),
    pytest.param("eval /* c */ (x);", id="comment-variable"),
    pytest.param("\\u0065val(x);", id="escape-variable"),
    pytest.param('(eval)("a" + "b");', id="parenthesised-two-literals-joined"),
    # forms the old pattern matched: unchanged, constants included
    pytest.param('eval("const");', id="bare-constant-unchanged"),
    pytest.param("eval('const');", id="bare-single-quoted-unchanged"),
    pytest.param("eval(`const`);", id="bare-template-unchanged"),
    pytest.param('eval ("const");', id="bare-spaced-constant-unchanged"),
    pytest.param('window.eval("const");', id="window-constant-unchanged"),
    pytest.param("self.eval('const');", id="self-constant-unchanged"),
    pytest.param('globalThis.eval("const");', id="globalThis-constant-unchanged"),
    pytest.param('window . eval ("const");', id="window-spaced-constant-unchanged"),
]


@pytest.mark.parametrize("src", STILL_REPORTED_THROUGH_A_NEW_FORM)
def test_everything_else_is_still_reported(src: str) -> None:
    assert _lines("var pad = 1;\n" + src + "\n") == [2 + src.count("\n")], src


def test_a_newline_before_the_paren_with_a_variable_argument_is_reported_on_the_eval_line() -> None:
    assert _lines("var pad = 1;\neval\n(x);\n") == [2]
    assert _lines('var pad = 1;\neval\n("x");\n') == []


def test_a_constant_string_form_does_not_hide_a_real_call_on_the_same_line() -> None:
    assert _lines('(0, eval)("this"); eval(x);\n') == [1]
    assert _lines('(0, eval)("this"); (0, eval)(y);\n') == [1]
    assert _lines('(0, eval)("this");\n(0, eval)(y);\n') == [2]


# ---------------------------------------------------------------------------
# CL-3b (verifier A-1): where the tokenizer cannot tell a regex from a division, or
# a comment from code, it must report. Ground truth for every program below is
# V8: the file was run, and the planted `eval(...)` executed.
# ---------------------------------------------------------------------------

_MISSES = json.loads((Path(__file__).parent / "fixtures" / "e1_lexer_misses.json").read_text(encoding="utf-8"))


def _call_lines(src: str) -> set[int]:
    """The lines holding the planted call, numbered as the analyzer numbers them."""
    return {i for i, line in enumerate(src.splitlines(), 1) if "eval(code)" in line or "eval((" in line or "eval(userInput)" in line}


@pytest.mark.parametrize("case", _MISSES["repros"], ids=[c["name"] for c in _MISSES["repros"]])
def test_the_verifiers_one_line_repros_are_reported(case: dict) -> None:
    calls = _call_lines(case["src"])
    assert calls, case["name"]
    assert calls <= set(_lines(case["src"], "app.js")), case["name"]


@pytest.mark.parametrize(
    "case", _MISSES["v8_fuzz_misses"], ids=[c["name"] for c in _MISSES["v8_fuzz_misses"]]
)
def test_every_program_the_v8_fuzz_executed_and_the_tokenizer_lost_is_reported(case: dict) -> None:
    # The calls that are code, by the TypeScript parser. A text that merely spells
    # `eval(code)` inside a template or a string is not one. The parser knows no
    # HTML-like comments, so a program it finds no call in falls back to the text.
    calls = set(case["real_calls"]) or _call_lines(case["src"])
    assert calls, case["name"]
    assert calls <= set(_lines(case["src"], "app" + case["suffix"])), case["name"]


LEXER_CONFUSION = [
    pytest.param("var x = 1; <!-- /*\neval((userInput));\n// */", id="html-comment-opens-a-block-comment"),
    pytest.param("var x = 1; <!-- /*\neval(userInput);\n// */", id="html-comment-plain-form"),
    pytest.param('var q = 1 <!-- "\u2028eval((userInput));', id="html-comment-with-a-quote-ended-by-ls"),
    pytest.param('var q = 1 <!-- "\u2029eval((userInput));', id="html-comment-with-a-quote-ended-by-ps"),
    pytest.param("-->/*\neval((userInput));\n// */", id="close-comment-at-line-start"),
    pytest.param("  -->/*\neval((userInput));\n// */", id="close-comment-after-white-space"),
    pytest.param("#!/usr/bin/env node\u2028var u = 1; eval((userInput));", id="hashbang-ended-by-ls"),
    pytest.param("#!/usr/bin/env node\u2029var u = 1; eval((userInput));", id="hashbang-ended-by-ps"),
    pytest.param("var k = function(){} / 1; eval((userInput)); var z = 2 / 1;", id="function-expression-then-division"),
    pytest.param("var C = class {} / 1; eval((userInput)); var z = 2 / 1;", id="class-expression-then-division"),
    pytest.param("var k = (function(){}) / 1; eval((userInput)); var z = 2 / 1;", id="parenthesised-function-then-division"),
    pytest.param("var o = {} / 1; eval((userInput)); var z = 2 / 1;", id="object-literal-then-division"),
    pytest.param("var s = '\"'; L: { } /\"/.test(s) && eval((userInput));", id="label-block-then-a-regex-with-a-quote"),
    pytest.param("var s = '\"'; switch (1) { case 1: { } /\"/.test(s) && eval((userInput)); }", id="case-block-then-a-regex-with-a-quote"),
    pytest.param("var s = '\"'; if (1) { } /\"/.test(s) && eval((userInput));", id="if-block-then-a-regex-with-a-quote"),
    pytest.param("var s = '`'; { } /`/.test(s) && eval((userInput));", id="bare-block-then-a-regex-with-a-backtick"),
    pytest.param("for (var m of /\"/.exec('a')) eval((userInput)); var q = \"b\";", id="regex-after-of"),
    pytest.param("async function f(){ var r = await /\"/.test('a'); eval((userInput)); var q = \"b\"; }", id="regex-after-await"),
    pytest.param("function* g(){ var r = yield /\"/.test('a'); eval((userInput)); var q = \"b\"; }", id="regex-after-yield"),
    pytest.param("var await = 4; var r = await / 2; eval((userInput)); var z = 6 / 3;", id="await-as-a-name-then-division"),
    pytest.param("var yield = 4; var r = yield / 2; eval((userInput)); var z = 6 / 3;", id="yield-as-a-name-then-division"),
    pytest.param("var of = 4; var r = of / 2; eval((userInput)); var z = 6 / 3;", id="of-as-a-name-then-division"),
    pytest.param("var a = 1, b = 2; var n = a! / b; eval((userInput)); var z = '\"' / 1;", id="ts-non-null-then-division"),
    pytest.param("var x = a --> 0; eval((userInput)); var q = '\"';", id="goes-to-operator"),
    pytest.param("var x = a <!--b; eval((userInput)); var q = '\"';", id="html-open-inside-an-expression"),
]


@pytest.mark.parametrize("src", LEXER_CONFUSION)
def test_a_construct_the_tokenizer_cannot_decide_reports_the_call(src: str) -> None:
    calls = _call_lines(src)
    assert calls, src
    assert calls <= set(_lines(src, "app.js")), src


# ---------------------------------------------------------------------------
# CL-3c: at an undecided construct both readings are followed, so a file that
# merely contains one is still read as tokens. Tier A `fe` accuracy/page.tsx:433
# was a string in a data array, reported once the whole file fell back to the raw
# pattern.
# ---------------------------------------------------------------------------

_JSX_FILE = (
    "export default function Page() {\n"
    "  return (\n"
    "    <Section\n"
    "      icon={<Target className=\"w-6 h-6\" />}\n"
    "      code={accuracyReproduceCommand()} />\n"
    "  );\n"
    "}\n"
    "const rows = [\n"
    "  [\"HIGH\", \"Unsafe eval() with dynamic arg\", \"introduction/mitre.py:218\"],\n"
    "  // eval(x) is dangerous\n"
    "  `use eval(y) rarely`,\n"
    "];\n"
)


def test_a_string_in_a_file_with_an_undecided_construct_is_not_reported() -> None:
    assert _lines(_JSX_FILE, "page.tsx") == []
    assert _lines(_JSX_FILE, "page.jsx") == []
    # OR-88: the prose lines are not removed; they come back demoted (a WARN, never
    # a BLOCK), which is also what keeps Tier A `fe` at exit 0.
    for name in ("page.tsx", "page.jsx"):
        assert _floor_lines(_JSX_FILE, name) == _raw_lines(_JSX_FILE) == [9, 10, 11], name
        assert {_grade(f) for f in _eval_findings(_JSX_FILE, name)} == {DEMOTED}, name


def test_a_real_call_in_that_file_is_still_reported_on_its_own_line() -> None:
    src = _JSX_FILE + "export const run = (code: string) => eval(code);\n"
    assert _lines(src, "page.tsx") == [13]


@pytest.mark.parametrize(
    "src, expected",
    [
        pytest.param("var k = function(){} / 1;\nvar s = 'eval(x)';\n// eval(y)\neval(z);\n", [4], id="function-expression-division"),
        pytest.param("L: { } /\"/.test(s);\nvar t = 'eval(x)';\neval(z);\n", [3], id="label-block-regex-with-a-quote"),
        pytest.param("var x = 1; <!-- /*\nvar t = 'eval(x)';\neval(z);\n// */\n", [3], id="html-comment-with-a-block-opener"),
        pytest.param("var n = a! / b;\nvar t = 'eval(x)';\neval(z);\n", [3], id="non-null-then-division"),
        pytest.param("var a = 1;\nx = a --> 0;\nvar t = 'eval(x)';\neval(z);\n", [4], id="goes-to-operator"),
    ],
)
def test_the_readings_agree_on_a_string_and_on_the_real_call(src: str, expected: list[int]) -> None:
    assert _lines(src) == expected


def test_a_hundred_undecided_constructs_in_a_row_are_read_precisely_in_bounded_time() -> None:
    # Each line forks; the two readings meet again at the end of the line, so the
    # readings never pile up and the file keeps its precise reading.
    src = "".join(f'var v{i} = {{}} / 1 / "{i}";\n' for i in range(100)) + "var t = 'eval(x)';\neval(z);\n"
    start = time.monotonic()
    with _deadline(60):
        found = _lines(src)
    assert found == [102]
    assert time.monotonic() - start < 30


def test_thirty_thousand_undecided_constructs_are_read_precisely_in_bounded_time() -> None:
    src = "var q = {} / 1; /a/g.test(q);\n" * 30_000 + "var t = 'eval(x)';\neval(z);\n"
    assert len(src) < 1_048_576
    start = time.monotonic()
    with _deadline(60):
        found = _lines(src)
    assert found == [30_002]
    assert time.monotonic() - start < 30


def test_readings_that_never_meet_fall_back_to_the_raw_pattern_within_the_budget() -> None:
    # A division and a regex that each swallow the next quote: the readings drift
    # apart for good, the budget is spent, and the raw pattern decides.
    src = ('var a = {} / 1 /"/; var b = "\n' * 3000) + "eval(x);\n"
    start = time.monotonic()
    with _deadline(60):
        found = _floor_lines(src)
    assert found[-1] == 3001
    assert time.monotonic() - start < 30


_UNDECIDED = "var k = function(){} / 1;\nvar s = 'eval(x)';\neval(z);\n"


@pytest.mark.parametrize(
    "limit, value",
    [
        pytest.param("_JS_MAX_READINGS", -1, id="readings-alive-at-once"),
        pytest.param("_JS_MAX_FORKS_BASE", -10_000, id="forks-followed"),
        pytest.param("_JS_MAX_WORK_FACTOR", -100_000, id="characters-read-across-readings"),
    ],
)
def test_readings_past_a_budget_fall_back_to_the_raw_pattern(monkeypatch, limit: str, value: int) -> None:
    from analyzers import ast_analyzer

    assert _lines(_UNDECIDED) == [3]  # both readings followed: the string is a string
    monkeypatch.setattr(ast_analyzer, limit, value)
    # Over budget: no reading completes, so the raw pattern decides, as in rc.3 and
    # v3.7.0: every line is reported at HIGH/HIGH (a doubt reports; the give-up is
    # not a decision, so nothing is lowered).
    #   old (CL2-1 first cut): assert _lines(_UNDECIDED) == []   (demoted on a give-up)
    #   new (rc.4 brief, no unsafe reduction in BLOCK severity): all HIGH
    assert _floor_lines(_UNDECIDED) == [2, 3]
    assert _lines(_UNDECIDED) == [2, 3]


# ---------------------------------------------------------------------------
# Fail open: a file the lexer cannot follow keeps today's raw match
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "src, raw_lines",
    [
        pytest.param("} // eval(a)\neval(b);\n", [1, 2], id="closing-brace-nothing-opened"),
        pytest.param(") // eval(a)\neval(b);\n", [1, 2], id="closing-paren-nothing-opened"),
        pytest.param("eval(b);\n/* eval(c)\n", [1, 2], id="unterminated-block-comment"),
        pytest.param("eval(b);\nx = `eval(c)\n", [1, 2], id="unterminated-template"),
        pytest.param("eval(b);\nx = `a ${ eval(c)\n", [1, 2], id="unterminated-template-expression"),
        pytest.param("f(eval(a);\n// eval(b)\n", [1, 2], id="paren-left-open"),
        pytest.param("if (x) {\n// eval(b)\neval(c);\n", [2, 3], id="brace-left-open"),
    ],
)
def test_a_file_the_lexer_cannot_follow_keeps_the_raw_match_for_every_line(
    src: str, raw_lines: list[int]
) -> None:
    # The file cannot be read reliably, so every `eval(` the old pattern found
    # stays reported, comments included, at the grade it always had: HIGH/HIGH.
    # No reading completes, so nothing is decided and nothing is lowered.
    #   old (CL2-1 first cut): grades == {DEMOTED}
    #   new (rc.4 brief): grades == {CONFIRMED}
    assert _floor_lines(src) == raw_lines
    assert _lines(src) == raw_lines
    assert {_grade(f) for f in _eval_findings(src)} == {CONFIRMED}


# ---------------------------------------------------------------------------
# Cost: one linear pass, whatever the shape of the line
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "unit",
    [
        "a = b / c / d;",
        "x = /[/[/[a/;",
        "/*c*/ // c\n",
        "s = 'a\\'b\"c'; t = `${a}${b}`;",
        "\\u0065 \\u0065val ",
        "}{)(][ ",
        "/[",
        "'",
        "`${",
        "//",
        "a /= /re/g;",
    ],
)
def test_a_megabyte_of_any_shape_is_scanned_in_linear_time(unit: str) -> None:
    # The trailing call makes the file a candidate, so the lexer really runs.
    src = unit * (900_000 // len(unit)) + "\neval(1);\n"
    start = time.monotonic()
    with _deadline(30):
        _scan(src)
    assert time.monotonic() - start < 15, unit


def test_a_megabyte_of_ordinary_minified_code_with_one_eval_is_fast_and_found() -> None:
    chunk = "function a(b){return b+1}var c=a(2),d='x/y',e=/q[/]r/g.test(d),f=c/2;"
    src = chunk * (900_000 // len(chunk)) + "eval(g);"
    start = time.monotonic()
    with _deadline(30):
        found = _lines(src)
    assert found == [1]
    assert time.monotonic() - start < 15


# ---------------------------------------------------------------------------
# CL2-1 (owner ruling OR-88): the recognisers may lower a finding, never remove it
#
# rc.3 failed independent verification because the tokenizer's reading decided
# whether a site was reported at all: eleven families of shape (rc.2: `<!--` with
# `/*`, `<!--` with a quote ended by U+2028, `-->` with `/*`, a hashbang ended by
# U+2028, a function-expression and a class-expression division, a label block
# before a regex; rc.3: `extends`, `export default`, `for await`, `</`, JSX text
# with an apostrophe, a URL or a backtick) made it read real, executed code as
# text and the call was dropped, where v3.7.0 reported it. Shape-by-shape fixes
# were not converging, so the rule is structural: every site the v3.7.0 pattern
# matches is reported, and the tokenizer chooses only between two grades.
# ---------------------------------------------------------------------------

_FAMILIES = json.loads(
    (Path(__file__).parent / "fixtures" / "e1_cl2_families.json").read_text(encoding="utf-8")
)["cases"]
_RC2_FAMILIES = [c for c in _FAMILIES if c["round"] == "rc2"]
_RC3_FAMILIES = [c for c in _FAMILIES if c["round"] == "rc3"]
_CONTROLS = [c for c in _FAMILIES if c["round"] == "control"]


def test_the_family_fixture_holds_every_family_of_both_rounds() -> None:
    assert len(_RC2_FAMILIES) == 7
    assert sorted(c["name"] for c in _RC3_FAMILIES) == sorted(
        [
            "new_for_await_mjs_plain_arg",
            "new_jsx_apostrophe",
            "new_jsx_apostrophe_plain_arg",
            "new_jsx_backtick",
            "new_jsx_url",
            "new_lt_regex",
            "new_x1_for_await",
            "new_x2_extends",
            "new_x3_export_default",
        ]
    )
    assert len(_CONTROLS) == 2


@pytest.mark.parametrize("case", _FAMILIES, ids=[c["name"] for c in _FAMILIES])
def test_a_verifier_family_is_reported_on_its_eval_line_never_zero(case: dict) -> None:
    # Each file ran under Node/V8 and its `eval(...)` executed. Whatever the
    # tokenizer made of the construct before it, the line must carry a finding.
    found = _eval_findings(case["src"], case["filename"])
    on_the_line = [f for f in found if _line_of(f) == case["eval_line"]]
    assert on_the_line, case["name"]
    assert {_grade(f) for f in on_the_line} <= {CONFIRMED, DEMOTED}, case["name"]


# The rc.3 families whose construct the lexer now reads correctly: a regex after
# `extends` and after `default`, and the paren of `for await`. (JSX text and `</`
# stay demoted: the floor reports them, a WARN.)
_CONFIRMED_RC3 = {"new_x1_for_await", "new_x2_extends", "new_x3_export_default", "new_for_await_mjs_plain_arg"}
_CONFIRMED = _RC2_FAMILIES + _CONTROLS + [c for c in _RC3_FAMILIES if c["name"] in _CONFIRMED_RC3]


@pytest.mark.parametrize("case", _CONFIRMED, ids=[c["name"] for c in _CONFIRMED])
def test_a_call_the_tokenizer_confirms_keeps_the_high_grade(case: dict) -> None:
    # CL-3c reads both ways at the rc.2 constructs, so the call is confirmed: HIGH,
    # able to corroborate textscan (D20), exactly as in rc.3.
    assert case["eval_line"] in _lines(case["src"], case["filename"]), case["name"]


@pytest.mark.parametrize(
    "case",
    [c for c in _RC3_FAMILIES if c["name"] not in _CONFIRMED_RC3],
    ids=[c["name"] for c in _RC3_FAMILIES if c["name"] not in _CONFIRMED_RC3],
)
def test_a_call_in_jsx_text_or_after_lt_slash_is_reported_demoted(case: dict) -> None:
    # The reading of these two shapes is not attempted (JSX text is read as code
    # and `</` as a closing tag); the floor reports the call, as a WARN.
    on_the_line = [f for f in _eval_findings(case["src"], case["filename"]) if _line_of(f) == case["eval_line"]]
    assert {_grade(f) for f in on_the_line} == {DEMOTED}, case["name"]


def _shape_sources() -> list:
    out = []
    for label, group in (
        ("real", REAL_EVAL),
        ("not", NOT_EVAL),
        ("const", CONSTANT_THROUGH_A_NEW_FORM),
        ("still", STILL_REPORTED_THROUGH_A_NEW_FORM),
    ):
        for p in group:
            out.append(pytest.param(p.values[0], id=f"{label}-{p.id}"))
    for p in LEXER_CONFUSION:
        out.append(pytest.param(p.values[0], id=f"confusion-{p.id}"))
    for c in _FAMILIES:
        out.append(pytest.param(c["src"], id=f"family-{c['name']}"))
    return out


@pytest.mark.parametrize("src", _shape_sources())
def test_every_site_the_v370_pattern_matches_is_reported(src: str) -> None:
    for full in (src, "var pad = 1;\n" + src + "\n"):
        assert set(_raw_lines(full)) <= set(_floor_lines(full)), full


@pytest.mark.parametrize("src", _shape_sources())
def test_a_reported_site_is_either_confirmed_or_demoted_and_never_anything_else(src: str) -> None:
    for f in _eval_findings(src):
        assert _grade(f) in (CONFIRMED, DEMOTED), f


@pytest.mark.parametrize(
    "tokenizer, grade",
    [
        # decided: a complete reading found no call anywhere, so every raw match is lowered
        pytest.param(lambda source: set(), DEMOTED, id="finds-nothing"),
        # not decided: it could not read the file, so every raw match keeps its v3.7.0 grade
        pytest.param(lambda source: None, CONFIRMED, id="gives-up"),
    ],
)
@pytest.mark.parametrize("src", _shape_sources())
def test_a_tokenizer_that_decides_wrongly_cannot_remove_a_site(monkeypatch, src: str, tokenizer, grade) -> None:
    # The structural rule, independent of any lexer: a tokenizer that reports no
    # call anywhere, or one that cannot read the file, still leaves every site the
    # v3.7.0 pattern matches reported. A wrong decision lowers the grade (WARN); a
    # give-up lowers nothing (HIGH/HIGH, as in rc.3 and v3.7.0).
    from analyzers import ast_analyzer

    monkeypatch.setattr(ast_analyzer, "_js_eval_lines", tokenizer)
    expected = _raw_lines(src)
    assert _floor_lines(src) == expected, src
    assert {_grade(f) for f in _eval_findings(src)} <= {grade}, src


def test_the_demoted_grade_is_the_one_that_warns_and_never_corroborates() -> None:
    # MEDIUM severity and LOW confidence: the decision layer holds a LOW band at
    # WARN under every `--fail-on` (held_confidence_low); the collapse's
    # strongestClaim only ever copies a HIGHER confidence from another member, so
    # LOW lends nothing; and HasDeterministicDetection needs HIGH. Textscan's own
    # grade for the same call is HIGH severity at MEDIUM confidence.
    (found,) = _eval_findings("// eval((x))\n")
    assert _grade(found) == DEMOTED == ("MEDIUM", "LOW")
    assert found["confidence"] == "LOW"


def test_a_demoted_finding_keeps_the_identity_of_the_confirmed_one() -> None:
    # Identity is rule=<id>, so the id, rule_id, title, category and references
    # must be the confirmed ones or every baseline entry for the rule moves.
    (confirmed,) = _eval_findings("eval((x));\n")
    (demoted,) = _eval_findings("// eval((x))\n")
    for key in ("id", "rule_id", "title", "category", "source", "references"):
        assert confirmed[key] == demoted[key], key
    assert confirmed["id"] == confirmed["rule_id"] == EVAL
    assert _grade(confirmed) == CONFIRMED
    assert confirmed["endpoint"] == "app.js:1" and demoted["endpoint"] == "app.js:1"


def test_a_demoted_finding_says_why_and_still_carries_the_standard_advice() -> None:
    (confirmed,) = _eval_findings("eval((x));\n")
    (demoted,) = _eval_findings("// eval((x))\n")
    assert demoted["fix"].endswith(confirmed["fix"])
    assert demoted["fix"] != confirmed["fix"]
    assert "could not confirm" in demoted["fix"]


def test_the_prose_lines_of_the_frontend_come_back_demoted_not_blocking() -> None:
    # Tier A `fe`: accuracy/page.tsx:433, security-reference.ts:216 and
    # changelog-data.ts:58 are prose in a string. They return, at the demoted
    # grade that WARNs (the Tier A exit stays 0).
    page = '    ["HIGH", "Unsafe eval() with dynamic arg", "introduction/mitre.py:218"],\n'
    ref = '  "python-eval-injection": { en: "eval() or exec() with a dynamic argument", ar: "x" },\n'
    log = '  { text: "Fixed the eval() false positive in comments" },\n'
    for src, name in ((page, "page.tsx"), (ref, "security-reference.ts"), (log, "changelog-data.ts")):
        assert _lines(src, name) == [], name
        assert _floor_lines(src, name) == [1], name
        assert {_grade(f) for f in _eval_findings(src, name)} == {DEMOTED}, name


@pytest.mark.parametrize(
    "src, name",
    [
        pytest.param("class A extends /\"/.constructor {} eval(userInput);\n", "app.js", id="extends"),
        pytest.param("export default /\"/.test(s) && eval(userInput);\n", "app.mjs", id="export-default"),
        pytest.param("(async () => {\n for await (const x of y) /\"/.test(s) && eval(userInput);\n})();\n", "app.mjs", id="for-await"),
        pytest.param("var a = 1; var r = a </\"/.test(s) || eval(userInput);\n", "app.js", id="lt-slash"),
        pytest.param("const a = <p>it's</p>; eval(userInput);\n", "P.tsx", id="jsx-apostrophe"),
        pytest.param("const a = <a>http://x.example</a>; eval(userInput);\n", "P.tsx", id="jsx-url"),
        pytest.param("const a = <p>a ` b</p>;\neval(userInput);\nconst b = <p>` c</p>;\n", "P.tsx", id="jsx-backtick"),
    ],
)
def test_the_plain_argument_form_of_each_rc3_family_is_reported(src: str, name: str) -> None:
    # `eval(userInput)` is also what textscan sees; the Python engine's own
    # finding must exist too, so the scan never shows nothing for the call.
    assert set(_raw_lines(src)) <= set(_floor_lines(src, name)), src
    assert _floor_lines(src, name), src


# ---------------------------------------------------------------------------
# CL2-1 addition (WS-C2's give-up audit): a lexer that raises is lost evaluation
#
# `_analyze_js_heuristic` calls `scope_evidence.js_identifier_escape` (R6-E7a) and
# the E-1 tokenizer with no guard. An exception from either used to leave the
# call: it aborted the file's analysis and the rest of the walk with it. It must
# instead make the file lost evaluation (`AnalysisIncomplete` names it, so the
# injection check is not reported `ok`), keep the findings of the file and of every
# other file, and never let the file read as analysed.
# ---------------------------------------------------------------------------


def _scan_with_incomplete(files: dict[str, str]) -> tuple[list[dict], list[tuple[str, str]]]:
    findings: list[dict] = []
    incomplete: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as d:
        for name, src in files.items():
            Path(d, name).write_text(src, encoding="utf-8")
        try:
            ASTAnalyzer(d, "python").run(findings.append)
        except AnalysisIncomplete as exc:
            incomplete = list(exc.files)
    return findings, incomplete


def _raises(*_args, **_kwargs):
    raise ValueError("lexer exploded")


@pytest.mark.parametrize("lexer", ["js_identifier_escape", "_js_eval_lines"])
@pytest.mark.parametrize("exc", [ValueError("boom"), RecursionError("deep"), MemoryError()])
def test_a_lexer_that_raises_makes_the_file_lost_evaluation(monkeypatch, lexer: str, exc: BaseException) -> None:
    from analyzers import ast_analyzer

    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr(ast_analyzer, lexer, boom)
    findings, incomplete = _scan_with_incomplete({"a.js": "var q = 1;\neval(x);\n", "b.js": "// eval(y)\n"})
    # The file is named as lost evaluation, with a reason that says an internal
    # failure (the generic one `_analyze_python` uses), not "analysed".
    assert sorted(name for name, _ in incomplete) == ["a.js", "b.js"]
    assert all(reason.startswith(("internal error", "recursion limit", "out of memory")) for _, reason in incomplete)


@pytest.mark.parametrize("lexer", ["js_identifier_escape", "_js_eval_lines"])
def test_a_lexer_that_raises_aborts_neither_the_file_nor_the_walk(monkeypatch, lexer: str) -> None:
    from analyzers import ast_analyzer

    monkeypatch.setattr(ast_analyzer, lexer, _raises)
    findings, incomplete = _scan_with_incomplete(
        {"a.js": "var q = 1;\neval(x);\nel.innerHTML = y;\n", "z.py": "import os\nos.system(cmd)\n"}
    )
    ids = {f["id"] for f in findings}
    # The rest of the file is still read (the raw floor reports its `eval(` and the
    # other JS patterns still fire) and the other file in the tree is still analysed.
    assert "SEC-JS_EVAL" in ids
    assert "SEC-JS_INNER_HTML" in ids
    assert any(f["endpoint"].startswith("z.py") for f in findings)
    assert [name for name, _ in incomplete] == ["a.js"]


def test_a_lexer_that_raises_is_never_a_clean_scan(monkeypatch) -> None:
    from analyzers import ast_analyzer

    monkeypatch.setattr(ast_analyzer, "js_identifier_escape", _raises)
    # A file with no finding at all in it still reads as lost evaluation.
    findings, incomplete = _scan_with_incomplete({"quiet.js": "var a = 1;\n"})
    assert findings == []
    assert [name for name, _ in incomplete] == ["quiet.js"]


def test_a_working_lexer_leaves_the_file_analysed() -> None:
    findings, incomplete = _scan_with_incomplete({"a.js": "var q = 1;\neval(x);\n"})
    assert incomplete == []
    assert [f["endpoint"] for f in findings if f["id"] == EVAL] == ["a.js:2"]


def test_a_tokenizer_that_raises_reports_every_raw_match_at_the_v370_grade(monkeypatch) -> None:
    # A crash is a give-up like any other: it decided nothing, so every match of the
    # v3.7.0 pattern is reported at HIGH/HIGH (and the file is lost evaluation), and no
    # other line is reported.
    #   old (CL2-1 first cut): lines [1, 3] at the demoted grade
    #   new (rc.4 brief, no unsafe reduction in BLOCK severity): the same lines at HIGH/HIGH
    from analyzers import ast_analyzer

    monkeypatch.setattr(ast_analyzer, "_js_eval_lines", _raises)
    src = "// eval(a)\nvar q = 1;\neval(b);\nvar r = 2;\n"
    assert _floor_lines(src) == [1, 3]
    assert _lines(src) == [1, 3]
    assert {_grade(f) for f in _eval_findings(src)} == {CONFIRMED}


def _budget_exhausting_program() -> str:
    # A valid script: Node runs it and the `eval` executes (it prints `EVAL-EXECUTED`).
    # `{}/{}/...` is a division of object literals, and each `/` after a `}` is a point
    # where the tokenizer follows two readings (a division or a regular expression).
    # With a fork every three characters it spends its fork budget, no reading completes,
    # and it gives up.
    return (
        'var userInput = "globalThis.__hit = 1";\n'
        + "var x = {}" + "/{}" * 20_000 + ";\n"
        + "eval(userInput);\n"
        + "console.log(globalThis.__hit === 1 ? 'EVAL-EXECUTED' : 'no');\n"
    )


def test_a_valid_program_that_exhausts_the_tokenizer_budget_reports_its_real_eval_at_high() -> None:
    # An adversary controls the budget, so a give-up must never be a downgrade: the real
    # `eval(userInput)` of a program the tokenizer cannot finish reading is HIGH/HIGH.
    from analyzers import ast_analyzer

    src = _budget_exhausting_program()
    assert ast_analyzer._js_eval_lines(src) is None  # the tokenizer gave up
    eval_line = 3
    assert src.splitlines()[eval_line - 1] == "eval(userInput);"
    graded = {_line_of(f): _grade(f) for f in _eval_findings(src)}
    assert graded[eval_line] == CONFIRMED
    assert eval_line in _lines(src)
