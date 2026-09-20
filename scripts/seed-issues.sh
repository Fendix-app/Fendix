#!/usr/bin/env bash
set -euo pipefail

# Seed the first batch of "good first issue" issues on the repo.
# Run once after making the repo public.
#
# Prerequisites: gh CLI authenticated (gh auth status)
# Usage: ./scripts/seed-issues.sh

REPO="Fendix-app/Fendix"

echo "Creating good-first-issue tickets on $REPO..."
echo ""

# Ensure labels exist (gh errors if label doesn't exist on the repo)
echo "Ensuring labels exist..."
gh label create "good first issue" --repo "$REPO" --color 7057ff --description "Good for newcomers" 2>/dev/null || true
gh label create "help wanted" --repo "$REPO" --color 008672 --description "Extra attention is needed" 2>/dev/null || true
gh label create "semgrep-rule" --repo "$REPO" --color fbca04 --description "New Semgrep detection rule" 2>/dev/null || true
gh label create "documentation" --repo "$REPO" --color 0075ca --description "Improvements or additions to documentation" 2>/dev/null || true
gh label create "plugin" --repo "$REPO" --color d4c5f9 --description "Plugin system extension" 2>/dev/null || true
echo ""

gh issue create --repo "$REPO" \
  --title "engine: add LDAP injection as the 8th reachable taint-chain sink class" \
  --label "good first issue,help wanted" \
  --body "$(cat <<'EOF'
## Summary

Fendix v0.11 ships 7 reachable taint-chain sink classes (SQLi / SSRF /
open-redirect / XSS / cmd-injection / path-traversal / insecure deserialization).
LDAP injection is the natural 8th — well-defined surface, narrow attack
shape, parity with everything else.

## Why this is a good first issue

- **Self-contained:** one new helper method + one new branch in
  ``visit_Call``. No cross-package refactor.
- **Pattern-by-mirror:** copy the structure from any of the existing
  reachable sinks (``_is_xss_html_sink``, ``_is_path_traversal_sink``,
  ``_is_ssrf``). Each is ~40 LOC + a sink-names ``frozenset`` + a couple
  of emit-site lines.
- **Clear scope:** sinks are ``ldap3.Connection.search`` /
  ``ldap.search_s`` / ``ldap.search_ext_s`` with a non-literal filter
  string. Skip Constant args; rely on ``_collect_taint_chain`` to set
  ``reachable: true`` when the filter traces back to a request source.

## Example vulnerable code

```python
import ldap
def find_user():
    username = request.args.get("u")
    filter_str = f"(uid={username})"
    return ldap.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

## Example safe code

```python
import ldap, ldap.filter
def find_user():
    username = request.args.get("u")
    filter_str = ldap.filter.filter_format("(uid=%s)", [username])
    return ldap.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

## CWE / OWASP reference

CWE-90: LDAP Injection

## Suggested severity / confidence

HIGH severity, MEDIUM confidence (matching SSRF/XSS/path-traversal posture).

## Implementation notes

- Files to touch:
  - ``python/analyzers/ast_analyzer.py`` — new ``_is_ldap_injection`` /
    ``_ldap_sink_name`` helpers + emit branch in ``visit_Call``; new
    ``_LDAP_SINK_NAMES`` frozenset at module level
  - ``python/tests/test_ast_analyzer.py`` — new ``TestLDAPInjectionReachable``
    class mirroring ``TestPathTraversalReachable`` (TASK-134)
- Don't forget: the second positional arg in some ldap3 APIs is the filter;
  others take it via kwarg. ``_is_path_traversal_sink``'s
  ``_path_traversal_arg_index`` is the precedent for handling that.

### Contribution checklist

- [ ] New ``_LDAP_SINK_NAMES`` frozenset added
- [ ] ``_is_ldap_injection`` + ``_ldap_sink_name`` helpers added
- [ ] Emit branch added to ``visit_Call``
- [ ] At least 5 unit tests (TP positive / multi-hop / Constant-safe / Name-in-scope-safe / shape-parity)
- [ ] ``python -m pytest python/tests/test_ast_analyzer.py`` passes
- [ ] Update ``docs/accuracy.md`` "Categories not in the corpus" — drop LDAP from the list, add new corpus file at ``scripts/accuracy/corpus/ldap.py``
EOF
)"

echo "  [1/5] LDAP injection as 8th reachable sink"

gh issue create --repo "$REPO" \
  --title "eval: build a PyGoat ground-truth manifest for real-world precision/recall" \
  --label "good first issue,documentation,help wanted" \
  --body "$(cat <<'EOF'
## Summary

The ``/accuracy`` page (and ``docs/accuracy.md``) publishes a 3-track
engine evaluation. Track 3 — scanning PyGoat — reports **category
coverage** (every OWASP Top 10 class PyGoat advertises was detected)
but **NOT precision/recall** on a real codebase, because PyGoat doesn't
ship a machine-readable line manifest.

This issue: triage each of PyGoat's 147 findings as TP / FP / not-
applicable, file the result as ``scripts/accuracy/pygoat-manifest.json``,
and update the harness so it can score Track 3 the same way Track 1 is
scored.

## Why this is a good first issue

- **No engine code required.** Pure classification work — read each
  finding, look at the source location, decide.
- **Real-world calibration.** Currently we only have synthetic
  precision/recall (F1 = 1.000); a real-codebase number is what
  potential users actually care about.
- **Bounded scope.** 147 findings × ~30 seconds of human triage each
  = ~75 minutes of focused work.

## Reproduce

```bash
git clone --depth 1 https://github.com/adeyosemanputra/pygoat /tmp/pygoat
./bin/fendix scan --code /tmp/pygoat --python-engine --format json --output /tmp/pygoat.json
```

## Acceptance criteria

- [ ] ``scripts/accuracy/pygoat-manifest.json`` lists every (file, line, category)
      from the scan with one of: ``TP`` (real vulnerability PyGoat
      teaches), ``FP`` (engine flagged a non-issue), ``NA`` (test
      fixture / lab solution / fendix-self FP-style)
- [ ] ``scripts/accuracy/run.py`` extended with a ``--pygoat-manifest``
      mode that scores Track 3 the same way Track 1 is scored
- [ ] ``docs/accuracy.md`` Track 3 section updated with the resulting
      precision / recall / F1 numbers (replacing the current
      "category coverage only" caveat)
- [ ] Numbers reproduced + published on the ``/accuracy`` frontend page

## Reference

- ``scripts/accuracy/manifest.json`` — the synthetic-corpus ground-truth
  manifest. Mirror its structure (file + line + label).
- ``docs/accuracy.md`` Track 3 section — currently honest about not
  having this number; replace the caveat with the actual measurement.
EOF
)"

echo "  [2/5] PyGoat ground-truth manifest"

gh issue create --repo "$REPO" \
  --title "rule: detect Express.js response without helmet() middleware" \
  --label "good first issue,semgrep-rule,help wanted" \
  --body "$(cat <<'EOF'
## Rule summary

Detect Express apps that call `app.listen()` without importing or using
`helmet` (or manually setting security headers).

## Language(s)

JavaScript / TypeScript

## Example vulnerable code

```javascript
const app = express();
app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## Example safe code

```javascript
const app = express();
app.use(helmet());
app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
```

## CWE / OWASP reference

CWE-693: Protection Mechanism Failure

## Suggested severity

MEDIUM

## Implementation notes

- Add to `python/rules/injection.yaml` (Semgrep rules live under `python/rules/` even for JS targets — Semgrep handles multi-language)
- This is a file-level pattern — look for `express()` + `listen()` without `helmet`
- Semgrep's `pattern-not` + `pattern-inside` combinators make this ergonomic
- Test fixtures go in `python/tests/fixtures/` as `.js` files

### Contribution checklist

- [ ] Rule YAML added to `python/rules/injection.yaml` (with `languages: [javascript, typescript]`)
- [ ] At least 1 true-positive `.js` test fixture in `python/tests/fixtures/`
- [ ] At least 1 true-negative `.js` test fixture
- [ ] `python -m pytest python/tests/test_semgrep_runner.py` passes
EOF
)"

echo "  [3/5] Express.js helmet rule"

gh issue create --repo "$REPO" \
  --title "docs: add juice-shop walkthrough screenshots to README" \
  --label "good first issue,documentation,help wanted" \
  --body "$(cat <<'EOF'
## Summary

The README references a juice-shop benchmark but has no screenshots showing
what a Fendix scan report looks like. Add 2-3 annotated screenshots.

## Context

First-time visitors to the repo need to see what the output looks like
before they invest time installing. The `fendix demo` command produces
an HTML report against juice-shop — capture that.

## Acceptance criteria

- [ ] 2-3 screenshots added to `docs/images/` (PNG, <500KB each)
- [ ] README.md updated with `![...]()` references in the "Quick start" section
- [ ] Screenshots show: (a) terminal output of a scan, (b) HTML report summary, (c) a finding detail

## How to reproduce

```bash
# Requires Docker
fendix demo --open
# Screenshot the terminal + the HTML report that opens
```
EOF
)"

echo "  [4/5] README screenshots"

gh issue create --repo "$REPO" \
  --title "plugin: custom header compliance check (reference plugin)" \
  --label "good first issue,plugin,help wanted" \
  --body "$(cat <<'EOF'
## Summary

Write a reference plugin that checks API responses for a required custom
header (e.g., `X-Request-Id` for tracing). This demonstrates the blackbox
plugin contract with a simple, achievable scope.

## Context

Demonstrates the plugin system (docs/plugins.md) with a real-world use case
beyond the existing 3 reference plugins. Shows how a blackbox plugin can
bring its own compliance logic without modifying the core engine.

## Acceptance criteria

- [ ] Plugin lives at `examples/plugins/required-header-check/`
- [ ] `plugin.yaml` with mode: blackbox, timeout: 30s
- [ ] Entrypoint script (Python) that reads ScanRequest, makes GET requests
      to each endpoint, checks for the configured header
- [ ] Emits LOW finding for each endpoint missing the header
- [ ] Header name configurable via env var (default: `X-Request-Id`)
- [ ] README in the plugin directory explaining what it does
- [ ] Works end-to-end: `fendix scan --url http://target` picks it up

## Pointers

- Plugin authoring guide: `docs/plugins.md`
- Existing reference plugins: `examples/plugins/`
- Look at `examples/plugins/custom-blackbox-check/` for the closest pattern

## How to test

```bash
cp -r examples/plugins/required-header-check ~/.fendix/plugins/
# Start any HTTP server that doesn't set X-Request-Id
python3 -m http.server 9999 &
fendix scan --url http://localhost:9999
# Should see the plugin's finding in output
kill %1
```
EOF
)"

echo "  [5/5] Required header check plugin"

echo ""
echo "Done! 5 good-first-issue tickets created."
echo "View them: gh issue list --repo $REPO --label 'good first issue'"
