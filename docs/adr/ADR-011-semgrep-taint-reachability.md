# ADR-011: Semgrep Taint Findings Count as Reachable per Language

## Status

Accepted (2026-10-27). Owner decision D1 of the framework parity gap-closure
plan (2026-10-24), ruled as R-D1, implemented in its Task 4.1. The
controller's ruling R-pf56 amends the brief's condition on the trace: a
taint-mode match is the proof, and the trace only adds detail. Task 4.1 adds
the mechanism with every language disabled. Tasks 4.3 (JavaScript and
TypeScript), 4.4 (Java) and 4.5 (Go) add the taint rules and enable a
language once it meets the gate below. On the corpus evidence alone they
enabled `javascript` and `typescript`, `java` and `go`.

Amended by ruling R-pf81: a blind real-world evaluation measured taint-tier
precision of 0.077 (JavaScript and TypeScript), 0.111 (Java) and 0.091 (Go),
all below the 0.80 rule fixed in advance, so no language is enabled and the
three packs report warnings. The evidence is under
[Enabled languages](#enabled-languages) and
[Real-world precision](#real-world-precision).

## Context

Fendix proves that request input reaches a sink for Python only. The Python
AST analyzer (`tree_sitter_sidecar`) records the flow as a `TaintChain` and
sets `Reachable`. For JavaScript, TypeScript, Java and Go, findings come from
textscan (`native_go`, one line at a time) and from the bundled Semgrep pack
(`semgrep_shim`, patterns). Neither proves a flow. Phase 4 of the plan adds
in-house Semgrep taint packs for those languages. Semgrep reports a taint
match only when a source reaches a sink, and with `--dataflow-traces` it can
show the path.

D1 asked whether such a finding counts as `Reachable`. The flag carries
weight in three places:

- `confidence.Score` adds +10 (`reachable_taint_path`).
- `decision.corroborate` counts it as an independent signal, so a
  MEDIUM-band finding at or above `--fail-on` blocks on it
  (`decision.applyConfidenceGate`).
- The finding is escalated one severity level:
  `engine.escalateNonCorrelatedReachable` for a finding that did not
  correlate, `engine.mergeFindings` for one that did.

Granting the flag to a pack nobody has measured would let that pack's false
positives block builds.

A spike on a one-file Express app found one more fact. Semgrep 1.141.0 with no
Semgrep account logged in leaves `extra.dataflow_trace` out of its `--json`
output, and `codeFlows` out of its `--sarif` output. Its text output prints
the trace. The same formatter replaces `extra.lines` with `requires login`,
which Fendix already works around by reading the line from disk. The trace
exists inside the CLI before that formatter runs, and its shape is the one
Semgrep's output schema (`semgrep_output_v1`) defines (positions shortened):

```text
"dataflow_trace": {
  "taint_source": ["CliLoc", [{"path": "app.js", "start": {"line": 7, "col": 16, "offset": 138},
                               "end": {"line": 7, "col": 30, "offset": 152}}, "req.query.name"]],
  "intermediate_vars": [{"location": {"path": "app.js", "start": {...}, "end": {...}}, "content": "name"},
                        {"location": {"path": "app.js", "start": {...}, "end": {...}}, "content": "sql"}],
  "taint_sink": ["CliLoc", [{"path": "app.js", "start": {"line": 9, ...}, "end": {...}},
                             "db.query(sql, (err, rows) => res.json(rows))"]]
}
```

`taint_source` and `taint_sink` are ATD variants, encoded as tagged arrays:
`["CliLoc", [location, content]]`, or
`["CliCall", [[location, content], [intermediate_var, ...], <trace>]]` for a
flow that passes through a call. Semgrep's open-source engine does not follow
taint across functions (`--pro-intrafile` requires Semgrep Pro), so the
spike's trace is all `CliLoc`. The decoder reads both variants.

## Decision

**R-D1.** A Semgrep taint finding counts as `Reachable` only for the
languages in `semgrep.ReachabilityLanguages`. A language is enabled when its
taint pack reaches precision >= 0.90 on the corpus v2 development set
(`benchmarks/frameworks/`) and stays within the plan's noise budget (its
Task 0.5). The release gate checks holdout precision. Task 4.1 shipped the
map empty; each language is added in the change that carries its evidence.

**R-pf81: the real-world gate.** The development set is the packs' own
corpus, so it cannot show how they behave on code nobody wrote them against.
A language is enabled only if, in addition, a blind evaluation on fresh public
production repositories finds precision of at least 0.80 on at least 10
triaged taint-tier findings. JavaScript and TypeScript, Java and Go met the
development gate and failed this one, and shipped warn-only (the map is empty).

**R-pf56: the match is the proof, the trace is detail.** Semgrep reports a
match of a `mode: taint` rule only when one of the rule's declared sources
reached its sink within one function. That match is the reachability claim.
The per-language precision gate (R-D1) is what protects its quality. A trace
is not required, because a logged-out Semgrep never sends one, and a finding
must not be reachable or not depending on a login.

**The tier.** `models.TierSemgrepTaint` (`semgrep_taint`) is the tier of such
a finding. `semgrep.mapResult` assigns it when all three hold:

1. The rule sets `metadata.fendix_reachability: taint`.
2. The rule is a taint rule: `mode: taint` in the bundled rule pack. A
   pattern rule's match proves no flow, whatever its metadata says.
3. Every language in the rule's `languages` is in `ReachabilityLanguages`.
   Semgrep accepts the aliases `js`, `ts` and `golang`; they count as
   `javascript`, `typescript` and `go`. A rule whose languages are unknown or
   empty fails this check.

Semgrep's result carries the rule's metadata, but neither its `mode` nor its
`languages`. Both are read from the rule YAML embedded in the binary
(`ruleSpecs`), and a rule the pack does not contain fails the check.

The finding then gets `Reachable` and the new tier. Its `TaintChain` always
ends at the finding's own file, line and `Sink`:

- **With a trace** (a logged-in run), the chain is the source, the
  intermediate variables, then the sink. A `CliCall` is flattened in
  dataflow order. Each link's file is made relative the way `Endpoint` is,
  and its expression is masked for credential-shaped literals the way `Sink`
  is. The trace's sink step is replaced by the finding's own link when it is
  the same location, and is followed by it otherwise.
- **Without a trace**, or with one that does not decode or has no source, the
  chain is the finding's own link alone.

When any condition fails, the finding is the `semgrep_shim` finding it was
before, and the trace is never decoded. Scan passes `--dataflow-traces` on
every run. No bundled rule sets `fendix_reachability` yet, so no finding
changes.

**Identity does not depend on the trace, the login or the gate.** A rule that
sets `fendix_reachability: taint` takes its identity only from what every run
has. Its `Sink` is the match's own first line, read from disk, or else the
first line of `extra.lines`. It is never the trace's sink, and never the
whole `extra.lines`: a logged-in run sends every line of a multi-line match
there. Its `Symbol` is empty, because Semgrep sends metavariables only to a
logged-in account. `models.Fingerprint` reads the file, the symbol and the
operation, and for these findings all three are the same logged in or out,
with or without a trace, gate open or closed. No rule bundled before this ADR
sets the key, so no existing identity moves.

**Still a Semgrep tier.** `models.SourceTier.IsSemgrep` is true for both
Semgrep tiers. Every rule that limits a Semgrep finding reads it:

- `confidence.HasDeterministicDetection` stays false, so a Semgrep finding
  never earns the +30 deterministic-detection delta.
- Both tiers take the -5 `tier_semgrep` delta.
- `engine.stampToolIDs` gives both the tool id `semgrep`, so Fendix's Semgrep
  pass and an imported Semgrep SARIF never corroborate each other.
- `engine.mergeFindings` never sets `ProvenPath` for a Semgrep tier. The
  managed-CI contract's rule `proven_path_requires_route_and_taint` rejects
  `proven_path` with `analyzer_implementation: "semgrep"`.
- `managedci.FactsFrom` exports both tiers as `analyzer_implementation:
  "semgrep"`, so the backend applies the same `tier_semgrep` delta and the
  same deterministic-detection exclusion as the engine.

A proven `semgrep_taint` finding scores 35 base + 10 static + 10 reachable -
5 tier = 50, in the MEDIUM band. At or above `--fail-on` it blocks through
the reachable-path signal, never on its own say-so: the gate's invariant that
a MEDIUM band needs an independent signal is unchanged.

**Severity.** A `Reachable` finding is escalated one severity level by
`engine.escalateNonCorrelatedReachable`. A correlated one gets the
correlation bump and the reachable bump from `engine.mergeFindings`. A taint
rule declared `fendix_severity: HIGH` therefore reports CRITICAL once its
language is enabled. Rule authors declare a taint rule at the severity they
want before that bump.

**TrustRank 2.** `CollapseDuplicateLocations` keeps one finding per
(Category, Endpoint) when different analyzer tiers report the same location.
It keeps the highest `TrustRank`, then the highest severity, then the
`findingLess` order. It does not move `Reachable` or `TaintChain` from a
dropped finding to the kept one. The taint packs' sinks overlap textscan's
JavaScript, Java and Go rules (`native_go`, rank 2) on the same lines.

- At the shim's rank 0, textscan's finding would always be kept and the taint
  proof would be dropped, which is the proof Phase 4 exists to add.
- At rank 2 the two tie. `escalateNonCorrelatedReachable` runs before the
  collapse, so a proven finding declared at textscan's severity arrives one
  level higher and is kept with its chain. A taint rule declared below
  textscan's severity loses the tie on purpose.
- Rank 2 also puts it above the shim and the unknown tier, so a proven finding
  is kept over a Semgrep pattern finding on the same line.
- Not rank 3: that is the Python AST analyzer, which cleared the F1 >= 0.95
  gate. A taint pack's gate is a development-set precision measurement, and
  its proof stops at the function boundary.

## Consequences

**Positive:**
- A language becomes provable by adding one key to `ReachabilityLanguages`,
  with its precision evidence in that change. No other code moves.
- It works on a default run. A logged-out Semgrep run proves the same
  findings a logged-in one does.
- Turning a language on, logging in or out, and the trace arriving or not do
  not change a finding's identity (`TestTraceNeverMovesIdentity`).
- No detection changes in Task 4.1. The framework parity gate shows no case
  change.

**Negative:**
- **A logged-out run shows no path.** Semgrep 1.141.0 with no account logged
  in leaves `dataflow_trace` out of `--json`, so a default run's chain is the
  finding's own location alone. That is the CLI and the GitHub Action, neither
  of which logs in to Semgrep, and the parity harness. A reader sees where
  the sink is, but not the source line. Fendix does not parse Semgrep's text
  output to recover it.
- The proof is Semgrep's, not Fendix's. Whether a match is a real flow
  depends on the rule's sources, sinks and sanitizers. The per-language
  precision gate is the only measurement of that, so a language must not be
  enabled without it.
- `--dataflow-traces` is passed on every run. Measured with Semgrep 1.141.0
  over the parity corpus, three runs each way: one run over the whole corpus
  took 1.52 s without the flag and 1.55 s with it, and one run per framework
  directory (nine runs) took 9.29 s and 9.61 s in total. With a taint rule
  added the totals were 9.63 s and 9.91 s. That is about 3%, within the
  run-to-run spread, and far inside the 120 s timeout.
- `semgrep_taint` is a new value of the published `source_tier` enum
  (`docs/schema.json`, `docs/reporting-contract.json`). The change is
  additive, but `fendix_frontend` needs a `npm run docs:contracts:sync`
  follow-up.

**Mitigations:**
- `TestNoLanguageClearsTheRealWorldGate` (first
  `TestReachabilityLanguagesShipEmpty`, later `TestReachabilityLanguagesAreTheClearedOnes`)
  pins the enabled set, which is empty, so the change that enables a language
  must also update that test. The JavaScript, Java and Go pack tests assert
  the shipped gate is closed and, with a map injected, that it opens.
- `TestLoggedOutTaintResultIsReachableWithoutATrace` runs on Semgrep's real
  logged-out output, and `TestTraceNeverMovesIdentity` checks that both
  recorded runs, gate open and closed, have one fingerprint.
- `TestNonTaintRuleNeverReachable` covers a rule without the metadata, a
  pattern rule with it, and a rule the pack does not contain.
  `TestTaintRuleWithALanguageNotEnabledStaysShim` covers a rule with one of
  its two languages enabled and a rule with none.
- A trace is decoded only for a reachable finding and never fails the
  document. `TestUnreadableTaintTraceOnlyLosesDetail` covers an unknown
  variant tag, a trace of the wrong type, a location without a path and a
  trace without a source.
- `TestSemgrepTaintNeverDeterministic`, `TestSemgrepTaintMediumWithReachableBlocks`
  and `TestSemgrepTaintWithoutReachableWarns` pin the scoring and the gate.
  `TestNoBlockWithoutCorroboration` checks the block invariant for the new
  tier too.
- `TestProvenPathNeverFromASemgrepTier`,
  `TestCorrelatedSemgrepTaintTakesTheReachableEscalation`,
  `TestNoIndependence_FendixSemgrepTaintVsImportedSemgrep` and
  `TestSemgrepTaintTierExportsAsSemgrep` pin the Semgrep-tier limits and the
  escalation.

## Enabled languages

No language is enabled: `ReachabilityLanguages` is empty (R-pf81). Every pack
below met the development gate and failed the real-world one.

| Language | Pack | Development-set precision | Noise on the clean target | Real-world precision | Decision |
|---|---|---|---|---|---|
| `javascript`, `typescript` | Task 4.3 (`javascript-injection`, `javascript-web`, `javascript-crypto`) | 96 / (96 + 3) = 0.970 over the 174 Express, NestJS and Next.js cases. The 3 FPs are the `sqli-safe_lookalike` cases the Python engine's `SEC-JS_SQL_TEMPLATE` already flagged; none is a pack finding. | No new finding on `node-express-realworld` (2.4 kLOC). Of the pack's 19 matches on `juice-shop` and `nodegoat`, 17 are true positives. | 1 / 13 = 0.077 (12 repos) | Warn-only |
| `java` | Task 4.4 (Spring packs `java-injection`, `java-web`, `java-crypto`) | 35 / (35 + 2) = 0.946 on the Spring corpus; both false positives are textscan's | no new finding on `spring-petclinic` | 1 / 9 = 0.111 (20 repos; 10 findings, one unclear) | Warn-only |
| `go` | Task 4.5 (Go packs `go-injection`, `go-web`, `go-crypto`) | 72 / (72 + 4) = 0.947 on the net/http and Gin cases; the four false positives are textscan's | no new finding on `golang-gin-realworld` | 1 / 11 = 0.091 (38 repos) | Warn-only |

Precision is true positives over true and false positives on the
language's cases of `benchmarks/frameworks/`, counted on the integrated build
(`make parity-baseline`), so it also counts findings of other analyzers.

`javascript` and `typescript` would be enabled together: every rule of the
JavaScript and TypeScript pack declares both, and a rule counts only when all
its languages are enabled. Holdout precision is checked by the controller after
the packs are integrated, and may disable a language.

### Real-world precision

The evaluation scanned 70 fresh public production repositories (12 JavaScript
and TypeScript, 20 Java and 38 Go; none over about 300 kLOC) at commit
`6901cf7`, and triaged every taint-tier finding by reading the handler and
the helpers it calls (34 in all, no sampling). The decision rule was fixed in
advance: a language ships blocking only with precision of at least 0.80 on at
least 10 findings. All three had at least 10 findings and precision far below
0.80. The outcome does not change if the one unclear Java finding is counted
as true (0.20), or if every borderline label is flipped.

The three true positives are low impact: one authenticated path traversal
and two unvalidated open redirects. The false
positives share a few causes:

- `js-weak-random-token-taint` reports any `Math.random()` whose value flows
  to a return or a call, whatever it is used for (5 of 13 JavaScript findings).
- An open redirect whose URL comes from configuration, with only a selector
  from the request (4 Java findings), and a redirect validator the rule
  cannot see through (JavaScript and Go).
- A sink matched by method name rather than type (`go-sqli-taint`, 3 Go
  findings), and a project's own sanitiser (Java XSS and path traversal).

The method, the per-language table, the false-positive causes and the list of
scanned repositories are in
[`benchmarks/frameworks/REALWORLD.md`](../../benchmarks/frameworks/REALWORLD.md).
The corpus gate is unchanged. A language is enabled again only when its
pack, fixed for these causes, clears both gates on a new evaluation.
