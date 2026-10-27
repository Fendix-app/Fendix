# ADR-011: Semgrep Taint Findings Count as Reachable per Language

## Status

Accepted (2026-10-27). Owner decision D1 of the framework parity gap-closure
plan (2026-10-24), ruled as R-D1, implemented in its Task 4.1. Task 4.1 adds
the mechanism with every language disabled. Tasks 4.3 (JavaScript and
TypeScript), 4.4 (Java) and 4.5 (Go) add the taint rules and enable a
language once it meets the gate below.

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
Task 0.5). The release gate checks holdout precision. The map ships empty.

**The tier.** `models.TierSemgrepTaint` (`semgrep_taint`) is the tier of such
a finding. `semgrep.mapResult` assigns it only when all three hold:

1. The rule sets `metadata.fendix_reachability: taint`.
2. Every language in the rule's `languages` is in `ReachabilityLanguages`.
   Semgrep's results do not name a language, so the languages are read from
   the bundled rule pack. A rule whose languages are unknown or empty fails
   this check. Semgrep's aliases `js`, `ts` and `golang` count as
   `javascript`, `typescript` and `go`.
3. The result's `dataflow_trace` has a source that decodes.

The finding then gets `Reachable`, the new tier, and the trace as its
`TaintChain`: the source, the intermediate variables, then the sink. A
`CliCall` is flattened in dataflow order. Each link's file is made relative
the way `Endpoint` is, and its expression is masked for credential-shaped
literals the way `Sink` is. The chain always ends at the finding's own file,
line and `Sink`.

When any condition fails, the finding is the `semgrep_shim` finding it was
before, and the trace is never decoded. Scan passes `--dataflow-traces` on
every run. No bundled rule sets `fendix_reachability` yet, so no finding
changes.

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
a MEDIUM band needs an independent signal is unchanged. Its reachability also
takes the correlator's reachable escalation, as it takes the non-correlated
one.

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
  level higher and is kept with its chain. Rule authors declare a taint rule
  at the severity they want before that bump (a plan constraint), so a taint
  rule declared below textscan's severity loses the tie on purpose.
- Rank 2 also puts it above the shim and the unknown tier, so a proven finding
  is kept over a Semgrep pattern finding on the same line.
- Not rank 3: that is the Python AST analyzer, which cleared the F1 >= 0.95
  gate. A taint pack's gate is a development-set precision measurement, and
  its proof stops at the function boundary.

## Consequences

**Positive:**
- A language becomes provable by adding one key to `ReachabilityLanguages`,
  with its precision evidence in that change. No other code moves.
- A proven Semgrep taint finding carries the same `reachable`, `taint_chain`
  and SARIF `codeFlows` a Python finding does.
- Turning a language on does not change a finding's identity
  (`TestTaintGateKeepsFindingIdentity`). The chain ends at the finding's own
  file and `Sink`, which are the identity inputs `models.Fingerprint` reads.
- No detection changes in Task 4.1. The framework parity gate shows no case
  change.

**Negative:**
- **A logged-out Semgrep sends no trace.** Condition 3 fails for every
  finding of a run with no Semgrep account logged in. That is the default for
  the CLI and the GitHub Action, neither of which logs in to Semgrep, and of
the parity harness. Enabling a language under
  this ADR has no effect on such runs until the trace reaches Fendix. Task 4.3
  must choose how before it enables a language. The candidates are reading
  the trace from Semgrep's text output, written alongside the JSON in the
  same run; or treating a taint-mode match as the proof, since Semgrep
  reports one only when a source reaches the sink, with a chain that holds
  only the finding's own location. This ADR records the problem. It does not
  choose.
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
- `TestReachabilityLanguagesShipEmpty` fails when a language is added, so
  the change that enables one must also update that test.
- The trace is decoded only for a rule that asks for it, and never fails the
  document. `TestUnreadableTaintTraceNeverDropsFindings` covers an unknown
  variant tag, a trace of the wrong type, and a location without a path.
- `TestTaintRuleWithALanguageNotEnabledStaysShim` covers a rule with one of
  its two languages enabled, a rule of unknown languages and a rule with none.
- `TestSemgrepTaintNeverDeterministic`, `TestSemgrepTaintMediumWithReachableBlocks`
  and `TestSemgrepTaintWithoutReachableWarns` pin the scoring and the gate.
  `TestNoBlockWithoutCorroboration` checks the block invariant for the new
  tier too.
- `TestProvenPathNeverFromASemgrepTier`,
  `TestNoIndependence_FendixSemgrepTaintVsImportedSemgrep` and
  `TestSemgrepTaintTierExportsAsSemgrep` pin the Semgrep-tier limits.
