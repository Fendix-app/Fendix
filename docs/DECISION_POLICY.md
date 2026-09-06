# Fendix Decision Policy

**Status:** shipped in the decision-integrity change (RC-1 / RC-2 / RC-3)
**Policy version:** `1.0.0` — stamped into every report as `metadata.policy_version` (`decision.PolicyVersion`). Bumped when a rule in `applyConfidenceGate` or the corroboration taxonomy changes meaning; the report schema version does not move for that.
**Authoritative implementation:** `go/internal/decision/decision.go`
**Escape hatch:** `--enforce-confidence=false` restores the pre-policy
severity-only mapping byte-for-byte.

This document is the human-readable form of the policy. Where the two disagree,
the code is right and this file is a bug.

---

## The four states

Fendix keeps these distinct and never silently promotes one to the next:

| State | Meaning |
|---|---|
| **Observed condition** | a scanner observed something potentially relevant |
| **Security evidence** | the observation supports a security claim |
| **Confirmed vulnerability** | sufficient independent/correlated evidence exists |
| **Blocking decision** | evidence meets the explicit policy required to fail CI |

**A finding never becomes `BLOCK` because its rule carries a high static
severity.** Severity is a constant chosen by the scanner that emitted the
finding; on its own it says nothing about whether the claim was established.

---

## Inputs

Three independent axes feed a decision. They are deliberately not collapsed.

**Severity** — the scanner's static impact estimate, capped by
`models.MaxSeverityForConfidence` against the producer's `Confidence` enum.
Decides only whether the finding meets `--fail-on`.

**Confidence band** — `confidence.Score` produces a deterministic 0–100 score
and buckets it: `HIGH ≥ 70`, `MEDIUM ≥ 40`, `LOW` below. Every point comes from
a documented rule with a plain-text reason; the reasons sum to the score. There
is no AI anywhere in this path (Constitution Rule 8).

**Corroboration** — `decision.corroborate` partitions the signals supporting the
claim into two classes.

### Independent signals

An observation **distinct from** the one that produced the claim — something
that could have disagreed and didn't.

| Signal | Set by |
|---|---|
| `cross-engine agreement` | `Source == correlated` (DAST and SAST both flagged it) |
| `confirmed route` | a live request reached the vulnerable route |
| `reachable taint path` | the AST analyzer proved source → sink |
| `proven path` | confirmed route **and** reachable chain |
| `payload-validated probe` | an active probe's payload elicited the predicted response (`Payload` **and** `Response`) |
| `independent cross-tool corroboration` | `engine.CorrelateCrossTool` — another tool reported the same normalized CWE at the same normalized location |
| `contradicted authentication requirement` | a declared `security` requirement was not enforced live |

### Self-evident signals

The claim **is** the observation. Strong — these carry the scorer's largest
deltas — but not confirmation, because there is no second observation that could
have disagreed.

| Signal | Set by |
|---|---|
| `direct observation of a live response` | a deterministic read: a header, cookie attribute or CORS value present or absent |
| `deterministic detection in production code` | a high-confidence pattern match in non-test, non-fixture source |
| `imported high-precision rule` | an external tool declaring its own rule high-precision (SARIF import) |

### Not a signal

`Source == blackbox` is **not** corroboration. It restates a field the report
already exports. Counting it made every DAST finding corroborate itself, which
reduced the gate to "severity ≥ `--fail-on`" — this was RC-1, and it is why
`liveRuntimeObservation` no longer exists.

---

## The rules

Evaluated in order, in `applyConfidenceGate`.

```
severity < --fail-on
    severity ≥ MEDIUM                                    → WARN
    otherwise                                            → INFO

severity ≥ --fail-on
    marked unconfirmed-by-live-scan, no independent      → WARN
    band LOW                                             → WARN
    NO signal of any class                               → WARN
    band MEDIUM, no INDEPENDENT signal                   → WARN
    otherwise                                            → BLOCK
```

Then the dependency-applicability gate, for a threshold-crossing `deps` finding:

```
applicability = evidence_against, --block-on-inapplicable off  → WARN
```

It applies whether the confidence gate left the finding at BLOCK or already at
WARN, so applicability is the STATED reason whenever it applies rather than a
fact the reader has to correlate. The finding keeps its id, severity, CVE
identity and full evidence text; the score never moves.

Then the test-fixture de-escalation (`--deescalate-tests`, on by default):

```
BLOCK + in test/fixture code + no independent signal     → WARN
WARN  + below --fail-on + in test/fixture code           → INFO
```

A finding whose severity met `--fail-on` is never reported below WARN.

### Why self-evident signals still gate at HIGH

An earlier revision required an independent signal unconditionally. A test
caught that it broke the case `deterministicDetn` exists for: a **real hardcoded
credential in production source on a code-only scan**, where a second
observation is impossible in principle. Demanding one would mean secrets can
never gate a code-only scan.

The distinction that matters is whether the observation **establishes** the
claim:

- **secrets** — "this regex matched a credential in non-test source" *is*
  substantially the claim. Sufficient at HIGH.
- **auth_bypass** — "HTTP 200 with no Authorization header" is *not* the claim
  "authentication was bypassed". It is missing the premise *authentication was
  expected here*, which no status code can supply. It scores no signal at all
  and is held at WARN until a declared expectation supplies that premise.

---

## Authentication expectation

`models.AuthExpectation` is three-state, and the third state is load-bearing.

| State | Source | Claim on an unauthenticated 2xx | Severity |
|---|---|---|---|
| `required` | OpenAPI operation/global `security` | `Authentication requirement bypassed` | CRITICAL |
| `unknown` (zero value) | nothing established one | `Unauthenticated endpoint observed` | MEDIUM |
| `public` | `security: []` or `security: [{}]` | `Unauthenticated endpoint observed` | INFO |

Collapsing `unknown` into `public` would suppress real bypasses. Collapsing it
into `required` flags every public endpoint — that was RC-2.

**No path is ever special-cased.** A `/status` the spec declares protected
reports a bypass; an `/api/admin` the spec declares public does not.

---

## Evidence preservation

Two rules the pipeline may not violate.

**Rule 3 — de-escalate, never delete.** No policy arm drops a finding, edits its
evidence text or changes its confidence score. Only `Status`, `Reason` and one
appended `+0` explainability line move.

**Proof union — a duplicate never erases a proof.** `engine.Deduplicate` folds
`Reachable`, `ProvenPath`, `RouteConfirmed` by OR, `SourceTier` by max trust,
and `TaintChain` / `Route` from the member that proved one. Only members that
carried the evidence contribute, so the fold cannot manufacture it. Before RC-3
these rode along with the lexicographic-minimum group member, so a confirmed
occurrence merged with an earlier-sorting unconfirmed one lost its proof
systematically.

**Unknown is never false.** At every layer, a fact that was not evaluated is
distinguishable from one evaluated to false. In the SARIF export the evidence
sub-object is a `map`, not a struct, precisely so an unevaluated key can be
**absent** — a struct field is either true or false, and `omitempty` on a bool
would make a genuinely-evaluated `false` unrepresentable.

---

## Auditability

Every decision exports its justification in SARIF
`result.properties.decision`:

```json
{
  "status": "BLOCK",
  "reason": "severity at or above the --fail-on threshold; corroborated by: reachable taint path",
  "independent_signals": ["reachable taint path"],
  "self_evident_signals": ["deterministic detection in production code"],
  "evidence": {
    "reachable": true,
    "flow_established": true,
    "source_controlled": true,
    "sink_detected": true
  }
}
```

The partition is computed **once**, in `decide()`, and stamped onto the finding
from the `Decision` the gate produced. It is never re-derived downstream — that
is how an exporter drifts from the policy it claims to describe.

**Invariant, enforced by `TestNoBlockWithoutCorroboration` over 20,400 evidence
shapes:** no `BLOCK` exists without a corroborating signal, and no MEDIUM-band
`BLOCK` exists without an independent one.

---

## Dependency applicability

`models.Applicability` is three-state, and three is what the analyzer can
produce (`scanner/deps/applicability.resolve`):

| State | Meaning | Effect |
|---|---|---|
| `` (unknown) | no importable component known, or the grep failed open | normal policy |
| `applicable` | an affected component IS imported | normal policy (eligible to BLOCK) |
| `evidence_against` | no affected component is imported | held at WARN |

There is deliberately no fourth "confirmed non-applicable" state. The backing
evidence is a static import grep and dynamic import forms can defeat it, so
absence of an import is *evidence* against applicability, never proof — the
state is named after what it is. Symmetrically `applicable` means "imported",
not "the vulnerable function is reached": Fendix builds no dependency call
graph.

`--block-on-inapplicable` restores blocking for teams whose policy is "no
vulnerable version ships, applicable or not".

---

## Policy override

`--enforce-confidence=false` restores the legacy severity-only gate, so an
uncorroborated finding can fail a build again. Because a BLOCK then means
something different, the decision records it:

| Field | Meaning |
|---|---|
| `decision.policy` | `enforced` or `relaxed` |
| `decision.policy_override` | present and `true` only when the relaxation CHANGED the outcome |

`policy_override` is deliberately **not** "the relaxed policy was in effect". A
relaxed run whose findings are all independently corroborated blocks identically
under either policy; marking those would cry wolf until readers ignore the flag.
`decide()` runs the shipped gate on a shadow copy and compares, and the reason
string names what the shipped policy would have done.

Both keys are omitted otherwise, so their presence is the signal.

---

## Compatibility

`--enforce-confidence=false` restores the severity-only mapping byte-for-byte:
corroboration is ignored entirely and severity alone decides.
`TestLegacyPolicyIgnoresCorroborationEntirely` locks it.

**Behaviour change on upgrade:** scans that exited 1 on a bare blackbox finding
now exit 0. This is intended — that exit code was produced by a severity
constant plus a tautology.
