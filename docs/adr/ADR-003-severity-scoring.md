# ADR-003: Severity Scoring Model

## Status

Superseded as the runtime severity policy; retained as a tested reference
model for the confidence caps.

## Superseding implementation

Runtime severity is discrete: each producer assigns severity, correlation and
proven reachability may escalate it, and
`models.EnforceSeverityConsistency` applies the confidence cap. No scanner
calls `CalculateSeverity` or `CalculateSeverityReachable`. Build gating is a
separate decision axis implemented in `internal/decision` and documented in
[`DECISION_POLICY.md`](../DECISION_POLICY.md).

The formula below remains in `internal/models/scoring.go` as a reference model
and test oracle. It must not be described as the function that computes a live
scan's severity.

## Context

Security findings need consistent, explainable severity levels. Different sources (black-box, white-box, correlated) and different confidence levels should influence the final severity. A finding confirmed by both engines should be rated higher than one flagged by only one.

## Decision

Use a multiplicative scoring model:

```
Score = ImpactBase[category] x ConfidenceMult[confidence] x SourceMult[source]
```

**Thresholds:**
- CRITICAL >= 9.0
- HIGH >= 7.0
- MEDIUM >= 4.0
- LOW >= 1.0
- INFO < 1.0

**Impact base values** reflect the real-world damage potential of each vulnerability category, based on OWASP Top 10 and CWE severity ratings.

**Source multiplier** slightly elevates correlated findings (1.1x) and slightly reduces whitebox-only findings (0.9x), reflecting the confidence difference between runtime-confirmed and static-analysis-only issues.

## Consequences

**Positive:**
- Deterministic: same input always produces same severity
- Explainable: users can understand why a finding has a specific severity
- Correlated findings naturally get higher scores
- Low-confidence findings are appropriately downgraded

**Negative:**
- The multipliers are chosen by judgment, not statistical analysis
- Some edge cases may produce unexpected severity levels at threshold boundaries

**Mitigations:**
- Table-driven tests cover all category/confidence/source combinations
- Scoring model is documented in MEMORY.md for easy reference
