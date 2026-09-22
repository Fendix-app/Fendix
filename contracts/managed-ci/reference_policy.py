#!/usr/bin/env python3
"""Reference interpreter for the managed-CI finding and release policy specifications.

This is contract tooling, not production code. It evaluates
`v2/policy/finding-policy-<version>.json` and `v2/policy/managed-release-2.0.0.json`
exactly as written, so the canonical validator can prove that every generated
engine vector and every decision fixture is DERIVED from evidence facts and
policy rather than asserted. The backend implements the same interpretation.
"""

from __future__ import annotations

import json
from pathlib import Path

LIVE_SOURCES = ("blackbox", "correlated")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class Unclassifiable(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _resolve(ref: str, ctx: dict):
    namespace, _, name = ref.partition(".")
    return ctx[namespace][name]


def evaluate(predicate: dict, ctx: dict, spec: dict) -> bool:
    if "all" in predicate:
        return all(evaluate(p, ctx, spec) for p in predicate["all"])
    if "any" in predicate:
        return any(evaluate(p, ctx, spec) for p in predicate["any"])
    if "not" in predicate:
        return not evaluate(predicate["not"], ctx, spec)
    if "always" in predicate:
        return predicate["always"] is True
    if "predicate" in predicate:
        return evaluate(spec["predicates"][predicate["predicate"]], ctx, spec)
    value = _resolve(predicate["ref"], ctx)
    if "eq" in predicate:
        expected = predicate["eq"]
        return value == expected and type(value) is type(expected)
    if "in" in predicate:
        return value in predicate["in"]
    if "gte" in predicate:
        return value >= predicate["gte"]
    if "gte_ref" in predicate:
        return value >= _resolve(predicate["gte_ref"], ctx)
    raise ValueError(f"unknown predicate operator: {sorted(predicate)}")


def classify_finding(finding: dict, fail_on: str, spec: dict, options: dict) -> dict:
    """Classify one finding. Raises Unclassifiable for missing or conflicting facts."""
    facts = finding.get("evidence_facts") or {}
    unknown = sorted(set(facts) - set(spec["facts"]))
    if unknown:
        raise ValueError(f"unknown evidence facts {unknown}")  # the schema rejects these first
    missing = [name for name in spec["required_facts"] if name not in facts]
    if missing:
        raise Unclassifiable(spec["missing_fact_behavior"], ",".join(missing))

    rank = spec["severity_rank"]
    derived = {
        "severity_rank": rank[finding["severity"]],
        "severity_cap_rank": rank[spec["severity_cap_by_rule_precision"][facts["rule_precision"]]],
        "corroborating_tool_count": len(facts["corroborating_tools"]),
        "above_threshold": rank[finding["severity"]] >= rank[fail_on],
    }
    ctx = {
        "facts": facts,
        "finding": {"severity": finding["severity"], "category": finding["category"]},
        "options": options,
        "derived": derived,
    }
    for rule in spec["consistency_rules"]:
        if evaluate(rule["violated_when"], ctx, spec):
            raise Unclassifiable(spec["conflicting_fact_behavior"], rule["code"])

    score_spec = spec["score"]
    score = score_spec["base"]["delta"]
    codes = [score_spec["base"]["code"]]
    for rule in score_spec["rules"]:
        if evaluate(rule["when"], ctx, spec):
            score += rule["delta"]
            codes.append(rule["code"])
    ceiling = score_spec["ceiling"]
    if score > ceiling["max"]:
        codes.append(ceiling["code"])
    score = max(score_spec["floor"], min(ceiling["max"], score))
    band = next(b["band"] for b in score_spec["bands"] if score >= b["min"])

    independent = [s["name"] for s in spec["signals"]["independent"] if evaluate(s["when"], ctx, spec)]
    self_evident = [s["name"] for s in spec["signals"]["self_evident"] if evaluate(s["when"], ctx, spec)]
    derived.update(
        score=score,
        band=band,
        independent_signal_count=len(independent),
        signal_count=len(independent) + len(self_evident),
    )

    arms = spec["classification"]["at_or_above_threshold" if derived["above_threshold"] else "below_threshold"]
    first = next(arm for arm in arms if evaluate(arm["when"], ctx, spec))
    status, trace = first["status"], [first["code"]]
    for adjustment in spec["classification"]["adjustments"]:
        derived["status"] = status
        if evaluate(adjustment["when"], ctx, spec):
            status = adjustment["status"]
            trace.append(adjustment["code"])
    return {
        "score": score,
        "band": band,
        "score_codes": codes,
        "independent_signals": independent,
        "self_evident_signals": self_evident,
        "status": status,
        "rule_trace": trace,
    }


def _dedupe(codes):
    out = []
    for code in codes:
        if code not in out:
            out.append(code)
    return out


def coverage_codes(manifest: dict, required: list) -> list:
    analyzers = {a["analyzer_id"]: a for a in manifest["analyzers"]}
    observed = set(manifest["coverage"]["observed_analyzers"])
    codes = []
    for name in sorted(required):
        entry = analyzers.get(name)
        # The invariant: a required analyzer is satisfied ONLY by status
        # `completed` AND presence in observed_analyzers. Every other status —
        # not_applicable included, and any status a future contract adds — and
        # absence are gaps. Written as the one positive case so a new status
        # can never fall through as covered.
        if entry is not None and entry["status"] == "completed" and name in observed:
            continue
        if entry is not None and entry["status"] == "failed":
            codes.append("required_analyzer_failed")
            continue
        if entry is not None and entry["status"] == "skipped" and entry["reason_code"] == "diff_unchanged":
            codes.append("differential_scope_rejected")
        codes.append("required_coverage_missing")
    for gap in manifest["coverage"]["gaps"]:
        if gap["analyzer_id"] in required:
            codes += ["reported_coverage_gap", "required_coverage_missing"]
    for entry in manifest["analyzers"]:
        if entry["analyzer_id"] not in required and entry["status"] == "failed":
            codes.append("optional_analyzer_failed")
    return _dedupe(codes)


def decide_submission(document: dict, finding_spec: dict, release_spec: dict, binding_policy: dict) -> dict:
    """The authoritative decision for one submission under a binding policy snapshot."""
    manifest = document["manifest"]
    options = finding_spec["options"]["managed_ci_default"]
    counts = {"blocking": 0, "warning": 0, "informational": 0}
    unclassifiable = []
    findings = []
    for finding in manifest["findings"]:
        try:
            result = classify_finding(finding, binding_policy["fail_on_severity"], finding_spec, options)
        except Unclassifiable as exc:
            unclassifiable.append(exc.code)
            findings.append({"finding_id": finding["finding_id"], "unclassifiable": exc.code, "detail": exc.detail})
            continue
        counts[release_spec["finding_status_counts"][result["status"]]] += 1
        findings.append({"finding_id": finding["finding_id"], **result})

    coverage = coverage_codes(manifest, binding_policy["required_analyzers"])
    unclassifiable_codes = [c for c in release_spec["unclassifiable_findings"]["reason_codes_in_order"] if c in unclassifiable]
    if counts["blocking"] > 0:
        decision, lead = "BLOCK", "blocking_findings"
    elif coverage or unclassifiable_codes:
        decision, lead = "INCOMPLETE", None
    elif counts["warning"] > 0:
        decision, lead = "WARN", "non_blocking_findings"
    else:
        decision, lead = "PASS", "policy_passed"
    reason_codes = _dedupe(([lead] if lead else []) + coverage + unclassifiable_codes)
    return {
        "decision": decision,
        "fail_gate": decision in release_spec["fail_gate_decisions"],
        "coverage_state": "incomplete" if coverage else "complete",
        "backend_policy_version": release_spec["backend_policy_version"],
        "reason_codes": reason_codes,
        "counts": counts,
        "findings": findings,
    }
