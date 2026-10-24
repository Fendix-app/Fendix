#!/usr/bin/env python3
"""Framework parity benchmark: one labelled corpus, one engine, nine frameworks.

Runs `fendix scan --code` over each framework's corpus (see SPEC.md) and scores
every case at file level: a vulnerable case is detected when a finding of the
same class lands in its file, and a safe case is a false positive when one does.

Secrets never live in the corpus. Case files carry placeholder tokens that are
replaced with synthetic, format-valid values in a temporary copy, so the
repository never contains anything a secret scanner or push protection would
flag.

Usage:
    PATH=<dir with python3 + semgrep>:$PATH FENDIX_ENGINE=<python engine dir> \\
        python3 benchmarks/frameworks/run_parity.py --fendix <binary> --out <dir>

Gate mode (what `make parity` runs): add `--isolate --gate baseline.json` to fail
(exit 1) when any case is worse than the committed baseline, and
`--isolate --write-baseline baseline.json` to record the current run as the new
baseline. Both need --isolate, so the baseline and the gate always measure the
same thing.

Standard library only; Python 3.9+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

ROOT = Path(__file__).resolve().parent
FRAMEWORKS = ["django", "flask", "fastapi", "express", "nestjs", "nextjs", "spring", "nethttp", "gin"]
FAMILY = {
    "django": "python",
    "flask": "python",
    "fastapi": "python",
    "express": "js-ts",
    "nestjs": "js-ts",
    "nextjs": "js-ts",
    "spring": "java",
    "nethttp": "go",
    "gin": "go",
}
CORE_CLASSES = ["sqli", "cmdi", "xss", "ssrf", "path_traversal", "open_redirect", "hardcoded_secret"]
CLASSES = CORE_CLASSES + ["weak_password_hash", "jwt_no_verify", "weak_random_token", "ssti"]
CORE_VARIANTS = ["direct", "indirect", "safe", "safe_lookalike"]
VARIANTS = CORE_VARIANTS + ["cross_file", "alt_api"]
STATUS_RANK = {"BLOCK": 3, "WARN": 2, "INFO": 1}
MARKER = re.compile(r"EVAL-(SINK|SAFE)\b")

# Rule id (the part after the analyzer prefix) -> class, or a tuple of classes
# when one rule legitimately covers two (PY_XSS_HTML_SINK also flags
# render_template_string, which is template injection). Every rule id the
# engine emits that is not listed here is reported as "unmapped", so a missing
# mapping shows up in the results instead of silently counting as a miss.
RULE_CLASS = {
    # SQL injection
    "PY_SQL_INJECTION": "sqli",
    "JS_SQL_TEMPLATE": "sqli",
    "JAVA_SQL_INJECTION": "sqli",
    "GO_SQL_INJECTION": "sqli",
    "django-orm-raw-sql": "sqli",
    "python-sql-injection-string-format": "sqli",
    # Command injection
    "PY_OS_SYSTEM": "cmdi",
    "PY_OS_POPEN": "cmdi",
    "PY_SUBPROCESS_SHELL": "cmdi",
    "JS_CHILD_PROCESS_SHELL": "cmdi",
    "JAVA_EXEC_COMMAND_INJECTION": "cmdi",
    "GO_EXEC_COMMAND_INJECTION": "cmdi",
    "python-command-injection-shell-true": "cmdi",
    "python-subprocess-shell-true-with-variable": "cmdi",
    # XSS
    "PY_XSS_HTML_SINK": ("xss", "ssti"),
    "JS_INNER_HTML": "xss",
    "JS_INNER_HTML_USER_INPUT": "xss",
    "JS_DOCUMENT_WRITE": "xss",
    "JAVA_XSS_REFLECTED": "xss",
    # Server-side template injection (CWE-94)
    "flask-render-template-string-injection": "ssti",
    # SSRF
    "PY_SSRF": "ssrf",
    "JAVA_SSRF": "ssrf",
    # Path traversal
    "PY_PATH_TRAVERSAL": "path_traversal",
    "JAVA_PATH_TRAVERSAL": "path_traversal",
    # Open redirect
    "PY_OPEN_REDIRECT": "open_redirect",
    # Hard-coded secrets (language-specific rules; secrets/* is handled below)
    "JS_HARDCODED_AWS_KEY": "hardcoded_secret",
    "GO_HARDCODED_AWS_KEY": "hardcoded_secret",
    "python-aws-access-key-id-literal": "hardcoded_secret",
    "python-hardcoded-secret-assignment": "hardcoded_secret",
    "python-pem-private-key-literal": "hardcoded_secret",
    "python-gcp-service-account-inline": "hardcoded_secret",
    "python-slack-webhook-url-literal": "hardcoded_secret",
    "python-hardcoded-db-url": "hardcoded_secret",
    # Weak password hashing
    "PY_WEAK_CRYPTO_PASSWORD": "weak_password_hash",
    "GO_WEAK_HASH_PASSWORD": "weak_password_hash",
    "JAVA_WEAK_CRYPTO": "weak_password_hash",
    "python-md5-used-for-password": "weak_password_hash",
    "python-sha1-used-for-password": "weak_password_hash",
    # JWT accepted without signature verification
    "PY_JWT_WEAK": "jwt_no_verify",
    "python-jwt-decode-no-verification": "jwt_no_verify",
    # Non-cryptographic RNG for tokens
    "JAVA_WEAK_RANDOM": "weak_random_token",
    "python-random-for-token-generation": "weak_random_token",
}


# Fallback for findings the engine emits without a rule_id (v3.6.3: the Python
# engine's JavaScript pattern checks). Keyed on the title, checked in order.
TITLE_CLASS = [
    (re.compile(r"\bSQL\b", re.I), "sqli"),
    (re.compile(r"command injection|child_process|os\.system|shell", re.I), "cmdi"),
    (re.compile(r"XSS|cross-site scripting|innerHTML|document\.write", re.I), "xss"),
    (re.compile(r"SSRF|server-side request", re.I), "ssrf"),
    (re.compile(r"path traversal|directory traversal", re.I), "path_traversal"),
    (re.compile(r"open redirect", re.I), "open_redirect"),
    (re.compile(r"template injection|SSTI", re.I), "ssti"),
    (re.compile(r"\bJWT\b", re.I), "jwt_no_verify"),
    (re.compile(r"MD5|SHA-?1|weak hash", re.I), "weak_password_hash"),
    (re.compile(r"secret|credential|access key|api key|token", re.I), "hardcoded_secret"),
]


def rule_classes(rule_id: str, title: str = "") -> frozenset:
    """The classes a finding counts for; empty when it maps to none."""
    if rule_id.startswith("secrets/"):
        return frozenset({"hardcoded_secret"})
    if rule_id:
        mapped = RULE_CLASS.get(rule_id.rsplit("/", 1)[-1])
        if mapped is None:
            return frozenset()
        return frozenset({mapped} if isinstance(mapped, str) else mapped)
    for pattern, klass in TITLE_CLASS:
        if pattern.search(title or ""):
            return frozenset({klass})
    return frozenset()


def _derive(seed: str, alphabet: str, length: int) -> str:
    out, counter = [], 0
    while len(out) < length:
        digest = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return "".join(out[:length])


def synthetic_secrets(framework: str) -> Dict[str, str]:
    """Deterministic, format-valid, never-real credentials for one framework."""
    upper32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b64ish = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    seed = f"fendix-framework-parity:{framework}"
    return {
        "__EVAL_AWS_ACCESS_KEY_ID__": "AKIA" + _derive(seed + ":aws-id", upper32, 16),
        "__EVAL_AWS_SECRET_ACCESS_KEY__": _derive(seed + ":aws-secret", b64ish, 40),
        "__EVAL_GITHUB_TOKEN__": "ghp_" + _derive(seed + ":gh", alnum, 36),
        "__EVAL_DB_PASSWORD__": _derive(seed + ":db", alnum, 24),
    }


def materialize(framework: str, dest: Path) -> None:
    shutil.copytree(ROOT / framework, dest)
    secrets = synthetic_secrets(framework)
    for path in dest.rglob("*"):
        if not path.is_file() or path.name == "manifest.json":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "__EVAL_" in text:
            for token, value in secrets.items():
                text = text.replace(token, value)
            path.write_text(text, encoding="utf-8")


def marker_line(path: Path) -> Optional[int]:
    if not path.exists():  # an isolated tree holds only one case's files
        return None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if MARKER.search(line):
            return number
    return None


def occurrences(finding: dict) -> List[tuple]:
    """(relative path, line) for every occurrence of a code finding."""
    endpoints = [o.get("endpoint", "") for o in finding.get("occurrences") or []] or [finding.get("endpoint", "")]
    result = []
    for endpoint in endpoints:
        if not endpoint or endpoint.startswith("/") or "://" in endpoint or " /" in endpoint:
            continue
        path, _, line = endpoint.rpartition(":")
        if path and line.isdigit():
            result.append((path.replace("\\", "/"), int(line)))
        else:
            result.append((endpoint.replace("\\", "/"), None))
    return result


def scan(fendix: str, code_dir: Path, fail_on: str) -> tuple:
    """Run one scan; return (report, wall-clock seconds)."""
    cmd = [fendix, "scan", "--code", str(code_dir), "--format", "json", "--offline", "--fail-on", fail_on]
    started = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(code_dir.parent))
    elapsed = time.perf_counter() - started
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"fendix exited {proc.returncode} on {code_dir}:\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout), elapsed


def source_size(root: Path) -> dict:
    files = lines = 0
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go"}:
            files += 1
            lines += sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
    return {"files": files, "lines": lines}


def timing(fendix: str, framework: str, tmp: Path, fail_on: str, repeats: int, scale: int) -> dict:
    """Median wall time for the corpus as-is and for `scale` copies of it.

    The 1x corpus is ~30 small files, so its time is mostly fixed startup cost
    (Python engine and Semgrep start-up). The scaled run shows throughput.
    """
    result = {}
    for label, copies in (("1x", 1), (f"{scale}x", scale)):
        root = tmp / f"{framework}-time-{label}"
        for k in range(copies):
            materialize(framework, root / f"copy{k:02d}")
        samples = [scan(fendix, root, fail_on)[1] for _ in range(repeats)]
        size = source_size(root)
        median = statistics.median(samples)
        result[label] = {
            **size,
            "seconds_median": round(median, 2),
            "seconds_samples": [round(s, 2) for s in samples],
            "kloc_per_second": round(size["lines"] / 1000 / median, 2) if median else None,
        }
        shutil.rmtree(root)
    return result


def materialize_isolated(framework: str, case: dict, manifest: dict, dest: Path) -> None:
    """One case alone: the framework tree with every OTHER case's files removed.

    The engine groups findings by title across files (engine.Deduplicate), so
    in a full-corpus scan a case inherits the BLOCK/WARN status of whichever
    occurrence the group's representative came from. Scanning a case alone
    gives the status the engine assigns to that case's own evidence. Support
    files (routing tables, app bootstrap) stay, so route binding still works.
    """
    materialize(framework, dest)
    keep = {case["file"], case.get("entry_file")}
    for other in manifest["cases"]:
        if other["id"] == case["id"]:
            continue
        for rel in (other["file"], other.get("entry_file")):
            if rel and rel not in keep:
                target = dest / rel
                if target.exists():
                    target.unlink()


def score_framework(framework: str, report: dict, scan_root: Path) -> dict:
    manifest = json.loads((ROOT / framework / "manifest.json").read_text())
    # A cross_file case owns two files: the sink file and its handler. A finding
    # in either one counts for that case (the sink file carries the marker).
    case_of_file: Dict[str, str] = {}
    for case in manifest["cases"]:
        case_of_file[case["file"]] = case["id"]
        if case.get("entry_file"):
            case_of_file[case["entry_file"]] = case["id"]
    by_case: Dict[str, List[dict]] = defaultdict(list)
    unmapped: Counter = Counter()
    without_rule_id: Counter = Counter()
    support_findings: List[dict] = []

    for finding in report.get("findings", []):
        rule_id = finding.get("rule_id") or ""
        title = finding.get("title") or ""
        classes = rule_classes(rule_id, title)
        if not rule_id:
            without_rule_id[title] += 1
        if not classes:
            unmapped[rule_id or f"(no rule_id) {title}"] += 1
        for path, line in occurrences(finding):
            record = {
                "rule_id": rule_id or f"(no rule_id) {title}",
                "classes": sorted(classes),
                "file": path,
                "status": finding.get("status"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "source_tier": finding.get("source_tier"),
                "line": line,
            }
            if path in case_of_file:
                by_case[case_of_file[path]].append(record)
            else:
                support_findings.append(record)

    cases = []
    for case in manifest["cases"]:
        hits = by_case.get(case["id"], [])
        same = [h for h in hits if case["class"] in h["classes"]]
        other = [h for h in hits if case["class"] not in h["classes"]]
        sink = marker_line(scan_root / case["file"])
        best = max(same, key=lambda h: STATUS_RANK.get(h["status"], 0), default=None)
        flagged = bool(same)
        cases.append(
            {
                **case,
                "core": case["class"] in CORE_CLASSES and case["variant"] in CORE_VARIANTS,
                "outcome": ("TP" if flagged else "FN") if case["vulnerable"] else ("FP" if flagged else "TN"),
                "blocks": bool(best and best["status"] == "BLOCK"),
                "best_status": best["status"] if best else None,
                "rules": sorted({h["rule_id"] for h in same}),
                "line_delta": min(
                    (abs(h["line"] - sink) for h in same if h["line"] and sink and h["file"] == case["file"]),
                    default=None,
                ),
                "hit_in_entry_file": any(h["file"] == case.get("entry_file") for h in same),
                "off_target_rules": sorted({h["rule_id"] for h in other}),
            }
        )

    status = (report.get("metadata") or {}).get("scanner_status") or report.get("scanner_status") or []
    return {
        "framework": framework,
        "family": FAMILY[framework],
        "cases": cases,
        "scanner_status": {s["name"]: s["state"] for s in status},
        "unmapped_rules": dict(unmapped),
        "findings_without_rule_id": dict(without_rule_id),
        "support_file_findings": support_findings,
        "engine_version": (report.get("metadata") or {}).get("engine_version") or report.get("engine_version"),
    }


def metrics(cases: List[dict]) -> dict:
    count = Counter(c["outcome"] for c in cases)
    tp, fn, fp, tn = count["TP"], count["FN"], count["FP"], count["TN"]
    blocked = sum(1 for c in cases if c["vulnerable"] and c["blocks"])
    blocked_fp = sum(1 for c in cases if not c["vulnerable"] and c["blocks"])
    vulnerable = tp + fn

    def ratio(a, b):
        return round(a / b, 3) if b else None

    return {
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "TN": tn,
        "recall": ratio(tp, vulnerable),
        "precision": ratio(tp, tp + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "block_recall": ratio(blocked, vulnerable),
        "safe_cases_blocked": blocked_fp,
    }


# ── Regression gate ──────────────────────────────────────────────────────────

# (outcome, blocks) per case id: the part of a case's result the gate pins.
CaseState = Tuple[str, bool]

# The only outcome changes that count as getting better. Any other change in a
# case's outcome (TP->FN, TN->FP, or a label flip such as TP->TN) is a
# regression, so a manifest edit forces a deliberate --write-baseline.
IMPROVEMENTS = {("FN", "TP"), ("FP", "TN")}
SAFE_OUTCOMES = {"TN", "FP"}


class GateResult(NamedTuple):
    regressions: List[str]
    improvements: List[str]


def compare_to_baseline(current: Dict[str, CaseState], baseline: Dict[str, CaseState]) -> GateResult:
    """Compare a run with the baseline, case by case.

    Regressions (the gate fails): a detected case is missed, a safe case is
    flagged, a vulnerable case no longer blocks, a safe case newly blocks, a
    baseline case is absent from the run, or a run case is absent from the
    baseline. Improvements are reported but never fail the gate.
    """
    regressions: List[str] = []
    improvements: List[str] = []
    for case_id in sorted(baseline):
        if case_id not in current:
            regressions.append(f"{case_id}: missing from run")
            continue
        was, was_blocks = baseline[case_id]
        now, now_blocks = current[case_id]
        if was != now:
            (improvements if (was, now) in IMPROVEMENTS else regressions).append(f"{case_id}: {was}->{now}")
        if now in SAFE_OUTCOMES:
            if now_blocks and not was_blocks:
                regressions.append(f"{case_id}: safe case now blocks")
            elif was_blocks and not now_blocks and was == now:
                improvements.append(f"{case_id}: safe case no longer blocks")
        elif was == now:  # a vulnerable case whose outcome is unchanged
            if was_blocks and not now_blocks:
                regressions.append(f"{case_id}: no longer blocks")
            elif now_blocks and not was_blocks:
                improvements.append(f"{case_id}: now blocks")
    regressions.extend(f"{case_id}: not in baseline" for case_id in sorted(set(current) - set(baseline)))
    return GateResult(regressions, improvements)


def load_baseline(path) -> Dict[str, CaseState]:
    """Read a baseline file into the {case id: (outcome, blocks)} form the gate compares."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return {case_id: (c["outcome"], bool(c["blocks"])) for case_id, c in document["cases"].items()}


def write_baseline(path, engine: str, current: Dict[str, CaseState]) -> None:
    """Record a run as the baseline. Sorted keys and a final newline keep diffs minimal."""
    document = {
        "engine": engine,
        "cases": {case_id: {"outcome": outcome, "blocks": blocks} for case_id, (outcome, blocks) in sorted(current.items())},
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fendix", required=True, help="path to the fendix binary under test")
    parser.add_argument("--out", required=True, help="directory for results.json")
    parser.add_argument("--fail-on", default="HIGH")
    parser.add_argument("--frameworks", default=",".join(FRAMEWORKS))
    parser.add_argument("--repeats", type=int, default=3, help="timed runs per size (median is reported)")
    parser.add_argument("--scale", type=int, default=20, help="copies of the corpus for the throughput run")
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument(
        "--isolate",
        action="store_true",
        help="scan every case in its own tree so its status is not inherited from a grouped sibling (slow: one scan per case)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--gate",
        metavar="BASELINE",
        help="compare the run with this baseline file; exit 1 on any regression (requires --isolate)",
    )
    mode.add_argument(
        "--write-baseline",
        metavar="BASELINE",
        help="record this run as the baseline file (requires --isolate and every framework)",
    )
    args = parser.parse_args()
    frameworks = [f for f in args.frameworks.split(",") if f]
    if (args.gate or args.write_baseline) and not args.isolate:
        parser.error("--gate and --write-baseline need --isolate: the baseline pins per-case blocks")
    if args.write_baseline and sorted(frameworks) != sorted(FRAMEWORKS):
        parser.error("--write-baseline records every framework; drop --frameworks")
    unknown = [f for f in frameworks if f not in FRAMEWORKS]
    if unknown:
        parser.error(f"unknown framework(s): {', '.join(unknown)}")

    version = subprocess.run([args.fendix, "version"], capture_output=True, text=True).stdout.strip()
    semgrep = shutil.which("semgrep")
    semgrep_version = (
        subprocess.run([semgrep, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
        if semgrep
        else None
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="fendix-parity-") as tmp:
        for framework in frameworks:
            scan_root = Path(tmp) / framework
            materialize(framework, scan_root)
            report, _ = scan(args.fendix, scan_root, args.fail_on)
            results.append(score_framework(framework, report, scan_root))
            if args.isolate:
                manifest = json.loads((ROOT / framework / "manifest.json").read_text())
                isolated = {}
                for case in manifest["cases"]:
                    case_root = Path(tmp) / f"{framework}-iso" / case["id"]
                    materialize_isolated(framework, case, manifest, case_root)
                    case_report, _ = scan(args.fendix, case_root, args.fail_on)
                    scored = score_framework(framework, case_report, case_root)
                    isolated[case["id"]] = next(c for c in scored["cases"] if c["id"] == case["id"])
                    shutil.rmtree(case_root)
                for c in results[-1]["cases"]:
                    iso = isolated[c["id"]]
                    c["grouped"] = {"outcome": c["outcome"], "blocks": c["blocks"], "best_status": c["best_status"]}
                    c["outcome"], c["blocks"], c["best_status"] = iso["outcome"], iso["blocks"], iso["best_status"]
                    c["rules"], c["line_delta"] = iso["rules"], iso["line_delta"]
            if not args.no_timing:
                results[-1]["timing"] = timing(args.fendix, framework, Path(tmp), args.fail_on, args.repeats, args.scale)
            m = metrics(results[-1]["cases"])
            print(f"{framework:9} recall={m['recall']} fpr={m['false_positive_rate']} blocks={m['block_recall']}", file=sys.stderr)

    all_cases = [c for r in results for c in r["cases"]]
    summary = {
        "by_framework": {r["framework"]: metrics(r["cases"]) for r in results},
        # The original 28 cases per framework, comparable with v1 results.
        "by_framework_core": {r["framework"]: metrics([c for c in r["cases"] if c["core"]]) for r in results},
        "by_family_core": {
            family: metrics([c for r in results if r["family"] == family for c in r["cases"] if c["core"]])
            for family in sorted({r["family"] for r in results})
        },
        "by_family": {
            family: metrics([c for r in results if r["family"] == family for c in r["cases"]])
            for family in sorted({r["family"] for r in results})
        },
        "by_family_class": {
            f"{family}/{klass}": metrics(
                [c for r in results if r["family"] == family for c in r["cases"] if c["class"] == klass]
            )
            for family in sorted({r["family"] for r in results})
            for klass in CLASSES
        },
        "by_variant_family": {
            f"{family}/{variant}": metrics(
                [c for r in results if r["family"] == family for c in r["cases"] if c["variant"] == variant]
            )
            for family in sorted({r["family"] for r in results})
            for variant in VARIANTS
        },
        "overall": metrics(all_cases),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(
        json.dumps(
            {
                "engine": version,
                "semgrep": semgrep_version,
                "fail_on": args.fail_on,
                "python": sys.version.split()[0],
                "summary": summary,
                "frameworks": results,
            },
            indent=2,
        )
    )
    print(json.dumps(summary["by_family"], indent=2))

    current = {c["id"]: (c["outcome"], c["blocks"]) for c in all_cases}
    if args.write_baseline:
        write_baseline(args.write_baseline, version, current)
        print(f"wrote baseline for {len(current)} cases to {args.write_baseline}")
    if args.gate:
        baseline = load_baseline(args.gate)
        # With --frameworks, gate only the frameworks that ran. Case ids start
        # with the framework name (SPEC.md), so the rest of the baseline is
        # out of scope rather than "missing from run".
        baseline = {k: v for k, v in baseline.items() if any(k.startswith(f"{f}-") for f in frameworks)}
        gate = compare_to_baseline(current, baseline)
        for line in gate.improvements:
            print(f"improved: {line}")
        for line in gate.regressions:
            print(f"REGRESSION: {line}")
        if gate.improvements:
            print(f"Re-run with --write-baseline {args.gate} and commit it, so the new expectations show in the diff.")
        verdict = "GATE FAILED" if gate.regressions else "GATE OK"
        print(f"{verdict}: {len(gate.regressions)} regressions, {len(gate.improvements)} improvements ({len(baseline)} cases)")
        return 1 if gate.regressions else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
