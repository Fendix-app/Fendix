#!/usr/bin/env python3
"""Real-world noise baseline: findings per kLOC on pinned open-source applications.

For every target in targets.json this fetches the application at its pinned
commit into a temporary directory, runs

    fendix scan --code <dir> --format json --offline

and records how many findings the engine reports, per rule and per thousand lines
of source. New detection rules are held to a noise budget measured against the
clean applications (see README.md), so this has to be run before and after a rule
pack lands.

Usage:
    PATH=<dir with python3 + semgrep>:$PATH FENDIX_ENGINE=<python engine dir> \\
        python3 benchmarks/realworld-noise/run.py --fendix <binary> --out <dir>

Writes <dir>/noise.json:

    {name: {"kloc": float, "findings": int, "per_kloc": float, "by_rule": {rule_id: int}}}

A scan only counts when the analyzers in REQUIRED_SCANNERS (secrets, textscan, semgrep,
python-engine) report state "ok" in the report's metadata.scanner_status; with semgrep or
the Python engine missing, the engine still exits 0 with too few findings. A target that
cannot be fetched or scanned, or whose required analyzer did not run, is reported on
stderr and left out of noise.json; the run goes on with the other targets and exits 1 at
the end. Exit codes 0 and 1 from `fendix scan` are normal (1 means findings at or above
the fail threshold); anything else is a per-target error.

Set TMPDIR to choose where the clones go. They are deleted when the run ends
unless --keep-clones is given. Standard library only; Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent

# Files counted towards kLOC: the languages the engine has analyzers for.
SOURCE_EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go")
# Directories never counted, at any depth: dependencies, build output, VCS data.
SKIP_DIRS = frozenset({"node_modules", "vendor", "dist", "build", ".git", "target", ".next"})

REMOTE_BASE = "https://github.com/"

# `fendix scan` exits 1 when findings reach the fail threshold; both are a finished scan.
SCAN_OK_EXIT_CODES = (0, 1)
NO_RULE_ID = "(no rule_id)"

# A scan only counts as a measurement when these analyzers ran: if semgrep or the Python
# engine is missing or crashes, the scan still exits 0 with fewer findings and the noise
# would be under-measured. Every other analyzer is allowed to be skipped or unavailable:
# --offline disables the dependency scanners, and dast, spec, active-probes, plugins and
# the python-engine/* sub-checks do not apply to a source-only scan.
REQUIRED_SCANNERS = ("secrets", "textscan", "semgrep", "python-engine")

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA = re.compile(r"[0-9a-f]{40}")
_TARGET_KEYS = ("name", "repo", "sha", "language", "code_dir")


class TargetError(Exception):
    """One target could not be fetched, scanned or parsed. The run goes on without it."""


# ── pure parts ───────────────────────────────────────────────────────────────


def _count_lines(path: str) -> int:
    """Lines in a file, counting an unterminated last line. Bytes, so encoding never matters."""
    lines = 0
    last = b"\n"
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            lines += chunk.count(b"\n")
            last = chunk[-1:]
    if last != b"\n":
        lines += 1
    return lines


def count_kloc(root) -> float:
    """Thousands of lines in the source files under `root`.

    Symbolic links are neither followed nor counted, so a link cannot pull in
    files from outside the tree or loop. Unreadable files count as zero.
    """
    lines = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if os.path.splitext(filename)[1].lower() not in SOURCE_EXTENSIONS:
                continue
            path = os.path.join(dirpath, filename)
            if os.path.islink(path):
                continue
            try:
                lines += _count_lines(path)
            except OSError:
                continue
    return lines / 1000


def count_by_rule(findings: List[dict]) -> Dict[str, int]:
    """Findings per rule_id, most frequent first (ties alphabetical), so the output is stable."""
    counts: Dict[str, int] = {}
    for finding in findings:
        rule_id = finding.get("rule_id") or NO_RULE_ID
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def summarize(kloc: float, findings: List[dict]) -> dict:
    """The noise.json row for one target. Density is computed before anything is rounded."""
    per_kloc = len(findings) / kloc if kloc > 0 else 0.0
    return {
        "kloc": round(kloc, 3),
        "findings": len(findings),
        "per_kloc": round(per_kloc, 3),
        "by_rule": count_by_rule(findings),
    }


def parse_report(text: str) -> dict:
    """The JSON object of a `fendix scan --format json` report."""
    try:
        report = json.loads(text)
    except ValueError as exc:
        raise TargetError(f"scan output is not JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise TargetError("scan output is not a JSON object")
    return report


def report_findings(report: dict) -> List[dict]:
    """The findings array of a parsed report."""
    findings = report.get("findings")
    if findings is None:
        return []
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        raise TargetError("scan output has a malformed 'findings' field")
    return findings


def parse_findings(text: str) -> List[dict]:
    """The findings array of a `fendix scan --format json` report."""
    return report_findings(parse_report(text))


def check_scanner_health(report: dict) -> None:
    """Raise TargetError unless every analyzer in REQUIRED_SCANNERS reports state "ok".

    The engine records a crashed or missing analyzer in `metadata.scanner_status` and
    still exits 0, so the exit code cannot be trusted for this. Entries for any other
    analyzer are ignored, whatever their state. A report with no scanner_status at all
    is rejected: it cannot show that anything ran.
    """
    metadata = report.get("metadata")
    status = metadata.get("scanner_status") if isinstance(metadata, dict) else None
    if not isinstance(status, list) or not status or not all(isinstance(e, dict) for e in status):
        raise TargetError("scan output has no usable metadata.scanner_status, so it cannot show the analyzers ran")

    problems = []
    for name in REQUIRED_SCANNERS:
        entries = [e for e in status if e.get("name") == name]
        if not entries:
            problems.append(f"{name} is missing from scanner_status")
            continue
        for entry in entries:
            if entry.get("state") != "ok":
                detail = "".join(f" {key}={' '.join(str(entry[key]).split())}" for key in ("reason", "detail") if entry.get(key))
                problems.append(f"{name} state={entry.get('state')!r}{detail}")
    if problems:
        raise TargetError("required analyzer did not run: " + "; ".join(problems))


def load_targets(path) -> List[dict]:
    """Read and validate targets.json. Every target must be pinned to a full commit SHA."""
    try:
        targets = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read targets from {path}: {exc}") from exc
    if not isinstance(targets, list) or not targets:
        raise ValueError(f"{path}: expected a non-empty list of targets")

    seen_names, seen_repos = set(), set()
    for index, target in enumerate(targets):
        where = f"{path}: target #{index}"
        if not isinstance(target, dict) or set(target) != set(_TARGET_KEYS):
            raise ValueError(f"{where}: expected exactly the keys {', '.join(_TARGET_KEYS)}")
        for key in _TARGET_KEYS:
            if not isinstance(target[key], str) or not target[key]:
                raise ValueError(f"{where}: {key!r} must be a non-empty string")
        where = f"{path}: target {target['name']!r}"
        if not _NAME.fullmatch(target["name"]):
            raise ValueError(f"{where}: name must be letters, digits, '.', '_' or '-'")
        if not _REPO.fullmatch(target["repo"]):
            raise ValueError(f"{where}: repo must be 'owner/name' on github.com")
        if not _SHA.fullmatch(target["sha"]):
            raise ValueError(f"{where}: sha must be a full 40-character lowercase commit SHA, not a branch or tag")
        code_dir = target["code_dir"]
        if code_dir.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", code_dir):
            raise ValueError(f"{where}: code_dir must be a relative path inside the repository")
        if target["name"] in seen_names or target["repo"] in seen_repos:
            raise ValueError(f"{where}: duplicate name or repo")
        seen_names.add(target["name"])
        seen_repos.add(target["repo"])
    return targets


# ── subprocess plumbing ──────────────────────────────────────────────────────


def _tail(data: Optional[bytes], limit: int = 1500) -> str:
    text = (data or b"").decode("utf-8", errors="replace").strip()
    return text[-limit:]


def scan(fendix: str, code_dir, *, cwd, timeout: float) -> List[dict]:
    """Run `fendix scan` over `code_dir` and return its findings.

    Raises TargetError when the scan did not finish, or finished without its required
    analyzers (see check_scanner_health): such a scan would under-count findings.
    """
    argv = [fendix, "scan", "--code", str(code_dir), "--format", "json", "--offline"]
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise TargetError(f"fendix scan timed out after {timeout:g}s: {_tail(exc.stderr)}") from exc
    except OSError as exc:
        raise TargetError(f"cannot run {fendix}: {exc}") from exc
    if proc.returncode not in SCAN_OK_EXIT_CODES:
        raise TargetError(f"fendix scan exited {proc.returncode}: {_tail(proc.stderr)}")
    report = parse_report(proc.stdout.decode("utf-8", errors="replace"))
    check_scanner_health(report)
    return report_findings(report)


def fetch(target: dict, dest: Path, *, timeout: float = 900) -> None:
    """Fetch `target` at exactly its pinned commit into `dest`, which must not exist yet."""
    url = f"{REMOTE_BASE}{target['repo']}.git"
    sha = target["sha"]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")

    def git(*args: str) -> str:
        try:
            proc = subprocess.run(
                ["git", *args], cwd=str(dest), env=env, capture_output=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise TargetError(f"git {args[0]} timed out after {timeout:g}s") from exc
        except OSError as exc:
            raise TargetError(f"cannot run git: {exc}") from exc
        if proc.returncode != 0:
            raise TargetError(f"git {args[0]} exited {proc.returncode}: {_tail(proc.stderr)}")
        return proc.stdout.decode("utf-8", errors="replace").strip()

    dest.mkdir(parents=True)
    git("init", "-q")
    git("remote", "add", "origin", url)
    git("fetch", "-q", "--depth", "1", "origin", sha)
    git("-c", "advice.detachedHead=false", "checkout", "-q", "--detach", "FETCH_HEAD")
    head = git("rev-parse", "HEAD")
    if head != sha:
        raise TargetError(f"checked out {head}, expected the pinned {sha}")


# ── driver ───────────────────────────────────────────────────────────────────


def _measure(target: dict, fendix: str, work: Path, timeout: float) -> dict:
    dest = work / target["name"]
    fetch(target, dest)
    code_dir = dest / target["code_dir"]
    if not code_dir.is_dir():
        raise TargetError(f"code_dir {target['code_dir']!r} is not a directory in {target['repo']}@{target['sha']}")
    kloc = count_kloc(code_dir)
    started = time.monotonic()
    findings = scan(fendix, code_dir, cwd=work, timeout=timeout)
    row = summarize(kloc, findings)
    print(
        f"noise: {target['name']:<14} {row['kloc']:>9.3f} kLOC {row['findings']:>6} findings "
        f"{row['per_kloc']:>8.3f}/kLOC ({time.monotonic() - started:.0f}s scan)",
        file=sys.stderr,
    )
    return row


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure findings per kLOC on the pinned real-world applications in targets.json.",
    )
    parser.add_argument("--fendix", required=True, help="path to the fendix binary to measure")
    parser.add_argument("--out", required=True, help="directory to write noise.json into")
    parser.add_argument("--targets", default=str(HERE / "targets.json"), help="targets file (default: targets.json next to this script)")
    parser.add_argument("--only", help="comma-separated target names to run (default: all)")
    parser.add_argument("--timeout", type=float, default=3600, help="seconds allowed for one scan (default 3600)")
    parser.add_argument("--keep-clones", action="store_true", help="do not delete the clones when the run ends")
    args = parser.parse_args(argv)

    try:
        targets = load_targets(args.targets)
    except ValueError as exc:
        parser.error(str(exc))
    if args.only:
        wanted = [name.strip() for name in args.only.split(",") if name.strip()]
        unknown = sorted(set(wanted) - {t["name"] for t in targets})
        if unknown:
            parser.error(f"--only names no target: {', '.join(unknown)}")
        targets = [t for t in targets if t["name"] in wanted]

    # A relative path would stop resolving once the scan runs from the clone directory.
    found = shutil.which(args.fendix)
    fendix = os.path.abspath(found) if found else args.fendix

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="fendix-noise-"))
    results: Dict[str, dict] = {}
    errors: Dict[str, str] = {}
    try:
        for target in targets:
            try:
                results[target["name"]] = _measure(target, fendix, work, args.timeout)
            except TargetError as exc:
                errors[target["name"]] = str(exc)
                print(f"noise: {target['name']}: ERROR {exc}", file=sys.stderr)
    finally:
        if args.keep_clones:
            print(f"noise: clones kept in {work}", file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)

    (out / "noise.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if errors:
        print(
            f"noise: {len(errors)} of {len(targets)} targets failed ({', '.join(errors)}); "
            "noise.json has only the others",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
