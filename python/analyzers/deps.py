"""Dependency CVE checker — scans project dependencies for known vulnerabilities.

Three primary paths, one offline fallback:

  - PyPI (requirements.txt):  pip-audit primary; local hardcoded list as fallback
  - npm (package.json):       npm audit primary;  local hardcoded list as fallback
  - Go (go.mod):              govulncheck primary; no fallback (no curated Go list)

Each primary tool runs only when its binary is on $PATH. When a primary tool
runs but fails (subprocess error, malformed JSON, non-success exit code), the
analyzer falls back to the curated list rather than swallowing the error and
emitting zero findings — that was a real bug pre-TASK-090.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, NamedTuple

# Manifest size cap (F-L10). Mirrors ast_analyzer.py's `_MAX_FILE_BYTES`
# pattern: refuse to read_text() a requirements.txt / package.json that an
# untrusted repo has inflated to gigabytes, which would OOM the engine. A real
# manifest is a few KB; even huge monorepos stay well under 4 MB.
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024  # 4 MB


# Advisory-id priority for _canonical_advisory_id, highest first. Anything
# not listed lands in an implicit "other" tier.
_CANONICAL_ID_TIERS = ("CVE-", "GHSA-", "PYSEC-")


def _canonical_advisory_id(ids: list[str]) -> str:
    """Pick the id a dependency finding is published under.

    This MIRRORS the Go pip scanner's ``canonicalID`` (FIX-05) exactly, and
    it has to. ``engine.Deduplicate`` collapses the Go/Python overlap only
    because the two engines' finding TITLES are byte-identical — its dedup
    key is ``Severity|Category|Title``. If only the Go side canonicalised,
    every dependency vulnerability would be reported TWICE under
    ``--python-engine``.

    Priority is CVE > GHSA > PYSEC > everything else, lexicographically
    smallest within a tier so the choice is a pure function of the id SET
    rather than of iteration order. Prefix matching is exact-with-hyphen,
    so a real OSV prefix like ``BIT-`` lands in "other" instead of being
    promoted past the PYSEC id that should win.

    Deliberately NOT applied to the govulncheck path: vuln.go.dev emits one
    ``GO-*`` record per vulnerability with aliases pointing outward, so the
    duplicate-record problem does not arise there, and the ``GO-*`` id shape
    is locked by a cross-language parity test.
    """
    best = ""
    best_tier = len(_CANONICAL_ID_TIERS)
    for cid in ids:
        if not cid:
            continue
        tier = len(_CANONICAL_ID_TIERS)
        for i, prefix in enumerate(_CANONICAL_ID_TIERS):
            if cid.startswith(prefix):
                tier = i
                break
        if not best or tier < best_tier or (tier == best_tier and cid < best):
            best, best_tier = cid, tier
    return best


def _read_capped(path: Path) -> str | None:
    """Read ``path`` as UTF-8 text, or return None if it's too large to trust.

    F-L10: stat the file first and skip (logging to stderr) anything over
    ``_MAX_MANIFEST_BYTES`` so a hostile oversized manifest can't be slurped
    whole into memory. OSError (unreadable/missing) also returns None — the
    caller treats both as "no manifest to scan".
    """
    try:
        if not path.is_file():
            # A named pipe or a device (once links are followed) would block the
            # read for a writer that never comes (round 5, redteam5-11).
            print(
                f"[fendix-engine] deps: skipping {path.name} — not a regular file",
                file=sys.stderr,
            )
            return None
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            print(
                f"[fendix-engine] deps: skipping {path.name} — exceeds "
                f"{_MAX_MANIFEST_BYTES}-byte manifest cap",
                file=sys.stderr,
            )
            return None
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"[fendix-engine] deps: could not read {path.name}: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Local known-vulnerable package list (fallback when pip-audit is absent)
# Each entry: (package_name, max_safe_version_exclusive, cve_id, severity, description)
# Version comparison: finding emitted if installed_version < max_safe_version
# ---------------------------------------------------------------------------


class _KnownVuln(NamedTuple):
    package: str  # canonical PyPI name (lowercase)
    safe_from: str  # first SAFE version (>=), e.g. "2.20.0"
    cve: str
    severity: str
    title: str
    fix: str


_KNOWN_PYPI_VULNS: list[_KnownVuln] = [
    _KnownVuln(
        "pyyaml",
        "5.1",
        "CVE-2017-18342",
        "CRITICAL",
        "PyYAML yaml.load() arbitrary code execution",
        "Upgrade pyyaml >= 5.1 and replace yaml.load() with yaml.safe_load().",
    ),
    _KnownVuln(
        "pyyaml",
        "5.4",
        "CVE-2020-14343",
        "CRITICAL",
        "PyYAML arbitrary code execution via yaml.load() with full Loader",
        "Upgrade pyyaml >= 5.4 and replace yaml.load() with yaml.safe_load().",
    ),
    _KnownVuln(
        "requests",
        "2.20.0",
        "CVE-2018-18074",
        "HIGH",
        "requests HTTP redirect leaks credentials via Referer header",
        "Upgrade requests >= 2.20.0.",
    ),
    _KnownVuln(
        "requests",
        "2.31.0",
        "CVE-2023-32681",
        "HIGH",
        "requests Proxy-Authorization header leak on redirect",
        "Upgrade requests >= 2.31.0.",
    ),
    _KnownVuln(
        "lxml",
        "4.6.3",
        "CVE-2021-28957",
        "MEDIUM",
        "lxml XSS via HTML cleanup",
        "Upgrade lxml >= 4.6.3.",
    ),
    _KnownVuln(
        "urllib3",
        "1.26.5",
        "CVE-2021-33503",
        "HIGH",
        "urllib3 ReDoS via malformed percent-encoded characters",
        "Upgrade urllib3 >= 1.26.5.",
    ),
    _KnownVuln(
        "pillow",
        "9.0.1",
        "CVE-2022-22817",
        "CRITICAL",
        "Pillow arbitrary code execution via PIL.ImageMath.eval",
        "Upgrade Pillow >= 9.0.1.",
    ),
    _KnownVuln(
        "cryptography",
        "41.0.0",
        "CVE-2023-23931",
        "HIGH",
        "cryptography NULL pointer dereference in PKCS12 parsing",
        "Upgrade cryptography >= 41.0.0.",
    ),
    _KnownVuln(
        "django",
        "3.2.19",
        "CVE-2023-31047",
        "HIGH",
        "Django potential bypass of file upload validators",
        "Upgrade Django >= 3.2.19, 4.1.9, or 4.2.1.",
    ),
    _KnownVuln(
        "flask",
        "2.3.2",
        "CVE-2023-30861",
        "HIGH",
        "Flask session cookie leak via cookie policy regression",
        "Upgrade Flask >= 2.3.2.",
    ),
    _KnownVuln(
        "jinja2",
        "3.1.3",
        "CVE-2024-22195",
        "MEDIUM",
        "Jinja2 HTML attribute injection via xmlattr filter",
        "Upgrade Jinja2 >= 3.1.3.",
    ),
    _KnownVuln(
        "werkzeug",
        "3.0.3",
        "CVE-2024-34069",
        "HIGH",
        "Werkzeug debugger PIN brute-force when network accessible",
        "Upgrade Werkzeug >= 3.0.3 and disable the debugger in production.",
    ),
    _KnownVuln(
        "paramiko",
        "3.4.0",
        "CVE-2023-48795",
        "MEDIUM",
        "Paramiko Terrapin SSH prefix truncation attack",
        "Upgrade paramiko >= 3.4.0.",
    ),
]

_KNOWN_NPM_VULNS: list[_KnownVuln] = [
    _KnownVuln(
        "lodash",
        "4.17.21",
        "CVE-2021-23337",
        "HIGH",
        "lodash command injection via template function",
        "Upgrade lodash >= 4.17.21.",
    ),
    _KnownVuln(
        "axios",
        "0.21.1",
        "CVE-2020-28168",
        "MEDIUM",
        "axios SSRF via server-side redirects",
        "Upgrade axios >= 0.21.1.",
    ),
    _KnownVuln(
        "minimist",
        "1.2.6",
        "CVE-2021-44906",
        "CRITICAL",
        "minimist prototype pollution",
        "Upgrade minimist >= 1.2.6.",
    ),
    _KnownVuln(
        "node-forge",
        "1.3.0",
        "CVE-2022-0122",
        "MEDIUM",
        "node-forge URL parsing open redirect",
        "Upgrade node-forge >= 1.3.0.",
    ),
]


# ---------------------------------------------------------------------------
# Version parsing / comparison
# ---------------------------------------------------------------------------


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints for comparison.

    Retained for callers/tests that want the raw numeric tuple; the actual
    vulnerability comparison now goes through packaging.version (see
    `_is_vulnerable`) which understands pre-releases, epochs, and PEP 440
    ordering (audit #34/#35). This helper still strips common spec prefixes.
    """
    v = v.strip().lstrip("v=^~")
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        if m:
            result.append(int(m.group(1)))
        else:
            break
    return tuple(result) if result else (0,)


def _is_vulnerable(installed: str, safe_from: str) -> bool:
    """Return True if installed version < safe_from (PEP 440 ordering).

    Audit #34/#35: uses packaging.version so `9.0.1rc1 < 9.0.1` is True
    (pre-release) and `1!2.0` epoch ordering is honored. Falls back to the
    numeric-tuple compare only if both versions are unparseable by PEP 440.
    """
    try:
        from packaging.version import InvalidVersion, Version

        try:
            return Version(installed) < Version(safe_from)
        except InvalidVersion:
            pass
    except Exception:  # noqa: BLE001 — packaging always present, defensive
        pass
    try:
        return _parse_version(installed) < _parse_version(safe_from)
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Requirements.txt parser
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    # name, optional extras `[a,b]` (audit #20), optional version spec.
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([><=!~^]{1,3}\s*[\d.]+.*?)?\s*(?:#.*)?$"
)


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version_spec) from requirements.txt content."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            pkg = m.group(1).lower().replace("_", "-")
            spec = (m.group(2) or "").strip()
            results.append((pkg, spec))
    return results


def _extract_pinned_version(spec: str) -> str | None:
    """If spec is an exact pin (==X.Y.Z or PEP 440 ===X), return the version.

    Audit #33: `===` is an exact (arbitrary-equality) pin and must be treated
    like `==`, not downgraded to an unpinned advisory.
    """
    m = re.match(r"^={2,3}\s*([\w.\-+!]+)", spec.strip())
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# package.json parser
# ---------------------------------------------------------------------------


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version_spec) from package.json content."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    results = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        for pkg, ver in deps.items():
            results.append((pkg.lower(), str(ver)))
    return results


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------


class DepsAnalyzer:
    """Checks project dependencies for known CVEs.

    Strategy:
      1. Find requirements.txt / package.json / go.mod under code_path.
      2. For each manifest, try the corresponding primary tool first
         (pip-audit / npm audit / govulncheck).
      3. If the primary tool is missing OR fails at runtime, fall back to
         the local hardcoded known-vuln list (PyPI + npm only — Go has no
         curated fallback).
    """

    def __init__(self, code_path: str) -> None:
        """Initialize with the project root directory."""
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Scan for vulnerable dependencies and emit findings."""
        root = Path(self.code_path)
        if not root.exists():
            return

        req_file = root / "requirements.txt"
        pkg_file = root / "package.json"
        go_mod = root / "go.mod"

        if req_file.exists():
            self._check_requirements(req_file, emit_fn)

        if pkg_file.exists():
            self._check_npm(pkg_file, emit_fn)

        if go_mod.exists():
            self._check_go_modules(go_mod, emit_fn)

    # ------------------------------------------------------------------
    # PyPI checks
    # ------------------------------------------------------------------

    def _check_requirements(
        self, req_file: Path, emit_fn: Callable[[dict], None]
    ) -> None:
        """Run pip-audit if installed; fall back to the curated local list.

        Fallback fires when pip-audit is absent OR fails (timeout, non-success
        exit, malformed JSON). Pre-TASK-090 a tool failure was swallowed and
        no findings were emitted — that masked a regex-key bug for months
        because no exception ever surfaced to the user.
        """
        text = _read_capped(req_file)
        if text is None:  # F-L10: oversized/unreadable manifest — skip
            return
        packages = _parse_requirements(text)

        if shutil.which("pip-audit"):
            if self._run_pip_audit(req_file, emit_fn):
                return  # primary path succeeded — don't double-emit
            # pip-audit failed; fall through to local list
        self._local_pypi_check(packages, req_file, emit_fn)

    def _run_pip_audit(self, req_file: Path, emit_fn: Callable[[dict], None]) -> bool:
        """Run pip-audit and emit findings. Return True iff the run was clean.

        pip-audit exits 0 (no vulns) or 1 (vulns found) on success; any other
        exit code is a tool error. Both 0 and 1 count as a successful run, so
        a clean scan with zero findings doesn't trigger the local fallback.
        """
        try:
            proc = subprocess.run(
                ["pip-audit", "-r", str(req_file), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(
                f"[fendix-engine] pip-audit failed, falling back to local list: {exc}",
                file=sys.stderr,
            )
            return False

        if proc.returncode not in (0, 1):
            stderr_excerpt = (proc.stderr or "").strip().splitlines()[:3]
            print(
                "[fendix-engine] pip-audit exited "
                f"{proc.returncode}, falling back to local list. "
                f"stderr: {' | '.join(stderr_excerpt)[:200]}",
                file=sys.stderr,
            )
            return False

        # pip-audit exits 1 BOTH on "vulns found" (success) AND on internal
        # errors (e.g. can't install a package to read its metadata under a
        # newer Python). In the failure case stdout is empty; the previous
        # path parsed `{}`, found zero entries, returned True, and the local
        # fallback never fired — silent zero-finding scan.
        if proc.returncode == 1 and not (proc.stdout or "").strip():
            stderr_excerpt = (proc.stderr or "").strip().splitlines()[:3]
            print(
                "[fendix-engine] pip-audit exited 1 with empty stdout — "
                "treating as failure, falling back to local list. "
                f"stderr: {' | '.join(stderr_excerpt)[:200]}",
                file=sys.stderr,
            )
            return False

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            print(
                f"[fendix-engine] pip-audit produced invalid JSON, "
                f"falling back to local list: {exc}",
                file=sys.stderr,
            )
            return False

        # Modern pip-audit (>=2.x) emits "dependencies"; older builds used
        # "vulnerabilities". Accept both — that mismatch was the silent bug
        # this rewrite fixes.
        entries = data.get("dependencies") or data.get("vulnerabilities") or []
        for entry in entries:
            pkg = entry.get("name", "unknown")
            ver = entry.get("version", "?")
            for v in entry.get("vulns", []) or []:
                vid = v.get("id", "CVE-UNKNOWN")
                # Name the finding after the CANONICAL id of its alias set,
                # matching the Go pip scanner byte-for-byte so dedup keeps
                # collapsing the two engines' overlap (see
                # _canonical_advisory_id). The CVE is routinely present only
                # as an alias, which is why the picker ranges over both.
                all_ids = sorted({i for i in [vid, *(v.get("aliases") or [])] if i})
                canonical = _canonical_advisory_id(all_ids) or vid
                # Canonical first, then every other id, so nothing a record
                # was known by is dropped by the rename.
                refs = [canonical] + [i for i in all_ids if i != canonical]
                fix_versions = v.get("fix_versions") or []
                fix_text = (
                    f"Upgrade to {pkg}=={fix_versions[0]} or later."
                    if fix_versions
                    else "Upgrade to a patched version (no fix listed by pip-audit)."
                )
                emit_fn(
                    {
                        "id": f"SEC-DEPS-{canonical.replace('-', '_')}",
                        "rule_id": canonical,
                        "dependency": {
                            "ecosystem": "PyPI",
                            "package": pkg,
                            "version": ver,
                            "manifest": req_file.name,
                        },
                        "title": f"Vulnerable dependency: {pkg}=={ver} ({canonical})",
                        "severity": "HIGH",
                        "source": "whitebox",
                        "category": "deps",
                        "endpoint": req_file.name,
                        "evidence": f"{pkg}=={ver}: {(v.get('description') or '')[:200]}",
                        "fix": fix_text,
                        "references": refs,
                        "confidence": "HIGH",
                        "line": req_file.name,
                    }
                )
        return True

    def _local_pypi_check(
        self,
        packages: list[tuple[str, str]],
        req_file: Path,
        emit_fn: Callable[[dict], None],
    ) -> None:
        """Check packages against the local known-vulnerable list."""
        pkg_map = {pkg: spec for pkg, spec in packages}
        for vuln in _KNOWN_PYPI_VULNS:
            spec = pkg_map.get(vuln.package)
            if spec is None:
                continue
            pinned = _extract_pinned_version(spec)
            if pinned and _is_vulnerable(pinned, vuln.safe_from):
                emit_fn(
                    {
                        "id": f"SEC-DEPS-{vuln.cve.replace('-', '_')}",
                        "rule_id": vuln.cve,
                        "dependency": {
                            "ecosystem": "PyPI",
                            "package": vuln.package,
                            "version": pinned,
                            "manifest": req_file.name,
                        },
                        "title": f"Vulnerable dependency: {vuln.package}=={pinned} ({vuln.cve})",
                        "severity": vuln.severity,
                        "source": "whitebox",
                        "category": "deps",
                        "endpoint": req_file.name,
                        "evidence": (
                            f"{vuln.package}=={pinned} is vulnerable to {vuln.cve}: {vuln.title}"
                        ),
                        "fix": vuln.fix,
                        "references": [vuln.cve],
                        "confidence": "HIGH",
                        "line": req_file.name,
                    }
                )
            elif not pinned and spec:
                # Unpinned — emit INFO advisory
                emit_fn(
                    {
                        "id": f"SEC-DEPS-UNPINNED-{vuln.package.upper().replace('-', '_')}",
                        # A distinct rule from the vulnerable-pin one above:
                        # "this dependency is unpinned" and "this pinned
                        # version is vulnerable" are different claims about
                        # different states, and must not share an identity.
                        "rule_id": f"deps.unpinned/{vuln.cve}",
                        "dependency": {
                            "ecosystem": "PyPI",
                            "package": vuln.package,
                            "manifest": req_file.name,
                        },
                        "title": (
                            f"Dependency {vuln.package!r} is not pinned — "
                            f"known vulnerable versions exist ({vuln.cve})"
                        ),
                        "severity": "INFO",
                        "source": "whitebox",
                        "category": "deps",
                        "endpoint": req_file.name,
                        "evidence": f"{vuln.package}{spec} (unpinned; {vuln.cve} affects < {vuln.safe_from})",
                        "fix": f"Pin to a specific safe version: {vuln.package}>={vuln.safe_from}. {vuln.fix}",
                        "references": [vuln.cve],
                        "confidence": "LOW",
                        "line": req_file.name,
                    }
                )

    # ------------------------------------------------------------------
    # npm checks
    # ------------------------------------------------------------------

    def _check_npm(self, pkg_file: Path, emit_fn: Callable[[dict], None]) -> None:
        """Run npm audit if installed; fall back to the curated local list.

        npm audit needs a package-lock.json or node_modules/ alongside the
        manifest — without one it errors out. Either case (missing tool or
        missing lockfile) trips the fallback so users always get something.
        """
        text = _read_capped(pkg_file)
        if text is None:  # F-L10: oversized/unreadable manifest — skip
            return
        packages = _parse_package_json(text)

        if shutil.which("npm") and self._has_npm_lockfile(pkg_file.parent):
            if self._run_npm_audit(pkg_file, emit_fn):
                return  # primary path succeeded
        self._local_npm_check(packages, pkg_file, emit_fn)

    @staticmethod
    def _has_npm_lockfile(directory: Path) -> bool:
        """Return True if npm audit can run from `directory`.

        npm audit reads `package-lock.json`, `npm-shrinkwrap.json`, or the
        installed `node_modules/` tree. With none of those it exits non-zero
        and emits no JSON.
        """
        return (
            (directory / "package-lock.json").exists()
            or (directory / "npm-shrinkwrap.json").exists()
            or (directory / "node_modules").is_dir()
        )

    def _run_npm_audit(self, pkg_file: Path, emit_fn: Callable[[dict], None]) -> bool:
        """Run `npm audit --json` and emit findings. Return True iff clean run.

        npm audit exits 0 (no vulns) or 1 (vulns found) on success; any other
        code (network failure, missing lockfile, bad cwd) is a tool error.
        """
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=str(pkg_file.parent),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(
                f"[fendix-engine] npm audit failed, falling back to local list: {exc}",
                file=sys.stderr,
            )
            return False

        # npm audit returns 1 when vulns are found — that's a successful run.
        if proc.returncode not in (0, 1):
            stderr_excerpt = (proc.stderr or "").strip().splitlines()[:3]
            print(
                f"[fendix-engine] npm audit exited {proc.returncode}, "
                f"falling back to local list. stderr: "
                f"{' | '.join(stderr_excerpt)[:200]}",
                file=sys.stderr,
            )
            return False

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            print(
                f"[fendix-engine] npm audit produced invalid JSON, "
                f"falling back to local list: {exc}",
                file=sys.stderr,
            )
            return False

        # audit #19: npm exits 1 BOTH on "vulns found" (success) and on an
        # internal error (ENOLOCK, EAUTH, offline) where it emits an error
        # document with non-empty stdout but no "vulnerabilities" key. The
        # empty-stdout guard used for pip-audit won't catch this — inspect the
        # parsed document. Treat an error doc as a failure so the local
        # fallback fires instead of silently reporting a clean scan.
        if isinstance(data, dict) and (
            "error" in data or "vulnerabilities" not in data
        ):
            err = data.get("error")
            detail = (
                (err.get("summary") or err.get("code") or "")
                if isinstance(err, dict)
                else ""
            )
            print(
                "[fendix-engine] npm audit returned an error document, "
                f"falling back to local list. {detail}".strip(),
                file=sys.stderr,
            )
            return False

        sev_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
        }
        # npm audit v2 format: {"vulnerabilities": {"pkg": {...}}}
        for pkg_name, info in (data.get("vulnerabilities") or {}).items():
            severity = (info.get("severity") or "moderate").upper()
            via = info.get("via") or []
            cves = [v.get("url", "") for v in via if isinstance(v, dict)]
            emit_fn(
                {
                    "id": f"SEC-DEPS-NPM-{pkg_name.upper().replace('-', '_').replace('@', '').replace('/', '_')}",
                    # npm audit reports per PACKAGE, not per advisory, so the
                    # package IS the rule identity here. Saying so explicitly
                    # beats letting identity fall back to the positional id.
                    "rule_id": f"deps.npm-audit/{pkg_name}",
                    "dependency": {
                        "ecosystem": "npm",
                        "package": pkg_name,
                        "manifest": pkg_file.name,
                    },
                    "title": f"Vulnerable npm package: {pkg_name} (severity: {severity})",
                    "severity": sev_map.get(severity, "MEDIUM"),
                    "source": "whitebox",
                    "category": "deps",
                    "endpoint": pkg_file.name,
                    "evidence": f"npm audit found {severity} vulnerability in {pkg_name}",
                    "fix": f"Run 'npm audit fix' or update {pkg_name} manually.",
                    "references": [c for c in cves[:3] if c],
                    "confidence": "HIGH",
                    "line": pkg_file.name,
                }
            )
        return True

    def _local_npm_check(
        self,
        packages: list[tuple[str, str]],
        pkg_file: Path,
        emit_fn: Callable[[dict], None],
    ) -> None:
        """Check npm packages against local known-vulnerable list."""
        pkg_map = {pkg: spec for pkg, spec in packages}
        for vuln in _KNOWN_NPM_VULNS:
            spec = pkg_map.get(vuln.package)
            if spec is None:
                continue
            # B8 (version-range-floor): a non-exact spec (^/~/>=/<) declares a
            # RANGE, and npm resolves it to the latest matching version — often
            # a patched one. Without a lockfile on this path we can only see the
            # range FLOOR, so a vulnerable floor is an ADVISORY (INFO/LOW), not a
            # confirmed-installed HIGH. An exact pin keeps its real severity.
            is_range = bool(re.match(r"^\s*[\^~><]", spec))
            pinned = re.sub(r"^[^0-9]*", "", spec)
            if pinned and _is_vulnerable(pinned, vuln.safe_from):
                severity = "INFO" if is_range else vuln.severity
                note = (
                    f" (range floor {pinned}; resolve the lockfile for the "
                    f"installed version)"
                    if is_range
                    else ""
                )
                emit_fn(
                    {
                        "id": f"SEC-DEPS-{vuln.cve.replace('-', '_')}",
                        "rule_id": vuln.cve,
                        "dependency": {
                            "ecosystem": "npm",
                            "package": vuln.package,
                            "version": pinned,
                            "manifest": pkg_file.name,
                        },
                        "title": f"Vulnerable npm package: {vuln.package}@{pinned} ({vuln.cve})",
                        "severity": severity,
                        "source": "whitebox",
                        "category": "deps",
                        "endpoint": pkg_file.name,
                        "evidence": (
                            f"{vuln.package}@{pinned} is vulnerable to {vuln.cve}: {vuln.title}{note}"
                        ),
                        "fix": vuln.fix,
                        "references": [vuln.cve],
                        "confidence": "HIGH" if not is_range else "LOW",
                        "line": pkg_file.name,
                    }
                )

    # ------------------------------------------------------------------
    # Go module checks (govulncheck)
    # ------------------------------------------------------------------

    def _check_go_modules(self, go_mod: Path, emit_fn: Callable[[dict], None]) -> None:
        """Run govulncheck against a Go module if the tool is installed.

        No local fallback for Go: maintaining a curated Go vuln list would
        duplicate the OSV database that govulncheck already consults. When
        the tool is missing we log a stderr hint so the user knows what to
        install; production CI will have it.
        """
        if not shutil.which("govulncheck"):
            print(
                "[fendix-engine] govulncheck not installed; skipping Go module "
                "scan. Install via 'go install golang.org/x/vuln/cmd/govulncheck@latest'.",
                file=sys.stderr,
            )
            return
        self._run_govulncheck(go_mod, emit_fn)

    def _run_govulncheck(self, go_mod: Path, emit_fn: Callable[[dict], None]) -> bool:
        """Run `govulncheck -json ./...` and emit findings. Return True iff clean.

        govulncheck exits 0 (no vulns), 3 (vulns found in called code), or
        anything else (tool error). Output is newline-delimited JSON: each
        line is a single message with one of several types ("config",
        "progress", "osv", "finding"). We parse "osv" entries (the
        vulnerability records) and "finding" entries (specific call traces),
        then emit one fendix finding per OSV that has at least one finding —
        OSVs with no calls are vendored-but-uncalled and don't warrant a
        scary report on their own.
        """
        try:
            proc = subprocess.run(
                ["govulncheck", "-json", "./..."],
                cwd=str(go_mod.parent),
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(
                f"[fendix-engine] govulncheck failed: {exc}",
                file=sys.stderr,
            )
            return False

        # 0 = no vulns, 3 = vulns found (per govulncheck docs); everything
        # else is a tool error that should bubble up so users know.
        if proc.returncode not in (0, 3):
            stderr_excerpt = (proc.stderr or "").strip().splitlines()[:3]
            print(
                f"[fendix-engine] govulncheck exited {proc.returncode}. "
                f"stderr: {' | '.join(stderr_excerpt)[:300]}",
                file=sys.stderr,
            )
            return False

        for finding in _parse_govulncheck_json(proc.stdout):
            emit_fn({**finding, "endpoint": go_mod.name, "line": go_mod.name})
        return True


def _parse_govulncheck_json(stdout: str) -> list[dict]:
    """Parse govulncheck JSON stdout and return a list of finding dicts.

    govulncheck emits a stream of JSON objects, separated only by whitespace.
    Real output is **pretty-printed multi-line** (each object spans many
    lines), not single-line NDJSON, so a naive `for line in splitlines()`
    parser misses everything past the first `{`. Use json.JSONDecoder's
    `raw_decode` to consume one object at a time from a sliding offset.

    We collect:
      - "osv" messages (vulnerability records keyed by ID)
      - "finding" messages (each ties an OSV ID to one or more call traces)

    Then we emit one fendix finding per OSV that was actually called by the
    target's code (the trace contains a frame with `function` set). Vendored
    or transitively-imported-but-uncalled vulns are dropped — that's exactly
    how govulncheck distinguishes real risk from supply-chain noise.

    Pulled out as a module-level function so the unit tests can run it
    against fixture stdout without standing up a fake subprocess.
    """
    osvs: dict[str, dict] = {}
    called_ids: set[str] = set()

    decoder = json.JSONDecoder()
    pos = 0
    n = len(stdout)
    while pos < n:
        # Skip whitespace separating objects (newlines + indent in
        # pretty-printed mode; single newlines in NDJSON mode — both work).
        while pos < n and stdout[pos].isspace():
            pos += 1
        if pos >= n:
            break
        try:
            msg, end = decoder.raw_decode(stdout, pos)
            pos = end
        except json.JSONDecodeError:
            # Best-effort recovery: drop to the next opening brace and retry.
            nxt = stdout.find("{", pos + 1)
            if nxt < 0:
                break
            pos = nxt
            continue

        if not isinstance(msg, dict):
            continue
        if "osv" in msg and isinstance(msg["osv"], dict):
            osv = msg["osv"]
            osv_id = osv.get("id")
            if osv_id:
                osvs[osv_id] = osv
        elif "finding" in msg and isinstance(msg["finding"], dict):
            f = msg["finding"]
            osv_id = f.get("osv")
            # The finding only counts as "called" when the trace reaches
            # one of the user's own packages — govulncheck signals this by
            # populating `trace[].function` for the called frame. Vendored-
            # but-not-called findings have a one-element trace with only
            # module+package set.
            trace = f.get("trace") or []
            has_call = any(isinstance(t, dict) and t.get("function") for t in trace)
            if osv_id and has_call:
                called_ids.add(osv_id)

    findings: list[dict] = []
    for osv_id in sorted(called_ids):
        osv = osvs.get(osv_id, {})
        summary = osv.get("summary") or osv_id
        details = (osv.get("details") or "")[:200]
        affected = osv.get("affected") or []
        # The affected Go module name — the package half of this finding's
        # identity. OSV puts it at affected[].package.name; absent records
        # leave it empty rather than inventing one.
        module = ""
        for a in affected:
            name = ((a.get("package") or {}).get("name") or "").strip()
            if name:
                module = name
                break
        # First "ranges" entry's first "fixed" event is the canonical fix
        # version per OSV schema (https://ossf.github.io/osv-schema/).
        fix_version = ""
        for a in affected:
            ranges = a.get("ranges") or []
            for r in ranges:
                for ev in r.get("events") or []:
                    if isinstance(ev, dict) and ev.get("fixed"):
                        fix_version = ev["fixed"]
                        break
                if fix_version:
                    break
            if fix_version:
                break
        aliases = osv.get("aliases") or []
        refs = [osv_id] + [a for a in aliases if a]

        findings.append(
            {
                "id": f"SEC-DEPS-GO-{osv_id.replace('-', '_')}",
                "rule_id": osv_id,
                "dependency": {"ecosystem": "Go", "package": module},
                "title": f"Vulnerable Go module: {summary} ({osv_id})",
                "severity": "HIGH",  # govulncheck reports a real call trace
                "source": "whitebox",
                "category": "deps",
                "evidence": f"{osv_id}: {details}",
                "fix": (
                    f"Upgrade to {fix_version} or later."
                    if fix_version
                    else "Upgrade to a patched version (no fix listed)."
                ),
                "references": refs,
                "confidence": "HIGH",
            }
        )
    return findings
