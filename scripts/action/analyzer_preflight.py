#!/usr/bin/env python3
"""Required analyzers for the composite Action: which ones, and whether they run.

The Action fails closed when an analyzer it requires cannot run. This module
holds the two halves of that contract, and both the Action and the image
builds use it:

- resolve_required() turns the require-analyzers input into the list the
  Action enforces: auto (Semgrep whenever code is scanned), an explicit list
  of engine analyzer names, or none (an explicit opt-out).
- probe_semgrep() runs the Semgrep that the scan will run on a bundled rule
  and file that must match. It tests that Semgrep executes and reports, not
  which version it claims, so a missing executable, a Semgrep without
  semgrep-core, a damaged install, a startup crash, a binary for another
  architecture and a hang each fail with their own message. The probe needs
  no network: the rule is local and the version check is off.

The engine enforces the same list at scan time (--require-analyzers), so a
Semgrep that passes here and fails during the scan still exits 2.

Run as a script (the Action's "Preflight required analyzers" step, or an
image build), it probes every required analyzer that has a probe and exits 2
on the first failure, with one ::error line naming the analyzer.

Standard library only, Python 3.9 or later: the Action runs it with its own
3.11 interpreter and the images with their 3.14.
"""
import argparse
import glob
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The engine's analyzer registry (go/internal/engine/registry.go), in its
# order. python/tests/test_action_preflight.py fails if the two drift.
REGISTRY = (
    "dast", "spec", "active-probes",
    "secrets", "textscan", "semgrep",
    "govulncheck", "pip", "npm",
    "python-engine", "python-engine/auth", "python-engine/injection", "python-engine/deps",
    "plugins",
)

# Semgrep's Linux wheels from 1.173.0: manylinux_2_34 and musllinux_1_2, on
# x86_64 and aarch64. Older platforms get only the source distribution, and a
# build from it has no semgrep-core, so it cannot scan.
GLIBC_FLOOR = (2, 34)
MUSL_FLOOR = (1, 2)
SUPPORTED_MACHINES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
SUPPORTED_RUNNERS = "Ubuntu 22.04 or later, Debian 12 or later, RHEL 9 or later, Amazon Linux 2023"
IMAGE = "docker.io/fendixapp/fendix"
IMAGE_DOCS = "https://github.com/Fendix-app/Fendix/blob/main/docs/INTEGRATION_GUIDE.md#34-the-docker-image-invoked-directly"

# Long enough for a cold Semgrep start on a slow runner (a healthy one takes
# a few seconds), and well inside the 120 s the engine gives Semgrep per scan.
PROBE_TIMEOUT = 90
PROBE_RULE_ID = "fendix-preflight-probe"
PROBE_RULE = f"""rules:
  - id: {PROBE_RULE_ID}
    languages: [python]
    severity: INFO
    message: Fendix analyzer preflight probe
    pattern: fendix_preflight_probe(...)
"""
PROBE_FILE = "probe.py"
PROBE_SOURCE = "fendix_preflight_probe(1)\n"
PROBE_LINE = 1


class RequirementError(Exception):
    """An invalid require-analyzers input."""


class PreflightError(Exception):
    """A required analyzer that cannot run, worded for the workflow log."""

    def __init__(self, analyzer, message):
        super().__init__(message)
        self.analyzer = analyzer

    @property
    def title(self):
        return f"Fendix required analyzer {self.analyzer} is unavailable"

    def line(self):
        """The ::error line: the title names the analyzer, and so does the text."""
        return error_command(self.title, f"Required analyzer {self.analyzer} cannot run. {self}")


def workflow_value(value):
    """One workflow-command line, whatever the value contains."""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def error_command(title, message):
    title = workflow_value(title).replace(":", "%3A").replace(",", "%2C")
    return f"::error title={title}::{workflow_value(message)}"


# --- Which analyzers are required ---------------------------------------------

def resolve_required(value, code, mode="local"):
    """The analyzers the Action requires, and how they were chosen.

    Returns (names, kind) where kind is "auto", "explicit" or "none".
    auto requires semgrep whenever code is scanned: the engine records it
    not_applicable without --code, and the Action installs it for every code
    scan. Managed mode takes only auto, because there the binding's backend
    policy owns the requirement and the runner may not narrow it.
    """
    raw = (value or "").strip()
    keyword = raw.lower()
    if mode == "managed" and keyword not in ("", "auto"):
        raise RequirementError(
            f"managed mode does not accept require-analyzers '{raw}': the binding's backend policy decides what is "
            "required, so leave it at auto")
    if keyword in ("", "auto"):
        return (["semgrep"] if (code or "").strip() else []), "auto"
    if keyword == "none":
        return [], "none"
    names = []
    for item in raw.split(","):
        name = item.strip()
        if not name:
            raise RequirementError(f"require-analyzers '{raw}' has an empty entry; use comma-separated analyzer names")
        if name.lower() in ("auto", "none"):
            raise RequirementError(f"require-analyzers '{raw}' mixes '{name}' with analyzer names; use it on its own")
        if name not in REGISTRY:
            raise RequirementError(
                f"require-analyzers names unknown analyzer '{name}'; known analyzers: {', '.join(REGISTRY)}")
        if name not in names:
            names.append(name)
    return names, "explicit"


# --- The runner's platform ----------------------------------------------------

def _version_tuple(text):
    parts = re.findall(r"\d+", text or "")
    return tuple(int(p) for p in parts[:2]) if len(parts) >= 2 else None


def musl_version():
    """musl's version from its dynamic loader, or None when there is none."""
    for loader in sorted(glob.glob("/lib/ld-musl-*.so.1")):
        try:
            result = subprocess.run([loader], capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)?)", result.stdout + result.stderr)
        if match:
            return match.group(1)
    return None


def platform_facts():
    """What decides whether a Semgrep wheel exists for this runner."""
    system = platform.system()
    machine = platform.machine()
    libc, libc_version = None, None
    if system == "Linux":
        try:
            value = os.confstr("CS_GNU_LIBC_VERSION")
        except (AttributeError, ValueError, OSError):
            value = None
        if value and " " in value:
            libc, libc_version = value.split(" ", 1)
        else:
            libc_version = musl_version()
            libc = "musl" if libc_version else None
    return {"system": system, "machine": machine, "libc": libc, "libc_version": libc_version,
            "python": platform.python_version(), "mac": platform.mac_ver()[0] if system == "Darwin" else ""}


def describe_platform(facts):
    machine = facts.get("machine") or "an unknown architecture"
    if facts.get("system") == "Linux":
        if facts.get("libc") and facts.get("libc_version"):
            return f"{facts['libc']} {facts['libc_version']} on {machine}"
        return f"Linux with an unidentified C library on {machine}"
    if facts.get("system") == "Darwin":
        return f"macOS {facts.get('mac') or ''} on {machine}".replace("  ", " ")
    return f"{facts.get('system') or 'an unknown OS'} on {machine}"


def platform_shortfall(facts):
    """Why Semgrep publishes no wheel for this runner, or None when it does."""
    machine = SUPPORTED_MACHINES.get((facts.get("machine") or "").lower())
    if facts.get("system") == "Darwin":
        return None if machine else f"Semgrep publishes macOS wheels only for x86_64 and arm64, not {facts.get('machine')}"
    if facts.get("system") != "Linux":
        return f"Semgrep publishes wheels only for Linux and macOS, not {facts.get('system')}"
    shortfalls = []
    version = _version_tuple(facts.get("libc_version"))
    if facts.get("libc") == "glibc":
        if version is None or version < GLIBC_FLOOR:
            shortfalls.append(f"glibc {facts.get('libc_version')} is older than 2.34")
    elif facts.get("libc") == "musl":
        if version is None or version < MUSL_FLOOR:
            shortfalls.append(f"musl {facts.get('libc_version')} is older than 1.2")
    else:
        shortfalls.append("its C library is neither glibc nor musl")
    if not machine:
        shortfalls.append(f"{facts.get('machine')} is neither x86_64 nor aarch64")
    return "; ".join(shortfalls) or None


def no_wheel_message(package, requirement, facts, *, required):
    """The preparation error, or warning, for a package with no wheel here."""
    here = describe_platform(facts)
    shortfall = platform_shortfall(facts)
    name = "Semgrep" if package == "semgrep" else package
    if shortfall is None:
        cause = (f"pip found no installable wheel of {requirement} although this runner ({here}) is a platform "
                 f"{name} publishes wheels for. The package index may be unreachable or filtered; see pip's output above.")
    elif package == "semgrep":
        cause = (f"{requirement} has no wheel for this runner: it has {here}, and {shortfall}. Semgrep publishes Linux "
                 "wheels only for glibc 2.34 or later (manylinux_2_34) or musl 1.2 or later (musllinux_1_2), on x86_64 "
                 "or aarch64. The Action installs wheels only and never builds Semgrep from source: a source build has "
                 "no semgrep-core, so it could not scan.")
    else:
        cause = (f"{requirement} has no wheel for this runner ({here}: {shortfall}). The Action installs the engine's "
                 "Python dependencies from wheels only and never builds them from source. Supported Linux runners have "
                 "glibc 2.34 or later, or musl 1.2 or later, on x86_64 or aarch64.")
    if not required:
        return cause
    remedies = (f" Remedies: run the scan in the official image, {IMAGE}@sha256:<digest> pinned by digest, as a "
                f"container job ({IMAGE_DOCS} has the job and the current digest); or use a runner with glibc 2.34 "
                f"or later ({SUPPORTED_RUNNERS}).")
    if package == "semgrep":
        remedies += (" To scan without Semgrep, set require-analyzers to none, or to a list without semgrep: the scan "
                     "then runs without it, and the gate does not enforce its coverage.")
    return cause + remedies


# --- Does the required analyzer run -------------------------------------------

def _tail(text, lines=3, limit=500):
    kept = [line.strip() for line in (text or "").splitlines() if line.strip()][-lines:]
    joined = " | ".join(kept)
    return joined if len(joined) <= limit else "..." + joined[-limit:]


def _signal_name(number):
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"signal {number}"


def _run(command, timeout, tmpdir=None):
    """Run the probe in its own session so a timeout also stops semgrep-core.
    tmpdir keeps the child's temporary files (Semgrep writes some) in the
    probe's own directory, which is removed afterwards."""
    env = dict(os.environ)
    if tmpdir:
        env["TMPDIR"] = str(tmpdir)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.communicate()
        raise
    return process.returncode, stdout, stderr


def probe_semgrep(executable=None, timeout=PROBE_TIMEOUT, workdir=None):
    """Run Semgrep on the bundled probe and require its one known match.

    executable defaults to the semgrep on PATH, the one the engine runs.
    Returns (version, seconds) on success; raises PreflightError otherwise.
    """
    path = executable or _which("semgrep")
    if not path:
        raise PreflightError("semgrep", "no semgrep executable is on PATH, so the scan could not run Semgrep. Engine "
                                        "preparation installs it; see that step's output.")
    with tempfile.TemporaryDirectory(prefix="fendix-preflight.", dir=workdir) as temp:
        rule = Path(temp) / "rule.yaml"
        rule.write_text(PROBE_RULE)
        target = Path(temp) / "target"
        target.mkdir()
        (target / PROBE_FILE).write_text(PROBE_SOURCE)
        command = [path, "--config", str(rule), "--json", "--no-git-ignore", "--quiet",
                   "--metrics=off", "--disable-version-check", str(target)]
        started = time.monotonic()
        try:
            scratch = Path(temp) / "tmp"
            scratch.mkdir()
            code, stdout, stderr = _run(command, timeout, tmpdir=scratch)
        except subprocess.TimeoutExpired:
            raise PreflightError("semgrep", f"Semgrep at {path} did not finish the preflight probe, one rule on one "
                                            f"file, within {timeout} s, so it would not finish a scan either.") from None
        except OSError as error:
            if getattr(error, "errno", None) == 8:  # ENOEXEC
                raise PreflightError("semgrep", f"{path} is not an executable this runner can run ({error.strerror}): "
                                                "it is built for another architecture, or it is damaged.") from None
            raise PreflightError("semgrep", f"{path} could not be started: {error.strerror or error}.") from None
        seconds = time.monotonic() - started
    if code < 0:
        raise PreflightError("semgrep", f"Semgrep at {path} crashed on the preflight probe ({_signal_name(-code)}). "
                                        f"stderr: {_tail(stderr) or '(empty)'}")
    if "semgrep-core" in stderr and code != 0:
        raise PreflightError("semgrep", f"Semgrep at {path} has no semgrep-core, the engine that does the scanning, "
                                        f"so it cannot scan (a build from Semgrep's source distribution has none). "
                                        f"stderr: {_tail(stderr)}")
    if code not in (0, 1):
        raise PreflightError("semgrep", f"Semgrep at {path} exited {code} on the preflight probe. "
                                        f"stderr: {_tail(stderr) or '(empty)'}")
    try:
        document = json.loads(stdout)
    except ValueError:
        raise PreflightError("semgrep", f"Semgrep at {path} exited {code} but did not write JSON, so the engine could "
                                        f"not read its results. Output: {_tail(stdout, 1, 200) or '(empty)'}") from None
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        raise PreflightError("semgrep", f"Semgrep at {path} wrote JSON without a results list, so the engine could "
                                        "not read its results.")
    if not any(_is_probe_match(result) for result in results):
        errors = document.get("errors") or []
        detail = "; ".join(_tail(str(e.get("message", e)) if isinstance(e, dict) else str(e), 1, 160) for e in errors[:3])
        raise PreflightError("semgrep", f"Semgrep at {path} ran but did not report the probe's one known match "
                                        f"({len(results)} results, {len(errors)} errors{': ' + detail if detail else ''}). "
                                        "Its install is damaged or its engine is not running rules, so a scan would "
                                        "find nothing and look clean.")
    return str(document.get("version") or "unknown version"), seconds


def _is_probe_match(result):
    if not isinstance(result, dict):
        return False
    check_id = str(result.get("check_id", ""))
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    return ((check_id == PROBE_RULE_ID or check_id.endswith("." + PROBE_RULE_ID))
            and str(result.get("path", "")).endswith(PROBE_FILE) and start.get("line") == PROBE_LINE)


def _which(name):
    import shutil
    return shutil.which(name)


PROBES = {"semgrep": probe_semgrep}


def run_preflight(required, out=print):
    """Probe each required analyzer that has a probe. Raises PreflightError."""
    for name in required:
        probe = PROBES.get(name)
        if probe is None:
            out(f"{name}: no setup probe; the engine enforces it at scan time (--require-analyzers)")
            continue
        version, seconds = probe()
        out(f"{name}: Semgrep {version} at {_which('semgrep') or 'PATH'} reported the probe's known match "
            f"in {seconds:.1f} s: preflight passed")


def parse_list(value):
    return [name for name in (value or "").split(",") if name]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--analyzers", help="comma-separated analyzers to probe (default: $REQUIRED)")
    args = parser.parse_args(argv)
    required = parse_list(args.analyzers if args.analyzers is not None else os.environ.get("REQUIRED", ""))
    unknown = [name for name in required if name not in REGISTRY]
    if unknown:
        print(error_command("Fendix require-analyzers", f"unknown analyzer {unknown[0]!r}"), file=sys.stderr)
        return 2
    if not required:
        kind = os.environ.get("REQUIREMENT", "")
        if kind == "none":
            print("No analyzer is required (require-analyzers: none): required-analyzer enforcement is off, so "
                  "nothing is checked here.")
        else:
            print("No analyzer is required: require-analyzers is auto and the code input is empty, so this scan "
                  "runs no code analyzer.")
        return 0
    print(f"Required analyzers: {', '.join(required)}")
    try:
        run_preflight(required)
    except PreflightError as error:
        print(error.line(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
