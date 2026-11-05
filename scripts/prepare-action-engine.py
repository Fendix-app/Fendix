#!/usr/bin/env python3
"""Prepare the Action's Python tree outside the scanned checkout.

The automatic path uses a signed build record to bind the installed binary to
an immutable source commit, and installs that release's own hash-locked
dependency set. An explicit engine_path remains caller-managed.

Either way, dependencies install from wheels only (--only-binary=:all:): a
package with no wheel for the runner stops preparation with exit 2 and names
the package and the runner's platform. Nothing is built from source, because
a Semgrep built from its source distribution has no semgrep-core and cannot
scan. The one exception is a Semgrep that no requirement needs
(require-analyzers none, or a list without it): it is left out with a
warning, and the scan records it unavailable.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

REPO = "Fendix-app/Fendix"
ISSUER = "https://token.actions.githubusercontent.com"
# Release trees carry python/requirements.lock from v3.6.1. Up to v3.6.0 the
# published requirements permit Pydantic 2.14, which breaks the Semgrep MCP
# 1.16.x import, so those trees keep the proven compatibility boundary.
FIRST_BUILD_RECORD = (3, 5, 0)
LAST_LOCKLESS = (3, 6, 0)
PYDANTIC_BOUND = "pydantic<2.14"
DOWNLOAD_ATTEMPTS = 3
TRANSIENT_STATUS = {429, 500, 502, 503, 504}
WHEELS_ONLY = "--only-binary=:all:"


def _load_preflight():
    path = Path(__file__).resolve().parent / "action" / "analyzer_preflight.py"
    spec = importlib.util.spec_from_file_location("analyzer_preflight", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = _load_preflight()


class PrepareError(Exception):
    """A preparation failure, worded for the workflow log. A title, when set,
    becomes the annotation title (for example the analyzer it costs)."""

    def __init__(self, message, title=None):
        super().__init__(message)
        self.title = title


class DownloadError(PrepareError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def safe_line(value):
    if "\n" in value or "\r" in value:
        raise ValueError("Action paths must not contain line breaks")
    return value


def version_tuple(version):
    match = re.match(r"v(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise PrepareError(f"cannot read a release version from {version!r}")
    return tuple(int(part) for part in match.groups())


def validate_record(record, version, binary):
    if record.get("schema_version") != "engine-build-record/v1":
        raise ValueError("unsupported engine build record schema")
    source = record.get("source", {})
    if record.get("engine_version") != version or source.get("tag") != version:
        raise ValueError("build record version does not match installed binary")
    if source.get("repository") != REPO:
        raise ValueError("build record belongs to another repository")
    commit = source.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("build record has no immutable source commit")
    digest = "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest()
    if not any(a.get("executable_sha256") == digest for a in record.get("artifacts", [])):
        raise ValueError("installed binary is not an artifact in the signed build record")
    return commit


def is_transient(error):
    """Network trouble that may pass. Never a missing file, a refused request
    or a TLS failure: retrying those cannot help and only hides the cause."""
    if isinstance(error, urllib.error.HTTPError):
        return error.code in TRANSIENT_STATUS
    if isinstance(error, urllib.error.URLError):
        error = error.reason
    if isinstance(error, ssl.SSLError):
        return False
    return isinstance(error, (TimeoutError, ConnectionError, http.client.IncompleteRead))


def describe(error):
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP {error.code} {error.reason}"
    if isinstance(error, urllib.error.URLError):
        return str(error.reason)
    return f"{type(error).__name__}: {error}"


def download(url, path):
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                with path.open("wb") as target:
                    while chunk := response.read(1024 * 1024):
                        target.write(chunk)
            return
        except Exception as error:  # noqa: BLE001 - classified below
            if not is_transient(error) or attempt == DOWNLOAD_ATTEMPTS:
                tries = f" after {attempt} attempts" if attempt > 1 else ""
                status = error.code if isinstance(error, urllib.error.HTTPError) else None
                raise DownloadError(f"could not download {url}{tries}: {describe(error)}", status) from error
            print(f"Download of {url} failed ({describe(error)}); retrying ({attempt}/{DOWNLOAD_ATTEMPTS})", flush=True)
            time.sleep(2 ** attempt)


def run(command, failure):
    """Run a preparation command; on failure say which step failed."""
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as error:
        raise PrepareError(f"{failure} (exit {error.returncode}; see the output above)") from error
    except FileNotFoundError as error:
        raise PrepareError(f"{failure}: {command[0]} was not found") from error


def extract_python(archive, destination):
    """Extract regular python/ files only, never links or traversal paths."""
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 3 or parts[1] != "python":
                continue
            relative = Path(*parts[2:])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe source archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("source archive contains a link or special file")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream:
                target.write_bytes(stream.read())
    validate_tree(destination)


def validate_tree(tree):
    if not (tree / "engine.py").is_file() or not (tree / "requirements.txt").is_file():
        raise ValueError("engine_path must contain engine.py and requirements.txt")


def fetch_build_record(base, version, work):
    for name in ("build-record.json", "build-record.json.sig", "build-record.json.crt"):
        try:
            download(f"{base}/{name}", work / name)
        except DownloadError as error:
            if error.status != 404:
                raise
            if name != "build-record.json":
                raise PrepareError(f"the signed build record for Fendix {version} is incomplete: {name} is missing from the release") from error
            if version_tuple(version) < FIRST_BUILD_RECORD:
                raise PrepareError(
                    f"Fendix {version} predates signed build records (they are published from v3.5.0), so its Python "
                    "engine cannot be prepared automatically. Pin version to v3.5.0 or later, or set engine_path to "
                    "a version-matched python/ tree") from error
            raise PrepareError(
                f"Fendix {version} has no signed build record on its release (build-record.json returned 404). "
                "If the release was just published its assets may still be uploading; otherwise pin another "
                "version or set engine_path to a version-matched python/ tree") from error


def automatic_tree(binary, work):
    output = subprocess.check_output([str(binary), "version"], text=True).strip()
    match = re.fullmatch(r"fendix version (v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?) \([^\n]+\)", output)
    if not match:
        raise ValueError("automatic Python preparation requires a released binary; provide engine_path for custom builds")
    version = match.group(1)
    fetch_build_record(f"https://github.com/{REPO}/releases/download/{version}", version, work)
    identity = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{version}"
    run([
        "cosign", "verify-blob", "--signature", str(work / "build-record.json.sig"),
        "--certificate", str(work / "build-record.json.crt"),
        "--certificate-identity", identity,
        "--certificate-oidc-issuer", ISSUER, str(work / "build-record.json"),
    ], f"the signed build record for Fendix {version} did not verify against {identity}; nothing was prepared from unverified source")
    commit = validate_record(json.loads((work / "build-record.json").read_text()), version, binary)
    archive = work / "source.tar.gz"
    download(f"https://codeload.github.com/{REPO}/tar.gz/{commit}", archive)
    tree = work / "python"
    tree.mkdir()
    extract_python(archive, tree)
    print(f"Prepared Python source for {version} at commit {commit}")
    return tree, version


def install_plan(tree, release_version):
    """The pip arguments for the engine's dependencies, and a log line.

    release_version is the Fendix release that owns the tree (automatic path);
    None means a caller-managed engine_path, whose install is unchanged.
    """
    requirements = ["-r", str(tree / "requirements.txt"), PYDANTIC_BOUND]
    if release_version is None:
        return requirements, f"Custom engine_path: installing its requirements.txt with the {PYDANTIC_BOUND} compatibility bound"
    lock = tree / "requirements.lock"
    if lock.is_file():
        # The release's resolved set, exclusively: nothing unpinned on top.
        return ["--require-hashes", "-r", str(lock)], f"Installing the locked dependencies of Fendix {release_version} (requirements.lock, --require-hashes)"
    if version_tuple(release_version) <= LAST_LOCKLESS:
        return requirements, f"Fendix {release_version} ships no requirements.lock: installing requirements.txt with the {PYDANTIC_BOUND} compatibility bound"
    raise PrepareError(f"the verified source of Fendix {release_version} has no python/requirements.lock; releases after v3.6.0 ship one")


def error_line(error):
    """One workflow-command line, whatever the message contains."""
    title = getattr(error, "title", None)
    if title:
        return preflight.error_command(title, str(error))
    message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::error::Python engine preparation failed: {message}"


def warning_line(title, message):
    return f"::warning title={title}::{preflight.workflow_value(message)}"


MISSING = re.compile(r"No matching distribution found for ([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\S*)")


def missing_distribution(log):
    """(name, requirement) of the package pip found no installable file for."""
    try:
        text = Path(log).read_text(errors="replace")
    except OSError:
        return None
    match = MISSING.search(text)
    if not match:
        return None
    name = match.group(1)
    return re.sub(r"[-_.]+", "-", name).lower(), (name + match.group(2)).strip()


def without_package(pip_args, package, work):
    """pip_args with the named package removed from its requirements file.

    Drops the requirement line and its continuation lines (the --hash lines of
    a lock), so --require-hashes still covers every other pinned package.
    """
    args = list(pip_args)
    index = args.index("-r") + 1
    source = Path(args[index])
    kept, skipping = [], False
    pattern = re.compile(rf"^{re.escape(package)}\s*(?:[<>=!~;\[]|\\|$)", re.IGNORECASE)
    for line in source.read_text().splitlines():
        normalised = re.sub(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", lambda m: re.sub(r"[-_.]+", "-", m.group(1)), line)
        if skipping or pattern.match(normalised):
            skipping = line.rstrip().endswith("\\")
            continue
        kept.append(line)
    target = Path(work) / f"without-{package}-{source.name}"
    target.write_text("\n".join(kept) + "\n")
    args[index] = str(target)
    return args


def resolve_requirement():
    """The required analyzers from the Action inputs (see analyzer_preflight)."""
    try:
        return preflight.resolve_required(os.environ.get("REQUIRE_ANALYZERS", "auto"),
                                          os.environ.get("CODE", ""), os.environ.get("MODE", "local"))
    except preflight.RequirementError as error:
        raise PrepareError(str(error), title="Fendix require-analyzers") from error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine-path", default=os.environ.get("ENGINE_PATH", ""))
    args = parser.parse_args()
    # Before anything is downloaded: an invalid input fails at once.
    required, kind = resolve_requirement()
    import shutil
    binary = shutil.which("fendix")
    if not binary:
        raise ValueError("install Fendix before preparing its Python engine")
    runner_temp = Path(safe_line(os.environ["RUNNER_TEMP"])).resolve()
    work = Path(tempfile.mkdtemp(prefix="fendix-action-", dir=runner_temp))
    if args.engine_path:
        tree = Path(safe_line(args.engine_path)).resolve()
        validate_tree(tree)
        release_version = None
    else:
        tree, release_version = automatic_tree(Path(binary).resolve(), work)
    prepare(binary, tree, release_version, work, required=required)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as handle:
            handle.write(f"required-analyzers={','.join(required)}\n")
            handle.write(f"requirement={kind}\n")


def install(venv, pip_args, source, work, attempt):
    """pip install, wheels only. Returns the pip log path on failure, None on success."""
    log = Path(work) / f"pip-{attempt}.log"
    command = [str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check",
               WHEELS_ONLY, "--log", str(log), *pip_args]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as error:
        return log, error.returncode
    except FileNotFoundError as error:
        raise PrepareError(f"installing the Python engine's dependencies failed ({source}): {command[0]} was not found") from error
    return None, 0


def prepare(binary, tree, release_version, work, required=()):
    """Install the tree's dependencies in a venv under work, sync the engine to
    the tree, then publish both for the rest of the job. release_version is
    None for a caller-managed engine_path (see install_plan). required names
    the analyzers the Action requires: a dependency they need must install."""
    pip_args, note = install_plan(tree, release_version)
    venv = work / "venv"
    run([sys.executable, "-m", "venv", str(venv)], "creating the Python virtual environment failed")
    print(note, flush=True)
    print(f"Wheels only ({WHEELS_ONLY}): no dependency is built from source", flush=True)
    source = "requirements.lock" if "--require-hashes" in pip_args else f"requirements.txt with {PYDANTIC_BOUND}"
    log, code = install(venv, pip_args, source, work, 1)
    if log is not None:
        missing = missing_distribution(log)
        facts = preflight.platform_facts()
        if missing and missing[0] == "semgrep" and "semgrep" not in required:
            # Nothing requires Semgrep: leave it out rather than fail, and say
            # so. The scan records it unavailable and coverage incomplete.
            print(warning_line("Fendix scans without Semgrep",
                               preflight.no_wheel_message("semgrep", missing[1], facts, required=False)
                               + " No requirement needs Semgrep, so it is left out: the scan records semgrep "
                                 "unavailable and its coverage as incomplete."), flush=True)
            log, code = install(venv, without_package(pip_args, "semgrep", work), source, work, 2)
            missing = missing_distribution(log) if log is not None else None
        if log is not None:
            if missing:
                package, requirement = missing
                title = (f"Fendix required analyzer {package} is unavailable" if package == "semgrep"
                         else f"Fendix engine dependency {package} is unavailable")
                prefix = "Required analyzer semgrep cannot run. " if package == "semgrep" else ""
                raise PrepareError(prefix + preflight.no_wheel_message(package, requirement, facts, required=True),
                                   title=title)
            raise PrepareError(f"installing the Python engine's dependencies failed ({source}) "
                               f"(exit {code}; see the output above)")
    # Publish only after dependency installation and sync both succeed.
    run([str(binary), "engine", "sync", "--dir", str(tree)], f"fendix engine sync --dir {tree} failed")
    with open(os.environ["GITHUB_ENV"], "a") as handle:
        handle.write(f"FENDIX_ENGINE={safe_line(str(tree))}\n")
    with open(os.environ["GITHUB_PATH"], "a") as handle:
        handle.write(f"{safe_line(str(venv / 'bin'))}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - every failure becomes one clear line
        print(error_line(error), file=sys.stderr)
        # 2, the engine's setup-failure code: nothing was prepared or published.
        sys.exit(2)
