"""Tests for the engine.py IPC contract.

Verifies that the Python engine reads a ScanRequest from stdin
and emits valid JSON lines terminated by {"done": true, "total": N}.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path

ENGINE_PATH = Path(__file__).parent.parent / "engine.py"


def _run(request: dict, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run the engine with the given request dict, return CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _parse_output(result: subprocess.CompletedProcess) -> list[dict]:
    """Parse all stdout lines as JSON objects."""
    lines = [l for l in result.stdout.strip().split("\n") if l]
    return [json.loads(l) for l in lines]


def test_engine_emits_done_on_empty_request() -> None:
    """Engine should emit done terminator even with no checks."""
    result = _run({"mode": "whitebox", "checks": [], "verbose": False})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True
    assert objects[-1]["total"] == 0


def test_engine_outputs_valid_json_lines() -> None:
    """Every line of engine output must be valid JSON."""
    result = _run({"mode": "whitebox", "checks": ["secrets"], "code_path": "/nonexistent"})
    assert result.returncode == 0
    for line in result.stdout.strip().split("\n"):
        if line:
            json.loads(line)  # raises on invalid JSON


def test_engine_done_total_matches_finding_count() -> None:
    """done.total must equal the number of finding lines emitted."""
    result = _run({"mode": "whitebox", "checks": [], "code_path": "/nonexistent"})
    assert result.returncode == 0
    objects = _parse_output(result)
    findings = [o for o in objects if "id" in o or "title" in o]
    terminator = objects[-1]
    assert terminator["done"] is True
    assert terminator["total"] == len(findings)


def test_engine_handles_invalid_json_gracefully() -> None:
    """Engine must not crash on invalid JSON — exits with code 2."""
    proc = subprocess.run(
        [sys.executable, str(ENGINE_PATH)],
        input="not valid json {{{",
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 2
    # Even on error, emits a done line
    assert proc.stdout.strip()
    last = json.loads(proc.stdout.strip().split("\n")[-1])
    assert last["done"] is True
    assert "error" in last


def test_engine_verbose_logs_to_stderr_not_stdout() -> None:
    """verbose=true must write diagnostics to stderr, not stdout."""
    result = _run({"mode": "whitebox", "checks": [], "verbose": True})
    assert result.returncode == 0
    # Every stdout line is valid JSON — no text mixed in
    for line in result.stdout.strip().split("\n"):
        if line:
            json.loads(line)
    # stderr should contain the verbose log message
    assert "[fendix-engine]" in result.stderr


def test_engine_skips_check_when_code_path_missing() -> None:
    """Checks that require code_path must be silently skipped if not provided."""
    result = _run({"mode": "whitebox", "checks": ["secrets", "semgrep", "deps"]})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True


def test_engine_skips_auth_check_when_spec_missing() -> None:
    """Auth check requires spec; must be skipped if not provided."""
    result = _run({"mode": "whitebox", "checks": ["auth"]})
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True


def test_engine_continues_after_analyzer_crash() -> None:
    """If one analyzer crashes, the engine must still emit done."""
    # /nonexistent path will not crash SecretsAnalyzer (it just yields nothing),
    # so we test the general resilience: engine always terminates
    result = _run(
        {"mode": "whitebox", "checks": ["secrets", "deps"], "code_path": "/nonexistent/path"}
    )
    assert result.returncode == 0
    objects = _parse_output(result)
    assert objects[-1]["done"] is True


def _statuses(objects: list[dict]) -> dict[str, dict]:
    return {o["status"]["check"]: o["status"] for o in objects if isinstance(o.get("status"), dict)}


def _load_engine_module():
    spec = importlib.util.spec_from_file_location("fendix_engine_under_test", ENGINE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_status_lines_for_every_check_even_when_none_run() -> None:
    result = _run({"mode": "whitebox", "checks": [], "verbose": False})
    objects = _parse_output(result)
    statuses = _statuses(objects)
    assert set(statuses) == {"auth", "injection", "deps"}
    for s in statuses.values():
        assert s["state"] == "skipped"
        assert s["reason"] == "disabled_by_flag"
    assert objects[-1]["protocol"] == 2


def test_exactly_one_status_line_per_check() -> None:
    result = _run({"mode": "whitebox", "checks": ["auth", "injection", "deps"], "code_path": "/nonexistent"})
    lines = [o["status"]["check"] for o in _parse_output(result) if isinstance(o.get("status"), dict)]
    assert sorted(lines) == ["auth", "deps", "injection"]


def test_status_not_applicable_when_input_missing() -> None:
    result = _run({"mode": "whitebox", "checks": ["auth", "injection", "deps"], "verbose": False})
    statuses = _statuses(_parse_output(result))
    assert statuses["auth"]["reason"] == "not_applicable"
    assert statuses["injection"]["reason"] == "not_applicable"
    assert statuses["deps"]["reason"] == "not_applicable"


def test_done_total_ignores_status_lines() -> None:
    result = _run({"mode": "whitebox", "checks": ["injection"], "code_path": "/nonexistent"})
    objects = _parse_output(result)
    findings = [o for o in objects if "title" in o]
    assert objects[-1]["done"] is True
    assert objects[-1]["total"] == len(findings)


def test_injection_ok_on_python_and_unsupported_on_js_only() -> None:
    with tempfile.TemporaryDirectory() as py_dir, tempfile.TemporaryDirectory() as js_dir:
        Path(py_dir, "app.py").write_text("import os\nx = os.environ.get('X')\n")
        Path(js_dir, "app.js").write_text("const x = 1;\n")
        py = _statuses(_parse_output(_run({"mode": "whitebox", "checks": ["injection"], "code_path": py_dir})))
        js = _statuses(_parse_output(_run({"mode": "whitebox", "checks": ["injection"], "code_path": js_dir})))
    assert py["injection"]["state"] == "ok"
    assert js["injection"]["state"] == "skipped"
    assert js["injection"]["reason"] == "unsupported_target"
    assert "JavaScript" in js["injection"]["detail"]


def test_run_check_classifies_import_error_and_exception(capsys) -> None:
    engine = _load_engine_module()

    def missing() -> None:
        raise ImportError("No module named 'packaging'")

    def broken() -> None:
        raise ValueError("bad spec")

    assert engine._run_check("deps", "deps", missing, False) == ("skipped", "dependency_missing", "No module named 'packaging'")
    state, reason, detail = engine._run_check("auth", "auth (spec)", broken, False)
    assert (state, reason) == ("failed", "execution_error")
    assert detail == "ValueError: bad spec"
    assert engine._run_check("injection", "injection (ast)", lambda: None, False) == ("ok", None, None)
