"""Required analyzers for the composite Action (scripts/action/analyzer_preflight.py).

Which analyzers the require-analyzers input requires, how the runner's
platform is described when Semgrep has no wheel for it, and the functional
Semgrep probe, run against fake `semgrep` executables for every way a broken
install fails: missing, not executable, another architecture, a crash, a
non-zero exit, no semgrep-core, no JSON, no results, a wrong result and a
hang. No network and no real Semgrep are needed.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "action" / "analyzer_preflight.py"
spec = importlib.util.spec_from_file_location("analyzer_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

GLIBC_231 = {"system": "Linux", "machine": "x86_64", "libc": "glibc", "libc_version": "2.31", "python": "3.11.13", "mac": ""}


class RegistryTests(unittest.TestCase):
    def test_registry_matches_the_engine(self):
        source = (REPO / "go" / "internal" / "engine" / "registry.go").read_text()
        constants = dict(re.findall(r'^\s*(Analyzer\w+)\s*=\s*"([^"]+)"', source, re.MULTILINE))
        body = re.search(r"var Registry = \[\]string\{(.*?)\n\}", source, re.DOTALL).group(1)
        names = [constants[name] for name in re.findall(r"Analyzer\w+", body)]
        self.assertEqual(tuple(names), preflight.REGISTRY)


class ResolveTests(unittest.TestCase):
    def test_auto_requires_semgrep_for_a_code_scan(self):
        for value in ("auto", "AUTO", " auto ", ""):
            with self.subTest(value=value):
                self.assertEqual(preflight.resolve_required(value, "."), (["semgrep"], "auto"))

    def test_auto_requires_nothing_without_code(self):
        # A URL-only scan: the engine records semgrep not_applicable.
        self.assertEqual(preflight.resolve_required("auto", ""), ([], "auto"))
        self.assertEqual(preflight.resolve_required("auto", "  "), ([], "auto"))

    def test_none_is_the_explicit_opt_out(self):
        for value in ("none", "None", "NONE"):
            with self.subTest(value=value):
                self.assertEqual(preflight.resolve_required(value, "."), ([], "none"))

    def test_explicit_list_is_validated_and_deduplicated(self):
        self.assertEqual(preflight.resolve_required("semgrep, secrets,semgrep,python-engine/injection", "."),
                         (["semgrep", "secrets", "python-engine/injection"], "explicit"))
        self.assertEqual(preflight.resolve_required("secrets", "."), (["secrets"], "explicit"))

    def test_invalid_lists_fail_with_a_reason(self):
        for value, reason in (("semgerp", "unknown analyzer 'semgerp'"), ("Semgrep", "unknown analyzer"),
                              ("semgrep,,secrets", "empty entry"), ("semgrep,none", "mixes 'none'"),
                              ("auto,semgrep", "mixes 'auto'"), ("semgrep;rm -rf /", "unknown analyzer")):
            with self.subTest(value=value):
                with self.assertRaises(preflight.RequirementError) as failure:
                    preflight.resolve_required(value, ".")
                self.assertIn(reason, str(failure.exception))
        with self.assertRaises(preflight.RequirementError) as failure:
            preflight.resolve_required("semgerp", ".")
        self.assertIn("dast", str(failure.exception))  # the message lists the registry

    def test_managed_mode_takes_only_auto(self):
        self.assertEqual(preflight.resolve_required("auto", ".", mode="managed"), (["semgrep"], "auto"))
        for value in ("none", "secrets"):
            with self.subTest(value=value):
                with self.assertRaises(preflight.RequirementError) as failure:
                    preflight.resolve_required(value, ".", mode="managed")
                self.assertIn("backend policy", str(failure.exception))


class PlatformTests(unittest.TestCase):
    def facts(self, **overrides):
        facts = dict(GLIBC_231)
        facts.update(overrides)
        return facts

    def test_glibc_and_architecture_detection(self):
        with mock.patch.object(preflight.platform, "system", return_value="Linux"), \
                mock.patch.object(preflight.platform, "machine", return_value="x86_64"), \
                mock.patch.object(preflight.os, "confstr", create=True, return_value="glibc 2.31"):
            facts = preflight.platform_facts()
        self.assertEqual((facts["libc"], facts["libc_version"], facts["machine"]), ("glibc", "2.31", "x86_64"))

    def test_musl_detection_reads_the_loader(self):
        with tempfile.TemporaryDirectory() as temp:
            loader = Path(temp) / "ld-musl-x86_64.so.1"
            loader.write_text("#!/bin/sh\nprintf 'musl libc (x86_64)\\nVersion 1.2.4\\n' >&2\nexit 1\n")
            loader.chmod(0o755)
            with mock.patch.object(preflight.glob, "glob", return_value=[str(loader)]):
                self.assertEqual(preflight.musl_version(), "1.2.4")
            with mock.patch.object(preflight.platform, "system", return_value="Linux"), \
                    mock.patch.object(preflight.os, "confstr", create=True, side_effect=ValueError("unrecognized")), \
                    mock.patch.object(preflight.glob, "glob", return_value=[str(loader)]):
                facts = preflight.platform_facts()
        self.assertEqual((facts["libc"], facts["libc_version"]), ("musl", "1.2.4"))

    def test_shortfall_by_platform(self):
        cases = [
            (self.facts(), "glibc 2.31 is older than 2.34"),
            (self.facts(libc_version="2.26"), "glibc 2.26 is older than 2.34"),
            (self.facts(libc_version="2.34"), None),
            (self.facts(libc_version="2.39", machine="aarch64"), None),
            (self.facts(libc_version="2.39", machine="ppc64le"), "ppc64le is neither x86_64 nor aarch64"),
            (self.facts(libc="musl", libc_version="1.1.24"), "musl 1.1.24 is older than 1.2"),
            (self.facts(libc="musl", libc_version="1.2.4"), None),
            (self.facts(libc=None, libc_version=None), "neither glibc nor musl"),
            (self.facts(system="Darwin", machine="arm64", libc=None, libc_version=None, mac="15.1"), None),
        ]
        for facts, want in cases:
            with self.subTest(facts=facts):
                got = preflight.platform_shortfall(facts)
                if want is None:
                    self.assertIsNone(got)
                else:
                    self.assertIn(want, got)

    def test_required_semgrep_message_names_everything_a_user_needs(self):
        message = preflight.no_wheel_message("semgrep", "semgrep==1.182.1", self.facts(), required=True)
        for want in ("semgrep==1.182.1", "glibc 2.31 on x86_64", "glibc 2.34 or later", "manylinux_2_34",
                     "musl 1.2 or later", "x86_64 or aarch64", "never builds Semgrep from source",
                     "no semgrep-core", "docker.io/fendixapp/fendix@sha256:", "container job",
                     "INTEGRATION_GUIDE.md#34", "Ubuntu 22.04", "Debian 12", "RHEL 9", "Amazon Linux 2023",
                     "require-analyzers to none"):
            self.assertIn(want, message)

    def test_unrequired_semgrep_message_has_no_remedies(self):
        message = preflight.no_wheel_message("semgrep", "semgrep==1.182.1", self.facts(), required=False)
        self.assertIn("glibc 2.31", message)
        self.assertNotIn("Remedies", message)

    def test_supported_platform_points_at_the_index_not_the_platform(self):
        message = preflight.no_wheel_message("semgrep", "semgrep==1.182.1", self.facts(libc_version="2.39"), required=True)
        self.assertIn("package index may be unreachable", message)
        self.assertNotIn("older than", message)

    def test_other_package_message_names_it(self):
        message = preflight.no_wheel_message("pydantic-core", "pydantic-core==2.46.5", self.facts(machine="ppc64le"), required=True)
        self.assertIn("pydantic-core==2.46.5", message)
        self.assertIn("ppc64le is neither x86_64 nor aarch64", message)
        self.assertNotIn("require-analyzers to none", message)


MATCH = {"check_id": "tmp.fendix-preflight.abc.fendix-preflight-probe", "path": "/x/target/probe.py",
         "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 26}}


def semgrep_script(body):
    return "#!/bin/sh\n" + textwrap.dedent(body)


class ProbeTests(unittest.TestCase):
    """probe_semgrep against fake semgrep executables."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def fake(self, content, mode=0o755, name="semgrep"):
        path = self.root / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        path.chmod(mode)
        return str(path)

    def json_fake(self, document, code=0):
        doc = self.root / "doc.json"
        doc.write_text(json.dumps(document))
        return self.fake(semgrep_script(f"""\
            printf '%s\\n' "$@" > "{self.root}/argv"
            cat "{doc}"
            exit {code}
        """))

    def failure(self, executable, timeout=preflight.PROBE_TIMEOUT):
        with self.assertRaises(preflight.PreflightError) as failure:
            preflight.probe_semgrep(executable, timeout=timeout)
        self.assertEqual(failure.exception.analyzer, "semgrep")
        return str(failure.exception)

    def test_healthy_semgrep_passes_and_runs_offline(self):
        version, seconds = preflight.probe_semgrep(self.json_fake({"version": "1.182.1", "results": [MATCH], "errors": []}))
        self.assertEqual(version, "1.182.1")
        self.assertGreaterEqual(seconds, 0)
        argv = (self.root / "argv").read_text().splitlines()
        for flag in ("--json", "--metrics=off", "--disable-version-check", "--no-git-ignore", "--config"):
            self.assertIn(flag, argv)
        rule = Path(argv[argv.index("--config") + 1])
        self.assertFalse(rule.exists(), "the probe's temporary files were left behind")

    def test_bare_rule_id_also_matches(self):
        match = dict(MATCH, check_id="fendix-preflight-probe")
        preflight.probe_semgrep(self.json_fake({"version": "1.141.0", "results": [match]}))

    def test_missing_semgrep(self):
        with mock.patch.object(preflight, "_which", return_value=None):
            message = self.failure(None)
        self.assertIn("no semgrep executable is on PATH", message)

    def test_not_executable(self):
        message = self.failure(self.fake(semgrep_script("exit 0\n"), mode=0o644))
        self.assertIn("could not be started", message)

    def test_wrong_architecture_or_corrupt_binary(self):
        # Not an ELF for this machine and no #! line: exec fails with ENOEXEC.
        message = self.failure(self.fake(b"\x7fELF\x02\x01\x01" + os.urandom(64)))
        self.assertIn("not an executable this runner can run", message)
        self.assertIn("another architecture", message)

    def test_startup_crash(self):
        message = self.failure(self.fake(semgrep_script("echo 'Fatal Python error' >&2; kill -SEGV $$\n")))
        self.assertIn("crashed", message)
        self.assertIn("SIGSEGV", message)

    def test_non_zero_exit(self):
        message = self.failure(self.fake(semgrep_script("echo 'something broke' >&2; exit 3\n")))
        self.assertIn("exited 3", message)
        self.assertIn("something broke", message)

    def test_no_semgrep_core(self):
        # What a Semgrep built from its source distribution prints.
        message = self.failure(self.fake(semgrep_script(
            "echo 'Failed to find semgrep-core in PATH or in the semgrep package.' >&2; exit 2\n")))
        self.assertIn("has no semgrep-core", message)
        self.assertIn("source distribution", message)

    def test_exit_zero_with_no_results_is_a_damaged_install(self):
        message = self.failure(self.json_fake({"version": "1.182.1", "results": [], "errors": []}))
        self.assertIn("did not report the probe's one known match", message)
        self.assertIn("0 results", message)
        self.assertIn("look clean", message)

    def test_errors_are_named_when_the_match_is_missing(self):
        message = self.failure(self.json_fake({"results": [], "errors": [{"message": "rule parse error"}]}, code=2))
        self.assertIn("exited 2", message)
        message = self.failure(self.json_fake({"results": [], "errors": [{"message": "rule parse error"}]}))
        self.assertIn("rule parse error", message)

    def test_wrong_output(self):
        message = self.failure(self.fake(semgrep_script("echo 'Usage: semgrep [OPTIONS]'\n")))
        self.assertIn("did not write JSON", message)
        self.assertIn("Usage: semgrep", message)

    def test_json_without_results(self):
        message = self.failure(self.json_fake({"version": "1.182.1"}))
        self.assertIn("without a results list", message)

    def test_a_result_elsewhere_is_not_the_probe_match(self):
        for result in (dict(MATCH, path="/x/target/other.py"), dict(MATCH, start={"line": 2}),
                       dict(MATCH, check_id="another-rule"), "not a result"):
            with self.subTest(result=result):
                self.failure(self.json_fake({"results": [result]}))

    def test_hang_is_bounded_and_killed(self):
        executable = self.fake(semgrep_script(f"""\
            (sleep 60; touch "{self.root}/survived") &
            sleep 60
        """))
        started = time.monotonic()
        message = self.failure(executable, timeout=1)
        self.assertLess(time.monotonic() - started, 15)
        self.assertIn("within 1 s", message)
        time.sleep(0.5)
        self.assertFalse((self.root / "survived").exists())


class MainTests(unittest.TestCase):
    """The script as the Action's preflight step runs it."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def run_step(self, required, requirement="auto", semgrep=None):
        if semgrep is not None:
            path = self.bin / "semgrep"
            path.write_text(semgrep)
            path.chmod(0o755)
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "REQUIRED": required, "REQUIREMENT": requirement}
        return subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, check=False)

    def test_failed_probe_is_one_error_line_naming_the_analyzer(self):
        result = self.run_step("semgrep", semgrep=semgrep_script(
            "echo 'Failed to find semgrep-core in PATH or in the semgrep package.' >&2; exit 2\n"))
        self.assertEqual(result.returncode, 2, result.stderr)
        errors = [line for line in result.stderr.splitlines() if line.startswith("::error")]
        self.assertEqual(len(errors), 1, result.stderr)
        self.assertTrue(errors[0].startswith("::error title=Fendix required analyzer semgrep is unavailable::"
                                             "Required analyzer semgrep cannot run."), errors[0])
        self.assertNotIn("passed", result.stdout)

    def test_missing_semgrep_on_path(self):
        result = self.run_step("semgrep")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no semgrep executable is on PATH", result.stderr)

    def test_passing_probe(self):
        doc = self.root / "doc.json"
        doc.write_text(json.dumps({"version": "1.182.1", "results": [MATCH]}))
        result = self.run_step("semgrep", semgrep=semgrep_script(f'cat "{doc}"\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("semgrep: Semgrep 1.182.1 at", result.stdout)
        self.assertIn("preflight passed", result.stdout)

    def test_analyzers_without_a_probe_are_left_to_the_engine(self):
        result = self.run_step("python-engine,secrets")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("python-engine: no setup probe; the engine enforces it at scan time", result.stdout)

    def test_none_says_enforcement_is_off(self):
        result = self.run_step("", requirement="none")
        self.assertEqual(result.returncode, 0)
        self.assertIn("require-analyzers: none", result.stdout)
        self.assertIn("enforcement is off", result.stdout)

    def test_no_code_requires_nothing(self):
        result = self.run_step("", requirement="auto")
        self.assertEqual(result.returncode, 0)
        self.assertIn("code input is empty", result.stdout)

    def test_unknown_analyzer_fails_closed(self):
        result = self.run_step("semgrep,bogus")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown analyzer", result.stderr)

    def test_error_line_cannot_inject_a_command(self):
        line = preflight.PreflightError("semgrep", "first\n::warning::x %").line()
        self.assertNotIn("\n", line)
        self.assertIn("first%0A::warning::x %25", line)


if __name__ == "__main__":
    unittest.main()
